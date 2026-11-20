//! The day ceilings of `budgets.hard_ceilings` and the running cap of `budgets.concurrency`, as
//! the authority of the worker applies them.
//!
//! Before this the policy had the ceilings and nothing read them: admission said yes whatever a
//! repository or the organization had spent in the day, and the running cap per repository was a
//! constant `true`.
//!
//! The first group runs over the in-memory store and a clock the test moves, so the day boundary
//! is exact. The second group runs the engine over PostgreSQL, where the day is the one of the
//! database clock and the spend is what real attempts recorded.

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use factory_composition::authority::StoreAuthority;
use factory_composition::seams::FileAllowlist;
use factory_composition::startup::load_policy;
use factory_domain::contracts::{Contract, DomainEvent};
use factory_domain::ids::{CorrelationId, JobId, PrincipalId, RepositoryId, TenantId};
use factory_domain::machines::guards::AdmissionFacts;
use factory_domain::policy::PolicyEngine;
use factory_domain::policy::budget::{Metric, Scope};
use factory_domain::scope::TenantScope;
use factory_domain::state::JobStatus;
use factory_domain::vocabulary::{AutonomyLevel, ExecutionMode, StageKind};
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::store::{
    AuditFilter, NewJob, NewPrincipal, PipelineScope, PrincipalKind, Store,
};
use factory_testkit::clock::FakeClock;
use factory_testkit::fixtures::{Ids, SeededRepository};
use factory_testkit::store::InMemoryStore;
use factory_workflow::commands::Authority;
use factory_workflow::engine::{Admission, Engine};
use factory_workflow::scheduler::Deferral;
use serde_json::json;
use support::engine::PgWorld;
use support::pg_world;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// The real policies, with the ceilings a test lowers. A ceiling can only go down.
fn policy_with(lower: &[(Scope, Metric, f64)]) -> Arc<PolicyEngine> {
    let loaded = load_policy(&root(), &[]).expect("the real policies load");
    let mut engine =
        PolicyEngine::new(&loaded.security, &loaded.approval).expect("the evaluators build");
    for (scope, metric, value) in lower {
        engine.budget = engine
            .budget
            .lowered(*scope, &[(*metric, *value)])
            .expect("a lower ceiling is accepted");
    }
    Arc::new(engine)
}

/// A directory with an allowlist that lists GitHub user 1001 as a requester of `tenants`.
fn allowlist_for(tenants: &[TenantId], name: &str) -> (PathBuf, Arc<FileAllowlist>) {
    let checkout = root().join("target/spend-ceilings").join(format!(
        "{name}-{}-{}",
        std::process::id(),
        tenants[0].as_uuid().simple()
    ));
    std::fs::create_dir_all(checkout.join("allowlist")).expect("a directory");
    let mut text = "version: 1\nentries:\n".to_owned();
    for tenant in tenants {
        text.push_str(&format!(
            "  - tenant: {}\n    github_user_id: 1001\n    login: requester-one\n    designations: [requester]\n",
            tenant.as_uuid()
        ));
    }
    std::fs::write(checkout.join("allowlist/allowlist.yaml"), text).expect("the allowlist file");
    let allowlist = Arc::new(FileAllowlist::in_checkout(&checkout));
    (checkout, allowlist)
}

// ---- over the in-memory store ---------------------------------------------------------------------

/// A tenant with repositories, a requester and an authority, over the in-memory store.
struct Bench {
    store: Arc<InMemoryStore>,
    clock: Arc<FakeClock>,
    ids: Ids,
    tenant: TenantId,
    requester: PrincipalId,
    authority: StoreAuthority,
    checkout: PathBuf,
}

impl Bench {
    async fn new(start: &str, name: &str, lower: &[(Scope, Metric, f64)]) -> Self {
        let clock = Arc::new(FakeClock::starting_at(start));
        let store = Arc::new(InMemoryStore::new(clock.clone()));
        let ids = Ids::new();
        let tenant = ids.tenant();
        let (checkout, allowlist) = allowlist_for(&[tenant], name);
        let requester = Self::requester_of(&store, &ids, tenant).await;
        let authority =
            StoreAuthority::new(store.clone(), allowlist, policy_with(lower), clock.clone());
        Self {
            store,
            clock,
            ids,
            tenant,
            requester,
            authority,
            checkout,
        }
    }

    async fn requester_of(store: &InMemoryStore, ids: &Ids, tenant: TenantId) -> PrincipalId {
        let requester = PrincipalId::from_uuid(ids.job().as_uuid());
        let mut tx = store.begin(TenantScope::new(tenant)).await.expect("a tx");
        tx.insert_principal(NewPrincipal {
            id: requester,
            kind: PrincipalKind::Human {
                github_user_id: 1001,
            },
            login: None,
        })
        .await
        .expect("a principal");
        tx.commit().await.expect("commit");
        requester
    }

    fn repository(&self) -> RepositoryId {
        self.store.seed_repository(self.tenant)
    }

    /// A job of `repository` whose one ended attempt reported `cost`, now.
    async fn job_that_spent(&self, repository: RepositoryId, cost: serde_json::Value) -> JobId {
        let job = self.ids.job();
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        tx.insert_job(NewJob {
            id: job,
            correlation_id: CorrelationId::from_uuid(job.as_uuid()),
            repository,
            requester: self.requester,
            execution_mode: ExecutionMode::Test,
            autonomy_level: AutonomyLevel::L0,
            pipeline_scope: PipelineScope::new(vec![StageKind::Intake]).expect("a scope"),
            origin: None,
        })
        .await
        .expect("a job");
        let event = DomainEvent::from_json_value(json!({
            "schema_version": 1,
            "event_id": self.ids.event().to_string(),
            "event_type": "attempt.succeeded",
            "event_version": 1,
            "tenant_id": self.tenant.to_string(),
            "job_id": job.to_string(),
            "aggregate": { "type": "attempt", "id": self.ids.attempt().to_string(), "version": 2 },
            "transition_id": "A03",
            "correlation_id": job.to_string(),
            "causation_id": null,
            "occurred_at": self.clock.now().to_string(),
            "producer": "testkit.fake",
            "payload": { "cost_micro_usd": cost }
        }))
        .expect("an attempt event");
        tx.enqueue_event(event).await.expect("the event is stored");
        tx.commit().await.expect("commit");
        job
    }

    async fn facts(&self, repository: RepositoryId) -> AdmissionFacts {
        self.authority
            .admission(self.tenant, self.requester, repository)
            .await
            .expect("facts")
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.checkout);
    }
}

#[tokio::test]
async fn a_repository_at_its_day_ceiling_has_no_room_and_its_neighbour_has() {
    // The real ceiling: 100 dollars for one repository in one day.
    let bench = Bench::new("2026-11-10T09:00:00Z", "repository", &[]).await;
    let (busy, quiet) = (bench.repository(), bench.repository());

    bench.job_that_spent(busy, json!(60_000_000u64)).await;
    let facts = bench.facts(busy).await;
    assert!(
        facts.repository_day_budget_has_room && facts.organization_day_budget_has_room,
        "60 of 100 dollars leaves room: {facts:?}"
    );

    bench.job_that_spent(busy, json!(40_000_000u64)).await;
    let facts = bench.facts(busy).await;
    assert!(
        !facts.repository_day_budget_has_room,
        "100 of 100 dollars is the ceiling reached: {facts:?}"
    );
    assert!(
        facts.organization_day_budget_has_room,
        "100 of the organization's 500 dollars leaves room: {facts:?}"
    );
    // Nothing else about admission changed, so the refusal is the ceiling and only the ceiling.
    assert!(facts.requester_on_allowlist && facts.repository_registered_and_enabled);
    assert!(facts.tenant_within_job_quota && facts.policy_allows_request_class);

    let facts = bench.facts(quiet).await;
    assert!(
        facts.repository_day_budget_has_room,
        "the spend of one repository does not fill another: {facts:?}"
    );
}

#[tokio::test]
async fn the_day_is_the_utc_day_of_the_database_clock() {
    let bench = Bench::new("2026-11-10T23:50:00Z", "day", &[]).await;
    let repository = bench.repository();
    bench
        .job_that_spent(repository, json!(100_000_000u64))
        .await;
    assert!(!bench.facts(repository).await.repository_day_budget_has_room);

    // Nine minutes later it is still the tenth of November.
    bench.clock.advance(Duration::from_secs(9 * 60));
    assert!(!bench.facts(repository).await.repository_day_budget_has_room);

    // At ten past midnight UTC the spend of yesterday no longer counts.
    bench.clock.advance(Duration::from_secs(11 * 60));
    assert!(
        bench.facts(repository).await.repository_day_budget_has_room,
        "a new UTC day starts with nothing spent"
    );
}

#[tokio::test]
async fn the_organization_ceiling_counts_every_repository_of_the_tenant_and_no_other_tenant() {
    let lower = [(Scope::OrgDay, Metric::Usd, 150.0)];
    let bench = Bench::new("2026-11-10T09:00:00Z", "organization", &lower).await;
    let (first, second, third) = (bench.repository(), bench.repository(), bench.repository());
    bench.job_that_spent(first, json!(80_000_000u64)).await;
    assert!(bench.facts(third).await.organization_day_budget_has_room);
    bench.job_that_spent(second, json!(80_000_000u64)).await;

    let facts = bench.facts(third).await;
    assert!(
        !facts.organization_day_budget_has_room,
        "160 of 150 dollars across two repositories is the organization's ceiling reached: {facts:?}"
    );
    assert!(
        facts.repository_day_budget_has_room,
        "the third repository itself spent nothing: {facts:?}"
    );

    // Another tenant of the same store is another organization.
    let other = bench.ids.tenant();
    let (checkout, allowlist) = allowlist_for(&[other], "organization-other");
    let requester = Bench::requester_of(&bench.store, &bench.ids, other).await;
    let theirs = bench.store.seed_repository(other);
    let authority = StoreAuthority::new(
        bench.store.clone(),
        allowlist,
        policy_with(&lower),
        bench.clock.clone(),
    );
    let facts = authority
        .admission(other, requester, theirs)
        .await
        .expect("facts");
    assert!(facts.organization_day_budget_has_room, "{facts:?}");
    let _ = std::fs::remove_dir_all(checkout);
}

#[tokio::test]
async fn a_spend_that_cannot_be_read_counts_as_the_ceiling_reached() {
    let bench = Bench::new("2026-11-10T09:00:00Z", "unreadable", &[]).await;
    let (broken, sound) = (bench.repository(), bench.repository());
    // An attempt whose cost is not a number of millionths of a dollar: nothing can be summed.
    bench.job_that_spent(broken, json!("a lot")).await;

    let facts = bench.facts(broken).await;
    assert!(
        !facts.repository_day_budget_has_room && !facts.organization_day_budget_has_room,
        "a spend nobody can read is not a spend with room: {facts:?}"
    );
    // The other repository's own spend can be read (it is nothing); the organization's cannot.
    let facts = bench.facts(sound).await;
    assert!(facts.repository_day_budget_has_room, "{facts:?}");
    assert!(!facts.organization_day_budget_has_room, "{facts:?}");
}

// ---- the engine over PostgreSQL -----------------------------------------------------------------------

/// An engine of `world` whose authority is the real one, under `policy`.
fn engine_with(world: &PgWorld, tenant: TenantId, policy: Arc<PolicyEngine>) -> (Engine, PathBuf) {
    let (checkout, allowlist) = allowlist_for(&[tenant], "engine");
    let authority = Arc::new(StoreAuthority::new(
        world.store.clone(),
        allowlist,
        policy,
        world.deps.clock.clone(),
    ));
    let mut deps = world.deps.clone();
    deps.authority = authority;
    let engine =
        Engine::new(deps, world.config.clone(), world.handlers.clone()).expect("an engine");
    (engine, checkout)
}

async fn admit(engine: &Engine, world: &PgWorld, repository: RepositoryId) -> (JobId, Admission) {
    let job = engine
        .receive_job(world.tenant, world.requester, repository)
        .await
        .expect("received");
    let admission = engine.admit_job(world.tenant, job).await.expect("decided");
    (job, admission)
}

/// The reasons of the audit records that deny something about `job`.
async fn denials(world: &PgWorld, job: JobId) -> Vec<String> {
    let mut tx = world
        .store
        .begin(TenantScope::new(world.tenant))
        .await
        .expect("a tx");
    let records = tx
        .read_audit(AuditFilter::Job(job), 0, 100)
        .await
        .expect("the audit log");
    tx.rollback().await.expect("rollback");
    records
        .into_iter()
        .filter(|record| record.event.decision == factory_ports::store::AuditDecision::Deny)
        .map(|record| record.event.reason)
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_is_refused_at_admission_when_the_repository_spent_its_day_and_the_audit_names_the_ceiling()
 {
    let (_db, world, tenant) = pg_world().await;
    // One dollar a day for a repository, so that one attempt of two dollars reaches it.
    let policy = policy_with(&[(Scope::RepoDay, Metric::Usd, 1.0)]);
    let (engine, checkout) = engine_with(&world, tenant, policy);

    let (first, admission) = admit(&engine, &world, world.repository).await;
    assert!(
        matches!(admission, Admission::Admitted { .. }),
        "{admission:?}"
    );
    world.script(StageKind::Intake).agent_spending(2_000_000);
    let claimed = engine
        .claim_next(&PgWorld::worker("worker-spend"))
        .await
        .expect("claim");
    assert_eq!(claimed.started.len(), 1, "{claimed:?}");
    engine
        .run_attempt(&claimed.started[0])
        .await
        .expect("the attempt runs");

    let (second, admission) = admit(&engine, &world, world.repository).await;
    assert_eq!(admission, Admission::Rejected);
    assert_eq!(
        engine.job_status(tenant, second).await.expect("a status"),
        JobStatus::Rejected
    );
    let reasons = denials(&world, second).await;
    assert_eq!(reasons.len(), 1, "{reasons:?}");
    assert!(
        reasons[0].contains("budgets.hard_ceilings.per_repo_day"),
        "the audit record names the ceiling: {reasons:?}"
    );
    assert!(
        !reasons[0].contains("per_org_day") && !reasons[0].contains("allowlist"),
        "and only the test that failed: {reasons:?}"
    );
    // The job that was running is not touched by the refusal of the next one.
    assert!(denials(&world, first).await.is_empty());
    let _ = std::fs::remove_dir_all(checkout);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repository_that_started_its_jobs_of_the_day_starts_no_more() {
    let (_db, world, tenant) = pg_world().await;
    let policy = policy_with(&[(Scope::RepoDay, Metric::JobsStarted, 2.0)]);
    let (engine, checkout) = engine_with(&world, tenant, policy);

    for _ in 0..2 {
        let (_, admission) = admit(&engine, &world, world.repository).await;
        assert!(
            matches!(admission, Admission::Admitted { .. }),
            "{admission:?}"
        );
    }
    let (third, admission) = admit(&engine, &world, world.repository).await;
    assert_eq!(admission, Admission::Rejected);
    let reasons = denials(&world, third).await;
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("budgets.hard_ceilings.per_repo_day")),
        "{reasons:?}"
    );
    // A refused job is not a started job: the count stays at two, so the answer does not change.
    let (_, admission) = admit(&engine, &world, world.repository).await;
    assert_eq!(admission, Admission::Rejected);
    let _ = std::fs::remove_dir_all(checkout);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_third_job_of_a_repository_does_not_start_while_two_are_running() {
    let (db, world, tenant) = pg_world().await;
    let policy = policy_with(&[]);
    assert_eq!(policy.budget.max_running_jobs_per_repo(), 2);
    let (engine, checkout) = engine_with(&world, tenant, policy);
    let worker = PgWorld::worker("worker-cap");

    let mut jobs = Vec::new();
    for _ in 0..3 {
        let (job, admission) = admit(&engine, &world, world.repository).await;
        assert!(
            matches!(admission, Admission::Admitted { .. }),
            "{admission:?}"
        );
        jobs.push(job);
    }
    // Two attempts start and stay running: nobody runs them to their end.
    let mut running = Vec::new();
    for _ in 0..2 {
        let claimed = engine.claim_next(&worker).await.expect("claim");
        assert_eq!(claimed.started.len(), 1, "{claimed:?}");
        running.push(claimed.started[0].job);
    }
    assert_ne!(running[0], running[1], "two jobs are running");

    // The third job's stage run is found and is not started.
    let claimed = engine.claim_next(&worker).await.expect("claim");
    assert!(claimed.started.is_empty(), "{claimed:?}");
    assert_eq!(claimed.deferred.len(), 1, "{claimed:?}");
    assert_eq!(claimed.deferred[0].1, Deferral::QuotaExceeded);

    // The cap is per repository: a job of another repository starts while the first is full.
    let second = RepositoryId::from_uuid(world.ids.new_uuid());
    db.run(
        &SeededRepository {
            tenant: &tenant.as_uuid().to_string(),
            id: &second.as_uuid().to_string(),
            installation: 1000,
            github_repository: 2999,
            full_name: "org/repo-second",
            default_branch: "main",
            autonomy_ceiling: "L0",
        }
        .sql(),
    )
    .await;
    let (elsewhere, admission) = admit(&engine, &world, second).await;
    assert!(
        matches!(admission, Admission::Admitted { .. }),
        "{admission:?}"
    );
    let claimed = engine.claim_next(&worker).await.expect("claim");
    assert_eq!(claimed.started.len(), 1, "{claimed:?}");
    assert_eq!(claimed.started[0].job, elsewhere);
    assert!(jobs.iter().all(|job| *job != elsewhere));
    let _ = std::fs::remove_dir_all(checkout);
}

// ---- the ceiling of one job ---------------------------------------------------------------------------

#[test]
fn the_rework_caps_of_each_count_are_read_from_the_policy() {
    use factory_composition::pipeline::apply_budget_policy;
    use factory_domain::machines::limits::ReworkTrack;
    use factory_domain::values::Sha256Digest;
    use factory_domain::vocabulary::ExecutionMode;
    use factory_workflow::engine::EngineConfig;

    let loaded = load_policy(&root(), &[]).expect("the real policies load");
    let config_for = |security: &factory_domain::policy::SecurityPolicy| {
        let engine = PolicyEngine::new(security, &loaded.approval).expect("the evaluators build");
        let mut config = EngineConfig::new(ExecutionMode::Test, Sha256Digest::of(b"policy"));
        apply_budget_policy(&mut config, &engine.budget);
        config
    };
    // The real policy: two rounds on every count, two repairs.
    let config = config_for(&loaded.security);
    for track in ReworkTrack::ALL {
        assert_eq!(config.rework_limits.cap(*track).get(), 2, "{track}");
    }
    assert_eq!(config.repair_cap.get(), 2);
    assert_eq!(config.job_budget_micro_usd, 25_000_000);

    // A policy that lowers one count lowers that count in the engine and no other.
    let mut lowered = (*loaded.security).clone();
    lowered
        .budgets
        .hard_ceilings
        .per_job
        .max_design_rework_iterations = 0;
    lowered
        .budgets
        .hard_ceilings
        .per_job
        .max_specification_rework_iterations = 1;
    lowered
        .untrusted_content
        .structured_output
        .bounded_repair_attempts = 1;
    let config = config_for(&lowered);
    assert_eq!(config.rework_limits.cap(ReworkTrack::Design).get(), 0);
    assert_eq!(
        config.rework_limits.cap(ReworkTrack::Specification).get(),
        1
    );
    assert_eq!(config.rework_limits.cap(ReworkTrack::Code).get(), 2);
    assert_eq!(
        config.rework_limits.cap(ReworkTrack::Documentation).get(),
        2
    );
    assert_eq!(config.repair_cap.get(), 1);
}

#[test]
fn the_ceiling_of_a_job_is_read_from_the_policy() {
    use factory_composition::pipeline::job_budget_micro_usd;
    // `budgets.hard_ceilings.per_job.max_usd` is 25 dollars, and work stops at the whole of it.
    assert_eq!(job_budget_micro_usd(&policy_with(&[]).budget), 25_000_000);
    let lowered = policy_with(&[(Scope::Job, Metric::Usd, 3.5)]);
    assert_eq!(job_budget_micro_usd(&lowered.budget), 3_500_000);
    // A scope that has no ceiling in dollars would give zero, and zero starts nothing.
    let nothing = policy_with(&[(Scope::Job, Metric::Usd, 0.0)]);
    assert_eq!(job_budget_micro_usd(&nothing.budget), 0);
}
