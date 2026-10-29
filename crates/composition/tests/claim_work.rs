//! The step a worker takes before each claim: admit the received jobs and apply the decisions that
//! people asked for. Real: PostgreSQL, the engine, the allowlist file, the policy files, the
//! authority and the hook. Scripted: the stage handlers (the engine suite's) and the approval
//! service, which is replaced by a recording stand-in labelled as such because a pull request
//! approval needs the whole delivery pipeline (the complete run in `apps/worker/tests` uses the
//! real service).

mod support;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use factory_composition::authority::StoreAuthority;
use factory_composition::decision_signing::{DecisionKeys, Signing};
use factory_composition::decisions::{
    APPLIED, AllowlistAuthority, ApprovalSubmitter, AuditMarkers, ClaimWork, ClaimWorkDeps,
    DECISIONS_PER_PASS, DecisionAuthority, DecisionFields, DecisionMarkers, MAX_TRIES, Marked,
    Pending, REJECTED, REQUESTED, Reason, Unreadable,
};
use factory_composition::delivery::StoreApprovalSources;
use factory_composition::seams::FileAllowlist;
use factory_composition::startup::{LoadedPolicies, load_policy};
use factory_composition::system::SystemClock;
use factory_domain::ids::{AuditEventId, CausationId, JobId, PrincipalId, StageRunId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, StageRunStatus};
use factory_domain::values::{Slug, Timestamp};
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, AuditFilter, NewAuditEvent, NewPrincipal, OutboxSeq,
    PrincipalKind, Store,
};
use factory_workflow::engine::Engine;
use factory_workflow::stages::approval::{ApprovalCommand, Outcome, ServiceError, Verb};
use support::engine::PgWorld;
use support::pg_world;

const REQUESTER: u64 = 1001;
const OPERATOR: u64 = 3001;
const APPROVER: u64 = 3002;
const STRANGER: u64 = 3003;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// Records the commands it was given and answers `Applied`. A stand-in for `ApprovalService`.
#[derive(Default)]
struct RecordingSubmitter {
    seen: Mutex<Vec<ApprovalCommand>>,
}

#[async_trait(?Send)]
impl ApprovalSubmitter for RecordingSubmitter {
    async fn submit(&self, command: ApprovalCommand) -> Result<Outcome, ServiceError> {
        let id = command.id;
        self.seen.lock().expect("lock").push(command);
        Ok(Outcome::Applied {
            approval: factory_domain::ids::ApprovalId::from_uuid(id.as_uuid()),
        })
    }
}

/// Fails to write the marker, as a process that stopped right after the engine's commit.
struct StopsBeforeTheMarker;

#[async_trait(?Send)]
impl DecisionMarkers for StopsBeforeTheMarker {
    async fn mark(&self, _: TenantId, _: &Pending, _: &Marked) -> Result<(), Unreadable> {
        Err(Unreadable)
    }
}

/// Says yes to everybody. The broken wiring of the authority check.
struct PermitsEveryone;

#[async_trait(?Send)]
impl DecisionAuthority for PermitsEveryone {
    async fn permits(&self, _: TenantId, _: u64, _: Verb, _: &str) -> Result<bool, Unreadable> {
        Ok(true)
    }
}

/// Can never read the allowlist.
struct Unreadable_;

#[async_trait(?Send)]
impl DecisionAuthority for Unreadable_ {
    async fn permits(&self, _: TenantId, _: u64, _: Verb, _: &str) -> Result<bool, Unreadable> {
        Err(Unreadable)
    }
}

struct Rig {
    _db: support::TestDb,
    world: PgWorld,
    tenant: TenantId,
    checkout: PathBuf,
    policies: LoadedPolicies,
    allowlist: Arc<FileAllowlist>,
    engine: Arc<Engine>,
    submitter: Arc<RecordingSubmitter>,
    operator: PrincipalId,
    approver: PrincipalId,
    stranger: PrincipalId,
    /// The clock the hook reads. A test moves it to age a request.
    clock: Arc<dyn Clock>,
    /// How many decisions a pass deals with for the tenant.
    per_pass: usize,
    /// The keys the API signs with and the hook verifies with (AUT-12).
    keys: Arc<DecisionKeys>,
}

/// The system clock, `ahead` of itself: how a request looks after it has waited.
struct Ahead(Duration);

impl Clock for Ahead {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    fn now(&self) -> Timestamp {
        SystemClock.now().checked_add(self.0).expect("a time")
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.checkout);
    }
}

fn allowlist_text(tenant: TenantId, entries: &[(u64, &str, &str)]) -> String {
    let mut text = String::from("version: 1\nentries:\n");
    for (id, login, designations) in entries {
        text.push_str(&format!(
            "  - tenant: {}\n    github_user_id: {id}\n    login: {login}\n    designations: [{designations}]\n",
            tenant.as_uuid()
        ));
    }
    text
}

impl Rig {
    async fn new() -> Self {
        let (db, world, tenant) = pg_world().await;
        let policies = load_policy(&repository_root(), &[]).expect("the real policies load");
        // Not under the system temporary directory: see the worker README, mismatch 2.
        let checkout = repository_root()
            .join("target/claim-work")
            .join(world.ids.new_uuid().simple().to_string());
        std::fs::create_dir_all(checkout.join("allowlist")).expect("a directory");
        let allowlist = Arc::new(FileAllowlist::in_checkout(&checkout));
        let mut rig = Self {
            _db: db,
            tenant,
            checkout,
            policies,
            allowlist: allowlist.clone(),
            engine: Arc::new(world.restarted_engine()),
            submitter: Arc::new(RecordingSubmitter::default()),
            operator: world.requester,
            approver: world.requester,
            stranger: world.requester,
            clock: world.deps.clock.clone(),
            per_pass: DECISIONS_PER_PASS,
            keys: Arc::new(DecisionKeys::generated().expect("a signing key")),
            world,
        };
        rig.write_allowlist(&[
            (REQUESTER, "requester-one", "requester"),
            (OPERATOR, "operator-one", "operator"),
            (APPROVER, "approver-one", "approver"),
            (STRANGER, "stranger-one", "requester"),
        ]);
        rig.operator = rig.person(OPERATOR, "operator-one").await;
        rig.approver = rig.person(APPROVER, "approver-one").await;
        rig.stranger = rig.person(STRANGER, "stranger-one").await;
        // The engine decides admission and roles from the same file, as a worker does.
        let mut deps = rig.world.deps.clone();
        deps.authority = Arc::new(StoreAuthority::new(
            rig.world.store.clone(),
            allowlist,
            Arc::clone(&rig.policies.engine),
            rig.world.deps.clock.clone(),
        ));
        rig.engine = Arc::new(
            Engine::new(deps, rig.world.config.clone(), rig.world.handlers.clone())
                .expect("the engine starts"),
        );
        rig
    }

    fn write_allowlist(&self, entries: &[(u64, &str, &str)]) {
        std::fs::write(
            self.checkout.join("allowlist/allowlist.yaml"),
            allowlist_text(self.tenant, entries),
        )
        .expect("the allowlist file");
    }

    async fn person(&self, github: u64, login: &str) -> PrincipalId {
        let id = PrincipalId::from_uuid(self.world.ids.new_uuid());
        let mut tx = self
            .world
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        tx.insert_principal(NewPrincipal {
            id,
            kind: PrincipalKind::Human {
                github_user_id: github,
            },
            login: Some(login.to_owned()),
        })
        .await
        .expect("a principal");
        tx.commit().await.expect("commit");
        id
    }

    fn hook_with(
        &self,
        authority: Arc<dyn DecisionAuthority>,
        markers: Arc<dyn DecisionMarkers>,
    ) -> ClaimWork {
        ClaimWork::new(ClaimWorkDeps {
            engine: Arc::clone(&self.engine),
            store: self.world.store.clone(),
            tenants: vec![self.tenant],
            submitter: self.submitter.clone(),
            approvals: Arc::new(StoreApprovalSources::new(
                self.world.store.clone(),
                self.world.deps.artifacts.clone(),
                self.allowlist.clone(),
            )),
            authority,
            markers,
            clock: self.clock.clone(),
            max_age: Duration::from_secs(72 * 3600),
            per_pass: self.per_pass,
            keys: self.keys.clone(),
        })
    }

    fn real_authority(&self) -> Arc<dyn DecisionAuthority> {
        Arc::new(AllowlistAuthority::new(
            self.allowlist.clone(),
            Arc::clone(&self.policies.approval),
            self.world.deps.clock.clone(),
        ))
    }

    fn real_markers(&self) -> Arc<dyn DecisionMarkers> {
        Arc::new(AuditMarkers::new(
            self.world.store.clone(),
            self.policies.hash.clone(),
            self.keys.clone(),
        ))
    }

    /// A hook as the worker builds it.
    fn hook(&self) -> ClaimWork {
        self.hook_with(self.real_authority(), self.real_markers())
    }

    /// A received job, as the API leaves it.
    async fn received(&self) -> JobId {
        self.engine
            .receive_job(self.tenant, self.world.requester, self.world.repository)
            .await
            .expect("received")
    }

    /// A job that the hook admitted.
    async fn active(&self) -> JobId {
        let job = self.received().await;
        self.hook().pass(self.tenant).await;
        assert_eq!(self.status(job).await, JobStatus::Active);
        job
    }

    async fn status(&self, job: JobId) -> JobStatus {
        self.engine
            .job_status(self.tenant, job)
            .await
            .expect("a status")
    }

    /// Writes the record that `POST /v1/jobs/{id}/decisions` writes.
    async fn request(
        &self,
        by: PrincipalId,
        job: JobId,
        verb: Verb,
        stage_run: Option<StageRunId>,
        target: Option<&str>,
        reason: &str,
    ) -> AuditEventId {
        let id = AuditEventId::from_uuid(self.world.ids.new_uuid());
        let fields = DecisionFields {
            verb,
            job,
            stage_run,
            head: None,
            evidence: None,
            target: target.map(str::to_owned),
        };
        let mut tx = self
            .world
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let correlation = tx.get_job(job).await.expect("a job").value.correlation_id;
        tx.record_audit(NewAuditEvent {
            id,
            actor: AuditActor::Human(by),
            action: AuditAction::new(REQUESTED).expect("an action"),
            subject: self.signed(id, by, &fields),
            decision: AuditDecision::Record,
            reason: format!("requested: {reason}"),
            policy_hash: self.policies.hash.clone(),
            job: Some(job),
            stage_run,
            correlation_id: correlation,
        })
        .await
        .expect("the request is recorded");
        tx.commit().await.expect("commit");
        id
    }

    /// The actions of the audit records of a job, in order, that this module writes or reads.
    async fn trail(&self, job: JobId) -> Vec<String> {
        let mut tx = self
            .world
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let records = tx
            .read_audit(AuditFilter::Job(job), 0, 500)
            .await
            .expect("audit");
        let _ = tx.rollback().await;
        records
            .into_iter()
            .map(|record| record.event.action.as_str().to_owned())
            .filter(|action| action.starts_with("decision."))
            .collect()
    }

    async fn reason_of(&self, job: JobId, action: &str) -> Option<String> {
        let mut tx = self
            .world
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let records = tx
            .read_audit(AuditFilter::Job(job), 0, 500)
            .await
            .expect("audit");
        let _ = tx.rollback().await;
        records
            .into_iter()
            .find(|record| record.event.action.as_str() == action)
            .map(|record| record.event.reason)
    }

    /// How many events of the job the engine wrote because of this command.
    async fn effects_of(&self, job: JobId, decision: AuditEventId) -> usize {
        let mut tx = self
            .world
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let events = tx
            .read_events(job, OutboxSeq::START, 1000)
            .await
            .expect("events");
        let _ = tx.rollback().await;
        let command = CausationId::from_uuid(decision.as_uuid());
        events
            .iter()
            .filter(|row| row.event.causation_id == Some(command))
            .count()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_received_job_is_admitted_by_a_pass() {
    let rig = Rig::new().await;
    let job = rig.received().await;
    assert_eq!(rig.status(job).await, JobStatus::Received);
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Active);
    let view = rig.engine.job_view(rig.tenant, job).await.expect("a view");
    assert!(!view.stage_runs.is_empty(), "the stage runs were made");
    assert!(
        view.stage_runs
            .iter()
            .any(|run| run.status == StageRunStatus::Ready),
        "the first stage is ready: {view:#?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_pass_does_not_admit_again() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let before = rig.engine.job_view(rig.tenant, job).await.expect("a view");
    rig.hook().pass(rig.tenant).await;
    rig.hook().pass(rig.tenant).await;
    let after = rig.engine.job_view(rig.tenant, job).await.expect("a view");
    assert_eq!(before, after);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_requester_who_left_the_allowlist_is_not_admitted_and_the_job_is_rejected() {
    let rig = Rig::new().await;
    rig.write_allowlist(&[(OPERATOR, "operator-one", "operator")]);
    let job = rig.received().await;
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Rejected);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pause_and_a_resume_are_each_applied_once_and_marked() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let hook = rig.hook();

    let pause = rig
        .request(rig.operator, job, Verb::Pause, None, None, "a short stop")
        .await;
    hook.pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Paused);
    assert_eq!(rig.trail(job).await, [REQUESTED, APPLIED]);
    assert_eq!(rig.effects_of(job, pause).await, 1);

    // Another pass, and a worker that starts from nothing, change nothing.
    hook.pass(rig.tenant).await;
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Paused);
    assert_eq!(rig.trail(job).await, [REQUESTED, APPLIED]);
    assert_eq!(rig.effects_of(job, pause).await, 1);

    let resume = rig
        .request(rig.operator, job, Verb::Resume, None, None, "go on")
        .await;
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Active);
    assert_eq!(
        rig.trail(job).await,
        [REQUESTED, APPLIED, REQUESTED, APPLIED]
    );
    assert_eq!(rig.effects_of(job, resume).await, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_is_applied_and_the_marker_says_so() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    rig.request(rig.operator, job, Verb::Cancel, None, None, "not needed")
        .await;
    rig.hook().pass(rig.tenant).await;
    assert!(
        matches!(
            rig.status(job).await,
            JobStatus::Cancelling | JobStatus::Cancelled
        ),
        "{:?}",
        rig.status(job).await
    );
    assert_eq!(rig.trail(job).await, [REQUESTED, APPLIED]);
    assert_eq!(
        rig.reason_of(job, APPLIED).await.as_deref(),
        Some("The job was cancelled.")
    );
}

/// The kill test. A worker stops after the engine committed the pause and before it wrote the
/// marker: the first hook's marker never lands. A second worker, with no memory, finds a request
/// with no marker, asks the engine whether it applied that command, writes the marker, and does
/// nothing to the job.
#[tokio::test(flavor = "multi_thread")]
async fn a_stop_between_the_engine_commit_and_the_marker_neither_applies_twice_nor_loses_it() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let pause = rig
        .request(rig.operator, job, Verb::Pause, None, None, "a short stop")
        .await;

    // First worker: applies, then "dies" before the marker.
    rig.hook_with(rig.real_authority(), Arc::new(StopsBeforeTheMarker))
        .pass(rig.tenant)
        .await;
    assert_eq!(rig.status(job).await, JobStatus::Paused, "it was applied");
    assert_eq!(rig.trail(job).await, [REQUESTED], "and left no marker");
    assert_eq!(rig.effects_of(job, pause).await, 1);

    // Second worker: no memory of the first.
    let survivor = rig.hook();
    survivor.pass(rig.tenant).await;
    survivor.pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Paused);
    assert_eq!(
        rig.trail(job).await,
        [REQUESTED, APPLIED],
        "one marker, and it says applied, not rejected"
    );
    assert_eq!(
        rig.effects_of(job, pause).await,
        1,
        "the engine did the work once"
    );
}

/// The same stop for a decision whose effect ends the job: the marker must still say "applied",
/// although the job is now terminal and every check of the world as it is would refuse.
#[tokio::test(flavor = "multi_thread")]
async fn a_stop_after_a_cancel_that_ended_the_job_still_ends_with_an_applied_marker() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let cancel = rig
        .request(rig.operator, job, Verb::Cancel, None, None, "not needed")
        .await;
    rig.hook_with(rig.real_authority(), Arc::new(StopsBeforeTheMarker))
        .pass(rig.tenant)
        .await;
    assert_eq!(rig.trail(job).await, [REQUESTED]);
    let effects = rig.effects_of(job, cancel).await;
    assert!(effects >= 1);
    // The cancellation completes by itself over the next engine calls; whatever state the job is
    // in, the fresh worker must not reject the decision for it.
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.trail(job).await, [REQUESTED, APPLIED]);
    assert_eq!(rig.effects_of(job, cancel).await, effects);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_person_who_left_the_allowlist_since_the_api_checked_is_refused_and_nothing_moves() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    rig.request(rig.operator, job, Verb::Pause, None, None, "a short stop")
        .await;
    // The API let the request in. Before the worker reads it, the person is removed.
    rig.write_allowlist(&[(REQUESTER, "requester-one", "requester")]);
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Active, "nothing moved");
    assert_eq!(rig.trail(job).await, [REQUESTED, REJECTED]);
    let reason = rig.reason_of(job, REJECTED).await.expect("a reason");
    assert_eq!(reason, "The person may not take this decision now.");
}

/// API-1 at apply time (R-14, R-4): the narrowing of an allowlist entry is read when the worker
/// applies the decision, not when the API recorded it. An operator who was narrowed to some other
/// repository after the request was made is refused, and nothing moves. The same entry narrowed to
/// the job's own repository (spelled in another case) still works.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_narrowed_to_another_repository_since_the_request_is_refused_at_apply_time() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    rig.request(rig.operator, job, Verb::Pause, None, None, "a short stop")
        .await;
    // Narrowed, after the API let the request in, to a repository that is not the job's.
    std::fs::write(
        rig.checkout.join("allowlist/allowlist.yaml"),
        format!(
            "{}    repositories: [\"org/somewhere-else\"]\n",
            allowlist_text(rig.tenant, &[(OPERATOR, "operator-one", "operator")])
        ),
    )
    .expect("narrowed");
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Active, "nothing moved");
    assert_eq!(rig.trail(job).await, [REQUESTED, REJECTED]);
    assert_eq!(
        rig.reason_of(job, REJECTED).await.as_deref(),
        Some("The person may not take this decision now."),
        "the same plain words as any other refusal of authority"
    );

    // Narrowed to the job's own repository, in capitals: the same request, asked again, is applied.
    std::fs::write(
        rig.checkout.join("allowlist/allowlist.yaml"),
        format!(
            "{}    repositories: [\"ORG/REPO-0\"]\n",
            allowlist_text(rig.tenant, &[(OPERATOR, "operator-one", "operator")])
        ),
    )
    .expect("narrowed to this repository");
    rig.request(rig.operator, job, Verb::Pause, None, None, "again")
        .await;
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Paused);
}

/// The approver's side of the same defect: an approver narrowed to another repository never reaches
/// the approval service.
#[tokio::test(flavor = "multi_thread")]
async fn an_approver_narrowed_to_another_repository_never_reaches_the_service() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let view = rig.engine.job_view(rig.tenant, job).await.expect("a view");
    rig.write_allowlist(&[(REQUESTER, "requester-one", "requester")]);
    std::fs::write(
        rig.checkout.join("allowlist/allowlist.yaml"),
        format!(
            "{}{}    repositories: [\"org/somewhere-else\"]\n",
            allowlist_text(rig.tenant, &[(REQUESTER, "requester-one", "requester")]),
            allowlist_text(rig.tenant, &[(APPROVER, "approver-one", "approver")]).replacen(
                "version: 1\nentries:\n",
                "",
                1
            ),
        ),
    )
    .expect("narrowed");
    rig.request(
        rig.approver,
        job,
        Verb::Reject,
        Some(view.stage_runs[0].id),
        None,
        "not for this repository",
    )
    .await;
    rig.hook().pass(rig.tenant).await;
    assert!(
        rig.submitter.seen.lock().expect("lock").is_empty(),
        "a narrowed approver reached the approval service"
    );
    assert_eq!(rig.trail(job).await, [REQUESTED, REJECTED]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_person_who_never_held_the_designation_is_refused() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    // A requester asks for a pause, which needs an operator. A record like this means the API's
    // check was bypassed or wrong.
    rig.request(rig.stranger, job, Verb::Pause, None, None, "let me")
        .await;
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Active);
    assert_eq!(rig.trail(job).await, [REQUESTED, REJECTED]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_for_a_job_that_has_ended_is_refused_with_a_plain_reason() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    // The job ends by a cancellation that completes: pause it first so no attempt is live.
    rig.request(rig.operator, job, Verb::Cancel, None, None, "done with it")
        .await;
    rig.hook().pass(rig.tenant).await;
    // Let the cancellation finish (the engine finishes it over its next calls).
    for _ in 0..5 {
        let _ = rig.engine.sweep().await;
        if rig.status(job).await == JobStatus::Cancelled {
            break;
        }
    }
    assert_eq!(rig.status(job).await, JobStatus::Cancelled);
    rig.request(rig.operator, job, Verb::Pause, None, None, "too late")
        .await;
    rig.hook().pass(rig.tenant).await;
    assert_eq!(
        rig.trail(job).await,
        [REQUESTED, APPLIED, REQUESTED, REJECTED]
    );
    assert_eq!(
        rig.reason_of(job, REJECTED).await.as_deref(),
        Some("The job has ended.")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreadable_allowlist_makes_the_decision_wait_and_then_it_is_rejected_by_the_cap() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    rig.request(rig.operator, job, Verb::Pause, None, None, "a short stop")
        .await;
    let hook = rig.hook_with(Arc::new(Unreadable_), rig.real_markers());
    for _ in 0..(MAX_TRIES - 1) {
        hook.pass(rig.tenant).await;
        assert_eq!(rig.trail(job).await, [REQUESTED], "it waits");
        assert_eq!(rig.status(job).await, JobStatus::Active);
    }
    hook.pass(rig.tenant).await;
    assert_eq!(rig.trail(job).await, [REQUESTED, REJECTED]);
    assert_eq!(rig.status(job).await, JobStatus::Active, "nothing moved");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejection_and_a_rework_reach_the_approval_service_with_the_right_command() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let run = StageRunId::from_uuid(rig.world.ids.new_uuid());
    // The stage run must exist for the audit record to name it; the stand-in service does not read
    // it, so the record names the job's first stage run.
    let view = rig.engine.job_view(rig.tenant, job).await.expect("a view");
    let first = view.stage_runs[0].id;
    let _ = run;
    let reject = rig
        .request(
            rig.approver,
            job,
            Verb::Reject,
            Some(first),
            None,
            "this is not what I asked for",
        )
        .await;
    let rework = rig
        .request(
            rig.approver,
            job,
            Verb::Rework,
            Some(first),
            Some("ARCHITECTURE"),
            "the design misses the error cases",
        )
        .await;
    rig.hook().pass(rig.tenant).await;
    assert_eq!(
        rig.trail(job).await,
        [REQUESTED, REQUESTED, APPLIED, APPLIED]
    );
    let seen = rig.submitter.seen.lock().expect("lock");
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].id, CausationId::from_uuid(reject.as_uuid()));
    assert_eq!(seen[0].verb, Verb::Reject);
    assert_eq!(
        seen[0].sender.id, APPROVER,
        "the sender is found by numeric id"
    );
    assert_eq!(seen[0].reason, "this is not what I asked for");
    assert_eq!(seen[0].tenant, rig.tenant);
    assert_eq!(seen[0].job, job);
    assert_eq!(seen[0].stage_run, first);
    assert_eq!(seen[1].id, CausationId::from_uuid(rework.as_uuid()));
    assert_eq!(seen[1].verb, Verb::Rework);
    assert_eq!(
        seen[1].rework_target,
        Some(factory_domain::vocabulary::StageKind::Architecture)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_rejection_by_someone_who_is_not_an_approver_never_reaches_the_service() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let view = rig.engine.job_view(rig.tenant, job).await.expect("a view");
    rig.request(
        rig.operator,
        job,
        Verb::Reject,
        Some(view.stage_runs[0].id),
        None,
        "an operator is not an approver",
    )
    .await;
    rig.hook().pass(rig.tenant).await;
    assert!(rig.submitter.seen.lock().expect("lock").is_empty());
    assert_eq!(rig.trail(job).await, [REQUESTED, REJECTED]);
}

// ===== The requirements of the review (R-1 to R-17), proved on PostgreSQL ============================
//
// `docs/reviews/api-security-review.md`, section 8, lists what the hook must do with a record it did
// not write. The tests below are the ones that are not in the older part of this file.

impl Rig {
    /// Writes any `decision.requested` record, as a login of the application group could: the actor,
    /// the subject and the columns are the caller's to choose. Returns its id.
    async fn raw_request(
        &self,
        actor: AuditActor,
        subject: &str,
        job: Option<JobId>,
        stage_run: Option<StageRunId>,
        reason: &str,
    ) -> AuditEventId {
        let id = AuditEventId::from_uuid(self.world.ids.new_uuid());
        self.write_request(id, actor, subject, job, stage_run, reason)
            .await;
        id
    }

    /// The subject the API writes for `fields`, with the word that only the API can make, for this
    /// event and this person.
    fn signed(&self, id: AuditEventId, by: PrincipalId, fields: &DecisionFields) -> String {
        self.keys.signed_subject(&Signing {
            tenant: self.tenant,
            actor: by,
            event: id,
            requested_at: "2026-10-28T12:00:00Z",
            fields,
        })
    }

    /// Writes a record with a correct word, as the API would, but with the columns the caller
    /// chooses (they may disagree with the subject).
    async fn raw_signed(
        &self,
        by: PrincipalId,
        fields: &DecisionFields,
        job: Option<JobId>,
        stage_run: Option<StageRunId>,
        reason: &str,
    ) -> AuditEventId {
        let id = AuditEventId::from_uuid(self.world.ids.new_uuid());
        let subject = self.signed(id, by, fields);
        self.write_request(id, AuditActor::Human(by), &subject, job, stage_run, reason)
            .await;
        id
    }

    async fn write_request(
        &self,
        id: AuditEventId,
        actor: AuditActor,
        subject: &str,
        job: Option<JobId>,
        stage_run: Option<StageRunId>,
        reason: &str,
    ) {
        let mut tx = self
            .world
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        tx.record_audit(NewAuditEvent {
            id,
            actor,
            action: AuditAction::new(REQUESTED).expect("an action"),
            subject: subject.to_owned(),
            decision: AuditDecision::Record,
            reason: reason.to_owned(),
            policy_hash: self.policies.hash.clone(),
            job,
            stage_run,
            correlation_id: factory_domain::ids::CorrelationId::from_uuid(
                self.world.ids.new_uuid(),
            ),
        })
        .await
        .expect("the record is written");
        tx.commit().await.expect("commit");
    }

    /// Every audit record of the tenant that the hook writes, as `(action, subject, reason)`.
    async fn markers(&self) -> Vec<(String, String, String)> {
        let mut tx = self
            .world
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let records = tx
            .read_audit(AuditFilter::Tenant, 0, 1000)
            .await
            .expect("audit");
        let _ = tx.rollback().await;
        records
            .into_iter()
            .filter(|record| matches!(record.event.action.as_str(), APPLIED | REJECTED))
            .map(|record| {
                (
                    record.event.action.as_str().to_owned(),
                    record.event.subject,
                    record.event.reason,
                )
            })
            .collect()
    }
}

/// R-2. The record is untrusted input. A subject that reads like a decision but is not byte for byte
/// the text the API writes is not a decision: it is rejected with a marker, so that it stops being a
/// candidate, and nothing moves.
#[tokio::test(flavor = "multi_thread")]
async fn r2_a_subject_that_is_not_the_canonical_text_is_rejected_and_nothing_moves() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let human = AuditActor::Human(rig.operator);
    let cancel = DecisionFields {
        verb: Verb::Cancel,
        job,
        stage_run: None,
        head: None,
        evidence: None,
        target: None,
    };
    let canonical = cancel.subject();
    let id = job.as_text();
    let shapes = [
        // Same words, another order.
        format!("job={id} verb=cancel run=none head=none evidence=none target=none"),
        // White space that the lenient reader ignores.
        canonical.replace(' ', "  "),
        format!("{canonical} "),
        format!(" {canonical}"),
        // A key twice: the lenient reader keeps the last.
        format!("verb=pause {canonical}"),
        // Another case.
        canonical.replace("verb=cancel", "verb=CANCEL"),
        // An extra word.
        format!("{canonical} extra=1"),
        // Not a decision at all.
        "this is not the grammar of a decision".to_owned(),
    ];
    for subject in &shapes {
        rig.raw_request(
            human.clone(),
            subject,
            Some(job),
            None,
            "requested: not needed",
        )
        .await;
    }
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Active, "nothing moved");
    let markers = rig.markers().await;
    assert_eq!(
        markers.len(),
        shapes.len(),
        "one marker for each: {markers:#?}"
    );
    for (action, subject, reason) in &markers {
        assert_eq!(action, REJECTED);
        assert_eq!(reason, Reason::Malformed.text());
        assert!(subject.contains("code=malformed"), "{subject}");
    }
    // The records are no longer candidates: a worker that starts from nothing writes no more markers.
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.markers().await.len(), shapes.len());
    // And the same words in the canonical order, from the same actor, with the API's word, are a
    // decision.
    rig.raw_signed(
        rig.operator,
        &cancel,
        Some(job),
        None,
        "requested: not needed",
    )
    .await;
    rig.hook().pass(rig.tenant).await;
    assert!(matches!(
        rig.status(job).await,
        JobStatus::Cancelling | JobStatus::Cancelled
    ));
}

/// R-2. The columns must say what the subject says, and the actor must be a human principal.
#[tokio::test(flavor = "multi_thread")]
async fn r2_the_columns_and_the_actor_must_agree_with_the_subject() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let other = rig.active().await;
    let run = rig
        .engine
        .job_view(rig.tenant, job)
        .await
        .expect("a view")
        .stage_runs[0]
        .id;
    let fields_for = |job: JobId, stage_run: Option<StageRunId>| DecisionFields {
        verb: Verb::Pause,
        job,
        stage_run,
        head: None,
        evidence: None,
        target: None,
    };
    // The subject names one job and the column another. Each record carries the API's word, so the
    // columns are what is wrong with it.
    rig.raw_signed(
        rig.operator,
        &fields_for(job, None),
        Some(other),
        None,
        "requested: x",
    )
    .await;
    // The subject names a job and the column names none.
    rig.raw_signed(
        rig.operator,
        &fields_for(job, None),
        None,
        None,
        "requested: x",
    )
    .await;
    // The subject names a stage run and the column names none.
    rig.raw_signed(
        rig.operator,
        &fields_for(job, Some(run)),
        Some(job),
        None,
        "requested: x",
    )
    .await;
    // A service, not a person, asks.
    rig.raw_request(
        AuditActor::System(Slug::parse("api-bot").expect("a slug")),
        &fields_for(job, None).subject(),
        Some(job),
        None,
        "requested: x",
    )
    .await;
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Active);
    assert_eq!(rig.status(other).await, JobStatus::Active);
    let markers = rig.markers().await;
    assert_eq!(markers.len(), 4, "{markers:#?}");
    assert!(
        markers
            .iter()
            .all(|(action, _, reason)| action == REJECTED && reason == Reason::Malformed.text())
    );
}

fn fields_of(verb: Verb, job: JobId) -> DecisionFields {
    DecisionFields {
        verb,
        job,
        stage_run: None,
        head: None,
        evidence: None,
        target: None,
    }
}

/// AUT-12 (R-1). A row that any login of the application group could write is not a decision unless
/// it carries the word only the API can make. Six forgeries, each with a different flaw, all
/// rejected with the one fixed code, and nothing moves: no word; a word made with another key; a
/// word over another job; a word over another verb; a word over another person; and a genuine
/// subject copied onto a new event id.
#[tokio::test(flavor = "multi_thread")]
async fn aut_12_a_forged_row_is_rejected_with_a_fixed_code_and_nothing_moves() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let other = rig.active().await;
    let operator = || AuditActor::Human(rig.operator);
    let new_id = || AuditEventId::from_uuid(rig.world.ids.new_uuid());
    let cancel = fields_of(Verb::Cancel, job);

    // 1. No word at all: the canonical text of the grammar, as the API wrote it before the word.
    rig.raw_request(
        operator(),
        &cancel.subject(),
        Some(job),
        None,
        "requested: x",
    )
    .await;
    // 2. A word made with a key the API does not hold.
    let stranger_key = DecisionKeys::generated().expect("a key");
    let id = new_id();
    let subject = stranger_key.signed_subject(&Signing {
        tenant: rig.tenant,
        actor: rig.operator,
        event: id,
        requested_at: "2026-10-28T12:00:00Z",
        fields: &cancel,
    });
    rig.write_request(id, operator(), &subject, Some(job), None, "requested: x")
        .await;
    // 3. A genuine word for a cancel of another job, on a subject that names this one.
    let id = new_id();
    let genuine = rig.signed(id, rig.operator, &fields_of(Verb::Cancel, other));
    let forged = genuine.replace(&other.as_text(), &job.as_text());
    assert_ne!(forged, genuine);
    rig.write_request(id, operator(), &forged, Some(job), None, "requested: x")
        .await;
    // 4. A genuine word for a pause, on a subject that says cancel.
    let id = new_id();
    let genuine = rig.signed(id, rig.operator, &fields_of(Verb::Pause, job));
    let forged = genuine.replace("verb=pause", "verb=cancel");
    assert_ne!(forged, genuine);
    rig.write_request(id, operator(), &forged, Some(job), None, "requested: x")
        .await;
    // 5. A genuine word made for the operator, on a row that names the approver as its actor.
    let id = new_id();
    let genuine = rig.signed(id, rig.operator, &cancel);
    rig.write_request(
        id,
        AuditActor::Human(rig.approver),
        &genuine,
        Some(job),
        None,
        "requested: x",
    )
    .await;
    // 6. A replay: a subject that was genuine for one event id, written under another.
    let genuine = rig.signed(new_id(), rig.operator, &cancel);
    rig.write_request(
        new_id(),
        operator(),
        &genuine,
        Some(job),
        None,
        "requested: x",
    )
    .await;

    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Active, "nothing moved");
    assert_eq!(rig.status(other).await, JobStatus::Active);
    let markers = rig.markers().await;
    assert_eq!(markers.len(), 6, "one marker for each: {markers:#?}");
    for (action, subject, reason) in &markers {
        assert_eq!(action, REJECTED);
        assert_eq!(reason, Reason::NotSigned.text());
        assert!(subject.contains("code=not_signed"), "{subject}");
        // The marker holds nothing from the record: not its verb, not the job, not the person.
        assert!(subject.contains("actor=none"), "{subject}");
        assert!(!subject.contains(&job.as_text()), "{subject}");
    }
    // They are no longer candidates, and a genuine request on top of them is applied.
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.markers().await.len(), 6);
    rig.request(rig.operator, job, Verb::Cancel, None, None, "a real one")
        .await;
    rig.hook().pass(rig.tenant).await;
    assert!(matches!(
        rig.status(job).await,
        JobStatus::Cancelling | JobStatus::Cancelled
    ));
}

/// AUT-12. A row that is replayed with its own event id is the same row and applies once, as before.
#[tokio::test(flavor = "multi_thread")]
async fn aut_12_a_genuine_request_still_applies_exactly_once() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let id = rig
        .request(rig.operator, job, Verb::Pause, None, None, "a short stop")
        .await;
    rig.hook().pass(rig.tenant).await;
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Paused);
    assert_eq!(rig.effects_of(job, id).await, 1);
    assert_eq!(rig.trail(job).await, [REQUESTED, APPLIED]);
}

/// AUT-12. During a rotation the hook accepts a word made with the previous key and with the
/// current one, and one made with a key older than both is rejected with the fixed code.
#[tokio::test(flavor = "multi_thread")]
async fn aut_12_a_rotation_accepts_the_previous_key_and_nothing_older() {
    let mut rig = Rig::new().await;
    let (a, b, c) = (rig.active().await, rig.active().await, rig.active().await);
    rig.keys = Arc::new(DecisionKeys::fixed_for_tests(&[1; 48], None).expect("a key"));
    rig.request(rig.operator, a, Verb::Pause, None, None, "signed before")
        .await;
    // The rotation: the API now signs with the second key; the hook holds both.
    rig.keys = Arc::new(DecisionKeys::fixed_for_tests(&[2; 48], Some(&[1; 48])).expect("keys"));
    rig.request(rig.operator, b, Verb::Pause, None, None, "signed after")
        .await;
    // A third key, which neither side holds.
    let hook_keys = rig.keys.clone();
    rig.keys = Arc::new(DecisionKeys::fixed_for_tests(&[3; 48], None).expect("a key"));
    rig.request(
        rig.operator,
        c,
        Verb::Pause,
        None,
        None,
        "signed with an old key",
    )
    .await;
    rig.keys = hook_keys;
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(a).await, JobStatus::Paused);
    assert_eq!(rig.status(b).await, JobStatus::Paused);
    assert_eq!(rig.status(c).await, JobStatus::Active);
    let markers = rig.markers().await;
    let rejected: Vec<_> = markers
        .iter()
        .filter(|(action, _, _)| action == REJECTED)
        .collect();
    assert_eq!(rejected.len(), 1, "{markers:#?}");
    assert!(rejected[0].1.contains("code=not_signed"), "{rejected:?}");
}

/// R-3. A request that names a job of another tenant finds nothing in its own: it is rejected with a
/// marker (not skipped), and the other tenant's job does not move.
#[tokio::test(flavor = "multi_thread")]
async fn r3_a_request_for_a_job_of_another_tenant_is_rejected_and_that_job_does_not_move() {
    let rig = Rig::new().await;
    let other_tenant = TenantId::from_uuid(rig.world.ids.new_uuid());
    let (repository, principal, job) = (
        rig.world.ids.new_uuid(),
        rig.world.ids.new_uuid(),
        rig.world.ids.new_uuid(),
    );
    rig._db
        .run(&format!(
            "INSERT INTO tenants (id, slug, display_name) VALUES ('{t}', 'tenant-b-{s}', 'B'); \
             INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch) \
               VALUES ('{t}', '{repository}', 7001, 7002, 'other/repo', 'main'); \
             INSERT INTO principals (tenant_id, id, kind, github_user_id, login) VALUES ('{t}', '{principal}', 'human', 7003, 'other-person'); \
             INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level, pipeline_scope, correlation_id) \
               VALUES ('{t}', '{job}', '{repository}', '{principal}', 'test', 'L1', ARRAY['INTAKE'], '{c}')",
            t = other_tenant.as_uuid(),
            s = &job.simple().to_string()[..8],
            c = rig.world.ids.new_uuid(),
        ))
        .await;
    let foreign = JobId::from_uuid(job);
    let ours = rig.active().await;
    let fields = DecisionFields {
        verb: Verb::Cancel,
        job: foreign,
        stage_run: None,
        head: None,
        evidence: None,
        target: None,
    };
    // The record lives in our tenant; it can name the job only in its text, because the column is a
    // foreign key into our own jobs. It carries the API's word, so it is the job that is wrong.
    rig.raw_signed(rig.operator, &fields, None, None, "requested: x")
        .await;
    rig.hook().pass(rig.tenant).await;
    let markers = rig.markers().await;
    assert_eq!(markers.len(), 1, "{markers:#?}");
    assert_eq!(markers[0].0, REJECTED);
    let status = rig
        ._db
        .text(&format!("SELECT status FROM jobs WHERE id = '{job}'"))
        .await;
    assert_eq!(
        status.as_deref(),
        Some("RECEIVED"),
        "the other tenant's job did not move"
    );
    assert_eq!(rig.status(ours).await, JobStatus::Active);
}

/// R-4. The person is resolved to a principal now, and a disabled one is not a current user.
#[tokio::test(flavor = "multi_thread")]
async fn r4_a_principal_disabled_since_the_request_is_not_a_current_user() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    rig.request(rig.operator, job, Verb::Pause, None, None, "a short stop")
        .await;
    rig._db
        .run(&format!(
            "UPDATE principals SET disabled_at = now() WHERE id = '{}'",
            rig.operator.as_uuid()
        ))
        .await;
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Active);
    assert_eq!(
        rig.reason_of(job, REJECTED).await.as_deref(),
        Some(Reason::NotCurrentUser.text())
    );
}

/// R-4. An allowlist entry that has an end date stops granting authority at it, also for a request
/// that was recorded before.
#[tokio::test(flavor = "multi_thread")]
async fn r4_an_entry_that_expired_since_the_request_is_refused() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    rig.request(rig.operator, job, Verb::Pause, None, None, "a short stop")
        .await;
    std::fs::write(
        rig.checkout.join("allowlist/allowlist.yaml"),
        format!(
            "{}    expires_at: \"2020-01-01T00:00:00Z\"\n",
            allowlist_text(rig.tenant, &[(OPERATOR, "operator-one", "operator")])
        ),
    )
    .expect("an expired entry");
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Active);
    assert_eq!(
        rig.reason_of(job, REJECTED).await.as_deref(),
        Some(Reason::NotAuthorized.text())
    );
}

/// R-10. Two requests for the same thing are two requests, applied in the order of the audit
/// sequence: the first pauses, the second finds the job paused and is rejected, with a marker.
#[tokio::test(flavor = "multi_thread")]
async fn r10_two_requests_for_the_same_pause_are_two_requests_in_order() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let first = rig
        .request(rig.operator, job, Verb::Pause, None, None, "once")
        .await;
    let second = rig
        .request(rig.operator, job, Verb::Pause, None, None, "twice")
        .await;
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Paused);
    assert_eq!(
        rig.trail(job).await,
        [REQUESTED, REQUESTED, APPLIED, REJECTED]
    );
    assert_eq!(rig.effects_of(job, first).await, 1);
    assert_eq!(rig.effects_of(job, second).await, 0);
}

/// R-9. Two hooks that take the same request at the same moment (two workers) apply it once and write
/// one marker, and the marker says it was applied, not that it was out of place.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r9_two_hooks_racing_for_one_request_apply_it_once() {
    let rig = Rig::new().await;
    for round in 0..8 {
        let job = rig.active().await;
        let pause = rig
            .request(rig.operator, job, Verb::Pause, None, None, "a short stop")
            .await;
        let (a, b) = (rig.hook(), rig.hook());
        tokio::join!(a.pass(rig.tenant), b.pass(rig.tenant));
        // A request that one hook gave up on for this pass is picked up on the next.
        a.pass(rig.tenant).await;
        b.pass(rig.tenant).await;
        assert_eq!(rig.status(job).await, JobStatus::Paused, "round {round}");
        assert_eq!(
            rig.effects_of(job, pause).await,
            1,
            "round {round}: the engine did the work once"
        );
        assert_eq!(
            rig.trail(job).await,
            [REQUESTED, APPLIED],
            "round {round}: one marker, and it says applied"
        );
    }
}

/// R-11. A request that waited longer than the approval window is rejected as expired and never
/// applied late. One that was applied in time and found without its marker after the window is still
/// an applied request: the check for "already applied" comes before the check of age.
#[tokio::test(flavor = "multi_thread")]
async fn r11_an_old_request_is_rejected_as_expired_but_an_applied_one_stays_applied() {
    let mut rig = Rig::new().await;
    let job = rig.active().await;
    let pause = rig
        .request(rig.operator, job, Verb::Pause, None, None, "a short stop")
        .await;
    rig.clock = Arc::new(Ahead(Duration::from_secs(73 * 3600)));
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.status(job).await, JobStatus::Active, "not applied late");
    assert_eq!(rig.trail(job).await, [REQUESTED, REJECTED]);
    assert_eq!(
        rig.reason_of(job, REJECTED).await.as_deref(),
        Some(Reason::Expired.text())
    );
    assert_eq!(rig.effects_of(job, pause).await, 0);

    // Applied in time, the marker lost, found a week later.
    rig.clock = Arc::new(SystemClock);
    let second = rig.active().await;
    let cancel = rig
        .request(rig.operator, second, Verb::Pause, None, None, "again")
        .await;
    rig.hook_with(rig.real_authority(), Arc::new(StopsBeforeTheMarker))
        .pass(rig.tenant)
        .await;
    assert_eq!(rig.status(second).await, JobStatus::Paused);
    rig.clock = Arc::new(Ahead(Duration::from_secs(24 * 7 * 3600)));
    rig.hook().pass(rig.tenant).await;
    assert_eq!(rig.trail(second).await, [REQUESTED, APPLIED]);
    assert_eq!(rig.effects_of(second, cancel).await, 1);
}

/// R-12. One pass deals with a bounded number of requests; the rest wait for the next. No request is
/// lost and none is dealt with twice.
#[tokio::test(flavor = "multi_thread")]
async fn r12_a_pass_deals_with_a_bounded_number_and_the_rest_wait() {
    let mut rig = Rig::new().await;
    rig.per_pass = 3;
    let job = rig.active().await;
    for n in 0..7 {
        rig.request(
            rig.operator,
            job,
            Verb::Pause,
            None,
            None,
            &format!("stop {n}"),
        )
        .await;
    }
    let hook = rig.hook();
    for expected in [3, 6, 7] {
        hook.pass(rig.tenant).await;
        assert_eq!(rig.markers().await.len(), expected);
    }
    hook.pass(rig.tenant).await;
    assert_eq!(rig.markers().await.len(), 7, "nothing is done twice");
    assert_eq!(rig.status(job).await, JobStatus::Paused);
}

/// R-13. The marker of every outcome names the request, a fixed code, the numeric id of the person
/// and the version of the allowlist, and nothing the person wrote. The person is told the same plain
/// words whatever failed.
#[tokio::test(flavor = "multi_thread")]
async fn r13_a_marker_has_a_code_the_numeric_id_and_the_allowlist_version_and_no_request_text() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let canary = "reason-text-that-must-not-be-copied";
    let applied = rig
        .request(rig.operator, job, Verb::Pause, None, None, canary)
        .await;
    let refused = rig
        .request(rig.stranger, job, Verb::Resume, None, None, canary)
        .await;
    rig.hook().pass(rig.tenant).await;
    let markers = rig.markers().await;
    assert_eq!(markers.len(), 2, "{markers:#?}");
    let version = rig
        .allowlist
        .read()
        .expect("the allowlist")
        .version_hash()
        .to_owned();
    for (_, subject, reason) in &markers {
        assert!(!subject.contains(canary) && !reason.contains(canary));
        assert!(
            subject.contains(&format!("allowlist={}", &version[7..23])),
            "{subject}"
        );
    }
    let applied_marker = markers
        .iter()
        .find(|(_, subject, _)| subject.contains(&applied.as_uuid().hyphenated().to_string()))
        .expect("the marker of the pause");
    assert!(
        applied_marker.1.contains("code=applied")
            && applied_marker.1.contains(&format!("actor={OPERATOR}"))
    );
    let refused_marker = markers
        .iter()
        .find(|(_, subject, _)| subject.contains(&refused.as_uuid().hyphenated().to_string()))
        .expect("the marker of the refusal");
    assert!(
        refused_marker.1.contains("code=not_authorized")
            && refused_marker.1.contains(&format!("actor={STRANGER}"))
    );
    assert_eq!(
        refused_marker.2,
        "The person may not take this decision now."
    );
}

/// R-17. Nothing the person wrote reaches a log line of the hook.
#[tokio::test(flavor = "multi_thread")]
async fn r17_no_log_line_of_the_hook_holds_the_text_of_a_request() {
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let _ = tracing::subscriber::set_global_default(Lines(seen.clone()));
    let rig = Rig::new().await;
    let job = rig.active().await;
    let canary = "text-of-a-request-that-must-stay-out-of-logs";
    rig.request(rig.operator, job, Verb::Pause, None, None, canary)
        .await;
    rig.request(rig.stranger, job, Verb::Cancel, None, None, canary)
        .await;
    rig.raw_request(
        AuditActor::Human(rig.operator),
        canary,
        Some(job),
        None,
        canary,
    )
    .await;
    rig.hook().pass(rig.tenant).await;
    let lines = seen.lock().expect("lines").clone();
    assert!(
        lines
            .iter()
            .any(|line| line.contains("a decision was dealt with")),
        "the hook logs its outcomes: {lines:#?}"
    );
    assert!(
        lines.iter().all(|line| !line.contains(canary)),
        "a log line holds the text of a request: {lines:#?}"
    );
}

/// A subscriber that keeps every event as one line of text.
struct Lines(Arc<Mutex<Vec<String>>>);

impl tracing::Subscriber for Lines {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        struct Text(String);
        impl tracing::field::Visit for Text {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={value:?} ", field.name()));
            }
        }
        let mut text = Text(String::new());
        event.record(&mut text);
        self.0.lock().expect("lines").push(text.0);
    }
}

/// The break. The authority check is the thing that stops a removed person; take it out of both
/// places that make it (the hook's and the engine's own, by giving the engine an authority that
/// grants every role) and the same check must fail.
async fn a_removed_person_cannot_pause(rig: &Rig, hook: &ClaimWork) -> Result<(), String> {
    let job = rig.active().await;
    rig.request(rig.operator, job, Verb::Pause, None, None, "a short stop")
        .await;
    rig.write_allowlist(&[(REQUESTER, "requester-one", "requester")]);
    hook.pass(rig.tenant).await;
    match rig.status(job).await {
        JobStatus::Active => Ok(()),
        other => Err(format!("a removed person paused the job: {other:?}")),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_check_that_a_removed_person_cannot_act_passes_on_the_real_wiring() {
    let rig = Rig::new().await;
    assert_eq!(
        a_removed_person_cannot_pause(&rig, &rig.hook()).await,
        Ok(())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn break_applying_a_decision_without_rechecking_authority_is_caught() {
    let mut rig = Rig::new().await;
    // Remove both walls: the hook says yes to everyone, and the engine grants every role to every
    // principal (the engine suite's list, with the operator granted).
    let permissive = Arc::new(support::engine::StaticAuthority::new());
    permissive.grant(
        rig.operator,
        &[factory_domain::vocabulary::HumanRole::Operator],
    );
    let mut deps = rig.world.deps.clone();
    deps.authority = permissive;
    rig.engine = Arc::new(
        Engine::new(deps, rig.world.config.clone(), rig.world.handlers.clone())
            .expect("the engine starts"),
    );
    let broken = rig.hook_with(Arc::new(PermitsEveryone), rig.real_markers());
    let caught = a_removed_person_cannot_pause(&rig, &broken).await;
    assert!(
        caught.is_err(),
        "the check must fail when the authority check is gone: {caught:?}"
    );
}

// ---- SF-02: the lines of the hook about a job carry the correlation id of that job ----------

/// Keeps the JSON lines the telemetry pipeline writes.
#[derive(Clone, Default)]
struct JsonLines(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for JsonLines {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl JsonLines {
    fn lines(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.0.lock().expect("lock"))
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// Runs `body` under the real telemetry pipeline on this thread, and returns the lines it wrote.
fn with_json_logs<T>(body: impl std::future::Future<Output = T>) -> (T, Vec<String>) {
    let redactor = Arc::new(
        factory_domain::redaction::Redactor::builder()
            .build()
            .expect("builds"),
    );
    let config = factory_observability::telemetry::TelemetryConfig::new(
        "factory-claim-work-test",
        "0.0.0",
        Arc::new(factory_observability::redact::RedactorScrubber::new(
            redactor,
        )),
    );
    let logs = JsonLines::default();
    let sink = logs.clone();
    let pipeline = factory_observability::telemetry::build_pipeline(&config, move || sink.clone())
        .expect("the pipeline builds");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let out = pipeline.in_scope(|| runtime.block_on(body));
    (out, logs.lines())
}

/// SF-02. A line of the hook that is about one job is written inside the stretch span of that job,
/// so it starts with the job's correlation id (the conventions page, section 7). It was not: the
/// line "a received job was decided" named the job and the line "a decision was dealt with" named
/// nothing.
#[test]
fn sf_02_the_lines_of_the_hook_about_a_job_carry_the_correlation_id_of_that_job() {
    let ((correlation, other_correlation), lines) = with_json_logs(async {
        let rig = Rig::new().await;
        let job = rig.received().await;
        let other = rig.received().await;
        rig.hook().pass(rig.tenant).await;
        rig.request(rig.operator, job, Verb::Pause, None, None, "a short stop")
            .await;
        rig.hook().pass(rig.tenant).await;
        let correlation_of = |job: JobId| {
            let store = rig.world.store.clone();
            let tenant = rig.tenant;
            async move {
                let mut tx = store.begin(TenantScope::new(tenant)).await.expect("a tx");
                let found = tx.get_job(job).await.expect("a job").value.correlation_id;
                let _ = tx.rollback().await;
                found.to_string()
            }
        };
        (correlation_of(job).await, correlation_of(other).await)
    });
    for message in ["a received job was decided", "a decision was dealt with"] {
        let about: Vec<&String> = lines.iter().filter(|line| line.contains(message)).collect();
        assert!(
            !about.is_empty(),
            "the hook wrote no line '{message}': {lines:#?}"
        );
        for line in about {
            assert!(
                line.starts_with(&format!("{{\"correlation_id\":\"{correlation}\""))
                    || line.starts_with(&format!("{{\"correlation_id\":\"{other_correlation}\"")),
                "the line '{message}' carries no correlation id of a job: {line}"
            );
        }
    }
    // The decision was about the first job, so its line carries that job's id and not the other's.
    let decision = lines
        .iter()
        .find(|line| line.contains("a decision was dealt with"))
        .expect("a line");
    assert!(
        decision.starts_with(&format!("{{\"correlation_id\":\"{correlation}\"")),
        "the decision line carries the id of another job: {decision}"
    );
}
