//! The step a worker takes before each claim: admit the received jobs and apply the decisions that
//! people asked for. Real: PostgreSQL, the engine, the allowlist file, the policy files, the
//! authority and the hook. Scripted: the stage handlers (the engine suite's) and the approval
//! service, which is replaced by a recording stand-in labelled as such because a pull request
//! approval needs the whole delivery pipeline (the complete run in `apps/worker/tests` uses the
//! real service).

mod support;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_composition::authority::StoreAuthority;
use factory_composition::decisions::{
    APPLIED, AllowlistAuthority, ApprovalSubmitter, AuditMarkers, ClaimWork, ClaimWorkDeps,
    DecisionAuthority, DecisionFields, DecisionMarkers, MAX_TRIES, Marked, Pending, REJECTED,
    REQUESTED, Unreadable,
};
use factory_composition::delivery::StoreApprovalSources;
use factory_composition::seams::FileAllowlist;
use factory_composition::startup::{LoadedPolicies, load_policy};
use factory_domain::ids::{AuditEventId, CausationId, JobId, PrincipalId, StageRunId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, StageRunStatus};
use factory_domain::values::Slug;
use factory_ports::clock::IdGenerator;
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
            subject: fields.subject(),
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

#[tokio::test(flavor = "multi_thread")]
async fn a_record_that_is_not_a_decision_is_left_alone() {
    let rig = Rig::new().await;
    let job = rig.active().await;
    let mut tx = rig
        .world
        .store
        .begin(TenantScope::new(rig.tenant))
        .await
        .expect("a tx");
    let correlation = tx.get_job(job).await.expect("a job").value.correlation_id;
    tx.record_audit(NewAuditEvent {
        id: AuditEventId::from_uuid(rig.world.ids.new_uuid()),
        actor: AuditActor::System(Slug::parse("someone-else").expect("a slug")),
        action: AuditAction::new(REQUESTED).expect("an action"),
        subject: "this is not the grammar of a decision".to_owned(),
        decision: AuditDecision::Record,
        reason: "requested: nothing".to_owned(),
        policy_hash: rig.policies.hash.clone(),
        job: Some(job),
        stage_run: None,
        correlation_id: correlation,
    })
    .await
    .expect("recorded");
    tx.commit().await.expect("commit");
    rig.hook().pass(rig.tenant).await;
    assert_eq!(
        rig.trail(job).await,
        [REQUESTED],
        "no marker for a non-decision"
    );
    assert_eq!(rig.status(job).await, JobStatus::Active);
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
