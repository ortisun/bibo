//! The state of a job on its issue (ADR 0017): one label, one status comment, written after the
//! job changed, outside the engine's transaction, and never able to hurt a job.
//!
//! A job gets a status only after its intake stage has passed (finding STS-1). A job in these
//! tests is therefore "accepted" with `Rig::accepted`: admitted and with a passed intake stage run.
//! A bare `Rig::job` is a job that intake has not accepted, and nothing is written for it.
//!
//! Real: the step, the policy-built labels, the in-memory store's transactions (jobs, requests,
//! repositories, audit records). **Fake, and labelled so:** the store (`InMemoryStore`), the
//! status writer (`FakeIssueStatusWriter`, in front of a decorator that fails or stalls on
//! demand), the change host (it only ends credentials) and the clock. The GitHub adapter is tested
//! on its own in `crates/github/tests/issue_status.rs`; nothing here reaches GitHub.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use factory_composition::hooks::BeforeClaim as _;
use factory_composition::indexing::ActiveJobs;
use factory_composition::issue_status::{
    DISABLED, FAILED, FIRST_BACKOFF, IssueStatusDeps, IssueStatusReporter, MAX_TRIES,
    MAX_UPDATES_PER_HOUR, MAX_UPDATES_PER_MINUTE, RECHECK_AFTER, StatusPermission, StatusStep,
    StatusStepInputs, WRITTEN, intake_accepted, next_wait,
};
use factory_composition::redaction::redactor_from_policy;
use factory_composition::startup::load_policy;
use factory_domain::ids::{
    AttemptId, CorrelationId, JobId, PrincipalId, RepositoryId, StageRunId, TenantId,
};
use factory_domain::policy::issue_workflow::StatusLabel;
use factory_domain::scope::TenantScope;
use factory_domain::state::{Guard, JobEvent, JobStatus, StageRunEvent, StageRunStatus};
use factory_domain::values::{MediaType, NonNegativeInt, Sha256Digest};
use factory_domain::vocabulary::{AutonomyLevel, ExecutionMode, Fidelity, StageKind};
use factory_ports::clock::Uuid;
use factory_ports::githost::{ChangeHost, GitHostError, GitScope, IssueRef};
use factory_ports::issue_status::{
    CommentWrite, IssueStatusWriter, LabelOutcome, StatusComment, StatusScope, StatusStamp,
};
use factory_ports::paths::RepoRef;
use factory_ports::store::{
    AppliedTransition, AuditFilter, GateRecord, NewArtifactIndexEntry, NewJob, NewOriginalRequest,
    NewPrincipal, NewStageRun, PipelineScope, PrincipalKind, RequestSource, StageRunEffects,
    StartAttempt, Store, WorkerId,
};
use factory_testkit::clock::{FakeClock, SequentialIdGenerator};
use factory_testkit::fixtures::cleared;
use factory_testkit::githost::FakeChangeHost;
use factory_testkit::issue_status::{FakeIssueStatusWriter, status_labels};
use factory_testkit::store::InMemoryStore;
use tokio::sync::Notify;

const REPO: &str = "acme/widgets";
const ISSUE: u64 = 12;

fn root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

fn uid(n: u128) -> Uuid {
    Uuid::from_u128((n << 80) | (0x7_u128 << 76) | (0b10_u128 << 62))
}

fn issue() -> IssueRef {
    IssueRef {
        repo: RepoRef::parse(REPO).unwrap(),
        number: ISSUE,
    }
}

/// A status writer in front of the fake: it can fail every call or the next few, count the calls,
/// hold every call until released, and it notes whether the session of the call was shielded from
/// the sweep of ended jobs while the call ran. Labelled fake by the fake behind it.
struct Decorated {
    inner: FakeIssueStatusWriter,
    failing: Mutex<Option<GitHostError>>,
    fail_times: Mutex<Vec<GitHostError>>,
    calls: AtomicUsize,
    jobs: Arc<ActiveJobs>,
    sessions: Mutex<Vec<(JobId, bool)>>,
    hold: Mutex<Option<Arc<Notify>>>,
    panic_next: AtomicBool,
}

impl Decorated {
    fn new(jobs: Arc<ActiveJobs>) -> Arc<Self> {
        Arc::new(Self {
            inner: FakeIssueStatusWriter::new(),
            failing: Mutex::new(None),
            fail_times: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
            jobs,
            sessions: Mutex::new(Vec::new()),
            hold: Mutex::new(None),
            panic_next: AtomicBool::new(false),
        })
    }

    fn fail_always(&self, error: Option<GitHostError>) {
        *self.failing.lock().unwrap_or_else(PoisonError::into_inner) = error;
    }

    fn fail_next(&self, errors: Vec<GitHostError>) {
        *self
            .fail_times
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = errors;
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    async fn before(&self, scope: &StatusScope) -> Result<(), GitHostError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((scope.session, self.jobs.running().contains(&scope.session)));
        let hold = self
            .hold
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(hold) = hold {
            hold.notified().await;
        }
        assert!(
            !self.panic_next.swap(false, Ordering::SeqCst),
            "the writer panics on demand"
        );
        if let Some(error) = self
            .failing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            return Err(error);
        }
        let mut next = self
            .fail_times
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if next.is_empty() {
            Ok(())
        } else {
            Err(next.remove(0))
        }
    }
}

#[async_trait]
impl IssueStatusWriter for Decorated {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    async fn set_status_label(
        &self,
        scope: &StatusScope,
        issue: &IssueRef,
        label: &StatusLabel,
    ) -> Result<LabelOutcome, GitHostError> {
        self.before(scope).await?;
        self.inner.set_status_label(scope, issue, label).await
    }

    async fn upsert_status_comment(
        &self,
        scope: &StatusScope,
        issue: &IssueRef,
        comment: &StatusComment,
    ) -> Result<CommentWrite, GitHostError> {
        self.before(scope).await?;
        self.inner
            .upsert_status_comment(scope, issue, comment)
            .await
    }
}

struct Rig {
    clock: Arc<FakeClock>,
    store: Arc<InMemoryStore>,
    tenant: TenantId,
    repository: RepositoryId,
    writer: Arc<Decorated>,
    host: Arc<FakeChangeHost>,
    jobs: Arc<ActiveJobs>,
    reporter: IssueStatusReporter,
    next: u128,
}

impl Rig {
    fn new() -> Self {
        let clock = Arc::new(FakeClock::starting_at("2026-11-02T10:00:00Z"));
        let store = Arc::new(InMemoryStore::new(clock.clone()));
        let tenant = TenantId::from_uuid(uid(1));
        let repository = store.seed_repository(tenant);
        let jobs = Arc::new(ActiveJobs::new());
        let writer = Decorated::new(Arc::clone(&jobs));
        let host = Arc::new(FakeChangeHost::new());
        let reporter = Self::reporter_over(&clock, &store, tenant, &writer, &host, &jobs);
        Self {
            clock,
            store,
            tenant,
            repository,
            writer,
            host,
            jobs,
            reporter,
            next: 100,
        }
    }

    fn reporter_over(
        clock: &Arc<FakeClock>,
        store: &Arc<InMemoryStore>,
        tenant: TenantId,
        writer: &Arc<Decorated>,
        host: &Arc<FakeChangeHost>,
        jobs: &Arc<ActiveJobs>,
    ) -> IssueStatusReporter {
        let policies = load_policy(&root(), &[]).expect("the real policies load");
        IssueStatusReporter::new(IssueStatusDeps {
            store: store.clone(),
            writer: writer.clone(),
            host: host.clone(),
            labels: Arc::new(status_labels()),
            clock: clock.clone(),
            ids: Arc::new(SequentialIdGenerator::new()),
            jobs: Arc::clone(jobs),
            tenants: vec![tenant],
            policy_hash: Sha256Digest::of(b"the policy in force"),
            permission: StatusPermission::from_level(AutonomyLevel::L0),
            redactor: Arc::new(redactor_from_policy(&policies.security).expect("a redactor")),
        })
    }

    /// Another worker over the same store, the same GitHub and the same clock.
    fn another_reporter(&self) -> IssueStatusReporter {
        Self::reporter_over(
            &self.clock,
            &self.store,
            self.tenant,
            &self.writer,
            &self.host,
            &self.jobs,
        )
    }

    fn id(&mut self) -> u128 {
        self.next += 1;
        self.next
    }

    /// A job in `RECEIVED` with the issue its original request names (or none). Intake has not
    /// accepted anything yet, so no status is written for it.
    async fn job(&mut self, source_ref: Option<&str>) -> JobId {
        self.job_from(RequestSource::GithubIssue, source_ref).await
    }

    /// A job that was submitted through the API: it has its request from the moment it exists.
    async fn api_job(&mut self, source_ref: Option<&str>) -> JobId {
        self.job_from(RequestSource::Api, source_ref).await
    }

    /// A job the factory has accepted on its issue: admitted, with the intake stage passed. This
    /// is where a status starts (finding STS-1). It is `ACTIVE` at version 2.
    async fn accepted(&mut self, source_ref: Option<&str>) -> JobId {
        let job = self.job(source_ref).await;
        self.admit(job).await;
        self.pass_intake(job).await;
        job
    }

    /// Drives the intake stage run of an `ACTIVE` job to `PASSED` through legal moves of the
    /// stage run machine, as the engine does: ready, started, gated, passed.
    async fn pass_intake(&mut self, job: JobId) {
        let n = self.id();
        let run = StageRunId::from_uuid(uid(n + 4000));
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .unwrap();
        let inserted = tx
            .insert_stage_run(NewStageRun {
                id: run,
                job_id: job,
                kind: StageKind::Intake,
                run_number: 1,
                max_attempts: 3,
                rework_of: None,
            })
            .await
            .unwrap()
            .row;
        let at = factory_domain::values::Timestamp::parse("2026-11-02T10:00:00Z").unwrap();
        let index = |bytes: &'static [u8]| NewArtifactIndexEntry {
            sha256: Sha256Digest::of(bytes),
            media_type: MediaType::parse("application/octet-stream").unwrap(),
            size_bytes: NonNegativeInt::new(i64::try_from(bytes.len()).unwrap()).unwrap(),
            origin: None,
        };
        tx.index_artifact(index(b"contract")).await.unwrap();
        tx.index_artifact(index(b"report")).await.unwrap();
        let ready = AppliedTransition::plan(
            StageRunStatus::Pending,
            StageRunEvent::PreconditionsMet,
            at,
            cleared(Guard::UpstreamPassed),
        )
        .unwrap();
        let version = tx
            .transition_stage_run(
                run,
                inserted.version,
                ready,
                StageRunEffects {
                    contract_sha256: Some(Sha256Digest::of(b"contract")),
                    ..StageRunEffects::default()
                },
            )
            .await
            .unwrap();
        let start = AppliedTransition::plan(
            StageRunStatus::Ready,
            StageRunEvent::Start,
            at,
            cleared(Guard::LeaseAcquired),
        )
        .unwrap();
        tx.start_attempt(StartAttempt {
            attempt: AttemptId::from_uuid(uid(n + 5000)),
            stage_run: run,
            expected: version,
            worker: WorkerId::new("worker-1").unwrap(),
            lease_ttl: Duration::from_secs(60),
            attempt_timeout: Duration::from_secs(600),
            transition: start,
        })
        .await
        .unwrap();
        let version = tx.get_stage_run(run).await.unwrap().version;
        let gating = AppliedTransition::plan(
            StageRunStatus::Running,
            StageRunEvent::AttemptSucceeded,
            at,
            cleared(Guard::OutputSchemaValid),
        )
        .unwrap();
        let version = tx
            .transition_stage_run(run, version, gating, StageRunEffects::default())
            .await
            .unwrap();
        let passed = AppliedTransition::plan(
            StageRunStatus::Gating,
            StageRunEvent::GatePassed,
            at,
            cleared(Guard::GatePassEvidenced),
        )
        .unwrap();
        tx.transition_stage_run(
            run,
            version,
            passed,
            StageRunEffects {
                gate: Some(GateRecord {
                    outcome: factory_domain::vocabulary::GateOutcome::Passed,
                    report_sha256: Some(Sha256Digest::of(b"report")),
                    failing_set_sha256: None,
                }),
                ..StageRunEffects::default()
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    async fn job_from(&mut self, source: RequestSource, source_ref: Option<&str>) -> JobId {
        let n = self.id();
        let principal = PrincipalId::from_uuid(uid(n));
        let job = JobId::from_uuid(uid(n + 1000));
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .unwrap();
        tx.insert_principal(NewPrincipal {
            id: principal,
            kind: PrincipalKind::Human {
                github_user_id: u64::try_from(n).unwrap(),
            },
            login: Some("octocat".to_owned()),
        })
        .await
        .unwrap();
        tx.insert_job(NewJob {
            id: job,
            correlation_id: CorrelationId::from_uuid(uid(n + 2000)),
            repository: self.repository,
            requester: principal,
            execution_mode: ExecutionMode::Test,
            autonomy_level: AutonomyLevel::L1,
            pipeline_scope: PipelineScope::new(vec![StageKind::Intake]).unwrap(),
            origin: None,
        })
        .await
        .unwrap();
        if let Some(source_ref) = source_ref {
            tx.record_original_request(NewOriginalRequest {
                id: uid(n + 3000),
                job,
                revision: 1,
                source,
                source_ref: Some(source_ref.to_owned()),
                author_github_user_id: Some(1),
                text: "Add a word count command.".to_owned(),
            })
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
        job
    }

    async fn status(&self, job: JobId) -> JobStatus {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .unwrap();
        let status = tx.get_job(job).await.unwrap().value.status;
        let _ = tx.rollback().await;
        status
    }

    /// Moves the job with a legal transition of the machine.
    async fn move_job(&self, job: JobId, event: JobEvent, guard: Guard) {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .unwrap();
        let row = tx.get_job(job).await.unwrap();
        let at = factory_domain::values::Timestamp::parse("2026-11-02T10:00:00Z").unwrap();
        let plan = AppliedTransition::plan(row.value.status, event, at, cleared(guard)).unwrap();
        tx.transition_job(job, row.version, plan).await.unwrap();
        tx.commit().await.unwrap();
    }

    async fn admit(&self, job: JobId) {
        self.move_job(job, JobEvent::Admit, Guard::AdmissionOk)
            .await;
    }

    async fn pause(&self, job: JobId) {
        self.move_job(job, JobEvent::Pause, Guard::ActorMayPause)
            .await;
    }

    async fn resume(&self, job: JobId) {
        self.move_job(job, JobEvent::Resume, Guard::ActorMayPause)
            .await;
    }

    async fn fail(&self, job: JobId) {
        self.move_job(job, JobEvent::FailJob, Guard::Unrecoverable)
            .await;
    }

    async fn audit(&self, job: JobId, action: &str) -> Vec<String> {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .unwrap();
        let records = tx.read_audit(AuditFilter::Job(job), 0, 500).await.unwrap();
        let _ = tx.rollback().await;
        records
            .into_iter()
            .filter(|r| r.event.action.as_str() == action)
            .map(|r| format!("{} | {}", r.event.subject, r.event.reason))
            .collect()
    }

    fn labels(&self) -> Vec<String> {
        self.writer.inner.labels_of(&issue())
    }

    fn comments(&self) -> Vec<String> {
        self.writer.inner.app_comments(&issue())
    }
}

// ---- it writes ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_new_job_gets_one_label_and_one_comment_and_each_change_edits_them() {
    let mut rig = Rig::new();
    let job = rig.job(Some("acme/widgets#12")).await;
    // The factory has not accepted the issue yet: the job is waiting for admission, and then for
    // intake. Nothing is written, not even `factory: queued` (finding STS-1).
    rig.reporter.pass(rig.tenant).await;
    rig.admit(job).await;
    rig.reporter.pass(rig.tenant).await;
    assert!(rig.labels().is_empty() && rig.comments().is_empty());
    assert_eq!(rig.writer.calls(), 0);

    rig.pass_intake(job).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: working".to_owned()]);
    assert_eq!(rig.comments().len(), 1);
    assert!(rig.comments()[0].contains("I am working on this now"));
    rig.pause(job).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: paused".to_owned()]);
    rig.resume(job).await;
    rig.fail(job).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: failed".to_owned()]);
    let comments = rig.comments();
    assert_eq!(comments.len(), 1, "one comment however many changes");
    assert!(
        comments[0].contains("could not be finished"),
        "{}",
        comments[0]
    );
    let stamp = StatusStamp::from_text(&comments[0]).expect("the marker");
    assert_eq!(stamp.job, job);
    assert!(comments[0].lines().all(|l| !l.contains("factory:")));
}

#[tokio::test]
async fn negative_nt_stat_06_nothing_in_the_comment_comes_from_the_issue_or_a_model() {
    let mut rig = Rig::new();
    rig.accepted(Some("acme/widgets#12")).await;
    rig.reporter.pass(rig.tenant).await;
    let visible = rig.comments()[0]
        .split("<!--")
        .next()
        .unwrap_or_default()
        .to_owned();
    assert!(
        !visible.contains("word count"),
        "the request text is not in the comment"
    );
    assert!(!visible.contains(REPO));
    assert_eq!(
        visible.trim(),
        "I am working on this now. I will update this comment when something changes."
    );
}

#[tokio::test]
async fn a_success_is_recorded_in_the_audit_log_once_for_each_version() {
    let mut rig = Rig::new();
    let job = rig.accepted(Some("acme/widgets#12")).await;
    rig.reporter.pass(rig.tenant).await;
    rig.reporter.pass(rig.tenant).await;
    let written = rig.audit(job, WRITTEN).await;
    assert_eq!(written.len(), 1, "{written:?}");
    assert!(written[0].starts_with(&format!("job {} version 2 state ACTIVE", job.as_text())));
    rig.pause(job).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.audit(job, WRITTEN).await.len(), 2);
}

// ---- it never hurts a job ------------------------------------------------------------------------

#[tokio::test]
async fn negative_nt_stat_05_a_failing_github_never_fails_blocks_or_rolls_back_a_job() {
    let mut rig = Rig::new();
    let job = rig.accepted(Some("acme/widgets#12")).await;
    rig.writer.fail_always(Some(GitHostError::Unavailable));
    rig.reporter.pass(rig.tenant).await;
    assert!(
        rig.labels().is_empty() && rig.comments().is_empty(),
        "nothing was written"
    );
    // The job is exactly where it was and moves on as before.
    assert_eq!(rig.status(job).await, JobStatus::Active);
    rig.pause(job).await;
    assert_eq!(rig.status(job).await, JobStatus::Paused);
    // The failure is on record and in the health report, as degraded, never as not ready.
    let failed = rig.audit(job, FAILED).await;
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert!(
        failed[0].contains("will be tried again: unavailable"),
        "{failed:?}"
    );
    let check = rig.reporter.health_check();
    assert_eq!(
        check.status,
        factory_composition::health::CheckStatus::Degraded,
        "{check:?}"
    );
    let report = factory_composition::health::HealthReport::from_checks(
        factory_composition::profile::Profile::Test,
        true,
        vec![check],
        &[],
    );
    assert!(
        report.ready,
        "a failing status write does not make the process unready"
    );
}

#[tokio::test]
async fn negative_nt_stat_05_a_stalled_github_does_not_hold_up_the_hook_and_the_write_finishes_when_it_answers()
 {
    let mut rig = Rig::new();
    let job = rig.accepted(Some("acme/widgets#12")).await;
    let gate = Arc::new(Notify::new());
    *rig.writer.hold.lock().unwrap() = Some(Arc::clone(&gate));
    // The hook returns although the writer is stuck: the write runs in a task of its own.
    tokio::time::timeout(Duration::from_secs(5), rig.reporter.before_claim())
        .await
        .expect("the hook returns at once");
    tokio::task::yield_now().await;
    assert!(rig.labels().is_empty());
    rig.pause(job).await;
    assert_eq!(
        rig.status(job).await,
        JobStatus::Paused,
        "the job moved on meanwhile"
    );
    // Let it answer.
    *rig.writer.hold.lock().unwrap() = None;
    gate.notify_one();
    gate.notify_one();
    for _ in 0..50 {
        if !rig.labels().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(rig.labels(), vec!["factory: working".to_owned()]);
}

#[tokio::test]
async fn negative_nt_stat_05_a_transient_failure_waits_a_back_off_and_is_tried_again_and_the_comment_is_still_one()
 {
    let mut rig = Rig::new();
    let job = rig.accepted(Some("acme/widgets#12")).await;
    // The first comment write fails after the host may have acted; the retry must not duplicate.
    rig.writer.fail_next(vec![GitHostError::Unavailable]);
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 1);
    // Before the back-off ends nothing is tried.
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 1, "no try inside the back-off");
    rig.clock.advance(FIRST_BACKOFF + Duration::from_secs(1));
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: working".to_owned()]);
    assert_eq!(rig.comments().len(), 1);
    assert_eq!(rig.audit(job, WRITTEN).await.len(), 1);
    assert_eq!(rig.audit(job, FAILED).await.len(), 1);
    assert_eq!(
        rig.reporter.health_check().status,
        factory_composition::health::CheckStatus::Pass,
        "a failure that was made good is not shown any more"
    );
}

#[tokio::test]
async fn negative_nt_stat_05_it_gives_up_on_a_version_after_the_tries_and_starts_again_with_the_next_version()
 {
    let mut rig = Rig::new();
    let job = rig.accepted(Some("acme/widgets#12")).await;
    rig.writer.fail_always(Some(GitHostError::Unavailable));
    for _ in 0..(MAX_TRIES + 2) {
        rig.clock.advance(Duration::from_secs(30 * 60));
        rig.reporter.pass(rig.tenant).await;
    }
    assert_eq!(
        rig.writer.calls(),
        usize::try_from(MAX_TRIES).unwrap(),
        "no more tries than the bound"
    );
    let failed = rig.audit(job, FAILED).await;
    assert_eq!(failed.len(), usize::try_from(MAX_TRIES).unwrap());
    assert!(failed.last().unwrap().contains("gave up on this version"));
    assert_eq!(rig.reporter.health().gave_up, 1);
    // A new version of the job is a new start.
    rig.writer.fail_always(None);
    rig.pause(job).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: paused".to_owned()]);
}

#[tokio::test]
async fn negative_nt_stat_05_a_refusal_that_a_retry_cannot_cure_is_not_retried() {
    let mut rig = Rig::new();
    let job = rig.accepted(Some("acme/widgets#12")).await;
    rig.writer.fail_always(Some(GitHostError::Forbidden));
    rig.reporter.pass(rig.tenant).await;
    rig.clock.advance(Duration::from_secs(3600));
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 1);
    let failed = rig.audit(job, FAILED).await;
    assert_eq!(failed.len(), 1);
    assert!(
        failed[0].contains("gave up on this version: forbidden"),
        "{failed:?}"
    );
}

#[tokio::test]
async fn negative_nt_stat_05_a_scan_during_a_write_does_not_skip_the_back_off_of_a_failed_version()
{
    let mut rig = Rig::new();
    rig.accepted(Some("acme/widgets#12")).await;
    let reporter = Arc::new(rig.another_reporter());
    reporter.scan(rig.tenant).await;
    // The write is stuck at GitHub, and then fails.
    let gate = Arc::new(Notify::new());
    *rig.writer.hold.lock().unwrap() = Some(Arc::clone(&gate));
    rig.writer.fail_always(Some(GitHostError::Unavailable));
    let delivering = {
        let reporter = Arc::clone(&reporter);
        tokio::spawn(async move { reporter.deliver_due().await })
    };
    for _ in 0..50 {
        if rig.writer.calls() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(rig.writer.calls(), 1, "the write is under way");
    // The hook scans again while it waits: the version in flight is not queued a second time.
    reporter.scan(rig.tenant).await;
    assert_eq!(reporter.health().pending, 0);
    *rig.writer.hold.lock().unwrap() = None;
    gate.notify_one();
    delivering.await.expect("the delivery ends");
    assert_eq!(
        reporter.health().retrying,
        1,
        "the failed version waits for its back-off"
    );
    // Nothing is tried again until the back-off has passed.
    reporter.deliver_due().await;
    reporter.scan(rig.tenant).await;
    reporter.deliver_due().await;
    assert_eq!(rig.writer.calls(), 1);
}

// ---- idempotent under at-least-once, and the newest version wins ----------------------------------

#[tokio::test]
async fn two_workers_over_the_same_jobs_leave_one_label_and_one_comment() {
    let mut rig = Rig::new();
    rig.accepted(Some("acme/widgets#12")).await;
    let second = rig.another_reporter();
    rig.reporter.pass(rig.tenant).await;
    second.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: working".to_owned()]);
    assert_eq!(rig.comments().len(), 1);
}

#[tokio::test]
async fn a_restarted_worker_does_not_write_again_what_the_audit_log_says_it_wrote() {
    let mut rig = Rig::new();
    let job = rig.accepted(Some("acme/widgets#12")).await;
    rig.reporter.pass(rig.tenant).await;
    let calls = rig.writer.calls();
    assert!(calls > 0);
    // The process restarts: a new reporter, an empty memory.
    let restarted = rig.another_reporter();
    restarted.pass(rig.tenant).await;
    assert_eq!(
        rig.writer.calls(),
        calls,
        "nothing to write: the log says version 2 is on the issue"
    );
    // One more change after the restart is written.
    rig.pause(job).await;
    restarted.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: paused".to_owned()]);
}

#[tokio::test]
async fn when_two_updates_race_the_newer_version_stays_on_the_issue() {
    let mut rig = Rig::new();
    let job = rig.accepted(Some("acme/widgets#12")).await;
    // Worker A reads the job at version 2 and is slow to write.
    let slow = rig.another_reporter();
    slow.scan(rig.tenant).await;
    // The job moves to version 3 and worker B writes it at once.
    rig.pause(job).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: paused".to_owned()]);
    // Worker A now writes its older news. It must not take the issue back.
    slow.deliver_due().await;
    assert_eq!(
        rig.labels(),
        vec!["factory: paused".to_owned()],
        "the label stays"
    );
    let comments = rig.comments();
    assert_eq!(comments.len(), 1);
    assert!(comments[0].contains("paused this work"), "{}", comments[0]);
    // The control: worker A's next look sees version 3 is written elsewhere... and finishes the same.
    slow.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: paused".to_owned()]);
}

#[tokio::test]
async fn several_changes_before_a_write_become_one_write_of_the_newest() {
    let mut rig = Rig::new();
    let job = rig.accepted(Some("acme/widgets#12")).await;
    rig.reporter.scan(rig.tenant).await;
    rig.pause(job).await;
    rig.reporter.scan(rig.tenant).await;
    rig.resume(job).await;
    rig.reporter.scan(rig.tenant).await;
    rig.pause(job).await;
    rig.reporter.scan(rig.tenant).await;
    rig.reporter.deliver_due().await;
    assert_eq!(rig.labels(), vec!["factory: paused".to_owned()]);
    assert_eq!(rig.writer.calls(), 2, "one comment call and one label call");
}

#[tokio::test]
async fn negative_nt_stat_04_a_flood_of_jobs_is_written_at_a_bounded_rate() {
    let mut rig = Rig::new();
    let mut ids = Vec::new();
    for _ in 0..(MAX_UPDATES_PER_MINUTE + 4) {
        ids.push(rig.accepted(Some("acme/widgets#12")).await);
    }
    rig.reporter.pass(rig.tenant).await;
    // Two calls for each update (the comment and the label); no more updates than the bound.
    assert_eq!(rig.writer.calls(), MAX_UPDATES_PER_MINUTE * 2);
    assert_eq!(rig.reporter.health().pending, 4);
    // A minute later the rest follows.
    rig.clock.advance(Duration::from_secs(61));
    rig.reporter.deliver_due().await;
    assert_eq!(rig.reporter.health().pending, 0);
}

// ---- only what the factory accepted, only enabled repositories ------------------------------------

#[tokio::test]
async fn a_job_with_no_original_request_has_no_issue_the_factory_accepted_and_gets_nothing() {
    let mut rig = Rig::new();
    rig.accepted(None).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 0);
}

#[tokio::test]
async fn an_issue_in_another_repository_than_the_jobs_is_never_written_on() {
    let mut rig = Rig::new();
    rig.accepted(Some("acme/other#12")).await;
    rig.accepted(Some("not a pointer")).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 0);
}

#[tokio::test]
async fn a_repository_that_is_switched_off_gets_nothing_and_a_switch_off_before_the_write_stops_it()
{
    let mut rig = Rig::new();
    rig.accepted(Some("acme/widgets#12")).await;
    rig.store.disable_repository(rig.repository);
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 0, "switched off when the job was read");
    // The control: enabled, the same job is written.
    let mut rig = Rig::new();
    let job_b = rig.accepted(Some("acme/widgets#12")).await;
    rig.reporter.scan(rig.tenant).await;
    rig.store.disable_repository(rig.repository);
    rig.reporter.deliver_due().await;
    assert_eq!(
        rig.writer.calls(),
        0,
        "switched off between the read and the write"
    );
    assert_eq!(rig.audit(job_b, FAILED).await.len(), 1);
}

#[tokio::test]
async fn an_old_job_the_worker_never_wrote_for_is_left_alone_and_a_just_finished_one_is_written() {
    let mut rig = Rig::new();
    let old = rig.accepted(Some("acme/widgets#12")).await;
    rig.fail(old).await;
    // A long time passes with no worker looking: the job ended long ago.
    rig.clock.advance(Duration::from_secs(3600));
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 0, "history is not rewritten");
    // A job that ended just now is written.
    let fresh = rig.accepted(Some("acme/widgets#13")).await;
    rig.fail(fresh).await;
    rig.reporter.pass(rig.tenant).await;
    assert!(rig.writer.calls() > 0);
}

// ---- the credential of a round -----------------------------------------------------------------------

#[tokio::test]
async fn each_round_uses_a_fresh_session_that_the_sweep_spares_and_that_is_ended_afterwards() {
    let mut rig = Rig::new();
    let job = rig.accepted(Some("acme/widgets#12")).await;
    rig.reporter.pass(rig.tenant).await;
    rig.pause(job).await;
    rig.reporter.pass(rig.tenant).await;
    let sessions = rig.writer.sessions.lock().unwrap().clone();
    assert!(sessions.len() >= 4);
    assert!(
        sessions.iter().all(|(_, shielded)| *shielded),
        "the sweep of ended jobs spares the session while it writes"
    );
    let distinct: std::collections::BTreeSet<_> = sessions.iter().map(|(s, _)| *s).collect();
    assert_eq!(distinct.len(), 2, "one session for each round");
    assert!(
        distinct.iter().all(|s| s != &job),
        "the session is not the job: a job's tokens end with the job"
    );
    assert!(
        rig.jobs.running().is_empty(),
        "no session is left in the shield"
    );
    // The credential of a finished round is ended: the host refuses it now.
    let (session, _) = sessions[0];
    let refused = rig
        .host
        .fetch_target(&GitScope {
            tenant: rig.tenant,
            job: session,
            stage: StageKind::Delivery,
            repo: RepoRef::parse(REPO).unwrap(),
        })
        .await;
    assert_eq!(refused.err(), Some(GitHostError::Unauthorized));
}

#[test]
fn the_policy_loads_from_the_protected_checkout_and_a_checkout_without_it_stops_the_start() {
    use factory_composition::startup::{StartupFailure, load_issue_workflow};
    let loaded = load_issue_workflow(&root(), &[]).expect("the real policy loads");
    assert_eq!(loaded.labels.iter().count(), JobStatus::ALL.len());
    assert!(loaded.hash.starts_with("sha256:"));
    // The control: a checkout that holds no such file has no label to write, and the step does
    // not start with a default.
    let empty = std::env::temp_dir().join(format!("issue-workflow-none-{}", std::process::id()));
    std::fs::create_dir_all(&empty).expect("a directory");
    let refused = load_issue_workflow(&empty, &[]);
    let _ = std::fs::remove_dir_all(&empty);
    assert!(
        matches!(refused, Err(StartupFailure::Policy(_))),
        "{refused:?}"
    );
}

#[test]
fn the_audit_actions_are_fixed_words_that_the_api_login_cannot_write() {
    assert_eq!(WRITTEN, "issue_status.written");
    assert_eq!(FAILED, "issue_status.failed");
    // Neither is in the list of the trigger that limits the API's database login.
    let migration = std::fs::read_to_string(
        root().join("migrations/2026-10-29-002100_api_audit_actions/up.sql"),
    )
    .expect("the migration");
    assert!(!migration.contains("issue_status"));
}

// ---- STS-1: only after intake accepted the issue ------------------------------------------------

#[test]
fn only_a_passed_intake_run_means_the_factory_accepted_the_issue() {
    use StageRunStatus as S;
    // The sibling: a passed run, or one that passed and was replaced since.
    assert!(intake_accepted(
        [(StageKind::Intake, S::Passed)].into_iter()
    ));
    assert!(intake_accepted(
        [
            (StageKind::Intake, S::Superseded),
            (StageKind::Intake, S::Running)
        ]
        .into_iter()
    ));
    // Every other state of an intake run is not an acceptance, and neither is another stage.
    for status in [
        S::Pending,
        S::Ready,
        S::Running,
        S::Gating,
        S::WaitingForHuman,
        S::Blocked,
        S::ReworkRequested,
        S::Failed,
        S::Skipped,
        S::Cancelled,
    ] {
        assert!(
            !intake_accepted([(StageKind::Intake, status)].into_iter()),
            "{status:?}"
        );
    }
    assert!(!intake_accepted(
        [
            (StageKind::Specification, S::Passed),
            (StageKind::Delivery, S::Passed)
        ]
        .into_iter()
    ));
    assert!(!intake_accepted(std::iter::empty()));
}

#[tokio::test]
async fn an_api_job_for_an_issue_that_intake_refuses_gets_nothing_before_or_after_the_refusal() {
    let mut rig = Rig::new();
    // Somebody who may submit jobs aims one at an issue that nobody labelled. The request is stored
    // the moment the job exists, so the step can see it. It used to write `queued` here, then
    // `rejected` when intake refused the job.
    let refused = rig.api_job(Some("acme/widgets#7")).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 0, "submitted: nothing is written");
    rig.admit(refused).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(
        rig.writer.calls(),
        0,
        "admitted, with the request on file and intake not through: nothing is written"
    );
    // Intake looks at GitHub, finds no label of an authorised person and refuses; the job ends.
    rig.fail(refused).await;
    rig.clock.advance(Duration::from_secs(60));
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 0, "the refusal writes nothing either");
    assert!(rig.labels().is_empty() && rig.comments().is_empty());
    assert!(rig.audit(refused, WRITTEN).await.is_empty());
    assert!(rig.audit(refused, FAILED).await.is_empty());

    // A job refused at admission is not accepted either.
    let denied = rig.api_job(Some("acme/widgets#8")).await;
    rig.move_job(denied, JobEvent::RejectAtAdmission, Guard::AdmissionDenied)
        .await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 0);

    // The sibling: an API job whose intake passes is written, like any other.
    let accepted = rig.api_job(Some("acme/widgets#12")).await;
    rig.admit(accepted).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 0, "still not through intake");
    rig.pass_intake(accepted).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: working".to_owned()]);
}

#[tokio::test]
async fn a_job_that_intake_has_not_accepted_cannot_displace_the_comment_of_one_that_it_has() {
    let mut rig = Rig::new();
    let accepted = rig.accepted(Some("acme/widgets#12")).await;
    rig.reporter.pass(rig.tenant).await;
    let before = rig.comments();
    assert_eq!(before.len(), 1);
    // A later job for the same issue number, submitted by somebody else, starts after the first
    // and so would win the stamp. It is not accepted, so it writes nothing at all.
    rig.clock.advance(Duration::from_secs(5));
    let intruder = rig.api_job(Some("acme/widgets#12")).await;
    rig.admit(intruder).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(
        rig.comments(),
        before,
        "the comment of the accepted job stays"
    );
    let stamp = StatusStamp::from_text(&rig.comments()[0]).expect("the marker");
    assert_eq!(stamp.job, accepted);
    assert_eq!(rig.writer.calls(), 2);
}

// ---- STS-2: Retry-After and the hourly bound -------------------------------------------------------

#[test]
fn the_next_wait_is_the_larger_of_the_back_off_and_what_github_asked_for() {
    let secs = Duration::from_secs;
    assert_eq!(next_wait(1, None), secs(30));
    assert_eq!(
        next_wait(1, Some(secs(5))),
        secs(30),
        "a shorter ask changes nothing"
    );
    assert_eq!(
        next_wait(1, Some(secs(600))),
        secs(600),
        "a longer ask is obeyed"
    );
    assert_eq!(
        next_wait(3, Some(secs(60))),
        secs(120),
        "the back-off of the third try is longer"
    );
    assert_eq!(
        next_wait(1, Some(secs(86_400))),
        secs(3600),
        "and an absurd ask is cut at one hour"
    );
}

#[tokio::test]
async fn a_wait_that_github_asked_for_moves_the_next_try_past_the_back_off() {
    let mut rig = Rig::new();
    let job = rig.accepted(Some("acme/widgets#12")).await;
    // GitHub answered "wait ten minutes"; the adapter did not sleep through it and reported it.
    rig.writer.fail_next(vec![GitHostError::RateLimited {
        retry_after: Some(Duration::from_secs(600)),
    }]);
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 1);
    // The step's own back-off is 30 seconds. It used to retry then, before the wait GitHub asked for.
    rig.clock.advance(FIRST_BACKOFF + Duration::from_secs(1));
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 1, "no try after the back-off alone");
    rig.clock.advance(Duration::from_secs(8 * 60));
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(
        rig.writer.calls(),
        1,
        "no try before the ten minutes are over"
    );
    rig.clock.advance(Duration::from_secs(100));
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: working".to_owned()]);
    let failed = rig.audit(job, FAILED).await;
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert!(failed[0].contains("rate_limited"), "{failed:?}");
    assert_eq!(rig.audit(job, WRITTEN).await.len(), 1);
}

#[tokio::test]
async fn a_wait_shorter_than_the_back_off_does_not_hasten_the_next_try() {
    let mut rig = Rig::new();
    rig.accepted(Some("acme/widgets#12")).await;
    rig.writer.fail_next(vec![GitHostError::RateLimited {
        retry_after: Some(Duration::from_secs(5)),
    }]);
    rig.reporter.pass(rig.tenant).await;
    rig.clock.advance(Duration::from_secs(10));
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(
        rig.writer.calls(),
        1,
        "the back-off of 30 seconds still holds"
    );
    rig.clock.advance(FIRST_BACKOFF);
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: working".to_owned()]);
}

#[tokio::test]
async fn negative_nt_stat_04_no_more_updates_in_an_hour_than_the_hourly_bound_whatever_the_minute_allows()
 {
    let mut rig = Rig::new();
    // One issue for each job, so that no update is a newer stamp's loser.
    for n in 0..(MAX_UPDATES_PER_HOUR + 6) {
        rig.accepted(Some(&format!("acme/widgets#{}", 100 + n)))
            .await;
    }
    // Twenty-five minutes of looking once a minute: the minute allows six, the hour allows 120.
    for _ in 0..25 {
        rig.reporter.pass(rig.tenant).await;
        rig.clock.advance(Duration::from_secs(61));
    }
    assert_eq!(
        rig.writer.calls(),
        MAX_UPDATES_PER_HOUR * 2,
        "the comment and the label of each update, and no update past the hour's bound"
    );
    assert_eq!(rig.reporter.health().pending, 6);
    // The hour moves on and the rest follows.
    rig.clock.advance(Duration::from_secs(3600));
    rig.reporter.deliver_due().await;
    assert_eq!(rig.reporter.health().pending, 0);
    assert_eq!(rig.writer.calls(), (MAX_UPDATES_PER_HOUR + 6) * 2);
}

// ---- STS-3: the end state is written once more ----------------------------------------------------

#[tokio::test]
async fn the_end_state_is_written_once_more_and_a_late_older_write_is_repaired() {
    let mut rig = Rig::new();
    let job = rig.accepted(Some("acme/widgets#12")).await;
    rig.reporter.pass(rig.tenant).await;
    let working = StatusStamp::from_text(&rig.comments()[0]).expect("the marker");
    let working_text =
        "I am working on this now. I will update this comment when something changes.";
    rig.fail(job).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: failed".to_owned()]);

    // A second worker listed the comments before the end state was written and edits after it:
    // GitHub has no conditional edit, so the issue now shows an older update.
    rig.writer.inner.land_a_late_write(
        &issue(),
        &StatusComment::new(working, working_text.to_owned()).unwrap(),
        "factory: working",
    );
    assert_eq!(rig.labels(), vec!["factory: working".to_owned()]);
    assert!(rig.comments()[0].contains("I am working on this now"));

    // Nothing is due yet. Then the second look makes the end state right again.
    rig.clock.advance(RECHECK_AFTER - Duration::from_secs(10));
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(
        rig.labels(),
        vec!["factory: working".to_owned()],
        "not due yet"
    );
    rig.clock.advance(Duration::from_secs(20));
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: failed".to_owned()]);
    assert_eq!(rig.comments().len(), 1);
    assert!(
        rig.comments()[0].contains("could not be finished"),
        "{}",
        rig.comments()[0]
    );

    // It is one extra write, not a loop, and it is not recorded as a second success.
    let calls = rig.writer.calls();
    rig.clock.advance(Duration::from_secs(3600));
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), calls);
    assert_eq!(
        rig.audit(job, WRITTEN).await.len(),
        2,
        "working, then failed"
    );
}

#[tokio::test]
async fn a_state_that_is_not_an_end_state_is_not_written_a_second_time() {
    let mut rig = Rig::new();
    rig.accepted(Some("acme/widgets#12")).await;
    rig.reporter.pass(rig.tenant).await;
    let calls = rig.writer.calls();
    rig.clock.advance(RECHECK_AFTER * 3);
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), calls);
}

// ---- STS-4: a round that dies leaves nothing behind ------------------------------------------------

async fn the_session_is_gone(rig: &Rig) {
    for _ in 0..100 {
        if rig.jobs.running().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        rig.jobs.running().is_empty(),
        "the session is not left in the shield"
    );
    let session = rig.writer.sessions.lock().unwrap()[0].0;
    // The credential is ended too: the host refuses it now.
    for _ in 0..100 {
        let refused = rig
            .host
            .fetch_target(&GitScope {
                tenant: rig.tenant,
                job: session,
                stage: StageKind::Delivery,
                repo: RepoRef::parse(REPO).unwrap(),
            })
            .await;
        if refused.err() == Some(GitHostError::Unauthorized) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the credential of the round is still alive");
}

#[tokio::test]
async fn a_panic_in_a_write_does_not_leave_the_session_in_the_shield_or_the_credential_alive() {
    let mut rig = Rig::new();
    rig.accepted(Some("acme/widgets#12")).await;
    let reporter = Arc::new(rig.another_reporter());
    reporter.scan(rig.tenant).await;
    rig.writer.panic_next.store(true, Ordering::SeqCst);
    let delivering = {
        let reporter = Arc::clone(&reporter);
        tokio::spawn(async move { reporter.deliver_due().await })
    };
    let joined = delivering.await;
    assert!(joined.is_err_and(|e| e.is_panic()), "the write panicked");
    the_session_is_gone(&rig).await;
}

#[tokio::test]
async fn a_cancelled_write_does_not_leave_the_session_in_the_shield_or_the_credential_alive() {
    let mut rig = Rig::new();
    rig.accepted(Some("acme/widgets#12")).await;
    let reporter = Arc::new(rig.another_reporter());
    reporter.scan(rig.tenant).await;
    // The write is stuck at GitHub when the task is dropped, as at shutdown.
    let gate = Arc::new(Notify::new());
    *rig.writer.hold.lock().unwrap() = Some(Arc::clone(&gate));
    let delivering = {
        let reporter = Arc::clone(&reporter);
        tokio::spawn(async move { reporter.deliver_due().await })
    };
    for _ in 0..100 {
        if rig.writer.calls() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(rig.writer.calls(), 1, "the write is under way");
    assert!(
        !rig.jobs.running().is_empty(),
        "and its session is in the shield while it runs"
    );
    delivering.abort();
    assert!(delivering.await.is_err_and(|e| e.is_cancelled()));
    the_session_is_gone(&rig).await;
}

// ---- STS-6: the policy hash and the approval row --------------------------------------------------

fn approval() -> factory_domain::policy::approval::ApprovalPolicy {
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    (*policies.approval).clone()
}

#[test]
fn the_row_write_status_label_decides_whether_and_at_which_level_the_step_writes() {
    use factory_domain::policy::approval::Requirement;
    let real = approval();
    let permission = StatusPermission::from_policy(&real).expect("the real row is usable");
    for level in AutonomyLevel::ALL {
        assert!(
            permission.allows(*level),
            "{level:?}: the real row starts at L0"
        );
    }

    // The row raised to L2: a job at L1 is not written for.
    let mut raised = real.clone();
    raised
        .actions
        .iter_mut()
        .find(|row| row.id == StatusPermission::ACTION)
        .expect("the row")
        .min_level = "L2".to_owned();
    let raised = StatusPermission::from_policy(&raised).expect("a usable row");
    assert!(!raised.allows(AutonomyLevel::L0) && !raised.allows(AutonomyLevel::L1));
    assert!(raised.allows(AutonomyLevel::L2) && raised.allows(AutonomyLevel::L3));

    // The row changed to need a person: the step cannot use it, and the worker starts it off.
    let mut human = real.clone();
    human
        .actions
        .iter_mut()
        .find(|row| row.id == StatusPermission::ACTION)
        .expect("the row")
        .requires = Some(Requirement::Human);
    assert!(StatusPermission::from_policy(&human).is_err());
    // The row removed: the same.
    let mut gone = real;
    gone.actions
        .retain(|row| row.id != StatusPermission::ACTION);
    assert!(StatusPermission::from_policy(&gone).is_err());
}

#[tokio::test]
async fn a_level_below_the_one_the_row_allows_gets_no_status() {
    let mut rig = Rig::new();
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    rig.reporter = IssueStatusReporter::new(IssueStatusDeps {
        store: rig.store.clone(),
        writer: rig.writer.clone(),
        host: rig.host.clone(),
        labels: Arc::new(status_labels()),
        clock: rig.clock.clone(),
        ids: Arc::new(SequentialIdGenerator::new()),
        jobs: Arc::clone(&rig.jobs),
        tenants: vec![rig.tenant],
        policy_hash: Sha256Digest::of(b"the policy in force"),
        // The jobs of the rig run at L1.
        permission: StatusPermission::from_level(AutonomyLevel::L2),
        redactor: Arc::new(redactor_from_policy(&policies.security).expect("a redactor")),
    });
    rig.accepted(Some("acme/widgets#12")).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 0);
    // The sibling: the rig's usual reporter, whose row starts at L0, writes for the same job.
    let usual = rig.another_reporter();
    usual.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: working".to_owned()]);
}

fn step_inputs(rig: &Rig, checkout: std::path::PathBuf) -> StatusStepInputs {
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    StatusStepInputs {
        store: rig.store.clone(),
        writer: rig.writer.clone(),
        host: rig.host.clone(),
        clock: rig.clock.clone(),
        ids: Arc::new(SequentialIdGenerator::new()),
        jobs: Arc::clone(&rig.jobs),
        tenants: vec![rig.tenant],
        redactor: Arc::new(redactor_from_policy(&policies.security).expect("a redactor")),
        approval: Arc::clone(&policies.approval),
        base_policy_hash: policies.hash.clone(),
        checkout,
        untrusted_roots: Vec::new(),
    }
}

#[tokio::test]
async fn the_records_of_a_write_bind_the_hash_of_the_issue_workflow_policy() {
    let mut rig = Rig::new();
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    let step = StatusStep::build(step_inputs(&rig, root()));
    let StatusStep::Writing(reporter) = &step else {
        panic!("the real checkout gives a step that writes");
    };
    let job = rig.accepted(Some("acme/widgets#12")).await;
    reporter.pass(rig.tenant).await;
    let loaded = factory_composition::startup::load_issue_workflow(&root(), &[]).expect("loads");
    let expected =
        factory_composition::startup::bind_issue_workflow_hash(&policies.hash, &loaded.hash);
    assert_ne!(
        expected, policies.hash,
        "the workflow policy is part of the hash"
    );
    let mut tx = rig.store.begin(TenantScope::new(rig.tenant)).await.unwrap();
    let records = tx.read_audit(AuditFilter::Job(job), 0, 50).await.unwrap();
    let _ = tx.rollback().await;
    let written: Vec<_> = records
        .iter()
        .filter(|r| r.event.action.as_str() == WRITTEN)
        .collect();
    assert_eq!(written.len(), 1);
    assert_eq!(written[0].event.policy_hash, expected);
    // Another workflow policy gives another hash.
    assert_ne!(
        factory_composition::startup::bind_issue_workflow_hash(&policies.hash, "sha256:other"),
        expected
    );
}

// ---- STS-7: a policy that cannot be used does not stop the worker ------------------------------

fn empty_checkout(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("issue-status-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("a directory");
    dir
}

#[tokio::test]
async fn a_missing_issue_workflow_policy_turns_the_step_off_and_degraded_and_audits_it_and_writes_nothing()
 {
    let mut rig = Rig::new();
    let job = rig.accepted(Some("acme/widgets#12")).await;
    let dir = empty_checkout("missing");
    let step = StatusStep::build(step_inputs(&rig, dir.clone()));
    let _ = std::fs::remove_dir_all(&dir);
    // The step exists: the worker starts.
    assert!(step.is_off());
    let check = step.health_check();
    assert_eq!(
        check.status,
        factory_composition::health::CheckStatus::Degraded,
        "{check:?}"
    );
    assert!(
        check.detail.contains("policies/issue-workflow.yaml"),
        "the reason is in the line: {check:?}"
    );
    let report = factory_composition::health::HealthReport::from_checks(
        factory_composition::profile::Profile::Test,
        true,
        vec![check],
        &[],
    );
    assert!(
        report.ready,
        "a step that is off does not make the process unready"
    );

    // It writes nothing, however many claims come, and it records the fact once for the tenant.
    let hook = step.hook();
    hook.before_claim().await;
    hook.before_claim().await;
    tokio::task::yield_now().await;
    assert_eq!(rig.writer.calls(), 0);
    assert!(rig.labels().is_empty() && rig.comments().is_empty());
    let mut tx = rig.store.begin(TenantScope::new(rig.tenant)).await.unwrap();
    let records = tx.read_audit(AuditFilter::Tenant, 0, 100).await.unwrap();
    let _ = tx.rollback().await;
    let off: Vec<_> = records
        .iter()
        .filter(|r| r.event.action.as_str() == DISABLED)
        .collect();
    assert_eq!(off.len(), 1, "one record for the tenant: {records:?}");
    assert!(off[0].event.reason.contains("writes nothing on any issue"));
    assert_eq!(
        rig.status(job).await,
        JobStatus::Active,
        "the job is untouched"
    );

    // The sibling: the real checkout gives a step that writes.
    let step = StatusStep::build(step_inputs(&rig, root()));
    assert!(!step.is_off());
}

#[tokio::test]
async fn a_broken_issue_workflow_policy_and_a_different_trigger_label_do_the_same() {
    let rig = Rig::new();
    // A file that is not the policy.
    let dir = empty_checkout("broken");
    std::fs::create_dir_all(dir.join("policies")).expect("a directory");
    std::fs::write(
        dir.join("policies/issue-workflow.yaml"),
        "schema_version: 1\nnot: a policy\n",
    )
    .expect("a file");
    let step = StatusStep::build(step_inputs(&rig, dir.clone()));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(step.is_off(), "a broken file");

    // The two policies disagree about the label that starts work: the engine acts on the approval
    // policy's, so labels written from the other would describe a different trigger.
    let mut inputs = step_inputs(&rig, root());
    let mut changed = (*inputs.approval).clone();
    changed.intake.trigger_label = "build".to_owned();
    inputs.approval = Arc::new(changed);
    let step = StatusStep::build(inputs);
    assert!(step.is_off(), "a trigger label that differs");
    assert!(step.health_check().detail.contains("trigger label"));
}

// ---- STS-8: the repository is compared the same way everywhere -------------------------------------

#[tokio::test]
async fn a_differently_cased_source_ref_is_written_with_the_name_as_registered() {
    let mut rig = Rig::new();
    // The repository is registered as acme/widgets. The request names it in other letters, as
    // GitHub allows and as the API accepts.
    let job = rig.accepted(Some("Acme/Widgets#12")).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(
        rig.labels(),
        vec!["factory: working".to_owned()],
        "the issue is found in the registered spelling"
    );
    assert_eq!(rig.comments().len(), 1);
    assert!(rig.audit(job, FAILED).await.is_empty());
    assert_eq!(rig.audit(job, WRITTEN).await.len(), 1);
    // A different repository is still a different repository.
    rig.accepted(Some("Acme/Widgets-2#13")).await;
    let calls = rig.writer.calls();
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), calls);
}
