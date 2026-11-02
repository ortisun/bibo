//! The state of a job on its issue (ADR 0017): one label, one status comment, written after the
//! job changed, outside the engine's transaction, and never able to hurt a job.
//!
//! Real: the step, the policy-built labels, the in-memory store's transactions (jobs, requests,
//! repositories, audit records). **Fake, and labelled so:** the store (`InMemoryStore`), the
//! status writer (`FakeIssueStatusWriter`, in front of a decorator that fails or stalls on
//! demand), the change host (it only ends credentials) and the clock. The GitHub adapter is tested
//! on its own in `crates/github/tests/issue_status.rs`; nothing here reaches GitHub.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use factory_composition::hooks::BeforeClaim as _;
use factory_composition::indexing::ActiveJobs;
use factory_composition::issue_status::{
    FAILED, FIRST_BACKOFF, IssueStatusDeps, IssueStatusReporter, MAX_TRIES, MAX_UPDATES_PER_MINUTE,
    WRITTEN,
};
use factory_composition::redaction::redactor_from_policy;
use factory_composition::startup::load_policy;
use factory_domain::ids::{CorrelationId, JobId, PrincipalId, RepositoryId, TenantId};
use factory_domain::policy::issue_workflow::StatusLabel;
use factory_domain::scope::TenantScope;
use factory_domain::state::{Guard, JobEvent, JobStatus};
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::{AutonomyLevel, ExecutionMode, Fidelity, StageKind};
use factory_ports::clock::Uuid;
use factory_ports::githost::{ChangeHost, GitHostError, GitScope, IssueRef};
use factory_ports::issue_status::{
    CommentWrite, IssueStatusWriter, LabelOutcome, StatusComment, StatusScope, StatusStamp,
};
use factory_ports::paths::RepoRef;
use factory_ports::store::{
    AppliedTransition, AuditFilter, NewJob, NewOriginalRequest, NewPrincipal, PipelineScope,
    PrincipalKind, RequestSource, Store,
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

    /// A job in `RECEIVED` with the issue its original request names (or none).
    async fn job(&mut self, source_ref: Option<&str>) -> JobId {
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
                source: RequestSource::GithubIssue,
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
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: queued".to_owned()]);
    assert_eq!(rig.comments().len(), 1);
    assert!(rig.comments()[0].contains("waiting in the queue"));

    rig.admit(job).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: working".to_owned()]);
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
    rig.job(Some("acme/widgets#12")).await;
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
        "I have accepted this request and it is waiting in the queue. I will update this comment when something changes."
    );
}

#[tokio::test]
async fn a_success_is_recorded_in_the_audit_log_once_for_each_version() {
    let mut rig = Rig::new();
    let job = rig.job(Some("acme/widgets#12")).await;
    rig.reporter.pass(rig.tenant).await;
    rig.reporter.pass(rig.tenant).await;
    let written = rig.audit(job, WRITTEN).await;
    assert_eq!(written.len(), 1, "{written:?}");
    assert!(written[0].starts_with(&format!("job {} version 1 state RECEIVED", job.as_text())));
    rig.admit(job).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.audit(job, WRITTEN).await.len(), 2);
}

// ---- it never hurts a job ------------------------------------------------------------------------

#[tokio::test]
async fn negative_nt_stat_05_a_failing_github_never_fails_blocks_or_rolls_back_a_job() {
    let mut rig = Rig::new();
    let job = rig.job(Some("acme/widgets#12")).await;
    rig.writer.fail_always(Some(GitHostError::Unavailable));
    rig.reporter.pass(rig.tenant).await;
    assert!(
        rig.labels().is_empty() && rig.comments().is_empty(),
        "nothing was written"
    );
    // The job is exactly where it was and moves on as before.
    assert_eq!(rig.status(job).await, JobStatus::Received);
    rig.admit(job).await;
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
    let job = rig.job(Some("acme/widgets#12")).await;
    let gate = Arc::new(Notify::new());
    *rig.writer.hold.lock().unwrap() = Some(Arc::clone(&gate));
    // The hook returns although the writer is stuck: the write runs in a task of its own.
    tokio::time::timeout(Duration::from_secs(5), rig.reporter.before_claim())
        .await
        .expect("the hook returns at once");
    tokio::task::yield_now().await;
    assert!(rig.labels().is_empty());
    rig.admit(job).await;
    assert_eq!(
        rig.status(job).await,
        JobStatus::Active,
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
    assert_eq!(rig.labels(), vec!["factory: queued".to_owned()]);
}

#[tokio::test]
async fn negative_nt_stat_05_a_transient_failure_waits_a_back_off_and_is_tried_again_and_the_comment_is_still_one()
 {
    let mut rig = Rig::new();
    let job = rig.job(Some("acme/widgets#12")).await;
    // The first comment write fails after the host may have acted; the retry must not duplicate.
    rig.writer.fail_next(vec![GitHostError::Unavailable]);
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 1);
    // Before the back-off ends nothing is tried.
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 1, "no try inside the back-off");
    rig.clock.advance(FIRST_BACKOFF + Duration::from_secs(1));
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: queued".to_owned()]);
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
    let job = rig.job(Some("acme/widgets#12")).await;
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
    rig.admit(job).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: working".to_owned()]);
}

#[tokio::test]
async fn negative_nt_stat_05_a_refusal_that_a_retry_cannot_cure_is_not_retried() {
    let mut rig = Rig::new();
    let job = rig.job(Some("acme/widgets#12")).await;
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
    rig.job(Some("acme/widgets#12")).await;
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
    let job = rig.job(Some("acme/widgets#12")).await;
    rig.admit(job).await;
    let second = rig.another_reporter();
    rig.reporter.pass(rig.tenant).await;
    second.pass(rig.tenant).await;
    assert_eq!(rig.labels(), vec!["factory: working".to_owned()]);
    assert_eq!(rig.comments().len(), 1);
}

#[tokio::test]
async fn a_restarted_worker_does_not_write_again_what_the_audit_log_says_it_wrote() {
    let mut rig = Rig::new();
    let job = rig.job(Some("acme/widgets#12")).await;
    rig.admit(job).await;
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
    let job = rig.job(Some("acme/widgets#12")).await;
    rig.admit(job).await;
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
    let job = rig.job(Some("acme/widgets#12")).await;
    rig.reporter.scan(rig.tenant).await;
    rig.admit(job).await;
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
        ids.push(rig.job(Some("acme/widgets#12")).await);
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
    rig.job(None).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 0);
}

#[tokio::test]
async fn an_issue_in_another_repository_than_the_jobs_is_never_written_on() {
    let mut rig = Rig::new();
    rig.job(Some("acme/other#12")).await;
    rig.job(Some("not a pointer")).await;
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 0);
}

#[tokio::test]
async fn a_repository_that_is_switched_off_gets_nothing_and_a_switch_off_before_the_write_stops_it()
{
    let mut rig = Rig::new();
    rig.job(Some("acme/widgets#12")).await;
    rig.store.disable_repository(rig.repository);
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 0, "switched off when the job was read");
    // The control: enabled, the same job is written.
    let mut rig = Rig::new();
    let job_b = rig.job(Some("acme/widgets#12")).await;
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
    let old = rig.job(Some("acme/widgets#12")).await;
    rig.admit(old).await;
    rig.fail(old).await;
    // A long time passes with no worker looking: the job ended long ago.
    rig.clock.advance(Duration::from_secs(3600));
    rig.reporter.pass(rig.tenant).await;
    assert_eq!(rig.writer.calls(), 0, "history is not rewritten");
    // A job that ended just now is written.
    let fresh = rig.job(Some("acme/widgets#13")).await;
    rig.admit(fresh).await;
    rig.fail(fresh).await;
    rig.reporter.pass(rig.tenant).await;
    assert!(rig.writer.calls() > 0);
}

// ---- the credential of a round -----------------------------------------------------------------------

#[tokio::test]
async fn each_round_uses_a_fresh_session_that_the_sweep_spares_and_that_is_ended_afterwards() {
    let mut rig = Rig::new();
    let job = rig.job(Some("acme/widgets#12")).await;
    rig.reporter.pass(rig.tenant).await;
    rig.admit(job).await;
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
