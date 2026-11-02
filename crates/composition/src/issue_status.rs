//! Showing the state of a job on its issue (ports v1.2, ADR 0017).
//!
//! After a job changes state, the worker writes one `factory: <state>` label and keeps one status
//! comment up to date on the issue the job came from. The labels and the comment are
//! **observability**. They decide nothing, no job waits for them, and a failure to write them
//! never fails, blocks or undoes a job.
//!
//! # How a change reaches the issue
//!
//! * **The job row is the source.** A state change commits in the engine's transaction, as before.
//!   Before each claim, [`IssueStatusReporter`] reads the job rows of the tenants this worker
//!   serves (outside any transaction of the engine, in a read-only one) and compares each job's
//!   version with the version it has already written. That is level-triggered: a missed signal, a
//!   restart or a second worker cannot lose a change, because the next look sees the same
//!   difference. The outbox is not the read model (ADR 0014); it is a notification record.
//! * **Delivery runs apart from the loop.** The reading takes a few database queries. The writing
//!   to GitHub, with its pauses and retries, runs in a task of its own that the hook starts, so a
//!   slow or failing GitHub never delays a claim.
//! * **Newest wins.** A job that changes twice before the first change is written is written once,
//!   with the newest version. The status comment carries the stamp of the version it shows, and
//!   the adapter never overwrites a newer stamp ([`CommentWrite::Superseded`]); the comment is
//!   written first, and a superseded write skips the label.
//! * **At least once, idempotent.** A write that may have reached GitHub is repeated until it is
//!   known to have: the label call and the comment call are both safe to repeat. A success is
//!   recorded in the audit log as `issue_status.written`, so a restarted worker knows which jobs
//!   it has been writing for and where it stopped.
//! * **Retries with a back-off, then it gives up for that version.** A transient failure waits
//!   30 seconds, then doubles, up to [`MAX_TRIES`] tries. Every failed try is recorded as
//!   `issue_status.failed` with a fixed code, and shows in [`IssueStatusReporter::health`]. The
//!   next version of the job starts again.
//!
//! # What it writes on, and what it never touches
//!
//! * Only for a repository that is registered and **enabled** (checked when the job is read and
//!   again just before the write), and only on the issue that the job's stored original request
//!   names, in the repository of the job. A job that has no original request yet (a job a webhook
//!   made, before intake has fetched and recorded the issue) has no issue the factory has accepted
//!   and gets no status.
//! * A job that was already over when this worker first looked, and that it never wrote for, is
//!   left alone unless it ended within [`ENROL_WINDOW`]: turning the feature on does not rewrite
//!   the history of the repository.
//! * The label comes from the policy and cannot be anything else (`StatusLabel`). The comment is
//!   built from a closed template: the state, the stage, a link. No model output and no text of
//!   the issue is in it ([`status_text`]).
//!
//! # Write amplification
//!
//! GitHub asks an integration to make changes serially, one second apart (see the adapter). This
//! step makes at most [`MAX_UPDATES_PER_MINUTE`] updates a minute, one at a time, and one update
//! is a few requests. A flood of state changes therefore turns into a bounded trickle, newest
//! version first for each job.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{AuditEventId, CorrelationId, JobId, RepositoryId, TenantId};
use factory_domain::policy::issue_workflow::StatusLabels;
use factory_domain::redaction::Redactor;
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, StageRunStatus, Status as _};
use factory_domain::values::{AggregateVersion, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::StageKind;
use factory_github::percent_encode_component;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::{ChangeHost, GitHostError, IssueRef};
use factory_ports::issue_status::{
    CommentWrite, IssueStatusWriter, StatusComment, StatusScope, StatusStamp,
};
use factory_ports::paths::RepoRef;
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, AuditFilter, Job, JobFilter, NewAuditEvent, Store,
    StoreError, Tx, Versioned,
};

use crate::delivery::job_branch;
use crate::health::CheckResult;
use crate::hooks::BeforeClaim;
use crate::indexing::ActiveJobs;
use crate::seams::issue_of;

/// The audit action of a status that was written. The worker writes it. The API's database
/// trigger does not list it, so a row with this action did not come from the API.
pub const WRITTEN: &str = "issue_status.written";

/// The audit action of a try that failed, with a fixed code in its reason.
pub const FAILED: &str = "issue_status.failed";

/// The component that writes both records.
const ACTOR: &str = "worker.issue-status";

/// How many tries one version of a job gets before the step gives up on it.
pub const MAX_TRIES: u32 = 6;

/// The wait before the second try. It doubles for each try after.
pub const FIRST_BACKOFF: Duration = Duration::from_secs(30);

/// The longest wait between two tries.
pub const LONGEST_BACKOFF: Duration = Duration::from_secs(20 * 60);

/// The most updates made in one minute, across all tenants of this worker.
pub const MAX_UPDATES_PER_MINUTE: usize = 6;

/// How long after the end of a job this worker still writes its last state when it has never
/// written for the job before.
pub const ENROL_WINDOW: Duration = Duration::from_secs(15 * 60);

/// The jobs read in one page.
const PAGE: u32 = 200;
/// The pages of open jobs read for one tenant in one scan.
const OPEN_PAGES: usize = 5;
/// The newest jobs of any state read for one tenant in one scan.
const RECENT: u32 = 100;
/// New jobs looked into in one scan of one tenant. The others wait for the next scan.
const CANDIDATES_PER_SCAN: usize = 50;
/// Jobs that left the open list and are read by id in one scan of one tenant.
const LEFT_PER_SCAN: usize = 100;
/// The most updates waiting at once.
const PENDING_CAP: usize = 1_000;
/// The pages of a job's audit records read to find where it stopped writing.
const AUDIT_PAGES: usize = 10;
/// The jobs remembered. Past this the memory is cleared and rebuilt from the audit log.
const SEEN_CAP: usize = 100_000;
/// The updates one delivery task makes before it ends and the next hook starts another.
const PER_TASK: usize = 20;

/// Why a try did not work. The set is closed, and it is what the audit log and the health report
/// say: never a message from GitHub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureCode {
    /// GitHub could not be reached, or answered with a server error.
    Unavailable,
    /// GitHub asked the worker to slow down.
    RateLimited,
    /// GitHub refused the credential: the App does not hold `issues: write` here.
    Forbidden,
    /// The issue or the repository is not there for this installation.
    NotFound,
    /// The text or the label was refused before it was sent.
    Refused,
    /// The credential was ended while the write ran, or the comment changed under the call.
    Interrupted,
    /// The repository was switched off or the issue is no longer the job's.
    NotAllowed,
}

impl FailureCode {
    /// The word in the audit record and in the health report.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::RateLimited => "rate_limited",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Refused => "refused",
            Self::Interrupted => "interrupted",
            Self::NotAllowed => "not_allowed",
        }
    }

    /// True when trying again can help.
    #[must_use]
    pub const fn can_be_retried(self) -> bool {
        matches!(
            self,
            Self::Unavailable | Self::RateLimited | Self::Interrupted
        )
    }

    fn of(error: &GitHostError) -> Self {
        match error {
            GitHostError::Unavailable => Self::Unavailable,
            GitHostError::RateLimited { .. } => Self::RateLimited,
            GitHostError::Forbidden => Self::Forbidden,
            GitHostError::NotFound => Self::NotFound,
            GitHostError::Unauthorized | GitHostError::Conflict => Self::Interrupted,
            GitHostError::UnsafeText
            | GitHostError::BranchNotAllowed
            | GitHostError::Rejected(_) => Self::Refused,
        }
    }
}

/// What the step reports about itself, for the health report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatusHealth {
    /// Updates waiting to be written.
    pub pending: usize,
    /// Updates that failed their last try and will be tried again.
    pub retrying: usize,
    /// Versions the step gave up on since it started.
    pub gave_up: u64,
    /// Updates written since it started.
    pub written: u64,
    /// The code of the last failed try, if there was one.
    pub last_failure: Option<FailureCode>,
}

/// The sentence for the stage a job is in. A closed list: it grows only with the stage kinds.
#[must_use]
pub const fn stage_phrase(stage: StageKind) -> &'static str {
    match stage {
        StageKind::Intake => "reading the request",
        StageKind::RepositoryIntelligence => "studying the repository",
        StageKind::Specification => "writing the specification",
        StageKind::DomainDiscovery => "checking the details of the subject",
        StageKind::Architecture => "designing the change",
        StageKind::TaskPlanning => "planning the tasks",
        StageKind::Implementation => "writing the code",
        StageKind::Validation => "running the checks",
        StageKind::Review => "reviewing the change",
        StageKind::Documenting => "writing the documentation",
        StageKind::DocumentationReview => "reviewing the documentation",
        StageKind::Delivery => "preparing the pull request",
        StageKind::Approval => "going through the approval step",
        StageKind::Merge => "finishing up",
    }
}

/// The link to the draft pull request of a finished job: the list of pull requests of the
/// repository, narrowed to the job's branch. A link to `github.com`, the one host the output
/// hygiene allows.
#[must_use]
pub fn pull_request_link(repo: &RepoRef, job: JobId) -> Option<String> {
    let branch = job_branch(job).ok()?;
    Some(format!(
        "https://github.com/{}/{}/pulls?q=head%3A{}",
        repo.owner(),
        repo.name(),
        percent_encode_component(branch.as_str())
    ))
}

/// The text of the status comment. A closed template: the state, the stage, one link. It holds no
/// model output, nothing the issue said, and no identifier. The stamp that identifies the job and
/// its version is in the hidden marker the adapter adds.
#[must_use]
pub fn status_text(state: JobStatus, stage: Option<StageKind>, link: Option<&str>) -> String {
    let doing = stage.map(stage_phrase);
    let mut text = match state {
        JobStatus::Received => "I have accepted this request and it is waiting in the queue.".to_owned(),
        JobStatus::Active => match doing {
            Some(doing) => format!("I am working on this now. At the moment I am {doing}."),
            None => "I am working on this now.".to_owned(),
        },
        JobStatus::WaitingForHuman => match doing {
            Some(doing) => format!(
                "I need a person to answer a question or make a decision before I can go on. I stopped while {doing}."
            ),
            None => "I need a person to answer a question or make a decision before I can go on."
                .to_owned(),
        },
        JobStatus::Paused => {
            "An operator paused this work. It will carry on when they resume it.".to_owned()
        }
        JobStatus::Blocked => match doing {
            Some(doing) => format!(
                "I stopped while {doing}, because a check could not run or something is missing. A person needs to look at it and decide how to go on."
            ),
            None => "I stopped because a check could not run or something is missing. A person needs to look at it and decide how to go on.".to_owned(),
        },
        JobStatus::Cancelling => "This work is being stopped.".to_owned(),
        JobStatus::Completed => match link {
            Some(link) => format!(
                "The work is finished. A draft pull request is ready for review: [open pull requests of this job]({link}). A person has to review it and merge it."
            ),
            None => "The work is finished. A draft pull request is ready for review. A person has to review it and merge it.".to_owned(),
        },
        JobStatus::Failed => "The work stopped because it could not be finished, and no retry is left. The factory's job log has the details; ask the person who manages the factory for this repository.".to_owned(),
        JobStatus::Cancelled => "An operator cancelled this work. Nothing more will happen on this issue unless someone asks again.".to_owned(),
        JobStatus::Rejected => "This work was rejected: either the request was refused at the start, or an approver turned the result down.".to_owned(),
    };
    if !state.is_terminal() {
        text.push_str(" I will update this comment when something changes.");
    }
    text
}

/// What the step is built from.
pub struct IssueStatusDeps {
    /// The store, on the worker's tenant pool.
    pub store: Arc<dyn Store>,
    /// Writes the label and the comment.
    pub writer: Arc<dyn IssueStatusWriter>,
    /// Ends the credential of a round of writes.
    pub host: Arc<dyn ChangeHost>,
    /// The label of each job state, from the policy.
    pub labels: Arc<StatusLabels>,
    /// Time.
    pub clock: Arc<dyn Clock>,
    /// Identifiers for the rounds of writes.
    pub ids: Arc<dyn IdGenerator>,
    /// Jobs the process is working on. A round of writes notes its identifier here so that the
    /// sweep of ended jobs leaves its credential alone.
    pub jobs: Arc<ActiveJobs>,
    /// The tenants this worker serves.
    pub tenants: Vec<TenantId>,
    /// The hash of the policy in force, written on the records.
    pub policy_hash: Sha256Digest,
    /// The one redactor of the process. A comment with a secret in it is not written.
    pub redactor: Arc<Redactor>,
}

#[derive(Debug, Clone)]
struct Pending {
    tenant: TenantId,
    job: JobId,
    correlation: CorrelationId,
    status: JobStatus,
    version: AggregateVersion,
    started: Timestamp,
    repository: RepositoryId,
    repo: RepoRef,
    issue: IssueRef,
    stage: Option<StageKind>,
    failures: u32,
    not_before: Option<Timestamp>,
}

#[derive(Default)]
struct State {
    /// The newest version written, or known to need no write, for each job.
    seen: HashMap<JobId, i64>,
    /// Jobs a scan found open, by tenant, so that one that leaves the list is read by id.
    open: HashMap<TenantId, HashSet<JobId>>,
    /// What waits to be written: one entry for each job, the newest version.
    pending: BTreeMap<JobId, Pending>,
    /// The version of each job that a delivery has taken off the queue and is writing now. A scan
    /// that meets the same version counts it as settled, so a failed try is not queued again at
    /// once, with no back-off.
    in_flight: HashMap<JobId, i64>,
    /// When the last updates were made, for the rate bound.
    recent_updates: VecDeque<Timestamp>,
    health: StatusHealth,
}

/// Writes the state of the jobs of this worker's tenants onto their issues. A step before each
/// claim ([`BeforeClaim`]).
pub struct IssueStatusReporter {
    inner: Arc<Inner>,
}

struct Inner {
    deps: IssueStatusDeps,
    state: Mutex<State>,
    delivering: AtomicBool,
}

/// Lets the next delivery task start when this one ends, also when it panics.
struct Releasing(Arc<Inner>);

impl Drop for Releasing {
    fn drop(&mut self) {
        self.0.delivering.store(false, Ordering::SeqCst);
    }
}

impl IssueStatusReporter {
    /// The step, over its collaborators.
    #[must_use]
    pub fn new(deps: IssueStatusDeps) -> Self {
        Self {
            inner: Arc::new(Inner {
                deps,
                state: Mutex::new(State::default()),
                delivering: AtomicBool::new(false),
            }),
        }
    }

    /// Reads the jobs of one tenant and notes what has to be written. A few read-only queries.
    pub async fn scan(&self, tenant: TenantId) {
        self.inner.scan(tenant).await;
    }

    /// Writes what is due, one update at a time, until nothing is due or the bound of the minute
    /// is reached. The hook starts this in a task of its own; a test awaits it.
    pub async fn deliver_due(&self) {
        self.inner.deliver_due().await;
    }

    /// A scan of one tenant followed by the writes that are due. Used by tests and tools; the
    /// worker loop uses [`BeforeClaim`], which does not wait for the writes.
    pub async fn pass(&self, tenant: TenantId) {
        self.scan(tenant).await;
        self.deliver_due().await;
    }

    /// What the step reports about itself.
    #[must_use]
    pub fn health(&self) -> StatusHealth {
        let state = self.inner.state();
        StatusHealth {
            pending: state.pending.len(),
            retrying: state.pending.values().filter(|p| p.failures > 0).count(),
            ..state.health
        }
    }

    /// The line for the health report. Writing the status is observability: a problem is
    /// *degraded*, and it never makes the process not ready.
    #[must_use]
    pub fn health_check(&self) -> CheckResult {
        let health = self.health();
        match health.last_failure {
            Some(code) if health.retrying > 0 || health.gave_up > 0 => CheckResult::degraded(
                "issue status",
                &format!(
                    "{} update(s) are retrying and {} version(s) were given up; the last failure was {}",
                    health.retrying,
                    health.gave_up,
                    code.word()
                ),
            ),
            _ => CheckResult::pass(
                "issue status",
                &format!(
                    "{} update(s) written, {} waiting",
                    health.written, health.pending
                ),
            ),
        }
    }
}

#[async_trait(?Send)]
impl BeforeClaim for IssueStatusReporter {
    async fn before_claim(&self) {
        for tenant in self.inner.deps.tenants.clone() {
            self.inner.scan(tenant).await;
        }
        if self.inner.has_due() && !self.inner.delivering.swap(true, Ordering::SeqCst) {
            let inner = Arc::clone(&self.inner);
            tokio::spawn(async move {
                let _release = Releasing(Arc::clone(&inner));
                inner.deliver_due().await;
            });
        }
    }
}

fn derived_id(kind: &str, job: JobId, version: AggregateVersion, attempt: u32) -> AuditEventId {
    let digest = Sha256Digest::of(format!("{kind}\n{job}\n{version}\n{attempt}").as_bytes());
    let number = u128::from_str_radix(&digest.hex()[..32], 16).unwrap_or(0);
    AuditEventId::from_uuid(uuid::Builder::from_random_bytes(number.to_be_bytes()).into_uuid())
}

fn backoff(failures: u32) -> Duration {
    let doubled = FIRST_BACKOFF.saturating_mul(2_u32.saturating_pow(failures.saturating_sub(1)));
    doubled.min(LONGEST_BACKOFF)
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn has_due(&self) -> bool {
        let now = self.deps.clock.now();
        self.state()
            .pending
            .values()
            .any(|p| p.not_before.is_none_or(|at| at <= now))
    }

    // ---- reading ----------------------------------------------------------------------------

    async fn scan(&self, tenant: TenantId) {
        let Ok(mut tx) = self.deps.store.begin(TenantScope::new(tenant)).await else {
            tracing::warn!(
                "the jobs cannot be read for the issue status: the store is unavailable"
            );
            return;
        };
        let found = self.scan_in(tenant, &mut *tx).await;
        let _ = tx.rollback().await;
        if found.is_none() {
            tracing::warn!("the jobs cannot be read for the issue status");
        }
    }

    async fn scan_in(&self, tenant: TenantId, tx: &mut dyn Tx) -> Option<()> {
        let mut jobs: Vec<Versioned<Job>> = Vec::new();
        let open: Vec<JobStatus> = JobStatus::ALL
            .iter()
            .copied()
            .filter(|s| !s.is_terminal())
            .collect();
        let mut cursor = None;
        for _ in 0..OPEN_PAGES {
            let page = tx
                .list_jobs(
                    JobFilter {
                        statuses: open.clone(),
                        repository: None,
                    },
                    cursor.clone(),
                    PAGE,
                )
                .await
                .ok()?;
            jobs.extend(page.rows);
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        let recent = tx
            .list_jobs(JobFilter::default(), None, RECENT)
            .await
            .ok()?
            .rows;
        let listed_open: HashSet<JobId> = jobs.iter().map(|j| j.value.id).collect();
        jobs.extend(
            recent
                .into_iter()
                .filter(|j| !listed_open.contains(&j.value.id)),
        );
        // A job that was open at the last scan and is not in either list has moved on, perhaps to
        // an end state, and is older than the newest hundred. Read it by id.
        let left: Vec<JobId> = {
            let state = self.state();
            let listed: HashSet<JobId> = jobs.iter().map(|j| j.value.id).collect();
            state
                .open
                .get(&tenant)
                .map(|known| {
                    known
                        .difference(&listed)
                        .copied()
                        .take(LEFT_PER_SCAN)
                        .collect()
                })
                .unwrap_or_default()
        };
        for id in left {
            match tx.get_job(id).await {
                Ok(job) => jobs.push(job),
                Err(StoreError::NotFound) => {}
                Err(_) => return None,
            }
        }
        {
            let mut state = self.state();
            state.open.insert(
                tenant,
                jobs.iter()
                    .filter(|j| !j.value.status.is_terminal())
                    .map(|j| j.value.id)
                    .collect(),
            );
            if state.seen.len() > SEEN_CAP {
                state.seen.clear();
            }
        }

        let mut looked_into = 0;
        for job in &jobs {
            if self.is_settled(job) {
                continue;
            }
            if looked_into >= CANDIDATES_PER_SCAN {
                break;
            }
            looked_into += 1;
            self.consider(tenant, tx, job).await?;
        }
        Some(())
    }

    /// True when this version of the job is written, queued or known to need no write.
    fn is_settled(&self, job: &Versioned<Job>) -> bool {
        let state = self.state();
        let version = job.version.get();
        state.seen.get(&job.value.id).is_some_and(|v| *v >= version)
            || state
                .in_flight
                .get(&job.value.id)
                .is_some_and(|v| *v >= version)
            || state
                .pending
                .get(&job.value.id)
                .is_some_and(|p| p.version.get() >= version)
    }

    async fn consider(
        &self,
        tenant: TenantId,
        tx: &mut dyn Tx,
        job: &Versioned<Job>,
    ) -> Option<()> {
        let id = job.value.id;
        // Where did this worker stop for this job? Asked once for each job it meets.
        let first_sight = !self.state().seen.contains_key(&id);
        let enrolled = if first_sight {
            let prior = self.prior_version(tx, id).await?;
            self.state().seen.insert(id, prior.unwrap_or(0));
            prior.is_some()
        } else {
            true
        };
        if self.is_settled(job) {
            return Some(());
        }
        let now = self.deps.clock.now();
        if job.value.status.is_terminal() && !enrolled {
            let recent = job
                .value
                .terminal_at
                .as_ref()
                .and_then(|at| at.checked_add(ENROL_WINDOW))
                .is_some_and(|end| end > now);
            if !recent {
                self.state().seen.insert(id, job.version.get());
                return Some(());
            }
        }
        let Some(target) = self.resolve(tx, job).await? else {
            // Not a job the factory has accepted on an issue, yet. A job that is over never
            // will be.
            if job.value.status.is_terminal() {
                self.state().seen.insert(id, job.version.get());
            }
            return Some(());
        };
        let pending = Pending {
            tenant,
            job: id,
            correlation: job.value.correlation_id,
            status: job.value.status,
            version: job.version,
            started: job.value.created_at,
            repository: job.value.repository,
            repo: target.repo,
            issue: target.issue,
            stage: target.stage,
            failures: 0,
            not_before: None,
        };
        let mut state = self.state();
        if state.pending.len() < PENDING_CAP || state.pending.contains_key(&id) {
            state.pending.insert(id, pending);
        }
        Some(())
    }

    /// The newest version of the job that this worker wrote, from the audit log.
    async fn prior_version(&self, tx: &mut dyn Tx, job: JobId) -> Option<Option<i64>> {
        let mut after = 0;
        let mut newest: Option<i64> = None;
        for _ in 0..AUDIT_PAGES {
            let page = tx
                .read_audit(AuditFilter::Job(job), after, PAGE)
                .await
                .ok()?;
            let count = page.len();
            for record in &page {
                after = record.sequence;
                if record.event.action.as_str() == WRITTEN
                    && matches!(&record.event.actor, AuditActor::System(who) if who.as_str() == ACTOR)
                    && let Some(version) = written_version(&record.event.subject)
                {
                    newest = newest.max(Some(version));
                }
            }
            if u32::try_from(count).unwrap_or(u32::MAX) < PAGE {
                break;
            }
        }
        Some(newest)
    }

    /// The issue a job's status goes on, when the factory has accepted it for the job: the job's
    /// stored original request names it, it is in the job's own repository, and the repository is
    /// registered and enabled. `None` for anything less; `None` of the outer option when the store
    /// cannot answer.
    async fn resolve(&self, tx: &mut dyn Tx, job: &Versioned<Job>) -> Option<Option<Target>> {
        let request = match tx.get_original_request(job.value.id, None).await {
            Ok(request) => request,
            Err(StoreError::NotFound) => return Some(None),
            Err(_) => return None,
        };
        let repository = match tx.get_repository(job.value.repository).await {
            Ok(repository) => repository.value,
            Err(StoreError::NotFound) => return Some(None),
            Err(_) => return None,
        };
        let Some(issue) = request.source_ref.as_deref().and_then(issue_of) else {
            return Some(None);
        };
        let Ok(repo) = RepoRef::parse(&repository.full_name) else {
            return Some(None);
        };
        if !repository.enabled
            || !issue
                .repo
                .to_string()
                .eq_ignore_ascii_case(&repo.to_string())
        {
            return Some(None);
        }
        let stage = match tx.list_stage_runs(job.value.id).await {
            Ok(runs) => current_stage(runs.iter().map(|r| (r.value.kind, r.value.status))),
            Err(_) => return None,
        };
        Some(Some(Target { repo, issue, stage }))
    }

    // ---- writing ----------------------------------------------------------------------------

    async fn deliver_due(&self) {
        for _ in 0..PER_TASK {
            let Some(item) = self.next_due() else {
                return;
            };
            self.deliver(item).await;
        }
    }

    /// The next update that is due, taken off the queue, or `None`.
    fn next_due(&self) -> Option<Pending> {
        let now = self.deps.clock.now();
        let mut state = self.state();
        while let Some(front) = state.recent_updates.front() {
            if front
                .checked_add(Duration::from_secs(60))
                .is_some_and(|end| end <= now)
            {
                state.recent_updates.pop_front();
            } else {
                break;
            }
        }
        if state.recent_updates.len() >= MAX_UPDATES_PER_MINUTE {
            return None;
        }
        let id = state
            .pending
            .values()
            .find(|p| p.not_before.is_none_or(|at| at <= now))
            .map(|p| p.job)?;
        let item = state.pending.remove(&id)?;
        state.in_flight.insert(item.job, item.version.get());
        state.recent_updates.push_back(now);
        Some(item)
    }

    async fn deliver(&self, item: Pending) {
        let outcome = self.write(&item).await;
        let job = item.job;
        match outcome {
            Ok(()) => {
                {
                    let mut state = self.state();
                    state.seen.insert(item.job, item.version.get());
                    state.health.written += 1;
                }
                self.record(&item, WRITTEN, AuditDecision::Record, 0, None)
                    .await;
            }
            Err(code) => self.failed(item, code).await,
        }
        self.state().in_flight.remove(&job);
    }

    async fn failed(&self, mut item: Pending, code: FailureCode) {
        item.failures += 1;
        let give_up = !code.can_be_retried() || item.failures >= MAX_TRIES;
        let now = self.deps.clock.now();
        {
            let mut state = self.state();
            state.health.last_failure = Some(code);
            if give_up {
                state.health.gave_up += 1;
                // Settled for this version: the next version of the job starts again.
                state.seen.insert(item.job, item.version.get());
            } else {
                let wait = backoff(item.failures);
                item.not_before = now.checked_add(wait);
                // A newer version that a scan queued meanwhile replaces this one.
                state
                    .pending
                    .entry(item.job)
                    .or_insert_with(|| item.clone());
            }
        }
        tracing::warn!(
            code = code.word(),
            tries = item.failures,
            gave_up = give_up,
            "the state of a job could not be written on its issue; the job is not affected"
        );
        self.record(
            &item,
            FAILED,
            AuditDecision::Deny,
            item.failures,
            Some((code, give_up)),
        )
        .await;
    }

    /// One update: the comment first (it carries the stamp that settles a race), then the label.
    async fn write(&self, item: &Pending) -> Result<(), FailureCode> {
        // The repository must still be enabled and the issue must still be the job's.
        if !self.still_allowed(item).await? {
            return Err(FailureCode::NotAllowed);
        }
        let link = (item.status == JobStatus::Completed)
            .then(|| pull_request_link(&item.repo, item.job))
            .flatten();
        let text = status_text(item.status, item.stage, link.as_deref());
        if self
            .deps
            .redactor
            .contains_secret(text.as_bytes())
            .unwrap_or(true)
        {
            return Err(FailureCode::Refused);
        }
        let stamp = StatusStamp {
            started: item.started,
            version: item.version,
            job: item.job,
        };
        let comment = StatusComment::new(stamp, text).map_err(|_| FailureCode::Refused)?;
        let label = self.deps.labels.label_for(item.status);

        // A fresh identifier for the credential of this round. The sweep of ended jobs spares it
        // while the round runs, and the credential is ended when the round is over.
        let session = JobId::from_uuid(self.deps.ids.new_uuid());
        self.deps.jobs.enter(session, item.tenant);
        let scope = StatusScope {
            tenant: item.tenant,
            session,
            repo: item.repo.clone(),
        };
        let done = async {
            let written = self
                .deps
                .writer
                .upsert_status_comment(&scope, &item.issue, &comment)
                .await
                .map_err(|e| FailureCode::of(&e))?;
            if matches!(written, CommentWrite::Superseded(_)) {
                // A newer update owns the issue. Its label is its own to write.
                return Ok(());
            }
            self.deps
                .writer
                .set_status_label(&scope, &item.issue, label)
                .await
                .map(|_| ())
                .map_err(|e| FailureCode::of(&e))
        }
        .await;
        let _ = self.deps.host.revoke_job_tokens(session).await;
        self.deps.jobs.leave(session);
        done
    }

    async fn still_allowed(&self, item: &Pending) -> Result<bool, FailureCode> {
        let mut tx = self
            .deps
            .store
            .begin(TenantScope::new(item.tenant))
            .await
            .map_err(|_| FailureCode::Unavailable)?;
        let found = tx.get_repository(item.repository).await;
        let _ = tx.rollback().await;
        match found {
            Ok(repository) => Ok(repository.value.enabled),
            Err(StoreError::NotFound) => Ok(false),
            Err(_) => Err(FailureCode::Unavailable),
        }
    }

    /// Writes one audit record. A failure to write it is logged and nothing else.
    async fn record(
        &self,
        item: &Pending,
        action: &str,
        decision: AuditDecision,
        attempt: u32,
        failure: Option<(FailureCode, bool)>,
    ) {
        let (Ok(actor), Ok(action)) = (Slug::parse(ACTOR), AuditAction::new(action)) else {
            return;
        };
        let reason = match failure {
            None => "The state of the job was written on its issue.".to_owned(),
            Some((code, true)) => format!(
                "The state of the job could not be written on its issue and the step gave up on this version: {}.",
                code.word()
            ),
            Some((code, false)) => format!(
                "The state of the job could not be written on its issue and will be tried again: {}.",
                code.word()
            ),
        };
        let event = NewAuditEvent {
            id: derived_id(action.as_str(), item.job, item.version, attempt),
            actor: AuditActor::System(actor),
            action,
            // Identifiers, a number and a fixed word: nothing the issue or a model wrote.
            subject: format!(
                "job {} version {} state {}",
                item.job.as_text(),
                item.version,
                item.status.as_str()
            ),
            decision,
            reason,
            policy_hash: self.deps.policy_hash.clone(),
            job: Some(item.job),
            stage_run: None,
            correlation_id: item.correlation,
        };
        let Ok(mut tx) = self.deps.store.begin(TenantScope::new(item.tenant)).await else {
            tracing::warn!("an issue status record could not be written: the store is unavailable");
            return;
        };
        let written = match tx.record_audit(event).await {
            Ok(_) | Err(StoreError::Constraint(_)) => tx.commit().await.is_ok(),
            Err(_) => {
                let _ = tx.rollback().await;
                false
            }
        };
        if !written {
            tracing::warn!("an issue status record could not be written");
        }
    }
}

struct Target {
    repo: RepoRef,
    issue: IssueRef,
    stage: Option<StageKind>,
}

/// The version in the subject of a `issue_status.written` record, in the words
/// `job <id> version <n> state <STATE>`.
fn written_version(subject: &str) -> Option<i64> {
    let mut words = subject.split(' ');
    (words.next()? == "job").then_some(())?;
    words.next()?;
    (words.next()? == "version").then_some(())?;
    words.next()?.parse().ok()
}

/// The stage a job is in: the furthest stage of the pipeline that has a run in motion, or none.
fn current_stage(runs: impl Iterator<Item = (StageKind, StageRunStatus)>) -> Option<StageKind> {
    let order = |kind: StageKind| StageKind::ALL.iter().position(|k| *k == kind);
    runs.filter(|(_, status)| {
        matches!(
            status,
            StageRunStatus::Ready
                | StageRunStatus::Running
                | StageRunStatus::Gating
                | StageRunStatus::WaitingForHuman
                | StageRunStatus::Blocked
        )
    })
    .map(|(kind, _)| kind)
    .max_by_key(|kind| order(*kind))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_state_has_a_text_and_a_stage_has_a_phrase_and_no_text_holds_an_identifier() {
        for state in JobStatus::ALL {
            for stage in [None, Some(StageKind::Validation)] {
                let text = status_text(*state, stage, Some("https://github.com/o/r/pulls?q=x"));
                assert!(text.len() > 20, "{state:?}");
                assert!(text.ends_with('.'), "{state:?}: {text}");
                assert!(!text.contains("job-"), "{text}");
                assert!(!text.contains(state.as_str()), "{text}");
                assert!(!text.contains("factory:"), "{text}");
            }
        }
        for stage in StageKind::ALL {
            assert!(!stage_phrase(*stage).is_empty());
        }
    }

    #[test]
    fn a_working_job_names_its_stage_and_a_finished_one_links_the_pull_request() {
        let working = status_text(JobStatus::Active, Some(StageKind::Implementation), None);
        assert!(working.contains("writing the code"), "{working}");
        assert!(working.contains("I will update this comment"));
        let done = status_text(
            JobStatus::Completed,
            None,
            Some("https://github.com/o/r/pulls?q=x"),
        );
        assert!(
            done.contains("(https://github.com/o/r/pulls?q=x)"),
            "{done}"
        );
        assert!(
            !done.contains("I will update"),
            "a finished job promises no update"
        );
        let without = status_text(JobStatus::Completed, None, None);
        assert!(!without.contains("http"));
    }

    #[test]
    fn the_backoff_doubles_and_has_a_ceiling() {
        assert_eq!(backoff(1), Duration::from_secs(30));
        assert_eq!(backoff(2), Duration::from_secs(60));
        assert_eq!(backoff(3), Duration::from_secs(120));
        assert_eq!(backoff(40), LONGEST_BACKOFF);
    }

    #[test]
    fn the_written_record_reads_back_as_its_version() {
        assert_eq!(
            written_version("job 018f3e4a-0000-7000-8000-000000000001 version 7 state ACTIVE"),
            Some(7)
        );
        assert_eq!(written_version("job x version seven state ACTIVE"), None);
        assert_eq!(written_version("something else"), None);
    }

    #[test]
    fn the_current_stage_is_the_furthest_one_in_motion() {
        let runs = [
            (StageKind::Intake, StageRunStatus::Passed),
            (StageKind::Specification, StageRunStatus::Running),
            (StageKind::Architecture, StageRunStatus::Pending),
        ];
        assert_eq!(
            current_stage(runs.into_iter()),
            Some(StageKind::Specification)
        );
        assert_eq!(current_stage(std::iter::empty()), None);
    }

    #[test]
    fn a_failure_code_says_whether_a_retry_can_help() {
        assert!(FailureCode::Unavailable.can_be_retried());
        assert!(FailureCode::RateLimited.can_be_retried());
        assert!(!FailureCode::Forbidden.can_be_retried());
        assert!(!FailureCode::Refused.can_be_retried());
        assert!(!FailureCode::NotAllowed.can_be_retried());
        assert_eq!(
            FailureCode::of(&GitHostError::RateLimited { retry_after: None }),
            FailureCode::RateLimited
        );
        assert_eq!(
            FailureCode::of(&GitHostError::UnsafeText),
            FailureCode::Refused
        );
    }
}
