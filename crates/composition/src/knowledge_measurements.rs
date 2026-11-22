//! The weekly measurement pull request: the snapshot of the last whole week of each project, as a
//! draft pull request into that project's knowledge base (ADR 0029, ADR 0031,
//! `docs/architecture/process-metrics-and-improvement.md`, "The weekly measurement pull request").
//!
//! # When it runs
//!
//! Before each claim ([`BeforeClaim`]), at most once every [`PASS_EVERY`] (one hour) for each
//! tenant the worker serves. A pass reads the facts of the tenant once and looks at the last whole
//! ISO week of each repository the jobs belong to. A repository whose week is settled (proposed,
//! recorded, declined, or with nothing to say) is not looked at again for that week by this
//! process. A pass that could not finish for a repository tries it again at the next pass.
//!
//! # What it never does
//!
//! It never fails a claim or a job: a failure is logged. It never merges and never writes to the
//! default branch: the port offers neither, and it writes only the branch
//! `factory/knowledge-measurements`. A repository that is not enabled, or whose default branch has
//! no `docs/knowledge/README.md`, gets nothing. A build that does not know its own commit proposes
//! nothing, because a snapshot names the commit that computed it.
//!
//! # The audit trail
//!
//! `knowledge.measurement_proposed` when a pull request was opened or updated, with the week and
//! the number, written by the component `worker.knowledge_measurements`, with no job.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{AuditEventId, CorrelationId, JobId, RepositoryId, TenantId};
use factory_domain::knowledge::{
    EntryId, FactoryEntry, Header, INDEX_FILE, KNOWLEDGE_ROOT, KnowledgeBase, KnowledgeFile,
};
use factory_domain::metrics::{
    ComparisonSettings, LatestMeasurement, ProposalState, WeeklyDecision, WeeklyNothingBecause,
    Window, decide_weekly, has_any_sample, last_whole_week, weekly_pull_request_text,
};
use factory_domain::scope::TenantScope;
use factory_domain::values::{GitSha, Sha256Digest, Slug, Timestamp};
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::{ChangeHost, GitHostError, PullRequestLifecycle, PullRequestRef};
use factory_ports::paths::{RepoPath, RepoRef};
use factory_ports::proposal::{
    FileAt, ProposalBranch, ProposalHost, ProposalMarker, ProposalScope, ProposedFile,
    PullRequestProposal,
};
use factory_ports::store::{AuditAction, AuditActor, AuditDecision, NewAuditEvent, Store};
use factory_workflow::process_metrics::{
    JobRecord, of_repository, read_job_records, repositories_of, snapshot_of, window_facts,
};

use crate::hooks::BeforeClaim;
use crate::indexing::ActiveJobs;
use crate::issue_status::Round;

/// How long one process waits between two passes for the same tenant: one hour.
pub const PASS_EVERY: Duration = Duration::from_secs(60 * 60);

/// The most bytes of the knowledge index the factory reads: 1 MiB.
pub const MAX_INDEX_BYTES: u64 = 1 << 20;

/// The audit action of a measurement pull request that was opened or updated.
pub const PROPOSED: &str = "knowledge.measurement_proposed";

/// The component that writes it.
const ACTOR: &str = "worker.knowledge_measurements";

/// The commit this build was made from, when the build said so in `FACTORY_BUILD_COMMIT`
/// (`infra/service-images/build.sh` sets it for a clean tree). A value that is not a full Git
/// object id counts as none.
#[must_use]
pub fn build_commit() -> Option<GitSha> {
    option_env!("FACTORY_BUILD_COMMIT").and_then(|text| GitSha::parse(text).ok())
}

/// What the weekly step is built from.
pub struct KnowledgeMeasurementsDeps {
    /// The store, on the worker's tenant pool.
    pub store: Arc<dyn Store>,
    /// The code host, through the proposal port.
    pub host: Arc<dyn ProposalHost>,
    /// The change host, to end the credential of each proposal (`revoke_job_tokens`).
    pub changes: Arc<dyn ChangeHost>,
    /// The jobs the process is working on: a proposal's session is noted there while it runs.
    pub jobs: Arc<ActiveJobs>,
    /// The time: the week, and the hour between two passes.
    pub clock: Arc<dyn Clock>,
    /// Fresh identifiers: one session for each proposal, one id for each audit record.
    pub ids: Arc<dyn IdGenerator>,
    /// The tenants this worker serves.
    pub tenants: Vec<TenantId>,
    /// The hash of the policy in force, for the audit records.
    pub policy_hash: Sha256Digest,
    /// The commit of this build, or `None` when it does not know it.
    pub commit: Option<GitSha>,
}

/// Why nothing was proposed for a repository's week.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skipped {
    /// The build does not know its commit.
    NoBuildCommit,
    /// No metric has a sample in the week.
    NoSample,
    /// The repository is not enabled, or its row cannot be read.
    NotEnabled,
    /// The default branch has no `docs/knowledge/README.md`.
    NoKnowledgeBase,
    /// The index is larger than [`MAX_INDEX_BYTES`] or not UTF-8.
    IndexUnreadable,
    /// The decision of the design's table.
    Decided(WeeklyNothingBecause),
}

/// How the week of one repository ended, for a test and the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Measured {
    /// A pull request was opened or updated with the week.
    Proposed(PullRequestRef, EntryId),
    /// Nothing was proposed, and why. The week is settled.
    Skipped(Skipped),
    /// The step could not finish; the next pass tries again.
    Failed(String),
}

/// The weekly step.
pub struct KnowledgeMeasurements {
    deps: KnowledgeMeasurementsDeps,
    last_pass: Mutex<BTreeMap<TenantId, Timestamp>>,
    settled: Mutex<BTreeSet<(TenantId, RepositoryId, EntryId)>>,
}

fn index_path() -> Result<RepoPath, GitHostError> {
    RepoPath::new(&format!("{KNOWLEDGE_ROOT}{INDEX_FILE}")).map_err(|_| GitHostError::Unavailable)
}

/// The text of a file, when it was found, is small enough and is UTF-8.
fn text_of(found: FileAt) -> Result<Option<String>, Skipped> {
    match found {
        FileAt::Missing => Ok(None),
        FileAt::TooLarge => Err(Skipped::IndexUnreadable),
        FileAt::Found(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| Skipped::IndexUnreadable),
    }
}

/// The week right before `window`, of the same length.
fn week_before(window: Window) -> Option<Window> {
    let length = window.to().duration_since(&window.from())?;
    Window::new(window.from().checked_sub(length)?, window.from()).ok()
}

impl KnowledgeMeasurements {
    /// The step, over its collaborators.
    #[must_use]
    pub fn new(deps: KnowledgeMeasurementsDeps) -> Self {
        Self {
            deps,
            last_pass: Mutex::new(BTreeMap::new()),
            settled: Mutex::new(BTreeSet::new()),
        }
    }

    /// One pass for one tenant, unless one ran less than an hour ago. Returns what happened to
    /// each repository it looked at.
    pub async fn pass(&self, tenant: TenantId) -> Vec<(RepositoryId, Measured)> {
        let now = self.deps.clock.now();
        {
            let mut last = self
                .last_pass
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if last
                .get(&tenant)
                .is_some_and(|at| now.duration_since(at).is_some_and(|d| d < PASS_EVERY))
            {
                return Vec::new();
            }
            last.insert(tenant, now);
        }
        let Ok(week) = last_whole_week(now) else {
            return Vec::new();
        };
        let Ok(mut tx) = self.deps.store.begin(TenantScope::new(tenant)).await else {
            tracing::warn!("the weekly measurement cannot read the store; it is tried again later");
            return Vec::new();
        };
        let records = read_job_records(tx.as_mut()).await;
        let _ = tx.rollback().await;
        let Ok(records) = records else {
            tracing::warn!("the weekly measurement cannot read the facts; it is tried again later");
            return Vec::new();
        };
        let mut done = Vec::new();
        for repository in repositories_of(&records) {
            let id = EntryId::parse(&week.identifier());
            let Ok(id) = id else { continue };
            if self
                .settled
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains(&(tenant, repository, id.clone()))
            {
                continue;
            }
            let measured = self
                .propose_for(
                    tenant,
                    repository,
                    &of_repository(&records, repository),
                    week,
                )
                .await;
            if !matches!(measured, Measured::Failed(_)) {
                self.settled
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert((tenant, repository, id));
            }
            done.push((repository, measured));
        }
        done
    }

    /// Proposes the week `week` of one repository from the records of its jobs.
    pub async fn propose_for(
        &self,
        tenant: TenantId,
        repository: RepositoryId,
        records: &[JobRecord],
        week: Window,
    ) -> Measured {
        let Some(commit) = self.deps.commit.clone() else {
            return Measured::Skipped(Skipped::NoBuildCommit);
        };
        match window_facts(records, week) {
            Ok(facts) if has_any_sample(&facts) => {}
            Ok(_) => return Measured::Skipped(Skipped::NoSample),
            Err(error) => return Measured::Failed(error.to_string()),
        }
        let Some(repo) = self.enabled_repository(tenant, repository).await else {
            return Measured::Skipped(Skipped::NotEnabled);
        };
        let session = JobId::from_uuid(self.deps.ids.new_uuid());
        let round = Round::start(
            Arc::clone(&self.deps.jobs),
            Arc::clone(&self.deps.changes),
            session,
            tenant,
        );
        let scope = ProposalScope {
            tenant,
            session,
            repo: repo.clone(),
        };
        let outcome = self.propose(&scope, records, week, commit).await;
        round.finish().await;
        match outcome {
            Ok(Measured::Proposed(pr, id)) => {
                tracing::info!("the weekly measurement pull request was opened or updated");
                self.audit(
                    tenant,
                    &repo,
                    format!(
                        "The factory proposed the process numbers of {id} in pull request {}. A person reviews and merges it; the factory never merges.",
                        pr.number
                    ),
                )
                .await;
                Measured::Proposed(pr, id)
            }
            Ok(other) => other,
            Err(error) => {
                // The error is the caller's answer; the log line says only that.
                tracing::warn!("the weekly measurement could not finish; it is tried again later");
                Measured::Failed(error.to_string())
            }
        }
    }

    async fn enabled_repository(
        &self,
        tenant: TenantId,
        repository: RepositoryId,
    ) -> Option<RepoRef> {
        let mut tx = self.deps.store.begin(TenantScope::new(tenant)).await.ok()?;
        let found = tx.get_repository(repository).await;
        let _ = tx.rollback().await;
        let row = found.ok()?.value;
        if !row.enabled {
            return None;
        }
        RepoRef::parse(&row.full_name).ok()
    }

    async fn propose(
        &self,
        scope: &ProposalScope,
        records: &[JobRecord],
        week: Window,
        commit: GitSha,
    ) -> Result<Measured, GitHostError> {
        let host = &self.deps.host;
        let index = index_path()?;
        let base = host.default_branch(scope).await?;
        let default_index = match text_of(
            host.read_file(scope, &base.commit, &index, MAX_INDEX_BYTES)
                .await?,
        ) {
            Ok(Some(text)) => text,
            Ok(None) => return Ok(Measured::Skipped(Skipped::NoKnowledgeBase)),
            Err(skipped) => return Ok(Measured::Skipped(skipped)),
        };
        let id = EntryId::parse(&week.identifier()).map_err(|_| GitHostError::Unavailable)?;
        let latest = host
            .latest_pull_request(scope, ProposalBranch::KnowledgeMeasurements)
            .await?;
        let found = latest.as_ref().map(|pull| LatestMeasurement {
            state: match pull.lifecycle {
                PullRequestLifecycle::Open => ProposalState::Open,
                PullRequestLifecycle::Merged => ProposalState::Merged,
                PullRequestLifecycle::Closed => ProposalState::Closed,
            },
            week: match &pull.marker {
                Some(ProposalMarker::Measurement(week)) => Some(week.clone()),
                _ => None,
            },
        });
        let decision = decide_weekly(found.as_ref(), &id);
        let index_source = match decision {
            WeeklyDecision::Nothing(because) => {
                return Ok(Measured::Skipped(Skipped::Decided(because)));
            }
            WeeklyDecision::OpenNew => default_index.clone(),
            WeeklyDecision::AddToOpen => {
                // Read the index on the open pull request, so a week it already holds is kept.
                let head = latest
                    .as_ref()
                    .map(|pull| pull.head.clone())
                    .ok_or(GitHostError::Unavailable)?;
                match text_of(
                    host.read_file(scope, &head, &index, MAX_INDEX_BYTES)
                        .await?,
                ) {
                    Ok(Some(text)) => text,
                    Ok(None) => default_index.clone(),
                    Err(skipped) => return Ok(Measured::Skipped(skipped)),
                }
            }
        };

        let measurement = snapshot_of(
            records,
            week,
            week_before(week),
            commit,
            ComparisonSettings::default(),
        )
        .map_err(|_| GitHostError::Unavailable)?;
        let entry = measurement
            .render_entry()
            .map_err(|_| GitHostError::Unavailable)?;
        let header = FactoryEntry::check(
            id.as_str(),
            "measurement",
            &measurement.window.title(),
            None,
        )
        .map_err(|_| GitHostError::Unavailable)?;
        let file = KnowledgeFile {
            file: measurement.entry_path(),
            header: Header::Factory(header),
        };
        let new_index = KnowledgeBase::insert_index_line(&index_source, &file);
        let recorded = KnowledgeBase::listed_measurements(&default_index);
        let held: Vec<EntryId> = KnowledgeBase::listed_measurements(&new_index)
            .into_iter()
            .filter(|listed| !recorded.contains(listed))
            .collect();
        let (title, body) =
            weekly_pull_request_text(week, &held).map_err(|_| GitHostError::Unavailable)?;
        let entry_path = RepoPath::new(&format!("{KNOWLEDGE_ROOT}{}", file.file))
            .map_err(|_| GitHostError::Unavailable)?;
        let pr = host
            .propose(
                scope,
                &PullRequestProposal {
                    branch: ProposalBranch::KnowledgeMeasurements,
                    base,
                    marker: ProposalMarker::Measurement(id.clone()),
                    files: vec![
                        ProposedFile {
                            path: entry_path,
                            bytes: entry.into_bytes(),
                        },
                        ProposedFile {
                            path: index,
                            bytes: new_index.into_bytes(),
                        },
                    ],
                    title,
                    body,
                },
            )
            .await?;
        Ok(Measured::Proposed(pr, id))
    }

    async fn audit(&self, tenant: TenantId, repo: &RepoRef, reason: String) {
        let (Ok(actor), Ok(action)) = (Slug::parse(ACTOR), AuditAction::new(PROPOSED)) else {
            return;
        };
        let id = AuditEventId::from_uuid(self.deps.ids.new_uuid());
        let event = NewAuditEvent {
            id,
            actor: AuditActor::System(actor),
            action,
            subject: format!("repository {repo}"),
            decision: AuditDecision::Allow,
            reason: reason.chars().take(1000).collect(),
            policy_hash: self.deps.policy_hash.clone(),
            job: None,
            stage_run: None,
            correlation_id: CorrelationId::from_uuid(id.as_uuid()),
        };
        let Ok(mut tx) = self.deps.store.begin(TenantScope::new(tenant)).await else {
            tracing::warn!(
                "the weekly measurement cannot write its audit record: the store is unavailable"
            );
            return;
        };
        if tx.record_audit(event).await.is_ok() {
            let _ = tx.commit().await;
        } else {
            let _ = tx.rollback().await;
        }
    }
}

#[async_trait(?Send)]
impl BeforeClaim for KnowledgeMeasurements {
    async fn before_claim(&self) {
        for tenant in &self.deps.tenants {
            self.pass(*tenant).await;
        }
    }
}
