//! The rules check: proposes the project's rules for agents as a draft pull request when a
//! repository is onboarded and when the factory's template changes (ADR 0026,
//! `docs/architecture/project-rules.md`).
//!
//! # When it runs
//!
//! * **At onboarding.** [`crate::repository_changes::RepositoryChanges`] calls
//!   [`ProjectRulesSync::onboarded`] after it applied a signed request to register or to enable a
//!   repository, once the change is committed.
//! * **When the factory is updated.** Before each claim ([`BeforeClaim`]), for the repository of
//!   each job that waits for admission, the same set the protection preflight reads. A new release
//!   with a new template version proposes the update at the next job of each repository.
//!
//! One repository is checked at most once every [`RECHECK_AFTER`] (one hour) for the same template
//! version by one process. The onboarding trigger checks at once, whatever the hour says. Every
//! check reads the state on GitHub again, so a restarted worker or a second worker is harmless:
//! the decision is the same, and GitHub refuses a second open pull request from one branch.
//!
//! # What it never does
//!
//! It never fails a request, a claim or a job. A failure is logged and the repository is checked
//! again after the hour. It never merges and never writes to the default branch: the port does not
//! offer either.
//!
//! # The audit trail
//!
//! `project_rules.proposed` when a pull request was opened or updated, with the version and the
//! number; `project_rules.not_proposed` when the installed file cannot be managed (malformed
//! markers, not UTF-8, too large), so the owner learns that a person must repair it. Both are
//! written by the component `worker.project_rules`, with no job.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{AuditEventId, CorrelationId, JobId, RepositoryId, TenantId};
use factory_domain::project_rules::{
    Decision, FileFound, NothingBecause, Proposal, SKELETON, TEMPLATE_VERSION, Template, classify,
    decide, pull_request_text, read_installed, render,
};
use factory_domain::scope::TenantScope;
use factory_domain::state::JobStatus;
use factory_domain::values::{Sha256Digest, Slug, Timestamp};
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::{ChangeHost, GitHostError, PullRequestLifecycle, PullRequestRef};
use factory_ports::paths::{RepoPath, RepoRef};
use factory_ports::project_rules::{
    FileAt, MAX_RULES_FILE_BYTES, ProjectRulesHost, ProposedFile, RULES_FILE, RulesProposal,
    RulesScope,
};
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, JobFilter, NewAuditEvent, Store,
};

use crate::hooks::BeforeClaim;
use crate::indexing::ActiveJobs;
use crate::issue_status::Round;

/// How long one process waits before it checks the same repository again for the same template
/// version: one hour.
pub const RECHECK_AFTER: Duration = Duration::from_secs(60 * 60);

/// The most waiting jobs one pass looks at for one tenant, as the protection preflight.
const PER_PASS: u32 = 50;

/// The audit action of a proposal that was opened or updated.
pub const PROPOSED: &str = "project_rules.proposed";
/// The audit action of an installed file the factory cannot manage.
pub const NOT_PROPOSED: &str = "project_rules.not_proposed";
/// The component that writes both.
const ACTOR: &str = "worker.project_rules";

/// What the check is built from.
pub struct ProjectRulesSyncDeps {
    /// The store, on the worker's tenant pool.
    pub store: Arc<dyn Store>,
    /// The code host, through the port of the rules pull request.
    pub host: Arc<dyn ProjectRulesHost>,
    /// The change host, to end the credential of each check (`revoke_job_tokens`).
    pub changes: Arc<dyn ChangeHost>,
    /// The jobs the process is working on: a check's session is noted there while it runs, so the
    /// sweep of ended jobs does not revoke its credential mid-way.
    pub jobs: Arc<ActiveJobs>,
    /// The time, for the hour between two checks.
    pub clock: Arc<dyn Clock>,
    /// Fresh identifiers: one session for each check, one id for each audit record.
    pub ids: Arc<dyn IdGenerator>,
    /// The tenants this worker serves.
    pub tenants: Vec<TenantId>,
    /// The hash of the policy in force, for the audit records.
    pub policy_hash: Sha256Digest,
}

/// How one check ended, for a test and the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checked {
    /// A pull request was opened or updated.
    Proposed(PullRequestRef),
    /// Nothing to propose, and why.
    Nothing(NothingBecause),
    /// The check could not finish; it is tried again after the hour.
    Failed(GitHostError),
    /// The repository was checked less than an hour ago for this template version.
    Recently,
    /// The repository row cannot be read or its name is not a repository name.
    UnknownRepository,
}

/// Something the worker calls after it applied an onboarding request.
#[async_trait]
pub trait RepositoryOnboarded: Send + Sync {
    /// A request to register or to enable `repository` was applied and committed.
    async fn onboarded(&self, tenant: TenantId, repository: RepositoryId);
}

/// The rules check.
pub struct ProjectRulesSync {
    deps: ProjectRulesSyncDeps,
    template: Template<'static>,
    last: Mutex<BTreeMap<(TenantId, RepositoryId), (u32, Timestamp)>>,
}

impl ProjectRulesSync {
    /// The check, over its collaborators, with the template the factory ships.
    #[must_use]
    pub fn new(deps: ProjectRulesSyncDeps) -> Self {
        Self::with_template(deps, Template::current())
    }

    /// The same, with another template: for tests of the "older" and "newer" cases.
    #[doc(hidden)]
    #[must_use]
    pub fn with_template(deps: ProjectRulesSyncDeps, template: Template<'static>) -> Self {
        Self {
            deps,
            template,
            last: Mutex::new(BTreeMap::new()),
        }
    }

    /// Checks the repository unless it was checked less than an hour ago for this template.
    pub async fn check(&self, tenant: TenantId, repository: RepositoryId) -> Checked {
        let now = self.deps.clock.now();
        let recent = self
            .last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(tenant, repository))
            .is_some_and(|(version, at)| {
                *version == self.template.version
                    && now.duration_since(at).is_some_and(|d| d < RECHECK_AFTER)
            });
        if recent {
            return Checked::Recently;
        }
        self.check_now(tenant, repository).await
    }

    /// Checks the repository now, and notes the time.
    pub async fn check_now(&self, tenant: TenantId, repository: RepositoryId) -> Checked {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                (tenant, repository),
                (self.template.version, self.deps.clock.now()),
            );
        let Some(repo) = self.repository(tenant, repository).await else {
            return Checked::UnknownRepository;
        };
        let session = JobId::from_uuid(self.deps.ids.new_uuid());
        let round = Round::start(
            Arc::clone(&self.deps.jobs),
            Arc::clone(&self.deps.changes),
            session,
            tenant,
        );
        let scope = RulesScope {
            tenant,
            session,
            repo: repo.clone(),
        };
        let outcome = self.decide_and_propose(&scope).await;
        round.finish().await;
        match &outcome {
            Ok(Checked::Proposed(pr)) => {
                // The number and the version are in the audit record below.
                tracing::info!("the rules pull request was opened or updated");
                self.audit(
                    tenant,
                    PROPOSED,
                    AuditDecision::Allow,
                    &repo,
                    format!(
                        "The factory proposed version {} of the rules for agents in pull request {}. A person reviews and merges it; the factory never merges.",
                        self.template.version, pr.number
                    ),
                )
                .await;
            }
            Ok(Checked::Nothing(NothingBecause::Unreadable(why))) => {
                // The reason is in the audit record below.
                tracing::warn!("the rules file of a repository cannot be managed");
                self.audit(
                    tenant,
                    NOT_PROPOSED,
                    AuditDecision::Deny,
                    &repo,
                    format!(
                        "AGENTS.md on the default branch cannot be managed ({}): a person must repair its factory markers, its encoding or its size. The agents read it as it is, or the factory's built-in copy when it is too large or not UTF-8.",
                        why.code()
                    ),
                )
                .await;
            }
            Ok(Checked::Nothing(_)) => {
                tracing::debug!("no rules pull request is needed");
            }
            Ok(_) => {}
            // The error is the caller's answer (`Checked::Failed`); the log line says only that.
            Err(_) => {
                tracing::warn!("the rules check could not finish; it is tried again later");
            }
        }
        outcome.unwrap_or_else(Checked::Failed)
    }

    /// One pass for one tenant: the repositories of the jobs that wait for admission.
    pub async fn pass(&self, tenant: TenantId) -> Vec<(RepositoryId, Checked)> {
        let mut done = Vec::new();
        for repository in self.waiting_repositories(tenant).await {
            let checked = self.check(tenant, repository).await;
            done.push((repository, checked));
        }
        done
    }

    async fn waiting_repositories(&self, tenant: TenantId) -> Vec<RepositoryId> {
        let Ok(mut tx) = self.deps.store.begin(TenantScope::new(tenant)).await else {
            return Vec::new();
        };
        let listed = tx
            .list_jobs(
                JobFilter {
                    statuses: vec![JobStatus::Received],
                    repository: None,
                },
                None,
                PER_PASS,
            )
            .await;
        let _ = tx.rollback().await;
        let Ok(page) = listed else {
            return Vec::new();
        };
        let mut seen = BTreeSet::new();
        page.rows
            .into_iter()
            .map(|job| job.value.repository)
            .filter(|repository| seen.insert(*repository))
            .collect()
    }

    async fn repository(&self, tenant: TenantId, repository: RepositoryId) -> Option<RepoRef> {
        let mut tx = self.deps.store.begin(TenantScope::new(tenant)).await.ok()?;
        let found = tx.get_repository(repository).await;
        let _ = tx.rollback().await;
        RepoRef::parse(&found.ok()?.value.full_name).ok()
    }

    async fn decide_and_propose(&self, scope: &RulesScope) -> Result<Checked, GitHostError> {
        let host = &self.deps.host;
        let base = host.default_branch(scope).await?;
        let rules_path = RepoPath::new(RULES_FILE).map_err(|_| GitHostError::Unavailable)?;
        let file = host
            .read_file(scope, &base.commit, &rules_path, MAX_RULES_FILE_BYTES)
            .await?;
        let installed = read_installed(match &file {
            FileAt::Missing => FileFound::Missing,
            FileAt::TooLarge => FileFound::TooLarge,
            FileAt::Found(bytes) => FileFound::Bytes(bytes),
        });
        let state = classify(&installed, self.template);
        if !state.wants_proposal() {
            return Ok(match decide(state, Proposal::None, self.template.version) {
                Decision::Nothing(because) => Checked::Nothing(because),
                Decision::Propose => Checked::Nothing(NothingBecause::UpToDate),
            });
        }
        let latest = host.latest_rules_pull_request(scope).await?;
        let proposal = match latest {
            None => Proposal::None,
            Some(found) => match found.lifecycle {
                PullRequestLifecycle::Open => Proposal::Open(found.proposed_version),
                PullRequestLifecycle::Merged => Proposal::Merged(found.proposed_version),
                PullRequestLifecycle::Closed => Proposal::Closed(found.proposed_version),
            },
        };
        if let Decision::Nothing(because) = decide(state, proposal, self.template.version) {
            return Ok(Checked::Nothing(because));
        }
        let Some(text) = render(&installed, self.template) else {
            return Ok(Checked::Nothing(NothingBecause::Unreadable(
                factory_domain::project_rules::Unreadable::MalformedMarkers,
            )));
        };
        let mut files = vec![ProposedFile {
            path: rules_path,
            bytes: text.into_bytes(),
        }];
        let mut skeleton = Vec::new();
        for (path, body) in SKELETON {
            let at = RepoPath::new(path).map_err(|_| GitHostError::Unavailable)?;
            if host
                .read_file(scope, &base.commit, &at, MAX_RULES_FILE_BYTES)
                .await?
                == FileAt::Missing
            {
                skeleton.push(path);
                files.push(ProposedFile {
                    path: at,
                    bytes: body.as_bytes().to_vec(),
                });
            }
        }
        let (title, body) = pull_request_text(state, self.template.version, &skeleton);
        let pr = host
            .propose(
                scope,
                &RulesProposal {
                    base,
                    version: self.template.version,
                    files,
                    title,
                    body,
                },
            )
            .await?;
        Ok(Checked::Proposed(pr))
    }

    async fn audit(
        &self,
        tenant: TenantId,
        action: &str,
        decision: AuditDecision,
        repo: &RepoRef,
        reason: String,
    ) {
        let (Ok(actor), Ok(action)) = (Slug::parse(ACTOR), AuditAction::new(action)) else {
            return;
        };
        let id = AuditEventId::from_uuid(self.deps.ids.new_uuid());
        let event = NewAuditEvent {
            id,
            actor: AuditActor::System(actor),
            action,
            subject: format!("repository {repo}"),
            decision,
            reason: reason.chars().take(1000).collect(),
            policy_hash: self.deps.policy_hash.clone(),
            job: None,
            stage_run: None,
            correlation_id: CorrelationId::from_uuid(id.as_uuid()),
        };
        let Ok(mut tx) = self.deps.store.begin(TenantScope::new(tenant)).await else {
            tracing::warn!(
                "the rules check cannot write its audit record: the store is unavailable"
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

#[async_trait]
impl RepositoryOnboarded for ProjectRulesSync {
    async fn onboarded(&self, tenant: TenantId, repository: RepositoryId) {
        let _ = self.check_now(tenant, repository).await;
    }
}

#[async_trait(?Send)]
impl BeforeClaim for ProjectRulesSync {
    async fn before_claim(&self) {
        for tenant in &self.deps.tenants {
            self.pass(*tenant).await;
        }
    }
}

/// The template version this build ships, for a health line or a test.
#[must_use]
pub const fn template_version() -> u32 {
    TEMPLATE_VERSION
}
