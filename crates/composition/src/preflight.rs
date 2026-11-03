//! The protection preflight recorder: [`ProtectionPreflight`], a step before each claim.
//!
//! # Why it exists
//!
//! A repository whose protection was never checked runs at autonomy level L0 (ADR 0009: the store
//! reports L0 for it), and at L0 `approve_pr` is refused as below its minimum level, so nobody
//! could ever approve a job of such a repository. The policy says the protection is "verified at
//! onboarding and at each job start" (`policies/security.yaml`, `credentials.repository_requirements`),
//! and until now no process did either: the complete run recorded the result in the database by
//! hand, as an administrator would.
//!
//! # What it does
//!
//! Before the jobs of a tenant are admitted, for the repository of each `RECEIVED` job it
//!
//! 1. reads the protection of the default branch from the code host
//!    ([`IssueSource::repository_protection`], the port that offers it; the Administration
//!    permission is never asked for);
//! 2. asks for the recorded statement of an administrator that the App is on no bypass list
//!    ([`BypassAttestations`]), which the App cannot read for itself;
//! 3. judges both against the policy with [`ProtectionReport::evaluate`], which lists every missing
//!    item and not only the first. That includes the number of approving reviews the rules require:
//!    it must be at least the number every pull request needs (`policies/approval.yaml`,
//!    `risk_tiers`), and a count that could not be read is not enough (SF-07);
//! 4. records the result with `RepositoryOps::record_protection_preflight`, and writes an audit
//!    record when the result is a refusal or changed.
//!
//! The step runs before [`crate::decisions::ClaimWork`] admits the job, so the job that arrives
//! first at a repository is judged on the protection it has now. Because it runs for every job
//! that waits for admission, the check is repeated at each job start. A protection that cannot be
//! read is recorded as not passed: the repository is capped at L0 until a later pass reads it.
//!
//! # What it does not do
//!
//! The attestation has no production source yet. [`NoAttestations`] says "nobody attested", so a
//! deployment that does not pass another source caps every repository at L0 and says why in the
//! audit record. Who records the statement, and where, is for the architect and the security
//! reviewer to decide. The worker README lists it.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::ids::{AuditEventId, CorrelationId, JobId, RepositoryId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::state::JobStatus;
use factory_domain::values::{Sha256Digest, Slug};
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::clock::IdGenerator;
use factory_ports::githost::{
    AppId, BypassAttestation, GitScope, IssueSource, PreflightFailure, PreflightVerdict,
};
use factory_ports::paths::RepoRef;
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, JobFilter, NewAuditEvent, Store, StoreError,
};

use crate::hooks::BeforeClaim;

/// The most waiting jobs one pass looks at for one tenant.
const PER_PASS: u32 = 50;

/// Where the statement of an administrator comes from: "the factory's App is on no bypass list of
/// this repository".
#[async_trait]
pub trait BypassAttestations: Send + Sync {
    /// Says whether the statement comes from an administrator (`real`) or from a stand-in that
    /// attests whatever it is asked (`fake`). The profile check refuses a `fake` in production
    /// (RR-7): a source that always answers "nobody can bypass" turns the preflight into a pass.
    /// A source with nothing to say ([`NoAttestations`]) is `real` in this sense: it cannot make a
    /// false pass.
    fn fidelity(&self) -> Fidelity;

    /// The statement for the repository, or `None`. A source that cannot be read answers `None`:
    /// the preflight then fails closed.
    async fn attestation(
        &self,
        tenant: TenantId,
        repository: &RepoRef,
    ) -> Option<BypassAttestation>;
}

/// The source that has nothing. Every preflight that uses it names the missing statement.
pub struct NoAttestations;

#[async_trait]
impl BypassAttestations for NoAttestations {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn attestation(&self, _: TenantId, _: &RepoRef) -> Option<BypassAttestation> {
        None
    }
}

/// What the recorder is built from.
pub struct PreflightDeps {
    /// The store, on the worker's tenant pool.
    pub store: Arc<dyn Store>,
    /// Reads the protection of the default branch.
    pub source: Arc<dyn IssueSource>,
    /// The GitHub App the factory's required checks must be pinned to.
    pub app: AppId,
    /// The names of the checks the factory posts and the ruleset must require.
    pub checks: Vec<Slug>,
    /// The approving reviews the rules must require at least: the number every pull request needs
    /// by the policy (`AuthorityPolicy::approvals_every_pull_request_needs`). The composition root
    /// takes it from the policy; there is no default (SF-07).
    pub required_approvals: u32,
    /// The administrator's statement about the bypass list.
    pub attestations: Arc<dyn BypassAttestations>,
    /// The tenants this worker serves.
    pub tenants: Vec<TenantId>,
    /// The hash of the policy in force, for the audit record.
    pub policy_hash: Sha256Digest,
    /// New identifiers.
    pub ids: Arc<dyn IdGenerator>,
}

/// Records the protection preflight of the repository of each job that waits for admission.
pub struct ProtectionPreflight {
    deps: PreflightDeps,
}

/// What one repository's preflight came to, for a test and the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    /// The repository.
    pub repository: RepositoryId,
    /// Whether the policy's requirements all hold.
    pub passed: bool,
    /// What was missing, in plain English. Empty when it passed.
    pub missing: Vec<String>,
}

fn sentence(failure: &PreflightFailure) -> String {
    match failure {
        PreflightFailure::NoRulesetRules => {
            "No ruleset rule applies to the default branch.".to_owned()
        }
        PreflightFailure::PullRequestNotRequired => "A pull request is not required.".to_owned(),
        PreflightFailure::CodeOwnerReviewMissing => "Code owner review is not required.".to_owned(),
        PreflightFailure::StaleApprovalsKept => {
            "Approvals are kept when new commits are pushed.".to_owned()
        }
        PreflightFailure::ApprovingReviewsUnknown => {
            "The number of approving reviews that the rules require could not be read.".to_owned()
        }
        PreflightFailure::ApprovingReviewsBelowPolicy { found, needed } => format!(
            "The rules require {found} approving {}, and the policy needs at least {needed}.",
            if *found == 1 { "review" } else { "reviews" }
        ),
        PreflightFailure::ForcePushAllowed => "Force pushes are allowed.".to_owned(),
        PreflightFailure::DeletionAllowed => "The branch can be deleted.".to_owned(),
        PreflightFailure::FactoryCheckNotRequired(name) => {
            format!("The check {name} is not required.")
        }
        PreflightFailure::FactoryCheckNotPinned(name) => {
            format!("The check {name} is not pinned to the factory's App.")
        }
        PreflightFailure::BypassNotAttested => {
            "Nobody recorded that the App is on no bypass list.".to_owned()
        }
    }
}

impl ProtectionPreflight {
    /// A recorder over its collaborators.
    #[must_use]
    pub fn new(deps: PreflightDeps) -> Self {
        Self { deps }
    }

    /// The approving reviews the rules of a repository must require at least, as this recorder
    /// judges them (SF-07).
    #[must_use]
    pub const fn required_approvals(&self) -> u32 {
        self.deps.required_approvals
    }

    /// One pass for one tenant. Public so a test can run it without a loop. The results are those
    /// of the repositories it looked at.
    pub async fn pass(&self, tenant: TenantId) -> Vec<Recorded> {
        let waiting = self.waiting_repositories(tenant).await;
        let mut done = Vec::new();
        for (repository, job) in waiting {
            if let Some(recorded) = self.check(tenant, repository, job).await {
                done.push(recorded);
            }
        }
        done
    }

    /// The repositories of the jobs that wait for admission, once each, with one job of each.
    async fn waiting_repositories(&self, tenant: TenantId) -> Vec<(RepositoryId, JobId)> {
        let Ok(mut tx) = self.deps.store.begin(TenantScope::new(tenant)).await else {
            tracing::warn!(
                "the protection preflight cannot list the waiting jobs: the store is unavailable"
            );
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
            tracing::warn!("the protection preflight cannot list the waiting jobs");
            return Vec::new();
        };
        let mut seen = BTreeSet::new();
        page.rows
            .into_iter()
            .filter(|job| seen.insert(job.value.repository))
            .map(|job| (job.value.repository, job.value.id))
            .collect()
    }

    async fn check(
        &self,
        tenant: TenantId,
        repository: RepositoryId,
        job: JobId,
    ) -> Option<Recorded> {
        let (row, version) = {
            let mut tx = self.deps.store.begin(TenantScope::new(tenant)).await.ok()?;
            let found = tx.get_repository(repository).await;
            let _ = tx.rollback().await;
            let found = found.ok()?;
            (found.value, found.version)
        };
        let repo = RepoRef::parse(&row.full_name).ok()?;
        let scope = GitScope {
            tenant,
            job,
            stage: StageKind::Intake,
            repo: repo.clone(),
        };
        let attestation = self.deps.attestations.attestation(tenant, &repo).await;
        let missing: Vec<String> = match self.deps.source.repository_protection(&scope).await {
            Ok(report) => {
                match report.evaluate(
                    self.deps.app,
                    &self.deps.checks,
                    attestation.as_ref(),
                    self.deps.required_approvals,
                ) {
                    PreflightVerdict::Pass => Vec::new(),
                    PreflightVerdict::CapAtL0(failures) => failures.iter().map(sentence).collect(),
                }
            }
            // A protection that cannot be read is not a protection that holds.
            Err(_) => vec!["The protection of the default branch could not be read.".to_owned()],
        };
        let passed = missing.is_empty();
        let changed = passed != row.protection_preflight_passed;
        let recorded = {
            let mut tx = self.deps.store.begin(TenantScope::new(tenant)).await.ok()?;
            let outcome = async {
                tx.record_protection_preflight(repository, version, passed)
                    .await?;
                if changed || !passed {
                    tx.record_audit(self.audit(&row.full_name, passed, &missing))
                        .await?;
                }
                Ok::<(), StoreError>(())
            }
            .await;
            match outcome {
                Ok(()) => tx.commit().await.is_ok(),
                Err(_) => {
                    // A stale version means another worker recorded it first: nothing to do.
                    tracing::info!("the protection preflight was not recorded this pass");
                    let _ = tx.rollback().await;
                    false
                }
            }
        };
        recorded.then_some(Recorded {
            repository,
            passed,
            missing,
        })
    }

    fn audit(&self, full_name: &str, passed: bool, missing: &[String]) -> NewAuditEvent {
        let reason = if passed {
            "Every protection requirement of the policy holds for the default branch.".to_owned()
        } else {
            let listed = missing.join(" ");
            let capped: String = listed.chars().take(900).collect();
            format!("The repository runs at level L0 until this is fixed. {capped}")
        };
        let id = AuditEventId::from_uuid(self.deps.ids.new_uuid());
        NewAuditEvent {
            id,
            actor: AuditActor::System(
                Slug::parse("worker.preflight").expect("a fixed name is a slug"),
            ),
            action: AuditAction::new("repository.protection_preflight")
                .expect("a fixed action name is valid"),
            subject: format!("repository {full_name}"),
            decision: if passed {
                AuditDecision::Allow
            } else {
                AuditDecision::Deny
            },
            reason,
            policy_hash: self.deps.policy_hash.clone(),
            job: None,
            stage_run: None,
            correlation_id: CorrelationId::from_uuid(id.as_uuid()),
        }
    }
}

#[async_trait(?Send)]
impl BeforeClaim for ProtectionPreflight {
    async fn before_claim(&self) {
        for tenant in &self.deps.tenants {
            self.pass(*tenant).await;
        }
    }
}
