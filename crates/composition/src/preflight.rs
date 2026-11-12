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
//! 4. reads the workflow files of the default branch ([`IssueSource::workflow_files`], with the
//!    right to read contents and nothing more) and judges each with
//!    [`factory_contracts::workflows`]: a workflow that a push to a `factory/` branch or a pull
//!    request to the default branch would start, with a secret, a write token or an unknown runner
//!    in reach, is *exposed* (threat T-48). What that costs is the policy's choice
//!    (`credentials.repository_requirements.exposed_workflows`): `cap_at_l0` caps the repository
//!    like any other missing item, unless the owner recorded an acknowledgement of exactly those
//!    workflows ([`BypassAttestations::workflow_acknowledgement`]); `record_only` names them in
//!    the audit record and does not cap. Workflow files that could not be read are never taken
//!    for "none is exposed";
//! 5. records the result with `RepositoryOps::record_protection_preflight`, and writes an audit
//!    record when the result is a refusal or changed, and every time a repository passes with
//!    exposed workflows (because of an acknowledgement, or because the policy only records).
//!
//! The step runs before [`crate::decisions::ClaimWork`] admits the job, so the job that arrives
//! first at a repository is judged on the protection it has now. Because it runs for every job
//! that waits for admission, the check is repeated at each job start. A protection that cannot be
//! read is recorded as not passed: the repository is capped at L0 until a later pass reads it.
//!
//! # What it does not do
//!
//! It does not judge the statement it is given. The production source is the configuration key
//! `github.bypass_attestations` (`crate::external::ConfigAttestations`): an entry there lifts the
//! cap for its repository. Such an entry has no expiry, cannot be withdrawn except by editing the
//! configuration, is not checked against the designations of the person it names, and leaves no
//! audit record of its own. Whether the statement should move into the database, with an expiry
//! and a recorded withdrawal, is for the architect and the security reviewer to decide.
//! [`NoAttestations`] says "nobody attested" and is what a caller without a source uses: it caps
//! every repository at L0 and says why in the audit record.
//!
//! The workflow check has limits of its own, and every rule it applies is written from GitHub's
//! documentation and UNVERIFIED against the real GitHub (see [`factory_contracts::workflows`]).
//! It reads the files of the default branch only: it cannot see the secrets policy of the
//! organization, the default permissions of the workflow token, the protection of an
//! environment, a required workflow that an organization ruleset adds, or a reusable workflow in
//! another repository. A workflow file that the factory's own branch adds or changes is not read
//! here; the protected paths of the policy (`protected_paths`, group `ci_workflows`, mode
//! `deny_write` on `.github/**`) are what stops the builder from writing one. An acknowledgement
//! names paths, not contents: a workflow that is acknowledged and later made worse, at the same
//! path, stays acknowledged. The same limits as for the bypass statement apply to it: no expiry,
//! no withdrawal except by editing the configuration, no check of the person it names.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use factory_contracts::workflows::exposed_workflows;
use factory_domain::ids::{AuditEventId, CorrelationId, JobId, RepositoryId, TenantId};
use factory_domain::policy::security::ExposedWorkflows;
use factory_domain::scope::TenantScope;
use factory_domain::state::JobStatus;
use factory_domain::values::{Sha256Digest, Slug};
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::clock::IdGenerator;
use factory_ports::githost::{
    AppId, BypassAttestation, ExposedWorkflow, GitScope, IssueSource, PreflightFailure,
    PreflightVerdict, WorkflowExposureAcknowledgement, WorkflowRule,
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

    /// The owner's recorded statement that named workflows of the repository are exposed to the
    /// factory's branches on purpose (threat T-48), or `None`. It comes from the same place as
    /// the statement about the bypass list and has the same standing. The default is `None`: a
    /// source that keeps no such statement acknowledges nothing, and the preflight then caps a
    /// repository with exposed workflows.
    async fn workflow_acknowledgement(
        &self,
        tenant: TenantId,
        repository: &RepoRef,
    ) -> Option<WorkflowExposureAcknowledgement> {
        let _ = (tenant, repository);
        None
    }
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
    /// What exposed workflows cost a repository: the value of
    /// `credentials.repository_requirements.exposed_workflows` in `policies/security.yaml`. The
    /// composition root takes it from the policy; there is no default (threat T-48).
    pub exposed_workflows: ExposedWorkflows,
    /// The administrator's statement about the bypass list, and the owner's acknowledgement of
    /// exposed workflows.
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
    /// The workflows found exposed, whatever that cost the repository. Empty when none is, and
    /// when the workflow files could not be read (`missing` then says so).
    pub exposed_workflows: Vec<ExposedWorkflow>,
    /// True when the repository passed and would not have without the owner's acknowledgement of
    /// its exposed workflows.
    pub passed_on_acknowledgement: bool,
}

/// A path as it is shown in a sentence: one line, at most 120 characters. The path comes from the
/// target repository, so it is not trusted to be short or printable.
fn shown_path(path: &str) -> String {
    let flat: String = path
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(120)
        .collect();
    if path.chars().count() > 120 {
        format!("{flat}...")
    } else {
        flat
    }
}

/// One exposed workflow, in plain English with the reason codes: "The workflow
/// .github/workflows/ci.yml is exposed to factory branches: it reads a secret (uses_secrets)."
fn exposure_sentence(workflow: &ExposedWorkflow) -> String {
    let reasons: Vec<&str> = workflow
        .reasons
        .iter()
        .map(|reason| reason.text())
        .collect();
    let codes: Vec<&str> = workflow
        .reasons
        .iter()
        .map(|reason| reason.code())
        .collect();
    format!(
        "The workflow {} is exposed to factory branches: it {} ({}).",
        shown_path(&workflow.path),
        reasons.join("; it "),
        codes.join(", ")
    )
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
        PreflightFailure::WorkflowsNotRead => {
            "The workflows of the default branch could not be read, so nothing says that none is exposed to factory branches.".to_owned()
        }
        PreflightFailure::WorkflowExposed(workflow) => exposure_sentence(workflow),
        PreflightFailure::WorkflowAcknowledgementDoesNotMatch => {
            "The recorded acknowledgement of exposed workflows names a different list of workflows, so it covers none of them.".to_owned()
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
        let acknowledgement = self
            .deps
            .attestations
            .workflow_acknowledgement(tenant, &repo)
            .await;
        let rule = WorkflowRule {
            exposed_caps_at_l0: self.deps.exposed_workflows == ExposedWorkflows::CapAtL0,
            acknowledgement: acknowledgement.as_ref(),
        };
        let mut exposed = Vec::new();
        let mut passed_on_acknowledgement = false;
        let missing: Vec<String> = match self.deps.source.repository_protection(&scope).await {
            Ok(mut report) => {
                // The workflows are read and judged here, whatever the report said about them:
                // the adapter reads the rules and has no reader for workflow files. A read that
                // fails leaves `None`, which is never taken for "none is exposed".
                report.exposed_workflows = self
                    .deps
                    .source
                    .workflow_files(&scope)
                    .await
                    .ok()
                    .map(|files| exposed_workflows(&files, report.default_branch.as_str()));
                let workflows_read = report.exposed_workflows.is_some();
                exposed = report.exposed_workflows.clone().unwrap_or_default();
                let missing: Vec<String> = match report.evaluate(
                    self.deps.app,
                    &self.deps.checks,
                    attestation.as_ref(),
                    self.deps.required_approvals,
                    rule,
                ) {
                    PreflightVerdict::Pass => Vec::new(),
                    PreflightVerdict::CapAtL0(failures) => failures.iter().map(sentence).collect(),
                };
                passed_on_acknowledgement = missing.is_empty()
                    && rule.exposed_caps_at_l0
                    && report.exposure_is_acknowledged(rule.acknowledgement);
                // A policy that only records does not cap for files that could not be read
                // either. The log says so, because no audit record will.
                if !rule.exposed_caps_at_l0 && !workflows_read {
                    tracing::warn!(
                        "the workflow files of a repository could not be read; the policy only records exposed workflows, so the repository is not capped for it"
                    );
                }
                missing
            }
            // A protection that cannot be read is not a protection that holds.
            Err(_) => vec!["The protection of the default branch could not be read.".to_owned()],
        };
        let passed = missing.is_empty();
        let changed = passed != row.protection_preflight_passed;
        // A pass with exposed workflows is recorded every time: it rests on a person's statement
        // or on a policy that chose not to cap, and the record names both.
        let passed_with_exposure = passed && !exposed.is_empty();
        let recorded = {
            let mut tx = self.deps.store.begin(TenantScope::new(tenant)).await.ok()?;
            let outcome = async {
                tx.record_protection_preflight(repository, version, passed)
                    .await?;
                if changed || !passed || passed_with_exposure {
                    tx.record_audit(
                        self.audit(
                            &row.full_name,
                            passed,
                            &missing,
                            &exposed,
                            acknowledgement
                                .as_ref()
                                .filter(|_| passed_on_acknowledgement),
                        ),
                    )
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
            exposed_workflows: exposed,
            passed_on_acknowledgement,
        })
    }

    fn audit(
        &self,
        full_name: &str,
        passed: bool,
        missing: &[String],
        exposed: &[ExposedWorkflow],
        acknowledged: Option<&WorkflowExposureAcknowledgement>,
    ) -> NewAuditEvent {
        let reason = if passed && exposed.is_empty() {
            "Every protection requirement of the policy holds for the default branch.".to_owned()
        } else if passed {
            let why = match acknowledged {
                Some(statement) => format!(
                    "The repository passed because of an acknowledgement of exposed workflows: principal {} recorded at {} that these workflows are exposed to factory branches on purpose.",
                    statement.by,
                    statement.at.as_text()
                ),
                None => "The repository has exposed workflows and is not capped for them: the policy says record_only (credentials.repository_requirements.exposed_workflows).".to_owned(),
            };
            let listed: Vec<String> = exposed.iter().map(exposure_sentence).collect();
            let capped: String = listed.join(" ").chars().take(700).collect();
            format!("{why} {capped}")
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
