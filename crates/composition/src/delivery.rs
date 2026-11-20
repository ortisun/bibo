//! The delivery and approval stages' sources of fact: [`StoreApprovalSources`]
//! (`ApprovalSources`) and [`StoreDeliverySources`] (`DeliverySources`).
//!
//! # Approval
//!
//! All four questions are reads of things the store or the protected configuration holds: the
//! numeric GitHub id of the person who asked (the principal row of the job's requester), the
//! allowlist as the file is now, the autonomy level of the job row, and the `approval-request`
//! document that the approval stage stored as its output.
//!
//! # Delivery
//!
//! Two of the four questions are answered from the store. The other two read the job's object
//! store and the validation configuration, and are answered once [`StoreDeliverySources::with_repository`]
//! gave them both; until then they fail closed:
//!
//! | Method | Status |
//! |---|---|
//! | `target` | answered: repository and base branch from the repository row, the issue from the stored request, the head branch `factory/job-<job id>`, the risk facts joined from the job and measured from the stored design. `links` is empty: no stored document lists the paths of the task, decision and documentation files on the branch |
//! | `ledger` | answered: the whole chain is read and verified just now, the assurance levels come from the entries that claim them |
//! | `current_values` | answered with `with_repository`: the hash of the gate definitions and the digest of the verify image come from `validation::current_values`, the function the validation stage uses for its own binding, so the two cannot disagree. Without it: `Unavailable` |
//! | `tree_of` | answered with `with_repository`: `JobRepo::tree_of` of the job's object store (pending architect confirmation, ports document section 16). Without it: `Unavailable` |
//!
//! A method that is not wired answers `Unavailable`, so the delivery stage fails closed at the
//! point where it needs it. `assemble::blocked_seams` lists them for a binary that does not wire
//! them yet.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::evidence_ledger_entry::ClaimKind;
use factory_domain::ids::{JobId, StageRunId, TenantId};
use factory_domain::policy::PolicyEngine;
use factory_domain::policy::authority::{Allowlist, AutonomyLevel};
use factory_domain::state::StageRunStatus;
use factory_domain::values::GitSha;
use factory_domain::vocabulary::{AutonomyLevel as VocabularyLevel, Fidelity, StageKind};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::Clock;
use factory_ports::paths::{BranchName, CommitSha, RepoRef};
use factory_ports::store::{PrincipalKind, Store, StoreError};
use factory_ports::workspace::WorkspaceProvider;
use factory_workflow::handlers::RunIdentity;
use factory_workflow::stages::approval::{ApprovalRequest, ApprovalSources};
use factory_workflow::stages::architecture::design::Design;
use factory_workflow::stages::architecture::risk::{either, measure};
use factory_workflow::stages::architecture::seams::RiskSource;
use factory_workflow::stages::delivery::{
    CurrentValues, DeliverySources, DeliveryTarget, LedgerState, SeamError,
};
use factory_workflow::stages::validation::ValidationConfig;

use crate::reading::Reader;
use crate::risk::StoreRisk;
use crate::seams::{FileAllowlist, issue_of};

fn seam(error: &factory_ports::store::StoreError) -> SeamError {
    match error {
        factory_ports::store::StoreError::NotFound => SeamError::NotFound,
        _ => SeamError::Unavailable,
    }
}

// ------------------------------------------------------------------------------------------
// ApprovalSources
// ------------------------------------------------------------------------------------------

/// Facts about the people and the policy around a job, read from the store and the allowlist file.
#[derive(Clone)]
pub struct StoreApprovalSources {
    reader: Reader,
    allowlist: Arc<FileAllowlist>,
}

impl StoreApprovalSources {
    /// Sources over the store, the artifact store and the allowlist.
    #[must_use]
    pub fn new(
        store: Arc<dyn Store>,
        artifacts: Arc<dyn ArtifactStore>,
        allowlist: Arc<FileAllowlist>,
    ) -> Self {
        Self {
            reader: Reader::new(store, artifacts),
            allowlist,
        }
    }
}

#[async_trait]
impl ApprovalSources for StoreApprovalSources {
    fn fidelity(&self) -> Fidelity {
        self.reader.store().fidelity()
    }

    async fn requester(&self, run: &RunIdentity) -> Result<u64, SeamError> {
        let mut tx = self.reader.begin(run.tenant).await?;
        let outcome = async {
            let job = tx.get_job(run.job).await.map_err(|e| seam(&e))?.value;
            let principal = tx
                .get_principal(job.requester)
                .await
                .map_err(|e| seam(&e))?;
            match principal.kind {
                PrincipalKind::Human { github_user_id } => Ok(github_user_id),
                PrincipalKind::Service => Err(SeamError::NotFound),
            }
        }
        .await;
        let _ = tx.rollback().await;
        outcome
    }

    async fn allowlist(&self, _tenant: TenantId) -> Result<Allowlist, SeamError> {
        self.allowlist.read()
    }

    async fn level(&self, tenant: TenantId, job: JobId) -> Result<AutonomyLevel, SeamError> {
        let mut tx = self.reader.begin(tenant).await?;
        let found = async {
            let stored = tx.get_job(job).await?;
            let repository = tx.get_repository(stored.value.repository).await?;
            Ok::<_, StoreError>(repository.value.autonomy_ceiling)
        }
        .await;
        let _ = tx.rollback().await;
        // The level a job runs at is the effective ceiling of its repository **now**, not the one
        // written on the job row. The row is fixed when the job is received, and a job that arrives
        // before the first protection preflight of its repository is received at L0, because the
        // store reports L0 for a repository with no passed preflight (ADR 0009). The preflight
        // then passes before the job is admitted, and the job would stay at L0 for ever, so no
        // approval of it could pass. Reading the ceiling now also lowers a job whose repository
        // lost its protection after the job was received, which is the safe direction.
        let level = found.map_err(|e| seam(&e))?;
        // The store names the level with the vocabulary type and the policy with its own.
        Ok(match level {
            VocabularyLevel::L0 => AutonomyLevel::L0,
            VocabularyLevel::L1 => AutonomyLevel::L1,
            VocabularyLevel::L2 => AutonomyLevel::L2,
            VocabularyLevel::L3 => AutonomyLevel::L3,
        })
    }

    async fn request(
        &self,
        tenant: TenantId,
        stage_run: StageRunId,
    ) -> Result<ApprovalRequest, SeamError> {
        let mut tx = self.reader.begin(tenant).await?;
        let outcome = async {
            let outputs = Reader::outputs(&mut *tx, stage_run).await?;
            let hash = outputs
                .get(factory_workflow::stages::approval::REQUEST)
                .ok_or(SeamError::NotFound)?;
            let bytes = self.reader.bytes(&mut *tx, tenant, hash).await?;
            let value = serde_json::from_slice::<serde_json::Value>(&bytes)
                .map_err(|_| SeamError::Unavailable)?;
            ApprovalRequest::from_json(&value).ok_or(SeamError::Unavailable)
        }
        .await;
        let _ = tx.rollback().await;
        outcome
    }
}

// ------------------------------------------------------------------------------------------
// DeliverySources
// ------------------------------------------------------------------------------------------

/// The facts the delivery stage reads from the store, and, once [`Self::with_repository`] gave
/// them the job's object store and the validation configuration, the tree of a commit and the
/// values the validation evidence is bound to.
#[derive(Clone)]
pub struct StoreDeliverySources {
    reader: Reader,
    policy: Arc<PolicyEngine>,
    clock: Arc<dyn Clock>,
    job_risk: StoreRisk,
    repository: Option<RepositoryAccess>,
}

/// What the two methods that read the job's object store need.
#[derive(Clone)]
struct RepositoryAccess {
    workspaces: Arc<dyn WorkspaceProvider>,
    validation: Arc<ValidationConfig>,
}

impl StoreDeliverySources {
    /// Sources over the store, the artifact store, the policy and the clock.
    #[must_use]
    pub fn new(
        store: Arc<dyn Store>,
        artifacts: Arc<dyn ArtifactStore>,
        policy: Arc<PolicyEngine>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            job_risk: StoreRisk::new(Arc::clone(&store), Arc::clone(&artifacts)),
            reader: Reader::new(store, artifacts),
            policy,
            clock,
            repository: None,
        }
    }

    /// Lets the sources read the job's object store: the tree of a commit comes from the
    /// workspace provider's repository, and the values the validation evidence is bound to come
    /// from the validation stage's own function with the configuration the stage runs with.
    /// Without it both methods stay closed, as they were.
    #[must_use]
    pub fn with_repository(
        mut self,
        workspaces: Arc<dyn WorkspaceProvider>,
        validation: Arc<ValidationConfig>,
    ) -> Self {
        self.repository = Some(RepositoryAccess {
            workspaces,
            validation,
        });
        self
    }
}

/// The branch a job worked from, as its repository map records it: the integration branch of the
/// project's gitflow. A map written before the field existed names none, and the job worked from
/// `default`.
///
/// # Errors
/// [`SeamError::Unavailable`] when the map is not JSON, or names the branch with something that is
/// not text: the stored map is the factory's own, so either means it cannot be trusted.
pub fn base_branch_of(map: &[u8], default: &str) -> Result<String, SeamError> {
    let map =
        serde_json::from_slice::<serde_json::Value>(map).map_err(|_| SeamError::Unavailable)?;
    match map.get("base_branch") {
        None => Ok(default.to_owned()),
        Some(recorded) => recorded
            .as_str()
            .map(str::to_owned)
            .ok_or(SeamError::Unavailable),
    }
}

/// The name of the factory branch of a job.
///
/// # Errors
/// [`SeamError::Unavailable`] if the name is not a branch name (it always is for a job id).
pub fn job_branch(job: JobId) -> Result<BranchName, SeamError> {
    BranchName::new(&format!("factory/job-{job}")).map_err(|_| SeamError::Unavailable)
}

#[async_trait]
impl DeliverySources for StoreDeliverySources {
    fn fidelity(&self) -> Fidelity {
        self.reader.store().fidelity()
    }

    async fn target(&self, run: &RunIdentity) -> Result<DeliveryTarget, SeamError> {
        let job_risk = self.job_risk.of(run).await?;
        let (job_facts, agent_claim) = (job_risk.facts, job_risk.agent_claim);
        let mut tx = self.reader.begin(run.tenant).await?;
        let outcome = async {
            let job = tx.get_job(run.job).await.map_err(|e| seam(&e))?.value;
            let repository = tx
                .get_repository(job.repository)
                .await
                .map_err(|e| seam(&e))?
                .value;
            let request = tx
                .get_original_request(run.job, None)
                .await
                .map_err(|e| seam(&e))?;
            let issue = request
                .source_ref
                .as_deref()
                .and_then(issue_of)
                .ok_or(SeamError::NotFound)?;
            // What the factory measured: the facts the design shows, joined with the job's.
            let runs = tx.list_stage_runs(run.job).await.map_err(|e| seam(&e))?;
            let architecture = runs
                .iter()
                .rfind(|candidate| {
                    candidate.value.kind == StageKind::Architecture
                        && candidate.value.status == StageRunStatus::Passed
                })
                .ok_or(SeamError::Unavailable)?;
            let outputs = Reader::outputs(&mut *tx, architecture.value.id).await?;
            let hash = outputs
                .get("architecture-design")
                .ok_or(SeamError::Unavailable)?;
            let bytes = self.reader.bytes(&mut *tx, run.tenant, hash).await?;
            let design = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|value| Design::read(&value).ok())
                .ok_or(SeamError::Unavailable)?;
            let risk = either(job_facts, measure(&design, &self.policy));
            // The branch the job worked from: the repository map records it (the integration branch
            // of the project's gitflow); a map written before it did names none, and the job worked
            // from the default branch.
            let mut base = repository.default_branch.clone();
            if let Some(intelligence) = runs.iter().rfind(|candidate| {
                candidate.value.kind == StageKind::RepositoryIntelligence
                    && candidate.value.status == StageRunStatus::Passed
            }) {
                let outputs = Reader::outputs(&mut *tx, intelligence.value.id).await?;
                if let Some(hash) = outputs.get("repository-map") {
                    let bytes = self.reader.bytes(&mut *tx, run.tenant, hash).await?;
                    base = base_branch_of(&bytes, &base)?;
                }
            }
            Ok(DeliveryTarget {
                repo: RepoRef::parse(&repository.full_name).map_err(|_| SeamError::NotFound)?,
                base: BranchName::new(&base).map_err(|_| SeamError::NotFound)?,
                head: job_branch(run.job)?,
                issue,
                risk,
                agent_claim,
                links: Vec::new(),
            })
        }
        .await;
        let _ = tx.rollback().await;
        outcome
    }

    async fn current_values(
        &self,
        run: &RunIdentity,
        base: &CommitSha,
    ) -> Result<CurrentValues, SeamError> {
        let access = self.repository.as_ref().ok_or(SeamError::Unavailable)?;
        let repo = access
            .workspaces
            .repo(run.job)
            .await
            .map_err(|_| SeamError::Unavailable)?;
        let (definition_hash, image_digest) =
            factory_workflow::stages::validation::current_values(&*repo, &access.validation, base)
                .await
                .map_err(|_| SeamError::Unavailable)?;
        Ok(CurrentValues {
            definition_hash,
            image_digest,
        })
    }

    async fn ledger(&self, run: &RunIdentity) -> Result<LedgerState, SeamError> {
        let mut tx = self.reader.begin(run.tenant).await?;
        let entries = Reader::job_ledger(&mut *tx, run.job).await;
        let _ = tx.rollback().await;
        let entries = entries?;
        // The chain is verified now, and an implementation that cannot verify says so.
        factory_domain::ledger::verify_chain(&entries).map_err(|_| SeamError::Unavailable)?;
        let last = entries.last().ok_or(SeamError::NotFound)?;
        let mut attained = Vec::new();
        for entry in &entries {
            if entry.claim.kind == ClaimKind::MeasuredFact
                && let Some(level) = entry.claim.assurance_level
                && !attained.iter().any(|(seen, _)| *seen == level)
            {
                attained.push((level, entry.metadata.entry_id));
            }
        }
        Ok(LedgerState {
            entry_count: u64::try_from(entries.len()).unwrap_or(u64::MAX),
            head_sequence: u64::try_from(last.metadata.sequence.get()).unwrap_or(u64::MAX),
            head_hash: last.entry_hash.clone(),
            chain_verified_at: self.clock.now(),
            attained,
            dispositions: Vec::new(),
        })
    }

    async fn tree_of(&self, run: &RunIdentity, commit: &CommitSha) -> Result<GitSha, SeamError> {
        let access = self.repository.as_ref().ok_or(SeamError::Unavailable)?;
        let repo = access
            .workspaces
            .repo(run.job)
            .await
            .map_err(|_| SeamError::Unavailable)?;
        repo.tree_of(commit).await.map_err(|error| match error {
            // A commit the job's store does not hold is not a tree to compare with.
            factory_ports::workspace::WorkspaceError::UnknownCommit => SeamError::NotFound,
            _ => SeamError::Unavailable,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{SeamError, base_branch_of};

    #[test]
    fn the_base_branch_is_the_one_the_map_records_or_the_default() {
        assert_eq!(
            base_branch_of(br#"{"base_branch":"develop"}"#, "main").as_deref(),
            Ok("develop")
        );
        assert_eq!(
            base_branch_of(br#"{"commit_sha":"a"}"#, "main").as_deref(),
            Ok("main")
        );
        assert_eq!(
            base_branch_of(br#"{"base_branch":7}"#, "main"),
            Err(SeamError::Unavailable)
        );
        assert_eq!(base_branch_of(b"{", "main"), Err(SeamError::Unavailable));
    }
}
