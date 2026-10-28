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
//! Two of the four questions are answered here and two are **BLOCKED**:
//!
//! | Method | Status |
//! |---|---|
//! | `target` | answered: repository and base branch from the repository row, the issue from the stored request, the head branch `factory/job-<job id>`, the risk facts joined from the job and measured from the stored design. `links` is empty: no stored document lists the paths of the task, decision and documentation files on the branch |
//! | `ledger` | answered: the whole chain is read and verified just now, the assurance levels come from the entries that claim them |
//! | `current_values` | **BLOCKED**: the gate definition hash is computed by private code of the validation stage (`load_definitions`, `definition_of`), and a second implementation here would drift from it. Needs a public function in the workflow crate |
//! | `tree_of` | **BLOCKED**: no port exposes the tree id of a commit, and this crate may not start `git` (DEP-10). Needs `JobRepo::tree_of` in the ports and the sandbox adapter |
//!
//! The two blocked methods answer `Unavailable`, so the delivery stage fails closed at the point
//! where it needs them. They are listed in `assemble::blocked_seams`.

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
use factory_ports::store::{PrincipalKind, Store};
use factory_workflow::handlers::RunIdentity;
use factory_workflow::stages::approval::{ApprovalRequest, ApprovalSources};
use factory_workflow::stages::architecture::design::Design;
use factory_workflow::stages::architecture::risk::{either, measure};
use factory_workflow::stages::architecture::seams::RiskSource;
use factory_workflow::stages::delivery::{
    CurrentValues, DeliverySources, DeliveryTarget, LedgerState, SeamError,
};

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
        let found = tx.get_job(job).await;
        let _ = tx.rollback().await;
        let level = found.map_err(|e| seam(&e))?.value.autonomy_level;
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

/// The facts the delivery stage reads from the store.
#[derive(Clone)]
pub struct StoreDeliverySources {
    reader: Reader,
    policy: Arc<PolicyEngine>,
    clock: Arc<dyn Clock>,
    job_risk: StoreRisk,
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
        }
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
        let job_facts = self.job_risk.of(run).await?.facts;
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
            Ok(DeliveryTarget {
                repo: RepoRef::parse(&repository.full_name).map_err(|_| SeamError::NotFound)?,
                base: BranchName::new(&repository.default_branch)
                    .map_err(|_| SeamError::NotFound)?,
                head: job_branch(run.job)?,
                issue,
                risk,
                links: Vec::new(),
            })
        }
        .await;
        let _ = tx.rollback().await;
        outcome
    }

    async fn current_values(
        &self,
        _run: &RunIdentity,
        _base: &CommitSha,
    ) -> Result<CurrentValues, SeamError> {
        // BLOCKED: see the module note.
        Err(SeamError::Unavailable)
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

    async fn tree_of(&self, _run: &RunIdentity, _commit: &CommitSha) -> Result<GitSha, SeamError> {
        // BLOCKED: see the module note.
        Err(SeamError::Unavailable)
    }
}
