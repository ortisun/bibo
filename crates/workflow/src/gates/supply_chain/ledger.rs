//! The recorded decisions in the evidence ledger: how they are written and how they are read back.
//!
//! A decision on a dependency (or on its build code) is recorded by one use case,
//! `Engine::record_dependency_decision`. It stores the decision ([`DependencyApproval::to_json`])
//! as an artifact of the tenant and appends one ledger entry to the job's hash chain: an
//! `expert_judgment` claim with two pieces of evidence, the attestor (the person's principal and
//! role) and the artifact (its hash). [`LedgerApprovals`] is the other side: the implementation of
//! [`RecordedApprovals`] that reads those entries back for the gate.
//!
//! What makes an entry "written by the approval command" is that **only the engine appends to the
//! ledger**: a candidate repository, a sandbox and a stage output cannot. The reader still asks
//! for more than a marker. It reads the entries of one tenant and one job only, refuses the
//! whole ledger when its chain does not verify, takes the artifact by the hash the entry names
//! and checks the document it finds names the same tenant and job, so a document planted in the
//! store under another entry's name is not read as a decision.
//!
//! Writer and reader share the claim text and the note on the artifact, so they cannot drift.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::evidence_ledger_entry::{ClaimKind, Evidence};
use factory_domain::ids::{JobId, TenantId};
use factory_domain::ledger::verify_chain;
use factory_domain::scope::TenantScope;
use factory_domain::vocabulary::Fidelity;
use factory_ports::artifact::ArtifactStore;
use factory_ports::store::Store;

use super::approval::RecordedApprovals;
use super::approval::{ApprovalKind, DecisionScope, DependencyApproval};
use crate::engine::read_all_ledger;

/// How the statement of the claim of a recorded decision begins.
pub const STATEMENT_PREFIX: &str = "A person decided on ";

/// The description of the artifact evidence that holds the decision.
pub const ARTIFACT_NOTE: &str = "dependency-decision";

/// The statement of the ledger claim for a decision.
#[must_use]
pub fn statement_of(approval: &DependencyApproval) -> String {
    let (name, version) = (&approval.subject.name, &approval.subject.version);
    match approval.kind {
        ApprovalKind::NewDependency => {
            format!("{STATEMENT_PREFIX}the new direct dependency {name} {version}.")
        }
        ApprovalKind::BuildCode => {
            format!("{STATEMENT_PREFIX}the build code of the package {name} {version}.")
        }
    }
}

/// The decisions recorded in the ledger, read through the store and the artifact store.
#[derive(Clone)]
pub struct LedgerApprovals {
    store: Arc<dyn Store>,
    artifacts: Arc<dyn ArtifactStore>,
}

impl LedgerApprovals {
    /// A reader over these two ports.
    #[must_use]
    pub fn new(store: Arc<dyn Store>, artifacts: Arc<dyn ArtifactStore>) -> Self {
        Self { store, artifacts }
    }

    async fn read(&self, tenant: TenantId, job: JobId) -> Option<Vec<DependencyApproval>> {
        let scope = TenantScope::new(tenant);
        let mut tx = self.store.begin(scope).await.ok()?;
        let entries = read_all_ledger(&mut *tx, job).await;
        let entries = match entries {
            Ok(entries) if verify_chain(&entries).is_ok() => entries,
            _ => {
                let _ = tx.rollback().await;
                return None;
            }
        };
        let mut found = Vec::new();
        for entry in &entries {
            if entry.metadata.job_id != job
                || entry.claim.kind != ClaimKind::ExpertJudgment
                || !entry.claim.statement.as_str().starts_with(STATEMENT_PREFIX)
            {
                continue;
            }
            for evidence in &entry.evidence {
                let Evidence::Artifact(held) = evidence else {
                    continue;
                };
                if held.description.as_ref().map(|d| d.as_str()) != Some(ARTIFACT_NOTE) {
                    continue;
                }
                let Ok(indexed) = tx.get_artifact_index(&held.sha256).await else {
                    continue;
                };
                let Ok(bytes) = self.artifacts.get(&scope, &indexed.artifact).await else {
                    continue;
                };
                let Ok(document) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                    continue;
                };
                if let Some(approval) = DependencyApproval::from_json(&document)
                    && approval.scope == (DecisionScope { tenant, job })
                    && statement_of(&approval) == entry.claim.statement.as_str()
                {
                    found.push(approval);
                }
            }
        }
        let _ = tx.rollback().await;
        Some(found)
    }
}

#[async_trait]
impl RecordedApprovals for LedgerApprovals {
    fn fidelity(&self) -> Fidelity {
        // It reads the ledger of the store it is given, and verifies the rows. What the store is
        // (real or in memory) is the store's own fidelity in the registry.
        Fidelity::Real
    }

    /// Every decision recorded for `job`, or none when the ledger cannot be read or does not
    /// verify. None means the gate asks the person again, which is the safe side.
    async fn for_job(&self, tenant: TenantId, job: JobId) -> Vec<DependencyApproval> {
        self.read(tenant, job).await.unwrap_or_default()
    }
}
