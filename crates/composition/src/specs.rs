//! The three seams of the specification stage that read or keep state in the store:
//! [`StoreSpecDrafts`] (`SpecDrafts`), [`StoreSpecApprovals`] (`SpecApprovals`) and
//! [`StoreSpecHistory`] (`SpecHistory`).
//!
//! No table holds a specification draft and the store port has no operation for one, so a draft
//! is an artifact: the stage run's draft is stored as a JSON document in the artifact store,
//! indexed for the tenant, and linked to the stage run as an output under the role
//! `spec-draft-<k>` (`k` counts the drafts the run kept, from 1). The engine's readers skip a role
//! that is not of the form `<deliverable>.a<n>`, so these links are invisible to them, and the
//! link has a creation time by the database clock. That time is what binds an approval to a
//! draft (below).
//!
//! # Which draft an approval is for
//!
//! A draft is identified by the hash of its contract bytes, the hash the stage computes before it
//! asks a person. The engine records a person's approval as a ledger entry of expert judgment on the stage run
//! (who, in which role, when). It does not say which draft the person saw. The seam answers
//! "the approval of the draft with this hash" with the window in which the person decided: an
//! approval counts for a draft if it was recorded after the draft was kept and before the next
//! draft of the same run was kept. An approval before a draft existed, or between two drafts,
//! belongs to the earlier one. This relies on the engine's clock and the database clock being the
//! same machine's, which is the Slice 1 deployment. The mismatch list in the README asks for the
//! draft hash to ride on the decision.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::SpecificationContract;
use factory_domain::contracts::evidence_ledger_entry::{ClaimKind, Evidence};
use factory_domain::contracts::specification_contract::{ApprovalBasis, SpecApproverRole};
use factory_domain::state::StageRunStatus;
use factory_domain::values::{MediaType, Sha256Digest, Slug};
use factory_domain::vocabulary::{Fidelity, HumanRole, StageKind};
use factory_ports::artifact::ArtifactStore;
use factory_ports::paths::CommitSha;
use factory_ports::store::{
    ArtifactDirection, NewArtifactIndexEntry, StageRunArtifact, Store, StoreError,
};
use factory_workflow::handlers::RunIdentity;
use factory_workflow::stages::specification::seams::{
    ApprovalRecord, DraftRecord, PreviousSpec, SeamError, SpecApprovals, SpecDrafts, SpecHistory,
};
use serde::{Deserialize, Serialize};

use crate::reading::Reader;

const DRAFT_ROLE_PREFIX: &str = "spec-draft-";

/// The words of the sentence the engine writes into the ledger when a person approves. The entry
/// has no field for the outcome, so the sentence is read.
const APPROVED: &str = " approved the ";

/// What a draft is stored as.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDraft {
    commit: String,
    feature_directory: String,
    contract: String,
    evidence: String,
}

fn draft_number(role: &str) -> Option<u32> {
    let digits = role.strip_prefix(DRAFT_ROLE_PREFIX)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The links of a stage run that are drafts, oldest first.
fn draft_links(links: Vec<StageRunArtifact>) -> Vec<(u32, StageRunArtifact)> {
    let mut drafts: Vec<(u32, StageRunArtifact)> = links
        .into_iter()
        .filter(|link| link.direction == ArtifactDirection::Output)
        .filter_map(|link| draft_number(link.role.as_str()).map(|k| (k, link)))
        .collect();
    drafts.sort_by_key(|(k, _)| *k);
    drafts
}

fn seam(error: &StoreError) -> SeamError {
    match error {
        StoreError::NotFound => SeamError::NotFound,
        _ => SeamError::Unavailable,
    }
}

// ------------------------------------------------------------------------------------------
// SpecDrafts
// ------------------------------------------------------------------------------------------

/// Keeps the draft of a stage run in the artifact store, linked to the run.
#[derive(Clone)]
pub struct StoreSpecDrafts {
    reader: Reader,
}

impl StoreSpecDrafts {
    /// Drafts over the store and the artifact store.
    #[must_use]
    pub fn new(store: Arc<dyn Store>, artifacts: Arc<dyn ArtifactStore>) -> Self {
        Self {
            reader: Reader::new(store, artifacts),
        }
    }
}

#[async_trait]
impl SpecDrafts for StoreSpecDrafts {
    fn fidelity(&self) -> Fidelity {
        // Durable when the store and the artifact store are.
        if self.reader.store().fidelity() == Fidelity::Real
            && self.reader.artifacts().fidelity() == Fidelity::Real
        {
            Fidelity::Real
        } else {
            Fidelity::Fake
        }
    }

    async fn save(&self, run: &RunIdentity, record: DraftRecord) -> Result<(), SeamError> {
        let stored = StoredDraft {
            commit: record.commit.as_str().to_owned(),
            feature_directory: record.feature_directory,
            contract: String::from_utf8(record.contract).map_err(|_| SeamError::Unavailable)?,
            evidence: String::from_utf8(record.evidence).map_err(|_| SeamError::Unavailable)?,
        };
        let bytes = serde_json::to_vec(&stored).map_err(|_| SeamError::Unavailable)?;
        let reference = self
            .reader
            .artifacts()
            .put(
                bytes,
                MediaType::parse("application/json").map_err(|_| SeamError::Unavailable)?,
            )
            .await
            .map_err(|_| SeamError::Unavailable)?;
        let mut tx = self.reader.begin(run.tenant).await?;
        let outcome = async {
            let existing = draft_links(
                tx.list_stage_run_artifacts(run.stage_run)
                    .await
                    .map_err(|error| seam(&error))?,
            );
            // The same draft again is not a second draft.
            if existing
                .last()
                .is_some_and(|(_, link)| link.sha256 == reference.sha256)
            {
                return Ok(());
            }
            let entry =
                NewArtifactIndexEntry::from_reference(&reference, Some((run.job, run.stage_run)))
                    .ok_or(SeamError::Unavailable)?;
            tx.index_artifact(entry)
                .await
                .map_err(|error| seam(&error))?;
            let next = existing.last().map_or(1, |(k, _)| k + 1);
            let role = Slug::parse(&format!("{DRAFT_ROLE_PREFIX}{next}"))
                .map_err(|_| SeamError::Unavailable)?;
            tx.link_stage_run_artifact(
                run.stage_run,
                ArtifactDirection::Output,
                role,
                reference.sha256.clone(),
            )
            .await
            .map_err(|error| seam(&error))
        }
        .await;
        match outcome {
            Ok(()) => tx.commit().await.map_err(|_| SeamError::Unavailable),
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    async fn load(&self, run: &RunIdentity) -> Result<Option<DraftRecord>, SeamError> {
        let mut tx = self.reader.begin(run.tenant).await?;
        let outcome = async {
            let drafts = draft_links(
                tx.list_stage_run_artifacts(run.stage_run)
                    .await
                    .map_err(|error| seam(&error))?,
            );
            let Some((_, newest)) = drafts.last() else {
                return Ok(None);
            };
            let bytes = self
                .reader
                .bytes(&mut *tx, run.tenant, &newest.sha256)
                .await?;
            let stored: StoredDraft =
                serde_json::from_slice(&bytes).map_err(|_| SeamError::Unavailable)?;
            Ok(Some(DraftRecord {
                commit: CommitSha::parse(&stored.commit).map_err(|_| SeamError::Unavailable)?,
                feature_directory: stored.feature_directory,
                contract: stored.contract.into_bytes(),
                evidence: stored.evidence.into_bytes(),
            }))
        }
        .await;
        let _ = tx.rollback().await;
        outcome
    }
}

// ------------------------------------------------------------------------------------------
// SpecApprovals
// ------------------------------------------------------------------------------------------

/// Reads the approval of a specification draft from the ledger of its stage run.
#[derive(Clone)]
pub struct StoreSpecApprovals {
    reader: Reader,
}

impl StoreSpecApprovals {
    /// Approvals over the store and the artifact store.
    #[must_use]
    pub fn new(store: Arc<dyn Store>, artifacts: Arc<dyn ArtifactStore>) -> Self {
        Self {
            reader: Reader::new(store, artifacts),
        }
    }
}

fn spec_role(role: HumanRole) -> Option<SpecApproverRole> {
    match role {
        HumanRole::Approver => Some(SpecApproverRole::Approver),
        HumanRole::Operator => Some(SpecApproverRole::Operator),
        _ => None,
    }
}

#[async_trait]
impl SpecApprovals for StoreSpecApprovals {
    fn fidelity(&self) -> Fidelity {
        self.reader.store().fidelity()
    }

    async fn approval(
        &self,
        run: &RunIdentity,
        draft: &Sha256Digest,
    ) -> Result<Option<ApprovalRecord>, SeamError> {
        let mut tx = self.reader.begin(run.tenant).await?;
        let outcome = async {
            let drafts = draft_links(
                tx.list_stage_run_artifacts(run.stage_run)
                    .await
                    .map_err(|error| seam(&error))?,
            );
            // A draft is identified by the hash of its contract bytes, which is the hash the
            // stage computes before it asks (`Evidence::draft_sha256`).
            let mut hashes = Vec::with_capacity(drafts.len());
            for (_, link) in &drafts {
                let bytes = self
                    .reader
                    .bytes(&mut *tx, run.tenant, &link.sha256)
                    .await?;
                let stored: StoredDraft =
                    serde_json::from_slice(&bytes).map_err(|_| SeamError::Unavailable)?;
                hashes.push(Sha256Digest::of(stored.contract.as_bytes()));
            }
            // The window of this draft: from the time it was kept to the time the next was. When
            // the same contract was kept twice, the newest keeping counts.
            let Some(at) = hashes.iter().rposition(|hash| hash == draft) else {
                // A draft the run never kept has no approval.
                return Ok(None);
            };
            let from = drafts[at].1.created_at;
            let until = drafts.get(at + 1).map(|(_, link)| link.created_at);
            let entries = Reader::run_ledger(&mut *tx, run.job, run.stage_run).await?;
            let found = entries
                .iter()
                .filter(|entry| entry.claim.kind == ClaimKind::ExpertJudgment)
                .filter(|entry| entry.claim.statement.as_str().contains(APPROVED))
                .flat_map(|entry| entry.evidence.iter())
                .filter_map(|evidence| match evidence {
                    Evidence::ExpertJudgment(judgment) => Some(judgment),
                    _ => None,
                })
                .filter(|judgment| {
                    judgment.recorded_at >= from
                        && until.is_none_or(|end| judgment.recorded_at < end)
                })
                .find_map(|judgment| {
                    spec_role(judgment.attestor.role).map(|role| ApprovalRecord {
                        principal: judgment.attestor.principal_id,
                        role,
                        basis: ApprovalBasis::HumanDecision,
                        at: judgment.recorded_at,
                    })
                });
            Ok(found)
        }
        .await;
        let _ = tx.rollback().await;
        outcome
    }
}

// ------------------------------------------------------------------------------------------
// SpecHistory
// ------------------------------------------------------------------------------------------

/// The sentence given to the writer when a revision has no recorded reason of its own. The engine
/// stores no reason with a supersession by an edited request, so this is all the seam can say. The
/// writer reads the new request as well, so it sees what changed.
pub const REVISION_REASON: &str = "The source request was edited after the specification was approved. Revise the specification so that it matches the current request.";

/// Finds the approved specification that a new run revises.
#[derive(Clone)]
pub struct StoreSpecHistory {
    reader: Reader,
}

impl StoreSpecHistory {
    /// A history over the store and the artifact store.
    #[must_use]
    pub fn new(store: Arc<dyn Store>, artifacts: Arc<dyn ArtifactStore>) -> Self {
        Self {
            reader: Reader::new(store, artifacts),
        }
    }
}

#[async_trait]
impl SpecHistory for StoreSpecHistory {
    fn fidelity(&self) -> Fidelity {
        self.reader.fidelity()
    }

    async fn previous(&self, run: &RunIdentity) -> Result<Option<PreviousSpec>, SeamError> {
        let mut tx = self.reader.begin(run.tenant).await?;
        let outcome = async {
            let this = tx
                .get_stage_run(run.stage_run)
                .await
                .map_err(|error| seam(&error))?
                .value;
            let runs = tx
                .list_stage_runs(run.job)
                .await
                .map_err(|error| seam(&error))?;
            // Earlier runs of the stage, newest first. Only one that was approved and then
            // replaced, or that stands approved, is the basis of a revision.
            let earlier = runs.iter().rev().filter(|candidate| {
                candidate.value.kind == StageKind::Specification
                    && candidate.value.run_number < this.run_number
                    && matches!(
                        candidate.value.status,
                        StageRunStatus::Superseded | StageRunStatus::Passed
                    )
            });
            for candidate in earlier {
                let outputs = Reader::outputs(&mut *tx, candidate.value.id).await?;
                let Some(contract_hash) = outputs.get("specification-contract") else {
                    continue;
                };
                let bytes = self
                    .reader
                    .bytes(&mut *tx, run.tenant, contract_hash)
                    .await?;
                let Ok(contract) = serde_json::from_slice::<SpecificationContract>(&bytes) else {
                    continue;
                };
                if contract.metadata.status
                    != factory_domain::contracts::specification_contract::SpecStatus::Approved
                {
                    continue;
                }
                let commit = match outputs.get("specification-evidence") {
                    Some(hash) => {
                        let evidence = self.reader.bytes(&mut *tx, run.tenant, hash).await?;
                        serde_json::from_slice::<serde_json::Value>(&evidence)
                            .ok()
                            .and_then(|value| {
                                value
                                    .get("head_commit")
                                    .and_then(serde_json::Value::as_str)
                                    .and_then(|text| CommitSha::parse(text).ok())
                            })
                    }
                    None => None,
                };
                let Some(commit) = commit else {
                    // An approved specification whose files cannot be located is not a basis the
                    // stage can revise. The stage fails closed rather than start from scratch.
                    return Err(SeamError::Unavailable);
                };
                return Ok(Some(PreviousSpec {
                    contract,
                    commit,
                    reason: REVISION_REASON.to_owned(),
                }));
            }
            Ok(None)
        }
        .await;
        let _ = tx.rollback().await;
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_draft_role_carries_its_number_and_nothing_else_is_one() {
        assert_eq!(draft_number("spec-draft-1"), Some(1));
        assert_eq!(draft_number("spec-draft-12"), Some(12));
        assert_eq!(draft_number("spec-draft-"), None);
        assert_eq!(draft_number("spec-draft-x"), None);
        assert_eq!(draft_number("specification-contract.a1"), None);
        assert_eq!(draft_number("human-answer-1"), None);
    }
}
