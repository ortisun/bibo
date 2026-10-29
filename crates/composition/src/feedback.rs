//! The seams that tell a stage run why it replaces another one: `ReworkSource` (implementation,
//! documenting, specification) and `RoundSource` (architecture, planning).
//!
//! The engine hands a handler no feedback. What happened is in the store, and this module reads it
//! back from the evidence the engine itself wrote:
//!
//! 1. **Which run failed.** When a gate sends work back, the engine, in one transaction, moves the
//!    failing run to `REWORK_REQUESTED` and creates a new run for the target stage and every stage
//!    after it. Each new run names the run it replaces (`rework_of`) and has the transaction's
//!    database time as its `created_at`. So the failing run is the one among the replaced runs
//!    that stands in `REWORK_REQUESTED`.
//! 2. **Why.** Each gate report the failing run produced is a ledger entry with test evidence, and
//!    the report is stored by its hash; the ones whose result is `failed` are the failed reports.
//!    A review verdict is a ledger entry with artifact evidence; its findings are the review's.
//! 3. **What the replaced run built.** Its output `implementation-result` or `documentation-result`
//!    names the head commit; the new run builds on it.
//!
//! A run that replaces nothing has no feedback (`None`). A store that cannot be read is
//! `Unavailable` and the stage fails closed, as the contract of both traits says: a rework run must
//! not run as if it were a first run.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::evidence_ledger_entry::{Evidence, TestResult};
use factory_domain::contracts::review_verdict::Finding;
use factory_domain::contracts::{ArtifactRef, GateReport, ReviewVerdict};
use factory_domain::ids::StageRunId;
use factory_domain::state::StageRunStatus;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::artifact::ArtifactStore;
use factory_ports::paths::CommitSha;
use factory_ports::store::{Store, Tx};
use factory_workflow::handlers::RunIdentity;
use factory_workflow::stages::architecture::seams::{PreviousRound, RoundSource};
use factory_workflow::stages::implementation::seams::{ReworkContext, ReworkSource};
use factory_workflow::stages::intake::seams::SeamError;

use crate::reading::Reader;

/// The words the engine puts on the artifact evidence of a review verdict. The verdict is found by
/// them and by the media type, because the ledger entry has no field that says "verdict".
const VERDICT_DESCRIPTION: &str = "The review verdict as the reviewer returned it";

/// Reads feedback for reworked runs from the stored evidence.
#[derive(Clone)]
pub struct StoreFeedback {
    reader: Reader,
}

/// What a replaced run left, found from the run that replaces it.
struct Replaced {
    /// The run this one replaces.
    previous: StageRunId,
    /// How many runs in the chain, this one excluded.
    round: u8,
    /// The run that failed its gate or was sent back, when it can be told.
    failing: Option<StageRunId>,
}

impl StoreFeedback {
    /// A source over the store and the artifact store.
    #[must_use]
    pub fn new(store: Arc<dyn Store>, artifacts: Arc<dyn ArtifactStore>) -> Self {
        Self {
            reader: Reader::new(store, artifacts),
        }
    }

    /// Finds the run this one replaces, how many rounds deep the chain is and the run that failed.
    async fn replaced(tx: &mut dyn Tx, run: &RunIdentity) -> Result<Option<Replaced>, SeamError> {
        let this = tx
            .get_stage_run(run.stage_run)
            .await
            .map_err(|_| SeamError::Unavailable)?
            .value;
        let Some(previous) = this.rework_of else {
            return Ok(None);
        };
        let runs = tx
            .list_stage_runs(run.job)
            .await
            .map_err(|_| SeamError::Unavailable)?;
        // The chain of runs of this stage: this one, the one it replaced, the one before.
        let mut round = 0_u8;
        let mut cursor = Some(this.id);
        while let Some(id) = cursor {
            let Some(found) = runs.iter().find(|candidate| candidate.value.id == id) else {
                break;
            };
            cursor = found.value.rework_of;
            if cursor.is_some() {
                round = round.saturating_add(1);
            }
        }
        // The runs the same rework move replaced, and among them the one that failed.
        let failing = runs
            .iter()
            .filter(|candidate| {
                candidate.value.rework_of.is_some() && candidate.value.created_at == this.created_at
            })
            .filter_map(|candidate| candidate.value.rework_of)
            .find(|id| {
                runs.iter().any(|other| {
                    other.value.id == *id && other.value.status == StageRunStatus::ReworkRequested
                })
            });
        Ok(Some(Replaced {
            previous,
            round,
            failing,
        }))
    }

    /// The gate reports the failing run produced that failed, and the findings of its verdict.
    async fn what_failed(
        &self,
        tx: &mut dyn Tx,
        run: &RunIdentity,
        failing: StageRunId,
    ) -> Result<(Vec<GateReport>, Vec<Finding>), SeamError> {
        let entries = Reader::run_ledger(tx, run.job, failing).await?;
        let mut failed_hashes: Vec<Sha256Digest> = Vec::new();
        let mut verdict_hashes: Vec<Sha256Digest> = Vec::new();
        for entry in &entries {
            for evidence in &entry.evidence {
                match evidence {
                    Evidence::Test(test)
                        if test.result == TestResult::Failed
                            && !failed_hashes.contains(&test.gate_report_sha256) =>
                    {
                        failed_hashes.push(test.gate_report_sha256.clone());
                    }
                    Evidence::Artifact(artifact)
                        if artifact
                            .description
                            .as_ref()
                            .is_some_and(|text| text.as_str() == VERDICT_DESCRIPTION)
                            && !verdict_hashes.contains(&artifact.sha256) =>
                    {
                        verdict_hashes.push(artifact.sha256.clone());
                    }
                    _ => {}
                }
            }
        }
        let mut reports = Vec::new();
        for hash in &failed_hashes {
            let bytes = self.reader.bytes(tx, run.tenant, hash).await?;
            let report =
                serde_json::from_slice::<GateReport>(&bytes).map_err(|_| SeamError::Unavailable)?;
            reports.push(report);
        }
        let mut findings = Vec::new();
        for hash in &verdict_hashes {
            let bytes = self.reader.bytes(tx, run.tenant, hash).await?;
            let verdict = serde_json::from_slice::<ReviewVerdict>(&bytes)
                .map_err(|_| SeamError::Unavailable)?;
            findings.extend(verdict.findings);
        }
        Ok((reports, findings))
    }

    /// The head commit named by a replaced run's result document, if it has one.
    async fn head_of(
        &self,
        tx: &mut dyn Tx,
        run: &RunIdentity,
        previous: StageRunId,
    ) -> Result<Option<CommitSha>, SeamError> {
        let name = match run.kind {
            StageKind::Implementation => "implementation-result",
            StageKind::Documenting => "documentation-result",
            _ => return Ok(None),
        };
        let outputs = Reader::outputs(tx, previous).await?;
        let Some(hash) = outputs.get(name) else {
            return Ok(None);
        };
        let bytes = self.reader.bytes(tx, run.tenant, hash).await?;
        Ok(serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("head_commit")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|text| CommitSha::parse(text).ok())
            }))
    }

    /// The commit the repository map was read at: the base of the job.
    async fn base_of(&self, tx: &mut dyn Tx, run: &RunIdentity) -> Result<CommitSha, SeamError> {
        let runs = tx
            .list_stage_runs(run.job)
            .await
            .map_err(|_| SeamError::Unavailable)?;
        let repo_run = runs
            .iter()
            .rfind(|candidate| {
                candidate.value.kind == StageKind::RepositoryIntelligence
                    && candidate.value.status == StageRunStatus::Passed
            })
            .ok_or(SeamError::NotFound)?;
        let outputs = Reader::outputs(tx, repo_run.value.id).await?;
        let hash = outputs.get("repository-map").ok_or(SeamError::NotFound)?;
        let bytes = self.reader.bytes(tx, run.tenant, hash).await?;
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("commit_sha")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|text| CommitSha::parse(text).ok())
            })
            .ok_or(SeamError::NotFound)
    }
}

/// Rolls back the read transaction and passes `outcome` through.
async fn end<T>(tx: Box<dyn Tx>, outcome: Result<T, SeamError>) -> Result<T, SeamError> {
    let _ = tx.rollback().await;
    outcome
}

#[async_trait]
impl ReworkSource for StoreFeedback {
    fn fidelity(&self) -> Fidelity {
        self.reader.fidelity()
    }

    async fn of(&self, run: &RunIdentity) -> Result<Option<ReworkContext>, SeamError> {
        let mut tx = self.reader.begin(run.tenant).await?;
        let outcome = async {
            let Some(replaced) = Self::replaced(&mut *tx, run).await? else {
                return Ok(None);
            };
            let (failed_reports, findings) = match replaced.failing {
                Some(failing) => self.what_failed(&mut *tx, run, failing).await?,
                None => (Vec::new(), Vec::new()),
            };
            let previous_head = match self.head_of(&mut *tx, run, replaced.previous).await? {
                Some(head) => head,
                // A stage with no result document builds on the base of the job.
                None => self.base_of(&mut *tx, run).await?,
            };
            Ok(Some(ReworkContext {
                previous_head,
                failed_reports,
                findings,
                round: replaced.round,
            }))
        }
        .await;
        end(tx, outcome).await
    }
}

#[async_trait]
impl RoundSource for StoreFeedback {
    fn fidelity(&self) -> Fidelity {
        self.reader.fidelity()
    }

    async fn previous(&self, run: &RunIdentity) -> Result<Option<PreviousRound>, SeamError> {
        let mut tx = self.reader.begin(run.tenant).await?;
        let outcome = async {
            let Some(replaced) = Self::replaced(&mut *tx, run).await? else {
                return Ok(None);
            };
            let failed_reports = match replaced.failing {
                Some(failing) => self.what_failed(&mut *tx, run, failing).await?.0,
                None => Vec::new(),
            };
            let (plan_version, previous_plan) = if run.kind == StageKind::TaskPlanning {
                self.previous_plan(&mut *tx, run, replaced.previous).await?
            } else {
                (0, None)
            };
            Ok(Some(PreviousRound {
                round: replaced.round,
                failed_reports,
                plan_version,
                previous_plan,
            }))
        }
        .await;
        end(tx, outcome).await
    }
}

impl StoreFeedback {
    /// The plan the replaced planning run made and its version.
    async fn previous_plan(
        &self,
        tx: &mut dyn Tx,
        run: &RunIdentity,
        previous: StageRunId,
    ) -> Result<(u32, Option<ArtifactRef>), SeamError> {
        let outputs = Reader::outputs(tx, previous).await?;
        let Some(hash) = outputs.get("task-plan") else {
            return Ok((0, None));
        };
        let reference = Reader::reference(tx, hash).await?;
        let bytes = self.reader.bytes(tx, run.tenant, hash).await?;
        let version = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .pointer("/metadata/plan_version")
                    .and_then(serde_json::Value::as_u64)
            })
            .and_then(|version| u32::try_from(version).ok())
            .unwrap_or(0);
        Ok((version, Some(reference)))
    }
}
