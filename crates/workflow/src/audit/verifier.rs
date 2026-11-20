//! The job audit verifier: reads a job back and says whether its record can be trusted.
//!
//! It checks what the engine promises about a job's record, from the record alone:
//!
//! * the evidence ledger is one unbroken hash chain (ADR 0008);
//! * in a production job no entry was made by a fake component or in test mode (INV-08);
//! * every `PASSED` stage run has evidence behind it: a gate report for a gate pass, a named
//!   person's judgment for an approval or an override (INV-03, INV-06);
//! * every `SKIPPED` stage run has the rule that skipped it in the ledger.
//!
//! The verifier does not repair anything. A finding names what is wrong and where, in plain
//! English, and the caller decides.

use factory_domain::contracts::EvidenceLedgerEntry;
use factory_domain::contracts::evidence_ledger_entry::EvidenceKind;
use factory_domain::ids::{JobId, StageRunId, TenantId};
use factory_domain::ledger::{ChainError, verify_chain};
use factory_domain::state::StageRunStatus;
use factory_domain::vocabulary::{ExecutionMode, RecorderFidelity};

use crate::engine::{Engine, EngineError};

/// One thing the verifier found wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// The ledger is not one unbroken chain.
    ChainBroken(ChainError),
    /// A production job holds an entry made by a fake or simulated component, or in test mode.
    FakeEntryInProduction {
        /// The position of the entry.
        sequence: u64,
    },
    /// A stage run is `PASSED` and no ledger entry holds the evidence that passed it.
    PassedWithoutEvidence {
        /// The stage run.
        stage_run: StageRunId,
    },
    /// A stage run is `SKIPPED` and no ledger entry holds the rule that skipped it.
    SkippedWithoutRule {
        /// The stage run.
        stage_run: StageRunId,
    },
}

/// What the verifier read and what it found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    /// The job.
    pub job: JobId,
    /// How many ledger entries were read.
    pub entries_checked: usize,
    /// How many stage runs were checked.
    pub stage_runs_checked: usize,
    /// What is wrong. Empty when the record can be trusted.
    pub findings: Vec<Finding>,
}

impl AuditReport {
    /// True when nothing is wrong.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

/// The stage runs of a job by how they ended, as the verifier needs them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOutcomes {
    /// Runs that are `PASSED`.
    pub passed: Vec<StageRunId>,
    /// Runs that are `SKIPPED`.
    pub skipped: Vec<StageRunId>,
}

impl RunOutcomes {
    /// Sorts stage runs by how they ended.
    #[must_use]
    pub fn from_statuses(runs: impl IntoIterator<Item = (StageRunId, StageRunStatus)>) -> Self {
        let mut outcomes = Self::default();
        for (id, status) in runs {
            match status {
                StageRunStatus::Passed => outcomes.passed.push(id),
                StageRunStatus::Skipped => outcomes.skipped.push(id),
                _ => {}
            }
        }
        outcomes
    }
}

/// Checks a ledger and the outcomes of the stage runs against the rules above.
#[must_use]
pub fn check_job(
    entries: &[EvidenceLedgerEntry],
    outcomes: &RunOutcomes,
    mode: ExecutionMode,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Err(error) = verify_chain(entries) {
        findings.push(Finding::ChainBroken(error));
    }
    if mode == ExecutionMode::Production {
        for entry in entries {
            let made_by_a_stand_in = entry.metadata.recorded_by.fidelity != RecorderFidelity::Real
                || entry.metadata.execution_mode != ExecutionMode::Production;
            if made_by_a_stand_in {
                findings.push(Finding::FakeEntryInProduction {
                    sequence: entry.sequence(),
                });
            }
        }
    }
    let evidenced = |run: StageRunId, kinds: &[EvidenceKind]| {
        entries.iter().any(|entry| {
            entry.metadata.stage_run_id == run
                && entry
                    .evidence
                    .iter()
                    .any(|evidence| kinds.contains(&evidence.kind()))
        })
    };
    for run in &outcomes.passed {
        // A gate pass rests on a gate report. An approval or an override rests on a person.
        if !evidenced(*run, &[EvidenceKind::Test, EvidenceKind::ExpertJudgment]) {
            findings.push(Finding::PassedWithoutEvidence { stage_run: *run });
        }
    }
    for run in &outcomes.skipped {
        if !evidenced(*run, &[EvidenceKind::Source]) {
            findings.push(Finding::SkippedWithoutRule { stage_run: *run });
        }
    }
    findings
}

impl Engine {
    /// Reads a job back and checks its record.
    ///
    /// # Errors
    /// The store errors of the reads.
    pub async fn verify_job(
        &self,
        tenant: TenantId,
        job: JobId,
    ) -> Result<AuditReport, EngineError> {
        let view = self.job_view(tenant, job).await?;
        let mut tx = self.tenant_tx(tenant).await?;
        let entries = crate::engine::read_all_ledger(&mut *tx, job).await?;
        tx.rollback().await?;
        let outcomes =
            RunOutcomes::from_statuses(view.stage_runs.iter().map(|run| (run.id, run.status)));
        let findings = check_job(&entries, &outcomes, self.config.mode);
        Ok(AuditReport {
            job,
            entries_checked: entries.len(),
            stage_runs_checked: outcomes.passed.len() + outcomes.skipped.len(),
            findings,
        })
    }
}
