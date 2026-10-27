//! Checking that the evidence a gate handed over is about this stage run and may be used.
//!
//! A gate report or a review verdict is a typed document, and the engine does not trust a
//! document because a handler returned it. Before anything is written, each one must name this
//! job, this stage run and this attempt, must have been made in the execution mode of the job,
//! must follow the rules of its schema (a `PASSED` report whose commands did not all exit with
//! code 0 is refused by the schema type), and must not repeat a gate. Evidence that fails any of
//! these is not recorded and cannot pass a stage.

use std::collections::BTreeSet;

use factory_domain::contracts::Contract;
use factory_domain::ids::{AttemptId, JobId, StageRunId};
use factory_domain::vocabulary::{ExecutionMode, Fidelity};

use super::decision::GateDecision;

/// What the evidence must be about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expectation {
    /// The job.
    pub job: JobId,
    /// The stage run that is being judged.
    pub stage_run: StageRunId,
    /// The attempt whose output is being judged.
    pub attempt: AttemptId,
    /// The execution mode of the job.
    pub mode: ExecutionMode,
}

/// Why a piece of evidence cannot be used. The set is closed and carries no document text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceProblem {
    /// A report or verdict names another job or another stage run.
    #[error("a gate document names another job or stage run")]
    WrongSubject,
    /// A report names another attempt.
    #[error("a gate report names another attempt")]
    WrongAttempt,
    /// A document was made in another execution mode than the job runs in.
    #[error("a gate document was made in another execution mode")]
    WrongMode,
    /// A fake component made evidence for a production job.
    #[error("a fake component made evidence for a production job")]
    FakeInProduction,
    /// Two reports claim to be the report of one gate.
    #[error("two reports claim the same gate")]
    DuplicateGate,
    /// A document breaks a rule of its schema.
    #[error("a gate document breaks a rule of its schema")]
    InvalidDocument,
}

/// Checks every report and the verdict of a decision.
///
/// # Errors
/// The first problem found. The decision is then not recorded and the stage run is blocked.
pub fn check_evidence(
    decision: &GateDecision,
    expect: &Expectation,
) -> Result<(), EvidenceProblem> {
    let mut gates = BTreeSet::new();
    for report in &decision.reports {
        report
            .validate()
            .map_err(|_| EvidenceProblem::InvalidDocument)?;
        let meta = &report.metadata;
        if meta.job_id != expect.job || meta.stage_run_id != expect.stage_run {
            return Err(EvidenceProblem::WrongSubject);
        }
        if meta
            .attempt_id
            .is_some_and(|attempt| attempt != expect.attempt)
        {
            return Err(EvidenceProblem::WrongAttempt);
        }
        if meta.execution_mode != expect.mode {
            return Err(EvidenceProblem::WrongMode);
        }
        if expect.mode == ExecutionMode::Production && report.environment.fidelity == Fidelity::Fake
        {
            return Err(EvidenceProblem::FakeInProduction);
        }
        if !gates.insert(meta.gate_id.as_str().to_owned()) {
            return Err(EvidenceProblem::DuplicateGate);
        }
    }
    if let Some(verdict) = &decision.review {
        verdict
            .validate()
            .map_err(|_| EvidenceProblem::InvalidDocument)?;
        let meta = &verdict.metadata;
        if meta.job_id != expect.job || meta.stage_run_id != expect.stage_run {
            return Err(EvidenceProblem::WrongSubject);
        }
        if meta.execution_mode != expect.mode {
            return Err(EvidenceProblem::WrongMode);
        }
        if expect.mode == ExecutionMode::Production
            && meta.reviewer.runtime.fidelity == Fidelity::Fake
        {
            return Err(EvidenceProblem::FakeInProduction);
        }
    }
    Ok(())
}
