//! Which assurance claims of a gate decision may be written to the ledger.
//!
//! A gate decision can say that a passed gate supports an assurance level. The engine does not
//! take the handler's word for it. A claim is written only from evidence that is real and
//! current:
//!
//! * the engine itself records as a real component (a test run records as a fake, and the domain
//!   refuses an assurance level on a fake entry, INV-08);
//! * the claim names a gate whose report is in the same decision;
//! * the report passed, so a failed or blocked gate supports nothing;
//! * the report was made by a real environment, never a fake one;
//! * the report is current: it was made in the execution mode of the job and for this attempt. A
//!   report with no attempt cannot be shown to be about this one, so it is not current.
//!
//! A claim that does not meet all of these is dropped without an error. The stage run still
//! passes or fails on its evidence as before; it simply supports no assurance level.

use factory_domain::contracts::GateReport;
use factory_domain::vocabulary::{AssuranceLevel, Fidelity, GateOutcome, RecorderFidelity};

use super::decision::GateDecision;
use super::evidence::Expectation;

/// An assurance claim that may be written: the level, and the report that supports it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AssuranceEntry<'a> {
    /// The level the report supports.
    pub level: AssuranceLevel,
    /// Where the report is in `GateDecision::reports`, so the caller can find its stored form.
    pub report_index: usize,
    /// The report.
    pub report: &'a GateReport,
}

/// The claims of `decision` that real, current evidence supports, in the order they were made.
#[must_use]
pub fn assurance_entries<'a>(
    decision: &'a GateDecision,
    expect: &Expectation,
    recorder: RecorderFidelity,
) -> Vec<AssuranceEntry<'a>> {
    if recorder != RecorderFidelity::Real {
        return Vec::new();
    }
    decision
        .assurance
        .iter()
        .filter_map(|claim| {
            let (report_index, report) = decision
                .reports
                .iter()
                .enumerate()
                .find(|(_, report)| report.metadata.gate_id == claim.gate)?;
            let current = report.metadata.attempt_id == Some(expect.attempt)
                && report.metadata.execution_mode == expect.mode;
            let real = report.environment.fidelity == Fidelity::Real;
            (report.outcome == GateOutcome::Passed && real && current).then_some(AssuranceEntry {
                level: claim.level,
                report_index,
                report,
            })
        })
        .collect()
}
