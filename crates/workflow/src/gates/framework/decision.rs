//! What a stage handler's `evaluate` returns: the typed evidence a gate found.
//!
//! A decision is a bundle of **evidence**, not a verdict. The handler hands over the gate reports
//! it produced and the reviewer's verdict, as the typed contracts of `schemas/`. The engine then
//! validates each document, stores it, writes the ledger entries that cite it, and only then asks
//! the domain guard whether the stage run may pass. Nothing in a decision says "passed": a handler
//! that sets a flag has no flag to set (see `crate::gates::framework`).

use factory_domain::contracts::{GateReport, ReviewVerdict};

/// The evidence a gate collected for one stage run.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct GateDecision {
    /// One report for each deterministic gate that ran, and one `BLOCKED` report for each that
    /// could not run. A gate that has no report is treated as one that did not run (INV-06).
    pub reports: Vec<GateReport>,
    /// The independent reviewer's verdict, for a stage that has a reviewer.
    pub review: Option<ReviewVerdict>,
    /// The gate itself asks a person, such as the approval stage or an ambiguous intake.
    pub human_gate: bool,
    /// A deterministic check detected a violation of policy. The stage is blocked and nobody is
    /// asked: a reviewer's opinion about policy is a `ReviewVerdict` finding instead.
    pub policy_violation: bool,
}
