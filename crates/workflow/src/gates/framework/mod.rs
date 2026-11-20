//! The gate framework: how stored evidence becomes a gate outcome.
//!
//! * [`decision`] is what a stage handler's `evaluate` returns: typed gate reports and a review
//!   verdict. It has no field that says "passed".
//! * [`evidence`] checks that each document is about this stage run, was made in the job's
//!   execution mode, follows its schema, and does not repeat a gate.
//! * [`resolve`] reads the contract's evaluator and the evidence and says what the gate found:
//!   pass, blocked, failed, changes required, or a person. A gate that did not run blocks.
//!
//! The engine applies the result: it writes the ledger entries, asks the domain guard for the
//! move that the result names, and commits the move with its evidence in one transaction
//! (INV-03). The agent's own account of its work appears nowhere in this module.

pub mod assurance;
pub mod decision;
pub mod evidence;
pub mod resolve;

pub use assurance::{AssuranceEntry, assurance_entries};
pub use decision::{AssuranceClaim, GateDecision};
pub use evidence::{EvidenceProblem, Expectation, check_evidence};
pub use resolve::{BlockCause, Resolution, failing_set, resolve, snapshots, uncovered_criteria};

#[cfg(test)]
mod tests;
