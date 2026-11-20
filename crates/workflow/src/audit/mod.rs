//! The audit stream: who did what, under which policy hash and correlation id.
//!
//! The engine writes an audit record for each decision that the policy requires to be recorded
//! (`policies/security.yaml`, `audit.must_record`). [`action`] names the required types.

mod action;
mod verifier;

pub use action::{AuditAction, AuditDecision, AuditKind};
pub use verifier::{AuditReport, Finding, RunOutcomes, check_job};
