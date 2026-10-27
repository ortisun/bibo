//! The gate framework: how stored evidence becomes a gate outcome.
//!
//! The pieces arrive in order: the [`decision`] types now, the evidence rules and the outcome
//! computation in the gate increment.

pub mod decision;

pub use decision::GateDecision;
