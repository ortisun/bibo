//! The command gates: format, lint, build and tests, run in a fresh verify container.
//!
//! A command gate is an argument vector that the **base commit's** project manifest declares
//! ([`definition`]). The validation stage runs it through the sandbox port and the supervisor
//! observes how it ended. This module holds the three pure steps around that run:
//!
//! 1. [`definition`] turns the manifest into gates, passing each vector through the command
//!    policy of the `verify` profile, and hashes the set.
//! 2. [`verdict`] maps what the supervisor observed to `PASSED`, `FAILED` or `BLOCKED`, reading
//!    the test output with [`libtest`] for the test gate.
//! 3. [`report`] builds the gate report from the observation. Nothing in a report comes from a
//!    file the sandbox wrote.
//!
//! No function here runs anything or reads anything: the stage handler in
//! `crate::stages::validation` owns the ports.

pub mod definition;
pub mod libtest;
pub mod report;
pub mod verdict;

pub use definition::{
    CommandGate, MANIFEST_JSON_PATH, MANIFEST_PATH, Refusal, Resolved, Role, TrustedGates, gate_id,
};
pub use libtest::{Outcomes, Status};
pub use verdict::{Fail, Reading, Verdict, Why, interpret};
