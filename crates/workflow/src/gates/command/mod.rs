//! The command gates: format, lint, build and tests, run in a fresh verify container.
//!
//! A command gate is an argument vector that the **base commit's** project manifest declares
//! ([`definition`]). The validation stage runs it through the sandbox port and the supervisor
//! observes how it ended. This module holds the three pure steps around that run:
//!
//! 1. [`definition`] turns the manifest into gates, passing each vector through the command
//!    policy of the `verify` profile, and hashes the set.
//! 2. [`verdict`] maps what the supervisor observed to `PASSED`, `FAILED` or `BLOCKED`. For the
//!    test gate it reads the test report in the format the manifest names: [`libtest`] (the
//!    default), [`junit`] or [`tap`]. All three produce the one model of [`outcomes`], so
//!    nothing after the reading knows which test runner ran.
//! 3. [`report`] builds the gate report from the observation. Nothing in a gate report is
//!    copied from a file the sandbox wrote: a test report file is read back by a command the
//!    supervisor runs and observes, and only the verdict drawn from it enters the gate report.
//!
//! No function here runs anything or reads anything: the stage handler in
//! `crate::stages::validation` owns the ports.

pub mod definition;
pub mod junit;
pub mod libtest;
pub mod outcomes;
pub mod report;
pub mod tap;
pub mod verdict;

pub use definition::{
    CommandGate, MANIFEST_JSON_PATH, MANIFEST_PATH, Refusal, Resolved, Role, TestReport,
    TrustedGates, gate_id,
};
pub use outcomes::{Outcomes, ReportKind, Status};
pub use verdict::{Fail, Reading, Verdict, Why, interpret};
