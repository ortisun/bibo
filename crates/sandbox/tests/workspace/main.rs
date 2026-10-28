//! The host-side workspace against real git (work package `s1-workspace-ingestion`).
//!
//! * `contract`: the workspace contract suite of the testkit, run against this adapter with real
//!   git and a local bare repository as the remote.
//!
//! Tests that need Docker report BLOCKED (a panic that starts `BLOCKED:`) when there is no
//! daemon or no image. They never skip quietly.

#[path = "../support/mod.rs"]
mod support;

mod contract;
mod harness;
