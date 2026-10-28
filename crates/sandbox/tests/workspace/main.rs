//! The host-side workspace against real git (work package `s1-workspace-ingestion`).
//!
//! * `contract`: the workspace contract suite of the testkit, run against this adapter with real
//!   git and a local bare repository as the remote.
//! * `behavior`: restart, renames and type changes, the path rules, the patch and the views.
//! * `hostile`: the hostile fixtures of the security harness against the audit and ingestion, with
//!   the spawn recorder and the canary sweeper.
//! * `breaks`: deliberate breaks that the guards must catch.
//!
//! Tests that need Docker report BLOCKED (a panic that starts `BLOCKED:`) when there is no
//! daemon or no image. They never skip quietly.

#[path = "../support/mod.rs"]
mod support;

mod behavior;
mod contract;
mod harness;
mod hostile;
mod world;
