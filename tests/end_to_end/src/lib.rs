//! The end-to-end acceptance harness of the Universal Agentic Software Factory.
//!
//! # What is here
//!
//! * [`evidence`]: the evidence of one run, as plain data. The assertions read it.
//! * [`assertions`]: A1 to A14, machine-checkable, from `docs/architecture/slice-plan.md`.
//! * [`issues`]: the English, Portuguese, hostile, edited, ambiguous and out-of-policy requests.
//! * [`canned`]: an honest evidence set for the happy path, used to prove the assertions.
//!
//! The pieces that run a scenario (the scenario definitions, the runner and the wirings) are added
//! in the modules that follow. A wiring is the thing that drives the factory and collects the
//! evidence. The composition package supplies the real one. [`scripted`] is the stand-in that runs
//! today, with labelled fakes.
//!
//! # The rule
//!
//! Nothing is mocked without a label, and a result that could not be produced is `BLOCKED`, never
//! a pass. The harness reads stored records and GitHub, not log text.

pub mod assertions;
pub mod canned;
pub mod check;
pub mod evidence;
pub mod issues;
pub mod mutations;
pub mod preflight;
pub mod runner;
pub mod scenario_checks;
pub mod scenarios;
#[cfg(feature = "scripted")]
pub mod scripted;

pub use check::{Check, Env, StageSpec, Verdict};
pub use evidence::{Mode, RunEvidence};

use std::path::{Path, PathBuf};

/// The root of the repository that holds this crate: two levels above `tests/end_to_end`.
#[must_use]
pub fn repository_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| manifest.to_path_buf(), Path::to_path_buf)
}
