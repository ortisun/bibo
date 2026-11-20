//! Contract tests for the `word-count` fixture repository.
//!
//! The fixture (`fixtures/repos/word-count`) is the repository the end-to-end run works on. It has
//! to stay a small, honest, dependency-free Rust tool: if it drifts, the end-to-end proof stops
//! meaning what it says. This crate pins it.
//!
//! * [`checks`] reads the fixture as files and reports every rule it breaks. A check that finds
//!   nothing returns an empty list.
//! * [`exec`] runs the fixture's own commands (format, lint, build, test) on a copy, on the host
//!   or in the pinned verify image. It reports `Blocked` when the host or Docker cannot run them,
//!   never a pass.
//! * [`workdir`] makes the copies. The fixture directory itself is never written to.
//!
//! The tests in `tests/` run each check on the real fixture and on a copy with one deliberate
//! defect, so a check that cannot fail is caught here.

pub mod checks;
pub mod exec;
pub mod workdir;

use std::fmt;
use std::path::{Path, PathBuf};

/// One rule that the fixture breaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The check that found it, such as `layout` or `manifest`.
    pub check: &'static str,
    /// What is wrong, in a sentence.
    pub detail: String,
}

impl Finding {
    /// A finding of `check`.
    pub fn new(check: &'static str, detail: impl Into<String>) -> Self {
        Self {
            check,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.check, self.detail)
    }
}

/// The result of something that may not be able to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It ran and held.
    Passed,
    /// It ran and found problems.
    Failed(Vec<Finding>),
    /// It could not run, so there is no evidence either way. The reason says what is missing.
    Blocked(String),
}

impl Outcome {
    /// True only for [`Outcome::Passed`].
    #[must_use]
    pub fn is_passed(&self) -> bool {
        matches!(self, Self::Passed)
    }
}

/// The root of the factory repository that holds this crate: two levels above `tests/contract`.
#[must_use]
pub fn repository_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| manifest.to_path_buf(), Path::to_path_buf)
}

/// The fixture directory of the repository that holds this crate.
#[must_use]
pub fn fixture_dir() -> PathBuf {
    repository_root().join("fixtures/repos/word-count")
}
