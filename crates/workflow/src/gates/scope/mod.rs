//! The host-side gates: rules over the trusted tree diff.
//!
//! These gates read the change the way the control plane sees it, on the host, from the job's
//! object store, after the sandbox is gone. None of them runs in the sandbox and none of them
//! reads a file the sandbox wrote. The inputs are the changed paths and both versions of each
//! file ([`diff::FileChange`]) and the extended headers of the exported patch ([`patch`]).
//!
//! | Module | Gate | Answers |
//! |---|---|---|
//! | [`protected`] | `protected-paths-unchanged`, and the refusals that belong to `test-file-protection` | whether the policy lets this diff through |
//! | [`weakening`] | `test-file-protection` | whether a test was skipped, removed or weakened inside a file |
//! | [`secrets`] | `secret-scan` | whether a new line is a secret |
//! | [`acceptance`] | `acceptance-evidence` | whether every requirement has a passed covering test |
//!
//! Every function is pure. The stage handler reads the ports and hands the values in.

pub mod acceptance;
pub mod diff;
pub mod lines;
pub mod patch;
pub mod protected;
pub mod secrets;
pub mod weakening;

pub use diff::{FileChange, entries};
pub use patch::{Facts, PatchFact};

/// One thing a host-side gate refuses. It names a path and never the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// A slug naming the check, such as `protected-path-changed`.
    pub check: &'static str,
    /// What is wrong, in a plain sentence.
    pub message: String,
    /// The path, when the violation is about one.
    pub path: Option<String>,
    /// The line from 1, when the violation is about one.
    pub line: Option<u32>,
}
