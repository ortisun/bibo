//! The protected-path rules, applied to the trusted tree diff.
//!
//! `PathPolicy::check_diff` decides every entry with the folding, the rename and the type rules
//! of the policy. This module only sorts what it refuses into two gates:
//!
//! * `protected-paths-unchanged`: everything except test code. A change to CI, the gate and
//!   toolchain configuration, agent instruction files, the factory's own configuration or
//!   version-control internals, a hidden path, a path that is not safe, a gitlink or a link that
//!   escapes.
//! * `test-file-protection`: a change the `test_code` and `test_fixtures_and_goldens` groups
//!   refuse, which is a removed, renamed or edited line of an existing test or fixture.
//!
//! No evidence of an exception is passed to the policy. A protected change that a person
//! approved reaches the stage through the approval flow, never through the builder's patch.

use factory_domain::policy::RepoKind;
use factory_domain::policy::paths::{
    ChangeEvidence, DiffEntry, DiffVerdict, PathDenial, PathDenialReason, PathPolicy,
};

use super::Violation;

/// The policy groups whose refusals belong to the test-protection gate.
const TEST_GROUPS: [&str; 2] = ["test_code", "test_fixtures_and_goldens"];

/// What the policy refused, sorted into the two gates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Refusals {
    /// For `protected-paths-unchanged`.
    pub protected: Vec<Violation>,
    /// For `test-file-protection`.
    pub tests: Vec<Violation>,
}

/// Decides the diff and sorts the refusals.
#[must_use]
pub fn check(policy: &PathPolicy, entries: &[DiffEntry]) -> Refusals {
    let verdict = policy.check_diff(RepoKind::Target, entries, None, &ChangeEvidence::default());
    let DiffVerdict::Blocked { denials } = verdict else {
        return Refusals::default();
    };
    let mut refusals = Refusals::default();
    for denied in denials {
        let in_test_group = TEST_GROUPS.contains(&denied.denial.rule.id());
        let violation = Violation {
            check: check_id(&denied.denial),
            message: sentence(&denied.path, &denied.denial),
            path: (!denied.path.is_empty()).then_some(denied.path),
            line: None,
        };
        if in_test_group {
            refusals.tests.push(violation);
        } else {
            refusals.protected.push(violation);
        }
    }
    refusals
}

fn check_id(denial: &PathDenial) -> &'static str {
    match denial.reason {
        PathDenialReason::Hidden => "hidden-path",
        PathDenialReason::DenyWrite => "protected-path-changed",
        PathDenialReason::AppendOnly => "append-only-path-changed",
        PathDenialReason::AdditionsOnly => "test-code-not-additions-only",
        PathDenialReason::Unnormalizable(_) => "unsafe-path",
        PathDenialReason::OutsideWriteAllow => "outside-write-allow",
        PathDenialReason::OutsideTaskScope => "outside-task-scope",
        PathDenialReason::Gitlink => "gitlink",
        PathDenialReason::SymlinkEscapes | PathDenialReason::SymlinkIntoProtected => {
            "symlink-escapes"
        }
        PathDenialReason::TooManyFiles => "too-many-files",
    }
}

fn sentence(path: &str, denial: &PathDenial) -> String {
    let rule = denial.rule.to_string();
    let what = match denial.reason {
        PathDenialReason::Hidden => "is a hidden path that no change may touch",
        PathDenialReason::DenyWrite => "is a protected path that a builder may not change",
        PathDenialReason::AppendOnly => {
            "may gain new files but an existing file there may not change"
        }
        PathDenialReason::AdditionsOnly => {
            "is test code, and an existing file may only gain lines, so a removed or edited line is refused"
        }
        PathDenialReason::Unnormalizable(_) => "is not a safe repository path",
        PathDenialReason::OutsideWriteAllow => "is outside the paths a change may write",
        PathDenialReason::OutsideTaskScope => "is outside the files the task owns",
        PathDenialReason::Gitlink => "is a gitlink, which no change may add",
        PathDenialReason::SymlinkEscapes | PathDenialReason::SymlinkIntoProtected => {
            "is a link that points outside the workspace or into a protected place"
        }
        PathDenialReason::TooManyFiles => "is one of more changed files than the policy allows",
    };
    format!("The path {path} {what} (policy rule {rule}).")
}
