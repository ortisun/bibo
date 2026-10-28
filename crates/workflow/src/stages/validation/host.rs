//! The host-side gates: what the control plane decides from the committed trees alone.
//!
//! These run first and run before any command: a change that touches a protected path, weakens a
//! test or adds a secret never reaches a sandbox, because the builder's code is not run on a
//! change the policy already refuses.

use factory_domain::redaction::Redactor;

use super::assemble::HostResult;
use super::config::ValidationConfig;
use super::gather::Gathered;
use crate::gates::scope::secrets::{Scan, scan};
use crate::gates::scope::{entries, protected, weakening};

/// The three host-side results.
#[derive(Debug, Clone)]
pub struct HostResults {
    /// `protected-paths-unchanged`.
    pub protected: HostResult,
    /// The part of `test-file-protection` that needs no command.
    pub tests: HostResult,
    /// `secret-scan`.
    pub secrets: HostResult,
}

impl HostResults {
    /// True when no host-side rule refused or failed to run. Only then may a command run.
    #[must_use]
    pub fn clean(&self) -> bool {
        [&self.protected, &self.tests, &self.secrets]
            .iter()
            .all(|result| matches!(result, HostResult::Passed(_)))
    }
}

fn blocked(missing: &str, reason: &str) -> HostResult {
    HostResult::Blocked {
        missing: missing.to_owned(),
        reason: reason.to_owned(),
    }
}

/// Applies the path rules, the weakening rules and the secret scan to the change.
#[must_use]
pub fn evaluate(cfg: &ValidationConfig, gathered: &Gathered) -> HostResults {
    let secrets = secrets(&cfg.redactor, gathered);
    if !gathered.listed {
        let missing = blocked(
            "the list of changed paths",
            "The list of changed paths could not be made from the object store, so the change cannot be judged.",
        );
        return HostResults {
            protected: missing.clone(),
            tests: missing,
            secrets,
        };
    }
    let Some(facts) = gathered.facts.as_ref().filter(|facts| facts.understood()) else {
        let missing = blocked(
            "a patch the gate can read",
            "The exported patch could not be read, so modes, links and gitlinks in the change cannot be judged.",
        );
        return HostResults {
            protected: missing.clone(),
            tests: missing,
            secrets,
        };
    };
    let diff = entries(&gathered.files, facts);
    let refusals = protected::check(&cfg.policy.paths, &diff);
    let protected = if refusals.protected.is_empty() {
        HostResult::Passed(
            "The policy allows every path of the change: none is protected, hidden or unsafe."
                .to_owned(),
        )
    } else {
        HostResult::Failed(refusals.protected)
    };
    let tests = if gathered.all_readable() {
        let mut violations = refusals.tests;
        violations.extend(weakening::weakened(&gathered.files));
        if violations.is_empty() {
            HostResult::Passed(
                "No existing test file lost or changed a line, and no new line skips a test."
                    .to_owned(),
            )
        } else {
            HostResult::Failed(violations)
        }
    } else {
        blocked(
            "readable versions of every changed file",
            "A changed file could not be read at both commits, so the tests in it cannot be compared.",
        )
    };
    HostResults {
        protected,
        tests,
        secrets,
    }
}

fn secrets(redactor: &Redactor, gathered: &Gathered) -> HostResult {
    if !gathered.listed {
        return blocked(
            "the list of changed paths",
            "The list of changed paths could not be made from the object store, so the change cannot be scanned.",
        );
    }
    match scan(redactor, &gathered.files) {
        Scan::Clean => HostResult::Passed(
            "The lines the change adds match no secret pattern of the policy.".to_owned(),
        ),
        Scan::Found(violations) => HostResult::Failed(violations),
        Scan::Unscannable(_) => blocked(
            "a scan of every changed file",
            "A changed file could not be scanned in full, and an unscanned file is not a clean one.",
        ),
    }
}
