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
use crate::gates::scope::{build_code, entries, lint, protected, weakening};

/// The host-side results.
#[derive(Debug, Clone)]
pub struct HostResults {
    /// `protected-paths-unchanged`.
    pub protected: HostResult,
    /// The part of `lint` that needs no command: a lint level lowered, an allow attribute added
    /// or an ignore list grown (`lint_relaxation`, AUT-4). A hit fails the `lint` gate.
    pub lint: HostResult,
    /// The part of `test-file-protection` that needs no command.
    pub tests: HostResult,
    /// `secret-scan`.
    pub secrets: HostResult,
    /// Build code that is new to the project (`build_script_added`, AUT-5). A hit blocks the
    /// `build` gate until a security approver decides (`approve_build_code`), and no command runs:
    /// a command that built the change would run the build code first.
    pub build_code: HostResult,
}

impl HostResults {
    /// True when no host-side rule refused or failed to run. Only then may a command run.
    #[must_use]
    pub fn clean(&self) -> bool {
        [
            &self.protected,
            &self.lint,
            &self.tests,
            &self.secrets,
            &self.build_code,
        ]
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
            lint: missing.clone(),
            tests: missing.clone(),
            secrets,
            build_code: missing,
        };
    }
    let Some(facts) = gathered.facts.as_ref().filter(|facts| facts.understood()) else {
        let missing = blocked(
            "a patch the gate can read",
            "The exported patch could not be read, so modes, links and gitlinks in the change cannot be judged.",
        );
        return HostResults {
            protected: missing.clone(),
            lint: missing.clone(),
            tests: missing.clone(),
            secrets,
            build_code: missing,
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
    let lint = if gathered.all_readable() {
        let relaxations = lint::relaxed(&gathered.files);
        if relaxations.is_empty() {
            HostResult::Passed(
                "The change lowers no lint level, adds no attribute that silences a lint and grows no ignore list."
                    .to_owned(),
            )
        } else {
            HostResult::Failed(relaxations)
        }
    } else {
        blocked(
            "readable versions of every changed file",
            "A changed file could not be read at both commits, so a relaxed lint in it cannot be seen.",
        )
    };
    let build_code = if gathered.all_readable() {
        let found = build_code::added(&gathered.files);
        if found.is_empty() {
            HostResult::Passed(
                "The change adds no build script, no procedural macro and no build dependency."
                    .to_owned(),
            )
        } else {
            HostResult::NeedsDecision {
                missing: needs_decision(&found),
                reason: "The change adds build code of the project's own. It runs whenever the project is built, so it waits for a security approver before any command builds it."
                    .to_owned(),
            }
        }
    } else {
        blocked(
            "readable versions of every changed file",
            "A changed file could not be read at both commits, so new build code in it cannot be seen.",
        )
    };
    HostResults {
        protected,
        lint,
        tests,
        secrets,
        build_code,
    }
}

/// What is awaited, naming the paths and not the content, within the length a report keeps.
fn needs_decision(found: &[crate::gates::scope::Violation]) -> String {
    const MOST_PATHS: usize = 5;
    let mut paths: Vec<&str> = found
        .iter()
        .filter_map(|violation| violation.path.as_deref())
        .collect();
    paths.dedup();
    let shown: Vec<&str> = paths.iter().copied().take(MOST_PATHS).collect();
    let more = paths.len().saturating_sub(shown.len());
    let mut text = format!(
        "a security approver's decision ({}) on the new build code in: {}",
        build_code::DECISION,
        shown.join(", ")
    );
    if more > 0 {
        text.push_str(&format!(" and {more} more"));
    }
    text
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
