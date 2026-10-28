//! What must be true before a scenario runs: the prerequisites of a real run, and the protection of
//! the fixture remote.
//!
//! A repository that fails the protection preflight runs at autonomy level L0 and opens no pull
//! request (ADR 0009), so a scenario that needs a pull request cannot say anything about it there.
//! The harness refuses to run, and says why. A missing prerequisite is `BLOCKED`, never a pass.

use crate::evidence::ProtectionFacts;

/// One thing a real run needs, the variable that names it, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Need {
    /// What is needed, in words.
    pub what: &'static str,
    /// The environment variable the harness reads for it.
    pub variable: &'static str,
    /// Why the run cannot do without it.
    pub why: &'static str,
}

/// The prerequisites of the scenarios that use real adapters (E1 and E2).
pub const REAL_NEEDS: [Need; 5] = [
    Need {
        what: "an API key for the model provider with a provider-side hard spend limit",
        variable: "FACTORY_E2E_MODEL_API_KEY",
        why: "the agent tools run behind a broker that holds the real key; a subscription login cannot be brokered or metered",
    },
    Need {
        what: "a registered GitHub App (its id)",
        variable: "FACTORY_E2E_GITHUB_APP_ID",
        why: "the factory mints a narrowed installation token for each job",
    },
    Need {
        what: "the private key file of the GitHub App",
        variable: "FACTORY_E2E_GITHUB_APP_KEY_FILE",
        why: "the token minter signs the App's request with it",
    },
    Need {
        what: "a fixture repository on GitHub with a branch-protection ruleset (owner/name)",
        variable: "FACTORY_E2E_FIXTURE_REPO",
        why: "a repository that fails the protection preflight runs at level L0 and opens no pull request",
    },
    Need {
        what: "the named requester allowlist in protected configuration",
        variable: "FACTORY_E2E_REQUESTER_ALLOWLIST",
        why: "requester authorization is part of what the scenario shows",
    },
];

/// What is missing from the environment, one line for each, ready to print after `BLOCKED:`.
/// `lookup` returns the value of a variable, or `None`.
#[must_use]
pub fn missing_needs(lookup: impl Fn(&str) -> Option<String>) -> Vec<String> {
    REAL_NEEDS
        .iter()
        .filter(|need| lookup(need.variable).is_none_or(|value| value.trim().is_empty()))
        .map(|need| format!("{} (set {}): {}", need.what, need.variable, need.why))
        .collect()
}

/// The ways a repository's protection falls short of `policies/security.yaml`
/// (`credentials.repository_requirements`). Empty when the protection is acceptable.
#[must_use]
pub fn protection_problems(protection: &ProtectionFacts) -> Vec<String> {
    let mut problems = Vec::new();
    if !protection.require_pull_request {
        problems.push("the default branch does not require a pull request".to_owned());
    }
    if protection.required_approvals == 0 {
        problems.push("the default branch requires no approving review".to_owned());
    }
    if protection.required_checks.is_empty() {
        problems.push("the default branch requires no status check".to_owned());
    }
    for check in &protection.required_checks {
        if !check.pinned_to_app {
            problems.push(format!(
                "the required check {} is not pinned to the factory's App, so any source can satisfy it",
                check.context
            ));
        }
    }
    if !protection.dismiss_stale_reviews {
        problems.push("a new commit does not dismiss earlier approvals".to_owned());
    }
    if !protection.require_code_owner_review {
        problems
            .push("a change to a protected path does not need a code owner's review".to_owned());
    }
    if protection.allow_force_pushes {
        problems.push("force pushes to the default branch are allowed".to_owned());
    }
    if protection.allow_deletions {
        problems.push("the default branch can be deleted".to_owned());
    }
    if protection.app_may_bypass {
        problems.push("the factory's App is on the bypass list".to_owned());
    }
    problems
}

/// A protection that satisfies every requirement.
#[must_use]
pub fn compliant_protection() -> ProtectionFacts {
    ProtectionFacts {
        require_pull_request: true,
        required_approvals: 1,
        required_checks: vec![crate::evidence::RequiredCheckFacts {
            context: "ci".to_owned(),
            pinned_to_app: true,
        }],
        dismiss_stale_reviews: true,
        enforce_admins: true,
        allow_force_pushes: false,
        allow_deletions: false,
        require_code_owner_review: true,
        app_may_bypass: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_compliant_protection_has_no_problem() {
        assert!(protection_problems(&compliant_protection()).is_empty());
    }

    #[test]
    fn each_requirement_is_checked_on_its_own() {
        type Break = fn(&mut ProtectionFacts);
        let breaks: [(&str, Break); 8] = [
            ("require a pull request", |p| p.require_pull_request = false),
            ("approving review", |p| p.required_approvals = 0),
            ("status check", |p| p.required_checks.clear()),
            ("pinned to the factory's App", |p| {
                p.required_checks[0].pinned_to_app = false
            }),
            ("dismiss earlier approvals", |p| {
                p.dismiss_stale_reviews = false
            }),
            ("code owner", |p| p.require_code_owner_review = false),
            ("force pushes", |p| p.allow_force_pushes = true),
            ("bypass list", |p| p.app_may_bypass = true),
        ];
        for (needle, change) in breaks {
            let mut protection = compliant_protection();
            change(&mut protection);
            let problems = protection_problems(&protection);
            assert_eq!(problems.len(), 1, "{needle}: {problems:?}");
            assert!(problems[0].contains(needle), "{needle}: {problems:?}");
        }
    }

    #[test]
    fn every_missing_need_is_named_with_its_variable() {
        let all_missing = missing_needs(|_| None);
        assert_eq!(all_missing.len(), REAL_NEEDS.len());
        for need in REAL_NEEDS {
            assert!(all_missing.iter().any(|line| line.contains(need.variable)));
        }
        let blank = missing_needs(|_| Some("  ".to_owned()));
        assert_eq!(blank.len(), REAL_NEEDS.len(), "a blank value is missing");
        let none_missing = missing_needs(|_| Some("value".to_owned()));
        assert!(none_missing.is_empty());
    }
}
