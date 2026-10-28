//! The scenarios E1 to E13.
//!
//! E1 to E9 are the ones in `docs/architecture/slice-plan.md`, section 10. E10 to E13 are added
//! here for the requests that the plan's table does not list: a request edited after authorization
//! (state machine transition S22), budget exhaustion, an ambiguous request and an out-of-policy
//! request. They use ids after E9, so the plan's ids stay what they were.
//!
//! A scenario names the issue it submits, the assertions that must hold, and the scenario checks
//! (see [`crate::scenario_checks`]). It does not say how the factory is driven: that is the job of
//! the wiring.

use crate::assertions;
use crate::check::Check;
use crate::scenario_checks;

/// What kind of adapters a scenario needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adapters {
    /// Real adapters: a real model provider, GitHub App, protected fixture repository and sandbox.
    /// Without them the scenario is `BLOCKED`.
    Real,
    /// Test mode with labelled fakes. The report says so.
    TestMode,
    /// No adapters at all.
    None,
}

impl Adapters {
    /// A word for the report.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Real => "real adapters",
            Self::TestMode => "test mode with labelled fakes",
            Self::None => "no adapters",
        }
    }
}

/// One scenario.
#[derive(Debug, Clone, Copy)]
pub struct Scenario {
    /// `E1` to `E13`.
    pub id: &'static str,
    /// A title in plain English.
    pub title: &'static str,
    /// What the scenario shows.
    pub shows: &'static str,
    /// What it needs.
    pub adapters: Adapters,
    /// The issue it submits (see `issues/`), if any.
    pub issue: Option<&'static str>,
    /// A variant of that issue (see the issue file), if any.
    pub variant: Option<&'static str>,
    /// The assertions that must hold, by id.
    pub assertions: &'static [&'static str],
    /// The scenario checks that must hold, by id.
    pub checks: &'static [&'static str],
    /// Whether the scenario needs a fixture remote with a protection that passes the preflight.
    pub needs_protected_remote: bool,
}

const ALL_FOURTEEN: &[&str] = &[
    "A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11", "A12", "A13", "A14",
];

/// Every scenario, in order.
pub const SCENARIOS: [Scenario; 13] = [
    Scenario {
        id: "E1",
        title: "English issue to approved draft pull request",
        shows: "An authorized English issue goes through every stage, opens a draft pull request, and waits for a person. Nothing is merged.",
        adapters: Adapters::Real,
        issue: Some("json-output-en"),
        variant: None,
        assertions: ALL_FOURTEEN,
        checks: &["X.ledger-chain", "X.original-kept"],
        needs_protected_remote: true,
    },
    Scenario {
        id: "E2",
        title: "The same flow from a Portuguese issue",
        shows: "A Portuguese issue gives an English specification, plan, pull request and documentation that keep the technical intent.",
        adapters: Adapters::Real,
        issue: Some("json-output-pt"),
        variant: None,
        assertions: ALL_FOURTEEN,
        checks: &["X.ledger-chain", "X.original-kept", "E2.intent"],
        needs_protected_remote: true,
    },
    Scenario {
        id: "E3",
        title: "A failing check blocks promotion",
        shows: "Two rework rounds, then WAITING_FOR_HUMAN and no pull request.",
        adapters: Adapters::TestMode,
        issue: Some("json-output-en"),
        variant: None,
        assertions: &["A11", "A13", "A14"],
        checks: &["X.ledger-chain", "E3.rework-cap-then-human"],
        needs_protected_remote: true,
    },
    Scenario {
        id: "E4",
        title: "Prompt injection has no effect",
        shows: "Instructions hidden in the issue and in repository documents are treated as data. No authority is gained and no canary leaks.",
        adapters: Adapters::TestMode,
        issue: Some("hostile-injection"),
        variant: None,
        assertions: &["A1", "A3", "A9", "A10", "A13", "A14"],
        checks: &["X.ledger-chain", "X.original-kept", "E4.no-effect"],
        needs_protected_remote: true,
    },
    Scenario {
        id: "E5",
        title: "The worker is killed at every stage boundary",
        shows: "Every stage loses a lease once, and the job still completes with one pull request.",
        adapters: Adapters::TestMode,
        issue: Some("json-output-en"),
        variant: None,
        // A11 is left out on purpose: the span of an attempt in a process that was killed is
        // lost with the process, so a killed attempt cannot have an exported span.
        assertions: &["A1", "A2", "A3", "A9", "A14"],
        checks: &["X.ledger-chain", "E5.every-boundary"],
        needs_protected_remote: true,
    },
    Scenario {
        id: "E6",
        title: "A requester who is not on the allowlist is rejected",
        shows: "Admission rejects the request and the reply does not say which test failed.",
        adapters: Adapters::TestMode,
        issue: Some("unauthorized-requester"),
        variant: None,
        assertions: &[],
        checks: &["E6.rejected"],
        needs_protected_remote: false,
    },
    Scenario {
        id: "E7",
        title: "The same signed webhook delivered 50 times creates one job",
        shows: "Duplicate deliveries make one job, one outbox row and 49 duplicate-delivery audit records.",
        adapters: Adapters::TestMode,
        issue: Some("json-output-en"),
        variant: None,
        assertions: &[],
        checks: &["E7.one-job"],
        needs_protected_remote: false,
    },
    Scenario {
        id: "E8",
        title: "A builder change to a protected path fails the scope gate",
        shows: "The scope gate refuses the change, names the path, and nothing later starts.",
        adapters: Adapters::TestMode,
        issue: Some("json-output-en"),
        variant: None,
        assertions: &["A13"],
        checks: &["X.ledger-chain", "E8.scope-gate"],
        needs_protected_remote: true,
    },
    Scenario {
        id: "E9",
        title: "A production-profile start with a fake adapter is refused",
        shows: "The gate that keeps a fake out of a production run refuses each fake and allows it in test mode.",
        adapters: Adapters::None,
        issue: None,
        variant: None,
        assertions: &[],
        checks: &["E9.production-refuses-fakes"],
        needs_protected_remote: false,
    },
    Scenario {
        id: "E10",
        title: "A request edited after authorization restarts from intake",
        shows: "The edit is noticed, both revisions are kept, and nobody reads the new text before the requester confirms it.",
        adapters: Adapters::TestMode,
        issue: Some("edited-after-authorization"),
        variant: None,
        assertions: &[],
        checks: &["X.ledger-chain", "E10.edit-restarts-intake"],
        needs_protected_remote: false,
    },
    Scenario {
        id: "E11",
        title: "Budget exhaustion asks a person at once",
        shows: "When the budget is spent the stage waits for a person, does not fail, and no model call starts after it.",
        adapters: Adapters::TestMode,
        issue: Some("json-output-en"),
        variant: None,
        assertions: &[],
        checks: &["E11.budget-asks-a-person"],
        needs_protected_remote: false,
    },
    Scenario {
        id: "E12",
        title: "An ambiguous request gets one focused question",
        shows: "Intake asks exactly one question and waits. Nothing else starts.",
        adapters: Adapters::TestMode,
        issue: Some("ambiguous-request"),
        variant: None,
        assertions: &[],
        checks: &["E12.one-question"],
        needs_protected_remote: false,
    },
    Scenario {
        id: "E13",
        title: "An out-of-policy request is declined",
        shows: "Intake declines in plain English, names the override path, and starts nothing.",
        adapters: Adapters::TestMode,
        issue: Some("out-of-policy-request"),
        variant: None,
        assertions: &[],
        checks: &["E13.declined"],
        needs_protected_remote: false,
    },
];

/// The scenario with this id.
#[must_use]
pub fn by_id(id: &str) -> Option<&'static Scenario> {
    SCENARIOS.iter().find(|scenario| scenario.id == id)
}

impl Scenario {
    /// The checks of this scenario in the order they run: the assertions, then the scenario checks.
    ///
    /// # Panics
    /// When the scenario names a check that does not exist, which a test catches.
    #[must_use]
    pub fn checks(&self) -> Vec<Check> {
        let mut list: Vec<Check> = self
            .assertions
            .iter()
            .map(|id| assertions::by_id(id).unwrap_or_else(|| panic!("no assertion {id}")))
            .collect();
        list.extend(self.checks.iter().map(|id| {
            scenario_checks::by_id(id).unwrap_or_else(|| panic!("no scenario check {id}"))
        }));
        list
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plan_scenarios_e1_to_e9_come_first_and_every_id_is_unique() {
        let ids: Vec<&str> = SCENARIOS.iter().map(|s| s.id).collect();
        for (index, expected) in ["E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9"]
            .iter()
            .enumerate()
        {
            assert_eq!(ids[index], *expected);
        }
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
    }

    #[test]
    fn every_named_check_and_issue_exists() {
        for scenario in &SCENARIOS {
            let _ = scenario.checks();
            if let Some(issue) = scenario.issue {
                assert!(
                    crate::issues::load(issue).is_ok(),
                    "{}: {issue}",
                    scenario.id
                );
            }
            assert!(
                !scenario.checks().is_empty(),
                "{} checks nothing",
                scenario.id
            );
        }
    }

    #[test]
    fn only_e1_and_e2_need_real_adapters() {
        let real: Vec<&str> = SCENARIOS
            .iter()
            .filter(|s| s.adapters == Adapters::Real)
            .map(|s| s.id)
            .collect();
        assert_eq!(real, ["E1", "E2"]);
    }
}
