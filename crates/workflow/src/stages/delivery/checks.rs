//! Gate results as check runs.
//!
//! A check run is how a result reaches the code host as the App's own word, and a ruleset can
//! require it. The rule here is the one that keeps a required check honest: **only a gate that
//! passed is a success.** A gate that did not run, or could not, asks a person; a gate that does
//! not apply is neutral; nothing that is not a pass is ever a success.
//!
//! | Gate outcome | Conclusion |
//! |---|---|
//! | `PASSED` | success |
//! | `FAILED` | failure |
//! | `BLOCKED` | action required |
//! | `NOT_APPLICABLE` | neutral |
//!
//! The table is the one `factory-github` uses for its own helper. This crate cannot import an
//! adapter, so the table is written here too, and a test pins both columns.
//!
//! A check run is made for `(commit, name, external_id)` and the code host updates it on a repeat,
//! so a restarted stage that publishes again changes the run it made and makes no second one.

use factory_domain::contracts::GateReport;
use factory_domain::values::Slug;
use factory_domain::vocabulary::{GateOutcome, Verdict};
use factory_ports::githost::{CheckConclusion, CheckRequest, CheckStatus};
use factory_ports::paths::CommitSha;

use super::text::fragment;

/// The check that carries the gate reports of the validation stage.
pub const CHECK_VALIDATION: &str = "factory-validation";
/// The check that carries the independent review.
pub const CHECK_REVIEW: &str = "factory-review";

/// How one gate outcome is shown.
#[must_use]
pub const fn conclusion_for_gate(outcome: GateOutcome) -> CheckConclusion {
    match outcome {
        GateOutcome::Passed => CheckConclusion::Success,
        GateOutcome::Failed => CheckConclusion::Failure,
        GateOutcome::Blocked => CheckConclusion::ActionRequired,
        GateOutcome::NotApplicable => CheckConclusion::Neutral,
    }
}

/// How a set of gates is shown together: any failure fails it, else any blocked gate needs a
/// person, else it is a success only when at least one gate passed, else it is neutral. An empty
/// set is neutral: no evidence is not a pass.
#[must_use]
pub fn conclusion_for_gates(outcomes: &[GateOutcome]) -> CheckConclusion {
    if outcomes.contains(&GateOutcome::Failed) {
        CheckConclusion::Failure
    } else if outcomes.contains(&GateOutcome::Blocked) {
        CheckConclusion::ActionRequired
    } else if outcomes.contains(&GateOutcome::Passed) {
        CheckConclusion::Success
    } else {
        CheckConclusion::Neutral
    }
}

/// How the reviewer's verdict is shown. Only `PASS` is a success.
#[must_use]
pub const fn conclusion_for_verdict(verdict: Verdict) -> CheckConclusion {
    match verdict {
        Verdict::Pass => CheckConclusion::Success,
        Verdict::ChangesRequired | Verdict::Block => CheckConclusion::Failure,
        Verdict::NeedsHuman => CheckConclusion::ActionRequired,
    }
}

fn name(text: &str) -> Option<Slug> {
    Slug::parse(text).ok()
}

/// Where the work a check reports was done, in words. A check is attached to the head of the pull
/// request, which is where the host shows it. When the documentation commit is the head, the gates
/// ran and the reviewer read the code commit under it, and the check says so instead of claiming
/// that the head itself was validated.
fn where_it_was_done(head: &CommitSha, done_on: &CommitSha) -> (String, &'static str) {
    if head == done_on {
        ("this commit".to_owned(), "")
    } else {
        (
            format!("the code commit {done_on}"),
            " The commit after it holds documentation only.",
        )
    }
}

/// The check run for the validation reports. It is attached to `commit`, the head of the pull
/// request; `validated` is the code commit the gates ran on. `None` only if a name is not a slug,
/// which no constant here is.
#[must_use]
pub fn validation_check(
    commit: &CommitSha,
    validated: &CommitSha,
    external_id: &Slug,
    reports: &[GateReport],
) -> Option<CheckRequest> {
    let outcomes: Vec<GateOutcome> = reports.iter().map(|report| report.outcome).collect();
    let conclusion = conclusion_for_gates(&outcomes);
    let passed = outcomes
        .iter()
        .filter(|o| **o == GateOutcome::Passed)
        .count();
    let (place, note) = where_it_was_done(commit, validated);
    let mut summary = format!(
        "{passed} of {} validation gates passed on {place}.{note}\n",
        outcomes.len()
    );
    for report in reports {
        summary.push_str(&format!(
            "\n- {}: {}",
            fragment(report.metadata.gate_id.as_str()),
            report.outcome.as_str()
        ));
    }
    Some(CheckRequest {
        commit: commit.clone(),
        name: name(CHECK_VALIDATION)?,
        external_id: external_id.clone(),
        status: CheckStatus::Completed(conclusion),
        title: format!("{passed} of {} gates passed", outcomes.len()),
        summary: truncate(&summary),
        details_url: None,
    })
}

/// The check run for the independent review. It is attached to `commit`, the head of the pull
/// request; `reviewed` is the code commit the reviewer read.
#[must_use]
pub fn review_check(
    commit: &CommitSha,
    reviewed: &CommitSha,
    external_id: &Slug,
    verdict: Verdict,
    findings: usize,
) -> Option<CheckRequest> {
    let (place, note) = where_it_was_done(commit, reviewed);
    let of = if note.is_empty() {
        String::new()
    } else {
        format!(" for {place}")
    };
    Some(CheckRequest {
        commit: commit.clone(),
        name: name(CHECK_REVIEW)?,
        external_id: external_id.clone(),
        status: CheckStatus::Completed(conclusion_for_verdict(verdict)),
        title: format!("Independent review: {}", verdict.as_str()),
        summary: truncate(&format!(
            "The independent reviewer gave the verdict {} with {findings} finding(s){of}.{note}",
            verdict.as_str()
        )),
        details_url: None,
    })
}

fn truncate(text: &str) -> String {
    const LIMIT: usize = 3900;
    if text.len() <= LIMIT {
        return text.to_owned();
    }
    let mut end = LIMIT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n\nThe list is cut here.", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_passed_gate_is_a_success() {
        for outcome in [
            GateOutcome::Failed,
            GateOutcome::Blocked,
            GateOutcome::NotApplicable,
        ] {
            assert_ne!(
                conclusion_for_gate(outcome),
                CheckConclusion::Success,
                "{outcome:?}"
            );
        }
        assert_eq!(
            conclusion_for_gate(GateOutcome::Passed),
            CheckConclusion::Success
        );
        assert_eq!(
            conclusion_for_gate(GateOutcome::Blocked),
            CheckConclusion::ActionRequired
        );
        assert_eq!(
            conclusion_for_gate(GateOutcome::NotApplicable),
            CheckConclusion::Neutral
        );
    }

    #[test]
    fn a_set_is_a_success_only_when_nothing_failed_or_blocked_and_something_passed() {
        use GateOutcome::{Blocked, Failed, NotApplicable, Passed};
        assert_eq!(
            conclusion_for_gates(&[Passed, Passed]),
            CheckConclusion::Success
        );
        assert_eq!(
            conclusion_for_gates(&[Passed, Blocked]),
            CheckConclusion::ActionRequired
        );
        assert_eq!(
            conclusion_for_gates(&[Passed, Blocked, Failed]),
            CheckConclusion::Failure
        );
        assert_eq!(
            conclusion_for_gates(&[NotApplicable]),
            CheckConclusion::Neutral
        );
        assert_eq!(conclusion_for_gates(&[]), CheckConclusion::Neutral);
    }

    #[test]
    fn only_a_pass_verdict_is_a_success() {
        assert_eq!(
            conclusion_for_verdict(Verdict::Pass),
            CheckConclusion::Success
        );
        for verdict in [
            Verdict::ChangesRequired,
            Verdict::Block,
            Verdict::NeedsHuman,
        ] {
            assert_ne!(
                conclusion_for_verdict(verdict),
                CheckConclusion::Success,
                "{verdict:?}"
            );
        }
    }
}
