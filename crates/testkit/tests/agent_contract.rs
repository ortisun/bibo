//! The scripted runtime against the shared agent runtime contract suite, and against each
//! deliberate defect. Time is paused so the cancellation checks run without waiting.

use factory_testkit::agent::{FakeAgentRuntimeSubject, RuntimeDefect};
use factory_testkit::contracts::agent;

#[tokio::test(start_paused = true)]
async fn the_scripted_runtime_passes_the_agent_runtime_contract() {
    let report = agent::run(|| async { FakeAgentRuntimeSubject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), agent::checks().len());
}

const DEFECTS: [(RuntimeDefect, &[&str]); 7] = [
    (
        RuntimeDefect::IgnoresCancellation,
        &[
            "a_cancel_that_is_already_set_stops_the_run",
            "a_cancel_during_a_run_stops_it_promptly",
        ],
    ),
    (
        RuntimeDefect::SwallowsDenials,
        &["denied_tool_calls_are_reported"],
    ),
    (
        RuntimeDefect::JudgesOutput,
        &["a_run_returns_the_output_unjudged_with_a_stored_transcript"],
    ),
    (
        RuntimeDefect::IgnoresBudget,
        &["a_run_over_its_cost_limit_is_refused"],
    ),
    (
        RuntimeDefect::BlursFailures,
        &["every_failure_keeps_its_own_closed_variant"],
    ),
    (
        RuntimeDefect::LosesTranscript,
        &["a_run_returns_the_output_unjudged_with_a_stored_transcript"],
    ),
    (
        RuntimeDefect::GuessesCapabilities,
        &["a_run_that_needs_a_missing_capability_is_refused"],
    ),
];

#[tokio::test(start_paused = true)]
async fn the_agent_runtime_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in DEFECTS {
        let report =
            agent::run(|| async move { FakeAgentRuntimeSubject::with_defect(defect) }).await;
        assert!(
            !report.is_ok(),
            "the suite passed a runtime with the defect {defect:?}"
        );
        for name in must_fail {
            assert!(
                report.failed_check(name),
                "the defect {defect:?} should fail {name}, but the failed checks were {:?}",
                report.failed_names()
            );
        }
    }
}
