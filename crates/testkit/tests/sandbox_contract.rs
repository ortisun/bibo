//! The fake sandbox against the shared sandbox contract suite, and against each deliberate
//! defect. Time is paused, so a command that "sleeps" for an hour takes no real time, and a
//! sandbox that ignores a cancel or a timeout is caught by the suite's own time limits.

use factory_testkit::contracts::sandbox;
use factory_testkit::sandbox::{FakeSandboxSubject, SandboxDefect};

#[tokio::test(start_paused = true)]
async fn the_fake_sandbox_passes_the_sandbox_contract() {
    let report = sandbox::run(|| async { FakeSandboxSubject::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), sandbox::checks().len());
}

const DEFECTS: [(SandboxDefect, &[&str]); 8] = [
    (
        SandboxDefect::IgnoresCancellation,
        &[
            "a_cancel_that_is_already_set_stops_the_command_before_it_starts",
            "a_cancel_during_a_long_command_ends_it_promptly",
        ],
    ),
    (
        SandboxDefect::IgnoresTimeout,
        &["a_command_past_its_timeout_is_killed_and_flagged"],
    ),
    (
        SandboxDefect::AcceptsWeakSpec,
        &[
            "a_spec_weaker_than_the_policy_is_refused_and_builds_nothing",
            "a_network_that_does_not_suit_the_profile_is_refused",
        ],
    ),
    (
        SandboxDefect::ReturnsSessionOnPostureMismatch,
        &["a_container_that_differs_from_its_spec_is_removed_and_never_returned"],
    ),
    (
        SandboxDefect::LeavesOrphans,
        &["sweeping_removes_only_sandboxes_whose_attempt_is_not_live"],
    ),
    (
        SandboxDefect::NoWallClock,
        &["a_sandbox_past_its_wall_clock_refuses_commands"],
    ),
    (
        SandboxDefect::UncappedOutput,
        &["output_beyond_the_cap_is_cut_and_flagged"],
    ),
    (
        SandboxDefect::ReportsFailureAsSuccess,
        &[
            "exit_codes_are_reported_as_they_are",
            "a_missing_program_is_a_failed_command",
        ],
    ),
];

#[tokio::test(start_paused = true)]
async fn the_sandbox_contract_catches_every_deliberate_defect() {
    for (defect, must_fail) in DEFECTS {
        let report = sandbox::run(|| async move { FakeSandboxSubject::with_defect(defect) }).await;
        assert!(
            !report.is_ok(),
            "the suite passed a sandbox with the defect {defect:?}"
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

#[tokio::test(start_paused = true)]
async fn a_sandbox_that_ignores_cancellation_is_reported_in_plain_words() {
    let report = sandbox::run(|| async {
        FakeSandboxSubject::with_defect(SandboxDefect::IgnoresCancellation)
    })
    .await;
    let (_, why) = report
        .failed
        .iter()
        .find(|(name, _)| *name == "a_cancel_during_a_long_command_ends_it_promptly")
        .expect("the cancellation check must fail");
    assert!(
        why.contains("still running 10 seconds after the cancel"),
        "{why}"
    );
}
