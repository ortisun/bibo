//! Security review of the agent runtime adapters (docs/reviews/isolation-core-security-review.md).
//!
//! Tests marked `#[ignore = "confirmed defect ..."]` fail today and show a defect; they pass when
//! the defect is fixed. Tests without `#[ignore]` pin something the review tried to break and could
//! not. Run the defect tests with:
//!
//! ```text
//! CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
//!   cargo test -p factory-runtime --test security_review -- --ignored
//! ```
//!
//! These tests use the scripted sandbox session of the runtime suite, so they need no Docker and
//! call no model. The adapter under test is the real one.

#[path = "../support/mod.rs"]
mod support;

use factory_ports::agent::AgentRunError;
use support::scripted::{Step, Tool, run};
use support::{Harness, recorded};

fn killed_after_a_complete_stream(stdout: &str, code: Option<i32>, signal: Option<i32>) -> Step {
    Step::Output {
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
        exit_code: code,
        signal,
        truncated: false,
    }
}

/// RTM-1, FIXED. The Claude Code adapter used to decide success from the last `result` line of
/// the stream and never looked at how the process ended. Codex needs `completed` and exit code 0.
/// A tool process that was killed by a signal, or that exited with an error, after a line that
/// says `completed` was a success for Claude Code. The stream is attacker-writable (see SBX-4): a
/// child of the tool can write a complete `result` line into the tool's stdout and then kill the
/// tool, and the run was a success with the text of the forged line as its output.
#[tokio::test]
async fn rtm_1_claude_success_needs_a_clean_exit_as_codex_does() {
    let h = Harness::new();
    let stdout = recorded::stdout("claude-turn-env");
    let mut accepted = Vec::new();
    for (label, code, signal) in [
        ("killed by SIGKILL", None, Some(9)),
        ("exit code 1", Some(1), None),
        ("exit code 137", Some(137), None),
    ] {
        let (report, _) = run(
            &h,
            Tool::Claude,
            killed_after_a_complete_stream(&stdout, code, signal),
            |_| {},
        )
        .await;
        if report.outcome.is_ok() {
            accepted.push(label);
        }
    }
    assert!(
        accepted.is_empty(),
        "a stream with a completed result is a success even when the tool was {accepted:?}"
    );
}

/// What held: the same shapes for Codex are never a success.
#[tokio::test]
async fn held_codex_success_needs_a_clean_exit() {
    let h = Harness::new();
    let stdout = recorded::stdout("codex-turn-custom-provider");
    for (code, signal) in [(None, Some(9)), (Some(1), None), (Some(137), None)] {
        let (report, _) = run(
            &h,
            Tool::Codex,
            killed_after_a_complete_stream(&stdout, code, signal),
            |_| {},
        )
        .await;
        assert!(
            report.outcome.is_err(),
            "code {code:?} signal {signal:?}: {:?}",
            report.outcome
        );
    }
}

/// What held: a stream with no result, or with an error result, is a typed failure and not an
/// output, and a malformed line is skipped without taking the rest of the stream with it.
#[tokio::test]
async fn held_missing_and_error_results_are_failures() {
    let h = Harness::new();
    let (empty, _) = run(&h, Tool::Claude, Step::exits(0, ""), |_| {}).await;
    assert_eq!(
        empty.outcome.clone().err(),
        Some(AgentRunError::OutputMissing)
    );
    let garbage = "not json\n{\"type\":\"result\"}\n\u{0}\u{0}\n";
    let (broken, _) = run(&h, Tool::Claude, Step::exits(0, garbage), |_| {}).await;
    assert!(broken.outcome.is_err());
}

/// RTM-1 and SBX-4 together: a line of the stream that someone else wrote does not make a run a
/// success when it is a second terminal event, or when the stream goes on after it. The tools
/// write one terminal event, last (97 recorded runs of Claude Code and Codex show that), so a
/// second one, or an event after it, is not the tool's.
#[tokio::test]
async fn rtm_1_a_second_terminal_event_or_an_event_after_it_is_not_a_success() {
    let h = Harness::new();
    let claude = recorded::stdout("claude-turn-env");
    let line_of = |text: &str, kind: &str| {
        text.lines()
            .find(|l| l.contains(&format!("\"type\":\"{kind}\"")))
            .unwrap_or_else(|| panic!("the recorded run has a {kind} event"))
            .to_owned()
    };
    let result_line = line_of(&claude, "result");
    let assistant_line = line_of(&claude, "assistant");
    // The control: the recorded stream, as it is, with a clean exit, is a success.
    let (control, _) = run(&h, Tool::Claude, Step::exits(0, &claude), |_| {}).await;
    assert!(control.outcome.is_ok(), "{:?}", control.outcome);
    for (label, tampered) in [
        ("a second result", format!("{claude}{result_line}\n")),
        (
            "an event after the result",
            format!("{claude}{assistant_line}\n"),
        ),
        (
            "a forged result first",
            format!(
                "{}\n{claude}",
                result_line.replace("FAKE-PROVIDER", "FORGED")
            ),
        ),
    ] {
        let (report, _) = run(&h, Tool::Claude, Step::exits(0, &tampered), |_| {}).await;
        assert!(
            report.outcome.is_err(),
            "Claude Code: {label} must not be a success: {:?}",
            report.outcome
        );
    }

    let codex = recorded::stdout("codex-turn-custom-provider");
    let done_line = line_of(&codex, "turn.completed");
    let item_line = line_of(&codex, "item.completed");
    let (control, _) = run(&h, Tool::Codex, Step::exits(0, &codex), |_| {}).await;
    assert!(control.outcome.is_ok(), "{:?}", control.outcome);
    for (label, tampered) in [
        ("a second completion", format!("{codex}{done_line}\n")),
        (
            "an item after the completion",
            format!("{codex}{item_line}\n"),
        ),
    ] {
        let (report, _) = run(&h, Tool::Codex, Step::exits(0, &tampered), |_| {}).await;
        assert!(
            report.outcome.is_err(),
            "Codex: {label} must not be a success: {:?}",
            report.outcome
        );
    }
}
