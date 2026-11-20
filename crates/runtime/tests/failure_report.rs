//! A run that fails still reports what it used (work package done criterion 9, ADR 0014 decision 1):
//! a run that times out, is cancelled or exits with a failure still returns its usage, its stored
//! transcript and its permission denials, and an output over the limit is `OutputTooLarge`.
//!
//! The tool command is a scripted stand-in process, **labelled fake**: it prints what the tools
//! print when they are cut short, and the adapter code under test is the real one.

mod support;

use factory_ports::agent::{AgentRunError, AgentRunReport, CostMicroUsd, ExitInfo};
use support::scripted::{Step, Tool, run};
use support::{Harness, limits};

fn assistant(id: &str, input: u64, output: u64) -> String {
    let event = serde_json::json!({
        "type": "assistant",
        "message": {"id": id, "usage": {"input_tokens": input, "output_tokens": output}},
    });
    format!("{event}\n")
}

fn aborted_result(denied: &str) -> String {
    let event = serde_json::json!({
        "type": "result", "subtype": "error_during_execution", "is_error": true,
        "terminal_reason": "aborted_streaming", "result": "",
        "usage": {"input_tokens": 700, "output_tokens": 40},
        "total_cost_usd": 0.0125,
        "permission_denials": [{"tool_name": denied, "tool_use_id": "toolu_1", "tool_input": {}}],
    });
    format!("{event}\n")
}

async fn assert_has_evidence(h: &Harness, report: &AgentRunReport, what: &str) {
    assert!(report.transcript.is_some(), "{what}: no transcript");
    let text = h.transcript_of(report).await;
    assert!(
        text.contains("\"type\":\"factory\""),
        "{what}: no trailer in {text}"
    );
}

#[tokio::test]
async fn failure_report_a_timeout_at_the_soft_deadline_keeps_usage_denials_and_transcript() {
    let h = Harness::new();
    // `timeout` interrupted Claude Code; it wrote a clean aborted result with what it had used.
    let stdout = format!("{}{}", assistant("msg_a", 700, 40), aborted_result("Bash"));
    let (report, _) = run(&h, Tool::Claude, Step::exits(124, &stdout), |_| {}).await;
    assert_eq!(report.outcome.clone().err(), Some(AgentRunError::Timeout));
    assert_eq!(report.usage.input_tokens, 700);
    assert_eq!(report.usage.output_tokens, 40);
    assert_eq!(report.usage.cost, CostMicroUsd(12_500));
    assert_eq!(report.permission_denials.len(), 1);
    assert_eq!(report.permission_denials[0].tool, "Bash");
    assert_eq!(
        report.exit,
        Some(ExitInfo {
            code: Some(124),
            signal: None
        })
    );
    assert_has_evidence(&h, &report, "soft timeout").await;
    assert!(h.transcript_of(&report).await.contains("aborted_streaming"));
}

#[tokio::test]
async fn failure_report_a_hard_timeout_keeps_the_partial_stream_and_its_usage() {
    let h = Harness::new();
    // The sandbox killed the container at the hard deadline: no result event, partial output.
    let partial = format!(
        "{}{}",
        assistant("msg_a", 500, 30),
        assistant("msg_b", 600, 10)
    );
    let (report, _) = run(
        &h,
        Tool::Claude,
        Step::TimedOut {
            stdout: partial.into_bytes(),
        },
        |_| {},
    )
    .await;
    assert_eq!(report.outcome.clone().err(), Some(AgentRunError::Timeout));
    assert_eq!(report.usage.input_tokens, 1100);
    assert_eq!(report.usage.requests, 2);
    assert_has_evidence(&h, &report, "hard timeout").await;
    assert!(h.transcript_of(&report).await.contains("msg_b"));
}

#[tokio::test]
async fn failure_report_a_cancelled_run_still_returns_a_transcript() {
    let h = Harness::new();
    for tool in [Tool::Claude, Tool::Codex] {
        let (report, _) = run(&h, tool, Step::Cancelled, |_| {}).await;
        assert_eq!(report.outcome.clone().err(), Some(AgentRunError::Cancelled));
        assert_eq!(report.usage.cost, CostMicroUsd(0));
        assert_has_evidence(&h, &report, "cancel").await;
    }
}

#[tokio::test]
async fn failure_report_a_cancel_that_is_already_set_starts_nothing() {
    use factory_ports::agent::AgentRuntime;
    use factory_testkit::clock::FakeCancel;
    let h = Harness::new();
    let mut session = support::scripted::ScriptedSession::new(&h, Tool::Claude, Step::exits(0, ""));
    let watch = session.watch();
    let runtime =
        factory_runtime::ClaudeCodeRuntime::new(Default::default(), h.io.clone(), h.attestation());
    let cancel = FakeCancel::new();
    cancel.cancel();
    let req = support::request(&h, "claude-code-cli", "m", "http://egress:8080");
    let report = runtime.run(&mut session, req, &cancel).await;
    assert_eq!(report.outcome.err(), Some(AgentRunError::Cancelled));
    assert!(
        watch.seen().is_empty(),
        "no command may run after the cancel"
    );
}

#[tokio::test]
async fn failure_report_an_exit_with_a_failure_keeps_usage_stderr_and_transcript() {
    let h = Harness::new();
    let stdout = assistant("msg_a", 321, 12);
    let step = Step::Output {
        stdout: stdout.into_bytes(),
        stderr: b"the tool crashed: segmentation".to_vec(),
        exit_code: Some(2),
        signal: None,
        truncated: false,
    };
    let (report, _) = run(&h, Tool::Claude, step, |_| {}).await;
    assert_eq!(
        report.outcome.clone().err(),
        Some(AgentRunError::ProcessFailed(ExitInfo {
            code: Some(2),
            signal: None
        }))
    );
    assert_eq!(report.usage.input_tokens, 321);
    assert_has_evidence(&h, &report, "failure exit").await;
    assert!(h.transcript_of(&report).await.contains("the tool crashed"));
}

#[tokio::test]
async fn failure_report_codex_failures_keep_their_usage_too() {
    let h = Harness::new();
    // A Codex turn that failed after a command ran.
    let stdout = concat!(
        "{\"type\":\"turn.started\"}\n",
        "{\"type\":\"item.completed\",\"item\":{\"type\":\"command_execution\",\"status\":\"failed\"}}\n",
        "{\"type\":\"error\",\"message\":\"Reconnecting... 1/1 (We're currently experiencing high demand)\"}\n",
        "{\"type\":\"turn.failed\",\"error\":{\"message\":\"We're currently experiencing high demand\"}}\n",
    );
    let (report, _) = run(&h, Tool::Codex, Step::exits(1, stdout), |_| {}).await;
    assert_eq!(
        report.outcome.clone().err(),
        Some(AgentRunError::ProviderUnavailable)
    );
    // One command, one reconnect and the first request: three requests reached the provider.
    assert_eq!(report.usage.requests, 3);
    assert_has_evidence(&h, &report, "codex failure").await;
    let (report, _) = run(
        &h,
        Tool::Codex,
        Step::TimedOut {
            stdout: stdout.as_bytes().to_vec(),
        },
        |_| {},
    )
    .await;
    assert_eq!(report.outcome.err(), Some(AgentRunError::Timeout));
}

#[tokio::test]
async fn failure_report_an_output_over_the_limit_is_output_too_large() {
    let h = Harness::new();
    let big = "x".repeat(2048);
    let line = serde_json::json!({
        "type": "result", "subtype": "success", "is_error": false,
        "terminal_reason": "completed", "result": big,
        "usage": {"input_tokens": 9, "output_tokens": 9}, "total_cost_usd": 0.001,
    });
    let stdout = format!("{line}\n");
    for tool in [Tool::Claude] {
        let (report, _) = run(&h, tool, Step::exits(0, &stdout), |r| {
            r.max_output_bytes = 64
        })
        .await;
        assert_eq!(
            report.outcome.clone().err(),
            Some(AgentRunError::OutputTooLarge)
        );
        assert_eq!(report.usage.input_tokens, 9, "usage survives");
        assert_has_evidence(&h, &report, "oversize").await;
        // One byte over the limit fails; exactly the limit passes.
        let (over, _) = run(&h, tool, Step::exits(0, &stdout), |r| {
            r.max_output_bytes = 2047
        })
        .await;
        assert_eq!(over.outcome.err(), Some(AgentRunError::OutputTooLarge));
        let (exact, _) = run(&h, tool, Step::exits(0, &stdout), |r| {
            r.max_output_bytes = 2048
        })
        .await;
        assert!(exact.outcome.is_ok());
    }
    let codex = format!(
        "{{\"type\":\"turn.started\"}}\n{{\"type\":\"item.completed\",\"item\":{{\"type\":\"agent_message\",\"text\":\"{big}\"}}}}\n{{\"type\":\"turn.completed\",\"usage\":{{\"input_tokens\":4,\"output_tokens\":4}}}}\n"
    );
    let (report, _) = run(&h, Tool::Codex, Step::exits(0, &codex), |r| {
        r.max_output_bytes = 64
    })
    .await;
    assert_eq!(
        report.outcome.clone().err(),
        Some(AgentRunError::OutputTooLarge)
    );
    assert_eq!(report.usage.input_tokens, 4);
}

#[tokio::test]
async fn failure_report_a_cut_stream_with_no_result_is_output_too_large() {
    let h = Harness::new();
    let step = Step::Output {
        stdout: assistant("msg_a", 5, 5).into_bytes(),
        stderr: Vec::new(),
        exit_code: Some(0),
        signal: None,
        truncated: true,
    };
    let (report, _) = run(&h, Tool::Claude, step, |_| {}).await;
    assert_eq!(report.outcome.err(), Some(AgentRunError::OutputTooLarge));
}

#[tokio::test]
async fn failure_report_a_run_over_its_cost_limit_is_refused_but_keeps_its_usage() {
    let h = Harness::new();
    let line = serde_json::json!({
        "type": "result", "subtype": "success", "is_error": false,
        "terminal_reason": "completed", "result": "done",
        "usage": {"input_tokens": 1000, "output_tokens": 100}, "total_cost_usd": 3.0,
    });
    let stdout = format!("{line}\n");
    let (report, _) = run(&h, Tool::Claude, Step::exits(0, &stdout), |r| {
        r.limits = limits(60, 2.0, 10);
    })
    .await;
    assert_eq!(
        report.outcome.clone().err(),
        Some(AgentRunError::BudgetRefused)
    );
    assert_eq!(report.usage.cost, CostMicroUsd(3_000_000));
    assert_has_evidence(&h, &report, "budget").await;
    // At the limit is not over it.
    let (report, _) = run(&h, Tool::Claude, Step::exits(0, &stdout), |r| {
        r.limits = limits(60, 3.0, 10);
    })
    .await;
    assert!(report.outcome.is_ok());
}

#[tokio::test]
async fn failure_report_nothing_secret_survives_into_the_transcript_the_denials_or_the_output() {
    let h = Harness::new();
    let secret = support::runtime_secret("REPORT");
    h.register_secret("job-token", &secret);
    let event = serde_json::json!({
        "type": "result", "subtype": "error_during_execution", "is_error": true,
        "terminal_reason": "aborted_streaming", "result": format!("leak {secret}"),
        "usage": {"input_tokens": 1, "output_tokens": 1}, "total_cost_usd": 0.0,
        "permission_denials": [{"tool_name": format!("Bash-{secret}"), "tool_use_id": "toolu_9"}],
    });
    let tool_result = serde_json::json!({
        "type": "user",
        "message": {"content": [{"type": "tool_result", "tool_use_id": "toolu_9",
            "content": format!("denied; the token is {secret}")}]},
    });
    let step = Step::Output {
        stdout: format!("{tool_result}\n{event}\n").into_bytes(),
        stderr: format!("stderr {secret}").into_bytes(),
        exit_code: Some(0),
        signal: None,
        truncated: false,
    };
    let (report, _) = run(&h, Tool::Claude, step, |_| {}).await;
    let transcript = h.transcript_of(&report).await;
    assert!(
        !transcript.contains(&secret),
        "the transcript must hold no secret"
    );
    for denial in &report.permission_denials {
        assert!(!denial.tool.contains(&secret) && !denial.reason.contains(&secret));
    }
    assert!(transcript.contains("[REDACTED:job-token]"));
}
