//! Output parsing (work package done criterion 6): the outputs the spike recorded from the real
//! tools parse into outcomes with usage, and malformed output maps to a typed error.
//!
//! The recordings are real tool output against the spike's fake provider (fidelity: fake). The
//! tool command is played by the scripted session; the adapter code under test is the real one.

mod support;

use factory_ports::agent::{AgentRunError, AgentRunReport, CostMicroUsd, ExitInfo};
use support::scripted::{Step, Tool, run};
use support::{Harness, recorded};

async fn claude_case(h: &Harness, case: &str) -> AgentRunReport {
    let stdout = recorded::stdout(case);
    run(h, Tool::Claude, Step::exits(0, &stdout), |_| {})
        .await
        .0
}

async fn codex_case(h: &Harness, case: &str) -> AgentRunReport {
    let stdout = recorded::stdout(case);
    run(h, Tool::Codex, Step::exits(0, &stdout), |_| {}).await.0
}

fn text_of(report: &AgentRunReport) -> String {
    let output = report.outcome.clone().expect("an output");
    String::from_utf8(output.as_bytes().to_vec()).expect("text")
}

#[tokio::test]
async fn output_parsing_a_recorded_claude_turn_gives_the_result_text_and_the_usage() {
    let h = Harness::new();
    let report = claude_case(&h, "claude-turn-env").await;
    assert_eq!(
        text_of(&report),
        "FAKE-PROVIDER-REPLY: canned answer, no model was called."
    );
    // 1234 input, 7 cache writes and 89 cache reads are all tokens sent to the model.
    assert_eq!(report.usage.input_tokens, 1234 + 7 + 89);
    assert_eq!(report.usage.output_tokens, 56);
    assert_eq!(report.usage.cost, CostMicroUsd(6109));
    assert_eq!(report.usage.requests, 1);
    assert_eq!(report.runtime_version.as_deref(), Some("2.1.311"));
    assert_eq!(
        report.exit,
        Some(ExitInfo {
            code: Some(0),
            signal: None
        })
    );
    assert!(report.permission_denials.is_empty());
    let transcript = h.transcript_of(&report).await;
    assert!(transcript.contains("\"type\":\"system\""));
    assert!(transcript.contains("\"type\":\"factory\""));
}

#[tokio::test]
async fn output_parsing_usage_adds_up_across_the_requests_of_a_run() {
    let h = Harness::new();
    let report = claude_case(&h, "claude-tool-turns").await;
    assert!(report.outcome.is_ok());
    assert_eq!(report.usage.input_tokens, 2468 + 14 + 178);
    assert_eq!(report.usage.output_tokens, 112);
    assert_eq!(report.usage.requests, 2, "a tool call makes two requests");
    let report = codex_case(&h, "codex-tool-turns").await;
    assert!(text_of(&report).starts_with("FAKE-PROVIDER: tool output received"));
    assert_eq!(report.usage.input_tokens, 2468);
    assert_eq!(report.usage.output_tokens, 112);
    assert_eq!(report.usage.requests, 2);
}

#[tokio::test]
async fn output_parsing_a_denied_tool_call_is_reported_with_the_tools_own_words() {
    let h = Harness::new();
    let report = claude_case(&h, "claude-perm-bash-default").await;
    assert!(report.outcome.is_ok(), "a denial does not fail the run");
    assert_eq!(report.permission_denials.len(), 1);
    let denial = &report.permission_denials[0];
    assert_eq!(denial.tool, "Bash");
    assert!(
        denial
            .reason
            .starts_with("Permission for this tool use was denied"),
        "{}",
        denial.reason
    );
}

#[tokio::test]
async fn output_parsing_a_recorded_codex_turn_gives_the_last_message_and_the_usage() {
    let h = Harness::new();
    let report = codex_case(&h, "codex-turn-custom-provider").await;
    assert_eq!(
        text_of(&report),
        "FAKE-PROVIDER-REPLY: canned answer, no model was called."
    );
    assert_eq!(report.usage.input_tokens, 1234);
    assert_eq!(report.usage.output_tokens, 56);
    // Codex reports no cost; the broker's meter is the truth.
    assert_eq!(report.usage.cost, CostMicroUsd(0));
    assert_eq!(report.runtime_version.as_deref(), Some("0.163.0"));
}

#[tokio::test]
async fn output_parsing_the_output_is_bytes_that_nothing_judged() {
    let h = Harness::new();
    for text in [
        "not json at all",
        "{\"half\": ",
        "{\"a\":1,\"a\":2}",
        "  \u{fffd}\u{fffd}  ",
    ] {
        let line = serde_json::json!({
            "type": "result", "subtype": "success", "is_error": false,
            "terminal_reason": "completed", "result": text,
            "usage": {"input_tokens": 1, "output_tokens": 1}, "total_cost_usd": 0.0,
        });
        let (report, _) = run(
            &h,
            Tool::Claude,
            Step::exits(0, &format!("{line}\n")),
            |_| {},
        )
        .await;
        assert_eq!(
            text_of(&report),
            text,
            "the adapter must not parse or repair the output"
        );
    }
}

#[tokio::test]
async fn output_parsing_malformed_output_maps_to_a_typed_error() {
    let h = Harness::new();
    let cases: [(&str, Step, AgentRunError); 6] = [
        (
            "garbage and exit 0",
            Step::exits(0, "this is not json\n{broken\n"),
            AgentRunError::OutputMissing,
        ),
        (
            "empty and exit 0",
            Step::exits(0, ""),
            AgentRunError::OutputMissing,
        ),
        (
            "a result with no error flag",
            Step::exits(
                0,
                "{\"type\":\"result\",\"subtype\":\"success\",\"result\":\"ok\"}\n",
            ),
            AgentRunError::OutputMissing,
        ),
        (
            "an array where an event should be",
            Step::exits(0, "[1,2,3]\n"),
            AgentRunError::OutputMissing,
        ),
        (
            "a result that stops half way",
            Step::exits(0, "{\"type\":\"result\",\"is_error\":false,\"result\":\"ok"),
            AgentRunError::OutputMissing,
        ),
        (
            "garbage and exit 3",
            Step::exits(3, "boom\n"),
            AgentRunError::ProcessFailed(ExitInfo {
                code: Some(3),
                signal: None,
            }),
        ),
    ];
    for (name, step, want) in cases {
        let (report, _) = run(&h, Tool::Claude, step, |_| {}).await;
        assert_eq!(report.outcome.clone().err(), Some(want), "{name}");
        assert!(
            report.transcript.is_some(),
            "{name}: the transcript is still stored"
        );
    }
    let codex: [(&str, Step, AgentRunError); 4] = [
        (
            "garbage",
            Step::exits(0, "garbage\n"),
            AgentRunError::OutputMissing,
        ),
        ("empty", Step::exits(0, ""), AgentRunError::OutputMissing),
        (
            "a completed turn with no message",
            Step::exits(
                0,
                "{\"type\":\"turn.started\"}\n{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}\n",
            ),
            AgentRunError::OutputMissing,
        ),
        (
            "a completed turn with exit 1",
            Step::exits(
                1,
                "{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"x\"}}\n{\"type\":\"turn.completed\",\"usage\":{}}\n",
            ),
            AgentRunError::ProcessFailed(ExitInfo {
                code: Some(1),
                signal: None,
            }),
        ),
    ];
    for (name, step, want) in codex {
        let (report, _) = run(&h, Tool::Codex, step, |_| {}).await;
        assert_eq!(report.outcome.clone().err(), Some(want), "{name}");
    }
}

#[tokio::test]
async fn output_parsing_a_secret_in_the_output_is_redacted_before_it_leaves() {
    let h = Harness::new();
    let secret = support::runtime_secret("OUTPUT");
    h.register_secret("job-token", &secret);
    let line = serde_json::json!({
        "type": "result", "subtype": "success", "is_error": false,
        "terminal_reason": "completed", "result": format!("{{\"leak\":\"{secret}\"}}"),
        "usage": {"input_tokens": 1, "output_tokens": 1}, "total_cost_usd": 0.0,
    });
    let (report, _) = run(
        &h,
        Tool::Claude,
        Step::exits(0, &format!("{line}\n")),
        |_| {},
    )
    .await;
    let text = text_of(&report);
    assert!(!text.contains(&secret));
    assert!(text.contains("[REDACTED:job-token]"));
    assert!(!h.transcript_of(&report).await.contains(&secret));
}
