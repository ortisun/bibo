//! Failure mapping (work package done criterion 7): provider outage, rate limit, missing and
//! refused credential, budget, cancellation and timeout map into the closed `AgentRunError` set.
//!
//! The tool command is played by a scripted stand-in (labelled fake) that prints what the spike
//! recorded the real tools printing against a fake provider that answered with each failure.
//! Claude Code reports a provider failure with `subtype: "success"` and exits 0 on SIGINT, so the
//! adapter must read `is_error` and `terminal_reason`: several cases below pin that.

mod support;

use factory_ports::agent::{AgentRunError, ExitInfo};
use support::scripted::{Step, Tool, run};
use support::{Harness, recorded};

fn claude_result(
    is_error: bool,
    subtype: &str,
    reason: Option<&str>,
    status: Option<u64>,
    text: &str,
) -> String {
    let event = serde_json::json!({
        "type": "result",
        "subtype": subtype,
        "is_error": is_error,
        "terminal_reason": reason,
        "api_error_status": status,
        "result": text,
        "usage": {"input_tokens": 0, "output_tokens": 0},
        "total_cost_usd": 0,
        "permission_denials": [],
    });
    format!("{event}\n")
}

async fn outcome(h: &Harness, tool: Tool, step: Step) -> Option<AgentRunError> {
    let (report, _) = run(h, tool, step, |_| {}).await;
    assert!(
        report.transcript.is_some(),
        "a failed run still stores its transcript"
    );
    report.outcome.err()
}

#[tokio::test]
async fn failure_mapping_recorded_claude_failures_land_in_the_closed_set() {
    let h = Harness::new();
    let cases = [
        ("claude-auth-none", AgentRunError::AuthenticationRequired),
        ("claude-http-500", AgentRunError::ProviderUnavailable),
        ("claude-http-402", AgentRunError::BudgetRefused),
        ("claude-http-403", AgentRunError::AuthenticationRequired),
        ("claude-max-turns-flag", AgentRunError::BudgetRefused),
        ("claude-max-budget", AgentRunError::BudgetRefused),
        // SIGINT: exit code 0, but the result says it was aborted.
        ("claude-cancel-int", AgentRunError::Cancelled),
    ];
    for (case, want) in cases {
        let step = Step::exits(0, &recorded::stdout(case));
        assert_eq!(outcome(&h, Tool::Claude, step).await, Some(want), "{case}");
    }
}

#[tokio::test]
async fn failure_mapping_the_success_subtype_never_makes_a_failed_run_a_success() {
    let h = Harness::new();
    // The recorded provider failures carry `subtype: "success"` and exit code 0 or 1.
    for case in ["claude-auth-none", "claude-http-500", "claude-http-402"] {
        let stdout = recorded::stdout(case);
        assert!(stdout.contains("\"subtype\":\"success\""), "{case}");
        for code in [0, 1] {
            let (report, _) = run(&h, Tool::Claude, Step::exits(code, &stdout), |_| {}).await;
            assert!(
                report.outcome.is_err(),
                "{case} with exit {code} is not a success"
            );
        }
    }
    // A clean run is only `is_error == false` with `terminal_reason == "completed"`.
    let odd = claude_result(false, "success", Some("something_new"), None, "text");
    assert!(matches!(
        outcome(&h, Tool::Claude, Step::exits(0, &odd)).await,
        Some(AgentRunError::ProcessFailed(_))
    ));
    let none = claude_result(false, "success", None, None, "text");
    assert!(
        outcome(&h, Tool::Claude, Step::exits(0, &none))
            .await
            .is_some()
    );
}

#[tokio::test]
async fn failure_mapping_status_codes_of_a_claude_provider_failure() {
    let h = Harness::new();
    let api = |status: Option<u64>, text: &str| {
        claude_result(true, "success", Some("api_error"), status, text)
    };
    let cases = [
        (
            api(Some(401), "API Error: 401"),
            AgentRunError::AuthenticationRequired,
        ),
        (
            api(Some(403), "API Error: 403"),
            AgentRunError::AuthenticationRequired,
        ),
        (
            api(Some(402), "API Error: 402"),
            AgentRunError::BudgetRefused,
        ),
        (
            api(Some(429), "API Error: 429"),
            AgentRunError::RateLimited { retry_after: None },
        ),
        (
            api(Some(500), "API Error: 500"),
            AgentRunError::ProviderUnavailable,
        ),
        (
            api(Some(529), "API Error: 529"),
            AgentRunError::ProviderUnavailable,
        ),
        (
            api(None, "Not logged in"),
            AgentRunError::AuthenticationRequired,
        ),
        (
            api(None, "Can't reach the API server"),
            AgentRunError::ProviderUnavailable,
        ),
    ];
    for (stdout, want) in cases {
        let got = outcome(&h, Tool::Claude, Step::exits(1, &stdout)).await;
        assert_eq!(got, Some(want), "{stdout}");
    }
}

#[tokio::test]
async fn failure_mapping_a_retried_rejection_is_read_from_the_retry_events() {
    let h = Harness::new();
    // Claude Code retried a 401 and was cut off before it wrote a result.
    let retries =
        "{\"type\":\"system\",\"subtype\":\"api_retry\",\"attempt\":1,\"error_status\":401}\n";
    let cut = format!(
        "{retries}{}",
        claude_result(true, "success", Some("api_error"), None, "gave up")
    );
    assert_eq!(
        outcome(&h, Tool::Claude, Step::exits(1, &cut)).await,
        Some(AgentRunError::AuthenticationRequired)
    );
    let report = run(&h, Tool::Claude, Step::exits(1, &cut), |_| {}).await.0;
    assert_eq!(
        report.usage.requests, 1,
        "a retry is a request the provider refused"
    );
}

#[tokio::test]
async fn failure_mapping_a_claude_run_with_no_result_event() {
    let h = Harness::new();
    let cases = [
        (Step::exits(0, ""), AgentRunError::OutputMissing),
        (Step::exits(143, ""), AgentRunError::Cancelled),
        (
            Step::exits(1, ""),
            AgentRunError::ProcessFailed(ExitInfo {
                code: Some(1),
                signal: None,
            }),
        ),
        // `timeout` interrupted the tool at the soft deadline.
        (Step::exits(124, ""), AgentRunError::Timeout),
        // ... and the tool ignored the interrupt and was killed.
        (Step::exits(137, ""), AgentRunError::Timeout),
        (
            Step::Output {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: None,
                signal: Some(9),
                truncated: false,
            },
            AgentRunError::Cancelled,
        ),
    ];
    for (step, want) in cases {
        assert_eq!(
            outcome(&h, Tool::Claude, step.clone()).await,
            Some(want.clone()),
            "{step:?}"
        );
    }
}

#[tokio::test]
async fn failure_mapping_recorded_codex_failures_land_in_the_closed_set() {
    let h = Harness::new();
    let cases = [
        ("codex-auth-none", AgentRunError::AuthenticationRequired),
        ("codex-auth-wrong", AgentRunError::AuthenticationRequired),
        ("codex-http-403", AgentRunError::AuthenticationRequired),
        ("codex-http-402", AgentRunError::BudgetRefused),
        (
            "codex-http-429",
            AgentRunError::RateLimited { retry_after: None },
        ),
        ("codex-http-500", AgentRunError::ProviderUnavailable),
        (
            "codex-unreachable-bounded",
            AgentRunError::ProviderUnavailable,
        ),
    ];
    for (case, want) in cases {
        // Codex exits 1 on every one of these.
        let step = Step::exits(1, &recorded::stdout(case));
        assert_eq!(outcome(&h, Tool::Codex, step).await, Some(want), "{case}");
    }
}

#[tokio::test]
async fn failure_mapping_a_codex_failure_is_never_a_success_whatever_the_exit_code() {
    let h = Harness::new();
    let stdout = recorded::stdout("codex-http-500");
    for code in [0, 1] {
        let got = outcome(&h, Tool::Codex, Step::exits(code, &stdout)).await;
        assert_eq!(got, Some(AgentRunError::ProviderUnavailable));
    }
    let cases = [
        (Step::exits(124, ""), AgentRunError::Timeout),
        (Step::exits(143, ""), AgentRunError::Cancelled),
        (Step::exits(0, ""), AgentRunError::OutputMissing),
        (
            Step::exits(2, "garbage"),
            AgentRunError::ProcessFailed(ExitInfo {
                code: Some(2),
                signal: None,
            }),
        ),
    ];
    for (step, want) in cases {
        assert_eq!(
            outcome(&h, Tool::Codex, step.clone()).await,
            Some(want),
            "{step:?}"
        );
    }
}

#[tokio::test]
async fn failure_mapping_a_status_number_inside_another_number_is_not_a_status() {
    let h = Harness::new();
    let stdout = "{\"type\":\"turn.started\"}\n{\"type\":\"turn.failed\",\"error\":{\"message\":\"request 10401 failed on port 54290\"}}\n";
    let got = outcome(&h, Tool::Codex, Step::exits(1, stdout)).await;
    assert_eq!(
        got,
        Some(AgentRunError::ProcessFailed(ExitInfo {
            code: Some(1),
            signal: None
        }))
    );
}
