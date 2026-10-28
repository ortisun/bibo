//! Which production code opens each span of the conventions page (package
//! `s1-observability-instrumentation`).
//!
//! The page names six spans. Three are opened today: `factory.job` by the composition root through
//! the helper of the observability crate, `factory.attempt` and `factory.gate` by the engine. The
//! other three have no opener, and a test for each is marked as a confirmed gap and ignored, so the
//! build stays green while the gap stays visible. Run them with `cargo nextest run -p
//! factory-composition --test span_openers --run-ignored only`.
//!
//! The scan reads text, so it misses a span opened under a name built at run time. The behavior of
//! the spans that exist is tested in `crates/workflow/tests/trace_shape.rs`.

mod telemetry_scan;

use telemetry_scan::{production_sources, span_names};

/// Whether production code outside the observability crate opens the span `name`: with the literal
/// in a `tracing` span macro or `#[instrument]`, or, for the job span, through a helper of the
/// observability crate.
fn some_code_opens(name: &str, helper: Option<&str>) -> bool {
    production_sources().iter().any(|(path, text)| {
        if path.starts_with("crates/observability/") {
            return false;
        }
        let literal = format!("\"{name}\"");
        let opens_by_literal = text.contains(&literal)
            && (text.contains("info_span!")
                || text.contains("span!(")
                || text.contains("#[instrument"));
        opens_by_literal || helper.is_some_and(|h| text.contains(h))
    })
}

#[test]
fn the_page_names_six_spans() {
    assert_eq!(
        span_names(),
        [
            "factory.agent",
            "factory.attempt",
            "factory.gate",
            "factory.job",
            "factory.stage_run",
            "factory.tool_call"
        ],
        "a span was added to or removed from the page: say what this file does about it"
    );
}

#[test]
fn the_spans_that_exist_today_have_an_opener() {
    // So a refactor that drops one is noticed here and not only in the scenarios.
    assert!(some_code_opens("factory.attempt", None));
    assert!(some_code_opens("factory.gate", None));
    assert!(some_code_opens("factory.job", Some("job_stretch_span")));
}

/// Gap OBS-2, closed (the test of its behavior is in `crates/workflow/tests/trace_shape.rs`).
/// This one is the scan side: `run_attempt` in the engine opens `factory.stage_run`.
#[test]
fn some_code_opens_the_stage_run_span() {
    assert!(some_code_opens("factory.stage_run", None));
}

/// Confirmed gap OBS-3. The conventions page has a `factory.agent` span for one agent invocation
/// inside an attempt, with the agent id, the model, the token counts and the cost. No production
/// code opens one, so there is nothing to join the cost and the tokens of an invocation to its
/// attempt.
///
/// Owner: `crates/workflow`, `src/engine` (where `stage_ports` builds the ports a handler gets).
/// Seven handler sites call `ports.runtime.run`. Smallest change: `stage_ports` hands over a
/// runtime port that wraps `AgentRuntime::run` in `info_span!("factory.agent",
/// factory.correlation_id, factory.job_id, factory.attempt_id, factory.agent_id, factory.outcome
/// = Empty)` and records `factory.outcome`, `factory.model` and the metered tokens and cost when
/// the call returns.
#[test]
#[ignore = "confirmed gap OBS-3: no code opens a factory.agent span"]
fn some_code_opens_the_agent_span() {
    assert!(some_code_opens("factory.agent", None));
}

/// Confirmed gap OBS-4. The conventions page has a `factory.tool_call` span for one tool call made
/// by an agent. No production code opens one.
///
/// Owner: `crates/runtime` (the adapters see each tool call in the tool's output) or the engine
/// wrapper from OBS-3. Smallest change: when the adapter parses a tool call from the stream, open
/// `info_span!("factory.tool_call", factory.correlation_id, factory.job_id, factory.attempt_id,
/// factory.tool_name, factory.outcome = Empty)`, record `factory.tool_args_sha256` and the outcome
/// (`denied` when policy refused it).
#[test]
#[ignore = "confirmed gap OBS-4: no code opens a factory.tool_call span"]
fn some_code_opens_the_tool_call_span() {
    assert!(some_code_opens("factory.tool_call", None));
}
