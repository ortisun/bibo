//! Which production code opens each span of the conventions page (package
//! `s1-observability-instrumentation`).
//!
//! The page names six spans, and each has an opener: `factory.job` is opened by the composition
//! root through the helper of the observability crate; `factory.stage_run`, `factory.attempt`,
//! `factory.gate` and `factory.agent` by the engine; `factory.tool_call` by the two agent runtime
//! adapters. Until the telemetry gap fix three of them had none, and a test for each was marked as
//! a confirmed gap and ignored, so the build stayed green while the gap stayed visible.
//!
//! The scan reads text, so it misses a span opened under a name built at run time. The behavior of
//! the engine's spans is tested in `crates/workflow/tests/trace_shape.rs`, and that of the adapters'
//! spans in `crates/runtime/tests/telemetry.rs`.

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

/// Gap OBS-3, closed (the test of its behavior is in `crates/workflow/tests/trace_shape.rs`). The
/// engine hands every handler a runtime that wraps `AgentRuntime::run` in `factory.agent`
/// (`crates/workflow/src/engine/agent_span.rs`), so the seven handler sites that call
/// `ports.runtime.run` need no span of their own.
#[test]
fn some_code_opens_the_agent_span() {
    assert!(some_code_opens("factory.agent", None));
}

/// Gap OBS-4, closed (the tests of its behavior are in `crates/runtime/tests/telemetry.rs`). Both
/// adapters of `crates/runtime` open `factory.tool_call` for each tool call they read from the
/// tool's event stream, through `src/toolspan.rs`. What the span still lacks is gap OBS-12.
#[test]
fn some_code_opens_the_tool_call_span() {
    assert!(some_code_opens("factory.tool_call", None));
}
