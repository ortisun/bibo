//! The shape of the spans an engine run produces (overview QA-7, package
//! `s1-observability-instrumentation`).
//!
//! The engine runs here over the in-memory fakes with scripted stage handlers, inside a
//! `factory.job` span that stands in for the one the composition root opens. A recording
//! `Subscriber` reads the spans back and compares them with the tables of the conventions page:
//! name, required attributes, allowed attributes, the kind of each value, the outcome, and the
//! parent. What the page lists and the engine does not yet emit is written as a test marked as a
//! confirmed gap and ignored, so the build stays green while the gap stays visible. The gaps that
//! need a scan of the source tree (no code opens an agent or a tool call span) are in
//! `crates/composition/tests/span_openers.rs`, because the inner crates may not read files.
//!
//! Run the gap tests with `cargo nextest run -p factory-workflow --test trace_shape
//! --run-ignored only`.

mod support;
mod telemetry_support;

use factory_domain::vocabulary::StageKind;
use factory_workflow::scheduler::ClaimedAttempt;
use support::World;
use telemetry_support::{Recorder, SpanRecord, Value, outcome_values, shape_problems};
use tracing::Instrument as _;

/// Runs the next stage run of the job to its result, inside a stand-in `factory.job` span, and
/// returns the claim and the id of that span's record.
async fn run_one(world: &World, recorder: &Recorder) -> (ClaimedAttempt, u64) {
    world.advance(400);
    let claimed = world.claim_one("worker-1").await;
    let stretch = tracing::info_span!(
        "factory.job",
        factory.correlation_id = %claimed.correlation,
        factory.job_id = %claimed.job,
        factory.tenant_id = %world.tenant,
        factory.outcome = tracing::field::Empty,
        factory.error_class = tracing::field::Empty,
    );
    world
        .engine
        .run_attempt(&claimed)
        .instrument(stretch)
        .await
        .expect("the attempt runs");
    let job_span = recorder
        .spans()
        .into_iter()
        .rev()
        .find(|s| s.name == "factory.job")
        .expect("the stretch span was recorded");
    (claimed, job_span.id)
}

fn named<'a>(spans: &'a [SpanRecord], name: &str) -> Vec<&'a SpanRecord> {
    spans.iter().filter(|s| s.name == name).collect()
}

#[tokio::test]
async fn an_engine_run_produces_attempt_and_gate_spans_with_the_required_attributes() {
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;

    let mut kinds = Vec::new();
    for _ in 0..3 {
        let (claimed, _) = run_one(&world, &recorder).await;
        kinds.push(claimed.kind);
    }

    let spans = recorder.spans();
    let attempts = named(&spans, "factory.attempt");
    let gates = named(&spans, "factory.gate");
    assert_eq!(attempts.len(), 3, "one attempt span for each attempt run");
    assert_eq!(gates.len(), 3, "one gate span for each attempt run");
    for span in attempts.iter().chain(gates.iter()) {
        assert_eq!(
            shape_problems(span),
            Vec::<String>::new(),
            "{} does not meet the conventions page: {:?}",
            span.name,
            span.fields
        );
    }
    for (attempt, kind) in attempts.iter().zip(&kinds) {
        assert_eq!(
            attempt.text("factory.stage_kind").as_deref(),
            Some(kind.as_str()),
            "the attempt span names its stage kind"
        );
        assert_eq!(
            attempt.text("factory.outcome").as_deref(),
            Some("succeeded")
        );
    }
    let allowed = outcome_values();
    for span in attempts.iter().chain(gates.iter()) {
        let outcome = span.text("factory.outcome").expect("an outcome");
        assert!(
            allowed.contains(&outcome),
            "{outcome} is not an outcome value of the conventions page"
        );
    }
    for gate in &gates {
        assert_eq!(
            gate.text("factory.outcome").as_deref(),
            Some("passed"),
            "a scripted passing gate is recorded as passed"
        );
        assert!(
            !gate.text("factory.gate_id").unwrap_or_default().is_empty(),
            "the gate span names its gate"
        );
    }
}

#[tokio::test]
async fn the_attempt_number_is_recorded_as_a_signed_integer() {
    // `tracing-opentelemetry` 0.34 turns an unsigned field into a string, and the conventions
    // page asks for `i64`. The engine must not record `attempt_number` as `u32` or `u64`.
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;
    run_one(&world, &recorder).await;

    let spans = recorder.spans();
    let attempt = named(&spans, "factory.attempt")[0];
    assert_eq!(
        attempt.fields.get("factory.attempt_number"),
        Some(&Value::I64(1))
    );
    for span in &spans {
        for (key, value) in &span.fields {
            assert!(
                !matches!(value, Value::U64(_)),
                "{} records {key} as an unsigned integer, which arrives as a string",
                span.name
            );
        }
    }
}

#[tokio::test]
async fn the_gate_hangs_from_the_attempt_the_attempt_from_the_stage_run_and_that_from_the_stretch()
{
    // Before gap OBS-2 was closed this test said the attempt hangs from the job stretch. The
    // conventions page puts a stage run span in between (section 3: "a stage run hangs off the job
    // span, an attempt hangs off the stage run, and the agent, tool call and gate spans hang off
    // the attempt or the stage run"), so the expected parent of the attempt changed.
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;
    let (_, stretch) = run_one(&world, &recorder).await;

    let spans = recorder.spans();
    let stage_run = named(&spans, "factory.stage_run")[0];
    let attempt = named(&spans, "factory.attempt")[0];
    let gate = named(&spans, "factory.gate")[0];
    assert_eq!(
        gate.parent,
        Some(attempt.id),
        "the gate hangs from the attempt"
    );
    assert_eq!(
        attempt.parent,
        Some(stage_run.id),
        "the attempt hangs from the stage run"
    );
    assert_eq!(
        stage_run.parent,
        Some(stretch),
        "the stage run hangs from the job stretch"
    );
}

#[tokio::test]
async fn every_span_carries_the_ids_of_the_same_job() {
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    let job = world.admitted_job().await;
    run_one(&world, &recorder).await;
    run_one(&world, &recorder).await;

    for span in recorder.spans() {
        assert_eq!(
            span.text("factory.job_id").as_deref(),
            Some(job.to_string().as_str()),
            "{} names another job",
            span.name
        );
    }
    let correlation: std::collections::BTreeSet<String> = recorder
        .spans()
        .iter()
        .filter_map(|s| s.text("factory.correlation_id"))
        .collect();
    assert_eq!(
        correlation.len(),
        1,
        "one correlation id for the job: {correlation:?}"
    );
}

#[tokio::test]
async fn a_blocked_gate_is_recorded_as_blocked() {
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .evals_otherwise(support::Eval::Blocked);
    run_one(&world, &recorder).await;

    let spans = recorder.spans();
    let gate = named(&spans, "factory.gate")[0];
    assert_eq!(gate.text("factory.outcome").as_deref(), Some("blocked"));
    assert_eq!(shape_problems(gate), Vec::<String>::new());
}

// ---- The stage run span, and the error class (gaps OBS-2 and OBS-11, closed) ---------------

/// Gap OBS-2, closed. The conventions page has a `factory.stage_run` span between the job and the
/// attempt. `run_attempt` now opens one and runs the attempt span under it.
#[tokio::test]
async fn a_stage_run_span_sits_between_the_job_and_the_attempt() {
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;
    let (claimed, stretch) = run_one(&world, &recorder).await;

    let spans = recorder.spans();
    let stage_runs = named(&spans, "factory.stage_run");
    assert_eq!(stage_runs.len(), 1, "no factory.stage_run span was opened");
    assert_eq!(shape_problems(stage_runs[0]), Vec::<String>::new());
    assert_eq!(stage_runs[0].parent, Some(stretch));
    assert_eq!(
        stage_runs[0].text("factory.stage_run_id").as_deref(),
        Some(claimed.stage_run.to_string().as_str())
    );
    assert_eq!(
        stage_runs[0].text("factory.stage_kind").as_deref(),
        Some(claimed.kind.as_str())
    );
    let attempt = named(&spans, "factory.attempt")[0];
    assert_eq!(attempt.parent, Some(stage_runs[0].id));
}

#[tokio::test]
async fn the_stage_run_span_says_how_the_stage_run_ended() {
    // A pass ends the run as passed, and the span says so. The outcome comes from the status the
    // run holds after the commit.
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;
    run_one(&world, &recorder).await;

    let spans = recorder.spans();
    let stage_run = named(&spans, "factory.stage_run")[0];
    assert_eq!(stage_run.text("factory.outcome").as_deref(), Some("passed"));
    assert!(
        outcome_values().contains(&"passed".to_owned()),
        "passed is an outcome value of the conventions page"
    );
}

#[tokio::test]
async fn a_gate_that_fails_for_good_and_a_blocked_gate_end_the_stage_run_span_as_failed_and_blocked()
 {
    for (eval, expected) in [
        (support::Eval::Fail("check"), "failed"),
        (support::Eval::Blocked, "blocked"),
    ] {
        let recorder = Recorder::new();
        let _installed = recorder.install();
        let world = World::new().await;
        world.admitted_job().await;
        world.script(StageKind::Intake).evals_otherwise(eval);
        run_one(&world, &recorder).await;

        let spans = recorder.spans();
        let stage_run = named(&spans, "factory.stage_run")[0];
        assert_eq!(
            stage_run.text("factory.outcome").as_deref(),
            Some(expected),
            "{:?}",
            stage_run.fields
        );
    }
}

#[tokio::test]
async fn a_retried_stage_run_has_a_span_for_each_attempt_with_the_same_stage_run_id() {
    // The stage run outlives a process and a worker, so each attempt opens a stage run span of its
    // own. The identifier ties them together. A run that is retried is not over, so the first
    // span has no outcome and the second has one.
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;
    world.script(StageKind::Intake).queue([support::Step::Fail(
        factory_workflow::handlers::StageError::Tool,
    )]);
    let (first, _) = run_one(&world, &recorder).await;
    world.advance(400);
    let (second, _) = run_one(&world, &recorder).await;
    assert_eq!(first.stage_run, second.stage_run, "the same stage run");

    let spans = recorder.spans();
    let stage_runs = named(&spans, "factory.stage_run");
    assert_eq!(stage_runs.len(), 2);
    assert_eq!(
        stage_runs[0].text("factory.stage_run_id"),
        stage_runs[1].text("factory.stage_run_id")
    );
    assert_eq!(
        stage_runs[0].text("factory.outcome"),
        None,
        "a retry does not end the stage run: {:?}",
        stage_runs[0].fields
    );
    assert_eq!(
        stage_runs[1].text("factory.outcome").as_deref(),
        Some("passed")
    );
    let attempts = named(&spans, "factory.attempt");
    assert_eq!(attempts[0].parent, Some(stage_runs[0].id));
    assert_eq!(attempts[1].parent, Some(stage_runs[1].id));
}

/// Gap OBS-11, closed. The page allows `factory.error_class` on an attempt: "the failure class the
/// engine recorded, when the work failed". The attempt span now declares the field and records the
/// class in its wire spelling.
#[tokio::test]
async fn a_failed_attempt_span_records_the_failure_class() {
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;
    world.script(StageKind::Intake).queue([support::Step::Fail(
        factory_workflow::handlers::StageError::Tool,
    )]);
    run_one(&world, &recorder).await;

    let spans = recorder.spans();
    let attempt = named(&spans, "factory.attempt")[0];
    assert_eq!(attempt.text("factory.outcome").as_deref(), Some("failed"));
    assert_eq!(
        attempt.text("factory.error_class").as_deref(),
        Some("TOOL_ERROR"),
        "the failed attempt records its error class: {:?}",
        attempt.fields
    );
    assert_eq!(shape_problems(attempt), Vec::<String>::new());
}

#[tokio::test]
async fn the_error_class_is_always_one_of_the_failure_classes_and_only_on_failed_attempts() {
    // The value is a closed set: the wire spelling of a `FailureClass`, never text from a tool.
    use factory_domain::machines::failure::FailureClass;
    use factory_workflow::handlers::StageError;
    let closed: Vec<&str> = [
        FailureClass::ToolError,
        FailureClass::ProviderError,
        FailureClass::SandboxError,
        FailureClass::BudgetExhausted,
        FailureClass::PolicyDenied,
        FailureClass::InvalidOutput,
        FailureClass::TimedOut,
        FailureClass::LeaseLost,
        FailureClass::Internal,
    ]
    .iter()
    .map(|class| class.as_str())
    .collect();
    for (error, expected) in [
        (StageError::Tool, "TOOL_ERROR"),
        (StageError::Provider, "PROVIDER_ERROR"),
        (StageError::PolicyDenied, "POLICY_DENIED"),
        (StageError::InvalidOutput, "INVALID_OUTPUT"),
    ] {
        let recorder = Recorder::new();
        let _installed = recorder.install();
        let world = World::new().await;
        world.admitted_job().await;
        world
            .script(StageKind::Intake)
            .queue([support::Step::Fail(error)]);
        run_one(&world, &recorder).await;
        let spans = recorder.spans();
        let class = named(&spans, "factory.attempt")[0]
            .text("factory.error_class")
            .expect("a class");
        assert_eq!(class, expected);
        assert!(closed.contains(&class.as_str()), "{class} is not a class");
    }

    // A passing attempt declares the field and never fills it.
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;
    run_one(&world, &recorder).await;
    let spans = recorder.spans();
    let attempt = named(&spans, "factory.attempt")[0];
    assert_eq!(attempt.text("factory.error_class"), None);
    assert_eq!(attempt.declared_only, ["factory.error_class"]);
}

// ---- The agent span (gap OBS-3, closed) ----------------------------------------------------

use factory_ports::agent::{AgentRunError, CostMicroUsd, Usage};
use factory_testkit::agent::AdversarialScript;
use serde_json::json;

/// What the fake runtime reports for a run that used these tokens and this much money.
fn used(input: u64, output: u64, micro_usd: u64) -> Usage {
    Usage {
        input_tokens: input,
        output_tokens: output,
        cost: CostMicroUsd(micro_usd),
        requests: 2,
    }
}

/// Gap OBS-3, closed. The conventions page has a `factory.agent` span for one agent invocation
/// inside an attempt. The engine hands each handler a runtime that wraps `AgentRuntime::run` in it,
/// so a stage that runs an agent gets the span without code of its own.
#[tokio::test]
async fn an_agent_run_is_a_span_under_the_attempt_with_its_model_tokens_and_cost() {
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;
    world.script(StageKind::Intake).runs_an_agent();
    world.runtime.queue(AdversarialScript {
        usage: used(1200, 340, 1_500_000),
        ..AdversarialScript::returning(json!({ "stage": "INTAKE" }))
    });
    let (claimed, _) = run_one(&world, &recorder).await;

    let spans = recorder.spans();
    let agents = named(&spans, "factory.agent");
    assert_eq!(agents.len(), 1, "one agent run, one span: {spans:?}");
    let agent = agents[0];
    assert_eq!(shape_problems(agent), Vec::<String>::new(), "{agent:?}");
    let attempt = named(&spans, "factory.attempt")[0];
    assert_eq!(
        agent.parent,
        Some(attempt.id),
        "the agent hangs from the attempt"
    );
    assert_eq!(
        agent.text("factory.attempt_id").as_deref(),
        Some(claimed.attempt.to_string().as_str())
    );
    assert_eq!(
        agent.text("factory.job_id").as_deref(),
        Some(claimed.job.to_string().as_str())
    );
    assert_eq!(
        agent.text("factory.correlation_id").as_deref(),
        Some(claimed.correlation.to_string().as_str())
    );
    assert_eq!(agent.text("factory.outcome").as_deref(), Some("succeeded"));
    assert_eq!(agent.text("factory.model").as_deref(), Some("fake-model"));
    assert!(
        !agent
            .text("factory.agent_id")
            .unwrap_or_default()
            .is_empty(),
        "the agent span names the agent"
    );
    // Counts are signed integers and the cost is dollars, a double.
    assert_eq!(
        agent.fields.get("factory.tokens_input"),
        Some(&Value::I64(1200))
    );
    assert_eq!(
        agent.fields.get("factory.tokens_output"),
        Some(&Value::I64(340))
    );
    assert_eq!(agent.fields.get("factory.cost_usd"), Some(&Value::F64(1.5)));
    assert_eq!(
        agent.declared_only,
        ["error.type"],
        "a run that worked leaves error.type empty and nothing else"
    );
}

#[tokio::test]
async fn a_failed_agent_run_says_how_it_failed_with_a_fixed_word_and_never_the_tools_text() {
    for (error, outcome, kind) in [
        (AgentRunError::Timeout, "timed_out", "timeout"),
        (AgentRunError::Cancelled, "cancelled", "cancelled"),
        (
            AgentRunError::ProviderUnavailable,
            "failed",
            "provider_unavailable",
        ),
        (AgentRunError::BudgetRefused, "failed", "budget_refused"),
    ] {
        let recorder = Recorder::new();
        let _installed = recorder.install();
        let world = World::new().await;
        world.admitted_job().await;
        world.script(StageKind::Intake).runs_an_agent();
        world
            .runtime
            .queue(AdversarialScript::returning(json!({})).failing_with(error));
        run_one(&world, &recorder).await;

        let spans = recorder.spans();
        let agent = named(&spans, "factory.agent")[0];
        assert_eq!(shape_problems(agent), Vec::<String>::new());
        assert_eq!(agent.text("factory.outcome").as_deref(), Some(outcome));
        assert_eq!(agent.text("error.type").as_deref(), Some(kind));
        assert!(
            outcome_values().contains(&outcome.to_owned()),
            "{outcome} is an outcome value of the page"
        );
    }
}

#[tokio::test]
async fn a_stage_that_runs_no_agent_opens_no_agent_span() {
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;
    run_one(&world, &recorder).await;
    assert!(named(&recorder.spans(), "factory.agent").is_empty());
}
