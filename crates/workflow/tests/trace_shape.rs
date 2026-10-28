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
async fn the_gate_hangs_from_the_attempt_and_the_attempt_from_the_job_stretch() {
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;
    let (_, stretch) = run_one(&world, &recorder).await;

    let spans = recorder.spans();
    let attempt = named(&spans, "factory.attempt")[0];
    let gate = named(&spans, "factory.gate")[0];
    assert_eq!(
        gate.parent,
        Some(attempt.id),
        "the gate hangs from the attempt"
    );
    assert_eq!(
        attempt.parent,
        Some(stretch),
        "with no stage run span, the attempt hangs from the job stretch (gap OBS-2)"
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

// ---- Confirmed gaps ----------------------------------------------------------------------

/// Confirmed gap OBS-2. The conventions page has a `factory.stage_run` span between the job and
/// the attempt. The engine does not open one, so the attempt hangs from the job stretch and a
/// stage run that is retried shows as sibling attempts with nothing to group them.
///
/// Owner: `crates/workflow`, `src/engine/attempt.rs`. Smallest change: in `run_attempt`, open
/// `tracing::info_span!("factory.stage_run", factory.correlation_id, factory.job_id,
/// factory.stage_run_id, factory.stage_kind, factory.outcome = Empty)` and run the attempt span
/// inside it; record the outcome of the stage run when the transition is known.
#[tokio::test]
#[ignore = "confirmed gap OBS-2: the engine opens no factory.stage_run span"]
async fn a_stage_run_span_sits_between_the_job_and_the_attempt() {
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;
    let (_, stretch) = run_one(&world, &recorder).await;

    let spans = recorder.spans();
    let stage_runs = named(&spans, "factory.stage_run");
    assert_eq!(stage_runs.len(), 1, "no factory.stage_run span was opened");
    assert_eq!(shape_problems(stage_runs[0]), Vec::<String>::new());
    assert_eq!(stage_runs[0].parent, Some(stretch));
    let attempt = named(&spans, "factory.attempt")[0];
    assert_eq!(attempt.parent, Some(stage_runs[0].id));
}

/// Confirmed gap OBS-11. The page allows `factory.error_class` on an attempt: "the failure class
/// the engine recorded, when the work failed". The engine does not declare the field on the attempt
/// span, so a failed or timed out attempt says `failed` or `timed_out` and not why, and a trace
/// search cannot separate a tool error from a provider error without opening the ledger.
///
/// Owner: `crates/workflow`, `src/engine/attempt.rs`, `run_attempt`. Smallest change: declare
/// `factory.error_class = tracing::field::Empty` on the span and, when the outcome is
/// `AttemptOutcome::Failed { class, .. }`, record the class in its wire spelling (`TOOL_ERROR`,
/// `TIMED_OUT`, and so on), a closed set.
#[tokio::test]
#[ignore = "confirmed gap OBS-11: a failed attempt span records no factory.error_class"]
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
    assert!(
        attempt
            .text("factory.error_class")
            .is_some_and(|class| !class.is_empty()),
        "the failed attempt records no error class: {:?}",
        attempt.fields
    );
}
