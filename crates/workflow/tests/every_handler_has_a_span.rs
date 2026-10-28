//! Every stage handler runs inside a span (overview QA-7, package
//! `s1-observability-instrumentation`).
//!
//! A stage handler opens no span itself. The engine opens the `factory.attempt` span around the
//! whole attempt and the `factory.gate` span around `evaluate`, and it is the only caller of
//! `execute` and `evaluate`. So "every handler has a span" has three parts:
//!
//! 1. **The spans themselves**, in this file. The engine runs every one of the 13 stage kinds of
//!    the Slice 1 scope through its attempt path, and the test reads the spans back: the name from
//!    the conventions table, the required attributes, the outcome of the attempt and the result of
//!    the gate, and the parent.
//! 2. **A registry the build checks**, in `crates/composition/tests/handler_registry_scan.rs`. A
//!    source scan finds every production `impl StageHandler` and compares it with a table, so a new
//!    handler that is not listed fails the build. It also checks that the engine's attempt code is
//!    the only caller of `execute` and `evaluate`, so no path runs a handler outside these spans.
//!    The scan lives there because the inner crates, `workflow` among them, may not read files
//!    (rule DEP-05), tests included.
//! 3. **The real handlers.** They are not driven here. Each stage package tests its own handler;
//!    the engine's spans do not depend on what a handler does, and this file proves that with a
//!    scripted handler for every kind.

mod support;
mod telemetry_support;

use std::collections::BTreeSet;

use factory_domain::vocabulary::StageKind;
use support::World;
use telemetry_support::{Recorder, SpanRecord, shape_problems};
use tracing::Instrument as _;

/// `RepositoryIntelligence` for `StageKind::RepositoryIntelligence`, from the wire name
/// `REPOSITORY_INTELLIGENCE`.
fn variant_name(kind: StageKind) -> String {
    kind.as_str()
        .split('_')
        .map(|word| {
            let lower = word.to_lowercase();
            let mut chars = lower.chars();
            chars
                .next()
                .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                .unwrap_or_default()
        })
        .collect()
}

fn child_gate<'a>(spans: &'a [SpanRecord], attempt: &SpanRecord) -> Vec<&'a SpanRecord> {
    spans
        .iter()
        .filter(|s| s.name == "factory.gate" && s.parent == Some(attempt.id))
        .collect()
}

#[tokio::test]
async fn the_engine_opens_an_attempt_span_and_a_gate_span_for_every_stage_kind() {
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    let job = world.admitted_job().await;

    let mut seen: BTreeSet<String> = BTreeSet::new();
    for _ in 0..world.config.scope.len() {
        world.advance(400);
        let claimed = world.claim_one("worker-1").await;
        let before = recorder.spans().len();
        let stretch = tracing::info_span!(
            "factory.job",
            factory.correlation_id = %claimed.correlation,
            factory.job_id = %claimed.job,
            factory.tenant_id = %world.tenant,
        );
        world
            .engine
            .run_attempt(&claimed)
            .instrument(stretch)
            .await
            .expect("the attempt runs");

        let spans = recorder.spans();
        let new_spans = &spans[before..];
        let attempt = new_spans
            .iter()
            .find(|s| s.name == "factory.attempt")
            .unwrap_or_else(|| panic!("no attempt span for {}", claimed.kind));
        assert_eq!(
            shape_problems(attempt),
            Vec::<String>::new(),
            "{}: {:?}",
            claimed.kind,
            attempt.fields
        );
        assert_eq!(
            attempt.text("factory.stage_kind").as_deref(),
            Some(claimed.kind.as_str()),
            "the attempt span names the stage kind it ran"
        );
        assert_eq!(
            attempt.text("factory.job_id").as_deref(),
            Some(job.to_string().as_str())
        );
        assert_eq!(
            attempt.text("factory.outcome").as_deref(),
            Some("succeeded"),
            "{}: the outcome of the attempt is recorded",
            claimed.kind
        );

        let gates = child_gate(new_spans, attempt);
        assert_eq!(
            gates.len(),
            1,
            "{}: one gate span under the attempt",
            claimed.kind
        );
        assert_eq!(
            shape_problems(gates[0]),
            Vec::<String>::new(),
            "{}",
            claimed.kind
        );
        assert_eq!(
            gates[0].text("factory.outcome").as_deref(),
            Some("passed"),
            "{}: the result of the gate is recorded",
            claimed.kind
        );
        assert!(
            gates[0].declared_only.is_empty(),
            "{}: a gate field was declared and never filled: {:?}",
            claimed.kind,
            gates[0].declared_only
        );
        seen.insert(variant_name(claimed.kind));
    }
    let in_scope: BTreeSet<String> = world
        .config
        .scope
        .iter()
        .map(|k| variant_name(*k))
        .collect();
    assert_eq!(in_scope.len(), 13, "Slice 1 runs thirteen stage kinds");
    assert_eq!(
        seen, in_scope,
        "the run did not reach every stage kind in the scope"
    );
}

#[tokio::test]
async fn an_attempt_span_ends_with_its_outcome_when_the_stage_asks_a_person() {
    // The outcome is set after the attempt returns, whatever the result: a stage that needs a
    // person still says how it ended.
    let recorder = Recorder::new();
    let _installed = recorder.install();
    let world = World::new().await;
    world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .queue([support::Step::NeedsHuman]);
    world.advance(400);
    let claimed = world.claim_one("worker-1").await;
    world
        .engine
        .run_attempt(&claimed)
        .await
        .expect("the attempt runs");

    let spans = recorder.spans();
    let attempt = spans
        .iter()
        .find(|s| s.name == "factory.attempt")
        .expect("an attempt span");
    // `factory.error_class` is declared on every attempt span and filled only when the attempt
    // fails (conventions page: "the failure class the engine recorded, when the work failed"),
    // because `tracing` cannot add a field that was not declared at creation. An attempt that asks
    // a person did not fail, so that one field is allowed to stay empty. Any other declared field
    // must be filled.
    let unfilled: Vec<&String> = attempt
        .declared_only
        .iter()
        .filter(|name| *name != "factory.error_class")
        .collect();
    assert!(
        unfilled.is_empty(),
        "an attempt field was declared and never filled: {unfilled:?}"
    );
    let outcome = attempt.text("factory.outcome").expect("an outcome");
    assert!(
        telemetry_support::outcome_values().contains(&outcome),
        "{outcome} is not an outcome value of the conventions page"
    );
}
