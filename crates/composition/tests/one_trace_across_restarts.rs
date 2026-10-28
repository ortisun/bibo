//! Two engine instances that work on one job, one after the other, write into one trace (ADR 0013,
//! package `s1-observability-instrumentation`).
//!
//! The engine runs over the in-memory fakes with scripted stage handlers (the rig of the workflow
//! crate's own tests, included with `#[path]`). Each stretch of work runs inside the span that the
//! composition helper opens, the telemetry pipeline is the real one with an in-memory exporter
//! behind the attribute guard, and the spans are read back from that exporter. The second engine is
//! built from the same store and configuration, as a restarted process would be, and it opens its
//! own stretch.

#[path = "../../workflow/tests/support/mod.rs"]
mod world_support;

use std::sync::Arc;

use factory_composition::telemetry::job_stretch;
use factory_domain::redaction::Redactor;
use factory_domain::values::Traceparent;
use factory_observability::redact::RedactorScrubber;
use factory_observability::telemetry::{TelemetryConfig, build_pipeline_with_span_exporter};
use factory_observability::testing::SpanCapture;
use tracing::Instrument as _;
use world_support::World;

/// The few fields of an exported span that the checks read. The type is named here so the test
/// does not name the SDK's.
#[derive(Debug, Clone)]
struct Seen {
    name: String,
    trace_id: String,
    span_id: String,
    parent_span_id: String,
    parent_is_remote: bool,
    attributes: Vec<(String, String)>,
}

impl Seen {
    fn attribute(&self, key: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }
}

struct Run {
    spans: Vec<Seen>,
    job: factory_domain::ids::JobId,
    events: Vec<factory_domain::contracts::DomainEvent>,
}

/// Runs the first stage of a job on one engine and the second stage on a restarted one, each
/// inside its own stretch, and returns what was exported and what the job wrote to its outbox.
fn two_engines_on_one_job() -> Run {
    let redactor = Arc::new(Redactor::builder().build().expect("builds"));
    let config = TelemetryConfig::new(
        "factory-restart-test",
        "0.0.0",
        Arc::new(RedactorScrubber::new(redactor)),
    );
    let capture = SpanCapture::new();
    let pipeline = build_pipeline_with_span_exporter(&config, std::io::sink, capture.clone())
        .expect("the pipeline builds");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");

    let (job, events) = pipeline.in_scope(|| {
        runtime.block_on(async {
            let world = World::new().await;
            let job = world.admitted_job().await;

            // The first process holds the claim and runs the intake.
            world.advance(400);
            let first = world.claim_one("worker-1").await;
            let stretch = job_stretch(
                &first.correlation.to_string(),
                &first.job.to_string(),
                &world.tenant.to_string(),
            );
            world
                .engine
                .run_attempt(&first)
                .instrument(stretch)
                .await
                .expect("the first attempt runs");

            // The process stops. A second engine over the same store picks the job up later.
            let restarted = world.restarted_engine();
            world.advance(400);
            let claim = restarted
                .claim_next(&World::worker("worker-2"))
                .await
                .expect("claim");
            let second = claim.started.into_iter().next().expect("a second attempt");
            assert_eq!(second.job, job);
            assert_ne!(second.attempt, first.attempt);
            let stretch = job_stretch(
                &second.correlation.to_string(),
                &second.job.to_string(),
                &world.tenant.to_string(),
            );
            restarted
                .run_attempt(&second)
                .instrument(stretch)
                .await
                .expect("the second attempt runs");
            (job, world.events(job).await)
        })
    });
    pipeline.flush().expect("flush");

    let spans = capture
        .spans()
        .into_iter()
        .map(|span| Seen {
            name: span.name.to_string(),
            trace_id: span.span_context.trace_id().to_string(),
            span_id: span.span_context.span_id().to_string(),
            parent_span_id: span.parent_span_id.to_string(),
            parent_is_remote: span.parent_span_is_remote,
            attributes: span
                .attributes
                .iter()
                .map(|kv| (kv.key.as_str().to_owned(), kv.value.as_str().into_owned()))
                .collect(),
        })
        .collect();
    Run { spans, job, events }
}

fn derived(job: factory_domain::ids::JobId) -> (String, String) {
    let traceparent = Traceparent::for_job(job);
    let mut parts = traceparent.as_str().split('-').skip(1);
    (
        parts.next().expect("a trace id").to_owned(),
        parts.next().expect("a span id").to_owned(),
    )
}

#[test]
fn two_engines_that_work_on_one_job_produce_one_trace_id() {
    let run = two_engines_on_one_job();
    let (trace_id, _) = derived(run.job);

    let names: Vec<&str> = run.spans.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names.iter().filter(|n| **n == "factory.job").count(),
        2,
        "one stretch for each engine: {names:?}"
    );
    assert_eq!(
        names.iter().filter(|n| **n == "factory.attempt").count(),
        2,
        "{names:?}"
    );
    for span in &run.spans {
        assert_eq!(
            span.trace_id, trace_id,
            "{} is in another trace: {span:?}",
            span.name
        );
    }
}

#[test]
fn both_stretches_hang_from_the_same_derived_remote_parent() {
    let run = two_engines_on_one_job();
    let (_, root_span_id) = derived(run.job);
    let stretches: Vec<_> = run
        .spans
        .iter()
        .filter(|s| s.name == "factory.job")
        .collect();
    assert_eq!(stretches.len(), 2);
    for stretch in &stretches {
        assert_eq!(
            stretch.parent_span_id, root_span_id,
            "the stretch does not hang from the derived root: {stretch:?}"
        );
        assert!(stretch.parent_is_remote);
    }
    assert_ne!(
        stretches[0].span_id, stretches[1].span_id,
        "each stretch is a span of its own"
    );
}

#[test]
fn the_attempts_and_gates_hang_from_their_own_stretch() {
    let run = two_engines_on_one_job();
    let stretches: Vec<_> = run
        .spans
        .iter()
        .filter(|s| s.name == "factory.job")
        .collect();
    for attempt in run.spans.iter().filter(|s| s.name == "factory.attempt") {
        assert!(
            stretches
                .iter()
                .any(|s| s.span_id == attempt.parent_span_id),
            "an attempt hangs from no stretch: {attempt:?}"
        );
        let gate = run
            .spans
            .iter()
            .find(|s| s.name == "factory.gate" && s.parent_span_id == attempt.span_id);
        assert!(gate.is_some(), "the attempt has no gate span: {attempt:?}");
    }
}

#[test]
fn the_events_of_the_job_carry_the_same_trace_context() {
    // The engine writes the derived traceparent into each outbox event, so an event and the spans
    // of its job are found by one trace id.
    let run = two_engines_on_one_job();
    let expected = Traceparent::for_job(run.job);
    assert!(!run.events.is_empty(), "the job wrote no event");
    for event in &run.events {
        assert_eq!(
            event.traceparent.as_ref(),
            Some(&expected),
            "event {:?} has another trace context",
            event.event_type
        );
    }
}

#[test]
fn the_stretch_spans_carry_the_required_attributes() {
    let run = two_engines_on_one_job();
    for stretch in run.spans.iter().filter(|s| s.name == "factory.job") {
        for key in [
            "factory.correlation_id",
            "factory.job_id",
            "factory.tenant_id",
        ] {
            assert!(
                stretch.attribute(key).is_some_and(|v| !v.is_empty()),
                "the stretch lacks {key}: {stretch:?}"
            );
        }
        assert_eq!(
            stretch.attribute("factory.job_id"),
            Some(run.job.to_string().as_str())
        );
    }
}
