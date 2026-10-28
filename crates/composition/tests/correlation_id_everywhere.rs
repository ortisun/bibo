//! The correlation id appears on every log line, span and event of a job (package
//! `s1-observability-instrumentation`; the conventions page, section 7).
//!
//! The engine runs over the in-memory fakes with scripted stage handlers (the rig of the workflow
//! crate's own tests, included with `#[path]`), inside the stretch span that the composition helper
//! opens, under the real telemetry pipeline. The test reads three things back: the log lines the
//! pipeline wrote, the spans its exporter received, and the events the job wrote to its outbox.
//! One job has one correlation id, and it must be on all three.

#[path = "../../workflow/tests/support/mod.rs"]
mod world_support;

use std::io::Write;
use std::sync::{Arc, Mutex};

use factory_composition::telemetry::job_stretch;
use factory_domain::redaction::Redactor;
use factory_observability::redact::RedactorScrubber;
use factory_observability::telemetry::{TelemetryConfig, build_pipeline_with_span_exporter};
use factory_observability::testing::SpanCapture;
use factory_workflow::handlers::StageError;
use tracing::Instrument as _;
use world_support::{Step, World};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Capture {
    /// The lines the job wrote. The pipeline's own note about an attribute it dropped is a line
    /// about the telemetry pipeline and not about the job, and it is written when a span is
    /// exported, outside the job's scope, so it has no correlation id and needs none.
    fn lines(&self) -> Vec<String> {
        String::from_utf8_lossy(&self.0.lock().expect("lock"))
            .lines()
            .filter(|line| !line.contains("\"target\":\"factory_observability::"))
            .map(str::to_owned)
            .collect()
    }
}

struct Seen {
    correlation: String,
    lines: Vec<String>,
    /// The `factory.correlation_id` of each exported span, with the span name.
    spans: Vec<(String, Option<String>)>,
    /// The `correlation_id` of each outbox event.
    events: Vec<String>,
    /// How many lines the job wrote while its stretch was open.
    lines_in_stretch: usize,
}

/// Runs a job through three stage runs, one of which fails once and is retried, with a log line
/// from the worker around each attempt, as the worker loop writes them.
fn run_a_job() -> Seen {
    let redactor = Arc::new(Redactor::builder().build().expect("builds"));
    let config = TelemetryConfig::new(
        "factory-correlation-test",
        "0.0.0",
        Arc::new(RedactorScrubber::new(redactor)),
    );
    let capture = SpanCapture::new();
    let logs = Capture::default();
    let sink = logs.clone();
    let pipeline =
        build_pipeline_with_span_exporter(&config, move || sink.clone(), capture.clone())
            .expect("the pipeline builds");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");

    let (correlation, events, lines_in_stretch) = pipeline.in_scope(|| {
        runtime.block_on(async {
            let world = World::new().await;
            world
                .script(factory_domain::vocabulary::StageKind::Intake)
                .queue([Step::Fail(StageError::Tool)]);
            let job = world.admitted_job().await;
            let mut correlation = String::new();
            let mut lines_in_stretch = 0;
            // Four attempts: the intake fails once and is run again, then two more stages.
            for _ in 0..4 {
                world.advance(400);
                let claimed = world.claim_one("worker-1").await;
                correlation = claimed.correlation.to_string();
                let stretch = job_stretch(
                    &claimed.correlation.to_string(),
                    &claimed.job.to_string(),
                    &world.tenant.to_string(),
                );
                let before = logs.lines().len();
                async {
                    tracing::info!(stage = claimed.kind.as_str(), "attempt starting");
                    let outcome = world.engine.run_attempt(&claimed).await.expect("runs");
                    tracing::info!(outcome = ?outcome, "attempt finished");
                }
                .instrument(stretch)
                .await;
                lines_in_stretch += logs.lines().len() - before;
            }
            let events = world
                .events(job)
                .await
                .into_iter()
                .map(|event| event.correlation_id.to_string())
                .collect::<Vec<_>>();
            (correlation, events, lines_in_stretch)
        })
    });
    pipeline.flush().expect("flush");

    let spans = capture
        .spans()
        .into_iter()
        .map(|span| {
            let id = span
                .attributes
                .iter()
                .find(|kv| kv.key.as_str() == "factory.correlation_id")
                .map(|kv| kv.value.as_str().into_owned());
            (span.name.to_string(), id)
        })
        .collect();
    Seen {
        correlation,
        lines: logs.lines(),
        spans,
        events,
        lines_in_stretch,
    }
}

#[test]
fn every_log_line_written_inside_a_job_carries_its_correlation_id() {
    let seen = run_a_job();
    assert!(
        seen.lines_in_stretch >= 8,
        "the worker wrote two lines around each of four attempts: {}",
        seen.lines_in_stretch
    );
    let marker = format!("\"correlation_id\":\"{}\"", seen.correlation);
    for line in &seen.lines {
        assert!(line.starts_with('{'), "not a JSON line: {line}");
        assert!(
            line.contains(&marker),
            "a log line of the job has no correlation id: {line}"
        );
    }
}

#[test]
fn every_span_of_the_job_carries_its_correlation_id() {
    let seen = run_a_job();
    let count = |name: &str| seen.spans.iter().filter(|(n, _)| n == name).count();
    assert_eq!(count("factory.job"), 4, "{:?}", seen.spans);
    assert_eq!(count("factory.attempt"), 4, "{:?}", seen.spans);
    assert_eq!(
        count("factory.stage_run"),
        4,
        "one stage run span for each attempt that ran: {:?}",
        seen.spans
    );
    assert_eq!(
        count("factory.gate"),
        3,
        "the failed intake attempt reaches no gate: {:?}",
        seen.spans
    );
    for (name, id) in &seen.spans {
        assert_eq!(
            id.as_deref(),
            Some(seen.correlation.as_str()),
            "{name} has another correlation id"
        );
    }
}

#[test]
fn every_event_of_the_job_carries_its_correlation_id() {
    let seen = run_a_job();
    assert!(!seen.events.is_empty());
    for id in &seen.events {
        assert_eq!(id, &seen.correlation);
    }
}

#[test]
fn the_three_agree_on_one_id_for_the_whole_job() {
    // A job that is retried keeps one correlation id across attempts.
    let seen = run_a_job();
    let mut ids: Vec<&str> = seen.events.iter().map(String::as_str).collect();
    ids.extend(seen.spans.iter().filter_map(|(_, id)| id.as_deref()));
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids, [seen.correlation.as_str()]);
}
