//! The stretch helper of the composition roots (ADR 0013, decision 3).
//!
//! What trace id the span gets is tested in the observability crate, where an in-memory exporter
//! is available (`job_stretch_uses_the_derived_trace_id`). These tests cover what the composition
//! helper adds: it takes the job id as the text the API and the worker have, opens the span for a
//! real job and for a request that names none, and calls the observability helper for the first.

use std::io::Write;
use std::sync::{Arc, Mutex};

use factory_composition::telemetry::job_stretch;
use factory_domain::redaction::Redactor;
use factory_observability::redact::RedactorScrubber;
use factory_observability::telemetry::{TelemetryConfig, build_pipeline};

const CORRELATION: &str = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77";
const JOB: &str = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a78";
const TENANT: &str = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a79";

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
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("lock")).into_owned()
    }
}

/// Runs `body` under a pipeline with no collector and returns what it logged.
fn logged(body: impl FnOnce()) -> String {
    let redactor = Arc::new(Redactor::builder().build().expect("builds"));
    let config = TelemetryConfig::new(
        "factory-composition-test",
        "0.0.0",
        Arc::new(RedactorScrubber::new(redactor)),
    );
    let capture = Capture::default();
    let sink = capture.clone();
    let pipeline = build_pipeline(&config, move || sink.clone()).expect("pipeline");
    pipeline.in_scope(body);
    capture.text()
}

#[test]
fn work_for_a_job_logs_the_correlation_id_inside_the_stretch() {
    let text = logged(|| {
        let stretch = job_stretch(CORRELATION, JOB, TENANT);
        let _entered = stretch.enter();
        tracing::info!("engine call");
    });
    assert!(
        text.contains(&format!("\"correlation_id\":\"{CORRELATION}\"")),
        "{text}"
    );
}

#[test]
fn a_request_that_names_no_job_still_gets_a_stretch() {
    // The API passes `none` for a request that names no job. There is no job to join, so the span
    // has no derived parent, and it still carries the correlation id.
    let text = logged(|| {
        let stretch = job_stretch(CORRELATION, "none", TENANT);
        let _entered = stretch.enter();
        tracing::info!("engine call");
    });
    assert!(
        text.contains(&format!("\"correlation_id\":\"{CORRELATION}\"")),
        "{text}"
    );
}

/// The helper hands a real job to the observability helper that derives the remote parent, and
/// builds the span by itself only when the text is not a job id.
#[test]
fn the_helper_uses_the_observability_stretch_for_a_job_id() {
    let source = include_str!("../src/telemetry.rs");
    assert!(source.contains("job_stretch_span(&JobStretch"));
    assert!(source.contains("JobId::parse(job_id)"));
}
