//! Log lines carry the job correlation id, and they leave the process free of secrets.

mod common;

use common::{Capture, is_valid_json};
use factory_observability::logging::{self, CorrelationId, CorrelationLayer, InvalidCorrelationId};
use factory_observability::names::{self, attr};
use factory_observability::redact::{Scrub, ScrubError};
use factory_observability::spans::{self, Job, StageRun};
use std::borrow::Cow;
use std::sync::Arc;
use tracing::field::Empty;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

const CORRELATION: &str = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77";
const JOB: &str = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a78";

fn with_logging<T>(capture: &Capture, body: impl FnOnce() -> T) -> T {
    let subscriber = tracing_subscriber::registry()
        .with(CorrelationLayer::new())
        .with(logging::log_layer(
            capture.clone(),
            common::policy_scrubber(),
            EnvFilter::new("trace"),
        ));
    tracing::subscriber::with_default(subscriber, body)
}

fn correlation_field() -> String {
    format!("\"{}\":\"{}\"", names::CORRELATION_LOG_FIELD, CORRELATION)
}

#[test]
fn log_lines_carry_correlation_id() {
    let capture = Capture::default();
    with_logging(&capture, || {
        let job = spans::job_span(&Job {
            correlation_id: CORRELATION,
            job_id: JOB,
            tenant_id: "tenant-1",
        });
        let _job = job.enter();
        tracing::info!("job admitted");
        // A span that is deeper in the tree finds the id on the job span above it.
        let stage_run = spans::stage_run_span(&StageRun {
            correlation_id: CORRELATION,
            job_id: JOB,
            stage_run_id: "sr-1",
            stage_kind: "INTAKE",
        });
        let _stage_run = stage_run.enter();
        tracing::warn!("stage run slow");
    });
    let lines = capture.lines();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        assert!(is_valid_json(line), "not valid JSON: {line}");
        assert!(
            line.contains(&correlation_field()),
            "no correlation id in: {line}"
        );
    }
    assert!(lines[0].contains("job admitted"));
    assert!(lines[1].contains("stage run slow"));
}

#[test]
fn the_correlation_id_is_a_top_level_field() {
    let capture = Capture::default();
    with_logging(&capture, || {
        let job = spans::job_span(&Job {
            correlation_id: CORRELATION,
            job_id: JOB,
            tenant_id: "tenant-1",
        });
        let _job = job.enter();
        tracing::info!("hello");
    });
    assert!(
        capture.lines()[0].starts_with(&format!("{{{}", correlation_field())),
        "the id should be the first top-level field: {}",
        capture.lines()[0]
    );
}

#[test]
fn a_line_outside_any_job_has_no_correlation_id() {
    let capture = Capture::default();
    with_logging(&capture, || {
        tracing::info!("starting up");
    });
    let line = &capture.lines()[0];
    assert!(is_valid_json(line));
    assert!(!line.contains(names::CORRELATION_LOG_FIELD), "{line}");
}

#[test]
fn an_id_recorded_after_the_span_was_created_is_picked_up() {
    let capture = Capture::default();
    with_logging(&capture, || {
        let span = tracing::info_span!("factory.job", { attr::CORRELATION_ID } = Empty);
        let _entered = span.enter();
        tracing::info!("before");
        span.record(attr::CORRELATION_ID, CORRELATION);
        tracing::info!("after");
    });
    let lines = capture.lines();
    assert!(!lines[0].contains(names::CORRELATION_LOG_FIELD));
    assert!(lines[1].contains(&correlation_field()));
}

#[test]
fn a_malformed_id_never_reaches_the_log() {
    let capture = Capture::default();
    with_logging(&capture, || {
        let span = tracing::info_span!("factory.job", { attr::CORRELATION_ID } = r#"x","evil":"1"#);
        let _entered = span.enter();
        tracing::info!("hello");
    });
    let line = &capture.lines()[0];
    assert!(is_valid_json(line), "{line}");
    assert!(!line.contains("evil"), "{line}");
    assert!(!line.contains(names::CORRELATION_LOG_FIELD), "{line}");
}

#[test]
fn awkward_message_text_keeps_the_line_valid_json() {
    let capture = Capture::default();
    with_logging(&capture, || {
        let span = tracing::info_span!("factory.job", { attr::CORRELATION_ID } = CORRELATION);
        let _entered = span.enter();
        tracing::info!("quote \" backslash \\ newline \n tab \t unicode \u{e9}\u{1f980}");
    });
    let lines = capture.lines();
    assert_eq!(
        lines.len(),
        1,
        "an embedded newline must not split the line"
    );
    assert!(is_valid_json(&lines[0]), "{}", lines[0]);
    assert!(lines[0].contains(&correlation_field()));
}

#[test]
fn a_secret_in_a_log_line_is_redacted_before_it_is_written() {
    let capture = Capture::default();
    let secret = format!("ghp_{}", "a".repeat(36));
    with_logging(&capture, || {
        let span = tracing::info_span!("factory.job", { attr::CORRELATION_ID } = CORRELATION);
        let _entered = span.enter();
        tracing::error!("push failed with token {secret}");
        tracing::info!({ attr::ERROR_CLASS } = %secret, "second");
    });
    let output = capture.lines().join("\n");
    assert!(
        !output.contains(&secret),
        "the token reached the log: {output}"
    );
    assert!(output.contains("[REDACTED:github_token_classic]"));
    for line in capture.lines() {
        assert!(is_valid_json(&line), "{line}");
    }
}

#[derive(Debug)]
struct Failing;

impl Scrub for Failing {
    fn scrub<'a>(&self, _text: &'a str) -> Result<Cow<'a, str>, ScrubError> {
        Err(ScrubError::Unavailable)
    }
}

#[test]
fn when_the_scrubber_fails_the_line_is_replaced_and_the_original_is_not_written() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::registry()
        .with(CorrelationLayer::new())
        .with(logging::log_layer(
            capture.clone(),
            Arc::new(Failing),
            EnvFilter::new("trace"),
        ));
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!("contains SECRETWORD");
    });
    let output = capture.lines().join("\n");
    assert!(!output.contains("SECRETWORD"), "{output}");
    assert!(is_valid_json(&capture.lines()[0]), "{output}");
    assert!(output.contains("redactor unavailable"));
}

#[test]
fn correlation_ids_are_lower_case_uuids_and_nothing_else() {
    assert_eq!(
        CorrelationId::parse(CORRELATION).unwrap().as_str(),
        CORRELATION
    );
    for bad in [
        "",
        "0192F3A4-7B1C-7D3E-9A52-1C8F0E4B6A77",
        "0192f3a47b1c7d3e9a521c8f0e4b6a77",
        "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a7",
        "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77 ",
        "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a7g",
        "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77\"}",
    ] {
        assert_eq!(
            CorrelationId::parse(bad),
            Err(InvalidCorrelationId),
            "accepted {bad:?}"
        );
    }
}
