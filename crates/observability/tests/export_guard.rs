//! What reaches an exporter, checked with an in-memory exporter behind the real `tracing` layer
//! and the real tracer provider. No network is involved.

use factory_observability::guard::{
    AttributeGuard, GuardSnapshot, SCRUBBER_UNAVAILABLE, TRUNCATION_MARKER,
};
use factory_observability::names::{self, MAX_ATTRIBUTE_VALUE_BYTES, ShapeError, attr, span};
use factory_observability::redact::{PolicyPatternScrubber, Scrub, ScrubError};
use factory_observability::spans::{self, Agent, Attempt, Gate, Job, StageRun, ToolCall};
use factory_observability::trace::{self, SpanProcessing};
use opentelemetry::Value;
use opentelemetry::trace::Status;
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};
use std::borrow::Cow;
use std::sync::Arc;
use tracing::info_span;
use tracing_subscriber::prelude::*;

const CORRELATION: &str = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77";
const JOB: &str = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a78";

struct Harness {
    exporter: InMemorySpanExporter,
    provider: SdkTracerProvider,
    guard: AttributeGuard,
}

impl Harness {
    fn new() -> Self {
        Self::with_scrubber(Arc::new(PolicyPatternScrubber::new()))
    }

    fn with_scrubber(scrubber: Arc<dyn Scrub>) -> Self {
        Self::with_guard(AttributeGuard::new(scrubber))
    }

    fn with_guard(guard: AttributeGuard) -> Self {
        let exporter = InMemorySpanExporter::default();
        let provider = trace::tracer_provider(
            exporter.clone(),
            guard.clone(),
            trace::resource("test", "0.0.0", "test"),
            SpanProcessing::Simple,
        );
        Self {
            exporter,
            provider,
            guard,
        }
    }

    /// Run `body` with a subscriber that exports through this harness.
    fn run<T>(&self, body: impl FnOnce() -> T) -> T {
        let subscriber = tracing_subscriber::registry().with(trace::otel_layer(&self.provider));
        tracing::subscriber::with_default(subscriber, body)
    }

    fn finished(&self) -> Vec<SpanData> {
        self.provider.force_flush().expect("flush");
        self.exporter.get_finished_spans().expect("read spans")
    }

    fn stats(&self) -> GuardSnapshot {
        self.guard.stats().snapshot()
    }
}

fn text_of(span: &SpanData, key: &str) -> Option<String> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| kv.value.as_str().into_owned())
}

fn keys_of(span: &SpanData) -> Vec<String> {
    span.attributes
        .iter()
        .map(|kv| kv.key.as_str().to_string())
        .collect()
}

fn fake_token() -> String {
    format!("ghp_{}", "a".repeat(36))
}

#[derive(Debug)]
struct FailingScrubber;

impl Scrub for FailingScrubber {
    fn scrub<'a>(&self, _text: &'a str) -> Result<Cow<'a, str>, ScrubError> {
        Err(ScrubError::Unavailable)
    }
}

#[test]
fn a_secret_in_an_attribute_is_redacted_before_export() {
    let harness = Harness::new();
    let secret = fake_token();
    harness.run(|| {
        let call = spans::tool_call_span(&ToolCall {
            correlation_id: CORRELATION,
            job_id: JOB,
            attempt_id: JOB,
            tool_name: &format!("deploy --token {secret}"),
        });
        drop(call);
    });
    let exported = harness.finished();
    assert_eq!(exported.len(), 1);
    assert_eq!(
        text_of(&exported[0], attr::TOOL_NAME).as_deref(),
        Some("deploy --token [REDACTED:github_token_classic]")
    );
    assert!(
        !format!("{exported:?}").contains(&secret),
        "the secret is still somewhere in the exported span"
    );
    assert_eq!(harness.stats().redacted_values, 1);
}

#[test]
fn secrets_are_also_removed_from_span_names_event_names_and_event_attributes() {
    let harness = Harness::new();
    let secret = fake_token();
    harness.run(|| {
        let span = info_span!("factory.job", "otel.name" = format!("job {secret}"));
        let _entered = span.enter();
        tracing::info!({ attr::ERROR_CLASS } = %secret, "retrying with {secret}");
    });
    let exported = harness.finished();
    assert_eq!(exported.len(), 1);
    let dump = format!("{exported:?}");
    assert!(!dump.contains(&secret), "a secret survived: {dump}");
    assert_eq!(exported[0].name, "job [REDACTED:github_token_classic]");
    let event = &exported[0].events.events[0];
    assert_eq!(event.name, "retrying with [REDACTED:github_token_classic]");
    let class = event
        .attributes
        .iter()
        .find(|kv| kv.key.as_str() == attr::ERROR_CLASS)
        .expect("the event keeps its allowlisted attribute");
    assert_eq!(class.value.as_str(), "[REDACTED:github_token_classic]");
}

#[test]
fn the_text_of_an_error_status_is_not_exported() {
    let harness = Harness::new();
    harness.run(|| {
        let span = info_span!(
            "factory.job",
            "otel.status_code" = tracing::field::Empty,
            "otel.status_description" = tracing::field::Empty,
        );
        span.record("otel.status_code", "error");
        span.record(
            "otel.status_description",
            "relation \"jobs\" does not exist at /srv/factory/db.rs:88",
        );
    });
    let exported = harness.finished();
    match &exported[0].status {
        Status::Error { description } => assert_eq!(description.as_ref(), ""),
        other => panic!("expected an error status without text, got {other:?}"),
    }
}

#[test]
fn attributes_off_the_allowlist_are_dropped_and_counted() {
    let harness = Harness::new();
    harness.run(|| {
        let span = info_span!(
            "factory.job",
            { attr::JOB_ID } = JOB,
            prompt = "Write a long essay about the repository",
            issue_body = "The body of the issue, with private details",
            authorization = "Bearer abc",
        );
        drop(span);
    });
    let exported = harness.finished();
    assert_eq!(keys_of(&exported[0]), [attr::JOB_ID]);
    assert_eq!(exported[0].dropped_attributes_count, 3);
    assert_eq!(harness.stats().dropped_attributes, 3);
    let dump = format!("{exported:?}");
    assert!(!dump.contains("essay") && !dump.contains("private details"));
}

#[test]
fn a_long_value_is_cut_and_marked() {
    let harness = Harness::new();
    harness.run(|| {
        drop(info_span!(
            "factory.job",
            { attr::JOB_ID } = "x".repeat(10_000)
        ));
    });
    let exported = harness.finished();
    let value = text_of(&exported[0], attr::JOB_ID).expect("kept");
    assert_eq!(
        value.len(),
        MAX_ATTRIBUTE_VALUE_BYTES + TRUNCATION_MARKER.len()
    );
    assert!(value.ends_with(TRUNCATION_MARKER));
    assert_eq!(harness.stats().truncated_values, 1);
}

#[test]
fn a_cut_never_splits_a_multi_byte_character() {
    // 'e with acute' is two bytes, so a limit of 255 falls inside a character.
    let guard =
        AttributeGuard::new(Arc::new(PolicyPatternScrubber::new())).with_max_value_bytes(255);
    let harness = Harness::with_guard(guard);
    harness.run(|| {
        drop(info_span!(
            "factory.job",
            { attr::JOB_ID } = "\u{e9}".repeat(300)
        ));
    });
    let value = text_of(&harness.finished()[0], attr::JOB_ID).expect("kept");
    assert!(value.starts_with('\u{e9}') && value.ends_with(TRUNCATION_MARKER));
    assert_eq!(value.len(), 254 + TRUNCATION_MARKER.len());
}

#[test]
fn a_secret_that_straddles_the_cut_is_removed_whole() {
    let harness = Harness::new();
    let secret = fake_token();
    let padded = format!("{}{}", "a ".repeat(125), secret);
    harness.run(|| {
        drop(info_span!("factory.job", { attr::JOB_ID } = padded));
    });
    let exported = harness.finished();
    let value = text_of(&exported[0], attr::JOB_ID).expect("kept");
    assert!(
        !value.contains("ghp_"),
        "part of the token survived: {value}"
    );
}

#[test]
fn when_the_scrubber_fails_the_original_text_is_never_exported() {
    let harness = Harness::with_scrubber(Arc::new(FailingScrubber));
    harness.run(|| {
        drop(info_span!(
            "factory.job",
            "otel.name" = "name with SECRETWORD",
            { attr::JOB_ID } = "value with SECRETWORD"
        ));
    });
    let exported = harness.finished();
    assert!(!format!("{exported:?}").contains("SECRETWORD"));
    assert_eq!(
        text_of(&exported[0], attr::JOB_ID).as_deref(),
        Some(SCRUBBER_UNAVAILABLE)
    );
    assert!(harness.stats().scrub_failures >= 2);
}

fn value_of(span: &SpanData, key: &str) -> Option<Value> {
    span.attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .map(|kv| kv.value.clone())
}

#[test]
fn numbers_pass_through_unchanged() {
    let harness = Harness::new();
    harness.run(|| {
        drop(info_span!(
            "factory.agent",
            { attr::TOKENS_INPUT } = 120i64,
            { attr::COST_USD } = 0.25f64,
        ));
    });
    let exported = harness.finished();
    assert_eq!(
        value_of(&exported[0], attr::TOKENS_INPUT),
        Some(Value::I64(120))
    );
    assert_eq!(
        value_of(&exported[0], attr::COST_USD),
        Some(Value::F64(0.25))
    );
}

/// The conventions page tells call sites to record integers as `i64`. This test pins the reason:
/// `tracing-opentelemetry` 0.34 turns an unsigned field into a string. If an upgrade changes
/// that, this test fails and the page can be relaxed.
#[test]
fn an_unsigned_field_arrives_as_a_string_so_call_sites_record_integers_as_i64() {
    let harness = Harness::new();
    harness.run(|| {
        drop(info_span!("factory.agent", { attr::TOKENS_INPUT } = 120u64));
    });
    let exported = harness.finished();
    assert!(matches!(
        value_of(&exported[0], attr::TOKENS_INPUT),
        Some(Value::String(_))
    ));
}

#[test]
fn the_attempt_number_is_exported_as_an_integer() {
    let harness = Harness::new();
    harness.run(|| {
        drop(spans::attempt_span(&Attempt {
            correlation_id: CORRELATION,
            job_id: JOB,
            stage_run_id: "sr-1",
            attempt_id: "at-1",
            attempt_number: 2,
        }));
    });
    let exported = harness.finished();
    assert_eq!(
        value_of(&exported[0], attr::ATTEMPT_NUMBER),
        Some(Value::I64(2))
    );
}

#[test]
fn every_span_kind_keeps_the_attributes_it_requires_through_the_guard() {
    let harness = Harness::new();
    harness.run(|| {
        let job = spans::job_span(&Job {
            correlation_id: CORRELATION,
            job_id: JOB,
            tenant_id: "tenant-1",
        });
        let _job = job.enter();
        let stage_run = spans::stage_run_span(&StageRun {
            correlation_id: CORRELATION,
            job_id: JOB,
            stage_run_id: "sr-1",
            stage_kind: "INTAKE",
        });
        let _stage_run = stage_run.enter();
        let attempt = spans::attempt_span(&Attempt {
            correlation_id: CORRELATION,
            job_id: JOB,
            stage_run_id: "sr-1",
            attempt_id: "at-1",
            attempt_number: 1,
        });
        let _attempt = attempt.enter();
        let agent = spans::agent_span(&Agent {
            correlation_id: CORRELATION,
            job_id: JOB,
            attempt_id: "at-1",
            agent_id: "software_engineer",
        });
        spans::record_outcome(&agent, "succeeded");
        let tool = spans::tool_call_span(&ToolCall {
            correlation_id: CORRELATION,
            job_id: JOB,
            attempt_id: "at-1",
            tool_name: "read_file",
        });
        spans::record_outcome(&tool, "denied");
        let gate = spans::gate_span(&Gate {
            correlation_id: CORRELATION,
            job_id: JOB,
            stage_run_id: "sr-1",
            gate_id: "scope-check",
        });
        spans::record_outcome(&gate, "passed");
        spans::record_outcome(&attempt, "succeeded");
        drop((agent, tool, gate));
    });

    let exported = harness.finished();
    let mut seen: Vec<&str> = exported.iter().map(|s| s.name.as_ref()).collect();
    seen.sort_unstable();
    let mut expected = vec![
        span::JOB,
        span::STAGE_RUN,
        span::ATTEMPT,
        span::AGENT,
        span::TOOL_CALL,
        span::GATE,
    ];
    expected.sort_unstable();
    assert_eq!(seen, expected, "one exported span per kind");

    for exported_span in &exported {
        let result = names::check_span_shape(exported_span.name.as_ref(), keys_of(exported_span));
        assert_eq!(result, Ok(()), "{} has the wrong shape", exported_span.name);
    }
}

#[test]
fn spans_nest_from_job_to_stage_run_to_attempt_to_agent() {
    let harness = Harness::new();
    harness.run(|| {
        let job = spans::job_span(&Job {
            correlation_id: CORRELATION,
            job_id: JOB,
            tenant_id: "tenant-1",
        });
        let _job = job.enter();
        let stage_run = spans::stage_run_span(&StageRun {
            correlation_id: CORRELATION,
            job_id: JOB,
            stage_run_id: "sr-1",
            stage_kind: "INTAKE",
        });
        let _stage_run = stage_run.enter();
        let attempt = spans::attempt_span(&Attempt {
            correlation_id: CORRELATION,
            job_id: JOB,
            stage_run_id: "sr-1",
            attempt_id: "at-1",
            attempt_number: 1,
        });
        let _attempt = attempt.enter();
        drop(spans::agent_span(&Agent {
            correlation_id: CORRELATION,
            job_id: JOB,
            attempt_id: "at-1",
            agent_id: "software_engineer",
        }));
    });
    let exported = harness.finished();
    let by_name = |name: &str| exported.iter().find(|s| s.name == name).expect(name);
    let trace_id = by_name(span::JOB).span_context.trace_id();
    for s in &exported {
        assert_eq!(
            s.span_context.trace_id(),
            trace_id,
            "{} left the trace",
            s.name
        );
    }
    let id = |name: &str| by_name(name).span_context.span_id();
    assert_eq!(by_name(span::STAGE_RUN).parent_span_id, id(span::JOB));
    assert_eq!(by_name(span::ATTEMPT).parent_span_id, id(span::STAGE_RUN));
    assert_eq!(by_name(span::AGENT).parent_span_id, id(span::ATTEMPT));
}

#[test]
fn a_call_site_that_forgets_attributes_is_caught_by_the_shape_check() {
    let harness = Harness::new();
    harness.run(|| {
        drop(info_span!(
            "factory.gate",
            { attr::CORRELATION_ID } = CORRELATION,
            { attr::JOB_ID } = JOB,
        ));
    });
    let exported = harness.finished();
    let result = names::check_span_shape(span::GATE, keys_of(&exported[0]));
    match result {
        Err(ShapeError::MissingAttributes(missing)) => {
            assert!(missing.contains(&attr::GATE_ID) && missing.contains(&attr::OUTCOME));
        }
        other => panic!("expected the missing attributes to be named, got {other:?}"),
    }
}
