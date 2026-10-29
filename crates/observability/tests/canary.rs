//! Canary secrets in every telemetry sink (negative test NT-SEC-01, telemetry sinks).
//!
//! A canary is a value that must never leave the process. Each test puts canaries into a span
//! attribute, a span name, a span event, an error status and log lines, runs them through the
//! pipeline that `build_pipeline_with_span_exporter` builds from a [`TelemetryConfig`], and reads
//! what an in-memory span exporter and a captured log writer received. The scrubber in the
//! configuration is the real `domain::redaction::Redactor`, built from the patterns in
//! `policies/security.yaml`.
//!
//! Every canary is assembled when a test runs, from pieces that do not look like a credential to a
//! repository secret scan. None is a real credential.

mod common;

use common::{Capture, base64, policy_patterns};
use factory_domain::redaction::{Limits, Redactor};
use factory_observability::guard::SCRUBBER_UNAVAILABLE;
use factory_observability::names::attr;
use factory_observability::redact::RedactorScrubber;
use factory_observability::telemetry::{
    Pipeline, TelemetryConfig, build_pipeline_with_span_exporter,
};
use opentelemetry_sdk::trace::InMemorySpanExporter;
use std::sync::Arc;
use tracing::info_span;

/// The fixed text a failing redactor leaves in a log file in place of a line.
const DROPPED_LINE_MESSAGE: &str = "log line dropped: redactor unavailable";

struct Rig {
    pipeline: Pipeline,
    spans: InMemorySpanExporter,
    logs: Capture,
}

impl Rig {
    fn new(redactor: Redactor) -> Self {
        let config = TelemetryConfig::new(
            "factory-canary-test",
            "0.0.0",
            Arc::new(RedactorScrubber::new(Arc::new(redactor))),
        );
        let spans = InMemorySpanExporter::default();
        let logs = Capture::default();
        let pipeline = build_pipeline_with_span_exporter(&config, logs.clone(), spans.clone())
            .expect("the pipeline builds");
        Self {
            pipeline,
            spans,
            logs,
        }
    }

    /// Everything that left the process, as one text: the debug form of every exported span, and
    /// every log line.
    fn everything_exported(&self) -> String {
        self.pipeline.flush().expect("flush");
        let spans = self.spans.get_finished_spans().expect("read the spans");
        format!("{spans:?}\n{}", self.logs.lines().join("\n"))
    }
}

fn policy_redactor_with(canaries: &[(&str, &str)]) -> Redactor {
    let redactor = Redactor::builder()
        .patterns(policy_patterns())
        .build()
        .expect("the policy patterns compile");
    for (label, value) in canaries {
        redactor
            .register(label, value.as_bytes())
            .expect("the canary can be registered");
    }
    redactor
}

/// A value the factory itself holds. It has no vendor format, so only the registry can find it.
fn registered_canary() -> String {
    ["canary", "7f3a", "Q9xk2", "mB4v", "ZLp0"].join("-")
}

/// A bearer token in the shape of an authorization header.
fn bearer_canary() -> String {
    format!("Authorization: {} {}", "Bearer", "tK3".repeat(8))
}

/// A connection URL with a password.
fn url_password_canary() -> (String, String) {
    let password = ["pw", "Xz81", "qLm"].join("");
    let url = format!(
        "{}://{}:{}@{}",
        "postgres", "svc_user", password, "db.internal:5432"
    );
    (url, password)
}

/// The text the canaries must not appear in, in the forms a reader could use to find them.
fn forms_of(secret: &str) -> Vec<String> {
    vec![
        secret.to_string(),
        base64(secret.as_bytes()),
        secret
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    ]
}

/// Puts the same canary text in every sink the pipeline has.
fn emit_everywhere(text: &str) {
    let span = info_span!(
        "factory.tool_call",
        { attr::TOOL_NAME } = text,
        { attr::JOB_ID } = text,
        "otel.name" = format!("call {text}"),
        "otel.status_code" = tracing::field::Empty,
        "otel.status_description" = tracing::field::Empty,
        // A key off the allowlist is dropped, and the canary with it.
        prompt = text,
    );
    span.record("otel.status_code", "error");
    span.record("otel.status_description", text);
    let entered = span.enter();
    tracing::warn!("retrying with {text}");
    tracing::warn!({ attr::ERROR_CLASS } = %text, "event with a field");
    // The text is in the message of one line and in a field of another. Both on one line is a
    // different case, see `a_url_with_a_password_twice_on_one_log_line_is_redacted`.
    tracing::info!({ attr::TOOL_NAME } = %text, "log field");
    tracing::info!("log message {text}");
    drop(entered);
    drop(span);
    // A line outside any span goes through the same writer.
    tracing::error!(detail = %text, "start-up note");
}

#[test]
fn canary_is_redacted_in_spans_events_and_logs() {
    let canary = registered_canary();
    let rig = Rig::new(policy_redactor_with(&[("broker_keys", &canary)]));
    rig.pipeline.in_scope(|| emit_everywhere(&canary));

    let exported = rig.everything_exported();
    for form in forms_of(&canary) {
        assert!(
            !exported.contains(&form),
            "the canary survived as {form:?} in:\n{exported}"
        );
    }
    // The marker is there, so the redactor ran and did not merely lose the text.
    assert!(
        exported.contains("[REDACTED:broker_keys]"),
        "no marker in:\n{exported}"
    );
    let stats = rig.pipeline.stats().snapshot();
    assert!(
        stats.redacted_values >= 3,
        "the guard redacted too few span values: {stats:?}"
    );
    assert_eq!(stats.scrub_failures, 0);
}

#[test]
fn a_registered_secret_a_bearer_token_and_a_url_password_never_reach_any_exported_field() {
    let registered = registered_canary();
    let bearer = bearer_canary();
    let (url, password) = url_password_canary();
    let rig = Rig::new(policy_redactor_with(&[(
        "database_credentials",
        &registered,
    )]));

    rig.pipeline.in_scope(|| {
        emit_everywhere(&registered);
        emit_everywhere(&bearer);
        emit_everywhere(&url);
    });

    let exported = rig.everything_exported();
    let bearer_value = bearer
        .rsplit(' ')
        .next()
        .expect("a token follows the scheme");
    for secret in [registered.as_str(), bearer_value, password.as_str()] {
        for form in forms_of(secret) {
            assert!(
                !exported.contains(&form),
                "{form:?} survived in:\n{exported}"
            );
        }
    }
    assert!(
        exported.contains("[REDACTED:authorization_header]"),
        "{exported}"
    );
    assert!(
        exported.contains("[REDACTED:url_with_credentials]"),
        "{exported}"
    );
    assert!(
        exported.contains("[REDACTED:database_credentials]"),
        "{exported}"
    );
}

#[test]
fn a_log_field_with_a_bearer_token_is_redacted() {
    let bearer = bearer_canary();
    let rig = Rig::new(policy_redactor_with(&[]));
    rig.pipeline.in_scope(|| {
        tracing::info!(header = %bearer, "request received");
    });
    let lines = rig.logs.lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains("[REDACTED:authorization_header]"),
        "{}",
        lines[0]
    );
    assert!(!lines[0].contains(&"tK3".repeat(8)), "{}", lines[0]);
}

#[test]
fn a_redactor_that_fails_drops_the_value_and_the_line() {
    // Anything longer than 48 bytes makes this redactor fail, as an oversized input would.
    let redactor = Redactor::builder()
        .patterns(policy_patterns())
        .limits(Limits {
            max_input_bytes: 48,
            ..Limits::default()
        })
        .build()
        .expect("builds");
    let rig = Rig::new(redactor);
    let canary = format!("{}-{}", registered_canary(), "x".repeat(60));
    rig.pipeline.in_scope(|| emit_everywhere(&canary));

    let exported = rig.everything_exported();
    assert!(
        !exported.contains(&registered_canary()),
        "the canary was written although the redactor failed:\n{exported}"
    );
    assert!(
        exported.contains(SCRUBBER_UNAVAILABLE),
        "span values were not replaced:\n{exported}"
    );
    assert!(
        exported.contains(DROPPED_LINE_MESSAGE),
        "log lines were not replaced:\n{exported}"
    );
    assert!(rig.pipeline.stats().snapshot().scrub_failures >= 1);
}

/// Gap OBS-1, fixed in the pattern. The `url_with_credentials` pattern of the security policy
/// used to end its match only at white space or a slash, so on a JSON log line it ran on past the
/// closing quote. If the same URL stood twice on the line, as in
/// `info!(url = %url, "connecting to {url}")`, the first match ended inside the second URL, after
/// its scheme. The regex engine reports only matches that do not overlap, so the second URL was
/// no longer found and its password stayed in the line. The password and host classes now stop at
/// quotes and at the delimiters of a JSON line.
#[test]
fn a_url_with_a_password_twice_on_one_log_line_is_redacted() {
    let (url, password) = url_password_canary();
    let rig = Rig::new(policy_redactor_with(&[]));
    rig.pipeline.in_scope(|| {
        tracing::info!({ attr::TOOL_NAME } = %url, "connecting to {url}");
    });
    let lines = rig.logs.lines().join("\n");
    assert!(
        !lines.contains(&password),
        "the password survived in:\n{lines}"
    );
}
