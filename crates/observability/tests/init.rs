//! Configuration of the telemetry pipeline, and initialization of the process.
//!
//! `init` installs a global subscriber, which a process can do once. Everything that touches
//! that global state is in a single test, so the result does not depend on which tests share a
//! process.

mod common;

use common::{Capture, is_valid_json};
use factory_observability::telemetry::{
    InitError, TelemetryConfig, build_pipeline, init, is_initialized,
};
use std::collections::HashMap;
use std::time::Duration;

fn lookup(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = vars
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |key| map.get(key).cloned()
}

fn config(vars: &[(&str, &str)]) -> Result<TelemetryConfig, InitError> {
    TelemetryConfig::from_lookup("factory-test", "1.2.3", lookup(vars))
}

#[test]
fn defaults_export_nothing_and_log_at_info() {
    let config = config(&[]).expect("defaults are valid");
    assert_eq!(config.service_name(), "factory-test");
    assert_eq!(config.service_version(), "1.2.3");
    assert_eq!(config.environment(), "local");
    assert_eq!(config.otlp_endpoint(), None);
    assert_eq!(config.log_filter(), "info");
    assert_eq!(config.metric_interval(), Duration::from_secs(15));
}

#[test]
fn the_standard_endpoint_variable_sets_the_collector_and_a_trailing_slash_is_ignored() {
    let config = config(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318/")]).unwrap();
    assert_eq!(config.otlp_endpoint(), Some("http://localhost:4318"));
    assert_eq!(
        config.traces_url().as_deref(),
        Some("http://localhost:4318/v1/traces")
    );
    assert_eq!(
        config.metrics_url().as_deref(),
        Some("http://localhost:4318/v1/metrics")
    );
}

#[test]
fn an_empty_endpoint_means_not_set() {
    assert_eq!(
        config(&[("OTEL_EXPORTER_OTLP_ENDPOINT", "")])
            .unwrap()
            .otlp_endpoint(),
        None
    );
}

#[test]
fn the_sdk_disabled_switch_turns_export_off() {
    let config = config(&[
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318"),
        ("OTEL_SDK_DISABLED", "true"),
    ])
    .unwrap();
    assert_eq!(config.otlp_endpoint(), None);
}

#[test]
fn environment_and_log_filter_come_from_the_factory_variables() {
    let config = config(&[
        ("FACTORY_ENV", "staging"),
        ("FACTORY_LOG", "debug,hyper=off"),
    ])
    .unwrap();
    assert_eq!(config.environment(), "staging");
    assert_eq!(config.log_filter(), "debug,hyper=off");
}

#[test]
fn endpoints_that_could_leak_a_credential_or_cannot_work_are_refused() {
    for bad in [
        "https://collector.example:4318",
        "http://user:secret@collector.example:4318",
        "localhost:4318",
        "ftp://collector.example",
        "http://collector.example:4318?token=abc",
        "http://collector.example:4318#frag",
        "http://",
        "http://has space:4318",
    ] {
        let result = config(&[("OTEL_EXPORTER_OTLP_ENDPOINT", bad)]);
        assert!(
            matches!(result, Err(InitError::InvalidEndpoint(_))),
            "accepted {bad:?}: {result:?}"
        );
    }
}

#[test]
fn an_endpoint_error_never_repeats_the_credential() {
    let secret = "hunter2hunter2";
    let error = config(&[(
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        &format!("http://user:{secret}@collector.example"),
    )])
    .unwrap_err();
    assert!(!error.to_string().contains(secret), "{error}");
}

#[test]
fn a_log_filter_that_does_not_parse_is_refused() {
    let result = config(&[("FACTORY_LOG", "info,[unterminated")]);
    assert!(
        matches!(result, Err(InitError::InvalidLogFilter(_))),
        "{result:?}"
    );
}

#[test]
fn a_pipeline_without_a_collector_still_logs_with_the_correlation_id() {
    let capture = Capture::default();
    let pipeline = build_pipeline(&config(&[]).unwrap(), capture.clone()).expect("builds");
    pipeline.in_scope(|| {
        let span = tracing::info_span!(
            "factory.job",
            "factory.correlation_id" = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77"
        );
        let _entered = span.enter();
        tracing::info!("hello from the job");
        // Metric events are accepted and go nowhere when there is no collector.
        tracing::info!(
            monotonic_counter.factory_retries_total = 1u64,
            stage = "INTAKE"
        );
    });
    pipeline.flush().expect("nothing to flush is not an error");
    let lines = capture.lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(is_valid_json(&lines[0]));
    assert!(lines[0].contains("\"correlation_id\":\"0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77\""));
    pipeline.shutdown().expect("shuts down cleanly");
}

/// The only test that installs the global subscriber.
#[test]
fn init_is_idempotent() {
    assert!(!is_initialized());
    let config = config(&[]).unwrap();

    let first = init(&config).expect("the first call installs the pipeline");
    assert!(first.owns_pipeline());
    assert!(is_initialized());
    assert!(tracing::dispatcher::has_been_set());

    let second = init(&config).expect("a second call is not an error");
    assert!(
        !second.owns_pipeline(),
        "only the first call owns the pipeline"
    );

    // Telemetry still works, and nothing panics when the first guard goes away.
    tracing::info!("still logging after two inits");
    drop(first);
    let third = init(&config).expect("a call after the first guard is gone is not an error either");
    assert!(!third.owns_pipeline());
    assert!(is_initialized());
    tracing::info!("still logging after the first guard dropped");
}
