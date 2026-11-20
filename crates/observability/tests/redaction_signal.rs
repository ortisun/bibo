//! How an operator learns that the redactor replaced something (runbook
//! `docs/observability/runbook-first-run-signals.md`, signal 5): the counter
//! `factory_redactions_total`.
//!
//! The gap OBS-10 is closed. The attribute guard counts the values it redacted, truncated and
//! dropped (`GuardStats`), and each of those counts now also raises the counter, with the kind and
//! nothing else. The tests below show three things:
//!
//! * the metric equals the guard's own counts;
//! * the label set is closed: whatever a customer puts in a span, the only label key is `kind` and
//!   the only values are the three fixed words, so no secret, pattern id, key or free text can
//!   become a label;
//! * the pipeline enforces the same even when a call site breaks the rule.

mod common;

use factory_observability::guard::AttributeGuard;
use factory_observability::metrics::{
    self, LABELS, METRICS, REDACTION_KINDS, RedactionKind, label, name,
};
use factory_observability::spans::{self, ToolCall};
use factory_observability::trace::{self, SpanProcessing};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};
use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tracing_subscriber::prelude::*;

const CORRELATION: &str = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a77";
const JOB: &str = "0192f3a4-7b1c-7d3e-9a52-1c8f0e4b6a78";

#[test]
fn a_redaction_is_counted_in_a_metric() {
    assert!(
        METRICS
            .iter()
            .any(|metric| metric.name == "factory_redactions_total"),
        "the metrics table has no counter for redactions"
    );
    let spec = METRICS
        .iter()
        .find(|metric| metric.name == name::REDACTIONS_TOTAL)
        .expect("the counter is in the table");
    assert_eq!(spec.labels, [label::KIND], "one label, and it is `kind`");
}

#[test]
fn the_kinds_are_the_three_fixed_words_and_fit_the_label() {
    let words: Vec<&str> = RedactionKind::ALL.iter().map(|k| k.as_str()).collect();
    assert_eq!(words, ["redacted", "truncated", "dropped"]);
    assert_eq!(RedactionKind::ALL.len(), REDACTION_KINDS);
    let label = LABELS
        .iter()
        .find(|l| l.name == label::KIND)
        .expect("the label is in the table");
    assert!(
        REDACTION_KINDS <= label.max_values,
        "the closed set must fit the size the page gives the label"
    );
}

// ---- A pipeline that exports spans through the guard and counts through the meter provider ----

struct Pipeline {
    tracer: SdkTracerProvider,
    meter: SdkMeterProvider,
    metrics: InMemoryMetricExporter,
    guard: AttributeGuard,
}

impl Pipeline {
    fn new(guard: AttributeGuard) -> Self {
        let spans = InMemorySpanExporter::default();
        let tracer = trace::tracer_provider(
            spans,
            guard.clone(),
            trace::resource("test", "0.0.0", "test"),
            SpanProcessing::Simple,
        );
        let metrics = InMemoryMetricExporter::default();
        let meter = metrics::meter_provider(
            metrics.clone(),
            trace::resource("test", "0.0.0", "test"),
            Duration::from_secs(3600),
        );
        Self {
            tracer,
            meter,
            metrics,
            guard,
        }
    }

    fn run<T>(&self, body: impl FnOnce() -> T) -> T {
        let subscriber = tracing_subscriber::registry()
            .with(trace::otel_layer(&self.tracer))
            .with(metrics::metrics_layer(&self.meter));
        tracing::subscriber::with_default(subscriber, body)
    }

    /// The points of `factory_redactions_total`, each as its labels and its value.
    fn redaction_points(&self) -> Vec<(BTreeMap<String, String>, u64)> {
        self.tracer.force_flush().expect("flush spans");
        self.meter.force_flush().expect("flush metrics");
        let mut points = Vec::new();
        // Each flush exports the running totals again, so only the last export counts.
        let exports = self.metrics.get_finished_metrics().expect("read");
        let Some(resource) = exports.last() else {
            return points;
        };
        for scope in resource.scope_metrics() {
            for metric in scope.metrics() {
                if metric.name() != name::REDACTIONS_TOTAL {
                    continue;
                }
                let AggregatedMetrics::U64(MetricData::Sum(sum)) = metric.data() else {
                    panic!("the counter is not a u64 sum");
                };
                for point in sum.data_points() {
                    points.push((labels_of(point.attributes()), point.value()));
                }
            }
        }
        points
    }

    /// The total for one kind, zero when there is no point.
    fn total(&self, kind: RedactionKind) -> u64 {
        self.redaction_points()
            .into_iter()
            .filter(|(labels, _)| {
                labels.get(label::KIND).map(String::as_str) == Some(kind.as_str())
            })
            .map(|(_, value)| value)
            .sum()
    }
}

fn labels_of<'a>(attributes: impl Iterator<Item = &'a KeyValue>) -> BTreeMap<String, String> {
    attributes
        .map(|kv| (kv.key.as_str().to_owned(), kv.value.as_str().into_owned()))
        .collect()
}

fn guard() -> AttributeGuard {
    AttributeGuard::new(common::policy_scrubber())
}

/// A span with a tool name, which is a string attribute the guard scrubs and cuts.
fn tool_call(name: &str) {
    drop(spans::tool_call_span(&ToolCall {
        correlation_id: CORRELATION,
        job_id: JOB,
        attempt_id: JOB,
        tool_name: name,
    }));
}

fn fake_token(tag: char) -> String {
    format!("ghp_{}", tag.to_string().repeat(36))
}

#[test]
fn the_metric_equals_the_counts_of_the_guard() {
    let pipeline = Pipeline::new(guard());
    pipeline.run(|| {
        // Three values with a secret in them.
        for tag in ['a', 'b', 'c'] {
            tool_call(&format!("deploy --token {}", fake_token(tag)));
        }
        // Two values that are over the length limit.
        for _ in 0..2 {
            tool_call(&"x".repeat(1_000));
        }
        // An attribute that is not on the allowlist, set by a call site that should not.
        tracing::info_span!(
            "factory.job",
            factory.prompt = "a prompt",
            factory.job_id = JOB
        );
    });
    // A span's name carries its tool name as well as its attribute, so one value can be redacted
    // or cut twice. The test does not depend on how many places a value lands in; it compares the
    // metric with the guard's own counts.
    let stats = pipeline.guard.stats().snapshot();
    assert!(stats.redacted_values >= 3, "{stats:?}");
    assert!(stats.truncated_values >= 2, "{stats:?}");
    assert!(stats.dropped_attributes >= 1, "{stats:?}");

    assert_eq!(
        pipeline.total(RedactionKind::Redacted),
        stats.redacted_values
    );
    assert_eq!(
        pipeline.total(RedactionKind::Truncated),
        stats.truncated_values
    );
    assert_eq!(
        pipeline.total(RedactionKind::Dropped),
        stats.dropped_attributes + stats.scrub_failures
    );
}

#[test]
fn a_scrubber_that_fails_is_counted_as_dropped_because_the_original_is_not_passed_on() {
    #[derive(Debug)]
    struct Failing;
    impl factory_observability::redact::Scrub for Failing {
        fn scrub<'a>(
            &self,
            _text: &'a str,
        ) -> Result<std::borrow::Cow<'a, str>, factory_observability::redact::ScrubError> {
            Err(factory_observability::redact::ScrubError::Unavailable)
        }
    }
    let pipeline = Pipeline::new(AttributeGuard::new(std::sync::Arc::new(Failing)));
    pipeline.run(|| tool_call("anything"));
    let stats = pipeline.guard.stats().snapshot();
    assert!(stats.scrub_failures >= 1, "{stats:?}");
    assert_eq!(pipeline.total(RedactionKind::Dropped), stats.scrub_failures);
    assert_eq!(pipeline.total(RedactionKind::Redacted), 0);
}

// ---- The label set is closed ----------------------------------------------------------------

#[test]
fn whatever_a_customer_puts_in_a_span_the_only_label_is_kind_with_one_of_three_words() {
    let pipeline = Pipeline::new(guard());
    let secrets: Vec<String> = ('a'..='z').map(fake_token).collect();
    pipeline.run(|| {
        // Fifty values that differ in every way a label could vary on: the secret, the text
        // around it, the length and the key of the attribute that holds it.
        for (index, secret) in secrets.iter().enumerate() {
            tool_call(&format!(
                "run-{index} --token {secret} {}",
                "y".repeat(index * 20)
            ));
        }
        for index in 0..25 {
            let value = format!("value {index}");
            tracing::info_span!(
                "factory.job",
                factory.job_id = JOB,
                customer.alpha = value.as_str(),
                customer.beta = value.as_str()
            );
        }
    });

    let points = pipeline.redaction_points();
    let allowed: BTreeSet<&str> = RedactionKind::ALL.iter().map(|k| k.as_str()).collect();
    assert!(!points.is_empty(), "the pipeline counted nothing");
    assert!(
        points.len() <= REDACTION_KINDS,
        "{} series for {REDACTION_KINDS} kinds: {points:?}",
        points.len()
    );
    for (labels, _) in &points {
        assert_eq!(
            labels.keys().map(String::as_str).collect::<Vec<_>>(),
            [label::KIND],
            "a label other than `kind`: {labels:?}"
        );
        assert!(
            allowed.contains(labels[label::KIND].as_str()),
            "a label value that is not a kind: {labels:?}"
        );
    }
    let everything = format!("{points:?}");
    for secret in &secrets {
        assert!(!everything.contains(secret), "a secret is in the metric");
    }
    assert!(
        !everything.contains("github_token_classic"),
        "a pattern id is in the metric: {everything}"
    );
    assert!(!everything.contains("customer."), "{everything}");
    assert!(!everything.contains("value "), "{everything}");
}

#[test]
fn a_call_site_that_adds_a_label_to_the_metric_gets_it_removed_by_the_view() {
    // The second line of defense: if some code records the counter itself with more than the kind,
    // the meter provider keeps `kind` and nothing else, so the extra text never becomes a series.
    let pipeline = Pipeline::new(guard());
    let secret = fake_token('q');
    pipeline.run(|| {
        tracing::info!(
            monotonic_counter.factory_redactions_total = 1_u64,
            kind = "redacted",
            pattern = "github_token_classic",
            matched = secret.as_str(),
            job = JOB
        );
        tracing::info!(
            monotonic_counter.factory_redactions_total = 1_u64,
            kind = "redacted",
            pattern = "another_pattern",
            matched = "other text",
            job = "another job"
        );
    });
    let points = pipeline.redaction_points();
    assert_eq!(points.len(), 1, "extra labels split the series: {points:?}");
    assert_eq!(points[0].0.len(), 1);
    assert_eq!(points[0].0[label::KIND], "redacted");
    assert_eq!(points[0].1, 2);
}

#[test]
fn a_kind_that_is_not_one_of_the_three_cannot_be_built_from_text() {
    // There is no constructor from text: the enum has exactly the three variants, and
    // `record_redaction` takes the enum. This match fails to compile when a variant is added
    // without a word on the page and a place in this test.
    fn word(kind: RedactionKind) -> &'static str {
        match kind {
            RedactionKind::Redacted => "redacted",
            RedactionKind::Truncated => "truncated",
            RedactionKind::Dropped => "dropped",
        }
    }
    for kind in RedactionKind::ALL {
        assert_eq!(word(kind), kind.as_str());
    }
}
