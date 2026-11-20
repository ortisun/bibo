//! Metric names, labels and the guarantees the metric pipeline gives about them.

mod common;

use common::{CONVENTIONS, names_in, table};
use factory_observability::metrics::{self, LABELS, METRICS, MetricKind, MetricSpec, label, name};
use factory_observability::names::{ATTRIBUTES, Cardinality};
use factory_observability::trace;
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};
use std::collections::BTreeSet;
use std::time::Duration;
use tracing_subscriber::prelude::*;

const TOTAL_SERIES_BUDGET: usize = 5_000;
const LABEL_SETS_PER_METRIC_BUDGET: usize = 500;

fn is_metric_name(name: &str) -> bool {
    !name.is_empty()
        && name.starts_with("factory_")
        && !name.contains("__")
        && !name.ends_with('_')
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

#[test]
fn metric_names_follow_the_convention() {
    for spec in METRICS {
        assert!(is_metric_name(spec.name), "bad metric name {}", spec.name);
        match spec.kind {
            MetricKind::Counter => assert!(
                spec.name.ends_with("_total"),
                "counter {} must end in _total",
                spec.name
            ),
            MetricKind::Gauge | MetricKind::Histogram => assert!(
                !spec.name.ends_with("_total"),
                "{} is not a counter and must not end in _total",
                spec.name
            ),
        }
        assert!(
            spec.meaning.ends_with('.') && spec.meaning.len() > 20,
            "{} needs a sentence as its description",
            spec.name
        );
        assert!(
            spec.unit.is_ascii() && spec.unit.len() <= 63 && !spec.unit.is_empty(),
            "{} has an unusable unit {:?}",
            spec.name,
            spec.unit
        );
    }
}

#[test]
fn a_unit_appears_in_the_name_as_well_as_in_the_unit_field() {
    for spec in METRICS {
        match spec.unit {
            "s" => assert!(
                spec.name.contains("_seconds"),
                "{} has unit s but no _seconds in its name",
                spec.name
            ),
            "{USD}" => assert!(
                spec.name.contains("_usd"),
                "{} has unit {{USD}} but no _usd in its name",
                spec.name
            ),
            other => assert!(
                other.starts_with('{') && other.ends_with('}'),
                "{} uses unit {other:?}; use s, {{USD}} or a counted-thing annotation such as {{retry}}",
                spec.name
            ),
        }
    }
}

#[test]
fn the_required_metrics_exist_under_stable_names() {
    let names: BTreeSet<&str> = METRICS.iter().map(|m| m.name).collect();
    assert_eq!(names.len(), METRICS.len(), "a metric name appears twice");
    for required in [
        "factory_queue_depth",
        "factory_stage_duration_seconds",
        "factory_stage_runs_total",
        "factory_gate_failures_total",
        "factory_retries_total",
        "factory_spend_usd_total",
    ] {
        assert!(names.contains(required), "missing metric {required}");
    }
    assert_eq!(name::QUEUE_DEPTH, "factory_queue_depth");
    assert_eq!(name::SPEND_USD_TOTAL, "factory_spend_usd_total");
}

#[test]
fn nothing_high_cardinality_is_used_as_a_metric_label() {
    let forbidden = [
        "job_id",
        "stage_run_id",
        "attempt_id",
        "tenant_id",
        "correlation_id",
        "trace_id",
        "span_id",
        "user",
        "email",
        "path",
        "url",
        "prompt",
        "message",
        "model_output",
    ];
    // The bare form of every unbounded span attribute is also not a label.
    let unbounded_bare: BTreeSet<&str> = ATTRIBUTES
        .iter()
        .filter(|a| a.cardinality == Cardinality::Unbounded)
        .map(|a| a.key.strip_prefix("factory.").unwrap_or(a.key))
        .collect();

    let declared: BTreeSet<&str> = LABELS.iter().map(|l| l.name).collect();
    for spec in METRICS {
        for used in spec.labels {
            assert!(
                declared.contains(used),
                "{} uses label {used}, which has no entry in LABELS",
                spec.name
            );
            assert!(!forbidden.contains(used), "{used} must not be a label");
            assert!(
                !unbounded_bare.contains(used),
                "{used} names an unbounded attribute and must not be a label"
            );
            assert!(
                !used.ends_with("_id") && !used.ends_with("_sha256") && !used.ends_with("_hash"),
                "{used} looks like an identifier or a digest"
            );
        }
    }
    for label_spec in LABELS {
        assert!(
            label_spec.max_values <= 64,
            "label {} allows {} values; a label this wide belongs on a span",
            label_spec.name,
            label_spec.max_values
        );
        assert!(
            label_spec
                .name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_')
                && !label_spec.name.contains('.'),
            "label {} is not a plain lower case word",
            label_spec.name
        );
    }
}

fn label_set_bound(spec: &MetricSpec) -> usize {
    spec.labels
        .iter()
        .map(|used| {
            LABELS
                .iter()
                .find(|l| l.name == *used)
                .map(|l| l.max_values)
                .expect("declared")
        })
        .product()
}

fn series_for(spec: &MetricSpec) -> usize {
    let per_set = match spec.kind {
        MetricKind::Histogram => spec.buckets.len() + 1 + 2, // buckets, +Inf, sum, count
        _ => 1,
    };
    spec.max_label_sets * per_set
}

#[test]
fn label_sets_fit_inside_the_cardinality_budget() {
    let mut total = 0;
    for spec in METRICS {
        assert!(
            spec.max_label_sets <= label_set_bound(spec),
            "{} claims {} label sets, more than its labels allow ({})",
            spec.name,
            spec.max_label_sets,
            label_set_bound(spec)
        );
        assert!(
            spec.max_label_sets <= LABEL_SETS_PER_METRIC_BUDGET,
            "{} allows {} label sets",
            spec.name,
            spec.max_label_sets
        );
        total += series_for(spec);
    }
    assert!(
        total <= TOTAL_SERIES_BUDGET,
        "the metrics can create {total} series; the budget is {TOTAL_SERIES_BUDGET}"
    );
}

#[test]
fn histogram_buckets_are_sorted_and_only_histograms_have_them() {
    for spec in METRICS {
        match spec.kind {
            MetricKind::Histogram => {
                assert!(spec.buckets.len() >= 5, "{} has too few buckets", spec.name);
                assert!(
                    spec.buckets.windows(2).all(|pair| pair[0] < pair[1]),
                    "{} buckets are not strictly increasing",
                    spec.name
                );
            }
            _ => assert!(spec.buckets.is_empty(), "{} is not a histogram", spec.name),
        }
    }
}

#[test]
fn conventions_page_metric_table_equals_the_constants() {
    let from_page: Vec<(String, String, String, BTreeSet<String>)> = table(CONVENTIONS, "metrics")
        .iter()
        .map(|row| {
            (
                row[0].clone(),
                row[1].clone(),
                row[2].clone(),
                names_in(&row[3]),
            )
        })
        .collect();
    let from_code: Vec<(String, String, String, BTreeSet<String>)> = METRICS
        .iter()
        .map(|m| {
            (
                m.name.to_string(),
                m.kind.as_str().to_string(),
                m.unit.to_string(),
                m.labels.iter().map(|l| l.to_string()).collect(),
            )
        })
        .collect();
    assert_eq!(from_page, from_code);
}

#[test]
fn conventions_page_label_table_equals_the_constants() {
    let from_page: Vec<(String, String)> = table(CONVENTIONS, "labels")
        .iter()
        .map(|row| (row[0].clone(), row[1].clone()))
        .collect();
    let from_code: Vec<(String, String)> = LABELS
        .iter()
        .map(|l| (l.name.to_string(), l.max_values.to_string()))
        .collect();
    assert_eq!(from_page, from_code);
}

// ---- The pipeline ------------------------------------------------------------------------

struct Pipeline {
    provider: SdkMeterProvider,
    exporter: InMemoryMetricExporter,
}

impl Pipeline {
    fn new() -> Self {
        let exporter = InMemoryMetricExporter::default();
        let provider = metrics::meter_provider(
            exporter.clone(),
            trace::resource("test", "0.0.0", "test"),
            Duration::from_secs(3600),
        );
        Self { provider, exporter }
    }

    fn run(&self, body: impl FnOnce()) {
        let subscriber =
            tracing_subscriber::registry().with(metrics::metrics_layer(&self.provider));
        tracing::subscriber::with_default(subscriber, body);
    }

    /// Every exported metric as (name, unit, description, labels of each data point, values).
    fn collected(&self) -> Vec<Collected> {
        self.provider.force_flush().expect("flush");
        let mut out = Vec::new();
        for resource_metrics in self.exporter.get_finished_metrics().expect("read") {
            for scope in resource_metrics.scope_metrics() {
                for metric in scope.metrics() {
                    let mut points = Vec::new();
                    collect_points(metric.data(), &mut points);
                    out.push(Collected {
                        name: metric.name().to_string(),
                        unit: metric.unit().to_string(),
                        description: metric.description().to_string(),
                        points,
                    });
                }
            }
        }
        out
    }
}

struct Collected {
    name: String,
    unit: String,
    description: String,
    points: Vec<Point>,
}

struct Point {
    labels: Vec<(String, String)>,
    value: f64,
    bounds: Vec<f64>,
}

fn pairs<'a>(attributes: impl Iterator<Item = &'a KeyValue>) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = attributes
        .map(|kv| (kv.key.as_str().to_string(), kv.value.as_str().into_owned()))
        .collect();
    pairs.sort();
    pairs
}

fn collect_points(data: &AggregatedMetrics, out: &mut Vec<Point>) {
    fn from_data<T: Copy + Into<f64>>(data: &MetricData<T>, out: &mut Vec<Point>) {
        match data {
            MetricData::Sum(sum) => {
                for p in sum.data_points() {
                    out.push(Point {
                        labels: pairs(p.attributes()),
                        value: p.value().into(),
                        bounds: vec![],
                    });
                }
            }
            MetricData::Gauge(gauge) => {
                for p in gauge.data_points() {
                    out.push(Point {
                        labels: pairs(p.attributes()),
                        value: p.value().into(),
                        bounds: vec![],
                    });
                }
            }
            MetricData::Histogram(histogram) => {
                for p in histogram.data_points() {
                    out.push(Point {
                        labels: pairs(p.attributes()),
                        value: p.count() as f64,
                        bounds: p.bounds().collect(),
                    });
                }
            }
            MetricData::ExponentialHistogram(_) => panic!("no exponential histograms expected"),
        }
    }
    match data {
        AggregatedMetrics::F64(d) => from_data(d, out),
        AggregatedMetrics::I64(d) => {
            // i64 does not convert to f64 losslessly in the type system, so go through a map.
            match d {
                MetricData::Sum(sum) => out.extend(sum.data_points().map(|p| Point {
                    labels: pairs(p.attributes()),
                    value: p.value() as f64,
                    bounds: vec![],
                })),
                MetricData::Gauge(gauge) => out.extend(gauge.data_points().map(|p| Point {
                    labels: pairs(p.attributes()),
                    value: p.value() as f64,
                    bounds: vec![],
                })),
                _ => panic!("unexpected i64 aggregation"),
            }
        }
        AggregatedMetrics::U64(d) => match d {
            MetricData::Sum(sum) => out.extend(sum.data_points().map(|p| Point {
                labels: pairs(p.attributes()),
                value: p.value() as f64,
                bounds: vec![],
            })),
            _ => panic!("unexpected u64 aggregation"),
        },
    }
}

fn only<'a>(collected: &'a [Collected], name: &str) -> &'a Collected {
    collected
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("{name} was not exported"))
}

#[test]
fn a_metric_event_becomes_an_instrument_with_the_documented_unit_and_description() {
    let pipeline = Pipeline::new();
    pipeline.run(|| {
        tracing::info!(
            monotonic_counter.factory_retries_total = 1u64,
            stage = "INTAKE"
        );
    });
    let collected = pipeline.collected();
    let retries = only(&collected, name::RETRIES_TOTAL);
    let spec = METRICS
        .iter()
        .find(|m| m.name == name::RETRIES_TOTAL)
        .unwrap();
    assert_eq!(retries.unit, spec.unit);
    assert_eq!(retries.description, spec.meaning);
    assert_eq!(retries.points.len(), 1);
    assert_eq!(
        retries.points[0].labels,
        [("stage".to_string(), "INTAKE".to_string())]
    );
    assert_eq!(retries.points[0].value, 1.0);
}

#[test]
fn a_label_that_is_not_listed_is_dropped_from_the_exported_series() {
    let pipeline = Pipeline::new();
    pipeline.run(|| {
        for job in [
            "0192f3a4-0000-7000-8000-000000000001",
            "0192f3a4-0000-7000-8000-000000000002",
        ] {
            tracing::info!(
                monotonic_counter.factory_retries_total = 1u64,
                stage = "INTAKE",
                job_id = job,
                correlation_id = job,
            );
        }
    });
    let collected = pipeline.collected();
    let retries = only(&collected, name::RETRIES_TOTAL);
    assert_eq!(
        retries.points.len(),
        1,
        "two jobs must share one series: {:?}",
        retries.points.iter().map(|p| &p.labels).collect::<Vec<_>>()
    );
    assert_eq!(
        retries.points[0].labels,
        [("stage".to_string(), "INTAKE".to_string())]
    );
    assert_eq!(retries.points[0].value, 2.0);
}

#[test]
fn a_metric_name_that_is_not_registered_is_not_exported() {
    let pipeline = Pipeline::new();
    pipeline.run(|| {
        tracing::info!(monotonic_counter.factory_made_up_total = 1u64);
        tracing::info!(
            monotonic_counter.factory_retries_total = 1u64,
            stage = "INTAKE"
        );
    });
    let collected = pipeline.collected();
    assert!(collected.iter().all(|c| c.name != "factory_made_up_total"));
    assert!(collected.iter().any(|c| c.name == name::RETRIES_TOTAL));
}

#[test]
fn a_metric_recorded_with_the_wrong_kind_is_not_exported() {
    let pipeline = Pipeline::new();
    pipeline.run(|| {
        // factory_retries_total is a counter. A histogram of the same name is a mistake.
        tracing::info!(histogram.factory_retries_total = 1.0f64, stage = "INTAKE");
    });
    let collected = pipeline.collected();
    assert!(
        collected.iter().all(|c| c.name != name::RETRIES_TOTAL),
        "exported with the wrong kind"
    );
}

#[test]
fn a_histogram_uses_the_documented_buckets() {
    let pipeline = Pipeline::new();
    pipeline.run(|| {
        tracing::info!(
            histogram.factory_stage_duration_seconds = 12.5f64,
            stage = "VALIDATION",
            outcome = "passed",
        );
    });
    let collected = pipeline.collected();
    let duration = only(&collected, name::STAGE_DURATION_SECONDS);
    let spec = METRICS
        .iter()
        .find(|m| m.name == name::STAGE_DURATION_SECONDS)
        .unwrap();
    assert_eq!(duration.unit, "s");
    assert_eq!(duration.points[0].bounds, spec.buckets);
    assert_eq!(duration.points[0].value, 1.0, "one observation");
}

#[test]
fn a_gauge_keeps_the_last_value() {
    let pipeline = Pipeline::new();
    pipeline.run(|| {
        tracing::info!(gauge.factory_queue_depth = 7i64, queue = "ready_stage_runs");
        tracing::info!(gauge.factory_queue_depth = 3i64, queue = "ready_stage_runs");
    });
    let collected = pipeline.collected();
    let depth = only(&collected, name::QUEUE_DEPTH);
    assert_eq!(depth.points.len(), 1);
    assert_eq!(depth.points[0].value, 3.0);
}

#[test]
fn too_many_distinct_label_values_are_folded_into_an_overflow_series() {
    let pipeline = Pipeline::new();
    let spec = METRICS
        .iter()
        .find(|m| m.name == name::RETRIES_TOTAL)
        .unwrap();
    pipeline.run(|| {
        for i in 0..(spec.max_label_sets * 3) {
            let stage = format!("STAGE_{i}");
            tracing::info!(
                                monotonic_counter.factory_retries_total = 1u64,
                stage = %stage,
            );
        }
    });
    let collected = pipeline.collected();
    let retries = only(&collected, name::RETRIES_TOTAL);
    assert!(
        retries.points.len() <= spec.max_label_sets + 1,
        "{} series were exported; the cap is {} plus one overflow series",
        retries.points.len(),
        spec.max_label_sets
    );
    assert!(
        retries
            .points
            .iter()
            .any(|p| p.labels.iter().any(|(k, _)| k == "otel.metric.overflow")),
        "the overflow series is missing"
    );
    let total: f64 = retries.points.iter().map(|p| p.value).sum();
    assert_eq!(
        total,
        (spec.max_label_sets * 3) as f64,
        "no count may be lost"
    );
}

#[test]
fn a_metric_event_never_reaches_the_log_or_the_trace() {
    use factory_observability::guard::AttributeGuard;
    use factory_observability::logging::{self, CorrelationLayer};
    use factory_observability::trace::SpanProcessing;
    use opentelemetry_sdk::trace::InMemorySpanExporter;

    let pipeline = Pipeline::new();
    let spans_out = InMemorySpanExporter::default();
    let tracer_provider = trace::tracer_provider(
        spans_out.clone(),
        AttributeGuard::new(common::policy_scrubber()),
        trace::resource("test", "0.0.0", "test"),
        SpanProcessing::Simple,
    );
    let log = common::Capture::default();
    let subscriber = tracing_subscriber::registry()
        .with(CorrelationLayer::new())
        .with(logging::log_layer(
            log.clone(),
            common::policy_scrubber(),
            tracing_subscriber::EnvFilter::new("trace"),
        ))
        .with(trace::otel_layer(&tracer_provider))
        .with(metrics::metrics_layer(&pipeline.provider));
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("factory.job");
        let _entered = span.enter();
        tracing::info!(
            monotonic_counter.factory_retries_total = 1u64,
            stage = "INTAKE"
        );
        tracing::info!("an ordinary log line");
    });

    let lines = log.lines();
    assert_eq!(
        lines.len(),
        1,
        "only the ordinary line may be logged: {lines:?}"
    );
    assert!(lines[0].contains("an ordinary log line"));

    tracer_provider.force_flush().expect("flush");
    let exported = spans_out.get_finished_spans().expect("spans");
    let events: Vec<&str> = exported[0]
        .events
        .events
        .iter()
        .map(|e| e.name.as_ref())
        .collect();
    assert_eq!(
        events,
        ["an ordinary log line"],
        "the metric became a span event"
    );

    let collected = pipeline.collected();
    assert_eq!(only(&collected, name::RETRIES_TOTAL).points[0].value, 1.0);
}

#[test]
fn label_names_in_code_match_the_constants() {
    assert_eq!(label::STAGE, "stage");
    assert_eq!(label::OUTCOME, "outcome");
    assert_eq!(label::GATE, "gate");
    assert_eq!(label::PROVIDER, "provider");
    assert_eq!(label::QUEUE, "queue");
}
