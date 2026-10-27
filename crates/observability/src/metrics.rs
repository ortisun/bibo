//! The metrics the factory exposes, and the guarantees about their names and labels.
//!
//! Metrics are recorded with plain `tracing` events, so that crates which may only depend on
//! `tracing` can record them. An event with a field whose name starts with `monotonic_counter.`,
//! `counter.`, `gauge.` or `histogram.` updates the instrument of that name. Every other field of
//! the event becomes a label:
//!
//! ```text
//! tracing::info!(monotonic_counter.factory_retries_total = 1u64, stage = "INTAKE");
//! ```
//!
//! Record counts as `u64` or `i64`, gauges as `i64` and durations and money as `f64`. Do not add
//! a `target:` argument: with one, the `tracing` macros cannot parse a dotted field name.
//! [`is_metric_event`] recognises these events by their field names, and the log and span layers
//! skip them, so a metric never shows up as a log line or a span event.
//!
//! The pipeline does not trust the call site. A view attached to the meter provider
//! ([`view`]) checks every instrument against [`METRICS`]:
//!
//! * A name that is not in the table is dropped. So is a name used with the wrong kind of
//!   instrument.
//! * The unit, the description and, for a histogram, the buckets come from the table.
//! * Only the labels the table lists for that metric are kept. A job identifier, a correlation
//!   id or any other unlisted field is removed before aggregation, so it can never multiply the
//!   number of series.
//! * The number of distinct label sets is capped. Past the cap, new sets are folded into one
//!   overflow series and no count is lost.

use opentelemetry::Key;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::{
    Aggregation, Instrument, InstrumentKind, PeriodicReader, SdkMeterProvider, Stream,
};
use std::time::Duration;
use tracing::Subscriber;
use tracing_opentelemetry::MetricsLayer;
use tracing_subscriber::layer::Layer;
use tracing_subscriber::registry::LookupSpan;

/// The prefixes that mark a field as a metric value. They are the ones `tracing-opentelemetry`
/// looks for.
const METRIC_FIELD_PREFIXES: &[&str] = &["monotonic_counter.", "counter.", "gauge.", "histogram."];

/// Whether an event is a metric update, judged by the names of its fields. The log layer and the
/// span layer use this to skip such events.
pub fn is_metric_event(metadata: &tracing::Metadata<'_>) -> bool {
    metadata.is_event()
        && metadata.fields().iter().any(|field| {
            METRIC_FIELD_PREFIXES
                .iter()
                .any(|prefix| field.name().starts_with(prefix))
        })
}

/// Metric names.
pub mod name {
    pub const QUEUE_DEPTH: &str = "factory_queue_depth";
    pub const STAGE_DURATION_SECONDS: &str = "factory_stage_duration_seconds";
    pub const STAGE_RUNS_TOTAL: &str = "factory_stage_runs_total";
    pub const GATE_FAILURES_TOTAL: &str = "factory_gate_failures_total";
    pub const RETRIES_TOTAL: &str = "factory_retries_total";
    pub const SPEND_USD_TOTAL: &str = "factory_spend_usd_total";
}

/// Label names. A label is a single lower case word.
pub mod label {
    pub const STAGE: &str = "stage";
    pub const OUTCOME: &str = "outcome";
    pub const GATE: &str = "gate";
    pub const PROVIDER: &str = "provider";
    pub const QUEUE: &str = "queue";
}

/// The kind of instrument behind a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    /// The latest value of something that goes up and down.
    Gauge,
    /// A total that only grows.
    Counter,
    /// A distribution of measurements, kept in buckets.
    Histogram,
}

impl MetricKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MetricKind::Gauge => "gauge",
            MetricKind::Counter => "counter",
            MetricKind::Histogram => "histogram",
        }
    }
}

/// A label and the most values it may take.
#[derive(Debug, Clone, Copy)]
pub struct LabelSpec {
    pub name: &'static str,
    /// The size of the closed set the label draws from, with room to grow. Not a count of the
    /// values in use today.
    pub max_values: usize,
    pub meaning: &'static str,
}

/// One metric.
#[derive(Debug, Clone, Copy)]
pub struct MetricSpec {
    pub name: &'static str,
    pub kind: MetricKind,
    /// A UCUM unit such as `s`, or a counted-thing annotation such as `{retry}`.
    pub unit: &'static str,
    pub labels: &'static [&'static str],
    /// The most distinct label sets the metric may hold. Never more than the product of the
    /// label sizes.
    pub max_label_sets: usize,
    /// Upper bounds of the histogram buckets, in the metric's unit. Empty for other kinds.
    pub buckets: &'static [f64],
    pub meaning: &'static str,
}

pub const LABELS: &[LabelSpec] = &[
    LabelSpec {
        name: label::STAGE,
        max_values: 16,
        meaning: "The stage kind, spelled as in the state machine file, such as INTAKE.",
    },
    LabelSpec {
        name: label::OUTCOME,
        max_values: 12,
        meaning: "One of the outcome values on the conventions page.",
    },
    LabelSpec {
        name: label::GATE,
        max_values: 48,
        meaning: "The gate identifier from the gate catalog.",
    },
    LabelSpec {
        name: label::PROVIDER,
        max_values: 8,
        meaning: "The model provider the broker reports, such as anthropic.",
    },
    LabelSpec {
        name: label::QUEUE,
        max_values: 4,
        meaning: "The name of a work queue, such as ready_stage_runs.",
    },
];

/// Bucket bounds for stage durations, in seconds: from a quick deterministic stage to an hour.
const STAGE_DURATION_BUCKETS: &[f64] = &[
    1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1200.0, 1800.0, 3600.0,
];

pub const METRICS: &[MetricSpec] = &[
    MetricSpec {
        name: name::QUEUE_DEPTH,
        kind: MetricKind::Gauge,
        unit: "{stage_run}",
        labels: &[label::QUEUE],
        max_label_sets: 4,
        buckets: &[],
        meaning: "Stage runs that are ready and waiting for a worker, by queue.",
    },
    MetricSpec {
        name: name::STAGE_DURATION_SECONDS,
        kind: MetricKind::Histogram,
        unit: "s",
        labels: &[label::STAGE, label::OUTCOME],
        max_label_sets: 80,
        buckets: STAGE_DURATION_BUCKETS,
        meaning: "Wall-clock time from the start of a stage run to its end, by stage kind and outcome.",
    },
    MetricSpec {
        name: name::STAGE_RUNS_TOTAL,
        kind: MetricKind::Counter,
        unit: "{stage_run}",
        labels: &[label::STAGE, label::OUTCOME],
        max_label_sets: 80,
        buckets: &[],
        meaning: "Stage runs that ended, by stage kind and outcome. The error rate is the share with outcome failed.",
    },
    MetricSpec {
        name: name::GATE_FAILURES_TOTAL,
        kind: MetricKind::Counter,
        unit: "{gate_failure}",
        labels: &[label::GATE, label::OUTCOME],
        max_label_sets: 96,
        buckets: &[],
        meaning: "Gate evaluations that ended failed or blocked, by gate and outcome.",
    },
    MetricSpec {
        name: name::RETRIES_TOTAL,
        kind: MetricKind::Counter,
        unit: "{retry}",
        labels: &[label::STAGE],
        max_label_sets: 16,
        buckets: &[],
        meaning: "Retries scheduled after a retryable attempt failure, by stage kind.",
    },
    MetricSpec {
        name: name::SPEND_USD_TOTAL,
        kind: MetricKind::Counter,
        unit: "{USD}",
        labels: &[label::PROVIDER, label::STAGE],
        max_label_sets: 128,
        buckets: &[],
        meaning: "Model spend in US dollars as metered by the broker, by provider and stage kind.",
    },
];

fn kind_of(instrument: InstrumentKind) -> Option<MetricKind> {
    match instrument {
        InstrumentKind::Counter => Some(MetricKind::Counter),
        InstrumentKind::Gauge => Some(MetricKind::Gauge),
        InstrumentKind::Histogram => Some(MetricKind::Histogram),
        _ => None,
    }
}

/// The view that enforces [`METRICS`]. See the module documentation.
pub fn view(instrument: &Instrument) -> Option<Stream> {
    let known = METRICS
        .iter()
        .find(|spec| spec.name == instrument.name())
        .filter(|spec| kind_of(instrument.kind()) == Some(spec.kind));
    let stream = match known {
        None => Stream::builder().with_aggregation(Aggregation::Drop),
        Some(spec) => {
            let builder = Stream::builder()
                .with_unit(spec.unit)
                .with_description(spec.meaning)
                .with_allowed_attribute_keys(spec.labels.iter().map(|label| Key::new(*label)))
                .with_cardinality_limit(spec.max_label_sets);
            match spec.kind {
                MetricKind::Histogram => {
                    builder.with_aggregation(Aggregation::ExplicitBucketHistogram {
                        boundaries: spec.buckets.to_vec(),
                        record_min_max: false,
                    })
                }
                _ => builder,
            }
        }
    };
    stream.build().ok()
}

/// A meter provider that exports through `exporter` every `interval` and applies [`view`].
pub fn meter_provider<E>(exporter: E, resource: Resource, interval: Duration) -> SdkMeterProvider
where
    E: PushMetricExporter,
{
    let reader = PeriodicReader::builder(exporter)
        .with_interval(interval)
        .build();
    SdkMeterProvider::builder()
        .with_resource(resource)
        .with_reader(reader)
        .with_view(view)
        .build()
}

/// The `tracing` layer that turns metric events into instruments on `provider`.
pub fn metrics_layer<S>(provider: &SdkMeterProvider) -> impl Layer<S> + use<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    MetricsLayer::new(provider.clone())
}
