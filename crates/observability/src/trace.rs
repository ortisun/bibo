//! Building the trace half of the pipeline: the tracer provider and the `tracing` layer that feeds
//! it.
//!
//! Every exporter, real or in memory, is wrapped in a [`RedactingSpanExporter`], so no path
//! through this module sends an unchecked span anywhere.

use crate::guard::{AttributeGuard, RedactingSpanExporter};
use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{SdkTracer, SdkTracerProvider, SpanExporter};
use tracing::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::Layer;
use tracing_subscriber::registry::LookupSpan;

/// The name of the instrumentation scope on every span this crate produces.
pub const INSTRUMENTATION_SCOPE: &str = "factory-observability";

/// How finished spans reach the exporter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanProcessing {
    /// Export each span as it ends, on the thread that ended it. Tests use this so they can read
    /// the result at once. Do not use it in a service: it makes every span wait for the exporter.
    Simple,
    /// Queue spans and export them in batches from a background thread.
    Batch,
}

/// The resource that describes this process on every exported span and metric.
pub fn resource(service_name: &str, service_version: &str, environment: &str) -> Resource {
    Resource::builder()
        .with_service_name(service_name.to_string())
        .with_attributes([
            KeyValue::new("service.version", service_version.to_string()),
            KeyValue::new("deployment.environment.name", environment.to_string()),
        ])
        .build()
}

/// A tracer provider whose exporter is guarded by `guard`.
pub fn tracer_provider<E>(
    exporter: E,
    guard: AttributeGuard,
    resource: Resource,
    processing: SpanProcessing,
) -> SdkTracerProvider
where
    E: SpanExporter + 'static,
{
    let exporter = RedactingSpanExporter::new(exporter, guard);
    let builder = SdkTracerProvider::builder().with_resource(resource);
    match processing {
        SpanProcessing::Simple => builder.with_simple_exporter(exporter),
        SpanProcessing::Batch => builder.with_batch_exporter(exporter),
    }
    .build()
}

/// The `tracing` layer that turns spans into OpenTelemetry spans.
///
/// It is configured to add nothing of its own: no source location, thread, busy or idle time,
/// level, target or exception fields. Those would be attributes outside the allowlist, and the
/// guard would drop them, so it is cheaper not to create them. Errors still mark the span as
/// failed. Their text does not travel (see [`AttributeGuard`]).
pub fn otel_layer<S>(provider: &SdkTracerProvider) -> impl Layer<S> + use<S>
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    let layer: OpenTelemetryLayer<S, SdkTracer> = tracing_opentelemetry::layer()
        .with_tracer(provider.tracer(INSTRUMENTATION_SCOPE))
        .with_location(false)
        .with_tracked_inactivity(false)
        .with_threads(false)
        .with_level(false)
        .with_target(false)
        .with_error_fields_to_exceptions(false)
        .with_error_records_to_exceptions(false)
        .with_error_events_to_exceptions(false)
        .with_error_events_to_status(true);
    // A metric update is not a span event. The libraries that carry the export are not traced:
    // tracing the exporter's own requests would feed the exporter with its own output.
    layer.with_filter(filter_fn(|metadata| {
        !crate::metrics::is_metric_event(metadata) && !is_export_machinery(metadata.target())
    }))
}

/// Targets of the crates that send telemetry. Spans and events from them stay out of the trace.
const EXPORT_MACHINERY: &[&str] = &[
    "opentelemetry",
    "hyper",
    "hyper_util",
    "reqwest",
    "h2",
    "tower",
    "http",
    "tokio",
];

fn is_export_machinery(target: &str) -> bool {
    EXPORT_MACHINERY.iter().any(|prefix| {
        target
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with("::") || rest.starts_with('_'))
    })
}
