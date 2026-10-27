//! Starting telemetry for a process.
//!
//! A binary calls [`init`] once, early in `main`, and keeps the returned [`TelemetryGuard`] until
//! it exits. After that, `tracing` spans become OpenTelemetry spans, `tracing` metric events
//! become metrics, and log lines go to standard error as JSON.
//!
//! Export is off unless a collector is configured. With no collector the process still logs, and
//! spans and metric events cost almost nothing.
//!
//! [`build_pipeline`] does the same work without touching process-wide state, which is what the
//! tests use.

use crate::guard::{AttributeGuard, GuardStats};
use crate::logging::{self, CorrelationLayer};
use crate::redact::{PolicyPatternScrubber, Scrub};
use crate::trace::SpanProcessing;
use crate::{metrics, trace};
use opentelemetry_otlp::{MetricExporter, Protocol, SpanExporter, WithExportConfig};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tracing::Dispatch;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::prelude::*;

/// The standard OpenTelemetry variable for the collector address. A base URL, for example
/// `http://localhost:4318`. The signal paths `/v1/traces` and `/v1/metrics` are added here.
pub const ENV_OTLP_ENDPOINT: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";
/// The standard OpenTelemetry switch. `true` turns export off even when an endpoint is set.
pub const ENV_SDK_DISABLED: &str = "OTEL_SDK_DISABLED";
/// Log filter in the `RUST_LOG` syntax. Defaults to `info`.
pub const ENV_LOG: &str = "FACTORY_LOG";
/// The deployment environment named on every span and metric. Defaults to `local`.
pub const ENV_ENVIRONMENT: &str = "FACTORY_ENV";

/// Why telemetry could not be started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitError {
    /// The collector address is unusable. The message never repeats the address, because an
    /// address can carry a credential.
    InvalidEndpoint(String),
    /// The log filter does not parse.
    InvalidLogFilter(String),
    /// An exporter could not be built.
    ExporterBuild(String),
    /// Some other code installed a global `tracing` subscriber first.
    SubscriberAlreadySet,
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InitError::InvalidEndpoint(reason) => write!(f, "invalid collector endpoint: {reason}"),
            InitError::InvalidLogFilter(reason) => write!(f, "invalid log filter: {reason}"),
            InitError::ExporterBuild(reason) => write!(f, "cannot build the exporter: {reason}"),
            InitError::SubscriberAlreadySet => {
                f.write_str("another global tracing subscriber is already installed")
            }
        }
    }
}

impl std::error::Error for InitError {}

/// Why buffered telemetry could not be flushed or shut down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlushError {
    Trace(String),
    Metrics(String),
}

impl fmt::Display for FlushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlushError::Trace(reason) => write!(f, "spans were not exported: {reason}"),
            FlushError::Metrics(reason) => write!(f, "metrics were not exported: {reason}"),
        }
    }
}

impl std::error::Error for FlushError {}

/// Settings for the pipeline. A value of this type is always valid: the endpoint and the log
/// filter are checked when they are set.
#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    service_name: String,
    service_version: String,
    environment: String,
    otlp_endpoint: Option<String>,
    log_filter: String,
    metric_interval: Duration,
    export_timeout: Duration,
}

impl TelemetryConfig {
    /// Settings with no collector, the `info` log level and the `local` environment.
    pub fn new(service_name: &str, service_version: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
            service_version: service_version.to_string(),
            environment: "local".to_string(),
            otlp_endpoint: None,
            log_filter: "info".to_string(),
            metric_interval: Duration::from_secs(15),
            export_timeout: Duration::from_secs(10),
        }
    }

    /// Read the settings from the process environment.
    pub fn from_env(service_name: &str, service_version: &str) -> Result<Self, InitError> {
        Self::from_lookup(service_name, service_version, |key| std::env::var(key).ok())
    }

    /// Read the settings through `lookup`, so a test can supply the variables.
    pub fn from_lookup(
        service_name: &str,
        service_version: &str,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, InitError> {
        let mut config = Self::new(service_name, service_version);
        let disabled =
            lookup(ENV_SDK_DISABLED).is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
        if !disabled
            && let Some(endpoint) = lookup(ENV_OTLP_ENDPOINT).filter(|v| !v.trim().is_empty())
        {
            config = config.with_otlp_endpoint(&endpoint)?;
        }
        if let Some(filter) = lookup(ENV_LOG).filter(|v| !v.trim().is_empty()) {
            config = config.with_log_filter(&filter)?;
        }
        if let Some(environment) = lookup(ENV_ENVIRONMENT).filter(|v| !v.trim().is_empty()) {
            config.environment = environment.trim().to_string();
        }
        Ok(config)
    }

    /// Send telemetry to the collector at `endpoint`, a base URL such as `http://localhost:4318`.
    ///
    /// Only plain `http://` is accepted, because this build has no TLS support. The address must
    /// not carry a user name, a password, a query or a fragment.
    pub fn with_otlp_endpoint(mut self, endpoint: &str) -> Result<Self, InitError> {
        self.otlp_endpoint = Some(validate_endpoint(endpoint)?);
        Ok(self)
    }

    pub fn with_log_filter(mut self, filter: &str) -> Result<Self, InitError> {
        EnvFilter::try_new(filter)
            .map_err(|error| InitError::InvalidLogFilter(error.to_string()))?;
        self.log_filter = filter.trim().to_string();
        Ok(self)
    }

    pub fn with_environment(mut self, environment: &str) -> Self {
        self.environment = environment.to_string();
        self
    }

    pub fn with_metric_interval(mut self, interval: Duration) -> Self {
        self.metric_interval = interval;
        self
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub fn service_version(&self) -> &str {
        &self.service_version
    }

    pub fn environment(&self) -> &str {
        &self.environment
    }

    pub fn otlp_endpoint(&self) -> Option<&str> {
        self.otlp_endpoint.as_deref()
    }

    pub fn log_filter(&self) -> &str {
        &self.log_filter
    }

    pub fn metric_interval(&self) -> Duration {
        self.metric_interval
    }

    /// Where spans are sent, or `None` when export is off.
    pub fn traces_url(&self) -> Option<String> {
        self.otlp_endpoint
            .as_ref()
            .map(|base| format!("{base}/v1/traces"))
    }

    /// Where metrics are sent, or `None` when export is off.
    pub fn metrics_url(&self) -> Option<String> {
        self.otlp_endpoint
            .as_ref()
            .map(|base| format!("{base}/v1/metrics"))
    }
}

fn validate_endpoint(raw: &str) -> Result<String, InitError> {
    let reject = |reason: &str| Err(InitError::InvalidEndpoint(reason.to_string()));
    let trimmed = raw.trim();
    let Some(rest) = trimmed.strip_prefix("http://") else {
        return reject(
            "the address must start with http:// (this build has no TLS support, so https:// is refused)",
        );
    };
    if rest
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '@' | '?' | '#' | '\\'))
    {
        return reject(
            "the address must not contain a user name, a password, a query, a fragment or spaces",
        );
    }
    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty() || host.starts_with(':') {
        return reject("the address has no host");
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

/// A built pipeline: the subscriber, and the providers that have to be flushed and shut down.
pub struct Pipeline {
    dispatch: Dispatch,
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
    stats: Arc<GuardStats>,
}

impl fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pipeline")
            .field("exports_spans", &self.tracer_provider.is_some())
            .field("exports_metrics", &self.meter_provider.is_some())
            .finish()
    }
}

impl Pipeline {
    /// Run `body` with this pipeline as the current subscriber, on this thread only.
    pub fn in_scope<T>(&self, body: impl FnOnce() -> T) -> T {
        tracing::dispatcher::with_default(&self.dispatch, body)
    }

    /// What the guard in front of the exporter has done so far.
    pub fn stats(&self) -> Arc<GuardStats> {
        Arc::clone(&self.stats)
    }

    /// Send everything that is buffered, and wait until it has been sent or has failed.
    pub fn flush(&self) -> Result<(), FlushError> {
        let traces = self.tracer_provider.as_ref().map(|p| {
            p.force_flush()
                .map_err(|e| FlushError::Trace(e.to_string()))
        });
        let metrics = self.meter_provider.as_ref().map(|p| {
            p.force_flush()
                .map_err(|e| FlushError::Metrics(e.to_string()))
        });
        traces.transpose()?;
        metrics.transpose()?;
        Ok(())
    }

    /// Flush and stop the exporters. Nothing is exported afterwards.
    pub fn shutdown(self) -> Result<(), FlushError> {
        let traces = self
            .tracer_provider
            .as_ref()
            .map(|p| p.shutdown().map_err(|e| FlushError::Trace(e.to_string())));
        let metrics = self
            .meter_provider
            .as_ref()
            .map(|p| p.shutdown().map_err(|e| FlushError::Metrics(e.to_string())));
        traces.transpose()?;
        metrics.transpose()?;
        Ok(())
    }
}

/// Build the pipeline without installing it as the process-wide subscriber.
///
/// `log_writer` receives the JSON log lines. With no collector in `config`, nothing is exported.
pub fn build_pipeline<M>(config: &TelemetryConfig, log_writer: M) -> Result<Pipeline, InitError>
where
    M: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let filter = EnvFilter::try_new(config.log_filter())
        .map_err(|error| InitError::InvalidLogFilter(error.to_string()))?;
    let scrubber: Arc<dyn Scrub> = Arc::new(PolicyPatternScrubber::new());
    let guard = AttributeGuard::new(Arc::clone(&scrubber));
    let stats = guard.stats();
    let resource = trace::resource(
        config.service_name(),
        config.service_version(),
        config.environment(),
    );

    let (tracer_provider, meter_provider) = match (config.traces_url(), config.metrics_url()) {
        (Some(traces_url), Some(metrics_url)) => {
            let span_exporter = SpanExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint(traces_url)
                .with_timeout(config.export_timeout)
                .build()
                .map_err(|error| InitError::ExporterBuild(error.to_string()))?;
            let metric_exporter = MetricExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint(metrics_url)
                .with_timeout(config.export_timeout)
                .build()
                .map_err(|error| InitError::ExporterBuild(error.to_string()))?;
            (
                Some(trace::tracer_provider(
                    span_exporter,
                    guard,
                    resource.clone(),
                    SpanProcessing::Batch,
                )),
                Some(metrics::meter_provider(
                    metric_exporter,
                    resource,
                    config.metric_interval(),
                )),
            )
        }
        _ => (None, None),
    };

    let trace_layer = tracer_provider.as_ref().map(trace::otel_layer);
    let metrics_layer = meter_provider.as_ref().map(metrics::metrics_layer);
    let subscriber = tracing_subscriber::registry()
        .with(CorrelationLayer::new())
        .with(logging::log_layer(log_writer, scrubber, filter))
        .with(trace_layer)
        .with(metrics_layer);

    Ok(Pipeline {
        dispatch: Dispatch::new(subscriber),
        tracer_provider,
        meter_provider,
        stats,
    })
}

static INIT_LOCK: Mutex<()> = Mutex::new(());
static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Whether [`init`] has installed the pipeline in this process.
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::SeqCst)
}

/// Keeps the pipeline alive. Dropping the guard that [`init`] returned first flushes buffered
/// telemetry and stops the exporters, so hold it until the process is about to exit.
#[derive(Debug)]
pub struct TelemetryGuard {
    pipeline: Option<Pipeline>,
}

impl TelemetryGuard {
    /// True for the guard of the call that installed the pipeline. Guards of later calls own
    /// nothing and do nothing.
    pub fn owns_pipeline(&self) -> bool {
        self.pipeline.is_some()
    }

    /// Send everything that is buffered. A guard that owns nothing has nothing to send.
    pub fn flush(&self) -> Result<(), FlushError> {
        self.pipeline.as_ref().map_or(Ok(()), Pipeline::flush)
    }

    /// What the guard in front of the exporter has done, for the guard that owns the pipeline.
    pub fn stats(&self) -> Option<Arc<GuardStats>> {
        self.pipeline.as_ref().map(Pipeline::stats)
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(pipeline) = self.pipeline.take() {
            // A failed shutdown cannot be reported from a destructor, and the process is ending.
            let _ = pipeline.shutdown();
        }
    }
}

/// Install the pipeline for this process.
///
/// Safe to call more than once. The first call installs the pipeline and returns the guard that
/// owns it. Every later call, from any thread, changes nothing and returns a guard that owns
/// nothing, even after the first guard has been dropped. A process installs its subscriber only
/// once, so there is no second pipeline to build.
pub fn init(config: &TelemetryConfig) -> Result<TelemetryGuard, InitError> {
    let _serialized = INIT_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    if INITIALIZED.load(Ordering::SeqCst) {
        return Ok(TelemetryGuard { pipeline: None });
    }
    let pipeline = build_pipeline(config, std::io::stderr)?;
    tracing::dispatcher::set_global_default(pipeline.dispatch.clone())
        .map_err(|_| InitError::SubscriberAlreadySet)?;
    INITIALIZED.store(true, Ordering::SeqCst);
    Ok(TelemetryGuard {
        pipeline: Some(pipeline),
    })
}
