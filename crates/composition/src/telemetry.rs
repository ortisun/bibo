//! Telemetry set-up for a binary of this package.
//!
//! ADR 0013 asks that every binary builds the redactor from the loaded policy and the registry of
//! secret values and passes it to the telemetry set-up, and that the worker and the API run each
//! stretch of work on a job inside a `factory.job` span.
//!
//! # What is wired, and what is not
//!
//! * [`config_for`] passes the real redactor to `TelemetryConfig::with_scrubber`, through
//!   [`RedactorScrubber`](crate::redaction::RedactorScrubber). The observability crate still
//!   installs `PolicyPatternScrubber` by default and does not make the scrubber a required
//!   argument: work package `s1-telemetry-wiring` (ADR 0013) has not landed. This module is the
//!   only place that builds the configuration, so a binary of this package cannot forget the
//!   scrubber, but a different caller of `TelemetryConfig::new` still could.
//! * [`job_stretch`] opens the `factory.job` span with the three required attributes. The span has
//!   **no remote parent**: ADR 0013 expects a helper in the observability crate that sets the
//!   derived trace context, and none exists (`spans::job_span` only reads the current span, and
//!   setting a remote parent needs `tracing-opentelemetry` and `opentelemetry` as direct
//!   dependencies, which this package does not take without a person's approval). The derived
//!   `traceparent` is already written into each outbox event by the engine
//!   (`Traceparent::for_job`), so the events and the spans share the correlation id and the job
//!   id, which is how a backend joins them until the helper exists.

use std::sync::Arc;

use factory_domain::redaction::Redactor;
use factory_observability::spans::{Job, job_span};
use factory_observability::telemetry::{InitError, TelemetryConfig, TelemetryGuard};
use tracing::Span;

use crate::config::TelemetryConfig as TelemetrySettings;
use crate::profile::Profile;
use crate::redaction::RedactorScrubber;

/// Builds the configuration for a binary, with the real redactor as the scrubber.
///
/// # Errors
/// [`InitError`] when the endpoint or the filter in the settings is not valid.
pub fn config_for(
    service: &str,
    version: &str,
    profile: Profile,
    settings: &TelemetrySettings,
    redactor: &Arc<Redactor>,
) -> Result<TelemetryConfig, InitError> {
    let mut config = TelemetryConfig::new(service, version)
        .with_environment(profile.name())
        .with_scrubber(Arc::new(RedactorScrubber::new(Arc::clone(redactor))));
    if let Some(endpoint) = &settings.otlp_endpoint {
        config = config.with_otlp_endpoint(endpoint)?;
    }
    if let Some(filter) = &settings.log_filter {
        config = config.with_log_filter(filter)?;
    }
    Ok(config)
}

/// Installs the process-wide pipeline. Call once, early, before any work.
///
/// # Errors
/// [`InitError`].
pub fn init(config: &TelemetryConfig) -> Result<TelemetryGuard, InitError> {
    factory_observability::telemetry::init(config)
}

/// The `factory.job` span for one stretch of work on a job: the worker while it holds a claim.
/// Everything the engine does for the job runs inside it.
#[must_use]
pub fn job_stretch(correlation_id: &str, job_id: &str, tenant_id: &str) -> Span {
    job_span(&Job {
        correlation_id,
        job_id,
        tenant_id,
    })
}
