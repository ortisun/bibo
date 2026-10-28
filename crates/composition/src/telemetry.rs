//! Telemetry set-up for a binary of this package.
//!
//! ADR 0013 asks that every binary builds the redactor from the loaded policy and the registry of
//! secret values and passes it to the telemetry set-up, and that the worker and the API run each
//! stretch of work on a job inside a `factory.job` span.
//!
//! * [`config_for`] passes the real redactor to `TelemetryConfig::new`, which takes the scrubber as
//!   a required argument. Nothing in the workspace can start telemetry without one, so this module
//!   is not the only thing standing between a binary and a missing scrubber.
//! * [`job_stretch`] opens the `factory.job` span with the three required attributes. The span has
//!   **no remote parent** yet: the helper in the observability crate that sets the derived trace
//!   context comes in the next change. The derived `traceparent` is already written into each
//!   outbox event by the engine (`Traceparent::for_job`).

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
    let mut config = TelemetryConfig::new(
        service,
        version,
        Arc::new(RedactorScrubber::new(Arc::clone(redactor))),
    )
    .with_environment(profile.name());
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
