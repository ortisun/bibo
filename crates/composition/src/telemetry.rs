//! Telemetry set-up for a binary of this package.
//!
//! ADR 0013 asks that every binary builds the redactor from the loaded policy and the registry of
//! secret values and passes it to the telemetry set-up, and that the worker and the API run each
//! stretch of work on a job inside a `factory.job` span.
//!
//! * [`config_for`] passes the real redactor to `TelemetryConfig::new`, which takes the scrubber as
//!   a required argument. Nothing in the workspace can start telemetry without one, so this module
//!   is not the only thing standing between a binary and a missing scrubber.
//! * [`job_stretch`] opens the `factory.job` span with the three required attributes and the remote
//!   parent derived from the job id (`factory_observability::spans::job_stretch_span`). Every
//!   process that works on a job writes into that job's one trace: the API while it handles a
//!   command, the worker while it holds a claim, and any process after a restart. The derived
//!   `traceparent` is also written into each outbox event by the engine (`Traceparent::for_job`).

use std::sync::Arc;

use factory_domain::ids::JobId;
use factory_domain::redaction::Redactor;
use factory_observability::spans::{Job, JobStretch, job_span, job_stretch_span};
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

/// The `factory.job` span for one stretch of work on a job: the worker while it holds a claim, the
/// API while it handles a command on the job. Everything the engine does for the job runs inside
/// it.
///
/// The span's remote parent is derived from the job id, so every stretch of one job, in any
/// process, is in one trace. `job_id` that is not a job id (the API passes `none` for a request
/// that names no job) gives a stretch with no derived parent: there is no job to join.
#[must_use]
pub fn job_stretch(correlation_id: &str, job_id: &str, tenant_id: &str) -> Span {
    match JobId::parse(job_id) {
        Ok(job) => job_stretch_span(&JobStretch {
            correlation_id,
            job,
            tenant_id,
        }),
        Err(_) => job_span(&Job {
            correlation_id,
            job_id,
            tenant_id,
        }),
    }
}
