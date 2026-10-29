//! Start-up of the worker: what the shared composition core does, then what only the worker does.
//!
//! [`boot`] runs [`factory_composition::assemble::prepare`] (policy, image catalog, redactor,
//! secrets, telemetry, both database pools), then starts the model broker listener, which
//! registers the provider keys with the redactor, and last checks that every kind of secret the
//! policy lists has a value ([`Prepared::check_secret_kinds`]), and then assembles the real
//! providers from the configuration. The secret-kind check comes before the providers because the
//! broker's keys are one of the kinds; a provider that cannot be assembled (a missing image
//! catalog, no Spec Kit installation) is a start-up failure and not a first-job failure.

use std::sync::Arc;

use factory_composition::assemble::{Identity, Prepared, prepare};
use factory_composition::config::FactoryConfig;
use factory_composition::indexing::ActiveJobs;
use factory_composition::providers::{ProviderInputs, Providers, assemble, system_runner};
use factory_composition::startup::StartupFailure;
use factory_composition::system::{RandomIds, SystemClock};

use crate::broker_host::{HostedBroker, start as start_broker};

/// The identity the worker reports to telemetry.
pub const IDENTITY: Identity = Identity {
    service: "factory-worker",
    version: env!("CARGO_PKG_VERSION"),
};

/// What [`boot`] built: the shared parts and the hosted broker.
pub struct Booted {
    /// The parts every binary has.
    pub prepared: Prepared,
    /// The hosted broker.
    pub broker: HostedBroker,
    /// The real sandbox, workspace and specification providers.
    pub providers: Providers,
    /// The jobs the loop is working on, which the indexing wrappers of the providers read. Hand
    /// it to `WorkerLoop::with_active_jobs`.
    pub jobs: Arc<ActiveJobs>,
}

/// Runs the start-up checks of the worker and builds the parts that need no credential.
///
/// # Errors
/// The first [`StartupFailure`].
pub async fn boot(config: &FactoryConfig) -> Result<Booted, StartupFailure> {
    let mut prepared = prepare(config, IDENTITY).await?;
    let ids = RandomIds::new().map_err(|error| StartupFailure::Other(error.to_string()))?;
    let broker = start_broker(
        &config.broker,
        &prepared.routing.policy,
        Arc::clone(&prepared.redactor),
        Arc::new(SystemClock),
        Arc::new(ids),
        &mut prepared.secrets,
    )?;
    prepared.check_secret_kinds(config.profile)?;
    let jobs = Arc::new(ActiveJobs::new());
    let providers = assemble(ProviderInputs {
        config,
        policies: &prepared.policies,
        redactor: Arc::clone(&prepared.redactor),
        artifacts: Arc::clone(&prepared.artifacts),
        clock: Arc::new(SystemClock),
        ids: Arc::new(RandomIds::new().map_err(|error| StartupFailure::Other(error.to_string()))?),
        store: prepared.store.clone(),
        jobs: Arc::clone(&jobs),
        runner: system_runner(),
    })
    .map_err(|error| StartupFailure::Other(error.to_string()))?;
    Ok(Booted {
        prepared,
        broker,
        providers,
        jobs,
    })
}
