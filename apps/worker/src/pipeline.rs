//! The worker's use of the pipeline assembly (AUT-13).
//!
//! [`factory_composition::pipeline::assemble_pipeline`] builds the thirteen handlers, the engine,
//! the approval service, the hook that applies decisions, the protection preflight and the drift
//! channel from the configuration. [`assemble_loop`] gives it what a running worker holds (the
//! pools, the policy, the hosted broker, the real providers, the keys of the decision requests) and
//! puts the result into a [`WorkerLoop`] with the steps before each claim, the active-jobs note and
//! the drift pump, in the order a loop runs them.
//!
//! What the worker cannot give is [`ExternalPorts`]: the agent runtime, the model router, the issue
//! source and the change host, which need a credential or a file that does not exist yet, the three
//! seams of the dependency gates that no adapter implements, and the probes of what the runtime can
//! do. [`external_ports`] says so for a deployment, and `main` then stops with `BLOCKED` lines as
//! before. The day an adapter exists, `external_ports` returns it and the worker runs the whole
//! pipeline without any other change; a test that supplies stand-ins runs it today.

use std::sync::Arc;

use factory_composition::assemble::{Blocked, blocked_adapters, blocked_pipeline_inputs};
use factory_composition::config::FactoryConfig;
use factory_composition::decision_signing::DecisionKeys;
use factory_composition::pipeline::{
    ExternalPorts, Pipeline, PipelineError, PipelineInputs, Tuning, assemble_pipeline,
};
use factory_composition::seams::FileAllowlist;
use factory_composition::startup::StartupFailure;
use factory_composition::system::{RandomIds, Shutdown, SystemClock, TokioTicker};
use factory_ports::agent::ModelBroker;
use factory_ports::store::{Store, WorkerId};
use factory_sandbox::container::images::ImageCatalog;

use crate::boot::Booted;
use crate::run::WorkerLoop;

/// The platform the sandbox images are chosen for when the configuration names none.
fn host_platform() -> &'static str {
    if std::env::consts::ARCH == "aarch64" {
        "linux/arm64"
    } else {
        "linux/amd64"
    }
}

/// What a deployment can give today: nothing. Every item that is missing is listed, and `main`
/// prints it as a `BLOCKED:` line.
///
/// # Errors
/// The adapters and the seams that are not assembled, with the reason for each.
pub fn external_ports(config: &FactoryConfig) -> Result<ExternalPorts, Vec<String>> {
    let mut missing: Vec<String> = blocked_adapters(config.profile)
        .into_iter()
        .map(|Blocked { port, reason }| format!("{}: {reason}", port.label()))
        .collect();
    missing.extend(
        blocked_pipeline_inputs()
            .into_iter()
            .map(|item| format!("{}: {}", item.seam, item.reason)),
    );
    Err(missing)
}

/// Assembles the pipeline from what the worker holds and the ports it was given, and puts it in a
/// loop.
///
/// # Errors
/// [`StartupFailure`] when the keys cannot be read, the catalog cannot be loaded, or the pipeline
/// cannot be assembled (a port the profile refuses, a handler missing, a setting unusable).
pub fn assemble_loop(
    booted: &Booted,
    config: &FactoryConfig,
    external: ExternalPorts,
    shutdown: Shutdown,
) -> Result<(WorkerLoop, Pipeline), StartupFailure> {
    let prepared = &booted.prepared;
    let decision_keys = Arc::new(DecisionKeys::load(
        config.profile,
        config.decisions.as_ref(),
        &prepared.redactor,
    )?);
    let catalog_text = std::fs::read_to_string(&config.sandbox.images_catalog).map_err(|_| {
        StartupFailure::Images(format!(
            "{} cannot be read",
            config.sandbox.images_catalog.display()
        ))
    })?;
    let platform: &str = config
        .sandbox
        .platform
        .as_deref()
        .unwrap_or_else(|| host_platform());
    let catalog = ImageCatalog::from_json(&catalog_text, platform)
        .map_err(|error| StartupFailure::Images(error.to_string()))?;
    let store: Arc<dyn Store> = prepared.store.clone();
    let broker: Arc<dyn ModelBroker> = booted.broker.core.clone();
    let tenants = config
        .worker
        .served_tenants()
        .map_err(|error| StartupFailure::Other(error.to_string()))?;
    let ids = RandomIds::new().map_err(|error| StartupFailure::Other(error.to_string()))?;
    let pipeline = assemble_pipeline(PipelineInputs {
        profile: config.profile,
        settings: config.stages.clone(),
        definitions_root: config.definitions_root.clone(),
        policies: prepared.policies.clone(),
        redactor: Arc::clone(&prepared.redactor),
        store,
        artifacts: Arc::clone(&prepared.artifacts),
        clock: Arc::new(SystemClock),
        ids: Arc::new(ids),
        providers: booted.providers.clone(),
        catalog,
        sandbox_scratch: config.sandbox.workspace_root.join(".specs"),
        broker,
        external,
        allowlist: Arc::new(FileAllowlist::in_checkout(&config.protected_checkout)),
        tenants,
        decision_keys,
        tuning: Tuning::default(),
    })
    .map_err(|error: PipelineError| StartupFailure::Other(error.to_string()))?;
    let mut worker_loop = WorkerLoop::shared(
        Arc::clone(&pipeline.engine),
        Arc::new(TokioTicker),
        WorkerId::new(&format!(
            "{}-{}",
            config.worker.name_prefix,
            std::process::id()
        ))
        .map_err(|error| StartupFailure::Other(error.to_string()))?,
        config.worker.clone(),
        shutdown,
    )
    .with_active_jobs(Arc::clone(&booted.jobs))
    .with_drift_pump(Arc::clone(&pipeline.drift));
    for hook in &pipeline.before_claim {
        worker_loop = worker_loop.with_before_claim(Arc::clone(hook));
    }
    Ok((worker_loop, pipeline))
}
