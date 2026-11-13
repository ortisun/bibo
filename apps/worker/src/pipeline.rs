//! The worker's use of the pipeline assembly (AUT-13).
//!
//! [`factory_composition::pipeline::assemble_pipeline`] builds the thirteen handlers, the engine,
//! the approval service, the hook that applies decisions, the protection preflight and the drift
//! channel from the configuration. [`assemble_loop`] gives it what a running worker holds (the
//! pools, the policy, the hosted broker, the real providers, the keys of the decision requests) and
//! puts the result into a [`WorkerLoop`] with the steps before each claim, the active-jobs note and
//! the drift pump, in the order a loop runs them.
//!
//! The ports that reach the outside world (the agent runtime, the model router, the issue source,
//! the change host, the capability probes, the registry and the advisory database date) are built by
//! [`external_ports`] from the configuration, through
//! [`factory_composition::external::assemble_external`]. What the configuration does not supply it
//! names, one line for each, starting with the configuration key; `main` prints the lines as
//! `BLOCKED:` and exits with code 3. With a complete configuration the worker runs the pipeline.

use std::sync::Arc;
use std::time::Duration;

use factory_composition::config::FactoryConfig;
use factory_composition::decision_signing::DecisionKeys;
use factory_composition::external::{
    ExternalInputs, ExternalWorld, ProbeInputs, ProbeReport, RuntimeParts, assemble_external,
    probe_at_startup, runtimes_for_tenant,
};
use factory_composition::hooks::BeforeClaim;
use factory_composition::issue_status::{StatusStep, StatusStepInputs};
use factory_composition::pipeline::{
    ExternalPorts, Pipeline, PipelineError, PipelineInputs, Tuning, assemble_pipeline,
};
use factory_composition::policy_broker::{JobSpend, PolicyBroker};
use factory_composition::profile::PortName;
use factory_composition::redaction::RegisteringBroker;
use factory_composition::routing::{enabled_models, first_selection};
use factory_composition::sandbox_specs::PolicySpecs;
use factory_composition::seams::FileAllowlist;
use factory_composition::spec_skills::bundle_for_writer;
use factory_composition::startup::StartupFailure;
use factory_composition::system::{RandomIds, Shutdown, SystemClock, TokioTicker};
use factory_composition::token_sweep::RevokeEndedJobs;
use factory_domain::vocabulary::StageKind;
use factory_ports::agent::ModelBroker;
use factory_ports::issue_status::IssueStatusWriter;
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

/// The model broker the engine issues job tokens through: the broker core of this process, behind
/// the routing policy. Every request the engine makes is cut to the stage's models, the stage's
/// ceiling and what is left of the job's ceiling before the core sees it.
#[must_use]
pub fn policy_broker(booted: &Booted) -> Arc<dyn ModelBroker> {
    Arc::new(PolicyBroker::new(
        booted.broker.core.clone(),
        Arc::clone(&booted.prepared.routing.policy),
        booted.broker.core.clone() as Arc<dyn JobSpend>,
    ))
}

fn image_catalog(config: &FactoryConfig) -> Result<ImageCatalog, StartupFailure> {
    let text = std::fs::read_to_string(&config.sandbox.images_catalog).map_err(|_| {
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
    ImageCatalog::from_json(&text, platform)
        .map_err(|error| StartupFailure::Images(error.to_string()))
}

/// What the start-up probe of the runtimes comes to: a declaration in the local and test profiles
/// when the configuration says so, otherwise each runtime probed in an `agent` sandbox, and
/// `Blocked` with the reason when that cannot be done.
async fn probe_runtimes(booted: &Booted, config: &Arc<FactoryConfig>) -> ProbeReport {
    if config.runtimes.declare_capabilities {
        return ProbeReport::Declared;
    }
    let prepared = &booted.prepared;
    let Ok(tenants) = config.worker.served_tenants() else {
        return ProbeReport::NotConfigured {
            key: "worker.tenants",
            reason: "holds an entry that is not a UUID".to_owned(),
        };
    };
    let Some(tenant) = tenants.first().copied() else {
        return ProbeReport::NotConfigured {
            key: "worker.tenants",
            reason: "is empty, and the probe reads its output as a tenant; list the tenant this worker serves".to_owned(),
        };
    };
    let Ok(catalog) = image_catalog(config) else {
        return ProbeReport::Blocked("the sandbox image catalog cannot be read".to_owned());
    };
    let Ok(enabled) = enabled_models(&prepared.routing.policy, &config.broker.upstreams) else {
        return ProbeReport::NotConfigured {
            key: "broker.upstreams",
            reason: "enables a model the routing policy does not list".to_owned(),
        };
    };
    let Some(model) = first_selection(&prepared.routing.policy, StageKind::Intake, &enabled) else {
        return ProbeReport::NotConfigured {
            key: "broker.upstreams",
            reason: "enables no model that the routing policy routes to the INTAKE stage"
                .to_owned(),
        };
    };
    let Ok(ids) = RandomIds::new() else {
        return ProbeReport::Blocked("the random source of identifiers is unavailable".to_owned());
    };
    let registering = Arc::new(RegisteringBroker::new(
        policy_broker(booted),
        Arc::clone(&prepared.redactor),
    ));
    let specs = PolicySpecs::new(
        Arc::clone(&prepared.policies.security),
        catalog,
        Arc::clone(&registering),
        config.sandbox.workspace_root.join(".specs"),
    );
    let parts = RuntimeParts {
        config: Arc::clone(config),
        artifacts: Arc::clone(&prepared.artifacts),
        redactor: Arc::clone(&prepared.redactor),
        attestation: booted.broker.core.clone(),
        spec_skills: None,
        mode: prepared.policies.security.credentials.model_providers.mode,
    };
    probe_at_startup(ProbeInputs {
        sandbox: Arc::clone(&booted.providers.sandbox),
        specs: &specs,
        broker: &registering,
        jobs: &booted.jobs,
        tenant,
        ids: &ids,
        model,
        runtimes: runtimes_for_tenant(&parts, tenant),
    })
    .await
}

/// Builds the ports that reach the outside world from the configuration.
///
/// # Errors
/// One line for each item the configuration does not supply or supplies unusably, starting with
/// the port and the configuration key: `issue source: github.installations: is empty ...`.
pub async fn external_ports(
    booted: &Booted,
    config: &Arc<FactoryConfig>,
) -> Result<ExternalWorld, Vec<String>> {
    let probes = probe_runtimes(booted, config).await;
    let prepared = &booted.prepared;
    // The skills the specification writer may see, from the Spec Kit installed in the protected
    // checkout. Without them the stage is unavailable with the real tool, so a checkout that cannot
    // supply them is a BLOCKED line and not a stage that fails on its first job.
    let (spec_skills, skills_blocked) = match bundle_for_writer(
        &config.definitions_root,
        &config.protected_checkout,
        &prepared.policies.security,
        &config.stages.agents.specification_writer,
    ) {
        Ok(bundle) => (Some(bundle), None),
        Err(error) => (
            None,
            Some(format!("agent runtime: protected_checkout: {error}")),
        ),
    };
    let built = assemble_external(ExternalInputs {
        config,
        security: &prepared.policies.security,
        routing: &prepared.routing,
        redactor: Arc::clone(&prepared.redactor),
        clock: Arc::new(SystemClock),
        artifacts: Arc::clone(&prepared.artifacts),
        jobs: Arc::clone(&booted.jobs),
        attestation: booted.broker.core.clone(),
        spec_skills,
        probes,
    });
    match (built, skills_blocked) {
        (Ok(world), None) => Ok(world),
        (Ok(_), Some(line)) => Err(vec![line]),
        (Err(blocked), skills) => Err(blocked
            .iter()
            .map(ToString::to_string)
            .chain(skills)
            .collect()),
    }
}

/// The step before each claim that revokes the GitHub installation tokens of jobs that are over.
#[must_use]
pub fn token_sweep(
    booted: &Booted,
    config: &FactoryConfig,
    world: &ExternalWorld,
) -> Option<Arc<dyn BeforeClaim>> {
    let tenants = config.worker.served_tenants().ok()?;
    let store: Arc<dyn Store> = booted.prepared.store.clone();
    // LB-04: a job that stays BLOCKED gives up its tokens after the bound of the security policy.
    // A job that waits for a person keeps its token.
    let blocked_after = Duration::from_secs(
        booted
            .prepared
            .policies
            .security
            .credentials
            .github_app
            .installation_token
            .revoke_when_blocked_after_s,
    );
    Some(Arc::new(
        RevokeEndedJobs::new(
            world.github.clone(),
            store,
            tenants,
            Arc::clone(&booted.jobs),
        )
        .revoking_blocked_after(blocked_after, Arc::new(SystemClock)),
    ))
}

/// The step before each claim that writes the state of each job on its issue: one
/// `factory: <state>` label and one status comment (ADR 0017). `None` when the configuration turns
/// it off (`github.write_issue_status: false`) or has no `github` table.
///
/// The labels come from `policies/issue-workflow.yaml` in the protected checkout, and the step
/// writes through the status writer of the GitHub adapter, which holds a token of its own. What
/// the step does when GitHub fails is in [`factory_composition::issue_status`]: nothing happens to
/// a job.
///
/// **A policy that cannot be used does not stop the worker.** If `policies/issue-workflow.yaml` is
/// missing or broken, or the approval policy does not allow the write, the step is built in its
/// off state: it writes nothing on any issue, reports itself as degraded with the reason and
/// records the fact in the audit log (finding STS-7). The status is observability, and ADR 0017
/// says a job never waits for, fails on or rolls back because of a label.
///
/// # Errors
/// [`StartupFailure`] when the tenants or the identifiers cannot be made, or the profile refuses
/// the writer. These are faults of the configuration, not of a policy file.
pub fn issue_status(
    booted: &Booted,
    config: &FactoryConfig,
    world: &ExternalWorld,
) -> Result<Option<StatusStep>, StartupFailure> {
    if !config.github.as_ref().is_some_and(|g| g.write_issue_status) {
        return Ok(None);
    }
    let tenants = config
        .worker
        .served_tenants()
        .map_err(|error| StartupFailure::Other(error.to_string()))?;
    let writer: Arc<dyn IssueStatusWriter> = Arc::new(world.github.issue_status_writer());
    config
        .profile
        .admit(PortName::Changes, writer.fidelity())
        .map_err(|refused| StartupFailure::Other(refused.to_string()))?;
    let ids = RandomIds::new().map_err(|error| StartupFailure::Other(error.to_string()))?;
    let store: Arc<dyn Store> = booted.prepared.store.clone();
    Ok(Some(StatusStep::build(StatusStepInputs {
        store,
        writer,
        host: Arc::clone(&world.ports.changes),
        clock: Arc::new(SystemClock),
        ids: Arc::new(ids),
        jobs: Arc::clone(&booted.jobs),
        tenants,
        redactor: Arc::clone(&booted.prepared.redactor),
        approval: Arc::clone(&booted.prepared.policies.approval),
        base_policy_hash: booted.prepared.policies.hash.clone(),
        checkout: config.protected_checkout.clone(),
        untrusted_roots: vec![config.sandbox.workspace_root.clone()],
        web_base_url: config.github.as_ref().map_or_else(
            || "https://github.com".to_owned(),
            |g| g.web_root().to_owned(),
        ),
    })))
}

/// Assembles the pipeline from what the worker holds and the ports it was given, and puts it in a
/// loop. `extra_hooks` run before the steps of the pipeline, before each claim.
///
/// # Errors
/// [`StartupFailure`] when the keys cannot be read, the catalog cannot be loaded, or the pipeline
/// cannot be assembled (a port the profile refuses, a handler missing, a setting unusable).
pub fn assemble_loop(
    booted: &Booted,
    config: &FactoryConfig,
    external: ExternalPorts,
    extra_hooks: Vec<Arc<dyn BeforeClaim>>,
    shutdown: Shutdown,
) -> Result<(WorkerLoop, Pipeline), StartupFailure> {
    let prepared = &booted.prepared;
    let decision_keys = Arc::new(DecisionKeys::load(
        config.profile,
        config.decisions.as_ref(),
        &prepared.redactor,
    )?);
    let catalog = image_catalog(config)?;
    let store: Arc<dyn Store> = prepared.store.clone();
    let broker: Arc<dyn ModelBroker> = policy_broker(booted);
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
    .with_drift_pump(Arc::clone(&pipeline.drift))
    // The hook that applies decisions between attempts also applies a cancel of the running job.
    .with_cancel_watch(pipeline.hook.clone());
    // The tokens of ended jobs are revoked first, so that a job admitted in this pass starts from
    // a clean slate; then the steps of the pipeline run in their own order.
    for hook in extra_hooks {
        worker_loop = worker_loop.with_before_claim(hook);
    }
    for hook in &pipeline.before_claim {
        worker_loop = worker_loop.with_before_claim(Arc::clone(hook));
    }
    Ok((worker_loop, pipeline))
}
