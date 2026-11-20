//! Start-up of the troubleshooter: the refusals first, then the real parts.
//!
//! It refuses to start, with a line that names the key or the file, when:
//!
//! * the configuration breaks a rule ([`TroubleshooterConfig::check`]): the gateway listens on an
//!   address that is not loopback, the tenant is not a UUID, the issue repository is not
//!   `owner/name`, the sandbox names no gateway upstream;
//! * a secret file is a link, is not a regular file or is readable by group or others (the
//!   observer's password, the store's URL, the VictoriaMetrics token, the Datadog keys, the broker
//!   key, the GitHub App key);
//! * the observer login can write or bypass row-level security, or is not a member of
//!   `factory_observer` (the check of `crates/mcp_postgres`, `Inspector::check_login`);
//! * the store's login is not a member of `factory_app` only, or the database lacks a migration;
//! * a policy, the agent's manifest, its prompt or its schemas do not load.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use factory_composition::broker_host::{CredentialSetting, HostedBroker, start as start_broker};
use factory_composition::external::{claude_runtime_for, github_adapter};
use factory_composition::providers::{DockerInputs, docker_sandbox, system_runner};
use factory_composition::redaction::{FactorySecrets, RegisteringBroker, redactor_from_policy};
use factory_composition::sandbox_specs::PolicySpecs;
use factory_composition::startup::{StartupFailure, load_policy, load_routing};
use factory_composition::system::{RandomIds, SystemClock};
use factory_composition::telemetry;
use factory_contracts::agent_schema::AgentSchemaLoader;
use factory_contracts::policy::{PolicyLoader, ProtectedPolicySource};
use factory_contracts::registry::FileAgentRegistry;
use factory_domain::policy::paths::PathPolicy;
use factory_domain::policy::troubleshooting::TroubleshootingPolicy;
use factory_domain::redaction::Redactor;
use factory_domain::values::{NonEmptyString, Sha256Digest, Slug};
use factory_mcp_gateway::{
    CatalogReport, FactoryRedactor, Gateway, GatewayServer, HttpUpstream, InProcessUpstream,
    UpstreamId, read_secret_file,
};
use factory_mcp_postgres::{ConnectSettings, Inspector, Limits, Password, PostgresMcp};
use factory_ports::agent::{AgentRuntime, ModelSelection, RequestCaps, RuntimeId, TurnAttestation};
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::registry::{AgentRegistry, VersionReq};
use factory_ports::triage_issue::TriageIssueWriter;
use factory_runtime::claude::RUNTIME_NAME;
use factory_sandbox::container::images::ImageCatalog;
use factory_storage::artifact_fs::LocalFsArtifactStore;
use factory_storage::pg::troubleshooting::TroubleshootingStore;
use factory_storage::pg::{DatabaseUrl, PgStore, PgStoreConfig, PoolSettings};

use crate::agent::SandboxAgentRunner;
use crate::config::TroubleshooterConfig;
use crate::probes::HttpHealth;
use crate::troubleshooter::{Parts, PromptKit, Settings, Troubleshooter};

/// The identity reported to telemetry.
pub const SERVICE: &str = "factory-troubleshooter";

/// The operations role of the troubleshooter in `policies/model_routing.yaml`.
pub const ROLE: &str = "troubleshooter";

/// What [`boot`] built.
pub struct Booted {
    /// The troubleshooter.
    pub troubleshooter: Troubleshooter,
    /// The URL of the store's login, for the advisory lock.
    pub lock_url: DatabaseUrl,
    /// The gateway's MCP server.
    pub server: GatewayServer,
    /// The broker listener.
    pub broker: HostedBroker,
    /// What the gateway offers, and what it does not.
    pub catalog: CatalogReport,
    /// The policy's probe period.
    pub probe_period: Duration,
    /// The telemetry pipeline, kept alive while the program runs.
    pub telemetry: Option<factory_observability::telemetry::TelemetryGuard>,
}

fn other(why: impl std::fmt::Display) -> StartupFailure {
    StartupFailure::Other(why.to_string())
}

/// Loads `policies/troubleshooting.yaml` from the protected checkout, checked against the
/// security policy, and its hash.
///
/// # Errors
/// [`StartupFailure::Policy`].
pub fn load_troubleshooting(
    checkout: &Path,
    untrusted: &[&Path],
    security: &factory_domain::policy::SecurityPolicy,
) -> Result<(TroubleshootingPolicy, Sha256Digest), StartupFailure> {
    let source = ProtectedPolicySource::protected_default_branch(checkout, untrusted)?;
    let loaded = PolicyLoader::load_troubleshooting(&source, security)?;
    let hash = Sha256Digest::parse(loaded.hash.as_str()).map_err(other)?;
    Ok((loaded.document, hash))
}

/// Reads the observer's password and checks the login (it must not be able to write).
///
/// # Errors
/// [`StartupFailure`] naming the file or the login's problem.
pub async fn observer_inspector(
    config: &TroubleshooterConfig,
    redactor: &Redactor,
) -> Result<Arc<Inspector>, StartupFailure> {
    let password = read_secret_file(&config.observer.password_file, "observer password")
        .map_err(|error| other(format!("observer.password_file: {error}")))?;
    redactor
        .register("observer_password", password.expose())
        .map_err(|_| {
            other("observer.password_file: the password cannot be registered with the redactor")
        })?;
    let settings = ConnectSettings::new(
        config.observer.host.clone(),
        config.observer.port,
        config.observer.user.clone(),
        config.observer.database.clone(),
    )
    .with_password(Password::new(password.expose().to_owned()));
    let inspector = Arc::new(Inspector::new(
        settings,
        Limits::default(),
        Arc::new(redactor.clone()),
    ));
    inspector
        .check_login()
        .await
        .map_err(|failure| other(format!("observer: will not use this login: {failure}")))?;
    Ok(inspector)
}

/// Builds the gateway over the configured upstreams and connects to them. Datadog and
/// VictoriaMetrics are optional; the PostgreSQL server is in process.
///
/// # Errors
/// [`StartupFailure`] naming the setting or the file.
pub async fn gateway(
    config: &TroubleshooterConfig,
    policy: &TroubleshootingPolicy,
    redactor: &Redactor,
    inspector: Arc<Inspector>,
) -> Result<(Gateway, CatalogReport), StartupFailure> {
    let mut builder = Gateway::builder(policy, Arc::new(FactoryRedactor::new(redactor.clone())))
        .upstream(Arc::new(InProcessUpstream::new(
            UpstreamId::Postgres,
            PostgresMcp::new(inspector),
        )));
    if let Some(vm) = &config.gateway.victoriametrics {
        builder = builder.upstream(Arc::new(
            HttpUpstream::victoriametrics(vm)
                .map_err(|e| other(format!("gateway.victoriametrics: {e}")))?,
        ));
    }
    if let Some(datadog) = &config.gateway.datadog {
        builder = builder.upstream(Arc::new(
            HttpUpstream::datadog(datadog, &policy.upstreams.datadog)
                .map_err(|e| other(format!("gateway.datadog: {e}")))?,
        ));
    }
    let gateway = builder
        .build()
        .map_err(|e| other(format!("gateway: {e}")))?;
    let report = gateway.connect().await;
    Ok((gateway, report))
}

/// Runs every start-up check and builds the troubleshooter.
///
/// # Errors
/// The first [`StartupFailure`].
#[allow(clippy::too_many_lines)]
pub async fn boot(config: &TroubleshooterConfig, dry_run: bool) -> Result<Booted, StartupFailure> {
    config
        .check()
        .map_err(|problems| other(problems.join("; ")))?;
    let tenant = config.tenant().map_err(other)?;
    let issue_repository = config.issue_repository().map_err(other)?;
    let untrusted = [config.sandbox.workspace_root.as_path()];
    let policies = load_policy(&config.protected_checkout, &untrusted)?;
    let routing = load_routing(&config.protected_checkout, &untrusted, &policies.security)?;
    let (policy, policy_hash) =
        load_troubleshooting(&config.protected_checkout, &untrusted, &policies.security)?;
    let role = routing
        .policy
        .operations_role(ROLE)
        .ok_or_else(|| other("policies/model_routing.yaml has no operations role troubleshooter"))?
        .clone();

    let redactor = Arc::new(redactor_from_policy(&policies.security).map_err(other)?);
    let mut secrets = FactorySecrets::new(Arc::clone(&redactor), &policies.security);
    let telemetry_guard = {
        let settings = telemetry::config_for(
            SERVICE,
            env!("CARGO_PKG_VERSION"),
            config.profile,
            &config.telemetry,
            &redactor,
        )
        .map_err(other)?;
        Some(telemetry::init(&settings).map_err(other)?)
    };

    // The read-only database login and the gateway.
    let inspector = observer_inspector(config, &redactor).await?;
    let (gateway, catalog) = gateway(config, &policy, &redactor, inspector).await?;
    let server = gateway
        .serve(config.gateway.listen, &config.gateway.allowed_hosts)
        .await
        .map_err(|e| other(format!("gateway.listen: {e}")))?;

    // The troubleshooter's own rows, on a worker-shaped login.
    let url_text = config
        .store
        .url_file
        .read()
        .map_err(|e| other(format!("store.url_file: {e}")))?;
    secrets
        .register_database_url(url_text.expose())
        .map_err(other)?;
    let url = DatabaseUrl::new(url_text.expose());
    let mut settings = PoolSettings::new(url.clone());
    settings.max_connections = config.store.max_connections.max(1);
    let store = TroubleshootingStore::connect(&settings, tenant)
        .await
        .map_err(|e| StartupFailure::Store(e.to_string()))?;
    let index = Arc::new(
        PgStore::connect(PgStoreConfig::new(settings))
            .await
            .map_err(|e| StartupFailure::Store(e.to_string()))?,
    );
    let artifacts: Arc<dyn factory_ports::artifact::ArtifactStore> = Arc::new(
        LocalFsArtifactStore::open(&config.artifacts.root, config.artifacts.max_bytes, index)
            .map_err(|e| other(format!("artifacts.root: {e}")))?,
    );

    // The broker, the sandbox and Claude Code.
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let ids: Arc<dyn IdGenerator> = Arc::new(RandomIds::new().map_err(other)?);
    let mode = policies.security.credentials.model_providers.mode;
    let broker = start_broker(
        &config.broker,
        CredentialSetting {
            mode,
            profile: config.profile,
        },
        &routing.policy,
        Arc::clone(&redactor),
        Arc::clone(&clock),
        Arc::clone(&ids),
        &mut secrets,
    )?;
    let registering = Arc::new(RegisteringBroker::new(
        Arc::clone(&broker.core) as Arc<dyn factory_ports::agent::ModelBroker>,
        Arc::clone(&redactor),
    ));
    let docker = docker_sandbox(DockerInputs {
        profile: config.profile,
        sandbox: &config.sandbox,
        security: &policies.security,
        runner: system_runner(),
        artifacts: Arc::clone(&artifacts),
        redactor: Arc::clone(&redactor),
        clock: Arc::clone(&clock),
        ids: Arc::clone(&ids),
    })
    .map_err(other)?;
    let catalog_text = std::fs::read_to_string(&config.sandbox.images_catalog)
        .map_err(|_| other("sandbox.images_catalog: cannot be read"))?;
    let images = ImageCatalog::from_json(
        &catalog_text,
        config.sandbox.platform.as_deref().unwrap_or("linux/amd64"),
    )
    .map_err(|e| StartupFailure::Images(e.to_string()))?;
    let specs = Arc::new(PolicySpecs::new(
        Arc::clone(&policies.security),
        images,
        Arc::clone(&registering),
        config.sandbox.workspace_root.join("troubleshooter"),
    ));
    let runtime: Arc<dyn AgentRuntime> = claude_runtime_for(
        config.runtimes.claude_code.as_ref(),
        mode,
        Arc::clone(&artifacts),
        Arc::clone(&redactor),
        Arc::clone(&broker.core) as Arc<dyn TurnAttestation>,
        tenant,
    );

    // The agent's definition.
    let registry = FileAgentRegistry::load(&config.protected_checkout).map_err(other)?;
    let agent_id = Slug::parse(ROLE).map_err(other)?;
    let manifest = registry
        .manifest(&agent_id, &VersionReq::SameMajor(1))
        .map_err(|e| other(format!("agents/troubleshooter: {e}")))?;
    let prompt = registry
        .prompt(&manifest)
        .map_err(|e| other(format!("agents/troubleshooter: {e}")))?;
    let schemas = AgentSchemaLoader::new(&config.protected_checkout)
        .load(&manifest)
        .map_err(other)?;
    let paths = PathPolicy::from_policy(&policies.security)
        .map_err(|_| other("the path policy cannot be built"))?;
    let model = ModelSelection {
        runtime: RuntimeId::new(RUNTIME_NAME).map_err(other)?,
        model: NonEmptyString::parse(&role.start_with).map_err(other)?,
    };
    let max_output_bytes = policies
        .security
        .untrusted_content
        .structured_output
        .max_output_bytes;
    let agent = Arc::new(SandboxAgentRunner {
        broker: registering,
        specs,
        sandbox: Arc::new(docker),
        runtime,
        manifest: manifest.clone(),
        model,
        per_request: Some(RequestCaps {
            max_input_tokens: role.per_request.max_input_tokens,
            max_output_tokens: role.per_request.max_output_tokens,
        }),
        max_output_bytes,
    });

    // GitHub.
    let adapter = github_adapter(
        config.profile,
        &config.github,
        &policies.security,
        Arc::clone(&redactor),
        Arc::clone(&clock),
    )
    .map_err(|(key, why)| other(format!("{key}: {why}")))?;
    let issues: Arc<dyn TriageIssueWriter> =
        Arc::new(adapter.triage_issue_writer(issue_repository.clone()));

    let probe_period = Duration::from_secs(policy.schedule.probe_period_s);
    let parts = Parts {
        policy: Arc::new(policy),
        policy_hash,
        gateway,
        health: Arc::new(HttpHealth),
        store,
        issues,
        agent,
        clock,
        ids,
        redactor,
        kit: PromptKit {
            manifest,
            prompt,
            paths,
            input_schema: schemas.inputs,
            output_schema: schemas.outputs,
        },
        settings: Settings {
            tenant,
            issue_repository,
            dry_run,
            datadog: config.gateway.datadog.is_some(),
            victoriametrics: config.gateway.victoriametrics.is_some(),
            api_base_url: config.api_health_url.clone(),
            health_timeout: Duration::from_secs(config.api_health_timeout_s),
            per_run_micro_usd: role.per_run.max_micro_usd,
            per_day_micro_usd: role.per_day.max_micro_usd,
        },
    };
    let troubleshooter = Troubleshooter::new(parts).map_err(other)?;
    Ok(Booted {
        troubleshooter,
        lock_url: url,
        server,
        broker,
        catalog,
        probe_period,
        telemetry: telemetry_guard,
    })
}
