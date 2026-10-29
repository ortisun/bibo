//! The adapters for the outside world, assembled from the configuration.
//!
//! Until this module the worker stopped with `BLOCKED:` lines because nothing built the adapters
//! that already existed in the library crates. [`assemble_external`] builds them from
//! [`FactoryConfig`](crate::config::FactoryConfig), the routing policy and the parts the process
//! holds, and returns the [`ExternalPorts`] the pipeline is assembled from. What it cannot build it
//! names: every item that is missing comes back as a [`BlockedItem`] whose text starts with the
//! **configuration key** that is missing or unusable, so a line reads
//! `BLOCKED: issue source: github.installations: is empty ...` and an operator knows what to write.
//!
//! | Port or seam | Built from |
//! |---|---|
//! | `IssueSource`, `ChangeHost` | `factory-github`: the App id, the private key file, the installations, the API base URL, over the `ureq` transport (rustls), with the permission policy of `policies/security.yaml` |
//! | `BypassAttestations` | `github.bypass_attestations`: the statements an administrator made, as the configuration records them |
//! | `AgentRuntime` | `factory-runtime`: the Claude Code and Codex adapters, one of each for every provider in `broker.upstreams`, bound to a tenant on first use ([`TenantRuntimes`]), behind one dispatcher ([`RuntimeSet`]); the turn attestation is the broker core |
//! | `ModelRouter` | [`PolicyModelRouter`] over the routing policy, offering only the models `broker.upstreams` enables |
//! | `CapabilityProbes` | the probe of each runtime in an `agent` sandbox ([`probe_at_startup`]); `BLOCKED` with the reason when the sandbox cannot be made (the Docker daemon does not answer, the image is not on the host), or a declared list in the local and test profiles |
//! | `RegistryMetadata` | [`CratesIoRegistry`] from `registry` |
//! | `AdvisoryDatabase` | [`FileAdvisoryDatabase`] from `advisory_database.date_file` |
//!
//! # The profile
//!
//! Nothing here builds a fake. The one list a person may write, the capabilities, is labelled fake
//! and only the local and test profiles accept it ([`crate::profile`] refuses it in production, and
//! so does the configuration). The loopback addresses the local and test profiles allow are the
//! configuration's business ([`crate::config::endpoint_problem`]); the adapters take the address
//! they are given and the production profile never gives them a plain one.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{AttemptId, JobId, PrincipalId, TenantId};
use factory_domain::policy::SecurityPolicy;
use factory_domain::redaction::Redactor;
use factory_domain::scope::TenantScope;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_github::{
    ApiBase, AppPolicy, GithubAdapter, GithubConfig as AdapterConfig, GithubParts, RingRs256Signer,
    StaticInstallations, TokioSleeper, UreqTransport,
};
use factory_ports::agent::{
    AgentRuntime, Capability, CapabilityObservation, CostMicroUsd, JobTokenRef, JobTokenRequest,
    ModelBroker, ModelSelection, ProbedCapabilities, RuntimeCapabilities, RuntimeId,
    TurnAttestation,
};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::{AppId, BypassAttestation};
use factory_ports::paths::RepoRef;
use factory_ports::sandbox::{SandboxProvider, TeardownReason};
use factory_ports::store::InstallationId;
use factory_runtime::probe::NeverCancelled;
use factory_runtime::{
    ClaudeCodeConfig, ClaudeCodeRuntime, CodexConfig, CodexRuntime, RunIo, SkillBundle,
};

use crate::advisory::FileAdvisoryDatabase;
use crate::config::{FactoryConfig, GithubConfig, RuntimeToolConfig};
use crate::crates_io::CratesIoRegistry;
use crate::indexing::ActiveJobs;
use crate::pipeline::ExternalPorts;
use crate::preflight::BypassAttestations;
use crate::profile::Profile;
use crate::redaction::RegisteringBroker;
use crate::routing::{PolicyModelRouter, enabled_models};
use crate::runtimes::{RuntimeSet, TenantRuntimes};
use crate::sandbox_specs::PolicySpecs;
use crate::seams::CachedProbes;
use crate::startup::LoadedRouting;
use crate::supply_chain::SupplyChainSources;
use factory_workflow::stages::intake::seams::AgentSandboxSpecs as _;

/// One thing the configuration does not yet supply, or supplies in a way that cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedItem {
    /// The port or seam, in the words of the `BLOCKED:` line (`issue source`, `RegistryMetadata`).
    pub label: &'static str,
    /// The configuration key that is missing or unusable.
    pub key: &'static str,
    /// What is wrong with it, and what to write.
    pub reason: String,
}

impl fmt::Display for BlockedItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}: {}", self.label, self.key, self.reason)
    }
}

/// What the start-up probe of the runtimes came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeReport {
    /// Each runtime was probed in a sandbox.
    Probed(ProbedCapabilities),
    /// A person declared the capabilities (`runtimes.declare_capabilities`, local and test only).
    Declared,
    /// The probe could not run, with the reason.
    Blocked(String),
    /// The probe could not run because of a configuration key, which is named.
    NotConfigured {
        /// The key to write.
        key: &'static str,
        /// What is wrong with it.
        reason: String,
    },
}

/// The names of the runtimes the providers of the configuration give.
#[must_use]
pub fn runtime_ids(config: &FactoryConfig) -> Vec<RuntimeId> {
    let mut found = Vec::new();
    for upstream in &config.broker.upstreams {
        let name = match upstream.provider.as_str() {
            "anthropic" => factory_runtime::claude::RUNTIME_NAME,
            "openai" => factory_runtime::codex::RUNTIME_NAME,
            _ => continue,
        };
        if let Ok(id) = RuntimeId::new(name)
            && !found.contains(&id)
        {
            found.push(id);
        }
    }
    found
}

/// Every capability, as a list a person wrote down. Labelled fake by its caller.
#[must_use]
pub fn declared_capabilities(runtimes: &[RuntimeId]) -> ProbedCapabilities {
    const ALL: [Capability; 8] = [
        Capability::JsonSchemaOutput,
        Capability::StructuredStream,
        Capability::BudgetFlag,
        Capability::SkillInvocation,
        Capability::HeadlessMultiTurn,
        Capability::BaseUrlOverride,
        Capability::CredentialFromFile,
        Capability::PermissionDenialReport,
    ];
    ProbedCapabilities(
        runtimes
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    RuntimeCapabilities {
                        runtime_version: "declared".to_owned(),
                        observations: ALL
                            .iter()
                            .map(|capability| CapabilityObservation {
                                capability: *capability,
                                supported: true,
                                source: "declared in the configuration".to_owned(),
                            })
                            .collect(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>(),
    )
}

// ---------------------------------------------------------------------------------------------
// The administrators' statements
// ---------------------------------------------------------------------------------------------

/// The statements of `github.bypass_attestations`, as the configuration records them. A repository
/// with no entry has no statement, and the preflight caps it at L0.
#[derive(Debug, Clone, Default)]
pub struct ConfigAttestations {
    statements: HashMap<(TenantId, RepoRef), BypassAttestation>,
}

impl ConfigAttestations {
    /// The statements of a GitHub configuration. An entry that does not parse is left out, and
    /// the configuration check has refused it already.
    #[must_use]
    pub fn from_config(github: &GithubConfig) -> Self {
        let mut statements = HashMap::new();
        for entry in &github.bypass_attestations {
            let (Ok(tenant), Ok(principal), Ok(at), Ok(repository)) = (
                entry.tenant.parse::<uuid::Uuid>(),
                entry.principal.parse::<uuid::Uuid>(),
                Timestamp::parse(&entry.recorded_at),
                RepoRef::parse(&entry.repository),
            ) else {
                continue;
            };
            statements.insert(
                (TenantId::from_uuid(tenant), repository),
                BypassAttestation {
                    by: PrincipalId::from_uuid(principal),
                    at,
                },
            );
        }
        Self { statements }
    }

    /// How many statements there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.statements.len()
    }

    /// True when there is none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }
}

#[async_trait]
impl BypassAttestations for ConfigAttestations {
    fn fidelity(&self) -> Fidelity {
        // It repeats what an administrator wrote down and invents nothing; with nothing written it
        // says nothing, which fails closed.
        Fidelity::Real
    }

    async fn attestation(
        &self,
        tenant: TenantId,
        repository: &RepoRef,
    ) -> Option<BypassAttestation> {
        self.statements.get(&(tenant, repository.clone())).cloned()
    }
}

// ---------------------------------------------------------------------------------------------
// GitHub
// ---------------------------------------------------------------------------------------------

/// Builds the GitHub App adapter from the configuration: the key file, the installations, the API
/// address and the permission policy. Nothing is sent until a port method is called.
///
/// # Errors
/// The key and the reason, for the item that cannot be built.
pub fn github_adapter(
    profile: Profile,
    github: &GithubConfig,
    security: &SecurityPolicy,
    redactor: Arc<Redactor>,
    clock: Arc<dyn Clock>,
) -> Result<GithubAdapter, (&'static str, String)> {
    let pem = github
        .key_file
        .read()
        .map_err(|error| ("github.key_file", error.to_string()))?;
    let signer = RingRs256Signer::from_pem(pem.expose()).map_err(|_| {
        (
            "github.key_file",
            "is not an RSA private key in PEM form".to_owned(),
        )
    })?;
    let base = if profile == Profile::Production {
        ApiBase::https(&github.api_base_url)
    } else if github.api_base_url.starts_with("http://") {
        ApiBase::loopback_for_tests(&github.api_base_url)
    } else {
        ApiBase::https(&github.api_base_url)
    }
    .map_err(|error| ("github.api_base_url", error.to_string()))?;
    let mut directory = StaticInstallations::new();
    for installation in &github.installations {
        let tenant = installation
            .tenant
            .parse::<uuid::Uuid>()
            .map(TenantId::from_uuid)
            .map_err(|_| ("github.installations", "a tenant is not a UUID".to_owned()))?;
        let repository = RepoRef::parse(&installation.repository).map_err(|_| {
            (
                "github.installations",
                "a repository is not owner/name".to_owned(),
            )
        })?;
        directory = directory.bind(
            tenant,
            repository,
            InstallationId(installation.installation_id),
        );
    }
    let policy = AppPolicy::from_github_app(&security.credentials.github_app);
    let config = AdapterConfig::new(AppId(github.app_id), base.clone(), policy);
    Ok(GithubAdapter::new(
        config,
        GithubParts {
            transport: Arc::new(UreqTransport::new(base)),
            signer: Arc::new(signer),
            clock,
            redactor,
            directory: Arc::new(directory),
            sleeper: Arc::new(TokioSleeper),
        },
    ))
}

// ---------------------------------------------------------------------------------------------
// The runtimes
// ---------------------------------------------------------------------------------------------

fn claude_config(
    tool: Option<&RuntimeToolConfig>,
    skills: Option<SkillBundle>,
) -> ClaudeCodeConfig {
    let mut config = ClaudeCodeConfig::default();
    if let Some(tool) = tool {
        if let Some(binary) = &tool.binary {
            config.binary.clone_from(binary);
        }
        if !tool.versions.is_empty() {
            config.accepted_versions.clone_from(&tool.versions);
        }
    }
    config.spec_skills = skills;
    config
}

fn codex_config(tool: Option<&RuntimeToolConfig>) -> CodexConfig {
    let mut config = CodexConfig::default();
    if let Some(tool) = tool {
        if let Some(binary) = &tool.binary {
            config.binary.clone_from(binary);
        }
        if !tool.versions.is_empty() {
            config.accepted_versions.clone_from(&tool.versions);
        }
    }
    config
}

/// What the runtimes are built from.
#[derive(Clone)]
pub struct RuntimeParts {
    /// The configuration.
    pub config: Arc<FactoryConfig>,
    /// Where the tools' transcripts and outputs are read from.
    pub artifacts: Arc<dyn ArtifactStore>,
    /// The one redactor.
    pub redactor: Arc<Redactor>,
    /// The broker's own record of the turns of a job token.
    pub attestation: Arc<dyn TurnAttestation>,
    /// The skills the specification stage may see, when the installation can supply them.
    pub spec_skills: Option<SkillBundle>,
}

fn io_for(parts: &RuntimeParts, tenant: TenantId) -> RunIo {
    RunIo::new(
        Arc::clone(&parts.artifacts),
        TenantScope::new(tenant),
        Arc::clone(&parts.redactor),
    )
}

/// The runtimes bound to one tenant, for a probe: they read the output of their own commands as
/// that tenant.
#[must_use]
pub fn runtimes_for_tenant(parts: &RuntimeParts, tenant: TenantId) -> Vec<Arc<dyn AgentRuntime>> {
    let mut runtimes: Vec<Arc<dyn AgentRuntime>> = Vec::new();
    for id in runtime_ids(&parts.config) {
        if id.as_str() == factory_runtime::claude::RUNTIME_NAME {
            runtimes.push(Arc::new(ClaudeCodeRuntime::new(
                claude_config(
                    parts.config.runtimes.claude_code.as_ref(),
                    parts.spec_skills.clone(),
                ),
                io_for(parts, tenant),
                Arc::clone(&parts.attestation),
            )));
        } else {
            runtimes.push(Arc::new(CodexRuntime::new(
                codex_config(parts.config.runtimes.codex.as_ref()),
                io_for(parts, tenant),
                Arc::clone(&parts.attestation),
            )));
        }
    }
    runtimes
}

/// The runtime the engine holds: one dispatcher over the tools of the deployment, each of which
/// serves every tenant ([`TenantRuntimes`]). `None` when no provider is configured.
#[must_use]
pub fn runtime_set(parts: &RuntimeParts, jobs: &Arc<ActiveJobs>) -> Option<Arc<RuntimeSet>> {
    let members: Vec<Arc<dyn AgentRuntime>> = runtime_ids(&parts.config)
        .into_iter()
        .map(|id| {
            let parts = parts.clone();
            let name = id.as_str().to_owned();
            Arc::new(TenantRuntimes::new(
                id,
                Fidelity::Real,
                Arc::clone(jobs),
                Box::new(move |tenant| {
                    let made: Arc<dyn AgentRuntime> =
                        if name == factory_runtime::claude::RUNTIME_NAME {
                            Arc::new(ClaudeCodeRuntime::new(
                                claude_config(
                                    parts.config.runtimes.claude_code.as_ref(),
                                    parts.spec_skills.clone(),
                                ),
                                io_for(&parts, tenant),
                                Arc::clone(&parts.attestation),
                            ))
                        } else {
                            Arc::new(CodexRuntime::new(
                                codex_config(parts.config.runtimes.codex.as_ref()),
                                io_for(&parts, tenant),
                                Arc::clone(&parts.attestation),
                            ))
                        };
                    Some(made)
                }),
            )) as Arc<dyn AgentRuntime>
        })
        .collect();
    RuntimeSet::new(members).map(Arc::new)
}

// ---------------------------------------------------------------------------------------------
// The start-up probe
// ---------------------------------------------------------------------------------------------

/// What the start-up probe needs.
pub struct ProbeInputs<'a> {
    /// The sandbox provider the stages use.
    pub sandbox: Arc<dyn SandboxProvider>,
    /// The sandbox specs.
    pub specs: &'a PolicySpecs,
    /// Issues the one token the `agent` sandbox needs to be made. It never spends.
    pub broker: &'a RegisteringBroker,
    /// The jobs the process works on; the probe notes its own so the output of its commands is
    /// indexed for the tenant.
    pub jobs: &'a ActiveJobs,
    /// The tenant the probe's output belongs to.
    pub tenant: TenantId,
    /// Identifiers.
    pub ids: &'a dyn IdGenerator,
    /// A model of the INTAKE routes, which the probe's token holds.
    pub model: ModelSelection,
    /// The runtimes to probe, bound to `tenant`.
    pub runtimes: Vec<Arc<dyn AgentRuntime>>,
}

/// Probes each runtime in an `agent` sandbox and returns what they support, or why it could not.
///
/// The probe creates one sandbox with a token that has a ceiling of one millionth of a dollar and
/// is revoked at the end; it sends no model request. When the sandbox cannot be made the answer is
/// [`ProbeReport::Blocked`] with the reason, and nothing is guessed: no runtime has a capability
/// that was not read from the tool.
pub async fn probe_at_startup(inputs: ProbeInputs<'_>) -> ProbeReport {
    let ProbeInputs {
        sandbox,
        specs,
        broker,
        jobs,
        tenant,
        ids,
        model,
        runtimes,
    } = inputs;
    if runtimes.is_empty() {
        return ProbeReport::Blocked(
            "no runtime to probe: broker.upstreams lists no provider".to_owned(),
        );
    }
    let job = JobId::from_uuid(ids.new_uuid());
    let attempt = AttemptId::from_uuid(ids.new_uuid());
    jobs.enter(job, tenant);
    jobs.enter_attempt(attempt, tenant);
    let report = probe_inside(
        &sandbox, specs, broker, tenant, job, attempt, model, &runtimes,
    )
    .await;
    jobs.leave_attempt(attempt);
    jobs.leave(job);
    report
}

#[allow(clippy::too_many_arguments)]
async fn probe_inside(
    sandbox: &Arc<dyn SandboxProvider>,
    specs: &PolicySpecs,
    broker: &RegisteringBroker,
    tenant: TenantId,
    job: JobId,
    attempt: AttemptId,
    model: ModelSelection,
    runtimes: &[Arc<dyn AgentRuntime>],
) -> ProbeReport {
    let token = match broker
        .issue(JobTokenRequest {
            tenant,
            job,
            stage: StageKind::Intake,
            cost_ceiling: CostMicroUsd(1),
            allowed_models: vec![model],
            ttl: Duration::from_secs(300),
        })
        .await
    {
        Ok(token) => token,
        Err(error) => {
            return ProbeReport::Blocked(format!(
                "the broker would not issue the token the probe sandbox needs: {error}"
            ));
        }
    };
    let report = match specs.agent_spec(job, attempt, JobTokenRef { id: token.id }) {
        Err(_) => ProbeReport::Blocked(
            "the policy and the image catalog cannot make an agent sandbox spec".to_owned(),
        ),
        Ok(spec) => match sandbox.create_verified(spec, &NeverCancelled).await {
            Err(factory_ports::sandbox::SandboxError::DaemonUnavailable) => ProbeReport::Blocked(
                "the Docker daemon does not answer, so the sandbox the probe runs in cannot be made"
                    .to_owned(),
            ),
            Err(factory_ports::sandbox::SandboxError::ImageUnavailable) => ProbeReport::Blocked(
                "the agent image is not on this host (images are never pulled)".to_owned(),
            ),
            Err(error) => ProbeReport::Blocked(format!("the probe sandbox cannot be made: {error}")),
            Ok(mut session) => {
                let mut found = BTreeMap::new();
                let mut blocked = None;
                for runtime in runtimes {
                    match runtime.probe(&mut *session).await {
                        Ok(capabilities) => {
                            found.insert(runtime.id().clone(), capabilities);
                        }
                        Err(error) => {
                            blocked = Some(format!("{}: {error}", runtime.id().as_str()));
                            break;
                        }
                    }
                }
                let _ = session.stop_and_remove(TeardownReason::Completed).await;
                match blocked {
                    Some(reason) => ProbeReport::Blocked(reason),
                    None => ProbeReport::Probed(ProbedCapabilities(found)),
                }
            }
        },
    };
    let _ = broker.revoke(&token.id).await;
    report
}

// ---------------------------------------------------------------------------------------------
// The assembly
// ---------------------------------------------------------------------------------------------

/// What [`assemble_external`] is built from.
pub struct ExternalInputs<'a> {
    /// The configuration.
    pub config: &'a Arc<FactoryConfig>,
    /// The security policy (the permissions of the App).
    pub security: &'a SecurityPolicy,
    /// The routing policy.
    pub routing: &'a LoadedRouting,
    /// The one redactor.
    pub redactor: Arc<Redactor>,
    /// The clock.
    pub clock: Arc<dyn Clock>,
    /// The artifact store.
    pub artifacts: Arc<dyn ArtifactStore>,
    /// The jobs being worked on.
    pub jobs: Arc<ActiveJobs>,
    /// The broker's record of the turns of a token (the broker core).
    pub attestation: Arc<dyn TurnAttestation>,
    /// The skills of the specification stage, when the installation supplies them.
    pub spec_skills: Option<SkillBundle>,
    /// What the start-up probe came to.
    pub probes: ProbeReport,
}

/// The ports the pipeline is assembled from, and the GitHub adapter they came from, which the
/// worker also needs for the step that revokes the installation tokens of an ended job.
pub struct ExternalWorld {
    /// The ports.
    pub ports: ExternalPorts,
    /// The GitHub adapter behind the issue source and the change host.
    pub github: GithubAdapter,
}

/// Builds the ports the pipeline needs from the outside world.
///
/// # Errors
/// Every item that cannot be built, each with the configuration key it needs. The list is complete:
/// one run shows all of it.
pub fn assemble_external(inputs: ExternalInputs<'_>) -> Result<ExternalWorld, Vec<BlockedItem>> {
    let ExternalInputs {
        config,
        security,
        routing,
        redactor,
        clock,
        artifacts,
        jobs,
        attestation,
        spec_skills,
        probes,
    } = inputs;
    let mut blocked: Vec<BlockedItem> = Vec::new();
    let both_github = |blocked: &mut Vec<BlockedItem>, key: &'static str, reason: String| {
        for label in ["issue source", "change host"] {
            blocked.push(BlockedItem {
                label,
                key,
                reason: reason.clone(),
            });
        }
    };

    // GitHub: the issue source, the change host, the protection facts.
    let mut github_ports = None;
    match &config.github {
        None => both_github(
            &mut blocked,
            "github",
            "is not set; the GitHub App needs github.app_id and github.key_file".to_owned(),
        ),
        Some(github) if github.installations.is_empty() => both_github(
            &mut blocked,
            "github.installations",
            "is empty; the App reaches no repository until an installation is listed for it"
                .to_owned(),
        ),
        Some(github) => match github_adapter(
            config.profile,
            github,
            security,
            Arc::clone(&redactor),
            Arc::clone(&clock),
        ) {
            Ok(adapter) => {
                github_ports = Some((
                    Arc::new(adapter.issue_source())
                        as Arc<dyn factory_ports::githost::IssueSource>,
                    Arc::new(adapter.change_host()) as Arc<dyn factory_ports::githost::ChangeHost>,
                    AppId(github.app_id),
                    Arc::new(ConfigAttestations::from_config(github))
                        as Arc<dyn BypassAttestations>,
                    adapter,
                ));
            }
            Err((key, reason)) => both_github(&mut blocked, key, reason),
        },
    }

    // The router and the runtime need a provider.
    let enabled = if config.broker.upstreams.is_empty() {
        None
    } else {
        match enabled_models(&routing.policy, &config.broker.upstreams) {
            Ok(set) => Some(set),
            Err(error) => {
                blocked.push(BlockedItem {
                    label: "model router",
                    key: "broker.upstreams",
                    reason: error.to_string(),
                });
                None
            }
        }
    };
    let router = match enabled {
        Some(set) => {
            match PolicyModelRouter::new(Arc::clone(&routing.policy)) {
                Ok(router) => Some(Arc::new(router.with_enabled(set))
                    as Arc<dyn factory_ports::agent::ModelRouter>),
                Err(error) => {
                    blocked.push(BlockedItem {
                        label: "model router",
                        key: "policies/model_routing.yaml",
                        reason: error.to_string(),
                    });
                    None
                }
            }
        }
        None => {
            if config.broker.upstreams.is_empty() {
                blocked.push(BlockedItem {
                    label: "model router",
                    key: "broker.upstreams",
                    reason: "lists no provider, so no model of the routing policy is enabled; list anthropic or openai with a key_file".to_owned(),
                });
            }
            None
        }
    };
    let runtime = if config.broker.upstreams.is_empty() {
        blocked.push(BlockedItem {
            label: "agent runtime",
            key: "broker.upstreams",
            reason: "lists no provider, so there is no tool to run; list anthropic or openai with a key_file".to_owned(),
        });
        None
    } else {
        runtime_set(
            &RuntimeParts {
                config: Arc::clone(config),
                artifacts,
                redactor,
                attestation,
                spec_skills,
            },
            &jobs,
        )
        .map(|set| set as Arc<dyn AgentRuntime>)
    };

    // The probes.
    let capability_probes = match probes {
        ProbeReport::Probed(found) => Some(Arc::new(CachedProbes::new(found, Fidelity::Real))),
        ProbeReport::Declared => Some(Arc::new(CachedProbes::new(
            declared_capabilities(&runtime_ids(config)),
            Fidelity::Fake,
        ))),
        ProbeReport::NotConfigured { key, reason } => {
            blocked.push(BlockedItem {
                label: "CapabilityProbes",
                key,
                reason,
            });
            None
        }
        ProbeReport::Blocked(reason) => {
            blocked.push(BlockedItem {
                label: "CapabilityProbes",
                // With no provider there is no runtime to probe, and the key to write is the
                // provider's.
                key: if config.broker.upstreams.is_empty() {
                    "broker.upstreams"
                } else {
                    "runtimes"
                },
                reason,
            });
            None
        }
    };

    // The dependency gates' sources.
    let registry = match &config.registry {
        None => {
            blocked.push(BlockedItem {
                label: "RegistryMetadata",
                key: "registry.base_url",
                reason: "is not set; without it every new direct dependency is unknown and waits for a security approver".to_owned(),
            });
            None
        }
        Some(registry) => match CratesIoRegistry::new(config.profile, registry) {
            Ok(client) => Some(Arc::new(client)
                as Arc<dyn factory_workflow::gates::supply_chain::facts::RegistryMetadata>),
            Err(error) => {
                blocked.push(BlockedItem {
                    label: "RegistryMetadata",
                    key: "registry.base_url",
                    reason: error.to_string(),
                });
                None
            }
        },
    };
    let advisory = match &config.advisory_database {
        None => {
            blocked.push(BlockedItem {
                label: "AdvisoryDatabase",
                key: "advisory_database.date_file",
                reason: "is not set; without a date the advisories gate is blocked".to_owned(),
            });
            None
        }
        Some(advisory) => Some(Arc::new(FileAdvisoryDatabase::new(
            advisory.date_file.clone(),
            Arc::clone(&clock),
        ))
            as Arc<dyn factory_workflow::gates::supply_chain::facts::AdvisoryDatabase>),
    };

    match (
        github_ports,
        router,
        runtime,
        capability_probes,
        registry,
        advisory,
    ) {
        (
            Some((issues, changes, app, attestations, github)),
            Some(router),
            Some(runtime),
            Some(probes),
            Some(registry),
            Some(advisory),
        ) if blocked.is_empty() => Ok(ExternalWorld {
            ports: ExternalPorts {
                runtime,
                router,
                issues,
                changes,
                probes,
                supply_chain: SupplyChainSources::real(registry, advisory),
                attestations,
                app,
            },
            github,
        }),
        _ => Err(blocked),
    }
}
