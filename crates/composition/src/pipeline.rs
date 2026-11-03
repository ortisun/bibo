//! The whole pipeline, assembled from the configuration: the thirteen stage handlers, the engine,
//! the approval service, the step before each claim, the protection preflight and the channel the
//! delivery stage reports a changed binding through (AUT-13).
//!
//! Before this module the thirteen handlers were built in one place only, the rig of the full run in
//! `apps/api/tests/full`, and no binary built the delivery stage, the approval stage, the approval
//! service or the preflight (items 35 to 37 of the worker's README). [`assemble_pipeline`] is that
//! construction, moved into the library, so a binary and a test build the pipeline the same way.
//!
//! # What is given and what is built
//!
//! The caller gives the ports this library cannot build: the four that need a credential or a file
//! that does not exist yet (the agent runtime, the model router, the issue source and the change
//! host, in [`ExternalPorts`]), the three seams of the supply chain gates that have no adapter, the
//! capability probes, the source of the administrator's statement about the bypass list, and the
//! providers ([`Providers`]: the sandbox, the workspaces and the specification provider, which
//! [`crate::providers::assemble`] builds for a deployment). A fake may be one of them only where
//! the profile says so: this library may not link the testkit (DEP-03), so a stand-in is always
//! something the caller built.
//!
//! Everything else is built here: the seams over the store, the authority, the validators, the
//! registry of agents, the ticker, and the handlers with their configuration
//! ([`StageSettings`](crate::config::StageSettings)).
//!
//! # What it refuses
//!
//! * A port the profile does not accept. [`PortRegistry::check`] runs for every port and lists
//!   every refusal: the production profile accepts no stand-in at all.
//! * A registry that lacks a handler for a stage the engine's scope names
//!   ([`PipelineError::MissingHandlers`]), so a stage forgotten here stops the process at start-up
//!   and not at the first job that reaches it.
//! * A production profile without the commit of the gate definitions.

use std::path::PathBuf;
use std::sync::Arc;

use factory_contracts::registry::FileAgentRegistry;
use factory_domain::ids::TenantId;
use factory_domain::redaction::Redactor;
use factory_domain::values::{GitSha, Slug};
use factory_domain::vocabulary::StageKind;
use factory_ports::agent::{AgentRuntime, ModelBroker, ModelRouter};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::{AppId, ChangeHost, IssueSource};
use factory_ports::paths::{RepoGlob, RepoPath};
use factory_ports::store::Store;
use factory_sandbox::container::images::ImageCatalog;
use factory_workflow::engine::{Engine, EngineConfig, EngineDeps};
use factory_workflow::gates::supply_chain::approval::RecordedApprovals;
use factory_workflow::gates::supply_chain::ledger::LedgerApprovals;
use factory_workflow::handlers::{HandlerRegistry, StageHandler};
use factory_workflow::stages::approval::{
    ApprovalConfig, ApprovalDeps, ApprovalHandler, ApprovalHandlerDeps, ApprovalService,
};
use factory_workflow::stages::architecture::{ArchitectureConfig, ArchitectureDeps};
use factory_workflow::stages::delivery::{
    DeliveryConfig, DeliveryDeps, DeliveryHandler, DesignRecheck,
};
use factory_workflow::stages::documentation_review::{
    DocsToolchain, DocumentationReviewConfig, DocumentationReviewDeps, DocumentationReviewHandler,
};
use factory_workflow::stages::documenting::{DocumentingConfig, DocumentingDeps};
use factory_workflow::stages::domain_discovery::DomainDiscoveryHandler;
use factory_workflow::stages::implementation::{
    CommitIdentity, ImplementationConfig, ImplementationDeps, ImplementationHandler, StageBudget,
};
use factory_workflow::stages::intake::judge::DesignJudge;
use factory_workflow::stages::intake::seams::CapabilityProbes;
use factory_workflow::stages::intake::{IntakeConfig, IntakeDeps, IntakeHandler};
use factory_workflow::stages::planning::{PlanningConfig, PlanningDeps, PlanningHandler};
use factory_workflow::stages::repo_intel::{RepoIntelConfig, RepoIntelDeps, RepoIntelHandler};
use factory_workflow::stages::review::{ReviewConfig, ReviewDeps, ReviewHandler};
use factory_workflow::stages::specification::{
    SpecificationConfig, SpecificationDeps, SpecificationHandler,
};
use factory_workflow::stages::validation::{
    Bounds, SupplyChainSeams, SupplyChainSettings, ValidationConfig, ValidationHandler,
};

use crate::authority::StoreAuthority;
use crate::config::StageSettings;
use crate::decision_signing::DecisionKeys;
use crate::decisions::{
    AllowlistAuthority, AuditMarkers, ClaimWork, ClaimWorkDeps, DECISIONS_PER_PASS, DecisionMarkers,
};
use crate::delivery::{StoreApprovalSources, StoreDeliverySources};
use crate::dependency_decisions::{DependencyDecisions, DependencyDecisionsDeps};
use crate::drift::{ChannelDrift, DriftPump, channel as drift_channel};
use crate::hooks::BeforeClaim;
use crate::intake_rejections::{IntakeRejections, IntakeRejectionsDeps};
use crate::preflight::{BypassAttestations, PreflightDeps, ProtectionPreflight};
use crate::profile::Profile;
use crate::providers::Providers;
use crate::redaction::RegisteringBroker;
use crate::registry::{PortRegistry, RegistryRefused, SeamsBuilder, SeamsIncomplete};
use crate::repository_changes::{ChangeAuthority, RepositoryChanges, RepositoryChangesDeps};
use crate::sandbox_specs::PolicySpecs;
use crate::seams::{
    FileAllowlist, RefreshRequests, SchemaChecker, StoreRepositories, StoreRequests, YamlManifests,
};
use crate::startup::LoadedPolicies;
use crate::supply_chain::{CurrentApprovals, Standing, SupplyChainSources};
use crate::system::TokioTicker;

/// Why the pipeline cannot be assembled.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    /// The profile refuses a port.
    #[error(transparent)]
    Refused(#[from] RegistryRefused),
    /// A seam was left out of the registry.
    #[error(transparent)]
    Seams(#[from] SeamsIncomplete),
    /// The registry of handlers lacks a stage the engine's scope names.
    #[error("the registry of handlers lacks {} stage(s): {}", .0.len(), stage_list(.0))]
    MissingHandlers(Vec<StageKind>),
    /// The production profile was given a stand-in for a source of the dependency gates.
    #[error("the production profile refuses a stand-in for: {}", .0.join(", "))]
    StandIn(Vec<&'static str>),
    /// A setting is missing or unusable.
    #[error("{0}")]
    Settings(String),
    /// Something the stages are built from could not be loaded.
    #[error("{0}")]
    Load(String),
}

fn stage_list(stages: &[StageKind]) -> String {
    stages
        .iter()
        .map(|stage| stage.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// What this library cannot build and a binary or a test must give.
#[derive(Clone)]
pub struct ExternalPorts {
    /// Runs the agents.
    pub runtime: Arc<dyn AgentRuntime>,
    /// Chooses the model for a stage.
    pub router: Arc<dyn ModelRouter>,
    /// Reads issues, comments and the protection of a repository.
    pub issues: Arc<dyn IssueSource>,
    /// Pushes branches, opens draft pull requests, posts comments and checks.
    pub changes: Arc<dyn ChangeHost>,
    /// What each runtime can do, probed.
    pub probes: Arc<dyn CapabilityProbes>,
    /// What the registry says about a package and how old the advisory database is. The decisions
    /// people recorded are not here: the pipeline reads them from the ledger itself.
    pub supply_chain: SupplyChainSources,
    /// The administrator's statement that the App is on no bypass list.
    pub attestations: Arc<dyn BypassAttestations>,
    /// The GitHub App the factory's checks are pinned to.
    pub app: AppId,
}

/// Applied to every handler before it is registered.
pub type HandlerDecorator = Box<dyn Fn(Arc<dyn StageHandler>) -> Arc<dyn StageHandler>>;

/// Changes the engine's configuration before the engine is built.
pub type EngineTuning = Box<dyn FnOnce(&mut EngineConfig)>;

/// Something a test needs to do to the assembly and a deployment does not.
#[derive(Default)]
pub struct Tuning {
    /// Applied to every handler before it is registered. A test puts a defective stage in the real
    /// pipeline this way, or traces what a stage returns.
    pub decorate: Option<HandlerDecorator>,
    /// Writes the markers of the hook, instead of the audit markers.
    pub markers: Option<Arc<dyn DecisionMarkers>>,
    /// Changes the engine's configuration (the lease and heartbeat times, say).
    pub engine: Option<EngineTuning>,
}

/// Everything [`assemble_pipeline`] is built from.
pub struct PipelineInputs {
    /// The profile.
    pub profile: Profile,
    /// The settings of the stages.
    pub settings: StageSettings,
    /// The checkout that holds `agents/`, `profiles/` and the schemas.
    pub definitions_root: PathBuf,
    /// The loaded policies.
    pub policies: LoadedPolicies,
    /// The one redactor of the process.
    pub redactor: Arc<Redactor>,
    /// The store.
    pub store: Arc<dyn Store>,
    /// Where blobs live.
    pub artifacts: Arc<dyn ArtifactStore>,
    /// Time.
    pub clock: Arc<dyn Clock>,
    /// Identifiers.
    pub ids: Arc<dyn IdGenerator>,
    /// The sandbox, the workspaces, the specification provider and the process runner.
    pub providers: Providers,
    /// The sandbox images, for the platform of the host.
    pub catalog: ImageCatalog,
    /// Where the sandbox specs keep their files.
    pub sandbox_scratch: PathBuf,
    /// The model broker the engine issues job tokens through.
    pub broker: Arc<dyn ModelBroker>,
    /// The ports this library cannot build.
    pub external: ExternalPorts,
    /// The allowlist file of the protected checkout.
    pub allowlist: Arc<FileAllowlist>,
    /// The tenants this process serves.
    pub tenants: Vec<TenantId>,
    /// The keys the hook verifies decision requests with.
    pub decision_keys: Arc<DecisionKeys>,
    /// What only a test changes.
    pub tuning: Tuning,
}

/// The assembled pipeline.
pub struct Pipeline {
    /// The engine.
    pub engine: Arc<Engine>,
    /// Every port, as the profile checked it.
    pub ports: PortRegistry,
    /// The stage and the fidelity of each registered handler.
    pub handlers: Vec<(StageKind, factory_domain::vocabulary::Fidelity)>,
    /// Applies the decisions of people and admits received jobs.
    pub hook: Arc<ClaimWork>,
    /// Records the protection preflight of each repository that waits.
    pub preflight: Arc<ProtectionPreflight>,
    /// Fills the request cache the contracts of stages are resolved from.
    pub requests: Arc<StoreRequests>,
    /// Serves the evidence-drift requests of the delivery and approval stages.
    pub drift: Arc<DriftPump>,
    /// Applies approvals, rejections and rework.
    pub approval_service: Arc<ApprovalService>,
    /// The delivery sources, which read the job's object store.
    pub delivery: Arc<StoreDeliverySources>,
    /// The approval sources.
    pub approvals: Arc<StoreApprovalSources>,
    /// The drafts of specifications, for the hook.
    pub spec_drafts: Arc<crate::specs::StoreSpecDrafts>,
    /// The steps before each claim, in the order a loop runs them: the request cache, the
    /// preflight, the hook.
    pub before_claim: Vec<Arc<dyn BeforeClaim>>,
    /// The decisions people recorded about new dependencies, read from the ledger by tenant and
    /// job. This is the very value the validation stage's supply chain gate reads.
    pub dependency_approvals: Arc<dyn RecordedApprovals>,
    /// The kind of each source of the dependency gates, for the report of what the run is made of.
    pub supply_chain: Vec<(&'static str, Standing)>,
}

fn slug(text: &str) -> Result<Slug, PipelineError> {
    Slug::parse(text).map_err(|_| PipelineError::Settings(format!("{text:?} is not an agent id")))
}

/// The blocks, as (gate, block code), that the policy says no override may pass.
#[must_use]
pub fn non_overridable_blocks(policies: &LoadedPolicies) -> Vec<(String, String)> {
    policies
        .security
        .gate_integrity
        .non_overridable_blocks
        .iter()
        .map(|block| (block.gate.clone(), block.code.clone()))
        .collect()
}

/// The commit of the gate definitions: the configured one, and for the profiles that are not
/// production a stand-in made from the policy hash, so that a report names something.
fn definition_commit(
    profile: Profile,
    settings: &StageSettings,
    policies: &LoadedPolicies,
) -> Result<GitSha, PipelineError> {
    let text = match (&settings.definition_commit, profile) {
        (Some(text), _) => text.clone(),
        (None, Profile::Production) => {
            return Err(PipelineError::Settings(
                "the production profile needs stages.definition_commit".to_owned(),
            ));
        }
        (None, _) => policies.hash.hex().chars().take(40).collect(),
    };
    GitSha::parse(&text).map_err(|_| {
        PipelineError::Settings("stages.definition_commit is not a commit id".to_owned())
    })
}

/// The stages the handlers cover but the registry lacks. Public so a test can show the check.
#[must_use]
pub fn missing_handlers(
    registered: &[(StageKind, factory_domain::vocabulary::Fidelity)],
    scope: &[StageKind],
) -> Vec<StageKind> {
    scope
        .iter()
        .copied()
        .filter(|kind| !registered.iter().any(|(held, _)| held == kind))
        .collect()
}

/// Assembles the pipeline. See the module notes.
///
/// # Errors
/// [`PipelineError`].
#[allow(clippy::too_many_lines)]
pub fn assemble_pipeline(inputs: PipelineInputs) -> Result<Pipeline, PipelineError> {
    let PipelineInputs {
        profile,
        settings,
        definitions_root,
        policies,
        redactor,
        store,
        artifacts,
        clock,
        ids,
        providers,
        catalog,
        sandbox_scratch,
        broker,
        external,
        allowlist,
        tenants,
        decision_keys,
        tuning,
    } = inputs;
    // A hook that replaces the markers, wraps every handler or changes the engine's configuration
    // is for a test. In the production profile it would let a library caller turn off what the
    // profile checks, so it is refused (RR-29).
    if profile == Profile::Production {
        let used: Vec<&str> = [
            ("decorate", tuning.decorate.is_some()),
            ("markers", tuning.markers.is_some()),
            ("engine", tuning.engine.is_some()),
        ]
        .into_iter()
        .filter_map(|(name, set)| set.then_some(name))
        .collect();
        if !used.is_empty() {
            return Err(PipelineError::Settings(format!(
                "the production profile refuses a tuning of the assembly ({})",
                used.join(", ")
            )));
        }
    }
    let Tuning {
        decorate,
        markers,
        engine: tune_engine,
    } = tuning;
    let commit = definition_commit(profile, &settings, &policies)?;
    let slug_of = |name: &String| slug(name);
    let agents = &settings.agents;

    // ---- the seams over the store --------------------------------------------------------
    let (drift_handle, pump) = drift_channel();
    let drift_handle: Arc<ChannelDrift> = Arc::new(drift_handle);
    let requests = Arc::new(StoreRequests::new(Arc::clone(&store)));
    let checker = Arc::new(SchemaChecker::new(&definitions_root));
    let manifests = Arc::new(YamlManifests::new().map_err(PipelineError::Load)?);
    let repositories = Arc::new(StoreRepositories::new(Arc::clone(&store)));
    let feedback = Arc::new(crate::feedback::StoreFeedback::new(
        Arc::clone(&store),
        Arc::clone(&artifacts),
    ));
    let risk = Arc::new(crate::risk::StoreRisk::new(
        Arc::clone(&store),
        Arc::clone(&artifacts),
    ));
    let spec_drafts = Arc::new(crate::specs::StoreSpecDrafts::new(
        Arc::clone(&store),
        Arc::clone(&artifacts),
    ));
    let spec_approvals = Arc::new(crate::specs::StoreSpecApprovals::new(
        Arc::clone(&store),
        Arc::clone(&artifacts),
    ));
    let spec_history = Arc::new(crate::specs::StoreSpecHistory::new(
        Arc::clone(&store),
        Arc::clone(&artifacts),
    ));
    let ledger = Arc::new(crate::ledger::StoreTaskLedger::new(
        Arc::clone(&store),
        Arc::clone(&clock),
        Arc::clone(&ids),
    ));
    let approval_sources = Arc::new(StoreApprovalSources::new(
        Arc::clone(&store),
        Arc::clone(&artifacts),
        Arc::clone(&allowlist),
    ));

    // ---- the sandbox specs and the validation stage's configuration -----------------------
    let registering = Arc::new(RegisteringBroker::new(
        Arc::clone(&broker),
        Arc::clone(&redactor),
    ));
    let specs = Arc::new(PolicySpecs::new(
        Arc::clone(&policies.security),
        catalog,
        Arc::clone(&registering),
        sandbox_scratch,
    ));
    let path_rules = crate::providers::path_rules(&policies.security);
    let verify = specs
        .verify_sandbox()
        .map_err(|_| PipelineError::Load("the verify sandbox cannot be specified".to_owned()))?;
    let fetch = specs
        .fetch_sandbox()
        .map_err(|_| PipelineError::Load("the fetch sandbox cannot be specified".to_owned()))?;
    // The decisions people recorded are read from the ledger, which only the engine appends to.
    // They are never a value the caller hands in (review B-4): a pipeline assembled over another
    // source would let a list the caller wrote stand for a person's decision.
    let dependency_approvals: Arc<dyn RecordedApprovals> = Arc::new(CurrentApprovals::new(
        Arc::new(LedgerApprovals::new(
            Arc::clone(&store),
            Arc::clone(&artifacts),
        )),
        Arc::clone(&allowlist),
        Arc::clone(&store),
        Arc::clone(&clock),
    ));
    let validation = Arc::new(ValidationConfig {
        policy: Arc::clone(&policies.engine),
        path_rules: path_rules.clone(),
        holdouts: Vec::new(),
        redactor: Arc::clone(&redactor),
        sandbox: verify.clone(),
        manifest: manifests.clone(),
        flaky_registry: std::collections::BTreeSet::new(),
        bounds: Bounds::default(),
        supply_chain: SupplyChainSeams {
            // The policy's value is the ceiling: the age limit of the advisory database and the
            // rule for when the gates run start from it, and configuration may only lower them.
            settings: SupplyChainSettings::from_policy(
                &policies.engine,
                fetch,
                factory_workflow::gates::supply_chain::licenses::LicensePolicy::owner_approved(),
                factory_workflow::gates::supply_chain::names::PopularNames::bundled()
                    .map_err(|error| PipelineError::Load(error.to_string()))?,
                factory_workflow::gates::supply_chain::run::SbomRule {
                    required: false,
                    tool: factory_workflow::gates::supply_chain::tools::SbomTool::default(),
                },
            ),
            approvals: Arc::clone(&dependency_approvals),
            registry: external.supply_chain.registry(),
            advisory_db: external.supply_chain.advisory_db(),
        },
    });
    let delivery = Arc::new(
        StoreDeliverySources::new(
            Arc::clone(&store),
            Arc::clone(&artifacts),
            Arc::clone(&policies.engine),
            Arc::clone(&clock),
        )
        .with_repository(Arc::clone(&providers.workspaces), validation.clone()),
    );

    // ---- the registry of ports, and what the profile says about it ------------------------
    let authority = Arc::new(StoreAuthority::new(
        Arc::clone(&store),
        Arc::clone(&allowlist),
        Arc::clone(&policies.engine),
        Arc::clone(&clock),
    ));
    let agent_registry = Arc::new(
        FileAgentRegistry::load(&definitions_root)
            .map_err(|error| PipelineError::Load(format!("the agent registry: {error}")))?,
    );
    let validator = Arc::new(
        factory_contracts::validator::SchemaOutputValidator::new()
            .map_err(|error| PipelineError::Load(format!("the schemas: {error}")))?,
    );
    let seams = SeamsBuilder::default()
        .output_check(checker.clone())
        .manifests(manifests.clone())
        .allowlist(allowlist.clone())
        .requests(requests.clone())
        .repositories(repositories.clone())
        .probes(Arc::clone(&external.probes))
        .ledger(ledger.clone())
        .rework(feedback.clone())
        .rounds(feedback.clone())
        .risk(risk.clone())
        .drift(drift_handle.clone())
        .spec_approvals(spec_approvals.clone())
        .spec_drafts(spec_drafts.clone())
        .spec_history(spec_history.clone())
        .delivery(delivery.clone())
        .approvals(approval_sources.clone())
        // The four inputs of the security decisions are seams of the registry like the others
        // (RR-7): the profile refuses a stand-in for each, whatever label it was handed with.
        .package_metadata(external.supply_chain.registry())
        .advisory_database(external.supply_chain.advisory_db())
        .recorded_approvals(Arc::clone(&dependency_approvals))
        .attestations(Arc::clone(&external.attestations))
        .build()?;
    let ports = PortRegistry {
        store: Arc::clone(&store),
        clock: Arc::clone(&clock),
        ids: Arc::clone(&ids),
        artifacts: Arc::clone(&artifacts),
        sandbox: Arc::clone(&providers.sandbox),
        workspaces: Arc::clone(&providers.workspaces),
        runtime: Arc::clone(&external.runtime),
        router: Arc::clone(&external.router),
        agents: agent_registry.clone(),
        validator: validator.clone(),
        broker: registering.clone(),
        specification: Arc::clone(&providers.specification),
        issues: Arc::clone(&external.issues),
        changes: Arc::clone(&external.changes),
        webhooks: None,
        process: Arc::clone(&providers.process),
        ticker: Arc::new(TokioTicker),
        authority: authority.clone(),
        seams,
    };
    // The two sources of the dependency gates carry a label of their own (blocked, stand-in,
    // real), which names them in the report. The profile's check below reads what each one says
    // it is (RR-7), so a stand-in handed over as "real" is refused in production too. Production
    // takes the blocked adapters, which fail closed, and refuses a stand-in.
    if profile == Profile::Production {
        let stand_ins = external.supply_chain.stand_ins();
        if !stand_ins.is_empty() {
            return Err(PipelineError::StandIn(stand_ins));
        }
    }
    ports.check(profile)?;

    // ---- the thirteen handlers ------------------------------------------------------------
    // The sidecar of the job network, by its alias. The placeholder host of the policy does not
    // resolve in a sandbox, so a tool given it could not reach the broker.
    let endpoint = crate::sandbox_specs::broker_endpoint();
    let budget = StageBudget {
        wall_time_seconds: settings.budget.wall_time_seconds,
        max_tokens: settings.budget.max_tokens,
        max_cost_usd: settings.budget.max_cost_usd,
        attempt_timeout_seconds: settings.budget.attempt_timeout_seconds,
        max_attempts: settings.budget.max_attempts,
    };
    let identity = CommitIdentity {
        name: settings.commit_identity.name.clone(),
        email: settings.commit_identity.email.clone(),
    };
    let agent_settings = factory_workflow::stages::architecture::shared::AgentSettings {
        broker: endpoint.clone(),
        max_output_bytes: settings.max_output_bytes,
        path_rules: path_rules.clone(),
    };
    let max_patch = settings.max_patch_bytes;
    let host = Arc::clone(&external.changes);
    let issues = Arc::clone(&external.issues);
    let probes = Arc::clone(&external.probes);

    let mut registry = HandlerRegistry::new();
    let mut registered: Vec<(StageKind, factory_domain::vocabulary::Fidelity)> = Vec::new();
    let mut register = |handler: Arc<dyn StageHandler>| -> Result<(), PipelineError> {
        registered.push((handler.kind(), handler.fidelity()));
        let handler = match &decorate {
            Some(decorate) => decorate(handler),
            None => handler,
        };
        registry
            .register(handler)
            .map_err(|error| PipelineError::Load(format!("a handler: {error:?}")))
    };

    register(Arc::new(IntakeHandler::new(
        IntakeConfig {
            label: settings.label.clone(),
            agent: slug_of(&agents.intake)?,
            rules: factory_workflow::stages::intake::IntakeRules::default(),
            definition_commit: commit.clone(),
            broker: endpoint.clone(),
            max_output_bytes: settings.max_output_bytes,
        },
        IntakeDeps {
            requests: requests.clone(),
            issues: issues.clone(),
            allowlists: allowlist.clone(),
            // The design rule is read from the protected checkout for every attempt, and the
            // comment that answers a person goes out through the same change host as the other
            // replies of the worker.
            design: Arc::new(crate::design_gate::FileDesignGatePolicy::new(
                policies.source.clone(),
            )),
            replies: Arc::new(crate::design_gate::IssueRefusalReplies::new(
                Arc::clone(&host),
                Arc::clone(&ids),
            )),
            policy: Arc::clone(&policies.engine),
            redactor: Arc::clone(&redactor),
            schemas: checker.clone(),
            sandboxes: specs.clone(),
            probes: probes.clone(),
            // The registered row of the job's repository: the design gate judges the person who
            // approved a design by its GitHub id (finding RH-3).
            repositories: repositories.clone(),
        },
    )))?;
    register(Arc::new(RepoIntelHandler::new(
        RepoIntelConfig {
            definition_commit: commit.clone(),
            path_rules: path_rules.clone(),
            default_timeout_seconds: 900,
            max_file_bytes: 64 * 1024,
            max_paths: 5000,
        },
        RepoIntelDeps {
            changes: host.clone(),
            repos: repositories.clone(),
            specs: specs.clone(),
            manifests: manifests.clone(),
            policy: Arc::clone(&policies.engine),
            redactor: Arc::clone(&redactor),
        },
    )))?;
    register(Arc::new(SpecificationHandler::new(
        SpecificationConfig {
            writer: slug_of(&agents.specification_writer)?,
            reviewer: slug_of(&agents.specification_reviewer)?,
            definition_commit: commit.clone(),
            broker: endpoint.clone(),
            max_output_bytes: settings.max_output_bytes,
            path_rules: crate::providers::specification_path_rules(&policies.security),
            identity: identity.clone(),
            constitution_path: RepoPath::new(factory_spec_adapter::postcond::CONSTITUTION)
                .map_err(|_| PipelineError::Settings("the constitution path".to_owned()))?,
            probe_globs: factory_spec_adapter::integrity::PROBE_GLOBS
                .iter()
                .map(|glob| {
                    RepoGlob::new(glob)
                        .map_err(|_| PipelineError::Settings("a probe glob".to_owned()))
                })
                .collect::<Result<Vec<_>, _>>()?,
            limits: factory_workflow::gates::spec::Limits::default(),
            max_file_bytes: 1_048_576,
            max_clarification_rounds: usize::try_from(settings.max_clarification_rounds)
                .unwrap_or(usize::MAX),
            human_approval_required: true,
            policy_principal: None,
            budget,
        },
        SpecificationDeps {
            provider: Arc::clone(&providers.specification),
            policy: Arc::clone(&policies.engine),
            redactor: Arc::clone(&redactor),
            profile: Arc::new(
                factory_workflow::gates::spec::profile::ProfileRules::from_policy(
                    &policies.security,
                    "SPECIFICATION",
                )
                .ok_or_else(|| {
                    PipelineError::Load("the specification profile of the policy".to_owned())
                })?,
            ),
            schemas: checker.clone(),
            specs: specs.clone(),
            probes: probes.clone(),
            approvals: spec_approvals.clone(),
            drafts: spec_drafts.clone(),
            history: spec_history.clone(),
            rework: feedback.clone(),
        },
    )))?;
    register(Arc::new(DomainDiscoveryHandler::new()))?;
    register(Arc::new(
        factory_workflow::stages::architecture::ArchitectureHandler::new(
            ArchitectureConfig {
                agent: slug_of(&agents.architect)?,
                critic: slug_of(&agents.critic)?,
                definition_commit: commit.clone(),
                settings: agent_settings.clone(),
                rules: factory_workflow::stages::architecture::checks::Rules::default(),
                budget,
            },
            ArchitectureDeps {
                policy: Arc::clone(&policies.engine),
                redactor: Arc::clone(&redactor),
                schemas: checker.clone(),
                specs: specs.clone(),
                probes: probes.clone(),
                risk: risk.clone(),
                rounds: feedback.clone(),
            },
        ),
    ))?;
    register(Arc::new(PlanningHandler::new(
        PlanningConfig {
            agent: slug_of(&agents.planner)?,
            definition_commit: commit.clone(),
            settings: agent_settings.clone(),
            limits: factory_workflow::gates::dag::Limits::default(),
            budget,
        },
        PlanningDeps {
            policy: Arc::clone(&policies.engine),
            redactor: Arc::clone(&redactor),
            schemas: checker.clone(),
            specs: specs.clone(),
            probes: probes.clone(),
            rounds: feedback.clone(),
        },
    )))?;
    register(Arc::new(ImplementationHandler::new(
        ImplementationConfig {
            agent: slug_of(&agents.builder)?,
            agent_version: "1.0.0".to_owned(),
            definition_commit: commit.clone(),
            broker: endpoint.clone(),
            max_output_bytes: settings.max_output_bytes,
            path_rules: path_rules.clone(),
            identity: identity.clone(),
            max_patch_bytes: max_patch,
            budget,
        },
        ImplementationDeps {
            policy: Arc::clone(&policies.engine),
            redactor: Arc::clone(&redactor),
            schemas: checker.clone(),
            specs: specs.clone(),
            probes: probes.clone(),
            ledger: ledger.clone(),
            rework: feedback.clone(),
        },
    )))?;
    register(Arc::new(ValidationHandler::new(validation.clone())))?;
    register(Arc::new(ReviewHandler::new(
        ReviewConfig {
            agent: slug_of(&agents.reviewer)?,
            agent_version: "1.0.0".to_owned(),
            definition_commit: commit.clone(),
            broker: endpoint.clone(),
            max_output_bytes: settings.max_output_bytes,
            path_rules: path_rules.clone(),
            max_patch_bytes: max_patch,
            budget,
        },
        ReviewDeps {
            policy: Arc::clone(&policies.engine),
            redactor: Arc::clone(&redactor),
            schemas: checker.clone(),
            specs: specs.clone(),
            probes: probes.clone(),
        },
    )))?;
    register(Arc::new(
        factory_workflow::stages::documenting::DocumentingHandler::new(
            DocumentingConfig {
                agent: slug_of(&agents.documentation_writer)?,
                agent_version: "1.0.0".to_owned(),
                definition_commit: commit.clone(),
                broker: endpoint.clone(),
                max_output_bytes: settings.max_output_bytes,
                path_rules: path_rules.clone(),
                identity: identity.clone(),
                max_patch_bytes: max_patch,
                budget,
            },
            DocumentingDeps {
                policy: Arc::clone(&policies.engine),
                redactor: Arc::clone(&redactor),
                schemas: checker.clone(),
                specs: specs.clone(),
                probes: probes.clone(),
                rework: feedback.clone(),
            },
        ),
    ))?;
    register(Arc::new(DocumentationReviewHandler::new(
        DocumentationReviewConfig {
            agent: slug_of(&agents.documentation_reviewer)?,
            agent_version: "1.0.0".to_owned(),
            definition_commit: commit.clone(),
            broker: endpoint.clone(),
            max_output_bytes: settings.max_output_bytes,
            path_rules: path_rules.clone(),
            max_patch_bytes: max_patch,
            budget,
            verify: verify.clone(),
            toolchain: DocsToolchain {
                build: settings.documentation.build.clone(),
                binary: crate::sandbox_specs::built_program(&settings.documentation.binary),
                diagrams: None,
                command_timeout_seconds: settings.documentation.command_timeout_seconds,
                max_output_bytes: settings.documentation.max_output_bytes,
            },
        },
        DocumentationReviewDeps {
            policy: Arc::clone(&policies.engine),
            redactor: Arc::clone(&redactor),
            schemas: checker.clone(),
            specs: specs.clone(),
            probes: probes.clone(),
        },
    )))?;
    register(Arc::new(DeliveryHandler::new(
        Arc::new(DeliveryConfig {
            policy: Arc::clone(&policies.engine),
            redactor: Arc::clone(&redactor),
            definition_commit: commit.clone(),
            readability: factory_workflow::gates::readability::ReadabilityGate::new(
                factory_workflow::gates::readability::Options::new(),
            ),
            max_patch_bytes: max_patch,
        }),
        DeliveryDeps {
            host: host.clone(),
            sources: delivery.clone(),
            drift: drift_handle.clone(),
            // The design is checked again right before the pull request is opened (DG-8): the
            // same judge as intake, over the same code host, the same rule file (read at every
            // attempt), the same allowlist and the same way of answering a person on the issue.
            recheck: DesignRecheck::new(
                DesignJudge::new(
                    issues.clone(),
                    Arc::new(crate::design_gate::FileDesignGatePolicy::new(
                        policies.source.clone(),
                    )),
                    Arc::clone(&policies.engine),
                    Arc::clone(&redactor),
                    repositories.clone(),
                ),
                allowlist.clone(),
                Arc::new(crate::design_gate::IssueRefusalReplies::new(
                    Arc::clone(&host),
                    Arc::clone(&ids),
                )),
                settings.label.clone(),
            ),
        },
    )))?;
    register(Arc::new(ApprovalHandler::new(
        Arc::new(ApprovalConfig {
            policy: Arc::clone(&policies.engine),
            definition_commit: commit.clone(),
        }),
        ApprovalHandlerDeps {
            host: host.clone(),
            delivery: delivery.clone(),
            approvals: approval_sources.clone(),
            drift: drift_handle.clone(),
        },
    )))?;

    // ---- the engine -----------------------------------------------------------------------
    // The blocks that no override may pass are the policy's (`gate_integrity.non_overridable_blocks`),
    // added to the floor the engine keeps. The engine reads the gate and the code of a block from
    // the event it stored and holds these back, whatever facts a caller hands an override.
    let mut config = EngineConfig::new(profile.execution_mode(), policies.hash.clone())
        .with_non_overridable_blocks(non_overridable_blocks(&policies));
    config.claim_batch = 1;
    if let Some(tune) = tune_engine {
        tune(&mut config);
    }
    let missing = missing_handlers(&registered, &config.scope);
    if !missing.is_empty() {
        return Err(PipelineError::MissingHandlers(missing));
    }
    let engine = Arc::new(
        Engine::new(
            EngineDeps {
                store: Arc::clone(&store),
                clock: Arc::clone(&clock),
                ids: Arc::clone(&ids),
                artifacts: Arc::clone(&artifacts),
                sandbox: Arc::clone(&providers.sandbox),
                workspaces: Arc::clone(&providers.workspaces),
                runtime: Arc::clone(&external.runtime),
                router: Arc::clone(&external.router),
                registry: agent_registry,
                validator,
                broker: registering,
                authority,
                ticker: Arc::new(TokioTicker),
            },
            config,
            registry,
        )
        .map_err(|error| PipelineError::Load(format!("the engine: {error}")))?,
    );

    // ---- the approval service, the hook and the preflight ---------------------------------
    let approval_service = Arc::new(ApprovalService::new(ApprovalDeps {
        engine: Arc::clone(&engine),
        store: Arc::clone(&store),
        host: Arc::clone(&external.changes),
        issues: Arc::clone(&external.issues),
        policy: Arc::clone(&policies.engine),
        policy_hash: policies.hash.clone(),
        delivery: delivery.clone(),
        approvals: approval_sources.clone(),
        clock: Arc::clone(&clock),
        ids: Arc::clone(&ids),
        redactor: Arc::clone(&redactor),
    }));
    let dependency_decisions = Arc::new(DependencyDecisions::new(DependencyDecisionsDeps {
        engine: Arc::clone(&engine),
        store: Arc::clone(&store),
        artifacts: Arc::clone(&artifacts),
        tenants: tenants.clone(),
        policy: Arc::clone(&policies.engine),
        policy_hash: policies.hash.clone(),
        sources: approval_sources.clone(),
        redactor: Arc::clone(&redactor),
        clock: Arc::clone(&clock),
        max_age: std::time::Duration::from_secs(crate::pipeline::APPROVAL_WINDOW_HOURS * 3600),
        keys: Arc::clone(&decision_keys),
    }));
    let stage_decisions = Arc::new(crate::stage_decisions::StageDecisions::new(
        crate::stage_decisions::StageDecisionsDeps {
            engine: Arc::clone(&engine),
            store: Arc::clone(&store),
            artifacts: Arc::clone(&artifacts),
            tenants: tenants.clone(),
            policy: Arc::clone(&policies.engine),
            policy_hash: policies.hash.clone(),
            sources: approval_sources.clone(),
            reprobe: Arc::new(crate::stage_decisions::NoReprobe),
            redactor: Arc::clone(&redactor),
            clock: Arc::clone(&clock),
            max_age: std::time::Duration::from_secs(crate::pipeline::APPROVAL_WINDOW_HOURS * 3600),
            keys: Arc::clone(&decision_keys),
        },
    ));
    // The reply to a label from someone who may not ask goes through the change host with the
    // narrow token of the approval stage, from this process: the API holds no credential.
    let rejections = Arc::new(IntakeRejections::new(IntakeRejectionsDeps {
        store: Arc::clone(&store),
        host: Arc::clone(&external.changes),
        policy_hash: policies.hash.clone(),
        keys: Arc::clone(&decision_keys),
        limits: crate::intake_rejections::ReplyLimits::STANDARD,
    }));
    // The one allowlist authority answers the decisions of people and the requests to change a
    // repository: the same file, read at the moment of each answer, and the same action table.
    let allowlist_authority = Arc::new(AllowlistAuthority::new(
        Arc::clone(&allowlist),
        Arc::clone(&policies.approval),
        Arc::clone(&clock),
    ));
    // Register, attest and enable are signed requests that this process applies (REG-2).
    let repository_changes = Arc::new(RepositoryChanges::new(RepositoryChangesDeps {
        store: Arc::clone(&store),
        authority: Arc::clone(&allowlist_authority) as Arc<dyn ChangeAuthority>,
        policy_hash: policies.hash.clone(),
        keys: Arc::clone(&decision_keys),
        clock: Arc::clone(&clock),
        max_age: crate::repository_changes::REQUEST_MAX_AGE,
    }));
    let hook = Arc::new(
        ClaimWork::new(ClaimWorkDeps {
            engine: Arc::clone(&engine),
            store: Arc::clone(&store),
            tenants: tenants.clone(),
            submitter: approval_service.clone(),
            approvals: approval_sources.clone(),
            authority: allowlist_authority,
            markers: markers.unwrap_or_else(|| {
                Arc::new(AuditMarkers::new(
                    Arc::clone(&store),
                    policies.hash.clone(),
                    Arc::clone(&decision_keys),
                ))
            }),
            clock: Arc::clone(&clock),
            max_age: std::time::Duration::from_secs(crate::pipeline::APPROVAL_WINDOW_HOURS * 3600),
            per_pass: DECISIONS_PER_PASS,
            keys: decision_keys,
        })
        .with_specification(spec_drafts.clone())
        .with_dependencies(dependency_decisions)
        .with_stage_decisions(stage_decisions)
        .with_recorded_decisions(Arc::clone(&dependency_approvals))
        .with_rejections(rejections)
        .with_repository_changes(repository_changes),
    );
    let check_names = [
        factory_workflow::stages::delivery::CHECK_VALIDATION,
        factory_workflow::stages::delivery::CHECK_REVIEW,
    ]
    .iter()
    .map(|name| slug(name))
    .collect::<Result<Vec<_>, _>>()?;
    let preflight = Arc::new(ProtectionPreflight::new(PreflightDeps {
        store: Arc::clone(&store),
        source: Arc::clone(&external.issues),
        app: external.app,
        checks: check_names,
        attestations: Arc::clone(&external.attestations),
        tenants: tenants.clone(),
        policy_hash: policies.hash.clone(),
        ids: Arc::clone(&ids),
    }));
    let refresh: Arc<dyn BeforeClaim> =
        Arc::new(RefreshRequests::new(Arc::clone(&requests), tenants));
    let before_claim: Vec<Arc<dyn BeforeClaim>> = vec![
        refresh,
        preflight.clone() as Arc<dyn BeforeClaim>,
        hook.clone() as Arc<dyn BeforeClaim>,
    ];
    Ok(Pipeline {
        engine,
        ports,
        handlers: registered,
        hook,
        preflight,
        requests,
        drift: Arc::new(pump),
        approval_service,
        delivery,
        approvals: approval_sources,
        spec_drafts,
        before_claim,
        dependency_approvals,
        supply_chain: external.supply_chain.standings(),
    })
}

/// The hours a request for a decision counts for (`approval_binding.expires_after_hours`).
pub const APPROVAL_WINDOW_HOURS: u64 = 72;
