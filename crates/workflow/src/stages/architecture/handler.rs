//! `ArchitectureHandler`, the `StageHandler` of the `ARCHITECTURE` stage.
//!
//! `execute` is in [`run`](super::run) and `evaluate` in [`gates`](super::gates). This file holds
//! the handler, what it is configured with, the names of its deliverables and gates, and the stage
//! contract.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::StageContract;
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::policy::PolicyEngine;
use factory_domain::redaction::Redactor;
use factory_domain::values::{GitSha, Slug};
use factory_domain::vocabulary::{Fidelity, RiskTier, StageKind};
use factory_ports::agent::{Capability, RoutingNeed};

use super::checks::Rules;
use super::seams::{
    AgentOutputCheck, CapabilityProbes, RiskSource, RoundSource, WorkspaceAgentSpecs,
};
use super::shared::AgentSettings;
use crate::gates::framework::GateDecision;
use crate::gates::readability::GATE_ID as READABILITY_GATE;
use crate::handlers::{
    ContractContext, GateContext, StageContext, StageError, StageHandler, StageOutput,
};
use crate::stages::implementation::StageBudget;
use crate::stages::implementation::input::{
    REPOSITORY_MAP, SPECIFICATION_CONTRACT, upstream_output,
};
use crate::stages::intake::common::{
    ContractBudget, ContractCriterion, ContractDeliverable, ContractInput, ContractSpec,
    stage_contract,
};
use crate::stages::validation::POLICY_INPUT;

/// The deliverable that holds the architect's design, byte for byte as it passed its schema. The
/// planning stage and the implementation stage read it by this name, which is the constant the
/// implementation stage declares, so the two cannot drift apart.
pub use crate::stages::implementation::input::ARCHITECTURE as DESIGN;
/// The deliverable that records what the stage measured and decided: the risk, the complexity,
/// the critic and what the architect was given.
pub const RECORD: &str = "architecture-record";
/// The deliverable that holds the draft records of the decisions.
pub const ADRS: &str = "adr-drafts";
/// The input that holds the domain profile, when the domain discovery stage produced one.
pub const DOMAIN_PROFILE: &str = "domain-profile";

/// The gate that reports whether every requirement has a design element and the other way round.
pub const TRACEABILITY_GATE: &str = "architecture-traceability";
/// The gate that reports whether the design is the kind a person can approve.
pub const COMPLETENESS_GATE: &str = "architecture-completeness";
/// The gate that reports on the independent critic.
pub const CRITIC_GATE: &str = "architecture-critic";

/// The tools the architect is granted, which are those of its manifest. A test compares the two.
pub const GRANTED_TOOLS: [&str; 4] = ["fs.read", "fs.list", "fs.search", "report.submit"];

/// What the handler is configured with. All of it comes from protected configuration.
#[derive(Debug, Clone)]
pub struct ArchitectureConfig {
    /// The agent that designs.
    pub agent: Slug,
    /// The agent that criticises, for work the policy says needs one. The registry may have none.
    pub critic: Slug,
    /// The commit of the factory's gate definitions, named in every report.
    pub definition_commit: GitSha,
    /// How the agents are run.
    pub settings: AgentSettings,
    /// The numbers of the acceptance gate.
    pub rules: Rules,
    /// The limits of the stage run.
    pub budget: StageBudget,
}

/// The collaborators of the handler, in one place so a composition root names each.
pub struct ArchitectureDeps {
    /// The policy evaluators.
    pub policy: Arc<PolicyEngine>,
    /// The redactor of the job.
    pub redactor: Arc<Redactor>,
    /// The check of an agent's output against its own schema.
    pub schemas: Arc<dyn AgentOutputCheck>,
    /// The sandbox spec factory.
    pub specs: Arc<dyn WorkspaceAgentSpecs>,
    /// The runtime probes.
    pub probes: Arc<dyn CapabilityProbes>,
    /// The risk facts of the job.
    pub risk: Arc<dyn RiskSource>,
    /// The round of rework this run replaces.
    pub rounds: Arc<dyn RoundSource>,
}

/// The `ARCHITECTURE` handler. See the module notes for what it does.
pub struct ArchitectureHandler {
    pub(super) config: ArchitectureConfig,
    pub(super) policy: Arc<PolicyEngine>,
    pub(super) redactor: Arc<Redactor>,
    pub(super) schemas: Arc<dyn AgentOutputCheck>,
    pub(super) specs: Arc<dyn WorkspaceAgentSpecs>,
    pub(super) probes: Arc<dyn CapabilityProbes>,
    pub(super) risk: Arc<dyn RiskSource>,
    pub(super) rounds: Arc<dyn RoundSource>,
}

impl ArchitectureHandler {
    /// A handler over its collaborators.
    #[must_use]
    pub fn new(config: ArchitectureConfig, deps: ArchitectureDeps) -> Self {
        Self {
            config,
            policy: deps.policy,
            redactor: deps.redactor,
            schemas: deps.schemas,
            specs: deps.specs,
            probes: deps.probes,
            risk: deps.risk,
            rounds: deps.rounds,
        }
    }
}

fn resolve(
    config: &ArchitectureConfig,
    ctx: &ContractContext<'_>,
) -> Result<StageContract, StageError> {
    let missing = || StageError::Blocked(BlockedCode::DependencyUnavailable);
    let from =
        |kind: StageKind, name: &'static str, description: &'static str, trust: &'static str| {
            let (run, artifact) = upstream_output(ctx.upstream, kind, name).ok_or_else(missing)?;
            Ok::<_, StageError>(ContractInput {
                name,
                description,
                sha256: artifact.sha256.clone(),
                media_type: "application/json",
                source: "previous_stage",
                produced_by: Some(run.id),
                commit_sha: None,
                retrieved_at: ctx.now,
                trust,
            })
        };
    let mut inputs = vec![
        from(
            StageKind::Specification,
            SPECIFICATION_CONTRACT,
            "The frozen specification the design must answer, requirement by requirement.",
            "untrusted",
        )?,
        from(
            StageKind::RepositoryIntelligence,
            REPOSITORY_MAP,
            "The languages, layout and commands of the repository, and the commit it was read at.",
            "untrusted",
        )?,
    ];
    // The domain profile is recorded when the domain discovery stage produced one. The architect's
    // prompt has no place for it, so it is evidence for the record and not text for the model.
    if let Ok(profile) = from(
        StageKind::DomainDiscovery,
        DOMAIN_PROFILE,
        "The domain profile that the domain discovery stage resolved.",
        "trusted_internal",
    ) {
        inputs.push(profile);
    }
    inputs.push(ContractInput {
        name: POLICY_INPUT,
        description: "The hash of the policy bundle in force when the stage run was resolved.",
        sha256: ctx.policy_hash.clone(),
        media_type: "application/json",
        source: "policy",
        produced_by: None,
        commit_sha: None,
        retrieved_at: ctx.now,
        trust: "trusted_internal",
    });
    let budget = &config.budget;
    stage_contract(&ContractSpec {
        kind: StageKind::Architecture,
        job: ctx.identity.job,
        stage_run: ctx.identity.stage_run,
        mode: ctx.mode,
        created_at: ctx.now,
        contract_id: "stage-contract.architecture",
        title: "Design the change for the frozen specification",
        purpose: "Have the architect turn the frozen specification into a design that a builder can implement, and check by rule that every requirement has a design element, that nothing was added for its own sake, and that high-risk work was reviewed by someone other than its author.",
        problem: "A design that nobody checks can leave a requirement out, add parts that no requirement asked for, or hide a risky choice. The factory must be able to show, requirement by requirement, what answers it, before any plan or code is made.",
        inputs,
        preconditions: vec![(
            "specification-frozen",
            "The specification stage passed and the specification is approved.",
            "upstream_stage_passed",
        )],
        method: (
            "One architect, deterministic acceptance checks, and an independent critic for high-risk work",
            "The architect reads the repository with tools that only read and returns a typed design. Rules check the mapping to the specification, the alternatives, the failure modes and the protected paths. The policy computes the risk tier from facts, and a critic who is not the architect reviews the design from that tier.",
            "Accept the design when the architect says it is done",
            "An agent's account of its own work is not evidence, and the architect reads text that anyone could have written.",
        ),
        agent: (config.agent.as_str().to_owned(), "1.0.0"),
        granted_tools: GRANTED_TOOLS.to_vec(),
        shell: "none",
        placement: Some("sandbox"),
        deliverables: vec![
            ContractDeliverable {
                name: DESIGN,
                description: "The design: its parts, its decisions with the alternatives weighed, its risks and its open questions, as the architect returned it.",
                media_type: "application/json",
                required: true,
            },
            ContractDeliverable {
                name: RECORD,
                description: "What the stage measured and decided: the risk tier and why, how much design the change needed, the critic or the reason there was none, and what the architect was given.",
                media_type: "application/json",
                required: true,
            },
            ContractDeliverable {
                name: ADRS,
                description: "A draft decision record for each decision of the design.",
                media_type: "application/json",
                required: true,
            },
        ],
        criteria: vec![
            ContractCriterion {
                id: "every-requirement-has-a-design-element",
                description: "Every requirement of the frozen specification is satisfied by a design element, and every design element answers a requirement that exists.",
                gate: TRACEABILITY_GATE,
            },
            ContractCriterion {
                id: "the-design-is-complete",
                description: "A change that is not trivial weighed alternatives and named how it could fail, and nothing in the design is there for its own sake or touches a protected path.",
                gate: COMPLETENESS_GATE,
            },
            ContractCriterion {
                id: "high-risk-work-had-an-independent-critic",
                description: "When the policy requires an independent critic for the risk tier, one that is not the architect reviewed the design and agreed.",
                gate: CRITIC_GATE,
            },
            ContractCriterion {
                id: "plain-english",
                description: "The titles and the text of the design pass the readability gate.",
                gate: READABILITY_GATE,
            },
        ],
        gates: vec![
            TRACEABILITY_GATE,
            COMPLETENESS_GATE,
            CRITIC_GATE,
            READABILITY_GATE,
        ],
        budget: ContractBudget {
            wall_time_seconds: budget.wall_time_seconds,
            max_tokens: budget.max_tokens,
            max_cost_usd: budget.max_cost_usd,
            attempt_timeout_seconds: budget.attempt_timeout_seconds,
            max_attempts: budget.max_attempts,
        },
        rollback: "Nothing outside the job is changed. Discard the design, its record and the draft decision records.",
        span_name: "stage.architecture",
    })
}

#[async_trait]
impl StageHandler for ArchitectureHandler {
    fn fidelity(&self) -> Fidelity {
        if self.schemas.fidelity() == Fidelity::Fake {
            Fidelity::Fake
        } else {
            Fidelity::Real
        }
    }

    fn kind(&self) -> StageKind {
        StageKind::Architecture
    }

    fn routing_need(&self, ctx: &ContractContext<'_>) -> Option<RoutingNeed> {
        Some(RoutingNeed {
            stage: ctx.identity.kind,
            tier: factory_domain::contracts::agent_manifest::RecommendedTier::Standard,
            required: vec![Capability::JsonSchemaOutput],
            risk: RiskTier::Medium,
            exclude: Vec::new(),
            probed: self.probes.probed(),
        })
    }

    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        resolve(&self.config, ctx)
    }

    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        super::run::execute(self, ctx).await
    }

    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        super::gates::evaluate(self, ctx).await
    }
}
