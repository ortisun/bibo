//! `ImplementationHandler`, the `StageHandler` of the `IMPLEMENTATION` stage.
//!
//! `execute` is in [`run`](super::run) and `evaluate` in [`gates`](super::gates). This file holds
//! the handler, what it is configured with, and the parts of the trait that need neither.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::StageContract;
use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::policy::PolicyEngine;
use factory_domain::redaction::Redactor;
use factory_domain::values::{GitSha, Slug};
use factory_domain::vocabulary::{Fidelity, RiskTier, StageKind};
use factory_ports::agent::{BrokerEndpoint, Capability, RoutingNeed};
use factory_ports::paths::PathRules;

use super::seams::{
    AgentOutputCheck, CapabilityProbes, ReworkSource, TaskLedger, WorkspaceAgentSpecs,
};
use crate::gates::framework::GateDecision;
use crate::handlers::{
    ContractContext, GateContext, StageContext, StageError, StageHandler, StageOutput,
};

/// Who the factory says made a commit. It is the factory's own fixed identity, never the
/// builder's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitIdentity {
    /// The author and committer name.
    pub name: String,
    /// The author and committer email.
    pub email: String,
}

/// The limits of the stage run, from the policy. They go into the stage contract, and the handler
/// stops starting tasks once the tokens or the money are spent.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StageBudget {
    /// Wall time for the whole stage run.
    pub wall_time_seconds: u32,
    /// Model tokens for all the tasks together.
    pub max_tokens: u32,
    /// Money for all the tasks together, in US dollars.
    pub max_cost_usd: f64,
    /// Time for one attempt.
    pub attempt_timeout_seconds: u32,
    /// Attempts before a person is asked.
    pub max_attempts: u32,
}

/// What the handler is configured with. All of it comes from protected configuration.
#[derive(Debug, Clone)]
pub struct ImplementationConfig {
    /// The agent that builds.
    pub agent: Slug,
    /// Its version, as the contract names it.
    pub agent_version: String,
    /// The commit of the factory's gate definitions, named in every report.
    pub definition_commit: GitSha,
    /// Where the sandbox reaches the model broker.
    pub broker: BrokerEndpoint,
    /// The most bytes of final output the runtime reads.
    pub max_output_bytes: u64,
    /// The path rules of the policy. The workspace applies every decision about a path from them.
    pub path_rules: PathRules,
    /// Who the commits are by.
    pub identity: CommitIdentity,
    /// The most bytes of patch the host exports for the statistics of one task.
    pub max_patch_bytes: u64,
    /// The limits of the stage run.
    pub budget: StageBudget,
}

/// The collaborators of the handler, in one place so a composition root names each.
pub struct ImplementationDeps {
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
    /// The durable state of the tasks.
    pub ledger: Arc<dyn TaskLedger>,
    /// Where the feedback of a rework round comes from.
    pub rework: Arc<dyn ReworkSource>,
}

/// The `IMPLEMENTATION` handler. See the module notes for what it does.
pub struct ImplementationHandler {
    pub(super) config: ImplementationConfig,
    pub(super) policy: Arc<PolicyEngine>,
    pub(super) redactor: Arc<Redactor>,
    pub(super) schemas: Arc<dyn AgentOutputCheck>,
    pub(super) specs: Arc<dyn WorkspaceAgentSpecs>,
    pub(super) probes: Arc<dyn CapabilityProbes>,
    pub(super) ledger: Arc<dyn TaskLedger>,
    pub(super) rework: Arc<dyn ReworkSource>,
}

impl ImplementationHandler {
    /// A handler over its collaborators.
    #[must_use]
    pub fn new(config: ImplementationConfig, deps: ImplementationDeps) -> Self {
        Self {
            config,
            policy: deps.policy,
            redactor: deps.redactor,
            schemas: deps.schemas,
            specs: deps.specs,
            probes: deps.probes,
            ledger: deps.ledger,
            rework: deps.rework,
        }
    }
}

#[async_trait]
impl StageHandler for ImplementationHandler {
    fn fidelity(&self) -> Fidelity {
        if [self.schemas.fidelity(), self.ledger.fidelity()].contains(&Fidelity::Fake) {
            Fidelity::Fake
        } else {
            Fidelity::Real
        }
    }

    fn kind(&self) -> StageKind {
        StageKind::Implementation
    }

    fn routing_need(&self, ctx: &ContractContext<'_>) -> Option<RoutingNeed> {
        Some(RoutingNeed {
            stage: ctx.identity.kind,
            tier: RecommendedTier::Standard,
            required: vec![Capability::JsonSchemaOutput, Capability::HeadlessMultiTurn],
            risk: RiskTier::Medium,
            exclude: Vec::new(),
            probed: self.probes.probed(),
        })
    }

    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        super::contract::resolve(&self.config, ctx)
    }

    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        super::run::execute(self, ctx).await
    }

    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        super::gates::evaluate(self, ctx).await
    }
}
