//! `SpecificationHandler`, the `StageHandler` of the `SPECIFICATION` stage.
//!
//! `execute` is in [`run`](super::run) and `evaluate` in [`gates`](super::gates). This file holds
//! the handler, what it is configured with, and the parts of the trait that need neither.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::StageContract;
use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::ids::PrincipalId;
use factory_domain::policy::PolicyEngine;
use factory_domain::redaction::Redactor;
use factory_domain::values::{GitSha, Slug};
use factory_domain::vocabulary::{Fidelity, RiskTier, StageKind};
use factory_ports::agent::{BrokerEndpoint, Capability, RoutingNeed};
use factory_ports::paths::{PathRules, RepoGlob, RepoPath};
use factory_ports::spec::SpecificationProvider;

use super::seams::{
    AgentOutputCheck, CapabilityProbes, ReworkSource, SpecApprovals, SpecDrafts, SpecHistory,
    WorkspaceAgentSpecs,
};
use crate::gates::framework::GateDecision;
use crate::gates::spec::Limits;
use crate::gates::spec::profile::ProfileRules;
use crate::handlers::{
    ContractContext, GateContext, StageContext, StageError, StageHandler, StageOutput,
};
pub use crate::stages::implementation::{CommitIdentity, StageBudget};

/// What the handler is configured with. All of it comes from protected configuration.
///
/// The paths and globs that belong to the Spec Kit layout are in here, passed in by the
/// composition root from the adapter's constants, because this crate may not know them.
#[derive(Debug, Clone)]
pub struct SpecificationConfig {
    /// The agent that writes.
    pub writer: Slug,
    /// The agent that reviews. It must not be the writer.
    pub reviewer: Slug,
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
    /// The path of the project constitution, written once for the repository and approved apart
    /// from any feature request.
    pub constitution_path: RepoPath,
    /// Globs of paths the host reads from the commit even when the run did not change them, so
    /// that an extension or a file of a denied skill that was there before is seen.
    pub probe_globs: Vec<RepoGlob>,
    /// The word lists and switches of the gate.
    pub limits: Limits,
    /// The most bytes of one file the host reads back.
    pub max_file_bytes: u64,
    /// The most rounds of clarification before a person decides how to go on.
    pub max_clarification_rounds: usize,
    /// Whether a person must approve. When false, a specification that passes every rule is
    /// frozen on the basis of the low-risk policy, with `policy_principal` as the approver.
    pub human_approval_required: bool,
    /// The principal that stands for the policy engine, for the low-risk basis.
    pub policy_principal: Option<PrincipalId>,
    /// The limits of the stage run.
    pub budget: StageBudget,
}

/// The collaborators of the handler, in one place so a composition root names each.
pub struct SpecificationDeps {
    /// Runs the skills and assembles the contract.
    pub provider: Arc<dyn SpecificationProvider>,
    /// The policy evaluators.
    pub policy: Arc<PolicyEngine>,
    /// The redactor of the job.
    pub redactor: Arc<Redactor>,
    /// The rules of the stage profile, from the policy.
    pub profile: Arc<ProfileRules>,
    /// The check of an agent's output against its own schema.
    pub schemas: Arc<dyn AgentOutputCheck>,
    /// The sandbox spec factory.
    pub specs: Arc<dyn WorkspaceAgentSpecs>,
    /// The runtime probes.
    pub probes: Arc<dyn CapabilityProbes>,
    /// Where the approvals of people come from.
    pub approvals: Arc<dyn SpecApprovals>,
    /// Where the draft is kept between attempts.
    pub drafts: Arc<dyn SpecDrafts>,
    /// Where the basis of a revision comes from.
    pub history: Arc<dyn SpecHistory>,
    /// Where the feedback of a rework round comes from.
    pub rework: Arc<dyn ReworkSource>,
}

/// The `SPECIFICATION` handler. See the module notes for what it does.
pub struct SpecificationHandler {
    pub(super) config: SpecificationConfig,
    pub(super) provider: Arc<dyn SpecificationProvider>,
    pub(super) policy: Arc<PolicyEngine>,
    pub(super) redactor: Arc<Redactor>,
    pub(super) profile: Arc<ProfileRules>,
    pub(super) schemas: Arc<dyn AgentOutputCheck>,
    pub(super) specs: Arc<dyn WorkspaceAgentSpecs>,
    pub(super) probes: Arc<dyn CapabilityProbes>,
    pub(super) approvals: Arc<dyn SpecApprovals>,
    pub(super) drafts: Arc<dyn SpecDrafts>,
    pub(super) history: Arc<dyn SpecHistory>,
    pub(super) rework: Arc<dyn ReworkSource>,
}

impl SpecificationHandler {
    /// A handler over its collaborators.
    #[must_use]
    pub fn new(config: SpecificationConfig, deps: SpecificationDeps) -> Self {
        Self {
            config,
            provider: deps.provider,
            policy: deps.policy,
            redactor: deps.redactor,
            profile: deps.profile,
            schemas: deps.schemas,
            specs: deps.specs,
            probes: deps.probes,
            approvals: deps.approvals,
            drafts: deps.drafts,
            history: deps.history,
            rework: deps.rework,
        }
    }
}

impl SpecificationHandler {
    /// What the writer of the specification needs: a runtime that runs the Spec Kit skills.
    pub(super) fn writer_need(&self) -> RoutingNeed {
        RoutingNeed {
            stage: StageKind::Specification,
            tier: RecommendedTier::Standard,
            required: vec![Capability::SkillInvocation],
            risk: RiskTier::Medium,
            exclude: Vec::new(),
            probed: self.probes.probed(),
            author: None,
        }
    }

    /// What the reviewer of the specification needs, routed against the model of the writer
    /// (`author`), so that the routing policy's rule of independence for the specification
    /// reviewer holds. The engine routes the same need when it issues the token, so the model
    /// chosen here is one the token allows.
    pub(super) fn reviewer_need(
        &self,
        author: Option<factory_ports::agent::ModelSelection>,
    ) -> RoutingNeed {
        RoutingNeed {
            stage: StageKind::Specification,
            tier: RecommendedTier::Standard,
            required: Vec::new(),
            risk: RiskTier::Medium,
            exclude: Vec::new(),
            probed: self.probes.probed(),
            author,
        }
    }
}

#[async_trait]
impl StageHandler for SpecificationHandler {
    fn fidelity(&self) -> Fidelity {
        let parts = [
            self.provider.fidelity(),
            self.schemas.fidelity(),
            self.approvals.fidelity(),
            self.drafts.fidelity(),
        ];
        if parts.contains(&Fidelity::Fake) {
            Fidelity::Fake
        } else {
            Fidelity::Real
        }
    }

    fn kind(&self) -> StageKind {
        StageKind::Specification
    }

    fn routing_need(&self, _ctx: &ContractContext<'_>) -> Option<RoutingNeed> {
        Some(self.writer_need())
    }

    fn reviewer_routing_need(&self, _ctx: &ContractContext<'_>) -> Option<RoutingNeed> {
        Some(self.reviewer_need(None))
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
