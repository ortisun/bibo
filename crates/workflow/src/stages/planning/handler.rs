//! `PlanningHandler`, the `StageHandler` of the `TASK_PLANNING` stage.
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
use factory_ports::agent::RoutingNeed;

use crate::gates::dag::{GATE_ID as VALIDATOR_GATE, Limits};
use crate::gates::framework::GateDecision;
use crate::gates::readability::GATE_ID as READABILITY_GATE;
use crate::handlers::{
    ContractContext, GateContext, StageContext, StageError, StageHandler, StageOutput,
};
use crate::stages::architecture::seams::{
    AgentOutputCheck, CapabilityProbes, RoundSource, WorkspaceAgentSpecs,
};
use crate::stages::architecture::shared::AgentSettings;
use crate::stages::implementation::StageBudget;
use crate::stages::implementation::input::{
    ARCHITECTURE, REPOSITORY_MAP, SPECIFICATION_CONTRACT, upstream_output,
};
use crate::stages::intake::common::{
    ContractBudget, ContractCriterion, ContractDeliverable, ContractInput, ContractSpec,
    stage_contract,
};
use crate::stages::validation::POLICY_INPUT;

/// The deliverable that holds the validated plan, a `task-dag` document. The implementation stage
/// reads it by this name, which is the constant that stage declares.
pub use crate::stages::implementation::input::TASK_PLAN;
/// The deliverable that holds the traceability matrix.
pub const MATRIX: &str = "plan-traceability";
/// The deliverable that records what the stage assigned, measured and asked.
pub const RECORD: &str = "plan-record";

/// The gate that reports whether the plan's metadata is what the factory assigned.
pub const METADATA_GATE: &str = "plan-metadata-matches";
/// The gate that reports whether every requirement can be followed to a task and back.
pub const TRACEABILITY_GATE: &str = "plan-traceability-complete";

/// The tools the planner is granted, which are those of its manifest. A test compares the two.
pub const GRANTED_TOOLS: [&str; 4] = ["fs.read", "fs.list", "fs.search", "report.submit"];

/// What the handler is configured with. All of it comes from protected configuration.
#[derive(Debug, Clone)]
pub struct PlanningConfig {
    /// The agent that plans.
    pub agent: Slug,
    /// The commit of the factory's gate definitions, named in every report.
    pub definition_commit: GitSha,
    /// How the agent is run.
    pub settings: AgentSettings,
    /// How large a plan and a task may be.
    pub limits: Limits,
    /// The limits of the stage run.
    pub budget: StageBudget,
}

/// The collaborators of the handler, in one place so a composition root names each.
pub struct PlanningDeps {
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
    /// The round of rework this run replaces.
    pub rounds: Arc<dyn RoundSource>,
}

/// The `TASK_PLANNING` handler. See the module notes for what it does.
pub struct PlanningHandler {
    pub(super) config: PlanningConfig,
    pub(super) policy: Arc<PolicyEngine>,
    pub(super) redactor: Arc<Redactor>,
    pub(super) schemas: Arc<dyn AgentOutputCheck>,
    pub(super) specs: Arc<dyn WorkspaceAgentSpecs>,
    pub(super) probes: Arc<dyn CapabilityProbes>,
    pub(super) rounds: Arc<dyn RoundSource>,
}

impl PlanningHandler {
    /// A handler over its collaborators.
    #[must_use]
    pub fn new(config: PlanningConfig, deps: PlanningDeps) -> Self {
        Self {
            config,
            policy: deps.policy,
            redactor: deps.redactor,
            schemas: deps.schemas,
            specs: deps.specs,
            probes: deps.probes,
            rounds: deps.rounds,
        }
    }
}

fn resolve(
    config: &PlanningConfig,
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
    let inputs = vec![
        from(
            StageKind::Specification,
            SPECIFICATION_CONTRACT,
            "The frozen specification the plan must cover, scenario by scenario.",
            "untrusted",
        )?,
        from(
            StageKind::Architecture,
            ARCHITECTURE,
            "The approved design the plan follows.",
            "untrusted",
        )?,
        from(
            StageKind::RepositoryIntelligence,
            REPOSITORY_MAP,
            "The languages, layout and commands of the repository, and the commit it was read at.",
            "untrusted",
        )?,
        ContractInput {
            name: POLICY_INPUT,
            description: "The hash of the policy bundle in force when the stage run was resolved.",
            sha256: ctx.policy_hash.clone(),
            media_type: "application/json",
            source: "policy",
            produced_by: None,
            commit_sha: None,
            retrieved_at: ctx.now,
            trust: "trusted_internal",
        },
    ];
    let budget = &config.budget;
    stage_contract(&ContractSpec {
        kind: StageKind::TaskPlanning,
        job: ctx.identity.job,
        stage_run: ctx.identity.stage_run,
        mode: ctx.mode,
        created_at: ctx.now,
        contract_id: "stage-contract.task-planning",
        title: "Plan the work as tasks a builder can run one at a time",
        purpose: "Have the planner turn the frozen specification and the approved design into a graph of tasks, then check the graph by rule: it can be run, it covers every scenario, no two tasks that could run together write the same file, and it is small enough to review.",
        problem: "A builder runs one task at a time, so a plan that has a cycle, leaves a scenario without a task, lets two tasks write the same file, or carries metadata the planner invented cannot be run safely. The factory must show that the plan is sound before any code is written.",
        inputs,
        preconditions: vec![(
            "design-approved",
            "The architecture stage passed.",
            "upstream_stage_passed",
        )],
        method: (
            "One planner, a deterministic validator, and a traceability matrix built from the stored documents",
            "The planner reads the repository with tools that only read and returns a typed plan inside an envelope. The factory compares the plan's metadata with the values it assigned, validates the graph, computes the critical path itself, and builds the matrix from the specification, the design and the plan.",
            "Trust the plan because the planner says it is sound",
            "A planner reads text that anyone could have written, and the values it copies into the plan are the factory's to assign.",
        ),
        agent: (config.agent.as_str().to_owned(), "1.0.0"),
        granted_tools: GRANTED_TOOLS.to_vec(),
        shell: "none",
        placement: Some("sandbox"),
        deliverables: vec![
            ContractDeliverable {
                name: TASK_PLAN,
                description: "The plan: a graph of tasks, as the planner returned it. Absent when the planner asked a person instead.",
                media_type: "application/json",
                required: false,
            },
            ContractDeliverable {
                name: MATRIX,
                description: "The traceability matrix from each requirement to the design, the tasks, the tests and the documentation, and back. Absent when the planner asked a person instead.",
                media_type: "application/json",
                required: false,
            },
            ContractDeliverable {
                name: RECORD,
                description: "What the stage assigned and measured: the values it assigned to the plan, the order and the critical path, and the question when the planner asked one.",
                media_type: "application/json",
                required: true,
            },
        ],
        criteria: vec![
            ContractCriterion {
                id: "metadata-is-the-factorys-own",
                description: "The plan's identifiers, hashes and time are the values the factory assigned.",
                gate: METADATA_GATE,
            },
            ContractCriterion {
                id: "the-plan-can-be-run",
                description: "The plan has no cycle, no missing dependency, no duplicate task, covers every scenario and requirement, orders every pair of tasks that could write the same file, and is of a size a person can review.",
                gate: VALIDATOR_GATE,
            },
            ContractCriterion {
                id: "every-requirement-can-be-followed",
                description: "Every requirement can be followed through the design to a task, and every task back to a requirement.",
                gate: TRACEABILITY_GATE,
            },
            ContractCriterion {
                id: "plain-english",
                description: "The titles and the text of every task pass the readability gate.",
                gate: READABILITY_GATE,
            },
        ],
        gates: vec![
            METADATA_GATE,
            VALIDATOR_GATE,
            TRACEABILITY_GATE,
            READABILITY_GATE,
        ],
        budget: ContractBudget {
            wall_time_seconds: budget.wall_time_seconds,
            max_tokens: budget.max_tokens,
            max_cost_usd: budget.max_cost_usd,
            attempt_timeout_seconds: budget.attempt_timeout_seconds,
            max_attempts: budget.max_attempts,
        },
        rollback: "Nothing outside the job is changed. Discard the plan, the matrix and the record.",
        span_name: "stage.task_planning",
    })
}

#[async_trait]
impl StageHandler for PlanningHandler {
    fn fidelity(&self) -> Fidelity {
        if self.schemas.fidelity() == Fidelity::Fake {
            Fidelity::Fake
        } else {
            Fidelity::Real
        }
    }

    fn kind(&self) -> StageKind {
        StageKind::TaskPlanning
    }

    fn routing_need(&self, ctx: &ContractContext<'_>) -> Option<RoutingNeed> {
        Some(RoutingNeed {
            stage: ctx.identity.kind,
            tier: factory_domain::contracts::agent_manifest::RecommendedTier::Standard,
            required: Vec::new(),
            risk: RiskTier::Medium,
            exclude: Vec::new(),
            probed: self.probes.probed(),
            author: None,
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
