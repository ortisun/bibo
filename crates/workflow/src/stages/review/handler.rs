//! `ReviewHandler`, the `StageHandler` of the `REVIEW` stage, and its stage contract.
//!
//! `execute` is in [`run`](super::run) and `evaluate` in [`gates`](super::gates).

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::Contract;
use factory_domain::contracts::StageContract;
use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::policy::PolicyEngine;
use factory_domain::redaction::Redactor;
use factory_domain::values::{GitSha, Slug};
use factory_domain::vocabulary::{Fidelity, RiskTier, StageKind};
use factory_ports::agent::{BrokerEndpoint, RoutingNeed};
use factory_ports::paths::PathRules;
use serde_json::json;

use super::gates::{EVIDENCE_GATE, GROUNDED_GATE};
use crate::gates::framework::GateDecision;
use crate::handlers::{
    ContractContext, GateContext, StageContext, StageError, StageHandler, StageOutput,
};
use crate::stages::implementation::StageBudget;
use crate::stages::implementation::input::{
    IMPLEMENTATION_RESULT, SPECIFICATION_CONTRACT, VALIDATION_EVIDENCE, upstream_output,
};
use crate::stages::implementation::seams::{
    AgentOutputCheck, CapabilityProbes, WorkspaceAgentSpecs,
};
use crate::stages::validation::POLICY_INPUT;

/// The name of the deliverable that holds the stored verdict.
pub const VERDICT: &str = "review-verdict";
/// The name of the deliverable that records what the reviewer was given and what it returned.
pub const RECORD: &str = "review-record";

/// The tools the reviewer is granted, which are those of its manifest. A test compares the two.
pub const GRANTED_TOOLS: [&str; 4] = ["fs.read", "fs.list", "fs.search", "report.submit"];

/// What the handler is configured with. All of it comes from protected configuration.
#[derive(Debug, Clone)]
pub struct ReviewConfig {
    /// The agent that reviews.
    pub agent: Slug,
    /// Its version, as the contract names it.
    pub agent_version: String,
    /// The commit of the factory's gate definitions, named in every report.
    pub definition_commit: GitSha,
    /// Where the sandbox reaches the model broker.
    pub broker: BrokerEndpoint,
    /// The most bytes of final output the runtime reads.
    pub max_output_bytes: u64,
    /// The path rules of the policy.
    pub path_rules: PathRules,
    /// The most bytes of patch the host exports for the reviewer.
    pub max_patch_bytes: u64,
    /// The limits of the stage run.
    pub budget: StageBudget,
}

/// The collaborators of the handler, in one place so a composition root names each.
pub struct ReviewDeps {
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
}

/// The `REVIEW` handler. See the module notes for what it does.
pub struct ReviewHandler {
    pub(super) config: ReviewConfig,
    pub(super) policy: Arc<PolicyEngine>,
    pub(super) redactor: Arc<Redactor>,
    pub(super) schemas: Arc<dyn AgentOutputCheck>,
    pub(super) specs: Arc<dyn WorkspaceAgentSpecs>,
    pub(super) probes: Arc<dyn CapabilityProbes>,
}

impl ReviewHandler {
    /// A handler over its collaborators.
    #[must_use]
    pub fn new(config: ReviewConfig, deps: ReviewDeps) -> Self {
        Self {
            config,
            policy: deps.policy,
            redactor: deps.redactor,
            schemas: deps.schemas,
            specs: deps.specs,
            probes: deps.probes,
        }
    }
}

fn resolve(config: &ReviewConfig, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
    let retrieved = ctx.now.as_text();
    let missing = || StageError::Blocked(BlockedCode::DependencyUnavailable);
    let mut inputs = Vec::new();
    for (kind, name, description, trust) in [
        (
            StageKind::Implementation,
            IMPLEMENTATION_RESULT,
            "The base commit and the head commit of the change under review.",
            "trusted_internal",
        ),
        (
            StageKind::Validation,
            VALIDATION_EVIDENCE,
            "The reports of the deterministic gates and the binding that says what they are about.",
            "trusted_internal",
        ),
        (
            StageKind::Specification,
            SPECIFICATION_CONTRACT,
            "The frozen specification the change is judged against.",
            "untrusted",
        ),
    ] {
        let (run, artifact) = upstream_output(ctx.upstream, kind, name).ok_or_else(missing)?;
        inputs.push(json!({
            "name": name,
            "description": description,
            "artifact": { "sha256": artifact.sha256.as_str(), "media_type": artifact.media_type.as_str() },
            "provenance": {
                "source": "previous_stage",
                "produced_by_stage_run_id": run.id.to_string(),
                "retrieved_at": retrieved,
            },
            "trust": trust,
        }));
    }
    // The project's rules for agents (ADR 0026), given to the code reviewer.
    inputs.extend(crate::stages::project_rules::contract_input_json(
        ctx.upstream,
        &retrieved,
    ));
    inputs.push(json!({
        "name": POLICY_INPUT,
        "description": "The hash of the policy bundle in force when the stage run was resolved.",
        "artifact": { "sha256": ctx.policy_hash.as_str(), "media_type": "application/json" },
        "provenance": { "source": "policy", "retrieved_at": retrieved },
        "trust": "trusted_internal",
    }));
    let budget = &config.budget;
    let document = json!({
        "schema_version": 1,
        "metadata": {
            "contract_id": "stage-contract.review",
            "contract_version": "1.0.0",
            "stage_kind": "REVIEW",
            "job_id": ctx.identity.job.to_string(),
            "stage_run_id": ctx.identity.stage_run.to_string(),
            "execution_mode": ctx.mode.as_str(),
            "created_at": retrieved,
            "domain_profiles": [{ "id": "general-software", "version": 1 }],
        },
        "title": "Review the change against the frozen specification",
        "purpose": "Have an independent reviewer judge the change from the frozen specification, the exported patch and the verified gate reports, and turn its answer into the stored verdict.",
        "problem_statement": "The builder says the work is done and the gates measured it. A second agent must still judge whether the change does what was asked, from the evidence only. It must not see the builder's own account, and nothing it says may outweigh a gate that failed.",
        "inputs": inputs,
        "preconditions": [{
            "id": "validation-passed",
            "description": "The implementation and validation stage runs passed and the evidence is about this commit.",
            "check": "upstream_stage_passed",
        }],
        "risk": {
            "tier": "low",
            "rationale": "The reviewer reads its own copy of the checkout with tools that only read, changes nothing and has no push credential. Its verdict is evidence for the gate and decides nothing by itself.",
            "domains": ["general-software"],
        },
        "methods": [{
            "name": "Independent reviewer with inputs of a type that excludes the builder's account",
            "rationale": "The prompt is assembled from inputs that cannot be a builder summary, in a read-only sandbox. The verdict is wrapped with the engine's own fields, its findings are deduplicated, and a gate checks that each one cites a line the patch shows.",
            "alternatives_considered": [{
                "name": "Show the reviewer the builder's summary to save time",
                "why_not": "A summary written by the author frames the change as correct before the reviewer has read it.",
            }],
            "escalation_trigger": "Ask a person when the reviewer returns NEEDS_HUMAN or BLOCK, when the same findings come back, or after two rounds of rework.",
        }],
        "capabilities": {
            "agent_manifest": { "id": config.agent.as_str(), "version": config.agent_version },
            "granted_tools": GRANTED_TOOLS,
            "permissions": {
                "filesystem_read": ["**"],
                "filesystem_write": [],
                "network": "none",
                "shell": "none",
            },
            "placement": "sandbox",
        },
        "deliverables": [
            {
                "name": VERDICT,
                "description": "The stored review verdict, with the findings deduplicated and identified by the factory. Absent only when the evidence was not about this commit and the reviewer did not run.",
                "media_type": "application/json",
                "required": false,
            },
            {
                "name": RECORD,
                "description": "What the reviewer was given, by name, class and hash, what it returned, and what it said it ignored.",
                "media_type": "application/json",
                "required": true,
            },
        ],
        "acceptance_criteria": [
            {
                "id": "evidence-is-verified",
                "description": "The gate reports are about this commit and no gate failed or was blocked.",
                "machine_verifiable": true,
                "verification": { "kind": "gate", "ref": EVIDENCE_GATE },
            },
            {
                "id": "verdict-is-grounded",
                "description": "The verdict was made from this specification, this patch and these gate reports, and every finding of a verdict other than PASS cites a file and a line that the patch shows.",
                "machine_verifiable": true,
                "verification": { "kind": "gate", "ref": GROUNDED_GATE },
            },
        ],
        "evaluator": {
            "kind": "gate_and_reviewer",
            "gate_ids": [EVIDENCE_GATE, GROUNDED_GATE],
            "reviewer_agent": { "id": config.agent.as_str(), "version": config.agent_version },
            "reviewer_must_not_see": ["builder_self_assessment", "builder_transcript"],
        },
        "evidence_refs": [],
        "confidence": {
            "level": "medium",
            "notes": "The verdict is an agent's opinion. The gates and the citations are checked by the factory.",
        },
        "assumptions": [],
        "budget": {
            "max_wall_time_seconds": budget.wall_time_seconds,
            "max_tokens": budget.max_tokens,
            "max_cost_usd": budget.max_cost_usd,
            "max_compute": { "cpu_millicores": 1000, "memory_mb": 2048, "disk_mb": 1024 },
        },
        "timeout_and_retries": {
            "attempt_timeout_seconds": budget.attempt_timeout_seconds,
            "max_attempts": budget.max_attempts,
            "backoff": { "initial_ms": 5000, "max_ms": 300_000, "jitter": "full" },
            "retry_on": [
                "TOOL_ERROR", "INVALID_OUTPUT", "PROVIDER_ERROR", "SANDBOX_ERROR", "TIMED_OUT",
                "LEASE_LOST"
            ],
            "max_rework_iterations": 2,
        },
        "idempotency": {
            "key_scheme": "stage_run_id plus the hashes of all input artifacts",
            "side_effects": "none",
        },
        "escalation": {
            "rollback": "The stage writes a verdict and a record and changes nothing else, so there is nothing to undo.",
            "escalate_to": "approver",
            "on": ["needs_human_verdict", "blocked", "rework_limit_reached", "stagnation_detected", "budget_exceeded"],
        },
        "telemetry": {
            "span_name": "stage.review",
            "attributes": ["job.id", "stage.run.id", "stage.kind"],
            "metrics": ["stage.duration"],
        },
    });
    StageContract::from_json_value(document).map_err(|_| StageError::Internal)
}

#[async_trait]
impl StageHandler for ReviewHandler {
    fn fidelity(&self) -> Fidelity {
        self.schemas.fidelity()
    }

    fn kind(&self) -> StageKind {
        StageKind::Review
    }

    fn routing_need(&self, ctx: &ContractContext<'_>) -> Option<RoutingNeed> {
        Some(RoutingNeed {
            stage: ctx.identity.kind,
            tier: RecommendedTier::Standard,
            required: Vec::new(),
            risk: RiskTier::Low,
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
