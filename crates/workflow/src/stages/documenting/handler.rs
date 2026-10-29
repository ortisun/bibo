//! `DocumentingHandler`, the `StageHandler` of the `DOCUMENTING` stage, and its stage contract.
//!
//! `execute` is in [`run`](super::run) and `evaluate` in [`gates`](super::gates).

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::{Contract, StageContract};
use factory_domain::policy::PolicyEngine;
use factory_domain::redaction::Redactor;
use factory_domain::values::{GitSha, Slug};
use factory_domain::vocabulary::{Fidelity, RiskTier, StageKind};
use factory_ports::agent::{BrokerEndpoint, Capability, RoutingNeed};
use factory_ports::paths::PathRules;
use serde_json::json;

use super::input::{
    DOCUMENTATION_PLAN, DOCUMENTATION_RESULT, DOMAIN_PROFILE, IMPLEMENTATION_RESULT,
    SPECIFICATION_CONTRACT, upstream_output,
};
use crate::gates::framework::GateDecision;
use crate::handlers::{
    ContractContext, GateContext, StageContext, StageError, StageHandler, StageOutput,
};
use crate::stages::implementation::seams::{
    AgentOutputCheck, CapabilityProbes, ReworkSource, WorkspaceAgentSpecs,
};
use crate::stages::implementation::{CommitIdentity, StageBudget};
use crate::stages::validation::POLICY_INPUT;

/// The gate that checks the plan against its schema and the commits it is bound to.
pub const PLAN_GATE: &str = "documenting-plan-recorded";
/// The gate that checks every changed path against the paths the writer may write.
pub const SCOPE_GATE: &str = "documenting-scope";
/// The gate that reports a change the audit refused.
pub const PROTECTED_GATE: &str = "documenting-protected-paths";
/// The gate that checks that each claim of the writer cites a file that exists.
pub const TRACE_GATE: &str = "documenting-traceability";

/// The tools the writer is granted, which are those of its manifest. A test compares the two.
pub const GRANTED_TOOLS: [&str; 4] = ["fs.read", "fs.list", "fs.write", "report.submit"];

/// What the handler is configured with. All of it comes from protected configuration.
#[derive(Debug, Clone)]
pub struct DocumentingConfig {
    /// The agent that writes.
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
    /// The most bytes of patch the host exports.
    pub max_patch_bytes: u64,
    /// The limits of the stage run.
    pub budget: StageBudget,
}

/// The collaborators of the handler, in one place so a composition root names each.
pub struct DocumentingDeps {
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
    /// Where the feedback of a rework round comes from.
    pub rework: Arc<dyn ReworkSource>,
}

/// The `DOCUMENTING` handler. See the module notes for what it does.
pub struct DocumentingHandler {
    pub(super) config: DocumentingConfig,
    pub(super) policy: Arc<PolicyEngine>,
    pub(super) redactor: Arc<Redactor>,
    pub(super) schemas: Arc<dyn AgentOutputCheck>,
    pub(super) specs: Arc<dyn WorkspaceAgentSpecs>,
    pub(super) probes: Arc<dyn CapabilityProbes>,
    pub(super) rework: Arc<dyn ReworkSource>,
}

impl DocumentingHandler {
    /// A handler over its collaborators.
    #[must_use]
    pub fn new(config: DocumentingConfig, deps: DocumentingDeps) -> Self {
        Self {
            config,
            policy: deps.policy,
            redactor: deps.redactor,
            schemas: deps.schemas,
            specs: deps.specs,
            probes: deps.probes,
            rework: deps.rework,
        }
    }
}

fn resolve(
    config: &DocumentingConfig,
    ctx: &ContractContext<'_>,
) -> Result<StageContract, StageError> {
    let retrieved = ctx.now.as_text();
    let missing = || StageError::Blocked(BlockedCode::DependencyUnavailable);
    let mut inputs = Vec::new();
    for (kind, name, description, trust, optional) in [
        (
            StageKind::Implementation,
            IMPLEMENTATION_RESULT,
            "The base commit and the head commit of the change to document.",
            "trusted_internal",
            false,
        ),
        (
            StageKind::Specification,
            SPECIFICATION_CONTRACT,
            "The frozen specification the documents must agree with.",
            "untrusted",
            false,
        ),
        (
            StageKind::DomainDiscovery,
            DOMAIN_PROFILE,
            "The domain profile, which adds domain content to the documentation plan.",
            "trusted_internal",
            true,
        ),
    ] {
        let Some((run, artifact)) = upstream_output(ctx.upstream, kind, name) else {
            if optional {
                continue;
            }
            return Err(missing());
        };
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
            "contract_id": "stage-contract.documenting",
            "contract_version": "1.0.0",
            "stage_kind": "DOCUMENTING",
            "job_id": ctx.identity.job.to_string(),
            "stage_run_id": ctx.identity.stage_run.to_string(),
            "execution_mode": ctx.mode.as_str(),
            "created_at": retrieved,
            "domain_profiles": [{ "id": "general-software", "version": 1 }],
        },
        "title": "Document the change that was built and reviewed",
        "purpose": "Derive the smallest set of documents the change needs, have the documentation writer write them in a sandbox, audit what it wrote, and commit it on the job branch.",
        "problem_statement": "The change was built, checked and reviewed, and a reader cannot use it until it is documented. The documents must say only what the code does, nothing may be forced on a change that needs no document, and a writer that tries to change code or a protected file must be stopped.",
        "inputs": inputs,
        "preconditions": [{
            "id": "review-passed",
            "description": "The implementation, validation and review stage runs passed.",
            "check": "upstream_stage_passed",
        }],
        "risk": {
            "tier": "low",
            "rationale": "The writer may write only the README, the changelog and Markdown files under docs, in a sandbox with no network except the model broker. The host audits the tree before it commits anything.",
            "domains": ["general-software"],
        },
        "methods": [{
            "name": "Impact policy in code, then one writer, audited ingestion, host commit",
            "rationale": "A program derives the plan from the diff, so no model decides what is documented. The writer's tree is audited and committed by the host, so no hook or configuration it wrote ever runs there.",
            "alternatives_considered": [{
                "name": "Let the writer decide which documents the change needs",
                "why_not": "An agent would document too much or too little, and its opinion could not be checked.",
            }],
            "escalation_trigger": "Ask a person when the writer needs a decision or the audit refuses its change.",
        }],
        "capabilities": {
            "agent_manifest": { "id": config.agent.as_str(), "version": config.agent_version },
            "granted_tools": GRANTED_TOOLS,
            "permissions": {
                "filesystem_read": ["**"],
                "filesystem_write": ["README.md", "CHANGELOG.md", "docs/**/*.md"],
                "network": "none",
                "shell": "none",
            },
            "placement": "sandbox",
        },
        "deliverables": [
            {
                "name": DOCUMENTATION_PLAN,
                "description": "The documentation plan: the pages, their audience, sources, terms and acceptance criteria, or the rule that says none is needed.",
                "media_type": "application/json",
                "required": true,
            },
            {
                "name": DOCUMENTATION_RESULT,
                "description": "The commits, the changed paths, the claims the writer cited with their sources, and any refusal of the audit.",
                "media_type": "application/json",
                "required": true,
            },
        ],
        "acceptance_criteria": [
            {
                "id": "plan-is-recorded-and-bound",
                "description": "The plan follows its schema and names the commits and the specification it was derived from.",
                "machine_verifiable": true,
                "verification": { "kind": "gate", "ref": PLAN_GATE },
            },
            {
                "id": "writer-stayed-in-scope",
                "description": "Every changed path is the README, the changelog or a Markdown file under docs.",
                "machine_verifiable": true,
                "verification": { "kind": "gate", "ref": SCOPE_GATE },
            },
            {
                "id": "no-protected-path-changed",
                "description": "The audit refused no change to a protected path, a hidden path, a link or a secret.",
                "machine_verifiable": true,
                "verification": { "kind": "gate", "ref": PROTECTED_GATE },
            },
            {
                "id": "claims-cite-their-sources",
                "description": "Each claim the writer made cites a file that exists at the documentation commit.",
                "machine_verifiable": true,
                "verification": { "kind": "gate", "ref": TRACE_GATE },
            },
        ],
        "evaluator": { "kind": "deterministic_gate", "gate_ids": [PLAN_GATE, SCOPE_GATE, PROTECTED_GATE, TRACE_GATE] },
        "evidence_refs": [],
        "confidence": {
            "level": "medium",
            "notes": "The plan, the commits and the changed paths are the host's own measurements. What the writer says about its work is recorded and not counted.",
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
            "rollback": "Nothing leaves the job's object store, so dropping the documentation commit undoes the stage.",
            "escalate_to": "approver",
            "on": ["budget_exceeded", "blocked", "policy_violation", "rework_limit_reached"],
        },
        "telemetry": {
            "span_name": "stage.documenting",
            "attributes": ["job.id", "stage.run.id", "stage.kind"],
            "metrics": ["stage.duration"],
        },
    });
    StageContract::from_json_value(document).map_err(|_| StageError::Internal)
}

#[async_trait]
impl StageHandler for DocumentingHandler {
    fn fidelity(&self) -> Fidelity {
        self.schemas.fidelity()
    }

    fn kind(&self) -> StageKind {
        StageKind::Documenting
    }

    fn routing_need(&self, ctx: &ContractContext<'_>) -> Option<RoutingNeed> {
        Some(RoutingNeed {
            stage: ctx.identity.kind,
            tier: RecommendedTier::Standard,
            required: vec![Capability::JsonSchemaOutput],
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
