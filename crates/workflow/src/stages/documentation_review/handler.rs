//! `DocumentationReviewHandler`, the `StageHandler` of the `DOCUMENTATION_REVIEW` stage, and its
//! stage contract.
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
use factory_ports::agent::{BrokerEndpoint, RoutingNeed};
use factory_ports::paths::PathRules;
use serde_json::json;

use super::verify::DocsToolchain;
use crate::gates::docs::check;
use crate::gates::framework::GateDecision;
use crate::gates::readability::GATE_ID as READABILITY_GATE;
use crate::handlers::{
    ContractContext, GateContext, StageContext, StageError, StageHandler, StageOutput,
};
use crate::stages::documenting::input::{
    DOCUMENTATION_GATE_REPORT, DOCUMENTATION_PLAN, DOCUMENTATION_RESULT, DOCUMENTATION_REVIEW,
    DOCUMENTATION_REVIEW_RECORD, IMPLEMENTATION_RESULT, SPECIFICATION_CONTRACT, upstream_output,
};
use crate::stages::implementation::StageBudget;
use crate::stages::implementation::seams::{
    AgentOutputCheck, AnswerHistory, CapabilityProbes, WorkspaceAgentSpecs,
};
use crate::stages::validation::{POLICY_INPUT, VerifySandbox};

/// The tools the reviewer is granted, which are those of its manifest. A test compares the two.
pub const GRANTED_TOOLS: [&str; 3] = ["fs.read", "fs.list", "report.submit"];

/// The gates of the stage: the readability gate and the nine checks of the Documentation Quality
/// Gate.
#[must_use]
pub fn gate_ids() -> Vec<&'static str> {
    let mut ids = vec![READABILITY_GATE];
    ids.extend(check::ALL);
    ids
}

/// What the handler is configured with. All of it comes from protected configuration.
#[derive(Debug, Clone)]
pub struct DocumentationReviewConfig {
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
    /// The most bytes of patch the host exports.
    pub max_patch_bytes: u64,
    /// The limits of the stage run.
    pub budget: StageBudget,
    /// The verify sandbox the gate runs the program in.
    pub verify: VerifySandbox,
    /// The commands: build, binary and diagram parser.
    pub toolchain: DocsToolchain,
}

/// The collaborators of the handler, in one place so a composition root names each.
pub struct DocumentationReviewDeps {
    /// The policy evaluators.
    pub policy: Arc<PolicyEngine>,
    /// The redactor of the job, which is also the secret scanner of the gate.
    pub redactor: Arc<Redactor>,
    /// The check of an agent's output against its own schema.
    pub schemas: Arc<dyn AgentOutputCheck>,
    /// The sandbox spec factory.
    pub specs: Arc<dyn WorkspaceAgentSpecs>,
    /// The runtime probes.
    pub probes: Arc<dyn CapabilityProbes>,
    /// What people answered to the earlier documentation review runs of the job.
    pub answers: Arc<dyn AnswerHistory>,
}

/// The `DOCUMENTATION_REVIEW` handler. See the module notes for what it does.
pub struct DocumentationReviewHandler {
    pub(super) config: DocumentationReviewConfig,
    pub(super) policy: Arc<PolicyEngine>,
    pub(super) redactor: Arc<Redactor>,
    pub(super) schemas: Arc<dyn AgentOutputCheck>,
    pub(super) specs: Arc<dyn WorkspaceAgentSpecs>,
    pub(super) probes: Arc<dyn CapabilityProbes>,
    pub(super) answers: Arc<dyn AnswerHistory>,
}

impl DocumentationReviewHandler {
    /// A handler over its collaborators.
    #[must_use]
    pub fn new(config: DocumentationReviewConfig, deps: DocumentationReviewDeps) -> Self {
        Self {
            config,
            policy: deps.policy,
            redactor: deps.redactor,
            schemas: deps.schemas,
            specs: deps.specs,
            probes: deps.probes,
            answers: deps.answers,
        }
    }
}

fn resolve(
    config: &DocumentationReviewConfig,
    ctx: &ContractContext<'_>,
) -> Result<StageContract, StageError> {
    let retrieved = ctx.now.as_text();
    let missing = || StageError::Blocked(BlockedCode::DependencyUnavailable);
    let mut inputs = Vec::new();
    for (kind, name, description, trust) in [
        (
            StageKind::Implementation,
            IMPLEMENTATION_RESULT,
            "The base commit and the head commit of the code under documentation.",
            "trusted_internal",
        ),
        (
            StageKind::Specification,
            SPECIFICATION_CONTRACT,
            "The frozen specification the documents are judged against.",
            "untrusted",
        ),
        (
            StageKind::Documenting,
            DOCUMENTATION_PLAN,
            "The documentation plan: the pages the change needs, or the rule that says none.",
            "trusted_internal",
        ),
        (
            StageKind::Documenting,
            DOCUMENTATION_RESULT,
            "The documentation commit and the paths it changed, as the host measured them.",
            "trusted_internal",
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
    // The project's rules for agents (ADR 0026), given to the documentation reviewer.
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
    let gates = gate_ids();
    let criteria: Vec<_> = gates
        .iter()
        .map(|gate| {
            json!({
                "id": format!("{gate}-holds"),
                "description": format!("The gate {gate} passed or does not apply."),
                "machine_verifiable": true,
                "verification": { "kind": "gate", "ref": gate },
            })
        })
        .collect();
    let budget = &config.budget;
    let document = json!({
        "schema_version": 1,
        "metadata": {
            "contract_id": "stage-contract.documentation-review",
            "contract_version": "1.0.0",
            "stage_kind": "DOCUMENTATION_REVIEW",
            "job_id": ctx.identity.job.to_string(),
            "stage_run_id": ctx.identity.stage_run.to_string(),
            "execution_mode": ctx.mode.as_str(),
            "created_at": retrieved,
            "domain_profiles": [{ "id": "general-software", "version": 1 }],
        },
        "title": "Check the documents and have them reviewed",
        "purpose": "Run the Documentation Quality Gate over the documents in a fresh verify sandbox, then have an independent reviewer judge them against the frozen specification, the plan, both diffs and the gate reports.",
        "problem_statement": "The documents were written by an agent. Code decides what code can decide: links, examples, names, coverage, secrets and staleness. An independent reviewer judges what code cannot, and it never sees what the writer says about its own work. A failed gate decides first, and a reviewer cannot overrule it.",
        "inputs": inputs,
        "preconditions": [{
            "id": "documenting-passed",
            "description": "The documenting stage run passed and produced a plan and a result.",
            "check": "upstream_stage_passed",
        }],
        "risk": {
            "tier": "low",
            "rationale": "The gate runs in a sandbox with no network, over a read-only checkout. The reviewer has tools that only read and its checkout is a copy that is never ingested.",
            "domains": ["general-software"],
        },
        "methods": [{
            "name": "Deterministic checks in a sandbox, then an independent reviewer",
            "rationale": "Examples run against the built program and names are compared with its help output, so a page cannot claim what the code does not do. The reviewer's prompt is assembled from inputs that cannot be a writer summary.",
            "alternatives_considered": [{
                "name": "Show the reviewer the writer's summary to save time",
                "why_not": "A summary written by the author frames the documents as correct before the reviewer has read them.",
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
                "name": DOCUMENTATION_GATE_REPORT,
                "description": "The reports of the Documentation Quality Gate and the readability gate, with the commits they are about.",
                "media_type": "application/json",
                "required": true,
            },
            {
                "name": DOCUMENTATION_REVIEW,
                "description": "The stored review verdict, with the findings deduplicated and identified by the factory.",
                "media_type": "application/json",
                "required": false,
            },
            {
                "name": DOCUMENTATION_REVIEW_RECORD,
                "description": "What the reviewer was given, by name, class and hash, and what it returned.",
                "media_type": "application/json",
                "required": true,
            },
        ],
        "acceptance_criteria": criteria,
        "evaluator": {
            "kind": "gate_and_reviewer",
            "gate_ids": gates,
            "reviewer_agent": { "id": config.agent.as_str(), "version": config.agent_version },
            "reviewer_must_not_see": ["builder_self_assessment", "builder_transcript"],
        },
        "evidence_refs": [],
        "confidence": {
            "level": "medium",
            "notes": "The gate reports are the factory's own measurements. The verdict is an agent's opinion, and a failed gate outweighs it.",
        },
        "assumptions": [],
        "budget": {
            "max_wall_time_seconds": budget.wall_time_seconds,
            "max_tokens": budget.max_tokens,
            "max_cost_usd": budget.max_cost_usd,
            "max_compute": { "cpu_millicores": 2000, "memory_mb": 4096, "disk_mb": 4096 },
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
            "rollback": "The stage writes reports and a verdict and changes nothing else, so there is nothing to undo.",
            "escalate_to": "approver",
            "on": ["needs_human_verdict", "blocked", "rework_limit_reached", "stagnation_detected", "budget_exceeded"],
        },
        "telemetry": {
            "span_name": "stage.documentation_review",
            "attributes": ["job.id", "stage.run.id", "stage.kind"],
            "metrics": ["stage.duration"],
        },
    });
    StageContract::from_json_value(document).map_err(|_| StageError::Internal)
}

#[async_trait]
impl StageHandler for DocumentationReviewHandler {
    fn fidelity(&self) -> Fidelity {
        // A stand-in for either collaborator makes the whole handler a stand-in.
        if [self.schemas.fidelity(), self.answers.fidelity()].contains(&Fidelity::Fake) {
            Fidelity::Fake
        } else {
            Fidelity::Real
        }
    }

    fn kind(&self) -> StageKind {
        StageKind::DocumentationReview
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
