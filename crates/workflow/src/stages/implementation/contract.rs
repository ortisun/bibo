//! The stage contract of the implementation stage.
//!
//! The contract is resolved once per stage run from the stage runs before it. It pins the inputs
//! by hash (the plan, the frozen specification, the architecture and the repository map), so a
//! different plan gives a different contract. It declares the sandbox as the only place the
//! builder runs (`placement: sandbox`, which the contract schema requires of this stage), the
//! files the builder may write, no network, and the three gates that judge the stage.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::{Contract, StageContract};
use factory_domain::vocabulary::StageKind;
use serde_json::{Value, json};

use super::handler::ImplementationConfig;
use super::input::{
    ARCHITECTURE, REPOSITORY_MAP, SPECIFICATION_CONTRACT, TASK_PLAN, upstream_output,
};
use crate::gates::command::gate_id;
use crate::handlers::{ContractContext, StageError};

/// The gate that checks every changed path against the files the task owns.
pub const SCOPE_GATE: &str = "implementation-scope";
/// The gate that checks the commits against what the audited ingestion reported.
pub const COMMITS_GATE: &str = "implementation-commits";
/// The gate that reports a change the audit refused. Same id as the validation stage's rule.
pub const PROTECTED_GATE: &str = gate_id::PROTECTED_PATHS;

/// The tools the builder is granted, which are those of its manifest. A test compares the two.
pub const GRANTED_TOOLS: [&str; 6] = [
    "fs.read",
    "fs.list",
    "fs.search",
    "fs.write",
    "exec.run",
    "report.submit",
];

/// The stage run needs these four deliverables of the runs before it.
const NEEDED: [(StageKind, &str, &str); 4] = [
    (
        StageKind::TaskPlanning,
        TASK_PLAN,
        "The validated task plan: the tasks, their order and the files each one owns.",
    ),
    (
        StageKind::Specification,
        SPECIFICATION_CONTRACT,
        "The frozen specification the work must satisfy.",
    ),
    (
        StageKind::Architecture,
        ARCHITECTURE,
        "The approved architecture the work follows.",
    ),
    (
        StageKind::RepositoryIntelligence,
        REPOSITORY_MAP,
        "The repository map, which names the commit the work starts from.",
    ),
];

/// Resolves the contract.
///
/// # Errors
/// [`StageError::Blocked`] when a run before this one did not produce a deliverable the stage
/// needs.
pub fn resolve(
    config: &ImplementationConfig,
    ctx: &ContractContext<'_>,
) -> Result<StageContract, StageError> {
    let retrieved = ctx.now.as_text();
    let mut inputs: Vec<Value> = Vec::with_capacity(NEEDED.len() + 1);
    for (kind, name, description) in NEEDED {
        let (run, artifact) = upstream_output(ctx.upstream, kind, name)
            .ok_or(StageError::Blocked(BlockedCode::DependencyUnavailable))?;
        inputs.push(json!({
            "name": name,
            "description": description,
            "artifact": { "sha256": artifact.sha256.as_str(), "media_type": artifact.media_type.as_str() },
            "provenance": {
                "source": "previous_stage",
                "produced_by_stage_run_id": run.id.to_string(),
                "retrieved_at": retrieved,
            },
            // Written by a model or read from a repository, so it is data to read.
            "trust": "untrusted",
        }));
    }
    // The project's rules for agents (ADR 0026), when the repository stage produced them.
    if let Some(rules) = crate::stages::project_rules::contract_input_json(ctx.upstream, &retrieved)
    {
        inputs.push(rules);
    }
    inputs.push(json!({
        "name": "policy-bundle",
        "description": "The hash of the policy bundle in force when the stage run was resolved.",
        "artifact": { "sha256": ctx.policy_hash.as_str(), "media_type": "application/json" },
        "provenance": { "source": "policy", "retrieved_at": retrieved },
        "trust": "trusted_internal",
    }));

    let gates = [SCOPE_GATE, COMMITS_GATE, PROTECTED_GATE];
    let budget = &config.budget;
    let document = json!({
        "schema_version": 1,
        "metadata": {
            "contract_id": "stage-contract.implementation",
            "contract_version": "1.0.0",
            "stage_kind": "IMPLEMENTATION",
            "job_id": ctx.identity.job.to_string(),
            "stage_run_id": ctx.identity.stage_run.to_string(),
            "execution_mode": ctx.mode.as_str(),
            "created_at": retrieved,
            "domain_profiles": [{ "id": "general-software", "version": 1 }],
        },
        "title": "Build the planned tasks in the sandbox",
        "purpose": "Run the builder over the tasks of the plan, in order, inside a sandbox. Audit what it wrote, commit it on the host, and record the commits and the evidence of each task.",
        "problem_statement": "The plan says what to build. A builder agent edits files in a sandbox, and everything it wrote is hostile until the factory has checked it. The factory ingests the change on the host, refuses a protected path or a secret, makes the commit itself, and names the commits so that the trusted gates and the independent reviewer judge the same change.",
        "inputs": inputs,
        "preconditions": [
            {
                "id": "plan-validated",
                "description": "The task plan passed the planner's validator and the earlier stages passed.",
                "check": "upstream_stage_passed",
            },
            {
                "id": "sandbox-available",
                "description": "The container runtime answers and the agent image is on the host.",
                "check": "tool_available",
            },
        ],
        "risk": {
            "tier": "medium",
            "rationale": "The builder writes code, but only in a sandbox with no network except the model broker. Nothing leaves the job's object store until the gates and the review have passed and a person approves.",
            "domains": ["general-software"],
        },
        "methods": [{
            "name": "One builder over the task graph, audited ingestion, host commit",
            "rationale": "Each task runs in a fresh sandbox over the commit of the task before it. The host audits the tree, refuses what the policy forbids, and makes the commit itself, so no hook, configuration or history the builder wrote ever runs on the host.",
            "alternatives_considered": [{
                "name": "Let the builder commit inside the sandbox",
                "why_not": "A commit made inside the sandbox could carry a hook, a rewritten history or a configuration that runs on the host. The builder has no git directory at all.",
            }],
            "escalation_trigger": "Ask a person when the builder is blocked, needs a decision, asks for a dependency, or the audit refuses its change.",
        }],
        "capabilities": {
            "agent_manifest": { "id": config.agent.as_str(), "version": config.agent_version },
            "granted_tools": GRANTED_TOOLS,
            "permissions": {
                "filesystem_read": ["**"],
                "filesystem_write": ["src/**", "tests/**"],
                "network": "none",
                "shell": "sandboxed_typed_wrapper",
            },
            "placement": "sandbox",
        },
        "deliverables": [
            {
                "name": super::evidence::RESULT,
                "description": "The base commit and the head commit, written by the factory from the commit it made.",
                "media_type": "application/json",
                "required": true,
            },
            {
                "name": super::evidence::EVIDENCE,
                "description": "For each task, the commit, the changed paths, the diff statistics and what the builder says it ran.",
                "media_type": "application/json",
                "required": true,
            },
        ],
        "acceptance_criteria": [
            {
                "id": "changes-inside-owned-files",
                "description": "Every path a task changed is a file that task owns.",
                "machine_verifiable": true,
                "verification": { "kind": "gate", "ref": SCOPE_GATE },
            },
            {
                "id": "commits-match-the-audit",
                "description": "The head commit holds exactly the changes the audited ingestion reported, and it differs from the base.",
                "machine_verifiable": true,
                "verification": { "kind": "gate", "ref": COMMITS_GATE },
            },
            {
                "id": "no-protected-path-changed",
                "description": "The audit refused no change to a protected path, a hidden path, a link or a secret.",
                "machine_verifiable": true,
                "verification": { "kind": "gate", "ref": PROTECTED_GATE },
            },
        ],
        "evaluator": { "kind": "deterministic_gate", "gate_ids": gates },
        "evidence_refs": [],
        "confidence": {
            "level": "medium",
            "notes": "The commits and the changed paths are the host's own measurements. What the builder says about its work is recorded and not counted.",
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
            "rollback": "Nothing leaves the job's object store, so dropping the job's commits undoes the stage.",
            "escalate_to": "approver",
            "on": ["budget_exceeded", "blocked", "policy_violation", "rework_limit_reached"],
        },
        "telemetry": {
            "span_name": "stage.implementation",
            "attributes": ["job.id", "stage.run.id", "stage.kind"],
            "metrics": ["stage.duration"],
        },
    });
    StageContract::from_json_value(document).map_err(|_| StageError::Internal)
}
