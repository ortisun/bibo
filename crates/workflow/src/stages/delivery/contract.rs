//! The stage contract of the delivery stage.
//!
//! The contract names every stored document the stage builds on as an input, with its hash, and
//! the hash of the policy bundle. A different document or a changed policy therefore gives a
//! different contract, and `execute` reads each document by the hash recorded here.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::{Contract, StageContract};
use serde_json::{Value, json};

use super::input::{POLICY_INPUT, SOURCES, upstream_output};
use crate::gates::readability::GATE_ID as READABILITY_GATE;
use crate::handlers::{ContractContext, StageError};

/// The deliverable that holds the evidence manifest.
pub const MANIFEST: &str = "evidence-manifest";
/// The deliverable that holds what the stage did: the pull request, the text and the checks.
pub const RESULT: &str = "delivery-result";
/// The gate that reads the pull request back from the code host.
pub const PULL_REQUEST_GATE: &str = "delivery-pull-request";
/// The gate that checks the stored manifest against its contract and its hash.
pub const MANIFEST_GATE: &str = "delivery-manifest";

/// Every gate of the stage.
pub const GATES: [(&str, &str); 3] = [
    (
        PULL_REQUEST_GATE,
        "The pull request exists, is a draft, is open, and points at the delivered commit.",
    ),
    (
        MANIFEST_GATE,
        "The evidence manifest follows its contract and its hash is the one in the pull request body.",
    ),
    (
        READABILITY_GATE,
        "The title and the body of the pull request are plain English and follow the readability rules.",
    ),
];

/// Resolves the contract.
///
/// # Errors
/// [`StageError::Blocked`] when an earlier stage produced no document that this stage reads.
pub fn resolve(ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
    let retrieved = ctx.now.as_text();
    let mut inputs: Vec<Value> = Vec::new();
    for (kind, name) in SOURCES {
        let (run, artifact) = upstream_output(ctx.upstream, kind, name)
            .ok_or(StageError::Blocked(BlockedCode::DependencyUnavailable))?;
        inputs.push(json!({
            "name": name,
            "description": format!("The deliverable {name} of an earlier stage, stored by the engine."),
            "artifact": { "sha256": artifact.sha256.as_str(), "media_type": artifact.media_type.as_str() },
            "provenance": {
                "source": "previous_stage",
                "produced_by_stage_run_id": run.id.to_string(),
                "retrieved_at": retrieved,
            },
            "trust": "trusted_internal",
        }));
    }
    inputs.push(json!({
        "name": POLICY_INPUT,
        "description": "The hash of the policy bundle in force when the stage run was resolved.",
        "artifact": { "sha256": ctx.policy_hash.as_str(), "media_type": "application/json" },
        "provenance": { "source": "policy", "retrieved_at": retrieved },
        "trust": "trusted_internal",
    }));

    let criteria: Vec<Value> = GATES
        .iter()
        .map(|(gate, description)| {
            json!({
                "id": format!("{gate}-passes"),
                "description": description,
                "machine_verifiable": true,
                "verification": { "kind": "gate", "ref": gate },
            })
        })
        .collect();
    let gate_ids: Vec<&str> = GATES.iter().map(|(gate, _)| *gate).collect();

    let document = json!({
        "schema_version": 1,
        "metadata": {
            "contract_id": "stage-contract.delivery",
            "contract_version": "1.0.0",
            "stage_kind": "DELIVERY",
            "job_id": ctx.identity.job.to_string(),
            "stage_run_id": ctx.identity.stage_run.to_string(),
            "execution_mode": ctx.mode.as_str(),
            "created_at": retrieved,
            "domain_profiles": [{ "id": "general-software", "version": 1 }],
        },
        "title": "Open the draft pull request with the evidence",
        "purpose": "Push the job branch, open a draft pull request whose body is written from the stored evidence, and publish the gate results as check runs. Nothing is merged and nothing is deployed.",
        "problem_statement": "A person decides whether the change is merged. They need one place that holds the change, the evidence behind it and an honest list of what was not verified, written in plain English from facts the factory measured and not from any agent's account.",
        "inputs": inputs,
        "preconditions": [
            {
                "id": "documentation-review-passed",
                "description": "Every earlier stage run passed and produced the documents this stage reads.",
                "check": "upstream_stage_passed",
            },
            {
                "id": "evidence-binding-holds",
                "description": "The base commit, the gate definitions, the policy and the image are the ones the gate reports were made for.",
                "check": "policy_allows",
            },
        ],
        "risk": {
            "tier": "medium",
            "rationale": "The stage writes to the code host: it pushes a factory branch and opens a draft pull request. It cannot merge, mark ready or deploy.",
        },
        "methods": [{
            "name": "Typed evidence into a template",
            "rationale": "Every sentence is written by the control plane from stored documents, so a model cannot put text, links or images into the pull request.",
            "alternatives_considered": [{
                "name": "Ask a model to write the pull request description",
                "why_not": "Model text can carry a hidden instruction, a link that leaks data or a claim the evidence does not support.",
            }],
            "escalation_trigger": "Ask a person when the evidence changed after the gates ran, when the text fails the readability gate or when the branch cannot be pushed as a fast-forward.",
        }],
        "capabilities": {
            "agent_manifest": { "id": "delivery-control-plane", "version": "1.0.0" },
            "granted_tools": [],
            "permissions": {
                "filesystem_read": ["**"],
                "filesystem_write": [],
                "network": "none",
                "shell": "none",
            },
            "placement": "not_applicable",
        },
        "deliverables": [
            {
                "name": MANIFEST,
                "description": "The evidence manifest, by content hash.",
                "media_type": "application/json",
                "required": true,
            },
            {
                "name": RESULT,
                "description": "The pull request, the text sent, the commits and the check runs.",
                "media_type": "application/json",
                "required": true,
            },
        ],
        "acceptance_criteria": criteria,
        "evaluator": { "kind": "deterministic_gate", "gate_ids": gate_ids },
        "evidence_refs": [],
        "confidence": {
            "level": "high",
            "notes": "Every fact comes from a stored document, a read of the code host or a rule applied by the control plane.",
        },
        "assumptions": [],
        "budget": {
            "max_wall_time_seconds": 600,
            "max_tokens": 0,
            "max_cost_usd": 0,
            "max_compute": { "cpu_millicores": 500, "memory_mb": 256, "disk_mb": 256 },
        },
        "timeout_and_retries": {
            "attempt_timeout_seconds": 600,
            "max_attempts": 3,
            "backoff": { "initial_ms": 5000, "max_ms": 60000, "jitter": "full" },
            "retry_on": ["TOOL_ERROR", "PROVIDER_ERROR", "TIMED_OUT", "LEASE_LOST"],
            "max_rework_iterations": 2,
        },
        "idempotency": {
            "key_scheme": "stage_run_id plus the hashes of all input artifacts. A push of a commit already on the branch changes nothing, the code host returns the open pull request for the same head branch, and it updates a check run for the same commit, name and external id, so a repeat makes no second pull request and no second check run.",
            "side_effects": "external_write",
            "compensating_action": "A person closes the draft pull request and deletes the factory branch on the code host. The factory deletes neither.",
        },
        "escalation": {
            "rollback": "The branch and the draft pull request stay. A person closes the pull request and deletes the branch; the factory never deletes either.",
            "escalate_to": "operator",
            "on": ["blocked", "policy_violation", "rework_limit_reached"],
        },
        "telemetry": {
            "span_name": "stage.delivery",
            "attributes": ["job.id", "stage.run.id", "stage.kind"],
            "metrics": ["stage.duration"],
        },
    });
    StageContract::from_json_value(document).map_err(|_| StageError::Internal)
}
