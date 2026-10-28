//! The stage contract of the approval stage.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::{Contract, StageContract};
use factory_domain::vocabulary::StageKind;
use serde_json::{Value, json};

use crate::handlers::{ContractContext, StageError};
use crate::stages::delivery::contract::{MANIFEST, RESULT as DELIVERY_RESULT};
use crate::stages::delivery::input::{
    DOCUMENTATION_GATE, DOCUMENTATION_PLAN, POLICY_INPUT, VALIDATION_EVIDENCE, upstream_output,
};

/// The deliverable: what the person is asked to decide.
pub const REQUEST: &str = "approval-request";
/// The gate report of the stage.
pub const GATE: &str = "approval-evidence-clear";

/// Which stage produces each input, in the order the contract lists them. The documentation plan
/// is here for its hash: the reports of the documentation gate are bound to it, and the stage
/// compares the two.
pub const SOURCES: [(StageKind, &str); 5] = [
    (StageKind::Delivery, DELIVERY_RESULT),
    (StageKind::Delivery, MANIFEST),
    (StageKind::Validation, VALIDATION_EVIDENCE),
    (StageKind::Documenting, DOCUMENTATION_PLAN),
    (StageKind::DocumentationReview, DOCUMENTATION_GATE),
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

    let document = json!({
        "schema_version": 1,
        "metadata": {
            "contract_id": "stage-contract.approval",
            "contract_version": "1.0.0",
            "stage_kind": "APPROVAL",
            "job_id": ctx.identity.job.to_string(),
            "stage_run_id": ctx.identity.stage_run.to_string(),
            "execution_mode": ctx.mode.as_str(),
            "created_at": retrieved,
            "domain_profiles": [{ "id": "general-software", "version": 1 }],
        },
        "title": "Ask a person to approve the draft pull request",
        "purpose": "Show a person exactly what was delivered, bound to the head, tree and base commits and the evidence manifest, and record their decision. Nothing is merged and nothing is deployed.",
        "problem_statement": "Only a person may decide that the change goes on to a merge. The decision must be about the exact commit and evidence the person saw, by someone the allowlist names, who is not the requester when the change is risky.",
        "inputs": inputs,
        "preconditions": [{
            "id": "delivery-passed",
            "description": "The delivery stage run passed and the pull request is an open draft at the delivered commit.",
            "check": "upstream_stage_passed",
        }],
        "risk": {
            "tier": "low",
            "rationale": "The stage reads the pull request and writes a request. The decision is a person's and is recorded by the approval service.",
        },
        "methods": [{
            "name": "Human decision bound to the evidence",
            "rationale": "A person approves a specific head with specific evidence. An approval for anything else does not count.",
            "alternatives_considered": [{
                "name": "Approve by label or by a review state on the code host",
                "why_not": "A label or a review does not name the commit, the tree and the evidence the person saw.",
            }],
            "escalation_trigger": "Ask a person always. Stop and supersede when the evidence changed after the gates ran.",
        }],
        "capabilities": {
            "agent_manifest": { "id": "approval-control-plane", "version": "1.0.0" },
            "granted_tools": [],
            "permissions": {
                "filesystem_read": ["**"],
                "filesystem_write": [],
                "network": "none",
                "shell": "none",
            },
            "placement": "not_applicable",
        },
        "deliverables": [{
            "name": REQUEST,
            "description": "What the person is asked to decide, with the binding they are shown.",
            "media_type": "application/json",
            "required": true,
        }],
        "acceptance_criteria": [
            {
                "id": "evidence-is-clear",
                "description": "Every gate in the evidence passed or does not apply, or was blocked and then decided by a person.",
                "machine_verifiable": true,
                "verification": { "kind": "gate", "ref": GATE },
            },
            {
                "id": "a-person-decides",
                "description": "An authorized person approves the exact head, tree, base and evidence manifest they saw.",
                "machine_verifiable": false,
                "verification": { "kind": "human_decision", "ref": "approve_pr" },
            },
        ],
        "evaluator": { "kind": "human" },
        "evidence_refs": [],
        "confidence": {
            "level": "high",
            "notes": "The request is read from the delivery and the code host; the decision is a person's.",
        },
        "assumptions": [],
        "budget": {
            "max_wall_time_seconds": 600,
            "max_tokens": 0,
            "max_cost_usd": 0,
            "max_compute": { "cpu_millicores": 250, "memory_mb": 128, "disk_mb": 64 },
        },
        "timeout_and_retries": {
            "attempt_timeout_seconds": 600,
            "max_attempts": 3,
            "backoff": { "initial_ms": 5000, "max_ms": 60000, "jitter": "full" },
            "retry_on": ["TOOL_ERROR", "PROVIDER_ERROR", "TIMED_OUT", "LEASE_LOST"],
            "max_rework_iterations": 2,
        },
        "idempotency": {
            "key_scheme": "stage_run_id plus the hashes of all input artifacts",
            "side_effects": "none",
        },
        "escalation": {
            "rollback": "Nothing outside the evidence store is changed, so there is nothing to undo.",
            "escalate_to": "approver",
            "on": ["blocked", "policy_violation", "rework_limit_reached"],
        },
        "telemetry": {
            "span_name": "stage.approval",
            "attributes": ["job.id", "stage.run.id", "stage.kind"],
            "metrics": ["stage.duration"],
        },
    });
    StageContract::from_json_value(document).map_err(|_| StageError::Internal)
}
