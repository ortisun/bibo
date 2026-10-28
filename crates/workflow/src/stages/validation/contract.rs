//! The stage contract of the validation stage.
//!
//! The contract is resolved once per stage run, from the stage runs before it and the policy in
//! force. It binds the run to the hash of the implementation result and the hash of the policy
//! bundle by naming them as inputs, so a different commit or a changed policy gives a different
//! contract, and the evidence binding compares the reports with these two values.

use factory_domain::contracts::{Contract, StageContract};
use serde_json::{Value, json};

use super::input::{IMPLEMENTATION_RESULT, SPECIFICATION_CONTRACT, upstream_output};
use crate::gates::command::gate_id;
use crate::gates::supply_chain::report::gate as supply_chain_gate;
use crate::handlers::{ContractContext, StageError};
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::vocabulary::StageKind;

/// The name of the input that carries the hash of the policy bundle.
pub const POLICY_INPUT: &str = "policy-bundle";

/// The name of the deliverable that holds the reports and the binding.
pub const EVIDENCE: &str = "validation-evidence";

/// Every gate of the stage, in the order the reports are written. The stage always writes a
/// report for each: a gate that does not apply, or cannot run, still says so.
pub const GATES: [(&str, &str); 9] = [
    (
        gate_id::FORMAT,
        "The code is formatted as the project requires.",
    ),
    (
        gate_id::LINT,
        "The linter finds nothing that the project forbids.",
    ),
    (
        gate_id::BUILD,
        "The project builds from the candidate commit.",
    ),
    (
        gate_id::UNIT_TESTS,
        "The tests run, and every one that ran passed.",
    ),
    (
        gate_id::PROTECTED_PATHS,
        "The change touches no protected path, hidden path or unsafe link.",
    ),
    (
        gate_id::TEST_PROTECTION,
        "No existing test was removed, ignored, skipped or weakened.",
    ),
    (
        gate_id::SECRET_SCAN,
        "The lines the change adds hold no secret.",
    ),
    (
        gate_id::ACCEPTANCE,
        "Every requirement of the frozen specification has a passed covering test.",
    ),
    (
        gate_id::EVIDENCE_BINDING,
        "The evidence is about this commit, this policy, this image and these definitions.",
    ),
];

/// The gates of the dependency and supply chain package, in report order. The stage makes a report
/// for each of them on every run: a change that touches no dependency file gets four reports that
/// say nothing applies, and a gate that cannot run says what is missing.
pub const SUPPLY_CHAIN_GATES: [(&str, &str); 4] = [
    (
        supply_chain_gate::INTEGRITY,
        "The dependency files agree with the base commit: no changed source, checksum, patch or build configuration.",
    ),
    (
        supply_chain_gate::REVIEW,
        "Every new direct dependency has a recorded human decision, and the packages that came in are licensed.",
    ),
    (
        supply_chain_gate::ADVISORIES,
        "No known advisory applies to the locked packages, according to a recent advisory database.",
    ),
    (
        supply_chain_gate::SBOM,
        "A software bill of materials was made when the job requires one.",
    ),
];

/// Resolves the contract.
///
/// # Errors
/// [`StageError::Blocked`] when the implementation run produced no result to verify.
pub fn resolve(ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
    let (implementation, result) = upstream_output(
        ctx.upstream,
        StageKind::Implementation,
        IMPLEMENTATION_RESULT,
    )
    .ok_or(StageError::Blocked(BlockedCode::DependencyUnavailable))?;
    let retrieved = ctx.now.as_text();
    let mut inputs = vec![
        json!({
            "name": IMPLEMENTATION_RESULT,
            "description": "The base commit and the candidate commit, written by the factory after it committed the audited change on the host.",
            "artifact": { "sha256": result.sha256.as_str(), "media_type": result.media_type.as_str() },
            "provenance": {
                "source": "previous_stage",
                "produced_by_stage_run_id": implementation.id.to_string(),
                "retrieved_at": retrieved,
            },
            "trust": "trusted_internal",
        }),
        json!({
            "name": POLICY_INPUT,
            "description": "The hash of the policy bundle in force when the stage run was resolved.",
            "artifact": { "sha256": ctx.policy_hash.as_str(), "media_type": "application/json" },
            "provenance": { "source": "policy", "retrieved_at": retrieved },
            "trust": "trusted_internal",
        }),
    ];
    if let Some((specification, contract)) = upstream_output(
        ctx.upstream,
        StageKind::Specification,
        SPECIFICATION_CONTRACT,
    ) {
        inputs.push(json!({
            "name": SPECIFICATION_CONTRACT,
            "description": "The frozen specification, read only for its requirement and scenario identifiers.",
            "artifact": { "sha256": contract.sha256.as_str(), "media_type": contract.media_type.as_str() },
            "provenance": {
                "source": "previous_stage",
                "produced_by_stage_run_id": specification.id.to_string(),
                "retrieved_at": retrieved,
            },
            "trust": "untrusted",
        }));
    }

    let criteria: Vec<Value> = GATES
        .iter()
        .chain(SUPPLY_CHAIN_GATES.iter())
        .map(|(gate, description)| {
            json!({
                "id": format!("{gate}-passes"),
                "description": description,
                "machine_verifiable": true,
                "verification": { "kind": "gate", "ref": gate },
            })
        })
        .collect();
    let gate_ids: Vec<&str> = GATES
        .iter()
        .chain(SUPPLY_CHAIN_GATES.iter())
        .map(|(gate, _)| *gate)
        .collect();

    let document = json!({
        "schema_version": 1,
        "metadata": {
            "contract_id": "stage-contract.validation",
            "contract_version": "1.0.0",
            "stage_kind": "VALIDATION",
            "job_id": ctx.identity.job.to_string(),
            "stage_run_id": ctx.identity.stage_run.to_string(),
            "execution_mode": ctx.mode.as_str(),
            "created_at": retrieved,
            "domain_profiles": [{ "id": "general-software", "version": 1 }],
        },
        "title": "Verify the change with the trusted gates",
        "purpose": "Run the gates that the protected base commit defines against the candidate commit in a fresh verify container, and record what the supervisor observed.",
        "problem_statement": "The builder says the work is done. Only evidence that the factory measured itself can show it, so the gates run from the base commit's definitions, in a container the builder never used, and the supervisor's own observation of each exit code is the result.",
        "inputs": inputs,
        "preconditions": [
            {
                "id": "implementation-passed",
                "description": "The implementation stage run passed and named the candidate commit.",
                "check": "upstream_stage_passed",
            },
            {
                "id": "verify-image-available",
                "description": "The pinned verify image is on the host and the container runtime answers.",
                "check": "tool_available",
            },
        ],
        "risk": {
            "tier": "low",
            "rationale": "The stage only reads the candidate commit in a read-only workspace with no network, and it writes evidence.",
        },
        "methods": [{
            "name": "Trusted gates in a fresh verify container",
            "rationale": "The definitions come from the protected base commit and the commands run in a container made for this stage run, so the builder can change neither the commands nor the place they run in.",
            "alternatives_considered": [{
                "name": "Read the gate results the builder produced",
                "why_not": "A result the builder wrote is a claim, not evidence, and test code can detect that it is under test.",
            }],
            "escalation_trigger": "Ask a person when a protected path changed, a test was weakened, a secret was found or the evidence is not about this commit.",
        }],
        "capabilities": {
            "agent_manifest": { "id": "trusted-gate-runner", "version": "1.0.0" },
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
            "name": EVIDENCE,
            "description": "The gate reports, one for each gate, and the evidence binding.",
            "media_type": "application/json",
            "required": true,
        }],
        "acceptance_criteria": criteria,
        "evaluator": { "kind": "deterministic_gate", "gate_ids": gate_ids },
        "evidence_refs": [],
        "confidence": {
            "level": "high",
            "notes": "Every result is the supervisor's observation of a command or a rule applied by the control plane to the committed trees.",
        },
        "assumptions": [],
        "budget": {
            "max_wall_time_seconds": 3600,
            "max_tokens": 0,
            "max_cost_usd": 0,
            "max_compute": { "cpu_millicores": 2000, "memory_mb": 2048, "disk_mb": 2048 },
        },
        "timeout_and_retries": {
            "attempt_timeout_seconds": 3600,
            "max_attempts": 2,
            "backoff": { "initial_ms": 5000, "max_ms": 60000, "jitter": "full" },
            "retry_on": ["TOOL_ERROR", "SANDBOX_ERROR", "TIMED_OUT", "LEASE_LOST"],
            "max_rework_iterations": 2,
        },
        "idempotency": {
            "key_scheme": "stage_run_id plus the hashes of all input artifacts",
            "side_effects": "none",
        },
        "escalation": {
            "rollback": "Nothing outside the verify container and the evidence store is changed, so there is nothing to undo.",
            "escalate_to": "operator",
            "on": ["blocked", "policy_violation", "rework_limit_reached"],
        },
        "telemetry": {
            "span_name": "stage.validation",
            "attributes": ["job.id", "stage.run.id", "stage.kind"],
            "metrics": ["stage.duration"],
        },
    });
    StageContract::from_json_value(document).map_err(|_| StageError::Internal)
}
