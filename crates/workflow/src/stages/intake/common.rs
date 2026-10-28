//! What both stages of this package build the same way: the stage contract, and the gate reports
//! of the gates that are not the readability gate.
//!
//! Both are assembled as JSON documents and read back through the typed contracts of
//! `factory-domain`, so a contract or a report that breaks a rule of its schema is refused here and
//! never reaches the engine.

use factory_domain::contracts::{Contract, GateReport, StageContract};
use factory_domain::ids::{AttemptId, GateReportId, JobId, StageRunId};
use factory_domain::values::{GitSha, Sha256Digest, Timestamp};
use factory_domain::vocabulary::{ExecutionMode, StageKind};
use serde_json::{Value, json};

use crate::handlers::StageError;

/// One input of a stage contract.
#[derive(Debug, Clone)]
pub struct ContractInput {
    /// The name of the input, a slug.
    pub name: &'static str,
    /// What it is, in a sentence.
    pub description: &'static str,
    /// The stored bytes.
    pub sha256: Sha256Digest,
    /// Their media type.
    pub media_type: &'static str,
    /// `untrusted_external`, `previous_stage` and the other sources of the contract schema.
    pub source: &'static str,
    /// The stage run that made it, for `previous_stage`.
    pub produced_by: Option<StageRunId>,
    /// The commit it was read at, for `repository`.
    pub commit_sha: Option<String>,
    /// When it was read.
    pub retrieved_at: Timestamp,
    /// `untrusted` or `trusted_internal`.
    pub trust: &'static str,
}

/// One deliverable of a stage contract.
#[derive(Debug, Clone, Copy)]
pub struct ContractDeliverable {
    /// The name, a slug.
    pub name: &'static str,
    /// What it is.
    pub description: &'static str,
    /// Its media type.
    pub media_type: &'static str,
    /// Whether the stage must produce it.
    pub required: bool,
}

/// One acceptance criterion, verified by a gate.
#[derive(Debug, Clone, Copy)]
pub struct ContractCriterion {
    /// The identifier.
    pub id: &'static str,
    /// What must hold.
    pub description: &'static str,
    /// The gate whose report decides it.
    pub gate: &'static str,
}

/// Everything that makes one stage's contract differ from another's.
#[derive(Debug, Clone)]
pub struct ContractSpec {
    /// The stage.
    pub kind: StageKind,
    /// The stage run, the job and the mode.
    pub job: JobId,
    /// The stage run.
    pub stage_run: StageRunId,
    /// Test mode or production mode.
    pub mode: ExecutionMode,
    /// When the engine asked.
    pub created_at: Timestamp,
    /// `stage-contract.intake`.
    pub contract_id: &'static str,
    /// The title, in plain English.
    pub title: &'static str,
    /// Why the stage exists.
    pub purpose: &'static str,
    /// The problem it solves, in plain English.
    pub problem: &'static str,
    /// The inputs, at least one.
    pub inputs: Vec<ContractInput>,
    /// The preconditions as `(id, description, check)`.
    pub preconditions: Vec<(&'static str, &'static str, &'static str)>,
    /// The name of the method and why.
    pub method: (&'static str, &'static str, &'static str, &'static str),
    /// The agent manifest and version, or the component that stands in for one.
    pub agent: (String, &'static str),
    /// The tools the stage grants, a subset of the manifest's.
    pub granted_tools: Vec<&'static str>,
    /// `none` or `sandboxed_typed_wrapper`.
    pub shell: &'static str,
    /// `sandbox` or none.
    pub placement: Option<&'static str>,
    /// What the stage produces.
    pub deliverables: Vec<ContractDeliverable>,
    /// How each is judged.
    pub criteria: Vec<ContractCriterion>,
    /// The gates of the evaluator.
    pub gates: Vec<&'static str>,
    /// Limits.
    pub budget: ContractBudget,
    /// The rollback sentence.
    pub rollback: &'static str,
    /// The span name, from the observability conventions.
    pub span_name: &'static str,
}

/// The numbers of a contract.
#[derive(Debug, Clone, Copy)]
pub struct ContractBudget {
    /// Wall time for the whole stage run.
    pub wall_time_seconds: u32,
    /// Tokens.
    pub max_tokens: u32,
    /// Cost in US dollars.
    pub max_cost_usd: f64,
    /// Time for one attempt.
    pub attempt_timeout_seconds: u32,
    /// Attempts.
    pub max_attempts: u32,
}

/// Builds the contract of a stage.
///
/// # Errors
/// [`StageError::Internal`] when the document breaks a rule of the contract schema. That is a
/// fault in the code that called, and a test of every stage proves it does not happen.
pub fn stage_contract(spec: &ContractSpec) -> Result<StageContract, StageError> {
    let inputs: Vec<Value> = spec
        .inputs
        .iter()
        .map(|input| {
            let mut provenance = json!({
                "source": input.source,
                "retrieved_at": input.retrieved_at,
            });
            if let (Some(run), Some(map)) = (input.produced_by, provenance.as_object_mut()) {
                map.insert("produced_by_stage_run_id".into(), json!(run.to_string()));
            }
            if let (Some(sha), Some(map)) = (&input.commit_sha, provenance.as_object_mut()) {
                map.insert("commit_sha".into(), json!(sha));
            }
            json!({
                "name": input.name,
                "description": input.description,
                "artifact": { "sha256": input.sha256, "media_type": input.media_type },
                "provenance": provenance,
                "trust": input.trust,
            })
        })
        .collect();
    let preconditions: Vec<Value> = spec
        .preconditions
        .iter()
        .map(|(id, description, check)| {
            json!({ "id": id, "description": description, "check": check })
        })
        .collect();
    let deliverables: Vec<Value> = spec
        .deliverables
        .iter()
        .map(|d| {
            json!({
                "name": d.name,
                "description": d.description,
                "media_type": d.media_type,
                "required": d.required,
            })
        })
        .collect();
    let criteria: Vec<Value> = spec
        .criteria
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "description": c.description,
                "machine_verifiable": true,
                "verification": { "kind": "gate", "ref": c.gate },
            })
        })
        .collect();
    let mut capabilities = json!({
        "agent_manifest": { "id": spec.agent.0, "version": spec.agent.1 },
        "granted_tools": spec.granted_tools,
        "permissions": {
            "filesystem_read": [],
            "filesystem_write": [],
            "network": "none",
            "shell": spec.shell,
        },
    });
    if let (Some(placement), Some(map)) = (spec.placement, capabilities.as_object_mut()) {
        map.insert("placement".into(), json!(placement));
    }
    let document = json!({
        "schema_version": 1,
        "metadata": {
            "contract_id": spec.contract_id,
            "contract_version": "1.0.0",
            "stage_kind": spec.kind.as_str(),
            "job_id": spec.job.to_string(),
            "stage_run_id": spec.stage_run.to_string(),
            "execution_mode": spec.mode.as_str(),
            "created_at": spec.created_at,
            "domain_profiles": [{ "id": "general-software", "version": 1 }],
        },
        "title": spec.title,
        "purpose": spec.purpose,
        "problem_statement": spec.problem,
        "inputs": inputs,
        "preconditions": preconditions,
        "risk": {
            "tier": "low",
            "rationale": "The stage reads text and a repository and changes nothing. The policy engine computes the risk tier of the job later from facts.",
            "domains": ["general-software"],
        },
        "methods": [{
            "name": spec.method.0,
            "rationale": spec.method.1,
            "alternatives_considered": [{ "name": spec.method.2, "why_not": spec.method.3 }],
            "escalation_trigger": "Ask a person when the stage cannot decide on facts alone.",
        }],
        "capabilities": capabilities,
        "deliverables": deliverables,
        "acceptance_criteria": criteria,
        "evaluator": { "kind": "deterministic_gate", "gate_ids": spec.gates },
        "evidence_refs": [],
        "confidence": {
            "level": "medium",
            "notes": "The stage records what it saw and decides nothing it cannot show.",
        },
        "assumptions": [],
        "budget": {
            "max_wall_time_seconds": spec.budget.wall_time_seconds,
            "max_tokens": spec.budget.max_tokens,
            "max_cost_usd": spec.budget.max_cost_usd,
            "max_compute": { "cpu_millicores": 1000, "memory_mb": 1024, "disk_mb": 512 },
        },
        "timeout_and_retries": {
            "attempt_timeout_seconds": spec.budget.attempt_timeout_seconds,
            "max_attempts": spec.budget.max_attempts,
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
            "rollback": spec.rollback,
            "escalate_to": "approver",
            "on": ["budget_exceeded", "needs_human_verdict"],
        },
        "telemetry": {
            "span_name": spec.span_name,
            "attributes": ["job.id", "stage.run.id", "stage.kind"],
            "metrics": ["stage.duration"],
        },
    });
    StageContract::from_json_value(document).map_err(|_| StageError::Internal)
}

/// How a gate ran, for its report.
#[derive(Debug, Clone)]
pub enum Executor {
    /// Code in the control plane.
    InProcess,
    /// Commands in a sandbox: its identity as the supervisor reports it.
    Sandbox {
        /// The sandbox id.
        sandbox_id: String,
        /// The image, by digest.
        image_digest: Sha256Digest,
        /// The network the sandbox had.
        network: &'static str,
    },
}

/// Which gate, and from what definition.
#[derive(Debug, Clone)]
pub struct GateDefinition {
    /// The gate id, a slug.
    pub id: &'static str,
    /// Its version.
    pub version: &'static str,
    /// The text of the definition, hashed into the report.
    pub text: &'static str,
    /// The commit of the definition in the factory repository.
    pub commit: GitSha,
}

/// The facts of one gate report.
#[derive(Debug, Clone)]
pub struct GateFacts {
    /// The gate.
    pub definition: GateDefinition,
    /// `PASSED`, `FAILED` or `BLOCKED`.
    pub outcome: &'static str,
    /// A title in plain English.
    pub title: String,
    /// Why, in plain English.
    pub reason: String,
    /// The checks that failed: id and message.
    pub failures: Vec<(String, String)>,
    /// For `BLOCKED`: the code and what was missing.
    pub blocked: Option<(&'static str, String)>,
    /// `real` or `fake`: what produced the facts. A gate that read a fake sandbox says so.
    pub fidelity: &'static str,
    /// How the gate ran.
    pub executor: Executor,
    /// The commands it ran, as JSON objects of the report schema.
    pub commands: Vec<Value>,
    /// Tool versions, as `(tool, version)`.
    pub tools: Vec<(String, String)>,
    /// The lines the evidence hash covers.
    pub evidence: Vec<String>,
}

/// Who the report is about.
#[derive(Debug, Clone, Copy)]
pub struct GateSubject {
    /// The job.
    pub job: JobId,
    /// The stage run.
    pub stage_run: StageRunId,
    /// The attempt.
    pub attempt: AttemptId,
    /// The mode.
    pub mode: ExecutionMode,
    /// The new report's id.
    pub report_id: GateReportId,
    /// When the gate started.
    pub started_at: Timestamp,
    /// When it finished.
    pub finished_at: Timestamp,
}

/// Builds a gate report.
///
/// # Errors
/// [`StageError::Internal`] when the report breaks a rule of the gate report schema.
pub fn gate_report(subject: &GateSubject, facts: &GateFacts) -> Result<GateReport, StageError> {
    let mut evidence = String::from("factory-stage-evidence-v1\n");
    for line in &facts.evidence {
        evidence.push_str(line);
        evidence.push('\n');
    }
    let environment = match &facts.executor {
        Executor::InProcess => json!({
            "fidelity": facts.fidelity,
            "executor_kind": "in_process",
            "tool_versions": facts.tools.iter()
                .map(|(tool, version)| json!({ "tool": tool, "version": version }))
                .collect::<Vec<_>>(),
        }),
        Executor::Sandbox {
            sandbox_id,
            image_digest,
            network,
        } => json!({
            "fidelity": facts.fidelity,
            "executor_kind": "sandbox_command",
            "sandbox": {
                "sandbox_id": sandbox_id,
                "image_digest": image_digest,
                "os": "linux",
                "arch": "unknown",
                "network": network,
            },
            "tool_versions": facts.tools.iter()
                .map(|(tool, version)| json!({ "tool": tool, "version": version }))
                .collect::<Vec<_>>(),
        }),
    };
    let mut document = json!({
        "schema_version": 1,
        "metadata": {
            "gate_report_id": subject.report_id.to_string(),
            "gate_id": facts.definition.id,
            "gate_version": facts.definition.version,
            "job_id": subject.job.to_string(),
            "stage_run_id": subject.stage_run.to_string(),
            "attempt_id": subject.attempt.to_string(),
            "execution_mode": subject.mode.as_str(),
            "trusted_definition": {
                "source": "central_config",
                "commit_sha": facts.definition.commit.as_str(),
                "definition_sha256": Sha256Digest::of(facts.definition.text.as_bytes()),
            },
        },
        "title": facts.title,
        "outcome": facts.outcome,
        "reason": facts.reason,
        "started_at": subject.started_at,
        "finished_at": subject.finished_at,
        "environment": environment,
        "commands": facts.commands,
        "evidence_hash": Sha256Digest::of(evidence.as_bytes()),
        "baseline_comparison": { "delta": "not_compared" },
    });
    if let Some(map) = document.as_object_mut() {
        if facts.outcome == "FAILED" {
            map.insert(
                "failures".into(),
                json!(
                    facts
                        .failures
                        .iter()
                        .map(|(id, message)| json!({ "check_id": id, "message": message }))
                        .collect::<Vec<_>>()
                ),
            );
        }
        if let Some((code, missing)) = &facts.blocked {
            map.insert(
                "blocked_reason".into(),
                json!({ "code": code, "missing": [missing] }),
            );
        }
    }
    GateReport::from_json_value(document).map_err(|_| StageError::Internal)
}
