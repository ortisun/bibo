//! The stage contract of the specification stage.
//!
//! It is resolved once per stage run from the stage runs before it. It pins the normalized request
//! and the repository map by hash, declares the sandbox as the only place the writer runs, the
//! files the writer may write, no network, and every gate that judges the stage.

use factory_domain::contracts::StageContract;
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::vocabulary::StageKind;

use super::handler::SpecificationConfig;
use super::input::{NORMALIZED_REQUEST, REPOSITORY_MAP, upstream_output};
use super::judge::REVIEW;
use super::{EVIDENCE, SPECIFICATION_CONTRACT};
use crate::gates::spec;
use crate::handlers::{ContractContext, StageError};
use crate::stages::intake::common::{
    ContractBudget, ContractCriterion, ContractDeliverable, ContractInput, ContractSpec,
    stage_contract,
};

/// The tools the writer is granted, which are those of its manifest. A test compares the two.
pub const GRANTED_TOOLS: [&str; 5] = [
    "fs.read",
    "fs.list",
    "fs.write",
    "exec.run",
    "report.submit",
];

/// Every gate of the evaluator, in the order of the report.
#[must_use]
pub fn gates() -> Vec<&'static str> {
    let mut all: Vec<&'static str> = spec::ALL.to_vec();
    all.insert(spec::ALL.len() - 1, REVIEW);
    all
}

/// Resolves the contract.
///
/// # Errors
/// [`StageError::Blocked`] when a run before this one did not produce a deliverable the stage
/// needs.
pub fn resolve(
    config: &SpecificationConfig,
    ctx: &ContractContext<'_>,
) -> Result<StageContract, StageError> {
    let missing = || StageError::Blocked(BlockedCode::DependencyUnavailable);
    let (request_run, request) =
        upstream_output(ctx.upstream, StageKind::Intake, NORMALIZED_REQUEST).ok_or_else(missing)?;
    let (map_run, map) = upstream_output(
        ctx.upstream,
        StageKind::RepositoryIntelligence,
        REPOSITORY_MAP,
    )
    .ok_or_else(missing)?;
    let mut inputs = vec![
        ContractInput {
            name: NORMALIZED_REQUEST,
            description: "The request in plain English, written by the intake stage.",
            sha256: request.sha256.clone(),
            media_type: "application/json",
            source: "previous_stage",
            produced_by: Some(request_run.id),
            commit_sha: None,
            retrieved_at: ctx.now,
            // Written from an issue by a model, so it is data to read.
            trust: "untrusted",
        },
        ContractInput {
            name: REPOSITORY_MAP,
            description: "The repository map, which names the commit the specification starts from.",
            sha256: map.sha256.clone(),
            media_type: "application/json",
            source: "previous_stage",
            produced_by: Some(map_run.id),
            commit_sha: None,
            retrieved_at: ctx.now,
            trust: "untrusted",
        },
        ContractInput {
            name: "policy-bundle",
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
    // The project's rules for agents (ADR 0026), given to the writer and the reviewer.
    inputs.extend(crate::stages::project_rules::contract_input(
        ctx.upstream,
        ctx.now,
    ));
    let criteria: Vec<ContractCriterion> = gates()
        .into_iter()
        .map(|gate| ContractCriterion {
            id: gate,
            description: "The gate of this name found nothing wrong.",
            gate,
        })
        .collect();
    let budget = &config.budget;
    stage_contract(&ContractSpec {
        kind: StageKind::Specification,
        job: ctx.identity.job,
        stage_run: ctx.identity.stage_run,
        mode: ctx.mode,
        created_at: ctx.now,
        contract_id: "stage-contract.specification",
        title: "Write the specification and freeze it",
        purpose: "Turn one authorized request into a feature specification with three of the four allowed Spec Kit skills, judge it with a gate of the factory's own and an independent reviewer, and freeze it only when a person decided.",
        problem: "A request is short and the build needs requirements that can be tested. The skills write the text, but they grade their own work and take their arguments as the user's own instruction. The factory passes the request in a file, checks the files and not the agent's report, ignores every tick the author wrote, and freezes the specification only after a recorded decision.",
        inputs,
        preconditions: vec![
            (
                "request-authorized",
                "The request passed the intake stage, so a person on the allowlist asked for it.",
                "upstream_stage_passed",
            ),
            (
                "sandbox-available",
                "The container runtime answers and the agent image is on the host.",
                "tool_available",
            ),
        ],
        method: (
            "Run the skills in a sandbox, audit and commit on the host, judge with fixed rules",
            "The files are the evidence. The host reads them back from the commit it made after the audit, and the rules do not depend on what the agent says.",
            "Let the agent commit and report its own result",
            "The skills vary from one run to the next and grade their own work, so their report is not evidence.",
        ),
        agent: (config.writer.as_str().to_owned(), "1.0.0"),
        granted_tools: GRANTED_TOOLS.to_vec(),
        shell: "sandboxed_typed_wrapper",
        placement: Some("sandbox"),
        deliverables: vec![
            ContractDeliverable {
                name: SPECIFICATION_CONTRACT,
                description: "The typed specification: draft until a person decides, frozen after.",
                media_type: "application/json",
                required: false,
            },
            ContractDeliverable {
                name: EVIDENCE,
                description: "What the host measured: commits, changed paths, hashes, denials and the review.",
                media_type: "application/json",
                required: true,
            },
        ],
        criteria,
        gates: gates(),
        budget: ContractBudget {
            wall_time_seconds: budget.wall_time_seconds,
            max_tokens: budget.max_tokens,
            max_cost_usd: budget.max_cost_usd,
            attempt_timeout_seconds: budget.attempt_timeout_seconds,
            max_attempts: budget.max_attempts,
        },
        rollback: "Nothing leaves the job's object store, so dropping the job's commits undoes the stage.",
        span_name: "stage.specification",
    })
}
