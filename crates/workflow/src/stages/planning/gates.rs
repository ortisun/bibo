//! `evaluate` of the planning stage: the evidence the engine judges.
//!
//! The gates read the stored plan and the stored record, and read the specification and the design
//! again by the hash the contract pinned. They take from the record only what the stage assigned
//! before the planner ran: the metadata the plan must carry. Everything else is computed again from
//! the stored documents, so the verdict does not rest on anything the planner wrote about itself.
//!
//! When the planner asked a person instead of planning, no gate has anything to check. Each says
//! so with a report that does not apply, and the decision is a human gate with the question in the
//! record.

use factory_domain::contracts::gate_report::{NotApplicableCode, NotApplicableDecider};
use factory_domain::contracts::task_dag::Task;
use factory_domain::contracts::{Contract, GateReport, SpecificationContract, TaskDag};
use factory_domain::policy::RepoKind;
use factory_domain::policy::paths::{ChangeEvidence, Operation, PathVerdict};
use serde_json::Value;

use super::handler::{
    MATRIX, METADATA_GATE, PlanningHandler, RECORD, TASK_PLAN, TRACEABILITY_GATE,
};
use super::metadata::Expected;
use super::run::{all_requirements, design_links};
use crate::gates::dag::{self, Finding, GATE_ID as VALIDATOR_GATE, Matrix, MatrixInput, SpecFacts};
use crate::gates::framework::GateDecision;
use crate::gates::readability::Artifact;
use crate::handlers::{GateContext, StageError};
use crate::stages::architecture::design::Design;
use crate::stages::architecture::shared::{
    definition, facts, not_applicable, output, read_for_gate, readability_report, subject,
};
use crate::stages::implementation::input::{ARCHITECTURE, SPECIFICATION_CONTRACT, input_artifact};
use crate::stages::intake::common::gate_report;

const METADATA_TEXT: &str = "plan-metadata-matches 1.0.0: the plan's identifier, version, job, mode, specification reference, architecture reference and time are the values the factory assigned before the planner ran.";
const VALIDATOR_TEXT: &str = "task-plan-validator 1.0.0: the task dependencies are acyclic with unique identifiers and no dangling edge, every acceptance scenario and requirement of the frozen specification has a task, no task serves nothing, no two tasks that nothing orders may write the same file or own the same interface, no task owns a protected path, and the sizes are within the limits.";
const TRACEABILITY_TEXT: &str = "plan-traceability-complete 1.0.0: every requirement can be followed through the design to a task, and every task back to a requirement, with no blocking gap in the matrix.";

fn failures(findings: &[Finding]) -> Vec<(String, String)> {
    findings
        .iter()
        .map(|finding| (finding.check_id(), finding.message.clone()))
        .collect()
}

/// The body of a task as the readability gate reads it: the four parts of the template, each under
/// its own heading. Public so that the end-to-end evidence collector hands the readability gate
/// the same text this stage judged (assertion A8).
#[must_use]
pub fn task_body(task: &Task) -> String {
    let list = |items: Vec<&str>| {
        items
            .into_iter()
            .map(|item| format!("- {item}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "## Why this matters\n{}\n\n## What needs to change\n{}\n\n## Acceptance criteria\n{}\n\n## Verification\n{}\n",
        task.why_this_matters.as_str(),
        task.what_needs_to_change.as_str(),
        list(
            task.acceptance_criteria
                .iter()
                .map(|c| c.as_str())
                .collect()
        ),
        list(task.verification.iter().map(|v| v.as_str()).collect()),
    )
}

fn nothing_to_check() -> &'static str {
    "The planner asked a person a question and made no plan, so there is nothing to check."
}

pub(super) async fn evaluate(
    handler: &PlanningHandler,
    ctx: &GateContext<'_>,
) -> Result<GateDecision, StageError> {
    let record_named = output(ctx, RECORD).ok_or(StageError::InvalidOutput)?;
    let record: Value = serde_json::from_slice(&read_for_gate(ctx, &record_named.artifact).await?)
        .map_err(|_| StageError::InvalidOutput)?;
    let commit = &handler.config.definition_commit;
    let asks = record.get("status").and_then(Value::as_str) == Some("needs_human");

    let na = |gate: &'static str, text: &'static str, title: &str| {
        not_applicable(
            &subject(ctx),
            facts(
                definition(gate, text, commit),
                "PASSED",
                title,
                nothing_to_check(),
                Vec::new(),
                vec![format!("record={}", record_named.artifact.sha256)],
            ),
            NotApplicableCode::NoMatchingFiles,
            NotApplicableDecider::DeterministicRule,
            nothing_to_check(),
        )
    };
    if asks {
        return Ok(GateDecision {
            reports: vec![
                na(METADATA_GATE, METADATA_TEXT, "There is no plan to compare")?,
                na(
                    VALIDATOR_GATE,
                    VALIDATOR_TEXT,
                    "There is no plan to validate",
                )?,
                na(
                    TRACEABILITY_GATE,
                    TRACEABILITY_TEXT,
                    "There is no plan to trace",
                )?,
                na(
                    crate::gates::readability::GATE_ID,
                    "readability 1.0.0: the text a stage wrote is plain English.",
                    "There is no plan text to read",
                )?,
            ],
            review: None,
            human_gate: true,
            policy_violation: false,
            assurance: Vec::new(),
        });
    }

    // The documents.
    let plan_named = output(ctx, TASK_PLAN).ok_or(StageError::InvalidOutput)?;
    output(ctx, MATRIX).ok_or(StageError::InvalidOutput)?;
    let plan_bytes = read_for_gate(ctx, &plan_named.artifact).await?;
    let plan = std::str::from_utf8(&plan_bytes)
        .ok()
        .and_then(|text| TaskDag::from_json_str(text).ok())
        .ok_or(StageError::InvalidOutput)?;
    let expected = record
        .get("expected_metadata")
        .and_then(Expected::from_json)
        .ok_or(StageError::InvalidOutput)?;
    let spec_ref =
        input_artifact(ctx.contract, SPECIFICATION_CONTRACT).ok_or(StageError::InvalidOutput)?;
    let spec = std::str::from_utf8(&read_for_gate(ctx, &spec_ref).await?)
        .ok()
        .and_then(|text| SpecificationContract::from_json_str(text).ok())
        .ok_or(StageError::InvalidOutput)?;
    let design_ref = input_artifact(ctx.contract, ARCHITECTURE).ok_or(StageError::InvalidOutput)?;
    let design = serde_json::from_slice::<Value>(&read_for_gate(ctx, &design_ref).await?)
        .ok()
        .and_then(|value| Design::read(&value).ok())
        .ok_or(StageError::InvalidOutput)?;
    let spec_facts = SpecFacts::from_contract(&spec);

    let evidence = |extra: String| {
        vec![
            format!("plan={}", plan_named.artifact.sha256),
            format!("specification={}", spec_ref.sha256),
            format!("design={}", design_ref.sha256),
            extra,
        ]
    };

    // Gate: the metadata is the factory's own.
    let mismatched = expected.mismatches(&plan.metadata);
    let metadata_report = if mismatched.is_empty() {
        gate_report(
            &subject(ctx),
            &facts(
                definition(METADATA_GATE, METADATA_TEXT, commit),
                "PASSED",
                "The plan carries the values the factory assigned",
                "Every identifier, hash and time in the plan's metadata is the value the factory assigned before the planner ran.",
                Vec::new(),
                evidence("metadata=equal".into()),
            ),
        )?
    } else {
        gate_report(
            &subject(ctx),
            &facts(
                definition(METADATA_GATE, METADATA_TEXT, commit),
                "FAILED",
                "The plan carries values the factory did not assign",
                "The planner was asked to copy the metadata unchanged, and some of it differs.",
                mismatched
                    .iter()
                    .map(|field| {
                        (
                            format!("plan-metadata.{}", field.replace(['_', '.'], "-")),
                            format!(
                                "The metadata field {field} is not the value the factory assigned. Copy the metadata from the input unchanged."
                            ),
                        )
                    })
                    .collect(),
                evidence(format!("metadata=differs:{}", mismatched.join(","))),
            ),
        )?
    };

    // Gate: the plan can be run.
    let mut report = dag::validate(&plan, &spec_facts, &handler.config.limits);
    let refuses = |path: &str| {
        matches!(
            handler.policy.paths.check(
                RepoKind::Target,
                path,
                Operation::Add,
                None,
                &ChangeEvidence::default()
            ),
            PathVerdict::Denied(_)
        )
    };
    report.findings.extend(dag::protected(&plan, &refuses));
    let validator_report = if report.findings.is_empty() {
        let analysis_note = report.analysis.as_ref().map_or_else(String::new, |a| {
            format!(
                " The critical path runs through {} task(s) and is expected to take {} seconds.",
                a.critical_path.tasks.len(),
                a.critical_path.seconds
            )
        });
        gate_report(
            &subject(ctx),
            &facts(
                definition(VALIDATOR_GATE, VALIDATOR_TEXT, commit),
                "PASSED",
                "The plan can be run",
                &format!(
                    "The plan has no cycle or missing dependency, covers every scenario and requirement, orders every pair of tasks that could write the same file, and is within its limits.{analysis_note}"
                ),
                Vec::new(),
                evidence(format!(
                    "order={}",
                    report
                        .analysis
                        .as_ref()
                        .map(|a| a.order.join(","))
                        .unwrap_or_default()
                )),
            ),
        )?
    } else {
        gate_report(
            &subject(ctx),
            &facts(
                definition(VALIDATOR_GATE, VALIDATOR_TEXT, commit),
                "FAILED",
                "The plan cannot be run as it is",
                "The plan breaks a rule of the validator. Each failure says which task or scenario and what to change.",
                failures(&report.findings),
                evidence(format!("findings={}", report.findings.len())),
            ),
        )?
    };

    // Gate: every requirement can be followed.
    let requirements = all_requirements(&spec);
    let links = design_links(&design);
    let matrix = Matrix::build(&MatrixInput {
        requirements: &requirements,
        scenarios: &spec_facts.scenarios,
        design: &links,
        plan: &plan,
    });
    let blockers: Vec<(String, String)> = matrix
        .gaps()
        .iter()
        .filter(|gap| gap.severity == dag::Severity::Blocker)
        .map(|gap| {
            (
                format!(
                    "{}.{}",
                    gap.kind,
                    factory_domain::values::Sha256Digest::of(gap.subject.as_bytes())
                        .hex()
                        .get(..8)
                        .unwrap_or("00000000")
                ),
                format!(
                    "The matrix has a gap that stops the plan: {} for {}.",
                    gap.kind.replace('-', " "),
                    gap.subject
                ),
            )
        })
        .collect();
    let notes = matrix.gaps().len() - blockers.len();
    let matrix_report = if blockers.is_empty() {
        gate_report(
            &subject(ctx),
            &facts(
                definition(TRACEABILITY_GATE, TRACEABILITY_TEXT, commit),
                "PASSED",
                "Every requirement can be followed to a task and back",
                &format!(
                    "Every requirement can be followed through the design to a task, and every task back to a requirement. The matrix records {notes} note(s) that do not stop the plan."
                ),
                Vec::new(),
                evidence(format!("notes={notes}")),
            ),
        )?
    } else {
        gate_report(
            &subject(ctx),
            &facts(
                definition(TRACEABILITY_GATE, TRACEABILITY_TEXT, commit),
                "FAILED",
                "A requirement cannot be followed to a task",
                "The traceability matrix has a gap that stops the plan.",
                blockers,
                evidence(format!("notes={notes}")),
            ),
        )?
    };

    // Gate: plain English.
    let bodies: Vec<(String, String, String)> = plan
        .tasks
        .iter()
        .map(|task| {
            (
                format!("tasks/{}", task.task_id.as_str()),
                task.title.as_str().to_owned(),
                task_body(task),
            )
        })
        .collect();
    let mut artifacts: Vec<Artifact<'_>> = vec![Artifact::request(
        plan.title.as_str(),
        plan.summary.as_str(),
    )];
    artifacts.extend(
        bodies
            .iter()
            .map(|(path, title, body)| Artifact::task(title, body).at(path)),
    );
    let readability: GateReport = readability_report(ctx, commit, &artifacts)?;

    Ok(GateDecision {
        reports: vec![
            metadata_report,
            validator_report,
            matrix_report,
            readability,
        ],
        review: None,
        human_gate: false,
        policy_violation: false,
        assurance: Vec::new(),
    })
}
