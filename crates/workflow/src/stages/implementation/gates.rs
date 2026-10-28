//! `evaluate` of the implementation stage: three deterministic gates over what the stage stored.
//!
//! | Gate | Answers |
//! |---|---|
//! | `implementation-scope` | Is every path a task changed a path that task owns? The globs come from the plan the contract pinned, not from the evidence the stage wrote |
//! | `implementation-commits` | Does the head commit hold only changes that the audited ingestion reported, and does it differ from the base? |
//! | `protected-paths-unchanged` | Did the audit refuse a change? A refusal is a policy violation: the stage run is blocked, and nobody is asked to override it by the reviewer |
//!
//! Nothing here reads anything the builder wrote. The commits are in the job's object store, the
//! changed paths are the host's export of the patch, and the owned files are in the plan.

use std::collections::BTreeSet;

use factory_domain::contracts::GateReport;
use factory_domain::ids::GateReportId;
use factory_domain::scope::TenantScope;

use super::contract::{COMMITS_GATE, PROTECTED_GATE, SCOPE_GATE};
use super::evidence::{EVIDENCE, ImplementationEvidence, RESULT};
use super::handler::ImplementationHandler;
use super::input::{TASK_PLAN, input_artifact, parse_candidate};
use super::plan;
use super::run::REWORK_PREFIX;
use super::scope;
use crate::gates::framework::GateDecision;
use crate::handlers::{GateContext, StageError};
use crate::stages::intake::common::{
    Executor, GateDefinition, GateFacts, GateSubject, gate_report,
};

const SCOPE_TEXT: &str = "implementation-scope 1.0.0: every path a task changed is matched by a glob of the files that task owns in the plan.";
const COMMITS_TEXT: &str = "implementation-commits 1.0.0: the head commit changes no path that the audited ingestion did not report, it is the commit of the last task, and it differs from the base.";
const PROTECTED_TEXT: &str = "protected-paths-unchanged 1.0.0 (implementation): the audit of the sandbox tree refused no change.";

pub(super) async fn evaluate(
    handler: &ImplementationHandler,
    ctx: &GateContext<'_>,
) -> Result<GateDecision, StageError> {
    let ports = ctx.ports;
    let scope_of_tenant = TenantScope::new(ctx.identity.tenant);
    let unavailable = || {
        StageError::Blocked(
            factory_domain::contracts::gate_report::BlockedCode::DependencyUnavailable,
        )
    };
    let stored = |name: &str| {
        ctx.outputs
            .iter()
            .find(|output| output.name.as_str() == name)
            .map(|output| output.artifact.clone())
    };
    let result_ref = stored(RESULT).ok_or(StageError::InvalidOutput)?;
    let evidence_ref = stored(EVIDENCE).ok_or(StageError::InvalidOutput)?;
    let result_bytes = ports
        .artifacts
        .get(&scope_of_tenant, &result_ref)
        .await
        .map_err(|_| unavailable())?;
    let evidence_bytes = ports
        .artifacts
        .get(&scope_of_tenant, &evidence_ref)
        .await
        .map_err(|_| unavailable())?;
    let candidate = parse_candidate(&result_bytes).ok_or(StageError::InvalidOutput)?;
    let evidence = serde_json::from_slice(&evidence_bytes)
        .ok()
        .and_then(|value| ImplementationEvidence::from_json(&value))
        .ok_or(StageError::InvalidOutput)?;
    if candidate.base.as_str() != evidence.base_commit
        || candidate.head.as_str() != evidence.head_commit
    {
        return Err(StageError::Internal);
    }
    let plan_ref = input_artifact(ctx.contract, TASK_PLAN).ok_or_else(unavailable)?;
    let plan_bytes = ports
        .artifacts
        .get(&scope_of_tenant, &plan_ref)
        .await
        .map_err(|_| unavailable())?;
    let task_plan = plan::read(&plan_bytes).map_err(|_| unavailable())?;

    let fidelity = if [
        ports.workspaces.fidelity(),
        ports.sandbox.fidelity(),
        ports.runtime.fidelity(),
        ports.artifacts.fidelity(),
    ]
    .contains(&factory_domain::vocabulary::Fidelity::Fake)
    {
        "fake"
    } else {
        "real"
    };
    let definition = |id: &'static str, text: &'static str| GateDefinition {
        id,
        version: "1.0.0",
        text,
        commit: handler.config.definition_commit.clone(),
    };
    let report = |gate: &'static str,
                  text: &'static str,
                  title: &str,
                  reason: String,
                  failures: Vec<(String, String)>,
                  blocked: Option<(&'static str, String)>,
                  evidence_lines: Vec<String>|
     -> Result<GateReport, StageError> {
        let now = ports.clock.now();
        gate_report(
            &GateSubject {
                job: ctx.identity.job,
                stage_run: ctx.identity.stage_run,
                attempt: ctx.attempt,
                mode: ctx.mode,
                report_id: GateReportId::from_uuid(ports.ids.new_uuid()),
                started_at: now,
                finished_at: ports.clock.now(),
            },
            &GateFacts {
                definition: definition(gate, text),
                outcome: if blocked.is_some() {
                    "BLOCKED"
                } else if failures.is_empty() {
                    "PASSED"
                } else {
                    "FAILED"
                },
                title: title.to_owned(),
                reason,
                failures,
                blocked,
                fidelity,
                executor: Executor::InProcess,
                commands: Vec::new(),
                tools: vec![("factory-implementation".to_owned(), "1.0.0".to_owned())],
                evidence: evidence_lines,
            },
        )
    };

    // The audit refused nothing, or it refused something and the stage run is blocked.
    let protected = match &evidence.refusal {
        None => report(
            PROTECTED_GATE,
            PROTECTED_TEXT,
            "Protected paths unchanged",
            "The audit of the sandbox tree refused no change.".to_owned(),
            Vec::new(),
            None,
            vec!["refusal=none".to_owned()],
        )?,
        Some(refusal) => {
            let mut failures: Vec<(String, String)> = refusal
                .paths
                .iter()
                .map(|(path, rule)| {
                    (
                        refusal.code.clone(),
                        format!(
                            "The audit refused the change of task {} at {} under the rule {}.",
                            refusal.task, path, rule
                        ),
                    )
                })
                .collect();
            if failures.is_empty() {
                failures.push((
                    refusal.code.clone(),
                    format!("The audit refused the change of task {}.", refusal.task),
                ));
            }
            let lines = refusal
                .paths
                .iter()
                .map(|(path, rule)| format!("refused={path}:{rule}"))
                .collect();
            report(
                PROTECTED_GATE,
                PROTECTED_TEXT,
                "Protected paths unchanged",
                "The audit refused a change, so nothing of that task was committed and the stage run is blocked."
                    .to_owned(),
                failures,
                None,
                lines,
            )?
        }
    };

    // Every changed path is a path its task owns.
    let mut out_of_scope = Vec::new();
    for task in &evidence.tasks {
        let owned = if task.key.starts_with(REWORK_PREFIX) {
            plan::all_owned_files(&task_plan)
        } else {
            task_plan
                .tasks
                .as_slice()
                .iter()
                .find(|planned| planned.task_id.as_str() == task.key)
                .map(plan::owned_files)
                .unwrap_or_default()
        };
        let changed: Vec<String> = task.changes.iter().map(|c| c.path.clone()).collect();
        out_of_scope.extend(scope::outside(&task.key, &owned, &changed));
    }
    let scope_report = report(
        SCOPE_GATE,
        SCOPE_TEXT,
        "Changes stay inside the owned files",
        if out_of_scope.is_empty() {
            "Every changed path is a file its task owns.".to_owned()
        } else {
            format!(
                "{} changed path(s) are files their task does not own.",
                out_of_scope.len()
            )
        },
        out_of_scope
            .iter()
            .map(|found| {
                (
                    "path-outside-owned-files".to_owned(),
                    format!(
                        "Task {} changed the path {}, which it does not own.",
                        found.task, found.path
                    ),
                )
            })
            .collect(),
        None,
        evidence
            .tasks
            .iter()
            .map(|task| format!("task={}:{}", task.key, task.commit))
            .collect(),
    )?;

    // The head commit is what the audit reported, and it is not the base.
    let mut failures: Vec<(String, String)> = Vec::new();
    let mut blocked: Option<(&'static str, String)> = None;
    let mut lines = vec![
        format!("base={}", candidate.base),
        format!("head={}", candidate.head),
    ];
    let nothing_committed = candidate.base == candidate.head;
    if nothing_committed {
        if evidence.refusal.is_none() {
            failures.push((
                "no-change".to_owned(),
                "The head commit is the base commit, so the stage changed nothing.".to_owned(),
            ));
        }
    } else {
        match ctx.ports.workspaces.repo(ctx.identity.job).await {
            Err(_) => {
                blocked = Some((
                    "dependency_unavailable",
                    "the job's object store".to_owned(),
                ))
            }
            Ok(repo) => match repo
                .export_patch(
                    &candidate.base,
                    &candidate.head,
                    handler.config.max_patch_bytes,
                    ctx.cancel,
                )
                .await
            {
                Err(factory_ports::workspace::WorkspaceError::Cancelled) => {
                    return Err(StageError::Cancelled);
                }
                Err(_) => blocked = Some(("dependency_unavailable", "the head commit".to_owned())),
                Ok(export) => {
                    let accounted: BTreeSet<&str> = evidence
                        .tasks
                        .iter()
                        .flat_map(|task| task.changes.iter().map(|c| c.path.as_str()))
                        .collect();
                    for changed in &export.changes {
                        lines.push(format!("exported={}", changed.path.as_str()));
                        if !accounted.contains(changed.path.as_str()) {
                            failures.push((
                                "head-commit-unaccounted-change".to_owned(),
                                format!(
                                    "The head commit changes {}, which no audited task change reported.",
                                    changed.path.as_str()
                                ),
                            ));
                        }
                    }
                    if evidence.tasks.last().map(|task| task.commit.as_str())
                        != Some(candidate.head.as_str())
                    {
                        failures.push((
                            "head-is-not-the-last-task".to_owned(),
                            "The head commit is not the commit of the last task.".to_owned(),
                        ));
                    }
                }
            },
        }
    }
    let commits_report = report(
        COMMITS_GATE,
        COMMITS_TEXT,
        "Commits match the audit",
        if blocked.is_some() {
            "The commits could not be read from the job's object store.".to_owned()
        } else if failures.is_empty() {
            "The head commit holds only changes the audited ingestion reported.".to_owned()
        } else {
            "The head commit does not match what the audited ingestion reported.".to_owned()
        },
        failures,
        blocked,
        lines,
    )?;

    Ok(GateDecision {
        reports: vec![scope_report, commits_report, protected],
        review: None,
        human_gate: false,
        policy_violation: evidence.refusal.is_some(),
        assurance: Vec::new(),
    })
}
