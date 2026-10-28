//! `evaluate` of the review stage: two deterministic gates, and the reviewer's verdict next to
//! them.
//!
//! | Gate | Answers |
//! |---|---|
//! | `review-evidence-verified` | Are the validation reports about this commit, and did every gate pass? A failed gate makes this report `FAILED`, a blocked gate or evidence about another commit makes it `BLOCKED` |
//! | `review-verdict-grounded` | Was the verdict made from this specification, this patch and these gate reports, and does every finding of a verdict other than `PASS` cite a file and a line that the patch shows? |
//!
//! The engine reads the decision in a fixed order: a missing or blocked gate, then a blocked
//! review, then a failed gate, and only then what the reviewer asked for. So a reviewer's `PASS`
//! cannot outweigh a gate that failed (NT-INJ-06): the failed gate is in this decision whatever
//! the reviewer said, and the engine sends the work back with the failing checks as the
//! difference between one round and the next.

use factory_domain::contracts::{Contract, GateReport, ReviewVerdict};
use factory_domain::ids::GateReportId;
use factory_domain::scope::TenantScope;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::Verdict;

use super::evidence::Evidence;
use super::handler::{ReviewHandler, VERDICT};
use super::locate::PatchIndex;
use crate::gates::framework::GateDecision;
use crate::handlers::{GateContext, StageError};
use crate::stages::implementation::input::{
    IMPLEMENTATION_RESULT, SPECIFICATION_CONTRACT, VALIDATION_EVIDENCE, input_artifact,
    parse_candidate,
};
use crate::stages::intake::common::{
    Executor, GateDefinition, GateFacts, GateSubject, gate_report,
};
use crate::stages::validation::POLICY_INPUT;

/// The gate that checks the validation reports.
pub const EVIDENCE_GATE: &str = "review-evidence-verified";
/// The gate that checks that the verdict is about this change and points at the patch.
pub const GROUNDED_GATE: &str = "review-verdict-grounded";

const EVIDENCE_TEXT: &str = "review-evidence-verified 1.0.0: the gate reports of the validation stage are bound to this implementation result, this pair of commits and this policy, none failed and none was blocked.";
const GROUNDED_TEXT: &str = "review-verdict-grounded 1.0.0: the verdict lists the specification, the patch and the gate reports that the stage gave the reviewer, and every finding of a verdict other than PASS cites a file and a line that the patch shows.";

/// What a gate found, before it is a report.
struct Finding {
    failures: Vec<(String, String)>,
    blocked: Option<(&'static str, String)>,
    reason: String,
    lines: Vec<String>,
}

pub(super) async fn evaluate(
    handler: &ReviewHandler,
    ctx: &GateContext<'_>,
) -> Result<GateDecision, StageError> {
    let ports = ctx.ports;
    let tenant = TenantScope::new(ctx.identity.tenant);
    let unavailable = || {
        StageError::Blocked(
            factory_domain::contracts::gate_report::BlockedCode::DependencyUnavailable,
        )
    };
    let read = |name: &'static str| {
        let reference = input_artifact(ctx.contract, name);
        let artifacts = ports.artifacts;
        async move {
            let reference = reference.ok_or_else(unavailable)?;
            let bytes = artifacts
                .get(&tenant, &reference)
                .await
                .map_err(|_| unavailable())?;
            Ok::<_, StageError>((reference, bytes))
        }
    };
    let (result_ref, result_bytes) = read(IMPLEMENTATION_RESULT).await?;
    let (_, evidence_bytes) = read(VALIDATION_EVIDENCE).await?;
    let (spec_ref, _) = read(SPECIFICATION_CONTRACT).await?;
    let policy = input_artifact(ctx.contract, POLICY_INPUT).ok_or_else(unavailable)?;
    let candidate = parse_candidate(&result_bytes).ok_or_else(unavailable)?;

    // Gate 1: the evidence.
    let evidence = Evidence::read(&evidence_bytes);
    let found = match &evidence {
        Err(problem) => Finding {
            failures: Vec::new(),
            blocked: Some((
                "dependency_unavailable",
                "the validation evidence".to_owned(),
            )),
            reason: format!("The validation evidence cannot be read: {problem}."),
            lines: vec!["evidence=unreadable".to_owned()],
        },
        Ok(evidence) => {
            let wrong = evidence.unbound(&candidate, &result_ref.sha256, &policy.sha256);
            let blocked = evidence.blocked();
            let failures = evidence.failures();
            let mut lines = vec![
                format!("base={}", candidate.base),
                format!("head={}", candidate.head),
            ];
            lines.extend(evidence.reports.iter().map(|(report, _)| {
                format!(
                    "{}={}",
                    report.metadata.gate_id.as_str(),
                    report.outcome.as_str()
                )
            }));
            if !wrong.is_empty() {
                Finding {
                    failures: Vec::new(),
                    blocked: Some((
                        "dependency_unavailable",
                        format!("evidence about this commit (the binding is wrong for {})", wrong.join(", ")),
                    )),
                    reason: "The gate reports are about another commit, another implementation result or another policy than the change under review.".to_owned(),
                    lines,
                }
            } else if !blocked.is_empty() {
                Finding {
                    failures: Vec::new(),
                    blocked: Some((
                        "dependency_unavailable",
                        format!("a verified result for {}", blocked.join(", ")),
                    )),
                    reason: "A gate of the validation stage could not run, so the change has no verified result for it.".to_owned(),
                    lines,
                }
            } else if !failures.is_empty() {
                Finding {
                    reason: format!(
                        "{} check(s) failed in the validation stage, so the change cannot pass whatever the reviewer says.",
                        failures.len()
                    ),
                    failures,
                    blocked: None,
                    lines,
                }
            } else {
                Finding {
                    failures: Vec::new(),
                    blocked: None,
                    reason: "Every gate of the validation stage passed, on this commit.".to_owned(),
                    lines,
                }
            }
        }
    };
    let evidence_report = report(
        handler,
        ctx,
        EVIDENCE_GATE,
        EVIDENCE_TEXT,
        "Validation evidence is verified",
        found,
    )?;

    // Gate 2: the verdict.
    let stored = ctx
        .outputs
        .iter()
        .find(|output| output.name.as_str() == VERDICT)
        .map(|output| output.artifact.clone());
    let grounded = match stored {
        None => Finding {
            failures: Vec::new(),
            blocked: Some((
                "dependency_unavailable",
                "the reviewer's verdict".to_owned(),
            )),
            reason: "The reviewer did not run, so there is no verdict.".to_owned(),
            lines: vec!["verdict=none".to_owned()],
        },
        Some(reference) => {
            let bytes = ports
                .artifacts
                .get(&tenant, &reference)
                .await
                .map_err(|_| unavailable())?;
            let verdict = std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| ReviewVerdict::from_json_str(text).ok());
            match verdict {
                None => Finding {
                    failures: Vec::new(),
                    blocked: Some(("dependency_unavailable", "a readable verdict".to_owned())),
                    reason: "The stored verdict does not follow its contract.".to_owned(),
                    lines: vec!["verdict=unreadable".to_owned()],
                },
                Some(verdict) => {
                    grounded(
                        handler,
                        ctx,
                        &candidate,
                        &verdict,
                        &spec_ref.sha256,
                        evidence.as_ref().ok(),
                    )
                    .await?
                }
            }
        }
    };
    let grounded_report = report(
        handler,
        ctx,
        GROUNDED_GATE,
        GROUNDED_TEXT,
        "Verdict is grounded in the patch",
        grounded,
    )?;

    // The verdict itself is evidence for the engine, next to the gates.
    let verdict = match ctx.outputs.iter().find(|o| o.name.as_str() == VERDICT) {
        Some(output) => {
            let bytes = ports
                .artifacts
                .get(&tenant, &output.artifact)
                .await
                .map_err(|_| unavailable())?;
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| ReviewVerdict::from_json_str(text).ok())
        }
        None => None,
    };
    Ok(GateDecision {
        reports: vec![evidence_report, grounded_report],
        review: verdict,
        human_gate: false,
        policy_violation: false,
        assurance: Vec::new(),
    })
}

/// Checks the verdict against what this stage gave the reviewer.
async fn grounded(
    handler: &ReviewHandler,
    ctx: &GateContext<'_>,
    candidate: &crate::stages::implementation::input::Candidate,
    verdict: &ReviewVerdict,
    spec: &Sha256Digest,
    evidence: Option<&Evidence>,
) -> Result<Finding, StageError> {
    let ports = ctx.ports;
    let unavailable = |what: &str| Finding {
        failures: Vec::new(),
        blocked: Some(("dependency_unavailable", what.to_owned())),
        reason: "The citations of the verdict could not be checked against the patch.".to_owned(),
        lines: vec![format!("patch=unavailable:{what}")],
    };
    let repo = match ports.workspaces.repo(ctx.identity.job).await {
        Ok(repo) => repo,
        Err(_) => return Ok(unavailable("the job's object store")),
    };
    let export = match repo
        .export_patch(
            &candidate.base,
            &candidate.head,
            handler.config.max_patch_bytes,
            ctx.cancel,
        )
        .await
    {
        Ok(export) => export,
        Err(factory_ports::workspace::WorkspaceError::Cancelled) => {
            return Err(StageError::Cancelled);
        }
        Err(_) => return Ok(unavailable("the patch")),
    };
    let patch = match ports
        .artifacts
        .get(&TenantScope::new(ctx.identity.tenant), &export.patch)
        .await
    {
        Ok(patch) => patch,
        Err(_) => return Ok(unavailable("the patch")),
    };
    let index = PatchIndex::parse(&patch);
    let mut failures = Vec::new();
    let inputs = &verdict.inputs_reviewed;
    if inputs.diff_sha256 != export.patch.sha256 {
        failures.push((
            "verdict-about-another-patch".to_owned(),
            "The verdict says the reviewer was given a patch other than the one the host exports for these commits.".to_owned(),
        ));
    }
    if inputs.frozen_spec_sha256 != *spec {
        failures.push((
            "verdict-about-another-specification".to_owned(),
            "The verdict says the reviewer was given a specification other than the frozen one."
                .to_owned(),
        ));
    }
    if let Some(evidence) = evidence {
        let given: Vec<GateReportId> = inputs
            .gate_reports
            .as_slice()
            .iter()
            .map(|r| r.gate_report_id)
            .collect();
        let mut expected: Vec<GateReportId> = evidence
            .references()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        let mut given_sorted = given;
        expected.sort();
        given_sorted.sort();
        if expected != given_sorted {
            failures.push((
                "verdict-about-other-gate-reports".to_owned(),
                "The verdict lists gate reports other than those of the validation stage."
                    .to_owned(),
            ));
        }
    }
    if verdict.verdict != Verdict::Pass {
        for finding in &verdict.findings {
            let shown = finding.location.as_ref().is_some_and(|location| {
                location.line_start.is_some_and(|start| {
                    let start = u32::try_from(start.get()).unwrap_or(0);
                    let end = location
                        .line_end
                        .and_then(|end| u32::try_from(end.get()).ok());
                    index.shows(location.path.as_str(), start, end)
                })
            });
            if !shown {
                failures.push((
                    "finding-not-in-the-patch".to_owned(),
                    format!(
                        "The finding {} cites a file and a line that the patch does not show.",
                        finding.finding_id.as_str()
                    ),
                ));
            }
        }
    }
    let lines = vec![
        format!("verdict={}", verdict.verdict.as_str()),
        format!("findings={}", verdict.findings.len()),
        format!("patch={}", export.patch.sha256),
    ];
    // A verdict that fails one of these checks is not evidence, but the work is not at fault, so
    // the report is `BLOCKED` and not `FAILED`: it is not sent back to the builder. The checks
    // that failed are named, so a person sees what was wrong.
    let blocked = (!failures.is_empty()).then(|| {
        let checks: Vec<&str> = failures.iter().map(|(id, _)| id.as_str()).collect();
        (
            "dependency_unavailable",
            format!(
                "a verdict that is about this change and points at the patch ({})",
                checks.join(", ")
            ),
        )
    });
    Ok(Finding {
        reason: if blocked.is_none() {
            "The verdict was made from this specification, this patch and these gate reports, and each of its findings points at the patch.".to_owned()
        } else {
            "The verdict cannot be trusted as evidence: it is not about this change, or it cites lines the patch does not show.".to_owned()
        },
        failures: Vec::new(),
        blocked,
        lines,
    })
}

fn report(
    handler: &ReviewHandler,
    ctx: &GateContext<'_>,
    gate: &'static str,
    text: &'static str,
    title: &str,
    found: Finding,
) -> Result<GateReport, StageError> {
    let ports = ctx.ports;
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
            definition: GateDefinition {
                id: gate,
                version: "1.0.0",
                text,
                commit: handler.config.definition_commit.clone(),
            },
            outcome: if found.blocked.is_some() {
                "BLOCKED"
            } else if found.failures.is_empty() {
                "PASSED"
            } else {
                "FAILED"
            },
            title: title.to_owned(),
            reason: found.reason,
            failures: found.failures,
            blocked: found.blocked,
            fidelity,
            executor: Executor::InProcess,
            commands: Vec::new(),
            tools: vec![("factory-review".to_owned(), "1.0.0".to_owned())],
            evidence: found.lines,
        },
    )
}
