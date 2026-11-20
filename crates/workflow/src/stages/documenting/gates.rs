//! `evaluate` of the documenting stage: four deterministic gates over what the stage stored.
//!
//! | Gate | Answers |
//! |---|---|
//! | `documenting-plan-recorded` | Does the stored plan follow its schema, and is it about the commits and the specification the contract pinned? |
//! | `documenting-scope` | Is every changed path one the writer's manifest lets it write? Recomputed from the manifest, not read from the evidence |
//! | `documenting-protected-paths` | Did the audit refuse a change? A refusal is a policy violation: the stage run is blocked |
//! | `documenting-traceability` | Does each claim of the writer cite a file that exists at the documentation commit, and did the writer cite anything? |
//!
//! Nothing here reads anything the writer wrote except its claims, and a claim counts for nothing
//! until the file it cites is found in the tree the host read.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::scope::TenantScope;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::Fidelity;
use factory_ports::paths::CommitSha;
use factory_ports::registry::VersionReq;
use serde_json::Value;

use super::handler::{DocumentingHandler, PLAN_GATE, PROTECTED_GATE, SCOPE_GATE, TRACE_GATE};
use super::input::{
    DOCUMENTATION_PLAN, DOCUMENTATION_RESULT, IMPLEMENTATION_RESULT, SPECIFICATION_CONTRACT,
    input_artifact, parse_candidate,
};
use super::run::write_globs;
use crate::gates::command::report::Subject;
use crate::gates::docs::check::Finding;
use crate::gates::docs::plan::{DocPlan, validate};
use crate::gates::docs::report::Reporter;
use crate::gates::framework::GateDecision;
use crate::handlers::{GateContext, StageError};
use crate::stages::implementation::scope::outside;

const PLAN_TEXT: &str = "documenting-plan-recorded 1.0.0: the stored plan follows documentation-plan.v1.schema.json and names the base commit, the head commit and the frozen specification that the stage contract pinned.";
const SCOPE_TEXT: &str = "documenting-scope 1.0.0: every path the documentation commit changed is matched by a glob of the files the writer's manifest lets it write.";
const PROTECTED_TEXT: &str =
    "documenting-protected-paths 1.0.0: the audit of the sandbox tree refused no change.";
const TRACE_TEXT: &str = "documenting-traceability 1.0.0: when the writer ran, it cited at least one source, and every file it cited exists at the documentation commit.";

fn finding(check: &'static str, message: String) -> Finding {
    Finding {
        check,
        file: None,
        line: None,
        message,
    }
}

pub(super) async fn evaluate(
    handler: &DocumentingHandler,
    ctx: &GateContext<'_>,
) -> Result<GateDecision, StageError> {
    let ports = ctx.ports;
    let tenant = TenantScope::new(ctx.identity.tenant);
    let unavailable = || StageError::Blocked(BlockedCode::DependencyUnavailable);
    let stored = |name: &str| {
        ctx.outputs
            .iter()
            .find(|output| output.name.as_str() == name)
            .map(|output| output.artifact.clone())
    };
    let read = |reference| {
        let artifacts = ports.artifacts;
        async move {
            artifacts
                .get(&tenant, &reference)
                .await
                .map_err(|_| unavailable())
        }
    };
    let plan_ref = stored(DOCUMENTATION_PLAN).ok_or(StageError::InvalidOutput)?;
    let result_ref = stored(DOCUMENTATION_RESULT).ok_or(StageError::InvalidOutput)?;
    let plan_bytes = read(plan_ref).await?;
    let result_bytes = read(result_ref).await?;
    let plan_json: Value =
        serde_json::from_slice(&plan_bytes).map_err(|_| StageError::InvalidOutput)?;
    let result: Value =
        serde_json::from_slice(&result_bytes).map_err(|_| StageError::InvalidOutput)?;
    let implementation =
        read(input_artifact(ctx.contract, IMPLEMENTATION_RESULT).ok_or_else(unavailable)?).await?;
    let spec_ref = input_artifact(ctx.contract, SPECIFICATION_CONTRACT).ok_or_else(unavailable)?;
    let candidate = parse_candidate(&implementation).ok_or_else(unavailable)?;

    let manifest = ports
        .registry
        .manifest(&handler.config.agent, &VersionReq::Any)
        .map_err(|_| StageError::Internal)?;
    let fidelity = if [
        ports.workspaces.fidelity(),
        ports.sandbox.fidelity(),
        ports.runtime.fidelity(),
        ports.artifacts.fidelity(),
    ]
    .contains(&Fidelity::Fake)
    {
        Fidelity::Fake
    } else {
        Fidelity::Real
    };
    let head = result["head_commit"].as_str().unwrap_or("");
    let reporter = Reporter {
        subject: Subject {
            job: ctx.identity.job,
            stage_run: ctx.identity.stage_run,
            attempt: ctx.attempt,
            mode: ctx.mode,
        },
        definition_commit: handler.config.definition_commit.clone(),
        fidelity,
        binding: Sha256Digest::of(
            format!("{}\n{}\n{head}", candidate.base, candidate.head).as_bytes(),
        ),
        sandbox: None,
        clock: ports.clock,
        ids: ports.ids,
    };

    // The plan follows its schema and is about the commits and the specification of the contract.
    let mut plan_findings = Vec::new();
    match validate(&plan_json) {
        Ok(()) => {
            if let Ok(plan) = DocPlan::from_json(&plan_json) {
                if plan.binding.base_commit != candidate.base.as_str()
                    || plan.binding.code_head != candidate.head.as_str()
                {
                    plan_findings.push(finding(
                        "plan-not-bound",
                        "The plan names other commits than the implementation result the contract pinned.".to_owned(),
                    ));
                }
                if plan.binding.specification_sha256 != spec_ref.sha256.to_string() {
                    plan_findings.push(finding(
                        "plan-not-bound",
                        "The plan names another frozen specification than the one the contract pinned.".to_owned(),
                    ));
                }
            }
        }
        Err(error) => plan_findings.push(finding(
            "plan-breaks-schema",
            format!("The stored plan breaks its schema: {error}."),
        )),
    }
    if CommitSha::parse(head).is_err() {
        plan_findings.push(finding(
            "result-head-missing",
            "The documentation result does not name a documentation commit.".to_owned(),
        ));
    }

    // Every changed path is a path the manifest lets the writer write.
    let changed: Vec<String> = result["changes"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["path"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let out_of_scope = outside("documenting", &write_globs(&manifest), &changed);
    let scope_findings: Vec<Finding> = out_of_scope
        .iter()
        .map(|found| Finding {
            check: "path-out-of-scope",
            file: Some(found.path.clone()),
            line: None,
            message: format!(
                "The writer changed {}, which is neither the README, the changelog nor a Markdown file under docs.",
                found.path
            ),
        })
        .collect();

    // The audit refused nothing.
    let refusal = result.get("refusal").filter(|value| !value.is_null());
    let protected_findings: Vec<Finding> = refusal
        .map(|refusal| {
            let code = refusal["code"].as_str().unwrap_or("refused");
            let paths = refusal["paths"].as_array().cloned().unwrap_or_default();
            if paths.is_empty() {
                return vec![finding(
                    "audit-refused",
                    format!("The audit refused the change of the writer under the rule {code}."),
                )];
            }
            paths
                .iter()
                .map(|pair| Finding {
                    check: "audit-refused",
                    file: pair[0].as_str().map(str::to_owned),
                    line: None,
                    message: format!(
                        "The audit refused the change at {} under the rule {}.",
                        pair[0].as_str().unwrap_or("a path"),
                        pair[1].as_str().unwrap_or(code)
                    ),
                })
                .collect()
        })
        .unwrap_or_default();

    // Each claim cites a file that exists, and a writer that ran cited something.
    let mut trace_findings: Vec<Finding> = result["unresolved_claims"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(|path| {
                    finding(
                        "claim-source-missing",
                        format!("A claim cites {path}, and no such file exists at the documentation commit."),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let ran = result["writer_ran"].as_bool().unwrap_or(false);
    let cited = result["reported"]["claims"]
        .as_array()
        .is_some_and(|claims| !claims.is_empty());
    if ran && refusal.is_none() && scope_findings.is_empty() && !cited {
        trace_findings.push(finding(
            "claims-uncited",
            "The writer wrote documents and cited no source for any statement in them.".to_owned(),
        ));
    }

    let reports = vec![
        reporter.in_process(
            PLAN_GATE,
            "Documentation plan is recorded and bound",
            PLAN_TEXT,
            if plan_findings.is_empty() {
                "The plan follows its schema and is about the commits and the specification the contract pinned."
            } else {
                "The plan breaks its schema or is about other commits."
            },
            &plan_findings,
        )?,
        reporter.in_process(
            SCOPE_GATE,
            "Writer stayed in its scope",
            SCOPE_TEXT,
            if scope_findings.is_empty() {
                "Every changed path is one the writer may write."
            } else {
                "The writer changed a path it may not write, so nothing was committed."
            },
            &scope_findings,
        )?,
        reporter.in_process(
            PROTECTED_GATE,
            "Protected paths unchanged",
            PROTECTED_TEXT,
            if protected_findings.is_empty() {
                "The audit of the sandbox tree refused no change."
            } else {
                "The audit refused a change, so nothing of it was committed and the stage run is blocked."
            },
            &protected_findings,
        )?,
        reporter.in_process(
            TRACE_GATE,
            "Claims cite their sources",
            TRACE_TEXT,
            if trace_findings.is_empty() {
                "Every claim cites a file that exists at the documentation commit."
            } else {
                "A claim has no source that can be found."
            },
            &trace_findings,
        )?,
    ];
    Ok(GateDecision {
        reports,
        // A refusal of the audit and a path out of scope are not for the writer to retry: the
        // stage run is blocked and a person decides.
        policy_violation: refusal.is_some() || !scope_findings.is_empty(),
        ..GateDecision::default()
    })
}
