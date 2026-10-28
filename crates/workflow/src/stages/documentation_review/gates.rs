//! `evaluate` of the documentation review stage: the stored reports and the stored verdict, handed
//! to the engine as evidence.
//!
//! The gate ran in `execute`, in a verify sandbox, and its reports were stored in
//! `documentation-gate-report`. This function reads them back and checks them against independent
//! sources before it hands them over: the document names the commits and the plan that the stage
//! contract pinned, every gate of the contract has a report, and each report is a valid gate
//! report of the contract. It adds nothing, removes nothing and decides nothing. The engine
//! decides with `resolve`: a gate that is blocked blocks, a gate that failed fails, and only then
//! is the reviewer's verdict read, so a `PASS` cannot outweigh a failed gate.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::{Contract, GateReport, ReviewVerdict};
use factory_domain::scope::TenantScope;
use serde_json::Value;

use super::handler::{DocumentationReviewHandler, gate_ids};
use crate::gates::framework::GateDecision;
use crate::handlers::{GateContext, StageError};
use crate::stages::documenting::input::{
    DOCUMENTATION_GATE_REPORT, DOCUMENTATION_PLAN, DOCUMENTATION_RESULT, DOCUMENTATION_REVIEW,
    IMPLEMENTATION_RESULT, input_artifact, parse_candidate,
};

pub(super) async fn evaluate(
    _handler: &DocumentationReviewHandler,
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
    let get = |reference| {
        let artifacts = ports.artifacts;
        async move {
            artifacts
                .get(&tenant, &reference)
                .await
                .map_err(|_| unavailable())
        }
    };
    let gate_ref = stored(DOCUMENTATION_GATE_REPORT).ok_or(StageError::InvalidOutput)?;
    let document: Value =
        serde_json::from_slice(&get(gate_ref).await?).map_err(|_| StageError::InvalidOutput)?;

    // The reports are about the commits and the plan the contract pinned, not about whatever the
    // stage says they are about.
    let pinned = |name: &str| input_artifact(ctx.contract, name).ok_or_else(unavailable);
    let candidate =
        parse_candidate(&get(pinned(IMPLEMENTATION_RESULT)?).await?).ok_or_else(unavailable)?;
    let result: Value = serde_json::from_slice(&get(pinned(DOCUMENTATION_RESULT)?).await?)
        .map_err(|_| unavailable())?;
    let plan = pinned(DOCUMENTATION_PLAN)?;
    let binding = &document["binding"];
    let same = binding["base_commit"] == candidate.base.as_str()
        && binding["code_head"] == candidate.head.as_str()
        && binding["documentation_head"] == result["head_commit"]
        && binding["plan_sha256"] == plan.sha256.as_str();
    if !same {
        return Err(StageError::InvalidOutput);
    }

    let mut reports = Vec::new();
    for item in document["reports"]
        .as_array()
        .ok_or(StageError::InvalidOutput)?
    {
        reports.push(
            GateReport::from_json_value(item.clone()).map_err(|_| StageError::InvalidOutput)?,
        );
    }
    // A gate the contract names and that has no report did not run. The engine blocks on it, so
    // this only fails early when the document is not the one the stage should have written.
    if reports.is_empty()
        || !reports
            .iter()
            .all(|report| gate_ids().contains(&report.metadata.gate_id.as_str()))
    {
        return Err(StageError::InvalidOutput);
    }

    let review = match stored(DOCUMENTATION_REVIEW) {
        Some(reference) => {
            let bytes = get(reference).await?;
            let verdict = ReviewVerdict::from_json_str(
                std::str::from_utf8(&bytes).map_err(|_| StageError::InvalidOutput)?,
            )
            .map_err(|_| StageError::InvalidOutput)?;
            verdict.validate().map_err(|_| StageError::InvalidOutput)?;
            Some(verdict)
        }
        None => None,
    };
    Ok(GateDecision {
        reports,
        review,
        ..GateDecision::default()
    })
}
