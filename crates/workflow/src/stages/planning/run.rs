//! `execute` of the planning stage.
//!
//! In order, and each step ends the stage if it fails:
//!
//! 1. Read the frozen specification, the approved design and the repository map by the hash the
//!    contract pinned. Refuse a specification that is not approved and a design that cannot be
//!    read.
//! 2. Learn what the round before this one said. If it made a plan, validate that plan again and
//!    work out which tasks passed every check and can be kept.
//! 3. Assign the plan's identifiers, version, hashes and time. The planner is shown them and is
//!    asked to copy them, and the stage keeps its own copy to compare with.
//! 4. Assemble the planner's prompt, with the specification, the design, the map and the assigned
//!    values as untrusted data, each in its own block, and run the planner over its own checkout
//!    of the base commit with tools that only read.
//! 5. Read the envelope strictly. If the planner asks a person, store the question and no plan. If
//!    it returns a plan, read the plan through the typed `task-dag` contract, run the validator to
//!    record the order and the critical path, and build the traceability matrix.
//! 6. Store the plan exactly as the planner wrote it, the matrix and the record.
//!
//! The plan is never repaired. A plan that fails a check is stored all the same, because the gate
//! needs it to say what is wrong, and the engine sends it back to a new run of this stage.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::specification_contract::SpecStatus;
use factory_domain::contracts::{Contract, SpecificationContract, TaskDag};
use factory_domain::ids::PlanId;
use factory_domain::policy::RepoKind;
use factory_domain::scope::TenantScope;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::{RiskTier, StageKind};
use serde_json::{Value, json};

use super::envelope::Envelope;
use super::handler::{MATRIX, PlanningHandler, RECORD, TASK_PLAN};
use super::metadata::{Assigned, Expected};
use super::replan::kept_tasks;
use crate::gates::dag::{self, DesignLink, Matrix, MatrixInput, SpecFacts};
use crate::handlers::{StageContext, StageError, StageOutput};
use crate::prompts::{Assembler, AssemblyRequest, ContentClass, Input, Limits, Scope, Source};
use crate::stages::architecture::design::Design;
use crate::stages::architecture::shared::{
    Call, Tools, feedback_text, human_answers, load, read_input, run_agent, seam, store_bytes,
    store_json,
};
use crate::stages::implementation::input::{
    ARCHITECTURE, REPOSITORY_MAP, SPECIFICATION_CONTRACT, map_commit,
};

/// The links of the design to the plan.
pub(super) fn design_links(design: &Design) -> Vec<DesignLink> {
    design
        .elements
        .iter()
        .map(|element| DesignLink {
            element_id: element.id.clone(),
            satisfies: element.satisfies.clone(),
            touches: element.touches.clone(),
        })
        .collect()
}

/// Every requirement identifier of the specification, functional or not.
pub(super) fn all_requirements(spec: &SpecificationContract) -> std::collections::BTreeSet<String> {
    spec.requirements
        .iter()
        .map(|requirement| requirement.id.as_str().to_owned())
        .chain(
            spec.nonfunctional_requirements
                .iter()
                .map(|requirement| requirement.id.as_str().to_owned()),
        )
        .collect()
}

pub(super) async fn execute(
    handler: &PlanningHandler,
    ctx: &mut StageContext<'_>,
) -> Result<StageOutput, StageError> {
    let ports = ctx.ports;
    let identity = ctx.identity;
    let missing = || StageError::Blocked(BlockedCode::DependencyUnavailable);

    // 1. The inputs.
    let (spec_ref, spec_bytes) = read_input(ctx, SPECIFICATION_CONTRACT).await?;
    let (design_ref, design_bytes) = read_input(ctx, ARCHITECTURE).await?;
    let (map_ref, map_bytes) = read_input(ctx, REPOSITORY_MAP).await?;
    let spec = std::str::from_utf8(&spec_bytes)
        .ok()
        .and_then(|text| SpecificationContract::from_json_str(text).ok())
        .ok_or_else(missing)?;
    if spec.metadata.status != SpecStatus::Approved {
        return Err(missing());
    }
    let design = serde_json::from_slice::<Value>(&design_bytes)
        .ok()
        .and_then(|value| Design::read(&value).ok())
        .ok_or_else(missing)?;
    let base = map_commit(&map_bytes).ok_or_else(missing)?;
    let facts = SpecFacts::from_contract(&spec);

    // 2. The rounds before this one, and the tasks that can be kept.
    let previous = handler.rounds.previous(&identity).await.map_err(seam)?;
    let mut kept: Vec<String> = Vec::new();
    if let Some(reference) = previous
        .as_ref()
        .and_then(|round| round.previous_plan.as_ref())
    {
        let bytes = ports
            .artifacts
            .get(&TenantScope::new(identity.tenant), reference)
            .await
            .map_err(|_| StageError::Tool)?;
        if let Some(plan) = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| TaskDag::from_json_str(text).ok())
        {
            let report = dag::validate(&plan, &facts, &handler.config.limits);
            kept = kept_tasks(&plan, &report.findings);
        }
    }
    let answers = human_answers(ctx).await?;
    let feedback = feedback_text(previous.as_ref(), &answers, &kept);

    // 3. The values the factory assigns.
    let now = ports.clock.now();
    let expected = Expected::assign(Assigned {
        plan: PlanId::from_uuid(ports.ids.new_uuid()),
        version: previous.as_ref().map_or(0, |round| round.plan_version) + 1,
        job: identity.job,
        mode: ctx.mode,
        spec: spec.metadata.spec_id,
        spec_version: spec.metadata.spec_version.get(),
        spec_sha256: spec_ref.sha256.clone(),
        architecture_sha256: design_ref.sha256.clone(),
        created_at: now,
    })
    .ok_or(StageError::Internal)?;

    // 4. The prompt and the planner.
    let planner = load(ports.registry, &handler.config.agent).map_err(|_| StageError::Internal)?;
    let host = |kind: &str, sha: &Sha256Digest| Source::HostArtifact {
        kind: kind.to_owned(),
        id: sha.to_string(),
    };
    let rendered = expected.render();
    let mut inputs = vec![
        Input::untrusted(
            "frozen_specification",
            ContentClass::SpecificationText,
            host("frozen-specification", &spec_ref.sha256),
            identity.tenant,
            spec_bytes.clone(),
        )
        .fetched_at(now),
        Input::untrusted(
            "architecture",
            ContentClass::ModelOutput,
            host("architecture-design", &design_ref.sha256),
            identity.tenant,
            design_bytes.clone(),
        )
        .fetched_at(now),
        Input::untrusted(
            "repository_map",
            ContentClass::ToolOutput,
            host("repository-map", &map_ref.sha256),
            identity.tenant,
            map_bytes.clone(),
        )
        .fetched_at(now),
        Input::untrusted(
            "plan_metadata",
            ContentClass::ToolOutput,
            host("plan-metadata", &Sha256Digest::of(rendered.as_bytes())),
            identity.tenant,
            rendered.clone().into_bytes(),
        )
        .fetched_at(now),
    ];
    if let Some(text) = &feedback {
        inputs.push(
            Input::untrusted(
                "rework_findings",
                ContentClass::ToolOutput,
                host("plan-check-findings", &Sha256Digest::of(text.as_bytes())),
                identity.tenant,
                text.clone().into_bytes(),
            )
            .fetched_at(now),
        );
    }
    let assembled = Assembler::new(&handler.redactor, &handler.policy.paths, Limits::default())
        .assemble(AssemblyRequest::new(
            &planner.manifest,
            &planner.prompt,
            Scope::new(identity.tenant, RepoKind::Target),
            inputs,
        ))
        .map_err(|_| StageError::Internal)?;
    let answer = run_agent(
        ctx,
        &handler.config.settings,
        Tools {
            redactor: handler.redactor.as_ref(),
            specs: handler.specs.as_ref(),
            probes: handler.probes.as_ref(),
            schemas: handler.schemas.as_ref(),
        },
        &Call {
            loaded: &planner,
            assembled: &assembled,
            base: &base,
            stage: StageKind::TaskPlanning,
            risk: RiskTier::Medium,
            report_ready: true,
        },
    )
    .await?;

    // 5. The envelope, and the plan inside it.
    let envelope =
        Envelope::read(&answer.validated.value).map_err(|_| StageError::InvalidOutput)?;
    let mut record = json!({
        "kind": RECORD,
        "schema_version": 1,
        "round": previous.as_ref().map_or(0, |round| round.round),
        "expected_metadata": expected.to_json(),
        "specification_sha256": spec_ref.sha256,
        "architecture_sha256": design_ref.sha256,
        "envelope_sha256": answer.validated.sha256,
        "kept_tasks": kept,
        "planner": {
            "agent": planner.manifest.id.as_str(),
            "version": planner.manifest.version.to_string(),
            "runtime": answer.runtime,
            "runtime_version": answer.runtime_version,
            "model": answer.model,
        },
        "prompt": {
            "signals": assembled.manifest().signals.iter().map(|signal| signal.name()).collect::<Vec<_>>(),
            "sha256": assembled.sha256(),
        },
        "usage": {
            "input_tokens": answer.usage.input_tokens,
            "output_tokens": answer.usage.output_tokens,
            "cost_micro_usd": answer.usage.cost.0,
            "requests": answer.usage.requests,
        },
    });
    let mut artifacts = Vec::new();
    let map = record.as_object_mut().ok_or(StageError::Internal)?;
    match envelope {
        Envelope::NeedsHuman {
            question,
            ignored_instructions,
        } => {
            map.insert("status".into(), json!("needs_human"));
            map.insert("human_question".into(), json!(question));
            map.insert("ignored_instructions".into(), json!(ignored_instructions));
        }
        Envelope::Done {
            plan: plan_value,
            ignored_instructions,
        } => {
            let plan = TaskDag::from_json_value(plan_value.clone())
                .map_err(|_| StageError::InvalidOutput)?;
            let report = dag::validate(&plan, &facts, &handler.config.limits);
            let matrix = Matrix::build(&MatrixInput {
                requirements: &all_requirements(&spec),
                scenarios: &facts.scenarios,
                design: &design_links(&design),
                plan: &plan,
            });
            let plan_bytes = serde_json::to_vec(&plan_value).map_err(|_| StageError::Internal)?;
            map.insert("status".into(), json!("done"));
            map.insert("plan_sha256".into(), json!(Sha256Digest::of(&plan_bytes)));
            map.insert("ignored_instructions".into(), json!(ignored_instructions));
            if let Some(analysis) = &report.analysis {
                map.insert(
                    "analysis".into(),
                    json!({
                        "order": analysis.order,
                        "critical_path": {
                            "tasks": analysis.critical_path.tasks,
                            "seconds": analysis.critical_path.seconds,
                        },
                        "declared_critical_path": analysis.declared_critical_path,
                        "parallel_pairs": analysis.parallel_pairs,
                    }),
                );
            }
            artifacts.push(store_bytes(ctx, TASK_PLAN, plan_bytes, "application/json").await?);
            artifacts.push(store_json(ctx, MATRIX, &matrix.to_json()).await?);
        }
    }
    artifacts.push(store_json(ctx, RECORD, &record).await?);
    Ok(StageOutput {
        artifacts,
        usage: answer.usage,
        permission_denials: answer.denials,
        ..StageOutput::default()
    })
}
