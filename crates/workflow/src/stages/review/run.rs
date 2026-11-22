//! `execute` of the review stage: the independent reviewer over the frozen specification, the
//! exported patch and the verified gate reports.
//!
//! In order, and each step ends the stage if it fails:
//!
//! 1. Read the implementation result, the validation evidence and the frozen specification by the
//!    hash the contract pinned. If the evidence is not about this change, the reviewer does not
//!    run: it would judge a change by reports of another one. The stage stores a record that says
//!    why, and the gate turns that into a `BLOCKED` report.
//! 2. Export the patch between the two commits from the job's object store, on the host.
//! 3. Make a checkout of the head commit and an `agent` sandbox over it, and check the spec the
//!    seam returned. The reviewer is granted no tool that writes or runs a command, and its
//!    checkout is a copy that is never ingested and is disposed of unread.
//! 4. Assemble the prompt with `assemble_independent`. Its inputs are of a type that no builder
//!    summary can have, and the hash of the builder's own evidence is withheld as well.
//! 5. Run the reviewer, remove the sandbox, check the answer against the schema of the agent, wrap
//!    it into the stored verdict with the factory's own fields, and check that every finding of a
//!    verdict other than `PASS` points at a line the patch shows.
//!
//! The reviewer's answer is never repaired. A document that fails a check is invalid output, and
//! the engine decides whether to try again.

use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::{ArtifactRef, Contract, VersionedRef};
use factory_domain::ids::ReviewId;
use factory_domain::policy::RepoKind;
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, Sha256Digest, Slug};
use factory_domain::vocabulary::{RiskTier, StageKind, Verdict};
use factory_ports::agent::{AgentRunRequest, RoutingNeed};
use factory_ports::registry::VersionReq;
use factory_ports::workspace::{WorkspacePurpose, WorkspaceRequest};
use serde_json::json;

use super::evidence::Evidence;
use super::findings::{EngineFields, Reviewer, wrap};
use super::handler::{RECORD, ReviewHandler, VERDICT};
use super::locate::PatchIndex;
use super::rejection::{Rejection, refuse};
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::handlers::{NamedArtifact, StageContext, StageError, StageOutput};
use crate::prompts::{Assembler, ContentClass, IndependentRequest, Input, Limits, Scope, Source};
use crate::stages::implementation::input::{
    IMPLEMENTATION_RESULT, SPECIFICATION_CONTRACT, VALIDATION_EVIDENCE, input_artifact,
    parse_candidate, upstream_output,
};
use crate::stages::implementation::run::{close, open_sandbox, workspace_error};
use crate::stages::implementation::seams::{WorkspaceAccess, verify_read_only_tools};
use crate::stages::validation::POLICY_INPUT;

/// The name of this stage in the reason of a refused answer.
const STAGE: &str = "code review";

fn slug(text: &str) -> Result<Slug, StageError> {
    Slug::parse(text).map_err(|_| StageError::Internal)
}

async fn store(
    ctx: &StageContext<'_>,
    name: &str,
    value: &serde_json::Value,
) -> Result<NamedArtifact, StageError> {
    let bytes = serde_json::to_vec(value).map_err(|_| StageError::Internal)?;
    let artifact = ctx
        .ports
        .artifacts
        .put(
            bytes,
            MediaType::parse("application/json").map_err(|_| StageError::Internal)?,
        )
        .await
        .map_err(|_| StageError::Tool)?;
    Ok(NamedArtifact {
        name: slug(name)?,
        artifact,
    })
}

/// A review that stops before the reviewer runs still proves that the sandbox can be made. The
/// contract declares a sandbox, and the engine fails a stage that declares one and never reports it
/// ready, so a missing sandbox cannot pass for a stage that did its work in one.
async fn prove_sandbox(
    handler: &ReviewHandler,
    ctx: &mut StageContext<'_>,
    head: &factory_ports::paths::CommitSha,
) -> Result<(), StageError> {
    let workspace = ctx
        .ports
        .workspaces
        .create(
            WorkspaceRequest {
                job: ctx.identity.job,
                attempt: ctx.attempt,
                base: head.clone(),
                protected_base: None,
                rules: handler.config.path_rules.clone(),
                purpose: WorkspacePurpose::Agent,
            },
            ctx.cancel,
        )
        .await
        .map_err(workspace_error)?;
    let result = match open_sandbox(
        handler.specs.as_ref(),
        ctx,
        workspace.as_ref(),
        WorkspaceAccess::Inspect,
        &[],
        true,
    )
    .await
    {
        Ok(session) => close(session, true).await,
        Err(error) => Err(error),
    };
    let _ = workspace.dispose().await;
    result
}

pub(super) async fn execute(
    handler: &ReviewHandler,
    ctx: &mut StageContext<'_>,
) -> Result<StageOutput, StageError> {
    let ports = ctx.ports;
    let identity = ctx.identity;
    let tenant = TenantScope::new(identity.tenant);
    let missing = || StageError::Blocked(BlockedCode::DependencyUnavailable);

    // 1. The inputs, by the hash the contract pinned.
    let read = |name: &'static str| {
        let reference = input_artifact(ctx.contract, name);
        let artifacts = ports.artifacts;
        async move {
            let reference: ArtifactRef = reference.ok_or_else(missing)?;
            let bytes = artifacts
                .get(&tenant, &reference)
                .await
                .map_err(|_| missing())?;
            Ok::<_, StageError>((reference, bytes))
        }
    };
    let (result_ref, result_bytes) = read(IMPLEMENTATION_RESULT).await?;
    let (_, evidence_bytes) = read(VALIDATION_EVIDENCE).await?;
    let (spec_ref, specification) = read(SPECIFICATION_CONTRACT).await?;
    let policy = input_artifact(ctx.contract, POLICY_INPUT).ok_or_else(missing)?;
    let candidate = parse_candidate(&result_bytes).ok_or_else(missing)?;
    let evidence = match Evidence::read(&evidence_bytes) {
        Ok(evidence) => evidence,
        Err(problem) => {
            let record = json!({
                "kind": RECORD,
                "reviewer_ran": false,
                "evidence": { "readable": false, "problem": problem.to_string() },
            });
            prove_sandbox(handler, ctx, &candidate.head).await?;
            return Ok(StageOutput {
                artifacts: vec![store(ctx, RECORD, &record).await?],
                ..StageOutput::default()
            });
        }
    };
    let unbound = evidence.unbound(&candidate, &result_ref.sha256, &policy.sha256);
    if !unbound.is_empty() {
        let record = json!({
            "kind": RECORD,
            "reviewer_ran": false,
            "evidence": { "readable": true, "not_bound_to": unbound },
        });
        prove_sandbox(handler, ctx, &candidate.head).await?;
        return Ok(StageOutput {
            artifacts: vec![store(ctx, RECORD, &record).await?],
            ..StageOutput::default()
        });
    }

    // 2. The patch, exported on the host.
    let repo = ports
        .workspaces
        .repo(identity.job)
        .await
        .map_err(workspace_error)?;
    let export = repo
        .export_patch(
            &candidate.base,
            &candidate.head,
            handler.config.max_patch_bytes,
            ctx.cancel,
        )
        .await
        .map_err(workspace_error)?;
    let patch = ports
        .artifacts
        .get(&tenant, &export.patch)
        .await
        .map_err(|_| StageError::Tool)?;
    let changed: Vec<String> = export
        .changes
        .iter()
        .map(|change| change.path.as_str().to_owned())
        .collect();

    // The agent and the words it is given.
    let manifest = ports
        .registry
        .manifest(&handler.config.agent, &VersionReq::Any)
        .map_err(|_| StageError::Internal)?;
    if !manifest
        .permitted_placements
        .as_slice()
        .contains(&factory_domain::contracts::agent_manifest::AgentPlacement::Sandbox)
    {
        return Err(StageError::Environment(
            factory_domain::machines::guards::EnvironmentCause::PolicyViolation,
        ));
    }
    // A reviewer changes nothing: it is granted no tool that writes or runs a command.
    verify_read_only_tools(&manifest)?;
    let prompt = ports
        .registry
        .prompt(&manifest)
        .map_err(|_| StageError::Internal)?;
    let rendered = evidence.render();
    // The project's rules for agents (ADR 0026): pinned by the contract, or the built-in copy.
    let rules = crate::stages::project_rules::block(ctx).await?;
    let assembled = {
        let now = ports.clock.now();
        let tenant_id = identity.tenant;
        let artifact = |kind: &str, sha: &Sha256Digest| Source::HostArtifact {
            kind: kind.to_owned(),
            id: sha.to_string(),
        };
        // The type of these inputs is the guard: `into_independent` refuses an agent's own account
        // of its work, so no builder summary can be passed to a reviewer prompt.
        let independent = |input: Input| input.fetched_at(now).into_independent();
        let inputs = vec![
            independent(Input::untrusted(
                "frozen_specification",
                ContentClass::SpecificationText,
                artifact("frozen-specification", &spec_ref.sha256),
                tenant_id,
                specification.clone(),
            )),
            independent(
                Input::untrusted(
                    "diff",
                    ContentClass::ModelOutput,
                    artifact("diff", &export.patch.sha256),
                    tenant_id,
                    patch.clone(),
                )
                .touching(changed.clone()),
            ),
            independent(Input::untrusted(
                "gate_reports",
                ContentClass::ToolOutput,
                artifact("gate-reports", &Sha256Digest::of(rendered.as_bytes())),
                tenant_id,
                rendered.clone().into_bytes(),
            )),
            rules.into_independent(),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StageError::Internal)?;
        // What the builder wrote about its own work never reaches this prompt. The hash of the
        // evidence manifest, which holds the builder's statements, is withheld as well.
        let mut scope = Scope::new(tenant_id, RepoKind::Target);
        if let Some((_, builder_evidence)) = upstream_output(
            ctx.upstream,
            StageKind::Implementation,
            crate::stages::implementation::EVIDENCE,
        ) {
            scope = scope.withholding(builder_evidence.sha256.clone());
        }
        Assembler::new(&handler.redactor, &handler.policy.paths, Limits::default())
            .assemble_independent(IndependentRequest::new(&manifest, &prompt, scope, inputs))
            .map_err(|_| StageError::Internal)?
    };

    // 3. A read-only checkout of the head commit, and a sandbox over it.
    let workspace = ports
        .workspaces
        .create(
            WorkspaceRequest {
                job: identity.job,
                attempt: ctx.attempt,
                base: candidate.head.clone(),
                protected_base: None,
                rules: handler.config.path_rules.clone(),
                // The agent profile takes a writable checkout only. This one is a copy for the
                // reviewer to read: it is never ingested, and it is disposed of unread.
                purpose: WorkspacePurpose::Agent,
            },
            ctx.cancel,
        )
        .await
        .map_err(workspace_error)?;
    let result = review_in(
        handler,
        ctx,
        workspace.as_ref(),
        &manifest,
        &assembled,
        &evidence,
        &export.patch,
        &patch,
        &spec_ref,
        &candidate,
    )
    .await;
    // The checkout goes whatever happened.
    let _ = workspace.dispose().await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn review_in(
    handler: &ReviewHandler,
    ctx: &mut StageContext<'_>,
    workspace: &dyn factory_ports::workspace::Workspace,
    manifest: &factory_domain::contracts::AgentManifest,
    assembled: &crate::prompts::Assembled,
    evidence: &Evidence,
    patch_ref: &ArtifactRef,
    patch: &[u8],
    spec_ref: &ArtifactRef,
    candidate: &crate::stages::implementation::input::Candidate,
) -> Result<StageOutput, StageError> {
    let ports = ctx.ports;
    let identity = ctx.identity;
    let mut session = open_sandbox(
        handler.specs.as_ref(),
        ctx,
        workspace,
        WorkspaceAccess::Inspect,
        &[],
        true,
    )
    .await?;
    // The same author the engine routed the token against, read from the same stored manifest, so
    // that the model the reviewer is run with is one the token allows.
    let author = crate::stages::implementation::evidence::builder_selection(
        ports.artifacts,
        &TenantScope::new(identity.tenant),
        ctx.upstream,
    )
    .await;
    let need = RoutingNeed {
        stage: StageKind::Review,
        tier: RecommendedTier::Standard,
        required: Vec::new(),
        risk: RiskTier::Low,
        exclude: Vec::new(),
        probed: handler.probes.probed(),
        author,
    };
    let route = match ports.router.route(&need) {
        Ok(route) => route,
        Err(_) => {
            let _ = close(session, false).await;
            return Err(StageError::Blocked(BlockedCode::ToolUnavailable));
        }
    };
    let token = ctx.job_token.ok_or(StageError::Internal)?;
    let model = route.model.model.as_str().to_owned();
    let independence = super::independence::record(&route);
    let request = AgentRunRequest {
        attempt: ctx.attempt,
        agent: VersionedRef {
            id: manifest.id.clone(),
            version: manifest.version.clone(),
        },
        prompt: assembled.to_port_prompt(),
        output_schema: manifest.outputs_schema.clone(),
        max_output_bytes: handler.config.max_output_bytes,
        broker: handler.config.broker.clone(),
        job_token: token,
        tools: manifest.allowed_tools.as_slice().to_vec(),
        limits: manifest.resource_limits.clone(),
        model: route.model,
        flag_set: route.flag_set,
        mcp_gateway: None,
    };
    let report = ports.runtime.run(&mut *session, request, ctx.cancel).await;
    close(session, report.outcome.is_ok()).await?;
    let output = match &report.outcome {
        Ok(output) => output.clone(),
        Err(error) => {
            ctx.note_failed_run(&report);
            return Err(error.clone().into());
        }
    };
    if ctx.cancel.is_cancelled() {
        return Err(StageError::Cancelled);
    }

    // 5. The answer, redacted, then checked twice and wrapped. The reviewer's free text (its title,
    // summary and the words of each finding) is written by a model that was shown the change, and
    // it goes into the verdict artifact and from there into later prompts and the pull request
    // description, so a secret in it is replaced before anything is stored (finding F-7 of the
    // cross-cutting security tests). The marker has no quote or backslash, so the JSON stays valid.
    // A reply the redactor cannot judge is not kept.
    let output_text = match std::str::from_utf8(output.as_bytes()) {
        Ok(text) => text,
        Err(_) => return Err(refuse(ctx, STAGE, &Rejection::NotText)),
    };
    let redacted_output = match handler.redactor.redact_str(output_text) {
        Ok(redacted) => {
            if redacted.report.replacements() > 0 {
                ctx.note_audit(AuditAction::new(
                    AuditKind::SecretRedactedOrBlocked,
                    AuditDecision::Noted,
                ));
            }
            redacted.output.into_owned()
        }
        Err(_) => {
            ctx.note_audit(AuditAction::new(
                AuditKind::SecretRedactedOrBlocked,
                AuditDecision::Denied,
            ));
            return Err(refuse(ctx, STAGE, &Rejection::NotRedactable));
        }
    };
    let Ok(validated) = handler
        .schemas
        .check(&manifest.outputs_schema, redacted_output.as_bytes())
    else {
        return Err(refuse(ctx, STAGE, &Rejection::Schema));
    };
    let fields = EngineFields {
        review: ReviewId::from_uuid(ports.ids.new_uuid()),
        job: identity.job,
        stage_run: identity.stage_run,
        mode: ctx.mode,
        created_at: ports.clock.now(),
        reviewer: Reviewer {
            agent_id: manifest.id.as_str().to_owned(),
            agent_version: manifest.version.to_string(),
            role: manifest.role.as_str().to_owned(),
            adapter: ports.runtime.id().as_str().to_owned(),
            adapter_version: report
                .runtime_version
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
            model: Some(model),
            fidelity: ports.runtime.fidelity(),
        },
        frozen_spec: spec_ref.sha256.clone(),
        diff: patch_ref.sha256.clone(),
        gate_reports: evidence.references(),
    };
    let wrapped = match wrap(&validated.value, &fields) {
        Ok(wrapped) => wrapped,
        Err(problem) => return Err(refuse(ctx, STAGE, &Rejection::of_wrap(&problem))),
    };
    // A finding of a verdict other than PASS cites a file and a line that the patch shows.
    if wrapped.verdict.verdict != Verdict::Pass {
        let index = PatchIndex::parse(patch);
        for (position, finding) in wrapped.verdict.findings.iter().enumerate() {
            let shown = finding.location.as_ref().is_some_and(|location| {
                location.line_start.is_some_and(|start| {
                    index.shows(
                        location.path.as_str(),
                        u32::try_from(start.get()).unwrap_or(0),
                        location
                            .line_end
                            .and_then(|end| u32::try_from(end.get()).ok()),
                    )
                })
            });
            if !shown {
                return Err(refuse(ctx, STAGE, &Rejection::not_shown(position, finding)));
            }
        }
    }

    let verdict_json = wrapped
        .verdict
        .to_json_value()
        .map_err(|_| StageError::Internal)?;
    let record = json!({
        "kind": RECORD,
        "reviewer_ran": true,
        "candidate": { "base_commit": candidate.base.as_str(), "head_commit": candidate.head.as_str() },
        "inputs": {
            "frozen_spec_sha256": spec_ref.sha256,
            "diff_sha256": patch_ref.sha256,
            "gate_report_ids": evidence.references().iter().map(|(id, _)| id.to_string()).collect::<Vec<_>>(),
            "builder_summary_given": false,
            "context": assembled.manifest().to_json(),
        },
        "reviewer": {
            "agent": manifest.id.as_str(),
            "version": manifest.version.to_string(),
            "runtime": ports.runtime.id().as_str(),
        },
        // How far the reviewer's model is from the builder's, from the router's decision.
        (super::independence::KEY): independence,
        "findings": {
            "reported": wrapped.reported_findings,
            "kept": wrapped.verdict.findings.len(),
        },
        "ignored_instructions": wrapped.ignored_instructions,
        "usage": {
            "input_tokens": report.usage.input_tokens,
            "output_tokens": report.usage.output_tokens,
            "cost_micro_usd": report.usage.cost.0,
            "requests": report.usage.requests,
        },
    });
    Ok(StageOutput {
        artifacts: vec![
            store(ctx, VERDICT, &verdict_json).await?,
            store(ctx, RECORD, &record).await?,
        ],
        usage: report.usage,
        permission_denials: report.permission_denials,
        ..StageOutput::default()
    })
}
