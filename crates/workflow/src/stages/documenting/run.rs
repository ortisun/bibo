//! `execute` of the documenting stage: the plan, the writer, the audit and the commit.
//!
//! In order, and each step ends the stage if it fails:
//!
//! 1. Read the implementation result and the frozen specification by the hash the contract pinned.
//! 2. Export the code patch from the job's object store on the host, read the tree at the base and
//!    at the head, and derive the documentation plan with the impact policy. The plan is stored
//!    whatever follows. A change that needs no document gets a plan that says so, and no writer
//!    runs.
//! 3. Otherwise make a checkout of the head commit (or of the head the replaced run ended with, for
//!    a rework round) and an `agent` sandbox over it, and check the spec the seam returned.
//! 4. Run the writer. The prompt holds the plan, the frozen specification, the code patch and, in
//!    a rework round, the failed reports and findings. All of it is untrusted data in a quoted
//!    block.
//! 5. Remove the sandbox, and only then read the tree. The host audits it (`Workspace::ingest`),
//!    checks that every changed path is a path the writer may write, and makes the commit itself.
//!
//! A change the audit refuses, or a path outside the writer's scope, is **never committed**: the
//! refusal and its paths go into `documentation-result`, and `evaluate` turns it into a policy
//! violation that blocks the stage run.

use factory_domain::contracts::agent_manifest::{AgentPlacement, RecommendedTier, ToolAccess};
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::{AgentManifest, ArtifactRef, VersionedRef};
use factory_domain::machines::guards::EnvironmentCause;
use factory_domain::policy::RepoKind;
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, Sha256Digest, Slug};
use factory_domain::vocabulary::{Fidelity, RiskTier, StageKind};
use factory_ports::agent::{AgentRunRequest, Capability, RoutingNeed};
use factory_ports::paths::CommitSha;
use factory_ports::registry::VersionReq;
use factory_ports::workspace::{
    ChangeKind, CommitRequest, JobRepo, Workspace, WorkspaceError, WorkspacePurpose,
    WorkspaceRequest,
};
use serde_json::{Value, json};

use super::handler::DocumentingHandler;
use super::input::{
    DOCUMENTATION_PLAN, DOCUMENTATION_RESULT, DOMAIN_PROFILE, IMPLEMENTATION_RESULT,
    SPECIFICATION_CONTRACT, input_artifact, parse_candidate,
};
use super::repo::{pages_naming, program_name, read_tree};
use super::writer::WriterReport;
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::gates::docs::plan::{Binding, Facts, derive, parse_patch};
use crate::handlers::{NamedArtifact, NeedsHumanRequest, StageContext, StageError, StageOutput};
use crate::prompts::{Assembler, AssemblyRequest, ContentClass, Input, Limits, Scope, Source};
use crate::stages::implementation::feedback;
use crate::stages::implementation::run::{
    close, mode_name, open_sandbox, seam_error, workspace_error,
};
use crate::stages::implementation::scope::outside;
use crate::stages::implementation::seams::WorkspaceAccess;

/// What the writer needs from the runtime.
const NEEDS: [Capability; 0] = [];

fn slug(text: &str) -> Result<Slug, StageError> {
    Slug::parse(text).map_err(|_| StageError::Internal)
}

async fn put(
    ctx: &StageContext<'_>,
    name: &str,
    value: &Value,
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

/// The globs the writer may write: the `fs.write` grants of its manifest.
pub(crate) fn write_globs(manifest: &AgentManifest) -> Vec<String> {
    manifest
        .allowed_tools
        .as_slice()
        .iter()
        .filter(|tool| tool.access == ToolAccess::Write)
        .flat_map(|tool| {
            tool.path_scope
                .iter()
                .flatten()
                .map(|glob| glob.as_str().to_owned())
        })
        .collect()
}

/// A change the audit refused.
fn refusal_of(error: &WorkspaceError) -> Option<(&'static str, Vec<(String, String)>)> {
    Some(match error {
        WorkspaceError::ProtectedPathChanged(violations) => (
            "protected-path-changed",
            violations
                .iter()
                .map(|v| (v.path.as_str().to_owned(), mode_name(v.mode).to_owned()))
                .collect(),
        ),
        WorkspaceError::SecretFound(findings) => (
            "secret-found",
            findings
                .iter()
                .map(|f| {
                    (
                        f.path
                            .as_ref()
                            .map(|p| p.as_str().to_owned())
                            .unwrap_or_default(),
                        f.rule.as_str().to_owned(),
                    )
                })
                .collect(),
        ),
        WorkspaceError::HiddenPathPresent(path) => (
            "hidden-path-present",
            vec![(path.as_str().to_owned(), "hidden".to_owned())],
        ),
        WorkspaceError::EscapingSymlink(path) => (
            "escaping-symlink",
            vec![(path.as_str().to_owned(), "link".to_owned())],
        ),
        WorkspaceError::Gitlink(path) => (
            "gitlink",
            vec![(path.as_str().to_owned(), "link".to_owned())],
        ),
        WorkspaceError::NestedGit(path) => (
            "nested-git",
            vec![(path.as_str().to_owned(), "git".to_owned())],
        ),
        WorkspaceError::TooLarge => ("change-too-large", Vec::new()),
        _ => return None,
    })
}

/// What the stage learned and records in `documentation-result`.
struct Outcome {
    head: CommitSha,
    writer_ran: bool,
    /// The runtime and the model the writer ran on, when it ran. The documentation reviewer is
    /// routed against it (`writer_selection`).
    writer_model: Option<(String, String)>,
    changes: Vec<(String, &'static str)>,
    additions: u64,
    deletions: u64,
    report: Option<WriterReport>,
    unresolved: Vec<String>,
    refusal: Option<(&'static str, Vec<(String, String)>)>,
    out_of_scope: Vec<String>,
    spent: factory_ports::agent::Usage,
}

pub(super) async fn execute(
    handler: &DocumentingHandler,
    ctx: &mut StageContext<'_>,
) -> Result<StageOutput, StageError> {
    let ports = ctx.ports;
    let identity = ctx.identity;
    let scope = TenantScope::new(identity.tenant);
    let missing = || StageError::Blocked(BlockedCode::DependencyUnavailable);

    // 1. The inputs, by the hash the contract pinned.
    let read = |name: &'static str| {
        let reference = input_artifact(ctx.contract, name);
        let artifacts = ports.artifacts;
        async move {
            let reference: ArtifactRef = reference.ok_or_else(missing)?;
            let bytes = artifacts
                .get(&scope, &reference)
                .await
                .map_err(|_| missing())?;
            Ok::<_, StageError>((reference, bytes))
        }
    };
    let (_, result_bytes) = read(IMPLEMENTATION_RESULT).await?;
    let (spec_ref, specification) = read(SPECIFICATION_CONTRACT).await?;
    let candidate = parse_candidate(&result_bytes).ok_or_else(missing)?;
    let profile = match input_artifact(ctx.contract, DOMAIN_PROFILE) {
        Some(reference) => {
            let bytes = ports
                .artifacts
                .get(&scope, &reference)
                .await
                .map_err(|_| missing())?;
            serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|v| v.get("profile").and_then(Value::as_str).map(str::to_owned))
                .unwrap_or_else(|| "general-software".to_owned())
        }
        None => "general-software".to_owned(),
    };

    // 2. The change, and the plan the impact policy derives from it.
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
        .get(&scope, &export.patch)
        .await
        .map_err(|_| StageError::Tool)?;
    let changed = parse_patch(&String::from_utf8_lossy(&patch));
    let tree_head = read_tree(repo.as_ref(), &candidate.head)
        .await
        .map_err(workspace_error)?;
    let tree_base = read_tree(repo.as_ref(), &candidate.base)
        .await
        .map_err(workspace_error)?;
    let path_list: Vec<String> = changed.iter().map(|file| file.path.clone()).collect();
    let paths: Vec<&str> = path_list.iter().map(String::as_str).collect();
    let facts = Facts {
        documented: pages_naming(&tree_base.pages, &paths),
        existing_pages: tree_base.pages.keys().cloned().collect(),
        program: tree_head
            .manifest
            .as_deref()
            .and_then(|manifest| program_name(manifest, &tree_head.files)),
        profile,
        changed,
    };
    let plan = derive(
        &facts,
        Binding {
            base_commit: candidate.base.as_str().to_owned(),
            code_head: candidate.head.as_str().to_owned(),
            specification_sha256: spec_ref.sha256.to_string(),
        },
    );
    let plan_json = plan.to_json();
    // The bytes the stage stores, kept: the writer's prompt needs the plan, and the engine has not
    // indexed the artifact for the tenant yet (it does that when it records the result), so the
    // stage cannot ask the artifact store for what it has just written.
    let plan_bytes = serde_json::to_vec(&plan_json).map_err(|_| StageError::Internal)?;
    let plan_artifact = put(ctx, DOCUMENTATION_PLAN, &plan_json).await?;

    // The agent and the words it is given.
    let manifest = ports
        .registry
        .manifest(&handler.config.agent, &VersionReq::Any)
        .map_err(|_| StageError::Internal)?;
    if !manifest
        .permitted_placements
        .as_slice()
        .contains(&AgentPlacement::Sandbox)
    {
        return Err(StageError::Environment(EnvironmentCause::PolicyViolation));
    }
    let rework = handler.rework.of(&identity).await.map_err(seam_error)?;
    let on = rework
        .as_ref()
        .map_or_else(|| candidate.head.clone(), |r| r.previous_head.clone());

    let outcome = if plan.needs_writing() {
        write_in_sandbox(
            handler,
            ctx,
            repo.as_ref(),
            &manifest,
            &on,
            &candidate.base,
            &plan_artifact.artifact,
            &plan_bytes,
            &specification,
            &spec_ref.sha256,
            &patch,
            &paths,
            rework.as_ref().map(feedback::render),
        )
        .await?
    } else {
        // Nothing to write: the sandbox is still proved, because the contract declares one and the
        // engine fails a stage that declares a sandbox and never reports it ready.
        prove_sandbox(handler, ctx, &candidate.head, &candidate.base).await?;
        Outcome {
            head: candidate.head.clone(),
            writer_ran: false,
            writer_model: None,
            changes: Vec::new(),
            additions: 0,
            deletions: 0,
            report: None,
            unresolved: Vec::new(),
            refusal: None,
            out_of_scope: Vec::new(),
            spent: factory_ports::agent::Usage::default(),
        }
    };
    if let Some(reason) = outcome
        .report
        .as_ref()
        .and_then(WriterReport::asks_a_person)
    {
        return Ok(StageOutput {
            artifacts: vec![plan_artifact],
            usage: outcome.spent,
            needs_human: Some(NeedsHumanRequest {
                reason: slug(reason)?,
                detail: None,
            }),
            ..StageOutput::default()
        });
    }

    let fake = [
        ports.workspaces.fidelity(),
        ports.sandbox.fidelity(),
        ports.runtime.fidelity(),
    ]
    .contains(&Fidelity::Fake);
    let report = outcome.report.as_ref();
    let result = json!({
        "schema_version": 1,
        "kind": DOCUMENTATION_RESULT,
        "base_commit": candidate.base.as_str(),
        "code_head": candidate.head.as_str(),
        "head_commit": outcome.head.as_str(),
        "writer_ran": outcome.writer_ran,
        // The engine's own routing answer, not the writer's account: the documentation reviewer
        // is routed against it, so that it is independent of the writer.
        "writer_model": outcome.writer_model.as_ref().map(|(runtime, model)| json!({
            "runtime": runtime,
            "model": model,
        })),
        "changes": outcome.changes.iter()
            .map(|(path, kind)| json!({ "path": path, "kind": kind }))
            .collect::<Vec<_>>(),
        "additions": outcome.additions,
        "deletions": outcome.deletions,
        // What the writer says. Statements, not evidence: the gates measure the documents.
        "reported": {
            "claims": report.map_or_else(Vec::new, |r| r.claims.iter()
                .map(|(claim, path)| json!({ "claim": claim, "evidence_path": path }))
                .collect()),
            "plan_coverage": report.map_or_else(Vec::new, |r| r.coverage.iter()
                .map(|(item, status)| json!({ "plan_item": item, "status": status }))
                .collect()),
            "files_written": report.map_or_else(Vec::new, |r| r.files_written.clone()),
            "ignored_instructions": report.map_or_else(Vec::new, |r| r.ignored_instructions.clone()),
        },
        "unresolved_claims": outcome.unresolved,
        "refusal": outcome.refusal.as_ref().map(|(code, paths)| json!({
            "code": code,
            "paths": paths.iter().map(|(p, r)| json!([p, r])).collect::<Vec<_>>(),
        })),
        "out_of_scope": outcome.out_of_scope,
        "spent": {
            "input_tokens": outcome.spent.input_tokens,
            "output_tokens": outcome.spent.output_tokens,
            "cost_micro_usd": outcome.spent.cost.0,
            "requests": outcome.spent.requests,
        },
        "fake": fake,
    });
    let result_artifact = put(ctx, DOCUMENTATION_RESULT, &result).await?;
    Ok(StageOutput {
        artifacts: vec![plan_artifact, result_artifact],
        usage: outcome.spent,
        ..StageOutput::default()
    })
}

/// A stage that writes nothing still proves that the sandbox can be made.
async fn prove_sandbox(
    handler: &DocumentingHandler,
    ctx: &mut StageContext<'_>,
    head: &CommitSha,
    job_base: &CommitSha,
) -> Result<(), StageError> {
    let workspace = ctx
        .ports
        .workspaces
        .create(
            WorkspaceRequest {
                job: ctx.identity.job,
                attempt: ctx.attempt,
                base: head.clone(),
                protected_base: Some(job_base.clone()),
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
        WorkspaceAccess::Edit,
        &NEEDS,
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

#[allow(clippy::too_many_arguments)]
async fn write_in_sandbox(
    handler: &DocumentingHandler,
    ctx: &mut StageContext<'_>,
    repo: &dyn JobRepo,
    manifest: &AgentManifest,
    on: &CommitSha,
    job_base: &CommitSha,
    plan_ref: &ArtifactRef,
    plan_bytes: &[u8],
    specification: &[u8],
    spec_sha: &Sha256Digest,
    patch: &[u8],
    changed_paths: &[&str],
    feedback_text: Option<String>,
) -> Result<Outcome, StageError> {
    // The writer's rounds start from the code head or an earlier round, and are judged against
    // the commit the job started from, as the builder's are (ADR 0024).
    let workspace = ctx
        .ports
        .workspaces
        .create(
            WorkspaceRequest {
                job: ctx.identity.job,
                attempt: ctx.attempt,
                base: on.clone(),
                protected_base: Some(job_base.clone()),
                rules: handler.config.path_rules.clone(),
                purpose: WorkspacePurpose::Agent,
            },
            ctx.cancel,
        )
        .await
        .map_err(workspace_error)?;
    let result = write_in(
        handler,
        ctx,
        repo,
        workspace.as_ref(),
        manifest,
        on,
        plan_ref,
        plan_bytes,
        specification,
        spec_sha,
        patch,
        changed_paths,
        feedback_text,
    )
    .await;
    // The checkout goes whatever happened. The commit it made stays in the job's object store.
    let _ = workspace.dispose().await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn write_in(
    handler: &DocumentingHandler,
    ctx: &mut StageContext<'_>,
    repo: &dyn JobRepo,
    workspace: &dyn Workspace,
    manifest: &AgentManifest,
    on: &CommitSha,
    plan_ref: &ArtifactRef,
    plan_bytes: &[u8],
    specification: &[u8],
    spec_sha: &Sha256Digest,
    patch: &[u8],
    changed_paths: &[&str],
    feedback_text: Option<String>,
) -> Result<Outcome, StageError> {
    let ports = ctx.ports;
    let identity = ctx.identity;
    let scope = TenantScope::new(identity.tenant);
    let mut session = open_sandbox(
        handler.specs.as_ref(),
        ctx,
        workspace,
        WorkspaceAccess::Edit,
        &NEEDS,
        true,
    )
    .await?;

    let prompt = ports
        .registry
        .prompt(manifest)
        .map_err(|_| StageError::Internal)?;
    let assembled = {
        let now = ports.clock.now();
        let tenant = identity.tenant;
        let artifact = |kind: &str, sha: &Sha256Digest| Source::HostArtifact {
            kind: kind.to_owned(),
            id: sha.to_string(),
        };
        let mut inputs = vec![
            Input::untrusted(
                "documentation_plan",
                ContentClass::ModelOutput,
                artifact("documentation-plan", &plan_ref.sha256),
                tenant,
                plan_bytes,
            )
            .fetched_at(now),
            Input::untrusted(
                "frozen_specification",
                ContentClass::SpecificationText,
                artifact("frozen-specification", spec_sha),
                tenant,
                specification.to_vec(),
            )
            .fetched_at(now),
            Input::untrusted(
                "diff",
                ContentClass::ModelOutput,
                artifact("diff", &Sha256Digest::of(patch)),
                tenant,
                patch.to_vec(),
            )
            .touching(changed_paths.iter().map(|p| (*p).to_owned()))
            .fetched_at(now),
        ];
        if let Some(text) = feedback_text {
            inputs.push(
                Input::untrusted(
                    "rework_findings",
                    ContentClass::ToolOutput,
                    Source::ToolOutput {
                        producer: "rework-feedback".to_owned(),
                    },
                    tenant,
                    text.into_bytes(),
                )
                .fetched_at(now),
            );
        }
        Assembler::new(&handler.redactor, &handler.policy.paths, Limits::default()).assemble(
            AssemblyRequest::new(
                manifest,
                &prompt,
                Scope::new(tenant, RepoKind::Target),
                inputs,
            ),
        )
    };
    let assembled = match assembled {
        Ok(assembled) => assembled,
        Err(_) => {
            let _ = close(session, false).await;
            return Err(StageError::Internal);
        }
    };
    let need = RoutingNeed {
        stage: StageKind::Documenting,
        tier: RecommendedTier::Standard,
        required: NEEDS.to_vec(),
        risk: RiskTier::Low,
        exclude: Vec::new(),
        probed: handler.probes.probed(),
        author: None,
    };
    let route = match ports.router.route(&need) {
        Ok(route) => route,
        Err(_) => {
            let _ = close(session, false).await;
            return Err(StageError::Blocked(BlockedCode::ToolUnavailable));
        }
    };
    let token = ctx.job_token.ok_or(StageError::Internal)?;
    let writer_model = (
        route.model.runtime.as_str().to_owned(),
        route.model.model.as_str().to_owned(),
    );
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
    };
    let report = ports.runtime.run(&mut *session, request, ctx.cancel).await;

    // The container is gone before anything is read from the tree it wrote to.
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
    let validated = handler
        .schemas
        .check(&manifest.outputs_schema, output.as_bytes())
        .map_err(|_| StageError::InvalidOutput)?;
    let parsed = WriterReport::read(&validated.value).map_err(|_| StageError::InvalidOutput)?;
    let mut outcome = Outcome {
        head: on.clone(),
        writer_ran: true,
        writer_model: Some(writer_model),
        changes: Vec::new(),
        additions: 0,
        deletions: 0,
        report: None,
        unresolved: Vec::new(),
        refusal: None,
        out_of_scope: Vec::new(),
        spent: report.usage,
    };
    if parsed.asks_a_person().is_some() {
        outcome.report = Some(parsed);
        return Ok(outcome);
    }

    // The audit. A refusal is a result, not a failure to try again.
    let change = match workspace.ingest(ctx.cancel).await {
        Ok(change) => change,
        Err(error) => {
            return match refusal_of(&error) {
                Some(refusal) => {
                    ctx.note_audit(AuditAction::new(
                        if refusal.0 == "secret-found" {
                            AuditKind::SecretRedactedOrBlocked
                        } else {
                            AuditKind::ProtectedPathDecision
                        },
                        AuditDecision::Denied,
                    ));
                    outcome.refusal = Some(refusal);
                    outcome.report = Some(parsed);
                    Ok(outcome)
                }
                None => Err(workspace_error(error)),
            };
        }
    };
    // The writer says it is done and the tree is as it was: its word is contradicted.
    if change.is_empty() || change.base() != on {
        return Err(StageError::InvalidOutput);
    }
    if ctx.cancel.is_cancelled() {
        return Err(StageError::Cancelled);
    }
    let changed: Vec<String> = change
        .changes()
        .iter()
        .map(|c| c.path.as_str().to_owned())
        .collect();
    // The writer may write the README, the changelog and Markdown under docs, and nothing else.
    let globs = write_globs(manifest);
    outcome.out_of_scope = outside("documenting", &globs, &changed)
        .into_iter()
        .map(|found| found.path)
        .collect();
    outcome.changes = change
        .changes()
        .iter()
        .map(|c| {
            (
                c.path.as_str().to_owned(),
                match c.kind {
                    ChangeKind::Added => "added",
                    ChangeKind::Modified => "modified",
                    ChangeKind::Deleted => "deleted",
                },
            )
        })
        .collect();
    if !outcome.out_of_scope.is_empty() {
        ctx.note_audit(AuditAction::new(
            AuditKind::ProtectedPathDecision,
            AuditDecision::Denied,
        ));
        outcome.report = Some(parsed);
        return Ok(outcome);
    }

    // The commit is made on the host, from the tree that was audited.
    let commit = workspace
        .commit(
            &change,
            CommitRequest {
                message: "Document the change\n\nWritten by the documentation writer, committed by the factory after the change was audited.\n".to_owned(),
                author_name: handler.config.identity.name.clone(),
                author_email: handler.config.identity.email.clone(),
            },
        )
        .await
        .map_err(workspace_error)?;
    let export = repo
        .export_patch(on, &commit, handler.config.max_patch_bytes, ctx.cancel)
        .await
        .map_err(workspace_error)?;
    let stored = ports
        .artifacts
        .get(&scope, &export.patch)
        .await
        .map_err(|_| StageError::Tool)?;
    let (additions, deletions) = crate::stages::implementation::evidence::diff_stats(&stored);
    outcome.additions = additions;
    outcome.deletions = deletions;

    // Traceability: each claim cites a file that exists at the documentation commit.
    let tree = read_tree(repo, &commit).await.map_err(workspace_error)?;
    outcome.unresolved = parsed
        .claims
        .iter()
        .filter(|(_, path)| !tree.files.contains(strip_place(path)))
        .map(|(_, path)| path.clone())
        .collect();
    outcome.head = commit;
    outcome.report = Some(parsed);
    Ok(outcome)
}

/// `src/main.rs:12` and `src/main.rs#L12` cite the file `src/main.rs`.
pub(crate) fn strip_place(path: &str) -> &str {
    let path = path.split('#').next().unwrap_or(path);
    match path.rsplit_once(':') {
        Some((file, line)) if !line.is_empty() && line.chars().all(|c| c.is_ascii_digit()) => file,
        _ => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_place_in_a_cited_path_is_cut_off() {
        assert_eq!(strip_place("src/main.rs:12"), "src/main.rs");
        assert_eq!(strip_place("src/main.rs#L12"), "src/main.rs");
        assert_eq!(strip_place("src/main.rs"), "src/main.rs");
    }
}
