//! `execute` of the documentation review stage: the gate in a verify sandbox, then the independent
//! reviewer.
//!
//! In order, and each step ends the stage if it fails:
//!
//! 1. Read the implementation result, the frozen specification, the documentation plan and the
//!    documentation result by the hash the contract pinned.
//! 2. Read the tree at the documentation commit and export two patches on the host: the whole
//!    change from the job's base to the documentation head (to know which pages changed) and the
//!    code patch. The documentation patch is the part of the whole change that touches the pages
//!    the gates judge, so the reviewer sees exactly those pages over the same commits, also when
//!    the pages were written in the code commits and the writer changed nothing (documentation
//!    policy 9.9).
//! 3. Run the programs the checks need in a fresh verify sandbox and remove it
//!    ([`verify`](super::verify)), then run the checks and the readability gate. Each check
//!    becomes one typed gate report, and the reports are stored in `documentation-gate-report`.
//! 4. Make a checkout of the documentation commit and an `agent` sandbox over it, and check the
//!    spec the seam returned. The reviewer is granted no tool that writes or runs a command, and
//!    its checkout is a copy that is never ingested.
//! 5. Assemble the prompt with `assemble_independent`. Its inputs are of a type that no writer
//!    summary can have, and the hash of the writer's own result is withheld as well. What people
//!    answered goes in as its own input, so a question they settled is not asked again: first
//!    the answers to the earlier documentation review runs of the job, read through the
//!    `AnswerHistory` seam, then the answers to this run.
//! 6. Run the reviewer, remove the sandbox, check the answer against the schema of the agent, wrap
//!    it into the stored verdict with the factory's own fields, and check that every finding of a
//!    verdict other than `PASS` points at a line one of the two patches shows.
//!
//! The gate runs whatever the reviewer will say, and the reviewer runs whatever the gate found:
//! its findings are extra feedback for the writer when a check failed. It decides nothing that a
//! failed check decided.

use factory_domain::contracts::agent_manifest::{AgentPlacement, RecommendedTier};
use factory_domain::contracts::gate_report::{BlockedCode, DefinitionSource};
use factory_domain::contracts::{ArtifactRef, Contract, GateReport, VersionedRef};
use factory_domain::ids::ReviewId;
use factory_domain::machines::guards::EnvironmentCause;
use factory_domain::policy::RepoKind;
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, Sha256Digest, Slug};
use factory_domain::vocabulary::{Fidelity, RiskTier, StageKind, Verdict};
use factory_ports::agent::{AgentRunRequest, RoutingNeed};
use factory_ports::paths::CommitSha;
use factory_ports::registry::VersionReq;
use factory_ports::workspace::{WorkspacePurpose, WorkspaceRequest};
use serde_json::{Value, json};

use super::document::{GateBinding, gate_document};
use super::handler::DocumentationReviewHandler;
use super::verify::{Io, observe_all};
use crate::gates::command::report::{Subject, image_digest};
use crate::gates::docs::check::{self, Inputs};
use crate::gates::docs::plan::{DocPlan, Form, parse_patch, select_files};
use crate::gates::docs::report::{Reporter, SandboxFacts};
use crate::gates::readability::{
    Artifact, DocumentType, Options, ReadabilityGate, ReportContext, ReviewerPolicy,
};
use crate::handlers::{NamedArtifact, StageContext, StageError, StageOutput};
use crate::prompts::{Assembler, ContentClass, IndependentRequest, Input, Limits, Scope, Source};
use crate::stages::documenting::input::{
    DOCUMENTATION_GATE_REPORT, DOCUMENTATION_PLAN, DOCUMENTATION_RESULT, DOCUMENTATION_REVIEW,
    DOCUMENTATION_REVIEW_RECORD, IMPLEMENTATION_RESULT, SPECIFICATION_CONTRACT, input_artifact,
    parse_candidate,
};
use crate::stages::documenting::repo::read_tree;
use crate::stages::implementation::feedback::earlier_answers;
use crate::stages::implementation::run::{close, open_sandbox, seam_error, workspace_error};
use crate::stages::implementation::seams::{WorkspaceAccess, verify_read_only_tools};
use crate::stages::review::findings::{EngineFields, Reviewer, wrap};
use crate::stages::review::locate::PatchIndex;

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

/// The reports as the reviewer reads them: what each gate found, in words, and where.
pub(crate) fn render_reports(reports: &[Value]) -> String {
    let mut text = String::new();
    for report in reports {
        let gate = report["metadata"]["gate_id"].as_str().unwrap_or("gate");
        let outcome = report["outcome"].as_str().unwrap_or("UNKNOWN");
        text.push_str(&format!(
            "Gate {gate}: {outcome}. {}\n",
            report["reason"].as_str().unwrap_or("")
        ));
        for failure in report["failures"].as_array().into_iter().flatten() {
            let place = failure["location"]["path"]
                .as_str()
                .map_or_else(String::new, |path| {
                    format!(
                        " ({path}{})",
                        failure["location"]["line"]
                            .as_u64()
                            .map_or_else(String::new, |line| format!(":{line}"))
                    )
                });
            text.push_str(&format!(
                "  - {}{place}: {}\n",
                failure["check_id"].as_str().unwrap_or("failure"),
                failure["message"].as_str().unwrap_or("")
            ));
        }
        if let Some(missing) = report["blocked_reason"]["missing"].as_array() {
            let names: Vec<&str> = missing.iter().filter_map(Value::as_str).collect();
            text.push_str(&format!("  - blocked, missing: {}\n", names.join(", ")));
        }
        if let Some(why) = report["not_applicable_reason"]["justification"].as_str() {
            text.push_str(&format!("  - not applicable: {why}\n"));
        }
    }
    text
}

/// The document type the readability gate judges a page as: the changelog by its name, a planned
/// page by the form the plan gives it, the README as reference, any other page as explanation.
/// Public so that the end-to-end evidence collector judges a page as this stage does (A8).
#[must_use]
pub fn document_type(plan: &DocPlan, path: &str) -> DocumentType {
    if path == "CHANGELOG.md" {
        return DocumentType::Changelog;
    }
    plan.items
        .iter()
        .find(|item| item.page == path)
        .map(|item| match item.form {
            Form::Tutorial => DocumentType::Tutorial,
            Form::HowTo => DocumentType::HowTo,
            Form::Reference => DocumentType::Reference,
            Form::Explanation => DocumentType::Explanation,
            Form::Changelog => DocumentType::Changelog,
        })
        .unwrap_or(if path == "README.md" {
            DocumentType::Reference
        } else {
            DocumentType::Explanation
        })
}

/// What the documentation diff says when the change touches no documentation page. A stated
/// absence, so that the reviewer never reads an empty block as a patch that went missing.
pub(crate) const NO_PAGES: &str =
    "No documentation page changed between the job's base commit and the documentation head.\n";

/// What the reviewer reads when nobody answered a question of this documentation review or of
/// an earlier run of it in the job.
pub(crate) const NO_ANSWERS: &str =
    "No person has answered a question of this documentation review.";

/// The most bytes of one answer of a person that are read. An answer is short text typed by a
/// person; the bound only stops a pasted file from filling the prompt.
const ANSWER_MAX_BYTES: usize = 8 * 1024;

/// The documentation diff the reviewer reads: the sections of the whole change, from the job's
/// base to the documentation head, that touch the pages the gates judged. [`NO_PAGES`] when they
/// are none (documentation policy 9.9).
pub(crate) fn documentation_diff(
    whole_patch: &[u8],
    pages: &std::collections::BTreeSet<String>,
) -> Vec<u8> {
    let selected = select_files(whole_patch, pages);
    if selected.is_empty() {
        NO_PAGES.as_bytes().to_vec()
    } else {
        selected
    }
}

/// The heading of the answers people gave to earlier documentation review runs of the job.
pub(crate) const EARLIER_RUNS: &str = "People answered questions that earlier runs of this documentation review asked, in this job. Their decisions stand.";

/// The heading of the answers people gave to this documentation review run.
pub(crate) const THIS_RUN: &str =
    "People answered questions this documentation review asked. Their decisions stand.";

/// What the reviewer reads in `people_answers`, and how many answers it holds from where.
pub(crate) struct PeopleAnswers {
    /// The text of the input.
    pub text: String,
    /// How many answers came from earlier runs of the stage in the job.
    pub earlier: usize,
    /// How many answers came from this run.
    pub this_run: usize,
}

/// The text of `people_answers`: the answers of the earlier runs under [`EARLIER_RUNS`], then the
/// answers of this run under [`THIS_RUN`], each group in the same form the other stages give their
/// reviewers. A group with no answer is left out, and [`NO_ANSWERS`] stands for both being empty
/// (documentation policy 9.9).
pub(crate) fn render_answers(earlier: &[String], this_run: &[String]) -> String {
    let earlier = earlier_answers(earlier);
    let this_run = earlier_answers(this_run);
    match (earlier.is_empty(), this_run.is_empty()) {
        (true, true) => NO_ANSWERS.to_owned(),
        (true, false) => format!("{THIS_RUN}\n{this_run}"),
        (false, true) => format!("{EARLIER_RUNS}\n{earlier}"),
        (false, false) => format!("{EARLIER_RUNS}\n{earlier}\n{THIS_RUN}\n{this_run}"),
    }
}

/// What people answered the earlier documentation review runs of the job, from the store through
/// the seam, and this run, from the stage's own context, as the reviewer reads it.
async fn people_answers(
    handler: &DocumentationReviewHandler,
    ctx: &StageContext<'_>,
) -> Result<PeopleAnswers, StageError> {
    let earlier = handler
        .answers
        .earlier_answers(&ctx.identity)
        .await
        .map_err(seam_error)?;
    let scope = TenantScope::new(ctx.identity.tenant);
    let mut this_run = Vec::with_capacity(ctx.human_inputs.len());
    for answer in ctx.human_inputs {
        let bytes = ctx
            .ports
            .artifacts
            .get(&scope, answer)
            .await
            .map_err(|_| StageError::Tool)?;
        let bounded = bytes
            .get(..bytes.len().min(ANSWER_MAX_BYTES))
            .unwrap_or(&bytes);
        this_run.push(String::from_utf8_lossy(bounded).into_owned());
    }
    Ok(PeopleAnswers {
        text: render_answers(&earlier, &this_run),
        earlier: earlier.len(),
        this_run: this_run.len(),
    })
}

/// The most bytes of a page that are read at the job's base to compare its title.
const MAX_BASE_PAGE_BYTES: u64 = 1024 * 1024;

/// The title of a page: its first level-one heading, or its path when it has none.
#[must_use]
pub fn title_of<'a>(path: &'a str, text: &'a str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix("# "))
        .map_or(path, str::trim)
}

/// Exports the patch between two commits on the host and reads it back.
async fn export_patch(
    repo: &dyn factory_ports::workspace::JobRepo,
    artifacts: &dyn factory_ports::artifact::ArtifactStore,
    scope: TenantScope,
    cancel: &dyn factory_ports::clock::CancelSignal,
    max: u64,
    from: CommitSha,
    to: CommitSha,
) -> Result<(factory_ports::workspace::PatchExport, Vec<u8>), StageError> {
    let exported = repo
        .export_patch(&from, &to, max, cancel)
        .await
        .map_err(workspace_error)?;
    let bytes = artifacts
        .get(&scope, &exported.patch)
        .await
        .map_err(|_| StageError::Tool)?;
    Ok((exported, bytes))
}

pub(super) async fn execute(
    handler: &DocumentationReviewHandler,
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
    let (_, implementation) = read(IMPLEMENTATION_RESULT).await?;
    let (spec_ref, specification) = read(SPECIFICATION_CONTRACT).await?;
    let (plan_ref, plan_bytes) = read(DOCUMENTATION_PLAN).await?;
    let (_, result_bytes) = read(DOCUMENTATION_RESULT).await?;
    let candidate = parse_candidate(&implementation).ok_or_else(missing)?;
    let plan_json: Value = serde_json::from_slice(&plan_bytes).map_err(|_| missing())?;
    let plan = DocPlan::from_json(&plan_json).map_err(|_| missing())?;
    let result: Value = serde_json::from_slice(&result_bytes).map_err(|_| missing())?;
    let docs_head = result["head_commit"]
        .as_str()
        .and_then(|head| CommitSha::parse(head).ok())
        .ok_or_else(missing)?;
    let written_over = result["code_head"].as_str().ok_or_else(missing)?.to_owned();

    // 2. The trees and the patches, read on the host.
    let repo = ports
        .workspaces
        .repo(identity.job)
        .await
        .map_err(workspace_error)?;
    let tree = read_tree(repo.as_ref(), &docs_head)
        .await
        .map_err(workspace_error)?;
    let max = handler.config.max_patch_bytes;
    let export = |from: CommitSha, to: CommitSha| {
        export_patch(
            repo.as_ref(),
            ports.artifacts,
            scope,
            ctx.cancel,
            max,
            from,
            to,
        )
    };
    let (whole_export, whole_patch) = export(candidate.base.clone(), docs_head.clone()).await?;
    let (code_export, code_patch) = export(candidate.base.clone(), candidate.head.clone()).await?;
    let whole = parse_patch(&String::from_utf8_lossy(&whole_patch));
    let changed_docs: std::collections::BTreeSet<String> = whole
        .iter()
        .filter(|file| {
            file.path.ends_with(".md") && file.kind != crate::gates::docs::plan::Kind::Deleted
        })
        .map(|file| file.path.clone())
        .collect();
    // The reviewer's documentation diff: the pages the gates judge, from the same patch and so
    // over the same commits as the gate report's binding. Stored, so that its hash in the record
    // names an artifact.
    let docs_patch = documentation_diff(&whole_patch, &changed_docs);
    let docs_ref = ports
        .artifacts
        .put(docs_patch.clone(), whole_export.patch.media_type.clone())
        .await
        .map_err(|_| StageError::Tool)?;
    let changelog_added: String = whole
        .iter()
        .filter(|file| file.path == "CHANGELOG.md")
        .flat_map(|file| file.added.iter().cloned())
        .collect::<Vec<_>>()
        .join("\n");
    let redactor = &handler.redactor;
    let secret = |text: &str| redactor.contains_secret(text.as_bytes()).ok();
    let inputs = Inputs {
        plan: &plan,
        files: &tree.files,
        pages: &tree.pages,
        changed_docs: &changed_docs,
        changelog_added: &changelog_added,
        source_env: &tree.env,
        source_flags: &tree.flags,
        code_head_now: candidate.head.as_str(),
        written_over: &written_over,
        secret: &secret,
    };

    // 3. The programs the checks need, run in a fresh verify sandbox, and the checks.
    let needs = check::needs(&inputs);
    let observations = observe_all(
        &Io {
            ports,
            scope,
            rules: handler.config.path_rules.clone(),
            sandbox: &handler.config.verify,
            toolchain: &handler.config.toolchain,
            cancel: ctx.cancel,
            job: identity.job,
            attempt: ctx.attempt,
        },
        &docs_head,
        &needs,
    )
    .await?;
    let results = check::run(&inputs, &observations);
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
    let subject = Subject {
        job: identity.job,
        stage_run: identity.stage_run,
        attempt: ctx.attempt,
        mode: ctx.mode,
    };
    let image =
        image_digest(handler.config.verify.image.reference()).map_err(|_| StageError::Internal)?;
    let reporter = Reporter {
        subject,
        definition_commit: handler.config.definition_commit.clone(),
        fidelity,
        binding: Sha256Digest::of(
            format!(
                "{}\n{}\n{}\n{}",
                candidate.base, candidate.head, docs_head, plan_ref.sha256
            )
            .as_bytes(),
        ),
        sandbox: Some(SandboxFacts {
            image,
            arch: handler.config.verify.arch.clone(),
        }),
        clock: ports.clock,
        ids: ports.ids,
    };
    let mut reports: Vec<GateReport> = Vec::with_capacity(check::ALL.len() + 1);
    // The pages whose title the change kept as it was at the job's base: those titles are the
    // project's and are not judged (documentation policy 9.3). A page the base lacks, or one
    // whose title changed, has its title judged.
    let mut kept_titles: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for path in &changed_docs {
        let Some(head_text) = tree.pages.get(path) else {
            continue;
        };
        let Ok(repo_path) = factory_ports::paths::RepoPath::new(path) else {
            continue;
        };
        match repo
            .read_file_at(
                &candidate.base,
                &repo_path,
                MAX_BASE_PAGE_BYTES,
                factory_ports::workspace::ReadView::Trusted,
            )
            .await
        {
            Ok(bytes) => {
                let base_text = String::from_utf8_lossy(&bytes);
                if title_of(path, &base_text) == title_of(path, head_text) {
                    kept_titles.insert(path.clone());
                }
            }
            Err(factory_ports::workspace::WorkspaceError::PathNotFound(_)) => {}
            Err(error) => return Err(workspace_error(error)),
        }
    }
    let readability = {
        let pages: Vec<(&String, &String)> = changed_docs
            .iter()
            .filter_map(|path| tree.pages.get_key_value(path))
            .collect();
        let artifacts: Vec<Artifact<'_>> = pages
            .iter()
            .map(|(path, text)| {
                let artifact =
                    Artifact::documentation(title_of(path, text), document_type(&plan, path), text)
                        .at(path);
                if kept_titles.contains(path.as_str()) {
                    artifact.with_title_kept()
                } else {
                    artifact
                }
            })
            .collect();
        let now = ports.clock.now();
        ReadabilityGate::new(Options::new())
            .evaluate(
                &artifacts,
                &ReportContext {
                    gate_report_id: factory_domain::ids::GateReportId::from_uuid(
                        ports.ids.new_uuid(),
                    ),
                    job_id: identity.job,
                    stage_run_id: identity.stage_run,
                    attempt_id: Some(ctx.attempt),
                    execution_mode: ctx.mode,
                    definition_source: DefinitionSource::CentralConfig,
                    definition_commit: handler.config.definition_commit.clone(),
                    started_at: now,
                    finished_at: ports.clock.now(),
                    reviewer: ReviewerPolicy::Optional,
                },
            )
            .map_err(|_| StageError::Internal)?
    };
    reports.push(readability);
    for result in &results {
        reports.push(reporter.check(result, observations.sandbox_id.as_deref())?);
    }
    let report_values: Vec<Value> = reports
        .iter()
        .map(|report| report.to_json_value().map_err(|_| StageError::Internal))
        .collect::<Result<_, _>>()?;
    let external = results
        .iter()
        .find(|result| result.gate == check::LINKS)
        .map_or(0, |result| result.warnings.len());
    let gate_document = gate_document(
        &GateBinding {
            base_commit: &candidate.base,
            code_head: &candidate.head,
            documentation_head: &docs_head,
            plan_sha256: &plan_ref.sha256,
            specification_sha256: &spec_ref.sha256,
        },
        observations.sandbox_id.as_deref(),
        external,
        &report_values,
    );
    let gate_artifact = put(ctx, DOCUMENTATION_GATE_REPORT, &gate_document).await?;

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
    // A reviewer changes nothing: it is granted no tool that writes or runs a command.
    verify_read_only_tools(&manifest)?;
    let prompt = ports
        .registry
        .prompt(&manifest)
        .map_err(|_| StageError::Internal)?;
    let rendered = render_reports(&report_values);
    let writer_result = input_artifact(ctx.contract, DOCUMENTATION_RESULT);
    // The project's rules for agents (ADR 0026): pinned by the contract, or the built-in copy.
    let rules = crate::stages::project_rules::block(ctx).await?;
    let people = people_answers(handler, ctx).await?;
    let answers = people.text;
    let answers_sha = Sha256Digest::of(answers.as_bytes());
    let assembled = {
        let now = ports.clock.now();
        let tenant_id = identity.tenant;
        let artifact = |kind: &str, sha: &Sha256Digest| Source::HostArtifact {
            kind: kind.to_owned(),
            id: sha.to_string(),
        };
        // The type of these inputs is the guard: `into_independent` refuses an agent's own account
        // of its work, so no writer summary can be passed to a reviewer prompt.
        let independent = |input: Input| input.fetched_at(now).into_independent();
        let code_paths: Vec<String> = code_export
            .changes
            .iter()
            .map(|change| change.path.as_str().to_owned())
            .collect();
        let doc_paths: Vec<String> = changed_docs.iter().cloned().collect();
        let inputs = vec![
            independent(Input::untrusted(
                "frozen_specification",
                ContentClass::SpecificationText,
                artifact("frozen-specification", &spec_ref.sha256),
                tenant_id,
                specification.clone(),
            )),
            independent(Input::untrusted(
                "documentation_plan",
                ContentClass::ModelOutput,
                artifact("documentation-plan", &plan_ref.sha256),
                tenant_id,
                plan_bytes.clone(),
            )),
            independent(
                Input::untrusted(
                    "code_diff",
                    ContentClass::ModelOutput,
                    artifact("diff", &code_export.patch.sha256),
                    tenant_id,
                    code_patch.clone(),
                )
                .touching(code_paths),
            ),
            independent(
                Input::untrusted(
                    "documentation_diff",
                    ContentClass::ModelOutput,
                    artifact("diff", &docs_ref.sha256),
                    tenant_id,
                    docs_patch.clone(),
                )
                .touching(doc_paths),
            ),
            independent(Input::untrusted(
                "gate_reports",
                ContentClass::ToolOutput,
                artifact("gate-reports", &Sha256Digest::of(rendered.as_bytes())),
                tenant_id,
                rendered.clone().into_bytes(),
            )),
            // What people decided comes from the factory's own record of their answers, never
            // from a file the writer wrote.
            independent(Input::untrusted(
                "people_answers",
                ContentClass::IssueComment,
                artifact("people-answers", &answers_sha),
                tenant_id,
                answers.clone().into_bytes(),
            )),
            rules.into_independent(),
        ]
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StageError::Internal)?;
        // What the writer wrote about its own work never reaches this prompt. The hash of its
        // result, which holds its claims, is withheld as well.
        let mut scope_of_prompt = Scope::new(tenant_id, RepoKind::Target);
        if let Some(reference) = &writer_result {
            scope_of_prompt = scope_of_prompt.withholding(reference.sha256.clone());
        }
        Assembler::new(&handler.redactor, &handler.policy.paths, Limits::default())
            .assemble_independent(IndependentRequest::new(
                &manifest,
                &prompt,
                scope_of_prompt,
                inputs,
            ))
            .map_err(|_| StageError::Internal)?
    };

    // A read-only checkout of the documentation commit, and a sandbox over it.
    let workspace = ports
        .workspaces
        .create(
            WorkspaceRequest {
                job: identity.job,
                attempt: ctx.attempt,
                base: docs_head.clone(),
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
    let reviewed = review_in(handler, ctx, workspace.as_ref(), &manifest, &assembled).await;
    // The checkout goes whatever happened.
    let _ = workspace.dispose().await;
    let (output, usage, denials, runtime_version, model, independence) = reviewed?;

    // The answer, checked twice and wrapped.
    let validated = handler
        .schemas
        .check(&manifest.outputs_schema, output.as_bytes())
        .map_err(|_| StageError::InvalidOutput)?;
    let gate_ids: Vec<_> = reports
        .iter()
        .zip(&report_values)
        .map(|(report, value)| {
            (
                report.metadata.gate_report_id,
                Sha256Digest::of(&serde_json::to_vec(value).unwrap_or_default()),
            )
        })
        .collect();
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
            adapter_version: runtime_version,
            model,
            fidelity: ports.runtime.fidelity(),
        },
        frozen_spec: spec_ref.sha256.clone(),
        diff: docs_ref.sha256.clone(),
        gate_reports: gate_ids.clone(),
    };
    let wrapped = wrap(&validated.value, &fields).map_err(|_| StageError::InvalidOutput)?;
    // A finding of a verdict other than PASS cites a file and a line that one of the two patches
    // shows.
    if wrapped.verdict.verdict != Verdict::Pass {
        let code_index = PatchIndex::parse(&code_patch);
        let docs_index = PatchIndex::parse(&docs_patch);
        for finding in &wrapped.verdict.findings {
            let shown = finding.location.as_ref().is_some_and(|location| {
                location.line_start.is_some_and(|start| {
                    let start = u32::try_from(start.get()).unwrap_or(0);
                    let end = location
                        .line_end
                        .and_then(|end| u32::try_from(end.get()).ok());
                    code_index.shows(location.path.as_str(), start, end)
                        || docs_index.shows(location.path.as_str(), start, end)
                })
            });
            if !shown {
                return Err(StageError::InvalidOutput);
            }
        }
    }
    let verdict_json = wrapped
        .verdict
        .to_json_value()
        .map_err(|_| StageError::Internal)?;
    let record = json!({
        "schema_version": 1,
        "kind": DOCUMENTATION_REVIEW_RECORD,
        "reviewer_ran": true,
        "candidate": {
            "base_commit": candidate.base.as_str(),
            "code_head": candidate.head.as_str(),
            "documentation_head": docs_head.as_str(),
        },
        "inputs": {
            "frozen_spec_sha256": spec_ref.sha256,
            "plan_sha256": plan_ref.sha256,
            "code_diff_sha256": code_export.patch.sha256,
            "documentation_diff_sha256": docs_ref.sha256,
            "documentation_diff_pages": changed_docs.iter().collect::<Vec<_>>(),
            "people_answers_sha256": answers_sha,
            "people_answers_given": people.this_run,
            "people_answers_of_earlier_runs": people.earlier,
            "gate_report_ids": gate_ids.iter().map(|(id, _)| id.to_string()).collect::<Vec<_>>(),
            "writer_summary_given": false,
            "context": assembled.manifest().to_json(),
        },
        "reviewer": {
            "agent": manifest.id.as_str(),
            "version": manifest.version.to_string(),
            "runtime": ports.runtime.id().as_str(),
        },
        // How far the reviewer's model is from the writer's, from the router's decision.
        (crate::stages::review::independence::KEY): independence,
        "findings": {
            "reported": wrapped.reported_findings,
            "kept": wrapped.verdict.findings.len(),
        },
        "ignored_instructions": wrapped.ignored_instructions,
    });
    Ok(StageOutput {
        artifacts: vec![
            gate_artifact,
            put(ctx, DOCUMENTATION_REVIEW, &verdict_json).await?,
            put(ctx, DOCUMENTATION_REVIEW_RECORD, &record).await?,
        ],
        usage,
        permission_denials: denials,
        ..StageOutput::default()
    })
}

type Reviewed = (
    factory_ports::agent::RawOutput,
    factory_ports::agent::Usage,
    Vec<factory_ports::agent::Denial>,
    String,
    Option<String>,
    Value,
);

async fn review_in(
    handler: &DocumentationReviewHandler,
    ctx: &mut StageContext<'_>,
    workspace: &dyn factory_ports::workspace::Workspace,
    manifest: &factory_domain::contracts::AgentManifest,
    assembled: &crate::prompts::Assembled,
) -> Result<Reviewed, StageError> {
    let ports = ctx.ports;
    let mut session = open_sandbox(
        handler.specs.as_ref(),
        ctx,
        workspace,
        WorkspaceAccess::Inspect,
        &[],
        true,
    )
    .await?;
    // The same author the engine routed the token against, read from the same stored result, so
    // that the model the reviewer is run with is one the token allows.
    let author = crate::stages::documenting::writer_selection(
        ports.artifacts,
        &TenantScope::new(ctx.identity.tenant),
        ctx.upstream,
    )
    .await;
    let need = RoutingNeed {
        stage: StageKind::DocumentationReview,
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
    let independence = crate::stages::review::independence::record(&route);
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
    Ok((
        output,
        report.usage,
        report.permission_denials,
        report
            .runtime_version
            .unwrap_or_else(|| "unknown".to_owned()),
        Some(model),
        independence,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    #[test]
    fn no_answer_anywhere_says_so() {
        assert_eq!(render_answers(&[], &[]), NO_ANSWERS);
    }

    #[test]
    fn answers_of_this_run_alone_come_under_their_heading() {
        let text = render_answers(&[], &texts(&["Review the README."]));
        assert!(text.starts_with(THIS_RUN), "{text}");
        assert!(text.contains("Answer 1 from a person:\n    Review the README.\n"));
        assert!(!text.contains(EARLIER_RUNS), "{text}");
    }

    #[test]
    fn answers_of_earlier_runs_alone_come_under_their_heading() {
        let text = render_answers(&texts(&["Under Unreleased."]), &[]);
        assert!(text.starts_with(EARLIER_RUNS), "{text}");
        assert!(text.contains("    Under Unreleased.\n"));
        assert!(!text.contains(THIS_RUN), "{text}");
    }

    #[test]
    fn earlier_answers_come_before_the_answers_of_this_run_in_the_order_given() {
        let text = render_answers(
            &texts(&["First decision.", "Second decision."]),
            &texts(&["Third decision."]),
        );
        let now = text.find(THIS_RUN).expect("this run's heading");
        assert!(text.find(EARLIER_RUNS).expect("the earlier heading") < now);
        let first = text.find("First decision.").expect("the first answer");
        let second = text.find("Second decision.").expect("the second answer");
        let third = text.find("Third decision.").expect("the third answer");
        assert!(first < second && second < now && now < third, "{text}");
        // Each group numbers its own answers from one.
        assert_eq!(text.matches("Answer 1 from a person:").count(), 2);
    }
}
