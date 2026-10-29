//! `execute` of the specification stage.
//!
//! In order, and each step ends the stage if it fails:
//!
//! 1. Read the normalized request and the repository map by the hash the contract pinned. The map
//!    names the commit the work starts from. Check that the project has a constitution: it is
//!    written once for the repository and approved apart from any feature request, so a feature
//!    run never writes it.
//! 2. Ask where the run stands: a first specification, a revision of a frozen one (a new feature
//!    directory, seeded from the old one), a rework round with feedback, or a run that resumes a
//!    draft a person is about to approve.
//! 3. Run the skills one at a time. Each skill has its own workspace over the commit of the skill
//!    before it and its own sandbox. The request is written into the checkout by the stage, the
//!    skill runs with a fixed instruction that names the file, the stage removes the file, the
//!    sandbox is removed, and only then does the host audit the tree (`Workspace::ingest`), commit
//!    it, read the files back from the commit and ask the provider to assemble the outcome. A
//!    violation of the stage profile stops the run there, and nothing is committed after it.
//! 4. Ask the independent reviewer, in a read-only sandbox, to read the specification.
//! 5. Run every rule of the gate. When all of them pass, freeze the specification if a person
//!    decided, or stop and ask.
//!
//! What the writer says about its work is never read here. The files, the hashes and the paths
//! the host measured are.

use std::collections::BTreeMap;
use std::time::Duration;

use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::specification_contract::QuestionId;
use factory_domain::contracts::{
    AgentManifest, ArtifactRef, Contract, SpecificationContract, VersionedRef,
};
use factory_domain::machines::guards::EnvironmentCause;
use factory_domain::policy::RepoKind;
use factory_domain::scope::TenantScope;
use factory_domain::values::{HumanText, MediaType, Sha256Digest, Slug};
use factory_domain::vocabulary::{Fidelity, RiskTier, StageKind};
use factory_ports::agent::{
    AgentRunRequest, AssembledPrompt, Capability, Denial, RoutingNeed, Usage,
};
use factory_ports::paths::{CommitSha, RepoGlob, RepoPath};
use factory_ports::registry::VersionReq;
use factory_ports::sandbox::{ExecArgv, ExecRequest, SandboxSession};
use factory_ports::spec::{
    FeatureDir, HumanAnswer, ParseReason, RevisionRequest, SpecContext, SpecError, SpecFile,
    SpecFileSet, SpecOperation, SpecOutcome, SpecRequest,
};
use factory_ports::workspace::{
    CommitRequest, JobRepo, ReadView, Workspace, WorkspaceError, WorkspacePurpose, WorkspaceRequest,
};
use serde_json::{Value, json};

use super::evidence::{Evidence, Failure, Refusal, ReviewRecord, Revision};
use super::handler::SpecificationHandler;
use super::input::{
    ANSWERS_FILE, EVIDENCE, NORMALIZED_REQUEST, REPOSITORY_MAP, REQUEST_FILE,
    SPECIFICATION_CONTRACT, input_artifact, map_commit,
};
use super::judge::{JudgeInput, all_clear, judge};
use super::seams::{DraftRecord, PreviousSpec, SeamError, WorkspaceAccess};
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::gates::spec::checklist::{Waiver, parse_waivers};
use crate::gates::spec::profile::ProfileEvidence;
use crate::gates::spec::rules;
use crate::handlers::{NamedArtifact, NeedsHumanRequest, StageContext, StageError, StageOutput};
use crate::prompts::{Assembler, ContentClass, IndependentRequest, Input, Limits, Scope, Source};
use crate::stages::architecture::critic::{Review, Verdict};
use crate::stages::implementation::run::{close, open_sandbox, seam_error, workspace_error};
use crate::stages::implementation::seams::verify_read_only_tools;

/// The most bytes of one human answer that go into a file.
const ANSWER_MAX_BYTES: usize = 8 * 1024;
/// The most files listed under the feature directory.
const LIST_LIMIT: usize = 200;

/// What the stage has used and said so far.
#[derive(Default)]
struct Tally {
    usage: Usage,
    denials: Vec<Denial>,
    sandbox_reported: bool,
}

/// How a skill run ended, for the loop over the skills.
enum Step {
    /// The skill ran and its files were assembled.
    Done(Box<SpecOutcome>),
    /// A violation or a failure was recorded in the evidence. No skill runs after it.
    Stopped,
}

fn slug(text: &str) -> Result<Slug, StageError> {
    Slug::parse(text).map_err(|_| StageError::Internal)
}

fn json_type() -> Result<MediaType, StageError> {
    MediaType::parse("application/json").map_err(|_| StageError::Internal)
}

fn op_name(op: SpecOperation) -> &'static str {
    match op {
        SpecOperation::Constitution => "constitution",
        SpecOperation::Specify => "specify",
        SpecOperation::Clarify => "clarify",
        SpecOperation::Checklist => "checklist",
    }
}

/// The lower-case letters and digits of a title, joined by hyphens, at most 40 characters.
fn short_name(title: &str) -> String {
    let mut name = String::new();
    for c in title.chars() {
        if c.is_ascii_alphanumeric() {
            name.push(c.to_ascii_lowercase());
        } else if !name.ends_with('-') && !name.is_empty() {
            name.push('-');
        }
        if name.len() >= 40 {
            break;
        }
    }
    let name = name.trim_matches('-').to_owned();
    if name.is_empty() {
        "spec".to_owned()
    } else {
        name
    }
}

/// The directory the factory chooses for a feature: the title, a tail of the job identifier so two
/// jobs never collide, and the revision for any version after the first.
fn feature_directory(title: &str, job: &str, version: u32) -> Result<FeatureDir, StageError> {
    let tail = &job[job.len().saturating_sub(8)..];
    let revision = if version > 1 {
        format!("-r{version}")
    } else {
        String::new()
    };
    FeatureDir::new(&format!("specs/{}-{tail}{revision}", short_name(title)))
        .map_err(|_| StageError::Internal)
}

async fn run_command(
    session: &mut dyn SandboxSession,
    cancel: &dyn factory_ports::clock::CancelSignal,
    words: &[&str],
    stdin: Option<Vec<u8>>,
) -> Result<(), StageError> {
    let argv = ExecArgv::new(words.iter().map(|w| (*w).to_owned()).collect())
        .map_err(|_| StageError::Internal)?;
    let result = session
        .exec(
            ExecRequest {
                argv,
                cwd: None,
                stdin,
                timeout: Duration::from_secs(30),
                max_output_bytes: 64 * 1024,
            },
            cancel,
        )
        .await?;
    if result.exit_code == Some(0) {
        Ok(())
    } else {
        Err(StageError::Sandbox)
    }
}

/// A refusal of the audited ingestion, as evidence.
fn refusal_of(error: &WorkspaceError) -> Option<Refusal> {
    let (code, paths): (&str, Vec<(String, String)>) = match error {
        WorkspaceError::ProtectedPathChanged(found) => (
            "protected-path-changed",
            found
                .iter()
                .map(|v| {
                    (
                        v.path.as_str().to_owned(),
                        crate::stages::implementation::run::mode_name(v.mode).to_owned(),
                    )
                })
                .collect(),
        ),
        WorkspaceError::SecretFound(found) => (
            "secret-found",
            found
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
        WorkspaceError::HiddenPathPresent(p) => (
            "hidden-path-present",
            vec![(p.as_str().to_owned(), "hidden".to_owned())],
        ),
        WorkspaceError::EscapingSymlink(p) => (
            "escaping-symlink",
            vec![(p.as_str().to_owned(), "link".to_owned())],
        ),
        WorkspaceError::Gitlink(p) => ("gitlink", vec![(p.as_str().to_owned(), "link".to_owned())]),
        WorkspaceError::NestedGit(p) => (
            "nested-git",
            vec![(p.as_str().to_owned(), "git".to_owned())],
        ),
        WorkspaceError::TooLarge => ("change-too-large", Vec::new()),
        _ => return None,
    };
    Some(Refusal {
        code: code.to_owned(),
        paths,
    })
}

/// The answers people gave, as one text for the file the skills read as data.
async fn answers_text(
    ctx: &StageContext<'_>,
) -> Result<(String, Vec<Waiver>, Vec<HumanAnswer>), StageError> {
    let scope = TenantScope::new(ctx.identity.tenant);
    let mut text = String::new();
    let mut waivers = Vec::new();
    let mut answered = Vec::new();
    for (index, answer) in ctx.human_inputs.iter().enumerate() {
        let bytes = ctx
            .ports
            .artifacts
            .get(&scope, answer)
            .await
            .map_err(|_| StageError::Tool)?;
        let bounded = bytes
            .get(..bytes.len().min(ANSWER_MAX_BYTES))
            .unwrap_or(&bytes);
        let one = String::from_utf8_lossy(bounded).into_owned();
        waivers.extend(parse_waivers(&one));
        answered.extend(answers_of(&one));
        text.push_str(&format!("Answer {} from a person:\n{one}\n\n", index + 1));
    }
    Ok((text, waivers, answered))
}

/// The answers in a person's text: one for each line `Q-014: the answer`. A text with no such line
/// answers the first question.
fn answers_of(text: &str) -> Vec<HumanAnswer> {
    let mut found = Vec::new();
    for line in text.lines() {
        if let Some((id, rest)) = line.trim().split_once(':')
            && let (Ok(question), Ok(answer)) =
                (QuestionId::parse(id.trim()), HumanText::parse(rest.trim()))
        {
            found.push(HumanAnswer { question, answer });
        }
    }
    if found.is_empty()
        && let (Ok(question), Ok(answer)) =
            (QuestionId::parse("Q-001"), HumanText::parse(text.trim()))
    {
        found.push(HumanAnswer { question, answer });
    }
    found
}

/// The files of a commit that the provider asked for, and the files the run changed, read back.
async fn read_set(
    h: &SpecificationHandler,
    repo: &dyn JobRepo,
    head: &CommitSha,
    expected: &[RepoPath],
    changed: &[RepoPath],
    feature: &FeatureDir,
    request: (&RepoPath, &[u8]),
) -> Result<Result<SpecFileSet, (String, ParseReason)>, StageError> {
    let mut wanted: Vec<RepoPath> = expected.iter().chain(changed).cloned().collect();
    let mut globs: Vec<RepoGlob> = h.config.probe_globs.clone();
    if let Ok(glob) = RepoGlob::new(&format!("{}/**", feature.as_str())) {
        globs.push(glob);
    }
    for glob in &globs {
        match repo
            .list_at(head, glob, LIST_LIMIT, ReadView::Trusted)
            .await
        {
            Ok(found) => wanted.extend(found),
            Err(WorkspaceError::Cancelled) => return Err(StageError::Cancelled),
            Err(error) => return Err(workspace_error(error)),
        }
    }
    wanted.sort();
    wanted.dedup();
    let mut files = Vec::new();
    for path in wanted {
        match repo
            .read_file_at(head, &path, h.config.max_file_bytes, ReadView::Trusted)
            .await
        {
            Ok(bytes) => files.push(SpecFile { path, bytes }),
            // A file the provider expected and the run did not leave is simply not in the set.
            Err(WorkspaceError::PathNotFound(_)) => {}
            Err(WorkspaceError::TooLarge) => {
                return Ok(Err((path.as_str().to_owned(), ParseReason::TooLarge)));
            }
            Err(WorkspaceError::Cancelled) => return Err(StageError::Cancelled),
            Err(error) => return Err(workspace_error(error)),
        }
    }
    files.push(SpecFile {
        path: request.0.clone(),
        bytes: request.1.to_vec(),
    });
    Ok(Ok(SpecFileSet {
        commit: head.clone(),
        files,
    }))
}

struct Work<'a> {
    feature: FeatureDir,
    request_file: RepoPath,
    request_bytes: Vec<u8>,
    answers_file: RepoPath,
    answers: String,
    answered: Vec<HumanAnswer>,
    manifest: AgentManifest,
    repo: Box<dyn JobRepo>,
    previous: Option<&'a PreviousSpec>,
    evidence: Evidence,
    tally: Tally,
    head: CommitSha,
}

/// Runs one skill from the commit `work.head` and judges what it left.
async fn run_skill(
    h: &SpecificationHandler,
    ctx: &mut StageContext<'_>,
    work: &mut Work<'_>,
    op: SpecOperation,
    seed: Option<(&str, &str)>,
    revision: Option<&PreviousSpec>,
) -> Result<Step, StageError> {
    let ports = ctx.ports;
    let identity = ctx.identity;
    let workspace = ports
        .workspaces
        .create(
            WorkspaceRequest {
                job: identity.job,
                attempt: ctx.attempt,
                base: work.head.clone(),
                rules: h.config.path_rules.clone(),
                purpose: WorkspacePurpose::Agent,
            },
            ctx.cancel,
        )
        .await
        .map_err(workspace_error)?;
    let result = run_skill_in(h, ctx, work, workspace.as_ref(), op, seed, revision).await;
    let _ = workspace.dispose().await;
    result
}

async fn run_skill_in(
    h: &SpecificationHandler,
    ctx: &mut StageContext<'_>,
    work: &mut Work<'_>,
    workspace: &dyn Workspace,
    op: SpecOperation,
    seed: Option<(&str, &str)>,
    revision: Option<&PreviousSpec>,
) -> Result<Step, StageError> {
    let ports = ctx.ports;
    let identity = ctx.identity;
    let mut session = open_sandbox(
        h.specs.as_ref(),
        ctx,
        workspace,
        WorkspaceAccess::Edit,
        &[Capability::SkillInvocation],
        !work.tally.sandbox_reported,
    )
    .await?;
    work.tally.sandbox_reported = true;

    // The stage puts the request and the answers into the checkout. The skills read them as data.
    let prepared = async {
        run_command(&mut *session, ctx.cancel, &["mkdir", "-p", "inputs"], None).await?;
        run_command(
            &mut *session,
            ctx.cancel,
            &["tee", "--", work.request_file.as_str()],
            Some(work.request_bytes.clone()),
        )
        .await?;
        if !work.answers.is_empty() {
            run_command(
                &mut *session,
                ctx.cancel,
                &["tee", "--", work.answers_file.as_str()],
                Some(work.answers.clone().into_bytes()),
            )
            .await?;
        }
        if let Some((from, to)) = seed {
            run_command(&mut *session, ctx.cancel, &["cp", "-R", from, to], None).await?;
        }
        Ok::<(), StageError>(())
    }
    .await;
    if let Err(error) = prepared {
        let _ = close(session, false).await;
        return Err(error);
    }

    let token = ctx.job_token.ok_or(StageError::Internal)?;
    let need = RoutingNeed {
        stage: StageKind::Specification,
        tier: RecommendedTier::Standard,
        required: vec![Capability::SkillInvocation],
        risk: RiskTier::Medium,
        exclude: Vec::new(),
        probed: h.probes.probed(),
        author: None,
    };
    let route = match ports.router.route(&need) {
        Ok(route) => route,
        Err(_) => {
            let _ = close(session, false).await;
            return Err(StageError::Blocked(BlockedCode::ToolUnavailable));
        }
    };
    let manifest = &work.manifest;
    let template = AgentRunRequest {
        attempt: ctx.attempt,
        agent: VersionedRef {
            id: manifest.id.clone(),
            version: manifest.version.clone(),
        },
        // The provider replaces the prompt with the invocation and the fixed instruction.
        prompt: AssembledPrompt {
            instructions: String::new(),
            data: Vec::new(),
        },
        output_schema: manifest.outputs_schema.clone(),
        max_output_bytes: h.config.max_output_bytes,
        broker: h.config.broker.clone(),
        job_token: token,
        tools: manifest.allowed_tools.as_slice().to_vec(),
        limits: manifest.resource_limits.clone(),
        model: route.model,
        flag_set: route.flag_set,
    };
    let request = SpecRequest {
        job: identity.job,
        op,
        feature_directory: work.feature.clone(),
        request_file: work.request_file.clone(),
        answers: work.answered.clone(),
        revision: revision.map(|p| RevisionRequest {
            reason: HumanText::parse(&p.reason).unwrap_or_else(|_| {
                HumanText::parse("A requirement of the specification changed.")
                    .expect("a fixed sentence is valid text")
            }),
        }),
    };
    let report = {
        let mut context = SpecContext {
            session: &mut *session,
            runtime: ports.runtime,
            run_template: template,
            cancel: ctx.cancel,
        };
        h.provider.run(&request, &mut context).await
    };
    work.evidence.operations.push(op_name(op).to_owned());

    // The sandbox is gone before anything is read from the tree it wrote to.
    let removal = run_command(
        &mut *session,
        ctx.cancel,
        &[
            "rm",
            "-f",
            "--",
            work.request_file.as_str(),
            work.answers_file.as_str(),
        ],
        None,
    )
    .await;
    let report = match report {
        Ok(report) => report,
        Err(error) => {
            let _ = close(session, false).await;
            return match error {
                SpecError::Runtime(error) => Err(error.into()),
                SpecError::ToolMissing => {
                    Err(StageError::Environment(EnvironmentCause::ToolMissing))
                }
                SpecError::PostConditionFailed(found) => {
                    work.evidence
                        .post_conditions
                        .extend(found.into_iter().map(|c| Failure {
                            name: c.name.as_str().to_owned(),
                            detail: c.detail,
                        }));
                    Ok(Step::Stopped)
                }
                other => Ok(record_assembly_error(work, other)?),
            };
        }
    };
    close(session, true).await?;
    removal?;
    for run in &report.skill_runs {
        work.tally.usage = work.tally.usage.saturating_add(run.usage);
        work.tally
            .denials
            .extend(run.permission_denials.iter().cloned());
        work.evidence.denials.extend(
            run.permission_denials
                .iter()
                .map(|d| (d.tool.clone(), d.reason.clone())),
        );
        if let Some(transcript) = &run.transcript {
            work.evidence
                .transcripts
                .push(transcript.sha256.as_str().to_owned());
            // The gate reads the transcripts back to look for a skill outside the profile. The
            // runtime stored the blob and nobody indexed it for the tenant, so the engine is asked
            // to, with the result of this attempt.
            ctx.note_transcript(transcript);
        }
    }
    if ctx.cancel.is_cancelled() {
        return Err(StageError::Cancelled);
    }

    // The audit, and the commit made on the host.
    let changed_paths: Vec<RepoPath>;
    match workspace.ingest(ctx.cancel).await {
        Ok(change) => {
            changed_paths = change
                .changes()
                .iter()
                .filter(|c| c.kind != factory_ports::workspace::ChangeKind::Deleted)
                .map(|c| c.path.clone())
                .collect();
            work.evidence
                .changed
                .extend(change.changes().iter().map(|c| c.path.as_str().to_owned()));
            // A frozen specification is never edited. A revision lives in a directory of its own.
            if let Some(old) = work
                .previous
                .and_then(|p| p.contract.provenance.feature_directory.as_ref())
                && let Ok(old_dir) = RepoPath::new(old.as_str())
                && let Some(touched) = change.changes().iter().find(|c| c.path.is_within(&old_dir))
            {
                work.evidence.post_conditions.push(Failure {
                    name: "frozen-specification-changed".to_owned(),
                    detail: format!(
                        "The run changed {}, which belongs to a specification that is already frozen.",
                        touched.path.as_str()
                    ),
                });
                return Ok(Step::Stopped);
            }
            if !change.is_empty() {
                let commit = workspace
                    .commit(
                        &change,
                        CommitRequest {
                            message: format!(
                                "Write the specification: {} step\n\nCommitted by the factory after the change was audited.\n",
                                op_name(op)
                            ),
                            author_name: h.config.identity.name.clone(),
                            author_email: h.config.identity.email.clone(),
                        },
                    )
                    .await
                    .map_err(workspace_error)?;
                work.head = commit;
            }
        }
        Err(error) => {
            return match refusal_of(&error) {
                Some(refusal) => {
                    ctx.note_audit(AuditAction::new(
                        if refusal.code == "secret-found" {
                            AuditKind::SecretRedactedOrBlocked
                        } else {
                            AuditKind::ProtectedPathDecision
                        },
                        AuditDecision::Denied,
                    ));
                    work.evidence.refusal = Some(refusal);
                    Ok(Step::Stopped)
                }
                None => Err(workspace_error(error)),
            };
        }
    }

    // The files, read back from the commit, and the provider's assembly of them.
    let set = match read_set(
        h,
        work.repo.as_ref(),
        &work.head,
        &report.expected_files,
        &changed_paths,
        &work.feature,
        (&work.request_file, &work.request_bytes),
    )
    .await?
    {
        Ok(set) => set,
        Err((path, reason)) => {
            work.evidence.parse_failure = Some((path, reason));
            return Ok(Step::Stopped);
        }
    };
    match h.provider.assemble(&request, &set) {
        Ok(outcome) => Ok(Step::Done(Box::new(outcome))),
        Err(error) => record_assembly_error(work, error),
    }
}

/// Records what the provider reported, or ends the stage for an environment fault.
fn record_assembly_error(work: &mut Work<'_>, error: SpecError) -> Result<Step, StageError> {
    match error {
        SpecError::ToolMissing => Err(StageError::Environment(EnvironmentCause::ToolMissing)),
        SpecError::VersionMismatch { .. } => {
            Err(StageError::Environment(EnvironmentCause::ToolMissing))
        }
        SpecError::IntegrityNotOk(findings) => {
            work.evidence
                .post_conditions
                .extend(findings.iter().map(|f| Failure {
                    name: "installation-not-ok".to_owned(),
                    detail: format!(
                        "An installed file is missing or differs from the pinned one ({}).",
                        f.rule.as_str()
                    ),
                }));
            Ok(Step::Stopped)
        }
        SpecError::ExtensionsPresent => {
            work.evidence.post_conditions.push(Failure {
                name: "extensions-present".to_owned(),
                detail: "An extension is installed, and none is allowed.".to_owned(),
            });
            Ok(Step::Stopped)
        }
        SpecError::PostConditionFailed(found) => {
            work.evidence
                .post_conditions
                .extend(found.into_iter().map(|c| Failure {
                    name: c.name.as_str().to_owned(),
                    detail: c.detail,
                }));
            Ok(Step::Stopped)
        }
        SpecError::ParseError { path, reason } => {
            work.evidence.parse_failure = Some((path.as_str().to_owned(), reason));
            Ok(Step::Stopped)
        }
        SpecError::Runtime(error) => Err(error.into()),
    }
}

/// Reads the text of the specification and of every checklist from the head commit, for the
/// reviewer.
async fn review_texts(
    work: &Work<'_>,
    h: &SpecificationHandler,
) -> Result<(Vec<u8>, Vec<u8>), StageError> {
    let dir = work.feature.as_str();
    let read = |path: String| async move {
        let path = RepoPath::new(&path).map_err(|_| StageError::Internal)?;
        match work
            .repo
            .read_file_at(
                &work.head,
                &path,
                h.config.max_file_bytes,
                ReadView::Trusted,
            )
            .await
        {
            Ok(bytes) => Ok(bytes),
            Err(WorkspaceError::PathNotFound(_)) => Ok(Vec::new()),
            Err(error) => Err(workspace_error(error)),
        }
    };
    let spec = read(format!("{dir}/spec.md")).await?;
    let mut checklists = Vec::new();
    let glob =
        RepoGlob::new(&format!("{dir}/checklists/*.md")).map_err(|_| StageError::Internal)?;
    let mut listed = work
        .repo
        .list_at(&work.head, &glob, LIST_LIMIT, ReadView::Trusted)
        .await
        .map_err(workspace_error)?;
    listed.sort();
    for path in listed {
        checklists.extend_from_slice(format!("File {}:\n", path.as_str()).as_bytes());
        checklists.extend(read(path.as_str().to_owned()).await?);
        checklists.push(b'\n');
    }
    Ok((spec, checklists))
}

/// Asks the independent reviewer. The reviewer reads the request, the specification and the
/// checklists, in a read-only sandbox, and sees nothing the writer said about its work.
async fn run_reviewer(
    h: &SpecificationHandler,
    ctx: &mut StageContext<'_>,
    work: &mut Work<'_>,
) -> Result<ReviewRecord, StageError> {
    let ports = ctx.ports;
    let manifest = match ports
        .registry
        .manifest(&h.config.reviewer, &VersionReq::Any)
    {
        Ok(manifest) if manifest.id != work.manifest.id => manifest,
        Ok(_) => return Ok(ReviewRecord::NotRun("reviewer-is-the-writer".to_owned())),
        Err(_) => return Ok(ReviewRecord::NotRun("no-such-agent".to_owned())),
    };
    verify_read_only_tools(&manifest)?;
    let prompt = ports
        .registry
        .prompt(&manifest)
        .map_err(|_| StageError::Internal)?;
    let (spec, checklists) = review_texts(work, h).await?;
    let workspace = ports
        .workspaces
        .create(
            WorkspaceRequest {
                job: ctx.identity.job,
                attempt: ctx.attempt,
                base: work.head.clone(),
                rules: h.config.path_rules.clone(),
                purpose: WorkspacePurpose::Agent,
            },
            ctx.cancel,
        )
        .await
        .map_err(workspace_error)?;
    let outcome = review_in(
        h,
        ctx,
        work,
        workspace.as_ref(),
        &manifest,
        prompt,
        spec,
        checklists,
    )
    .await;
    // The checkout of the reviewer is never ingested.
    let _ = workspace.dispose().await;
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn review_in(
    h: &SpecificationHandler,
    ctx: &mut StageContext<'_>,
    work: &mut Work<'_>,
    workspace: &dyn Workspace,
    manifest: &AgentManifest,
    prompt: factory_ports::registry::LoadedPrompt,
    spec: Vec<u8>,
    checklists: Vec<u8>,
) -> Result<ReviewRecord, StageError> {
    let ports = ctx.ports;
    let mut session = open_sandbox(
        h.specs.as_ref(),
        ctx,
        workspace,
        WorkspaceAccess::Inspect,
        &[],
        !work.tally.sandbox_reported,
    )
    .await?;
    work.tally.sandbox_reported = true;
    let tenant = ctx.identity.tenant;
    let now = ports.clock.now();
    let artifact = |kind: &str, bytes: &[u8]| Source::HostArtifact {
        kind: kind.to_owned(),
        id: Sha256Digest::of(bytes).to_string(),
    };
    let inputs = vec![
        Input::untrusted(
            "request",
            ContentClass::IssueText,
            artifact("normalized-request", &work.request_bytes),
            tenant,
            work.request_bytes.clone(),
        )
        .fetched_at(now),
        Input::untrusted(
            "specification",
            ContentClass::SpecificationText,
            artifact("specification-file", &spec),
            tenant,
            spec.clone(),
        )
        .fetched_at(now),
        Input::untrusted(
            "requirements_checklist",
            ContentClass::SpecificationText,
            artifact("checklist-files", &checklists),
            tenant,
            checklists.clone(),
        )
        .fetched_at(now),
    ];
    // The reviewer reads the request, the specification and the checklists, and nothing the
    // writer said about its own work. `assemble_independent` takes no other kind of input.
    let independent = inputs
        .into_iter()
        .map(Input::into_independent)
        .collect::<Result<Vec<_>, _>>();
    let assembled = independent.and_then(|inputs| {
        Assembler::new(&h.redactor, &h.policy.paths, Limits::default()).assemble_independent(
            IndependentRequest::new(
                manifest,
                &prompt,
                Scope::new(tenant, RepoKind::Target),
                inputs,
            ),
        )
    });
    let assembled = match assembled {
        Ok(assembled) => assembled,
        Err(_) => {
            let _ = close(session, false).await;
            return Err(StageError::Internal);
        }
    };
    let need = RoutingNeed {
        stage: StageKind::Specification,
        tier: RecommendedTier::Standard,
        required: Vec::new(),
        risk: RiskTier::Medium,
        exclude: Vec::new(),
        probed: h.probes.probed(),
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
    let request = AgentRunRequest {
        attempt: ctx.attempt,
        agent: VersionedRef {
            id: manifest.id.clone(),
            version: manifest.version.clone(),
        },
        prompt: assembled.to_port_prompt(),
        output_schema: manifest.outputs_schema.clone(),
        max_output_bytes: h.config.max_output_bytes,
        broker: h.config.broker.clone(),
        job_token: token,
        tools: manifest.allowed_tools.as_slice().to_vec(),
        limits: manifest.resource_limits.clone(),
        model: route.model,
        // The reviewer never sees the skills.
        flag_set: factory_ports::agent::FlagSet::Standard,
    };
    let report = ports.runtime.run(&mut *session, request, ctx.cancel).await;
    work.tally.usage = work.tally.usage.saturating_add(report.usage);
    work.tally
        .denials
        .extend(report.permission_denials.iter().cloned());
    close(session, report.outcome.is_ok()).await?;
    let output = match &report.outcome {
        Ok(output) => output.clone(),
        Err(error) => {
            ctx.note_failed_run(&report);
            return Err(error.clone().into());
        }
    };
    let validated = h
        .schemas
        .check(&manifest.outputs_schema, output.as_bytes())
        .map_err(|_| StageError::InvalidOutput)?;
    Ok(ReviewRecord::Answered {
        agent: manifest.id.as_str().to_owned(),
        version: manifest.version.to_string(),
        answer: validated.value,
    })
}

/// Freezes a draft: the status, the approver, the time, and the link to the specification it
/// revises.
fn freeze(
    draft: &SpecificationContract,
    approval: &super::seams::ApprovalRecord,
    previous: Option<&PreviousSpec>,
    resolution: &crate::gates::spec::checklist::Resolution,
    waivers: &[Waiver],
) -> Result<SpecificationContract, StageError> {
    let mut value = draft.to_json_value().map_err(|_| StageError::Internal)?;
    let meta = value
        .get_mut("metadata")
        .and_then(Value::as_object_mut)
        .ok_or(StageError::Internal)?;
    meta.insert("status".to_owned(), json!("approved"));
    meta.insert("approved_at".to_owned(), json!(approval.at.as_text()));
    meta.insert(
        "approved_by".to_owned(),
        json!({
            "principal_id": approval.principal.to_string(),
            "role": approval.role.as_str(),
            "basis": approval.basis.as_str(),
        }),
    );
    if let Some(previous) = previous {
        let basis = previous.contract.metadata.spec_version.get();
        meta.insert(
            "spec_id".to_owned(),
            json!(previous.contract.metadata.spec_id.to_string()),
        );
        meta.insert("spec_version".to_owned(), json!(basis + 1));
        meta.insert("supersedes_spec_version".to_owned(), json!(basis));
        value["provenance"]["revision"] =
            json!({ "method": "new_feature_directory", "basis_spec_version": basis });
    }
    // An approved specification has no blocking question that is still open. Each one that the
    // gate settled is recorded as answered, with how it was settled.
    if let Some(questions) = value
        .get_mut("open_questions")
        .and_then(Value::as_array_mut)
    {
        for question in questions {
            let id = question
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let waiver = waivers.iter().find(|w| w.question == id);
            let answer = if let Some(waiver) = waiver {
                Some(format!("A person waived this question: {}", waiver.reason))
            } else if resolution.verified.contains(&id) {
                Some(
                    "The independent reviewer verified this item. The tick the author wrote in the file was not counted."
                        .to_owned(),
                )
            } else {
                None
            };
            if let Some(answer) = answer
                && question.get("status").and_then(Value::as_str) == Some("open")
            {
                question["status"] = json!("answered");
                question["answer"] = json!(answer);
            }
        }
    }
    SpecificationContract::from_json_value(value).map_err(|_| StageError::Internal)
}

pub(super) async fn execute(
    h: &SpecificationHandler,
    ctx: &mut StageContext<'_>,
) -> Result<StageOutput, StageError> {
    let ports = ctx.ports;
    let identity = ctx.identity;
    let missing = || StageError::Blocked(BlockedCode::DependencyUnavailable);

    // 1. The inputs, by the hash the contract pinned.
    let scope = TenantScope::new(identity.tenant);
    let read = |name: &'static str| {
        let reference = input_artifact(ctx.contract, name);
        let artifacts = ports.artifacts;
        async move {
            let reference: ArtifactRef = reference.ok_or_else(missing)?;
            artifacts
                .get(&scope, &reference)
                .await
                .map_err(|_| missing())
        }
    };
    let request_doc: Value =
        serde_json::from_slice(&read(NORMALIZED_REQUEST).await?).map_err(|_| missing())?;
    let map_bytes = read(REPOSITORY_MAP).await?;
    let base = map_commit(&map_bytes).ok_or_else(missing)?;
    let title = request_doc
        .get("title")
        .and_then(Value::as_str)
        .ok_or_else(missing)?
        .to_owned();
    let description = request_doc
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("");
    let request_bytes = format!("# {title}\n\n{description}\n").into_bytes();

    let repo = ports
        .workspaces
        .repo(identity.job)
        .await
        .map_err(workspace_error)?;

    // 2. Where the run stands.
    let previous = h.history.previous(&identity).await.map_err(seam_error)?;
    let kept = h.drafts.load(&identity).await.map_err(seam_error)?;
    let rework = h.rework.of(&identity).await.map_err(seam_error)?;
    let (mut answers, waivers, answered) = answers_text(ctx).await?;
    if let Some(context) = &rework {
        answers.push_str(&crate::stages::implementation::feedback::render(context));
    }

    let writer_manifest = ports
        .registry
        .manifest(&h.config.writer, &VersionReq::Any)
        .map_err(|_| StageError::Internal)?;
    let version = previous.as_ref().map_or(1, |p| {
        u32::try_from(p.contract.metadata.spec_version.get()).unwrap_or(1) + 1
    });
    let kept = kept.filter(|record| !record.contract.is_empty());
    let feature = match &kept {
        Some(record) => {
            FeatureDir::new(&record.feature_directory).map_err(|_| StageError::Internal)?
        }
        None => feature_directory(&title, &identity.job.to_string(), version)?,
    };
    let start = previous
        .as_ref()
        .map_or_else(|| base.clone(), |p| p.commit.clone());
    let mut work = Work {
        feature: feature.clone(),
        request_file: RepoPath::new(REQUEST_FILE).map_err(|_| StageError::Internal)?,
        request_bytes,
        answers_file: RepoPath::new(ANSWERS_FILE).map_err(|_| StageError::Internal)?,
        answers,
        answered,
        manifest: writer_manifest,
        repo,
        previous: previous.as_ref(),
        evidence: Evidence::new(feature.as_str().to_owned(), base.as_str().to_owned()),
        tally: Tally::default(),
        head: start,
    };
    work.evidence.fake = [
        ports.workspaces.fidelity(),
        ports.sandbox.fidelity(),
        ports.runtime.fidelity(),
        h.provider.fidelity(),
    ]
    .contains(&Fidelity::Fake);
    if let Some(previous) = &previous {
        work.evidence.revision = Some(Revision {
            basis_version: u32::try_from(previous.contract.metadata.spec_version.get())
                .unwrap_or(1),
            basis_directory: previous
                .contract
                .provenance
                .feature_directory
                .as_ref()
                .map(|d| d.as_str().to_owned())
                .unwrap_or_default(),
            reason: previous.reason.clone(),
        });
    }

    // The constitution: written once for the repository and approved apart from any request.
    match work
        .repo
        .read_file_at(
            &base,
            &h.config.constitution_path,
            h.config.max_file_bytes,
            ReadView::Trusted,
        )
        .await
    {
        Ok(bytes) if !rules::has_placeholder(&String::from_utf8_lossy(&bytes)) => {}
        Ok(_) | Err(WorkspaceError::PathNotFound(_)) => {
            ready_check(h, ctx, &base).await?;
            return Ok(StageOutput {
                needs_human: Some(NeedsHumanRequest {
                    reason: slug("constitution-required")?,
                }),
                ..StageOutput::default()
            });
        }
        Err(error) => return Err(workspace_error(error)),
    }

    // 3. The skills, unless a draft is waiting for its approval.
    let mut contract: Option<SpecificationContract> = None;
    if let Some(record) = &kept {
        contract =
            SpecificationContract::from_json_str(&String::from_utf8_lossy(&record.contract)).ok();
        if let Some(saved) = serde_json::from_slice::<Value>(&record.evidence)
            .ok()
            .and_then(|v| Evidence::from_json(&v))
        {
            work.evidence = saved;
        }
        work.head = record.commit.clone();
        // No skill runs when a draft is waiting for its approval, and the engine still needs the
        // proof that the sandbox of this stage can be made.
        ready_check(h, ctx, &work.head).await?;
    } else {
        let revising = previous.as_ref();
        let operations: Vec<SpecOperation> = if revising.is_some() {
            vec![SpecOperation::Clarify, SpecOperation::Checklist]
        } else if work.answers.is_empty() {
            vec![SpecOperation::Specify, SpecOperation::Checklist]
        } else {
            vec![
                SpecOperation::Specify,
                SpecOperation::Clarify,
                SpecOperation::Checklist,
            ]
        };
        if revising.is_some() && work.answers.is_empty() {
            let reason = revising.map_or("", |p| p.reason.as_str());
            work.answers = format!(
                "The requirement changed. Apply this change to the specification:\n{reason}\n"
            );
        }
        for (index, op) in operations.iter().enumerate() {
            if ctx.cancel.is_cancelled() {
                return Err(StageError::Cancelled);
            }
            let seed = match (revising, index) {
                (Some(p), 0) => p
                    .contract
                    .provenance
                    .feature_directory
                    .as_ref()
                    .map(|d| (d.as_str().to_owned(), feature.as_str().to_owned())),
                _ => None,
            };
            let seed_refs = seed.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
            match run_skill(h, ctx, &mut work, *op, seed_refs, revising).await? {
                Step::Stopped => break,
                Step::Done(outcome) => match *outcome {
                    SpecOutcome::Draft(draft) => contract = Some(draft.contract),
                    SpecOutcome::NeedsHuman(questions) => {
                        work.evidence.questions = questions
                            .iter()
                            .map(|q| (q.id.as_str().to_owned(), q.question.as_str().to_owned()))
                            .collect();
                        let rounds = ctx.human_inputs.len();
                        let reason = if rounds >= h.config.max_clarification_rounds {
                            "clarification-limit-reached"
                        } else {
                            "clarification-needed"
                        };
                        return asked(h, ctx, &work, reason, None).await;
                    }
                },
            }
        }
    }
    if !work.evidence.operations.is_empty() || kept.is_some() {
        work.evidence.head_commit = Some(work.head.as_str().to_owned());
    }

    // The files as the host measured them in the commit.
    let mut committed: BTreeMap<String, Sha256Digest> = BTreeMap::new();
    if let Ok(glob) = RepoGlob::new(&format!("{}/**", feature.as_str())) {
        for path in work
            .repo
            .list_at(&work.head, &glob, LIST_LIMIT, ReadView::Trusted)
            .await
            .map_err(workspace_error)?
        {
            if let Ok(bytes) = work
                .repo
                .read_file_at(
                    &work.head,
                    &path,
                    h.config.max_file_bytes,
                    ReadView::Trusted,
                )
                .await
            {
                committed.insert(path.as_str().to_owned(), Sha256Digest::of(&bytes));
            }
        }
    }
    work.evidence.committed = committed
        .iter()
        .map(|(p, s)| (p.clone(), s.as_str().to_owned()))
        .collect();

    // 4. The independent review, once the files are understood and clean.
    let transcripts = read_transcripts(ctx, &work.evidence).await?;
    let profile_clean = h
        .profile
        .check(&ProfileEvidence {
            denials: &work.evidence.denials,
            transcripts: &transcripts,
            changed: &work.evidence.changed,
            committed: &committed.keys().cloned().collect::<Vec<_>>(),
        })
        .is_empty();
    let clean_so_far = profile_clean
        && contract.is_some()
        && work.evidence.parse_failure.is_none()
        && work.evidence.post_conditions.is_empty()
        && work.evidence.refusal.is_none()
        && work.evidence.denials.is_empty();
    if kept.is_none() && clean_so_far {
        work.evidence.review = run_reviewer(h, ctx, &mut work).await?;
        if let ReviewRecord::Answered { answer, .. } = &work.evidence.review
            && Review::read(answer).is_ok_and(|r| r.verdict == Verdict::NeedsHuman)
        {
            return asked(h, ctx, &work, "specification-review-question", None).await;
        }
    }
    if let Some(found) = contract.as_ref() {
        work.evidence.draft_authorization = rules::authorization(found)
            .into_iter()
            .map(|f| (f.code.to_owned(), f.message))
            .collect();
        let bytes = serde_json::to_vec(&found.to_json_value().map_err(|_| StageError::Internal)?)
            .map_err(|_| StageError::Internal)?;
        work.evidence.draft_sha256 = Some(Sha256Digest::of(&bytes).as_str().to_owned());
    }

    // 5. The gate's own rules, and the freeze.
    let unlisted = unlisted_files(contract.as_ref(), &committed);
    let judged = judge(&JudgeInput {
        contract: contract.as_ref(),
        evidence: &work.evidence,
        waivers: &waivers,
        limits: &h.config.limits,
        profile: &h.profile,
        transcripts: &transcripts,
        committed: &committed,
        unlisted: &unlisted,
        approval_recorded: None,
        writer: h.config.writer.as_str(),
    });
    // A skill outside the profile, or a file of one, is recorded as a denied tool call.
    if judged.iter().any(|gate| {
        gate.id == crate::gates::spec::STAGE_PROFILE
            && gate.findings.iter().any(|f| {
                matches!(
                    f.code,
                    "forbidden_skill_invoked"
                        | "skill_visible_outside_profile"
                        | "forbidden_artifact_present"
                )
            })
    }) {
        ctx.note_audit(AuditAction::new(
            AuditKind::ToolCallDenied,
            AuditDecision::Denied,
        ));
    }
    let mut final_contract = contract.clone();
    if all_clear(&judged)
        && let Some(draft) = &contract
    {
        let draft_sha = Sha256Digest::parse(work.evidence.draft_sha256.as_deref().unwrap_or(""))
            .map_err(|_| StageError::Internal)?;
        let approval = if h.config.human_approval_required {
            h.approvals
                .approval(&identity, &draft_sha)
                .await
                .map_err(seam_error)?
        } else {
            h.config.policy_principal.map(|principal| super::seams::ApprovalRecord {
                principal,
                role: factory_domain::contracts::specification_contract::SpecApproverRole::PolicyEngine,
                basis: factory_domain::contracts::specification_contract::ApprovalBasis::LowRiskPolicyWithPassingGate,
                at: ports.clock.now(),
            })
        };
        match approval {
            Some(approval) => {
                let resolution = super::judge::checklist_resolution(
                    draft,
                    &work.evidence,
                    &waivers,
                    h.config.writer.as_str(),
                );
                final_contract = Some(freeze(
                    draft,
                    &approval,
                    work.previous,
                    &resolution,
                    &waivers,
                )?);
            }
            None => {
                return asked(h, ctx, &work, "specification-approval-needed", Some(draft)).await;
            }
        }
    }

    // The stage's outputs. A failing run stores what it has, so the gate can say what is wrong.
    let mut stored = Vec::with_capacity(2);
    let evidence_bytes =
        serde_json::to_vec(&work.evidence.to_json()).map_err(|_| StageError::Internal)?;
    stored.push(NamedArtifact {
        name: slug(EVIDENCE)?,
        artifact: ports
            .artifacts
            .put(evidence_bytes, json_type()?)
            .await
            .map_err(|_| StageError::Tool)?,
    });
    if let Some(done) = &final_contract {
        let bytes = serde_json::to_vec(&done.to_json_value().map_err(|_| StageError::Internal)?)
            .map_err(|_| StageError::Internal)?;
        stored.push(NamedArtifact {
            name: slug(SPECIFICATION_CONTRACT)?,
            artifact: ports
                .artifacts
                .put(bytes, json_type()?)
                .await
                .map_err(|_| StageError::Tool)?,
        });
    }
    Ok(StageOutput {
        artifacts: stored,
        usage: work.tally.usage,
        permission_denials: work.tally.denials,
        ..StageOutput::default()
    })
}

/// The files of the feature directory that the contract does not record.
fn unlisted_files(
    contract: Option<&SpecificationContract>,
    committed: &BTreeMap<String, Sha256Digest>,
) -> Vec<String> {
    let recorded: Vec<&str> = contract
        .map(|c| {
            c.provenance
                .artifacts
                .as_slice()
                .iter()
                .map(|a| a.path.as_str())
                .collect()
        })
        .unwrap_or_default();
    committed
        .keys()
        .filter(|path| !recorded.contains(&path.as_str()))
        .cloned()
        .collect()
}

/// The stored transcripts, by hash.
async fn read_transcripts(
    ctx: &StageContext<'_>,
    evidence: &Evidence,
) -> Result<Vec<Vec<u8>>, StageError> {
    let scope = TenantScope::new(ctx.identity.tenant);
    let mut all = Vec::new();
    for hash in &evidence.transcripts {
        let sha256 = Sha256Digest::parse(hash).map_err(|_| StageError::Internal)?;
        let reference = ArtifactRef {
            sha256,
            media_type: MediaType::parse("text/plain").map_err(|_| StageError::Internal)?,
            size_bytes: None,
        };
        if let Ok(bytes) = ctx.ports.artifacts.get(&scope, &reference).await {
            all.push(bytes);
        }
    }
    Ok(all)
}

/// The stage run stops to ask a person. The draft and the questions are kept in the draft store
/// so that the person sees them and a later attempt starts from them.
async fn asked(
    h: &SpecificationHandler,
    ctx: &mut StageContext<'_>,
    work: &Work<'_>,
    reason: &'static str,
    draft: Option<&SpecificationContract>,
) -> Result<StageOutput, StageError> {
    let contract_bytes = match draft {
        Some(draft) => {
            serde_json::to_vec(&draft.to_json_value().map_err(|_| StageError::Internal)?)
                .map_err(|_| StageError::Internal)?
        }
        None => Vec::new(),
    };
    let evidence =
        serde_json::to_vec(&work.evidence.to_json()).map_err(|_| StageError::Internal)?;
    h.drafts
        .save(
            &ctx.identity,
            DraftRecord {
                commit: work.head.clone(),
                feature_directory: work.feature.as_str().to_owned(),
                contract: contract_bytes,
                evidence,
            },
        )
        .await
        .map_err(|e: SeamError| seam_error(e))?;
    Ok(StageOutput {
        usage: work.tally.usage,
        permission_denials: work.tally.denials.clone(),
        needs_human: Some(NeedsHumanRequest {
            reason: slug(reason)?,
        }),
        ..StageOutput::default()
    })
}

/// Proves that the sandbox can be made when the stage stops before it runs a skill, because the
/// engine fails a stage that declares a sandbox and never reports one.
async fn ready_check(
    h: &SpecificationHandler,
    ctx: &mut StageContext<'_>,
    base: &CommitSha,
) -> Result<(), StageError> {
    let workspace = ctx
        .ports
        .workspaces
        .create(
            WorkspaceRequest {
                job: ctx.identity.job,
                attempt: ctx.attempt,
                base: base.clone(),
                rules: h.config.path_rules.clone(),
                purpose: WorkspacePurpose::Agent,
            },
            ctx.cancel,
        )
        .await
        .map_err(workspace_error)?;
    let result = match open_sandbox(
        h.specs.as_ref(),
        ctx,
        workspace.as_ref(),
        WorkspaceAccess::Edit,
        &[Capability::SkillInvocation],
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
