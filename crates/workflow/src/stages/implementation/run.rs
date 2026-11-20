//! `execute` of the implementation stage: the builder over the task graph.
//!
//! In order, and each step ends the stage if it fails:
//!
//! 1. Read the plan, the frozen specification, the architecture and the repository map by the hash
//!    the contract pinned. The map names the base commit.
//! 2. Ask where the run stands: a first run builds every task of the plan, and a rework run builds
//!    one task that carries the feedback of the round that was sent back, on top of the commit
//!    that round ended with.
//! 3. Open the task graph in the ledger. A task that already `SUCCEEDED` (an earlier attempt of
//!    this stage run did it) is skipped and its commit is the base of the next one.
//! 4. For each task that is left: make a workspace over the commit of the task before it, make an
//!    `agent` sandbox over it and check that it is what was meant, run the builder, remove the
//!    sandbox, and only then read the tree. The host audits the tree (`Workspace::ingest`),
//!    commits the audited tree (`Workspace::commit`) and records the commit in the ledger.
//! 5. Write `implementation-result` from the commits the host made, and the evidence manifest.
//!
//! A change the audit refuses (a protected path, a hidden path, a link that leaves the workspace,
//! a nested git directory, a secret) is **never dropped and never committed**: the stage stops,
//! the refusal and its paths go into the evidence, and `evaluate` turns it into a policy
//! violation that blocks the stage run.

use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::contracts::task_dag::Task;
use factory_domain::contracts::{AgentManifest, ArtifactRef, StageContract, VersionedRef};
use factory_domain::machines::guards::EnvironmentCause;
use factory_domain::policy::RepoKind;
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, Sha256Digest, Slug};
use factory_domain::vocabulary::{RiskTier, StageKind};
use factory_ports::agent::{AgentRunRequest, Capability, Denial, RoutingNeed, Usage};
use factory_ports::paths::{CommitSha, PathMode};
use factory_ports::registry::{LoadedPrompt, VersionReq};
use factory_ports::sandbox::{SandboxSession, TeardownReason};
use factory_ports::workspace::{
    ChangeKind, CommitRequest, JobRepo, Workspace, WorkspaceError, WorkspacePurpose,
    WorkspaceRequest,
};

use super::evidence::{
    ChangedFile, EVIDENCE, ImplementationEvidence, RESULT, Refusal, Spent, TaskEvidence, diff_stats,
};
use super::handler::ImplementationHandler;
use super::input::{
    ARCHITECTURE, REPOSITORY_MAP, SPECIFICATION_CONTRACT, TASK_PLAN, input_artifact, map_commit,
};
use super::plan;
use super::report::ReportedCommand;
use super::report::{BuilderReport, Status};
use super::seams::{
    Hold, LedgerError, PlannedTask, ReworkContext, SeamError, WorkspaceAccess, verify_spec,
};
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::handlers::{
    NamedArtifact, NeedsHumanRequest, SandboxReady, StageContext, StageError, StageOutput,
};
use crate::prompts::{Assembler, AssemblyRequest, ContentClass, Input, Limits, Scope, Source};

/// The key prefix of the single task of a rework run.
pub(super) const REWORK_PREFIX: &str = "rework-round-";

/// What every task of the run shares.
struct Shared {
    manifest: AgentManifest,
    prompt: LoadedPrompt,
    plan_sha: Sha256Digest,
    specification: Vec<u8>,
    specification_sha: Sha256Digest,
    architecture: Vec<u8>,
    architecture_sha: Sha256Digest,
    feedback: Option<String>,
    /// The answers people gave to a question of this stage run, as text for the task block.
    answers: String,
}

/// The most bytes of one human answer that go into a prompt.
const ANSWER_MAX_BYTES: usize = 8 * 1024;

/// One unit of work for the builder.
struct Unit {
    key: Slug,
    title: String,
    text: String,
    /// The kind of the task, for the type of its commit. A rework round has none.
    kind: Option<factory_domain::contracts::task_dag::TaskKind>,
}

/// What the run has used and said so far.
#[derive(Default)]
struct Tally {
    usage: Usage,
    denials: Vec<Denial>,
    sandbox_reported: bool,
}

/// How one task ended.
enum TaskOutcome {
    /// The change was audited and committed.
    Committed(TaskEvidence, CommitSha),
    /// The audit refused the change. Nothing was committed.
    Refused(Refusal),
    /// The builder cannot go on, and a person is needed.
    Asked(&'static str),
}

pub(crate) fn ledger_error(error: LedgerError) -> StageError {
    match error {
        // This attempt was replaced by another worker. It stops; the engine already knows.
        LedgerError::Fenced => StageError::Cancelled,
        LedgerError::Illegal => StageError::Internal,
        LedgerError::Unavailable => StageError::Tool,
    }
}

pub(crate) fn seam_error(error: SeamError) -> StageError {
    match error {
        SeamError::Unavailable => StageError::Tool,
        SeamError::NotFound => StageError::Internal,
    }
}

pub(crate) fn workspace_error(error: WorkspaceError) -> StageError {
    match error {
        WorkspaceError::Cancelled => StageError::Cancelled,
        WorkspaceError::UnknownCommit | WorkspaceError::NotFetched => {
            StageError::Blocked(BlockedCode::DependencyUnavailable)
        }
        _ => StageError::Tool,
    }
}

fn slug(text: &str) -> Result<Slug, StageError> {
    Slug::parse(text).map_err(|_| StageError::Internal)
}

pub(crate) fn mode_name(mode: PathMode) -> &'static str {
    match mode {
        PathMode::Hidden => "hidden",
        PathMode::DenyWrite => "deny_write",
        PathMode::AppendOnly => "append_only",
        PathMode::AdditionsOnly => "additions_only",
        PathMode::Sensitive => "sensitive",
    }
}

fn kind_name(kind: ChangeKind) -> &'static str {
    match kind {
        ChangeKind::Added => "added",
        ChangeKind::Modified => "modified",
        ChangeKind::Deleted => "deleted",
    }
}

/// The refusal an ingestion error stands for, or `None` for an error that is a fault.
fn refusal_of(task: &str, error: &WorkspaceError) -> Option<Refusal> {
    let (code, paths): (&str, Vec<(String, String)>) = match error {
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
    };
    Some(Refusal {
        task: task.to_owned(),
        code: code.to_owned(),
        paths,
    })
}

/// Whether the tokens and the money of the stage allow another task.
fn within_budget(contract: &StageContract, usage: &Usage) -> bool {
    let budget = &contract.budget;
    let tokens = usage.input_tokens.saturating_add(usage.output_tokens);
    let allowed = u64::try_from(budget.max_tokens.get()).unwrap_or(0);
    let spent_usd = usage.cost.0 as f64 / 1_000_000.0;
    tokens <= allowed && spent_usd <= budget.max_cost_usd.as_f64()
}

fn spent_of(usage: &Usage) -> Spent {
    Spent {
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        cost_micro_usd: usage.cost.0,
        requests: usage.requests,
    }
}

pub(super) async fn execute(
    handler: &ImplementationHandler,
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
            let bytes = artifacts
                .get(&scope, &reference)
                .await
                .map_err(|_| missing())?;
            Ok::<_, StageError>((reference, bytes))
        }
    };
    let (plan_ref, plan_bytes) = read(TASK_PLAN).await?;
    let (spec_ref, specification) = read(SPECIFICATION_CONTRACT).await?;
    let (arch_ref, architecture) = read(ARCHITECTURE).await?;
    let (_, map_bytes) = read(REPOSITORY_MAP).await?;
    let task_plan = plan::read(&plan_bytes).map_err(|_| missing())?;
    let ordered = plan::order(&task_plan).map_err(|_| missing())?;
    let base = map_commit(&map_bytes).ok_or_else(missing)?;

    // 2. Where the run stands.
    let rework = handler.rework.of(&identity).await.map_err(seam_error)?;
    let units = units_of(&ordered, &task_plan, rework.as_ref())?;
    let mut head = rework
        .as_ref()
        .map_or_else(|| base.clone(), |context| context.previous_head.clone());

    // 3. The task graph.
    let planned: Vec<PlannedTask> = if rework.is_some() {
        units
            .iter()
            .map(|unit| PlannedTask {
                key: unit.key.clone(),
                depends_on: Vec::new(),
            })
            .collect()
    } else {
        ordered
            .iter()
            .map(|task| PlannedTask {
                key: plan::key(task),
                depends_on: task.depends_on.as_slice().to_vec(),
            })
            .collect()
    };
    let records = handler
        .ledger
        .open(&identity, &plan_ref.sha256, &planned)
        .await
        .map_err(ledger_error)?;

    // The agent that runs, and the words it is given.
    let manifest = ports
        .registry
        .manifest(&handler.config.agent, &VersionReq::Any)
        .map_err(|_| StageError::Internal)?;
    if !manifest
        .permitted_placements
        .as_slice()
        .contains(&factory_domain::contracts::agent_manifest::AgentPlacement::Sandbox)
    {
        return Err(StageError::Environment(EnvironmentCause::PolicyViolation));
    }
    let prompt = ports
        .registry
        .prompt(&manifest)
        .map_err(|_| StageError::Internal)?;
    let shared = Shared {
        manifest,
        prompt,
        plan_sha: plan_ref.sha256.clone(),
        specification,
        specification_sha: spec_ref.sha256.clone(),
        architecture,
        architecture_sha: arch_ref.sha256.clone(),
        feedback: rework.as_ref().map(super::feedback::render),
        answers: human_answers(ctx).await?,
    };

    let repo = ports
        .workspaces
        .repo(identity.job)
        .await
        .map_err(workspace_error)?;
    let mut tally = Tally::default();
    let mut tasks: Vec<TaskEvidence> = Vec::new();
    let mut refusal: Option<Refusal> = None;
    let mut asked: Option<&'static str> = None;

    // A run with nothing left to build still proves that the sandbox can be made, because the
    // engine fails a stage that declares a sandbox and never reports one.
    let nothing_left = units.iter().all(|unit| {
        records.iter().any(|r| {
            r.key == unit.key && r.status == factory_domain::state::TaskNodeStatus::Succeeded
        })
    });

    for unit in &units {
        let record = records.iter().find(|r| r.key == unit.key);
        if let Some(record) = record {
            use factory_domain::state::TaskNodeStatus;
            match record.status {
                TaskNodeStatus::Succeeded => {
                    let commit = record.commit.clone().ok_or(StageError::Internal)?;
                    let facts = task_facts(handler, ctx, repo.as_ref(), &head, &commit).await?;
                    tasks.push(TaskEvidence {
                        key: unit.key.as_str().to_owned(),
                        built_on: head.as_str().to_owned(),
                        commit: commit.as_str().to_owned(),
                        changes: facts.0,
                        additions: facts.1,
                        deletions: facts.2,
                        reported_commands: Vec::new(),
                        reported_tests: Vec::new(),
                        ignored_instructions: Vec::new(),
                        model: None,
                    });
                    head = commit;
                    continue;
                }
                TaskNodeStatus::Cancelled => return Err(StageError::Internal),
                TaskNodeStatus::Pending
                | TaskNodeStatus::Ready
                | TaskNodeStatus::Running
                | TaskNodeStatus::Failed => {}
            }
        }
        if !within_budget(ctx.contract, &tally.usage) {
            return Err(StageError::BudgetExhausted);
        }
        if ctx.cancel.is_cancelled() {
            return Err(StageError::Cancelled);
        }
        match run_one(
            handler,
            ctx,
            &shared,
            repo.as_ref(),
            unit,
            &head,
            &mut tally,
        )
        .await?
        {
            TaskOutcome::Committed(evidence, commit) => {
                tasks.push(evidence);
                head = commit;
            }
            TaskOutcome::Refused(found) => {
                refusal = Some(found);
                break;
            }
            TaskOutcome::Asked(reason) => {
                asked = Some(reason);
                break;
            }
        }
    }

    if nothing_left && !tally.sandbox_reported {
        ready_check(handler, ctx, &head, &mut tally).await?;
    }

    if let Some(reason) = asked {
        return Ok(StageOutput {
            usage: tally.usage,
            permission_denials: tally.denials,
            needs_human: Some(NeedsHumanRequest {
                reason: slug(reason)?,
            }),
            ..StageOutput::default()
        });
    }

    // 5. What leaves the stage.
    let evidence = ImplementationEvidence {
        base_commit: base.as_str().to_owned(),
        head_commit: head.as_str().to_owned(),
        tasks,
        refusal,
        rework_round: rework.as_ref().map(|context| context.round),
        spent: spent_of(&tally.usage),
        fake: ports.workspaces.fidelity() == factory_domain::vocabulary::Fidelity::Fake
            || ports.sandbox.fidelity() == factory_domain::vocabulary::Fidelity::Fake
            || ports.runtime.fidelity() == factory_domain::vocabulary::Fidelity::Fake,
    };
    let json_type = MediaType::parse("application/json").map_err(|_| StageError::Internal)?;
    let mut stored = Vec::with_capacity(2);
    for (name, value) in [
        (RESULT, evidence.result_json()),
        (EVIDENCE, evidence.to_json()),
    ] {
        let bytes = serde_json::to_vec(&value).map_err(|_| StageError::Internal)?;
        let artifact = ports
            .artifacts
            .put(bytes, json_type.clone())
            .await
            .map_err(|_| StageError::Tool)?;
        stored.push(NamedArtifact {
            name: slug(name)?,
            artifact,
        });
    }
    Ok(StageOutput {
        artifacts: stored,
        usage: tally.usage,
        permission_denials: tally.denials,
        ..StageOutput::default()
    })
}

/// The answers people gave to a question of this stage run, oldest first. The builder asked for a
/// decision with `NEEDS_HUMAN`; the answer is untrusted text and goes into the task block.
async fn human_answers(ctx: &StageContext<'_>) -> Result<String, StageError> {
    let scope = TenantScope::new(ctx.identity.tenant);
    let mut text = String::new();
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
        text.push_str(&format!(
            "\n\nAnswer {} from a person to your question:\n{}",
            index + 1,
            String::from_utf8_lossy(bounded)
        ));
    }
    Ok(text)
}

/// The units of work: the tasks of the plan in order, or, for a rework run, the one task that
/// carries the feedback.
fn units_of(
    ordered: &[&Task],
    task_plan: &factory_domain::contracts::TaskDag,
    rework: Option<&ReworkContext>,
) -> Result<Vec<Unit>, StageError> {
    let Some(context) = rework else {
        return Ok(ordered
            .iter()
            .map(|task| Unit {
                key: plan::key(task),
                title: task.title.as_str().to_owned(),
                text: plan::render_task(task),
                kind: Some(task.kind),
            })
            .collect());
    };
    let key = slug(&format!("{REWORK_PREFIX}{}", context.round))?;
    let mut text = format!(
        "Task {}: Fix the problems found in the previous round\n\n",
        key.as_str()
    );
    text.push_str(
        "The work below was built, checked and sent back. Fix only the problems listed under the gate reports. Do not start the plan again.\n\nThe tasks of the plan, for context:\n",
    );
    for task in ordered {
        text.push_str(&format!(
            "- {}: {}\n",
            task.task_id.as_str(),
            task.title.as_str()
        ));
    }
    text.push_str("\nFiles you may change (every other path is out of scope):\n");
    for glob in plan::all_owned_files(task_plan) {
        text.push_str(&format!("- {glob}\n"));
    }
    Ok(vec![Unit {
        key,
        title: "Fix the problems found in the previous round".to_owned(),
        text,
        kind: None,
    }])
}

/// The changed paths and the statistics of the commit `to` over `from`, from the host's own
/// object store.
async fn task_facts(
    handler: &ImplementationHandler,
    ctx: &StageContext<'_>,
    repo: &dyn JobRepo,
    from: &CommitSha,
    to: &CommitSha,
) -> Result<(Vec<ChangedFile>, u64, u64), StageError> {
    let export = repo
        .export_patch(from, to, handler.config.max_patch_bytes, ctx.cancel)
        .await
        .map_err(workspace_error)?;
    let patch = ctx
        .ports
        .artifacts
        .get(&TenantScope::new(ctx.identity.tenant), &export.patch)
        .await
        .map_err(|_| StageError::Tool)?;
    let (additions, deletions) = diff_stats(&patch);
    let changes = export
        .changes
        .iter()
        .map(|change| ChangedFile {
            path: change.path.as_str().to_owned(),
            kind: kind_name(change.kind).to_owned(),
        })
        .collect();
    Ok((changes, additions, deletions))
}

pub(crate) async fn close(
    session: Box<dyn SandboxSession>,
    completed: bool,
) -> Result<(), StageError> {
    session
        .stop_and_remove(if completed {
            TeardownReason::Completed
        } else {
            TeardownReason::Failed
        })
        .await
        .map(|_| ())
        .map_err(|_| StageError::Sandbox)
}

/// Makes the sandbox for a workspace and checks that it is what the stage meant: the spec is for
/// the `agent` profile over this workspace, the sandbox port has read the posture of the container
/// back and found it equal to the spec and the policy, and the runtime has what the stage needs. The sandbox is
/// removed again on every failure. When `report_ready` is set, the engine is told that the
/// sandbox is up.
pub(crate) async fn open_sandbox(
    specs: &dyn super::seams::WorkspaceAgentSpecs,
    ctx: &mut StageContext<'_>,
    workspace: &dyn Workspace,
    access: WorkspaceAccess,
    required: &[Capability],
    report_ready: bool,
) -> Result<Box<dyn SandboxSession>, StageError> {
    let ports = ctx.ports;
    let token = ctx.job_token.ok_or(StageError::Internal)?;
    let mounts = workspace.mounts();
    let spec = specs
        .spec(ctx.identity.job, ctx.attempt, token, mounts.clone(), access)
        .map_err(|_| StageError::Environment(EnvironmentCause::PolicyUnloadable))?;
    // The agent runs in the `agent` profile over this workspace and no other, with the access the
    // stage asked for, or it does not run.
    verify_spec(&spec, &mounts)?;
    let mut session = ports.sandbox.create_verified(spec, ctx.cancel).await?;
    let capabilities = match ports.runtime.probe(&mut *session).await {
        Ok(found) => found,
        Err(error) => {
            let _ = close(session, false).await;
            return Err(error.into());
        }
    };
    let satisfies = required
        .iter()
        .all(|capability| capabilities.supports(*capability));
    if !satisfies {
        let _ = close(session, false).await;
        return Err(StageError::Blocked(BlockedCode::ToolUnavailable));
    }
    if report_ready {
        ctx.report_sandbox_ready(SandboxReady {
            posture_verified: true,
            tool_grants_recorded: true,
            probe_satisfies_stage: satisfies,
        });
    }
    Ok(session)
}

/// What the builder needs from the runtime.
const BUILDER_NEEDS: [Capability; 1] = [Capability::HeadlessMultiTurn];

async fn open_builder_sandbox(
    handler: &ImplementationHandler,
    ctx: &mut StageContext<'_>,
    workspace: &dyn Workspace,
    tally: &mut Tally,
) -> Result<Box<dyn SandboxSession>, StageError> {
    let session = open_sandbox(
        handler.specs.as_ref(),
        ctx,
        workspace,
        WorkspaceAccess::Edit,
        &BUILDER_NEEDS,
        !tally.sandbox_reported,
    )
    .await?;
    tally.sandbox_reported = true;
    Ok(session)
}

/// Proves that the sandbox can be made when there is nothing left to build.
async fn ready_check(
    handler: &ImplementationHandler,
    ctx: &mut StageContext<'_>,
    head: &CommitSha,
    tally: &mut Tally,
) -> Result<(), StageError> {
    let workspace = ctx
        .ports
        .workspaces
        .create(
            WorkspaceRequest {
                job: ctx.identity.job,
                attempt: ctx.attempt,
                base: head.clone(),
                rules: handler.config.path_rules.clone(),
                purpose: WorkspacePurpose::Agent,
            },
            ctx.cancel,
        )
        .await
        .map_err(workspace_error)?;
    let result = match open_builder_sandbox(handler, ctx, workspace.as_ref(), tally).await {
        Ok(session) => close(session, true).await,
        Err(error) => Err(error),
    };
    let _ = workspace.dispose().await;
    result
}

/// One task: the ledger, the workspace, the sandbox, the builder, the audit and the commit.
async fn run_one(
    handler: &ImplementationHandler,
    ctx: &mut StageContext<'_>,
    shared: &Shared,
    repo: &dyn JobRepo,
    unit: &Unit,
    on: &CommitSha,
    tally: &mut Tally,
) -> Result<TaskOutcome, StageError> {
    let identity = ctx.identity;
    let hold = Hold {
        attempt: ctx.attempt,
        epoch: ctx.epoch,
    };
    handler
        .ledger
        .start(&identity, &unit.key, &hold)
        .await
        .map_err(ledger_error)?;
    let workspace = match ctx
        .ports
        .workspaces
        .create(
            WorkspaceRequest {
                job: identity.job,
                attempt: ctx.attempt,
                base: on.clone(),
                rules: handler.config.path_rules.clone(),
                purpose: WorkspacePurpose::Agent,
            },
            ctx.cancel,
        )
        .await
    {
        Ok(workspace) => workspace,
        Err(error) => {
            let _ = handler.ledger.fail(&identity, &unit.key, &hold).await;
            return Err(workspace_error(error));
        }
    };
    let result = build_in(
        handler,
        ctx,
        shared,
        repo,
        workspace.as_ref(),
        unit,
        on,
        &hold,
        tally,
    )
    .await;
    // The workspace goes whatever happened. The commit it made stays in the job's object store.
    let _ = workspace.dispose().await;
    if !matches!(result, Ok(TaskOutcome::Committed(..))) {
        let _ = handler.ledger.fail(&identity, &unit.key, &hold).await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn build_in(
    handler: &ImplementationHandler,
    ctx: &mut StageContext<'_>,
    shared: &Shared,
    repo: &dyn JobRepo,
    workspace: &dyn Workspace,
    unit: &Unit,
    on: &CommitSha,
    hold: &Hold,
    tally: &mut Tally,
) -> Result<TaskOutcome, StageError> {
    let ports = ctx.ports;
    let identity = ctx.identity;
    let mut session = open_builder_sandbox(handler, ctx, workspace, tally).await?;

    // The prompt. Everything the builder reads is untrusted data in a quoted block.
    let assembled = {
        let now = ports.clock.now();
        let tenant = identity.tenant;
        let artifact = |kind: &str, sha: &Sha256Digest| Source::HostArtifact {
            kind: kind.to_owned(),
            id: sha.to_string(),
        };
        let mut inputs = vec![
            Input::untrusted(
                "task",
                ContentClass::ModelOutput,
                artifact("task-plan", &shared.plan_sha),
                tenant,
                format!("{}{}", unit.text, shared.answers).into_bytes(),
            )
            .fetched_at(now),
            Input::untrusted(
                "frozen_specification",
                ContentClass::SpecificationText,
                artifact("frozen-specification", &shared.specification_sha),
                tenant,
                shared.specification.clone(),
            )
            .fetched_at(now),
            Input::untrusted(
                "architecture",
                ContentClass::ModelOutput,
                artifact("architecture-design", &shared.architecture_sha),
                tenant,
                shared.architecture.clone(),
            )
            .fetched_at(now),
        ];
        if let Some(feedback) = &shared.feedback {
            inputs.push(
                Input::untrusted(
                    "gate_reports",
                    ContentClass::ToolOutput,
                    Source::ToolOutput {
                        producer: "rework-feedback".to_owned(),
                    },
                    tenant,
                    feedback.clone().into_bytes(),
                )
                .fetched_at(now),
            );
        }
        let assembler = Assembler::new(&handler.redactor, &handler.policy.paths, Limits::default());
        assembler.assemble(AssemblyRequest::new(
            &shared.manifest,
            &shared.prompt,
            Scope::new(tenant, RepoKind::Target),
            inputs,
        ))
    };
    let assembled = match assembled {
        Ok(assembled) => assembled,
        Err(_) => {
            let _ = close(session, false).await;
            return Err(StageError::Internal);
        }
    };
    let need = RoutingNeed {
        stage: StageKind::Implementation,
        tier: RecommendedTier::Standard,
        required: BUILDER_NEEDS.to_vec(),
        risk: RiskTier::Medium,
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
    let builder_model = (
        route.model.runtime.as_str().to_owned(),
        route.model.model.as_str().to_owned(),
    );
    let request = AgentRunRequest {
        attempt: ctx.attempt,
        agent: VersionedRef {
            id: shared.manifest.id.clone(),
            version: shared.manifest.version.clone(),
        },
        prompt: assembled.to_port_prompt(),
        output_schema: shared.manifest.outputs_schema.clone(),
        max_output_bytes: handler.config.max_output_bytes,
        broker: handler.config.broker.clone(),
        job_token: token,
        tools: shared.manifest.allowed_tools.as_slice().to_vec(),
        limits: shared.manifest.resource_limits.clone(),
        model: route.model,
        flag_set: route.flag_set,
        mcp_gateway: None,
    };
    let report = ports.runtime.run(&mut *session, request, ctx.cancel).await;
    tally.usage = tally.usage.saturating_add(report.usage);
    tally
        .denials
        .extend(report.permission_denials.iter().cloned());

    // The container is gone before anything is read from the tree it wrote to. A container that
    // may still run is a reason to stop, not to read.
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

    // The report, checked twice. It decides nothing about the change. A report that is rejected is a
    // failed run, and a failed run keeps its evidence: the engine audits each denial the tool made
    // and indexes the transcript (finding F-1 of the cross-cutting security tests: a run whose
    // report was invalid left its denials out of the audit log).
    let Ok(validated) = handler
        .schemas
        .check(&shared.manifest.outputs_schema, output.as_bytes())
    else {
        ctx.note_failed_run(&report);
        return Err(StageError::InvalidOutput);
    };
    let Ok(parsed) = BuilderReport::read(&validated.value) else {
        ctx.note_failed_run(&report);
        return Err(StageError::InvalidOutput);
    };
    if parsed.task_id != unit.key.as_str() {
        ctx.note_failed_run(&report);
        return Err(StageError::InvalidOutput);
    }
    match parsed.status {
        Status::Blocked => return Ok(TaskOutcome::Asked("builder-blocked")),
        Status::NeedsHuman => return Ok(TaskOutcome::Asked("builder-needs-human")),
        Status::Done => {}
    }
    if parsed.dependency_requests > 0 {
        return Ok(TaskOutcome::Asked("dependency-requested"));
    }

    // The audit. A refusal is a result, not a failure to try again.
    let change = match workspace.ingest(ctx.cancel).await {
        Ok(change) => change,
        Err(error) => {
            return match refusal_of(unit.key.as_str(), &error) {
                Some(refusal) => {
                    ctx.note_audit(AuditAction::new(
                        if refusal.code == "secret-found" {
                            AuditKind::SecretRedactedOrBlocked
                        } else {
                            AuditKind::ProtectedPathDecision
                        },
                        AuditDecision::Denied,
                    ));
                    Ok(TaskOutcome::Refused(refusal))
                }
                None => Err(workspace_error(error)),
            };
        }
    };
    // The builder says it is done and the tree is the same as before: its word is contradicted.
    if change.is_empty() || change.base() != on {
        ctx.note_failed_run(&report);
        return Err(StageError::InvalidOutput);
    }
    if ctx.cancel.is_cancelled() {
        return Err(StageError::Cancelled);
    }
    // A worker that lost its lease while the builder ran makes no commit.
    handler
        .ledger
        .confirm(&identity, hold)
        .await
        .map_err(ledger_error)?;

    // The commit is made on the host, from the tree that was audited, and then recorded. Its
    // message follows the project's git conventions when it has them.
    let conventions = crate::conventions::load(ctx, on).await?;
    let body = format!(
        "Task {} of the plan, committed by the factory after the change was audited.",
        unit.key.as_str()
    );
    let message = crate::conventions::message_or(
        conventions.as_ref(),
        conventions
            .as_ref()
            .map_or("feat", |c| c.task_type(unit.kind)),
        None,
        &unit.title,
        &body,
        format!("{}\n\n{body}\n", unit.title),
    );
    let commit = workspace
        .commit(
            &change,
            CommitRequest {
                message,
                author_name: handler.config.identity.name.clone(),
                author_email: handler.config.identity.email.clone(),
            },
        )
        .await
        .map_err(workspace_error)?;
    handler
        .ledger
        .finish(&identity, &unit.key, &commit, hold)
        .await
        .map_err(ledger_error)?;

    let (_, additions, deletions) = task_facts(handler, ctx, repo, on, &commit).await?;
    let evidence = TaskEvidence {
        key: unit.key.as_str().to_owned(),
        built_on: on.as_str().to_owned(),
        commit: commit.as_str().to_owned(),
        changes: change
            .changes()
            .iter()
            .map(|changed| ChangedFile {
                path: changed.path.as_str().to_owned(),
                kind: kind_name(changed.kind).to_owned(),
            })
            .collect(),
        additions,
        deletions,
        reported_commands: parsed
            .commands_run
            .into_iter()
            .map(|command| ReportedCommand {
                argv: command
                    .argv
                    .iter()
                    .map(|argument| keep_no_secret(handler, ctx, argument))
                    .collect(),
                exit_code: command.exit_code,
            })
            .collect(),
        reported_tests: parsed
            .tests_added
            .iter()
            .map(|name| keep_no_secret(handler, ctx, name))
            .collect(),
        ignored_instructions: parsed
            .ignored_instructions
            .iter()
            .map(|text| keep_no_secret(handler, ctx, text))
            .collect(),
        model: Some(builder_model),
    };
    Ok(TaskOutcome::Committed(evidence, commit))
}

/// What the builder says about its own work goes into the evidence document, and from there into
/// the artifact store and the prompts of later stages. It is text written by a model, so it can hold
/// a secret the model was shown or invented. The redactor runs over it before it is kept, a
/// replacement is audited, and text the redactor cannot judge is dropped (finding F-3 of the
/// cross-cutting security tests: reported test names, command arguments and ignored instructions
/// reached the store unredacted).
fn keep_no_secret(
    handler: &ImplementationHandler,
    ctx: &mut StageContext<'_>,
    text: &str,
) -> String {
    match handler.redactor.redact_str(text) {
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
            String::from("[dropped: the text could not be checked for secrets]")
        }
    }
}
