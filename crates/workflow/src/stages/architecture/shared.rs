//! What the architecture stage and the planning stage do the same way: store a document, read an
//! input by the hash the contract pinned, run an agent that only reads, build the evidence that is
//! not a pass or a fail, and write the feedback of an earlier round for the next prompt.
//!
//! Nothing here decides anything about a design or a plan. The agent runs in the `agent` sandbox
//! over a checkout that is its own copy and is disposed of unread, with tools that only read.

use factory_domain::contracts::agent_manifest::{AgentPlacement, RecommendedTier};
use factory_domain::contracts::gate_report::{
    BlockedCode, NotApplicableCode, NotApplicableDecider,
};
use factory_domain::contracts::{AgentManifest, ArtifactRef, Contract, GateReport, VersionedRef};
use factory_domain::ids::GateReportId;
use factory_domain::scope::TenantScope;
use factory_domain::values::{GitSha, MediaType, Slug};
use factory_domain::vocabulary::{RiskTier, StageKind};
use factory_ports::agent::{AgentRunRequest, BrokerEndpoint, RoutingNeed, Usage};
use factory_ports::paths::{CommitSha, PathRules};
use factory_ports::registry::{LoadedPrompt, RegistryError, ValidatedOutput, VersionReq};
use factory_ports::workspace::{Workspace, WorkspacePurpose, WorkspaceRequest};
use serde_json::{Value, json};

use super::seams::{AgentOutputCheck, CapabilityProbes, WorkspaceAgentSpecs};
use crate::handlers::{GateContext, NamedArtifact, StageContext, StageError};
use crate::prompts::Assembled;
use crate::stages::implementation::input::input_artifact;
use crate::stages::implementation::run::{close, open_sandbox, workspace_error};
use crate::stages::implementation::seams::{WorkspaceAccess, verify_read_only_tools};
use crate::stages::intake::common::{
    Executor, GateDefinition, GateFacts, GateSubject, gate_report,
};

/// A slug the stage names itself.
pub(crate) fn slug(text: &str) -> Result<Slug, StageError> {
    Slug::parse(text).map_err(|_| StageError::Internal)
}

/// Stores bytes and names them as a deliverable.
pub(crate) async fn store_bytes(
    ctx: &StageContext<'_>,
    name: &str,
    bytes: Vec<u8>,
    media_type: &str,
) -> Result<NamedArtifact, StageError> {
    let artifact = ctx
        .ports
        .artifacts
        .put(
            bytes,
            MediaType::parse(media_type).map_err(|_| StageError::Internal)?,
        )
        .await
        .map_err(|_| StageError::Tool)?;
    Ok(NamedArtifact {
        name: slug(name)?,
        artifact,
    })
}

/// Stores a JSON document and names it as a deliverable.
pub(crate) async fn store_json(
    ctx: &StageContext<'_>,
    name: &str,
    value: &Value,
) -> Result<NamedArtifact, StageError> {
    let bytes = serde_json::to_vec(value).map_err(|_| StageError::Internal)?;
    store_bytes(ctx, name, bytes, "application/json").await
}

/// Reads the input the contract pinned under `name`, by its hash.
pub(crate) async fn read_input(
    ctx: &StageContext<'_>,
    name: &str,
) -> Result<(ArtifactRef, Vec<u8>), StageError> {
    let missing = || StageError::Blocked(BlockedCode::DependencyUnavailable);
    let reference = input_artifact(ctx.contract, name).ok_or_else(missing)?;
    let bytes = ctx
        .ports
        .artifacts
        .get(&TenantScope::new(ctx.identity.tenant), &reference)
        .await
        .map_err(|_| missing())?;
    Ok((reference, bytes))
}

/// The same, for the evaluation of a gate.
pub(crate) async fn read_for_gate(
    ctx: &GateContext<'_>,
    reference: &ArtifactRef,
) -> Result<Vec<u8>, StageError> {
    ctx.ports
        .artifacts
        .get(&TenantScope::new(ctx.identity.tenant), reference)
        .await
        .map_err(|_| StageError::Tool)
}

/// The output of this attempt called `name`.
pub(crate) fn output<'a>(ctx: &'a GateContext<'_>, name: &str) -> Option<&'a NamedArtifact> {
    ctx.outputs.iter().find(|named| named.name.as_str() == name)
}

/// Who a gate report is about, with the clock read once at the start.
pub(crate) fn subject(ctx: &GateContext<'_>) -> GateSubject {
    let started = ctx.ports.clock.now();
    GateSubject {
        job: ctx.identity.job,
        stage_run: ctx.identity.stage_run,
        attempt: ctx.attempt,
        mode: ctx.mode,
        report_id: GateReportId::from_uuid(ctx.ports.ids.new_uuid()),
        started_at: started,
        finished_at: ctx.ports.clock.now(),
    }
}

/// Which gate and from what definition.
pub(crate) fn definition(id: &'static str, text: &'static str, commit: &GitSha) -> GateDefinition {
    GateDefinition {
        id,
        version: "1.0.0",
        text,
        commit: commit.clone(),
    }
}

/// The facts of a report of a check that ran in the control plane.
pub(crate) fn facts(
    definition: GateDefinition,
    outcome: &'static str,
    title: &str,
    reason: &str,
    failures: Vec<(String, String)>,
    evidence: Vec<String>,
) -> GateFacts {
    GateFacts {
        definition,
        outcome,
        title: title.to_owned(),
        reason: reason.to_owned(),
        failures,
        blocked: None,
        fidelity: "real",
        executor: Executor::InProcess,
        commands: Vec::new(),
        tools: vec![(
            "factory-architecture-and-planning".to_owned(),
            "1.0.0".to_owned(),
        )],
        evidence,
    }
}

/// A report that says the gate does not apply, with who decided and why.
///
/// # Errors
/// [`StageError::Internal`] when the report would break a rule of its schema.
pub(crate) fn not_applicable(
    subject: &GateSubject,
    facts: GateFacts,
    code: NotApplicableCode,
    decided_by: NotApplicableDecider,
    justification: &str,
) -> Result<GateReport, StageError> {
    // The report builder writes passed, failed and blocked reports. The shape of a report that does
    // not apply differs in two fields, so the document is changed and read again through the
    // contract, which checks every rule of the schema.
    let base = gate_report(
        subject,
        &GateFacts {
            outcome: "PASSED",
            failures: Vec::new(),
            blocked: None,
            ..facts
        },
    )?;
    let mut document = base.to_json_value().map_err(|_| StageError::Internal)?;
    let map = document.as_object_mut().ok_or(StageError::Internal)?;
    map.insert("outcome".into(), json!("NOT_APPLICABLE"));
    map.insert(
        "not_applicable_reason".into(),
        json!({
            "code": code.as_str(),
            "justification": justification,
            "decided_by": decided_by.as_str(),
        }),
    );
    GateReport::from_json_value(document).map_err(|_| StageError::Internal)
}

/// What the stage is configured to run an agent with.
#[derive(Debug, Clone)]
pub struct AgentSettings {
    /// Where the sandbox reaches the model broker.
    pub broker: BrokerEndpoint,
    /// The most bytes of final output the runtime reads.
    pub max_output_bytes: u64,
    /// The path rules of the policy, which the checkout applies.
    pub path_rules: PathRules,
}

/// The seams an agent run needs.
#[derive(Clone, Copy)]
pub(crate) struct Tools<'a> {
    pub(crate) redactor: &'a factory_domain::redaction::Redactor,
    pub(crate) specs: &'a dyn WorkspaceAgentSpecs,
    pub(crate) probes: &'a dyn CapabilityProbes,
    pub(crate) schemas: &'a dyn AgentOutputCheck,
}

/// An agent found in the registry, with its prompt.
pub(crate) struct Loaded {
    pub(crate) manifest: AgentManifest,
    pub(crate) prompt: LoadedPrompt,
}

/// Why an agent could not be loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoadProblem {
    /// The registry has no agent with this id.
    Unknown,
    /// The agent exists and cannot be used: it may not run in a sandbox, or it holds a tool that
    /// writes, or its prompt is not intact.
    Unusable,
}

/// Finds an agent that only reads and may run in a sandbox.
pub(crate) fn load(
    registry: &dyn factory_ports::registry::AgentRegistry,
    agent: &Slug,
) -> Result<Loaded, LoadProblem> {
    let manifest = match registry.manifest(agent, &VersionReq::Any) {
        Ok(manifest) => manifest,
        Err(RegistryError::UnknownAgent | RegistryError::NoMatchingVersion) => {
            return Err(LoadProblem::Unknown);
        }
        Err(_) => return Err(LoadProblem::Unusable),
    };
    if !manifest
        .permitted_placements
        .as_slice()
        .contains(&AgentPlacement::Sandbox)
    {
        return Err(LoadProblem::Unusable);
    }
    verify_read_only_tools(&manifest).map_err(|_| LoadProblem::Unusable)?;
    let prompt = registry
        .prompt(&manifest)
        .map_err(|_| LoadProblem::Unusable)?;
    Ok(Loaded { manifest, prompt })
}

/// What one agent run gave back.
pub(crate) struct Answer {
    /// The answer, checked against the agent's own output schema.
    pub(crate) validated: ValidatedOutput,
    /// The exact bytes of the answer. Their hash is `validated.sha256`.
    pub(crate) raw: Vec<u8>,
    /// What the run used.
    pub(crate) usage: Usage,
    /// The tool calls policy denied.
    pub(crate) denials: Vec<factory_ports::agent::Denial>,
    /// The model, as the router chose it.
    pub(crate) model: String,
    /// The runtime adapter.
    pub(crate) runtime: String,
    /// The version of the tool that ran.
    pub(crate) runtime_version: String,
}

/// One run of an agent.
pub(crate) struct Call<'a> {
    pub(crate) loaded: &'a Loaded,
    pub(crate) assembled: &'a Assembled,
    pub(crate) base: &'a CommitSha,
    pub(crate) stage: StageKind,
    pub(crate) risk: RiskTier,
    /// Tell the engine the sandbox is up. Only the first run of an attempt does.
    pub(crate) report_ready: bool,
}

/// Runs an agent over its own checkout of the base commit, in the `agent` sandbox, and checks its
/// answer against its output schema. The checkout is disposed of whatever happened.
pub(crate) async fn run_agent(
    ctx: &mut StageContext<'_>,
    settings: &AgentSettings,
    tools: Tools<'_>,
    call: &Call<'_>,
) -> Result<Answer, StageError> {
    let workspace = ctx
        .ports
        .workspaces
        .create(
            WorkspaceRequest {
                job: ctx.identity.job,
                attempt: ctx.attempt,
                base: call.base.clone(),
                rules: settings.path_rules.clone(),
                purpose: WorkspacePurpose::Agent,
            },
            ctx.cancel,
        )
        .await
        .map_err(workspace_error)?;
    let result = run_in(ctx, settings, tools, call, workspace.as_ref()).await;
    let _ = workspace.dispose().await;
    result
}

async fn run_in(
    ctx: &mut StageContext<'_>,
    settings: &AgentSettings,
    tools: Tools<'_>,
    call: &Call<'_>,
    workspace: &dyn Workspace,
) -> Result<Answer, StageError> {
    let ports = ctx.ports;
    let manifest = &call.loaded.manifest;
    let mut session = open_sandbox(
        tools.specs,
        ctx,
        workspace,
        WorkspaceAccess::Inspect,
        &[],
        call.report_ready,
    )
    .await?;
    let need = RoutingNeed {
        stage: call.stage,
        tier: RecommendedTier::Standard,
        required: Vec::new(),
        risk: call.risk,
        exclude: Vec::new(),
        probed: tools.probes.probed(),
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
    let model = route.model.model.as_str().to_owned();
    let request = AgentRunRequest {
        attempt: ctx.attempt,
        agent: VersionedRef {
            id: manifest.id.clone(),
            version: manifest.version.clone(),
        },
        prompt: call.assembled.to_port_prompt(),
        output_schema: manifest.outputs_schema.clone(),
        max_output_bytes: settings.max_output_bytes,
        broker: settings.broker.clone(),
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
    // An artifact is a sink that refuses a secret. The agent read the repository with its own
    // tools, so a secret in a file it could read can come out in what it wrote. Nothing is stored
    // from such an answer, and a redactor that cannot check refuses it as well.
    match tools.redactor.contains_secret(output.as_bytes()) {
        Ok(false) => {}
        Ok(true) => return Err(StageError::PolicyDenied),
        Err(_) => return Err(StageError::Internal),
    }
    let validated = tools
        .schemas
        .check(&manifest.outputs_schema, output.as_bytes())
        .map_err(|_| StageError::InvalidOutput)?;
    Ok(Answer {
        validated,
        raw: output.as_bytes().to_vec(),
        usage: report.usage,
        denials: report.permission_denials,
        model,
        runtime: ports.runtime.id().as_str().to_owned(),
        runtime_version: report
            .runtime_version
            .unwrap_or_else(|| "unknown".to_owned()),
    })
}

/// Runs the readability gate over the text a stage wrote.
///
/// # Errors
/// [`StageError::Internal`] when the report cannot be built.
pub(crate) fn readability_report(
    ctx: &GateContext<'_>,
    commit: &GitSha,
    artifacts: &[crate::gates::readability::Artifact<'_>],
) -> Result<GateReport, StageError> {
    use crate::gates::readability::{Options, ReadabilityGate, ReportContext, ReviewerPolicy};
    let started = ctx.ports.clock.now();
    ReadabilityGate::new(Options::new())
        .evaluate(
            artifacts,
            &ReportContext {
                gate_report_id: GateReportId::from_uuid(ctx.ports.ids.new_uuid()),
                job_id: ctx.identity.job,
                stage_run_id: ctx.identity.stage_run,
                attempt_id: Some(ctx.attempt),
                execution_mode: ctx.mode,
                definition_source:
                    factory_domain::contracts::gate_report::DefinitionSource::CentralConfig,
                definition_commit: commit.clone(),
                started_at: started,
                finished_at: ctx.ports.clock.now(),
                reviewer: ReviewerPolicy::Optional,
            },
        )
        .map_err(|_| StageError::Internal)
}

/// The most bytes of one human answer that go into a prompt.
const ANSWER_MAX_BYTES: usize = 8 * 1024;

/// What the agent is told about the rounds before this one: why the earlier run was sent back, in
/// the words of the gates that failed it, and what a person answered. `None` for a first run that
/// no one has answered.
pub(crate) fn feedback_text(
    previous: Option<&super::seams::PreviousRound>,
    answers: &[String],
    kept: &[String],
) -> Option<String> {
    if previous.is_none() && answers.is_empty() {
        return None;
    }
    let mut text = String::new();
    if let Some(round) = previous {
        text.push_str(&format!(
            "This is rework round {}. The run before it was sent back for these reasons.\n",
            round.round
        ));
        for report in &round.failed_reports {
            for failure in report.failures.iter().flatten() {
                text.push_str(&format!("- {}\n", failure.message.as_str()));
            }
        }
        if !kept.is_empty() {
            text.push_str(&format!(
                "\nThese tasks passed every check. Keep them as they are unless a reason above names them: {}.\n",
                kept.join(", ")
            ));
        }
    }
    for (index, answer) in answers.iter().enumerate() {
        text.push_str(&format!(
            "\nAnswer {} from a person to your question:\n{}\n",
            index + 1,
            answer
        ));
    }
    Some(text)
}

/// The answers people gave to this stage run, each cut to a fixed size.
pub(crate) async fn human_answers(ctx: &StageContext<'_>) -> Result<Vec<String>, StageError> {
    let scope = TenantScope::new(ctx.identity.tenant);
    let mut answers = Vec::new();
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
        answers.push(String::from_utf8_lossy(bounded).into_owned());
    }
    Ok(answers)
}

/// A fault in a seam becomes the stage error that says so.
pub(crate) fn seam(error: super::seams::SeamError) -> StageError {
    match error {
        super::seams::SeamError::Unavailable => StageError::Tool,
        super::seams::SeamError::NotFound => StageError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slug_the_stage_names_itself_is_accepted_and_a_bad_one_is_an_internal_fault() {
        assert!(slug("architecture-record").is_ok());
        assert_eq!(slug("Not A Slug").unwrap_err(), StageError::Internal);
    }
}
