//! The rig: a test engine over the labelled fakes, with the real architecture and planning
//! handlers registered, stand-ins for the stages around them, and spies that record what happened.
//!
//! The scripted architect, critic and planner are the adversarial runtime (FX-ADV) of the testkit.
//! The planner is wrapped so that it copies the plan metadata out of its own prompt, as a real
//! planner is told to, because the values (a new identifier and the time) exist only when the stage
//! runs. A test can change one field after the copy to play a planner that does not copy.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::contracts::{
    AgentManifest, ArtifactRef, Contract, GateReport, SchemaRef, StageContract, Violation,
};
use factory_domain::ids::{AttemptId, JobId, StageRunId, TenantId};
use factory_domain::policy::{ApprovalPolicy, PolicyEngine, SecurityPolicy};
use factory_domain::redaction::{PatternAction, PatternSpec, Redactor};
use factory_domain::scope::TenantScope;
use factory_domain::state::StageRunStatus;
use factory_domain::values::{GitSha, MediaType, Sha256Digest, Slug, Uri};
use factory_domain::vocabulary::{Fidelity, RiskTier, StageKind};
use factory_ports::agent::{
    AgentRunReport, AgentRuntime, BrokerEndpoint, JobTokenRef, ProbeError, ProbedCapabilities,
    RuntimeCapabilities, RuntimeId,
};
use factory_ports::artifact::{ArtifactBackend, ArtifactError, ArtifactStore};
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{
    BranchName, CommitSha, PathMode, PathRule, PathRules, RepoGlob, RepoRef,
};
use factory_ports::registry::ValidatedOutput;
use factory_ports::sandbox::{
    ExecRequest, ExecResult, PostureReport, SandboxError, SandboxId, SandboxProfile,
    SandboxProvider, SandboxSession, SandboxSpec, TeardownReason, TeardownReport,
};
use factory_ports::workspace::{
    CommitRequest, FetchCredential, FetchTarget, IngestedChange, JobRepo, Workspace,
    WorkspaceError, WorkspaceMounts, WorkspaceProvider, WorkspaceRequest,
};
use factory_testkit::agent::{AdversarialScript, FakeAgentRuntime, RecordedPrompt};
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::fixtures::{Ids, sandbox_policy, sandbox_spec};
use factory_testkit::registry::InMemoryAgentRegistry;
use factory_testkit::router::probed;
use factory_testkit::sandbox::FakeSandbox;
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use factory_workflow::engine::{AttemptOutcome, Engine};
use factory_workflow::gates::dag::Limits;
use factory_workflow::handlers::{
    ContractContext, GateContext, HandlerRegistry, NamedArtifact, StageContext, StageError,
    StageHandler, StageOutput,
};
use factory_workflow::scheduler::ClaimedAttempt;
use factory_workflow::stages::architecture::checks::Rules;
use factory_workflow::stages::architecture::{
    AgentOutputCheck, AgentSettings, ArchitectureConfig, ArchitectureDeps, ArchitectureHandler,
    CapabilityProbes, JobRisk, PreviousRound, RiskSource, RoundSource, SeamError,
    WorkspaceAgentSpecs,
};
use factory_workflow::stages::implementation::input::{
    ARCHITECTURE, REPOSITORY_MAP, SPECIFICATION_CONTRACT, TASK_PLAN, upstream_output,
};
use factory_workflow::stages::implementation::seams::WorkspaceAccess;
use factory_workflow::stages::implementation::{StageBudget, plan as implementation_plan};
use factory_workflow::stages::intake::common::{
    ContractBudget, ContractCriterion, ContractDeliverable, ContractInput, ContractSpec, Executor,
    GateDefinition, GateFacts, GateSubject, gate_report, stage_contract,
};
use factory_workflow::stages::planning::{PlanningConfig, PlanningDeps, PlanningHandler};
use serde_json::{Value, json};

use crate::support::world::World;

const SECURITY_POLICY: &str = include_str!("../../../domain/tests/fixtures/policy/security.json");
const APPROVAL_POLICY: &str = include_str!("../../../domain/tests/fixtures/policy/approval.json");
pub const ARCHITECT_MANIFEST: &str = include_str!("../../../../agents/architect/manifest.json");
pub const ARCHITECT_PROMPT: &str = include_str!("../../../../agents/architect/prompt.md");
pub const PLANNER_MANIFEST: &str = include_str!("../../../../agents/planner/manifest.json");
pub const PLANNER_PROMPT: &str = include_str!("../../../../agents/planner/prompt.md");
const REVIEWER_MANIFEST: &str = include_str!("../../../../agents/code-reviewer/manifest.json");
const REVIEWER_PROMPT: &str = include_str!("../../../../agents/code-reviewer/prompt.md");
pub const SPECIFICATION: &str = include_str!(
    "../../../../schemas/examples/specification-contract/valid/approved-json-output-flag.json"
);
const PLANNER_FIXTURE: &str =
    include_str!("../../../../agents/planner/fixtures/valid/json-output-plan.json");

/// The events of one run, in the order they happened, across every port.
pub type Log = Arc<Mutex<Vec<String>>>;

pub fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().expect("the lock is never poisoned")
}

pub fn note(log: &Log, text: impl Into<String>) {
    lock(log).push(text.into());
}

pub fn policy_engine() -> Arc<PolicyEngine> {
    let security: SecurityPolicy =
        serde_json::from_str(SECURITY_POLICY).expect("the security policy fixture is valid");
    let approval: ApprovalPolicy =
        serde_json::from_str(APPROVAL_POLICY).expect("the approval policy fixture is valid");
    Arc::new(PolicyEngine::new(&security, &approval).expect("the policies build"))
}

pub fn redactor() -> Arc<Redactor> {
    let policy: SecurityPolicy = serde_json::from_str(SECURITY_POLICY).expect("valid");
    let patterns = policy.secrets.patterns.iter().map(|p| {
        let action = match p.action {
            factory_domain::policy::security::SecretAction::Block => PatternAction::Block,
            factory_domain::policy::security::SecretAction::Flag => PatternAction::Flag,
        };
        PatternSpec::new(p.id.clone(), p.regex.0.clone(), action)
    });
    Arc::new(
        Redactor::builder()
            .patterns(patterns)
            .build()
            .expect("the policy patterns compile"),
    )
}

pub fn definition_commit() -> GitSha {
    GitSha::parse("1405df66cbe219b0bf6355bc3d60361a8376b6b4").expect("a commit")
}

fn rules() -> PathRules {
    let mode = |group: &str, glob: &str, mode: PathMode| {
        (
            group.to_owned(),
            PathRule::Mode {
                glob: RepoGlob::new(glob).expect("a glob"),
                mode,
            },
        )
    };
    PathRules::new(vec![
        mode("secrets", ".env*", PathMode::Hidden),
        mode("ci", ".github/**", PathMode::DenyWrite),
        mode("test_code", "tests/**", PathMode::AdditionsOnly),
    ])
}

/// The files of the base commit.
pub fn base_files() -> Vec<(String, String)> {
    [
        (
            "Cargo.toml",
            "[package]\nname = \"word-count\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        ("src/main.rs", "fn main() {\n    println!(\"words\");\n}\n"),
        (
            "src/lib.rs",
            "pub fn count(text: &str) -> usize {\n    text.split_whitespace().count()\n}\n",
        ),
        ("tests/it.rs", "#[test]\nfn counts() {}\n"),
        (".github/workflows/ci.yml", "name: ci\non: push\n"),
        ("README.md", "# Word count\n"),
    ]
    .iter()
    .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
    .collect()
}

// ---- artifacts the tenant can read ---------------------------------------------------------

/// Wraps an artifact store so that whatever is stored is readable by the test tenant.
pub struct Granting {
    inner: InMemoryArtifactStore,
    tenant: TenantId,
}

impl Granting {
    pub fn new(inner: InMemoryArtifactStore, tenant: TenantId) -> Self {
        Self { inner, tenant }
    }
}

#[async_trait]
impl ArtifactStore for Granting {
    fn backend(&self) -> ArtifactBackend {
        self.inner.backend()
    }
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }
    async fn put(
        &self,
        bytes: Vec<u8>,
        media_type: MediaType,
    ) -> Result<ArtifactRef, ArtifactError> {
        let reference = self.inner.put(bytes, media_type).await?;
        self.inner.grant(self.tenant, &reference.sha256);
        Ok(reference)
    }
    async fn get(
        &self,
        scope: &TenantScope,
        reference: &ArtifactRef,
    ) -> Result<Vec<u8>, ArtifactError> {
        self.inner.get(scope, reference).await
    }
    async fn exists(
        &self,
        scope: &TenantScope,
        reference: &ArtifactRef,
    ) -> Result<bool, ArtifactError> {
        self.inner.exists(scope, reference).await
    }
}

// ---- the schema check ----------------------------------------------------------------------

/// A stand-in for `AgentSchema::validate_bytes`, which lives in `factory-contracts` and which this
/// crate cannot depend on. It accepts any JSON, or refuses everything, so that the stage's own
/// second defence is what the tests exercise.
pub struct StandInCheck {
    refusing: Mutex<bool>,
    asked: Mutex<Vec<SchemaRef>>,
}

impl StandInCheck {
    pub fn new() -> Self {
        Self {
            refusing: Mutex::new(false),
            asked: Mutex::new(Vec::new()),
        }
    }
    pub fn refuse_everything(&self) {
        *lock(&self.refusing) = true;
    }
    pub fn asked(&self) -> Vec<SchemaRef> {
        lock(&self.asked).clone()
    }
}

impl AgentOutputCheck for StandInCheck {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    fn check(&self, schema: &SchemaRef, bytes: &[u8]) -> Result<ValidatedOutput, Vec<Violation>> {
        lock(&self.asked).push(schema.clone());
        let refuse = |message: &str| {
            vec![Violation {
                path: "$".to_owned(),
                message: message.to_owned(),
            }]
        };
        if *lock(&self.refusing) {
            return Err(refuse("the stand-in check refuses every document"));
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| refuse("the bytes are not JSON"))?;
        Ok(ValidatedOutput {
            value,
            sha256: Sha256Digest::of(bytes),
            size_bytes: bytes.len() as u64,
        })
    }
}

pub struct FixedProbes;

impl CapabilityProbes for FixedProbes {
    fn probed(&self) -> ProbedCapabilities {
        probed(&["fake"])
    }
}

// ---- the sandbox spec seam -----------------------------------------------------------------

/// Builds the `agent` spec over the mounts it is given, and remembers what each spec asked for.
pub struct RigSpecs {
    pub seen: Mutex<Vec<(SandboxProfile, WorkspaceAccess)>>,
}

impl WorkspaceAgentSpecs for RigSpecs {
    fn spec(
        &self,
        job: JobId,
        attempt: AttemptId,
        _token: JobTokenRef,
        mounts: WorkspaceMounts,
        access: WorkspaceAccess,
    ) -> Result<SandboxSpec, SeamError> {
        let mut spec = sandbox_spec(&Ids::new(), SandboxProfile::Agent);
        spec.job = job;
        spec.attempt = attempt;
        spec.mounts.workspace = mounts;
        lock(&self.seen).push((spec.profile, access));
        Ok(spec)
    }
}

// ---- the seams that come from the store ----------------------------------------------------

/// The risk facts of the job, which a test sets.
pub struct RigRisk {
    pub job: Mutex<JobRisk>,
}

#[async_trait]
impl RiskSource for RigRisk {
    async fn of(
        &self,
        _run: &factory_workflow::handlers::RunIdentity,
    ) -> Result<JobRisk, SeamError> {
        Ok(*lock(&self.job))
    }
}

/// The rounds before the next run of a stage, which a test queues.
pub struct RigRounds {
    queue: Mutex<VecDeque<Option<PreviousRound>>>,
}

impl RigRounds {
    pub fn queue(&self, round: Option<PreviousRound>) {
        lock(&self.queue).push_back(round);
    }
}

#[async_trait]
impl RoundSource for RigRounds {
    async fn previous(
        &self,
        _run: &factory_workflow::handlers::RunIdentity,
    ) -> Result<Option<PreviousRound>, SeamError> {
        Ok(lock(&self.queue).pop_front().flatten())
    }
}

// ---- spies ---------------------------------------------------------------------------------

pub struct SpyWorkspaces {
    pub inner: Arc<FakeWorkspaceProvider>,
    pub log: Log,
}

struct SpyWorkspace {
    inner: Box<dyn Workspace>,
    log: Log,
}

#[async_trait]
impl WorkspaceProvider for SpyWorkspaces {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }
    async fn fetch(
        &self,
        job: JobId,
        target: &FetchTarget,
        branch: &BranchName,
        cancel: &dyn CancelSignal,
    ) -> Result<factory_ports::workspace::FetchedBase, WorkspaceError> {
        self.inner.fetch(job, target, branch, cancel).await
    }
    async fn create(
        &self,
        req: WorkspaceRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn Workspace>, WorkspaceError> {
        let base = req.base.as_str().to_owned();
        let inner = self.inner.create(req, cancel).await?;
        note(&self.log, format!("workspace.create:{base}"));
        Ok(Box::new(SpyWorkspace {
            inner,
            log: self.log.clone(),
        }))
    }
    async fn repo(&self, job: JobId) -> Result<Box<dyn JobRepo>, WorkspaceError> {
        self.inner.repo(job).await
    }
    async fn dispose_job(&self, job: JobId) -> Result<(), WorkspaceError> {
        self.inner.dispose_job(job).await
    }
    async fn sweep_orphans(
        &self,
        live: &[AttemptId],
        live_jobs: &[JobId],
    ) -> Result<Vec<AttemptId>, WorkspaceError> {
        self.inner.sweep_orphans(live, live_jobs).await
    }
}

#[async_trait]
impl Workspace for SpyWorkspace {
    fn mounts(&self) -> WorkspaceMounts {
        self.inner.mounts()
    }
    fn base(&self) -> &CommitSha {
        self.inner.base()
    }
    async fn ingest(&self, cancel: &dyn CancelSignal) -> Result<IngestedChange, WorkspaceError> {
        note(&self.log, "workspace.ingest");
        self.inner.ingest(cancel).await
    }
    async fn commit(
        &self,
        change: &IngestedChange,
        req: CommitRequest,
    ) -> Result<CommitSha, WorkspaceError> {
        note(&self.log, "workspace.commit");
        self.inner.commit(change, req).await
    }
    async fn dispose(self: Box<Self>) -> Result<(), WorkspaceError> {
        note(&self.log, "workspace.dispose");
        self.inner.dispose().await
    }
}

pub struct SpySandbox {
    pub inner: FakeSandbox,
    pub log: Log,
}

struct SpySession {
    inner: Box<dyn SandboxSession>,
    log: Log,
}

#[async_trait]
impl SandboxProvider for SpySandbox {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }
    async fn create_verified(
        &self,
        spec: SandboxSpec,
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn SandboxSession>, SandboxError> {
        note(
            &self.log,
            format!("sandbox.create:{}", spec.profile.as_str()),
        );
        let inner = self.inner.create_verified(spec, cancel).await?;
        Ok(Box::new(SpySession {
            inner,
            log: self.log.clone(),
        }))
    }
    async fn sweep_orphans(&self, live: &[AttemptId]) -> Result<Vec<SandboxId>, SandboxError> {
        self.inner.sweep_orphans(live).await
    }
}

#[async_trait]
impl SandboxSession for SpySession {
    fn id(&self) -> &SandboxId {
        self.inner.id()
    }
    fn posture(&self) -> &PostureReport {
        self.inner.posture()
    }
    async fn exec(
        &mut self,
        req: ExecRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<ExecResult, SandboxError> {
        note(&self.log, "sandbox.exec");
        self.inner.exec(req, cancel).await
    }
    async fn stop_and_remove(
        self: Box<Self>,
        reason: TeardownReason,
    ) -> Result<TeardownReport, SandboxError> {
        note(&self.log, "sandbox.removed");
        self.inner.stop_and_remove(reason).await
    }
}

// ---- the runtime ---------------------------------------------------------------------------

type Tweak = Box<dyn FnOnce(&mut Value) + Send>;

struct Queued {
    agent: String,
    output: Value,
    /// Copy the plan metadata out of the prompt into `output.plan.metadata`, then apply `tweak`.
    copy_metadata: bool,
    tweak: Option<Tweak>,
}

/// The scripted adversarial runtime, with one addition: a queued planner answer can copy the plan
/// metadata out of the prompt the planner receives, as a real planner is told to do.
pub struct Runtime {
    pub inner: FakeAgentRuntime,
    queue: Mutex<VecDeque<Queued>>,
    log: Log,
}

impl Runtime {
    fn push(&self, queued: Queued) {
        lock(&self.queue).push_back(queued);
    }
    pub fn runs(&self, agent: &str) -> usize {
        self.prompts(agent).len()
    }
    pub fn prompts(&self, agent: &str) -> Vec<RecordedPrompt> {
        self.inner
            .recorded_prompts()
            .into_iter()
            .filter(|p| p.agent.id.as_str() == agent)
            .collect()
    }
}

/// The text of one data block of a prompt, with the quoting removed.
pub fn block(prompt: &str, name: &str) -> String {
    let open = format!("<<<DATA name={name} ");
    let close = format!("<<<END name={name}>>>");
    let mut inside = false;
    let mut lines: Vec<&str> = Vec::new();
    for line in prompt.lines() {
        if line.starts_with(&open) {
            inside = true;
        } else if line.starts_with(&close) {
            break;
        } else if inside {
            lines.push(
                line.strip_prefix("> ")
                    .unwrap_or(line.trim_start_matches('>')),
            );
        }
    }
    lines.join("\n")
}

#[async_trait]
impl AgentRuntime for Runtime {
    fn id(&self) -> &RuntimeId {
        self.inner.id()
    }
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    async fn probe(
        &self,
        session: &mut dyn SandboxSession,
    ) -> Result<RuntimeCapabilities, ProbeError> {
        self.inner.probe(session).await
    }
    async fn run(
        &self,
        session: &mut dyn SandboxSession,
        req: factory_ports::agent::AgentRunRequest,
        cancel: &dyn CancelSignal,
    ) -> AgentRunReport {
        let agent = req.agent.id.as_str().to_owned();
        note(&self.log, format!("runtime.run:{agent}"));
        let queued = {
            let mut queue = lock(&self.queue);
            match queue.front() {
                Some(front) if front.agent == agent => queue.pop_front(),
                _ => None,
            }
        };
        if let Some(mut queued) = queued {
            if queued.copy_metadata {
                let metadata: Value =
                    serde_json::from_str(&block(&req.prompt.instructions, "plan_metadata"))
                        .expect("the prompt carries the plan metadata as JSON");
                queued.output["plan"]["metadata"] = metadata;
            }
            if let Some(tweak) = queued.tweak.take() {
                tweak(&mut queued.output);
            }
            self.inner
                .queue(AdversarialScript::returning(queued.output));
        }
        self.inner.run(session, req, cancel).await
    }
}

// ---- the stages around the two under test -------------------------------------------------

const GATE: &str = "standin-gate";
const GATE_TEXT: &str = "standin-gate 1.0.0: a stand-in stage stored its deliverables.";

fn standin_contract(
    ctx: &ContractContext<'_>,
    contract_id: &'static str,
    span: &'static str,
    deliverables: &[&'static str],
    inputs: Vec<ContractInput>,
) -> Result<StageContract, StageError> {
    stage_contract(&ContractSpec {
        kind: ctx.identity.kind,
        job: ctx.identity.job,
        stage_run: ctx.identity.stage_run,
        mode: ctx.mode,
        created_at: ctx.now,
        contract_id,
        title: "Stand in for a stage in a test",
        purpose: "Store the deliverables that the real stage would store, so that a stage under test has its inputs.",
        problem: "The stage under test reads what the stages before it produced, and those stages have their own tests.",
        inputs: if inputs.is_empty() {
            vec![ContractInput {
                name: "policy-bundle",
                description: "The hash of the policy bundle in force.",
                sha256: ctx.policy_hash.clone(),
                media_type: "application/json",
                source: "policy",
                produced_by: None,
                commit_sha: None,
                retrieved_at: ctx.now,
                trust: "trusted_internal",
            }]
        } else {
            inputs
        },
        preconditions: vec![(
            "upstream-passed",
            "The stages before this one passed.",
            "upstream_stage_passed",
        )],
        method: (
            "Store a fixed document",
            "A test needs the input to be exactly what it chose.",
            "Run the real stage",
            "The real stage has its own tests.",
        ),
        agent: ("standin".to_owned(), "1.0.0"),
        granted_tools: Vec::new(),
        shell: "none",
        // The contract of an implementation stage must say that its agent runs in the sandbox.
        placement: (ctx.identity.kind == StageKind::Implementation).then_some("sandbox"),
        deliverables: deliverables
            .iter()
            .map(|name| ContractDeliverable {
                name,
                description: "A fixed document.",
                media_type: "application/json",
                required: true,
            })
            .collect(),
        criteria: vec![ContractCriterion {
            id: "standin-criterion",
            description: "The stand-in stored its deliverables.",
            gate: GATE,
        }],
        gates: vec![GATE],
        budget: ContractBudget {
            wall_time_seconds: 300,
            max_tokens: 0,
            max_cost_usd: 0.0,
            attempt_timeout_seconds: 240,
            max_attempts: 1,
        },
        rollback: "Nothing outside the test is changed.",
        span_name: span,
    })
}

/// Stores fixed deliverables for a stage that runs before the ones under test.
pub struct Fixed {
    pub kind: StageKind,
    pub contract_id: &'static str,
    pub span: &'static str,
    pub deliverables: Vec<(&'static str, Vec<u8>)>,
}

#[async_trait]
impl StageHandler for Fixed {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    fn kind(&self) -> StageKind {
        self.kind
    }
    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        let names: Vec<&'static str> = self.deliverables.iter().map(|(n, _)| *n).collect();
        standin_contract(ctx, self.contract_id, self.span, &names, Vec::new())
    }
    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        let mut stored = Vec::new();
        for (name, bytes) in &self.deliverables {
            let artifact = ctx
                .ports
                .artifacts
                .put(
                    bytes.clone(),
                    MediaType::parse("application/json").map_err(|_| StageError::Internal)?,
                )
                .await
                .map_err(|_| StageError::Tool)?;
            stored.push(NamedArtifact {
                name: Slug::parse(name).map_err(|_| StageError::Internal)?,
                artifact,
            });
        }
        Ok(StageOutput {
            artifacts: stored,
            ..StageOutput::default()
        })
    }
    async fn evaluate(
        &self,
        ctx: &GateContext<'_>,
    ) -> Result<factory_workflow::gates::framework::GateDecision, StageError> {
        stand_in_decision(ctx)
    }
}

fn stand_in_decision(
    ctx: &GateContext<'_>,
) -> Result<factory_workflow::gates::framework::GateDecision, StageError> {
    let now = ctx.ports.clock.now();
    let report = gate_report(
        &GateSubject {
            job: ctx.identity.job,
            stage_run: ctx.identity.stage_run,
            attempt: ctx.attempt,
            mode: ctx.mode,
            report_id: factory_domain::ids::GateReportId::from_uuid(ctx.ports.ids.new_uuid()),
            started_at: now,
            finished_at: ctx.ports.clock.now(),
        },
        &GateFacts {
            definition: GateDefinition {
                id: GATE,
                version: "1.0.0",
                text: GATE_TEXT,
                commit: definition_commit(),
            },
            outcome: "PASSED",
            title: "The stand-in stored its deliverables".to_owned(),
            reason: "The stand-in stored its deliverables.".to_owned(),
            failures: Vec::new(),
            blocked: None,
            fidelity: "fake",
            executor: Executor::InProcess,
            commands: Vec::new(),
            tools: vec![("standin".to_owned(), "1.0.0".to_owned())],
            evidence: vec!["standin=PASSED".to_owned()],
        },
    )?;
    Ok(factory_workflow::gates::framework::GateDecision {
        reports: vec![report],
        ..Default::default()
    })
}

/// The implementation stage, as far as these two stages are concerned: it takes the plan and the
/// design from the runs before it by the names the real implementation stage uses, reads the plan
/// with the real implementation reader, and records the order it would run the tasks in.
pub struct ImplementationProbe;

pub const PROBE_RESULT: &str = "implementation-probe";

#[async_trait]
impl StageHandler for ImplementationProbe {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    fn kind(&self) -> StageKind {
        StageKind::Implementation
    }
    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        let missing = || {
            StageError::Blocked(
                factory_domain::contracts::gate_report::BlockedCode::DependencyUnavailable,
            )
        };
        let mut inputs = Vec::new();
        for (kind, name) in [
            (StageKind::TaskPlanning, TASK_PLAN),
            (StageKind::Architecture, ARCHITECTURE),
            (StageKind::RepositoryIntelligence, REPOSITORY_MAP),
            (StageKind::Specification, SPECIFICATION_CONTRACT),
        ] {
            let (run, artifact) = upstream_output(ctx.upstream, kind, name).ok_or_else(missing)?;
            inputs.push(ContractInput {
                name,
                description: "An input of the implementation stage.",
                sha256: artifact.sha256.clone(),
                media_type: "application/json",
                source: "previous_stage",
                produced_by: Some(run.id),
                commit_sha: None,
                retrieved_at: ctx.now,
                trust: "trusted_internal",
            });
        }
        standin_contract(
            ctx,
            "stage-contract.implementation",
            "stage.implementation",
            &[PROBE_RESULT],
            inputs,
        )
    }
    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        // The contract says the agent runs in the sandbox, so the engine wants to be told it is up.
        ctx.report_sandbox_ready(factory_workflow::handlers::SandboxReady {
            posture_verified: true,
            tool_grants_recorded: true,
            probe_satisfies_stage: true,
        });
        let reference = ctx
            .contract
            .inputs
            .iter()
            .find(|input| input.name.as_str() == TASK_PLAN)
            .map(|input| input.artifact.clone())
            .ok_or(StageError::Internal)?;
        let bytes = ctx
            .ports
            .artifacts
            .get(&TenantScope::new(ctx.identity.tenant), &reference)
            .await
            .map_err(|_| StageError::Tool)?;
        let plan = implementation_plan::read(&bytes).map_err(|_| StageError::InvalidOutput)?;
        let order: Vec<String> = implementation_plan::order(&plan)
            .map_err(|_| StageError::InvalidOutput)?
            .iter()
            .map(|task| task.task_id.as_str().to_owned())
            .collect();
        let artifact = ctx
            .ports
            .artifacts
            .put(
                serde_json::to_vec(&json!({ "kind": PROBE_RESULT, "order": order }))
                    .map_err(|_| StageError::Internal)?,
                MediaType::parse("application/json").map_err(|_| StageError::Internal)?,
            )
            .await
            .map_err(|_| StageError::Tool)?;
        Ok(StageOutput {
            artifacts: vec![NamedArtifact {
                name: Slug::parse(PROBE_RESULT).map_err(|_| StageError::Internal)?,
                artifact,
            }],
            ..StageOutput::default()
        })
    }
    async fn evaluate(
        &self,
        ctx: &GateContext<'_>,
    ) -> Result<factory_workflow::gates::framework::GateDecision, StageError> {
        stand_in_decision(ctx)
    }
}

// ---- the manifests ------------------------------------------------------------------------

pub fn architect_manifest() -> AgentManifest {
    serde_json::from_str(ARCHITECT_MANIFEST).expect("the real manifest is valid")
}

pub fn planner_manifest() -> AgentManifest {
    serde_json::from_str(PLANNER_MANIFEST).expect("the real manifest is valid")
}

/// The prompt of a critic for tests: the code reviewer's prompt with the inputs of an architecture
/// critic. No such agent exists in `agents/`, so a test builds one to prove what the stage does
/// when one is added.
pub fn critic_prompt() -> String {
    let mut text = REVIEWER_PROMPT
        .replace("# Code reviewer prompt", "# Architecture critic prompt")
        .replace("Agent: code-reviewer", "Agent: architecture-critic")
        .replace(
            "| `diff` | model_output | yes | The exported patch that the builder produced. |",
            "| `architecture_design` | model_output | yes | The design under review. |",
        )
        .replace(
            "| `gate_reports` | tool_output | yes | The reports of the deterministic gates that ran on the change. |",
            "| `repository_map` | tool_output | yes | The repository map. |",
        )
        .replace("{{input.diff}}", "{{input.architecture_design}}")
        .replace("{{input.gate_reports}}", "{{input.repository_map}}");
    text.push('\n');
    text
}

/// The manifest of a critic for tests, with the options a test needs to break one rule at a time.
pub fn critic_manifest(change: impl FnOnce(&mut Value)) -> AgentManifest {
    let prompt = critic_prompt();
    let mut value: Value = serde_json::from_str(REVIEWER_MANIFEST).expect("JSON");
    value["id"] = json!("architecture-critic");
    value["role"] = json!("architecture_critic");
    value["title"] = json!("Architecture critic");
    value["prompt"]["template_path"] = json!("agents/architecture-critic/prompt.md");
    value["prompt"]["template_sha256"] = json!(Sha256Digest::of(prompt.as_bytes()));
    change(&mut value);
    serde_json::from_value(value).expect("a manifest")
}

// ---- the rig -------------------------------------------------------------------------------

/// Whether the registry holds a critic, and which.
pub enum Critic {
    /// The registry has none, as in `agents/` today.
    None,
    /// The registry has this one.
    Manifest(Box<AgentManifest>),
}

pub struct Options {
    pub scope: Vec<StageKind>,
    pub critic: Critic,
    pub rules: Rules,
    pub limits: Limits,
    pub files: Vec<(String, String)>,
    pub specification: String,
    pub job_risk: JobRisk,
    /// Text the repository intelligence stand-in puts in the map, such as a README that addresses
    /// AI agents.
    pub map_notes: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            scope: vec![
                StageKind::Intake,
                StageKind::RepositoryIntelligence,
                StageKind::Specification,
                StageKind::DomainDiscovery,
                StageKind::Architecture,
                StageKind::TaskPlanning,
            ],
            critic: Critic::None,
            rules: Rules::default(),
            limits: Limits {
                allowed_roles: &["builder"],
                ..Limits::default()
            },
            files: base_files(),
            specification: SPECIFICATION.to_owned(),
            job_risk: JobRisk::default(),
            map_notes: "A small command line tool.".to_owned(),
        }
    }
}

impl Options {
    /// The stages up to the planning stage and the implementation stand-in after it.
    pub fn through_implementation() -> Self {
        let mut options = Self::default();
        options.scope.push(StageKind::Implementation);
        options
    }
}

pub struct Rig {
    pub world: World,
    pub engine: Engine,
    pub log: Log,
    pub runtime: Arc<Runtime>,
    pub specs: Arc<RigSpecs>,
    pub check: Arc<StandInCheck>,
    pub rounds: Arc<RigRounds>,
    pub risk: Arc<RigRisk>,
    pub artifacts: Arc<Granting>,
    pub base: CommitSha,
    pub job: JobId,
}

impl Rig {
    pub async fn new() -> Self {
        Self::build(Options::default()).await
    }

    pub async fn build(options: Options) -> Self {
        let scope = options.scope.clone();
        let world = World::with_config(|config| config.scope.clone_from(&scope)).await;
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let artifacts = Arc::new(Granting::new(
            InMemoryArtifactStore::new().indexed_by((*world.store).clone()),
            world.tenant,
        ));
        let repo = RepoRef::parse("example-org/fixture").expect("a repository");
        let remote = FakeRemote::new();
        let branch = BranchName::new("main").expect("a branch");
        let pairs: Vec<(&str, &str)> = options
            .files
            .iter()
            .map(|(p, c)| (p.as_str(), c.as_str()))
            .collect();
        remote.commit_on_branch(&repo, &branch, &pairs);
        let provider = Arc::new(FakeWorkspaceProvider::new(
            repo.clone(),
            remote.clone(),
            artifacts.clone(),
            rules(),
        ));
        let job = world
            .engine
            .receive_job(world.tenant, world.requester, world.repository)
            .await
            .expect("receive");
        let fetched = provider
            .fetch(
                job,
                &FetchTarget {
                    repo: repo.clone(),
                    credential: FetchCredential::new(format!("{}-{}", "read", "token")),
                },
                &branch,
                &factory_testkit::clock::FakeCancel::new(),
            )
            .await
            .expect("the fetch works");
        let base = fetched.commit;

        let sandbox = Arc::new(SpySandbox {
            inner: FakeSandbox::new(world.clock.clone(), artifacts.clone(), sandbox_policy()),
            log: log.clone(),
        });
        let runtime = Arc::new(Runtime {
            inner: FakeAgentRuntime::new(artifacts.clone()),
            queue: Mutex::new(VecDeque::new()),
            log: log.clone(),
        });
        let mut registry = InMemoryAgentRegistry::new();
        registry.add(architect_manifest(), Some(ARCHITECT_PROMPT));
        registry.add(planner_manifest(), Some(PLANNER_PROMPT));
        if let Critic::Manifest(manifest) = &options.critic {
            registry.add((**manifest).clone(), Some(&critic_prompt()));
        }

        let mut deps = world.deps.clone();
        deps.artifacts = artifacts.clone();
        deps.sandbox = sandbox;
        deps.workspaces = Arc::new(SpyWorkspaces {
            inner: provider.clone(),
            log: log.clone(),
        });
        deps.runtime = runtime.clone();
        deps.registry = Arc::new(registry);

        let specs = Arc::new(RigSpecs {
            seen: Mutex::new(Vec::new()),
        });
        let check = Arc::new(StandInCheck::new());
        let rounds = Arc::new(RigRounds {
            queue: Mutex::new(VecDeque::new()),
        });
        let risk = Arc::new(RigRisk {
            job: Mutex::new(options.job_risk),
        });
        let settings = AgentSettings {
            broker: BrokerEndpoint {
                base_url: Uri::parse("https://model-broker.sandbox.internal:8443").expect("a URI"),
            },
            max_output_bytes: 524_288,
            path_rules: rules(),
        };
        let budget = StageBudget {
            wall_time_seconds: 900,
            max_tokens: 250_000,
            max_cost_usd: 4.0,
            attempt_timeout_seconds: 900,
            max_attempts: 3,
        };
        let mut handlers = HandlerRegistry::new();
        if scope.contains(&StageKind::Architecture) {
            handlers
                .register(Arc::new(ArchitectureHandler::new(
                    ArchitectureConfig {
                        agent: Slug::parse("architect").expect("a slug"),
                        critic: Slug::parse("architecture-critic").expect("a slug"),
                        definition_commit: definition_commit(),
                        settings: settings.clone(),
                        rules: options.rules,
                        budget,
                    },
                    ArchitectureDeps {
                        policy: policy_engine(),
                        redactor: redactor(),
                        schemas: check.clone(),
                        specs: specs.clone(),
                        probes: Arc::new(FixedProbes),
                        risk: risk.clone(),
                        rounds: rounds.clone(),
                    },
                )))
                .expect("one handler");
        }
        if scope.contains(&StageKind::TaskPlanning) {
            handlers
                .register(Arc::new(PlanningHandler::new(
                    PlanningConfig {
                        agent: Slug::parse("planner").expect("a slug"),
                        definition_commit: definition_commit(),
                        settings,
                        limits: options.limits,
                        budget,
                    },
                    PlanningDeps {
                        policy: policy_engine(),
                        redactor: redactor(),
                        schemas: check.clone(),
                        specs: specs.clone(),
                        probes: Arc::new(FixedProbes),
                        rounds: rounds.clone(),
                    },
                )))
                .expect("one handler");
        }
        let map = serde_json::to_vec(&json!({
            "commit_sha": base.as_str(),
            "languages": ["rust"],
            "build": ["cargo build --locked"],
            "test": ["cargo test --locked"],
            "notes": options.map_notes,
        }))
        .expect("serializes");
        for fixed in [
            Fixed {
                kind: StageKind::Intake,
                contract_id: "stage-contract.intake",
                span: "stage.intake",
                deliverables: vec![(
                    "normalized-request",
                    b"{\"title\":\"Add a JSON option to the word count tool\"}".to_vec(),
                )],
            },
            Fixed {
                kind: StageKind::RepositoryIntelligence,
                contract_id: "stage-contract.repository-intelligence",
                span: "stage.repository_intelligence",
                deliverables: vec![(REPOSITORY_MAP, map)],
            },
            Fixed {
                kind: StageKind::Specification,
                contract_id: "stage-contract.specification",
                span: "stage.specification",
                deliverables: vec![(
                    SPECIFICATION_CONTRACT,
                    options.specification.clone().into_bytes(),
                )],
            },
            Fixed {
                kind: StageKind::DomainDiscovery,
                contract_id: "stage-contract.domain-discovery",
                span: "stage.domain_discovery",
                deliverables: vec![(
                    "domain-profile",
                    b"{\"profile\":\"general-software\"}".to_vec(),
                )],
            },
        ] {
            if scope.contains(&fixed.kind) {
                handlers.register(Arc::new(fixed)).expect("one handler");
            }
        }
        if scope.contains(&StageKind::Implementation) {
            handlers
                .register(Arc::new(ImplementationProbe))
                .expect("one handler");
        }
        let engine = Engine::new(deps, world.config.clone(), handlers).expect("the engine starts");
        Self {
            world,
            engine,
            log,
            runtime,
            specs,
            check,
            rounds,
            risk,
            artifacts,
            base,
            job,
        }
    }

    pub async fn admit(&self) {
        let admission = self
            .engine
            .admit_job(self.world.tenant, self.job)
            .await
            .expect("admit");
        assert!(
            matches!(
                admission,
                factory_workflow::engine::Admission::Admitted { .. }
            ),
            "{admission:?}"
        );
    }

    /// Claims the next stage run and runs its attempt.
    pub async fn run_next(&self) -> (ClaimedAttempt, AttemptOutcome) {
        self.world.advance(400);
        let claimed = self
            .engine
            .claim_next(&World::worker("worker-1"))
            .await
            .expect("claim");
        assert_eq!(claimed.started.len(), 1, "{claimed:?}");
        let claimed = claimed.started.into_iter().next().expect("one");
        let outcome = self
            .engine
            .run_attempt(&claimed)
            .await
            .expect("the attempt runs");
        (claimed, outcome)
    }

    /// Admits the job and runs the stand-ins before the architecture stage.
    pub async fn run_until_architecture(&self) {
        self.admit().await;
        for kind in [
            StageKind::Intake,
            StageKind::RepositoryIntelligence,
            StageKind::Specification,
            StageKind::DomainDiscovery,
        ] {
            let (claimed, outcome) = self.run_next().await;
            assert_eq!(claimed.kind, kind);
            assert_eq!(outcome, AttemptOutcome::Succeeded, "{kind:?}");
        }
    }

    /// Runs the architecture stage with this design and expects it to pass.
    pub async fn architecture_passes(&self, design: Value) {
        self.architect_returns(design);
        let (claimed, outcome) = self.run_next().await;
        assert_eq!(claimed.kind, StageKind::Architecture);
        assert_eq!(outcome, AttemptOutcome::Succeeded);
        assert_eq!(
            self.status(StageKind::Architecture).await,
            StageRunStatus::Passed
        );
    }

    pub fn architect_returns(&self, design: Value) {
        self.runtime.push(Queued {
            agent: "architect".to_owned(),
            output: design,
            copy_metadata: false,
            tweak: None,
        });
    }

    pub fn critic_returns(&self, review: Value) {
        self.runtime.push(Queued {
            agent: "architecture-critic".to_owned(),
            output: review,
            copy_metadata: false,
            tweak: None,
        });
    }

    /// The planner returns the plan of its fixture, with the metadata copied from the prompt and
    /// then this change applied to the plan.
    pub fn planner_plans(&self, change: impl FnOnce(&mut Value) + Send + 'static) {
        let envelope: Value = serde_json::from_str(PLANNER_FIXTURE).expect("the fixture is JSON");
        self.runtime.push(Queued {
            agent: "planner".to_owned(),
            output: envelope,
            copy_metadata: true,
            tweak: Some(Box::new(move |output| change(&mut output["plan"]))),
        });
    }

    /// The planner returns exactly this answer.
    pub fn planner_returns(&self, answer: Value) {
        self.runtime.push(Queued {
            agent: "planner".to_owned(),
            output: answer,
            copy_metadata: false,
            tweak: None,
        });
    }

    /// The names of the schemas the stages asked the check about, in order.
    pub fn asked_schema_names(&self) -> Vec<String> {
        self.check
            .asked()
            .iter()
            .map(|schema| schema.name.as_str().to_owned())
            .collect()
    }

    pub fn events(&self) -> Vec<String> {
        lock(&self.log).clone()
    }

    pub fn events_of(&self, prefix: &str) -> Vec<String> {
        self.events()
            .into_iter()
            .filter(|e| e.starts_with(prefix))
            .collect()
    }

    /// The status of the newest run of `kind`.
    pub async fn status(&self, kind: StageKind) -> StageRunStatus {
        self.world
            .view(self.job)
            .await
            .newest(kind)
            .expect("a run of that kind")
            .status
    }

    /// The status of every run of `kind`, oldest first.
    pub async fn statuses(&self, kind: StageKind) -> Vec<StageRunStatus> {
        self.world
            .view(self.job)
            .await
            .runs_of(kind)
            .map(|run| run.status)
            .collect()
    }

    pub async fn run_of(&self, kind: StageKind) -> StageRunId {
        self.world
            .view(self.job)
            .await
            .newest(kind)
            .expect("a run of that kind")
            .id
    }

    pub async fn runs_of(&self, kind: StageKind) -> usize {
        self.world.view(self.job).await.runs_of(kind).count()
    }

    /// The oldest run of `kind`: the one a gate sent back, once a rework run exists.
    pub async fn first_run_of(&self, kind: StageKind) -> StageRunId {
        self.world
            .view(self.job)
            .await
            .runs_of(kind)
            .next()
            .expect("a run of that kind")
            .id
    }

    /// The artifact the newest run of `kind` stored as `name`.
    pub async fn artifact_named(&self, kind: StageKind, name: &str) -> Option<ArtifactRef> {
        let run = self.run_of(kind).await;
        self.artifact_in(run, name).await
    }

    /// The deliverable `name` of one stage run, read back from the artifact store.
    pub async fn deliverable_in(&self, run: StageRunId, name: &str) -> Option<Value> {
        let reference = self.artifact_in(run, name).await?;
        let bytes = ArtifactStore::get(
            &*self.artifacts,
            &TenantScope::new(self.world.tenant),
            &reference,
        )
        .await
        .ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// The artifact one stage run stored as `name`.
    pub async fn artifact_in(&self, run: StageRunId, name: &str) -> Option<ArtifactRef> {
        let mut best: Option<(u32, ArtifactRef)> = None;
        for link in self.world.links(run).await {
            let role = link.role.as_str();
            let Some((found, attempt)) = role.rsplit_once(".a") else {
                continue;
            };
            let Ok(attempt) = attempt.parse::<u32>() else {
                continue;
            };
            if found == name && best.as_ref().is_none_or(|(n, _)| attempt > *n) {
                best = Some((
                    attempt,
                    ArtifactRef {
                        sha256: link.sha256.clone(),
                        media_type: MediaType::parse("application/json").expect("a media type"),
                        size_bytes: None,
                    },
                ));
            }
        }
        best.map(|(_, reference)| reference)
    }

    /// The deliverable `name` of the newest run of `kind`, read back from the artifact store.
    pub async fn deliverable(&self, kind: StageKind, name: &str) -> Option<Value> {
        let reference = self.artifact_named(kind, name).await?;
        let bytes = ArtifactStore::get(
            &*self.artifacts,
            &TenantScope::new(self.world.tenant),
            &reference,
        )
        .await
        .ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Every gate report of the job, read back through the artifact store.
    pub async fn gate_reports(&self) -> Vec<Value> {
        fn hashes(value: &Value, found: &mut Vec<String>) {
            match value {
                Value::String(text) if text.starts_with("sha256:") => found.push(text.clone()),
                Value::Array(items) => items.iter().for_each(|item| hashes(item, found)),
                Value::Object(map) => map.values().for_each(|item| hashes(item, found)),
                _ => {}
            }
        }
        let tenant = TenantScope::new(self.world.tenant);
        let mut seen = Vec::new();
        let mut reports = Vec::new();
        for entry in self.world.ledger(self.job).await {
            let mut found = Vec::new();
            hashes(
                &serde_json::to_value(&entry).expect("an entry serializes"),
                &mut found,
            );
            for text in found {
                if seen.contains(&text) {
                    continue;
                }
                seen.push(text.clone());
                let Ok(sha256) = Sha256Digest::parse(&text) else {
                    continue;
                };
                let reference = ArtifactRef {
                    sha256,
                    media_type: MediaType::parse("application/json").expect("a media type"),
                    size_bytes: None,
                };
                if let Ok(bytes) = ArtifactStore::get(&*self.artifacts, &tenant, &reference).await
                    && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
                    && value.pointer("/metadata/gate_id").is_some()
                {
                    reports.push(value);
                }
            }
        }
        reports
    }

    /// The reports of one stage run, by gate id.
    pub async fn reports_of(&self, run: StageRunId, gate: &str) -> Vec<Value> {
        self.gate_reports()
            .await
            .into_iter()
            .filter(|report| {
                report.pointer("/metadata/gate_id").and_then(Value::as_str) == Some(gate)
                    && report
                        .pointer("/metadata/stage_run_id")
                        .and_then(Value::as_str)
                        == Some(run.to_string().as_str())
            })
            .collect()
    }

    /// The typed reports of one stage run that failed, as the next round needs them.
    pub async fn failed_reports(&self, run: StageRunId) -> Vec<GateReport> {
        self.gate_reports()
            .await
            .into_iter()
            .filter(|report| {
                report
                    .pointer("/metadata/stage_run_id")
                    .and_then(Value::as_str)
                    == Some(run.to_string().as_str())
                    && report.get("outcome").and_then(Value::as_str) == Some("FAILED")
            })
            .map(|report| GateReport::from_json_value(report).expect("a report"))
            .collect()
    }
}

// ---- documents -----------------------------------------------------------------------------

/// A design that answers every requirement and success criterion of the example specification,
/// weighs two alternatives, names a way it can fail and stays inside one module.
pub fn design() -> Value {
    json!({
        "schema_version": 1,
        "status": "DONE",
        "title": "Add a JSON output mode",
        "summary": "A new formatter module prints the counts as JSON and the argument parser selects it when the flag is present.",
        "design_elements": [
            {
                "element_id": "json-formatter",
                "title": "Print counts as JSON",
                "responsibility": "Formats the line, word and character counts as one JSON object when the flag is given.",
                "kind": "module",
                "satisfies": ["FR-001", "SC-001"],
                "touches": ["src/main.rs", "src/output.rs"]
            },
            {
                "element_id": "plain-output-kept",
                "title": "Keep the plain text output",
                "responsibility": "Leaves the current plain text path untouched when the flag is absent.",
                "kind": "module",
                "satisfies": ["FR-002"],
                "touches": ["src/main.rs"]
            },
            {
                "element_id": "read-errors",
                "title": "Report unreadable files",
                "responsibility": "Writes a clear message to standard error and exits with a non-zero status when the file cannot be read.",
                "kind": "process",
                "satisfies": ["FR-003"],
                "touches": ["src/main.rs"]
            }
        ],
        "decisions": [{
            "decision_id": "hand-written-json",
            "title": "Write the JSON by hand",
            "choice": "Build the JSON text with the standard library, because the tool has no dependencies and the output has three fields.",
            "alternatives": [
                "Add a JSON library as a dependency.",
                "Print the JSON with a template string and no escaping."
            ],
            "consequences": "No new dependency is needed, and the formatter must escape its own output.",
            "needs_person": false
        }],
        "risks": ["The argument parser may change the order of flags."],
        "open_questions": [],
        "uncovered_requirements": [],
        "ignored_instructions": []
    })
}

/// The same design with a decision that adds a dependency, which the policy puts in the high tier.
pub fn high_risk_design() -> Value {
    let mut value = design();
    value["decisions"][0]["needs_person"] = json!(true);
    value["decisions"][0]["choice"] = json!(
        "Add a JSON library as a dependency, because it escapes text correctly and the team already trusts it."
    );
    value
}

/// A critic's answer.
pub fn review(verdict: &str, severity: &str) -> Value {
    let findings = if verdict == "PASS" {
        json!([])
    } else {
        json!([{
            "finding_id": "no-rollback",
            "severity": severity,
            "category": "maintainability",
            "title": "The design has no way back",
            "description": "Nothing says how to undo the dependency if it causes trouble.",
            "confidence": 0.9,
            "proposed_next_action": "fix",
            "defect_class": "code_behavior"
        }])
    };
    json!({
        "schema_version": 1,
        "verdict": verdict,
        "title": "Review of the design",
        "summary": "A short summary of the review of the design.",
        "findings": findings,
        "confidence_overall": 0.8,
        "ignored_instructions": []
    })
}

pub fn gate_outcome(reports: &[Value], gate: &str) -> Option<String> {
    reports
        .iter()
        .find(|report| report.pointer("/metadata/gate_id").and_then(Value::as_str) == Some(gate))
        .and_then(|report| report.get("outcome").and_then(Value::as_str))
        .map(str::to_owned)
}

pub fn risk_of(tier: RiskTier) -> JobRisk {
    JobRisk {
        facts: Default::default(),
        agent_claim: Some(tier),
    }
}
