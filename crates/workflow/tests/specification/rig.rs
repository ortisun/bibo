//! The rig: a test engine over the labelled fakes, with the real specification handler
//! registered, stand-ins for the stages around it, a scripted specification provider, and spies
//! that record what happened in what order.
//!
//! The real Spec Kit provider cannot be a dependency of this crate (rule DEP-01). The scripted
//! provider here runs the scripted adversarial runtime (FX-ADV) for every skill, applies the
//! files the test says the skill wrote, and assembles a contract from the exact bytes of the
//! committed files. The parser, the integrity checks and the post-conditions of the real provider
//! are proved in `factory-spec_adapter`, on the recorded real output.
#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::contracts::specification_contract::{
    ApprovalBasis, OpenQuestion, SpecApproverRole,
};
use factory_domain::contracts::{
    AgentManifest, ArtifactRef, Contract, SchemaRef, SpecificationContract, StageContract,
    Violation,
};
use factory_domain::ids::{AttemptId, GateReportId, JobId, PrincipalId, StageRunId, TenantId};
use factory_domain::policy::{ApprovalPolicy, PolicyEngine, SecurityPolicy};
use factory_domain::redaction::{PatternAction, PatternSpec, Redactor};
use factory_domain::scope::TenantScope;
use factory_domain::values::{GitSha, MediaType, Sha256Digest, Slug, Uri};
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::agent::{
    AgentRunReport, AgentRuntime, AssembledPrompt, BrokerEndpoint, Capability, JobTokenRef,
    ProbeError, ProbedCapabilities, RuntimeCapabilities, RuntimeId,
};
use factory_ports::artifact::{ArtifactBackend, ArtifactError, ArtifactStore};
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{
    BranchName, CommitSha, PathMode, PathRule, PathRules, RepoGlob, RepoPath, RepoRef,
};
use factory_ports::registry::ValidatedOutput;
use factory_ports::sandbox::{SandboxProfile, SandboxSession, SandboxSpec};
use factory_ports::spec::{
    ParseReason, SkillInvocation, SkillRun, SpecContext, SpecError, SpecFileSet, SpecOperation,
    SpecOutcome, SpecRequest, SpecRunReport, SpecificationDraft, SpecificationProvider,
};
use factory_ports::workspace::{FetchCredential, FetchTarget, WorkspaceMounts, WorkspaceProvider};
use factory_testkit::agent::{AdversarialScript, FakeAgentRuntime, RecordedPrompt};
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::contracts::workspace::TreeEdit;
use factory_testkit::fixtures::{Ids, sandbox_policy, sandbox_spec};
use factory_testkit::registry::InMemoryAgentRegistry;
use factory_testkit::router::probe_of;
use factory_testkit::sandbox::{FakeSandbox, ProgramOutput};
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use factory_workflow::engine::{AttemptOutcome, Engine};
use factory_workflow::gates::framework::GateDecision;
use factory_workflow::gates::spec::{Limits, profile::ProfileRules};
use factory_workflow::handlers::{
    ContractContext, GateContext, HandlerRegistry, NamedArtifact, RunIdentity, StageContext,
    StageError, StageHandler, StageOutput,
};
use factory_workflow::scheduler::ClaimedAttempt;
use factory_workflow::stages::implementation::{CommitIdentity, StageBudget};
use factory_workflow::stages::intake::common::{
    ContractBudget, ContractCriterion, ContractDeliverable, ContractInput, ContractSpec, Executor,
    GateDefinition, GateFacts, GateSubject, gate_report, stage_contract,
};
use factory_workflow::stages::intake::{AgentOutputCheck, CapabilityProbes};
use factory_workflow::stages::specification::{
    ApprovalRecord, DraftRecord, PreviousSpec, ReworkContext, ReworkSource, SeamError,
    SpecApprovals, SpecDrafts, SpecHistory, SpecificationConfig, SpecificationDeps,
    SpecificationHandler, WorkspaceAccess, WorkspaceAgentSpecs,
};
use serde_json::{Value, json};

use crate::support::world::World;

const SECURITY_POLICY: &str = include_str!("../../../domain/tests/fixtures/policy/security.json");
const APPROVAL_POLICY: &str = include_str!("../../../domain/tests/fixtures/policy/approval.json");
pub const WRITER_MANIFEST: &str =
    include_str!("../../../../agents/specification-writer/manifest.json");
pub const WRITER_PROMPT: &str = include_str!("../../../../agents/specification-writer/prompt.md");
pub const REVIEWER_MANIFEST: &str =
    include_str!("../../../../agents/specification-reviewer/manifest.json");
pub const REVIEWER_PROMPT: &str =
    include_str!("../../../../agents/specification-reviewer/prompt.md");
pub const EXAMPLE: &str = include_str!(
    "../../../../schemas/examples/specification-contract/valid/approved-json-output-flag.json"
);

pub const CONSTITUTION: &str = ".specify/memory/constitution.md";

/// The events of one run, in the order they happened, across every port.
pub type Log = Arc<Mutex<Vec<String>>>;

pub fn note(log: &Log, text: impl Into<String>) {
    log.lock().expect("lock").push(text.into());
}

pub fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().expect("the lock is never poisoned")
}

pub fn security_policy() -> SecurityPolicy {
    serde_json::from_str(SECURITY_POLICY).expect("the security policy fixture is valid")
}

pub fn policy_engine() -> Arc<PolicyEngine> {
    let approval: ApprovalPolicy =
        serde_json::from_str(APPROVAL_POLICY).expect("the approval policy fixture is valid");
    Arc::new(PolicyEngine::new(&security_policy(), &approval).expect("the policies build"))
}

pub fn redactor() -> Arc<Redactor> {
    let policy = security_policy();
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

pub fn path(text: &str) -> RepoPath {
    RepoPath::new(text).expect("a repository path")
}

pub fn rules() -> PathRules {
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
        mode("test_fixtures", "tests/fixtures/**", PathMode::DenyWrite),
    ])
}

pub const FILLED_CONSTITUTION: &str =
    "# Constitution\n\n## Principles\n\nI. Plain English. All text is clear English.\n";

pub fn base_files(constitution: Option<&str>) -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = [
        (
            "Cargo.toml",
            "[package]\nname = \"word-count\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        ("src/main.rs", "fn main() {\n    println!(\"words\");\n}\n"),
        (".github/workflows/ci.yml", "name: ci\non: push\n"),
        ("README.md", "# Word count\n"),
    ]
    .iter()
    .map(|(p, t)| ((*p).to_owned(), (*t).to_owned()))
    .collect();
    if let Some(text) = constitution {
        files.push((CONSTITUTION.to_owned(), text.to_owned()));
    }
    files
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

// ---- the schema check, the probes and the sandbox spec seam ---------------------------------

/// A stand-in for the schema check: accepts any JSON.
pub struct StandInCheck;

impl AgentOutputCheck for StandInCheck {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    fn check(&self, _schema: &SchemaRef, bytes: &[u8]) -> Result<ValidatedOutput, Vec<Violation>> {
        let value: Value = serde_json::from_slice(bytes).map_err(|_| {
            vec![Violation {
                path: "$".to_owned(),
                message: "the bytes are not JSON".to_owned(),
            }]
        })?;
        Ok(ValidatedOutput {
            value,
            sha256: Sha256Digest::of(bytes),
            size_bytes: bytes.len() as u64,
        })
    }
}

pub struct FixedProbes;

impl CapabilityProbes for FixedProbes {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    fn probed(&self) -> ProbedCapabilities {
        let mut all = ProbedCapabilities::default();
        all.0.insert(
            RuntimeId::new("fake").expect("a runtime id"),
            probe_of(&[
                Capability::JsonSchemaOutput,
                Capability::HeadlessMultiTurn,
                Capability::SkillInvocation,
            ]),
        );
        all
    }
}

pub struct RigSpecs {
    pub dirs: Arc<Mutex<Vec<PathBuf>>>,
    pub seen: Mutex<Vec<WorkspaceAccess>>,
}

impl RigSpecs {
    pub fn new() -> Self {
        Self {
            dirs: Arc::new(Mutex::new(Vec::new())),
            seen: Mutex::new(Vec::new()),
        }
    }
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
        lock(&self.dirs).push(mounts.workspace.clone());
        spec.mounts.workspace = mounts;
        lock(&self.seen).push(access);
        Ok(spec)
    }
}

// ---- the other seams ------------------------------------------------------------------------

pub struct RigApprovals {
    granted: Mutex<Option<ApprovalRecord>>,
    for_draft: Mutex<Vec<(String, ApprovalRecord)>>,
    pub asked: Mutex<Vec<String>>,
}

impl RigApprovals {
    pub fn new() -> Self {
        Self {
            granted: Mutex::new(None),
            for_draft: Mutex::new(Vec::new()),
            asked: Mutex::new(Vec::new()),
        }
    }
    /// Forgets every approval.
    pub fn clear(&self) {
        *lock(&self.granted) = None;
        lock(&self.for_draft).clear();
        lock(&self.asked).clear();
    }
    /// A person approved whatever draft is there.
    pub fn grant(&self, record: ApprovalRecord) {
        *lock(&self.granted) = Some(record);
    }
    /// A person approved this draft and no other.
    pub fn grant_for(&self, draft: &Sha256Digest, record: ApprovalRecord) {
        lock(&self.for_draft).push((draft.as_str().to_owned(), record));
    }
}

#[async_trait]
impl SpecApprovals for RigApprovals {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    async fn approval(
        &self,
        _run: &RunIdentity,
        draft: &Sha256Digest,
    ) -> Result<Option<ApprovalRecord>, SeamError> {
        lock(&self.asked).push(draft.as_str().to_owned());
        if let Some((_, record)) = lock(&self.for_draft)
            .iter()
            .find(|(sha, _)| sha == draft.as_str())
        {
            return Ok(Some(record.clone()));
        }
        Ok(lock(&self.granted).clone())
    }
}

pub struct RigDrafts {
    kept: Mutex<HashMap<StageRunId, DraftRecord>>,
}

impl RigDrafts {
    pub fn new() -> Self {
        Self {
            kept: Mutex::new(HashMap::new()),
        }
    }
    pub fn kept(&self, run: StageRunId) -> Option<DraftRecord> {
        lock(&self.kept).get(&run).cloned()
    }
}

#[async_trait]
impl SpecDrafts for RigDrafts {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }
    async fn save(&self, run: &RunIdentity, record: DraftRecord) -> Result<(), SeamError> {
        lock(&self.kept).insert(run.stage_run, record);
        Ok(())
    }
    async fn load(&self, run: &RunIdentity) -> Result<Option<DraftRecord>, SeamError> {
        Ok(lock(&self.kept).get(&run.stage_run).cloned())
    }
}

pub struct RigHistory {
    previous: Mutex<Option<PreviousSpec>>,
}

impl RigHistory {
    pub fn new() -> Self {
        Self {
            previous: Mutex::new(None),
        }
    }
    pub fn set(&self, previous: PreviousSpec) {
        *lock(&self.previous) = Some(previous);
    }
}

#[async_trait]
impl SpecHistory for RigHistory {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    async fn previous(&self, _run: &RunIdentity) -> Result<Option<PreviousSpec>, SeamError> {
        Ok(lock(&self.previous).clone())
    }
}

/// Stands for the composition root's feedback source. A test sets what the store would hold for
/// the next run: the commit of the draft that was sent back and the reports that failed.
pub struct RigRework {
    context: Mutex<Option<ReworkContext>>,
}

impl RigRework {
    pub fn new() -> Self {
        Self {
            context: Mutex::new(None),
        }
    }

    pub fn set(&self, context: ReworkContext) {
        *lock(&self.context) = Some(context);
    }
}

#[async_trait]
impl ReworkSource for RigRework {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    async fn of(&self, _run: &RunIdentity) -> Result<Option<ReworkContext>, SeamError> {
        Ok(lock(&self.context).clone())
    }
}

/// What the stage wrote into the sandbox with `tee`: the path and the bytes, in order.
pub type Written = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

// ---- the scripted specification provider ----------------------------------------------------

/// Stands for the Spec Kit provider. `run` drives FX-ADV through the sandbox it is given, and
/// `assemble` builds a contract from the exact bytes of the committed files.
pub struct ScriptedProvider {
    pub log: Log,
    pub artifacts: Arc<Granting>,
    pub requests: Mutex<Vec<SpecRequest>>,
    /// Transcripts to attach to the next skill runs, oldest first.
    pub transcripts: Mutex<VecDeque<Vec<u8>>>,
    /// Invocations to report with the next skill runs, oldest first. With none queued the run
    /// reports no invocation, as a fake that runs no skill does.
    pub invocations: Mutex<VecDeque<SkillInvocation>>,
    /// Errors the next calls of `assemble` return, oldest first.
    pub assembly_errors: Mutex<VecDeque<SpecError>>,
    /// Makes `assemble` return a contract that already claims to be approved.
    pub approved_by_the_writer: Mutex<bool>,
}

impl ScriptedProvider {
    pub fn requests_of(&self, op: SpecOperation) -> Vec<SpecRequest> {
        lock(&self.requests)
            .iter()
            .filter(|r| r.op == op)
            .cloned()
            .collect()
    }
}

fn checklist_questions(dir: &str, files: &SpecFileSet) -> Vec<Value> {
    let mut names: Vec<(&RepoPath, &Vec<u8>)> = files
        .files
        .iter()
        .filter(|f| f.path.as_str().starts_with(&format!("{dir}/checklists/")))
        .map(|f| (&f.path, &f.bytes))
        .collect();
    names.sort_by_key(|(p, _)| {
        (
            !p.as_str().ends_with("/requirements.md"),
            p.as_str().to_owned(),
        )
    });
    let mut out = Vec::new();
    let mut number = 100;
    for (file, bytes) in names {
        let base = file.as_str().rsplit('/').next().unwrap_or("").to_owned();
        for (index, line) in String::from_utf8_lossy(bytes).lines().enumerate() {
            let Some(item) = line
                .strip_prefix("- [ ] ")
                .or_else(|| line.strip_prefix("- [x] "))
            else {
                continue;
            };
            let (label, text) = match item.split_once(' ') {
                Some((first, rest)) if first.starts_with("CHK") => {
                    (first.to_owned(), rest.to_owned())
                }
                _ => (format!("on line {}", index + 1), item.to_owned()),
            };
            number += 1;
            out.push(json!({
                "id": format!("Q-{number}"),
                "question": format!("Checklist item {label} of {base}: {text}"),
                "blocking": true,
                "status": "open",
            }));
        }
    }
    out
}

#[async_trait]
impl SpecificationProvider for ScriptedProvider {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn run(
        &self,
        req: &SpecRequest,
        ctx: &mut SpecContext<'_>,
    ) -> Result<SpecRunReport, SpecError> {
        note(&self.log, format!("provider.run:{:?}", req.op));
        lock(&self.requests).push(req.clone());
        let mut template = ctx.run_template.clone();
        template.prompt = AssembledPrompt {
            instructions: format!(
                "RIG {:?} {} {}",
                req.op,
                req.feature_directory.as_str(),
                req.request_file.as_str()
            ),
            data: Vec::new(),
        };
        let report = ctx
            .runtime
            .run(&mut *ctx.session, template, ctx.cancel)
            .await;
        if let Err(error) = &report.outcome {
            return Err(SpecError::Runtime(error.clone()));
        }
        let queued = lock(&self.transcripts).pop_front();
        let transcript = match queued {
            Some(bytes) => Some(
                self.artifacts
                    .put(bytes, MediaType::parse("text/plain").expect("a media type"))
                    .await
                    .expect("the transcript is stored"),
            ),
            None => report.transcript.clone(),
        };
        let dir = req.feature_directory.as_str();
        let expected = [
            format!("{dir}/spec.md"),
            format!("{dir}/checklists/requirements.md"),
            format!("{dir}/checklists/requirements-quality.md"),
        ]
        .iter()
        .map(|p| path(p))
        .collect();
        Ok(SpecRunReport {
            op: req.op,
            feature_directory: req.feature_directory.clone(),
            expected_files: expected,
            skill_runs: vec![SkillRun {
                transcript,
                usage: report.usage,
                permission_denials: report.permission_denials,
                invocation: lock(&self.invocations).pop_front(),
            }],
        })
    }

    fn assemble(&self, req: &SpecRequest, files: &SpecFileSet) -> Result<SpecOutcome, SpecError> {
        note(&self.log, format!("provider.assemble:{:?}", req.op));
        if let Some(error) = lock(&self.assembly_errors).pop_front() {
            return Err(error);
        }
        let dir = req.feature_directory.as_str();
        let spec_path = path(&format!("{dir}/spec.md"));
        let Some(spec) = files.files.iter().find(|f| f.path == spec_path) else {
            return Err(SpecError::ParseError {
                path: spec_path,
                reason: ParseReason::Missing,
            });
        };
        let text = std::str::from_utf8(&spec.bytes).map_err(|_| SpecError::ParseError {
            path: spec_path.clone(),
            reason: ParseReason::NotText,
        })?;
        if let Some(at) = text.find("[NEEDS CLARIFICATION:") {
            let question = text[at + "[NEEDS CLARIFICATION:".len()..]
                .split(']')
                .next()
                .unwrap_or("")
                .trim()
                .to_owned();
            let open: OpenQuestion = serde_json::from_value(json!({
                "id": "Q-001",
                "question": question,
                "blocking": true,
                "status": "open",
                "source_marker": "NEEDS CLARIFICATION",
            }))
            .expect("a valid question");
            return Ok(SpecOutcome::NeedsHuman(vec![open]));
        }
        let mut value: Value = serde_json::from_str(EXAMPLE).expect("the example is JSON");
        let meta = value["metadata"].as_object_mut().expect("an object");
        meta.remove("approved_at");
        meta.remove("approved_by");
        meta.insert("status".to_owned(), json!("draft"));
        meta.insert("execution_mode".to_owned(), json!("test"));
        meta.insert("job_id".to_owned(), json!(req.job.to_string()));
        meta.insert("commit_sha".to_owned(), json!(files.commit.as_str()));
        value["provenance"]["host_runtime"]["fidelity"] = json!("fake");
        value["provenance"]["feature_directory"] = json!(dir);
        let mut artifacts: Vec<&factory_ports::spec::SpecFile> = files
            .files
            .iter()
            .filter(|f| f.path.as_str().starts_with(&format!("{dir}/")))
            .collect();
        artifacts.sort_by_key(|f| {
            (
                !f.path.as_str().ends_with("/spec.md"),
                !f.path.as_str().ends_with("/requirements.md"),
                f.path.as_str().to_owned(),
            )
        });
        value["provenance"]["artifacts"] = Value::Array(
            artifacts
                .iter()
                .map(|f| {
                    let role = if f.path.as_str().ends_with("/spec.md") {
                        "specification"
                    } else if f.path.as_str().ends_with("/requirements.md") {
                        "requirements_checklist"
                    } else {
                        "custom_checklist"
                    };
                    json!({
                        "role": role,
                        "path": f.path.as_str(),
                        "sha256": Sha256Digest::of(&f.bytes).as_str(),
                    })
                })
                .collect(),
        );
        value["open_questions"] = Value::Array(checklist_questions(dir, files));
        if req.revision.is_some() {
            value["metadata"]["spec_version"] = json!(2);
            value["metadata"]["supersedes_spec_version"] = json!(1);
            value["provenance"]["revision"] =
                json!({"method": "new_feature_directory", "basis_spec_version": 1});
        } else {
            value["metadata"]
                .as_object_mut()
                .expect("object")
                .remove("supersedes_spec_version");
            value["provenance"]
                .as_object_mut()
                .expect("object")
                .remove("revision");
        }
        if *lock(&self.approved_by_the_writer) {
            value["metadata"]["status"] = json!("approved");
            value["metadata"]["approved_at"] = json!("2026-10-27T08:58:30Z");
            value["metadata"]["approved_by"] = json!({
                "principal_id": "018f3a00-0000-7000-8000-00000000a001",
                "role": "approver",
                "basis": "human_decision",
            });
            value["open_questions"] = json!([]);
        }
        let contract = SpecificationContract::from_json_value(value).expect("a valid draft");
        Ok(SpecOutcome::Draft(Box::new(SpecificationDraft {
            contract,
            files: Vec::new(),
        })))
    }
}

// ---- the stand-ins around the stage ----------------------------------------------------------

const STANDIN_GATE: &str = "standin-gate";
const STANDIN_TEXT: &str = "standin-gate 1.0.0: a stand-in stage stored its deliverables.";

pub fn definition_commit() -> GitSha {
    GitSha::parse("1405df66cbe219b0bf6355bc3d60361a8376b6b4").expect("a commit")
}

/// Stores fixed deliverables.
pub struct Fixed {
    kind: StageKind,
    contract_id: &'static str,
    span: &'static str,
    deliverables: Vec<(&'static str, Vec<u8>)>,
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
        stage_contract(&ContractSpec {
            kind: ctx.identity.kind,
            job: ctx.identity.job,
            stage_run: ctx.identity.stage_run,
            mode: ctx.mode,
            created_at: ctx.now,
            contract_id: self.contract_id,
            title: "Stand in for a stage in a test",
            purpose: "Store the deliverables that the real stage would store, so that a stage under test has its inputs.",
            problem: "The stage under test reads what the stages before it produced, and those stages are not under test here.",
            inputs: vec![ContractInput {
                name: "policy-bundle",
                description: "The hash of the policy bundle in force.",
                sha256: ctx.policy_hash.clone(),
                media_type: "application/json",
                source: "policy",
                produced_by: None,
                commit_sha: None,
                retrieved_at: ctx.now,
                trust: "trusted_internal",
            }],
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
            placement: None,
            deliverables: self
                .deliverables
                .iter()
                .map(|(name, _)| ContractDeliverable {
                    name,
                    description: "A fixed document.",
                    media_type: "application/json",
                    required: true,
                })
                .collect(),
            criteria: vec![ContractCriterion {
                id: "standin-criterion",
                description: "The stand-in stored its deliverables.",
                gate: STANDIN_GATE,
            }],
            gates: vec![STANDIN_GATE],
            budget: ContractBudget {
                wall_time_seconds: 300,
                max_tokens: 0,
                max_cost_usd: 0.0,
                attempt_timeout_seconds: 240,
                max_attempts: 1,
            },
            rollback: "Nothing outside the test is changed.",
            span_name: self.span,
        })
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
    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        let now = ctx.ports.clock.now();
        let report = gate_report(
            &GateSubject {
                job: ctx.identity.job,
                stage_run: ctx.identity.stage_run,
                attempt: ctx.attempt,
                mode: ctx.mode,
                report_id: GateReportId::from_uuid(ctx.ports.ids.new_uuid()),
                started_at: now,
                finished_at: ctx.ports.clock.now(),
            },
            &GateFacts {
                definition: GateDefinition {
                    id: STANDIN_GATE,
                    version: "1.0.0",
                    text: STANDIN_TEXT,
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
                evidence: vec!["standin-gate=PASSED".to_owned()],
            },
        )?;
        Ok(GateDecision {
            reports: vec![report],
            ..GateDecision::default()
        })
    }
}

// ---- the runtime ---------------------------------------------------------------------------

type Edits = VecDeque<(String, Vec<TreeEdit>)>;

/// The scripted adversarial runtime with one addition: before a run returns it changes the
/// writable tree of the workspace the sandbox was made over, which is what the file tools of the
/// agent would have done.
pub struct Runtime {
    pub inner: FakeAgentRuntime,
    workspaces: Arc<FakeWorkspaceProvider>,
    dirs: Arc<Mutex<Vec<PathBuf>>>,
    edits: Mutex<Edits>,
    log: Log,
}

impl Runtime {
    pub fn edits(&self, agent: &str, edits: Vec<TreeEdit>) {
        lock(&self.edits).push_back((agent.to_owned(), edits));
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
        let edits = {
            let mut queue = lock(&self.edits);
            match queue.front() {
                Some((who, _)) if *who == agent => queue.pop_front().map(|(_, e)| e),
                _ => None,
            }
        };
        if let (Some(edits), Some(dir)) = (edits, lock(&self.dirs).last().cloned()) {
            for edit in edits {
                self.workspaces
                    .edit_tree(&dir, edit)
                    .expect("the workspace of the sandbox has a tree");
            }
        }
        self.inner.run(session, req, cancel).await
    }
}

// ---- the rig -------------------------------------------------------------------------------

pub struct Rig {
    pub world: World,
    pub engine: Engine,
    pub log: Log,
    pub runtime: Arc<Runtime>,
    pub provider: Arc<ScriptedProvider>,
    pub workspaces: Arc<FakeWorkspaceProvider>,
    pub specs: Arc<RigSpecs>,
    pub approvals: Arc<RigApprovals>,
    pub drafts: Arc<RigDrafts>,
    pub history: Arc<RigHistory>,
    pub rework: Arc<RigRework>,
    /// The files the stage put into the sandbox for the skills to read.
    pub written: Written,
    pub artifacts: Arc<Granting>,
    pub repo: RepoRef,
    pub base: CommitSha,
    pub job: JobId,
    /// The title the intake stand-in (or the real request) gives the job.
    pub title: String,
}

pub struct Options {
    pub description: String,
    pub constitution: Option<String>,
    pub human_approval_required: bool,
    pub policy_principal: Option<PrincipalId>,
    pub scope: Vec<StageKind>,
    pub max_rounds: usize,
    /// The bytes the intake stand-in stores as `normalized-request`, when a test wants the
    /// document of the real intake stage instead of the stand-in's own.
    pub request: Option<Vec<u8>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            description: "Users want the word count tool to print its counts as one JSON object."
                .to_owned(),
            constitution: Some(FILLED_CONSTITUTION.to_owned()),
            human_approval_required: true,
            policy_principal: None,
            scope: vec![
                StageKind::Intake,
                StageKind::RepositoryIntelligence,
                StageKind::Specification,
                StageKind::DomainDiscovery,
                StageKind::Architecture,
            ],
            max_rounds: 2,
            request: None,
        }
    }
}

pub fn writer_manifest() -> AgentManifest {
    serde_json::from_str(WRITER_MANIFEST).expect("the real manifest is valid")
}

pub fn reviewer_manifest() -> AgentManifest {
    serde_json::from_str(REVIEWER_MANIFEST).expect("the real manifest is valid")
}

pub fn person_record(principal: PrincipalId) -> ApprovalRecord {
    ApprovalRecord {
        principal,
        role: SpecApproverRole::Approver,
        basis: ApprovalBasis::HumanDecision,
        at: factory_domain::values::Timestamp::parse("2026-10-27T09:00:00Z").expect("a time"),
    }
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
            InMemoryArtifactStore::new().indexed_by((*world.memory_store()).clone()),
            world.tenant,
        ));
        let repo = RepoRef::parse("example-org/fixture").expect("a repository");
        let remote = FakeRemote::new();
        let branch = BranchName::new("main").expect("a branch");
        let files = base_files(options.constitution.as_deref());
        let pairs: Vec<(&str, &str)> = files
            .iter()
            .map(|(p, c)| (p.as_str(), c.as_str()))
            .collect();
        remote.commit_on_branch(&repo, &branch, &pairs);
        let workspaces = Arc::new(FakeWorkspaceProvider::new(
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
        let fetched = workspaces
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

        let written: Written = Arc::new(Mutex::new(Vec::new()));
        let tee_log = written.clone();
        let sandbox = Arc::new(
            FakeSandbox::new(world.clock.clone(), artifacts.clone(), sandbox_policy())
                .with_program("mkdir", ok)
                .with_program("tee", move |argv, stdin| {
                    let file = argv.last().cloned().unwrap_or_default();
                    lock(&tee_log).push((file, stdin.to_vec()));
                    ok(argv, stdin)
                })
                .with_program("rm", ok)
                .with_program("cp", ok),
        );
        let specs = Arc::new(RigSpecs::new());
        let runtime = Arc::new(Runtime {
            inner: FakeAgentRuntime::new(artifacts.clone()),
            workspaces: workspaces.clone(),
            dirs: specs.dirs.clone(),
            edits: Mutex::new(VecDeque::new()),
            log: log.clone(),
        });
        let mut registry = InMemoryAgentRegistry::new();
        registry.add(writer_manifest(), Some(WRITER_PROMPT));
        registry.add(reviewer_manifest(), Some(REVIEWER_PROMPT));

        let mut deps = world.deps.clone();
        deps.artifacts = artifacts.clone();
        deps.sandbox = sandbox;
        deps.workspaces = workspaces.clone();
        deps.runtime = runtime.clone();
        deps.registry = Arc::new(registry);

        let provider = Arc::new(ScriptedProvider {
            log: log.clone(),
            artifacts: artifacts.clone(),
            requests: Mutex::new(Vec::new()),
            transcripts: Mutex::new(VecDeque::new()),
            invocations: Mutex::new(VecDeque::new()),
            assembly_errors: Mutex::new(VecDeque::new()),
            approved_by_the_writer: Mutex::new(false),
        });
        let approvals = Arc::new(RigApprovals::new());
        let drafts = Arc::new(RigDrafts::new());
        let history = Arc::new(RigHistory::new());
        let rework = Arc::new(RigRework::new());
        let handler = SpecificationHandler::new(
            SpecificationConfig {
                writer: Slug::parse("specification-writer").expect("a slug"),
                reviewer: Slug::parse("specification-reviewer").expect("a slug"),
                definition_commit: definition_commit(),
                broker: BrokerEndpoint {
                    base_url: Uri::parse("https://model-broker.sandbox.internal:8443")
                        .expect("a URI"),
                },
                max_output_bytes: 524_288,
                path_rules: rules(),
                identity: CommitIdentity {
                    name: "Factory".to_owned(),
                    email: "factory@example.invalid".to_owned(),
                },
                constitution_path: path(CONSTITUTION),
                probe_globs: vec![
                    RepoGlob::new(".specify/extensions.yml").expect("a glob"),
                    RepoGlob::new("specs/*/plan.md").expect("a glob"),
                ],
                limits: Limits::default(),
                max_file_bytes: 1_048_576,
                max_clarification_rounds: options.max_rounds,
                human_approval_required: options.human_approval_required,
                policy_principal: options.policy_principal,
                budget: StageBudget {
                    wall_time_seconds: 3_600,
                    max_tokens: 2_000_000,
                    max_cost_usd: 10.0,
                    attempt_timeout_seconds: 3_600,
                    max_attempts: 3,
                },
            },
            SpecificationDeps {
                provider: provider.clone(),
                policy: policy_engine(),
                redactor: redactor(),
                profile: Arc::new(
                    ProfileRules::from_policy(&security_policy(), "SPECIFICATION")
                        .expect("the specification profile"),
                ),
                schemas: Arc::new(StandInCheck),
                specs: specs.clone(),
                probes: Arc::new(FixedProbes),
                approvals: approvals.clone(),
                drafts: drafts.clone(),
                history: history.clone(),
                rework: rework.clone(),
            },
        );
        let mut handlers = HandlerRegistry::new();
        handlers.register(Arc::new(handler)).expect("one handler");
        let title = options
            .request
            .as_deref()
            .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
            .and_then(|request| request["title"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "Add a json flag".to_owned());
        register_around(
            &mut handlers,
            &base,
            &options.description,
            options.request.clone(),
        );
        let engine = Engine::new(deps, world.config.clone(), handlers).expect("the engine starts");
        Self {
            world,
            engine,
            log,
            runtime,
            provider,
            workspaces,
            specs,
            approvals,
            drafts,
            history,
            rework,
            written,
            artifacts,
            repo,
            base,
            job,
            title,
        }
    }

    pub async fn admit(&self) {
        self.engine
            .admit_job(self.world.tenant, self.job)
            .await
            .expect("admit");
    }

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

    /// Runs the intake and repository stand-ins.
    pub async fn run_until_specification(&self) {
        self.admit().await;
        for kind in [StageKind::Intake, StageKind::RepositoryIntelligence] {
            let (claimed, outcome) = self.run_next().await;
            assert_eq!(claimed.kind, kind);
            assert_eq!(outcome, AttemptOutcome::Succeeded, "{kind:?}");
        }
    }

    /// The writer will write these files in its next skill run.
    pub fn writer_writes(&self, edits: Vec<TreeEdit>) {
        self.runtime.edits("specification-writer", edits);
        self.runtime
            .inner
            .queue(AdversarialScript::returning(json!({
                "schema_version": 1,
                "status": "DONE",
                "ignored_instructions": [],
            })));
    }

    /// The writer will write these files, and the run will behave like this script.
    pub fn writer_runs(&self, edits: Vec<TreeEdit>, script: AdversarialScript) {
        self.runtime.edits("specification-writer", edits);
        self.runtime.inner.queue(script);
    }

    /// The reviewer will answer this.
    pub fn reviewer_answers(&self, answer: Value) {
        self.runtime
            .inner
            .queue(AdversarialScript::returning(answer));
    }

    /// The directory the factory chose for the job's specification.
    pub fn feature(&self) -> String {
        let tail = self.job.to_string();
        format!(
            "specs/{}-{}",
            short_name(&self.title),
            &tail[tail.len() - 8..]
        )
    }

    /// The next skill run reports that it invoked `skill` with `arguments`, and its transcript
    /// shows the invocation the host replayed with `shown` as the arguments (Claude Code 2.1.325
    /// with `--replay-user-messages`).
    pub fn skill_invoked(&self, skill: &str, arguments: &str, shown: &str) {
        let replay = json!({
            "type": "user",
            "isReplay": true,
            "message": {"role": "user", "content": format!(
                "<command-message>{skill}</command-message>\n<command-name>/{skill}</command-name>\n<command-args>{shown}</command-args>"
            )},
        });
        lock(&self.provider.invocations).push_back(SkillInvocation {
            skill: skill.to_owned(),
            arguments: arguments.to_owned(),
        });
        lock(&self.provider.transcripts).push_back(format!("{replay}\n").into_bytes());
    }

    /// A writer that writes a sound specification, a checklist, and a reviewer that passes.
    pub fn a_sound_specification(&self) {
        let dir = self.feature();
        self.writer_writes(vec![
            write(&format!("{dir}/spec.md"), SPEC_TEXT),
            write(
                &format!("{dir}/checklists/requirements.md"),
                REQUIREMENTS_MD,
            ),
        ]);
        self.writer_writes(vec![write(
            &format!("{dir}/checklists/requirements-quality.md"),
            QUALITY_MD,
        )]);
        self.reviewer_answers(pass());
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

    pub async fn run_of(&self, kind: StageKind) -> StageRunId {
        self.world
            .view(self.job)
            .await
            .newest(kind)
            .expect("a run of that kind")
            .id
    }

    /// The deliverable `name` of the newest run of `kind` that has one, read back from the store.
    pub async fn deliverable(&self, kind: StageKind, name: &str) -> Option<Value> {
        let runs: Vec<StageRunId> = self
            .world
            .view(self.job)
            .await
            .runs_of(kind)
            .map(|run| run.id)
            .collect();
        for run in runs.into_iter().rev() {
            if let Some(found) = self.deliverable_in(run, name).await {
                return Some(found);
            }
        }
        None
    }

    pub async fn deliverable_in(&self, run: StageRunId, name: &str) -> Option<Value> {
        let tenant = TenantScope::new(self.world.tenant);
        for link in self.world.links(run).await {
            let reference = ArtifactRef {
                sha256: link.sha256.clone(),
                media_type: MediaType::parse("application/json").expect("a media type"),
                size_bytes: None,
            };
            if let Ok(bytes) = ArtifactStore::get(&*self.artifacts, &tenant, &reference).await
                && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
            {
                let is_contract =
                    name == "specification-contract" && value.get("requirements").is_some();
                let is_named = value.get("kind").and_then(Value::as_str) == Some(name);
                if is_contract || is_named {
                    return Some(value);
                }
            }
        }
        None
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

    /// The gate reports of one gate, newest last.
    pub async fn reports_of(&self, gate: &str) -> Vec<Value> {
        self.gate_reports()
            .await
            .into_iter()
            .filter(|r| r.pointer("/metadata/gate_id").and_then(Value::as_str) == Some(gate))
            .collect()
    }
}

fn ok(_: &[String], _: &[u8]) -> ProgramOutput {
    ProgramOutput {
        exit_code: Some(0),
        ..ProgramOutput::default()
    }
}

fn register_around(
    handlers: &mut HandlerRegistry,
    base: &CommitSha,
    description: &str,
    real_request: Option<Vec<u8>>,
) {
    let map = serde_json::to_vec(&json!({ "commit_sha": base.as_str() })).expect("serializes");
    let request = real_request.unwrap_or_else(|| {
        serde_json::to_vec(&json!({
            "title": "Add a json flag",
            "description": description,
        }))
        .expect("serializes")
    });
    let table = vec![
        Fixed {
            kind: StageKind::Intake,
            contract_id: "stage-contract.intake",
            span: "stage.intake",
            deliverables: vec![("normalized-request", request)],
        },
        Fixed {
            kind: StageKind::RepositoryIntelligence,
            contract_id: "stage-contract.repository-intelligence",
            span: "stage.repository_intelligence",
            deliverables: vec![("repository-map", map)],
        },
        Fixed {
            kind: StageKind::Architecture,
            contract_id: "stage-contract.architecture",
            span: "stage.architecture",
            deliverables: vec![(
                "architecture-design",
                b"{\"title\":\"A small design.\"}".to_vec(),
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
    ];
    for stand_in in table {
        handlers.register(Arc::new(stand_in)).expect("one handler");
    }
}

/// The lower-case letters and digits of a title, joined by hyphens, at most 40 characters: how the
/// stage names the feature directory.
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

pub fn write(path_text: &str, text: &str) -> TreeEdit {
    TreeEdit::Write(path(path_text), text.as_bytes().to_vec())
}

pub const SPEC_TEXT: &str = "# Feature Specification: Add a json flag\n\nA recorded stand-in for the text of a specification.\n";
pub const REQUIREMENTS_MD: &str = "# Specification Quality Checklist\n\n- [x] No implementation details\n- [x] Requirements are testable\n";
pub const QUALITY_MD: &str = "# Requirements Quality Checklist\n\n- [ ] CHK001 Is every requirement testable? [Clarity]\n- [ ] CHK002 Is the scope boundary stated? [Gap]\n";

/// A reviewer's answer that passes the specification.
pub fn pass() -> Value {
    json!({
        "schema_version": 1,
        "verdict": "PASS",
        "title": "Specification review",
        "summary": "No finding of medium severity or higher was found.",
        "findings": [],
        "confidence_overall": 0.85,
        "residual_risks": [],
        "ignored_instructions": [],
    })
}

/// A reviewer's answer that asks for changes and names an item of the checklist.
pub fn changes_required(item: &str) -> Value {
    json!({
        "schema_version": 1,
        "verdict": "CHANGES_REQUIRED",
        "title": "Specification review",
        "summary": "One finding must be fixed.",
        "findings": [{
            "finding_id": "unclear-requirement",
            "severity": "high",
            "category": "intent_alignment",
            "title": format!("The point of {item} is not met"),
            "description": format!("The text does not satisfy {item}, so the requirement cannot be tested."),
            "confidence": 0.8,
            "proposed_next_action": "clarify_specification",
            "defect_class": "specification",
        }],
        "confidence_overall": 0.8,
        "residual_risks": [],
        "ignored_instructions": [],
    })
}
