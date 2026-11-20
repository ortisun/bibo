//! The rig: a test engine over the labelled fakes, with the real implementation handler (and the
//! real review handler) registered, stand-ins for the stages around them, and spies that record
//! what happened in what order.
//!
//! The helpers are shared by the tests of both stages, so a test file does not use every one of
//! them.
#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::contracts::{AgentManifest, ArtifactRef, SchemaRef, Violation};
use factory_domain::ids::{AttemptId, JobId, StageRunId, TenantId};
use factory_domain::policy::{ApprovalPolicy, PolicyEngine, SecurityPolicy};
use factory_domain::redaction::{PatternAction, PatternSpec, Redactor};
use factory_domain::scope::TenantScope;
use factory_domain::state::TaskNodeStatus;
use factory_domain::values::{GitSha, MediaType, Sha256Digest, Slug, Uri};
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::agent::{
    AgentRunReport, AgentRuntime, BrokerEndpoint, JobTokenRef, ModelRouter, ProbeError,
    ProbedCapabilities, RoutingDecision, RoutingError, RoutingNeed, RuntimeCapabilities, RuntimeId,
};
use factory_ports::artifact::{ArtifactBackend, ArtifactError, ArtifactStore};
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{
    BranchName, CommitSha, PathMode, PathRule, PathRules, RepoGlob, RepoPath, RepoRef,
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
use factory_testkit::contracts::workspace::TreeEdit;
use factory_testkit::fixtures::{Ids, sandbox_policy, sandbox_spec};
use factory_testkit::registry::InMemoryAgentRegistry;
use factory_testkit::router::probed;
use factory_testkit::sandbox::FakeSandbox;
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use factory_workflow::engine::{AttemptOutcome, Engine};
use factory_workflow::handlers::{HandlerRegistry, RunIdentity};
use factory_workflow::scheduler::ClaimedAttempt;
use factory_workflow::stages::implementation::{
    CommitIdentity, Hold, ImplementationConfig, ImplementationDeps, ImplementationHandler,
    LedgerError, PlannedTask, ReworkContext, ReworkSource, SeamError, StageBudget, TaskLedger,
    TaskRecord, WorkspaceAccess, WorkspaceAgentSpecs,
};
use factory_workflow::stages::intake::{AgentOutputCheck, CapabilityProbes};
use serde_json::{Value, json};

use crate::support::world::World;

const SECURITY_POLICY: &str = include_str!("../../../domain/tests/fixtures/policy/security.json");
const APPROVAL_POLICY: &str = include_str!("../../../domain/tests/fixtures/policy/approval.json");
pub const BUILDER_MANIFEST: &str = include_str!("../../../../agents/builder/manifest.json");
pub const BUILDER_PROMPT: &str = include_str!("../../../../agents/builder/prompt.md");
pub const REVIEWER_MANIFEST: &str = include_str!("../../../../agents/code-reviewer/manifest.json");
pub const REVIEWER_PROMPT: &str = include_str!("../../../../agents/code-reviewer/prompt.md");
pub const PLAN: &str =
    include_str!("../../../../schemas/examples/task-dag/valid/json-output-flag-plan.json");
pub const SPECIFICATION: &str = include_str!(
    "../../../../schemas/examples/specification-contract/valid/approved-json-output-flag.json"
);

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

/// The path rules of the fixture repository: secret-bearing files are hidden; CI, the factory's
/// own directory and the test fixtures are protected; test code may only be added to.
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
        mode("ci", "scripts/ci/**", PathMode::DenyWrite),
        mode("factory", ".factory/**", PathMode::DenyWrite),
        mode("test_fixtures", "tests/fixtures/**", PathMode::DenyWrite),
        mode("test_code", "tests/**", PathMode::AdditionsOnly),
    ])
}

/// The files of the base commit.
pub fn base_files() -> Vec<(String, String)> {
    [
        ("Cargo.toml", "[package]\nname = \"word-count\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
        ("src/main.rs", "fn main() {\n    println!(\"words\");\n}\n"),
        ("src/lib.rs", "pub fn count(text: &str) -> usize {\n    text.split_whitespace().count()\n}\n"),
        ("tests/it.rs", "use word_count::count;\n\n#[test]\nfn counts_a_line() {\n    assert_eq!(count(\"one two\"), 2);\n}\n\n#[test]\nfn counts_one_word() {\n    assert_eq!(count(\"one\"), 1);\n}\n"),
        ("tests/fixtures/sample.txt", "one two three\n"),
        (".github/workflows/ci.yml", "name: ci\non: push\n"),
        ("scripts/ci/run.sh", "#!/bin/sh\ncargo test\n"),
        (".factory/project.json", "{}\n"),
        ("README.md", "# Word count\n"),
    ]
    .iter()
    .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
    .collect()
}

// ---- artifacts the tenant can read ---------------------------------------------------------

/// Wraps an artifact store so that whatever is stored is readable by the test tenant. This is what
/// the composition root must provide in production, where the store reads only a hash the tenant
/// has indexed: the stage reads the patch the workspace stored in the same attempt.
pub struct Granting {
    inner: InMemoryArtifactStore,
    tenant: TenantId,
    /// The next `get` fails, as a store that dropped the connection would.
    fail_next_get: std::sync::atomic::AtomicBool,
}

impl Granting {
    pub fn new(inner: InMemoryArtifactStore, tenant: TenantId) -> Self {
        Self {
            inner,
            tenant,
            fail_next_get: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Makes the next read fail.
    pub fn fail_next_get(&self) {
        self.fail_next_get
            .store(true, std::sync::atomic::Ordering::SeqCst);
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
        if self
            .fail_next_get
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ArtifactError::Io(
                factory_ports::artifact::BackendStep::Read,
            ));
        }
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

/// How the stand-in for the schema check behaves.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CheckMode {
    /// Accepts any document that is JSON, so the stage's own second defence is the only one.
    Permissive,
    /// Refuses every document, as the real check does for one that breaks the schema.
    Refusing,
}

/// A stand-in for `AgentSchema::validate_bytes`. The real one lives in `factory-contracts`, which
/// this crate cannot depend on; its behavior is proved by `tests/agent_output_schemas.rs` there.
pub struct StandInCheck {
    mode: Mutex<CheckMode>,
    asked: Mutex<Vec<SchemaRef>>,
}

impl StandInCheck {
    pub fn new() -> Self {
        Self {
            mode: Mutex::new(CheckMode::Permissive),
            asked: Mutex::new(Vec::new()),
        }
    }
    pub fn set(&self, mode: CheckMode) {
        *lock(&self.mode) = mode;
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
        if *lock(&self.mode) == CheckMode::Refusing {
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
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    fn probed(&self) -> ProbedCapabilities {
        probed(&["fake"])
    }
}

// ---- the sandbox spec seam -----------------------------------------------------------------

/// Builds the `agent` spec over the mounts it is given, and remembers which directory the last
/// workspace had, so that the runtime stand-in can edit the right tree.
pub struct RigSpecs {
    pub dirs: Arc<Mutex<Vec<PathBuf>>>,
    /// What each spec asked for: the profile and whether the checkout was writable.
    pub seen: Mutex<Vec<(SandboxProfile, bool, WorkspaceAccess)>>,
    /// Makes the next specs name another profile.
    pub profile: Mutex<Option<SandboxProfile>>,
    /// Makes the next specs mount the checkout with this read-only flag, whatever was asked. The
    /// agent profile takes a writable checkout only, so `Some(true)` is a spec the port refuses.
    pub read_only: Mutex<Option<bool>>,
    /// Makes the next specs mount another workspace than the one the stage made.
    pub other_workspace: Mutex<bool>,
}

impl RigSpecs {
    pub fn new() -> Self {
        Self {
            dirs: Arc::new(Mutex::new(Vec::new())),
            seen: Mutex::new(Vec::new()),
            profile: Mutex::new(None),
            read_only: Mutex::new(None),
            other_workspace: Mutex::new(false),
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
        let profile = lock(&self.profile).unwrap_or(SandboxProfile::Agent);
        let mut spec = sandbox_spec(&Ids::new(), profile);
        // A spec for another profile still carries the job token, so that the profile is the only
        // thing about it that is wrong.
        spec.job_token = sandbox_spec(&Ids::new(), SandboxProfile::Agent).job_token;
        spec.job = job;
        spec.attempt = attempt;
        lock(&self.dirs).push(mounts.workspace.clone());
        spec.mounts.workspace = mounts;
        if let Some(flag) = *lock(&self.read_only) {
            spec.mounts.workspace.workspace_read_only = flag;
        }
        if *lock(&self.other_workspace) {
            spec.mounts.workspace.workspace = PathBuf::from("/somewhere/else");
        }
        lock(&self.seen).push((profile, spec.mounts.workspace.workspace_read_only, access));
        Ok(spec)
    }
}

// ---- the task ledger -----------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Node {
    key: Slug,
    depends_on: Vec<Slug>,
    status: TaskNodeStatus,
    commit: Option<CommitSha>,
}

/// The durable state of the tasks, in memory. It keeps the rules of the task machine that matter
/// to the stage: a task starts only when everything it depends on `SUCCEEDED`, a write needs the
/// current epoch, and a task that was left `RUNNING` by a dead attempt can be taken again.
pub struct RigLedger {
    nodes: Mutex<BTreeMap<StageRunId, Vec<Node>>>,
    /// The highest epoch seen, and the epoch at or below which every write is refused.
    fence: Mutex<(u64, u64)>,
    log: Log,
    /// The next call of `fail` does nothing, as when a process dies before it can write.
    skip_fail: Mutex<bool>,
}

impl RigLedger {
    pub fn new(log: Log) -> Self {
        Self {
            nodes: Mutex::new(BTreeMap::new()),
            fence: Mutex::new((0, 0)),
            log,
            skip_fail: Mutex::new(false),
        }
    }

    /// Another worker takes the stage run: every write with an epoch seen so far is refused, and
    /// the epoch of the next claim is accepted.
    pub fn take_over(&self) {
        let mut fence = lock(&self.fence);
        fence.1 = fence.0;
    }

    pub fn skip_next_fail(&self) {
        *lock(&self.skip_fail) = true;
    }

    /// The statuses of the nodes of a stage run, in key order of creation.
    pub fn statuses(&self, run: StageRunId) -> Vec<(String, TaskNodeStatus)> {
        lock(&self.nodes)
            .get(&run)
            .map(|nodes| {
                nodes
                    .iter()
                    .map(|n| (n.key.as_str().to_owned(), n.status))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn commits(&self, run: StageRunId) -> Vec<CommitSha> {
        lock(&self.nodes)
            .get(&run)
            .map(|nodes| nodes.iter().filter_map(|n| n.commit.clone()).collect())
            .unwrap_or_default()
    }

    fn current(&self, hold: &Hold) -> Result<(), LedgerError> {
        let mut fence = lock(&self.fence);
        if hold.epoch.get() <= fence.1 {
            return Err(LedgerError::Fenced);
        }
        fence.0 = fence.0.max(hold.epoch.get());
        Ok(())
    }
}

#[async_trait]
impl TaskLedger for RigLedger {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn open(
        &self,
        run: &RunIdentity,
        _plan: &Sha256Digest,
        tasks: &[PlannedTask],
    ) -> Result<Vec<TaskRecord>, LedgerError> {
        let mut all = lock(&self.nodes);
        let nodes = all.entry(run.stage_run).or_insert_with(|| {
            tasks
                .iter()
                .map(|task| Node {
                    key: task.key.clone(),
                    depends_on: task.depends_on.clone(),
                    status: TaskNodeStatus::Pending,
                    commit: None,
                })
                .collect()
        });
        Ok(nodes
            .iter()
            .map(|n| TaskRecord {
                key: n.key.clone(),
                status: n.status,
                commit: n.commit.clone(),
            })
            .collect())
    }

    async fn start(&self, run: &RunIdentity, task: &Slug, hold: &Hold) -> Result<(), LedgerError> {
        self.current(hold)?;
        let mut all = lock(&self.nodes);
        let nodes = all.get_mut(&run.stage_run).ok_or(LedgerError::Illegal)?;
        let statuses: BTreeMap<String, TaskNodeStatus> = nodes
            .iter()
            .map(|n| (n.key.as_str().to_owned(), n.status))
            .collect();
        let node = nodes
            .iter_mut()
            .find(|n| &n.key == task)
            .ok_or(LedgerError::Illegal)?;
        if node
            .depends_on
            .iter()
            .any(|d| statuses.get(d.as_str()) != Some(&TaskNodeStatus::Succeeded))
        {
            return Err(LedgerError::Illegal);
        }
        match node.status {
            TaskNodeStatus::Succeeded | TaskNodeStatus::Cancelled => Err(LedgerError::Illegal),
            _ => {
                node.status = TaskNodeStatus::Running;
                note(&self.log, format!("ledger.start:{}", task.as_str()));
                Ok(())
            }
        }
    }

    async fn confirm(&self, _run: &RunIdentity, hold: &Hold) -> Result<(), LedgerError> {
        self.current(hold)
    }

    async fn finish(
        &self,
        run: &RunIdentity,
        task: &Slug,
        commit: &CommitSha,
        hold: &Hold,
    ) -> Result<(), LedgerError> {
        self.current(hold)?;
        let mut all = lock(&self.nodes);
        let node = all
            .get_mut(&run.stage_run)
            .and_then(|nodes| nodes.iter_mut().find(|n| &n.key == task))
            .ok_or(LedgerError::Illegal)?;
        if node.status != TaskNodeStatus::Running {
            return Err(LedgerError::Illegal);
        }
        node.status = TaskNodeStatus::Succeeded;
        node.commit = Some(commit.clone());
        note(&self.log, format!("ledger.finish:{}", task.as_str()));
        Ok(())
    }

    async fn fail(&self, run: &RunIdentity, task: &Slug, hold: &Hold) -> Result<(), LedgerError> {
        if std::mem::take(&mut *lock(&self.skip_fail)) {
            return Ok(());
        }
        self.current(hold)?;
        let mut all = lock(&self.nodes);
        let node = all
            .get_mut(&run.stage_run)
            .and_then(|nodes| nodes.iter_mut().find(|n| &n.key == task))
            .ok_or(LedgerError::Illegal)?;
        if node.status == TaskNodeStatus::Running {
            node.status = TaskNodeStatus::Failed;
            note(&self.log, format!("ledger.fail:{}", task.as_str()));
        }
        Ok(())
    }
}

// ---- the rework source ---------------------------------------------------------------------

/// What the composition root reads from the store: the feedback of the run that was replaced.
pub struct RigRework {
    next: Mutex<VecDeque<Option<ReworkContext>>>,
    pub asked: Mutex<Vec<StageRunId>>,
    pub unavailable: Mutex<bool>,
}

impl RigRework {
    pub fn new() -> Self {
        Self {
            next: Mutex::new(VecDeque::new()),
            asked: Mutex::new(Vec::new()),
            unavailable: Mutex::new(false),
        }
    }
    /// What the next call answers. Without a queued answer it answers `None` (a first run).
    pub fn queue(&self, answer: Option<ReworkContext>) {
        lock(&self.next).push_back(answer);
    }
}

#[async_trait]
impl ReworkSource for RigRework {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    async fn of(&self, run: &RunIdentity) -> Result<Option<ReworkContext>, SeamError> {
        lock(&self.asked).push(run.stage_run);
        if *lock(&self.unavailable) {
            return Err(SeamError::Unavailable);
        }
        Ok(lock(&self.next).pop_front().flatten())
    }
}

// ---- spies ---------------------------------------------------------------------------------

pub struct SpyWorkspaces {
    pub inner: Arc<FakeWorkspaceProvider>,
    pub log: Log,
    pub artifacts: Arc<Granting>,
}

/// The job's object store, with one change: the patch is shaped like the output of
/// `git diff --no-renames`, as the port promises, with `diff --git` headers and `@@` hunks. The
/// testkit fake writes bare `---`/`+++` lines and no hunks, so the stages' readers of a patch would
/// have nothing to read. The real adapter's patches are checked in its own tests.
struct GitShapedRepo {
    inner: Box<dyn JobRepo>,
    artifacts: Arc<Granting>,
}

fn render(path: &str, before: Option<&str>, after: Option<&str>) -> String {
    let mut text = format!("diff --git a/{path} b/{path}\n");
    let (old_name, new_name) = match (before, after) {
        (None, Some(_)) => {
            text.push_str("new file mode 100644\n");
            ("/dev/null".to_owned(), format!("b/{path}"))
        }
        (Some(_), None) => {
            text.push_str("deleted file mode 100644\n");
            (format!("a/{path}"), "/dev/null".to_owned())
        }
        _ => (format!("a/{path}"), format!("b/{path}")),
    };
    text.push_str(&format!("--- {old_name}\n+++ {new_name}\n"));
    let old: Vec<&str> = before.map(|t| t.lines().collect()).unwrap_or_default();
    let new: Vec<&str> = after.map(|t| t.lines().collect()).unwrap_or_default();
    let start = |lines: &Vec<&str>| if lines.is_empty() { 0 } else { 1 };
    text.push_str(&format!(
        "@@ -{},{} +{},{} @@\n",
        start(&old),
        old.len(),
        start(&new),
        new.len()
    ));
    for line in &old {
        text.push_str(&format!("-{line}\n"));
    }
    for line in &new {
        text.push_str(&format!("+{line}\n"));
    }
    text
}

#[async_trait]
impl JobRepo for GitShapedRepo {
    async fn read_file_at(
        &self,
        commit: &CommitSha,
        path: &RepoPath,
        max_bytes: u64,
        view: factory_ports::workspace::ReadView,
    ) -> Result<Vec<u8>, WorkspaceError> {
        self.inner.read_file_at(commit, path, max_bytes, view).await
    }
    async fn list_at(
        &self,
        commit: &CommitSha,
        glob: &RepoGlob,
        limit: usize,
        view: factory_ports::workspace::ReadView,
    ) -> Result<Vec<RepoPath>, WorkspaceError> {
        self.inner.list_at(commit, glob, limit, view).await
    }
    async fn export_patch(
        &self,
        base: &CommitSha,
        head: &CommitSha,
        max_bytes: u64,
        cancel: &dyn CancelSignal,
    ) -> Result<factory_ports::workspace::PatchExport, WorkspaceError> {
        use factory_ports::workspace::{ChangeKind, ReadView};
        let exported = self
            .inner
            .export_patch(base, head, max_bytes, cancel)
            .await?;
        let mut text = String::new();
        for change in &exported.changes {
            let read = |commit: &CommitSha| {
                let inner = &self.inner;
                let path = change.path.clone();
                let commit = commit.clone();
                async move {
                    inner
                        .read_file_at(&commit, &path, max_bytes, ReadView::Trusted)
                        .await
                        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                }
            };
            let before = match change.kind {
                ChangeKind::Added => None,
                _ => Some(read(base).await?),
            };
            let after = match change.kind {
                ChangeKind::Deleted => None,
                _ => Some(read(head).await?),
            };
            text.push_str(&render(
                change.path.as_str(),
                before.as_deref(),
                after.as_deref(),
            ));
        }
        let patch = self
            .artifacts
            .put(
                text.into_bytes(),
                MediaType::parse("text/x-diff").expect("a media type"),
            )
            .await
            .map_err(|_| WorkspaceError::Io(factory_ports::workspace::IoOperation::Walk))?;
        Ok(factory_ports::workspace::PatchExport {
            patch,
            changes: exported.changes,
        })
    }
    async fn push(
        &self,
        target: &factory_ports::workspace::PushTarget,
        commit: &CommitSha,
        cancel: &dyn CancelSignal,
    ) -> Result<(), WorkspaceError> {
        self.inner.push(target, commit, cancel).await
    }
    async fn tree_of(
        &self,
        commit: &CommitSha,
    ) -> Result<factory_domain::values::GitSha, WorkspaceError> {
        self.inner.tree_of(commit).await
    }
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
        let purpose = format!("{:?}", req.purpose)
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_owned();
        let base = req.base.as_str().to_owned();
        let inner = self.inner.create(req, cancel).await?;
        note(&self.log, format!("workspace.create:{purpose}:{base}"));
        Ok(Box::new(SpyWorkspace {
            inner,
            log: self.log.clone(),
        }))
    }
    async fn repo(&self, job: JobId) -> Result<Box<dyn JobRepo>, WorkspaceError> {
        Ok(Box::new(GitShapedRepo {
            inner: self.inner.repo(job).await?,
            artifacts: self.artifacts.clone(),
        }))
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
        note(&self.log, format!("workspace.commit:{}", req.author_name));
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
        let profile = spec.profile.as_str();
        note(&self.log, format!("sandbox.attempt:{profile}"));
        let inner = self.inner.create_verified(spec, cancel).await?;
        note(&self.log, format!("sandbox.create:{profile}"));
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

type Hook = Box<dyn FnOnce() + Send>;

/// The scripted adversarial runtime with two additions: before a run returns it changes the
/// writable tree of the workspace the sandbox was made over (what the builder's file tools would
/// have done), and it can run a hook (the lease is lost while the agent works).
pub struct Runtime {
    pub inner: FakeAgentRuntime,
    workspaces: Arc<FakeWorkspaceProvider>,
    dirs: Arc<Mutex<Vec<PathBuf>>>,
    edits: Mutex<VecDeque<(String, Vec<TreeEdit>)>>,
    hooks: Mutex<VecDeque<(String, Hook)>>,
    log: Log,
}

impl Runtime {
    /// The next run of `agent` changes the tree like this.
    pub fn edits(&self, agent: &str, edits: Vec<TreeEdit>) {
        lock(&self.edits).push_back((agent.to_owned(), edits));
    }
    /// The next run of `agent` calls `hook` before it returns.
    pub fn hook(&self, agent: &str, hook: impl FnOnce() + Send + 'static) {
        lock(&self.hooks).push_back((agent.to_owned(), Box::new(hook)));
    }
    pub fn runs(&self, agent: &str) -> usize {
        self.inner
            .recorded_prompts()
            .iter()
            .filter(|p| p.agent.id.as_str() == agent)
            .count()
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
        let report = self.inner.run(session, req, cancel).await;
        let hook = {
            let mut queue = lock(&self.hooks);
            match queue.front() {
                Some((who, _)) if *who == agent => queue.pop_front().map(|(_, h)| h),
                _ => None,
            }
        };
        if let Some(hook) = hook {
            hook();
        }
        report
    }
}

// ---- the rig -------------------------------------------------------------------------------

pub struct Rig {
    pub world: World,
    pub engine: Engine,
    pub log: Log,
    pub runtime: Arc<Runtime>,
    pub provider: Arc<FakeWorkspaceProvider>,
    pub remote: FakeRemote,
    pub specs: Arc<RigSpecs>,
    pub ledger: Arc<RigLedger>,
    pub rework: Arc<RigRework>,
    pub check: Arc<StandInCheck>,
    pub repo: RepoRef,
    pub base: CommitSha,
    pub artifacts: Arc<Granting>,
    pub job: JobId,
    /// What the validation stand-in reports. A test changes it between stage runs.
    pub validation: Arc<Mutex<crate::standin::ValidationMode>>,
}

/// What differs from one test to the next.
pub struct Options {
    /// The stage kinds the job runs, in pipeline order.
    pub scope: Vec<StageKind>,
    /// What the stand-in for the validation stage reports.
    pub validation: crate::standin::ValidationMode,
    /// The files of the base commit.
    pub files: Vec<(String, String)>,
    /// The plan the planning stand-in stores.
    pub plan: String,
    /// Builds the review handler too.
    pub review: bool,
    /// The manifest of the reviewer, when a test needs another one than the real one.
    pub reviewer: Option<AgentManifest>,
    /// The limits of the implementation stage, when a test needs smaller ones.
    pub budget: Option<StageBudget>,
    /// The router finds no model independent of the author of the work under review, as the
    /// policy router does when only the builder's family is served.
    pub no_independent_reviewer: bool,
    /// The router finds a reviewer of the author's own family but another model, as the policy
    /// router does in subscription mode under `must_differ_by: model`.
    pub same_family_reviewer: bool,
}

/// A router that refuses every need that names an author, and routes every other need as the
/// router it wraps does: the answer of the policy router when no served model is independent of
/// the author (`AuthorRoutingError::NoIndependentModel`, which the port reads as `NoRoute`).
pub struct NoIndependentReviewer(pub Arc<dyn ModelRouter>);

impl ModelRouter for NoIndependentReviewer {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    fn route(&self, need: &RoutingNeed) -> Result<RoutingDecision, RoutingError> {
        if need.author.is_some() {
            return Err(RoutingError::NoRoute);
        }
        self.0.route(need)
    }
}

/// A router that answers every need that names an author as the router it wraps does, and says
/// the chosen model is of the author's own family: the answer of the policy router in
/// subscription mode, where Claude Opus reviews the work of Claude Sonnet.
pub struct SameFamilyReviewer(pub Arc<dyn ModelRouter>);

impl ModelRouter for SameFamilyReviewer {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    fn route(&self, need: &RoutingNeed) -> Result<RoutingDecision, RoutingError> {
        let mut decision = self.0.route(need)?;
        if let Some(author) = &need.author {
            decision.independence = Some(factory_ports::agent::ReviewIndependence {
                author: author.clone(),
                kind: factory_ports::agent::IndependenceKind::SameFamilyOtherModel,
            });
        }
        Ok(decision)
    }
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
                StageKind::Implementation,
            ],
            validation: crate::standin::ValidationMode::AllPass,
            files: base_files(),
            plan: PLAN.to_owned(),
            review: false,
            reviewer: None,
            budget: None,
            no_independent_reviewer: false,
            same_family_reviewer: false,
        }
    }
}

impl Options {
    /// The whole way through: validation and review as well.
    pub fn through_review() -> Self {
        let mut options = Self::default();
        options.scope.push(StageKind::Validation);
        options.scope.push(StageKind::Review);
        options.review = true;
        options
    }
}

pub fn builder_manifest() -> AgentManifest {
    serde_json::from_str(BUILDER_MANIFEST).expect("the real manifest is valid")
}

pub fn reviewer_manifest() -> AgentManifest {
    serde_json::from_str(REVIEWER_MANIFEST).expect("the real manifest is valid")
}

pub fn definition_commit() -> GitSha {
    GitSha::parse("1405df66cbe219b0bf6355bc3d60361a8376b6b4").expect("a commit")
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

        let spy_workspaces = Arc::new(SpyWorkspaces {
            inner: provider.clone(),
            log: log.clone(),
            artifacts: artifacts.clone(),
        });
        let sandbox = Arc::new(SpySandbox {
            inner: FakeSandbox::new(world.clock.clone(), artifacts.clone(), sandbox_policy()),
            log: log.clone(),
        });
        let specs = Arc::new(RigSpecs::new());
        let fake_runtime = FakeAgentRuntime::new(artifacts.clone());
        let runtime = Arc::new(Runtime {
            inner: fake_runtime,
            workspaces: provider.clone(),
            dirs: specs.dirs.clone(),
            edits: Mutex::new(VecDeque::new()),
            hooks: Mutex::new(VecDeque::new()),
            log: log.clone(),
        });
        let mut registry = InMemoryAgentRegistry::new();
        registry.add(builder_manifest(), Some(BUILDER_PROMPT));
        registry.add(
            options.reviewer.clone().unwrap_or_else(reviewer_manifest),
            Some(REVIEWER_PROMPT),
        );

        let mut deps = world.deps.clone();
        deps.artifacts = artifacts.clone();
        deps.sandbox = sandbox;
        deps.workspaces = spy_workspaces;
        deps.runtime = runtime.clone();
        deps.registry = Arc::new(registry);
        if options.no_independent_reviewer {
            deps.router = Arc::new(NoIndependentReviewer(deps.router.clone()));
        }
        if options.same_family_reviewer {
            deps.router = Arc::new(SameFamilyReviewer(deps.router.clone()));
        }

        let ledger = Arc::new(RigLedger::new(log.clone()));
        let rework = Arc::new(RigRework::new());
        let check = Arc::new(StandInCheck::new());
        let handler = ImplementationHandler::new(
            ImplementationConfig {
                agent: Slug::parse("builder").expect("a slug"),
                agent_version: "1.0.0".to_owned(),
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
                max_patch_bytes: 1_048_576,
                budget: options.budget.unwrap_or(StageBudget {
                    wall_time_seconds: 14_400,
                    max_tokens: 2_000_000,
                    max_cost_usd: 15.0,
                    attempt_timeout_seconds: 14_400,
                    max_attempts: 3,
                }),
            },
            ImplementationDeps {
                policy: policy_engine(),
                redactor: redactor(),
                schemas: check.clone(),
                specs: specs.clone(),
                probes: Arc::new(FixedProbes),
                ledger: ledger.clone(),
                rework: rework.clone(),
            },
        );
        let mut handlers = HandlerRegistry::new();
        handlers.register(Arc::new(handler)).expect("one handler");
        let validation = crate::standin::register_around(
            &mut handlers,
            &world,
            &options,
            &base,
            artifacts.clone(),
            log.clone(),
        );
        if options.review {
            crate::review::register(&mut handlers, &check, &specs);
        }
        let engine = Engine::new(deps, world.config.clone(), handlers).expect("the engine starts");
        Self {
            world,
            engine,
            log,
            runtime,
            provider,
            remote,
            specs,
            ledger,
            rework,
            check,
            repo,
            base,
            artifacts,
            job,
            validation,
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

    /// Runs the stages before the implementation stage.
    pub async fn run_until_implementation(&self) {
        self.admit().await;
        for kind in [
            StageKind::Intake,
            StageKind::RepositoryIntelligence,
            StageKind::Specification,
            StageKind::DomainDiscovery,
            StageKind::Architecture,
            StageKind::TaskPlanning,
        ] {
            let (claimed, outcome) = self.run_next().await;
            assert_eq!(claimed.kind, kind);
            assert_eq!(outcome, AttemptOutcome::Succeeded, "{kind:?}");
        }
    }

    /// The builder will make these edits and report this.
    pub fn builder_will(&self, edits: Vec<TreeEdit>, report: Value) {
        self.runtime.edits("builder", edits);
        self.runtime
            .inner
            .queue(AdversarialScript::returning(report));
    }

    /// The builder's three tasks of the example plan, each with edits inside the files it owns.
    pub fn builder_does_the_plan(&self) {
        self.builder_will(
            vec![
                write("src/main.rs", MAIN),
                write("src/output.rs", OUTPUT),
                write("tests/json_output.rs", JSON_TEST),
            ],
            done(
                "add-json-output-formatter",
                &["src/main.rs", "src/output.rs", "tests/json_output.rs"],
            ),
        );
        self.builder_will(
            vec![write("tests/errors.rs", ERRORS_TEST)],
            done("cover-unreadable-file-error", &["tests/errors.rs"]),
        );
        self.builder_will(
            vec![write(
                "README.md",
                "# Word count\n\nUse --json to print JSON.\n",
            )],
            done("document-json-flag", &["README.md"]),
        );
    }

    pub fn events(&self) -> Vec<String> {
        lock(&self.log).clone()
    }

    /// The events whose text starts with `prefix`, in order.
    pub fn events_of(&self, prefix: &str) -> Vec<String> {
        self.events()
            .into_iter()
            .filter(|e| e.starts_with(prefix))
            .collect()
    }

    /// The stage run of the newest run of `kind`.
    pub async fn run_of(&self, kind: StageKind) -> StageRunId {
        self.world
            .view(self.job)
            .await
            .newest(kind)
            .expect("a run of that kind")
            .id
    }

    /// The runs of one kind, oldest first.
    pub async fn runs_of(
        &self,
        kind: StageKind,
    ) -> Vec<(StageRunId, factory_domain::state::StageRunStatus)> {
        self.world
            .view(self.job)
            .await
            .runs_of(kind)
            .map(|run| (run.id, run.status))
            .collect()
    }

    /// The deliverable `name` of the newest run of `kind` that has one, read back from the
    /// artifact store. A run that was replaced by rework keeps its outputs.
    pub async fn deliverable(&self, kind: StageKind, name: &str) -> Option<Value> {
        for (run, _) in self.runs_of(kind).await.into_iter().rev() {
            if let Some(found) = self.deliverable_in(run, name).await {
                return Some(found);
            }
        }
        None
    }

    /// The request for a person that the last attempt of `run` left, read back from the artifact
    /// store: the document that holds `needs_human`.
    pub async fn needs_human_request(&self, run: StageRunId) -> Option<Value> {
        let tenant = TenantScope::new(self.world.tenant);
        // The request is the output of the attempt that asked, not a link of the stage run.
        let mut tx = self.world.store.begin(tenant).await.expect("a tx");
        let attempts = tx.list_attempts(run).await.expect("the attempts");
        tx.rollback().await.expect("rollback");
        for output in attempts
            .iter()
            .rev()
            .filter_map(|attempt| attempt.value.output.clone())
        {
            let reference = ArtifactRef {
                sha256: output,
                media_type: MediaType::parse("application/json").expect("a media type"),
                size_bytes: None,
            };
            if let Ok(bytes) = ArtifactStore::get(&*self.artifacts, &tenant, &reference).await
                && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
                && value.get("needs_human").is_some()
            {
                return Some(value);
            }
        }
        None
    }

    /// The deliverable `name` of one stage run.
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
                && value.get("kind").and_then(Value::as_str) == Some(name)
            {
                return Some(value);
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
}

// ---- builder outputs -----------------------------------------------------------------------

pub fn write(path_text: &str, text: &str) -> TreeEdit {
    TreeEdit::Write(path(path_text), text.as_bytes().to_vec())
}

pub const MAIN: &str = "fn main() {\n    let json = std::env::args().any(|a| a == \"--json\");\n    println!(\"{}\", if json { \"{}\" } else { \"words\" });\n}\n";
pub const OUTPUT: &str = "//! Prints the counts as JSON.\n\npub struct Counts {\n    pub lines: usize,\n    pub words: usize,\n    pub characters: usize,\n}\n\npub fn to_json(counts: &Counts) -> String {\n    format!(\n        \"{{\\\"lines\\\":{},\\\"words\\\":{},\\\"characters\\\":{}}}\",\n        counts.lines, counts.words, counts.characters\n    )\n}\n\npub fn empty() -> Counts {\n    Counts { lines: 0, words: 0, characters: 0 }\n}\n";
pub const JSON_TEST: &str =
    "#[test]\nfn json_output_prints_three_counts() {\n    assert!(true);\n}\n";
pub const ERRORS_TEST: &str =
    "#[test]\nfn an_unreadable_file_is_an_error() {\n    assert!(true);\n}\n";

/// A valid builder report for `task`.
pub fn done(task: &str, files: &[&str]) -> Value {
    json!({
        "schema_version": 1,
        "status": "DONE",
        "task_id": task,
        "summary": "Everything the task asked for is done and the tests pass on my side.",
        "files_changed": files,
        "commands_run": [{ "argv": ["cargo", "test", "--locked"], "exit_code": 0 }],
        "tests_added": ["a_new_test"],
        "dependency_requests": [],
        "ignored_instructions": []
    })
}
