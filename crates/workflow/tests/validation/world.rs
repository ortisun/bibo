//! The harness: the in-memory ports, a fixture repository and the whole stage run.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::contracts::{ArtifactRef, GateReport, StageContract, Violation};
use factory_domain::ids::{AttemptId, CorrelationId, JobId, StageRunId, TenantId};
use factory_domain::policy::{ApprovalPolicy, PolicyEngine, SecurityPolicy};
use factory_domain::redaction::{PatternAction, Redactor};
use factory_domain::scope::TenantScope;
use factory_domain::state::StageRunStatus;
use factory_domain::values::{MediaType, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::{ExecutionMode, Fidelity, GateOutcome, StageKind};
use factory_ports::artifact::{ArtifactBackend, ArtifactError, ArtifactStore};
use factory_ports::clock::{CancelSignal, Clock};
use factory_ports::paths::{BranchName, CommitSha, RepoGlob, RepoRef};
use factory_ports::registry::{ContractKind, OutputValidator, ValidatedOutput};
use factory_ports::sandbox::{
    ExecRequest, ExecResult, Hardening, PostureReport, SandboxError, SandboxId, SandboxLimits,
    SandboxProvider, SandboxSession, SandboxSpec, TeardownReason, TeardownReport,
};
use factory_ports::store::LeaseEpoch;
use factory_ports::workspace::{FetchCredential, FetchTarget, WorkspaceProvider};
use factory_testkit::agent::FakeAgentRuntime;
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::broker::FakeModelBroker;
use factory_testkit::clock::{FakeCancel, FakeClock, SequentialIdGenerator};
use factory_testkit::contracts::workspace::fixture_rules;
use factory_testkit::fixtures::{Ids, image, sandbox_policy};
use factory_testkit::registry::InMemoryAgentRegistry;
use factory_testkit::router::StaticModelRouter;
use factory_testkit::sandbox::FakeSandbox;
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use factory_workflow::gates::framework::{
    EvidenceProblem, Expectation, GateDecision, Resolution, check_evidence, resolve,
};
use factory_workflow::gates::scope::own_build_code::ProjectBuildCodeApproval;
use factory_workflow::gates::supply_chain::approval::{
    DecisionScope, DependencyApproval, RecordedApprovals,
};
use factory_workflow::gates::supply_chain::facts::{
    AdvisoryDatabase, RegistryMetadata, RegistryRecord, StaticRegistry,
};
use factory_workflow::gates::supply_chain::licenses::LicensePolicy;
use factory_workflow::gates::supply_chain::names::PopularNames;
use factory_workflow::gates::supply_chain::run::{FetchSandbox, SbomRule};
use factory_workflow::gates::supply_chain::tools::SbomTool;
use factory_workflow::handlers::{
    ContractContext, GateContext, NamedArtifact, RunIdentity, StageContext, StageError,
    StageHandler, StagePorts, UpstreamRun,
};
use factory_workflow::stages::validation::{
    Bounds, JsonManifestReader, SupplyChainSeams, SupplyChainSettings, ValidationConfig,
    ValidationHandler, VerifySandbox,
};

use super::cargo::CargoScript;
use super::schema_check;

const SECURITY: &str = include_str!("../../../domain/tests/fixtures/policy/security.json");
const APPROVAL: &str = include_str!("../../../domain/tests/fixtures/policy/approval.json");
const SPECIFICATION: &str = include_str!(
    "../../../../schemas/examples/specification-contract/valid/approved-json-output-flag.json"
);

/// The manifest at the base commit: the four universal command gates.
pub const MANIFEST: &str = r#"{
  "schema_version": 1,
  "project": { "name": "word-count", "title": "Word count command line tool", "domain_tags": ["general-software", "command-line-tool"], "default_branch": "main" },
  "sandbox": { "image": "rust-fixture", "workdir": "/workspace" },
  "gates": [
    { "id": "format", "title": "Check the formatting", "argv": ["cargo", "fmt", "--check"], "timeout_seconds": 120, "mandatory": true },
    { "id": "lint", "title": "Run the linter", "argv": ["cargo", "clippy", "--all-targets", "--", "-D", "warnings"], "timeout_seconds": 600, "mandatory": true },
    { "id": "build", "title": "Build the project", "argv": ["cargo", "build"], "timeout_seconds": 600, "mandatory": true },
    { "id": "unit-tests", "title": "Run the tests", "argv": ["cargo", "test"], "timeout_seconds": 900, "mandatory": true }
  ],
  "protected_paths": [".factory/**", ".github/**"],
  "spec_kit": { "cli_version": "1.1.2", "integration": "claude", "may_initialize": true },
  "documentation": { "required_documents": [{ "path": "README.md", "purpose": "Explains what the tool does and how to use it." }], "changelog_path": "CHANGELOG.md" }
}"#;

/// The library of the base commit, with one test inside the source file.
pub const LIB: &str = "pub fn count(text: &str) -> usize {\n    text.split_whitespace().count()\n}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn unit_counts_words() {\n        assert_eq!(count(\"a b c\"), 3);\n    }\n}\n";

/// The files of the base commit.
/// The policy engine of the world's fixtures, with one change made to the security policy.
pub fn policy_with(change: impl FnOnce(&mut serde_json::Value)) -> Arc<PolicyEngine> {
    let mut security: serde_json::Value =
        serde_json::from_str(SECURITY).expect("the security policy fixture");
    change(&mut security);
    let security: SecurityPolicy =
        serde_json::from_value(security).expect("the changed security policy");
    let approval: ApprovalPolicy =
        serde_json::from_str(APPROVAL).expect("the approval policy fixture");
    Arc::new(PolicyEngine::new(&security, &approval).expect("a policy engine"))
}

pub fn base_files() -> Vec<(String, String)> {
    [
        ("Cargo.toml", "[package]\nname = \"word-count\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
        ("src/lib.rs", LIB),
        ("tests/it.rs", "use word_count::count;\n\n#[test]\nfn counts_a_line() {\n    assert_eq!(count(\"one two\"), 2);\n}\n\n#[test]\nfn counts_one_word() {\n    assert_eq!(count(\"one\"), 1);\n}\n\n#[test]\nfn counts_nothing() {\n    assert_eq!(count(\"\"), 0);\n}\n"),
        ("tests/holdout/case.rs", "// held out from the builder\n"),
        (".github/workflows/ci.yml", "name: ci\n"),
        ("CHANGELOG.md", "# Changelog\n"),
        ("README.md", "# Word count\n"),
        (".factory/project.json", MANIFEST),
    ]
    .iter()
    .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
    .collect()
}

/// A copy of the base files with some paths replaced, added or removed (`None`).
pub fn with(changes: &[(&str, Option<&str>)]) -> Vec<(String, String)> {
    let mut files = base_files();
    for (path, content) in changes {
        files.retain(|(existing, _)| existing != path);
        if let Some(text) = content {
            files.push(((*path).to_owned(), (*text).to_owned()));
        }
    }
    files
}

/// Wraps an artifact store so that whatever is stored is readable by the test tenant. This is
/// what the composition root must provide in production, where the store reads only a hash the
/// tenant has indexed.
pub struct Granting {
    inner: InMemoryArtifactStore,
    tenant: TenantId,
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

/// How a test changes what the supervisor reports for a command.
pub type Rewrite = Arc<dyn Fn(&[String], ExecResult) -> ExecResult + Send + Sync>;

/// The fake sandbox with a hook on every result, to make a command time out or be killed.
pub struct Tamper {
    inner: FakeSandbox,
    rewrite: Mutex<Option<Rewrite>>,
    created: Mutex<usize>,
    refuse: Mutex<Option<SandboxError>>,
}

impl Tamper {
    /// The next `create_verified` fails with this error, as a daemon that is down would.
    pub fn refuse_with(&self, error: SandboxError) {
        *self.refuse.lock().expect("the lock is never poisoned") = Some(error);
    }

    pub fn set(&self, rewrite: Rewrite) {
        *self.rewrite.lock().expect("the lock is never poisoned") = Some(rewrite);
    }

    pub fn created(&self) -> usize {
        *self.created.lock().expect("the lock is never poisoned")
    }

    /// How many sandboxes were created and not removed.
    pub fn live(&self) -> usize {
        self.inner.live_sandboxes().len()
    }
}

struct TamperSession {
    inner: Box<dyn SandboxSession>,
    rewrite: Option<Rewrite>,
}

#[async_trait]
impl SandboxProvider for Tamper {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }
    async fn create_verified(
        &self,
        spec: SandboxSpec,
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn SandboxSession>, SandboxError> {
        if let Some(error) = self
            .refuse
            .lock()
            .expect("the lock is never poisoned")
            .clone()
        {
            return Err(error);
        }
        let inner = self.inner.create_verified(spec, cancel).await?;
        *self.created.lock().expect("the lock is never poisoned") += 1;
        Ok(Box::new(TamperSession {
            inner,
            rewrite: self
                .rewrite
                .lock()
                .expect("the lock is never poisoned")
                .clone(),
        }))
    }
    async fn sweep_orphans(&self, live: &[AttemptId]) -> Result<Vec<SandboxId>, SandboxError> {
        self.inner.sweep_orphans(live).await
    }
}

#[async_trait]
impl SandboxSession for TamperSession {
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
        let argv = req.argv.as_slice().to_vec();
        let result = self.inner.exec(req, cancel).await?;
        Ok(match &self.rewrite {
            Some(rewrite) => rewrite(&argv, result),
            None => result,
        })
    }
    async fn stop_and_remove(
        self: Box<Self>,
        reason: TeardownReason,
    ) -> Result<TeardownReport, SandboxError> {
        self.inner.stop_and_remove(reason).await
    }
}

/// The decisions recorded for the job, as the composition root would load them from the ledger.
#[derive(Default)]
pub struct Approvals {
    dependencies: Mutex<Vec<DependencyApproval>>,
    build_code: Mutex<Vec<ProjectBuildCodeApproval>>,
}

impl Approvals {
    pub fn record(&self, approval: DependencyApproval) {
        self.dependencies
            .lock()
            .expect("the lock is never poisoned")
            .push(approval);
    }

    pub fn record_build_code(&self, approval: ProjectBuildCodeApproval) {
        self.build_code
            .lock()
            .expect("the lock is never poisoned")
            .push(approval);
    }
}

#[async_trait]
impl RecordedApprovals for Approvals {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    async fn for_job(&self, tenant: TenantId, job: JobId) -> Vec<DependencyApproval> {
        self.dependencies
            .lock()
            .expect("the lock is never poisoned")
            .iter()
            .filter(|approval| approval.scope == DecisionScope { tenant, job })
            .cloned()
            .collect()
    }

    async fn build_code_for_job(
        &self,
        tenant: TenantId,
        job: JobId,
    ) -> Vec<ProjectBuildCodeApproval> {
        self.build_code
            .lock()
            .expect("the lock is never poisoned")
            .iter()
            .filter(|approval| approval.scope == DecisionScope { tenant, job })
            .cloned()
            .collect()
    }
}

/// What the registry says about the packages of a test.
#[derive(Default)]
pub struct Registry(Mutex<StaticRegistry>);

impl Registry {
    pub fn know(&self, name: &str, record: RegistryRecord) {
        let mut table = self.0.lock().expect("the lock is never poisoned");
        *table = table.clone().with(name, record);
    }
}

#[async_trait]
impl RegistryMetadata for Registry {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    async fn lookup(&self, name: &str, version: &str) -> RegistryRecord {
        let table = self.0.lock().expect("the lock is never poisoned").clone();
        table.lookup(name, version).await
    }
}

/// The date of the advisory database in the image.
pub struct Database(Mutex<Option<Timestamp>>);

impl Database {
    pub fn updated(&self, at: Option<Timestamp>) {
        *self.0.lock().expect("the lock is never poisoned") = at;
    }
}

#[async_trait]
impl AdvisoryDatabase for Database {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    async fn updated_at(&self) -> Option<Timestamp> {
        *self.0.lock().expect("the lock is never poisoned")
    }
}

/// Checks a gate report against `schemas/gate-report.schema.json` and nothing else.
pub struct SchemaValidator;

impl OutputValidator for SchemaValidator {
    fn validate_bytes(
        &self,
        kind: ContractKind,
        version: u32,
        bytes: &[u8],
    ) -> Result<ValidatedOutput, Vec<Violation>> {
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
            vec![Violation {
                path: String::new(),
                message: "not JSON".to_owned(),
            }]
        })?;
        self.validate_value(kind, version, &value)?;
        Ok(ValidatedOutput {
            sha256: Sha256Digest::of(bytes),
            size_bytes: bytes.len() as u64,
            value,
        })
    }

    fn validate_value(
        &self,
        kind: ContractKind,
        _version: u32,
        instance: &serde_json::Value,
    ) -> Result<(), Vec<Violation>> {
        if kind != ContractKind::GateReport {
            return Ok(());
        }
        let schema: serde_json::Value =
            serde_json::from_str(schema_check::SCHEMA).expect("the schema is JSON");
        let problems = schema_check::problems(&schema, instance);
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems
                .into_iter()
                .map(|message| Violation {
                    path: String::new(),
                    message,
                })
                .collect())
        }
    }
}

/// One whole run of the stage: what `execute` stored and what `evaluate` handed the engine.
pub struct Ran {
    pub contract: StageContract,
    pub evidence: serde_json::Value,
    pub decision: GateDecision,
    pub resolution: Resolution,
    pub problem: Option<EvidenceProblem>,
}

impl Ran {
    pub fn report(&self, gate: &str) -> &GateReport {
        self.decision
            .reports
            .iter()
            .find(|report| report.metadata.gate_id.as_str() == gate)
            .unwrap_or_else(|| panic!("no report for {gate}"))
    }

    pub fn outcome(&self, gate: &str) -> GateOutcome {
        self.report(gate).outcome
    }

    pub fn failure_checks(&self, gate: &str) -> Vec<String> {
        self.report(gate)
            .failures
            .iter()
            .flatten()
            .map(|failure| failure.check_id.as_str().to_owned())
            .collect()
    }
}

pub struct World {
    pub clock: Arc<FakeClock>,
    pub ids: Arc<SequentialIdGenerator>,
    pub fixture: Ids,
    pub artifacts: Arc<Granting>,
    pub remote: FakeRemote,
    pub workspaces: Arc<FakeWorkspaceProvider>,
    pub sandbox: Arc<Tamper>,
    pub cargo: Arc<CargoScript>,
    pub cancel: FakeCancel,
    pub tenant: TenantId,
    pub job: JobId,
    pub stage_run: StageRunId,
    pub attempt: AttemptId,
    pub correlation: CorrelationId,
    pub repo: RepoRef,
    pub branch: BranchName,
    pub policy: Arc<PolicyEngine>,
    pub redactor: Arc<Redactor>,
    pub policy_hash: Sha256Digest,
    pub approvals: Arc<Approvals>,
    pub packages: Arc<Registry>,
    pub database: Arc<Database>,
    supply_tweak: Mutex<Option<fn(&mut SupplyChainSettings)>>,
    runtime: FakeAgentRuntime,
    router: StaticModelRouter,
    registry: InMemoryAgentRegistry,
    broker: Arc<FakeModelBroker>,
    validator: SchemaValidator,
}

impl World {
    pub fn new() -> Self {
        let fixture = Ids::new();
        // The tenant and the job of the decisions in `people`, so that a recorded decision is for
        // the run the world makes.
        let tenant = super::people::tenant();
        let clock = Arc::new(FakeClock::new());
        let ids = Arc::new(SequentialIdGenerator::new());
        let artifacts = Arc::new(Granting {
            inner: InMemoryArtifactStore::new(),
            tenant,
        });
        let repo = RepoRef::parse("example-org/word-count").expect("a repository");
        let branch = BranchName::new("main").expect("a branch");
        let remote = FakeRemote::new();
        let workspaces = Arc::new(FakeWorkspaceProvider::new(
            repo.clone(),
            remote.clone(),
            artifacts.clone(),
            fixture_rules(),
        ));
        let cargo = CargoScript::new();
        let sandbox = Arc::new(Tamper {
            inner: cargo.install(FakeSandbox::new(
                clock.clone(),
                artifacts.clone(),
                sandbox_policy(),
            )),
            rewrite: Mutex::new(None),
            created: Mutex::new(0),
            refuse: Mutex::new(None),
        });
        let security: SecurityPolicy =
            serde_json::from_str(SECURITY).expect("the security policy fixture");
        let approval: ApprovalPolicy =
            serde_json::from_str(APPROVAL).expect("the approval policy fixture");
        let policy = Arc::new(PolicyEngine::new(&security, &approval).expect("a policy engine"));
        let redactor = Arc::new(
            Redactor::builder()
                .pattern("github-token", "ghp_[A-Za-z0-9]{36}", PatternAction::Block)
                .pattern(
                    "private-key",
                    "-----BEGIN [A-Z ]*PRIVATE KEY-----",
                    PatternAction::Block,
                )
                .build()
                .expect("a redactor"),
        );
        Self {
            runtime: FakeAgentRuntime::new(artifacts.clone()),
            router: StaticModelRouter::new(Vec::new()),
            registry: InMemoryAgentRegistry::new(),
            broker: Arc::new(FakeModelBroker::new(clock.clone(), ids.clone())),
            validator: SchemaValidator,
            job: super::people::job(),
            stage_run: fixture.stage_run(),
            attempt: fixture.attempt(),
            correlation: fixture.correlation(),
            policy_hash: Sha256Digest::of(b"policy bundle one"),
            approvals: Arc::new(Approvals::default()),
            supply_tweak: Mutex::new(None),
            packages: Arc::new(Registry::default()),
            // One day old at the time of the fake clock.
            database: Arc::new(Database(Mutex::new(Some(
                Timestamp::parse("2026-10-27T00:00:00Z").expect("a time"),
            )))),
            clock,
            ids,
            fixture,
            artifacts,
            remote,
            workspaces,
            sandbox,
            cargo,
            cancel: FakeCancel::new(),
            tenant,
            repo,
            branch,
            policy,
            redactor,
        }
    }

    /// Puts a commit with exactly these files on the remote branch and fetches it into the job's
    /// object store, as the intake stage and the implementation stage do.
    pub async fn push(&self, files: &[(String, String)]) -> CommitSha {
        let pairs: Vec<(&str, &str)> = files
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        self.remote
            .commit_on_branch(&self.repo, &self.branch, &pairs);
        let fetched = self
            .workspaces
            .fetch(
                self.job,
                &FetchTarget {
                    repo: self.repo.clone(),
                    credential: FetchCredential::new(format!("{}-{}", "read", "token")),
                },
                &self.branch,
                &self.cancel,
            )
            .await
            .expect("the fetch works");
        fetched.commit
    }

    /// The settings of the dependency gates as a stage built from the world's policy has them,
    /// and then changed by the test through [`tweak_supply`](Self::tweak_supply), the way a
    /// composition root's configuration would change them.
    pub fn supply_settings(&self) -> SupplyChainSettings {
        let mut settings = SupplyChainSettings::from_policy(
            &self.policy,
            FetchSandbox {
                image: image(),
                limits: limits_for_fetch(),
                env: factory_ports::sandbox::FixedEnv::new(vec![(
                    "HOME".to_owned(),
                    "/home/agent".to_owned(),
                )])
                .expect("an environment"),
                hardening: Hardening::strict(10_001, 10_001),
                caches: Vec::new(),
                sidecar: "sidecar-fixture".to_owned(),
                arch: "arm64".to_owned(),
            },
            LicensePolicy::owner_approved(),
            PopularNames::bundled().expect("the bundled list"),
            SbomRule {
                required: false,
                tool: SbomTool::default(),
            },
        );
        if let Some(change) = *self
            .supply_tweak
            .lock()
            .expect("the lock is never poisoned")
        {
            change(&mut settings);
        }
        settings
    }

    /// Changes the settings of the dependency gates after they were built from policy.
    pub fn tweak_supply(&self, change: fn(&mut SupplyChainSettings)) {
        *self
            .supply_tweak
            .lock()
            .expect("the lock is never poisoned") = Some(change);
    }

    pub fn config(&self) -> ValidationConfig {
        let limits = limits_for_verify();
        ValidationConfig {
            policy: self.policy.clone(),
            path_rules: fixture_rules(),
            holdouts: vec![RepoGlob::new("tests/holdout/**").expect("a glob")],
            redactor: self.redactor.clone(),
            sandbox: VerifySandbox {
                image: image(),
                limits,
                env: factory_ports::sandbox::FixedEnv::new(vec![(
                    "HOME".to_owned(),
                    "/home/agent".to_owned(),
                )])
                .expect("an environment"),
                hardening: Hardening::strict(10_001, 10_001),
                caches: Vec::new(),
                arch: "arm64".to_owned(),
            },
            manifest: Arc::new(JsonManifestReader),
            flaky_registry: BTreeSet::new(),
            bounds: Bounds::default(),
            supply_chain: SupplyChainSeams {
                settings: self.supply_settings(),
                approvals: self.approvals.clone(),
                registry: self.packages.clone(),
                advisory_db: self.database.clone(),
            },
        }
    }

    pub fn handler(&self) -> ValidationHandler {
        ValidationHandler::new(Arc::new(self.config()))
    }

    pub fn ports(&self) -> StagePorts<'_> {
        StagePorts {
            artifacts: &*self.artifacts,
            sandbox: &*self.sandbox,
            workspaces: &*self.workspaces,
            runtime: &self.runtime,
            router: &self.router,
            registry: &self.registry,
            validator: &self.validator,
            broker: &*self.broker,
            clock: &*self.clock,
            ids: &*self.ids,
        }
    }

    pub fn identity(&self) -> RunIdentity {
        RunIdentity {
            tenant: self.tenant,
            job: self.job,
            correlation: self.correlation,
            stage_run: self.stage_run,
            kind: StageKind::Validation,
        }
    }

    pub async fn store_json(&self, value: &serde_json::Value) -> ArtifactRef {
        self.artifacts
            .put(
                serde_json::to_vec(value).expect("JSON"),
                MediaType::parse("application/json").expect("a media type"),
            )
            .await
            .expect("the artifact is stored")
    }

    /// The upstream runs a validation stage run sees: the implementation result and the frozen
    /// specification.
    pub async fn upstream(&self, base: &CommitSha, head: &CommitSha) -> Vec<UpstreamRun> {
        let result = self
            .store_json(&serde_json::json!({
                "base_commit": base.as_str(),
                "head_commit": head.as_str(),
            }))
            .await;
        let spec: serde_json::Value = serde_json::from_str(SPECIFICATION).expect("a specification");
        let spec = self.store_json(&spec).await;
        vec![
            UpstreamRun {
                id: self.fixture.stage_run(),
                kind: StageKind::Specification,
                status: StageRunStatus::Passed,
                outputs: vec![NamedArtifact {
                    name: Slug::parse("specification-contract").expect("a slug"),
                    artifact: spec,
                }],
            },
            UpstreamRun {
                id: self.fixture.stage_run(),
                kind: StageKind::Implementation,
                status: StageRunStatus::Passed,
                outputs: vec![NamedArtifact {
                    name: Slug::parse("implementation-result").expect("a slug"),
                    artifact: result,
                }],
            },
        ]
    }

    pub fn now(&self) -> Timestamp {
        self.clock.now()
    }

    pub fn resolve_contract(
        &self,
        handler: &ValidationHandler,
        upstream: &[UpstreamRun],
        policy_hash: &Sha256Digest,
    ) -> Result<StageContract, StageError> {
        handler.contract(&ContractContext {
            identity: self.identity(),
            mode: ExecutionMode::Test,
            policy_hash,
            now: self.now(),
            upstream,
            human_inputs: &[],
            request_edited: false,
        })
    }

    /// `execute`, and the storing of its documents the way the engine does it.
    pub async fn execute(
        &self,
        handler: &ValidationHandler,
        contract: &StageContract,
        upstream: &[UpstreamRun],
    ) -> Result<Vec<NamedArtifact>, StageError> {
        let mut ctx = StageContext::new(
            self.identity(),
            self.attempt,
            1,
            LeaseEpoch::NEVER_CLAIMED,
            ExecutionMode::Test,
            contract,
            self.ports(),
            &self.cancel,
            None,
            &[],
            upstream,
        );
        let output = handler.execute(&mut ctx).await?;
        let mut stored = Vec::new();
        for document in &output.documents {
            stored.push(NamedArtifact {
                name: document.name.clone(),
                artifact: self.store_json(&document.value).await,
            });
        }
        stored.extend(output.artifacts.iter().cloned());
        Ok(stored)
    }

    /// `evaluate`, the engine's evidence check and `resolve`.
    pub async fn evaluate(
        &self,
        handler: &ValidationHandler,
        contract: &StageContract,
        outputs: &[NamedArtifact],
        upstream: &[UpstreamRun],
    ) -> Result<Ran, StageError> {
        let gate = GateContext {
            identity: self.identity(),
            attempt: self.attempt,
            mode: ExecutionMode::Test,
            contract,
            ports: self.ports(),
            cancel: &self.cancel,
            outputs,
            human_inputs: &[],
            upstream,
        };
        let decision = handler.evaluate(&gate).await?;
        let problem = check_evidence(
            &decision,
            &Expectation {
                job: self.job,
                stage_run: self.stage_run,
                attempt: self.attempt,
                mode: ExecutionMode::Test,
            },
        )
        .err();
        let resolution = resolve(contract, &decision);
        let stored = outputs
            .iter()
            .find(|output| output.name.as_str() == "validation-evidence")
            .expect("the evidence is stored");
        let bytes = self
            .artifacts
            .get(&TenantScope::new(self.tenant), &stored.artifact)
            .await
            .expect("the evidence is readable");
        Ok(Ran {
            contract: contract.clone(),
            evidence: serde_json::from_slice(&bytes).expect("the evidence is JSON"),
            decision,
            resolution,
            problem,
        })
    }

    /// The whole stage run with the world's own handler.
    pub async fn run(&self, base: &CommitSha, head: &CommitSha) -> Ran {
        let handler = self.handler();
        let upstream = self.upstream(base, head).await;
        let contract = self
            .resolve_contract(&handler, &upstream, &self.policy_hash)
            .expect("the contract resolves");
        let outputs = self
            .execute(&handler, &contract, &upstream)
            .await
            .expect("execute works");
        self.evaluate(&handler, &contract, &outputs, &upstream)
            .await
            .expect("evaluate works")
    }

    /// A fixture project with a base commit and a head commit that changes `changes`.
    pub async fn project(&self, changes: &[(&str, Option<&str>)]) -> (CommitSha, CommitSha) {
        let base = self.push(&base_files()).await;
        let head = self.push(&with(changes)).await;
        (base, head)
    }
}

fn limits_for_verify() -> SandboxLimits {
    SandboxLimits {
        cpu_millis: nz(2000),
        memory_mb: nz(2048),
        memory_swap_mb: nz(2048),
        pids: nz(256),
        nofile: nz(2048),
        max_file_mb: nz(512),
        tmpfs_mb: nz(256),
        workspace_disk_mb: nz(2048),
        wall_clock: std::time::Duration::from_secs(600),
    }
}

/// Within the `fetch_deps` maximum of the sandbox policy fixture, which is lower than `verify`.
fn limits_for_fetch() -> SandboxLimits {
    SandboxLimits {
        cpu_millis: nz(1000),
        memory_mb: nz(1024),
        memory_swap_mb: nz(1024),
        pids: nz(128),
        nofile: nz(2048),
        max_file_mb: nz(512),
        tmpfs_mb: nz(256),
        workspace_disk_mb: nz(2048),
        wall_clock: std::time::Duration::from_secs(600),
    }
}

fn nz(value: u32) -> std::num::NonZeroU32 {
    std::num::NonZeroU32::new(value).expect("a non-zero value")
}
