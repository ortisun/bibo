//! The harness for a whole run of the gate: in-memory ports, a scripted `cargo`, and a recorder
//! that notes every sandbox the gate asks for and every command it runs there.
//!
//! The scripted `cargo` behaves like the real one where it matters to this gate: `fetch` and
//! `metadata` read and download and **never** run a build script; `build`, `test` and the rest
//! run the build script of a hostile package, which writes a marker and tries a connection.
//! Where a command ran (which profile, with or without a network) is known to the program
//! through the recorder, so a marker can be tied to the sandbox it appeared in.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::contracts::gate_report::{DefinitionSource, TrustedDefinition};
use factory_domain::contracts::{ArtifactRef, Contract, GateReport, Violation};
use factory_domain::ids::{AttemptId, JobId, StageRunId, TenantId};
use factory_domain::redaction::{PatternAction, Redactor};
use factory_domain::scope::TenantScope;
use factory_domain::values::{GitSha, MediaType, Sha256Digest, Timestamp};
use factory_domain::vocabulary::{ExecutionMode, Fidelity, GateOutcome};
use factory_ports::artifact::{ArtifactBackend, ArtifactError, ArtifactStore};
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{BranchName, CommitSha, RepoRef};
use factory_ports::registry::{ContractKind, OutputValidator, ValidatedOutput};
use factory_ports::sandbox::ExecArgv;
use factory_ports::sandbox::{
    ExecRequest, ExecResult, FixedEnv, Hardening, NetworkAttachment, PostureReport, SandboxError,
    SandboxId, SandboxLimits, SandboxProfile, SandboxProvider, SandboxSession, SandboxSpec,
    TeardownReason, TeardownReport,
};
use factory_ports::workspace::{FetchCredential, FetchTarget, WorkspaceProvider};
use factory_ports::workspace::{Workspace, WorkspacePurpose, WorkspaceRequest};
use factory_testkit::agent::FakeAgentRuntime;
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::broker::FakeModelBroker;
use factory_testkit::clock::{FakeCancel, FakeClock, SequentialIdGenerator};
use factory_testkit::contracts::workspace::fixture_rules;
use factory_testkit::fixtures::{Ids, image, sandbox_policy};
use factory_testkit::registry::InMemoryAgentRegistry;
use factory_testkit::router::StaticModelRouter;
use factory_testkit::sandbox::{FakeSandbox, ProgramOutput};
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use factory_workflow::gates::command::report::{ReportContext, Subject};
use factory_workflow::gates::supply_chain::approval::DependencyApproval;
use factory_workflow::gates::supply_chain::cargo::CargoFormat;
use factory_workflow::gates::supply_chain::facts::{
    RegistryMetadata, StaticDatabase, StaticRegistry,
};
use factory_workflow::gates::supply_chain::gate::{Done, Inputs, run};
use factory_workflow::gates::supply_chain::licenses::LicensePolicy;
use factory_workflow::gates::supply_chain::model::Side;
use factory_workflow::gates::supply_chain::names::PopularNames;
use factory_workflow::gates::supply_chain::review::Plan;
use factory_workflow::gates::supply_chain::run::{
    Bounds, DEFAULT_ADVISORY_DB_MAX_AGE_DAYS, FetchSandbox, Io, SbomRule, SupplyChainConfig,
};
use factory_workflow::gates::supply_chain::run::{
    Fetched, Scanned, fetch, fetch_spec, scan, verify_spec,
};
use factory_workflow::gates::supply_chain::tools::SbomTool;
use factory_workflow::handlers::{StageError, StagePorts};
use factory_workflow::stages::validation::VerifySandbox;
use serde_json::json;

use super::files::Files;
use super::people::build_engine;
use super::schema_check;

/// Where a command ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Where {
    /// A `fetch_deps` sandbox.
    Fetch,
    /// A `verify` sandbox.
    Verify,
    /// Not through the recorder.
    Elsewhere,
}

/// What the scripted audit prints.
#[derive(Debug, Clone, Copy)]
pub enum AuditScript {
    /// No advisory.
    Clean,
    /// One advisory.
    Found,
    /// Text that is not an audit document.
    Garbage,
    /// Exit code 1 with no document, as the tool does on an error.
    Error,
    /// A clean answer from a tool that was told to ignore an advisory by a configuration file.
    Ignoring,
}

/// What the scripted tools do.
#[derive(Debug, Clone)]
pub struct Script {
    pub audit_present: bool,
    pub audit: AuditScript,
    pub sbom_present: bool,
    pub fetch_exit: i32,
    pub metadata: String,
    /// The packages of the project carry a hostile build script.
    pub hostile: bool,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            audit_present: true,
            audit: AuditScript::Clean,
            sbom_present: false,
            fetch_exit: 0,
            metadata: metadata(&[]),
            hostile: false,
        }
    }
}

/// `cargo metadata` output for these packages: name, version, license, build code.
pub fn metadata(packages: &[(&str, &str, Option<&str>, bool)]) -> String {
    let list: Vec<serde_json::Value> = packages
        .iter()
        .map(|(name, version, license, build)| {
            let kinds = if *build {
                json!([{"kind": ["lib"]}, {"kind": ["custom-build"]}])
            } else {
                json!([{"kind": ["lib"]}])
            };
            json!({"name": name, "version": version, "license": license, "targets": kinds})
        })
        .collect();
    json!({"packages": list, "workspace_members": [], "version": 1}).to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub at: Where,
    pub argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    pub at: Where,
    pub name: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    pub at: Where,
    pub host: &'static str,
    pub reached: bool,
}

/// The scripted programs of the image, and the record of what they did.
pub struct Tools {
    script: Mutex<Script>,
    current: Mutex<Where>,
    network: Mutex<bool>,
    calls: Mutex<Vec<Call>>,
    markers: Mutex<Vec<Marker>>,
    attempts: Mutex<Vec<Attempt>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().expect("the lock is never poisoned")
}

impl Tools {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            script: Mutex::new(Script::default()),
            current: Mutex::new(Where::Elsewhere),
            network: Mutex::new(false),
            calls: Mutex::new(Vec::new()),
            markers: Mutex::new(Vec::new()),
            attempts: Mutex::new(Vec::new()),
        })
    }

    pub fn set(&self, script: Script) {
        *lock(&self.script) = script;
    }

    pub fn calls(&self) -> Vec<Call> {
        lock(&self.calls).clone()
    }

    pub fn calls_at(&self, at: Where) -> Vec<Vec<String>> {
        self.calls()
            .into_iter()
            .filter(|call| call.at == at)
            .map(|call| call.argv)
            .collect()
    }

    pub fn markers(&self) -> Vec<Marker> {
        lock(&self.markers).clone()
    }

    pub fn attempts(&self) -> Vec<Attempt> {
        lock(&self.attempts).clone()
    }

    fn enter(&self, at: Where, network: bool) {
        *lock(&self.current) = at;
        *lock(&self.network) = network;
    }

    fn answer(&self, argv: &[String]) -> ProgramOutput {
        let at = *lock(&self.current);
        lock(&self.calls).push(Call {
            at,
            argv: argv.to_vec(),
        });
        let script = lock(&self.script).clone();
        let text = |code: i32, out: &str| ProgramOutput {
            exit_code: Some(code),
            stdout: out.as_bytes().to_vec(),
            stderr: Vec::new(),
        };
        let word = |index: usize| argv.get(index).map(String::as_str).unwrap_or_default();
        let version = argv.iter().any(|w| w == "--version");
        match (word(0), word(1)) {
            ("cargo", "--version") => text(0, "cargo 1.98.0 (797e8a9bc 2026-08-05)\n"),
            ("cargo", "audit") if version => {
                if script.audit_present {
                    text(0, "cargo-audit-audit 0.22.2\n")
                } else {
                    ProgramOutput {
                        exit_code: Some(101),
                        stdout: Vec::new(),
                        stderr: b"error: no such command: `audit`\n".to_vec(),
                    }
                }
            }
            ("cargo", "sbom") if version => {
                if script.sbom_present {
                    text(0, "cargo-sbom 0.9.1\n")
                } else {
                    ProgramOutput {
                        exit_code: Some(101),
                        stdout: Vec::new(),
                        stderr: b"error: no such command: `sbom`\n".to_vec(),
                    }
                }
            }
            ("cargo", "audit") => match script.audit {
                AuditScript::Clean => text(
                    0,
                    r#"{"database":{},"lockfile":{"dependency-count":3},"settings":{},"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{}}"#,
                ),
                AuditScript::Found => text(
                    1,
                    r#"{"vulnerabilities":{"found":true,"count":1,"list":[{"advisory":{"id":"RUSTSEC-2021-0003","package":"smallvec"},"package":{"name":"smallvec","version":"0.6.9"}}]},"warnings":{}}"#,
                ),
                AuditScript::Garbage => text(0, "audit complete, all good"),
                AuditScript::Error => text(1, ""),
                AuditScript::Ignoring => text(
                    0,
                    r#"{"database":{},"lockfile":{"dependency-count":3},"settings":{"target_arch":[],"target_os":[],"severity":null,"ignore":["RUSTSEC-2020-0001"]},"vulnerabilities":{"found":false,"count":0,"list":[]},"warnings":{}}"#,
                ),
            },
            ("cargo", "sbom") => text(
                0,
                r#"{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"serde"}]}"#,
            ),
            // Reads the manifests and downloads the locked packages. It compiles nothing, so no
            // build script and no procedural macro runs, whatever the packages hold.
            ("cargo", "fetch") => text(script.fetch_exit, "Downloaded 3 packages\n"),
            ("cargo", "metadata") => text(0, &script.metadata),
            // Compiling runs the build script of every package that has one.
            ("cargo", "build" | "check" | "test" | "run" | "clippy" | "doc" | "nextest") => {
                if script.hostile {
                    lock(&self.markers).push(Marker {
                        at,
                        name: "build-rs",
                    });
                    lock(&self.attempts).push(Attempt {
                        at,
                        host: "attacker.test",
                        // The host is on no allow list, and a sandbox without a network reaches
                        // nothing at all.
                        reached: false,
                    });
                }
                text(0, "")
            }
            ("npm" | "pip" | "python", _) => {
                lock(&self.markers).push(Marker {
                    at,
                    name: "install-script",
                });
                text(0, "")
            }
            _ => ProgramOutput {
                exit_code: Some(127),
                stdout: Vec::new(),
                stderr: b"not found\n".to_vec(),
            },
        }
    }

    pub fn install(self: &Arc<Self>, sandbox: FakeSandbox) -> FakeSandbox {
        let programs: [&'static str; 4] = ["cargo", "npm", "pip", "python"];
        programs.into_iter().fold(sandbox, |sandbox, name| {
            let tools = Arc::clone(self);
            sandbox.with_program(name, move |argv, _| tools.answer(argv))
        })
    }
}

/// What a sandbox was created with.
#[derive(Debug, Clone)]
pub struct Created {
    pub profile: SandboxProfile,
    pub network: NetworkAttachment,
    pub job_token: bool,
    pub workspace_read_only: bool,
    pub env_names: Vec<String>,
}

/// Wraps the fake sandbox: records each spec, and tells the scripted tools where a command runs.
pub struct Recorder {
    inner: FakeSandbox,
    tools: Arc<Tools>,
    created: Mutex<Vec<Created>>,
}

impl Recorder {
    pub fn created(&self) -> Vec<Created> {
        lock(&self.created).clone()
    }

    pub fn live(&self) -> usize {
        self.inner.live_sandboxes().len()
    }
}

struct RecordedSession {
    inner: Box<dyn SandboxSession>,
    tools: Arc<Tools>,
    at: Where,
    network: bool,
}

#[async_trait]
impl SandboxProvider for Recorder {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    async fn create_verified(
        &self,
        spec: SandboxSpec,
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn SandboxSession>, SandboxError> {
        let at = match spec.profile {
            SandboxProfile::FetchDeps => Where::Fetch,
            SandboxProfile::Verify => Where::Verify,
            SandboxProfile::Agent => Where::Elsewhere,
        };
        let network = spec.network != NetworkAttachment::None;
        lock(&self.created).push(Created {
            profile: spec.profile,
            network: spec.network.clone(),
            job_token: spec.job_token.is_some(),
            workspace_read_only: spec.mounts.workspace.workspace_read_only,
            env_names: spec
                .env
                .pairs()
                .iter()
                .map(|(name, _)| name.clone())
                .collect(),
        });
        let inner = self.inner.create_verified(spec, cancel).await?;
        Ok(Box::new(RecordedSession {
            inner,
            tools: Arc::clone(&self.tools),
            at,
            network,
        }))
    }

    async fn sweep_orphans(&self, live: &[AttemptId]) -> Result<Vec<SandboxId>, SandboxError> {
        self.inner.sweep_orphans(live).await
    }
}

#[async_trait]
impl SandboxSession for RecordedSession {
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
        self.tools.enter(self.at, self.network);
        self.inner.exec(req, cancel).await
    }

    async fn stop_and_remove(
        self: Box<Self>,
        reason: TeardownReason,
    ) -> Result<TeardownReport, SandboxError> {
        self.inner.stop_and_remove(reason).await
    }
}

/// An artifact store whose contents the test tenant may read, as the composition root provides.
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

/// The result of one run, with the reports found by gate.
pub struct Ran {
    pub done: Done,
}

impl Ran {
    pub fn report(&self, gate: &str) -> &GateReport {
        self.done
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

    pub fn missing(&self, gate: &str) -> String {
        self.report(gate)
            .blocked_reason
            .as_ref()
            .map(|reason| {
                reason
                    .missing
                    .iter()
                    .map(|item| item.as_str().to_owned())
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_default()
    }

    pub fn warning_checks(&self, gate: &str) -> Vec<String> {
        self.report(gate)
            .warnings
            .iter()
            .flatten()
            .map(|warning| warning.check_id.as_str().to_owned())
            .collect()
    }

    pub fn warning_text(&self, gate: &str) -> String {
        self.report(gate)
            .warnings
            .iter()
            .flatten()
            .map(|warning| warning.message.as_str().to_owned())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

pub struct World {
    pub clock: Arc<FakeClock>,
    pub ids: Arc<SequentialIdGenerator>,
    pub artifacts: Arc<Granting>,
    pub remote: FakeRemote,
    pub workspaces: Arc<FakeWorkspaceProvider>,
    pub sandbox: Arc<Recorder>,
    pub tools: Arc<Tools>,
    pub cancel: FakeCancel,
    pub tenant: TenantId,
    pub job: JobId,
    pub stage_run: StageRunId,
    pub attempt: AttemptId,
    pub repo: RepoRef,
    pub branch: BranchName,
    pub redactor: Arc<Redactor>,
    pub sbom_subcommands: Vec<&'static str>,
    database: Mutex<Option<Timestamp>>,
    runtime: FakeAgentRuntime,
    router: StaticModelRouter,
    registry: InMemoryAgentRegistry,
    broker: Arc<FakeModelBroker>,
    validator: SchemaValidator,
}

fn nz(value: u32) -> std::num::NonZeroU32 {
    std::num::NonZeroU32::new(value).expect("a non-zero value")
}

fn limits() -> SandboxLimits {
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

impl World {
    pub fn new() -> Self {
        let fixture = Ids::new();
        // The tenant and the job of the decisions in `people`, so that a recorded decision is for
        // the run the world makes.
        let tenant = super::people::tenant();
        let clock = Arc::new(FakeClock::starting_at("2026-10-28T12:00:00Z"));
        let ids = Arc::new(SequentialIdGenerator::new());
        let artifacts = Arc::new(Granting {
            inner: InMemoryArtifactStore::new(),
            tenant,
        });
        let repo = RepoRef::parse("example-org/app").expect("a repository");
        let remote = FakeRemote::new();
        let workspaces = Arc::new(FakeWorkspaceProvider::new(
            repo.clone(),
            remote.clone(),
            artifacts.clone(),
            fixture_rules(),
        ));
        let tools = Tools::new();
        let sandbox = Arc::new(Recorder {
            inner: tools.install(FakeSandbox::new(
                clock.clone(),
                artifacts.clone(),
                sandbox_policy(),
            )),
            tools: tools.clone(),
            created: Mutex::new(Vec::new()),
        });
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
            branch: BranchName::new("main").expect("a branch"),
            sbom_subcommands: Vec::new(),
            // One day old at the time of the fake clock.
            database: Mutex::new(Some(
                Timestamp::parse("2026-10-27T12:00:00Z").expect("a time"),
            )),
            clock,
            ids,
            artifacts,
            remote,
            workspaces,
            sandbox,
            tools,
            cancel: FakeCancel::new(),
            tenant,
            repo,
            redactor,
        }
    }

    /// Puts a commit with exactly these files on the remote branch and fetches it into the job's
    /// object store.
    pub async fn push(&self, files: &Files) -> CommitSha {
        let pairs: Vec<(&str, &str)> = files
            .iter()
            .map(|(path, text)| (path.as_str(), text.as_str()))
            .collect();
        self.remote
            .commit_on_branch(&self.repo, &self.branch, &pairs);
        self.workspaces
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
            .expect("the fetch works")
            .commit
    }

    pub fn config(&self, sbom_required: bool) -> SupplyChainConfig {
        let env = || {
            FixedEnv::new(vec![("HOME".to_owned(), "/home/agent".to_owned())])
                .expect("an environment")
        };
        SupplyChainConfig {
            policy: Arc::new(build_engine(&self.sbom_subcommands)),
            path_rules: fixture_rules(),
            holdouts: Vec::new(),
            fetch: FetchSandbox {
                image: image(),
                limits: limits(),
                env: env(),
                hardening: Hardening::strict(10_001, 10_001),
                caches: Vec::new(),
                sidecar: "sidecar-fixture".to_owned(),
                arch: "arm64".to_owned(),
            },
            verify: VerifySandbox {
                image: image(),
                limits: limits(),
                env: env(),
                hardening: Hardening::strict(10_001, 10_001),
                caches: Vec::new(),
                arch: "arm64".to_owned(),
            },
            redactor: self.redactor.clone(),
            licenses: LicensePolicy::owner_approved(),
            popular: PopularNames::bundled().expect("the bundled list"),
            internal_names: vec!["acme-billing-core".to_owned()],
            sbom: SbomRule {
                required: sbom_required,
                tool: SbomTool::default(),
            },
            advisory_db_max_age_days: DEFAULT_ADVISORY_DB_MAX_AGE_DAYS,
            bounds: Bounds::default(),
        }
    }

    /// Sets the date of the advisory database the audit reads, or says it is not known.
    pub fn database_updated(&self, at: Option<Timestamp>) {
        *lock(&self.database) = at;
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

    /// Runs the whole gate for a base commit and a candidate.
    pub async fn gate(
        &self,
        base: &Files,
        head: &Files,
        registry: &dyn RegistryMetadata,
        approvals: &[DependencyApproval],
        sbom_required: bool,
    ) -> Result<Ran, StageError> {
        let base_commit = self.push(base).await;
        let head_commit = self.push(head).await;
        let cfg = self.config(sbom_required);
        let io = Io {
            ports: self.ports(),
            scope: TenantScope::new(self.tenant),
            cfg: &cfg,
            cancel: &self.cancel,
            job: self.job,
            attempt: self.attempt,
        };
        let format = CargoFormat;
        let side =
            |files: &Files| Side::of(&format, files.iter().map(|(p, t)| (p.as_str(), t.as_str())));
        let (base_side, head_side) = (side(base), side(head));
        let report = ReportContext {
            subject: Subject {
                job: self.job,
                stage_run: self.stage_run,
                attempt: self.attempt,
                mode: ExecutionMode::Test,
            },
            definition: TrustedDefinition {
                source: DefinitionSource::CentralConfig,
                commit_sha: GitSha::parse(base_commit.as_str()).expect("a sha"),
                definition_sha256: Sha256Digest::of(b"supply chain gate definitions"),
            },
            fidelity: Fidelity::Fake,
            binding: Sha256Digest::of(b"binding"),
        };
        let database = StaticDatabase(*lock(&self.database));
        let policy_hash = super::people::policy_hash();
        let inputs = Inputs {
            format: &format,
            base: &base_side,
            head: &head_side,
            head_commit: &head_commit,
            approvals,
            registry,
            advisory_db: &database,
            policy_hash: &policy_hash,
            report,
        };
        let done = run(&io, &inputs).await?;
        let ran = Ran { done };
        ran.assert_valid();
        Ok(ran)
    }
}

impl Ran {
    /// Every report follows the JSON schema and reads back through the domain type.
    pub fn assert_valid(&self) {
        for report in &self.done.reports {
            let value = serde_json::to_value(report).expect("a report is JSON");
            let schema: serde_json::Value =
                serde_json::from_str(schema_check::SCHEMA).expect("the schema is JSON");
            let problems = schema_check::problems(&schema, &value);
            assert!(
                problems.is_empty(),
                "{}: {problems:?}",
                report.metadata.gate_id
            );
            GateReport::from_json_value(value).expect("a report reads back");
        }
        let gates: BTreeSet<&str> = self
            .done
            .reports
            .iter()
            .map(|r| r.metadata.gate_id.as_str())
            .collect();
        assert_eq!(gates.len(), 4, "one report for each of the four gates");
    }
}

/// A registry table with no entry: nothing is known about any package.
pub fn unknown_registry() -> StaticRegistry {
    StaticRegistry::new()
}

impl World {
    fn io<'a>(&'a self, cfg: &'a SupplyChainConfig) -> Io<'a> {
        Io {
            ports: self.ports(),
            scope: TenantScope::new(self.tenant),
            cfg,
            cancel: &self.cancel,
            job: self.job,
            attempt: self.attempt,
        }
    }

    /// Calls the fetch of the gate directly, with a plan.
    pub async fn fetch_directly(
        &self,
        plan: &Plan,
        commit: &CommitSha,
    ) -> Result<Fetched, StageError> {
        let cfg = self.config(false);
        fetch(&self.io(&cfg), plan, commit).await
    }

    /// Calls the scan of the gate directly, with a plan.
    pub async fn scan_directly(
        &self,
        plan: &Plan,
        commit: &CommitSha,
    ) -> Result<Scanned, StageError> {
        let cfg = self.config(false);
        scan(&self.io(&cfg), plan, commit).await
    }

    /// A session made from the very spec the gate uses for a profile, over a workspace of
    /// `commit`, so that a test can run in it what a hostile project would run.
    pub async fn open(
        &self,
        commit: &CommitSha,
        profile: SandboxProfile,
    ) -> (Box<dyn SandboxSession>, Box<dyn Workspace>) {
        let cfg = self.config(false);
        let workspace = self
            .workspaces
            .create(
                WorkspaceRequest {
                    job: self.job,
                    attempt: self.attempt,
                    base: commit.clone(),
                    protected_base: None,
                    rules: fixture_rules(),
                    purpose: match profile {
                        SandboxProfile::Verify => WorkspacePurpose::Verify {
                            holdouts: Vec::new(),
                        },
                        _ => WorkspacePurpose::Agent,
                    },
                },
                &self.cancel,
            )
            .await
            .expect("a workspace");
        let spec = match profile {
            SandboxProfile::Verify => verify_spec(&cfg, self.job, self.attempt, workspace.mounts()),
            _ => fetch_spec(&cfg, self.job, self.attempt, workspace.mounts()),
        };
        let session = self
            .sandbox
            .create_verified(spec, &self.cancel)
            .await
            .expect("a sandbox");
        (session, workspace)
    }

    /// Runs a command in a session.
    pub async fn exec(
        session: &mut dyn SandboxSession,
        cancel: &dyn CancelSignal,
        words: &[&str],
    ) -> ExecResult {
        let argv = ExecArgv::new(words.iter().map(|w| (*w).to_owned()).collect()).expect("an argv");
        session
            .exec(
                ExecRequest {
                    argv,
                    cwd: None,
                    stdin: None,
                    timeout: std::time::Duration::from_secs(60),
                    max_output_bytes: 1024,
                },
                cancel,
            )
            .await
            .expect("the command ends")
    }
}
