//! The rig of the full run: one `word-count` job through every stage of Slice 1 with the real
//! handler of each stage, on a real PostgreSQL, behind the real API server on loopback.
//!
//! # What is real
//!
//! PostgreSQL (the API login on the server, the worker and engine logins on the worker side), the
//! API server and its bearer tokens (read from files the way a command line client would), the
//! signed webhook, the allowlist and the policy files, the engine, the step before each claim
//! (`ClaimWork`), the approval service with its judge, the evidence ledger, all thirteen stage
//! handlers, and every seam of the composition library.
//!
//! # What is scripted, and labelled
//!
//! * The agents: the playbook (`playbook/`), played by a runtime that reports itself as a fake.
//! * The sandbox: the testkit's fake sandbox. Its programs are `cargo` (the recorded output of a
//!   real run of the patched fixture), the tool itself (`--help` and `--version`, recorded) and
//!   the four small file programs the specification stage runs. **Every stage that runs a command
//!   in a sandbox used this fake**: `REPOSITORY_INTELLIGENCE`, `SPECIFICATION`, `VALIDATION` and
//!   `DOCUMENTATION_REVIEW`. The agent stages run the playbook in a sandbox too.
//! * The workspaces and the change host: the testkit's fakes over the files of the fixture.
//! * The model broker, and the supply chain's registry, advisory database and recorded approvals
//!   (the patch changes no dependency, so the supply chain gate does not apply).
//!
//! # Where the worker loop is
//!
//! A few lines here, not `factory_worker::run::WorkerLoop`: the rules of the workspace (`DEP-01`)
//! refuse an edge from one application to another, so a test of the API cannot link the worker.
//! The loop is tested in `apps/worker/tests`.

#![allow(dead_code)]

mod gitshape;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use factory_composition::authority::StoreAuthority;
use factory_composition::decisions::{ClaimWork, DecisionMarkers};
use factory_composition::delivery::{StoreApprovalSources, StoreDeliverySources};
use factory_composition::drift::DriftPump;
use factory_composition::indexing::{ActiveJobs, IndexingSandbox, IndexingWorkspaces};
use factory_composition::preflight::{BypassAttestations, ProtectionPreflight};
use factory_composition::sandbox_specs::sandbox_policy_from;
use factory_composition::seams::{CachedProbes, FileAllowlist, StoreRequests};
use factory_composition::startup::{LoadedPolicies, load_policy};
use factory_composition::system::{RandomIds, SystemClock};
use factory_domain::ids::{JobId, StageRunId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, StageRunStatus, Status};
use factory_domain::values::{GitSha, Sha256Digest, Timestamp};
use factory_domain::vocabulary::{ExecutionMode, StageKind};
use factory_ports::clock::IdGenerator;
use factory_ports::githost::{ActorLogin, GithubActor, IssueRef};
use factory_ports::paths::{BranchName, RepoRef};
use factory_ports::store::{AuditFilter, Store};
use factory_sandbox::container::images::ImageCatalog;
use factory_storage::artifact_fs::LocalFsArtifactStore;
use factory_testkit::agent::FakeAgentRuntime;
use factory_testkit::broker::FakeModelBroker;
use factory_testkit::clock::FakeClock;
use factory_testkit::contracts::githost::IssueSourceSubject;
use factory_testkit::githost::{FakeChangeHost, FakeIssueSource};
use factory_testkit::router::{RouteRule, StaticModelRouter};
use factory_testkit::sandbox::{FakeSandbox, ProgramOutput};
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use factory_workflow::engine::{Engine, JobView};
use factory_workflow::handlers::StageHandler;
use serde_json::json;

use crate::cargo::{CargoScript, TestRun};
use crate::playbook::{Playbook, PlaybookRuntime};
use crate::support::{Env, Req, small_pool};

pub const LABEL: &str = "factory";
pub const ISSUE: u64 = 12;

pub fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// The files of `fixtures/repos/word-count`, plus what the specification stage needs the
/// repository to hold: the Spec Kit installation and the constitution a person owns. The fixture
/// directory is never edited; this is the copy of the test.
pub fn fixture_files(playbook: &Playbook) -> Vec<(String, String)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("the fixture is readable")
            .map(|entry| entry.expect("an entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(root, &path, out);
            } else if let Ok(text) = std::fs::read_to_string(&path) {
                let relative = path.strip_prefix(root).expect("inside the root");
                out.push((relative.to_string_lossy().into_owned(), text));
            }
        }
    }
    let base = root().join("fixtures/repos/word-count");
    let mut files = Vec::new();
    walk(&base, &base, &mut files);
    for (path, bytes) in factory_composition::providers::spec_kit_installation(&root())
        .expect("the Spec Kit installation of this repository")
    {
        files.push((
            path,
            String::from_utf8(bytes).expect("the installation files are text"),
        ));
    }
    files.push((
        ".specify/memory/constitution.md".to_owned(),
        playbook.constitution(),
    ));
    files
}

/// Wraps a real handler and prints what it returns, so a failure says which call of which stage
/// ended it. It changes nothing the handler does.
struct Traced(Arc<dyn StageHandler>);

#[async_trait::async_trait]
impl StageHandler for Traced {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        self.0.fidelity()
    }

    fn kind(&self) -> StageKind {
        self.0.kind()
    }

    fn applicability(
        &self,
        ctx: &factory_workflow::handlers::ContractContext<'_>,
    ) -> factory_workflow::handlers::Applicability {
        self.0.applicability(ctx)
    }

    fn routing_need(
        &self,
        ctx: &factory_workflow::handlers::ContractContext<'_>,
    ) -> Option<factory_ports::agent::RoutingNeed> {
        self.0.routing_need(ctx)
    }

    fn contract(
        &self,
        ctx: &factory_workflow::handlers::ContractContext<'_>,
    ) -> Result<factory_domain::contracts::StageContract, factory_workflow::handlers::StageError>
    {
        self.0.contract(ctx)
    }

    async fn execute(
        &self,
        ctx: &mut factory_workflow::handlers::StageContext<'_>,
    ) -> Result<factory_workflow::handlers::StageOutput, factory_workflow::handlers::StageError>
    {
        let result = self.0.execute(ctx).await;
        if let Err(error) = &result {
            println!("TRACE {:?} execute: {error:?}", self.kind());
        }
        result
    }

    async fn evaluate(
        &self,
        ctx: &factory_workflow::handlers::GateContext<'_>,
    ) -> Result<
        factory_workflow::gates::framework::GateDecision,
        factory_workflow::handlers::StageError,
    > {
        let result = self.0.evaluate(ctx).await;
        if let Err(error) = &result {
            println!("TRACE {:?} evaluate: {error:?}", self.kind());
        }
        result
    }
}

/// A real handler whose output a test changes on the way to the engine: how a deliberate break
/// puts a stage that stores a deliverable under another name, or leaves one out, into the real
/// pipeline.
pub struct Tamper {
    pub inner: Arc<dyn StageHandler>,
    pub change: Box<
        dyn Fn(factory_workflow::handlers::StageOutput) -> factory_workflow::handlers::StageOutput
            + Send
            + Sync,
    >,
}

#[async_trait::async_trait]
impl StageHandler for Tamper {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        self.inner.fidelity()
    }

    fn kind(&self) -> StageKind {
        self.inner.kind()
    }

    fn applicability(
        &self,
        ctx: &factory_workflow::handlers::ContractContext<'_>,
    ) -> factory_workflow::handlers::Applicability {
        self.inner.applicability(ctx)
    }

    fn routing_need(
        &self,
        ctx: &factory_workflow::handlers::ContractContext<'_>,
    ) -> Option<factory_ports::agent::RoutingNeed> {
        self.inner.routing_need(ctx)
    }

    fn contract(
        &self,
        ctx: &factory_workflow::handlers::ContractContext<'_>,
    ) -> Result<factory_domain::contracts::StageContract, factory_workflow::handlers::StageError>
    {
        self.inner.contract(ctx)
    }

    async fn execute(
        &self,
        ctx: &mut factory_workflow::handlers::StageContext<'_>,
    ) -> Result<factory_workflow::handlers::StageOutput, factory_workflow::handlers::StageError>
    {
        self.inner
            .execute(ctx)
            .await
            .map(|output| (self.change)(output))
    }

    async fn evaluate(
        &self,
        ctx: &factory_workflow::handlers::GateContext<'_>,
    ) -> Result<
        factory_workflow::gates::framework::GateDecision,
        factory_workflow::handlers::StageError,
    > {
        self.inner.evaluate(ctx).await
    }
}

/// What a stage run took, for the report.
#[derive(Debug, Clone)]
pub struct Timed {
    pub kind: StageKind,
    pub outcome: String,
    pub took: Duration,
}

/// The worker side of the run.
pub struct Rig {
    pub env: Env,
    pub engine: Arc<Engine>,
    pub requests: Arc<StoreRequests>,
    pub hook: Arc<ClaimWork>,
    pub pump: Arc<DriftPump>,
    pub store: Arc<dyn Store>,
    pub artifacts: Arc<dyn factory_ports::artifact::ArtifactStore>,
    pub tenant: TenantId,
    pub host: Arc<FakeChangeHost>,
    pub issues: Arc<FakeIssueSource>,
    pub remote: FakeRemote,
    pub workspaces: Arc<FakeWorkspaceProvider>,
    pub playbook: Arc<Playbook>,
    pub cargo: Arc<CargoScript>,
    pub repo: RepoRef,
    pub policies: LoadedPolicies,
    pub handlers: Vec<(StageKind, factory_domain::vocabulary::Fidelity)>,
    pub timings: Mutex<Vec<Timed>>,
    pub scratch: PathBuf,
    pub base_files: Vec<(String, String)>,
    pub runtime: Arc<PlaybookRuntime>,
    pub jobs: Arc<ActiveJobs>,
    pub approvals: Arc<StoreApprovalSources>,
    pub preflight: Arc<ProtectionPreflight>,
    pub delivery: Arc<StoreDeliverySources>,
    pub spec_drafts: Arc<factory_composition::specs::StoreSpecDrafts>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

/// What a test does to the handler of a stage before it is registered: the way a deliberate break
/// puts a defective stage in the real pipeline.
pub type Wrap = Box<dyn Fn(Arc<dyn StageHandler>) -> Arc<dyn StageHandler>>;

/// Changes the rig builds with. The defaults are the honest run.
#[derive(Default)]
pub struct Options {
    /// Keeps the marker writer of the hook (a stop before the marker).
    pub markers: Option<Arc<dyn DecisionMarkers>>,
    /// Handlers to wrap, by stage. A break only.
    pub wrap: Vec<(StageKind, Wrap)>,
    /// The agent the review stage runs, when it is not the code reviewer. A break only.
    pub review_agent: Option<&'static str>,
    /// Files added to the base commit of the repository, as `(path, text)`. The canary run plants
    /// its secrets here.
    pub extra_files: Vec<(String, String)>,
}

fn nonzero(text: &str) -> GitSha {
    GitSha::parse(text).expect("a commit")
}

impl Rig {
    pub async fn start(env: Env, options: Options) -> Self {
        let ids = RandomIds::new().expect("random");
        let tenant = env.a.id;
        let repo = RepoRef::parse(&env.a.full_name).expect("a repository");
        let policies = load_policy(&root(), &[]).expect("the real policies load");
        let redactor = Arc::new(
            factory_composition::redaction::redactor_from_policy(&policies.security)
                .expect("redactor"),
        );
        // Not under the system temporary directory: see the worker README, mismatch 2.
        let scratch = root()
            .join("target/full-run")
            .join(ids.new_uuid().simple().to_string());
        std::fs::create_dir_all(&scratch).expect("a scratch directory");

        // The worker's own pools over the same database the API serves.
        let logins = env.db.server.logins().await;
        let store = Arc::new(
            factory_storage::pg::PgStore::connect(factory_composition::database::pools(
                small_pool(env.db.url(&logins.worker)),
                small_pool(env.db.url(&logins.engine)),
            ))
            .await
            .expect("the worker store becomes ready"),
        );
        let store_dyn: Arc<dyn Store> = store.clone();
        let artifacts: Arc<dyn factory_ports::artifact::ArtifactStore> = Arc::new(
            LocalFsArtifactStore::open(scratch.join("artifacts"), 64 * 1024 * 1024, store.clone())
                .expect("the artifact root opens"),
        );
        let fake_clock = Arc::new(FakeClock::new());
        let allowlist = Arc::new(FileAllowlist::in_checkout(&env.checkout));
        let _authority = Arc::new(StoreAuthority::new(
            store_dyn.clone(),
            allowlist.clone(),
            Arc::clone(&policies.engine),
            Arc::new(SystemClock),
        ));

        // The playbook, and the repository the fake code host and the fake workspaces share.
        let playbook = Playbook::word_count(&root());
        let remote = FakeRemote::new();
        let mut base_files = fixture_files(&playbook);
        base_files.extend(options.extra_files.clone());
        let borrowed: Vec<(&str, &str)> = base_files
            .iter()
            .map(|(p, c)| (p.as_str(), c.as_str()))
            .collect();
        remote.commit_on_branch(&repo, &BranchName::new("main").expect("main"), &borrowed);
        let host = Arc::new(FakeChangeHost::sharing(remote.clone()));

        // The issue the webhook names, with its text and its label.
        let issues = Arc::new(FakeIssueSource::new());
        let issue_ref = IssueRef {
            repo: repo.clone(),
            number: ISSUE,
        };
        let now = Timestamp::parse("2026-10-28T10:00:00Z").expect("a time");
        let requester = GithubActor {
            id: env.a.requester.github_id,
            login: ActorLogin::new("requester-one").expect("a login"),
        };
        issues.put_issue(factory_ports::githost::Issue {
            reference: issue_ref.clone(),
            title: "Add a --json flag".to_owned(),
            body: "Please add a --json flag to the word count tool so other programs can read the counts."
                .to_owned(),
            author: requester.clone(),
            labels: vec![LABEL.to_owned()],
            updated_at: now,
            fetched_at: now,
        });
        issues.seed_label(&issue_ref, LABEL, &requester).await;

        // The fake workspace provider, shared by the engine and the playbook runtime.
        let workspaces = Arc::new(FakeWorkspaceProvider::new(
            repo.clone(),
            remote.clone(),
            artifacts.clone(),
            factory_testkit::contracts::workspace::fixture_rules(),
        ));
        let runtime = Arc::new(PlaybookRuntime::new(
            FakeAgentRuntime::new(artifacts.clone()),
            playbook.clone(),
            workspaces.clone(),
        ));

        // The sandbox: the fake, with the programs of the verify image and of the specification
        // stage. The output of `cargo` and of the tool is what a real run of the patched
        // fixture printed.
        let derived = sandbox_policy_from(&policies.security, true).expect("limits fit");
        let catalog_json = std::fs::read_to_string(root().join("infra/sandbox-images/images.json"))
            .expect("the catalog");
        let _catalog = ImageCatalog::from_json(&catalog_json, "linux/arm64").expect("a catalog");
        let cargo = CargoScript::new();
        // The runs of `cargo test`, in the order the stages ask: the baseline of repository
        // intelligence, then the head and the baseline of validation.
        let recorded = |name: &str| playbook.recorded(name);
        let head = TestRun {
            stdout: recorded("cargo-test.head.stdout"),
            stderr: recorded("cargo-test.head.stderr"),
            exit: 0,
        };
        let base = TestRun {
            stdout: recorded("cargo-test.base.stdout"),
            stderr: recorded("cargo-test.base.stderr"),
            exit: 0,
        };
        cargo.queue_test_run(base.clone());
        cargo.queue_test_run(head);
        cargo.queue_test_run(base);
        let mut sandbox = cargo.install(FakeSandbox::new(
            fake_clock.clone(),
            artifacts.clone(),
            derived,
        ));
        let help = playbook.recorded("word-count--help.txt");
        let version = playbook.recorded("word-count--version.txt");
        sandbox = sandbox.with_program("word-count", move |argv: &[String], _: &[u8]| {
            match argv.get(1).map(String::as_str) {
                Some("--help") => ProgramOutput {
                    exit_code: Some(0),
                    stdout: help.clone().into_bytes(),
                    stderr: Vec::new(),
                },
                Some("--version") => ProgramOutput {
                    exit_code: Some(0),
                    stdout: version.clone().into_bytes(),
                    stderr: Vec::new(),
                },
                other => ProgramOutput {
                    exit_code: Some(2),
                    stdout: Vec::new(),
                    stderr: format!("the scripted word-count does not run {other:?}\n")
                        .into_bytes(),
                },
            }
        });
        // The small file programs the specification stage runs in the sandbox. A stand-in: they
        // succeed and change nothing, because the files the skills write are written into the
        // checkout by the playbook runtime.
        for program in ["mkdir", "tee", "rm", "cp"] {
            sandbox = sandbox.with_program(program, |_: &[String], _: &[u8]| ProgramOutput {
                exit_code: Some(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
        }

        let broker = Arc::new(FakeModelBroker::new(
            fake_clock.clone(),
            Arc::new(RandomIds::new().expect("random")),
        ));
        let catalog_text = std::fs::read_to_string(root().join("infra/sandbox-images/images.json"))
            .expect("the catalog");
        let probes = Arc::new(CachedProbes::new(factory_ports::agent::ProbedCapabilities(
            BTreeMap::from([(
                factory_ports::agent::RuntimeId::new("fake").expect("a runtime"),
                factory_testkit::router::probe_of(&[
                    factory_ports::agent::Capability::JsonSchemaOutput,
                    factory_ports::agent::Capability::HeadlessMultiTurn,
                    factory_ports::agent::Capability::SkillInvocation,
                ]),
            )]),
        )));
        let jobs = Arc::new(ActiveJobs::new());
        // The fake exports a patch no reader can parse (see `gitshape`); the stages need the shape
        // of `git diff`, so the repository it hands out is wrapped, and the indexing wrapper of
        // the worker goes over that.
        let indexed_workspaces = Arc::new(IndexingWorkspaces::new(
            Arc::new(gitshape::GitShapedWorkspaces {
                inner: workspaces.clone(),
                artifacts: artifacts.clone(),
            }),
            store_dyn.clone(),
            jobs.clone(),
        ));
        // The sandbox and the workspaces index what they write for the tenant, as the providers of
        // the worker do (`providers::assemble`), so a stage can read it back.
        let providers = factory_composition::providers::Providers {
            process: factory_composition::providers::system_runner(),
            sandbox: Arc::new(IndexingSandbox::new(
                Arc::new(sandbox),
                store_dyn.clone(),
                jobs.clone(),
            )),
            workspaces: indexed_workspaces.clone(),
            specification: factory_composition::providers::spec_kit_provider(
                &root(),
                ExecutionMode::Test,
            )
            .expect("the Spec Kit provider"),
        };

        // The protection of the repository, as the code host reports it. A stand-in, labelled: the
        // code host is the testkit's fake.
        issues
            .seed_protection(
                &repo,
                factory_ports::githost::ProtectionReport {
                    default_branch: BranchName::new("main").expect("main"),
                    source: factory_ports::githost::ProtectionSource::Rulesets,
                    requires_pull_request: true,
                    requires_code_owner_review: true,
                    dismisses_stale_approvals: true,
                    blocks_force_push: true,
                    blocks_deletion: true,
                    // The two checks the delivery stage publishes, both pinned to the App.
                    required_checks: ["factory-validation", "factory-review"]
                        .iter()
                        .map(|context| factory_ports::githost::RequiredCheck {
                            context: (*context).to_owned(),
                            integration_id: Some(factory_testkit::githost::FAKE_APP_ID.0),
                        })
                        .collect(),
                },
            )
            .await;

        let routes: Vec<RouteRule> = StageKind::ALL
            .iter()
            .map(|kind| RouteRule {
                stage: *kind,
                tier: factory_domain::contracts::agent_manifest::RecommendedTier::Standard,
                model: factory_ports::agent::ModelSelection {
                    runtime: factory_ports::agent::RuntimeId::new("fake").expect("a runtime"),
                    model: factory_domain::values::NonEmptyString::parse("fake-model")
                        .expect("a model"),
                },
                capabilities: Vec::new(),
            })
            .collect();

        // ---- the pipeline, assembled the way the worker assembles it -----------------------
        let mut settings = factory_composition::config::StageSettings {
            label: LABEL.to_owned(),
            definition_commit: Some("1405df66cbe219b0bf6355bc3d60361a8376b6b4".to_owned()),
            ..Default::default()
        };
        if let Some(agent) = options.review_agent {
            settings.agents.reviewer = agent.to_owned();
        }
        let wraps = options.wrap;
        let decorate: factory_composition::pipeline::HandlerDecorator = Box::new(move |handler| {
            let mut handler = handler;
            for (kind, wrap) in &wraps {
                if *kind == handler.kind() {
                    handler = wrap(handler);
                }
            }
            Arc::new(Traced(handler))
        });
        let pipeline = factory_composition::pipeline::assemble_pipeline(
            factory_composition::pipeline::PipelineInputs {
                profile: factory_composition::profile::Profile::Test,
                settings,
                definitions_root: root(),
                policies: policies.clone(),
                redactor: Arc::clone(&redactor),
                store: store_dyn.clone(),
                artifacts: artifacts.clone(),
                clock: Arc::new(SystemClock),
                ids: Arc::new(RandomIds::new().expect("random")),
                providers,
                catalog: ImageCatalog::from_json(&catalog_text, "linux/arm64").expect("a catalog"),
                sandbox_scratch: scratch.join("sandbox"),
                broker,
                external: factory_composition::pipeline::ExternalPorts {
                    runtime: runtime.clone(),
                    router: Arc::new(StaticModelRouter::new(routes)),
                    issues: issues.clone(),
                    changes: host.clone(),
                    probes,
                    supply_chain: factory_composition::pipeline::SupplyChainParts {
                        approvals: Arc::new(NoApprovals),
                        registry: Arc::new(NoRegistry),
                        advisory_db: Arc::new(RecentDatabase),
                    },
                    attestations: Arc::new(OperatorAttests(env.a.operator.principal)),
                    app: factory_testkit::githost::FAKE_APP_ID,
                },
                allowlist: allowlist.clone(),
                tenants: vec![tenant],
                decision_keys: Arc::clone(&env.state.decision_keys),
                tuning: factory_composition::pipeline::Tuning {
                    decorate: Some(decorate),
                    markers: options.markers,
                    engine: Some(Box::new(|config| {
                        config.lease_ttl = Duration::from_secs(30);
                        config.heartbeat_interval = Duration::from_secs(1);
                        config.teardown_grace = Duration::from_secs(2);
                    })),
                },
            },
        )
        .unwrap_or_else(|error| panic!("the pipeline assembles: {error}"));
        let factory_composition::pipeline::Pipeline {
            engine,
            handlers: fidelity,
            hook,
            preflight,
            requests,
            drift: pump,
            delivery,
            approvals: approvals_for_rig,
            spec_drafts,
            ..
        } = pipeline;
        Self {
            env,
            engine,
            requests,
            hook,
            pump,
            store: store_dyn,
            artifacts,
            tenant,
            host,
            issues,
            remote,
            workspaces,
            playbook,
            cargo,
            repo,
            policies,
            handlers: fidelity,
            timings: Mutex::new(Vec::new()),
            scratch,
            base_files,
            runtime,
            jobs,
            approvals: approvals_for_rig,
            preflight,
            delivery,
            spec_drafts,
        }
    }

    /// The loop of a worker, as a few lines: the request cache, the step before the claim, the
    /// claim, the attempt (with the drift pump served next to it). Returns the view when `done`
    /// holds or the time is up.
    pub async fn drive(
        &self,
        job: Option<JobId>,
        seconds: u64,
        done: impl Fn(&JobView) -> bool,
    ) -> Option<JobView> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
        let worker = factory_ports::store::WorkerId::new("worker-full-run").expect("a worker id");
        loop {
            let _ = self.requests.refresh(&[self.tenant]).await;
            self.preflight.pass(self.tenant).await;
            self.hook.pass(self.tenant).await;
            let _ = self.engine.sweep().await;
            let claimed = self.engine.claim_next(&worker).await.expect("a claim");
            for attempt in claimed.started {
                let started = Instant::now();
                self.jobs.enter(attempt.job, attempt.tenant);
                self.jobs.enter_attempt(attempt.attempt, attempt.tenant);
                let outcome = {
                    let attempt_run = self.engine.run_attempt(&attempt);
                    tokio::pin!(attempt_run);
                    loop {
                        tokio::select! {
                            outcome = &mut attempt_run => break outcome,
                            _ = self.pump.serve_next(&self.engine) => {}
                        }
                    }
                };
                self.jobs.leave(attempt.job);
                self.jobs.leave_attempt(attempt.attempt);
                println!("RUN {:?} {:?}", attempt.kind, outcome);
                self.timings
                    .lock()
                    .expect("the lock is never poisoned")
                    .push(Timed {
                        kind: attempt.kind,
                        outcome: format!("{outcome:?}"),
                        took: started.elapsed(),
                    });
            }
            if let Some(job) = job
                && let Ok(view) = self.engine.job_view(self.tenant, job).await
                && done(&view)
            {
                return Some(view);
            }
            if tokio::time::Instant::now() > deadline {
                return match job {
                    Some(job) => self.engine.job_view(self.tenant, job).await.ok(),
                    None => None,
                };
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// The administrator's statement that the App is on no bypass list: a stand-in, by the operator of
/// the tenant. The production source of the statement is not decided (`preflight.rs`).
struct OperatorAttests(factory_domain::ids::PrincipalId);

#[async_trait::async_trait]
impl BypassAttestations for OperatorAttests {
    async fn attestation(
        &self,
        _: TenantId,
        _: &RepoRef,
    ) -> Option<factory_ports::githost::BypassAttestation> {
        Some(factory_ports::githost::BypassAttestation {
            by: self.0,
            at: Timestamp::parse("2026-10-28T09:00:00Z").expect("a time"),
        })
    }
}

// ---- the three seams of the validation stage's supply chain that have no adapter yet --------

/// No dependency was approved by a person. The patch adds none, so nothing asks.
struct NoApprovals;

#[async_trait::async_trait]
impl factory_workflow::gates::supply_chain::approval::RecordedApprovals for NoApprovals {
    async fn for_job(
        &self,
        _tenant: TenantId,
        _job: JobId,
    ) -> Vec<factory_workflow::gates::supply_chain::approval::DependencyApproval> {
        Vec::new()
    }
}

/// A registry that knows no package. The patch adds none, so nothing asks.
struct NoRegistry;

#[async_trait::async_trait]
impl factory_workflow::gates::supply_chain::facts::RegistryMetadata for NoRegistry {
    async fn lookup(
        &self,
        _name: &str,
        _version: &str,
    ) -> factory_workflow::gates::supply_chain::facts::RegistryRecord {
        factory_workflow::gates::supply_chain::facts::RegistryRecord::default()
    }
}

/// An advisory database that was updated a day ago.
struct RecentDatabase;

#[async_trait::async_trait]
impl factory_workflow::gates::supply_chain::facts::AdvisoryDatabase for RecentDatabase {
    async fn updated_at(&self) -> Option<Timestamp> {
        Some(Timestamp::parse("2026-10-27T00:00:00Z").expect("a time"))
    }
}

// ---- the API side ----------------------------------------------------------------------------

/// The token of a person, written to a file as an operator would keep it and read back the way a
/// command line client reads it.
pub fn token_from_file(env: &Env, name: &str, token: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    let path = env.checkout.join(format!("{name}.token"));
    std::fs::write(&path, token).expect("the token file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    std::fs::read_to_string(&path)
        .expect("the token file is readable")
        .trim()
        .to_owned()
}

/// The signed webhook that says a person labelled the issue. It carries no text.
pub async fn label_the_issue(env: &Env) {
    let body = serde_json::to_vec(&json!({
        "action": "labeled",
        "installation": {"id": env.a.installation},
        "repository": {"id": env.a.github_repository, "full_name": env.a.full_name},
        "sender": {"id": env.a.requester.github_id, "login": "requester-one", "type": "User"},
        "issue": {"number": ISSUE, "node_id": "I_12", "updated_at": "2026-10-28T10:00:00Z"},
        "label": {"name": LABEL},
    }))
    .expect("json");
    let reply = env
        .send(env.delivery("issues", "0190a3b2-7c4d-4e5f-8a6b-000000000001", &body))
        .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
}

/// The job the requester sees in the listing.
pub async fn job_of(env: &Env, token: &str) -> JobId {
    let reply = env.send(Req::get("/v1/jobs").bearer(token)).await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    let body = reply.json();
    let first = body["jobs"][0]["job_id"]
        .as_str()
        .or_else(|| body["jobs"][0]["id"].as_str())
        .unwrap_or_else(|| panic!("the listing names a job: {body}"));
    JobId::parse(first).expect("a job id")
}

/// `POST /v1/jobs/{id}/decisions` as a person.
pub async fn decide(
    env: &Env,
    token: &str,
    job: JobId,
    key: &str,
    decision: serde_json::Value,
) -> crate::support::Reply {
    env.send(
        Req::post(&format!("/v1/jobs/{job}/decisions"))
            .bearer(token)
            .header("Idempotency-Key", key)
            .json(&decision),
    )
    .await
}

/// The actions of the audit records of a job that start with `prefix`, from the timeline the API
/// serves.
pub async fn timeline_actions(env: &Env, token: &str, job: JobId, prefix: &str) -> Vec<String> {
    let reply = env
        .send(Req::get(&format!("/v1/jobs/{job}/timeline")).bearer(token))
        .await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    reply.json()["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter(|entry| entry["kind"] == "audit")
        .filter_map(|entry| entry["action"].as_str().map(str::to_owned))
        .filter(|action| action.starts_with(prefix))
        .collect()
}

pub async fn count_audit(rig: &Rig, job: JobId, action: &str) -> usize {
    let mut tx = rig
        .store
        .begin(TenantScope::new(rig.tenant))
        .await
        .expect("a tx");
    let audit = tx
        .read_audit(AuditFilter::Job(job), 0, 2000)
        .await
        .expect("audit");
    let _ = tx.rollback().await;
    audit
        .iter()
        .filter(|record| record.event.action.as_str() == action)
        .count()
}

pub fn print_states(label: &str, view: &JobView) {
    println!("FULL-RUN {label}: job {:?}", view.status);
    for run in &view.stage_runs {
        println!(
            "FULL-RUN   {:?} #{}: {:?} after {} attempt(s)",
            run.kind,
            run.id.as_text(),
            run.status,
            run.attempts.len()
        );
    }
}

/// True when the job waits for a person, ended, or has a stage run that stopped for good.
pub fn stopped(view: &JobView) -> bool {
    view.status == JobStatus::WaitingForHuman
        || view.status.is_terminal()
        || view
            .stage_runs
            .iter()
            .any(|run| matches!(run.status, StageRunStatus::Blocked | StageRunStatus::Failed))
}

impl Rig {
    /// Every prompt an agent was given.
    pub fn runtime_prompts(&self) -> Vec<String> {
        self.runtime.prompts()
    }

    /// Every audit record of the tenant, as one text.
    pub async fn audit_text(&self, _job: JobId) -> String {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let records = tx
            .read_audit(AuditFilter::Tenant, 0, 5000)
            .await
            .expect("audit");
        let _ = tx.rollback().await;
        records
            .iter()
            .map(|record| {
                format!(
                    "{} {} {} {}",
                    record.event.action.as_str(),
                    record.event.subject,
                    record.event.reason,
                    format_args!("{:?}", record.event.actor)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Stops the API server and removes the checkout. The database goes with the test.
    pub fn finish(&self) {
        self.env.shutdown.raise();
        let _ = std::fs::remove_dir_all(&self.env.checkout);
    }

    /// The identity of a stage run, as a handler or a seam is given it.
    pub async fn identity(
        &self,
        job: JobId,
        stage_run: StageRunId,
        kind: StageKind,
    ) -> factory_workflow::handlers::RunIdentity {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let correlation = tx.get_job(job).await.expect("a job").value.correlation_id;
        let _ = tx.rollback().await;
        factory_workflow::handlers::RunIdentity {
            tenant: self.tenant,
            job,
            correlation,
            stage_run,
            kind,
        }
    }

    /// The head of the job's evidence ledger: what a person looking at the job now has seen.
    pub async fn ledger_head(
        &self,
        job: JobId,
        kind: StageKind,
        stage_run: StageRunId,
    ) -> Sha256Digest {
        use factory_workflow::stages::delivery::DeliverySources as _;
        let identity = self.identity(job, stage_run, kind).await;
        self.delivery
            .ledger(&identity)
            .await
            .expect("the ledger verifies and is read")
            .head_hash
    }

    /// The commit of the specification draft the stage kept for a person to read.
    pub async fn spec_draft_commit(&self, job: JobId, stage_run: StageRunId) -> String {
        use factory_workflow::stages::specification::SpecDrafts as _;
        let identity = self
            .identity(job, stage_run, StageKind::Specification)
            .await;
        self.spec_drafts
            .load(&identity)
            .await
            .expect("the draft is readable")
            .expect("the stage kept a draft")
            .commit
            .as_str()
            .to_owned()
    }

    /// What a stopped job left, for the person reading a failure: the audit records, and the
    /// documents each stage run stored (cut short).
    pub async fn dump(&self, job: JobId) {
        let scope = TenantScope::new(self.tenant);
        let mut tx = self.store.begin(scope).await.expect("a tx");
        let audit = tx
            .read_audit(AuditFilter::Job(job), 0, 2000)
            .await
            .expect("audit");
        let runs = tx.list_stage_runs(job).await.expect("stage runs");
        let mut links = Vec::new();
        for run in &runs {
            let found = tx
                .list_stage_run_artifacts(run.value.id)
                .await
                .expect("links");
            links.push((
                run.value.kind,
                run.value.status,
                found,
                run.value.gate.clone(),
            ));
        }
        let _ = tx.rollback().await;
        for record in &audit {
            println!(
                "AUDIT {} {} | {} | {}",
                record.sequence,
                record.event.action.as_str(),
                record.event.subject,
                record.event.reason
            );
        }
        for (kind, status, found, gate) in links {
            println!("STAGE {kind:?} {status:?}");
            if let Some(record) = gate {
                println!("  GATE {:?} {:?}", record.outcome, record.report_sha256);
                if let Some(hash) = record.report_sha256 {
                    let reference = factory_domain::contracts::ArtifactRef {
                        sha256: hash,
                        media_type: factory_domain::values::MediaType::parse("application/json")
                            .expect("a media type"),
                        size_bytes: None,
                    };
                    if let Ok(bytes) = self.artifacts.get(&scope, &reference).await {
                        let text: String =
                            String::from_utf8_lossy(&bytes).chars().take(4000).collect();
                        println!("  GATE-REPORT {text}");
                    }
                }
            }
            for link in found {
                let reference = factory_domain::contracts::ArtifactRef {
                    sha256: link.sha256.clone(),
                    media_type: factory_domain::values::MediaType::parse("application/json")
                        .expect("a media type"),
                    size_bytes: None,
                };
                let text = match self.artifacts.get(&scope, &reference).await {
                    Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                    Err(error) => format!("(unreadable: {error:?})"),
                };
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text)
                    && let Some(list) = value["transcripts"].as_array()
                {
                    for hash in list.iter().filter_map(|h| h.as_str()) {
                        for media in ["text/plain", "application/json"] {
                            let probe = factory_domain::contracts::ArtifactRef {
                                sha256: Sha256Digest::parse(hash).expect("a hash"),
                                media_type: factory_domain::values::MediaType::parse(media)
                                    .expect("a media type"),
                                size_bytes: None,
                            };
                            let found = self.artifacts.get(&scope, &probe).await;
                            println!(
                                "  TRANSCRIPT {hash} as {media}: {:?}",
                                found.map(|b| b.len())
                            );
                        }
                    }
                }
                let short: String = text.chars().take(1500).collect();
                println!("  {:?} {} => {short}", link.direction, link.role.as_str());
            }
        }
    }
}

/// The ledger of a stage run, newest status first, for the failure messages.
pub fn status_of(view: &JobView, kind: StageKind) -> Option<StageRunStatus> {
    view.newest(kind).map(|run| run.status)
}

pub fn stage_run_of(view: &JobView, kind: StageKind) -> StageRunId {
    view.newest(kind)
        .unwrap_or_else(|| panic!("{kind} has a stage run"))
        .id
}

pub fn job_is(view: &JobView, status: JobStatus) -> bool {
    view.status == status
}

pub fn sha_of(text: &str) -> Sha256Digest {
    Sha256Digest::of(text.as_bytes())
}

/// Prints what a job left when the test fails, so a failure shows why and not only where.
pub struct DumpOnFailure<'a> {
    rig: &'a Rig,
    job: JobId,
}

impl<'a> DumpOnFailure<'a> {
    pub fn new(rig: &'a Rig, job: JobId) -> Self {
        Self { rig, job }
    }
}

impl Drop for DumpOnFailure<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let handle = tokio::runtime::Handle::current();
            tokio::task::block_in_place(|| handle.block_on(self.rig.dump(self.job)));
        }
    }
}
