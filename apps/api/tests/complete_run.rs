//! The complete run in test mode: a job from a labelled issue, through every stage of Slice 1, up
//! to the approval, and then a person's approval through the real API to `COMPLETED`.
//!
//! # What is real
//!
//! PostgreSQL (the API login on the server, the worker and engine logins on the worker side), the
//! API server on a loopback port with a bearer token, the signed webhook, the allowlist file and
//! the policy files, the engine, the step before each claim (`ClaimWork`), the approval service
//! with its judge, the evidence ledger, the real handlers named in the table printed by the test,
//! and the real seams of the composition library.
//!
//! # What is scripted, and labelled
//!
//! The agent runtime (the classifier's answer comes from the recorded valid fixture), the sandbox
//! (`cargo` is a scripted program), the workspace provider, the code host and the issue source
//! (the testkit's fakes over the files of `fixtures/repos/word-count`), the model broker, and the
//! stage handlers of every stage that is not listed as real. `DeliverySources::tree_of` and
//! `current_values` are fixed values here because both fail closed in the composition library
//! (README, mismatch 16), and the `approval-request` the approval stage would store is built by
//! the test over the pull request on the fake code host.
//!
//! # Where the worker loop is
//!
//! The loop is a few lines here (refresh the request cache, run the step, claim, run the attempt),
//! not `factory_worker::run::WorkerLoop`: the rules of the workspace (`DEP-01`) refuse an edge from
//! one application to another, in any kind of dependency, so a test of the API cannot link the
//! worker and the other way round. The loop itself is tested in `apps/worker/tests`.

#[allow(dead_code, unused_imports)]
#[path = "../../../crates/workflow/tests/support/handler.rs"]
mod handler;
mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use factory_composition::authority::StoreAuthority;
use factory_composition::decisions::{
    AllowlistAuthority, AuditMarkers, ClaimWork, ClaimWorkDeps, DecisionMarkers, Marked, Pending,
    Unreadable,
};
use factory_composition::delivery::{StoreApprovalSources, StoreDeliverySources};
use factory_composition::redaction::RegisteringBroker;
use factory_composition::sandbox_specs::{PolicySpecs, sandbox_policy_from};
use factory_composition::seams::{
    CachedProbes, FileAllowlist, SchemaChecker, StoreRepositories, StoreRequests, YamlManifests,
};
use factory_composition::startup::load_policy;
use factory_composition::system::{RandomIds, SystemClock, TokioTicker};
use factory_contracts::registry::FileAgentRegistry;
use factory_domain::ids::{JobId, StageRunId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, StageRunStatus};
use factory_domain::values::{GitSha, Sha256Digest, Timestamp, Uri};
use factory_domain::vocabulary::{RiskTier, StageKind};
use factory_ports::agent::BrokerEndpoint;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::{
    ActorLogin, ChangeHost, DraftPrRequest, GitScope, GithubActor, IssueRef,
};
use factory_ports::paths::{BranchName, CommitSha, RepoRef};
use factory_ports::store::{AuditFilter, Store};
use factory_storage::artifact_fs::LocalFsArtifactStore;
use factory_testkit::agent::{AdversarialScript, FakeAgentRuntime};
use factory_testkit::broker::FakeModelBroker;
use factory_testkit::clock::FakeClock;
use factory_testkit::contracts::githost::IssueSourceSubject;
use factory_testkit::githost::{FakeChangeHost, FakeIssueSource};
use factory_testkit::router::{RouteRule, StaticModelRouter};
use factory_testkit::sandbox::{FakeSandbox, ProgramOutput};
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use factory_workflow::engine::{Engine, EngineConfig, EngineDeps, JobView};
use factory_workflow::handlers::HandlerRegistry;
use factory_workflow::stages::approval::{
    ApprovalDeps, ApprovalRequest, ApprovalService, ApprovalSources,
};
use factory_workflow::stages::delivery::{
    CurrentValues, DeliverySources, DeliveryTarget, LedgerState, SeamError,
};
use factory_workflow::stages::domain_discovery::DomainDiscoveryHandler;
use factory_workflow::stages::intake::{IntakeConfig, IntakeDeps, IntakeHandler};
use factory_workflow::stages::repo_intel::{RepoIntelConfig, RepoIntelDeps, RepoIntelHandler};
use handler::{Eval, ScriptHandle, ScriptedHandler};
use serde_json::json;
use support::{Env, Req, small_pool};

const LABEL: &str = "factory";
const ISSUE: u64 = 12;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// The files of `fixtures/repos/word-count`.
fn fixture_files() -> Vec<(String, String)> {
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
    files
}

// ---- stand-ins, each labelled -------------------------------------------------------------

/// `ApprovalSources` with the real answers for the people and the level, and the request that the
/// test built (the real approval stage is a scripted stand-in in this run, so nothing stored one).
struct RequestFromTheTest {
    real: StoreApprovalSources,
    request: Mutex<Option<ApprovalRequest>>,
}

#[async_trait]
impl ApprovalSources for RequestFromTheTest {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    async fn requester(
        &self,
        run: &factory_workflow::handlers::RunIdentity,
    ) -> Result<u64, SeamError> {
        self.real.requester(run).await
    }

    async fn allowlist(
        &self,
        tenant: TenantId,
    ) -> Result<factory_domain::policy::authority::Allowlist, SeamError> {
        self.real.allowlist(tenant).await
    }

    async fn level(
        &self,
        tenant: TenantId,
        job: JobId,
    ) -> Result<factory_domain::policy::authority::AutonomyLevel, SeamError> {
        self.real.level(tenant, job).await
    }

    async fn request(
        &self,
        _tenant: TenantId,
        _stage_run: StageRunId,
    ) -> Result<ApprovalRequest, SeamError> {
        self.request
            .lock()
            .expect("lock")
            .clone()
            .ok_or(SeamError::NotFound)
    }
}

/// `DeliverySources` with the real ledger and fixed `tree_of` and `current_values`, which fail
/// closed in the composition library.
struct FixedBindings {
    real: StoreDeliverySources,
    tree: GitSha,
    values: CurrentValues,
}

#[async_trait]
impl DeliverySources for FixedBindings {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        factory_domain::vocabulary::Fidelity::Fake
    }

    async fn target(
        &self,
        run: &factory_workflow::handlers::RunIdentity,
    ) -> Result<DeliveryTarget, SeamError> {
        self.real.target(run).await
    }

    async fn current_values(
        &self,
        _run: &factory_workflow::handlers::RunIdentity,
        _base: &CommitSha,
    ) -> Result<CurrentValues, SeamError> {
        Ok(self.values.clone())
    }

    async fn ledger(
        &self,
        run: &factory_workflow::handlers::RunIdentity,
    ) -> Result<LedgerState, SeamError> {
        self.real.ledger(run).await
    }

    async fn tree_of(
        &self,
        _run: &factory_workflow::handlers::RunIdentity,
        _commit: &CommitSha,
    ) -> Result<GitSha, SeamError> {
        Ok(self.tree.clone())
    }
}

/// The schema check of the engine, real for every document except the one the scripted stand-ins
/// of the engine suite store (a `review-verdict` with scripted content), which it accepts.
struct RealExceptScripted {
    real: factory_contracts::validator::SchemaOutputValidator,
}

impl factory_ports::registry::OutputValidator for RealExceptScripted {
    fn validate_bytes(
        &self,
        kind: factory_ports::registry::ContractKind,
        version: u32,
        bytes: &[u8],
    ) -> Result<factory_ports::registry::ValidatedOutput, Vec<factory_domain::contracts::Violation>>
    {
        if kind == factory_ports::registry::ContractKind::ReviewVerdict {
            let value = serde_json::from_slice(bytes).map_err(|_| {
                vec![factory_domain::contracts::Violation {
                    path: String::new(),
                    message: "not JSON".to_owned(),
                }]
            })?;
            return Ok(factory_ports::registry::ValidatedOutput {
                value,
                sha256: Sha256Digest::of(bytes),
                size_bytes: bytes.len() as u64,
            });
        }
        self.real.validate_bytes(kind, version, bytes)
    }

    fn validate_value(
        &self,
        kind: factory_ports::registry::ContractKind,
        version: u32,
        instance: &serde_json::Value,
    ) -> Result<(), Vec<factory_domain::contracts::Violation>> {
        if kind == factory_ports::registry::ContractKind::ReviewVerdict {
            return Ok(());
        }
        self.real.validate_value(kind, version, instance)
    }
}

// ---- the worker side --------------------------------------------------------------------

struct Worker {
    engine: Arc<Engine>,
    requests: Arc<StoreRequests>,
    hook: ClaimWork,
    store: Arc<dyn Store>,
    tenant: TenantId,
    host: Arc<FakeChangeHost>,
    remote: FakeRemote,
    sources: Arc<RequestFromTheTest>,
    delivery: Arc<StoreDeliverySources>,
    repo: RepoRef,
    policy_hash: Sha256Digest,
    scratch: PathBuf,
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.scratch);
    }
}

/// The stages whose handler is the real one in this run.
const REAL: [StageKind; 3] = [
    StageKind::Intake,
    StageKind::RepositoryIntelligence,
    StageKind::DomainDiscovery,
];

async fn worker(env: &Env, markers: Option<Arc<dyn DecisionMarkers>>) -> Worker {
    let ids = RandomIds::new().expect("random");
    let tenant = env.a.id;
    let repo = RepoRef::parse(&env.a.full_name).expect("a repository");
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    let redactor = Arc::new(
        factory_composition::redaction::redactor_from_policy(&policies.security).expect("redactor"),
    );
    // Not under the system temporary directory: see the worker README, mismatch 2.
    let scratch = root()
        .join("target/complete-run")
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
    let authority = Arc::new(StoreAuthority::new(
        store_dyn.clone(),
        allowlist.clone(),
        Arc::clone(&policies.engine),
        Arc::new(SystemClock),
    ));

    // The remote the fake code host and the fake workspaces share: the fixture on `main`.
    let remote = FakeRemote::new();
    let files = fixture_files();
    let borrowed: Vec<(&str, &str)> = files
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
    issues.put_issue(factory_ports::githost::Issue {
        reference: issue_ref.clone(),
        title: "Add a --json flag".to_owned(),
        body:
            "Please add a --json flag to the word count tool so other programs can read the counts."
                .to_owned(),
        author: GithubActor {
            id: env.a.requester.github_id,
            login: ActorLogin::new("requester-one").expect("a login"),
        },
        labels: vec![LABEL.to_owned()],
        updated_at: now,
        fetched_at: now,
    });
    issues
        .seed_label(
            &issue_ref,
            LABEL,
            &GithubActor {
                id: env.a.requester.github_id,
                login: ActorLogin::new("requester-one").expect("a login"),
            },
        )
        .await;

    // The scripted runtime: the classifier's answer is the recorded valid fixture.
    let runtime = FakeAgentRuntime::new(artifacts.clone());
    let classification: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            root().join("agents/intake-classifier/fixtures/valid/feature-with-json-flag.json"),
        )
        .expect("the valid fixture"),
    )
    .expect("JSON");
    runtime.queue(AdversarialScript::returning(classification));

    let derived = sandbox_policy_from(&policies.security, true).expect("limits fit");
    let catalog_json = std::fs::read_to_string(root().join("infra/sandbox-images/images.json"))
        .expect("the catalog");
    let catalog =
        factory_sandbox::container::images::ImageCatalog::from_json(&catalog_json, "linux/arm64")
            .expect("a catalog");
    let sandbox = FakeSandbox::new(fake_clock.clone(), artifacts.clone(), derived).with_program(
        "cargo",
        |_: &[String], _: &[u8]| ProgramOutput {
            exit_code: Some(0),
            stdout: b"test result: ok. 1 passed\n".to_vec(),
            stderr: Vec::new(),
        },
    );
    let broker = Arc::new(RegisteringBroker::new(
        Arc::new(FakeModelBroker::new(
            fake_clock.clone(),
            Arc::new(RandomIds::new().expect("random")),
        )),
        Arc::clone(&redactor),
    ));
    let specs = Arc::new(PolicySpecs::new(
        Arc::clone(&policies.security),
        catalog,
        Arc::clone(&broker),
        scratch.join("sandbox"),
    ));
    let requests = Arc::new(StoreRequests::new(store_dyn.clone()));
    let probes = Arc::new(CachedProbes::new(
        factory_ports::agent::ProbedCapabilities(BTreeMap::from([(
            factory_ports::agent::RuntimeId::new("fake").expect("a runtime"),
            factory_testkit::router::probe_of(&[
                factory_ports::agent::Capability::JsonSchemaOutput,
                factory_ports::agent::Capability::HeadlessMultiTurn,
                factory_ports::agent::Capability::SkillInvocation,
            ]),
        )])),
        factory_domain::vocabulary::Fidelity::Fake,
    ));
    let checker = Arc::new(SchemaChecker::new(root()));
    let commit = GitSha::parse("1405df66cbe219b0bf6355bc3d60361a8376b6b4").expect("a commit");
    let endpoint = BrokerEndpoint {
        base_url: Uri::parse("https://model-broker.sandbox.internal:8443").expect("a URI"),
    };

    // The handlers: three real, the rest scripted stand-ins of the engine suite.
    let mut scripts = BTreeMap::new();
    let mut handlers = HandlerRegistry::new();
    handlers
        .register(Arc::new(IntakeHandler::new(
            IntakeConfig {
                label: LABEL.to_owned(),
                agent: factory_domain::values::Slug::parse("intake-classifier").expect("a slug"),
                rules: factory_workflow::stages::intake::IntakeRules::default(),
                definition_commit: commit.clone(),
                broker: endpoint,
                max_output_bytes: 524_288,
            },
            IntakeDeps {
                requests: requests.clone(),
                issues: issues.clone(),
                allowlists: allowlist.clone(),
                policy: Arc::clone(&policies.engine),
                redactor: Arc::clone(&redactor),
                schemas: checker,
                sandboxes: specs.clone(),
                probes,
            },
        )))
        .expect("one handler per stage");
    handlers
        .register(Arc::new(RepoIntelHandler::new(
            RepoIntelConfig {
                definition_commit: commit,
                path_rules: factory_testkit::contracts::workspace::fixture_rules(),
                default_timeout_seconds: 900,
                max_file_bytes: 64 * 1024,
                max_paths: 5000,
            },
            RepoIntelDeps {
                changes: host.clone(),
                repos: Arc::new(StoreRepositories::new(store_dyn.clone())),
                specs: specs.clone(),
                manifests: Arc::new(YamlManifests::new().expect("manifests")),
                policy: Arc::clone(&policies.engine),
                redactor: Arc::clone(&redactor),
            },
        )))
        .expect("one handler per stage");
    handlers
        .register(Arc::new(DomainDiscoveryHandler::new()))
        .expect("one handler per stage");
    for kind in StageKind::ALL.iter().copied() {
        if REAL.contains(&kind)
            || !EngineConfig::new(
                factory_domain::vocabulary::ExecutionMode::Test,
                policies.hash.clone(),
            )
            .scope
            .contains(&kind)
        {
            continue;
        }
        let script = ScriptHandle::default();
        script.with(|s| {
            s.tweaks.backoff_initial_ms = 50;
            s.tweaks.backoff_max_ms = 200;
        });
        handlers
            .register(Arc::new(ScriptedHandler::new(kind, script.clone())))
            .expect("one handler per stage");
        scripts.insert(kind, script);
    }
    // The approval waits for a person.
    scripts
        .get(&StageKind::Approval)
        .expect("a script")
        .evals_otherwise(Eval::HumanGate);

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
    let deps = EngineDeps {
        store: store_dyn.clone(),
        clock: Arc::new(SystemClock),
        ids: Arc::new(RandomIds::new().expect("random")),
        artifacts: artifacts.clone(),
        sandbox: Arc::new(sandbox),
        workspaces: Arc::new(FakeWorkspaceProvider::new(
            repo.clone(),
            remote.clone(),
            artifacts.clone(),
            factory_testkit::contracts::workspace::fixture_rules(),
        )),
        runtime: Arc::new(runtime),
        router: Arc::new(StaticModelRouter::new(routes)),
        registry: Arc::new(FileAgentRegistry::load(&root()).expect("the real agent registry")),
        validator: Arc::new(RealExceptScripted {
            real: factory_contracts::validator::SchemaOutputValidator::new()
                .expect("the embedded schemas load"),
        }),
        broker,
        authority,
        ticker: Arc::new(TokioTicker),
    };
    let mut config = EngineConfig::new(
        factory_domain::vocabulary::ExecutionMode::Test,
        policies.hash.clone(),
    );
    config.claim_batch = 1;
    config.lease_ttl = Duration::from_secs(5);
    config.heartbeat_interval = Duration::from_millis(500);
    config.teardown_grace = Duration::from_secs(2);
    let engine = Arc::new(Engine::new(deps.clone(), config, handlers).expect("the engine starts"));

    // The approval service: real, over the engine, the store and the policy; the code host and the
    // two sources it reads are the stand-ins above.
    let delivery = Arc::new(StoreDeliverySources::new(
        store_dyn.clone(),
        artifacts.clone(),
        Arc::clone(&policies.engine),
        Arc::new(SystemClock),
    ));
    let sources = Arc::new(RequestFromTheTest {
        real: StoreApprovalSources::new(store_dyn.clone(), artifacts.clone(), allowlist.clone()),
        request: Mutex::new(None),
    });
    let service = Arc::new(ApprovalService::new(ApprovalDeps {
        engine: Arc::clone(&engine),
        store: store_dyn.clone(),
        host: host.clone(),
        issues: issues.clone(),
        policy: Arc::clone(&policies.engine),
        policy_hash: policies.hash.clone(),
        delivery: Arc::new(FixedBindings {
            real: StoreDeliverySources::new(
                store_dyn.clone(),
                artifacts.clone(),
                Arc::clone(&policies.engine),
                Arc::new(SystemClock),
            ),
            tree: GitSha::parse(&"7".repeat(40)).expect("a tree"),
            values: CurrentValues {
                definition_hash: Sha256Digest::of(b"definitions"),
                image_digest: Sha256Digest::of(b"image"),
            },
        }),
        approvals: sources.clone(),
        clock: Arc::new(SystemClock),
        ids: Arc::new(RandomIds::new().expect("random")),
        redactor: Arc::clone(&redactor),
    }));
    let hook = ClaimWork::new(ClaimWorkDeps {
        engine: Arc::clone(&engine),
        store: store_dyn.clone(),
        tenants: vec![tenant],
        submitter: service,
        approvals: sources.clone(),
        authority: Arc::new(AllowlistAuthority::new(
            allowlist,
            Arc::clone(&policies.approval),
            Arc::new(SystemClock),
        )),
        markers: markers.unwrap_or_else(|| {
            Arc::new(AuditMarkers::new(
                store_dyn.clone(),
                policies.hash.clone(),
                Arc::clone(&env.state.decision_keys),
            ))
        }),
        clock: Arc::new(SystemClock),
        max_age: std::time::Duration::from_secs(72 * 3600),
        per_pass: factory_composition::decisions::DECISIONS_PER_PASS,
        keys: Arc::clone(&env.state.decision_keys),
    });
    Worker {
        engine,
        requests,
        hook,
        store: store_dyn,
        tenant,
        host,
        remote,
        sources,
        delivery,
        repo,
        policy_hash: policies.hash.clone(),
        scratch,
    }
}

impl Worker {
    /// The loop of a worker, as a few lines: the request cache, the step before the claim, the
    /// claim, the attempt. Returns the view when `done` holds or the time is up.
    async fn drive(
        &self,
        job: Option<JobId>,
        seconds: u64,
        done: impl Fn(&JobView) -> bool,
    ) -> Option<JobView> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
        let worker =
            factory_ports::store::WorkerId::new("worker-complete-run").expect("a worker id");
        loop {
            let _ = self.requests.refresh(&[self.tenant]).await;
            self.hook.pass(self.tenant).await;
            let _ = self.engine.sweep().await;
            let claimed = self.engine.claim_next(&worker).await.expect("a claim");
            for attempt in claimed.started {
                let outcome = self.engine.run_attempt(&attempt).await;
                println!("RUN {:?} {:?}", attempt.kind, outcome);
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

fn print_states(label: &str, view: &JobView) {
    println!("COMPLETE-RUN {label}: job {:?}", view.status);
    for run in &view.stage_runs {
        println!(
            "COMPLETE-RUN   {:?}: {:?} after {} attempt(s)",
            run.kind,
            run.status,
            run.attempts.len()
        );
    }
}

async fn job_of(env: &Env) -> JobId {
    let reply = env
        .send(Req::get("/v1/jobs").bearer(&env.a.requester.token))
        .await;
    assert_eq!(reply.status, 200, "{}", reply.text());
    let body = reply.json();
    let first = body["jobs"][0]["job_id"]
        .as_str()
        .or_else(|| body["jobs"][0]["id"].as_str())
        .unwrap_or_else(|| panic!("the listing names a job: {body}"));
    JobId::parse(first).expect("a job id")
}

/// Fails to write the marker, as a worker that stopped right after the engine's commit.
struct StopsBeforeTheMarker;

#[async_trait::async_trait(?Send)]
impl DecisionMarkers for StopsBeforeTheMarker {
    async fn mark(&self, _: TenantId, _: &Pending, _: &Marked) -> Result<(), Unreadable> {
        Err(Unreadable)
    }
}

/// What the person needs to decide: the job, the approval stage run, the head and the evidence.
struct AtTheApproval {
    job: JobId,
    stage_run: StageRunId,
    head: CommitSha,
    evidence: Sha256Digest,
}

/// Submits the labelled issue through the signed webhook, runs the worker to the approval, and
/// builds the pull request and the request the person is asked about.
async fn up_to_the_approval(env: &Env, worker: &Worker) -> AtTheApproval {
    // 1. The webhook: a signed delivery that a person labelled an issue. It carries no text.
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
    let job = job_of(env).await;
    let received = worker
        .engine
        .job_status(worker.tenant, job)
        .await
        .expect("a status");
    assert_eq!(
        received,
        JobStatus::Received,
        "the API only records the job"
    );

    // 2. The worker admits it, fetches the issue in intake, and runs the stages to the approval.
    let view = worker
        .drive(Some(job), 120, |view| {
            view.status == JobStatus::WaitingForHuman
        })
        .await
        .expect("a view");
    print_states("up to the approval", &view);
    assert_eq!(view.status, JobStatus::WaitingForHuman, "{view:#?}");
    for kind in [StageKind::Intake, StageKind::RepositoryIntelligence] {
        assert_eq!(
            view.newest(kind).expect("a run").status,
            StageRunStatus::Passed,
            "{kind}"
        );
    }
    assert_eq!(
        view.newest(StageKind::DomainDiscovery)
            .expect("a run")
            .status,
        StageRunStatus::Skipped
    );
    let approval = view.newest(StageKind::Approval).expect("a run");
    assert_eq!(approval.status, StageRunStatus::WaitingForHuman);
    // The request text was fetched by the intake stage and stored as revision 1.
    {
        let mut tx = worker
            .store
            .begin(TenantScope::new(worker.tenant))
            .await
            .expect("a tx");
        let stored = tx
            .get_original_request(job, None)
            .await
            .expect("revision 1");
        let _ = tx.rollback().await;
        assert_eq!(stored.revision, 1);
        assert!(
            stored.text.starts_with("Add a --json flag"),
            "{}",
            stored.text
        );
    }

    // 3. The pull request on the fake code host, and the request the approval stage would store.
    let head_branch = BranchName::new(&format!("factory/job-{job}")).expect("a branch");
    let base_branch = BranchName::new("main").expect("main");
    let files = fixture_files();
    let mut borrowed: Vec<(&str, &str)> = files
        .iter()
        .map(|(p, c)| (p.as_str(), c.as_str()))
        .collect();
    borrowed.push(("docs/CHANGELOG.md", "Added the --json flag.\n"));
    let head = worker
        .remote
        .commit_on_branch(&worker.repo, &head_branch, &borrowed);
    let base = worker
        .remote
        .branch_tip(&worker.repo, &base_branch)
        .expect("a base");
    let stage_run = approval.id;
    let correlation = {
        let mut tx = worker
            .store
            .begin(TenantScope::new(worker.tenant))
            .await
            .expect("a tx");
        let correlation = tx.get_job(job).await.expect("a job").value.correlation_id;
        let _ = tx.rollback().await;
        correlation
    };
    let identity = factory_workflow::handlers::RunIdentity {
        tenant: worker.tenant,
        job,
        correlation,
        stage_run,
        kind: StageKind::Approval,
    };
    let pull_request = worker
        .host
        .open_draft_pull_request(
            &GitScope {
                tenant: worker.tenant,
                job,
                stage: StageKind::Delivery,
                repo: worker.repo.clone(),
            },
            DraftPrRequest {
                head: head_branch.clone(),
                base: base_branch,
                title: "Add a --json flag".to_owned(),
                body: "The factory made this change. A person merges it.".to_owned(),
            },
        )
        .await
        .expect("a draft pull request");
    let ledger = worker.delivery.ledger(&identity).await.expect("the ledger");
    let sha = |commit: &CommitSha| GitSha::parse(commit.as_str()).expect("a sha");
    *worker.sources.request.lock().expect("lock") = Some(ApprovalRequest {
        repository: env.a.full_name.clone(),
        pull_request: pull_request.number,
        head_branch: head_branch.as_str().to_owned(),
        base_branch: "main".to_owned(),
        pr_head: sha(&head),
        tree: GitSha::parse(&"7".repeat(40)).expect("a tree"),
        base: sha(&base),
        manifest: Sha256Digest::of(b"manifest"),
        spec_version: 1,
        gates_clear: true,
        open_translation_warnings: 0,
        tier: RiskTier::Low,
        protected_path_change: false,
        sensitive_file_change: false,
        new_dependency: false,
        requester: env.a.requester.github_id,
        evidence_binding: factory_workflow::stages::validation::Binding {
            implementation_result: Sha256Digest::of(b"result"),
            base_commit: sha(&base),
            head_commit: sha(&head),
            policy_hash: worker.policy_hash.clone(),
            image_digest: Sha256Digest::of(b"image"),
            definition_hash: Sha256Digest::of(b"definitions"),
        },
        created_at: SystemClock.now(),
    });
    AtTheApproval {
        job,
        stage_run,
        head,
        evidence: ledger.head_hash,
    }
}

/// The administrator's step: a repository runs at level L0 until a protection preflight passed for
/// it (ADR 0009; the store reports L0 for it), and at L0 nobody can approve (`approve_pr` needs
/// L1). No process of the factory records the preflight yet (README, mismatch 18), so the step is
/// taken here, in the database, as the superuser.
async fn administrator_records_the_preflight(env: &Env) {
    env.db
        .run(&format!(
            "UPDATE repositories SET protection_preflight_passed = true, version = version + 1 \
             WHERE tenant_id = '{}'",
            env.a.id.as_uuid()
        ))
        .await;
}

/// `POST /v1/jobs/{id}/decisions` as the approver.
async fn approver_decides(env: &Env, at: &AtTheApproval, key: &str) -> support::Reply {
    let decision = json!({
        "verb": "approve",
        "stage_run_id": at.stage_run.as_text(),
        "head": at.head.as_str(),
        "evidence": at.evidence.as_str(),
        "reason": "The change does what the issue asked.",
    });
    env.send(
        Req::post(&format!("/v1/jobs/{}/decisions", at.job))
            .bearer(&env.a.approver.token)
            .header("Idempotency-Key", key)
            .json(&decision),
    )
    .await
}

async fn decision_actions(env: &Env, job: JobId) -> Vec<String> {
    let reply = env
        .send(Req::get(&format!("/v1/jobs/{job}/timeline")).bearer(&env.a.requester.token))
        .await;
    assert_eq!(reply.status, 200);
    reply.json()["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .filter(|entry| entry["kind"] == "audit")
        .filter_map(|entry| entry["action"].as_str().map(str::to_owned))
        .filter(|action| action.starts_with("decision."))
        .collect()
}

async fn count_audit(worker: &Worker, job: JobId, action: &str) -> usize {
    let mut tx = worker
        .store
        .begin(TenantScope::new(worker.tenant))
        .await
        .expect("a tx");
    let audit = tx
        .read_audit(AuditFilter::Job(job), 0, 500)
        .await
        .expect("audit");
    let _ = tx.rollback().await;
    audit
        .iter()
        .filter(|record| record.event.action.as_str() == action)
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_labelled_issue_goes_through_every_stage_and_a_persons_approval_completes_it() {
    let env = Env::start().await;
    administrator_records_the_preflight(&env).await;
    let worker = worker(&env, None).await;
    let at = up_to_the_approval(&env, &worker).await;

    // The approver decides, through the API. The answer says it is recorded, not applied.
    let reply = approver_decides(&env, &at, "approve-complete-run-1").await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    assert_eq!(reply.json()["applied"], json!(false));

    // The worker applies it, once, and the job completes.
    let view = worker
        .drive(Some(at.job), 60, |view| view.status == JobStatus::Completed)
        .await
        .expect("a view");
    print_states("after the approval", &view);
    assert_eq!(view.status, JobStatus::Completed, "{view:#?}");
    assert_eq!(
        view.newest(StageKind::Approval).expect("a run").status,
        StageRunStatus::Passed
    );

    // The timeline the API serves shows the request and what became of it, and later passes do
    // not apply it again.
    assert_eq!(
        decision_actions(&env, at.job).await,
        ["decision.requested", "decision.applied"]
    );
    let again = worker
        .drive(Some(at.job), 2, |_| false)
        .await
        .expect("a view");
    assert_eq!(again.status, JobStatus::Completed);
    assert_eq!(count_audit(&worker, at.job, "decision.applied").await, 1);
    assert_eq!(count_audit(&worker, at.job, "approval.recorded").await, 1);
    env.stop().await;
}

/// A decision the worker refuses shows in the timeline, and one applied by a worker that stopped
/// before its marker is applied once and marked by the next.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_decision_shows_in_the_timeline_and_a_stop_before_the_marker_applies_once() {
    let env = Env::start().await;
    administrator_records_the_preflight(&env).await;
    let worker_one = worker(&env, Some(Arc::new(StopsBeforeTheMarker))).await;
    let at = up_to_the_approval(&env, &worker_one).await;
    let allowlist = env.checkout.join("allowlist/allowlist.yaml");

    // 1. The approver decides, and is taken off the allowlist before a worker reads the request.
    let reply = approver_decides(&env, &at, "approve-refused-1").await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    let with_approver = std::fs::read_to_string(&allowlist).expect("the allowlist file");
    let without_approver: String = with_approver
        .split("  - tenant:")
        .enumerate()
        .filter(|(index, part)| *index == 0 || !part.contains("designations: [approver]"))
        .map(|(index, part)| {
            if index == 0 {
                part.to_owned()
            } else {
                format!("  - tenant:{part}")
            }
        })
        .collect();
    assert_ne!(with_approver, without_approver);
    std::fs::write(&allowlist, without_approver).expect("the allowlist file");
    // A second worker, with real markers, reads the request and refuses it.
    let worker_two = worker(&env, None).await;
    *worker_two.sources.request.lock().expect("lock") =
        worker_one.sources.request.lock().expect("lock").clone();
    let still = worker_two
        .drive(Some(at.job), 3, |_| false)
        .await
        .expect("a view");
    assert_eq!(
        still.status,
        JobStatus::WaitingForHuman,
        "the refused decision moved nothing"
    );
    assert_eq!(
        decision_actions(&env, at.job).await,
        ["decision.requested", "decision.rejected"],
        "the refusal is in the timeline the API serves"
    );

    // 2. The approver is back on the list and decides again, with a new key. The first worker
    // applies it and stops before the marker.
    std::fs::write(&allowlist, with_approver).expect("the allowlist file");
    let reply = approver_decides(&env, &at, "approve-refused-2").await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    let done = worker_one
        .drive(Some(at.job), 60, |view| view.status == JobStatus::Completed)
        .await
        .expect("a view");
    assert_eq!(done.status, JobStatus::Completed, "{done:#?}");
    assert_eq!(
        count_audit(&worker_one, at.job, "decision.applied").await,
        0
    );
    assert_eq!(
        count_audit(&worker_one, at.job, "approval.recorded").await,
        1
    );

    // 3. The next worker finds a request with no marker, sees that the engine applied it, and
    // writes the marker. It does not record a second approval or move the job.
    let after = worker_two
        .drive(Some(at.job), 5, |_| false)
        .await
        .expect("a view");
    assert_eq!(after.status, JobStatus::Completed);
    assert_eq!(
        count_audit(&worker_two, at.job, "decision.applied").await,
        1
    );
    assert_eq!(
        count_audit(&worker_two, at.job, "approval.recorded").await,
        1
    );
    assert_eq!(
        decision_actions(&env, at.job).await,
        [
            "decision.requested",
            "decision.rejected",
            "decision.requested",
            "decision.applied"
        ]
    );
    env.stop().await;
}
