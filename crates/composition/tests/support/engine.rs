//! A whole engine over the real PostgreSQL store, the real local artifact store, the real ticker,
//! the real clock and identifier source, with the model-side and sandbox-side adapters faked.
//!
//! This is the test-profile wiring: it builds the engine the way the worker does, except that the
//! sandbox, the workspaces, the runtime, the router, the broker and the stage handlers are the
//! testkit's fakes and the engine suite's scripted handlers. The scripted handlers are included
//! from the engine's own tests with `#[path]`, so there is one scripted handler.
#![allow(dead_code, unused_imports)]

#[path = "../../../../crates/workflow/tests/support/authority.rs"]
pub mod authority;
#[path = "../../../../crates/workflow/tests/support/handler.rs"]
pub mod handler;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use factory_composition::config::LoopConfig;
use factory_composition::system::{RandomIds, Shutdown, SystemClock, TokioTicker};
use factory_domain::contracts::Violation;
use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::ids::{CausationId, JobId, PrincipalId, RepositoryId, StageRunId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::values::{NonEmptyString, Sha256Digest};
use factory_domain::vocabulary::{ExecutionMode, HumanRole, StageKind};
use factory_ports::agent::{ModelSelection, RuntimeId};
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::paths::RepoRef;
use factory_ports::registry::{ContractKind, OutputValidator, ValidatedOutput};
use factory_ports::store::{NewPrincipal, PrincipalKind, Store, WorkerId};
use factory_storage::artifact_fs::LocalFsArtifactStore;
use factory_storage::pg::PgStore;
use factory_testkit::agent::FakeAgentRuntime;
use factory_testkit::broker::FakeModelBroker;
use factory_testkit::clock::FakeClock;
use factory_testkit::contracts::workspace::fixture_rules;
use factory_testkit::fixtures::sandbox_policy;
use factory_testkit::registry::InMemoryAgentRegistry;
use factory_testkit::router::{RouteRule, StaticModelRouter};
use factory_testkit::sandbox::FakeSandbox;
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use factory_workflow::commands::{Actor, Decision, Subject};
use factory_workflow::engine::{Admission, Engine, EngineConfig, EngineDeps, JobView};
use factory_workflow::handlers::HandlerRegistry;

pub use authority::StaticAuthority;
pub use handler::{Eval, ScriptHandle, ScriptedHandler, Step};

/// Accepts every document except one that says `"invalid": true`.
pub struct ScriptedValidator;

impl OutputValidator for ScriptedValidator {
    fn validate_bytes(
        &self,
        kind: ContractKind,
        version: u32,
        bytes: &[u8],
    ) -> Result<ValidatedOutput, Vec<Violation>> {
        let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| {
            vec![Violation {
                path: String::new(),
                message: "the bytes are not a JSON document".to_owned(),
            }]
        })?;
        self.validate_value(kind, version, &value)?;
        Ok(ValidatedOutput {
            value,
            sha256: Sha256Digest::of(bytes),
            size_bytes: bytes.len() as u64,
        })
    }

    fn validate_value(
        &self,
        _kind: ContractKind,
        _version: u32,
        instance: &serde_json::Value,
    ) -> Result<(), Vec<Violation>> {
        if instance.get("invalid") == Some(&serde_json::Value::Bool(true)) {
            Err(vec![Violation {
                path: "invalid".to_owned(),
                message: "the scripted validator refuses this document".to_owned(),
            }])
        } else {
            Ok(())
        }
    }
}

/// A removed-on-drop scratch directory for the local artifact store.
pub struct Scratch(pub PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The pieces of an engine over PostgreSQL.
pub struct PgWorld {
    pub store: Arc<PgStore>,
    pub tenant: TenantId,
    pub requester: PrincipalId,
    pub repository: RepositoryId,
    pub authority: Arc<StaticAuthority>,
    pub scripts: HashMap<StageKind, ScriptHandle>,
    pub deps: EngineDeps,
    pub config: EngineConfig,
    pub handlers: HandlerRegistry,
    pub ids: Arc<RandomIds>,
    pub engine: Engine,
    next_github_user: AtomicU64,
    _scratch: Scratch,
}

impl PgWorld {
    /// Builds the world over an existing store whose database has `tenant` seeded with
    /// `repository`.
    pub async fn new(
        store: PgStore,
        tenant: TenantId,
        repository: RepositoryId,
        tune: impl FnOnce(&mut EngineConfig),
    ) -> Self {
        let ids = Arc::new(RandomIds::new().expect("the random source opens"));
        let store = Arc::new(store);
        let scratch = Scratch(
            std::env::temp_dir().join(format!("factory-worker-test-{}", ids.new_uuid().simple())),
        );
        let artifacts: Arc<dyn factory_ports::artifact::ArtifactStore> = Arc::new(
            LocalFsArtifactStore::open(&scratch.0, 64 * 1024 * 1024, store.clone())
                .expect("the artifact root opens"),
        );
        let fake_clock = Arc::new(FakeClock::new());
        let broker = Arc::new(FakeModelBroker::new(fake_clock.clone(), ids.clone()));
        let authority = Arc::new(StaticAuthority::new());
        let routes: Vec<RouteRule> = StageKind::ALL
            .iter()
            .map(|kind| RouteRule {
                stage: *kind,
                tier: RecommendedTier::Standard,
                model: ModelSelection {
                    runtime: RuntimeId::new("fake").expect("a runtime"),
                    model: NonEmptyString::parse("fake-model").expect("a model"),
                },
                capabilities: Vec::new(),
            })
            .collect();
        let repo = RepoRef::parse("example-org/fixture").expect("a repository");
        let deps = EngineDeps {
            store: store.clone(),
            clock: Arc::new(SystemClock),
            ids: ids.clone(),
            artifacts: artifacts.clone(),
            sandbox: Arc::new(FakeSandbox::new(
                fake_clock.clone(),
                artifacts.clone(),
                sandbox_policy(),
            )),
            workspaces: Arc::new(FakeWorkspaceProvider::new(
                repo,
                FakeRemote::new(),
                artifacts.clone(),
                fixture_rules(),
            )),
            runtime: Arc::new(FakeAgentRuntime::new(artifacts.clone())),
            router: Arc::new(StaticModelRouter::new(routes)),
            registry: Arc::new(InMemoryAgentRegistry::new()),
            validator: Arc::new(ScriptedValidator),
            broker: broker.clone(),
            authority: authority.clone(),
            ticker: Arc::new(TokioTicker),
        };
        let mut config = EngineConfig::new(ExecutionMode::Test, Sha256Digest::of(b"test policy"));
        // One attempt per claim, as the worker runs; short waits so real time is not wasted.
        config.claim_batch = 1;
        config.lease_ttl = Duration::from_secs(3);
        config.heartbeat_interval = Duration::from_millis(500);
        config.teardown_grace = Duration::from_secs(2);
        tune(&mut config);
        let mut scripts = HashMap::new();
        let mut handlers = HandlerRegistry::new();
        for kind in &config.scope {
            let script = ScriptHandle::default();
            script.with(|s| {
                s.broker = Some(broker.clone());
                s.tweaks.backoff_initial_ms = 50;
                s.tweaks.backoff_max_ms = 200;
            });
            handlers
                .register(Arc::new(ScriptedHandler::new(*kind, script.clone())))
                .expect("one handler per stage");
            scripts.insert(*kind, script);
        }
        let engine = Engine::new(deps.clone(), config.clone(), handlers.clone())
            .expect("a test engine starts");

        let requester = PrincipalId::from_uuid(ids.new_uuid());
        let mut tx = store.begin(TenantScope::new(tenant)).await.expect("a tx");
        tx.insert_principal(NewPrincipal {
            id: requester,
            kind: PrincipalKind::Human {
                github_user_id: 1001,
            },
            login: None,
        })
        .await
        .expect("a principal");
        tx.commit().await.expect("commit");

        Self {
            store,
            tenant,
            requester,
            repository,
            authority,
            scripts,
            deps,
            config,
            handlers,
            ids,
            engine,
            next_github_user: AtomicU64::new(2000),
            _scratch: scratch,
        }
    }

    /// A second engine over the same store and the same handlers: the process after a restart.
    pub fn restarted_engine(&self) -> Engine {
        Engine::new(
            self.deps.clone(),
            self.config.clone(),
            self.handlers.clone(),
        )
        .expect("a test engine starts")
    }

    pub fn script(&self, kind: StageKind) -> &ScriptHandle {
        self.scripts.get(&kind).expect("a script for every stage")
    }

    pub fn worker(name: &str) -> WorkerId {
        WorkerId::new(name).expect("a worker id")
    }

    /// Claims with `worker` and returns the one attempt that started.
    pub async fn claim_one(&self, worker: &str) -> factory_workflow::scheduler::ClaimedAttempt {
        let claimed = self
            .engine
            .claim_next(&Self::worker(worker))
            .await
            .expect("claim");
        assert_eq!(claimed.started.len(), 1, "{claimed:?}");
        claimed.started.into_iter().next().expect("one")
    }

    /// Stores a request and admits it.
    pub async fn admitted_job(&self) -> JobId {
        let job = self
            .engine
            .receive_job(self.tenant, self.requester, self.repository)
            .await
            .expect("receive");
        let admission = self
            .engine
            .admit_job(self.tenant, job)
            .await
            .expect("admit");
        assert!(
            matches!(admission, Admission::Admitted { .. }),
            "{admission:?}"
        );
        job
    }

    pub async fn view(&self, job: JobId) -> JobView {
        self.engine
            .job_view(self.tenant, job)
            .await
            .expect("a view")
    }

    /// Records a person in the tenant and gives them these roles on the allowlist.
    pub async fn person(&self, name: &str, roles: &[HumanRole]) -> PrincipalId {
        let id = PrincipalId::from_uuid(self.ids.new_uuid());
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let github_user_id = self.next_github_user.fetch_add(1, Ordering::Relaxed);
        tx.insert_principal(NewPrincipal {
            id,
            kind: PrincipalKind::Human { github_user_id },
            login: Some(name.to_owned()),
        })
        .await
        .expect("a principal");
        tx.commit().await.expect("commit");
        self.authority.grant(id, roles);
        id
    }

    pub fn actor(&self, principal: PrincipalId) -> Actor {
        Actor {
            tenant: self.tenant,
            principal,
            command: CausationId::from_uuid(self.ids.new_uuid()),
        }
    }

    /// The hash of the last ledger entry of a job.
    pub async fn head(&self, job: JobId) -> Sha256Digest {
        use factory_ports::store::LedgerOps;
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let head = tx
            .ledger_head(job)
            .await
            .expect("a head")
            .expect("an entry");
        let _ = tx.rollback().await;
        head.hash
    }

    /// Approves a stage run as a new approver who is not the requester.
    pub async fn approve(&self, engine: &Engine, job: JobId, run: StageRunId) {
        let approver = self.person("approver-x", &[HumanRole::Approver]).await;
        let seen = self.head(job).await;
        engine
            .decide(
                &self.actor(approver),
                Subject {
                    job,
                    stage_run: run,
                },
                Decision::Approve {
                    evidence_seen: seen,
                    warnings_decided: true,
                },
            )
            .await
            .expect("the approval applies");
    }

    /// The ledger of a job.
    pub async fn ledger(&self, job: JobId) -> Vec<factory_domain::contracts::EvidenceLedgerEntry> {
        use factory_ports::store::LedgerOps;
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let rows = tx.read_ledger(job, 1, 10_000).await.expect("ledger");
        tx.rollback().await.expect("rollback");
        rows
    }

    /// The loop settings the tests use: short waits.
    pub fn loop_settings() -> LoopConfig {
        LoopConfig {
            poll_interval_ms: 50,
            sweep_interval_s: 1,
            drain_s: 10,
            ..LoopConfig::default()
        }
    }
}
