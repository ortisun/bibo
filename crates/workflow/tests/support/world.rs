//! A whole engine over the in-memory fakes, with scripted stage handlers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use factory_domain::contracts::{DomainEvent, EvidenceLedgerEntry, Violation};
use factory_domain::ids::{JobId, PrincipalId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::values::{NonEmptyString, Sha256Digest};
use factory_domain::vocabulary::{ExecutionMode, StageKind};
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::paths::{CommitSha, RepoRef};
use factory_ports::registry::{ContractKind, OutputValidator};
use factory_ports::store::{AuditEvent, NewPrincipal, OutboxSeq, Store, SystemScope, Tx, WorkerId};
use factory_testkit::agent::FakeAgentRuntime;
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::broker::FakeModelBroker;
use factory_testkit::clock::{FakeClock, SequentialIdGenerator};
use factory_testkit::fixtures::sandbox_policy;
use factory_testkit::registry::InMemoryAgentRegistry;
use factory_testkit::router::StaticModelRouter;
use factory_testkit::sandbox::FakeSandbox;
use factory_testkit::store::InMemoryStore;
use factory_testkit::workspace::FakeWorkspaceProvider;
use factory_workflow::engine::{Admission, Engine, EngineConfig, EngineDeps, JobView};
use factory_workflow::handlers::HandlerRegistry;
use factory_workflow::scheduler::ClaimedAttempt;

use super::authority::StaticAuthority;
use super::handler::{ScriptHandle, ScriptedHandler};

/// Accepts every document except one that says `"invalid": true`.
pub struct ScriptedValidator;

impl OutputValidator for ScriptedValidator {
    fn validate(
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

/// The pieces of a test engine.
pub struct World {
    pub clock: Arc<FakeClock>,
    pub ids: Arc<SequentialIdGenerator>,
    pub store: Arc<InMemoryStore>,
    pub artifacts: Arc<InMemoryArtifactStore>,
    pub authority: Arc<StaticAuthority>,
    pub scripts: HashMap<StageKind, ScriptHandle>,
    pub deps: EngineDeps,
    pub config: EngineConfig,
    pub handlers: HandlerRegistry,
    pub engine: Engine,
    pub tenant: TenantId,
    pub requester: PrincipalId,
}

impl World {
    /// A test-mode engine with a scripted handler for every stage in the Slice 1 scope.
    pub async fn new() -> Self {
        Self::with_config(|_| {}).await
    }

    /// The same, after `tune` changed the configuration.
    pub async fn with_config(tune: impl FnOnce(&mut EngineConfig)) -> Self {
        let clock = Arc::new(FakeClock::new());
        let ids = Arc::new(SequentialIdGenerator::new());
        let store = Arc::new(InMemoryStore::new(clock.clone()));
        let artifacts = Arc::new(InMemoryArtifactStore::new());
        let authority = Arc::new(StaticAuthority::new());
        let repo = RepoRef::parse("example-org/fixture").expect("a repository");
        let base = CommitSha::parse(&"0123456789".repeat(4)).expect("a commit");
        let deps = EngineDeps {
            store: store.clone(),
            clock: clock.clone(),
            ids: ids.clone(),
            artifacts: artifacts.clone(),
            sandbox: Arc::new(FakeSandbox::new(
                clock.clone(),
                artifacts.clone(),
                sandbox_policy(),
            )),
            workspaces: Arc::new(FakeWorkspaceProvider::new(
                repo,
                base,
                &[("README.md", "hi")],
            )),
            runtime: Arc::new(FakeAgentRuntime::new(artifacts.clone())),
            router: Arc::new(StaticModelRouter::new(Vec::new())),
            registry: Arc::new(InMemoryAgentRegistry::new()),
            validator: Arc::new(ScriptedValidator),
            broker: Arc::new(FakeModelBroker::new(clock.clone(), ids.clone())),
            authority: authority.clone(),
        };
        let mut config = EngineConfig::new(ExecutionMode::Test, Sha256Digest::of(b"test policy"));
        tune(&mut config);
        let mut scripts = HashMap::new();
        let mut handlers = HandlerRegistry::new();
        for kind in &config.scope {
            let script = ScriptHandle::default();
            handlers
                .register(Arc::new(ScriptedHandler::new(*kind, script.clone())))
                .expect("one handler per stage");
            scripts.insert(*kind, script);
        }
        let engine = Engine::new(deps.clone(), config.clone(), handlers.clone())
            .expect("a test engine starts");

        let tenant = TenantId::from_uuid(ids.new_uuid());
        let requester = PrincipalId::from_uuid(ids.new_uuid());
        let mut tx = store.begin(TenantScope::new(tenant)).await.expect("a tx");
        tx.insert_principal(NewPrincipal {
            id: requester,
            external_ref: NonEmptyString::parse("github:1001").expect("a reference"),
            created_at: clock.now(),
        })
        .await
        .expect("a principal");
        tx.commit().await.expect("commit");

        Self {
            clock,
            ids,
            store,
            artifacts,
            authority,
            scripts,
            deps,
            config,
            handlers,
            engine,
            tenant,
            requester,
        }
    }

    /// A second engine over the same store, as after a restart of the process.
    pub fn restarted_engine(&self) -> Engine {
        Engine::new(
            self.deps.clone(),
            self.config.clone(),
            self.handlers.clone(),
        )
        .expect("a test engine starts")
    }

    /// The script of one stage.
    pub fn script(&self, kind: StageKind) -> &ScriptHandle {
        self.scripts.get(&kind).expect("a script for every stage")
    }

    /// A worker name.
    pub fn worker(name: &str) -> WorkerId {
        WorkerId::new(name).expect("a worker id")
    }

    /// Moves the clock, which is also the database clock.
    pub fn advance(&self, seconds: u64) {
        self.clock.advance(Duration::from_secs(seconds));
    }

    /// Stores a request and admits it.
    pub async fn admitted_job(&self) -> JobId {
        let job = self
            .engine
            .receive_job(self.tenant, self.requester)
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

    /// The read model of a job.
    pub async fn view(&self, job: JobId) -> JobView {
        self.engine
            .job_view(self.tenant, job)
            .await
            .expect("a view")
    }

    /// Claims with `worker` and returns the one attempt that started.
    pub async fn claim_one(&self, worker: &str) -> ClaimedAttempt {
        let claimed = self
            .engine
            .claim_next(&Self::worker(worker))
            .await
            .expect("claim");
        assert_eq!(claimed.started.len(), 1, "{claimed:?}");
        claimed.started.into_iter().next().expect("one")
    }

    /// A system transaction, as the engine opens to find work.
    pub async fn store_system(&self) -> Box<dyn Tx> {
        self.store
            .begin_system(SystemScope::engine())
            .await
            .expect("a system tx")
    }

    /// The outbox events of a job, oldest first.
    pub async fn events(&self, job: JobId) -> Vec<DomainEvent> {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let rows = tx
            .read_events(job, OutboxSeq::START, 10_000)
            .await
            .expect("events");
        tx.rollback().await.expect("rollback");
        rows.into_iter().map(|row| row.event).collect()
    }

    /// The audit records of a job.
    pub async fn audit(&self, job: JobId) -> Vec<AuditEvent> {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let rows = tx.read_audit(job, 10_000).await.expect("audit");
        tx.rollback().await.expect("rollback");
        rows
    }

    /// The ledger of a job.
    pub async fn ledger(&self, job: JobId) -> Vec<EvidenceLedgerEntry> {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let rows = tx.read_ledger(job, 1, 10_000).await.expect("ledger");
        tx.rollback().await.expect("rollback");
        rows
    }
}
