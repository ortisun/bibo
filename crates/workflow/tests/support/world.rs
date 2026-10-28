//! A whole engine over the in-memory fakes, with scripted stage handlers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::contracts::{DomainEvent, EvidenceLedgerEntry, Violation};
use factory_domain::ids::{CausationId, JobId, PrincipalId, RepositoryId, StageRunId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::values::{NonEmptyString, Sha256Digest};
use factory_domain::vocabulary::{ExecutionMode, HumanRole, StageKind};
use factory_ports::agent::{ModelSelection, RuntimeId};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::paths::RepoRef;
use factory_ports::registry::{ContractKind, OutputValidator, ValidatedOutput};
use factory_ports::store::{
    ArtifactIndexEntry, AuditFilter, AuditRecord, NewPrincipal, OutboxSeq, PrincipalKind, StageRun,
    StageRunArtifact, Store, SystemScope, SystemTx, WorkerId,
};
use factory_testkit::agent::FakeAgentRuntime;
use factory_testkit::broker::FakeModelBroker;
use factory_testkit::clock::FakeClock;
use factory_testkit::contracts::workspace::fixture_rules;
use factory_testkit::fixtures::sandbox_policy;
use factory_testkit::registry::InMemoryAgentRegistry;
use factory_testkit::router::{RouteRule, StaticModelRouter};
use factory_testkit::sandbox::FakeSandbox;
use factory_testkit::store::StoreDefect;
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use factory_workflow::commands::{Actor, Decision, Subject};
use factory_workflow::engine::{
    Admission, AttemptOutcome, Engine, EngineConfig, EngineDeps, JobView,
};
use factory_workflow::handlers::HandlerRegistry;
use factory_workflow::scheduler::ClaimedAttempt;

use super::artifacts::SwitchedArtifacts;
use super::authority::StaticAuthority;
use super::backend::{Backend, InMemoryBackend};
use super::handler::{ScriptHandle, ScriptedHandler};
use super::ids::FaultyIds;
use super::ticker::ManualTicker;

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

/// The pieces of a test engine.
///
/// The store is whatever the [`Backend`] provides, and the scenarios use it through the `Store`
/// port only. `clock` is the engine's clock. On the in-memory backend it is also the store's, so
/// moving it moves the database time; on another backend [`World::advance_time`] moves both.
pub struct World {
    pub clock: Arc<FakeClock>,
    pub ids: Arc<FaultyIds>,
    pub store: Arc<dyn Store>,
    /// The levers a scenario needs around the store, and its name for messages.
    pub backend: Arc<dyn Backend>,
    pub artifacts: Arc<dyn ArtifactStore>,
    /// The artifact store the engine writes through. A test can make its writes fail.
    pub artifact_switch: Arc<SwitchedArtifacts>,
    pub broker: Arc<FakeModelBroker>,
    pub authority: Arc<StaticAuthority>,
    pub scripts: HashMap<StageKind, ScriptHandle>,
    pub deps: EngineDeps,
    pub config: EngineConfig,
    pub handlers: HandlerRegistry,
    pub engine: Engine,
    pub tenant: TenantId,
    pub requester: PrincipalId,
    pub repository: RepositoryId,
    pub ticker: Arc<ManualTicker>,
    next_github_user: std::sync::atomic::AtomicU64,
}

impl World {
    /// A test-mode engine with a scripted handler for every stage in the Slice 1 scope.
    pub async fn new() -> Self {
        Self::with_config(|_| {}).await
    }

    /// The same, after `tune` changed the configuration.
    pub async fn with_config(tune: impl FnOnce(&mut EngineConfig)) -> Self {
        let clock = Arc::new(FakeClock::new());
        let backend = InMemoryBackend::new(clock.clone());
        Self::on(backend, clock, Arc::new(FaultyIds::new()), tune).await
    }

    /// The same, over a store that breaks one rule of the `Store` contract on purpose.
    pub async fn with_store_defect(defect: StoreDefect) -> Self {
        let clock = Arc::new(FakeClock::new());
        let backend = InMemoryBackend::with_defect(clock.clone(), defect);
        Self::on(backend, clock, Arc::new(FaultyIds::new()), |_| {}).await
    }

    /// A world over any backend. `clock` is the engine's clock and `ids` its identifier source.
    pub async fn on(
        backend: Arc<dyn Backend>,
        clock: Arc<FakeClock>,
        ids: Arc<FaultyIds>,
        tune: impl FnOnce(&mut EngineConfig),
    ) -> Self {
        let store = backend.store();
        // The artifact store answers for a tenant from the store's index rows, as the database
        // adapter does, so an artifact the engine indexed is readable with no extra grant.
        let artifacts = backend.artifacts();
        let artifact_switch = Arc::new(SwitchedArtifacts::new(artifacts.clone()));
        let authority = Arc::new(StaticAuthority::new());
        let ticker = Arc::new(ManualTicker::new());
        let broker = Arc::new(FakeModelBroker::new(clock.clone(), ids.clone()));
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
            clock: clock.clone(),
            ids: ids.clone(),
            artifacts: artifact_switch.clone(),
            sandbox: Arc::new(FakeSandbox::new(
                clock.clone(),
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
            ticker: ticker.clone(),
        };
        let mut config = EngineConfig::new(ExecutionMode::Test, Sha256Digest::of(b"test policy"));
        tune(&mut config);
        let mut scripts = HashMap::new();
        let mut handlers = HandlerRegistry::new();
        for kind in &config.scope {
            let script = ScriptHandle::default();
            script.with(|s| s.broker = Some(broker.clone()));
            handlers
                .register(Arc::new(ScriptedHandler::new(*kind, script.clone())))
                .expect("one handler per stage");
            scripts.insert(*kind, script);
        }
        let engine = Engine::new(deps.clone(), config.clone(), handlers.clone())
            .expect("a test engine starts");

        let tenant = TenantId::from_uuid(ids.new_uuid());
        let requester = PrincipalId::from_uuid(ids.new_uuid());
        let repository = backend.seed_tenant(tenant).await;
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
            clock,
            ids,
            store,
            backend,
            artifacts,
            artifact_switch,
            broker,
            authority,
            scripts,
            deps,
            config,
            handlers,
            engine,
            tenant,
            requester,
            repository,
            ticker,
            // The requester holds 1001.
            next_github_user: std::sync::atomic::AtomicU64::new(2000),
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

    /// The concrete in-memory store. The stage rigs build more fakes on top of it.
    ///
    /// # Panics
    /// On any other backend.
    pub fn memory_store(&self) -> Arc<factory_testkit::store::InMemoryStore> {
        self.backend
            .in_memory_store()
            .expect("this rig needs the in-memory store")
    }

    /// Moves the clock, which is also the database clock. Only on the in-memory backend, whose
    /// store reads this clock; on another backend use [`World::advance_time`].
    pub fn advance(&self, seconds: u64) {
        self.clock.advance(Duration::from_secs(seconds));
    }

    /// Moves the time of the engine and of the store forward by `seconds`, on any backend. A
    /// real database has a clock of its own, so its backend moves the stored times back by the
    /// same amount instead (see the PostgreSQL backend in `apps/worker/tests`).
    pub async fn advance_time(&self, seconds: u64) {
        self.clock.advance(Duration::from_secs(seconds));
        self.backend.advance_database_time(seconds).await;
    }

    /// Moves the engine's ticker, which ends the heartbeat and teardown waits that are due, and
    /// lets the engine run until it waits again. The database clock does not move.
    pub async fn tick(&self, seconds: u64) {
        self.ticker.advance(Duration::from_secs(seconds));
        tokio::task::yield_now().await;
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

    /// Records a person in the tenant and gives them these roles on the allowlist.
    pub async fn person(&self, name: &str, roles: &[HumanRole]) -> PrincipalId {
        let id = PrincipalId::from_uuid(self.ids.new_uuid());
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        // A numeric GitHub user id that no other person of the tenant holds.
        let github_user_id = self
            .next_github_user
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

    /// A new command by a principal, with a command id of its own.
    pub fn actor(&self, principal: PrincipalId) -> Actor {
        Actor {
            tenant: self.tenant,
            principal,
            command: CausationId::from_uuid(self.ids.new_uuid()),
        }
    }

    /// Runs `count` stage runs one after another, moving the clock past every lease and back-off
    /// in between. Each must succeed.
    pub async fn run_stages(&self, count: usize) {
        for _ in 0..count {
            self.advance(400);
            let (_, outcome) = self.run_next("worker-1").await;
            assert_eq!(outcome, AttemptOutcome::Succeeded);
        }
    }

    /// A job whose stages ran to the approval, which waits for a person.
    pub async fn at_approval(&self) -> (JobId, StageRunId) {
        self.script(StageKind::Approval)
            .evals_otherwise(super::handler::Eval::HumanGate);
        let job = self.admitted_job().await;
        self.run_stages(13).await;
        let run = self
            .view(job)
            .await
            .newest(StageKind::Approval)
            .expect("an approval run")
            .id;
        (job, run)
    }

    /// The hash of the last ledger entry of a job: the evidence digest an approver sees.
    pub async fn head(&self, job: JobId) -> Sha256Digest {
        self.ledger(job)
            .await
            .last()
            .expect("an entry")
            .entry_hash
            .clone()
    }

    /// Approves a stage run as a new approver who is not the requester.
    pub async fn approve(&self, job: JobId, run: StageRunId) {
        let approver = self.person("approver-x", &[HumanRole::Approver]).await;
        let seen = self.head(job).await;
        self.engine
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

    /// A system transaction, as the engine opens to find work.
    pub async fn store_system(&self) -> Box<dyn SystemTx> {
        self.store
            .begin_system(SystemScope::engine())
            .await
            .expect("a system tx")
    }

    /// Claims the next stage run with `worker` and runs its attempt. Returns what happened.
    pub async fn run_next(&self, worker: &str) -> (ClaimedAttempt, AttemptOutcome) {
        let claimed = self.claim_one(worker).await;
        let outcome = self
            .engine
            .run_attempt(&claimed)
            .await
            .expect("the attempt runs");
        (claimed, outcome)
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

    /// The tenant's index row for an artifact.
    pub async fn index_entry(&self, sha256: &Sha256Digest) -> ArtifactIndexEntry {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let entry = tx.get_artifact_index(sha256).await.expect("an index row");
        tx.rollback().await.expect("rollback");
        entry
    }

    /// The stored row of a stage run.
    pub async fn stage_run(&self, run: StageRunId) -> StageRun {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let row = tx.get_stage_run(run).await.expect("a stage run");
        tx.rollback().await.expect("rollback");
        row.value
    }

    /// What a stage run consumed and produced, as the store links it.
    pub async fn links(&self, run: StageRunId) -> Vec<StageRunArtifact> {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let links = tx.list_stage_run_artifacts(run).await.expect("links");
        tx.rollback().await.expect("rollback");
        links
    }

    /// The audit records of a job.
    pub async fn audit(&self, job: JobId) -> Vec<AuditRecord> {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a tx");
        let rows = tx
            .read_audit(AuditFilter::Job(job), 0, 10_000)
            .await
            .expect("audit");
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
