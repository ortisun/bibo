//! Shared support for the database tests of `factory-storage`.
//!
//! A test calls [`Scene::new`] and gets a migrated database of its own, two tenants that each have
//! a repository, and a store connected the way the deployment connects it: the tenant pool as the
//! API login (a member of `factory_api_app` and `factory_resolver`: it opens tenant transactions for
//! the four tables the API writes and may call the lookups), the system pool as the engine login. Fixtures that create tenants run as the
//! superuser, because the application role cannot insert into `tenants` by design. Everything the
//! code under test does, it does as an application login.
#![allow(dead_code)]

pub mod server;

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use diesel_async::SimpleAsyncConnection;
use factory_domain::ids::{AttemptId, JobId, PrincipalId, RepositoryId, StageRunId, TenantId};
use factory_domain::machines::failure::FailureClass;
use factory_domain::scope::TenantScope;
use factory_domain::state::{
    AttemptEvent, AttemptStatus, Guard, JobEvent, JobStatus, StageRunEvent, StageRunStatus, Status,
};
use factory_domain::values::{MediaType, NonNegativeInt, Sha256Digest, Timestamp};
use factory_domain::vocabulary::{AutonomyLevel, ExecutionMode, StageKind};
use factory_ports::store::{
    AppliedTransition, AttemptEnd, NewArtifactIndexEntry, NewJob, NewPrincipal, NewStageRun,
    PipelineScope, PrincipalKind, StageRunEffects, StartAttempt, StartedAttempt, Store, StoreError,
    SystemScope, SystemTx, Tx, Version, WorkerId,
};
use factory_storage::pg::{PgStore, PgStoreConfig, PoolSettings, TenantLogin};
use factory_testkit::fixtures::{Ids, SeededRepository, cleared};
use uuid::Uuid;

pub use server::{Login, TestDb, server};

/// A pool of a few connections, which is enough for the tests and keeps the server's connection
/// count low when many tests run at once.
pub fn small_pool(url: factory_storage::pg::DatabaseUrl) -> PoolSettings {
    let mut settings = PoolSettings::new(url);
    settings.max_connections = 12;
    settings.acquire_timeout = Duration::from_secs(20);
    settings
}

/// The configuration the tests use for the work of a tenant: the worker login on the tenant pool,
/// the engine login on the system pool. Since finding API-3 the API login is a narrow group of its
/// own (`factory_api_app`) and cannot write most tables, so it is not this store. The lookups and
/// the platform audit belong to the API's store: [`api_config_for`], and [`SplitStore`] joins the
/// two for a suite that expects one store to do everything.
pub async fn config_for(db: &TestDb) -> PgStoreConfig {
    let logins = db.server.logins().await;
    let mut config = PgStoreConfig::new(small_pool(db.url(&logins.worker)));
    config.system = Some(small_pool(db.url(&logins.engine)));
    config
}

/// The configuration of the API process: the API login, no system pool.
pub async fn api_config_for(db: &TestDb) -> PgStoreConfig {
    let logins = db.server.logins().await;
    let mut config = PgStoreConfig::new(small_pool(db.url(&logins.api)));
    config.tenant_login = TenantLogin::Api;
    config
}

/// Two real stores that answer as one, the way the deployment's two processes do together: the
/// tenant and system work goes to the worker and engine logins, the two lookups and the platform
/// audit to the API login. It exists so that the store contract, which expects one store to do
/// all of it, still runs against real logins that each hold only their own privileges.
pub struct SplitStore {
    pub tenant: std::sync::Arc<PgStore>,
    pub api: PgStore,
}

#[async_trait::async_trait]
impl Store for SplitStore {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        self.tenant.fidelity()
    }

    async fn begin(&self, scope: TenantScope) -> Result<Box<dyn Tx>, StoreError> {
        self.tenant.begin(scope).await
    }

    async fn begin_system(&self, scope: SystemScope) -> Result<Box<dyn SystemTx>, StoreError> {
        self.tenant.begin_system(scope).await
    }

    async fn resolve_token(
        &self,
        hash: &factory_ports::store::TokenHash,
        audience: &factory_ports::store::Audience,
    ) -> Result<Option<factory_domain::scope::ResolvedPrincipal>, StoreError> {
        self.api.resolve_token(hash, audience).await
    }

    async fn resolve_installation(
        &self,
        installation: factory_ports::store::InstallationId,
        repository: factory_ports::store::GithubRepositoryId,
    ) -> Result<Option<factory_domain::scope::ResolvedRepository>, StoreError> {
        self.api
            .resolve_installation(installation, repository)
            .await
    }

    async fn record_platform_audit(
        &self,
        scope: factory_domain::scope::PlatformScope,
        event: factory_ports::store::NewAuditEvent,
    ) -> Result<factory_ports::store::AuditRecord, StoreError> {
        self.api.record_platform_audit(scope, event).await
    }

    async fn committed(
        &self,
        scope: TenantScope,
        witness: factory_ports::store::Witness,
    ) -> Result<bool, StoreError> {
        self.tenant.committed(scope, witness).await
    }

    async fn schema_version(&self) -> Result<factory_ports::store::SchemaVersion, StoreError> {
        self.tenant.schema_version().await
    }
}

/// The configuration of a worker process: the worker login, no system pool.
pub async fn worker_config_for(db: &TestDb) -> PgStoreConfig {
    let logins = db.server.logins().await;
    PgStoreConfig::new(small_pool(db.url(&logins.worker)))
}

/// A database, two tenants and a store.
pub struct Scene {
    pub db: TestDb,
    /// The worker and engine logins.
    pub store: PgStore,
    /// The API login: the lookups and the platform audit.
    pub api: PgStore,
    pub ids: Ids,
    pub a: TenantId,
    pub b: TenantId,
}

impl Scene {
    pub async fn new() -> Self {
        let db = server().clone_database().await;
        let ids = Ids::new();
        let (a, b) = (ids.tenant(), ids.tenant());
        for (position, tenant) in [a, b].into_iter().enumerate() {
            seed_tenant(&db, tenant, position).await;
        }
        let store = PgStore::connect(config_for(&db).await)
            .await
            .expect("the store becomes ready");
        let api = PgStore::connect(api_config_for(&db).await)
            .await
            .expect("the API store becomes ready");
        Self {
            db,
            store,
            api,
            ids,
            a,
            b,
        }
    }

    /// The repository the scene seeded for a tenant.
    pub fn repository(&self, tenant: TenantId) -> RepositoryId {
        seeded_repository(tenant)
    }

    pub async fn tx(&self, tenant: TenantId) -> Box<dyn Tx> {
        self.store
            .begin(TenantScope::new(tenant))
            .await
            .expect("begin")
    }

    pub async fn system(&self) -> Box<dyn SystemTx> {
        self.store
            .begin_system(SystemScope::engine())
            .await
            .expect("begin_system")
    }

    pub async fn principal(&self, tenant: TenantId) -> PrincipalId {
        let id = self.ids.principal();
        let mut tx = self.tx(tenant).await;
        tx.insert_principal(NewPrincipal {
            id,
            kind: PrincipalKind::Human {
                github_user_id: next_github_id(),
            },
            login: Some("octocat".to_owned()),
        })
        .await
        .expect("insert principal");
        tx.commit().await.expect("commit principal");
        id
    }

    /// A new job in `RECEIVED`, committed.
    pub async fn job(&self, tenant: TenantId) -> JobId {
        let requester = self.principal(tenant).await;
        let id = self.ids.job();
        let mut tx = self.tx(tenant).await;
        tx.insert_job(NewJob {
            id,
            correlation_id: self.ids.correlation(),
            repository: self.repository(tenant),
            requester,
            execution_mode: ExecutionMode::Test,
            autonomy_level: AutonomyLevel::L1,
            pipeline_scope: PipelineScope::new(vec![StageKind::Intake]).expect("a scope"),
            origin: None,
        })
        .await
        .expect("insert job");
        tx.commit().await.expect("commit job");
        id
    }

    /// Moves a job from `RECEIVED` to `ACTIVE`, committed.
    pub async fn admit(&self, tenant: TenantId, job: JobId) {
        let mut tx = self.tx(tenant).await;
        let read = tx.get_job(job).await.expect("get job");
        assert_eq!(read.value.status, JobStatus::Received);
        let plan = AppliedTransition::plan(
            JobStatus::Received,
            JobEvent::Admit,
            at(),
            cleared(Guard::AdmissionOk),
        )
        .expect("J01");
        tx.transition_job(job, read.version, plan)
            .await
            .expect("admit");
        tx.commit().await.expect("commit admit");
    }

    /// An `ACTIVE` job.
    pub async fn active_job(&self, tenant: TenantId) -> JobId {
        let job = self.job(tenant).await;
        self.admit(tenant, job).await;
        job
    }

    /// A stage run in `READY` (back-off zero), committed.
    pub async fn ready_stage_run(&self, tenant: TenantId, job: JobId) -> StageRunId {
        let id = self.ids.stage_run();
        let mut tx = self.tx(tenant).await;
        let inserted = tx
            .insert_stage_run(NewStageRun {
                id,
                job_id: job,
                kind: StageKind::Intake,
                run_number: 1,
                max_attempts: 3,
                rework_of: None,
            })
            .await
            .expect("insert stage run");
        let plan = AppliedTransition::plan(
            StageRunStatus::INITIAL,
            StageRunEvent::PreconditionsMet,
            at(),
            cleared(Guard::UpstreamPassed),
        )
        .expect("S01");
        // The contract is an artifact the tenant has indexed; the table has a key to it.
        let contract = index_blob(&mut *tx, b"contract").await;
        let effects = StageRunEffects {
            contract_sha256: Some(contract),
            ..StageRunEffects::default()
        };
        tx.transition_stage_run(id, inserted.row.version, plan, effects)
            .await
            .expect("ready");
        tx.commit().await.expect("commit stage run");
        id
    }

    /// Starts an attempt for a `READY` stage run in a transaction of its own and commits it.
    pub async fn start(
        &self,
        tenant: TenantId,
        run: StageRunId,
        worker: &str,
    ) -> Result<StartedAttempt, StoreError> {
        let mut tx = self.tx(tenant).await;
        let version = tx.get_stage_run(run).await?.version;
        let started = start_in(&mut *tx, run, version, worker).await?;
        tx.commit().await?;
        Ok(started)
    }

    /// Ends the live attempt as failed and moves the run back to `READY` after `delay`.
    pub async fn fail_and_retry(
        &self,
        tenant: TenantId,
        started: &StartedAttempt,
        delay: Duration,
    ) {
        let mut tx = self.tx(tenant).await;
        let attempt = tx
            .get_attempt(started.attempt.value.id)
            .await
            .expect("read");
        let fail = AppliedTransition::plan(
            AttemptStatus::Starting,
            AttemptEvent::ProvisionFailed,
            at(),
            cleared(Guard::EpochCurrent),
        )
        .expect("A02");
        let end = AttemptEnd {
            failure_class: Some(FailureClass::SandboxError),
            ..AttemptEnd::default()
        };
        tx.transition_attempt(
            attempt.value.id,
            attempt.version,
            attempt.value.epoch,
            fail,
            end,
        )
        .await
        .expect("end the attempt");
        let run = tx
            .get_stage_run(started.attempt.value.stage_run_id)
            .await
            .expect("read the run");
        let retry = AppliedTransition::plan(
            StageRunStatus::Running,
            StageRunEvent::AttemptFailedRetryable,
            at(),
            cleared(Guard::RetryAllowed),
        )
        .expect("S05");
        let effects = StageRunEffects {
            not_before_after: Some(delay),
            ..StageRunEffects::default()
        };
        tx.transition_stage_run(run.value.id, run.version, retry, effects)
            .await
            .expect("schedule the retry");
        tx.commit().await.expect("commit the retry");
    }

    /// Every attempt of a stage run in number order, as the superuser sees it: id, number,
    /// status, epoch.
    pub async fn attempts_of(&self, stage_run: StageRunId) -> Vec<(Uuid, i64, String, i64)> {
        let count = self
            .db
            .number(&format!(
                "SELECT count(*) FROM attempts WHERE stage_run_id = '{}'",
                stage_run.as_uuid()
            ))
            .await;
        let mut found = Vec::new();
        for position in 0..count {
            let row = |column: &str| {
                format!(
                    "SELECT {column} FROM attempts WHERE stage_run_id = '{}' ORDER BY attempt_number OFFSET {position}",
                    stage_run.as_uuid()
                )
            };
            let id = self.db.text(&row("id")).await.expect("id");
            found.push((
                Uuid::parse_str(&id).expect("uuid"),
                self.db.number(&row("attempt_number")).await,
                self.db.text(&row("status")).await.expect("status"),
                self.db.number(&row("lease_epoch")).await,
            ));
        }
        found
    }
}

/// Indexes a blob of these bytes for the tenant of the transaction and returns its hash.
pub async fn index_blob(tx: &mut dyn Tx, bytes: &[u8]) -> Sha256Digest {
    let sha256 = Sha256Digest::of(bytes);
    tx.index_artifact(NewArtifactIndexEntry {
        sha256: sha256.clone(),
        media_type: MediaType::parse("text/plain").expect("media type"),
        size_bytes: NonNegativeInt::new(i64::try_from(bytes.len()).expect("small"))
            .expect("a size"),
        origin: None,
    })
    .await
    .expect("index the blob");
    sha256
}

/// Starts an attempt for a stage run read at `version`, in the transaction given.
pub async fn start_in(
    tx: &mut dyn Tx,
    run: StageRunId,
    version: Version,
    worker: &str,
) -> Result<StartedAttempt, StoreError> {
    let transition = AppliedTransition::plan(
        StageRunStatus::Ready,
        StageRunEvent::Start,
        at(),
        cleared(Guard::LeaseAcquired),
    )
    .expect("S03");
    tx.start_attempt(StartAttempt {
        attempt: AttemptId::from_uuid(Uuid::from_u128((1 << 100) | u128::from(next_github_id()))),
        stage_run: run,
        expected: version,
        worker: WorkerId::new(worker).expect("a worker name"),
        lease_ttl: Duration::from_secs(60),
        attempt_timeout: Duration::from_secs(600),
        transition,
    })
    .await
}

/// A fixed instant for the field the engine plans and the store ignores.
pub fn at() -> Timestamp {
    Timestamp::parse("2026-10-27T10:00:00Z").expect("a valid time")
}

static GITHUB_IDS: AtomicI64 = AtomicI64::new(5000);

/// A GitHub user id that no other call of this process used.
pub fn next_github_id() -> u64 {
    u64::try_from(GITHUB_IDS.fetch_add(1, Ordering::Relaxed)).expect("positive")
}

/// The id of the repository `seed_tenant` makes for a tenant.
pub fn seeded_repository(tenant: TenantId) -> RepositoryId {
    RepositoryId::from_uuid(Uuid::from_u128(tenant.as_uuid().as_u128() ^ 0x5eed))
}

/// Inserts a tenant and one enabled repository for it, as the superuser.
pub async fn seed_tenant(db: &TestDb, tenant: TenantId, position: usize) {
    let id = tenant.as_uuid();
    let slug = format!("tenant-{position}-{}", &id.simple().to_string()[..8]);
    let repository = seeded_repository(tenant).as_uuid();
    let installation = i64::try_from(1000 + position).expect("small");
    let github_repository = i64::try_from(2000 + position).expect("small");
    let repository_sql = SeededRepository {
        tenant: &id.to_string(),
        id: &repository.to_string(),
        installation: u64::try_from(installation).expect("positive"),
        github_repository: u64::try_from(github_repository).expect("positive"),
        full_name: &format!("org/repo-{position}"),
        default_branch: "main",
        autonomy_ceiling: "L0",
    }
    .sql();
    db.run(&format!(
        "INSERT INTO tenants (id, slug, display_name) VALUES ('{id}', '{slug}', 'Tenant {position}'); \
         {repository_sql}"
    ))
    .await;
}

/// Runs one statement as a login, inside one transaction that is always rolled back, with the
/// tenant setting made first when `tenant_setting` is given. The statement must return a column
/// named `v`. Gives the text of that column in the first row (`None` for no row), or the text of
/// the database error. For tests that probe the policy with raw SQL, which the `Tx` type does not
/// allow, so the error text here is for the test to read and never reaches a caller.
pub async fn as_login(
    db: &TestDb,
    login: &Login,
    tenant_setting: Option<&str>,
    sql: &str,
) -> Result<Option<String>, String> {
    use diesel::sql_query;
    use diesel_async::RunQueryDsl;
    let mut connection = db.connect_as(login).await;
    connection
        .batch_execute("BEGIN")
        .await
        .map_err(|error| error.to_string())?;
    if let Some(value) = tenant_setting {
        connection
            .batch_execute(&format!(
                "SELECT set_config('factory.tenant_id', '{value}', true)"
            ))
            .await
            .map_err(|error| error.to_string())?;
    }
    let outcome = sql_query(sql)
        .get_result::<server::Scalar>(&mut connection)
        .await;
    let _ = connection.batch_execute("ROLLBACK").await;
    match outcome {
        Ok(row) => Ok(Some(row.v)),
        Err(diesel::result::Error::NotFound) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}
