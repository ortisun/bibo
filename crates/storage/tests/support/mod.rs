//! Shared support for the database tests of `factory-storage`.
//!
//! A test calls [`Scene::new`] and gets a migrated database of its own, two tenants that each have
//! a repository, and a store connected the way the deployment connects it: the tenant pool as the
//! API login (which is also a member of `factory_app`, so it opens tenant transactions and may call
//! the lookups), the system pool as the engine login. Fixtures that create tenants run as the
//! superuser, because the application role cannot insert into `tenants` by design. Everything the
//! code under test does, it does as an application login.
#![allow(dead_code)]

pub mod server;

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use diesel_async::SimpleAsyncConnection;
use factory_domain::ids::{JobId, PrincipalId, RepositoryId, StageRunId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::state::{Guard, JobEvent, JobStatus, StageRunEvent, StageRunStatus, Status};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::{AutonomyLevel, ExecutionMode, StageKind};
use factory_ports::store::{
    AppliedTransition, NewJob, NewPrincipal, NewStageRun, PipelineScope, PrincipalKind,
    StageRunEffects, Store, SystemScope, SystemTx, Tx,
};
use factory_storage::pg::{PgStore, PgStoreConfig, PoolSettings, TenantLogin};
use factory_testkit::fixtures::{Ids, cleared};
use uuid::Uuid;

pub use server::{Login, TestDb, server};

/// A pool of a few connections, which is enough for the tests and keeps the server's connection
/// count low when many tests run at once.
pub fn small_pool(url: factory_storage::pg::DatabaseUrl) -> PoolSettings {
    let mut settings = PoolSettings::new(url);
    settings.max_connections = 6;
    settings.acquire_timeout = Duration::from_secs(20);
    settings
}

/// The configuration the tests use: the API login on the tenant pool (it can open tenant
/// transactions and call the lookups), the engine login on the system pool.
pub async fn config_for(db: &TestDb) -> PgStoreConfig {
    let logins = db.server.logins().await;
    let mut config = PgStoreConfig::new(small_pool(db.url(&logins.api)));
    config.tenant_login = TenantLogin::Api;
    config.system = Some(small_pool(db.url(&logins.engine)));
    config
}

/// The configuration of a worker process: the worker login, no system pool.
pub async fn worker_config_for(db: &TestDb) -> PgStoreConfig {
    let logins = db.server.logins().await;
    PgStoreConfig::new(small_pool(db.url(&logins.worker)))
}

/// A database, two tenants and a store.
pub struct Scene {
    pub db: TestDb,
    pub store: PgStore,
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
        Self {
            db,
            store,
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
        let effects = StageRunEffects {
            contract_sha256: Some(factory_domain::values::Sha256Digest::of(b"contract")),
            ..StageRunEffects::default()
        };
        tx.transition_stage_run(id, inserted.row.version, plan, effects)
            .await
            .expect("ready");
        tx.commit().await.expect("commit stage run");
        id
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
    db.run(&format!(
        "INSERT INTO tenants (id, slug, display_name) VALUES ('{id}', '{slug}', 'Tenant {position}'); \
         INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch) \
         VALUES ('{id}', '{repository}', {installation}, {github_repository}, 'org/repo-{position}', 'main');"
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
