//! Shared support for the database tests of `factory-storage`.
//!
//! A test calls [`Scene::new`] and gets a migrated database of its own, two tenants that each have
//! a repository, and a store connected the way the deployment connects it: the tenant pool as the
//! worker login, the system pool as the engine login. Fixtures that create tenants run as the
//! superuser, because the application role cannot insert into `tenants` by design. Everything the
//! code under test does, it does as an application login.
#![allow(dead_code)]

pub mod server;

use std::sync::Arc;
use std::time::Duration;

use diesel_async::SimpleAsyncConnection;
use factory_domain::ids::{AttemptId, JobId, PrincipalId, StageRunId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobEvent, JobStatus, StageRunEvent, StageRunStatus, Status};
use factory_domain::values::{NonEmptyString, Timestamp};
use factory_domain::vocabulary::{ExecutionMode, StageKind};
use factory_ports::store::{
    AppliedTransition, NewJob, NewPrincipal, NewStageRun, Store, SystemScope, Tx, Version, WorkerId,
};
use factory_storage::pg::{PgStore, PgStoreConfig, PoolSettings, TenantLogin};
use factory_testkit::fixtures::Ids;
use uuid::Uuid;

pub use server::{Login, TestDb, server};

/// The time now, for the fields the port takes from the caller's clock.
pub fn now() -> Timestamp {
    Timestamp::from_utc(time::OffsetDateTime::now_utc())
}

/// A pool of a few connections, which is enough for the tests and keeps the server's connection
/// count low when many tests run at once.
pub fn small_pool(url: factory_storage::pg::DatabaseUrl) -> PoolSettings {
    let mut settings = PoolSettings::new(url);
    settings.max_connections = 6;
    settings.acquire_timeout = Duration::from_secs(20);
    settings
}

/// The configuration the deployment would use, on a test database.
pub async fn config_for(db: &TestDb) -> PgStoreConfig {
    let logins = db.server.logins().await;
    let mut config = PgStoreConfig::new(small_pool(db.url(&logins.worker)));
    config.tenant_login = TenantLogin::Worker;
    config.system = Some(small_pool(db.url(&logins.engine)));
    config.execution_mode = ExecutionMode::Test;
    config
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
    /// A scene whose claims take any job, as the shared contract fixtures need.
    pub async fn new() -> Self {
        Self::with(|config| config.claim_only_active_jobs = false).await
    }

    /// A scene with the configuration changed by `adjust`.
    pub async fn with(adjust: impl FnOnce(&mut PgStoreConfig)) -> Self {
        let db = server().clone_database().await;
        let ids = Ids::new();
        let (a, b) = (ids.tenant(), ids.tenant());
        for (position, tenant) in [a, b].into_iter().enumerate() {
            seed_tenant(&db, tenant, position).await;
        }
        let mut config = config_for(&db).await;
        adjust(&mut config);
        let store = PgStore::connect(config)
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

    pub async fn tenant_tx(&self, tenant: TenantId) -> Box<dyn Tx> {
        self.store
            .begin(TenantScope::new(tenant))
            .await
            .expect("begin")
    }

    pub async fn system_tx(&self) -> Box<dyn Tx> {
        self.store
            .begin_system(SystemScope::engine())
            .await
            .expect("begin_system")
    }

    pub async fn principal(&self, tenant: TenantId) -> PrincipalId {
        let id = self.ids.principal();
        let mut tx = self.tenant_tx(tenant).await;
        tx.insert_principal(NewPrincipal {
            id,
            external_ref: NonEmptyString::parse(&format!("user-{id}")).expect("ref"),
            created_at: now(),
        })
        .await
        .expect("insert principal");
        tx.commit().await.expect("commit principal");
        id
    }

    /// A job in `RECEIVED`, committed.
    pub async fn job(&self, tenant: TenantId) -> JobId {
        let requester = self.principal(tenant).await;
        let id = self.ids.job();
        let mut tx = self.tenant_tx(tenant).await;
        tx.insert_job(NewJob {
            id,
            correlation_id: self.ids.correlation(),
            requester,
            created_at: now(),
        })
        .await
        .expect("insert job");
        tx.commit().await.expect("commit job");
        id
    }

    /// Moves a job from `RECEIVED` to `ACTIVE`, committed.
    pub async fn admit(&self, tenant: TenantId, job: JobId) {
        let mut tx = self.tenant_tx(tenant).await;
        let read = tx.get_job(job).await.expect("get job");
        assert_eq!(read.value.status, JobStatus::Received);
        let plan =
            AppliedTransition::plan(JobStatus::Received, JobEvent::Admit, now()).expect("J01");
        tx.transition_job(job, read.version, plan)
            .await
            .expect("admit");
        tx.commit().await.expect("commit admit");
    }

    /// A stage run in `READY`, committed.
    pub async fn ready_stage_run(&self, tenant: TenantId, job: JobId) -> StageRunId {
        let id = self.ids.stage_run();
        let mut tx = self.tenant_tx(tenant).await;
        let inserted = tx
            .insert_stage_run(NewStageRun {
                id,
                job_id: job,
                kind: StageKind::Intake,
                created_at: now(),
            })
            .await
            .expect("insert stage run");
        let plan = AppliedTransition::plan(
            StageRunStatus::INITIAL,
            StageRunEvent::PreconditionsMet,
            now(),
        )
        .expect("S01");
        tx.transition_stage_run(id, inserted.version, plan)
            .await
            .expect("ready");
        tx.commit().await.expect("commit stage run");
        id
    }

    /// Claims in a system transaction with a lease of 60 seconds, and commits.
    pub async fn claim(&self, worker: &str, limit: u32) -> Vec<factory_ports::store::ClaimedWork> {
        self.claim_for(worker, limit, Duration::from_secs(60)).await
    }

    /// Claims in a system transaction with a lease of `ttl`, and commits.
    pub async fn claim_for(
        &self,
        worker: &str,
        limit: u32,
        ttl: Duration,
    ) -> Vec<factory_ports::store::ClaimedWork> {
        let mut tx = self.system_tx().await;
        let claimed = tx
            .claim_ready(&WorkerId::new(worker).expect("worker"), limit, ttl)
            .await
            .expect("claim");
        tx.commit().await.expect("commit claim");
        claimed
    }

    /// The newest attempt of a stage run, as the superuser sees it: id, number, status, epoch.
    pub async fn newest_attempt(&self, stage_run: StageRunId) -> (AttemptId, i64, String, i64) {
        self.attempts_of(stage_run)
            .await
            .into_iter()
            .last()
            .expect("the stage run has an attempt")
    }

    /// Every attempt of a stage run in number order.
    pub async fn attempts_of(&self, stage_run: StageRunId) -> Vec<(AttemptId, i64, String, i64)> {
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
                AttemptId::from_uuid(Uuid::parse_str(&id).expect("uuid")),
                self.db.number(&row("attempt_number")).await,
                self.db.text(&row("status")).await.expect("status"),
                self.db.number(&row("lease_epoch")).await,
            ));
        }
        found
    }
}

/// Inserts a tenant and one enabled repository for it, as the superuser.
pub async fn seed_tenant(db: &TestDb, tenant: TenantId, position: usize) {
    let id = tenant.as_uuid();
    let slug = format!("tenant-{position}-{}", &id.simple().to_string()[..8]);
    let repository = Uuid::from_u128(id.as_u128() ^ 0x5eed);
    let installation = i64::try_from(1000 + position).expect("small");
    let github_repository = i64::try_from(2000 + position).expect("small");
    db.run(&format!(
        "INSERT INTO tenants (id, slug, display_name) VALUES ('{id}', '{slug}', 'Tenant {position}'); \
         INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch) \
         VALUES ('{id}', '{repository}', {installation}, {github_repository}, 'org/repo-{position}', 'main');"
    ))
    .await;
}

/// A shared handle to a version, for readability.
pub fn first_version() -> Version {
    Version::FIRST
}

pub type SharedScene = Arc<Scene>;

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
