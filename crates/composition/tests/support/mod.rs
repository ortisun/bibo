//! Shared support for the database tests of `factory-worker`.
//!
//! The real PostgreSQL server and the cloned, migrated databases are the ones the storage crate's
//! tests use: the file is included as it is, with `#[path]`, so there is one provisioning code.
//! A test calls [`Scene::new`] and gets a database of its own, two tenants that each have a
//! repository, and a store connected the way the worker connects it: the worker login on the
//! tenant pool and the engine login on the system pool.
#![allow(
    dead_code,
    unused_imports,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

pub mod engine;
#[path = "../../../../crates/storage/tests/support/server.rs"]
pub mod server;

use std::time::Duration;

use factory_domain::ids::{RepositoryId, TenantId};
use factory_storage::pg::{PgStore, PgStoreConfig, PoolSettings};
use factory_testkit::fixtures::SeededRepository;
use uuid::Uuid;

pub use server::{Login, TestDb, server};

/// Pool settings with a short acquire timeout and few connections, so many tests can share a
/// server.
pub fn small_pool(url: factory_storage::pg::DatabaseUrl) -> PoolSettings {
    let mut settings = PoolSettings::new(url);
    settings.max_connections = 6;
    settings.acquire_timeout = Duration::from_secs(20);
    settings
}

/// The configuration of a worker process over a test database.
pub async fn worker_config(db: &TestDb) -> PgStoreConfig {
    let logins = db.server.logins().await;
    factory_composition::database::pools(
        small_pool(db.url(&logins.worker)),
        small_pool(db.url(&logins.engine)),
    )
}

/// The repository `seed_tenant` makes for a tenant.
pub fn seeded_repository(tenant: TenantId) -> RepositoryId {
    RepositoryId::from_uuid(Uuid::from_u128(tenant.as_uuid().as_u128() ^ 0x5eed))
}

/// Inserts a tenant and one enabled repository for it, as the superuser.
pub async fn seed_tenant(db: &TestDb, tenant: TenantId, position: usize, full_name: &str) {
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
        full_name,
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

/// A database, one tenant with a repository, and a connected store.
pub struct Scene {
    pub db: TestDb,
    pub store: PgStore,
    pub tenant: TenantId,
}

impl Scene {
    pub async fn new() -> Self {
        let db = server().clone_database().await;
        let tenant = TenantId::from_uuid(Uuid::new_v4_for_tests());
        seed_tenant(&db, tenant, 0, "org/repo-0").await;
        let store = PgStore::connect(worker_config(&db).await)
            .await
            .expect("the store becomes ready");
        Self { db, store, tenant }
    }
}

/// Test identifiers without the `uuid` generator features: the server's own run id and a counter.
trait TestUuid {
    fn new_v4_for_tests() -> Uuid;
}

impl TestUuid for Uuid {
    fn new_v4_for_tests() -> Uuid {
        let ids = factory_composition::system::RandomIds::new().expect("the random source opens");
        factory_ports::clock::IdGenerator::new_uuid(&ids)
    }
}

/// A database of its own, a tenant with a repository, and a whole engine over the real store. The
/// stage handlers are the engine suite's scripted ones.
pub async fn pg_world() -> (TestDb, engine::PgWorld, TenantId) {
    let db = server().clone_database().await;
    let ids = factory_composition::system::RandomIds::new().expect("the random source opens");
    let tenant = TenantId::from_uuid(factory_ports::clock::IdGenerator::new_uuid(&ids));
    seed_tenant(&db, tenant, 0, "org/repo-0").await;
    let store = PgStore::connect(worker_config(&db).await)
        .await
        .expect("the store becomes ready");
    let world = engine::PgWorld::new(store, tenant, seeded_repository(tenant), |_| {}).await;
    (db, world, tenant)
}
