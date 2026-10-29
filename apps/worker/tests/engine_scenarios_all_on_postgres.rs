//! The whole engine scenario suite, on the real PostgreSQL store.
//!
//! `crates/workflow/tests/engine_scenarios/body.rs` holds the scenarios. They are written against
//! the `Store` port and the `Backend` levers of the workflow crate's test harness, and
//! `crates/workflow/tests/engine_scenarios.rs` runs them on the in-memory store. This file
//! includes the very same source and runs it on [`PgStore`], with a database of its own for every
//! scenario. A disagreement between the engine and the store shows as a scenario that passes in
//! memory and fails here.
//!
//! Only the worker package may do this: it is the one package allowed to link the engine and the
//! PostgreSQL adapter together (DEP-08). The scenario `engine_scenarios/in_memory_only.rs` needs a
//! store built to lie about its commits, which PostgreSQL cannot be made to do, so it is not
//! included here.
//!
//! # The clock
//!
//! The in-memory suite moves one `FakeClock` that stands for both the engine's clock and the
//! store's. A PostgreSQL server reads its own clock, and `now()` cannot be set. So a scenario that
//! waits past a lease, a deadline, a back-off or an approval's expiry does it the way the storage
//! crate's contract runner does: [`PgBackend::advance_database_time`] moves every stored time
//! that those rules compare with the clock back by the same number of seconds, as an operator's
//! repair with the triggers off for one transaction, and the engine's own `FakeClock` moves
//! forward. To the database that is the same as the clock moving forward, and nothing waits.
//! The engine's clock starts at the real time, so the times it writes agree with the server's.
//!
//! A test that cannot get a server panics with `BLOCKED:` and is never a pass.
#![allow(
    dead_code,
    unused_imports,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

#[path = "../../../crates/storage/tests/support/server.rs"]
mod harness_server;
#[path = "../../../crates/workflow/tests/support/mod.rs"]
mod harness_shared;

mod support {
    use std::ops::Deref;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use diesel_async::SimpleAsyncConnection;
    use factory_domain::ids::{RepositoryId, TenantId};
    use factory_domain::scope::TenantScope;
    use factory_domain::values::Timestamp;
    use factory_ports::artifact::ArtifactStore;
    use factory_ports::store::{AuditFilter, AuditRecord, Store, SystemScope, WorkerId};
    use factory_storage::artifact_fs::LocalFsArtifactStore;
    use factory_storage::pg::{PgStore, PgStoreConfig, PoolSettings, TenantLogin};
    use factory_testkit::clock::FakeClock;
    use factory_workflow::engine::EngineConfig;
    use uuid::Uuid;

    use super::harness_server::{TestDb, server};
    use super::harness_shared::World as SharedWorld;
    use super::harness_shared::ids::FaultyIds;
    pub use super::harness_shared::{
        Backend, Eval, ScriptHandle, ScriptedHandler, ScriptedValidator, Step,
    };

    /// The platform tenant of migration 2, which `record_platform_audit` writes under.
    const PLATFORM: u128 = 1;

    /// A removed-on-drop scratch directory for the local artifact store.
    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// `PgStore` on a database of its own, with the local file artifact store beside it.
    struct PgBackend {
        db: TestDb,
        /// The worker and engine logins.
        store: Arc<PgStore>,
        /// What the engine is given as its store: the one above, plus the API login's store for the
        /// platform audit (see `Split`). In the `worker` variant it is the one above, alone.
        port: Arc<dyn Store>,
        artifacts: Arc<dyn ArtifactStore>,
        _scratch: Scratch,
    }

    /// The worker's store with the API login's store behind the platform audit and the two lookups,
    /// the way the deployment's two processes divide them. Since finding API-3 the API login cannot
    /// write the tables the engine writes, so no single login can run every scenario.
    struct Split {
        tenant: Arc<PgStore>,
        api: PgStore,
    }

    #[async_trait]
    impl Store for Split {
        fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
            self.tenant.fidelity()
        }

        async fn begin(
            &self,
            scope: TenantScope,
        ) -> Result<Box<dyn factory_ports::store::Tx>, factory_ports::store::StoreError> {
            self.tenant.begin(scope).await
        }

        async fn begin_system(
            &self,
            scope: SystemScope,
        ) -> Result<Box<dyn factory_ports::store::SystemTx>, factory_ports::store::StoreError>
        {
            self.tenant.begin_system(scope).await
        }

        async fn resolve_token(
            &self,
            hash: &factory_ports::store::TokenHash,
            audience: &factory_ports::store::Audience,
        ) -> Result<
            Option<factory_domain::scope::ResolvedPrincipal>,
            factory_ports::store::StoreError,
        > {
            self.api.resolve_token(hash, audience).await
        }

        async fn resolve_installation(
            &self,
            installation: factory_ports::store::InstallationId,
            repository: factory_ports::store::GithubRepositoryId,
        ) -> Result<
            Option<factory_domain::scope::ResolvedRepository>,
            factory_ports::store::StoreError,
        > {
            self.api
                .resolve_installation(installation, repository)
                .await
        }

        async fn record_platform_audit(
            &self,
            scope: factory_domain::scope::PlatformScope,
            event: factory_ports::store::NewAuditEvent,
        ) -> Result<AuditRecord, factory_ports::store::StoreError> {
            self.api.record_platform_audit(scope, event).await
        }

        async fn committed(
            &self,
            scope: TenantScope,
            witness: factory_ports::store::Witness,
        ) -> Result<bool, factory_ports::store::StoreError> {
            self.tenant.committed(scope, witness).await
        }

        async fn schema_version(
            &self,
        ) -> Result<factory_ports::store::SchemaVersion, factory_ports::store::StoreError> {
            self.tenant.schema_version().await
        }
    }

    fn small_pool(url: factory_storage::pg::DatabaseUrl) -> PoolSettings {
        let mut settings = PoolSettings::new(url);
        settings.max_connections = 6;
        settings.acquire_timeout = Duration::from_secs(20);
        settings
    }

    impl PgBackend {
        async fn start() -> Arc<Self> {
            let db = server().clone_database().await;
            let logins = db.server.logins().await;
            // The suite includes the one scenario that records a webhook rejection under the
            // platform tenant, which only the API login may do (`Store::record_platform_audit`).
            // The tenant and system work is done as the worker and engine logins, and by default
            // the platform audit goes to a second store connected as the API login (`Split`), as
            // the storage contract runner does. `FACTORY_SCENARIO_LOGIN=worker` gives the engine
            // the worker's store alone, and that scenario is then refused by design.
            let config = factory_composition::database::pools(
                small_pool(db.url(&logins.worker)),
                small_pool(db.url(&logins.engine)),
            );
            let store = Arc::new(
                PgStore::connect(config)
                    .await
                    .expect("the store becomes ready"),
            );
            let port: Arc<dyn Store> =
                if std::env::var("FACTORY_SCENARIO_LOGIN").as_deref() == Ok("worker") {
                    store.clone()
                } else {
                    let mut api = PgStoreConfig::new(small_pool(db.url(&logins.api)));
                    api.tenant_login = TenantLogin::Api;
                    Arc::new(Split {
                        tenant: store.clone(),
                        api: PgStore::connect(api)
                            .await
                            .expect("the API store becomes ready"),
                    })
                };
            let scratch = Scratch(std::env::temp_dir().join(format!(
                "factory-scenarios-{}",
                Uuid::from_u128(rand_bits()).simple()
            )));
            let artifacts: Arc<dyn ArtifactStore> = Arc::new(
                LocalFsArtifactStore::open(&scratch.0, 64 * 1024 * 1024, store.clone())
                    .expect("the artifact root opens"),
            );
            Arc::new(Self {
                db,
                store,
                port,
                artifacts,
                _scratch: scratch,
            })
        }

        async fn audit_of(&self, tenant: TenantId) -> Vec<AuditRecord> {
            let mut tx = self
                .store
                .begin(TenantScope::new(tenant))
                .await
                .expect("begin");
            tx.read_audit(AuditFilter::Tenant, 0, 1000)
                .await
                .expect("read the audit log")
        }
    }

    /// Bits for a scratch directory name. The scenarios never depend on them.
    fn rand_bits() -> u128 {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let pid = u128::from(std::process::id());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        (now << 32) ^ (pid << 16) ^ u128::from(n)
    }

    #[async_trait]
    impl Backend for PgBackend {
        fn name(&self) -> &'static str {
            "postgresql"
        }

        fn store(&self) -> Arc<dyn Store> {
            self.port.clone()
        }

        fn artifacts(&self) -> Arc<dyn ArtifactStore> {
            self.artifacts.clone()
        }

        async fn seed_tenant(&self, tenant: TenantId) -> RepositoryId {
            let id = tenant.as_uuid();
            let repository = Uuid::from_u128(id.as_u128() ^ 0x5eed);
            self.db
                .run(&format!(
                    "INSERT INTO tenants (id, slug, display_name) \
                     VALUES ('{id}', 'scenario-{}', 'Scenario tenant'); \
                     INSERT INTO repositories (tenant_id, id, github_installation_id, \
                            github_repository_id, full_name, default_branch) \
                     VALUES ('{id}', '{repository}', 1000, 2000, 'example-org/fixture', 'main');",
                    &id.simple().to_string()[..12]
                ))
                .await;
            RepositoryId::from_uuid(repository)
        }

        /// Moves the database clock forward by `seconds`.
        ///
        /// A rule compares stored times with `now()`, which cannot be set. So every stored time
        /// that such a rule reads moves back by `seconds`, which is the same to the comparison,
        /// and nothing waits. The engine must therefore decide on the stored row it read in its
        /// transaction and never on a copy it carries from before the clock moved: a copy would
        /// still hold the old time (the timeout of an attempt did, until the engine took the
        /// deadline from the attempt row).
        async fn advance_database_time(&self, seconds: u64) {
            let shift = format!("make_interval(secs => {seconds})");
            let mut admin = self.db.admin().await;
            admin
                .batch_execute(&format!(
                    "BEGIN; SET LOCAL session_replication_role = replica; \
                     UPDATE attempts SET lease_expires_at = lease_expires_at - {shift}, \
                            deadline_at = deadline_at - {shift}, \
                            teardown_deadline_at = teardown_deadline_at - {shift}, \
                            last_heartbeat_at = last_heartbeat_at - {shift}, \
                            created_at = created_at - {shift}, ended_at = ended_at - {shift}; \
                     UPDATE stage_runs SET not_before = not_before - {shift}, \
                            created_at = created_at - {shift}, finished_at = finished_at - {shift}, \
                            superseded_at = superseded_at - {shift}; \
                     UPDATE approvals SET expires_at = expires_at - {shift}, \
                            created_at = created_at - {shift}, invalidated_at = invalidated_at - {shift}; \
                     COMMIT;"
                ))
                .await
                .expect("move the stored times");
        }

        async fn lose_next_commit_answer(&self) {
            self.store.lose_next_commit_answer();
        }

        async fn platform_audit(&self) -> Vec<AuditRecord> {
            self.audit_of(TenantId::from_uuid(Uuid::from_u128(PLATFORM)))
                .await
        }

        async fn tenant_audit(&self, tenant: TenantId) -> Vec<AuditRecord> {
            self.audit_of(tenant).await
        }
    }

    /// The scenario world over PostgreSQL. It has the constructors the scenarios call and
    /// everything else of the shared world through `Deref`.
    pub struct World(SharedWorld);

    impl Deref for World {
        type Target = SharedWorld;

        fn deref(&self) -> &SharedWorld {
            &self.0
        }
    }

    impl std::ops::DerefMut for World {
        fn deref_mut(&mut self) -> &mut SharedWorld {
            &mut self.0
        }
    }

    impl World {
        pub async fn new() -> Self {
            Self::with_config(|_| {}).await
        }

        pub async fn with_config(tune: impl FnOnce(&mut EngineConfig)) -> Self {
            let backend = PgBackend::start().await;
            // The engine's clock starts at the real time so that what it writes agrees with the
            // server. It is moved by `advance_time`, in step with the stored times.
            let now = Timestamp::from_utc(time::OffsetDateTime::now_utc());
            let clock = Arc::new(FakeClock::starting_at(&now.as_text()));
            let ids = Arc::new(FaultyIds::new());
            Self(SharedWorld::on(backend, clock, ids, tune).await)
        }

        pub fn worker(name: &str) -> WorkerId {
            SharedWorld::worker(name)
        }
    }
}

include!("../../../crates/workflow/tests/engine_scenarios/body.rs");
