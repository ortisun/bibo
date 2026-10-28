//! What the scenario [`World`](super::World) needs from a store that the `Store` port does not
//! offer: making a tenant, moving the database clock, and the two faults of the contract suite.
//!
//! The engine scenarios drive the engine through the public API and the `Store` port only, so the
//! same suite can run on another store. This trait is the whole of what differs between stores:
//! the in-memory one here, and PostgreSQL in `apps/worker/tests` (the only package that may link
//! the engine and the PostgreSQL adapter together, DEP-08).

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::ids::{RepositoryId, TenantId};
use factory_ports::artifact::ArtifactStore;
use factory_ports::store::{AuditRecord, Store};
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::clock::FakeClock;
use factory_testkit::store::{InMemoryStore, StoreDefect};

/// A store and the levers a scenario needs around it.
#[async_trait]
pub trait Backend: Send + Sync {
    /// A short name for messages.
    fn name(&self) -> &'static str;

    /// The store the engine runs on.
    fn store(&self) -> Arc<dyn Store>;

    /// The artifact store the engine writes through. It answers for a tenant from the store's
    /// index rows, as the database adapter does.
    fn artifacts(&self) -> Arc<dyn ArtifactStore>;

    /// Creates the tenant, as an owner of the database does when a customer is taken on, and
    /// registers one enabled repository for it.
    async fn seed_tenant(&self, tenant: TenantId) -> RepositoryId;

    /// Moves the time the store reads (leases, deadlines, back-off, approval expiry) forward by
    /// `seconds`. The engine's own clock is moved by the world.
    async fn advance_database_time(&self, seconds: u64);

    /// The next commit is applied, and its answer is lost: it reports `CommitOutcomeUnknown`.
    async fn lose_next_commit_answer(&self);

    /// The audit records stored under the platform tenant.
    async fn platform_audit(&self) -> Vec<AuditRecord>;

    /// The audit records stored under the tenant, read outside the port.
    async fn tenant_audit(&self, tenant: TenantId) -> Vec<AuditRecord>;

    /// The concrete in-memory store, for the stage rigs that build more fakes on top of it.
    /// `None` on any other backend.
    fn in_memory_store(&self) -> Option<Arc<InMemoryStore>> {
        None
    }
}

/// The in-memory store. Its clock is the world's clock, so the database time moves when the world
/// moves it and this backend has nothing more to do.
pub struct InMemoryBackend {
    store: Arc<InMemoryStore>,
    artifacts: Arc<InMemoryArtifactStore>,
}

impl InMemoryBackend {
    /// A faithful store on `clock`.
    pub fn new(clock: Arc<FakeClock>) -> Arc<Self> {
        Self::build(InMemoryStore::new(clock))
    }

    /// A store that breaks one rule of the contract on purpose.
    pub fn with_defect(clock: Arc<FakeClock>, defect: StoreDefect) -> Arc<Self> {
        Self::build(InMemoryStore::with_defect(clock, defect))
    }

    fn build(store: InMemoryStore) -> Arc<Self> {
        let store = Arc::new(store);
        let artifacts = Arc::new(InMemoryArtifactStore::new().indexed_by((*store).clone()));
        Arc::new(Self { store, artifacts })
    }
}

#[async_trait]
impl Backend for InMemoryBackend {
    fn name(&self) -> &'static str {
        "in-memory"
    }

    fn store(&self) -> Arc<dyn Store> {
        self.store.clone()
    }

    fn artifacts(&self) -> Arc<dyn ArtifactStore> {
        self.artifacts.clone()
    }

    async fn seed_tenant(&self, tenant: TenantId) -> RepositoryId {
        self.store.seed_repository(tenant)
    }

    async fn advance_database_time(&self, _seconds: u64) {}

    async fn lose_next_commit_answer(&self) {
        self.store.lose_next_commit_answer();
    }

    async fn platform_audit(&self) -> Vec<AuditRecord> {
        self.store.platform_audit()
    }

    async fn tenant_audit(&self, tenant: TenantId) -> Vec<AuditRecord> {
        self.store.tenant_audit(tenant)
    }

    fn in_memory_store(&self) -> Option<Arc<InMemoryStore>> {
        Some(self.store.clone())
    }
}
