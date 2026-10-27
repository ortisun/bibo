//! The shared store contract suite of `factory-testkit`, run against `PgStore` on a real
//! PostgreSQL server.
//!
//! The suite is the one the in-memory fake passes (ports v1.1). Every check gets a database of its
//! own, cloned from a migrated template, and the checks run side by side. The slow ones wait for
//! the database clock (the lease time to live in the suite is 60 seconds), so running them
//! together keeps the whole suite near the length of the longest check.
//!
//! No check is excluded. The test fails on any check that fails and on any that is skipped.
//!
//! [`PgSubject`] supplies what the port has no method for, as SQL run by the superuser in the
//! throwaway database: a repository, an API token, switching a repository off, and moving a stage
//! run's epoch to its maximum. The two faults (a stalled call and a lost answer to `COMMIT`) are
//! injected into the store itself.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use diesel_async::SimpleAsyncConnection;
use factory_domain::ids::{RepositoryId, StageRunId, TenantId};
use factory_domain::scope::{PlatformScope, ResolvedRepository};
use factory_domain::scope::{ResolvedPrincipal, TenantScope};
use factory_ports::store::{
    Audience, AuditFilter, AuditRecord, GithubRepositoryId, InstallationId, LeaseEpoch,
    NewAuditEvent, SchemaVersion, Store, StoreError, SystemScope, SystemTx, TokenHash, Tx, Witness,
};
use factory_storage::pg::PgStore;
use factory_testkit::contracts::store::{StoreSubject, checks};
use factory_testkit::contracts::{Report, SKIPPED_PREFIX};
use support::{TestDb, config_for, server};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use uuid::Uuid;

/// The platform tenant of migration 2, which `record_platform_audit` writes under.
const PLATFORM: u128 = 1;

/// The store the checks use: the real store, with tenants onboarded on first use.
///
/// The schema has a row per tenant, and the application role cannot insert one: onboarding is an
/// owner action (`docs/database/for-the-storage-crate.md`). The shared suite names tenants as bare
/// identifiers and never onboards them, which the in-memory fake does not need. So this wrapper
/// onboards a tenant, as the superuser, right before the first transaction opened for it. It adds
/// nothing else: every call goes to the real store.
struct OnboardingStore {
    inner: PgStore,
    db: Arc<TestDb>,
}

impl OnboardingStore {
    async fn onboard(&self, tenant: TenantId) {
        let id = tenant.as_uuid();
        self.db
            .run(&format!(
                "INSERT INTO tenants (id, slug, display_name) \
                 VALUES ('{id}', 't-{}', 'Contract tenant') ON CONFLICT (id) DO NOTHING",
                &id.simple().to_string()[..12]
            ))
            .await;
    }
}

#[async_trait]
impl Store for OnboardingStore {
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity {
        self.inner.fidelity()
    }

    async fn begin(&self, scope: TenantScope) -> Result<Box<dyn Tx>, StoreError> {
        self.onboard(scope.tenant_id()).await;
        self.inner.begin(scope).await
    }

    async fn begin_system(&self, scope: SystemScope) -> Result<Box<dyn SystemTx>, StoreError> {
        self.inner.begin_system(scope).await
    }

    async fn resolve_token(
        &self,
        hash: &TokenHash,
        audience: &Audience,
    ) -> Result<Option<ResolvedPrincipal>, StoreError> {
        self.inner.resolve_token(hash, audience).await
    }

    async fn resolve_installation(
        &self,
        installation: InstallationId,
        repository: GithubRepositoryId,
    ) -> Result<Option<ResolvedRepository>, StoreError> {
        self.inner
            .resolve_installation(installation, repository)
            .await
    }

    async fn record_platform_audit(
        &self,
        scope: PlatformScope,
        event: NewAuditEvent,
    ) -> Result<AuditRecord, StoreError> {
        self.inner.record_platform_audit(scope, event).await
    }

    async fn committed(&self, scope: TenantScope, witness: Witness) -> Result<bool, StoreError> {
        self.onboard(scope.tenant_id()).await;
        self.inner.committed(scope, witness).await
    }

    async fn schema_version(&self) -> Result<SchemaVersion, StoreError> {
        self.inner.schema_version().await
    }
}

struct PgSubject {
    db: Arc<TestDb>,
    store: OnboardingStore,
    counter: AtomicU64,
}

impl PgSubject {
    async fn new() -> Self {
        let db = Arc::new(server().clone_database().await);
        let inner = PgStore::connect(config_for(&db).await)
            .await
            .expect("the store becomes ready");
        Self {
            store: OnboardingStore {
                inner,
                db: db.clone(),
            },
            db,
            counter: AtomicU64::new(1),
        }
    }

    fn next(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }

    async fn ensure_tenant(&self, tenant: TenantId) {
        self.store.onboard(tenant).await;
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

#[async_trait]
impl StoreSubject for PgSubject {
    fn store(&self) -> &dyn Store {
        &self.store
    }

    /// A real store waits. The database clock is the server's, so there is nothing to shift.
    async fn advance_database_time(&self, by: Duration) {
        tokio::time::sleep(by + Duration::from_millis(100)).await;
    }

    async fn seed_repository(&self, tenant: TenantId) -> RepositoryId {
        self.ensure_tenant(tenant).await;
        let n = self.next();
        let id = Uuid::from_u128(tenant.as_uuid().as_u128() ^ (u128::from(n) << 96) ^ 0x5eed);
        self.db
            .run(&format!(
                "INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, \
                        full_name, default_branch) \
                 VALUES ('{}', '{id}', {}, {}, 'org/repo-{n}', 'main')",
                tenant.as_uuid(),
                1000 + n,
                2000 + n
            ))
            .await;
        RepositoryId::from_uuid(id)
    }

    async fn seed_token(&self, hash: TokenHash, audience: Audience, who: ResolvedPrincipal) {
        self.ensure_tenant(who.tenant).await;
        let hex: String = hash.0.iter().map(|byte| format!("{byte:02x}")).collect();
        let n = self.next();
        self.db
            .run(&format!(
                "INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, expires_at) \
                 VALUES ('{}', '{}', '{}', decode('{hex}', 'hex'), '{}', now() + interval '1 day')",
                who.tenant.as_uuid(),
                Uuid::from_u128(u128::from(n) | (1 << 100)),
                who.principal.as_uuid(),
                audience.0.as_str()
            ))
            .await;
    }

    async fn disable_repository(&self, repository: RepositoryId) {
        self.db
            .run(&format!(
                "UPDATE repositories SET enabled = false, version = version + 1 WHERE id = '{}'",
                repository.as_uuid()
            ))
            .await;
    }

    async fn stall_next_call(&self) {
        self.store.inner.stall_next_call();
    }

    async fn lose_next_commit_answer(&self) {
        self.store.inner.lose_next_commit_answer();
    }

    async fn platform_audit(&self) -> Vec<AuditRecord> {
        self.audit_of(TenantId::from_uuid(Uuid::from_u128(PLATFORM)))
            .await
    }

    async fn tenant_audit(&self, tenant: TenantId) -> Vec<AuditRecord> {
        self.audit_of(tenant).await
    }

    async fn force_lease_epoch(&self, tenant: TenantId, stage_run: StageRunId, epoch: LeaseEpoch) {
        // The trigger lets the epoch rise only with READY to RUNNING. A superuser switches the
        // triggers off for this one transaction, which is what a repair by an operator would do.
        let mut admin = self.db.admin().await;
        admin
            .batch_execute(&format!(
                "BEGIN; SET LOCAL session_replication_role = replica; \
                 UPDATE stage_runs SET lease_epoch = {} WHERE tenant_id = '{}' AND id = '{}'; COMMIT;",
                epoch.get(),
                tenant.as_uuid(),
                stage_run.as_uuid()
            ))
            .await
            .expect("set the epoch");
    }
}

/// Runs every check, all together, each on a fresh database.
async fn run_all() -> Report {
    let gate = Arc::new(Semaphore::new(12));
    let mut tasks = JoinSet::new();
    for check in checks() {
        let gate = gate.clone();
        tasks.spawn(async move {
            let _slot = gate.acquire_owned().await.expect("the gate stays open");
            let subject: Box<dyn StoreSubject> = Box::new(PgSubject::new().await);
            let outcome = (check.run)(&*subject).await;
            (check.name, outcome)
        });
    }
    let mut report = Report::default();
    while let Some(done) = tasks.join_next().await {
        let (name, outcome) = done.expect("a check task does not panic");
        match outcome {
            Ok(()) => report.passed.push(name),
            Err(why) if why.starts_with(SKIPPED_PREFIX) => report.skipped.push((name, why)),
            Err(why) => report.failed.push((name, why)),
        }
    }
    report.passed.sort_unstable();
    report.failed.sort_by_key(|(name, _)| *name);
    report
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_shared_store_contract_suite_against_postgres() {
    let report = run_all().await;
    let total = report.passed.len() + report.failed.len() + report.skipped.len();
    eprintln!(
        "{} checks: {} passed, {} failed, {} skipped",
        total,
        report.passed.len(),
        report.failed.len(),
        report.skipped.len()
    );
    assert_eq!(
        total,
        checks().len(),
        "every check of the suite must have run"
    );
    let problems: Vec<String> = report
        .failed
        .iter()
        .map(|(name, why)| format!("{name}: {why}"))
        .collect();
    assert!(
        report.skipped.is_empty(),
        "skipped checks: {:?}",
        report.skipped
    );
    assert!(
        problems.is_empty(),
        "the contract suite found problems:\n  {}",
        problems.join("\n  ")
    );
}
