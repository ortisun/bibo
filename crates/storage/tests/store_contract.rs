//! The shared store contract suite of `factory-testkit`, run against `PgStore` on a real
//! PostgreSQL server.
//!
//! The suite is the one the in-memory fake passes (ports v1.1). Every check gets a database of its
//! own, cloned from a migrated template, and the checks run side by side. All of them must pass: the
//! suite creates what it names (tenants through `StoreSubject::onboard_tenant`, artifacts through
//! the port, stage runs through the port), and the subject adds no trigger and no wrapper to the
//! store under test.
//!
//! [`PgSubject`] supplies what the port has no method for, as SQL run by the superuser in the
//! throwaway database: a tenant, a repository, an API token, switching a repository off, and
//! moving a stage run's epoch to its maximum. The two faults (a stalled call and a lost answer to
//! `COMMIT`) are injected into the store itself. The clock moves by waiting for a step of a few
//! seconds, because `database_time` reads the real clock, and by shifting the stored times for a
//! longer one, which costs no wait.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use diesel_async::SimpleAsyncConnection;
use factory_domain::ids::{RepositoryId, StageRunId, TenantId};
use factory_domain::scope::{ResolvedPrincipal, TenantScope};
use factory_ports::store::{Audience, AuditFilter, AuditRecord, LeaseEpoch, Store, TokenHash};
use factory_storage::pg::PgStore;
use factory_testkit::contracts::store::{StoreSubject, checks};
use factory_testkit::contracts::{Report, SKIPPED_PREFIX};
use factory_testkit::fixtures::SeededRepository;
use support::{SplitStore, TestDb, api_config_for, config_for, server};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use uuid::Uuid;

/// The platform tenant of migration 2, which `record_platform_audit` writes under.
const PLATFORM: u128 = 1;

/// The longest step of the clock that is made by waiting. A longer one moves the stored times.
const REAL_WAIT_LIMIT: Duration = Duration::from_secs(3);

struct PgSubject {
    db: Arc<TestDb>,
    /// The worker and engine logins: tenant and system transactions.
    store: Arc<PgStore>,
    /// The tenant store joined to the API login's, which answers the lookups and the platform
    /// audit. The contract expects one store to do all of it; the deployment has two processes.
    split: SplitStore,
    counter: AtomicU64,
}

impl PgSubject {
    async fn new() -> Self {
        let db = Arc::new(server().clone_database().await);
        let store = Arc::new(
            PgStore::connect(config_for(&db).await)
                .await
                .expect("the store becomes ready"),
        );
        let api = PgStore::connect(api_config_for(&db).await)
            .await
            .expect("the API store becomes ready");
        Self {
            split: SplitStore {
                tenant: Arc::clone(&store),
                api,
            },
            store,
            db,
            counter: AtomicU64::new(1),
        }
    }

    fn next(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
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
        &self.split
    }

    /// The schema has a row per tenant and the application role cannot insert one: onboarding is
    /// an owner action (`docs/database/for-the-storage-crate.md`), so it runs as the superuser.
    async fn onboard_tenant(&self, tenant: TenantId) {
        let id = tenant.as_uuid();
        self.db
            .run(&format!(
                "INSERT INTO tenants (id, slug, display_name) \
                 VALUES ('{id}', 't-{}', 'Contract tenant') ON CONFLICT (id) DO NOTHING",
                &id.simple().to_string()[..12]
            ))
            .await;
    }

    /// Moves the clock forward by at least `by`.
    ///
    /// A step of a few seconds waits on the real clock, which is the only way to move the reading
    /// of `database_time`. A longer step moves every stored time that a rule compares with the
    /// clock back by `by`, which is the same to every one of those comparisons and costs no
    /// wait. Both are real to the database: the second is a repair by an operator with the
    /// triggers off for one transaction.
    async fn advance_database_time(&self, by: Duration) {
        if by <= REAL_WAIT_LIMIT {
            tokio::time::sleep(by + Duration::from_millis(100)).await;
            return;
        }
        let seconds = by.as_secs() + 1;
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

    async fn seed_repository(&self, tenant: TenantId) -> RepositoryId {
        let n = self.next();
        let id = Uuid::from_u128(tenant.as_uuid().as_u128() ^ (u128::from(n) << 96) ^ 0x5eed);
        self.db
            .run(
                &SeededRepository {
                    tenant: &tenant.as_uuid().to_string(),
                    id: &id.to_string(),
                    installation: 1000 + n,
                    github_repository: 2000 + n,
                    full_name: &format!("org/repo-{n}"),
                    default_branch: "main",
                    autonomy_ceiling: "L0",
                }
                .sql(),
            )
            .await;
        RepositoryId::from_uuid(id)
    }

    async fn seed_token(&self, hash: TokenHash, audience: Audience, who: ResolvedPrincipal) {
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
        self.store.stall_next_call();
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
    assert!(
        report.skipped.is_empty(),
        "skipped checks: {:?}",
        report.skipped
    );
    report.assert_ok();
}
