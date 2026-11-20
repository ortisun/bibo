//! `PgStore`: the PostgreSQL implementation of the [`Store`] port.
//!
//! # Pools and logins
//!
//! The store holds up to two pools, each with its own login (ADR 0012):
//!
//! * the **tenant pool**. `begin` takes a connection from it and makes the tenant setting as the
//!   first statement of the transaction (see [`super::tx`]). In the API process its login is also
//!   a member of `factory_resolver`; `resolve_token`, `resolve_installation` and
//!   `record_platform_audit` run on it and are refused for any other login;
//! * the **system pool**, only in the engine process. `begin_system` finds work with it. It cannot
//!   write a row, so every change goes through a tenant transaction for the tenant that was found
//!   (see [`super::system`]).
//!
//! `connect` runs the role query on both pools and refuses to start when a login can bypass
//! row-level security, owns the tables, or is in the wrong groups. It also refuses a database
//! that is behind the code.
//!
//! # A dropped transaction
//!
//! Dropping a [`Tx`] without `commit` rolls it back (the port promises it). A `Drop` cannot wait
//! for the database, so the rollback runs as a task and the store remembers the task. The next
//! `begin` waits for every such task first. A caller that drops a transaction and starts another
//! therefore never sees the locks of the first.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Bytea, Text, Uuid as SqlUuid};
use diesel::{OptionalExtension, QueryableByName};
use diesel_async::RunQueryDsl;
use factory_domain::ids::{PrincipalId, RepositoryId, TenantId};
use factory_domain::scope::{PlatformScope, ResolvedPrincipal, ResolvedRepository, TenantScope};
use factory_domain::vocabulary::Fidelity;
use factory_ports::artifact::ArtifactBackend;
use factory_ports::store::{
    Audience, AuditOps, AuditRecord, FaultCode, GithubRepositoryId, InstallationId, NewAuditEvent,
    SchemaVersion, Store, StoreError, SystemScope, SystemTx, TokenHash, Tx, Witness,
};
use tokio::task::JoinHandle;
use uuid::Uuid;

use super::config::{PgStoreConfig, PoolSettings, TenantLogin};
use super::error::{StartupError, database};
use super::pool::{PgPool, PooledConnection};
use super::readiness::{self, Expected};
use super::system::PgSystemTx;
use super::tx::PgTx;

/// The tenant under which the platform audit is written (migration 2).
const PLATFORM_TENANT: Uuid = Uuid::from_u128(1);

/// Faults that a test can ask the store to inject into the next call, to show what the store does
/// with a stalled connection and with a lost answer to `COMMIT`. Nothing in production sets them.
#[derive(Debug, Default)]
pub(super) struct Faults {
    pub stall_next_call: AtomicBool,
    pub lose_next_commit_answer: AtomicBool,
}

impl Faults {
    pub(super) fn take_stall(&self) -> bool {
        self.stall_next_call.swap(false, Ordering::SeqCst)
    }

    pub(super) fn take_lost_commit(&self) -> bool {
        self.lose_next_commit_answer.swap(false, Ordering::SeqCst)
    }
}

/// What every transaction of a store shares.
pub(super) struct Shared {
    pub tenant_pool: PgPool,
    pub tenant_limits: PoolSettings,
    pub system_pool: Option<PgPool>,
    pub system_limits: Option<PoolSettings>,
    pub artifact_backend: ArtifactBackend,
    pub resolver: bool,
    pub faults: Faults,
    rollbacks: Mutex<Vec<JoinHandle<()>>>,
}

impl Shared {
    /// Waits for the rollbacks of dropped transactions, so their locks are gone.
    pub(super) async fn settle_rollbacks(&self) {
        let handles: Vec<JoinHandle<()>> = {
            let mut guard = self
                .rollbacks
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            std::mem::take(&mut *guard)
        };
        for handle in handles {
            // A rollback task that panicked has nothing more to tell us.
            let _ = handle.await;
        }
    }

    /// Remembers a rollback task started by a dropped transaction.
    pub(super) fn track_rollback(&self, handle: JoinHandle<()>) {
        let mut guard = self
            .rollbacks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        guard.retain(|task| !task.is_finished());
        guard.push(handle);
    }
}

/// The PostgreSQL store. Cheap to clone: the clones share the pools.
#[derive(Clone)]
pub struct PgStore {
    pub(super) shared: Arc<Shared>,
}

impl std::fmt::Debug for PgStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgStore")
            .field("system_pool", &self.shared.system_pool.is_some())
            .finish_non_exhaustive()
    }
}

impl PgStore {
    /// Builds the pools, checks each login and the schema, and returns a store that is ready.
    ///
    /// # Errors
    /// Returns a [`StartupError`] when a pool cannot connect, a login can bypass row-level
    /// security, owns a table, or is in the wrong groups, or the database is behind the code.
    pub async fn connect(config: PgStoreConfig) -> Result<Self, StartupError> {
        let tenant_pool = PgPool::new("tenant", &config.tenant)?;
        let system_pool = match &config.system {
            Some(settings) => Some(PgPool::new("system", settings)?),
            None => None,
        };
        Self::from_pools(tenant_pool, system_pool, &config).await
    }

    /// Like [`PgStore::connect`] with pools the caller built. The deliberate-break tests use it
    /// to hand in a pool with a weaker setup, and to keep a handle on the pool.
    ///
    /// # Errors
    /// The same as [`PgStore::connect`].
    #[doc(hidden)]
    pub async fn from_pools(
        tenant_pool: PgPool,
        system_pool: Option<PgPool>,
        config: &PgStoreConfig,
    ) -> Result<Self, StartupError> {
        let expected = match config.tenant_login {
            TenantLogin::Worker => Expected::Worker,
            TenantLogin::Api => Expected::Api,
        };
        let mut connection = tenant_pool
            .get()
            .await
            .map_err(|_| StartupError::Unreachable {
                pool: tenant_pool.label(),
            })?;
        readiness::check_role(&mut connection, tenant_pool.label(), expected).await?;
        readiness::check_schema(&mut connection).await?;
        drop(connection);

        if let Some(pool) = &system_pool {
            let mut connection = pool
                .get()
                .await
                .map_err(|_| StartupError::Unreachable { pool: pool.label() })?;
            readiness::check_role(&mut connection, pool.label(), Expected::System).await?;
            // The system login may read the migration table too; a database that is behind is
            // refused from either pool.
            readiness::check_schema(&mut connection).await?;
        }

        Ok(Self {
            shared: Arc::new(Shared {
                tenant_pool,
                tenant_limits: config.tenant.clone(),
                system_pool,
                system_limits: config.system.clone(),
                artifact_backend: config.artifact_backend,
                resolver: config.tenant_login == TenantLogin::Api,
                faults: Faults::default(),
                rollbacks: Mutex::new(Vec::new()),
            }),
        })
    }

    /// The next call of any transaction of this store never completes, as if the connection had
    /// stalled. A test uses it to show that a dropped call poisons the transaction. Not for
    /// production.
    #[doc(hidden)]
    pub fn stall_next_call(&self) {
        self.shared
            .faults
            .stall_next_call
            .store(true, Ordering::SeqCst);
    }

    /// The next `COMMIT` is applied by the database and its answer is dropped: the call reports
    /// `CommitOutcomeUnknown`, and the connection is closed as it would be after a lost answer.
    /// Not for production.
    #[doc(hidden)]
    pub fn lose_next_commit_answer(&self) {
        self.shared
            .faults
            .lose_next_commit_answer
            .store(true, Ordering::SeqCst);
    }

    /// A connection of the tenant pool, for the code that runs outside a transaction.
    async fn tenant_connection(&self) -> Result<PooledConnection, StoreError> {
        self.shared.tenant_pool.get().await
    }

    /// The three methods that need the API login are refused, without a database call, for any
    /// other login.
    fn require_api_login(&self) -> Result<(), StoreError> {
        if self.shared.resolver {
            Ok(())
        } else {
            tracing::error!(
                "a lookup was asked of a store whose tenant login is not the API login"
            );
            Err(StoreError::Internal(FaultCode::PermissionDenied))
        }
    }
}

#[derive(QueryableByName)]
struct TokenRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    principal_id: Uuid,
}

#[derive(QueryableByName)]
struct RepositoryRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    repository_id: Uuid,
}

#[async_trait]
impl Store for PgStore {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn begin(&self, scope: TenantScope) -> Result<Box<dyn Tx>, StoreError> {
        let tx = PgTx::begin(self.shared.clone(), scope.tenant_id()).await?;
        Ok(Box::new(tx))
    }

    async fn begin_system(&self, _scope: SystemScope) -> Result<Box<dyn SystemTx>, StoreError> {
        let tx = PgSystemTx::begin(self.shared.clone()).await?;
        Ok(Box::new(tx))
    }

    async fn resolve_token(
        &self,
        hash: &TokenHash,
        audience: &Audience,
    ) -> Result<Option<ResolvedPrincipal>, StoreError> {
        self.require_api_login()?;
        let mut connection = self.tenant_connection().await?;
        // The function is the whole answer: zero rows for an unknown, expired, revoked or
        // wrong-audience token, a disabled owner and a disabled tenant alike. No reason is read.
        let row = sql_query("SELECT tenant_id, principal_id FROM resolve_token($1, $2)")
            .bind::<Bytea, _>(hash.0.to_vec())
            .bind::<Text, _>(audience.0.as_str())
            .get_result::<TokenRow>(&mut *connection)
            .await
            .optional()
            .map_err(|error| database("resolve_token", &error))?;
        Ok(row.map(|row| ResolvedPrincipal {
            tenant: TenantId::from_uuid(row.tenant_id),
            principal: PrincipalId::from_uuid(row.principal_id),
        }))
    }

    async fn resolve_installation(
        &self,
        installation: InstallationId,
        repository: GithubRepositoryId,
    ) -> Result<Option<ResolvedRepository>, StoreError> {
        self.require_api_login()?;
        let (Ok(installation), Ok(repository)) =
            (i64::try_from(installation.0), i64::try_from(repository.0))
        else {
            // No column holds a number above the largest signed 64-bit value: nothing matches.
            return Ok(None);
        };
        let mut connection = self.tenant_connection().await?;
        let row = sql_query("SELECT tenant_id, repository_id FROM resolve_installation($1, $2)")
            .bind::<BigInt, _>(installation)
            .bind::<BigInt, _>(repository)
            .get_result::<RepositoryRow>(&mut *connection)
            .await
            .optional()
            .map_err(|error| database("resolve_installation", &error))?;
        Ok(row.map(|row| ResolvedRepository {
            tenant: TenantId::from_uuid(row.tenant_id),
            repository: RepositoryId::from_uuid(row.repository_id),
        }))
    }

    async fn record_platform_audit(
        &self,
        _scope: PlatformScope,
        event: NewAuditEvent,
    ) -> Result<AuditRecord, StoreError> {
        self.require_api_login()?;
        // The platform tenant is an ordinary tenant to the database: the same statement as any
        // audit record, in a transaction whose setting names it. The composite key refuses a job
        // (the platform tenant has none).
        let mut tx = PgTx::begin(self.shared.clone(), TenantId::from_uuid(PLATFORM_TENANT)).await?;
        let record = tx.record_audit(event).await?;
        Box::new(tx).commit().await?;
        Ok(record)
    }

    async fn committed(&self, scope: TenantScope, witness: Witness) -> Result<bool, StoreError> {
        let mut tx = PgTx::begin(self.shared.clone(), scope.tenant_id()).await?;
        let found = tx.witnessed(witness).await;
        // A read only transaction: a failed rollback changes nothing for the caller.
        let _ = Box::new(tx).rollback().await;
        found
    }

    async fn schema_version(&self) -> Result<SchemaVersion, StoreError> {
        let mut connection = self.tenant_connection().await?;
        let applied = readiness::applied_versions(&mut connection)
            .await
            .map_err(|error| database("schema_version", &error))?;
        Ok(readiness::version_number(applied.len()))
    }
}
