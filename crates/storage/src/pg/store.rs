//! `PgStore`: the PostgreSQL implementation of the [`Store`] port.
//!
//! # Pools and logins
//!
//! The store holds up to two pools, each with its own login (ADR 0012):
//!
//! * the **tenant pool**. `begin` takes a connection from it and makes the tenant setting as the
//!   first statement of the transaction. In the API process its login is also a member of
//!   `factory_resolver`, and the two lookups of [`PgStore::resolve_token`] and
//!   [`PgStore::resolve_installation`] run on it, outside a transaction;
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

use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use factory_domain::scope::TenantScope;
use factory_domain::vocabulary::{ExecutionMode, Fidelity, StageKind};
use factory_ports::artifact::ArtifactBackend;
use factory_ports::store::{SchemaVersion, Store, StoreError, SystemScope, Tx};
use tokio::task::JoinHandle;

use super::config::{AttemptTimings, JobDefaults, PgStoreConfig, TenantLogin};
use super::error::StartupError;
use super::pool::{PgPool, PooledConnection};
use super::readiness::{self, Expected};
use super::system::SystemTx;
use super::tx::PgTx;

/// The parts of the configuration that the operations read.
#[derive(Debug, Clone)]
pub(super) struct Settings {
    pub execution_mode: ExecutionMode,
    pub pipeline_scope: Vec<StageKind>,
    pub autonomy_level: &'static str,
    pub attempt_timings: AttemptTimings,
    pub artifact_backend: ArtifactBackend,
    pub claim_only_active_jobs: bool,
}

/// What every transaction of a store shares.
pub(super) struct Shared {
    pub tenant_pool: PgPool,
    pub system_pool: Option<PgPool>,
    pub settings: Settings,
    pub resolver: bool,
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

    /// A connection for a system step: a plain autocommit connection of the system pool.
    pub(super) async fn system_connection(&self) -> Result<PooledConnection, StoreError> {
        match &self.system_pool {
            Some(pool) => pool.get().await,
            None => {
                tracing::error!(
                    "a system transaction was asked for, but no system pool is configured"
                );
                Err(StoreError::Unavailable)
            }
        }
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

        check_job_defaults(&config.job_defaults)?;
        Ok(Self {
            shared: Arc::new(Shared {
                tenant_pool,
                system_pool,
                settings: Settings {
                    execution_mode: config.execution_mode,
                    pipeline_scope: config.job_defaults.pipeline_scope.clone(),
                    autonomy_level: config.job_defaults.autonomy_level.as_str(),
                    attempt_timings: config.attempt_timings,
                    artifact_backend: config.artifact_backend,
                    claim_only_active_jobs: config.claim_only_active_jobs,
                },
                resolver: config.tenant_login == TenantLogin::Api,
                rollbacks: Mutex::new(Vec::new()),
            }),
        })
    }
}

fn check_job_defaults(defaults: &JobDefaults) -> Result<(), StartupError> {
    let scope = &defaults.pipeline_scope;
    if scope.is_empty() || scope.len() > StageKind::ALL.len() {
        return Err(StartupError::Misconfigured(
            "the default pipeline scope needs between 1 and 14 stage kinds",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    if !scope.iter().all(|kind| seen.insert(*kind)) {
        return Err(StartupError::Misconfigured(
            "the default pipeline scope repeats a stage kind",
        ));
    }
    Ok(())
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

    async fn begin_system(&self, _scope: SystemScope) -> Result<Box<dyn Tx>, StoreError> {
        if self.shared.system_pool.is_none() {
            tracing::error!("begin_system was called on a store that has no system pool");
            return Err(StoreError::Unavailable);
        }
        self.shared.settle_rollbacks().await;
        Ok(Box::new(SystemTx::new(self.shared.clone())))
    }

    async fn schema_version(&self) -> Result<SchemaVersion, StoreError> {
        let mut connection = self.shared.tenant_pool.get().await?;
        let applied = readiness::applied_versions(&mut connection)
            .await
            .map_err(|error| super::error::generic("schema_version", &error))?;
        Ok(readiness::version_number(applied.len()))
    }
}
