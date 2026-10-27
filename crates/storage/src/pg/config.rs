//! Configuration of the PostgreSQL store.
//!
//! A database URL carries a password, so [`DatabaseUrl`] has no `Display` and no derived
//! `Debug`: a configuration that is logged, printed in a panic or put in an error shows
//! `[redacted]` and nothing else.

use std::fmt;
use std::time::Duration;

use factory_domain::vocabulary::{ExecutionMode, StageKind};
use factory_ports::artifact::ArtifactBackend;

/// A database connection URL. The value is a secret.
#[derive(Clone)]
pub struct DatabaseUrl(String);

impl DatabaseUrl {
    /// Wraps a PostgreSQL connection URL that carries a user and a password. Build it at run time
    /// from the secret store, from its pieces; do not write one in source.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        Self(url.into())
    }

    pub(super) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DatabaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DatabaseUrl([redacted])")
    }
}

/// One connection pool: a login, a size and how long a caller waits for a connection.
#[derive(Debug, Clone)]
pub struct PoolSettings {
    /// The URL of the login. One login per pool.
    pub url: DatabaseUrl,
    /// The most connections the pool opens.
    pub max_connections: usize,
    /// How long a call waits for a free connection before it fails with `Unavailable`.
    pub acquire_timeout: Duration,
}

impl PoolSettings {
    /// A pool of 8 connections that makes a caller wait up to 10 seconds.
    #[must_use]
    pub fn new(url: DatabaseUrl) -> Self {
        Self {
            url,
            max_connections: 8,
            acquire_timeout: Duration::from_secs(10),
        }
    }
}

/// Which groups the login of the tenant pool belongs to.
///
/// The readiness check compares the login with this and refuses to start on a difference
/// (`docs/database/for-the-storage-crate.md`, step 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantLogin {
    /// A member of `factory_app` only. The login of the worker.
    Worker,
    /// A member of `factory_app` and `factory_resolver`. The login of the API process. It is the
    /// only login that may call the two lookups.
    Api,
}

/// Values that the port cannot carry but the schema requires on a new row.
///
/// The port's `NewJob` has no repository, execution mode, autonomy level or pipeline scope, and
/// the schema has `NOT NULL` columns for all four. Until the port carries them (see the handover
/// report), the store takes them from here and from the tenant's oldest enabled repository.
#[derive(Debug, Clone)]
pub struct JobDefaults {
    /// The stage kinds a new job must pass. Between 1 and 14, no repeats.
    pub pipeline_scope: Vec<StageKind>,
    /// The autonomy level of a new job. `L0` reads and comments only, the safest value.
    pub autonomy_level: AutonomyLevel,
}

impl Default for JobDefaults {
    fn default() -> Self {
        Self {
            pipeline_scope: StageKind::ALL.to_vec(),
            autonomy_level: AutonomyLevel::L0,
        }
    }
}

/// The autonomy levels of `policies/security.yaml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutonomyLevel {
    /// Reads and comments only.
    L0,
    /// Draft pull requests.
    L1,
    /// Higher autonomy.
    L2,
    /// Highest autonomy.
    L3,
}

impl AutonomyLevel {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::L0 => "L0",
            Self::L1 => "L1",
            Self::L2 => "L2",
            Self::L3 => "L3",
        }
    }
}

/// Timings that the port does not carry and the schema requires.
#[derive(Debug, Clone, Copy)]
pub struct AttemptTimings {
    /// How long after its claim an attempt may run before the sweep times it out. Set from the
    /// database clock.
    pub deadline: Duration,
    /// How long a cancelling attempt may take to tear its sandbox down.
    pub teardown_grace: Duration,
}

impl Default for AttemptTimings {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(2 * 60 * 60),
            teardown_grace: Duration::from_secs(60),
        }
    }
}

/// Everything `PgStore::connect` needs.
#[derive(Debug, Clone)]
pub struct PgStoreConfig {
    /// The pool for tenant transactions. In the API process its login is also the resolver.
    pub tenant: PoolSettings,
    /// What the tenant login is allowed to be.
    pub tenant_login: TenantLogin,
    /// The pool for system transactions: the login of the engine. `None` in a process that never
    /// claims work, such as the API. `begin_system` then fails with `Unavailable`.
    pub system: Option<PoolSettings>,
    /// The mode of the process. A new job is stored in this mode, and the database refuses a
    /// ledger entry from a fake recorder in a production job.
    pub execution_mode: ExecutionMode,
    /// Values for the columns of a new job that the port does not carry.
    pub job_defaults: JobDefaults,
    /// Timings for new attempts.
    pub attempt_timings: AttemptTimings,
    /// The backend label stored with an artifact index row.
    pub artifact_backend: ArtifactBackend,
    /// When `true` (the default) `claim_ready` takes stage runs of `ACTIVE` jobs only, as the
    /// storage notes say. The shared contract fixtures never admit their jobs, so the contract
    /// subject turns this off; no other caller should.
    pub claim_only_active_jobs: bool,
}

impl PgStoreConfig {
    /// A configuration with the safe defaults: a worker login, no system pool, test mode off
    /// (production), active jobs only.
    #[must_use]
    pub fn new(tenant: PoolSettings) -> Self {
        Self {
            tenant,
            tenant_login: TenantLogin::Worker,
            system: None,
            execution_mode: ExecutionMode::Production,
            job_defaults: JobDefaults::default(),
            attempt_timings: AttemptTimings::default(),
            artifact_backend: ArtifactBackend::LocalFs,
            claim_only_active_jobs: true,
        }
    }
}
