//! Configuration of the PostgreSQL store.
//!
//! A database URL carries a password, so [`DatabaseUrl`] has no `Display` and no derived
//! `Debug`: a configuration that is logged, printed in a panic or put in an error shows
//! `[redacted]` and nothing else.
//!
//! The configuration holds no value that belongs to a row. A job's repository, execution mode,
//! autonomy level and pipeline scope come from the caller's `NewJob`; the lease time to live and
//! the attempt timeout come from `StartAttempt`; the teardown grace comes from `AttemptEnd`.

use std::fmt;
use std::time::Duration;

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

/// One connection pool: a login, a size, how long a caller waits for a connection, and the limits
/// the database applies to every transaction opened on it.
#[derive(Debug, Clone)]
pub struct PoolSettings {
    /// The URL of the login. One login per pool.
    pub url: DatabaseUrl,
    /// The most connections the pool opens.
    pub max_connections: usize,
    /// How long a call waits for a free connection before it fails with `Unavailable`.
    pub acquire_timeout: Duration,
    /// The longest one statement may run. The database enforces it for the whole transaction
    /// (`SET LOCAL statement_timeout`), and a timeout is reported as `Unavailable`.
    pub statement_timeout: Duration,
    /// The longest one statement waits for a row lock held by another transaction. A timeout is
    /// reported as `Unavailable`.
    pub lock_timeout: Duration,
}

impl PoolSettings {
    /// A pool of 8 connections that makes a caller wait up to 10 seconds, with a 30 second
    /// statement timeout and a 5 second lock timeout.
    #[must_use]
    pub fn new(url: DatabaseUrl) -> Self {
        Self {
            url,
            max_connections: 8,
            acquire_timeout: Duration::from_secs(10),
            statement_timeout: Duration::from_secs(30),
            lock_timeout: Duration::from_secs(5),
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
    /// A member of `factory_api_app` and `factory_resolver`, and not of `factory_app`. The login of
    /// the API process. It is the only login that may call the two lookups and write the platform
    /// audit, and it can write only the four tables the API writes.
    Api,
}

/// Everything `PgStore::connect` needs.
#[derive(Debug, Clone)]
pub struct PgStoreConfig {
    /// The pool for tenant transactions. In the API process its login is also the resolver, and
    /// the lookups and the platform audit run on it outside any tenant transaction.
    pub tenant: PoolSettings,
    /// What the tenant login is allowed to be.
    pub tenant_login: TenantLogin,
    /// The pool for system transactions: the login of the engine. `None` in a process that never
    /// claims work, such as the API. `begin_system` then fails with `Unavailable`.
    pub system: Option<PoolSettings>,
    /// The backend label stored with an artifact index row.
    pub artifact_backend: ArtifactBackend,
}

impl PgStoreConfig {
    /// A configuration with the safe defaults: a worker login and no system pool.
    #[must_use]
    pub fn new(tenant: PoolSettings) -> Self {
        Self {
            tenant,
            tenant_login: TenantLogin::Worker,
            system: None,
            artifact_backend: ArtifactBackend::LocalFs,
        }
    }
}
