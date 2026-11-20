//! A connection pool for one login.
//!
//! Every connection that comes out of the pool has first run `RESET factory.tenant_id`
//! (`docs/database/for-the-storage-crate.md`, step 6). The tenant setting that `Store::begin`
//! makes is local to its transaction and ends with it, so nothing in this crate leaves a value
//! behind. The reset is the second line: a session-level `SET` made by anything else on a pooled
//! connection would otherwise show its tenant to the next borrower.
//!
//! A connection that comes back with a transaction still open is also thrown away by the
//! library's own check (`is_broken`), never reused.

use std::time::Duration;

use diesel_async::AsyncPgConnection;
use diesel_async::pooled_connection::deadpool::{Object, Pool};
use diesel_async::pooled_connection::{
    AsyncDieselConnectionManager, ManagerConfig, RecyclingMethod,
};
use factory_ports::store::StoreError;

use super::config::PoolSettings;
use super::error::StartupError;

/// The statement run on a connection before it is handed out again.
pub(super) const RESET_TENANT_SETTING: &str = "RESET factory.tenant_id";

/// A pooled connection. Dropping it hands the connection back to the pool.
pub(super) type PooledConnection = Object<AsyncPgConnection>;

/// A pool of connections for one login.
#[derive(Clone)]
pub struct PgPool {
    inner: Pool<AsyncPgConnection>,
    label: &'static str,
    acquire_timeout: Duration,
}

impl std::fmt::Debug for PgPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgPool")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl PgPool {
    /// Builds a pool. No connection is opened until the first use.
    ///
    /// # Errors
    /// Returns [`StartupError::Misconfigured`] when the pool size is zero or the pool cannot be
    /// built.
    pub fn new(label: &'static str, settings: &PoolSettings) -> Result<Self, StartupError> {
        Self::with_recycling(
            label,
            settings,
            RecyclingMethod::CustomQuery(RESET_TENANT_SETTING.into()),
        )
    }

    /// Like [`PgPool::new`] but with a chosen recycling method. Used by the deliberate-break
    /// tests to show that the reset matters. Not for production.
    #[doc(hidden)]
    pub fn with_recycling(
        label: &'static str,
        settings: &PoolSettings,
        recycling: RecyclingMethod<AsyncPgConnection>,
    ) -> Result<Self, StartupError> {
        if settings.max_connections == 0 {
            return Err(StartupError::Misconfigured(
                "a pool needs at least one connection",
            ));
        }
        let mut manager_config = ManagerConfig::<AsyncPgConnection>::default();
        manager_config.recycling_method = recycling;
        let manager = AsyncDieselConnectionManager::<AsyncPgConnection>::new_with_config(
            settings.url.expose(),
            manager_config,
        );
        let inner = Pool::builder(manager)
            .max_size(settings.max_connections)
            .build()
            .map_err(|_| StartupError::Misconfigured("the connection pool could not be built"))?;
        Ok(Self {
            inner,
            label,
            acquire_timeout: settings.acquire_timeout,
        })
    }

    /// Takes a connection, waiting up to the acquire timeout.
    pub(super) async fn get(&self) -> Result<PooledConnection, StoreError> {
        match tokio::time::timeout(self.acquire_timeout, self.inner.get()).await {
            Ok(Ok(connection)) => Ok(connection),
            Ok(Err(error)) => {
                // The pool error can carry the library's text, which can carry the address of the
                // server. Log the kind only.
                tracing::warn!(
                    pool = self.label,
                    kind = pool_error_kind(&error),
                    "no connection"
                );
                Err(StoreError::Unavailable)
            }
            Err(_) => {
                tracing::warn!(pool = self.label, kind = "timeout", "no connection");
                Err(StoreError::Unavailable)
            }
        }
    }

    /// A raw connection, for the tests that must run SQL the `Tx` type does not allow (for
    /// example a session-level `SET`, to show that the reset removes it). Not for production.
    ///
    /// # Errors
    /// Returns [`StoreError::Unavailable`] when no connection can be had.
    #[doc(hidden)]
    pub async fn raw_connection_for_tests(&self) -> Result<PooledConnection, StoreError> {
        self.get().await
    }

    pub(super) const fn label(&self) -> &'static str {
        self.label
    }
}

fn pool_error_kind(error: &diesel_async::pooled_connection::deadpool::PoolError) -> &'static str {
    use diesel_async::pooled_connection::deadpool::PoolError;
    match error {
        PoolError::Timeout(_) => "timeout",
        PoolError::Backend(_) => "backend",
        PoolError::Closed => "closed",
        PoolError::NoRuntimeSpecified => "no runtime",
        PoolError::PostCreateHook(_) => "post create hook",
    }
}
