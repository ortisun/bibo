//! The two connection pools and the checks that go with them (ADR 0012).
//!
//! The worker holds **two pools with two logins**:
//!
//! * the **tenant pool**, a member of `factory_app`. Every state change is a tenant transaction
//!   (`Store::begin`), which sets the tenant as the first statement so row-level security applies;
//! * the **system pool**, a member of `factory_system`. It only finds work (`begin_system`): the
//!   claim candidates and the due attempts. It cannot write a row.
//!
//! [`connect`] reads the two URL files, checks that the login each URL names is the login the
//! configuration names (so the file and the setting cannot drift apart), registers the URLs and
//! their passwords with the redactor, and hands the pools to `PgStore::connect`, which runs the
//! role query on each pool and refuses a login that is a superuser, bypasses row-level security,
//! owns a table or is in the wrong groups, and refuses a database that is behind the code.

use std::path::Path;
use std::sync::Arc;

use factory_ports::artifact::ArtifactStore;
use factory_ports::store::Store;
use factory_storage::artifact_fs::LocalFsArtifactStore;
use factory_storage::pg::{
    DatabaseUrl, PgStore, PgStoreConfig, PoolSettings, StartupError, TenantLogin,
};

use crate::config::{ConfigError, DatabaseConfig, PoolConfig, login_of_url};
use crate::redaction::FactorySecrets;
use crate::startup::StartupFailure;

fn settings(
    pool: &PoolConfig,
    secrets: &mut FactorySecrets,
) -> Result<PoolSettings, StartupFailure> {
    let url = pool
        .url_file
        .read()
        .map_err(|error| StartupFailure::Store(error.to_string()))?;
    match login_of_url(url.expose()) {
        Some(login) if login == pool.login => {}
        _ => {
            return Err(StartupFailure::Store(format!(
                "the URL in {} does not connect as the login {} that the configuration names",
                pool.url_file.path().display(),
                pool.login
            )));
        }
    }
    secrets
        .register_database_url(url.expose())
        .map_err(|error| StartupFailure::Store(error.to_string()))?;
    let mut settings = PoolSettings::new(DatabaseUrl::new(url.expose()));
    settings.max_connections = pool.max_connections;
    Ok(settings)
}

/// Builds the store configuration of a worker: the worker login on the tenant pool and the
/// engine login on the system pool.
///
/// # Errors
/// [`StartupFailure::Store`] when a URL file is unsafe, unreadable or names another login, and
/// [`ConfigError::SameLogin`] (as text) when the two pools name the same login.
pub fn store_config(
    database: &DatabaseConfig,
    secrets: &mut FactorySecrets,
) -> Result<PgStoreConfig, StartupFailure> {
    if database.tenant.login == database.system.login {
        return Err(StartupFailure::Store(
            ConfigError::SameLogin(database.tenant.login.clone()).to_string(),
        ));
    }
    Ok(pools(
        settings(&database.tenant, secrets)?,
        settings(&database.system, secrets)?,
    ))
}

/// The one place that decides which pool is which: the tenant pool connects as the worker login
/// (a member of `factory_app`, not of `factory_resolver`), and the system pool is the engine's.
#[must_use]
pub fn pools(tenant: PoolSettings, system: PoolSettings) -> PgStoreConfig {
    let mut config = PgStoreConfig::new(tenant);
    config.tenant_login = TenantLogin::Worker;
    config.system = Some(system);
    config
}

/// Connects both pools, checks both roles and the schema, and returns a ready store.
///
/// # Errors
/// [`StartupFailure::Store`].
pub async fn connect(
    database: &DatabaseConfig,
    secrets: &mut FactorySecrets,
) -> Result<PgStore, StartupFailure> {
    let config = store_config(database, secrets)?;
    PgStore::connect(config).await.map_err(describe)
}

/// Builds the store configuration of the API: the API login on the one pool, which is a member of
/// `factory_api_app` and of `factory_resolver` (not of `factory_app`), and no system pool. The API cannot find work across
/// tenants, and the three calls that run before a tenant is known are refused to any other login
/// (`TenantLogin::Api`).
///
/// # Errors
/// [`StartupFailure::Store`] when the URL file is unsafe, unreadable or names another login.
pub fn api_store_config(
    api: &PoolConfig,
    secrets: &mut FactorySecrets,
) -> Result<PgStoreConfig, StartupFailure> {
    let mut config = PgStoreConfig::new(settings(api, secrets)?);
    config.tenant_login = TenantLogin::Api;
    config.system = None;
    Ok(config)
}

/// Connects the API's pool, checks its role and the schema, and returns a ready store.
///
/// # Errors
/// [`StartupFailure::Store`].
pub async fn connect_api(
    api: &PoolConfig,
    secrets: &mut FactorySecrets,
) -> Result<PgStore, StartupFailure> {
    let config = api_store_config(api, secrets)?;
    PgStore::connect(config).await.map_err(describe)
}

/// Opens the artifact store on `root` for a process that only reads it, such as the API. `index`
/// is the store that holds each tenant's artifact index: a read answers only for a hash the
/// tenant's own row names. The directory is made when it is missing, as for the worker.
///
/// # Errors
/// [`StartupFailure::Other`] when the directory cannot be made or opened.
pub fn open_artifacts(
    root: &Path,
    max_bytes: u64,
    index: Arc<dyn Store>,
) -> Result<Arc<dyn ArtifactStore>, StartupFailure> {
    LocalFsArtifactStore::open(root, max_bytes, index)
        .map(|opened| Arc::new(opened) as Arc<dyn ArtifactStore>)
        .map_err(|error| StartupFailure::Other(format!("the artifact store cannot open: {error}")))
}

/// A start-up error as plain text, without any URL.
fn describe(error: StartupError) -> StartupFailure {
    StartupFailure::Store(error.to_string())
}
