//! A migrated database on the test server, and logins of the deployment's shape.
//!
//! The server is the one `FACTORY_DB_ADMIN_URL` names: a superuser URL, the convention of
//! `scripts/db-test.sh` and `crates/storage/tests/support/server.rs`. Only databases named
//! `factory_t_*` and roles named `dbtest_*` are created, and each test drops what it made. When the
//! variable is not set the test panics with a message that starts with `BLOCKED:`: a test that
//! cannot run is never a pass. This support does not start a server of its own.
//!
//! Each test gets a database of its own with every migration applied by the superuser, the way the
//! deploy step applies them. Migrations take a cluster-wide lock first: the roles they create or
//! keep are cluster wide, and two test processes must not race to create `factory_observer`.
#![allow(dead_code, clippy::disallowed_methods)]

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use factory_domain::redaction::Redactor;
use factory_mcp_postgres::{ConnectSettings, Inspector, Limits, Password, Redact};
use tokio_postgres::config::Host;
use tokio_postgres::{Client, Config, NoTls};

/// A value every test redactor knows, as it would know a password. It has no secret's shape.
pub const PLANTED_VALUE: &str = "planted-value-for-the-redaction-tests";

/// The advisory lock key that serialises migrations across test processes.
const MIGRATION_LOCK: i64 = 0x0FAC_7012_0029;

fn unique() -> String {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos()),
    );
    hasher.write_u32(std::process::id());
    format!("{:012x}", hasher.finish() & 0xffff_ffff_ffff)
}

fn admin_config() -> Config {
    let url = std::env::var("FACTORY_DB_ADMIN_URL").unwrap_or_else(|_| {
        panic!("BLOCKED: FACTORY_DB_ADMIN_URL is not set; these tests need a PostgreSQL superuser URL (docs/database/running.md)")
    });
    Config::from_str(&url)
        .unwrap_or_else(|_| panic!("BLOCKED: FACTORY_DB_ADMIN_URL is not a PostgreSQL URL"))
}

pub async fn connect(config: &Config) -> Client {
    let (client, connection) = config
        .connect(NoTls)
        .await
        .unwrap_or_else(|_| panic!("BLOCKED: the test server is not reachable"));
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
}

fn migrations() -> Vec<(String, PathBuf)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let mut directories: Vec<PathBuf> = std::fs::read_dir(&root)
        .expect("read the migrations directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.join("up.sql").is_file())
        .collect();
    directories.sort();
    directories
        .into_iter()
        .map(|dir| {
            let name = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let version: String = name
                .split('_')
                .next()
                .unwrap_or("")
                .chars()
                .filter(char::is_ascii_digit)
                .collect();
            (version, dir.join("up.sql"))
        })
        .collect()
}

/// A login made by a test, with the password it was given.
#[derive(Debug, Clone)]
pub struct Login {
    pub name: String,
    pub password: String,
}

/// A migrated database of one test.
pub struct TestDb {
    admin: Config,
    pub name: String,
    roles: std::sync::Mutex<Vec<String>>,
    run: String,
}

impl TestDb {
    /// A fresh database with every migration applied, two tenants with a repository, people and a
    /// job each, and the test helpers of docs/database/tests/00_helpers.sql.
    pub async fn fresh() -> Self {
        let admin = admin_config();
        let run = unique();
        let name = format!("factory_t_mcp_{run}");
        let maintenance = connect(&admin).await;
        maintenance
            .batch_execute(&format!(
                "CREATE DATABASE \"{name}\" TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
            ))
            .await
            .expect("create the test database");
        let db = Self {
            admin,
            name,
            roles: std::sync::Mutex::new(Vec::new()),
            run,
        };
        maintenance
            .query("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK])
            .await
            .expect("take the migration lock");
        let client = db.admin().await;
        client
            .batch_execute(
                "CREATE TABLE __diesel_schema_migrations (version VARCHAR(50) PRIMARY KEY NOT NULL, \
                 run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
            )
            .await
            .expect("create the migration table");
        for (version, path) in migrations() {
            let sql = std::fs::read_to_string(&path).expect("read a migration");
            client
                .batch_execute(&sql)
                .await
                .unwrap_or_else(|error| panic!("migration {version} failed: {error}"));
            client
                .execute(
                    "INSERT INTO __diesel_schema_migrations (version) VALUES ($1)",
                    &[&version],
                )
                .await
                .expect("record the migration");
        }
        let _ = maintenance
            .query("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK])
            .await;
        let helpers = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/database/tests/00_helpers.sql"),
        )
        .expect("read the test helpers");
        client
            .batch_execute(&helpers)
            .await
            .expect("load the helpers");
        client
            .batch_execute(
                "SELECT dbtest.mk_tenant(1); SELECT dbtest.mk_tenant(2); \
                 SELECT dbtest.mk_job(1, 1); SELECT dbtest.mk_job(2, 1);",
            )
            .await
            .expect("make two tenants with a job each");
        db
    }

    fn config_for(&self, user: &str, password: Option<&str>) -> Config {
        let mut config = self.admin.clone();
        config.dbname(&self.name).user(user);
        if let Some(password) = password {
            config.password(password);
        }
        config
    }

    /// A superuser connection to this database. A superuser bypasses row-level security: for
    /// fixtures and for looking, never for the code under test.
    pub async fn admin(&self) -> Client {
        let mut config = self.admin.clone();
        config.dbname(&self.name);
        connect(&config).await
    }

    /// A connection as a login.
    pub async fn connect_as(&self, login: &Login) -> Client {
        connect(&self.config_for(&login.name, Some(&login.password))).await
    }

    /// A login in the given groups. With `observer_settings`, the role settings the deployment
    /// gives `factory_troubleshooter` (docs/database/observer-login.sql).
    pub async fn login(&self, label: &str, groups: &[&str], observer_settings: bool) -> Login {
        let name = format!("dbtest_{label}_{}", self.run);
        let password = unique() + &unique();
        let membership = if groups.is_empty() {
            String::new()
        } else {
            format!(" IN ROLE {}", groups.join(", "))
        };
        let admin = self.admin().await;
        admin
            .batch_execute(&format!(
                "CREATE ROLE \"{name}\" LOGIN PASSWORD '{password}' CONNECTION LIMIT 4{membership}"
            ))
            .await
            .expect("create a login");
        self.roles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(name.clone());
        if observer_settings {
            admin
                .batch_execute(&format!(
                    "ALTER ROLE \"{name}\" SET default_transaction_read_only = on; \
                     ALTER ROLE \"{name}\" SET statement_timeout = '5s'; \
                     ALTER ROLE \"{name}\" SET lock_timeout = '1s'; \
                     ALTER ROLE \"{name}\" SET idle_in_transaction_session_timeout = '10s';"
                ))
                .await
                .expect("set the observer settings");
        }
        Login { name, password }
    }

    /// The observer login of the deployment's shape.
    pub async fn observer(&self) -> Login {
        self.login("observer", &["factory_observer"], true).await
    }

    /// Connection settings of this database for a login.
    pub fn settings(&self, login: &Login) -> ConnectSettings {
        let host = match self.admin.get_hosts().first() {
            Some(Host::Tcp(host)) => host.clone(),
            Some(Host::Unix(path)) => path.display().to_string(),
            None => "localhost".to_owned(),
        };
        let port = self.admin.get_ports().first().copied().unwrap_or(5432);
        ConnectSettings::new(host, port, login.name.clone(), self.name.clone())
            .with_password(Password::new(login.password.clone()))
    }

    /// An inspector logged in as `login`, with a redactor that knows [`PLANTED_VALUE`].
    pub fn inspector(&self, login: &Login, limits: Limits) -> Arc<Inspector> {
        Arc::new(Inspector::new(
            self.settings(login),
            limits,
            planted_redactor(),
        ))
    }

    /// A number from the first column of the first row, as the superuser.
    pub async fn number(&self, sql: &str) -> i64 {
        let row = self
            .admin()
            .await
            .query_one(&format!("SELECT ({sql})::bigint"), &[])
            .await
            .unwrap_or_else(|error| panic!("{sql}: {error}"));
        row.get(0)
    }
}

/// A redactor with no pattern that knows [`PLANTED_VALUE`].
pub fn planted_redactor() -> Arc<dyn Redact> {
    let redactor = Redactor::builder().build().expect("a redactor");
    redactor
        .register("planted", PLANTED_VALUE)
        .expect("register the planted secret");
    Arc::new(redactor)
}

/// Fast limits for tests: a one-second statement timeout.
pub fn quick_limits() -> Limits {
    Limits {
        statement_timeout: std::time::Duration::from_secs(1),
        ..Limits::default()
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        let mut config = self.admin.clone();
        config.dbname("postgres");
        let name = self.name.clone();
        let roles = std::mem::take(
            &mut *self
                .roles
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        // A runtime of its own on a thread of its own: the test's runtime may be shutting down.
        let cleanup = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async {
                let Ok((client, connection)) = config.connect(NoTls).await else {
                    return;
                };
                tokio::spawn(async move {
                    let _ = connection.await;
                });
                let _ = client
                    .batch_execute(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))
                    .await;
                for role in roles {
                    let _ = client
                        .batch_execute(&format!("DROP ROLE IF EXISTS \"{role}\""))
                        .await;
                }
            });
        });
        let _ = cleanup.join();
    }
}
