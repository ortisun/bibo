//! A real PostgreSQL server for the tests, and databases cloned from a migrated template.
//!
//! Where the server comes from, first match wins (the same order as `scripts/db-test.sh`):
//!
//! 1. `FACTORY_DB_ADMIN_URL`, a superuser URL of a server you provide. Only databases named
//!    `factory_t_*` and `factory_tpl_*` and roles named `dbtest_*` are created and dropped. Do not
//!    point it at a server that matters.
//! 2. A private cluster from local PostgreSQL binaries (`initdb`, `pg_ctl`, `postgres`, found in
//!    `FACTORY_PG_BIN`, on `PATH`, or in the usual Homebrew and Debian places). It listens on a unix
//!    socket in a directory only this user can enter, and it is removed when the last test of the
//!    process is done.
//! 3. Docker, image `FACTORY_DB_IMAGE` (default `postgres:18`), on a random loopback port.
//!
//! `FACTORY_DB_PROVISION=local|docker|none` forces one of the last two or turns provisioning off.
//!
//! When no server can be had, the first test that needs one **panics with a message that starts
//! with `BLOCKED:`**. A test that cannot run is never a pass and never skipped quietly.
//!
//! Logins are created with the shape the deployment creates (`docs/database/for-the-storage-crate.md`):
//! a worker login in `factory_app`, an API login in `factory_app` and `factory_resolver`, and an
//! engine login in `factory_system`. The migrations run as a superuser, like the deploy step.
//!
//! This support code makes and removes the directories of a private cluster and reads the
//! migration files, so it allows the file system calls that `clippy.toml` bans for the crate.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::Text;
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};
use factory_storage::pg::DatabaseUrl;
use tokio::sync::OnceCell;

static SERVER: Mutex<Weak<Server>> = Mutex::new(Weak::new());
static NEXT: AtomicUsize = AtomicUsize::new(0);

/// The server of this process. Started by the first caller and stopped when the last test holding
/// it finishes.
///
/// # Panics
/// Panics with a message that starts with `BLOCKED:` when no PostgreSQL server can be had.
pub fn server() -> Arc<Server> {
    let mut guard = SERVER.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(running) = guard.upgrade() {
        return running;
    }
    let started = Arc::new(Server::start().unwrap_or_else(|why| panic!("BLOCKED: {why}")));
    *guard = Arc::downgrade(&started);
    started
}

enum Kind {
    Local {
        data: PathBuf,
        socket: PathBuf,
        bin: PathBuf,
    },
    Docker {
        container: String,
    },
    External,
}

/// A login role of the deployment shape.
#[derive(Debug, Clone)]
pub struct Login {
    pub name: String,
    password: String,
}

/// The three logins every database test uses.
pub struct Logins {
    pub worker: Login,
    pub api: Login,
    pub engine: Login,
}

/// A running PostgreSQL server and the means to talk to it.
pub struct Server {
    kind: Kind,
    host: String,
    port: u16,
    admin_user: String,
    admin_password: Option<String>,
    run: String,
    template: OnceCell<String>,
    logins: OnceCell<Logins>,
    databases: Mutex<Vec<String>>,
    roles: Mutex<Vec<String>>,
    pub version: String,
}

fn unique_run() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    format!("{:x}{:x}", std::process::id(), nanos & 0xff_ffff_ffff)
}

/// A throwaway secret: enough entropy for a login that exists for one test run.
fn random_secret() -> String {
    let mut text = String::new();
    for round in 0_u64..3 {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u64(round);
        hasher.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos()),
        );
        text.push_str(&format!("{:016x}", hasher.finish()));
    }
    text
}

fn find_binaries() -> Option<PathBuf> {
    let mut places: Vec<PathBuf> = Vec::new();
    if let Some(dir) = std::env::var_os("FACTORY_PG_BIN") {
        places.push(PathBuf::from(dir));
    }
    if let Some(path) = std::env::var_os("PATH") {
        places.extend(std::env::split_paths(&path));
    }
    for fixed in [
        "/opt/homebrew/opt/postgresql@18/bin",
        "/opt/homebrew/opt/postgresql@17/bin",
        "/usr/local/opt/postgresql@18/bin",
        "/usr/local/opt/postgresql@17/bin",
        "/usr/lib/postgresql/18/bin",
        "/usr/lib/postgresql/17/bin",
    ] {
        places.push(PathBuf::from(fixed));
    }
    // initdb alone is not enough: a client-only package ships one with no server beside it.
    places.into_iter().find(|dir| {
        ["initdb", "pg_ctl", "postgres"]
            .iter()
            .all(|name| dir.join(name).is_file())
    })
}

fn run(program: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("cannot run {}: {error}", program.display()))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "{} {} failed:\n{}{}",
            program.display(),
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

impl Server {
    fn start() -> Result<Self, String> {
        let mode = std::env::var("FACTORY_DB_PROVISION").unwrap_or_else(|_| "auto".to_owned());
        let blocking = Self::provision(&mode)?;
        Ok(blocking)
    }

    fn provision(mode: &str) -> Result<Self, String> {
        if let Ok(url) = std::env::var("FACTORY_DB_ADMIN_URL") {
            return Self::external(&url);
        }
        match mode {
            "none" => Err(
                "FACTORY_DB_PROVISION=none and FACTORY_DB_ADMIN_URL is not set, so there is no database"
                    .to_owned(),
            ),
            "docker" => Self::docker().map_err(|why| {
                format!("Docker is not available or could not start the PostgreSQL image: {why}")
            }),
            "local" => Self::local().map_err(|why| {
                format!("no local PostgreSQL server binaries were found, or the server did not start: {why}")
            }),
            _ => Self::local().or_else(|_| Self::docker()).map_err(|_| {
                "no PostgreSQL server: set FACTORY_DB_ADMIN_URL, install PostgreSQL 16 or later, or start Docker"
                    .to_owned()
            }),
        }
    }

    fn external(url: &str) -> Result<Self, String> {
        // A URL with a scheme, an optional user and password before an at sign, a host and an
        // optional port, a database name, and an optional query that may name a socket
        // directory (`host`) and a port.
        let rest = url
            .split_once("://")
            .map(|(_, rest)| rest)
            .ok_or("FACTORY_DB_ADMIN_URL is not a URL")?;
        let (authority, tail) = rest.split_once('/').unwrap_or((rest, ""));
        let query = tail.split_once('?').map_or("", |(_, query)| query);
        let (credentials, hostport) = authority
            .rsplit_once('@')
            .unwrap_or(("postgres", authority));
        let (user, password) = match credentials.split_once(':') {
            Some((user, password)) => (user.to_owned(), Some(password.to_owned())),
            None => (credentials.to_owned(), None),
        };
        let mut host = hostport.split(':').next().unwrap_or("").to_owned();
        let mut port = hostport
            .split(':')
            .nth(1)
            .and_then(|text| text.parse::<u16>().ok())
            .unwrap_or(5432);
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("host", value)) => host = value.to_owned(),
                Some(("port", value)) => port = value.parse().unwrap_or(port),
                _ => {}
            }
        }
        if host.is_empty() {
            "localhost".clone_into(&mut host);
        }
        let mut server = Self::blank(Kind::External, host, port, user, password);
        server.version = server.probe()?;
        Ok(server)
    }

    fn local() -> Result<Self, String> {
        let bin = find_binaries().ok_or("initdb, pg_ctl and postgres were not found")?;
        let run_id = unique_run();
        let data = std::env::temp_dir().join(format!("factory-pg-{run_id}"));
        // A unix socket path is limited to about 100 bytes, so the socket directory is short.
        let socket = PathBuf::from(format!("/tmp/fdb.{run_id}"));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&socket)
            .map_err(|error| format!("cannot make the socket directory: {error}"))?;
        let initdb = bin.join("initdb");
        run(
            &initdb,
            &[
                "-D",
                &data.display().to_string(),
                "-U",
                "postgres",
                "--auth=trust",
                "-E",
                "UTF8",
                "--no-locale",
                "--no-sync",
            ],
        )?;
        let options = format!(
            "-c listen_addresses= -c unix_socket_directories={} -c port=5432 -c fsync=off \
             -c synchronous_commit=off -c full_page_writes=off -c max_connections=300",
            socket.display()
        );
        let log = data.with_extension("log");
        run(
            &bin.join("pg_ctl"),
            &[
                "-D",
                &data.display().to_string(),
                "-l",
                &log.display().to_string(),
                "-w",
                "-o",
                &options,
                "start",
            ],
        )?;
        let mut server = Self::blank(
            Kind::Local {
                data,
                socket: socket.clone(),
                bin,
            },
            socket.display().to_string(),
            5432,
            "postgres".to_owned(),
            None,
        );
        server.version = server.probe()?;
        Ok(server)
    }

    fn docker() -> Result<Self, String> {
        let docker = Path::new("docker");
        run(docker, &["info"]).map_err(|_| "the docker daemon does not answer".to_owned())?;
        let image = std::env::var("FACTORY_DB_IMAGE").unwrap_or_else(|_| "postgres:18".to_owned());
        let password = random_secret();
        let name = format!("factory-store-test-{}", unique_run());
        run(
            docker,
            &[
                "run",
                "-d",
                "--rm",
                "--name",
                &name,
                "-e",
                &format!("POSTGRES_PASSWORD={password}"),
                "-p",
                "127.0.0.1::5432",
                &image,
                "-c",
                "fsync=off",
                "-c",
                "max_connections=300",
            ],
        )?;
        let mut port = None;
        for _ in 0..60 {
            if let Ok(text) = run(docker, &["port", &name, "5432/tcp"]) {
                port = text
                    .lines()
                    .next()
                    .and_then(|line| line.rsplit(':').next())
                    .and_then(|number| number.trim().parse::<u16>().ok());
            }
            if let Some(found) = port {
                let mut probe = Self::blank(
                    Kind::Docker {
                        container: name.clone(),
                    },
                    "127.0.0.1".to_owned(),
                    found,
                    "postgres".to_owned(),
                    Some(password.clone()),
                );
                if let Ok(version) = probe.probe() {
                    probe.version = version;
                    return Ok(probe);
                }
                std::mem::forget(probe);
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        let _ = run(docker, &["rm", "-f", &name]);
        Err("the container did not become ready".to_owned())
    }

    fn blank(kind: Kind, host: String, port: u16, user: String, password: Option<String>) -> Self {
        Self {
            kind,
            host,
            port,
            admin_user: user,
            admin_password: password,
            run: unique_run(),
            template: OnceCell::new(),
            logins: OnceCell::new(),
            databases: Mutex::new(Vec::new()),
            roles: Mutex::new(Vec::new()),
            version: String::new(),
        }
    }

    /// Asks the server for its version on a throwaway runtime, to check that it answers.
    fn probe(&self) -> Result<String, String> {
        let url =
            self.connection_string(&self.admin_user, self.admin_password.as_deref(), "postgres");
        // The runtime is made, used and dropped on a thread of its own, because this function may
        // be called from inside a test that already runs on a runtime.
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?;
            runtime.block_on(async {
                let mut connection = AsyncPgConnection::establish(&url)
                    .await
                    .map_err(|_| "the server is not reachable".to_owned())?;
                let row: Scalar = sql_query(
                    "SELECT current_setting('server_version') || CASE WHEN (SELECT rolsuper FROM pg_roles \
                     WHERE rolname = current_user) THEN '' ELSE ' NOT-SUPERUSER' END AS v",
                )
                .get_result(&mut connection)
                .await
                .map_err(|_| "the server did not answer".to_owned())?;
                if row.v.ends_with("NOT-SUPERUSER") {
                    return Err("the database user must be a superuser".to_owned());
                }
                Ok(row.v)
            })
        })
        .join()
        .unwrap_or_else(|_| Err("the probe panicked".to_owned()))
    }

    /// A connection string in the key and value form, which needs no escaping for a path.
    fn connection_string(&self, user: &str, password: Option<&str>, database: &str) -> String {
        let mut text = format!(
            "host={} port={} user={user} dbname={database}",
            self.host, self.port
        );
        if let Some(password) = password {
            text.push_str(&format!(" password={password}"));
        }
        text
    }

    /// A connection as the superuser to the named database.
    pub async fn admin(&self, database: &str) -> AsyncPgConnection {
        let url =
            self.connection_string(&self.admin_user, self.admin_password.as_deref(), database);
        AsyncPgConnection::establish(&url)
            .await
            .unwrap_or_else(|_| panic!("BLOCKED: the server stopped answering"))
    }

    async fn create_database(&self, name: &str, template: &str) {
        let mut admin = self.admin("postgres").await;
        let statement = if template == "template0" {
            format!(
                "CREATE DATABASE \"{name}\" TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C'"
            )
        } else {
            format!("CREATE DATABASE \"{name}\" TEMPLATE \"{template}\"")
        };
        // Two clones can race for the template. A refusal for that reason passes in a moment.
        let mut attempt = 0;
        loop {
            match admin.batch_execute(&statement).await {
                Ok(()) => break,
                Err(_) if attempt < 40 => {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => panic!("cannot create database {name}: {error}"),
            }
        }
        self.databases
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(name.to_owned());
    }

    /// The migrated template: all migrations applied by a superuser, in order, the way the deploy
    /// step does.
    async fn template(&self) -> &str {
        self.template
            .get_or_init(|| async {
                let name = format!("factory_tpl_{}", self.run);
                self.create_database(&name, "template0").await;
                let mut connection = self.admin(&name).await;
                connection
                    .batch_execute(
                        "CREATE TABLE __diesel_schema_migrations (\
                           version VARCHAR(50) PRIMARY KEY NOT NULL, \
                           run_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP)",
                    )
                    .await
                    .expect("create the migration table");
                for (version, sql) in migration_files() {
                    connection
                        .batch_execute(&sql)
                        .await
                        .unwrap_or_else(|error| panic!("migration {version} failed: {error}"));
                    connection
                        .batch_execute(&format!(
                            "INSERT INTO __diesel_schema_migrations (version) VALUES ('{version}')"
                        ))
                        .await
                        .expect("record the migration");
                }
                name
            })
            .await
    }

    /// The three logins of the deployment. Created once per server.
    pub async fn logins(&self) -> &Logins {
        // The groups come from the migrations, so the template comes first.
        self.template().await;
        self.logins
            .get_or_init(|| async {
                let worker = self.create_login("worker", &["factory_app"]).await;
                let api = self
                    .create_login("api", &["factory_api_app", "factory_resolver"])
                    .await;
                let engine = self.create_login("engine", &["factory_system"]).await;
                Logins {
                    worker,
                    api,
                    engine,
                }
            })
            .await
    }

    /// A login of any shape, for the tests that need a wrong one.
    pub async fn create_login(&self, label: &str, groups: &[&str]) -> Login {
        self.template().await;
        let name = format!("dbtest_{label}_{}", self.run);
        let password = random_secret();
        let mut admin = self.admin("postgres").await;
        let membership = if groups.is_empty() {
            String::new()
        } else {
            format!(" IN ROLE {}", groups.join(", "))
        };
        admin
            .batch_execute(&format!(
                "CREATE ROLE \"{name}\" LOGIN PASSWORD '{password}'{membership}"
            ))
            .await
            .unwrap_or_else(|error| panic!("cannot create the login {name}: {error}"));
        self.roles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(name.clone());
        Login { name, password }
    }

    /// The URL of a login on a database. Built at run time; never written in source.
    pub fn url(&self, login: &Login, database: &str) -> DatabaseUrl {
        DatabaseUrl::new(self.connection_string(&login.name, Some(&login.password), database))
    }

    /// The superuser's URL on a database.
    pub fn admin_url(&self, database: &str) -> DatabaseUrl {
        DatabaseUrl::new(self.connection_string(
            &self.admin_user,
            self.admin_password.as_deref(),
            database,
        ))
    }

    /// A fresh migrated database, cloned from the template.
    pub async fn clone_database(self: &Arc<Self>) -> TestDb {
        let template = self.template().await.to_owned();
        let name = format!(
            "factory_t_{}_{}",
            self.run,
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        self.create_database(&name, &template).await;
        TestDb {
            server: self.clone(),
            name,
        }
    }

    /// The migrations that are applied to the template, for the test that compares them with the
    /// versions the code expects.
    pub fn migration_versions() -> Vec<String> {
        migration_files()
            .into_iter()
            .map(|(version, _)| version)
            .collect()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        match &self.kind {
            Kind::Local { data, socket, bin } => {
                let _ = run(
                    &bin.join("pg_ctl"),
                    &[
                        "-D",
                        &data.display().to_string(),
                        "-m",
                        "immediate",
                        "-w",
                        "stop",
                    ],
                );
                let _ = std::fs::remove_dir_all(data);
                let _ = std::fs::remove_file(data.with_extension("log"));
                let _ = std::fs::remove_dir_all(socket);
            }
            Kind::Docker { container } => {
                let _ = run(Path::new("docker"), &["rm", "-f", container]);
            }
            Kind::External => self.drop_external(),
        }
    }
}

impl Server {
    /// On a server we do not own, drop what this run created.
    fn drop_external(&self) {
        let databases: Vec<String> = std::mem::take(
            &mut *self
                .databases
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        let roles: Vec<String> =
            std::mem::take(&mut *self.roles.lock().unwrap_or_else(PoisonError::into_inner));
        let url =
            self.connection_string(&self.admin_user, self.admin_password.as_deref(), "postgres");
        let cleanup = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async {
                let Ok(mut admin) = AsyncPgConnection::establish(&url).await else {
                    return;
                };
                for database in databases {
                    let _ = admin
                        .batch_execute(&format!(
                            "DROP DATABASE IF EXISTS \"{database}\" WITH (FORCE)"
                        ))
                        .await;
                }
                for role in roles {
                    let _ = admin
                        .batch_execute(&format!("DROP ROLE IF EXISTS \"{role}\""))
                        .await;
                }
            });
        });
        let _ = cleanup.join();
    }
}

/// The migrations of the repository as (diesel version, up.sql), oldest first. The version is the
/// digits of the directory name before the first underscore, as the Diesel CLI computes it.
fn migration_files() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let mut directories: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", root.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.join("up.sql").is_file())
        .collect();
    directories.sort();
    directories
        .into_iter()
        .map(|directory| {
            let name = directory
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let version: String = name
                .split('_')
                .next()
                .unwrap_or("")
                .chars()
                .filter(char::is_ascii_digit)
                .collect();
            let sql = std::fs::read_to_string(directory.join("up.sql"))
                .unwrap_or_else(|error| panic!("cannot read a migration: {error}"));
            (version, sql)
        })
        .collect()
}

#[derive(QueryableByName)]
pub struct Scalar {
    #[diesel(sql_type = Text)]
    pub v: String,
}

/// A migrated database for one test.
pub struct TestDb {
    pub server: Arc<Server>,
    pub name: String,
}

impl TestDb {
    /// The URL of a login on this database.
    pub fn url(&self, login: &Login) -> DatabaseUrl {
        self.server.url(login, &self.name)
    }

    /// A superuser connection to this database. A superuser bypasses row-level security, so it
    /// is for fixtures and for looking, never for the code under test.
    pub async fn admin(&self) -> AsyncPgConnection {
        self.server.admin(&self.name).await
    }

    /// A connection as a login, with no transaction and no tenant setting.
    pub async fn connect_as(&self, login: &Login) -> AsyncPgConnection {
        let url = self
            .server
            .connection_string(&login.name, Some(&login.password), &self.name);
        AsyncPgConnection::establish(&url)
            .await
            .unwrap_or_else(|error| panic!("cannot connect as {}: {error}", login.name))
    }

    /// Runs statements as the superuser.
    pub async fn run(&self, sql: &str) {
        self.admin()
            .await
            .batch_execute(sql)
            .await
            .unwrap_or_else(|error| panic!("fixture statement failed: {error}\n{sql}"));
    }

    /// The first column of the first row as text, as the superuser. `None` for no row.
    pub async fn text(&self, sql: &str) -> Option<String> {
        let wrapped = format!("SELECT (q.v)::text AS v FROM ({sql}) AS q(v) LIMIT 1");
        sql_query(wrapped)
            .get_result::<Scalar>(&mut self.admin().await)
            .await
            .ok()
            .map(|row| row.v)
    }

    /// A count or number as the superuser.
    pub async fn number(&self, sql: &str) -> i64 {
        self.text(sql)
            .await
            .and_then(|text| text.parse().ok())
            .unwrap_or(-1)
    }
}
