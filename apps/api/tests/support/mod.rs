//! Support for the tests of `factory-api`: a real PostgreSQL, two tenants with people and tokens,
//! the real server on a loopback port, and a raw HTTP client.
//!
//! The database server and the cloned, migrated databases are the storage crate's test support,
//! included with `#[path]` so that there is one provisioning code. Fixtures run as the superuser,
//! because the application roles cannot insert tenants or tokens by design; everything the code
//! under test does, it does as the API login. A test that cannot get a server panics with
//! `BLOCKED:` and is never a pass.
//!
//! The HTTP client writes the request bytes itself, so a test controls exactly what is sent (a
//! partial head, a forged header, a body that never ends).
#![allow(
    dead_code,
    unused_imports,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

#[path = "../../../../crates/storage/tests/support/server.rs"]
pub mod server;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use factory_api::boot::{StateInputs, assemble_state};
use factory_api::config::{GithubSettings, Limits};
use factory_api::routes::router;
use factory_api::server::serve;
use factory_api::state::{ApiPorts, ApiState};
use factory_api::tokens;
use factory_composition::authority::StoreAuthority;
use factory_composition::config::SecretFile;
use factory_composition::profile::Profile;
use factory_composition::redaction::{FactorySecrets, redactor_from_policy};
use factory_composition::seams::FileAllowlist;
use factory_composition::startup::load_policy;
use factory_composition::system::{RandomIds, Shutdown, SystemClock};
use factory_domain::ids::{PrincipalId, RepositoryId, TenantId};
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::githost::WebhookVerifier;
use factory_ports::store::Store;
use factory_storage::pg::{DatabaseUrl, PgStore, PgStoreConfig, PoolSettings, TenantLogin};
use factory_workflow::commands::Authority;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use uuid::Uuid;

pub use server::{Login, TestDb, server};

pub fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A pool of a few connections so many tests can share a server.
pub fn small_pool(url: DatabaseUrl) -> PoolSettings {
    let mut settings = PoolSettings::new(url);
    settings.max_connections = 8;
    settings.acquire_timeout = Duration::from_secs(20);
    settings
}

/// One person: a principal row with a numeric GitHub id, and a token.
#[derive(Clone)]
pub struct Person {
    pub principal: PrincipalId,
    pub github_id: u64,
    pub login: String,
    pub token: String,
}

/// One tenant: a repository and four people.
#[derive(Clone)]
pub struct Tenant {
    pub id: TenantId,
    pub repository: RepositoryId,
    pub installation: u64,
    pub github_repository: u64,
    pub full_name: String,
    pub requester: Person,
    pub approver: Person,
    pub operator: Person,
    /// A principal that is not on the allowlist.
    pub outsider: Person,
}

fn random_uuid() -> Uuid {
    RandomIds::new()
        .expect("the random source opens")
        .new_uuid()
}

fn random_token() -> String {
    let (a, b) = (random_uuid(), random_uuid());
    let mut secret = [0_u8; 32];
    secret[..16].copy_from_slice(a.as_bytes());
    secret[16..].copy_from_slice(b.as_bytes());
    tokens::format_token(&secret)
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Wraps the real store in a stand-in, for the deliberate breaks.
pub type StoreWrapper = Box<dyn FnOnce(Arc<PgStore>) -> Arc<dyn Store>>;

/// What a test may change about the environment it starts.
pub struct Options {
    pub profile: Profile,
    pub limits: Limits,
    pub authority: Option<Arc<dyn Authority>>,
    pub webhooks: Option<Option<Arc<dyn WebhookVerifier>>>,
    pub store_wrapper: Option<StoreWrapper>,
    pub factory_label: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            profile: Profile::Test,
            limits: Limits::default(),
            authority: None,
            webhooks: None,
            store_wrapper: None,
            factory_label: "factory".to_owned(),
        }
    }
}

pub struct Env {
    pub db: TestDb,
    pub addr: SocketAddr,
    pub state: Arc<ApiState>,
    pub store: Arc<PgStore>,
    pub a: Tenant,
    pub b: Tenant,
    pub webhook_secret: String,
    pub shutdown: Shutdown,
    pub checkout: PathBuf,
    server: JoinHandle<std::io::Result<()>>,
    writer: JoinHandle<()>,
}

impl Env {
    pub async fn start() -> Self {
        Self::start_with(Options::default()).await
    }

    pub async fn start_with(options: Options) -> Self {
        let db = server().clone_database().await;
        let a = seed_tenant(&db, 0, 1000).await;
        let b = seed_tenant(&db, 1, 2000).await;

        let checkout =
            std::env::temp_dir().join(format!("factory-api-test-{}", random_uuid().simple()));
        std::fs::create_dir_all(checkout.join("allowlist")).expect("the checkout directory");
        std::fs::write(
            checkout.join("allowlist/allowlist.yaml"),
            allowlist_text(&[&a, &b]),
        )
        .expect("the allowlist file");

        let logins = db.server.logins().await;
        let mut config = PgStoreConfig::new(small_pool(db.url(&logins.api)));
        config.tenant_login = TenantLogin::Api;
        config.system = None;
        let store = Arc::new(
            PgStore::connect(config)
                .await
                .expect("the store becomes ready"),
        );

        let policies = load_policy(&repository_root(), &[]).expect("the real policies load");
        let redactor = Arc::new(redactor_from_policy(&policies.security).expect("redactor"));
        let mut secrets = FactorySecrets::new(Arc::clone(&redactor), &policies.security);
        let webhook_secret = format!("{}{}", random_uuid().simple(), random_uuid().simple());
        let secret_file = checkout.join("webhook_secret");
        std::fs::write(&secret_file, &webhook_secret).expect("the secret file");
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600))
                .expect("mode");
        }
        let verifier = options.webhooks.unwrap_or_else(|| {
            Some(
                factory_composition::webhook::verifier_from_files(
                    &[SecretFile::at(secret_file)],
                    &mut secrets,
                )
                .expect("the verifier"),
            )
        });

        let store_dyn: Arc<dyn Store> = match options.store_wrapper {
            Some(wrap) => wrap(Arc::clone(&store)),
            None => store.clone(),
        };
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let ids: Arc<dyn IdGenerator> = Arc::new(RandomIds::new().expect("ids"));
        let allowlist_file = Arc::new(FileAllowlist::in_checkout(&checkout));
        let authority: Arc<dyn Authority> = options.authority.unwrap_or_else(|| {
            Arc::new(StoreAuthority::new(
                Arc::clone(&store_dyn),
                Arc::clone(&allowlist_file),
                Arc::clone(&policies.engine),
                Arc::clone(&clock),
            ))
        });
        let ports = ApiPorts {
            store: store_dyn,
            clock,
            ids,
            webhooks: verifier,
            authority,
            allowlist: allowlist_file.clone(),
        };
        let (state, writer) = assemble_state(StateInputs {
            profile: options.profile,
            ports,
            allowlist_file,
            policies,
            redactor,
            audience: "factory-api".to_owned(),
            github: GithubSettings {
                webhook_secret_files: Vec::new(),
                factory_label: options.factory_label,
            },
            limits: options.limits.clone(),
        })
        .expect("the state assembles");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let addr = listener.local_addr().expect("address");
        let shutdown = Shutdown::new();
        let server = tokio::spawn(serve(
            listener,
            router(Arc::clone(&state)),
            options.limits,
            shutdown.clone(),
        ));
        Self {
            db,
            addr,
            state,
            store,
            a,
            b,
            webhook_secret,
            shutdown,
            checkout,
            server,
            writer,
        }
    }

    pub async fn stop(self) {
        self.shutdown.raise();
        let _ = tokio::time::timeout(Duration::from_secs(20), self.server).await;
        self.writer.abort();
        let _ = std::fs::remove_dir_all(&self.checkout);
    }

    pub async fn send(&self, request: Req) -> Reply {
        send_bytes(self.addr, &request.build()).await
    }

    /// Signs a webhook body with the environment's secret.
    pub fn sign(&self, body: &[u8]) -> String {
        format!(
            "sha256={}",
            factory_testkit::webhook::hmac_sha256_hex(self.webhook_secret.as_bytes(), body)
        )
    }

    /// A signed delivery of `body`.
    pub fn delivery(&self, event: &str, delivery_id: &str, body: &[u8]) -> Req {
        Req::post("/v1/webhooks/github")
            .header("X-GitHub-Event", event)
            .header("X-GitHub-Delivery", delivery_id)
            .header("X-Hub-Signature-256", &self.sign(body))
            .header("Content-Type", "application/json")
            .body(body.to_vec())
    }

    /// Inserts a token row for a person, as the superuser. Returns the token text.
    pub async fn issue_token(&self, tenant: &Tenant, person: &Person, kind: Kind) -> String {
        let token = random_token();
        insert_token(&self.db, tenant.id, person.principal, &token, kind).await;
        token
    }
}

/// What a token row looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Valid,
    Expired,
    Revoked,
    WrongAudience,
}

async fn insert_token(
    db: &TestDb,
    tenant: TenantId,
    principal: PrincipalId,
    token: &str,
    kind: Kind,
) {
    let hash = hex_of(&tokens::hash_token(token).0);
    let id = random_uuid();
    let (audience, created, expires, revoked) = match kind {
        Kind::Valid => ("factory-api", "now()", "now() + interval '1 day'", "NULL"),
        Kind::Expired => (
            "factory-api",
            "now() - interval '2 days'",
            "now() - interval '1 day'",
            "NULL",
        ),
        Kind::Revoked => ("factory-api", "now()", "now() + interval '1 day'", "now()"),
        Kind::WrongAudience => ("other-api", "now()", "now() + interval '1 day'", "NULL"),
    };
    db.run(&format!(
        "INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, created_at, expires_at, revoked_at) \
         VALUES ('{}', '{id}', '{}', decode('{hash}', 'hex'), '{audience}', {created}, {expires}, {revoked})",
        tenant.as_uuid(),
        principal.as_uuid(),
    ))
    .await;
}

async fn seed_person(db: &TestDb, tenant: TenantId, github_id: u64, login: &str) -> Person {
    let principal = PrincipalId::from_uuid(random_uuid());
    db.run(&format!(
        "INSERT INTO principals (tenant_id, id, kind, github_user_id, login) \
         VALUES ('{}', '{}', 'human', {github_id}, '{login}')",
        tenant.as_uuid(),
        principal.as_uuid(),
    ))
    .await;
    let token = random_token();
    insert_token(db, tenant, principal, &token, Kind::Valid).await;
    Person {
        principal,
        github_id,
        login: login.to_owned(),
        token,
    }
}

async fn seed_tenant(db: &TestDb, position: usize, base: u64) -> Tenant {
    let id = TenantId::from_uuid(random_uuid());
    let repository = RepositoryId::from_uuid(random_uuid());
    let slug = format!(
        "tenant-{position}-{}",
        &id.as_uuid().simple().to_string()[..8]
    );
    let installation = 5000 + position as u64;
    let github_repository = 6000 + position as u64;
    let full_name = format!("org/repo-{position}");
    db.run(&format!(
        "INSERT INTO tenants (id, slug, display_name) VALUES ('{}', '{slug}', 'Tenant {position}'); \
         INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch, autonomy_ceiling) \
         VALUES ('{}', '{}', {installation}, {github_repository}, '{full_name}', 'main', 'L1');",
        id.as_uuid(),
        id.as_uuid(),
        repository.as_uuid(),
    ))
    .await;
    Tenant {
        id,
        repository,
        installation,
        github_repository,
        full_name,
        requester: seed_person(db, id, base + 1, "requester-one").await,
        approver: seed_person(db, id, base + 2, "approver-one").await,
        operator: seed_person(db, id, base + 3, "operator-one").await,
        outsider: seed_person(db, id, base + 4, "outsider-one").await,
    }
}

/// The allowlist file for these tenants: a requester, an approver and an operator each; the
/// outsider is not listed.
pub fn allowlist_text(tenants: &[&Tenant]) -> String {
    let mut text = String::from("version: 1\nentries:\n");
    for tenant in tenants {
        for (person, designation) in [
            (&tenant.requester, "requester"),
            (&tenant.approver, "approver"),
            (&tenant.operator, "operator"),
        ] {
            text.push_str(&format!(
                "  - tenant: {}\n    github_user_id: {}\n    login: {}\n    designations: [{designation}]\n",
                tenant.id.as_uuid(),
                person.github_id,
                person.login,
            ));
        }
    }
    text
}

// ---- the raw client ------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Req {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Req {
    pub fn get(path: &str) -> Self {
        Self::new("GET", path)
    }

    pub fn post(path: &str) -> Self {
        Self::new("POST", path)
    }

    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn bearer(self, token: &str) -> Self {
        self.header("Authorization", &format!("Bearer {token}"))
    }

    pub fn body(mut self, bytes: Vec<u8>) -> Self {
        self.body = bytes;
        self
    }

    pub fn json(self, value: &Value) -> Self {
        self.header("Content-Type", "application/json")
            .body(serde_json::to_vec(value).expect("json"))
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out = format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n",
            self.method, self.path
        )
        .into_bytes();
        for (name, value) in &self.headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        if self.method == "POST" || !self.body.is_empty() {
            out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&self.body);
        out
    }
}

#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&self.body)))
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The names of the headers, lower case, sorted, without the ones that vary by answer.
    pub fn header_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .headers
            .iter()
            .map(|(name, _)| name.to_ascii_lowercase())
            .filter(|name| {
                !matches!(
                    name.as_str(),
                    "date" | "content-length" | "www-authenticate" | "retry-after" | "allow"
                )
            })
            .collect();
        names.sort();
        names.dedup();
        names
    }
}

pub fn parse_reply(raw: &[u8]) -> Reply {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no head in {:?}", String::from_utf8_lossy(raw)));
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("a status line");
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();
    Reply {
        status,
        headers,
        body: raw[split + 4..].to_vec(),
    }
}

pub async fn send_bytes(addr: SocketAddr, bytes: &[u8]) -> Reply {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    // A server that answers before it has read a long body may reset the connection while the
    // client is still writing. What it sent first is still the answer.
    let _ = stream.write_all(bytes).await;
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 8192];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => raw.extend_from_slice(&chunk[..n]),
            Err(_) => panic!("the server did not answer in time"),
        }
    }
    parse_reply(&raw)
}

/// Opens a connection, writes `bytes` and returns the stream, for the tests that send a request
/// in pieces.
pub async fn open(addr: SocketAddr, bytes: &[u8]) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(bytes).await.expect("write");
    stream
}

/// Reads whatever the server sends until it closes the connection, within `within`. A reset
/// counts as a close.
pub async fn read_to_close(stream: &mut TcpStream, within: Duration) -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 8192];
    let deadline = tokio::time::Instant::now() + within;
    loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return Some(raw),
            Ok(Ok(n)) => raw.extend_from_slice(&chunk[..n]),
            Err(_) => return None,
        }
    }
}
