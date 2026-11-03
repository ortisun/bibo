//! The loopback rig: the real worker binary, started from a configuration file in which every
//! external endpoint is a loopback fake, over a real PostgreSQL.
//!
//! # What is real
//!
//! The `factory-worker` binary and everything its configuration builds (the GitHub App adapter with
//! its JWT, installation tokens and issue source, the change host, the status writer, the router,
//! the agent runtime adapters, the registry client, the token sweep, the broker listener, the
//! engine, the loop), the protected policies, the allowlist file, the artifact store and PostgreSQL.
//!
//! # What is fake, and labelled
//!
//! * GitHub: FX-GH of the test kit behind a front for the one route it does not have (the rules of
//!   the default branch). It runs on the system clock, so that the JWTs the adapter signs and the
//!   tokens the fake issues agree.
//! * The model providers and the registry: loopback servers that answer every request with a
//!   labelled `503` or `404` and record it. In a run that needs no sandbox no request must reach
//!   them, and a test asserts that.
//! * The API: the rows its webhook handler writes (a recorded delivery, a `RECEIVED` job with the
//!   webhook as origin, two audit records) are written by [`Lab::receive_webhook_job`] as the API
//!   login, through the store's own operations. The handler itself is tested by
//!   `apps/api/tests/webhook.rs`; the API cannot be linked here (DEP-01).
//!
//! Nothing leaves the machine. No key is a literal: every credential is made when the test runs.
#![allow(dead_code, clippy::disallowed_methods, clippy::disallowed_types)]

#[path = "../../../../crates/github/tests/common/keys.rs"]
mod keys;

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use factory_composition::startup::load_policy;
use factory_composition::system::{RandomIds, SystemClock};
use factory_domain::ids::{
    AuditEventId, CorrelationId, JobId, PrincipalId, RepositoryId, TenantId, WebhookDeliveryId,
};
use factory_domain::scope::TenantScope;
use factory_domain::values::{Sha256Digest, Slug};
use factory_domain::vocabulary::{AutonomyLevel, ExecutionMode};
use factory_ports::clock::IdGenerator;
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, DeliveryOutcome, GithubRepositoryId, InstallationId,
    JobOrigin, NewAuditEvent, NewJob, NewWebhookDelivery, PipelineScope, Store,
};
use factory_storage::pg::{PgStore, PgStoreConfig, TenantLogin};
use factory_testkit::fx::canary::{Canary, CanarySet, Sweeper};
use factory_testkit::fx::github::{FakeGithub, User};
use factory_testkit::fx::http::{HttpRequest, HttpResponse, HttpServer};
use factory_testkit::fx::sinks::{SinkCollector, SinkKind};
use factory_workflow::engine::config::SLICE_ONE_SCOPE;
use serde_json::{Value, json};

use super::deployment::{Deployment, deployment_in, repository_root, write_private};
use super::{seed_tenant, seeded_repository, small_pool};

/// The repository every scenario works on.
pub const REPO: &str = "example-org/word-count";
/// The installation of the App on it. `seed_tenant` registers the repository with this number.
pub const INSTALLATION: u64 = 1000;

/// A person the allowlist and the fake GitHub both know.
#[derive(Debug, Clone, Copy)]
pub struct Person {
    pub login: &'static str,
    pub id: u64,
}

/// On the allowlist as a requester.
pub const REQUESTER: Person = Person {
    login: "requester-one",
    id: 1001,
};
/// On the allowlist as an approver. Not the requester.
pub const APPROVER: Person = Person {
    login: "approver-one",
    id: 1002,
};
/// A GitHub account with write access that the allowlist does not list.
pub const OUTSIDER: Person = Person {
    login: "outsider-one",
    id: 1099,
};

/// Random bytes as hex, from the operating system, so that no key-shaped literal is in the source.
pub fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0_u8; bytes];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut buffer))
        .expect("random bytes");
    buffer.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free port");
    listener.local_addr().expect("an address").port()
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("a readable directory") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("a copied file");
        }
    }
}

/// What a recording fake saw: `METHOD /path`, one entry for each request.
#[derive(Clone, Default)]
pub struct Seen(Arc<Mutex<Vec<String>>>);

impl Seen {
    pub fn all(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn push(&self, request: &HttpRequest) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(format!("{} {}", request.method, request.path()));
    }
}

/// How a test changes the world before the worker starts.
#[derive(Default)]
pub struct Options {
    /// Changes the configuration text after the deployment wrote it.
    pub config: Option<Box<dyn FnOnce(String) -> String>>,
    /// Changes the protected checkout (a policy file, say) before the worker reads it.
    pub checkout: Option<Box<dyn FnOnce(&Path)>>,
    /// Does not register the two people as principals of the tenant, for a test whose engine rig
    /// registers its own.
    pub without_people: bool,
}

/// The values the run must never leak. They are made when the test runs.
pub struct Credentials {
    /// The body of the App's private key.
    pub app_key: String,
    /// The provider key the broker holds.
    pub provider_key: String,
    /// The key that signs decision requests.
    pub decision_key: String,
}

/// The world around one worker.
pub struct Lab {
    pub fake: FakeGithub,
    _github: HttpServer,
    _registry: HttpServer,
    _provider: HttpServer,
    /// Requests the registry fake received.
    pub registry_seen: Seen,
    /// Requests the model-provider fake received.
    pub provider_seen: Seen,
    pub tenant: TenantId,
    pub repository: RepositoryId,
    pub deployment: Deployment,
    pub protected: PathBuf,
    pub credentials: Credentials,
    /// The port the worker's broker listens on.
    pub broker_port: u16,
    api: PgStore,
    policy_hash: Sha256Digest,
    ids: RandomIds,
    worker: Option<Child>,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
}

impl Drop for Lab {
    fn drop(&mut self) {
        // A test that panicked before it stopped the worker still stops it the way a container
        // runtime does, and kills it only if it does not answer.
        let _ = self.stop_worker();
        let _ = std::fs::remove_dir_all(&self.deployment.dir);
        let _ = std::fs::remove_dir_all(&self.protected);
    }
}

/// The front of FX-GH: the one route it does not have, answered with the rules of a repository
/// whose default branch asks for nothing. Everything else is FX-GH's.
fn github_front(fake: &FakeGithub, request: &HttpRequest) -> HttpResponse {
    let segments: Vec<&str> = request.path().trim_matches('/').split('/').collect();
    if let ("GET", ["repos", _, _, "rules", "branches", _]) =
        (request.method.as_str(), segments.as_slice())
    {
        return HttpResponse::json(200, &json!([]));
    }
    fake.handle(request)
}

fn recording(name: &'static str, status: u16, body: Value, seen: &Seen) -> HttpServer {
    let seen = seen.clone();
    HttpServer::start(name, move |request| {
        seen.push(request);
        HttpResponse::json(status, &body).with_header("X-Factory-Fidelity", "fake")
    })
    .expect("a loopback fake starts")
}

impl Lab {
    /// Makes the world and the configuration. The worker is not started.
    pub async fn start(options: Options) -> Self {
        let ids = RandomIds::new().expect("random");
        let tenant = TenantId::from_uuid(ids.new_uuid());

        // GitHub, on the system clock.
        let fake = FakeGithub::with_clock(Arc::new(SystemClock));
        fake.add_repo(REPO, "main");
        fake.add_installation(INSTALLATION, "example-org", &[REPO]);
        for person in [REQUESTER, APPROVER, OUTSIDER] {
            fake.add_user(User::person(person.login, person.id, "write", "MEMBER"));
        }
        let github = {
            let fake = fake.clone();
            HttpServer::start("loopback-github", move |request| {
                github_front(&fake, request)
            })
            .expect("the GitHub fake starts")
        };
        let registry_seen = Seen::default();
        let registry = recording(
            "loopback-registry",
            404,
            json!({"errors": [{"detail": "Not Found"}]}),
            &registry_seen,
        );
        let provider_seen = Seen::default();
        let provider = recording(
            "loopback-provider",
            503,
            json!({"error": {"message": "no model is served by this fake"}}),
            &provider_seen,
        );

        // The protected checkout is a copy, so that a test can damage one policy file.
        let root = repository_root();
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let protected = root.join("target/loopback-e2e").join(format!(
            "protected-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&protected);
        copy_dir(&root.join("policies"), &protected.join("policies"));
        copy_dir(&root.join(".specify"), &protected.join(".specify"));
        copy_dir(
            &root.join(".claude/skills"),
            &protected.join(".claude/skills"),
        );
        std::fs::create_dir_all(protected.join("allowlist")).expect("a directory");
        let tenant_text = tenant.as_uuid().to_string();
        std::fs::write(
            protected.join("allowlist/allowlist.yaml"),
            format!(
                "version: 1\nentries:\n  - tenant: {tenant_text}\n    github_user_id: {}\n    login: {}\n    designations: [requester]\n  - tenant: {tenant_text}\n    github_user_id: {}\n    login: {}\n    designations: [approver]\n",
                REQUESTER.id, REQUESTER.login, APPROVER.id, APPROVER.login
            ),
        )
        .expect("the allowlist file");
        if let Some(change) = options.checkout {
            change(&protected);
        }

        // The deployment: a database with its logins and the configuration file.
        let broker_port = free_port();
        let credentials = Credentials {
            app_key: keys::Throwaway::new(keys::Form::Pkcs8).private_pem,
            provider_key: format!("loopback-provider-{}", random_hex(12)),
            decision_key: random_hex(32),
        };
        let github_base = github.base_url();
        let registry_base = registry.base_url();
        let provider_base = provider.base_url();
        let app_id = fake.app().id;
        let app_key = credentials.app_key.clone();
        let decision_key = credentials.decision_key.clone();
        let provider_key = credentials.provider_key.clone();
        let deployment = deployment_in(
            "local",
            false,
            &provider_base,
            &format!("127.0.0.1:{broker_port}"),
            Some(&protected),
            |dir| {
                write_private(&dir.join("app.pem"), &app_key);
                write_private(&dir.join("advisory.date"), "2026-10-27\n");
                write_private(&dir.join("decision.key"), &decision_key);
                // The provider key the deployment wrote is replaced with one made here, so that the
                // run can be swept for it.
                write_private(&dir.join("provider.key"), &provider_key);
                format!(
                    "github:\n  app_id: {app_id}\n  key_file: {dir}/app.pem\n  api_base_url: '{github_base}'\n  installations:\n    - {{ tenant: {tenant_text}, repository: {REPO}, installation_id: {INSTALLATION} }}\n\
                     registry: {{ base_url: '{registry_base}', user_agent: factory-loopback-test }}\n\
                     advisory_database: {{ date_file: {dir}/advisory.date }}\n\
                     runtimes: {{ declare_capabilities: true }}\n\
                     decisions: {{ key_file: {dir}/decision.key }}\n\
                     worker: {{ name_prefix: loopback, poll_interval_ms: 100, sweep_interval_s: 1, drain_s: 5, tenants: ['{tenant_text}'] }}\n",
                    dir = dir.display(),
                )
            },
        )
        .await;
        // No repository is ever fetched from the network: the remote is a directory that is not
        // there, so a stage that reached for one would fail on a missing path.
        let mut text = std::fs::read_to_string(&deployment.config_path).expect("the configuration");
        text = text.replace(
            "platform: linux/arm64 }",
            &format!(
                "platform: linux/arm64, remote: {{ directory: {}/remote }} }}",
                deployment.dir.display()
            ),
        );
        if let Some(change) = options.config {
            text = change(text);
        }
        std::fs::write(&deployment.config_path, text).expect("the changed configuration");

        // The tenant, its repository, the two people, as the superuser (the roles of the code
        // under test cannot insert tenants or principals).
        seed_tenant(&deployment.db, tenant, 0, REPO).await;
        for person in [REQUESTER, APPROVER] {
            if options.without_people {
                break;
            }
            deployment
                .db
                .run(&format!(
                    "INSERT INTO principals (tenant_id, id, kind, github_user_id, login) \
                     VALUES ('{tenant_text}', '{}', 'human', {}, '{}')",
                    ids.new_uuid(),
                    person.id,
                    person.login
                ))
                .await;
        }
        let logins = deployment.db.server.logins().await;
        let mut config = PgStoreConfig::new(small_pool(deployment.db.url(&logins.api)));
        config.tenant_login = TenantLogin::Api;
        config.system = None;
        let api = PgStore::connect(config)
            .await
            .expect("the API login connects");
        let policy_hash = load_policy(&protected, &[])
            .expect("the policies load")
            .hash;
        let stdout_log = deployment.dir.join("worker.stdout.log");
        let stderr_log = deployment.dir.join("worker.stderr.log");
        Self {
            fake,
            _github: github,
            _registry: registry,
            _provider: provider,
            registry_seen,
            provider_seen,
            repository: seeded_repository(tenant),
            tenant,
            deployment,
            protected,
            credentials,
            broker_port,
            api,
            policy_hash,
            ids,
            worker: None,
            stdout_log,
            stderr_log,
        }
    }

    /// Starts the real binary on the configuration file. `env` is added to its environment.
    pub fn spawn_worker(&mut self, env: &[(&str, &str)]) {
        let stdout = std::fs::File::create(&self.stdout_log).expect("a log file");
        let stderr = std::fs::File::create(&self.stderr_log).expect("a log file");
        let mut command = Command::new(env!("CARGO_BIN_EXE_factory-worker"));
        command
            .env("FACTORY_CONFIG", &self.deployment.config_path)
            .env("FACTORY_LOG", "info")
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        for (name, value) in env {
            command.env(name, value);
        }
        self.worker = Some(command.spawn().expect("the binary starts"));
    }

    /// The exit status of the worker if it has ended.
    pub fn worker_ended(&mut self) -> Option<std::process::ExitStatus> {
        self.worker
            .as_mut()
            .and_then(|c| c.try_wait().ok().flatten())
    }

    /// Asks the worker to stop as a container runtime does, waits for it and returns its exit code.
    pub fn stop_worker(&mut self) -> Option<i32> {
        let mut child = self.worker.take()?;
        if let Ok(Some(status)) = child.try_wait() {
            return status.code();
        }
        let _ = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                return status.code();
            }
            if Instant::now() > deadline {
                // Not killed with -9: a worker that does not stop on SIGTERM within the drain
                // budget is a finding, and the test says so.
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The text the worker wrote on standard output and standard error so far.
    pub fn logs(&self) -> (String, String) {
        (
            std::fs::read_to_string(&self.stdout_log).unwrap_or_default(),
            std::fs::read_to_string(&self.stderr_log).unwrap_or_default(),
        )
    }

    /// Writes what the API's webhook handler writes for a `factory` label that a requester applied
    /// to issue `number`: a recorded delivery, a `RECEIVED` job with the webhook as its origin and
    /// the two audit records. Done as the API login, through the store's operations.
    pub async fn receive_webhook_job(&self, number: u64, sender: Person) -> JobId {
        let principal: Option<String> = self
            .deployment
            .db
            .text(&format!(
                "SELECT id::text FROM principals WHERE github_user_id = {}",
                sender.id
            ))
            .await;
        let requester = PrincipalId::from_uuid(
            principal
                .expect("the sender is a registered principal")
                .parse()
                .expect("a uuid"),
        );
        let body = serde_json::to_vec(&json!({
            "action": "labeled",
            "installation": {"id": INSTALLATION},
            "repository": {"id": 2000, "full_name": REPO},
            "sender": {"id": sender.id, "login": sender.login, "type": "User"},
            "issue": {"number": number},
            "label": {"name": "factory"},
        }))
        .expect("json");
        let delivery_id = format!("0190a3b2-7c4d-4e5f-8a6b-{:012}", number);
        let scope = TenantScope::new(self.tenant);
        let mut tx = self.api.begin(scope).await.expect("a transaction");
        let recorded = tx
            .record_delivery(NewWebhookDelivery {
                id: WebhookDeliveryId::from_uuid(self.ids.new_uuid()),
                delivery_id: delivery_id.clone(),
                event_name: Slug::parse("issues").expect("a slug"),
                action: Some(Slug::parse("labeled").expect("a slug")),
                installation: InstallationId(INSTALLATION),
                repository: Some(GithubRepositoryId(2000)),
                sender_github_user_id: Some(sender.id),
                body_sha256: Sha256Digest::of(&body),
                semantic_key: Some(Sha256Digest::of(format!("labeled-{number}").as_bytes())),
            })
            .await
            .expect("the delivery is recorded");
        let DeliveryOutcome::Recorded(delivery_row) = recorded else {
            panic!("the delivery was taken for a repeat");
        };
        let job = JobId::from_uuid(self.ids.new_uuid());
        let correlation = CorrelationId::from_uuid(self.ids.new_uuid());
        let audit = |action: &str, decision: AuditDecision, subject: String, job: Option<JobId>| {
            NewAuditEvent {
                id: AuditEventId::from_uuid(self.ids.new_uuid()),
                actor: AuditActor::Anonymous(Slug::parse("webhook").expect("a slug")),
                action: AuditAction::new(action).expect("an action"),
                subject,
                decision,
                reason: "The loopback rig wrote the rows the API webhook handler writes."
                    .to_owned(),
                policy_hash: self.policy_hash.clone(),
                job,
                stage_run: None,
                correlation_id: if job.is_some() {
                    correlation
                } else {
                    CorrelationId::from_uuid(self.ids.new_uuid())
                },
            }
        };
        tx.record_audit(audit(
            "webhook_accepted_or_rejected.granted",
            AuditDecision::Allow,
            format!("delivery {delivery_id}"),
            None,
        ))
        .await
        .expect("audit");
        tx.insert_job(NewJob {
            id: job,
            correlation_id: correlation,
            repository: self.repository,
            requester,
            execution_mode: ExecutionMode::Test,
            autonomy_level: AutonomyLevel::L0,
            pipeline_scope: PipelineScope::new(SLICE_ONE_SCOPE.to_vec()).expect("a scope"),
            origin: Some(JobOrigin::Webhook(delivery_row)),
        })
        .await
        .expect("the job is inserted");
        tx.record_audit(audit(
            "job.received_from_webhook",
            AuditDecision::Record,
            format!("issue {REPO}#{number}"),
            Some(job),
        ))
        .await
        .expect("audit");
        tx.commit().await.expect("the transaction commits");
        job
    }

    // ---- looking at what the run left --------------------------------------------------------

    /// Rows of a query as JSON objects, read as the superuser.
    pub async fn rows(&self, query: &str) -> Vec<Value> {
        let sql = format!("SELECT coalesce(json_agg(t), '[]'::json) FROM ({query}) t");
        let text = self.deployment.db.text(&sql).await.expect("a result");
        serde_json::from_str::<Value>(&text)
            .expect("json")
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    pub async fn job_status(&self, job: JobId) -> String {
        self.deployment
            .db
            .text(&format!(
                "SELECT status FROM jobs WHERE id = '{}'",
                job.as_uuid()
            ))
            .await
            .unwrap_or_default()
    }

    /// The stage runs of the job, oldest first: kind, status, gate outcome, run number.
    pub async fn stage_runs(&self, job: JobId) -> Vec<Value> {
        self.rows(&format!(
            "SELECT stage_kind, status, gate_outcome, run_number FROM stage_runs \
             WHERE job_id = '{}' ORDER BY created_at, stage_kind",
            job.as_uuid()
        ))
        .await
    }

    pub async fn audit(&self, job: JobId) -> Vec<Value> {
        self.rows(&format!(
            "SELECT sequence, actor_type, actor_id, action, subject, decision, reason, correlation_id::text AS correlation_id \
             FROM audit_events WHERE job_id = '{}' ORDER BY sequence",
            job.as_uuid()
        ))
        .await
    }

    pub async fn outbox(&self, job: JobId) -> Vec<Value> {
        self.rows(&format!(
            "SELECT event_type, aggregate_type, transition_id, reason_code, payload, correlation_id::text AS correlation_id \
             FROM outbox WHERE job_id = '{}' ORDER BY seq",
            job.as_uuid()
        ))
        .await
    }

    pub async fn ledger(&self, job: JobId) -> Vec<Value> {
        self.rows(&format!(
            "SELECT sequence, recorded_component, recorded_fidelity, claim_kind, assurance_level, canonical_json \
             FROM ledger_entries WHERE job_id = '{}' ORDER BY sequence",
            job.as_uuid()
        ))
        .await
    }

    /// Polls `check` every 200 ms until it returns `Some`, the worker ends, or `seconds` pass.
    pub async fn wait_for<T>(
        &mut self,
        what: &str,
        seconds: u64,
        mut check: impl AsyncFnMut(&Lab) -> Option<T>,
    ) -> T {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            if let Some(found) = check(&*self).await {
                return found;
            }
            if let Some(status) = self.worker_ended() {
                let (_, stderr) = self.logs();
                panic!("the worker ended with {status} while waiting for {what}:\n{stderr}");
            }
            assert!(
                Instant::now() < deadline,
                "gave up waiting for {what}.\nstderr so far:\n{}",
                self.logs().1
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    /// Where a credential of this run was found, with no value: in the worker's output, any row the
    /// run left in the database, a stored artifact, or anything the fake GitHub received or that
    /// was posted on `issue`. The values searched for are every token the fake minted, the App's
    /// key, the provider key, the key that signs decisions and the database passwords. All were
    /// made when the test ran.
    pub async fn credential_leaks(&self, issue: u64) -> Vec<String> {
        let mut sweeper = Sweeper::new(&CanarySet::generate());
        for canary in self.fake.minted_secrets() {
            sweeper.add(&canary);
        }
        let body: String = self
            .credentials
            .app_key
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        sweeper.add(&Canary::custom("app-private-key-body", &body));
        sweeper.add(&Canary::custom(
            "provider-key",
            &self.credentials.provider_key,
        ));
        sweeper.add(&Canary::custom(
            "decision-signing-key",
            &self.credentials.decision_key,
        ));
        for file in ["tenant.url", "system.url"] {
            if let Some(password) = password_in(&self.deployment.dir.join(file)) {
                sweeper.add(&Canary::custom(
                    &format!("database-password-{file}"),
                    &password,
                ));
            }
        }

        let sinks = SinkCollector::new();
        let (stdout, stderr) = self.logs();
        sinks.record(SinkKind::Stdout, "worker", stdout);
        sinks.record(SinkKind::Stderr, "worker", &stderr);
        for line in stderr.lines() {
            sinks.record(SinkKind::LogLine, "worker", line);
        }
        // Every row of the tenant, and not only of the job.
        for (kind, table) in [
            (SinkKind::AuditRow, "audit_events"),
            (SinkKind::OutboxRow, "outbox"),
            (SinkKind::DatabaseDump, "ledger_entries"),
            (SinkKind::DatabaseDump, "jobs"),
            (SinkKind::DatabaseDump, "stage_runs"),
            (SinkKind::DatabaseDump, "attempts"),
            (SinkKind::DatabaseDump, "original_requests"),
            (SinkKind::DatabaseDump, "stage_run_artifacts"),
            (SinkKind::DatabaseDump, "webhook_deliveries"),
            (SinkKind::DatabaseDump, "principals"),
        ] {
            for row in self.rows(&format!("SELECT * FROM {table}")).await {
                sinks.record(kind, table, row.to_string());
            }
        }
        let mut files = Vec::new();
        read_files(&self.deployment.dir.join("artifacts"), &mut files);
        for (path, bytes) in &files {
            sinks.record(SinkKind::Artifact, &path.display().to_string(), bytes);
        }
        sinks.ingest_github(&self.fake);
        for comment in self.fake.comments(REPO, issue) {
            sinks.record(SinkKind::PullRequestText, "comment", comment);
        }
        let report = sinks.sweep(&sweeper);
        assert!(
            report.sinks_scanned > 20,
            "the sweep looked at {} sinks only",
            report.sinks_scanned
        );
        report.hits.iter().map(|hit| format!("{hit}")).collect()
    }

    /// How many entries the job's evidence ledger has, and the first thing wrong with its chain
    /// (or with its head, which the job row records apart from the entries), if anything is.
    pub async fn ledger_check(&self, job: JobId) -> (usize, Option<String>) {
        let logins = self.deployment.db.server.logins().await;
        let store = PgStore::connect(factory_composition::database::pools(
            small_pool(self.deployment.db.url(&logins.worker)),
            small_pool(self.deployment.db.url(&logins.engine)),
        ))
        .await
        .expect("a store");
        let mut tx = store
            .begin(TenantScope::new(self.tenant))
            .await
            .expect("a transaction");
        let entries = tx.read_ledger(job, 1, 10_000).await.expect("the ledger");
        let head = tx.ledger_head(job).await.expect("a head");
        let _ = tx.rollback().await;
        let problem = match head {
            None if entries.is_empty() => None,
            None => Some("the ledger has entries and the job has no head".to_owned()),
            Some(head) => factory_domain::ledger::verify_chain_against_head(&entries, &head)
                .err()
                .map(|error| error.to_string()),
        };
        (entries.len(), problem)
    }
}

fn read_files(dir: &Path, into: &mut Vec<(PathBuf, Vec<u8>)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            read_files(&path, into);
        } else if let Ok(bytes) = std::fs::read(&path) {
            into.push((path, bytes));
        }
    }
}

/// The password a connection string in a URL file holds.
fn password_in(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.split_whitespace()
        .find_map(|word| word.strip_prefix("password=").map(str::to_owned))
}
