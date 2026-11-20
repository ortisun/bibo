//! The world of the end-to-end tests, all offline: a migrated database on the test server of the
//! storage crate (`FACTORY_DB_ADMIN_URL`), the real read-only PostgreSQL MCP server over an
//! observer login, a VictoriaMetrics-like MCP server on loopback HTTP whose answer the test sets,
//! the real gateway, the testkit's in-memory triage issue writer behind a counter, a fake clock,
//! and a scripted agent runner in place of the sandbox.
#![allow(dead_code, clippy::disallowed_methods)]

#[path = "../../../../crates/storage/tests/support/server.rs"]
pub mod server;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use factory_composition::startup::load_policy;
use factory_contracts::agent_schema::AgentSchemaLoader;
use factory_contracts::registry::FileAgentRegistry;
use factory_domain::ids::TenantId;
use factory_domain::policy::paths::PathPolicy;
use factory_domain::policy::troubleshooting::TroubleshootingPolicy;
use factory_domain::redaction::Redactor;
use factory_domain::troubleshooting::issue::{SeenAgainComment, TriageIssue};
use factory_domain::troubleshooting::{FindingFingerprint, TroubleshootingRunId};
use factory_domain::values::{Sha256Digest, Slug};
use factory_domain::vocabulary::Fidelity;
use factory_mcp_gateway::{FactoryRedactor, Gateway, HttpUpstream, InProcessUpstream, UpstreamId};
use factory_mcp_postgres::{ConnectSettings, Inspector, Limits, Password, PostgresMcp};
use factory_ports::agent::{CostMicroUsd, Usage};
use factory_ports::githost::{GitHostError, IssueRef};
use factory_ports::paths::RepoRef;
use factory_ports::registry::{AgentRegistry, VersionReq};
use factory_ports::triage_issue::{OpenedIssue, RunScope, SeenAgainPost, TriageIssueWriter};
use factory_storage::pg::troubleshooting::{DayIncrement, TroubleshootingStore};
use factory_storage::pg::{DatabaseUrl, PoolSettings};
use factory_testkit::clock::{FakeClock, SequentialIdGenerator};
use factory_testkit::triage_issue::FakeTriageIssues;
use factory_troubleshooter::agent::{AgentJob, AgentResult, AgentRunner};
use factory_troubleshooter::probes::HealthCheck;
use factory_troubleshooter::troubleshooter::{Parts, PromptKit, Settings, Troubleshooter};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    JsonObject, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, RoleServer, ServerHandler};
use serde_json::{Value, json};

pub use server::TestDb;

/// The repository the testkit's issue writer accepts.
pub const ISSUE_REPOSITORY: &str = "example-org/fixture";

/// What one agent run costs in these tests: 0.10 dollars.
pub const RUN_COST: u64 = 100_000;

fn repository_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// ---------------------------------------------------------------------------------------------
// The VictoriaMetrics-like MCP server
// ---------------------------------------------------------------------------------------------

/// What the fake answers to `query`.
#[derive(Debug, Clone)]
pub enum VmAnswer {
    /// A vector with one sample of this value.
    Sample(String),
    /// A vector with no series.
    Empty,
    /// The tool fails.
    ToolError,
}

#[derive(Clone)]
struct FakeVm {
    answer: Arc<Mutex<VmAnswer>>,
}

fn schema() -> Arc<JsonObject> {
    Arc::new(
        serde_json::from_value(json!({
            "type": "object",
            "properties": {"query": {"type": "string"}},
        }))
        .expect("schema"),
    )
}

impl ServerHandler for FakeVm {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("fake-victoriametrics", "0.0.0"))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(ListToolsResult::with_all_items(vec![
            Tool::new("query", "Runs an instant PromQL query.", schema()),
            Tool::new("labels", "Lists label names.", schema()),
        ]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        if request.name != "query" {
            return Ok(CallToolResult::success(vec![ContentBlock::text("[]")]).into());
        }
        let answer = self.answer.lock().expect("answer").clone();
        let result = match answer {
            VmAnswer::Sample(value) => CallToolResult::success(vec![ContentBlock::text(
                json!({"status": "success", "data": {"resultType": "vector",
                    "result": [{"metric": {}, "value": [1_763_600_000, value]}]}})
                .to_string(),
            )]),
            VmAnswer::Empty => CallToolResult::success(vec![ContentBlock::text(
                json!({"status": "success", "data": {"resultType": "vector", "result": []}})
                    .to_string(),
            )]),
            VmAnswer::ToolError => {
                CallToolResult::error(vec![ContentBlock::text("bad_data: parse error")])
            }
        };
        Ok(result.into())
    }
}

/// The running fake.
pub struct VmServer {
    answer: Arc<Mutex<VmAnswer>>,
    task: tokio::task::JoinHandle<()>,
    pub url: String,
}

impl VmServer {
    pub fn set(&self, answer: VmAnswer) {
        *self.answer.lock().expect("answer") = answer;
    }

    /// Stops the server: every later call fails at the transport.
    pub fn stop(&self) {
        self.task.abort();
    }
}

impl Drop for VmServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_vm(answer: VmAnswer) -> VmServer {
    let answer = Arc::new(Mutex::new(answer));
    let handler = FakeVm {
        answer: Arc::clone(&answer),
    };
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let router = axum::Router::new().nest_service("/mcp", service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mcp", listener.local_addr().expect("addr"));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    VmServer { answer, task, url }
}

// ---------------------------------------------------------------------------------------------
// The scripted agent
// ---------------------------------------------------------------------------------------------

/// What the scripted agent returns on its next run.
#[derive(Debug, Clone)]
pub enum Script {
    /// These report bytes.
    Report(Vec<u8>),
    /// No output.
    Fails,
}

/// What a run of the scripted agent was asked.
#[derive(Debug, Clone)]
pub struct Asked {
    pub run: TroubleshootingRunId,
    pub tools: Vec<String>,
    pub ceiling: u64,
    pub data_names: Vec<String>,
}

/// An agent runner that returns queued scripts and records what it was asked.
#[derive(Default)]
pub struct ScriptedAgent {
    queue: Mutex<VecDeque<Script>>,
    asked: Mutex<Vec<Asked>>,
}

impl ScriptedAgent {
    pub fn queue(&self, script: Script) {
        self.queue.lock().expect("queue").push_back(script);
    }

    pub fn asked(&self) -> Vec<Asked> {
        self.asked.lock().expect("asked").clone()
    }
}

#[async_trait]
impl AgentRunner for ScriptedAgent {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn run(&self, job: AgentJob) -> AgentResult {
        self.asked.lock().expect("asked").push(Asked {
            run: job.run_id.clone(),
            tools: job.tools.iter().map(|t| t.as_str().to_owned()).collect(),
            ceiling: job.ceiling.0,
            data_names: job.prompt.data.iter().map(|d| d.source.clone()).collect(),
        });
        let script = self
            .queue
            .lock()
            .expect("queue")
            .pop_front()
            .unwrap_or(Script::Fails);
        let usage = Usage {
            cost: CostMicroUsd(RUN_COST),
            ..Usage::default()
        };
        match script {
            Script::Report(bytes) => AgentResult {
                output: Ok(bytes),
                usage,
            },
            Script::Fails => AgentResult {
                output: Err("the scripted agent produced no output".to_owned()),
                usage,
            },
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The issue writer, counted
// ---------------------------------------------------------------------------------------------

/// The testkit's in-memory writer, with every call counted.
#[derive(Default)]
pub struct CountingIssues {
    pub inner: FakeTriageIssues,
    pub opened: AtomicUsize,
    pub comments: AtomicUsize,
    pub calls: AtomicUsize,
    pub revoked: AtomicUsize,
}

impl CountingIssues {
    pub fn opened(&self) -> usize {
        self.opened.load(Ordering::SeqCst)
    }
    pub fn comments(&self) -> usize {
        self.comments.load(Ordering::SeqCst)
    }
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl TriageIssueWriter for CountingIssues {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn find_open_issue(
        &self,
        scope: &RunScope,
        fingerprint: &FindingFingerprint,
    ) -> Result<Option<IssueRef>, GitHostError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.find_open_issue(scope, fingerprint).await
    }

    async fn open_issue(
        &self,
        scope: &RunScope,
        issue: &TriageIssue,
    ) -> Result<OpenedIssue, GitHostError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let opened = self.inner.open_issue(scope, issue).await;
        if matches!(opened, Ok(OpenedIssue::Opened(_))) {
            self.opened.fetch_add(1, Ordering::SeqCst);
        }
        opened
    }

    async fn post_seen_again(
        &self,
        scope: &RunScope,
        issue: &IssueRef,
        comment: &SeenAgainComment,
    ) -> Result<SeenAgainPost, GitHostError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let posted = self.inner.post_seen_again(scope, issue, comment).await;
        if matches!(posted, Ok(SeenAgainPost::Posted(_))) {
            self.comments.fetch_add(1, Ordering::SeqCst);
        }
        posted
    }

    async fn revoke_run_tokens(&self, run: &TroubleshootingRunId) -> Result<(), GitHostError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.revoked.fetch_add(1, Ordering::SeqCst);
        self.inner.revoke_run_tokens(run).await
    }
}

// ---------------------------------------------------------------------------------------------
// The health check
// ---------------------------------------------------------------------------------------------

/// Every route answers 200.
pub struct HealthyApi;

#[async_trait]
impl HealthCheck for HealthyApi {
    async fn status(&self, _url: &str, _timeout: Duration) -> Option<u16> {
        Some(200)
    }
}

// ---------------------------------------------------------------------------------------------
// The policy, the reports
// ---------------------------------------------------------------------------------------------

/// A troubleshooting policy for the tests: two probes, the real schedule and caps.
pub fn policy() -> TroubleshootingPolicy {
    serde_json::from_value(json!({
        "schema_version": 1,
        "policy": {
            "id": "troubleshooting", "version": 1, "status": "designed",
            "default_action": "deny", "project_overrides": "tighten_only",
            "config_source": "protected_default_branch", "threats": ["T-03"]
        },
        "schedule": {
            "probe_period_s": 300, "sweep_period_s": 86400, "probe_cooldown_s": 21600,
            "max_concurrent_agent_runs": 1, "max_agent_runs_per_day": 8
        },
        "issues": {"max_new_per_day": 3, "max_comments_per_issue_per_day": 1,
                   "labels": ["troubleshooter", "troubleshooter: triage"]},
        "gateway": {"max_calls_per_run": 60, "max_calls_per_10s": 40,
                    "max_result_bytes": 65536, "call_deadline_s": 10, "run_wall_clock_s": 900},
        "upstreams": {
            "datadog": {"toolsets": ["core"], "omit_tools": ["create_datadog_notebook"]},
            "victoriametrics": {"disabled_tools": ["export"]}
        },
        "tools": [
            {"id": "mcp.victoriametrics.query", "gateway_name": "vm_query",
             "upstream": "victoriametrics", "upstream_tool": "query",
             "description": "Runs an instant PromQL query against the factory metrics."},
            {"id": "mcp.victoriametrics.labels", "gateway_name": "vm_labels",
             "upstream": "victoriametrics", "upstream_tool": "labels",
             "description": "Lists the label names of the factory metrics."},
            {"id": "mcp.datadog.search_monitors", "gateway_name": "datadog_search_monitors",
             "upstream": "datadog", "upstream_tool": "search_datadog_monitors",
             "description": "Lists Datadog monitors and their states."},
            {"id": "mcp.postgres.query", "gateway_name": "pg_query",
             "upstream": "postgres", "upstream_tool": "pg_query",
             "description": "Runs one read-only query against the factory database."},
            {"id": "mcp.postgres.factory_health", "gateway_name": "pg_factory_health",
             "upstream": "postgres", "upstream_tool": "pg_factory_health",
             "description": "Runs a fixed health check over the factory tables."}
        ],
        "probes": [
            {"id": "retries", "kind": "promql_threshold",
             "description": "Retries scheduled in the last hour.",
             "query": "sum(increase(factory_retries_total[1h]))",
             "comparator": "gt", "threshold": 10, "window_s": 3600, "severity": "medium",
             "checked_on": "unchecked"},
            {"id": "leases_past_expiry", "kind": "sql_check",
             "description": "Stage run leases still held after they expired.",
             "query": "leases_past_expiry", "comparator": "gt", "threshold": 0,
             "window_s": 300, "severity": "high", "checked_on": "unchecked"},
            {"id": "datadog_alerting", "kind": "datadog_monitors_alerting",
             "description": "Datadog monitors in Alert.",
             "query": "status:alert", "comparator": "gt", "threshold": 0,
             "window_s": 300, "severity": "high", "checked_on": "unchecked"}
        ]
    }))
    .expect("the test policy deserializes")
}

/// One finding of a report, citing `call_id` as a call of `tool`.
pub fn finding(probe_ids: &[&str], call_id: &str, tool: &str) -> Value {
    json!({
        "category": "retries",
        "severity": "medium",
        "component": "worker",
        "title": "Retries pile up after sandbox start failures",
        "probe_ids": probe_ids,
        "observations": [{
            "call_id": call_id,
            "tool": tool,
            "observed": "The retry counter rose by 12 in the last hour."
        }],
        "hypothesis": "The sandbox image fails its self-check, so attempts are retried.",
        "confidence": 0.6,
        "next_checks": ["Look at the failure classes of the attempts of the last hour."]
    })
}

/// The bytes of a `health-findings` v1 report.
pub fn report(status: &str, findings: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema_version": 1,
        "status": status,
        "summary": "The troubleshooter looked at the retries and the leases.",
        "findings": findings,
        "unavailable_sources": [],
        "ignored_instructions": []
    }))
    .expect("json")
}

// ---------------------------------------------------------------------------------------------
// The scene
// ---------------------------------------------------------------------------------------------

/// How a scene starts.
#[derive(Debug, Clone)]
pub struct SceneOptions {
    pub dry_run: bool,
    pub vm: VmAnswer,
    pub start: &'static str,
}

impl Default for SceneOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            vm: VmAnswer::Sample("12".to_owned()),
            start: "2026-11-20T00:00:00Z",
        }
    }
}

pub struct Scene {
    pub db: TestDb,
    pub tenant: TenantId,
    pub vm: VmServer,
    pub issues: Arc<CountingIssues>,
    pub agent: Arc<ScriptedAgent>,
    pub clock: Arc<FakeClock>,
    pub store: TroubleshootingStore,
    pub worker_url: DatabaseUrl,
    pub troubleshooter: Troubleshooter,
}

fn admin_host_port() -> (String, u16) {
    let url = std::env::var("FACTORY_DB_ADMIN_URL").unwrap_or_else(|_| {
        panic!(
            "BLOCKED: FACTORY_DB_ADMIN_URL is not set; these tests need a PostgreSQL superuser URL"
        )
    });
    let rest = url.split("://").nth(1).expect("a URL");
    let authority = rest.split('/').next().expect("an authority");
    let host_port = authority.rsplit('@').next().expect("a host");
    let (host, port) = host_port.rsplit_once(':').unwrap_or((host_port, "5432"));
    (host.to_owned(), port.parse().expect("a port"))
}

fn unique_word() -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    format!(
        "w{}x{}x{}",
        std::process::id(),
        nanos,
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

impl Scene {
    pub async fn new(options: SceneOptions) -> Self {
        let db = server::server().clone_database().await;
        let ids = factory_testkit::fixtures::Ids::new();
        let tenant = ids.tenant();
        db.run(&format!(
            "INSERT INTO tenants (id, slug, display_name) VALUES ('{tenant}', 'factory-{}', 'The factory')",
            &unique_word().to_ascii_lowercase()[..8]
        ))
        .await;

        // The observer login, with a password this test knows.
        let observer = db
            .server
            .create_login("observer", &["factory_observer"])
            .await;
        let password = format!("pw-{}", unique_word());
        db.run(&format!(
            "ALTER ROLE \"{}\" PASSWORD '{password}'",
            observer.name
        ))
        .await;
        let (host, port) = admin_host_port();
        let redactor = Redactor::builder().build().expect("a redactor");
        redactor
            .register("observer_password", &password)
            .expect("the password registers");
        let inspector = Arc::new(Inspector::new(
            ConnectSettings::new(host, port, observer.name.clone(), db.name.clone())
                .with_password(Password::new(password)),
            Limits::default(),
            Arc::new(redactor.clone()),
        ));
        inspector
            .check_login()
            .await
            .expect("the observer login is fit");

        let policy = policy();
        let vm = serve_vm(options.vm.clone()).await;
        let gateway = Gateway::builder(&policy, Arc::new(FactoryRedactor::new(redactor.clone())))
            .upstream(Arc::new(InProcessUpstream::new(
                UpstreamId::Postgres,
                PostgresMcp::new(inspector),
            )))
            .upstream(Arc::new(
                HttpUpstream::custom(
                    UpstreamId::Victoriametrics,
                    vm.url.parse().expect("url"),
                    HashMap::new(),
                    None,
                    Vec::new(),
                )
                .expect("the VictoriaMetrics client"),
            ))
            .build()
            .expect("the gateway builds");
        let report = gateway.connect().await;
        assert!(
            report.offered.iter().any(|t| t.gateway_name == "vm_query"),
            "{report:?}"
        );

        let logins = db.server.logins().await;
        let worker_url = db.url(&logins.worker);
        let mut settings = PoolSettings::new(worker_url.clone());
        settings.max_connections = 4;
        let store = TroubleshootingStore::connect(&settings, tenant)
            .await
            .expect("the store is ready");

        let root = repository_root();
        let loaded = load_policy(&root, &[]).expect("the repository policy loads");
        let registry = FileAgentRegistry::load(&root).expect("the agents load");
        let manifest = registry
            .manifest(
                &Slug::parse("troubleshooter").expect("slug"),
                &VersionReq::SameMajor(1),
            )
            .expect("the troubleshooter manifest");
        let prompt = registry.prompt(&manifest).expect("its prompt");
        let schemas = AgentSchemaLoader::new(&root)
            .load(&manifest)
            .expect("its schemas");

        let clock = Arc::new(FakeClock::starting_at(options.start));
        let issues = Arc::new(CountingIssues::default());
        let agent = Arc::new(ScriptedAgent::default());
        let troubleshooter = Troubleshooter::new(Parts {
            policy: Arc::new(policy),
            policy_hash: Sha256Digest::of(b"the test policy"),
            gateway,
            health: Arc::new(HealthyApi),
            store: store.clone(),
            issues: issues.clone(),
            agent: agent.clone(),
            clock: clock.clone(),
            ids: Arc::new(SequentialIdGenerator::new()),
            redactor: Arc::new(redactor),
            kit: PromptKit {
                manifest,
                prompt,
                paths: PathPolicy::from_policy(&loaded.security).expect("the path policy"),
                input_schema: schemas.inputs,
                output_schema: schemas.outputs,
            },
            settings: Settings {
                tenant,
                issue_repository: RepoRef::parse(ISSUE_REPOSITORY).expect("repo"),
                dry_run: options.dry_run,
                datadog: false,
                victoriametrics: true,
                api_base_url: "http://127.0.0.1:9".to_owned(),
                health_timeout: Duration::from_secs(1),
                per_run_micro_usd: 750_000,
                per_day_micro_usd: 3_000_000,
            },
        })
        .expect("the troubleshooter builds");
        Self {
            db,
            tenant,
            vm,
            issues,
            agent,
            clock,
            store,
            worker_url,
            troubleshooter,
        }
    }

    /// Moves the clock.
    pub fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    /// Adds to today's counters, as earlier runs of the day would have.
    pub async fn spend_the_day(&self, add: DayIncrement) {
        self.store
            .add_to_day(&factory_ports::clock::Clock::now(self.clock.as_ref()), add)
            .await
            .expect("counted");
    }
}
