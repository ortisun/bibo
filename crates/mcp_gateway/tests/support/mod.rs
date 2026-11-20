//! Fake upstream MCP servers built with rmcp, a policy fixture, and helpers. Everything is
//! offline: in-process pipes and loopback HTTP only.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use factory_domain::policy::troubleshooting::TroubleshootingPolicy;
use factory_domain::redaction::Redactor;
use factory_mcp_gateway::{
    FactoryRedactor, Gateway, GatewayServer, HttpUpstream, RunLimits, SecretValue, UpstreamId,
};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    JsonObject, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::{ErrorData, RoleServer, ServerHandler};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A value planted in upstream results that the test registers as a secret.
pub const PLANTED_SECRET: &str = "planted-gateway-test-value-0123456789";

/// The bearer token the fake VictoriaMetrics server expects. Obviously fake.
pub const FAKE_VM_TOKEN: &str = "fake-vm-mcp-token-for-offline-tests-only";

/// What a fake tool does when called.
#[derive(Debug, Clone)]
pub enum Behavior {
    /// Answers `<tool> answered <canonical arguments>`.
    Echo,
    /// Answers this text.
    Text(String),
    /// Answers this text as a tool error.
    ToolError(String),
    /// Sleeps, then answers `slept`.
    Sleep(Duration),
    /// Answers the `Authorization` header the server received.
    EchoAuthorization,
}

/// A fake MCP server whose tool list and behaviours a test can change while it runs.
#[derive(Clone, Default)]
pub struct FakeServer {
    tools: Arc<Mutex<Vec<String>>>,
    behaviors: Arc<Mutex<HashMap<String, Behavior>>>,
    calls: Arc<Mutex<Vec<String>>>,
    in_flight: Arc<AtomicUsize>,
    descriptions: Arc<Mutex<HashMap<String, String>>>,
    schema_padding: Arc<Mutex<HashMap<String, usize>>>,
    run_scopes: Arc<Mutex<Vec<Option<String>>>>,
}

impl FakeServer {
    pub fn with_tools(names: &[&str]) -> Self {
        let server = Self::default();
        for name in names {
            server.add_tool(name, Behavior::Echo);
        }
        server
    }

    pub fn add_tool(&self, name: &str, behavior: Behavior) {
        let mut tools = self.tools.lock().expect("tools");
        if !tools.iter().any(|t| t == name) {
            tools.push(name.to_owned());
        }
        self.behaviors
            .lock()
            .expect("behaviors")
            .insert(name.to_owned(), behavior);
    }

    /// Every tool name the server was asked to call, in order.
    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }

    /// Changes the description the server gives a tool.
    pub fn set_description(&self, name: &str, text: &str) {
        self.descriptions
            .lock()
            .expect("descriptions")
            .insert(name.to_owned(), text.to_owned());
    }

    /// Pads the input schema of a tool with a property description of this many bytes.
    pub fn pad_schema(&self, name: &str, bytes: usize) {
        self.schema_padding
            .lock()
            .expect("padding")
            .insert(name.to_owned(), bytes);
    }

    /// The run each call named in its `_meta`, in order.
    pub fn run_scopes(&self) -> Vec<Option<String>> {
        self.run_scopes.lock().expect("scopes").clone()
    }
}

fn schema() -> JsonObject {
    serde_json::from_value(serde_json::json!({
        "type": "object",
        "properties": {"query": {"type": "string", "description": "A query."}},
    }))
    .expect("schema")
}

impl ServerHandler for FakeServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("fake-upstream", "0.0.0"))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = self
            .tools
            .lock()
            .expect("tools")
            .iter()
            .map(|name| {
                let description = self
                    .descriptions
                    .lock()
                    .expect("descriptions")
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| format!("The upstream tool {name}."));
                let mut input = schema();
                if let Some(bytes) = self.schema_padding.lock().expect("padding").get(name) {
                    input.insert(
                        "description".to_owned(),
                        serde_json::Value::from("p".repeat(*bytes)),
                    );
                }
                let mut tool = Tool::new(name.clone(), description, Arc::new(input));
                tool.output_schema = Some(Arc::new(schema()));
                tool
            })
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let name = request.name.to_string();
        self.calls.lock().expect("calls").push(name.clone());
        self.run_scopes.lock().expect("scopes").push(
            context
                .meta
                .get(factory_domain::troubleshooting::BUDGET_SCOPE_META_KEY)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        );
        let behavior = self
            .behaviors
            .lock()
            .expect("behaviors")
            .get(&name)
            .cloned();
        let result = match behavior {
            None => return Err(ErrorData::invalid_params("no such tool", None)),
            Some(Behavior::Echo) => {
                let arguments = serde_json::Value::Object(request.arguments.unwrap_or_default());
                CallToolResult::success(vec![ContentBlock::text(format!(
                    "{name} answered {arguments}"
                ))])
            }
            Some(Behavior::Text(text)) => CallToolResult::success(vec![ContentBlock::text(text)]),
            Some(Behavior::ToolError(text)) => {
                CallToolResult::error(vec![ContentBlock::text(text)])
            }
            Some(Behavior::Sleep(duration)) => {
                self.in_flight.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(duration).await;
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                CallToolResult::success(vec![ContentBlock::text("slept")])
            }
            Some(Behavior::EchoAuthorization) => {
                let seen = context
                    .extensions
                    .get::<Parts>()
                    .and_then(|parts| parts.headers.get(header::AUTHORIZATION))
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("none")
                    .to_owned();
                CallToolResult::success(vec![ContentBlock::text(format!("I was sent {seen}"))])
            }
        };
        Ok(result.into())
    }
}

/// A running fake upstream over loopback HTTP, behind its own bearer check.
pub struct FakeHttpServer {
    pub addr: SocketAddr,
    pub server: FakeServer,
    task: tokio::task::JoinHandle<()>,
}

impl FakeHttpServer {
    pub fn url(&self) -> String {
        format!("http://{}/mcp", self.addr)
    }
}

impl Drop for FakeHttpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn require_fake_token(
    State(expected): State<Arc<String>>,
    request: Request,
    next: Next,
) -> Response {
    let ok = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        == Some(&format!("Bearer {expected}"));
    if ok {
        next.run(request).await
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

/// Serves `server` at `http://127.0.0.1:<port>/mcp`, requiring `Bearer <token>`.
pub async fn serve_fake_http(server: FakeServer, token: &str) -> FakeHttpServer {
    let handler = server.clone();
    let service = StreamableHttpService::new(
        move || Ok(handler.clone()),
        Arc::new(LocalSessionManager::default()),
        StreamableHttpServerConfig::default(),
    );
    let router =
        axum::Router::new()
            .nest_service("/mcp", service)
            .layer(middleware::from_fn_with_state(
                Arc::new(token.to_owned()),
                require_fake_token,
            ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    FakeHttpServer { addr, server, task }
}

/// The troubleshooting policy as JSON, with a small allowlist over the three upstreams.
pub fn policy() -> TroubleshootingPolicy {
    serde_json::from_value(serde_json::json!({
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
                   "labels": ["troubleshooter"]},
        "gateway": {"max_calls_per_run": 60, "max_calls_per_10s": 40,
                    "max_result_bytes": 65536, "call_deadline_s": 20, "run_wall_clock_s": 900},
        "upstreams": {
            "datadog": {"toolsets": ["core"], "omit_tools": ["create_datadog_notebook"]},
            "victoriametrics": {"disabled_tools": ["export"]}
        },
        "tools": [
            {"id": "mcp.datadog.search_logs", "gateway_name": "datadog_search_logs",
             "upstream": "datadog", "upstream_tool": "search_datadog_logs", "description": "The factory's description of search_datadog_logs."},
            {"id": "mcp.victoriametrics.query", "gateway_name": "vm_query",
             "upstream": "victoriametrics", "upstream_tool": "query", "description": "The factory's description of query."},
            {"id": "mcp.victoriametrics.labels", "gateway_name": "vm_labels",
             "upstream": "victoriametrics", "upstream_tool": "labels", "description": "The factory's description of labels."},
            {"id": "mcp.victoriametrics.alerts", "gateway_name": "vm_alerts",
             "upstream": "victoriametrics", "upstream_tool": "alerts", "description": "The factory's description of alerts."},
            {"id": "mcp.postgres.query", "gateway_name": "pg_query",
             "upstream": "postgres", "upstream_tool": "pg_query", "description": "The factory's description of pg_query."},
            {"id": "mcp.postgres.factory_health", "gateway_name": "pg_factory_health",
             "upstream": "postgres", "upstream_tool": "pg_factory_health", "description": "The factory's description of pg_factory_health."}
        ],
        "probes": []
    }))
    .expect("the policy fixture deserializes")
}

/// The factory's redactor with no patterns, plus the planted secret.
pub fn redactor() -> Arc<FactoryRedactor> {
    let redactor = FactoryRedactor::new(Redactor::builder().build().expect("a redactor"));
    factory_mcp_gateway::Redact::register_secret(&redactor, "planted", PLANTED_SECRET)
        .expect("register the planted value");
    Arc::new(redactor)
}

/// A file with this content and mode in a fresh scratch directory.
pub fn secret_file(name: &str, mode: u32, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "factory-mcp-gateway-tests-{}-{name}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join(name);
    std::fs::write(&path, content).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    path
}

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Small limits for tests.
pub fn limits(calls: u32, per_10s: u32, bytes: u64, deadline_ms: u64) -> RunLimits {
    RunLimits {
        max_calls_per_run: calls,
        max_calls_per_10s: per_10s,
        max_result_bytes: bytes,
        call_deadline: Duration::from_millis(deadline_ms),
        run_wall_clock: Duration::from_secs(60),
    }
}

/// The agent: an MCP client over the gateway's Streamable HTTP with a bearer token.
pub async fn agent(server: &GatewayServer, token: &str) -> HttpUpstream {
    let agent = HttpUpstream::custom(
        UpstreamId::Postgres,
        server.url().parse().expect("url"),
        HashMap::new(),
        Some(SecretValue::new(token.to_owned())),
        Vec::new(),
    )
    .expect("an agent client");
    factory_mcp_gateway::Upstream::connect(&agent)
        .await
        .expect("the agent connects with a valid token");
    agent
}

/// Sends one raw HTTP POST to the gateway (an MCP initialize) and returns the status code.
pub async fn raw_status(addr: SocketAddr, authorization: Option<&str>) -> u16 {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"0"}}}"#;
    let auth = authorization
        .map(|value| format!("Authorization: {value}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut head = vec![0_u8; 12];
    stream.read_exact(&mut head).await.expect("read status");
    let text = String::from_utf8_lossy(&head).to_string();
    text[9..12].parse().expect("a status code")
}

/// A gateway over an in-process "postgres" fake and a loopback-HTTP "victoriametrics" fake,
/// connected and serving on 127.0.0.1:0.
pub struct Fixture {
    pub gateway: Gateway,
    pub server: GatewayServer,
    pub postgres: FakeServer,
    pub vm: FakeHttpServer,
    pub redactor: Arc<FactoryRedactor>,
}

pub async fn fixture() -> Fixture {
    let postgres = FakeServer::with_tools(&["pg_query", "pg_factory_health"]);
    let vm = serve_fake_http(
        FakeServer::with_tools(&["query", "labels", "export"]),
        FAKE_VM_TOKEN,
    )
    .await;
    let token_file = secret_file("vm-token", 0o600, &format!("{FAKE_VM_TOKEN}\n"));
    let vm_upstream = HttpUpstream::victoriametrics(&factory_mcp_gateway::VictoriaMetricsConfig {
        url: vm.url(),
        token_file,
    })
    .expect("the VictoriaMetrics upstream");
    let redactor = redactor();
    let gateway = Gateway::builder(&policy(), redactor.clone())
        .upstream(Arc::new(factory_mcp_gateway::InProcessUpstream::new(
            UpstreamId::Postgres,
            postgres.clone(),
        )))
        .upstream(Arc::new(vm_upstream))
        .build()
        .expect("the gateway builds");
    gateway.connect().await;
    let server = gateway
        .serve("127.0.0.1:0".parse().expect("addr"), &[])
        .await
        .expect("the gateway serves");
    Fixture {
        gateway,
        server,
        postgres,
        vm,
        redactor,
    }
}

/// The text blocks of a result.
pub fn texts(result: &CallToolResult) -> Vec<String> {
    result
        .content
        .iter()
        .filter_map(|block| block.as_text().map(|text| text.text.clone()))
        .collect()
}

/// Arguments from JSON.
pub fn args(value: serde_json::Value) -> Option<JsonObject> {
    match value {
        serde_json::Value::Object(map) => Some(map),
        _ => None,
    }
}
