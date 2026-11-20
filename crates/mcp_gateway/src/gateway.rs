//! The gateway: the catalog of tools, the runs and their limits, and the call path shared by the
//! agent and the control plane.

use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use factory_domain::policy::troubleshooting::{GatewayTool, TroubleshootingPolicy};
use factory_domain::values::Sha256Digest;
use rmcp::model::{CallToolResult, ContentBlock, JsonObject, Tool};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::record::{
    CallId, CallOrigin, CallRecord, Outcome, RefusalReason, RefusalRecord, RunLimits, RunRecord,
};
use crate::redact::{Redact, SecretKey, redact_json};
use crate::secret::RunToken;
use crate::upstream::{Upstream, UpstreamId};

/// The most calls one run record holds. Past it, calls are refused without a record and counted
/// in [`RunRecord::unrecorded_calls`]. The health-findings schema cites at most `call-9999`.
/// [`MAX_CONTROL_PLANE_CALLS`] of it are the control plane's, the rest the agent's, so neither
/// can fill the other's share (TR-5).
pub const MAX_RECORDED_CALLS: usize = 1000;

/// The share of [`MAX_RECORDED_CALLS`] kept for the control plane's calls (the probes).
pub const MAX_CONTROL_PLANE_CALLS: usize = 500;

/// The most agent refusals one run record lists ([`RunRecord::refusals`]); past it they are
/// counted only.
pub const MAX_RECORDED_REFUSALS: usize = 200;

/// The largest upstream input schema the gateway passes to the model, as JSON. A tool whose schema
/// is larger is not offered ([`MissingReason::SchemaTooLarge`], TR-7).
pub const MAX_INPUT_SCHEMA_BYTES: usize = 16 * 1024;

/// The longest tool name kept in a record.
const MAX_RECORDED_NAME_BYTES: usize = 128;

/// The window of [`RunLimits::max_calls_per_10s`].
const RATE_WINDOW: Duration = Duration::from_secs(10);

/// How long connecting to and listing one upstream may take at start or refresh.
const CATALOG_TIMEOUT: Duration = Duration::from_secs(30);

/// The reason a finding names for an upstream tool that is not on the allowlist (threat T-51).
pub const UPSTREAM_TOOL_NOT_ALLOWED: &str = "upstream_tool_not_allowed";

/// Something the gateway refused to do. The message never holds a token or a credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GatewayError {
    /// Two upstreams with the same id were given.
    #[error("the upstream {} was given twice", .0.as_str())]
    DuplicateUpstream(UpstreamId),
    /// A credential of an upstream could not be registered for redaction.
    #[error(
        "the credential {0} could not be registered for redaction; the gateway will not use it"
    )]
    CredentialNotRedactable(&'static str),
    /// The run id is empty, too long, or has characters other than letters, digits, `.`, `_`,
    /// `:` and `-`.
    #[error("the run id is not valid")]
    BadRunId,
    /// A run with this id is already open.
    #[error("the run {0} is already open")]
    RunExists(String),
    /// No open run has this id.
    #[error("no open run has the id {0}")]
    UnknownRun(String),
    /// The limits asked for a run are looser than the policy's, or zero.
    #[error("the run limits {0:?} are looser than the policy or zero")]
    LooserLimits(Vec<&'static str>),
    /// The operating system's random source failed.
    #[error("no run token could be made")]
    TokenUnavailable,
    /// The run token could not be registered for redaction.
    #[error("the run token could not be registered for redaction")]
    TokenNotRedactable,
    /// The run's record is full; the call was refused without a record.
    #[error("the record of the run is full; the call was refused")]
    RecordFull,
    /// The listen address is not loopback.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// The listener could not be opened.
    #[error("the gateway cannot listen on {0}")]
    Listen(std::net::SocketAddr),
}

/// The result of one call of the control plane through the gateway ([`Gateway::call_for_run`]).
/// Every such call is recorded under an id, refused or not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallResult {
    /// The id the call was recorded under, to cite.
    pub call_id: CallId,
    /// How the call ended.
    pub outcome: Outcome,
    /// The redacted and capped result text, or a short reason when the call did not succeed.
    pub text: String,
}

impl CallResult {
    /// The MCP result the agent receives: a first text block naming the call id, then the
    /// result or the reason. `is_error` unless the outcome is `ok`.
    #[must_use]
    pub fn to_mcp(&self) -> CallToolResult {
        let content = vec![
            ContentBlock::text(format!("call_id: {}", self.call_id)),
            ContentBlock::text(self.text.clone()),
        ];
        if self.outcome == Outcome::Ok {
            CallToolResult::success(content)
        } else {
            CallToolResult::error(content)
        }
    }
}

/// The result of one agent call. A call refused before it reached an upstream has no id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentResult {
    pub(crate) call_id: Option<CallId>,
    pub(crate) outcome: Outcome,
    pub(crate) text: String,
}

impl AgentResult {
    /// The MCP result the agent receives: a first text block naming the call id (or saying that a
    /// refused call has none to cite), then the result or the reason.
    pub(crate) fn to_mcp(&self) -> CallToolResult {
        let first = match self.call_id {
            Some(id) => format!("call_id: {id}"),
            None => "call_id: none (a refused call is not recorded and cannot be cited)".to_owned(),
        };
        let content = vec![
            ContentBlock::text(first),
            ContentBlock::text(self.text.clone()),
        ];
        if self.outcome == Outcome::Ok {
            CallToolResult::success(content)
        } else {
            CallToolResult::error(content)
        }
    }
}

/// Which tools the gateway offers and why others are not offered.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CatalogReport {
    /// Tools listed to the agent.
    pub offered: Vec<ToolMapping>,
    /// Tools on the allowlist that are not listed.
    pub missing: Vec<MissingTool>,
    /// Tools an upstream offers that are not on the allowlist. Never listed or callable; each is
    /// a finding with the reason [`UPSTREAM_TOOL_NOT_ALLOWED`] (threat T-51).
    pub not_allowed: Vec<UpstreamTool>,
    /// Allowlisted tools whose upstream description or input schema changed since the gateway
    /// first listed them (TR-7). Each is withheld until the gateway is built again, and is in
    /// `missing` with [`MissingReason::ChangedSinceConnect`]; the troubleshooter flags it.
    pub changed: Vec<ChangedTool>,
}

/// An allowlisted tool whose upstream definition changed after the gateway pinned it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangedTool {
    /// The tool.
    #[serde(flatten)]
    pub tool: ToolMapping,
    /// SHA-256 of the definition the gateway pinned when it first listed the tool.
    pub pinned_sha256: Sha256Digest,
    /// SHA-256 of the definition the upstream offers now.
    pub current_sha256: Sha256Digest,
}

/// A gateway tool and the upstream tool it calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolMapping {
    /// The name the agent sees.
    pub gateway_name: String,
    /// The upstream.
    pub upstream: UpstreamId,
    /// The upstream tool.
    pub upstream_tool: String,
}

/// Why an allowlisted tool is not listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingReason {
    /// The upstream answered but does not offer the tool.
    NotOfferedByUpstream,
    /// The upstream could not be reached or listed.
    UpstreamUnavailable,
    /// No upstream with this id was given to the gateway (not configured).
    UpstreamNotConfigured,
    /// The upstream's input schema for the tool is larger than [`MAX_INPUT_SCHEMA_BYTES`].
    SchemaTooLarge,
    /// The upstream's description or input schema changed since the gateway first listed the
    /// tool ([`CatalogReport::changed`]).
    ChangedSinceConnect,
}

/// An allowlisted tool that is not listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MissingTool {
    /// The tool.
    #[serde(flatten)]
    pub tool: ToolMapping,
    /// Why.
    pub reason: MissingReason,
}

/// A tool an upstream offers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamTool {
    /// The upstream.
    pub upstream: UpstreamId,
    /// The tool's name there.
    pub upstream_tool: String,
}

struct ExposedTool {
    mapping: ToolMapping,
    tool: Tool,
}

#[derive(Default)]
struct Catalog {
    exposed: Vec<ExposedTool>,
    report: CatalogReport,
}

struct RunState {
    token: RunToken,
    token_key: SecretKey,
    limits: RunLimits,
    deadline: Instant,
    opened_at_unix_ms: u64,
    closing: bool,
    next_call: u64,
    agent_calls: u32,
    window: VecDeque<Instant>,
    calls: Vec<CallRecord>,
    unrecorded_calls: u64,
    agent_recorded: usize,
    control_recorded: usize,
    refusals: Vec<RefusalRecord>,
    unrecorded_refusals: u64,
    in_flight: u32,
}

impl RunState {
    fn record(&self, run_id: &str) -> RunRecord {
        RunRecord {
            run_id: run_id.to_owned(),
            opened_at_unix_ms: self.opened_at_unix_ms,
            closed: self.closing,
            limits: self.limits,
            calls: self.calls.clone(),
            unrecorded_calls: self.unrecorded_calls,
            refusals: self.refusals.clone(),
            unrecorded_refusals: self.unrecorded_refusals,
        }
    }
}

struct Inner {
    ceiling: RunLimits,
    allowlist: Vec<GatewayTool>,
    upstreams: Vec<Arc<dyn Upstream>>,
    redactor: Arc<dyn Redact>,
    catalog: RwLock<Catalog>,
    /// The digest of each allowlisted upstream tool's definition when the gateway first listed it.
    pinned: Mutex<HashMap<(UpstreamId, String), Sha256Digest>>,
    runs: Mutex<HashMap<String, RunState>>,
    idle: Notify,
}

/// The MCP gateway. Cheap to clone; clones share everything.
#[derive(Clone)]
pub struct Gateway {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let runs = self
            .inner
            .runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len();
        f.debug_struct("Gateway")
            .field("limits", &self.inner.ceiling)
            .field("allowlist", &self.inner.allowlist.len())
            .field(
                "upstreams",
                &self
                    .inner
                    .upstreams
                    .iter()
                    .map(|u| u.id())
                    .collect::<Vec<_>>(),
            )
            .field("open_runs", &runs)
            .finish_non_exhaustive()
    }
}

/// Builds a [`Gateway`].
pub struct GatewayBuilder {
    ceiling: RunLimits,
    allowlist: Vec<GatewayTool>,
    redactor: Arc<dyn Redact>,
    upstreams: Vec<Arc<dyn Upstream>>,
}

impl GatewayBuilder {
    /// Adds an upstream. Its credentials are registered with the redactor in
    /// [`GatewayBuilder::build`].
    #[must_use]
    pub fn upstream(mut self, upstream: Arc<dyn Upstream>) -> Self {
        self.upstreams.push(upstream);
        self
    }

    /// The gateway, with every upstream credential registered for exact-value redaction. Nothing
    /// is connected yet: call [`Gateway::connect`].
    ///
    /// # Errors
    /// [`GatewayError::DuplicateUpstream`] or [`GatewayError::CredentialNotRedactable`].
    pub fn build(self) -> Result<Gateway, GatewayError> {
        let mut seen = Vec::new();
        for upstream in &self.upstreams {
            let id = upstream.id();
            if seen.contains(&id) {
                return Err(GatewayError::DuplicateUpstream(id));
            }
            seen.push(id);
            for (label, value) in upstream.credentials() {
                self.redactor
                    .register_secret(label, value.expose())
                    .map_err(|_| GatewayError::CredentialNotRedactable(label))?;
            }
        }
        Ok(Gateway {
            inner: Arc::new(Inner {
                ceiling: self.ceiling,
                allowlist: self.allowlist,
                upstreams: self.upstreams,
                redactor: self.redactor,
                catalog: RwLock::new(Catalog::default()),
                pinned: Mutex::new(HashMap::new()),
                runs: Mutex::new(HashMap::new()),
                idle: Notify::new(),
            }),
        })
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// The longest prefix of `text` of at most `max` bytes that ends on a character boundary.
fn prefix(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// The marker that replaces the cut part of a result.
fn truncation_marker(cut: usize) -> String {
    format!("\n[truncated by the gateway: {cut} bytes cut]")
}

/// Cuts `text` to at most `max` bytes, the marker included, on a character boundary. `max` is at
/// least [`crate::record::MIN_RESULT_BYTES`], so the marker always fits.
pub(crate) fn truncate(text: String, max: usize) -> String {
    if text.len() <= max {
        return text;
    }
    let room = max.saturating_sub(truncation_marker(text.len()).len());
    let kept = prefix(&text, room).len();
    let mut out = String::with_capacity(max);
    out.push_str(&text[..kept]);
    out.push_str(&truncation_marker(text.len() - kept));
    out
}

/// SHA-256 of the RFC 8785 canonical JSON of the arguments, `{}` when there are none.
pub(crate) fn arguments_digest(arguments: Option<&JsonObject>) -> Sha256Digest {
    let value = Value::Object(arguments.cloned().unwrap_or_default());
    let bytes = serde_jcs::to_vec(&value)
        .or_else(|_| serde_json::to_vec(&value))
        .unwrap_or_default();
    Sha256Digest::of(&bytes)
}

/// SHA-256 of the RFC 8785 canonical JSON of an upstream tool's name, description and input
/// schema: what the gateway pins when it first lists the tool (TR-7).
pub(crate) fn definition_digest(tool: &Tool) -> Sha256Digest {
    let value = serde_json::json!({
        "name": tool.name,
        "description": tool.description,
        "input_schema": tool.input_schema.as_ref(),
    });
    let bytes = serde_jcs::to_vec(&value)
        .or_else(|_| serde_json::to_vec(&value))
        .unwrap_or_default();
    Sha256Digest::of(&bytes)
}

/// The text of an upstream result: its text blocks joined by newlines, a note for each block of
/// another kind, and the structured content when there is no block at all.
fn result_text(result: &CallToolResult) -> String {
    let mut parts: Vec<Cow<'_, str>> = Vec::with_capacity(result.content.len());
    for block in &result.content {
        match block.as_text() {
            Some(text) => parts.push(Cow::Borrowed(&text.text)),
            None => parts.push(Cow::Borrowed("[non-text content omitted by the gateway]")),
        }
    }
    if parts.is_empty()
        && let Some(structured) = &result.structured_content
    {
        parts.push(Cow::Owned(structured.to_string()));
    }
    parts.join("\n")
}

fn valid_run_id(run_id: &str) -> bool {
    (1..=128).contains(&run_id.len())
        && run_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

enum Admission {
    Refused(RefusalReason),
    Admitted {
        upstream: Arc<dyn Upstream>,
        upstream_tool: String,
        deadline: Duration,
        max_bytes: usize,
    },
}

impl Gateway {
    /// Starts a gateway for the policy's allowlist and limits. The redactor is the factory's
    /// (`FactoryRedactor`), shared with every other sink.
    #[must_use]
    pub fn builder(policy: &TroubleshootingPolicy, redactor: Arc<dyn Redact>) -> GatewayBuilder {
        GatewayBuilder {
            ceiling: RunLimits::from_policy(&policy.gateway),
            allowlist: policy.tools.clone(),
            redactor,
            upstreams: Vec::new(),
        }
    }

    /// The policy's limits, the loosest a run may have.
    #[must_use]
    pub fn policy_limits(&self) -> RunLimits {
        self.inner.ceiling
    }

    /// Connects every upstream, reads its tools and builds the catalog: the allowlisted tools
    /// the upstreams offer, with the upstream's description and input schema under the gateway
    /// name. An upstream that cannot be reached is not an error here: its tools are reported
    /// missing (`upstream_unavailable`), and the troubleshooter raises `source_unavailable`.
    pub async fn connect(&self) -> CatalogReport {
        let mut listings: HashMap<UpstreamId, Option<Vec<Tool>>> = HashMap::new();
        for upstream in &self.inner.upstreams {
            let listed = tokio::time::timeout(CATALOG_TIMEOUT, async {
                upstream.connect().await?;
                upstream.list_tools().await
            })
            .await
            .ok()
            .and_then(Result::ok);
            listings.insert(upstream.id(), listed);
        }
        let catalog = self.build_catalog(&listings);
        let report = catalog.report.clone();
        *self
            .inner
            .catalog
            .write()
            .unwrap_or_else(PoisonError::into_inner) = catalog;
        report
    }

    /// Reads every upstream's tools again (Datadog says its tools change) and rebuilds the
    /// catalog. The same as [`Gateway::connect`].
    pub async fn refresh(&self) -> CatalogReport {
        self.connect().await
    }

    fn build_catalog(&self, listings: &HashMap<UpstreamId, Option<Vec<Tool>>>) -> Catalog {
        let mut catalog = Catalog::default();
        let mut pinned = self
            .inner
            .pinned
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for entry in &self.inner.allowlist {
            let mapping = ToolMapping {
                gateway_name: entry.gateway_name.clone(),
                upstream: entry.upstream,
                upstream_tool: entry.upstream_tool.clone(),
            };
            let found = match listings.get(&entry.upstream) {
                None => Err(MissingReason::UpstreamNotConfigured),
                Some(None) => Err(MissingReason::UpstreamUnavailable),
                Some(Some(tools)) => tools
                    .iter()
                    .find(|tool| tool.name == entry.upstream_tool)
                    .ok_or(MissingReason::NotOfferedByUpstream),
            };
            let exposed = found.and_then(|upstream_tool| {
                // The definition is pinned the first time the gateway lists it; a later change is
                // withheld until the gateway is built again (TR-7).
                let current = definition_digest(upstream_tool);
                let key = (entry.upstream, entry.upstream_tool.clone());
                match pinned.get(&key) {
                    Some(first) if *first != current => {
                        catalog.report.changed.push(ChangedTool {
                            tool: mapping.clone(),
                            pinned_sha256: first.clone(),
                            current_sha256: current,
                        });
                        return Err(MissingReason::ChangedSinceConnect);
                    }
                    Some(_) => {}
                    None => {
                        pinned.insert(key, current);
                    }
                }
                self.exposed_tool(entry, upstream_tool)
            });
            match exposed {
                Ok(tool) => {
                    catalog.report.offered.push(mapping.clone());
                    catalog.exposed.push(ExposedTool { mapping, tool });
                }
                Err(reason) => catalog.report.missing.push(MissingTool {
                    tool: mapping,
                    reason,
                }),
            }
        }
        drop(pinned);
        for (upstream, listed) in listings {
            for tool in listed.iter().flatten() {
                let allowed =
                    self.inner.allowlist.iter().any(|entry| {
                        entry.upstream == *upstream && entry.upstream_tool == tool.name
                    });
                if !allowed {
                    catalog.report.not_allowed.push(UpstreamTool {
                        upstream: *upstream,
                        upstream_tool: prefix(&tool.name, MAX_RECORDED_NAME_BYTES).to_owned(),
                    });
                }
            }
        }
        catalog.report.not_allowed.sort_by(|a, b| {
            (a.upstream.as_str(), &a.upstream_tool).cmp(&(b.upstream.as_str(), &b.upstream_tool))
        });
        catalog
    }

    /// The upstream tool under its gateway name, with the policy's description and the
    /// upstream's input schema, redacted and at most [`MAX_INPUT_SCHEMA_BYTES`]. The upstream's own
    /// description, and anything else of its definition (output schema, annotations, icons,
    /// metadata), is not passed on: it would reach the model as part of its tool set, outside the
    /// prompt's data delimiters (TR-7).
    fn exposed_tool(&self, entry: &GatewayTool, upstream: &Tool) -> Result<Tool, MissingReason> {
        let schema_bytes = serde_json::to_vec(upstream.input_schema.as_ref())
            .map_or(usize::MAX, |bytes| bytes.len());
        if schema_bytes > MAX_INPUT_SCHEMA_BYTES {
            return Err(MissingReason::SchemaTooLarge);
        }
        let redactor = self.inner.redactor.as_ref();
        let mut schema = Value::Object((*upstream.input_schema).clone());
        redact_json(&mut schema, redactor).map_err(|_| MissingReason::UpstreamUnavailable)?;
        let Value::Object(schema) = schema else {
            return Err(MissingReason::UpstreamUnavailable);
        };
        Ok(Tool::new_with_raw(
            entry.gateway_name.clone(),
            Some(Cow::Owned(entry.description.clone())),
            Arc::new(schema),
        ))
    }

    /// Which tools are offered and which are not, as of the last [`Gateway::connect`].
    #[must_use]
    pub fn catalog_report(&self) -> CatalogReport {
        self.inner
            .catalog
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .report
            .clone()
    }

    /// The tools listed to the agent.
    #[must_use]
    pub fn listed_tools(&self) -> Vec<Tool> {
        self.inner
            .catalog
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .exposed
            .iter()
            .map(|exposed| exposed.tool.clone())
            .collect()
    }

    /// Opens a run and returns its bearer token: 256 random bits, valid until
    /// [`Gateway::close_run`] or until `limits.run_wall_clock` passed, whichever comes first.
    /// The token is registered with the redactor, so a result that echoes it is redacted.
    ///
    /// # Errors
    /// [`GatewayError::BadRunId`], [`GatewayError::RunExists`], [`GatewayError::LooserLimits`],
    /// [`GatewayError::TokenUnavailable`] or [`GatewayError::TokenNotRedactable`].
    pub fn open_run(&self, run_id: &str, limits: RunLimits) -> Result<RunToken, GatewayError> {
        if !valid_run_id(run_id) {
            return Err(GatewayError::BadRunId);
        }
        let problems = limits.problems_against(&self.inner.ceiling);
        if !problems.is_empty() {
            return Err(GatewayError::LooserLimits(problems));
        }
        let mut runs = self
            .inner
            .runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if runs.contains_key(run_id) {
            return Err(GatewayError::RunExists(run_id.to_owned()));
        }
        let token = RunToken::generate().map_err(|_| GatewayError::TokenUnavailable)?;
        let token_key = self
            .inner
            .redactor
            .register_secret("gateway_run_token", token.expose())
            .map_err(|_| GatewayError::TokenNotRedactable)?;
        runs.insert(
            run_id.to_owned(),
            RunState {
                token: token.clone(),
                token_key,
                limits,
                deadline: Instant::now() + limits.run_wall_clock,
                opened_at_unix_ms: unix_ms(),
                closing: false,
                next_call: 1,
                agent_calls: 0,
                window: VecDeque::new(),
                calls: Vec::new(),
                unrecorded_calls: 0,
                agent_recorded: 0,
                control_recorded: 0,
                refusals: Vec::new(),
                unrecorded_refusals: 0,
                in_flight: 0,
            },
        );
        Ok(token)
    }

    /// Closes a run: its token stops working at once, calls in flight finish (each within its
    /// deadline), and the final record is returned. The run is then forgotten, its token too.
    ///
    /// # Errors
    /// [`GatewayError::UnknownRun`].
    pub async fn close_run(&self, run_id: &str) -> Result<RunRecord, GatewayError> {
        {
            let mut runs = self
                .inner
                .runs
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let run = runs
                .get_mut(run_id)
                .filter(|run| !run.closing)
                .ok_or_else(|| GatewayError::UnknownRun(run_id.to_owned()))?;
            run.closing = true;
        }
        loop {
            let notified = self.inner.idle.notified();
            let mut notified = std::pin::pin!(notified);
            notified.as_mut().enable();
            {
                let mut runs = self
                    .inner
                    .runs
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if runs.get(run_id).is_none_or(|run| run.in_flight == 0) {
                    let Some(run) = runs.remove(run_id) else {
                        return Err(GatewayError::UnknownRun(run_id.to_owned()));
                    };
                    drop(runs);
                    self.inner.redactor.forget_secret(run.token_key);
                    return Ok(run.record(run_id));
                }
            }
            notified.await;
        }
    }

    /// The record of an open run so far.
    #[must_use]
    pub fn run_record(&self, run_id: &str) -> Option<RunRecord> {
        self.inner
            .runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(run_id)
            .map(|run| run.record(run_id))
    }

    /// The run whose token `presented` is, when that run is open and inside its wall clock. Every
    /// open run's token is compared in constant time, with no early exit.
    #[must_use]
    pub fn run_for_token(&self, presented: &str) -> Option<String> {
        let now = Instant::now();
        let runs = self
            .inner
            .runs
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut found = None;
        for (run_id, run) in runs.iter() {
            let matches = run.token.matches(presented);
            if matches && !run.closing && now < run.deadline {
                found = Some(run_id.clone());
            }
        }
        found
    }

    /// A call of the troubleshooter itself, for the deterministic probes: recorded in the run's
    /// record with the next call id, refused or not, with the same allowlist, deadline, redaction
    /// and result cap as an agent call, but not counted against the agent's call limits. The
    /// control plane has its own share of the record ([`MAX_CONTROL_PLANE_CALLS`]).
    ///
    /// # Errors
    /// [`GatewayError::UnknownRun`] for a run that is not open, [`GatewayError::RecordFull`].
    pub async fn call_for_run(
        &self,
        run_id: &str,
        gateway_tool: &str,
        arguments: Option<JsonObject>,
    ) -> Result<CallResult, GatewayError> {
        let result = self
            .call(run_id, CallOrigin::ControlPlane, gateway_tool, arguments)
            .await?;
        Ok(CallResult {
            // Every call of the control plane is given an id; a missing one cannot happen and is
            // reported as the record refusing it.
            call_id: result.call_id.ok_or(GatewayError::RecordFull)?,
            outcome: result.outcome,
            text: result.text,
        })
    }

    /// A call of the agent, already authenticated by its run token.
    pub(crate) async fn agent_call(
        &self,
        run_id: &str,
        gateway_tool: &str,
        arguments: Option<JsonObject>,
    ) -> Result<AgentResult, GatewayError> {
        self.call(run_id, CallOrigin::Agent, gateway_tool, arguments)
            .await
    }

    async fn call(
        &self,
        run_id: &str,
        origin: CallOrigin,
        gateway_tool: &str,
        arguments: Option<JsonObject>,
    ) -> Result<AgentResult, GatewayError> {
        let started = Instant::now();
        let started_at_unix_ms = unix_ms();
        let arguments_sha256 = arguments_digest(arguments.as_ref());
        let entry = self
            .inner
            .allowlist
            .iter()
            .find(|entry| entry.gateway_name == gateway_tool);
        let recorded_name = prefix(gateway_tool, MAX_RECORDED_NAME_BYTES).to_owned();
        let mut record = CallRecord {
            call_id: CallId::new(0),
            origin,
            gateway_tool: recorded_name.clone(),
            upstream: entry.map(|entry| entry.upstream),
            upstream_tool: entry.map(|entry| entry.upstream_tool.clone()),
            arguments_sha256: arguments_sha256.clone(),
            started_at_unix_ms,
            duration_ms: 0,
            result_bytes: 0,
            returned_bytes: 0,
            outcome: Outcome::Ok,
            result_sha256: Sha256Digest::of(b""),
        };

        let admission = {
            let mut runs = self
                .inner
                .runs
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let run = runs
                .get_mut(run_id)
                .filter(|run| !run.closing)
                .ok_or_else(|| GatewayError::UnknownRun(run_id.to_owned()))?;
            // Each origin has its own share of the record, so the agent cannot fill it and leave
            // the probes blind (TR-5).
            let (recorded, cap) = match origin {
                CallOrigin::Agent => (
                    run.agent_recorded,
                    MAX_RECORDED_CALLS - MAX_CONTROL_PLANE_CALLS,
                ),
                CallOrigin::ControlPlane => (run.control_recorded, MAX_CONTROL_PLANE_CALLS),
            };
            if recorded >= cap {
                run.unrecorded_calls += 1;
                return Err(GatewayError::RecordFull);
            }
            let admission = self.admit(run, origin, gateway_tool, started);
            match (&admission, origin) {
                // An agent call refused before it reached an upstream gets no call id: it is
                // recorded as a refusal, which cannot be cited.
                (Admission::Refused(reason), CallOrigin::Agent) => {
                    if run.refusals.len() < MAX_RECORDED_REFUSALS {
                        run.refusals.push(RefusalRecord {
                            gateway_tool: recorded_name,
                            arguments_sha256,
                            at_unix_ms: started_at_unix_ms,
                            reason: *reason,
                        });
                    } else {
                        run.unrecorded_refusals += 1;
                    }
                }
                // Every call of the control plane gets an id, refused or not, so that a probe that
                // could not run can be cited in a `source_unavailable` finding.
                (Admission::Refused(reason), CallOrigin::ControlPlane) => {
                    record.call_id = CallId::new(run.next_call);
                    run.next_call += 1;
                    run.control_recorded += 1;
                    record.outcome = Outcome::Refused(*reason);
                    let text = format!("refused: {}", reason.sentence());
                    record.result_sha256 = Sha256Digest::of(text.as_bytes());
                    run.calls.push(record.clone());
                }
                (Admission::Admitted { .. }, _) => {
                    record.call_id = CallId::new(run.next_call);
                    run.next_call += 1;
                    match origin {
                        CallOrigin::Agent => run.agent_recorded += 1,
                        CallOrigin::ControlPlane => run.control_recorded += 1,
                    }
                    run.in_flight += 1;
                }
            }
            admission
        };

        let (upstream, upstream_tool, deadline, max_bytes) = match admission {
            Admission::Refused(reason) => {
                return Ok(AgentResult {
                    call_id: (origin == CallOrigin::ControlPlane).then_some(record.call_id),
                    outcome: Outcome::Refused(reason),
                    text: format!("refused: {}", reason.sentence()),
                });
            }
            Admission::Admitted {
                upstream,
                upstream_tool,
                deadline,
                max_bytes,
            } => (upstream, upstream_tool, deadline, max_bytes),
        };

        let answered = tokio::time::timeout(
            deadline,
            upstream.call_tool_for_run(run_id, upstream_tool, arguments),
        )
        .await;
        let text = match answered {
            Err(_) => {
                record.outcome = Outcome::Timeout;
                format!(
                    "timeout: the source did not answer within {} ms",
                    millis(deadline)
                )
            }
            Ok(Err(_)) => {
                record.outcome = Outcome::UpstreamError;
                "upstream_error: the source did not answer".to_owned()
            }
            Ok(Ok(result)) => match self.inner.redactor.redact(&result_text(&result)) {
                Err(_) => {
                    record.outcome = Outcome::Refused(RefusalReason::RedactionFailed);
                    format!("refused: {}", RefusalReason::RedactionFailed.sentence())
                }
                Ok(redacted) => {
                    record.outcome = if result.is_error == Some(true) {
                        Outcome::ToolError
                    } else {
                        Outcome::Ok
                    };
                    record.result_bytes = redacted.len() as u64;
                    let returned = truncate(redacted, max_bytes);
                    record.returned_bytes = returned.len() as u64;
                    returned
                }
            },
        };
        record.duration_ms = millis(started.elapsed());
        record.result_sha256 = Sha256Digest::of(text.as_bytes());

        {
            let mut runs = self
                .inner
                .runs
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(run) = runs.get_mut(run_id) {
                run.in_flight = run.in_flight.saturating_sub(1);
                insert_in_order(&mut run.calls, record.clone());
            }
        }
        self.inner.idle.notify_waiters();
        Ok(AgentResult {
            call_id: Some(record.call_id),
            outcome: record.outcome,
            text,
        })
    }

    /// Decides whether a call goes to its upstream. Runs under the run table's lock.
    fn admit(
        &self,
        run: &mut RunState,
        origin: CallOrigin,
        gateway_tool: &str,
        now: Instant,
    ) -> Admission {
        let Some(entry) = self
            .inner
            .allowlist
            .iter()
            .find(|entry| entry.gateway_name == gateway_tool)
        else {
            return Admission::Refused(RefusalReason::ToolNotAllowed);
        };
        if now >= run.deadline {
            return Admission::Refused(RefusalReason::RunWallClock);
        }
        let offered = self
            .inner
            .catalog
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .exposed
            .iter()
            .any(|exposed| exposed.mapping.gateway_name == entry.gateway_name);
        let upstream = self
            .inner
            .upstreams
            .iter()
            .find(|upstream| upstream.id() == entry.upstream);
        let Some(upstream) = upstream.filter(|_| offered) else {
            return Admission::Refused(RefusalReason::ToolUnavailable);
        };
        if origin == CallOrigin::Agent {
            if run.agent_calls >= run.limits.max_calls_per_run {
                return Admission::Refused(RefusalReason::MaxCallsPerRun);
            }
            while run
                .window
                .front()
                .is_some_and(|first| *first + RATE_WINDOW <= now)
            {
                run.window.pop_front();
            }
            let in_window = u32::try_from(run.window.len()).unwrap_or(u32::MAX);
            if in_window >= run.limits.max_calls_per_10s {
                return Admission::Refused(RefusalReason::MaxCallsPer10s);
            }
            run.agent_calls += 1;
            run.window.push_back(now);
        }
        Admission::Admitted {
            upstream: Arc::clone(upstream),
            upstream_tool: entry.upstream_tool.clone(),
            deadline: run
                .limits
                .call_deadline
                .min(run.deadline.saturating_duration_since(now)),
            max_bytes: usize::try_from(run.limits.max_result_bytes).unwrap_or(usize::MAX),
        }
    }
}

/// Keeps the record in call id order when calls finish out of order.
fn insert_in_order(calls: &mut Vec<CallRecord>, record: CallRecord) {
    let at = calls.partition_point(|call| call.call_id < record.call_id);
    calls.insert(at, record);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_keeps_utf8_and_says_how_much_was_cut() {
        let text = "é".repeat(1000);
        let out = truncate(text.clone(), 200);
        assert!(out.len() <= 200, "{}", out.len());
        let marker_at = out.find("\n[truncated").expect("marker");
        let kept = &out[..marker_at];
        assert!(kept.chars().all(|c| c == 'é'));
        let cut = text.len() - kept.len();
        assert!(
            out.ends_with(&format!("[truncated by the gateway: {cut} bytes cut]")),
            "{out}"
        );
        assert_eq!(truncate("short".to_owned(), 200), "short");
        let exact = "a".repeat(200);
        assert_eq!(truncate(exact.clone(), 200), exact);
        let over = "a".repeat(201);
        let out = truncate(over, 200);
        assert!(out.len() <= 200);
        assert!(out.contains("bytes cut]"));
    }

    #[test]
    fn the_arguments_digest_is_canonical() {
        let a: JsonObject = serde_json::from_str(r#"{"b": 1, "a": [true, "x"]}"#).expect("json");
        let b: JsonObject = serde_json::from_str(r#"{"a":[true,"x"],"b":1}"#).expect("json");
        assert_eq!(arguments_digest(Some(&a)), arguments_digest(Some(&b)));
        assert_eq!(
            arguments_digest(None),
            Sha256Digest::of(b"{}"),
            "no arguments hash as an empty object"
        );
    }

    /// An upstream that answers at once, so the tests below can run on a paused clock.
    struct Instant0;

    impl Upstream for Instant0 {
        fn id(&self) -> UpstreamId {
            UpstreamId::Victoriametrics
        }

        fn connect(&self) -> crate::BoxFuture<'_, Result<(), crate::UpstreamError>> {
            Box::pin(async { Ok(()) })
        }

        fn list_tools(&self) -> crate::BoxFuture<'_, Result<Vec<Tool>, crate::UpstreamError>> {
            Box::pin(async {
                Ok(vec![Tool::new_with_raw(
                    "query",
                    None,
                    Arc::new(JsonObject::new()),
                )])
            })
        }

        fn call_tool(
            &self,
            _name: String,
            _arguments: Option<JsonObject>,
        ) -> crate::BoxFuture<'_, Result<CallToolResult, crate::UpstreamError>> {
            Box::pin(async { Ok(CallToolResult::success(vec![ContentBlock::text("1")])) })
        }
    }

    struct NoPatterns;

    impl Redact for NoPatterns {
        fn redact(&self, text: &str) -> Result<String, crate::RedactionFailed> {
            Ok(text.to_owned())
        }

        fn register_secret(
            &self,
            _label: &str,
            _value: &str,
        ) -> Result<SecretKey, crate::RegisterFailed> {
            Ok(SecretKey::new(0))
        }

        fn forget_secret(&self, _key: SecretKey) {}
    }

    fn policy() -> TroubleshootingPolicy {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "policy": {"id": "troubleshooting", "version": 1, "status": "designed",
                "default_action": "deny", "project_overrides": "tighten_only",
                "config_source": "protected_default_branch", "threats": ["T-03"]},
            "schedule": {"probe_period_s": 300, "sweep_period_s": 86400,
                "probe_cooldown_s": 21600, "max_concurrent_agent_runs": 1,
                "max_agent_runs_per_day": 8},
            "issues": {"max_new_per_day": 3, "max_comments_per_issue_per_day": 1,
                "labels": ["troubleshooter"]},
            "gateway": {"max_calls_per_run": 60, "max_calls_per_10s": 40,
                "max_result_bytes": 65536, "call_deadline_s": 20, "run_wall_clock_s": 900},
            "upstreams": {"datadog": {"toolsets": ["core"], "omit_tools": []},
                "victoriametrics": {"disabled_tools": []}},
            "tools": [{"id": "mcp.victoriametrics.query", "gateway_name": "vm_query",
                "upstream": "victoriametrics", "upstream_tool": "query",
                "description": "A PromQL query."}],
            "probes": []
        }))
        .expect("policy")
    }

    async fn gateway() -> Gateway {
        let gateway = Gateway::builder(&policy(), Arc::new(NoPatterns))
            .upstream(Arc::new(Instant0))
            .build()
            .expect("gateway");
        let report = gateway.connect().await;
        assert_eq!(report.offered.len(), 1);
        gateway
    }

    async fn agent_outcome(gateway: &Gateway, run: &str) -> Outcome {
        gateway
            .agent_call(run, "vm_query", None)
            .await
            .expect("recorded")
            .outcome
    }

    #[tokio::test(start_paused = true)]
    async fn calls_per_10_seconds_allow_exactly_the_limit_in_a_sliding_window() {
        let gateway = gateway().await;
        let limits = RunLimits {
            max_calls_per_10s: 4,
            ..gateway.policy_limits()
        };
        gateway.open_run("run", limits).expect("run");
        for _ in 0..4 {
            assert_eq!(agent_outcome(&gateway, "run").await, Outcome::Ok);
        }
        let refused = Outcome::Refused(RefusalReason::MaxCallsPer10s);
        assert_eq!(agent_outcome(&gateway, "run").await, refused);
        // Probes do not use the agent's window.
        let probe = gateway
            .call_for_run("run", "vm_query", None)
            .await
            .expect("probe");
        assert_eq!(probe.outcome, Outcome::Ok);
        tokio::time::advance(Duration::from_millis(9_999)).await;
        assert_eq!(agent_outcome(&gateway, "run").await, refused);
        tokio::time::advance(Duration::from_millis(1)).await;
        // Exactly 10 s after the first four, all four left the window.
        for _ in 0..4 {
            assert_eq!(agent_outcome(&gateway, "run").await, Outcome::Ok);
        }
        assert_eq!(agent_outcome(&gateway, "run").await, refused);
        let record = gateway.run_record("run").expect("record");
        let ok = record
            .calls
            .iter()
            .filter(|c| c.outcome == Outcome::Ok)
            .count();
        assert_eq!(ok, 9, "8 agent calls and 1 probe");
    }

    #[tokio::test(start_paused = true)]
    async fn calls_per_run_allow_exactly_the_limit() {
        let gateway = gateway().await;
        let limits = RunLimits {
            max_calls_per_run: 5,
            ..gateway.policy_limits()
        };
        gateway.open_run("run", limits).expect("run");
        for _ in 0..5 {
            assert_eq!(agent_outcome(&gateway, "run").await, Outcome::Ok);
            tokio::time::advance(Duration::from_secs(11)).await;
        }
        assert_eq!(
            agent_outcome(&gateway, "run").await,
            Outcome::Refused(RefusalReason::MaxCallsPerRun)
        );
        // Refused calls do not spend the budget, and an unknown tool is refused first.
        let unknown = gateway
            .agent_call("run", "vm_export", None)
            .await
            .expect("recorded");
        assert_eq!(
            unknown.outcome,
            Outcome::Refused(RefusalReason::ToolNotAllowed)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_run_wall_clock_ends_calls_and_the_token() {
        let gateway = gateway().await;
        let limits = RunLimits {
            run_wall_clock: Duration::from_secs(60),
            ..gateway.policy_limits()
        };
        let token = gateway.open_run("run", limits).expect("run");
        assert_eq!(
            gateway.run_for_token(token.expose()).as_deref(),
            Some("run")
        );
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(gateway.run_for_token(token.expose()), None);
        assert_eq!(
            agent_outcome(&gateway, "run").await,
            Outcome::Refused(RefusalReason::RunWallClock)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn refused_agent_calls_take_no_id_and_cannot_starve_the_probes() {
        // TR-5: refusals of the agent are free to make, so they must not mint citable ids nor
        // fill the record that the probes need.
        let gateway = gateway().await;
        gateway
            .open_run("run", gateway.policy_limits())
            .expect("run");
        for _ in 0..MAX_RECORDED_CALLS + 50 {
            let refused = gateway
                .agent_call("run", "nope", None)
                .await
                .expect("answered");
            assert_eq!(refused.call_id, None);
            assert_eq!(
                refused.outcome,
                Outcome::Refused(RefusalReason::ToolNotAllowed)
            );
            let mcp = refused.to_mcp();
            assert_eq!(mcp.is_error, Some(true));
            let first = mcp.content[0].as_text().expect("text").text.clone();
            assert!(first.starts_with("call_id: none"), "{first}");
        }
        // The probes still get ids, refused calls included, up to their own share.
        for n in 0..MAX_CONTROL_PLANE_CALLS {
            let tool = if n % 2 == 0 { "vm_query" } else { "nope" };
            let probe = gateway
                .call_for_run("run", tool, None)
                .await
                .expect("a probe is recorded");
            assert_eq!(probe.call_id.sequence(), n as u64 + 1);
        }
        assert_eq!(
            gateway.call_for_run("run", "vm_query", None).await,
            Err(GatewayError::RecordFull)
        );
        // The agent's share is its own.
        let agent = gateway
            .agent_call("run", "vm_query", None)
            .await
            .expect("answered");
        assert_eq!(agent.outcome, Outcome::Ok);
        assert!(agent.call_id.is_some());
        let record = gateway.close_run("run").await.expect("closed");
        assert_eq!(record.calls.len(), MAX_CONTROL_PLANE_CALLS + 1);
        assert_eq!(record.unrecorded_calls, 1);
        assert_eq!(record.refusals.len(), MAX_RECORDED_REFUSALS);
        assert_eq!(
            record.unrecorded_refusals,
            (MAX_RECORDED_CALLS + 50 - MAX_RECORDED_REFUSALS) as u64
        );
        assert_eq!(record.refusals[0].reason, RefusalReason::ToolNotAllowed);
        // A refused probe call is recorded, with its id, and is not evidence.
        let refused_probe = record.call("call-2").expect("recorded");
        assert_eq!(refused_probe.origin, CallOrigin::ControlPlane);
        assert_eq!(
            refused_probe.outcome,
            Outcome::Refused(RefusalReason::ToolNotAllowed)
        );
        assert!(record.evidence("call-2", "nope").is_none());
        let first = record.evidence("call-1", "vm_query").expect("evidence");
        assert_eq!(first.origin, CallOrigin::ControlPlane);
        assert_eq!(first.result_sha256, &Sha256Digest::of(b"1"));
        assert!(record.evidence("call-1", "vm_labels").is_none());
    }

    #[test]
    fn run_ids_are_checked() {
        assert!(valid_run_id("ts-run-2026-11-20T10:00:00Z_1"));
        assert!(!valid_run_id(""));
        assert!(!valid_run_id("a b"));
        assert!(!valid_run_id(&"a".repeat(129)));
    }
}
