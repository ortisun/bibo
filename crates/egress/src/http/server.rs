//! The broker's listener: what the per-job sidecar forwards from the sandbox arrives here.
//!
//! One request goes through these steps, and a refusal at any step sends nothing to a provider:
//!
//! 1. Read a bounded request head. Only `POST` to the four model routes and `GET /v1/models` are
//!    served; every other method and path is refused.
//! 2. Read the credential from `x-api-key` or `Authorization: Bearer`, and look it up. A bad
//!    credential is refused before the body is read.
//! 3. Check the beta header, then read the body (bounded) and check it against the allow schema
//!    of the API it is written for (`crate::broker::shape`): strict JSON, only the fields the
//!    runtimes send, no provider-side tool, remote server or fetched content. A body that fails is
//!    refused with a fixed answer and an audit event, and nothing is sent to a provider.
//! 4. Ask the core for a permit: audience, model list, price, caps, rate. The request is counted
//!    here.
//! 5. Clamp the output token limit to the per-request cap, build the upstream request from an
//!    allowlist of headers, add the real key, and call the provider with no redirects and no proxy.
//! 6. Stream the answer back (events are written as they are read) while reading usage from it,
//!    with the key scrubbed out, then settle the permit with what the answer reported. Of the
//!    provider's headers only a media type and a retry delay come back.
//!
//! The real key exists in this module in one place: the credential header of the upstream request.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use factory_domain::ids::JobId;
use factory_domain::redaction::Redactor;
use factory_ports::agent::AnswerEnd;
use serde_json::{Map, Value, json};

use super::scrub::StreamScrubber;
use super::secret::ProviderKey;
use super::usage::{StreamUsage, answer_end_from_json, counts_from_json};
use super::wire::{self, RequestHead};
use crate::broker::shape::{self, Violation, Wire, headers};
use crate::broker::{BrokerCore, Outcome, Permit, Provider, Refusal, RequestFacts};

/// Why a broker server could not be built or started. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StartError {
    /// A provider base URL is not `scheme://host[:port]` with nothing after it.
    #[error("a provider base URL is not of the form scheme://host[:port]")]
    BadBaseUrl,
    /// A provider base URL uses plain HTTP to a host that is not this machine.
    #[error("a provider base URL uses plain http to a host other than loopback")]
    PlainHttpToRemoteHost,
    /// Two upstreams were given for one provider.
    #[error("two upstreams were given for one provider")]
    DuplicateProvider,
    /// No upstream was given.
    #[error("no upstream was given")]
    NoUpstream,
    /// The scrubber's redactor could not be built or loaded with a key.
    #[error("the redactor could not be set up")]
    Redactor,
    /// The listener could not bind.
    #[error("the listener could not bind")]
    Bind,
}

/// Where the broker sends requests for one provider, and the key it signs them with.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    provider: Provider,
    base: String,
    key: ProviderKey,
}

impl UpstreamConfig {
    /// An upstream. `base_url` is `https://host[:port]`; `http://` is accepted only for a
    /// loopback host, which is how the tests reach the fake provider.
    ///
    /// # Errors
    /// [`StartError::BadBaseUrl`] or [`StartError::PlainHttpToRemoteHost`].
    pub fn new(provider: Provider, base_url: &str, key: ProviderKey) -> Result<Self, StartError> {
        let (scheme, authority) = base_url.split_once("://").ok_or(StartError::BadBaseUrl)?;
        if !matches!(scheme, "http" | "https") {
            return Err(StartError::BadBaseUrl);
        }
        if authority.is_empty()
            || authority.contains(['/', '?', '#', '@', '\\', ' '])
            || !authority
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-.:[]".contains(&b))
        {
            return Err(StartError::BadBaseUrl);
        }
        let host = host_of(authority);
        if scheme == "http" && !is_loopback_host(host) {
            return Err(StartError::PlainHttpToRemoteHost);
        }
        Ok(Self {
            provider,
            base: format!("{scheme}://{authority}"),
            key,
        })
    }
}

fn host_of(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("");
    }
    authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host)
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Sizes and times. The defaults suit a tool whose requests carry a growing conversation and
/// whose answers stream for minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerLimits {
    /// The most bytes of a request head.
    pub max_head_bytes: usize,
    /// How long the sandbox side may take to send the head.
    pub head_timeout: Duration,
    /// How long it may stay silent while sending the body.
    pub body_timeout: Duration,
    /// How long a write to the sandbox side may block.
    pub write_timeout: Duration,
    /// The most connections served at once. More are answered with 503.
    pub max_connections: usize,
    /// How long to wait to connect to the provider.
    pub upstream_connect: Duration,
    /// How long to wait for the provider's response head.
    pub upstream_first_byte: Duration,
    /// How long the provider may stay silent in the middle of an answer.
    pub upstream_idle: Duration,
    /// The longest a whole upstream call may take.
    pub upstream_total: Duration,
    /// The most bytes of a non-streamed answer the broker holds.
    pub max_buffered_response: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_head_bytes: 32 * 1024,
            head_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(60),
            max_connections: 64,
            upstream_connect: Duration::from_secs(10),
            upstream_first_byte: Duration::from_secs(300),
            upstream_idle: Duration::from_secs(120),
            upstream_total: Duration::from_secs(20 * 60),
            max_buffered_response: 16 * 1024 * 1024,
        }
    }
}

/// What the listener is built from.
#[derive(Debug, Clone)]
pub struct BrokerServerConfig {
    /// Where to listen.
    pub listen: SocketAddr,
    /// One upstream per provider the broker serves.
    pub upstreams: Vec<UpstreamConfig>,
    /// The job this listener serves, when it serves one. A token of another job is refused. A
    /// broker with one listener for every job leaves this empty and relies on the token alone.
    pub expected_job: Option<JobId>,
    /// Sizes and times.
    pub limits: ServerLimits,
}

struct Upstream {
    base: String,
    key: ProviderKey,
}

struct Shared {
    core: Arc<BrokerCore>,
    upstreams: BTreeMap<Provider, Upstream>,
    redactor: Redactor,
    expected_job: Option<JobId>,
    limits: ServerLimits,
    agent: ureq::Agent,
    active: AtomicUsize,
}

/// A running listener. Dropping it stops it.
pub struct BrokerServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl BrokerServer {
    /// Binds the listener and starts serving.
    ///
    /// # Errors
    /// [`StartError`].
    pub fn start(config: BrokerServerConfig, core: Arc<BrokerCore>) -> Result<Self, StartError> {
        if config.upstreams.is_empty() {
            return Err(StartError::NoUpstream);
        }
        let redactor = Redactor::builder()
            .build()
            .map_err(|_| StartError::Redactor)?;
        let mut upstreams = BTreeMap::new();
        for upstream in config.upstreams {
            redactor
                .register("provider_key", upstream.key.expose())
                .map_err(|_| StartError::Redactor)?;
            let slot = Upstream {
                base: upstream.base,
                key: upstream.key,
            };
            if upstreams.insert(upstream.provider, slot).is_some() {
                return Err(StartError::DuplicateProvider);
            }
        }
        let limits = config.limits;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .proxy(None)
            .https_only(false)
            .user_agent("factory-model-broker")
            .timeout_connect(Some(limits.upstream_connect))
            .timeout_recv_response(Some(limits.upstream_first_byte))
            .timeout_per_read(Some(limits.upstream_idle))
            .timeout_global(Some(limits.upstream_total))
            .build()
            .into();
        let shared = Arc::new(Shared {
            core,
            upstreams,
            redactor,
            expected_job: config.expected_job,
            limits,
            agent,
            active: AtomicUsize::new(0),
        });
        let listener = TcpListener::bind(config.listen).map_err(|_| StartError::Bind)?;
        let addr = listener.local_addr().map_err(|_| StartError::Bind)?;
        let stop = Arc::new(AtomicBool::new(false));
        let accept_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("broker-accept".to_owned())
            .spawn(move || accept_loop(&listener, &shared, &accept_stop))
            .map_err(|_| StartError::Bind)?;
        Ok(Self {
            addr,
            stop,
            thread: Mutex::new(Some(thread)),
        })
    }

    /// The address the listener is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops accepting connections. Requests already being served finish.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocked accept with a connection to ourselves.
        let wake = if self.addr.ip().is_unspecified() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.addr.port())
        } else {
            self.addr
        };
        let _ = TcpStream::connect_timeout(&wake, Duration::from_secs(1));
        let handle = self.thread.lock().ok().and_then(|mut t| t.take());
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

impl Drop for BrokerServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn accept_loop(listener: &TcpListener, shared: &Arc<Shared>, stop: &AtomicBool) {
    for incoming in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(mut stream) = incoming else {
            continue;
        };
        if shared.active.fetch_add(1, Ordering::SeqCst) >= shared.limits.max_connections {
            shared.active.fetch_sub(1, Ordering::SeqCst);
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            respond_error(&mut stream, 503, "overloaded", &[]);
            continue;
        }
        let worker = Arc::clone(shared);
        let spawned = thread::Builder::new()
            .name("broker-conn".to_owned())
            .spawn(move || {
                serve(&worker, stream);
                worker.active.fetch_sub(1, Ordering::SeqCst);
            });
        if spawned.is_err() {
            shared.active.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

// ---- one connection ----------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Route {
    Model,
    CountTokens,
}

fn route_for(method: &str, path: &str) -> Option<(Provider, Route)> {
    if method != "POST" {
        return None;
    }
    match path {
        "/v1/messages" => Some((Provider::Anthropic, Route::Model)),
        "/v1/messages/count_tokens" => Some((Provider::Anthropic, Route::CountTokens)),
        "/v1/responses" | "/v1/chat/completions" => Some((Provider::OpenAi, Route::Model)),
        _ => None,
    }
}

fn path_is_known(path: &str) -> bool {
    matches!(
        path,
        "/v1/messages"
            | "/v1/messages/count_tokens"
            | "/v1/responses"
            | "/v1/chat/completions"
            | "/v1/models"
    )
}

fn serve(shared: &Shared, mut stream: TcpStream) {
    let limits = shared.limits;
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(limits.head_timeout));
    let _ = stream.set_write_timeout(Some(limits.write_timeout));
    let (head, rest) = match wire::read_head(&mut stream, limits.max_head_bytes) {
        Ok(read) => read,
        Err(error) => {
            if let Some(status) = error.status() {
                respond_error(&mut stream, status, "invalid_request", &[]);
            }
            return;
        }
    };
    if head.method == "GET" && head.path == "/v1/models" {
        serve_models(shared, &mut stream, &head);
        return;
    }
    let Some((provider, route)) = route_for(&head.method, &head.path) else {
        // A WebSocket upgrade on a model route gets an answer at once, so a tool that tries it
        // falls back to plain HTTP without waiting.
        let status = if head.has("upgrade") {
            426
        } else if path_is_known(&head.path) {
            405
        } else {
            404
        };
        respond_error(&mut stream, status, "not_found", &[]);
        return;
    };
    if !shared.upstreams.contains_key(&provider) {
        respond_error(&mut stream, 404, "not_found", &[]);
        return;
    }
    serve_model_request(shared, &mut stream, &head, rest, provider, route);
}

/// The credential a request carries, or why it has none.
enum Credential {
    Missing,
    Conflict,
    Present(String),
}

fn credential(head: &RequestHead) -> Credential {
    if (head.has("x-api-key") && head.header("x-api-key").is_none())
        || (head.has("authorization") && head.header("authorization").is_none())
    {
        return Credential::Conflict;
    }
    let key = head.header("x-api-key").filter(|v| !v.is_empty());
    let bearer = head.header("authorization").and_then(|v| {
        let (scheme, token) = v.split_once(' ')?;
        scheme
            .eq_ignore_ascii_case("bearer")
            .then_some(token.trim())
    });
    match (key, bearer) {
        (Some(k), Some(b)) if k != b => Credential::Conflict,
        (Some(k), _) => Credential::Present(k.to_owned()),
        (None, Some(b)) if !b.is_empty() => Credential::Present(b.to_owned()),
        _ => Credential::Missing,
    }
}

fn serve_models(shared: &Shared, stream: &mut TcpStream, head: &RequestHead) {
    let presented = match credential(head) {
        Credential::Present(token) => token,
        Credential::Conflict => return respond_error(stream, 400, "invalid_request", &[]),
        Credential::Missing => String::new(),
    };
    match shared.core.authenticate(&presented, shared.expected_job) {
        // Codex asks for the model list at start. An empty list was accepted in the spike, and
        // nothing about the account is learned from the provider.
        Ok(_) => {
            let body = json!({"models": [], "object": "list", "data": []}).to_string();
            let _ = wire::write_response(
                stream,
                200,
                &[("Content-Type", "application/json")],
                body.as_bytes(),
            );
        }
        Err(refusal) => respond_refusal(stream, refusal),
    }
}

fn serve_model_request(
    shared: &Shared,
    stream: &mut TcpStream,
    head: &RequestHead,
    rest: Vec<u8>,
    provider: Provider,
    route: Route,
) {
    let presented = match credential(head) {
        Credential::Present(token) => token,
        Credential::Conflict => return respond_error(stream, 400, "invalid_request", &[]),
        Credential::Missing => String::new(),
    };
    // Step 2: a credential that does not work is refused before the body is read.
    if let Err(refusal) = shared.core.authenticate(&presented, shared.expected_job) {
        return respond_refusal(stream, refusal);
    }
    let is_json = head
        .header("content-type")
        .is_some_and(|t| t.to_ascii_lowercase().starts_with("application/json"));
    if !is_json {
        return respond_error(stream, 415, "unsupported_media_type", &[]);
    }
    let refuse_shape = |stream: &mut TcpStream, violation: Violation| {
        let refusal = shared
            .core
            .refuse_request_shape(&presented, shared.expected_job, violation);
        respond_refusal(stream, refusal);
    };
    let Some(wire) = Wire::for_path(&head.path) else {
        return respond_error(stream, 404, "not_found", &[]);
    };
    // The beta header decides, before the body is read, whether this is a request the broker
    // forwards at all. Two copies of the header are as unreadable as a bad value.
    let beta = if head.has("anthropic-beta") && head.header("anthropic-beta").is_none() {
        Err(Violation::BetaHeader)
    } else {
        headers::beta_header(provider, head.header("anthropic-beta"))
    };
    let beta = match beta {
        Ok(beta) => beta,
        Err(violation) => return refuse_shape(stream, violation),
    };
    let max_body = shared.core.caps().per_request.max_body_bytes;
    let Some(length) = head.content_length else {
        return respond_error(stream, 411, "length_required", &[]);
    };
    if length > max_body {
        return respond_error(stream, 413, "request_too_large", &[]);
    }
    if head
        .header("expect")
        .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
        && wire::write_continue(stream).is_err()
    {
        return;
    }
    let _ = stream.set_read_timeout(Some(shared.limits.body_timeout));
    let body = match wire::read_body(stream, rest, length) {
        Ok(body) => body,
        Err(error) => {
            if let Some(status) = error.status() {
                respond_error(stream, status, "invalid_request", &[]);
            }
            return;
        }
    };
    // The allow schema. What is forwarded below is this body, byte for byte, unless the output
    // limit had to be brought down.
    let mut object = match shape::check_body(wire, &body) {
        Ok(object) => object,
        Err(violation) => return refuse_shape(stream, violation),
    };
    let Some(model) = object
        .get("model")
        .and_then(Value::as_str)
        .filter(|m| model_name_ok(m))
        .map(str::to_owned)
    else {
        return respond_error(stream, 400, "invalid_request", &[]);
    };
    let facts = RequestFacts {
        provider,
        model: &model,
        expected_job: shared.expected_job,
    };
    let permit = match shared.core.authorize(&presented, &facts) {
        Ok(permit) => permit,
        Err(refusal) => return respond_refusal(stream, refusal),
    };
    // A model request is a turn of the conversation, and its answer is recorded as one
    // (`TurnAttestation`). A count-tokens call is not.
    let permit = match route {
        Route::Model => permit.for_turn(),
        Route::CountTokens => permit,
    };
    let forwarded = match route {
        Route::Model => {
            let changed = clamp_output_tokens(provider, &mut object, permit.max_output_tokens());
            if changed {
                serde_json::to_vec(&Value::Object(object)).unwrap_or(body)
            } else {
                body
            }
        }
        Route::CountTokens => body,
    };
    let Some(upstream) = shared.upstreams.get(&provider) else {
        permit.settle(Outcome::NoCharge);
        return respond_error(stream, 404, "not_found", &[]);
    };
    forward(
        shared,
        stream,
        head,
        upstream,
        provider,
        beta.as_deref(),
        &forwarded,
        permit,
    );
}

fn model_name_ok(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 200
        && model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._:/".contains(&b))
}

/// Brings the output token limit of a request down to `cap`, or sets it when the request names
/// none. Returns true when the object changed. A request that asks for less is left alone.
fn clamp_output_tokens(provider: Provider, object: &mut Map<String, Value>, cap: u64) -> bool {
    let fields: &[&str] = match provider {
        Provider::Anthropic => &["max_tokens"],
        // The Responses API names it `max_output_tokens`; Chat Completions has the older
        // `max_tokens` and the newer `max_completion_tokens`.
        Provider::OpenAi => &["max_output_tokens", "max_completion_tokens", "max_tokens"],
    };
    let mut present = false;
    let mut changed = false;
    for field in fields {
        if let Some(value) = object.get_mut(*field) {
            present = true;
            let over = match value.as_u64() {
                Some(asked) => asked > cap,
                // A negative, fractional or non-numeric limit is replaced by the cap.
                None => true,
            };
            if over {
                *value = Value::from(cap);
                changed = true;
            }
        }
    }
    if !present {
        let field = match provider {
            Provider::Anthropic => "max_tokens",
            // Chat Completions rejects the Responses field and the reverse. The route is not
            // known here, so a request that names none is left to the provider's own default,
            // which a ceiling revoke still bounds after the first answer.
            Provider::OpenAi => return false,
        };
        object.insert(field.to_owned(), Value::from(cap));
        changed = true;
    }
    changed
}

// ---- the upstream call -------------------------------------------------------------------------

/// Header values the broker forwards are plain printable ASCII of bounded length.
fn header_value_ok(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.bytes().all(|b| b == b' ' || b.is_ascii_graphic())
}

fn build_upstream_request(
    upstream: &Upstream,
    provider: Provider,
    head: &RequestHead,
    beta: Option<&str>,
    body: &[u8],
) -> Option<ureq::http::Request<Vec<u8>>> {
    let mut url = format!("{}{}", upstream.base, head.path);
    // The query of a model route has one use, Claude Code's `beta=true`. Nothing else crosses.
    if let Some(query) = headers::upstream_query(provider, head.query.as_deref()) {
        url.push('?');
        url.push_str(query);
    }
    let mut builder = ureq::http::Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json")
        .header("user-agent", "factory-model-broker");
    // Only these headers cross, and only when they look like what they should. Everything else a
    // tool sends is dropped: session identifiers, device identifiers, cookies, forwarding headers
    // and, above all, the job token in either of its two places. The beta list was reduced to the
    // values of the recorded runtimes before the body was read (`shape::headers::beta_header`).
    if let Some(value) = head.header("accept").filter(|v| header_value_ok(v)) {
        builder = builder.header("accept", value);
    }
    if let Some(value) = beta {
        builder = builder.header("anthropic-beta", value);
    }
    match provider {
        Provider::Anthropic => {
            let version = head
                .header("anthropic-version")
                .filter(|v| header_value_ok(v))
                .unwrap_or("2023-06-01");
            builder = builder
                .header("anthropic-version", version)
                .header("x-api-key", upstream.key.expose());
        }
        Provider::OpenAi => {
            builder = builder.header("authorization", format!("Bearer {}", upstream.key.expose()));
        }
    }
    builder.body(body.to_vec()).ok()
}

#[allow(clippy::too_many_arguments)]
fn forward(
    shared: &Shared,
    stream: &mut TcpStream,
    head: &RequestHead,
    upstream: &Upstream,
    provider: Provider,
    beta: Option<&str>,
    body: &[u8],
    permit: Permit,
) {
    let Some(request) = build_upstream_request(upstream, provider, head, beta, body) else {
        permit.settle(Outcome::NoCharge);
        return respond_error(stream, 400, "invalid_request", &[]);
    };
    let mut response = match shared.agent.run(request) {
        Ok(response) => response,
        Err(error) => {
            permit.settle(Outcome::NoCharge);
            let status = if matches!(error, ureq::Error::Timeout(_)) {
                504
            } else {
                502
            };
            return respond_error(stream, status, "upstream_unavailable", &[]);
        }
    };
    let status = response.status().as_u16();
    // A provider that answers 401 or 403 is refusing the broker's own key. That is the broker's
    // problem and not the tool's, and a 401 would make the tool retry ten times.
    if (300..400).contains(&status) || status == 401 || status == 403 {
        permit.settle(Outcome::NoCharge);
        return respond_error(stream, 502, "upstream_rejected_request", &[]);
    }
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let passed = passed_headers(&response);
    let header_refs: Vec<(&str, &str)> = passed
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();

    let is_stream = content_type
        .to_ascii_lowercase()
        .starts_with("text/event-stream");
    if (200..300).contains(&status) && is_stream {
        let reader = response.body_mut().with_config().limit(u64::MAX).reader();
        let (outcome, end) = relay_stream(stream, provider, status, &header_refs, reader, upstream);
        permit.settle_with_end(outcome, end);
        return;
    }
    // Everything else is held, up to a bound, so that it can be scrubbed whole and read for usage.
    let cap = shared.limits.max_buffered_response as u64;
    let buffered = response.body_mut().with_config().limit(cap).read_to_vec();
    let Ok(raw) = buffered else {
        permit.settle(if (200..300).contains(&status) {
            Outcome::Unreadable
        } else {
            Outcome::NoCharge
        });
        return respond_error(stream, 502, "upstream_unavailable", &[]);
    };
    let outcome = if (200..300).contains(&status) {
        counts_from_json(provider, &raw).map_or(Outcome::Unreadable, Outcome::Counted)
    } else {
        Outcome::NoCharge
    };
    // Only a successful answer whose usage could be read has an end the broker will attest.
    let end = match outcome {
        Outcome::Counted(_) => answer_end_from_json(provider, &raw),
        Outcome::NoCharge | Outcome::Unreadable => AnswerEnd::Failed,
    };
    let clean = shared
        .redactor
        .redact(&raw)
        .map(|r| r.output.into_owned())
        .unwrap_or_default();
    permit.settle_with_end(outcome, end);
    let _ = wire::write_response(stream, status, &header_refs, &clean);
}

/// The headers of the provider's answer that the tool gets: a media type from a short list and a
/// retry delay in whole seconds. The provider's request identifiers, organization, region and
/// rate-limit counters name the broker's account, and nothing in the sandbox needs them.
fn passed_headers(response: &ureq::http::Response<ureq::Body>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(value) = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
    {
        out.push((
            canonical("content-type"),
            headers::response_content_type(value).to_owned(),
        ));
    }
    if let Some(seconds) = response
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(headers::response_retry_after)
    {
        out.push((canonical("retry-after"), seconds.to_string()));
    }
    out
}

fn canonical(name: &str) -> String {
    name.split('-')
        .map(|part| {
            let mut chars = part.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_ascii_uppercase().to_string() + chars.as_str()
            })
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Copies a server-sent event stream to the tool as it arrives, reading its usage on the way.
fn relay_stream(
    client: &mut TcpStream,
    provider: Provider,
    status: u16,
    headers: &[(&str, &str)],
    mut upstream_body: impl Read,
    upstream: &Upstream,
) -> (Outcome, AnswerEnd) {
    let mut head_headers: Vec<(&str, &str)> = headers.to_vec();
    head_headers.push(("Cache-Control", "no-cache"));
    if wire::write_chunked_head(client, status, &head_headers).is_err() {
        return (Outcome::Unreadable, AnswerEnd::Failed);
    }
    let mut usage = StreamUsage::new(provider);
    let mut scrubber = StreamScrubber::new([upstream.key.expose()]);
    let mut chunk = [0_u8; 8192];
    let mut finished_cleanly = false;
    loop {
        match upstream_body.read(&mut chunk) {
            Ok(0) => {
                finished_cleanly = true;
                break;
            }
            Ok(n) => {
                usage.feed(&chunk[..n]);
                let clean = scrubber.push(&chunk[..n]);
                if wire::write_chunk(client, &clean).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    if finished_cleanly {
        let _ = wire::write_chunk(client, &scrubber.finish());
        let _ = wire::write_last_chunk(client);
    }
    // Usage that was seen in full is charged whatever happened to the client; a stream that was
    // cut before its report is charged the worst case.
    match usage.finish_with_end() {
        (Some(counts), end) => (Outcome::Counted(counts), end),
        (None, _) => (Outcome::Unreadable, AnswerEnd::Failed),
    }
}

// ---- answers the broker makes itself -----------------------------------------------------------

fn error_message(kind: &str) -> &'static str {
    match kind {
        "unknown_token" => "The credential is not valid at this broker.",
        "expired" => "The credential has expired.",
        "token_revoked" => "The credential was revoked.",
        "budget_exhausted" => "The budget for this job is exhausted.",
        "wrong_audience" => "The credential is not valid for this request.",
        "model_not_allowed" => "The model is not allowed for this credential.",
        "price_unknown" => "The model has no price at this broker.",
        "rate_limited" => "Too many requests. Retry later.",
        "too_many_in_flight" => "Too many requests are in progress. Retry later.",
        "upstream_unavailable" => "The model provider could not be reached.",
        "upstream_rejected_request" => "The model provider refused the broker's request.",
        "overloaded" => "The broker is busy. Retry later.",
        "request_shape" => "The request holds content that this broker does not forward.",
        _ => "The request was refused.",
    }
}

/// An error answer. The body holds a fixed sentence and a closed type, never text from the
/// request or from a provider.
fn respond_error(stream: &mut TcpStream, status: u16, kind: &str, extra: &[(&str, &str)]) {
    let body = json!({
        "type": "error",
        "error": {"type": kind, "message": error_message(kind)},
    })
    .to_string();
    let mut headers = vec![("Content-Type", "application/json")];
    headers.extend_from_slice(extra);
    let _ = wire::write_response(stream, status, &headers, body.as_bytes());
}

fn respond_refusal(stream: &mut TcpStream, refusal: Refusal) {
    let kind = match refusal {
        Refusal::Revoked(reason) if reason.is_budget_stop() => "budget_exhausted",
        Refusal::Revoked(_) => "token_revoked",
        other => other.as_str(),
    };
    let retry;
    let mut extra: Vec<(&str, &str)> = Vec::new();
    if let Refusal::RateLimited { retry_after_secs } = refusal {
        retry = retry_after_secs.to_string();
        extra.push(("Retry-After", retry.as_str()));
    }
    respond_error(stream, refusal.http_status(), kind, &extra);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ProviderKey {
        ProviderKey::new("k".repeat(32)).expect("a key")
    }

    #[test]
    fn a_base_url_is_scheme_host_and_port_and_nothing_else() {
        for ok in [
            "https://api.example.test",
            "https://api.example.test:8443",
            "http://127.0.0.1:9000",
            "http://localhost:9000",
            "http://[::1]:9000",
        ] {
            assert!(
                UpstreamConfig::new(Provider::Anthropic, ok, key()).is_ok(),
                "{ok}"
            );
        }
        for bad in [
            "api.example.test",
            "ftp://api.example.test",
            "https://",
            "https://api.example.test/v1",
            "https://user@api.example.test",
            "https://api.example.test?x=1",
            "https://api.example test",
            "https://api.example.test#frag",
        ] {
            assert_eq!(
                UpstreamConfig::new(Provider::Anthropic, bad, key()).unwrap_err(),
                StartError::BadBaseUrl,
                "{bad}"
            );
        }
    }

    #[test]
    fn the_real_key_is_never_sent_over_plain_http_to_another_machine() {
        for remote in [
            "http://api.example.test",
            "http://10.0.0.5:8000",
            "http://192.0.2.1",
        ] {
            assert_eq!(
                UpstreamConfig::new(Provider::OpenAi, remote, key()).unwrap_err(),
                StartError::PlainHttpToRemoteHost,
                "{remote}"
            );
        }
    }

    #[test]
    fn the_output_limit_is_clamped_set_or_left_alone() {
        let parse = |text: &str| -> Map<String, Value> {
            serde_json::from_str::<Value>(text)
                .expect("json")
                .as_object()
                .cloned()
                .expect("an object")
        };
        let mut over = parse(r#"{"model":"m","max_tokens":128000}"#);
        assert!(clamp_output_tokens(Provider::Anthropic, &mut over, 32_000));
        assert_eq!(over["max_tokens"], 32_000);
        let mut under = parse(r#"{"model":"m","max_tokens":100}"#);
        assert!(!clamp_output_tokens(
            Provider::Anthropic,
            &mut under,
            32_000
        ));
        assert_eq!(under["max_tokens"], 100);
        let mut none = parse(r#"{"model":"m"}"#);
        assert!(clamp_output_tokens(Provider::Anthropic, &mut none, 32_000));
        assert_eq!(none["max_tokens"], 32_000);
        let mut odd = parse(r#"{"model":"m","max_tokens":-5}"#);
        assert!(clamp_output_tokens(Provider::Anthropic, &mut odd, 32_000));
        assert_eq!(odd["max_tokens"], 32_000);
        let mut responses = parse(r#"{"model":"m","max_output_tokens":99999}"#);
        assert!(clamp_output_tokens(
            Provider::OpenAi,
            &mut responses,
            32_000
        ));
        assert_eq!(responses["max_output_tokens"], 32_000);
        let mut chat = parse(r#"{"model":"m","max_tokens":99999,"max_completion_tokens":5}"#);
        assert!(clamp_output_tokens(Provider::OpenAi, &mut chat, 32_000));
        assert_eq!(chat["max_tokens"], 32_000);
        assert_eq!(chat["max_completion_tokens"], 5);
    }

    #[test]
    fn model_names_are_plain() {
        assert!(model_name_ok("claude-test-model"));
        assert!(model_name_ok("vendor/model:tag.1"));
        assert!(!model_name_ok(""));
        assert!(!model_name_ok("a b"));
        assert!(!model_name_ok("a\nb"));
        assert!(!model_name_ok(&"x".repeat(201)));
    }

    #[test]
    fn header_names_are_written_in_the_usual_case() {
        assert_eq!(canonical("content-type"), "Content-Type");
        assert_eq!(canonical("x-request-id"), "X-Request-Id");
    }
}
