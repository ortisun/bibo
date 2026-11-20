//! The troubleshooter's MCP gateway (ADR 0021, decision 3).
//!
//! One MCP server, in the troubleshooter process, that the troubleshooter agent reaches as its
//! only MCP server. The gateway is the only place that:
//!
//! - **holds credentials.** The Datadog keys and the VictoriaMetrics token are read from files
//!   of mode 0600 or stricter ([`read_secret_file`]), sent only as fixed headers to their
//!   upstream, and registered with the redactor by exact value. They never appear in a `Debug`
//!   output, an error, or the call record.
//! - **decides which tools exist.** The agent sees exactly the tools of the policy's allowlist
//!   (`tools` of `policies/troubleshooting.yaml`) that their upstream offers, under the gateway
//!   name, with the upstream's description and input schema. An upstream tool that is not on the
//!   allowlist is never listed or callable, and is reported ([`CatalogReport::not_allowed`],
//!   reason [`UPSTREAM_TOOL_NOT_ALLOWED`], threat T-51).
//! - **checks a run token.** [`Gateway::open_run`] returns a random 256-bit token for one run;
//!   it stops working at [`Gateway::close_run`] or when the run's wall clock ends. Every HTTP
//!   request without a valid token gets 401.
//! - **limits.** Calls per run and per 10 seconds (agent calls), a deadline per call, a cap on
//!   result bytes with a truncation marker that says how much was cut, and the run's wall clock.
//!   A refused call is a tool error with a short reason, never a transport failure.
//! - **redacts** every result through the injected [`Redact`] seam before anyone sees it.
//! - **records** every call ([`CallRecord`]): run, `call-N` id, tools, upstream, argument digest,
//!   start, duration, bytes, outcome. The record of a run ([`RunRecord`]) is a typed value and
//!   canonical JSON for the ledger. The troubleshooter's own probes call through
//!   [`Gateway::call_for_run`] and are recorded in the same run with the same ids, so a probe
//!   value can be cited like an agent call.
//!
//! Upstreams are behind the [`Upstream`] trait: [`HttpUpstream`] for Datadog and
//! VictoriaMetrics (Streamable HTTP client), and [`InProcessUpstream`] for an rmcp server of this
//! process (the troubleshooter plugs in the read-only PostgreSQL server this way; this crate does
//! not depend on it).
//!
//! # Use
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use factory_mcp_gateway::*;
//! # async fn example(
//! #     policy: factory_domain::policy::troubleshooting::TroubleshootingPolicy,
//! #     config: GatewayConfig,
//! #     redactor: Arc<dyn Redact>,
//! #     postgres: Arc<dyn Upstream>,
//! # ) -> Result<(), Box<dyn std::error::Error>> {
//! config.validate()?;
//! let mut builder = Gateway::builder(&policy, redactor).upstream(postgres);
//! if let Some(datadog) = &config.datadog {
//!     builder = builder.upstream(Arc::new(HttpUpstream::datadog(datadog, &policy.upstreams.datadog)?));
//! }
//! let gateway = builder.build()?;
//! let report = gateway.connect().await; // report.not_allowed and report.missing become findings
//! let server = gateway.serve(config.listen, &config.allowed_hosts).await?;
//! let token = gateway.open_run("run-1", gateway.policy_limits())?;
//! // ... the probes call gateway.call_for_run("run-1", "vm_query", args), the agent runs ...
//! let record = gateway.close_run("run-1").await?;
//! let ledger_digest = record.digest()?;
//! # let _ = (server, token, report, ledger_digest);
//! # Ok(())
//! # }
//! ```

mod config;
mod gateway;
mod http_upstream;
mod record;
mod redact;
mod secret;
mod server;
mod upstream;

pub use config::{
    ConfigError, DATADOG_SITES, DatadogConfig, GatewayConfig, VictoriaMetricsConfig, check_listen,
};
pub use gateway::{
    CallResult, CatalogReport, Gateway, GatewayBuilder, GatewayError, MAX_RECORDED_CALLS,
    MissingReason, MissingTool, ToolMapping, UPSTREAM_TOOL_NOT_ALLOWED, UpstreamTool,
};
pub use http_upstream::{HttpUpstream, HttpUpstreamError, datadog_url};
pub use record::{
    CallId, CallOrigin, CallRecord, MIN_RESULT_BYTES, Outcome, RecordEncodingFailed, RefusalReason,
    RunLimits, RunRecord,
};
pub use redact::{
    FactoryRedactor, Redact, RedactionFailed, RegisterFailed, SecretKey, redact_json,
};
pub use secret::{CredentialError, RunToken, SecretValue, read_secret_file};
pub use server::GatewayServer;
pub use upstream::{BoxFuture, InProcessUpstream, Upstream, UpstreamError, UpstreamId};
