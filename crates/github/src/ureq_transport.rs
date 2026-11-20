//! The transport used outside the unit tests: `ureq` over rustls (ring) and the Mozilla roots.
//!
//! `ureq` is blocking, so each request runs under `tokio::task::spawn_blocking` and the future the
//! caller holds can be dropped safely (the blocking call finishes on its own and its answer is
//! discarded). The agent is built to be safe for a bearer token:
//!
//! * redirects are off (a `Location` on another host would otherwise receive the token),
//! * environment proxies are off,
//! * HTTPS only, unless the base is a loopback base made for the tests,
//! * a 30 second timeout over the whole call, and a 4 MiB limit on the response body.

use std::time::Duration;

use async_trait::async_trait;
use ureq::http;

use crate::wire::{ApiBase, Method, Transport, TransportError, WireRequest, WireResponse};

/// The timeout over a whole call (`ChangeHost` and `IssueSource`, "Cancellation and timeouts").
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest response body read. GitHub's answers the adapter reads are far smaller.
pub const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

/// A [`Transport`] backed by `ureq`.
#[derive(Clone)]
pub struct UreqTransport {
    base: ApiBase,
    agent: ureq::Agent,
}

impl std::fmt::Debug for UreqTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UreqTransport")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl UreqTransport {
    /// A transport for the base URL. TLS is used for an `https` base; a plain `http` base exists
    /// only for the loopback tests (see [`ApiBase::loopback_for_tests`]).
    #[must_use]
    pub fn new(base: ApiBase) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .https_only(!base.is_plain_http())
            .max_redirects(0)
            .proxy(None)
            .timeout_global(Some(REQUEST_TIMEOUT))
            .user_agent("factory-github-adapter")
            .build()
            .into();
        Self { base, agent }
    }

    /// The base URL.
    #[must_use]
    pub fn base(&self) -> &ApiBase {
        &self.base
    }

    fn send_blocking(
        agent: &ureq::Agent,
        url: &str,
        request: &WireRequest,
    ) -> Result<WireResponse, TransportError> {
        let method = match request.method {
            Method::Get => http::Method::GET,
            Method::Post => http::Method::POST,
            Method::Patch => http::Method::PATCH,
            Method::Delete => http::Method::DELETE,
        };
        let mut builder = http::Request::builder().method(method).uri(url);
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let prepared = builder
            .body(request.body.clone())
            .map_err(|_| TransportError::Protocol)?;
        let mut response = agent.run(prepared).map_err(map_error)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_ascii_lowercase(), v.to_owned()))
            })
            .collect();
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_vec()
            .map_err(map_error)?;
        Ok(WireResponse {
            status,
            headers,
            body,
        })
    }
}

fn map_error(error: ureq::Error) -> TransportError {
    match error {
        ureq::Error::Timeout(_) => TransportError::Timeout,
        ureq::Error::Io(_) | ureq::Error::ConnectionFailed | ureq::Error::HostNotFound => {
            TransportError::Connect
        }
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) | ureq::Error::TlsRequired => {
            TransportError::Connect
        }
        _ => TransportError::Protocol,
    }
}

#[async_trait]
impl Transport for UreqTransport {
    async fn execute(&self, request: WireRequest) -> Result<WireResponse, TransportError> {
        if !request.target.starts_with('/') {
            return Err(TransportError::Protocol);
        }
        let url = format!("{}{}", self.base.as_str(), request.target);
        let agent = self.agent.clone();
        tokio::task::spawn_blocking(move || Self::send_blocking(&agent, &url, &request))
            .await
            .map_err(|_| TransportError::Connect)?
    }
}
