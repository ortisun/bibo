//! Upstreams reached over Streamable HTTP: the Datadog MCP Server and `mcp-victoriametrics`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use factory_domain::policy::troubleshooting::DatadogNarrowing;
use reqwest::header::{HeaderName, HeaderValue};
use rmcp::ServiceExt;
use rmcp::model::{CallToolResult, JsonObject, Tool};
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;

use crate::config::{
    ConfigError, DatadogConfig, VictoriaMetricsConfig, check_victoriametrics_url, datadog_site,
};
use crate::secret::{CredentialError, SecretValue, read_secret_file};
use crate::upstream::{BoxFuture, ClientSession, Upstream, UpstreamError, UpstreamId};

/// An upstream could not be set up from the configuration.
#[derive(Debug, thiserror::Error)]
pub enum HttpUpstreamError {
    /// A configuration value is refused.
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// A credential file is refused.
    #[error(transparent)]
    Credential(#[from] CredentialError),
    /// The HTTP client could not be built.
    #[error("the HTTP client for the upstream {} could not be built", .0.as_str())]
    Client(UpstreamId),
}

/// The largest JSON response read from an upstream. The gateway cuts results far below this; the
/// cap only keeps a broken upstream from filling memory.
const MAX_UPSTREAM_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// An MCP server reached with the Streamable HTTP client, with fixed headers whose values come
/// from credential files. `Debug` shows the upstream and the URL, never a header value.
pub struct HttpUpstream {
    id: UpstreamId,
    url: reqwest::Url,
    client: reqwest::Client,
    headers: HashMap<HeaderName, HeaderValue>,
    bearer: Option<SecretValue>,
    credentials: Vec<(&'static str, SecretValue)>,
    session: ClientSession,
    connect_timeout: Duration,
}

impl std::fmt::Debug for HttpUpstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpUpstream")
            .field("id", &self.id)
            .field("url", &self.url.as_str())
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("bearer", &self.bearer.as_ref().map(|_| "<redacted>"))
            .finish_non_exhaustive()
    }
}

/// The URL of the Datadog MCP Server for a site, with the policy's narrowing:
/// `https://mcp.<site>/v1/mcp?toolsets=<a,b>&omit_tools=<x,y>`.
///
/// # Errors
/// [`ConfigError`] for a site that is not known.
pub fn datadog_url(site: &str, narrowing: &DatadogNarrowing) -> Result<reqwest::Url, ConfigError> {
    let site = datadog_site(site)?;
    let mut url = reqwest::Url::parse(&format!("https://mcp.{site}/v1/mcp"))
        .map_err(|_| ConfigError::UnknownDatadogSite(site.to_owned()))?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("toolsets", &narrowing.toolsets.join(","));
        if !narrowing.omit_tools.is_empty() {
            query.append_pair("omit_tools", &narrowing.omit_tools.join(","));
        }
    }
    Ok(url)
}

impl HttpUpstream {
    /// The Datadog MCP Server of the configured site, with `toolsets` and `omit_tools` from the
    /// policy and the `DD_API_KEY` and `DD_APPLICATION_KEY` headers read from their files.
    ///
    /// # Errors
    /// [`HttpUpstreamError`] naming the setting or the file, never a credential.
    pub fn datadog(
        config: &DatadogConfig,
        narrowing: &DatadogNarrowing,
    ) -> Result<Self, HttpUpstreamError> {
        let url = datadog_url(&config.site, narrowing)?;
        let api_key = read_secret_file(&config.api_key_file, "Datadog API key")?;
        let app_key = read_secret_file(&config.application_key_file, "Datadog application key")?;
        let headers = HashMap::from([
            (
                HeaderName::from_static("dd_api_key"),
                sensitive(&api_key, &config.api_key_file, "Datadog API key")?,
            ),
            (
                HeaderName::from_static("dd_application_key"),
                sensitive(
                    &app_key,
                    &config.application_key_file,
                    "Datadog application key",
                )?,
            ),
        ]);
        Self::build(
            UpstreamId::Datadog,
            url,
            headers,
            None,
            vec![
                ("datadog_api_key", api_key),
                ("datadog_application_key", app_key),
            ],
        )
    }

    /// `mcp-victoriametrics` at the configured URL, with `Authorization: Bearer` read from its
    /// file. The policy's disabled tools are set on the server by the deployment
    /// (`MCP_DISABLED_TOOLS`); the gateway allowlist applies whatever the server offers.
    ///
    /// # Errors
    /// [`HttpUpstreamError`] naming the setting or the file, never a credential.
    pub fn victoriametrics(config: &VictoriaMetricsConfig) -> Result<Self, HttpUpstreamError> {
        let url = check_victoriametrics_url(&config.url)?;
        let token = read_secret_file(&config.token_file, "VictoriaMetrics MCP token")?;
        Self::build(
            UpstreamId::Victoriametrics,
            url,
            HashMap::new(),
            Some(token.clone()),
            vec![("victoriametrics_mcp_token", token)],
        )
    }

    /// An upstream at any `http` or `https` URL with the given headers and bearer token, for the
    /// app's own wiring and for tests. The headers' values should be marked sensitive.
    ///
    /// # Errors
    /// [`HttpUpstreamError::Client`] when the HTTP client cannot be built.
    pub fn custom(
        id: UpstreamId,
        url: reqwest::Url,
        headers: HashMap<HeaderName, HeaderValue>,
        bearer: Option<SecretValue>,
        credentials: Vec<(&'static str, SecretValue)>,
    ) -> Result<Self, HttpUpstreamError> {
        Self::build(id, url, headers, bearer, credentials)
    }

    fn build(
        id: UpstreamId,
        url: reqwest::Url,
        headers: HashMap<HeaderName, HeaderValue>,
        bearer: Option<SecretValue>,
        credentials: Vec<(&'static str, SecretValue)>,
    ) -> Result<Self, HttpUpstreamError> {
        Ok(Self {
            id,
            url,
            client: http_client().map_err(|()| HttpUpstreamError::Client(id))?,
            headers,
            bearer,
            credentials,
            session: ClientSession::new(id),
            connect_timeout: Duration::from_secs(20),
        })
    }

    /// The URL the upstream is reached at. It carries no credential.
    #[must_use]
    pub fn url(&self) -> &reqwest::Url {
        &self.url
    }
}

fn sensitive(
    value: &SecretValue,
    path: &std::path::Path,
    what: &'static str,
) -> Result<HeaderValue, CredentialError> {
    let mut header =
        HeaderValue::from_str(value.expose()).map_err(|_| CredentialError::NotAHeaderValue {
            what,
            path: path.to_path_buf(),
        })?;
    header.set_sensitive(true);
    Ok(header)
}

/// A reqwest client with rustls over ring and the Mozilla roots (the TLS stack of the other HTTP
/// clients of the factory), no redirects (a redirect could carry the headers elsewhere), and no
/// proxy from the environment.
fn http_client() -> Result<reqwest::Client, ()> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| ())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| ())
}

impl Upstream for HttpUpstream {
    fn id(&self) -> UpstreamId {
        self.id
    }

    fn credentials(&self) -> Vec<(&'static str, SecretValue)> {
        self.credentials.clone()
    }

    fn connect(&self) -> BoxFuture<'_, Result<(), UpstreamError>> {
        Box::pin(async move {
            let mut config = StreamableHttpClientTransportConfig::with_uri(self.url.as_str())
                .custom_headers(self.headers.clone())
                .max_json_response_size(MAX_UPSTREAM_RESPONSE_BYTES);
            if let Some(bearer) = &self.bearer {
                config = config.auth_header(bearer.expose());
            }
            let transport = StreamableHttpClientTransport::with_client(self.client.clone(), config);
            let running = tokio::time::timeout(self.connect_timeout, ().serve(transport))
                .await
                .map_err(|_| UpstreamError::Connect(self.id))?
                .map_err(|_| UpstreamError::Connect(self.id))?;
            self.session.install(running);
            Ok(())
        })
    }

    fn list_tools(&self) -> BoxFuture<'_, Result<Vec<Tool>, UpstreamError>> {
        Box::pin(self.session.list_tools())
    }

    fn call_tool(
        &self,
        name: String,
        arguments: Option<JsonObject>,
    ) -> BoxFuture<'_, Result<CallToolResult, UpstreamError>> {
        Box::pin(self.session.call_tool(name, arguments))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn narrowing() -> DatadogNarrowing {
        serde_json::from_value(serde_json::json!({
            "toolsets": ["core"],
            "omit_tools": ["create_datadog_notebook", "edit_datadog_notebook"],
        }))
        .expect("narrowing")
    }

    #[test]
    fn the_datadog_url_carries_the_site_and_the_narrowing() {
        let url = datadog_url("datadoghq.eu", &narrowing()).expect("url");
        assert_eq!(
            url.as_str(),
            "https://mcp.datadoghq.eu/v1/mcp?toolsets=core&omit_tools=create_datadog_notebook%2Cedit_datadog_notebook"
        );
        assert!(datadog_url("ddog-gov.com", &narrowing()).is_err());
        assert!(datadog_url("example.com", &narrowing()).is_err());
    }

    #[test]
    fn the_tls_client_builds() {
        assert!(http_client().is_ok());
    }
}
