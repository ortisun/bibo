//! The troubleshooter's configuration file (YAML, read with the composition library's restricted
//! reader: no anchors, no tags, no URL with a password, unknown keys refused).
//!
//! Sections are the shared ones where a shared one exists: `gateway` is `mcp_gateway`'s
//! `GatewayConfig` (loopback listen, Datadog and VictoriaMetrics, each optional), and `store`,
//! `broker`, `sandbox`, `artifacts`, `github`, `runtimes` and `telemetry` are the worker's
//! sections from `factory_composition::config`. Every secret is a file: the store's URL, the
//! observer's password, the upstream credentials, the provider key, the GitHub App key.

use std::path::PathBuf;

use factory_composition::config::{
    ArtifactsConfig, BrokerConfig, ConfigError, GithubConfig, PoolConfig, RuntimesConfig,
    SandboxConfig, TelemetryConfig, read_document,
};
use factory_composition::profile::Profile;
use factory_domain::ids::TenantId;
use factory_mcp_gateway::GatewayConfig;
use factory_ports::paths::RepoRef;
use serde::Deserialize;

/// The read-only login of the PostgreSQL MCP server: a member of `factory_observer` only.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverConfig {
    /// The database host.
    pub host: String,
    /// The port.
    #[serde(default = "default_port")]
    pub port: u16,
    /// The database name.
    pub database: String,
    /// The login, such as `factory_troubleshooter`.
    pub user: String,
    /// The file that holds its password, mode 0600 or stricter.
    pub password_file: PathBuf,
}

const fn default_port() -> u16 {
    5432
}

const fn default_health_timeout() -> u64 {
    5
}

/// The whole configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TroubleshooterConfig {
    /// `production`, `local` or `test`.
    pub profile: Profile,
    /// The protected checkout the policies and the agent definitions are read from.
    pub protected_checkout: PathBuf,
    /// The tenant whose rows the troubleshooter writes and whose GitHub installation covers the
    /// issue repository, as a UUID.
    pub tenant: String,
    /// The one repository triage issues go to, `owner/name` (by default the factory's own).
    pub issue_repository: String,
    /// The base URL of the factory API, for the `http_health` probes, such as
    /// `http://127.0.0.1:8080`.
    pub api_health_url: String,
    /// How long a health probe waits, in seconds.
    #[serde(default = "default_health_timeout")]
    pub api_health_timeout_s: u64,
    /// The troubleshooter's own rows: a login that is a member of `factory_app` only.
    pub store: PoolConfig,
    /// The read-only login of the PostgreSQL MCP server.
    pub observer: ObserverConfig,
    /// The MCP gateway.
    pub gateway: GatewayConfig,
    /// The model broker the troubleshooter hosts for its own runs.
    pub broker: BrokerConfig,
    /// The sandbox (the troubleshooter profile needs `gateway_upstream`).
    pub sandbox: SandboxConfig,
    /// Where transcripts are kept.
    pub artifacts: ArtifactsConfig,
    /// The GitHub App, with an installation for the issue repository.
    pub github: GithubConfig,
    /// The agent tool.
    #[serde(default)]
    pub runtimes: RuntimesConfig,
    /// Telemetry.
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

impl TroubleshooterConfig {
    /// Reads a configuration file.
    ///
    /// # Errors
    /// A [`ConfigError`] naming the problem.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|_| ConfigError::Unreadable(path.display().to_string()))?;
        read_document(&text)
    }

    /// The tenant.
    ///
    /// # Errors
    /// The value is not a UUID.
    pub fn tenant(&self) -> Result<TenantId, String> {
        self.tenant
            .parse::<uuid::Uuid>()
            .map(TenantId::from_uuid)
            .map_err(|_| "tenant: is not a UUID".to_owned())
    }

    /// The issue repository.
    ///
    /// # Errors
    /// The value is not `owner/name`.
    pub fn issue_repository(&self) -> Result<RepoRef, String> {
        RepoRef::parse(&self.issue_repository)
            .map_err(|_| "issue_repository: is not owner/name".to_owned())
    }

    /// Every rule that needs no file and no network, each broken one a line that starts with the
    /// key to change.
    ///
    /// # Errors
    /// The lines.
    pub fn check(&self) -> Result<(), Vec<String>> {
        let mut problems = Vec::new();
        if let Err(error) = self.gateway.validate() {
            problems.push(format!("gateway: {error}"));
        }
        if let Err(why) = self.tenant() {
            problems.push(why);
        }
        if let Err(why) = self.issue_repository() {
            problems.push(why);
        }
        let url = self.api_health_url.as_str();
        let plain_loopback = url.starts_with("http://127.0.0.1")
            || url.starts_with("http://localhost")
            || url.starts_with("http://[::1]");
        let allowed = url.starts_with("https://")
            || (plain_loopback && self.profile != Profile::Production)
            || (url.starts_with("http://") && self.profile != Profile::Production);
        if !allowed {
            problems.push(
                "api_health_url: must be https, or http outside the production profile".to_owned(),
            );
        }
        if !(1..=60).contains(&self.api_health_timeout_s) {
            problems.push("api_health_timeout_s: must be 1 to 60 seconds".to_owned());
        }
        if self.sandbox.gateway_upstream.is_none() {
            problems.push(
                "sandbox.gateway_upstream: the troubleshooter sandbox needs the gateway's address for its sidecar"
                    .to_owned(),
            );
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(problems)
        }
    }
}
