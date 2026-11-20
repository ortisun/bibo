//! The gateway's deployment configuration: where it listens, and how it reaches Datadog and
//! VictoriaMetrics. No value here is a secret; the credentials are files named here.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

/// The Datadog sites whose MCP Server is `https://mcp.<site>/v1/mcp`. US1 and EU1 are named in
/// ADR 0021 ("What was checked"); US3, US5, AP1 and AP2 are the other commercial sites the
/// Datadog page lists. GovCloud (`ddog-gov.com`) is not supported by the MCP Server.
pub const DATADOG_SITES: [&str; 6] = [
    "datadoghq.com",
    "datadoghq.eu",
    "us3.datadoghq.com",
    "us5.datadoghq.com",
    "ap1.datadoghq.com",
    "ap2.datadoghq.com",
];

/// The whole gateway configuration, a section of the troubleshooter's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// The address the gateway's MCP server listens on. A loopback address, unless
    /// `allow_non_loopback_listen` is set; never an unspecified address (`0.0.0.0`, `::`).
    pub listen: SocketAddr,
    /// Lets `listen` be an address that is not loopback, such as the Docker bridge address of a
    /// Linux host (`172.17.0.1`), where the troubleshooter sandbox's sidecar reaches the host the
    /// way the worker's sidecars reach the model broker. Every request still needs the run token.
    /// Default false.
    #[serde(default)]
    pub allow_non_loopback_listen: bool,
    /// `Host` header values accepted besides the loopback names, such as the alias under which
    /// the egress sidecar relays the agent to the gateway (`egress`, ADR 0021, decision 5). Host
    /// names, with or without a port; without one any port matches.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// The Datadog MCP Server, when the deployment uses Datadog.
    #[serde(default)]
    pub datadog: Option<DatadogConfig>,
    /// The VictoriaMetrics MCP server, when the deployment runs one.
    #[serde(default)]
    pub victoriametrics: Option<VictoriaMetricsConfig>,
}

/// How the gateway reaches the Datadog MCP Server.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatadogConfig {
    /// The Datadog site, such as `datadoghq.com` or `datadoghq.eu`. One of [`DATADOG_SITES`].
    pub site: String,
    /// The file holding the API key (`DD_API_KEY` header), mode 0600 or stricter.
    pub api_key_file: PathBuf,
    /// The file holding the application key (`DD_APPLICATION_KEY` header), mode 0600 or
    /// stricter. The key must hold `mcp_read` and no `mcp_write`.
    pub application_key_file: PathBuf,
}

/// How the gateway reaches `mcp-victoriametrics`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VictoriaMetricsConfig {
    /// The server's Streamable HTTP endpoint, such as `http://vm-mcp:8080/mcp`. No user, no
    /// password, no query.
    pub url: String,
    /// The file holding the bearer token (`MCP_AUTH_TOKEN` of the server), mode 0600 or
    /// stricter.
    pub token_file: PathBuf,
}

/// A configuration value the gateway refuses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The listen address is not loopback and the configuration does not allow that.
    #[error(
        "the gateway listen address {0} is not a loopback address; set allow_non_loopback_listen to serve on it (the run token is still required on every request)"
    )]
    NotLoopback(SocketAddr),
    /// The listen address is unspecified (`0.0.0.0` or `::`), multicast or broadcast: it would
    /// listen on every interface, or on none that a sidecar can reach.
    #[error(
        "the gateway listen address {0} names no single interface; name the loopback address or the one bridge address the sidecar reaches"
    )]
    NotOneInterface(SocketAddr),
    /// An allowed host is empty or holds characters a host name cannot.
    #[error("the allowed host {0:?} is not a host name")]
    BadAllowedHost(String),
    /// The Datadog site is GovCloud, which the Datadog MCP Server does not support.
    #[error("the Datadog site {0} (GovCloud) is not supported by the Datadog MCP Server")]
    DatadogGovCloud(String),
    /// The Datadog site is not a known site.
    #[error("the Datadog site {0:?} is not one of the known sites ({known})", known = DATADOG_SITES.join(", "))]
    UnknownDatadogSite(String),
    /// The VictoriaMetrics URL cannot be used.
    #[error("the VictoriaMetrics URL is not usable: {0}")]
    BadVictoriaMetricsUrl(&'static str),
}

impl GatewayConfig {
    /// Every rule of the configuration that does not need a file or the network.
    ///
    /// # Errors
    /// The first [`ConfigError`].
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_listen_address(self.listen, self.allow_non_loopback_listen)?;
        for host in &self.allowed_hosts {
            check_host(host)?;
        }
        if let Some(datadog) = &self.datadog {
            datadog_site(&datadog.site)?;
        }
        if let Some(vm) = &self.victoriametrics {
            check_victoriametrics_url(&vm.url)?;
        }
        Ok(())
    }
}

/// Refuses a listen address that is not loopback.
///
/// # Errors
/// [`ConfigError::NotOneInterface`] or [`ConfigError::NotLoopback`].
pub fn check_listen(address: SocketAddr) -> Result<(), ConfigError> {
    check_listen_address(address, false)
}

/// The gateway's listen rule, the same as the model broker's deployment needs: loopback by
/// default; an address that is not loopback only when `allow_non_loopback` says so; never an
/// unspecified, multicast or broadcast address.
///
/// # Errors
/// [`ConfigError::NotOneInterface`] or [`ConfigError::NotLoopback`].
pub fn check_listen_address(
    address: SocketAddr,
    allow_non_loopback: bool,
) -> Result<(), ConfigError> {
    let ip = address.ip();
    let broadcast = matches!(ip, std::net::IpAddr::V4(v4) if v4.is_broadcast());
    if ip.is_unspecified() || ip.is_multicast() || broadcast {
        return Err(ConfigError::NotOneInterface(address));
    }
    if ip.is_loopback() || allow_non_loopback {
        Ok(())
    } else {
        Err(ConfigError::NotLoopback(address))
    }
}

pub(crate) fn check_host(host: &str) -> Result<(), ConfigError> {
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b':'));
    if ok {
        Ok(())
    } else {
        Err(ConfigError::BadAllowedHost(host.to_owned()))
    }
}

/// The site, checked against [`DATADOG_SITES`].
///
/// # Errors
/// [`ConfigError::DatadogGovCloud`] or [`ConfigError::UnknownDatadogSite`].
pub fn datadog_site(site: &str) -> Result<&'static str, ConfigError> {
    let wanted = site.trim().to_ascii_lowercase();
    if wanted == "ddog-gov.com" {
        return Err(ConfigError::DatadogGovCloud(wanted));
    }
    DATADOG_SITES
        .iter()
        .find(|known| **known == wanted)
        .copied()
        .ok_or_else(|| ConfigError::UnknownDatadogSite(site.to_owned()))
}

/// The URL, checked: `http` or `https`, a host, no user or password, no query or fragment.
///
/// # Errors
/// [`ConfigError::BadVictoriaMetricsUrl`].
pub fn check_victoriametrics_url(url: &str) -> Result<reqwest::Url, ConfigError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| ConfigError::BadVictoriaMetricsUrl("it does not parse as a URL"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ConfigError::BadVictoriaMetricsUrl(
            "the scheme must be http or https",
        ));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(ConfigError::BadVictoriaMetricsUrl("it has no host"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ConfigError::BadVictoriaMetricsUrl(
            "it carries a user or a password; the token comes from token_file",
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(ConfigError::BadVictoriaMetricsUrl(
            "it carries a query or a fragment",
        ));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(json: &str) -> Result<GatewayConfig, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn a_full_configuration_parses_and_validates() {
        let parsed = config(
            r#"{
                "listen": "127.0.0.1:7811",
                "allowed_hosts": ["egress-sidecar"],
                "datadog": {"site": "datadoghq.eu", "api_key_file": "/run/secrets/dd_api",
                            "application_key_file": "/run/secrets/dd_app"},
                "victoriametrics": {"url": "http://vm-mcp:8080/mcp", "token_file": "/run/secrets/vm"}
            }"#,
        )
        .expect("parses");
        assert_eq!(parsed.validate(), Ok(()));
    }

    #[test]
    fn unknown_keys_are_refused() {
        assert!(config(r#"{"listen": "127.0.0.1:1", "extra": 1}"#).is_err());
        assert!(
            config(
                r#"{"listen": "127.0.0.1:1", "datadog": {"site": "datadoghq.com",
                "api_key_file": "a", "application_key_file": "b", "api_key": "inline"}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn a_non_loopback_listen_address_needs_the_flag_and_an_unspecified_one_is_never_taken() {
        for address in ["10.0.0.5:7811", "172.17.0.1:9444", "[fd00::5]:7811"] {
            let parsed = config(&format!(r#"{{"listen": "{address}"}}"#)).expect("parses");
            assert!(
                matches!(parsed.validate(), Err(ConfigError::NotLoopback(_))),
                "{address}"
            );
            let allowed = config(&format!(
                r#"{{"listen": "{address}", "allow_non_loopback_listen": true}}"#
            ))
            .expect("parses");
            assert_eq!(allowed.validate(), Ok(()), "{address}");
        }
        for address in [
            "0.0.0.0:7811",
            "[::]:7811",
            "255.255.255.255:7811",
            "224.0.0.1:7811",
        ] {
            for flag in [false, true] {
                let parsed = config(&format!(
                    r#"{{"listen": "{address}", "allow_non_loopback_listen": {flag}}}"#
                ))
                .expect("parses");
                assert!(
                    matches!(parsed.validate(), Err(ConfigError::NotOneInterface(_))),
                    "{address} {flag}"
                );
            }
        }
        let parsed = config(r#"{"listen": "[::1]:7811"}"#).expect("parses");
        assert_eq!(parsed.validate(), Ok(()));
        assert!(matches!(
            check_listen("172.17.0.1:9444".parse().expect("address")),
            Err(ConfigError::NotLoopback(_))
        ));
    }

    #[test]
    fn datadog_sites_are_checked() {
        assert_eq!(datadog_site("datadoghq.com"), Ok("datadoghq.com"));
        assert_eq!(datadog_site("US5.datadoghq.com"), Ok("us5.datadoghq.com"));
        assert!(matches!(
            datadog_site("ddog-gov.com"),
            Err(ConfigError::DatadogGovCloud(_))
        ));
        for bad in [
            "",
            "evil.example",
            "datadoghq.com/../x",
            "mcp.datadoghq.com",
        ] {
            assert!(
                matches!(datadog_site(bad), Err(ConfigError::UnknownDatadogSite(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn victoriametrics_urls_are_checked() {
        assert!(check_victoriametrics_url("https://vm.internal/mcp").is_ok());
        for bad in [
            "ftp://vm/mcp",
            "http://someone@vm/mcp",
            "http://vm/mcp?token=x",
            "not a url",
        ] {
            assert!(check_victoriametrics_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn allowed_hosts_must_be_host_names() {
        let parsed =
            config(r#"{"listen": "127.0.0.1:1", "allowed_hosts": ["a b"]}"#).expect("parses");
        assert!(matches!(
            parsed.validate(),
            Err(ConfigError::BadAllowedHost(_))
        ));
    }
}
