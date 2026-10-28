//! The typed configuration of the API.
//!
//! One YAML file named by `FACTORY_CONFIG`, read with the restricted reader and decoded with
//! `deny_unknown_fields` (`factory_composition::config::read_document`), so a misspelled setting is
//! an error and not a weaker run. The same rules as the worker's: no default for the profile, the
//! API login or the protected checkout; a secret is the path of a file that only its owner may
//! read; the environment may repeat the profile and may replace the log filter, and cannot widen
//! anything.
//!
//! The API has one database pool, under `database.api`: its login belongs to `factory_api_app` and
//! `factory_resolver` and to nothing else. It has no system pool.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use factory_composition::config::{
    ArtifactsConfig, ConfigError, PoolConfig, SecretFile, TelemetryConfig, read_document,
};
use factory_composition::profile::Profile;
use serde::Deserialize;

/// The database section: the one login of the API.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiDatabase {
    /// The API pool. A member of `factory_api_app` and `factory_resolver`.
    pub api: PoolConfig,
}

/// GitHub-facing settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubSettings {
    /// One file for each webhook secret in the rotation window. Production needs at least one.
    #[serde(default)]
    pub webhook_secret_files: Vec<SecretFile>,
    /// The label whose application starts a job. FR-001.
    #[serde(default = "default_label")]
    pub factory_label: String,
}

fn default_label() -> String {
    "factory".to_owned()
}

impl Default for GithubSettings {
    fn default() -> Self {
        Self {
            webhook_secret_files: Vec::new(),
            factory_label: default_label(),
        }
    }
}

/// Token settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenSettings {
    /// The audience this API serves. A token issued for another audience is unknown.
    #[serde(default = "default_audience")]
    pub audience: String,
}

fn default_audience() -> String {
    "factory-api".to_owned()
}

impl Default for TokenSettings {
    fn default() -> Self {
        Self {
            audience: default_audience(),
        }
    }
}

/// Limits on what one request and one source may cost.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// The largest body of an ordinary request, in bytes. The webhook has its own limit, the
    /// verifier's.
    #[serde(default = "default_body")]
    pub max_body_bytes: usize,
    /// How long a client may take to send the headers of a request.
    #[serde(default = "default_header_ms")]
    pub header_timeout_ms: u64,
    /// How long a client may take to send the body once the headers are in.
    #[serde(default = "default_body_ms")]
    pub body_timeout_ms: u64,
    /// How long one request may take in all.
    #[serde(default = "default_request_ms")]
    pub request_timeout_ms: u64,
    /// The most connections open at once.
    #[serde(default = "default_connections")]
    pub max_connections: usize,
    /// How long a stop request lets open requests finish.
    #[serde(default = "default_drain_s")]
    pub drain_s: u64,
    /// Requests allowed per source address per minute (the TCP peer, never a forwarded header).
    #[serde(default = "default_per_ip")]
    pub per_ip_per_minute: u32,
    /// Webhook deliveries allowed per installation per minute (`policies/security.yaml`,
    /// `webhook.rate_limit`).
    #[serde(default = "default_per_installation")]
    pub webhook_per_installation_per_minute: u32,
}

const fn default_body() -> usize {
    256 * 1024
}
const fn default_header_ms() -> u64 {
    10_000
}
const fn default_body_ms() -> u64 {
    10_000
}
const fn default_request_ms() -> u64 {
    30_000
}
const fn default_connections() -> usize {
    256
}
const fn default_drain_s() -> u64 {
    15
}
const fn default_per_ip() -> u32 {
    600
}
const fn default_per_installation() -> u32 {
    120
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: default_body(),
            header_timeout_ms: default_header_ms(),
            body_timeout_ms: default_body_ms(),
            request_timeout_ms: default_request_ms(),
            max_connections: default_connections(),
            drain_s: default_drain_s(),
            per_ip_per_minute: default_per_ip(),
            webhook_per_installation_per_minute: default_per_installation(),
        }
    }
}

impl Limits {
    /// The header read timeout.
    #[must_use]
    pub const fn header_timeout(&self) -> Duration {
        Duration::from_millis(self.header_timeout_ms)
    }

    /// The body read timeout.
    #[must_use]
    pub const fn body_timeout(&self) -> Duration {
        Duration::from_millis(self.body_timeout_ms)
    }

    /// The whole-request timeout.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    /// The drain budget.
    #[must_use]
    pub const fn drain(&self) -> Duration {
        Duration::from_secs(self.drain_s)
    }
}

/// The whole configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// The profile. No default.
    pub profile: Profile,
    /// The checkout of the protected configuration branch: `policies/` and `allowlist/`.
    pub protected_checkout: PathBuf,
    /// The database.
    pub database: ApiDatabase,
    /// Where the server binds. The deployment publishes it to loopback or to a proxy.
    pub listen: SocketAddr,
    /// Accepted so that the local stack's file, which mounts the artifact volume, parses. This
    /// part of the API does not read artifacts.
    #[serde(default)]
    pub artifacts: Option<ArtifactsConfig>,
    /// GitHub-facing settings.
    #[serde(default)]
    pub github: GithubSettings,
    /// Tokens.
    #[serde(default)]
    pub tokens: TokenSettings,
    /// Limits.
    #[serde(default)]
    pub limits: Limits,
    /// Telemetry.
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

impl ApiConfig {
    /// Reads a configuration from text.
    ///
    /// # Errors
    /// A [`ConfigError`].
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        let config: Self = read_document(text)?;
        config.validate()?;
        Ok(config)
    }

    /// Reads the file at `path`.
    ///
    /// # Errors
    /// A [`ConfigError`].
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|_| ConfigError::Unreadable(path.display().to_string()))?;
        Self::from_yaml(&text)
    }

    /// Reads the file that `FACTORY_CONFIG` names and applies the environment's tightenings.
    ///
    /// # Errors
    /// A [`ConfigError`], also when `FACTORY_CONFIG` is not set or `FACTORY_PROFILE` disagrees.
    pub fn from_environment(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let path = lookup("FACTORY_CONFIG").ok_or(ConfigError::OutOfRange {
            field: "FACTORY_CONFIG",
            problem: "is not set; there is no default configuration file",
        })?;
        let mut config = Self::from_file(Path::new(&path))?;
        if let Some(named) = lookup("FACTORY_PROFILE")
            && named != config.profile.name()
        {
            return Err(ConfigError::ProfileMismatch {
                environment: named,
                file: config.profile.name(),
            });
        }
        if let Some(filter) = lookup("FACTORY_LOG") {
            config.telemetry.log_filter = Some(filter);
        }
        Ok(config)
    }

    /// Checks the rules that need no file other than this one.
    ///
    /// # Errors
    /// A [`ConfigError`].
    pub fn validate(&self) -> Result<(), ConfigError> {
        let out_of_range = |field, problem| Err(ConfigError::OutOfRange { field, problem });
        if self.database.api.login.is_empty() {
            return out_of_range("database.api.login", "must name a role");
        }
        if self.database.api.max_connections == 0 || self.database.api.max_connections > 256 {
            return out_of_range("database.api.max_connections", "must be between 1 and 256");
        }
        if !self.protected_checkout.is_absolute() {
            return out_of_range("protected_checkout", "must be an absolute path");
        }
        if self.profile == Profile::Production && self.github.webhook_secret_files.is_empty() {
            return out_of_range(
                "github.webhook_secret_files",
                "the production profile needs at least one webhook secret",
            );
        }
        let label = &self.github.factory_label;
        if label.is_empty() || label.len() > 50 || label.chars().any(char::is_control) {
            return out_of_range(
                "github.factory_label",
                "must be 1 to 50 printable characters",
            );
        }
        let audience = &self.tokens.audience;
        let audience_ok = !audience.is_empty()
            && audience.len() <= 64
            && audience.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            });
        if !audience_ok {
            return out_of_range(
                "tokens.audience",
                "must be a lower-case slug of at most 64 characters",
            );
        }
        let limits = &self.limits;
        if limits.max_body_bytes == 0 || limits.max_body_bytes > 4 * 1024 * 1024 {
            return out_of_range("limits.max_body_bytes", "must be between 1 and 4 MiB");
        }
        if limits.max_connections == 0 || limits.max_connections > 65_536 {
            return out_of_range("limits.max_connections", "must be between 1 and 65536");
        }
        for (field, value) in [
            ("limits.header_timeout_ms", limits.header_timeout_ms),
            ("limits.body_timeout_ms", limits.body_timeout_ms),
            ("limits.request_timeout_ms", limits.request_timeout_ms),
        ] {
            if value == 0 || value > 300_000 {
                return out_of_range(field, "must be between 1 ms and 300 s");
            }
        }
        if limits.per_ip_per_minute == 0 || limits.webhook_per_installation_per_minute == 0 {
            return out_of_range("limits", "a rate limit of zero would refuse every request");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal(profile: &str) -> String {
        format!(
            "profile: {profile}\n\
             protected_checkout: /srv/protected\n\
             database:\n  api: {{ url_file: /run/secrets/db_api, login: factory_api }}\n\
             listen: 127.0.0.1:8080\n"
        )
    }

    #[test]
    fn a_minimal_local_file_loads_with_safe_defaults() {
        let config = ApiConfig::from_yaml(&minimal("local")).expect("loads");
        assert_eq!(config.profile, Profile::Local);
        assert_eq!(config.tokens.audience, "factory-api");
        assert_eq!(config.limits.max_body_bytes, 256 * 1024);
        assert_eq!(config.github.factory_label, "factory");
    }

    #[test]
    fn production_needs_a_webhook_secret() {
        let refused = ApiConfig::from_yaml(&minimal("production")).unwrap_err();
        assert!(matches!(
            refused,
            ConfigError::OutOfRange {
                field: "github.webhook_secret_files",
                ..
            }
        ));
        let with_secret = format!(
            "{}github: {{ webhook_secret_files: [/run/secrets/webhook] }}\n",
            minimal("production")
        );
        assert!(ApiConfig::from_yaml(&with_secret).is_ok());
    }

    #[test]
    fn an_unknown_field_is_refused_so_a_typo_cannot_weaken_a_setting() {
        let text = format!("{}limits: {{ max_body_byte: 10 }}\n", minimal("local"));
        assert!(matches!(
            ApiConfig::from_yaml(&text),
            Err(ConfigError::Invalid(_))
        ));
        let worker_shaped = format!("{}broker: {{ listen: '127.0.0.1:1' }}\n", minimal("local"));
        assert!(ApiConfig::from_yaml(&worker_shaped).is_err());
    }

    #[test]
    fn a_file_without_a_profile_or_without_the_api_login_is_refused() {
        let no_profile = minimal("local").replacen("profile: local\n", "", 1);
        assert!(ApiConfig::from_yaml(&no_profile).is_err());
        let no_login = minimal("local").replace(
            "database:\n  api: { url_file: /run/secrets/db_api, login: factory_api }\n",
            "",
        );
        assert!(ApiConfig::from_yaml(&no_login).is_err());
    }

    #[test]
    fn the_limits_have_floors_and_ceilings() {
        for bad in [
            "limits: { max_body_bytes: 0 }",
            "limits: { max_body_bytes: 99999999 }",
            "limits: { header_timeout_ms: 0 }",
            "limits: { request_timeout_ms: 999999999 }",
            "limits: { per_ip_per_minute: 0 }",
            "tokens: { audience: 'Has Space' }",
            "github: { factory_label: '' }",
        ] {
            let text = format!("{}{bad}\n", minimal("local"));
            assert!(ApiConfig::from_yaml(&text).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_relative_checkout_and_an_inline_credential_are_refused() {
        let relative = minimal("local").replace("/srv/protected", "protected");
        assert!(ApiConfig::from_yaml(&relative).is_err());
        let url = [
            "postgres",
            "://",
            "svc",
            ":",
            "pw1234567",
            "@",
            "db/factory",
        ]
        .concat();
        let text = format!("{}note: {url}\n", minimal("local"));
        assert!(matches!(
            ApiConfig::from_yaml(&text),
            Err(ConfigError::InlineCredential(_) | ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn the_environment_cannot_change_the_profile() {
        let dir = std::env::temp_dir().join(format!("factory-api-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("api.yaml");
        std::fs::write(&file, minimal("local")).expect("write");
        let path = file.display().to_string();
        let lookup = |profile: &'static str| {
            let path = path.clone();
            move |name: &str| match name {
                "FACTORY_CONFIG" => Some(path.clone()),
                "FACTORY_PROFILE" => Some(profile.to_owned()),
                "FACTORY_LOG" => Some("debug".to_owned()),
                _ => None,
            }
        };
        assert!(matches!(
            ApiConfig::from_environment(lookup("production")),
            Err(ConfigError::ProfileMismatch { .. })
        ));
        let config = ApiConfig::from_environment(lookup("local")).expect("agrees");
        assert_eq!(config.telemetry.log_filter.as_deref(), Some("debug"));
        let _ = std::fs::remove_dir_all(dir);
        assert!(ApiConfig::from_environment(|_| None).is_err());
    }
}
