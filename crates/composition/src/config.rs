//! The typed configuration of a factory process.
//!
//! One YAML file, read with the restricted reader of `factory-contracts` (no anchors, no tags, no
//! merge keys, size and depth limits), decoded into the types below with `deny_unknown_fields`.
//! The environment may name the file and may tighten a few non-secret settings. Nothing else.
//!
//! # Rules this module keeps
//!
//! * **No default for a choice that matters.** The profile, the two database logins, the protected
//!   checkout and the artifact root have no default. A file that omits one is refused. A default
//!   exists only where the safe value is obvious (a log level, a poll interval).
//! * **A secret is a reference to a file, never a value.** A secret field is a [`SecretFile`]: a
//!   path. The file must be a regular file, not a symbolic link, and not readable by group or
//!   others. A value that looks like a credential anywhere in the file (a URL with a password) is
//!   refused before decoding, so a person who pastes one gets an error and not a quiet exposure.
//! * **Two logins, two pools.** The tenant pool and the system pool name different login roles,
//!   and a file that names the same role for both is refused (ADR 0012). The role that the URL in
//!   each secret file really connects as must equal the role the file names, so the two cannot
//!   drift apart.
//! * **The environment cannot widen anything.** `FACTORY_CONFIG` names the file. `FACTORY_PROFILE`,
//!   when set, must equal the file's profile and otherwise stops the process: an environment
//!   variable cannot turn `production` into `test`. `FACTORY_LOG` replaces the log filter.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use factory_contracts::yaml::{self, YamlLimits};
use serde::Deserialize;

use crate::profile::Profile;

/// Why a configuration cannot be used. The text names the field, never a secret value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("the configuration file {0} cannot be read")]
    Unreadable(String),
    /// The file is not valid YAML or does not match the schema.
    #[error("the configuration is not valid: {0}")]
    Invalid(String),
    /// A value looks like a credential written inline.
    #[error("the configuration holds an inline credential at {0}; name a file instead")]
    InlineCredential(String),
    /// The two database pools name the same login.
    #[error("the tenant pool and the system pool name the same login role {0}; they must differ")]
    SameLogin(String),
    /// A secret file is unsafe to read.
    #[error("the secret file {path} is {problem}")]
    UnsafeSecretFile {
        /// The path.
        path: String,
        /// What is wrong with it.
        problem: &'static str,
    },
    /// A setting is outside its allowed range.
    #[error("{field}: {problem}")]
    OutOfRange {
        /// The field.
        field: &'static str,
        /// What is wrong.
        problem: &'static str,
    },
    /// The environment disagrees with the file on something it may not change.
    #[error("the environment names profile {environment} but the file names {file}")]
    ProfileMismatch {
        /// The profile in the environment.
        environment: String,
        /// The profile in the file.
        file: &'static str,
    },
}

/// A path that names a file holding a secret.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct SecretFile(PathBuf);

impl SecretFile {
    /// A reference to the file at `path`.
    #[must_use]
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    /// The path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// Reads the secret. The file must be a regular file, not a symbolic link, with no permission
    /// for group or others. Trailing line breaks are removed.
    ///
    /// # Errors
    /// [`ConfigError::UnsafeSecretFile`] or [`ConfigError::Unreadable`].
    pub fn read(&self) -> Result<SecretText, ConfigError> {
        use std::os::unix::fs::PermissionsExt;
        let shown = self.0.display().to_string();
        let meta = std::fs::symlink_metadata(&self.0)
            .map_err(|_| ConfigError::Unreadable(shown.clone()))?;
        let unsafe_file = |problem| ConfigError::UnsafeSecretFile {
            path: shown.clone(),
            problem,
        };
        if meta.file_type().is_symlink() {
            return Err(unsafe_file("a symbolic link"));
        }
        if !meta.is_file() {
            return Err(unsafe_file("not a regular file"));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(unsafe_file("readable by group or others"));
        }
        let text = std::fs::read_to_string(&self.0).map_err(|_| ConfigError::Unreadable(shown))?;
        Ok(SecretText(text.trim_end_matches(['\n', '\r']).to_owned()))
    }
}

impl fmt::Debug for SecretFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretFile({})", self.0.display())
    }
}

/// The content of a secret file. It shows a placeholder when printed.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretText(String);

impl SecretText {
    /// The value, for the one place that needs it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText([redacted])")
    }
}

/// One database pool.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolConfig {
    /// The file holding the connection URL.
    pub url_file: SecretFile,
    /// The login role the URL connects as.
    pub login: String,
    /// The pool size.
    #[serde(default = "default_pool_size")]
    pub max_connections: usize,
}

const fn default_pool_size() -> usize {
    8
}

/// The two pools (ADR 0012): tenant transactions on one login, finding work on the other.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// The tenant pool. A worker login: member of `factory_app`.
    pub tenant: PoolConfig,
    /// The system pool. The engine login: member of `factory_system`.
    pub system: PoolConfig,
}

/// Where artifacts are kept.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactsConfig {
    /// The root of the content-addressed store.
    pub root: PathBuf,
    /// The largest single artifact, in bytes.
    #[serde(default = "default_max_artifact")]
    pub max_bytes: u64,
}

const fn default_max_artifact() -> u64 {
    64 * 1024 * 1024
}

/// The sandbox side.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    /// The catalog of pinned images.
    pub images_catalog: PathBuf,
    /// Where job token files are written for the broker mount.
    pub token_root: PathBuf,
    /// The platform to pick from the catalog; asked of the Docker daemon when absent.
    #[serde(default)]
    pub platform: Option<String>,
    /// Root of the job workspaces.
    pub workspace_root: PathBuf,
    /// Label value that marks the containers this factory created, for the janitor.
    #[serde(default = "default_owner")]
    pub owner: String,
    /// Where the target repositories are fetched from and pushed to.
    #[serde(default)]
    pub remote: RemoteConfig,
    /// The arguments of the egress sidecar's program (`--mode`, `--listen`, `--upstream`, ...).
    /// The sidecar image names the program; these say where the broker is, as the sidecar sees it,
    /// and what the relay may do. Empty means the sidecar is started with no arguments, which the
    /// real sidecar refuses, so a deployment that runs agents must set them.
    #[serde(default)]
    pub sidecar_command: Vec<String>,
}

fn default_owner() -> String {
    "factory-worker".to_owned()
}

/// Where the repositories live, and with that which transport the host-side version control may
/// use. Set at most one of the two fields; none means `https` to `github.com`.
///
/// (The restricted YAML reader decodes only plain structs and unit variants, so this is two
/// optional fields and not a tagged choice.)
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteConfig {
    /// The host of `https://<host>/<owner>/<name>.git`. The only transport the production
    /// profile allows.
    #[serde(default)]
    pub https_host: Option<String>,
    /// A directory of bare repositories (`file://<directory>/<owner>/<name>.git`), for the local
    /// and test profiles.
    #[serde(default)]
    pub directory: Option<PathBuf>,
}

/// The remote after the choice is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remote {
    /// `https` to this host.
    Https(String),
    /// Bare repositories in this directory.
    Directory(PathBuf),
}

impl RemoteConfig {
    /// The remote this setting names.
    ///
    /// # Errors
    /// [`ConfigError::OutOfRange`] when both fields are set, or the directory is not absolute.
    pub fn remote(&self) -> Result<Remote, ConfigError> {
        match (&self.https_host, &self.directory) {
            (Some(_), Some(_)) => Err(ConfigError::OutOfRange {
                field: "sandbox.remote",
                problem: "set https_host or directory, not both",
            }),
            (None, Some(directory)) if !directory.is_absolute() => Err(ConfigError::OutOfRange {
                field: "sandbox.remote.directory",
                problem: "must be an absolute path",
            }),
            (None, Some(directory)) => Ok(Remote::Directory(directory.clone())),
            (Some(host), None) => Ok(Remote::Https(host.clone())),
            (None, None) => Ok(Remote::Https("github.com".to_owned())),
        }
    }
}

/// A provider the broker forwards to.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// `anthropic` or `openai`.
    pub provider: String,
    /// The base URL, `scheme://host[:port]`.
    pub base_url: String,
    /// The file holding the provider key.
    pub key_file: SecretFile,
}

/// What a model costs, in millionths of a dollar per million tokens. The repository has no price
/// list, so the deployment supplies one; a model with no entry is refused by the broker.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceConfig {
    /// `anthropic` or `openai`.
    pub provider: String,
    /// The model name as the provider spells it.
    pub model: String,
    /// Input tokens.
    pub input: u64,
    /// Cache write tokens.
    pub cache_write: u64,
    /// Cache read tokens.
    pub cache_read: u64,
    /// Output tokens.
    pub output: u64,
}

/// The model broker hosted by the worker.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerConfig {
    /// Where the listener binds.
    pub listen: SocketAddr,
    /// The providers.
    #[serde(default)]
    pub upstreams: Vec<UpstreamConfig>,
    /// The price list.
    #[serde(default)]
    pub prices: Vec<PriceConfig>,
}

/// The GitHub App.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubConfig {
    /// The App id.
    pub app_id: u64,
    /// The file holding the App private key.
    pub key_file: SecretFile,
    /// The file holding the webhook secret (API only).
    #[serde(default)]
    pub webhook_secret_file: Option<SecretFile>,
}

/// How the worker loop paces itself.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoopConfig {
    /// A slug that starts the name of this worker in leases; the process id is appended.
    #[serde(default = "default_worker_name")]
    pub name_prefix: String,
    /// Wait between claims when there was no work, in milliseconds.
    #[serde(default = "default_poll_ms")]
    pub poll_interval_ms: u64,
    /// Wait between sweeps of expired leases and deadlines, in seconds.
    #[serde(default = "default_sweep_s")]
    pub sweep_interval_s: u64,
    /// How long a stop request lets a running attempt finish before the lease is left to expire,
    /// in seconds.
    #[serde(default = "default_drain_s")]
    pub drain_s: u64,
    /// The tenants this worker reads requests for (UUIDs). Empty means none: a job whose request
    /// is not in the cache has no contract and waits.
    #[serde(default)]
    pub tenants: Vec<String>,
}

impl LoopConfig {
    /// The tenants as identifiers.
    ///
    /// # Errors
    /// [`ConfigError::OutOfRange`] when an entry is not a UUID.
    pub fn served_tenants(&self) -> Result<Vec<factory_domain::ids::TenantId>, ConfigError> {
        self.tenants
            .iter()
            .map(|text| {
                text.parse::<uuid::Uuid>()
                    .map(factory_domain::ids::TenantId::from_uuid)
                    .map_err(|_| ConfigError::OutOfRange {
                        field: "worker.tenants",
                        problem: "every entry must be a UUID",
                    })
            })
            .collect()
    }
}

fn default_worker_name() -> String {
    "worker".to_owned()
}
const fn default_poll_ms() -> u64 {
    1000
}
const fn default_sweep_s() -> u64 {
    10
}
const fn default_drain_s() -> u64 {
    120
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self {
            name_prefix: default_worker_name(),
            poll_interval_ms: default_poll_ms(),
            sweep_interval_s: default_sweep_s(),
            drain_s: default_drain_s(),
            tenants: Vec::new(),
        }
    }
}

impl LoopConfig {
    /// The poll wait.
    #[must_use]
    pub const fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.poll_interval_ms)
    }

    /// The sweep wait.
    #[must_use]
    pub const fn sweep_interval(&self) -> Duration {
        Duration::from_secs(self.sweep_interval_s)
    }

    /// The drain budget.
    #[must_use]
    pub const fn drain(&self) -> Duration {
        Duration::from_secs(self.drain_s)
    }
}

/// Telemetry settings.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// The OTLP collector endpoint; none means no export.
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// The log filter.
    #[serde(default)]
    pub log_filter: Option<String>,
}

/// A secret value of the factory that the redactor must know, beyond the ones named elsewhere.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtraSecret {
    /// The label in the redaction marker.
    pub label: String,
    /// The file holding the value.
    pub file: SecretFile,
}

/// The whole configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryConfig {
    /// The profile. No default.
    pub profile: Profile,
    /// The checkout of the protected configuration branch that holds `policies/`. It must lie
    /// outside every job workspace and target repository.
    pub protected_checkout: PathBuf,
    /// The checkout that holds `agents/`, `profiles/` and the schemas. Often the same directory.
    pub definitions_root: PathBuf,
    /// The two pools.
    pub database: DatabaseConfig,
    /// Artifacts.
    pub artifacts: ArtifactsConfig,
    /// The sandbox side.
    pub sandbox: SandboxConfig,
    /// The model broker.
    pub broker: BrokerConfig,
    /// GitHub, when configured.
    #[serde(default)]
    pub github: Option<GithubConfig>,
    /// The worker loop.
    #[serde(default)]
    pub worker: LoopConfig,
    /// Telemetry.
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    /// More secret values for the redactor.
    #[serde(default)]
    pub extra_secrets: Vec<ExtraSecret>,
}

impl FactoryConfig {
    /// Reads a configuration from text.
    ///
    /// # Errors
    /// A [`ConfigError`].
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        let document = yaml::read(text, YamlLimits::POLICY)
            .map_err(|error| ConfigError::Invalid(error.to_string()))?;
        refuse_inline_credentials(&document.to_json(), "")?;
        let config: Self = document
            .decode()
            .map_err(|error| ConfigError::Invalid(error.to_string()))?;
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
    /// `lookup` is the environment, passed in so a test does not touch the process.
    ///
    /// # Errors
    /// A [`ConfigError`], also when `FACTORY_CONFIG` is not set.
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
        let (tenant, system) = (&self.database.tenant.login, &self.database.system.login);
        if tenant.is_empty() || system.is_empty() {
            return Err(ConfigError::OutOfRange {
                field: "database.*.login",
                problem: "must name a role",
            });
        }
        if tenant == system {
            return Err(ConfigError::SameLogin(tenant.clone()));
        }
        for (field, pool) in [
            ("database.tenant.max_connections", &self.database.tenant),
            ("database.system.max_connections", &self.database.system),
        ] {
            if pool.max_connections == 0 || pool.max_connections > 256 {
                return Err(ConfigError::OutOfRange {
                    field,
                    problem: "must be between 1 and 256",
                });
            }
        }
        for (field, path) in [
            ("protected_checkout", &self.protected_checkout),
            ("definitions_root", &self.definitions_root),
            ("artifacts.root", &self.artifacts.root),
            ("sandbox.images_catalog", &self.sandbox.images_catalog),
            ("sandbox.token_root", &self.sandbox.token_root),
            ("sandbox.workspace_root", &self.sandbox.workspace_root),
        ] {
            if !path.is_absolute() {
                return Err(ConfigError::OutOfRange {
                    field,
                    problem: "must be an absolute path",
                });
            }
        }
        // A conflict between the two fields is an error in every profile.
        self.sandbox.remote.remote()?;
        if self.profile == Profile::Production {
            if matches!(self.sandbox.remote.remote()?, Remote::Directory(_)) {
                return Err(ConfigError::OutOfRange {
                    field: "sandbox.remote",
                    problem: "the production profile fetches over https only",
                });
            }
            if self.broker.upstreams.is_empty() {
                return Err(ConfigError::OutOfRange {
                    field: "broker.upstreams",
                    problem: "the production profile needs at least one provider",
                });
            }
            if self.github.is_none() {
                return Err(ConfigError::OutOfRange {
                    field: "github",
                    problem: "the production profile needs the GitHub App",
                });
            }
        }
        if self.worker.poll_interval_ms == 0 || self.worker.sweep_interval_s == 0 {
            return Err(ConfigError::OutOfRange {
                field: "worker",
                problem: "the poll and sweep intervals must be above zero",
            });
        }
        Ok(())
    }

    /// The environment variables the process reads, for the README and the usage text.
    #[must_use]
    pub fn environment_variables() -> BTreeMap<&'static str, &'static str> {
        BTreeMap::from([
            (
                "FACTORY_CONFIG",
                "path of the configuration file (required)",
            ),
            (
                "FACTORY_PROFILE",
                "must equal the profile in the file when set",
            ),
            ("FACTORY_LOG", "replaces the log filter"),
        ])
    }
}

/// Walks a decoded document and refuses a string that has the shape of a URL with a password.
fn refuse_inline_credentials(value: &serde_json::Value, at: &str) -> Result<(), ConfigError> {
    match value {
        serde_json::Value::String(text) if looks_like_url_with_password(text) => {
            Err(ConfigError::InlineCredential(at.to_owned()))
        }
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                let here = if at.is_empty() {
                    key.clone()
                } else {
                    format!("{at}.{key}")
                };
                refuse_inline_credentials(inner, &here)?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for (index, inner) in items.iter().enumerate() {
                refuse_inline_credentials(inner, &format!("{at}[{index}]"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// True for a URL whose authority holds a user name, a colon and a password before the host.
fn looks_like_url_with_password(text: &str) -> bool {
    let Some((_, rest)) = text.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    authority
        .rsplit_once('@')
        .is_some_and(|(userinfo, _)| userinfo.contains(':'))
}

/// The value of one `key=value` word of a libpq connection string.
fn libpq_word<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.split_whitespace()
        .find_map(|word| word.strip_prefix(key)?.strip_prefix('='))
        .filter(|value| !value.is_empty())
}

/// The password of a libpq `key=value` connection string, if it has one.
#[must_use]
pub fn password_of_key_value(text: &str) -> Option<String> {
    libpq_word(text, "password").map(str::to_owned)
}

/// The login a connection URL names, without the password. Accepts the URL form with a user part
/// and the libpq `host=... user=... dbname=...` form.
#[must_use]
pub fn login_of_url(url: &str) -> Option<String> {
    if !url.contains("://") {
        return libpq_word(url, "user").map(str::to_owned);
    }
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let (userinfo, _) = authority.rsplit_once('@')?;
    let user = userinfo.split(':').next()?;
    if user.is_empty() {
        None
    } else {
        Some(user.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal(profile: &str, tenant: &str, system: &str) -> String {
        format!(
            "profile: {profile}\n\
             protected_checkout: /srv/protected\n\
             definitions_root: /srv/protected\n\
             database:\n  tenant: {{ url_file: /run/secrets/a, login: {tenant} }}\n  system: {{ url_file: /run/secrets/b, login: {system} }}\n\
             artifacts: {{ root: /var/artifacts }}\n\
             sandbox: {{ images_catalog: /srv/protected/images.json, token_root: /var/tokens, workspace_root: /var/ws }}\n\
             broker: {{ listen: '127.0.0.1:0' }}\n"
        )
    }

    #[test]
    fn a_minimal_local_file_loads_with_safe_defaults() {
        let config =
            FactoryConfig::from_yaml(&minimal("local", "factory_worker", "factory_engine"))
                .expect("loads");
        assert_eq!(config.profile, Profile::Local);
        assert_eq!(config.worker, LoopConfig::default());
        assert_eq!(config.database.tenant.max_connections, 8);
    }

    #[test]
    fn two_pools_two_roles() {
        let same = minimal("local", "factory_worker", "factory_worker");
        assert_eq!(
            FactoryConfig::from_yaml(&same).unwrap_err(),
            ConfigError::SameLogin("factory_worker".to_owned())
        );
    }

    #[test]
    fn a_file_without_a_profile_is_refused() {
        let text = minimal("local", "a", "b").replacen("profile: local\n", "", 1);
        assert!(matches!(
            FactoryConfig::from_yaml(&text),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn an_unknown_field_is_refused_so_a_typo_cannot_weaken_a_setting() {
        let text = format!("{}extra_setting: 1\n", minimal("local", "a", "b"));
        assert!(matches!(
            FactoryConfig::from_yaml(&text),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn production_needs_a_provider_and_the_app() {
        let refusal = FactoryConfig::from_yaml(&minimal("production", "a", "b")).unwrap_err();
        assert!(matches!(
            refusal,
            ConfigError::OutOfRange {
                field: "broker.upstreams",
                ..
            }
        ));
    }

    #[test]
    fn an_inline_credential_in_the_file_is_refused() {
        // The URL is built at run time so that no credential-shaped literal sits in the source.
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
        let text = format!("{}note: {url}\n", minimal("local", "a", "b"));
        assert!(matches!(
            FactoryConfig::from_yaml(&text),
            Err(ConfigError::InlineCredential(at)) if at == "note"
        ));
    }

    #[test]
    fn relative_paths_are_refused() {
        let text = minimal("local", "a", "b").replace(
            "/srv/protected\ndefinitions_root",
            "protected\ndefinitions_root",
        );
        assert!(matches!(
            FactoryConfig::from_yaml(&text),
            Err(ConfigError::OutOfRange {
                field: "protected_checkout",
                ..
            })
        ));
    }

    #[test]
    fn the_environment_cannot_change_the_profile() {
        let dir = std::env::temp_dir().join(format!("factory-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("factory.yaml");
        std::fs::write(&file, minimal("local", "a", "b")).expect("write");
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
        let refusal = FactoryConfig::from_environment(lookup("production")).unwrap_err();
        assert!(matches!(refusal, ConfigError::ProfileMismatch { .. }));
        let config = FactoryConfig::from_environment(lookup("local")).expect("agrees");
        assert_eq!(config.telemetry.log_filter.as_deref(), Some("debug"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_missing_config_variable_is_refused_without_a_default_path() {
        assert!(FactoryConfig::from_environment(|_| None).is_err());
    }

    #[test]
    fn the_login_is_read_from_a_url_without_its_password() {
        let url = ["postgres", "://", "factory_worker", ":", "pw", "@", "h/db"].concat();
        assert_eq!(login_of_url(&url).as_deref(), Some("factory_worker"));
        assert_eq!(login_of_url("postgres://h/db"), None);
    }

    #[test]
    fn a_secret_file_must_be_private_and_regular() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("factory-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let file = dir.join("secret");
        std::fs::write(&file, "value\n").expect("write");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("mode");
        let reference = SecretFile::at(&file);
        assert!(matches!(
            reference.read(),
            Err(ConfigError::UnsafeSecretFile {
                problem: "readable by group or others",
                ..
            })
        ));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("mode");
        assert_eq!(reference.read().expect("reads").expose(), "value");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).expect("link");
        assert!(matches!(
            SecretFile::at(&link).read(),
            Err(ConfigError::UnsafeSecretFile {
                problem: "a symbolic link",
                ..
            })
        ));
        let _ = std::fs::remove_dir_all(dir);
    }
}
