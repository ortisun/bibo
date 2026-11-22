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

/// A path that names a file holding a secret. A path written `~/name` in the configuration is read
/// from the home directory of the user the process runs as (`$HOME`), so the owner's subscription
/// token can stay where `claude setup-token` was run (`~/claud-oauth-token.txt`).
#[derive(Clone, PartialEq, Eq)]
pub struct SecretFile(PathBuf);

impl<'de> Deserialize<'de> for SecretFile {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let path = PathBuf::deserialize(deserializer)?;
        Ok(Self(expand_home(path)))
    }
}

/// `~/rest` becomes `$HOME/rest` when `HOME` is an absolute path; anything else is left as written.
fn expand_home(path: PathBuf) -> PathBuf {
    let Ok(rest) = path.strip_prefix("~") else {
        return path;
    };
    match std::env::var_os("HOME").map(PathBuf::from) {
        Some(home) if home.is_absolute() && path.as_os_str() != "~" => home.join(rest),
        _ => path,
    }
}

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
    /// More labels for every object this factory creates in Docker, beside the owner label. The
    /// janitor touches only objects that carry all of them, so a test run labels its objects
    /// with its own and removes only those.
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
    /// Where the target repositories are fetched from and pushed to.
    #[serde(default)]
    pub remote: RemoteConfig,
    /// The arguments of the egress sidecar's program (`--mode`, `--listen`, `--upstream`, ...).
    /// The sidecar image names the program; these say where the broker is, as the sidecar sees it,
    /// and what the relay may do. Empty means the sidecar is started with no arguments, which the
    /// real sidecar refuses, so a deployment that runs agents must set them.
    #[serde(default)]
    pub sidecar_command: Vec<String>,
    /// The MCP gateway's address as the sidecar sees it, `IP:PORT` (ADR 0021, Decision 5). Only a
    /// `troubleshooter` sandbox's sidecar gets the second fixed relay to it; every other sidecar
    /// is started with `sidecar_command` alone. Absent means no troubleshooter sandbox can start.
    #[serde(default)]
    pub gateway_upstream: Option<std::net::SocketAddr>,
    /// Where the Docker daemon is, as `DOCKER_HOST` would say: `unix:///<absolute socket path>` or
    /// `tcp://<host>:<port>`. None means the client's own default socket. The `docker` client of
    /// the worker runs with an empty environment, so this key is the only way to name a daemon that
    /// is not on the default socket (a rootless Docker, Colima, a remote host). A `tcp://` address
    /// must be on the loopback interface unless `allow_remote_docker` is set.
    #[serde(default)]
    pub docker_host: Option<String>,
    /// The directory of the Docker client's own configuration, as `DOCKER_CONFIG` would say. An
    /// absolute path to a directory. None means the client's default.
    #[serde(default)]
    pub docker_config: Option<PathBuf>,
    /// Allows `docker_host` to be a `tcp://` address that is not on the loopback interface. A
    /// daemon that is reached over a network gives whoever sits on that network the control of
    /// every container, so this is an explicit choice and the production profile refuses it.
    #[serde(default)]
    pub allow_remote_docker: bool,
    /// Allows `docker_config` to be a directory that names a Docker daemon or a credential helper:
    /// a `config.json` with a `currentContext` other than the default, a `contexts` directory
    /// with an entry, or `credsStore` / `credHelpers` (DR-6). A context can point the client at a
    /// daemon on another machine whatever `docker_host` says, and the production profile does
    /// not reach one over a network, so without this flag such a directory stops the start, and
    /// the production profile refuses the flag. Off by default.
    #[serde(default)]
    pub allow_docker_config_contexts: bool,
}

fn default_owner() -> String {
    "factory-worker".to_owned()
}

impl SandboxConfig {
    /// Checks the three Docker keys, which need no file other than the configuration. That
    /// `docker_config` is a directory on this machine is checked when the providers are built.
    ///
    /// # Errors
    /// [`ConfigError::OutOfRange`] naming the key.
    pub fn validate_docker(&self, profile: Profile) -> Result<(), ConfigError> {
        if self.allow_remote_docker && profile == Profile::Production {
            return Err(ConfigError::OutOfRange {
                field: "sandbox.allow_remote_docker",
                problem: "the production profile does not reach a Docker daemon over a network",
            });
        }
        if self.allow_docker_config_contexts && profile == Profile::Production {
            return Err(ConfigError::OutOfRange {
                field: "sandbox.allow_docker_config_contexts",
                problem: "the production profile does not accept a Docker configuration directory that names a daemon or a credential helper",
            });
        }
        if let Some(host) = &self.docker_host
            && let Some(problem) = docker_host_problem(host, self.allow_remote_docker)
        {
            return Err(ConfigError::OutOfRange {
                field: "sandbox.docker_host",
                problem,
            });
        }
        if let Some(directory) = &self.docker_config
            && (!directory.is_absolute()
                || directory
                    .components()
                    .any(|part| part == std::path::Component::ParentDir))
        {
            return Err(ConfigError::OutOfRange {
                field: "sandbox.docker_config",
                problem: "must be an absolute directory path with no .. part",
            });
        }
        Ok(())
    }
}

/// Why `host` may not be the address of the Docker daemon, or `None`.
///
/// Only two shapes are accepted: `unix://` and an absolute socket path, and `tcp://host:port`
/// where the host is on the loopback interface, or any plain host name or address when
/// `allow_remote` is set. Any other transport (`ssh://`, `npipe://`, `fd://`, `http://`) needs a
/// helper program or a socket activation that the worker's container does not have.
fn docker_host_problem(host: &str, allow_remote: bool) -> Option<&'static str> {
    const SHAPE: &str = "must be unix:///<absolute socket path> or tcp://<host>:<port>";
    if host.chars().any(|c| c.is_control() || c.is_whitespace()) || host.contains(['?', '#', '@']) {
        return Some("must be a plain address with no white space, query, fragment or user part");
    }
    if let Some(path) = host.strip_prefix("unix://") {
        let usable = path.starts_with('/')
            && path.len() > 1
            && !path.ends_with('/')
            && path.split('/').all(|part| part != "..");
        return (!usable).then_some(
            "a unix address must be unix:// followed by an absolute socket path with no .. part",
        );
    }
    let Some(rest) = host.strip_prefix("tcp://") else {
        return Some(SHAPE);
    };
    let (name, port) = match rest.strip_prefix('[') {
        Some(inside) => match inside.split_once("]:") {
            Some((name, port)) => (name, port),
            None => return Some(SHAPE),
        },
        None => match rest.rsplit_once(':') {
            Some((name, port)) if !name.contains(':') => (name, port),
            _ => return Some(SHAPE),
        },
    };
    let valid_port = port.parse::<u16>().is_ok_and(|p| p > 0);
    let plain_name = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | ':'));
    if !valid_port || !plain_name {
        return Some(SHAPE);
    }
    (!allow_remote && !is_loopback_host(name)).then_some(
        "a tcp address must be on the loopback interface unless allow_remote_docker is true",
    )
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
    /// The models of the routing policy that this provider is enabled for. Empty means every model
    /// the policy lists for the provider. A name the policy does not list for it is an error.
    #[serde(default)]
    pub models: Vec<String>,
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

/// The GitHub App installation that covers one repository of one tenant. The adapter does not
/// discover installations: a repository with no entry here is unreachable.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationConfig {
    /// The tenant, as a UUID.
    pub tenant: String,
    /// The repository, as `owner/name`.
    pub repository: String,
    /// The installation of the App on that repository.
    pub installation_id: u64,
}

/// An administrator's statement that the App is on no bypass list of a repository. The App does
/// not judge the bypass lists itself (a ruleset's list is not in the rules it reads, and the
/// bypass allowances of classic protection, readable with `administration: read` since
/// 2026-11-12, are not judged), so a person says it and the deployment records it here. Without a statement the repository runs at level L0.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationConfig {
    /// The tenant, as a UUID.
    pub tenant: String,
    /// The repository, as `owner/name`.
    pub repository: String,
    /// The administrator who made the statement, as the UUID of their principal.
    pub principal: String,
    /// When the statement was recorded, as a UTC time such as `2026-10-28T09:00:00Z`.
    pub recorded_at: String,
}

/// The statement of the owner of a repository that named workflows are exposed to the factory's
/// branches on purpose (threat T-48): for example, a repository whose only secret is harmless.
/// The preflight caps a repository with exposed workflows at level L0; an entry here lets it pass
/// when it names exactly the workflows found exposed. A workflow that is not in the list, or a
/// list that names a workflow that is no longer exposed, and the entry covers nothing.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowAcknowledgementConfig {
    /// The tenant, as a UUID.
    pub tenant: String,
    /// The repository, as `owner/name`.
    pub repository: String,
    /// The person who made the statement, as the UUID of their principal.
    pub principal: String,
    /// When the statement was recorded, as a UTC time such as `2026-11-12T09:00:00Z`.
    pub recorded_at: String,
    /// The paths of the workflow files the statement covers, each `.github/workflows/<file>`.
    pub workflows: Vec<String>,
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
    /// Where the GitHub API is. The production profile needs `https://api.github.com`; the other
    /// profiles also accept plain http on the loopback interface.
    #[serde(default = "default_github_api")]
    pub api_base_url: String,
    /// Which installation covers which repository of which tenant.
    #[serde(default)]
    pub installations: Vec<InstallationConfig>,
    /// The administrators' statements about the bypass list.
    #[serde(default)]
    pub bypass_attestations: Vec<AttestationConfig>,
    /// The owners' statements that named workflows are exposed to factory branches on purpose
    /// (threat T-48). At most one for a repository of a tenant.
    #[serde(default)]
    pub workflow_exposure_acknowledgements: Vec<WorkflowAcknowledgementConfig>,
    /// Writes the state of each job on its issue: one `factory: <state>` label and one status
    /// comment (ADR 0017). False stops the worker from writing on issues. Nothing else changes: the
    /// labels and the comment are observability and no job depends on them.
    #[serde(default = "default_true")]
    pub write_issue_status: bool,
    /// Opens a draft pull request in each repository that installs or updates the factory's rules
    /// for agents in `AGENTS.md`, at onboarding and when a new release changes them (ADR 0026).
    /// False stops the worker from opening it. The agents still read the project's `AGENTS.md`, or
    /// the factory's built-in copy when the project has none.
    #[serde(default = "default_true")]
    pub propose_project_rules: bool,
    /// Asks the code host, once an hour for each, whether a person merged or closed the pull
    /// requests the factory opened, and records the answer for the process metrics (ADR 0029,
    /// ports v1.5). The read needs no permission the App does not hold already. False stops the
    /// worker from asking: the pull requests then stay open in the store, and the rejection rate
    /// and the cost of an accepted pull request show too few samples.
    #[serde(default = "default_true")]
    pub follow_pull_requests: bool,
    /// Once a week for each project, proposes the process numbers of the last whole ISO week into
    /// the project's knowledge base as a draft pull request (ADR 0029, ADR 0031). Only for an
    /// enabled repository whose default branch has `docs/knowledge/README.md`. False stops the
    /// worker from proposing them; no job depends on it.
    #[serde(default = "default_true")]
    pub propose_knowledge_measurements: bool,
    /// The address of GitHub's web pages, `scheme://host[:port]` with no path, from which the
    /// factory builds the links it writes (the link to the draft pull request in the status
    /// comment of a finished job). The default is `https://github.com`; a GitHub Enterprise server
    /// has its own. The host must also be one `output_hygiene.allow_link_domains` of
    /// `policies/security.yaml` lists, or the adapter would strip every link, and the start says so.
    #[serde(default = "default_github_web")]
    pub web_base_url: String,
}

fn default_true() -> bool {
    true
}

fn default_github_api() -> String {
    "https://api.github.com".to_owned()
}

fn default_github_web() -> String {
    "https://github.com".to_owned()
}

impl GithubConfig {
    /// Why `web_base_url` cannot be used, or `None`: the rules of every outside address, and no
    /// path, because the links are built as `<base>/<owner>/<name>/...`.
    fn web_base_problem(&self, profile: Profile) -> Option<&'static str> {
        if let Some(problem) = endpoint_problem(profile, &self.web_base_url) {
            return Some(problem);
        }
        let (_, rest) = self.web_base_url.split_once("://")?;
        if rest.trim_end_matches('/').contains('/') {
            return Some("must be scheme://host[:port] with no path");
        }
        // A browser, and the filter of the GitHub adapter, end the host at a backslash like at a
        // slash, and the filter knows no host with a character that is not part of a name, a port
        // or an address. An address with such a character would pass for one host here and be read
        // as another there, so the links would be stripped and nothing would say so (DR-9). The
        // authority here ends at a slash, a query or a fragment only, so a backslash is inside it
        // and is refused with every other character the filter does not read.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        (!authority
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':')))
        .then_some(
            "the host must be a name or an address and a port: no backslash, user information or other character",
        )
    }

    /// The web address without a trailing slash, ready to have `/<owner>/<name>/...` added.
    #[must_use]
    pub fn web_root(&self) -> &str {
        self.web_base_url.trim_end_matches('/')
    }
}

/// The package registry the dependency gate asks about a new package (the crates.io API).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryConfig {
    /// The base URL of the registry API, such as `https://crates.io`. The production profile needs
    /// https and a host the egress policy lists for the cargo ecosystem.
    pub base_url: String,
    /// The `User-Agent` the client sends. The registry asks clients to identify themselves with a
    /// way to reach the operator. The production profile needs it.
    #[serde(default)]
    pub user_agent: Option<String>,
    /// The wall time of one request, in seconds.
    #[serde(default = "default_registry_timeout")]
    pub timeout_seconds: u64,
    /// The largest answer read, in bytes. A larger one reads as unknown.
    #[serde(default = "default_registry_max_bytes")]
    pub max_response_bytes: u64,
}

const fn default_registry_timeout() -> u64 {
    10
}
const fn default_registry_max_bytes() -> u64 {
    1_048_576
}

/// Where the date of the advisory database the audit reads is kept.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisoryConfig {
    /// A file with one line, the UTC time the database was last updated, such as
    /// `2026-10-28T09:00:00Z` or `2026-10-28`. The image build writes it. A file that is missing,
    /// unreadable, not a date or in the future reads as unknown, and the advisories gate is BLOCKED.
    pub date_file: PathBuf,
}

/// Where one agent tool is in the agent image and which versions the adapter accepts.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeToolConfig {
    /// The path of the tool inside the image. When absent the adapter's own default is used.
    #[serde(default)]
    pub binary: Option<String>,
    /// The versions the adapter accepts. Empty means the one the adapter was tested with.
    #[serde(default)]
    pub versions: Vec<String>,
}

/// The agent runtimes. Which ones exist follows from the providers in `broker.upstreams`
/// (`anthropic` gives `claude-code-cli`, `openai` gives `codex-cli`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimesConfig {
    /// The Claude Code tool.
    #[serde(default)]
    pub claude_code: Option<RuntimeToolConfig>,
    /// The Codex tool.
    #[serde(default)]
    pub codex: Option<RuntimeToolConfig>,
    /// Takes the capabilities of the runtimes from a declaration and not from a probe in a
    /// sandbox. For the local and test profiles only: a declared list is a claim nobody checked.
    #[serde(default)]
    pub declare_capabilities: bool,
}

/// The key that signs the requests for decisions (AUT-12, R-1 of the API review).
///
/// The API signs each `decision.requested` record with it and the worker's hook verifies the
/// record with it before anything else. Both processes name the same file. The key is a secret: a
/// reference to a file that only its owner may read, never a value.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionSigning {
    /// The file holding the current key: signs and verifies. At least 32 bytes.
    pub key_file: SecretFile,
    /// The file holding the previous key, during a rotation: verifies only. Remove it once every
    /// request signed with it has been dealt with (the approval window is 72 hours).
    #[serde(default)]
    pub previous_key_file: Option<SecretFile>,
    /// The moment after which the previous key is ignored, as a UTC time such as
    /// `2026-11-02T12:00:00Z`: 72 hours after the rotation, no more. Without it the production
    /// profile ignores the previous key (and says so in the log), so a key that leaked and was
    /// replaced stops verifying on its own and does not wait for someone to remove its file
    /// (RR-25). The other profiles accept the previous key until its file is removed.
    #[serde(default)]
    pub previous_key_valid_until: Option<String>,
}

/// The budget of one stage run: the wall time, the model tokens and cost, and the attempts.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSettings {
    /// The wall time of a stage run, in seconds.
    #[serde(default = "default_stage_wall_s")]
    pub wall_time_seconds: u32,
    /// The model tokens a stage run may use.
    #[serde(default = "default_stage_tokens")]
    pub max_tokens: u32,
    /// The model cost a stage run may use, in dollars.
    #[serde(default = "default_stage_cost")]
    pub max_cost_usd: f64,
    /// The wall time of one attempt, in seconds.
    #[serde(default = "default_stage_wall_s")]
    pub attempt_timeout_seconds: u32,
    /// The attempts of a stage run.
    #[serde(default = "default_stage_attempts")]
    pub max_attempts: u32,
}

const fn default_stage_wall_s() -> u32 {
    3_600
}
const fn default_stage_tokens() -> u32 {
    2_000_000
}
const fn default_stage_cost() -> f64 {
    10.0
}
const fn default_stage_attempts() -> u32 {
    2
}

impl Default for BudgetSettings {
    fn default() -> Self {
        Self {
            wall_time_seconds: default_stage_wall_s(),
            max_tokens: default_stage_tokens(),
            max_cost_usd: default_stage_cost(),
            attempt_timeout_seconds: default_stage_wall_s(),
            max_attempts: default_stage_attempts(),
        }
    }
}

/// The name and address the factory commits under.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitIdentitySettings {
    /// The author name.
    pub name: String,
    /// The author address.
    pub email: String,
}

impl Default for CommitIdentitySettings {
    fn default() -> Self {
        Self {
            name: "Software Factory".to_owned(),
            email: "factory@users.noreply.invalid".to_owned(),
        }
    }
}

/// How the documentation review builds the target project and finds the tool it documents.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationSettings {
    /// The command that builds the project.
    #[serde(default = "default_docs_build")]
    pub build: Vec<String>,
    /// The program the build makes and the pages describe. The first target of Slice 1 is the
    /// `word-count` fixture; a project manifest will name it for other projects.
    #[serde(default = "default_docs_binary")]
    pub binary: String,
    /// The wall time of one command, in seconds.
    #[serde(default = "default_docs_timeout")]
    pub command_timeout_seconds: u64,
    /// The most output of one command, in bytes.
    #[serde(default = "default_docs_output")]
    pub max_output_bytes: u64,
}

fn default_docs_build() -> Vec<String> {
    ["cargo", "build", "--locked"]
        .iter()
        .map(|word| (*word).to_owned())
        .collect()
}
fn default_docs_binary() -> String {
    "word-count".to_owned()
}
const fn default_docs_timeout() -> u64 {
    120
}
const fn default_docs_output() -> u64 {
    1_048_576
}

impl Default for DocumentationSettings {
    fn default() -> Self {
        Self {
            build: default_docs_build(),
            binary: default_docs_binary(),
            command_timeout_seconds: default_docs_timeout(),
            max_output_bytes: default_docs_output(),
        }
    }
}

/// The agents of the stages, by their id in `agents/`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentNames {
    /// Classifies the request.
    #[serde(default = "agent_intake")]
    pub intake: String,
    /// Writes the specification.
    #[serde(default = "agent_spec_writer")]
    pub specification_writer: String,
    /// Reviews the specification.
    #[serde(default = "agent_spec_reviewer")]
    pub specification_reviewer: String,
    /// Designs.
    #[serde(default = "agent_architect")]
    pub architect: String,
    /// Criticizes the design when its risk tier needs an independent critic. The stage uses only
    /// an agent whose role ends with `_critic`, so the code reviewer cannot stand in for it.
    #[serde(default = "agent_architecture_critic")]
    pub critic: String,
    /// Plans the tasks.
    #[serde(default = "agent_planner")]
    pub planner: String,
    /// Writes the code.
    #[serde(default = "agent_builder")]
    pub builder: String,
    /// Reviews the code. Never the builder.
    #[serde(default = "agent_code_reviewer")]
    pub reviewer: String,
    /// Writes the documentation.
    #[serde(default = "agent_doc_writer")]
    pub documentation_writer: String,
    /// Reviews the documentation.
    #[serde(default = "agent_doc_reviewer")]
    pub documentation_reviewer: String,
}

fn agent_intake() -> String {
    "intake-classifier".to_owned()
}
fn agent_spec_writer() -> String {
    "specification-writer".to_owned()
}
fn agent_spec_reviewer() -> String {
    "specification-reviewer".to_owned()
}
fn agent_architect() -> String {
    "architect".to_owned()
}
fn agent_architecture_critic() -> String {
    "architecture-critic".to_owned()
}
fn agent_code_reviewer() -> String {
    "code-reviewer".to_owned()
}
fn agent_planner() -> String {
    "planner".to_owned()
}
fn agent_builder() -> String {
    "builder".to_owned()
}
fn agent_doc_writer() -> String {
    "documentation-writer".to_owned()
}
fn agent_doc_reviewer() -> String {
    "documentation-reviewer".to_owned()
}

impl Default for AgentNames {
    fn default() -> Self {
        Self {
            intake: agent_intake(),
            specification_writer: agent_spec_writer(),
            specification_reviewer: agent_spec_reviewer(),
            architect: agent_architect(),
            critic: agent_architecture_critic(),
            planner: agent_planner(),
            builder: agent_builder(),
            reviewer: agent_code_reviewer(),
            documentation_writer: agent_doc_writer(),
            documentation_reviewer: agent_doc_reviewer(),
        }
    }
}

/// The settings of the thirteen stages that the stage code does not decide: names, budgets and
/// limits. Every one has a default, the numbers the stage tests use, so a deployment names only what
/// it changes. The commit of the gate definitions has none in the production profile.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageSettings {
    /// The label whose application asks the factory to work.
    #[serde(default = "default_stage_label")]
    pub label: String,
    /// The commit of the factory's own gate definitions, 40 hex digits, recorded in every gate
    /// report. The production profile needs it; the other profiles derive one from the policy.
    #[serde(default)]
    pub definition_commit: Option<String>,
    /// The identity commits are made under.
    #[serde(default)]
    pub commit_identity: CommitIdentitySettings,
    /// The budget of one stage run.
    #[serde(default)]
    pub budget: BudgetSettings,
    /// The largest answer of an agent, in bytes.
    #[serde(default = "default_stage_output")]
    pub max_output_bytes: u64,
    /// The largest patch a stage reads, in bytes.
    #[serde(default = "default_stage_patch")]
    pub max_patch_bytes: u64,
    /// The rounds of questions the specification stage may ask a person.
    #[serde(default = "default_stage_rounds")]
    pub max_clarification_rounds: u32,
    /// The agents.
    #[serde(default)]
    pub agents: AgentNames,
    /// The documentation review.
    #[serde(default)]
    pub documentation: DocumentationSettings,
}

fn default_stage_label() -> String {
    "factory".to_owned()
}
const fn default_stage_output() -> u64 {
    524_288
}
const fn default_stage_patch() -> u64 {
    1_048_576
}
const fn default_stage_rounds() -> u32 {
    2
}

impl Default for StageSettings {
    fn default() -> Self {
        Self {
            label: default_stage_label(),
            definition_commit: None,
            commit_identity: CommitIdentitySettings::default(),
            budget: BudgetSettings::default(),
            max_output_bytes: default_stage_output(),
            max_patch_bytes: default_stage_patch(),
            max_clarification_rounds: default_stage_rounds(),
            agents: AgentNames::default(),
            documentation: DocumentationSettings::default(),
        }
    }
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
    /// The key that signs the requests for decisions. The production profile needs it.
    #[serde(default)]
    pub decisions: Option<DecisionSigning>,
    /// The package registry the dependency gate asks about a new package.
    #[serde(default)]
    pub registry: Option<RegistryConfig>,
    /// Where the date of the advisory database is kept.
    #[serde(default)]
    pub advisory_database: Option<AdvisoryConfig>,
    /// The agent tools in the agent image.
    #[serde(default)]
    pub runtimes: RuntimesConfig,
    /// The settings of the stages: agents, budgets, limits.
    #[serde(default)]
    pub stages: StageSettings,
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
        self.sandbox.validate_docker(self.profile)?;
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
            if self.decisions.is_none() {
                return Err(ConfigError::OutOfRange {
                    field: "decisions.key_file",
                    problem: "the production profile needs the key that signs decision requests",
                });
            }
            if self.stages.definition_commit.is_none() {
                return Err(ConfigError::OutOfRange {
                    field: "stages.definition_commit",
                    problem: "the production profile needs the commit of the gate definitions",
                });
            }
        }
        if let Some(commit) = &self.stages.definition_commit
            && factory_domain::values::GitSha::parse(commit).is_err()
        {
            return Err(ConfigError::OutOfRange {
                field: "stages.definition_commit",
                problem: "must be a commit id of 40 hex digits",
            });
        }
        if self.worker.poll_interval_ms == 0 || self.worker.sweep_interval_s == 0 {
            return Err(ConfigError::OutOfRange {
                field: "worker",
                problem: "the poll and sweep intervals must be above zero",
            });
        }
        self.validate_external_world()
    }

    /// The rules for the settings that point at the outside world: the schemes of the URLs, the
    /// shape of the identifiers and the settings that only the other profiles may use.
    fn validate_external_world(&self) -> Result<(), ConfigError> {
        let production = self.profile == Profile::Production;
        for upstream in &self.broker.upstreams {
            if !matches!(upstream.provider.as_str(), "anthropic" | "openai") {
                return Err(ConfigError::OutOfRange {
                    field: "broker.upstreams[].provider",
                    problem: "must be anthropic or openai",
                });
            }
            endpoint_problem(self.profile, &upstream.base_url).map_or(Ok(()), |problem| {
                Err(ConfigError::OutOfRange {
                    field: "broker.upstreams[].base_url",
                    problem,
                })
            })?;
        }
        if let Some(github) = &self.github {
            endpoint_problem(self.profile, &github.api_base_url).map_or(Ok(()), |problem| {
                Err(ConfigError::OutOfRange {
                    field: "github.api_base_url",
                    problem,
                })
            })?;
            if let Some(problem) = github.web_base_problem(self.profile) {
                return Err(ConfigError::OutOfRange {
                    field: "github.web_base_url",
                    problem,
                });
            }
            for installation in &github.installations {
                installation
                    .tenant
                    .parse::<uuid::Uuid>()
                    .map_err(|_| ConfigError::OutOfRange {
                        field: "github.installations[].tenant",
                        problem: "must be a UUID",
                    })?;
                if !is_repository_name(&installation.repository) {
                    return Err(ConfigError::OutOfRange {
                        field: "github.installations[].repository",
                        problem: "must be owner/name",
                    });
                }
                if installation.installation_id == 0 {
                    return Err(ConfigError::OutOfRange {
                        field: "github.installations[].installation_id",
                        problem: "must be above zero",
                    });
                }
            }
            for statement in &github.bypass_attestations {
                if statement.tenant.parse::<uuid::Uuid>().is_err() {
                    return Err(ConfigError::OutOfRange {
                        field: "github.bypass_attestations[].tenant",
                        problem: "must be a UUID",
                    });
                }
                if !is_repository_name(&statement.repository) {
                    return Err(ConfigError::OutOfRange {
                        field: "github.bypass_attestations[].repository",
                        problem: "must be owner/name",
                    });
                }
                if statement.principal.parse::<uuid::Uuid>().is_err() {
                    return Err(ConfigError::OutOfRange {
                        field: "github.bypass_attestations[].principal",
                        problem: "must be a UUID",
                    });
                }
                if factory_domain::values::Timestamp::parse(&statement.recorded_at).is_err() {
                    return Err(ConfigError::OutOfRange {
                        field: "github.bypass_attestations[].recorded_at",
                        problem: "must be a UTC time such as 2026-10-28T09:00:00Z",
                    });
                }
            }
            let mut acknowledged = std::collections::BTreeSet::new();
            for statement in &github.workflow_exposure_acknowledgements {
                if statement.tenant.parse::<uuid::Uuid>().is_err() {
                    return Err(ConfigError::OutOfRange {
                        field: "github.workflow_exposure_acknowledgements[].tenant",
                        problem: "must be a UUID",
                    });
                }
                if !is_repository_name(&statement.repository) {
                    return Err(ConfigError::OutOfRange {
                        field: "github.workflow_exposure_acknowledgements[].repository",
                        problem: "must be owner/name",
                    });
                }
                if statement.principal.parse::<uuid::Uuid>().is_err() {
                    return Err(ConfigError::OutOfRange {
                        field: "github.workflow_exposure_acknowledgements[].principal",
                        problem: "must be a UUID",
                    });
                }
                if factory_domain::values::Timestamp::parse(&statement.recorded_at).is_err() {
                    return Err(ConfigError::OutOfRange {
                        field: "github.workflow_exposure_acknowledgements[].recorded_at",
                        problem: "must be a UTC time such as 2026-11-12T09:00:00Z",
                    });
                }
                // An empty list would acknowledge nothing, and a path outside the workflow
                // directory names no workflow: both are mistakes a person should hear about.
                let mut paths = std::collections::BTreeSet::new();
                let listed = !statement.workflows.is_empty()
                    && statement.workflows.iter().all(|path| {
                        path.strip_prefix(".github/workflows/")
                            .is_some_and(|name| !name.is_empty() && !name.contains('/'))
                            && paths.insert(path.as_str())
                    });
                if !listed {
                    return Err(ConfigError::OutOfRange {
                        field: "github.workflow_exposure_acknowledgements[].workflows",
                        problem: "must list at least one path, each .github/workflows/<file> and each once",
                    });
                }
                // Two statements for one repository would leave it to chance which one counts.
                if !acknowledged.insert((
                    statement.tenant.to_ascii_lowercase(),
                    statement.repository.to_ascii_lowercase(),
                )) {
                    return Err(ConfigError::OutOfRange {
                        field: "github.workflow_exposure_acknowledgements[].repository",
                        problem: "must appear once for a tenant",
                    });
                }
            }
        }
        if let Some(registry) = &self.registry {
            endpoint_problem(self.profile, &registry.base_url).map_or(Ok(()), |problem| {
                Err(ConfigError::OutOfRange {
                    field: "registry.base_url",
                    problem,
                })
            })?;
            if registry.timeout_seconds == 0 || registry.timeout_seconds > 120 {
                return Err(ConfigError::OutOfRange {
                    field: "registry.timeout_seconds",
                    problem: "must be between 1 and 120",
                });
            }
            if registry.max_response_bytes < 1024 || registry.max_response_bytes > 16 * 1024 * 1024
            {
                return Err(ConfigError::OutOfRange {
                    field: "registry.max_response_bytes",
                    problem: "must be between 1 KiB and 16 MiB",
                });
            }
            if let Some(agent) = &registry.user_agent
                && (agent.trim().is_empty()
                    || agent.len() > 200
                    || agent.chars().any(char::is_control))
            {
                return Err(ConfigError::OutOfRange {
                    field: "registry.user_agent",
                    problem: "must be a short line of printable text",
                });
            }
            if production && registry.user_agent.is_none() {
                return Err(ConfigError::OutOfRange {
                    field: "registry.user_agent",
                    problem: "the production profile needs a User-Agent that says who to reach",
                });
            }
        }
        if let Some(advisory) = &self.advisory_database
            && !advisory.date_file.is_absolute()
        {
            return Err(ConfigError::OutOfRange {
                field: "advisory_database.date_file",
                problem: "must be an absolute path",
            });
        }
        if production && self.runtimes.declare_capabilities {
            return Err(ConfigError::OutOfRange {
                field: "runtimes.declare_capabilities",
                problem: "the production profile probes the runtimes; a declaration is a claim nobody checked",
            });
        }
        Ok(())
    }

    /// Checks the hosts the production profile may reach against the egress policy: the model
    /// providers against `egress.broker_upstreams`, the registry against the cargo hosts of the
    /// `fetch_deps` profile, and GitHub against `api.github.com`. The other profiles may point
    /// anywhere that [`FactoryConfig::validate`] accepts, which includes the loopback interface.
    ///
    /// # Errors
    /// [`ConfigError::OutOfRange`] naming the key whose host the policy does not list.
    pub fn check_endpoints(
        &self,
        policy: &factory_domain::policy::SecurityPolicy,
    ) -> Result<(), ConfigError> {
        if self.profile != Profile::Production {
            return Ok(());
        }
        let not_listed = |field| ConfigError::OutOfRange {
            field,
            problem: "the host is not one the policy lists for the control plane",
        };
        for upstream in &self.broker.upstreams {
            let host = host_of(&upstream.base_url);
            let listed = policy
                .egress
                .broker_upstreams
                .iter()
                .any(|entry| Some(entry.host.as_str()) == host);
            if !listed {
                return Err(not_listed("broker.upstreams[].base_url"));
            }
        }
        if let Some(github) = &self.github
            && host_of(&github.api_base_url) != Some("api.github.com")
        {
            return Err(not_listed("github.api_base_url"));
        }
        if let Some(registry) = &self.registry {
            let host = host_of(&registry.base_url);
            let listed = policy.egress.profiles.fetch_deps.allow.iter().any(|entry| {
                entry.ecosystem.as_deref() == Some("cargo") && Some(entry.host.as_str()) == host
            });
            if !listed {
                return Err(not_listed("registry.base_url"));
            }
        }
        Ok(())
    }

    /// Checks that the host of the links the factory writes is one the output policy allows
    /// (`output_hygiene.allow_link_domains`, a listed host or a subdomain of one). The GitHub
    /// adapter strips a link to any other host, so a `github.web_base_url` that fails this would
    /// give a comment with no link and no error. It is checked in every profile.
    ///
    /// # Errors
    /// [`ConfigError::OutOfRange`] naming `github.web_base_url`.
    pub fn check_link_host(
        &self,
        policy: &factory_domain::policy::SecurityPolicy,
    ) -> Result<(), ConfigError> {
        let Some(github) = &self.github else {
            return Ok(());
        };
        // The host is read by the adapter's own parser (`keeps_link`), so that this check and the
        // filter that strips links cannot disagree about which host an address names. A backslash
        // is refused whatever the host before it is (DR-9).
        let domains: Vec<String> = policy
            .output_hygiene
            .allow_link_domains
            .iter()
            .map(|domain| domain.to_ascii_lowercase())
            .collect();
        let allowed = !github.web_base_url.contains('\\')
            && factory_github::keeps_link(&github.web_base_url, &domains);
        if allowed {
            Ok(())
        } else {
            Err(ConfigError::OutOfRange {
                field: "github.web_base_url",
                problem: "the host is not one output_hygiene.allow_link_domains of the security policy lists, so every link to it would be stripped",
            })
        }
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

/// Reads any configuration type the way [`FactoryConfig::from_yaml`] reads the worker's: the
/// restricted YAML reader (no anchors, no tags, no merge keys, size and depth limits), a refusal of
/// a value that looks like a URL with a password, then the decoding. The type should carry
/// `deny_unknown_fields`, so a misspelled setting is an error and not a weaker run. The API uses
/// this for its own configuration type.
///
/// # Errors
/// A [`ConfigError`].
pub fn read_document<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, ConfigError> {
    let document = yaml::read(text, YamlLimits::POLICY)
        .map_err(|error| ConfigError::Invalid(error.to_string()))?;
    refuse_inline_credentials(&document.to_json(), "")?;
    document
        .decode()
        .map_err(|error| ConfigError::Invalid(error.to_string()))
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

/// The host of a `scheme://host[:port][/path]` URL, without brackets for an IPv6 address.
#[must_use]
pub fn host_of(url: &str) -> Option<&str> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains('@') {
        return None;
    }
    if let Some(inner) = authority.strip_prefix('[') {
        return inner.split_once(']').map(|(host, _)| host);
    }
    authority.split(':').next().filter(|host| !host.is_empty())
}

/// True for a host that is on this machine.
fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

/// Why `url` may not be used as the address of an outside service in `profile`, or `None`.
///
/// `https` is accepted in every profile. Plain `http` is accepted only for the loopback interface
/// and never in the production profile. A URL with user information, a query or a fragment, with
/// white space or without a host is refused.
#[must_use]
pub fn endpoint_problem(profile: Profile, url: &str) -> Option<&'static str> {
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) || url.contains(['?', '#']) {
        return Some("must be a plain URL with no white space, query or fragment");
    }
    let Some(host) = host_of(url) else {
        return Some("must be scheme://host with no user information");
    };
    if url.starts_with("https://") {
        return None;
    }
    if url.starts_with("http://") {
        if profile == Profile::Production {
            return Some("the production profile reaches the outside world over https only");
        }
        return (!is_loopback_host(host))
            .then_some("plain http is accepted only for the loopback interface");
    }
    Some("must start with https://")
}

/// True for `owner/name` with the characters GitHub allows in both parts.
fn is_repository_name(text: &str) -> bool {
    let valid = |part: &str| {
        !part.is_empty()
            && part.len() <= 100
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    text.split_once('/')
        .is_some_and(|(owner, name)| valid(owner) && valid(name) && !name.contains('/'))
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

    const LOOPBACK_WORLD: &str = "github:\n  app_id: 7\n  key_file: /run/secrets/app\n  api_base_url: http://127.0.0.1:9\n  installations:\n    - { tenant: 2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60, repository: example-org/fixture, installation_id: 1 }\n  bypass_attestations:\n    - { tenant: 2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60, repository: example-org/fixture, principal: 9d1f2b1c-3c71-4d51-9a6d-0c3b6a5f7a10, recorded_at: '2026-10-28T09:00:00Z' }\n  workflow_exposure_acknowledgements:\n    - { tenant: 2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60, repository: example-org/fixture, principal: 9d1f2b1c-3c71-4d51-9a6d-0c3b6a5f7a10, recorded_at: '2026-11-12T09:00:00Z', workflows: ['.github/workflows/ci.yml'] }\nregistry: { base_url: 'http://127.0.0.1:9', user_agent: factory-test }\nadvisory_database: { date_file: /srv/db/date }\nruntimes:\n  claude_code: { versions: ['2.1.311'] }\n  declare_capabilities: true\n";

    fn with_world(profile: &str, world: &str) -> String {
        format!(
            "{}{world}",
            minimal(profile, "factory_worker", "factory_engine")
        )
    }

    #[test]
    fn a_complete_loopback_world_loads_in_the_local_profile() {
        let config = FactoryConfig::from_yaml(&with_world("local", LOOPBACK_WORLD)).expect("loads");
        let github = config.github.expect("github");
        assert_eq!(github.installations.len(), 1);
        assert_eq!(github.bypass_attestations.len(), 1);
        assert_eq!(github.workflow_exposure_acknowledgements.len(), 1);
        assert_eq!(
            github.workflow_exposure_acknowledgements[0].workflows,
            [".github/workflows/ci.yml"]
        );
        assert_eq!(config.registry.expect("registry").timeout_seconds, 10);
        assert!(config.runtimes.declare_capabilities);
    }

    #[test]
    fn writing_the_status_on_issues_is_on_unless_the_file_turns_it_off() {
        let on = FactoryConfig::from_yaml(&with_world("local", LOOPBACK_WORLD)).expect("loads");
        assert!(on.github.expect("github").write_issue_status);
        let off_world = LOOPBACK_WORLD.replace(
            "  api_base_url: http://127.0.0.1:9\n",
            "  api_base_url: http://127.0.0.1:9\n  write_issue_status: false\n",
        );
        assert_ne!(off_world, LOOPBACK_WORLD, "the edit applied");
        let off = FactoryConfig::from_yaml(&with_world("local", &off_world)).expect("loads");
        assert!(!off.github.expect("github").write_issue_status);
        // Not a switch for anything else: a misspelling is refused like any unknown key.
        let typo = LOOPBACK_WORLD.replace(
            "  api_base_url: http://127.0.0.1:9\n",
            "  api_base_url: http://127.0.0.1:9\n  write_issue_statuses: false\n",
        );
        assert!(FactoryConfig::from_yaml(&with_world("local", &typo)).is_err());
    }

    #[test]
    fn proposing_the_project_rules_is_on_unless_the_file_turns_it_off() {
        let on = FactoryConfig::from_yaml(&with_world("local", LOOPBACK_WORLD)).expect("loads");
        assert!(on.github.expect("github").propose_project_rules);
        let off_world = LOOPBACK_WORLD.replace(
            "  api_base_url: http://127.0.0.1:9\n",
            "  api_base_url: http://127.0.0.1:9\n  propose_project_rules: false\n",
        );
        assert_ne!(off_world, LOOPBACK_WORLD, "the edit applied");
        let off = FactoryConfig::from_yaml(&with_world("local", &off_world)).expect("loads");
        assert!(!off.github.expect("github").propose_project_rules);
    }

    #[test]
    fn proposing_the_weekly_measurement_is_on_unless_the_file_turns_it_off() {
        let on = FactoryConfig::from_yaml(&with_world("local", LOOPBACK_WORLD)).expect("loads");
        assert!(on.github.expect("github").propose_knowledge_measurements);
        let off_world = LOOPBACK_WORLD.replace(
            "  api_base_url: http://127.0.0.1:9\n",
            "  api_base_url: http://127.0.0.1:9\n  propose_knowledge_measurements: false\n",
        );
        assert_ne!(off_world, LOOPBACK_WORLD, "the edit applied");
        let off = FactoryConfig::from_yaml(&with_world("local", &off_world)).expect("loads");
        assert!(!off.github.expect("github").propose_knowledge_measurements);
    }

    #[test]
    fn following_the_pull_requests_is_on_unless_the_file_turns_it_off() {
        let on = FactoryConfig::from_yaml(&with_world("local", LOOPBACK_WORLD)).expect("loads");
        assert!(on.github.expect("github").follow_pull_requests);
        let off_world = LOOPBACK_WORLD.replace(
            "  api_base_url: http://127.0.0.1:9\n",
            "  api_base_url: http://127.0.0.1:9\n  follow_pull_requests: false\n",
        );
        assert_ne!(off_world, LOOPBACK_WORLD, "the edit applied");
        let off = FactoryConfig::from_yaml(&with_world("local", &off_world)).expect("loads");
        assert!(!off.github.expect("github").follow_pull_requests);
    }

    #[test]
    fn production_refuses_plain_http_for_every_outside_service() {
        // Break: production pointed at an http URL. Each outside address is refused on its own,
        // and not even the loopback interface is an exception in production.
        for (what, field) in [
            (
                "github:\n  app_id: 7\n  key_file: /run/secrets/app\n  api_base_url: http://api.github.com\n",
                "github.api_base_url",
            ),
            (
                "github:\n  app_id: 7\n  key_file: /run/secrets/app\n  api_base_url: http://127.0.0.1:9\n",
                "github.api_base_url",
            ),
        ] {
            let text = production_file(what);
            match FactoryConfig::from_yaml(&text) {
                Err(ConfigError::OutOfRange { field: found, .. }) => assert_eq!(found, field),
                other => panic!("{field}: {other:?}"),
            }
        }
        let registry = production_file(
            "github:\n  app_id: 7\n  key_file: /run/secrets/app\nregistry: { base_url: 'http://crates.io', user_agent: factory }\n",
        );
        assert!(matches!(
            FactoryConfig::from_yaml(&registry),
            Err(ConfigError::OutOfRange {
                field: "registry.base_url",
                ..
            })
        ));
        let provider = production_file("github:\n  app_id: 7\n  key_file: /run/secrets/app\n")
            .replace("https://api.anthropic.com", "http://api.anthropic.com");
        assert!(matches!(
            FactoryConfig::from_yaml(&provider),
            Err(ConfigError::OutOfRange {
                field: "broker.upstreams[].base_url",
                ..
            })
        ));
    }

    /// A production file that satisfies every production rule except what `world` changes.
    fn production_file(world: &str) -> String {
        format!(
            "profile: production\nprotected_checkout: /srv/protected\ndefinitions_root: /srv/protected\n\
             database:\n  tenant: {{ url_file: /run/secrets/a, login: factory_worker }}\n  system: {{ url_file: /run/secrets/b, login: factory_engine }}\n\
             artifacts: {{ root: /var/artifacts }}\n\
             sandbox: {{ images_catalog: /srv/protected/images.json, token_root: /var/tokens, workspace_root: /var/ws }}\n\
             broker:\n  listen: '127.0.0.1:0'\n  upstreams:\n    - {{ provider: anthropic, base_url: 'https://api.anthropic.com', key_file: /run/secrets/k }}\n\
             decisions: {{ key_file: /run/secrets/d }}\n\
             stages: {{ definition_commit: 1405df66cbe219b0bf6355bc3d60361a8376b6b4 }}\n{world}"
        )
    }

    #[test]
    fn the_production_baseline_loads_and_each_world_rule_is_checked_on_top_of_it() {
        let baseline = production_file("github:\n  app_id: 7\n  key_file: /run/secrets/app\n");
        assert!(FactoryConfig::from_yaml(&baseline).is_ok());
        // The registry needs a User-Agent in production.
        let no_agent = production_file(
            "github:\n  app_id: 7\n  key_file: /run/secrets/app\nregistry: { base_url: 'https://crates.io' }\n",
        );
        assert!(matches!(
            FactoryConfig::from_yaml(&no_agent),
            Err(ConfigError::OutOfRange {
                field: "registry.user_agent",
                ..
            })
        ));
        // A declared capability list is a claim nobody checked.
        let declared = production_file(
            "github:\n  app_id: 7\n  key_file: /run/secrets/app\nruntimes: { declare_capabilities: true }\n",
        );
        assert!(matches!(
            FactoryConfig::from_yaml(&declared),
            Err(ConfigError::OutOfRange {
                field: "runtimes.declare_capabilities",
                ..
            })
        ));
    }

    #[test]
    fn plain_http_is_for_the_loopback_interface_only_even_outside_production() {
        let elsewhere = with_world("local", LOOPBACK_WORLD)
            .replace("http://127.0.0.1:9'", "http://example.org'");
        assert!(matches!(
            FactoryConfig::from_yaml(&elsewhere),
            Err(ConfigError::OutOfRange {
                field: "registry.base_url",
                ..
            })
        ));
        for bad in [
            "ftp://x",
            "https://user:x@host",
            "https://h/p?q=1",
            "https://h h",
            "host",
        ] {
            assert!(endpoint_problem(Profile::Local, bad).is_some(), "{bad}");
        }
        assert!(endpoint_problem(Profile::Local, "http://[::1]:80").is_none());
        assert!(endpoint_problem(Profile::Production, "https://api.github.com").is_none());
    }

    #[test]
    fn an_installation_or_a_statement_with_a_bad_identifier_is_refused() {
        for (from, to, field) in [
            (
                "tenant: 2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60, repository: example-org/fixture, installation_id: 1",
                "tenant: nope, repository: example-org/fixture, installation_id: 1",
                "github.installations[].tenant",
            ),
            (
                "repository: example-org/fixture, installation_id: 1",
                "repository: fixture, installation_id: 1",
                "github.installations[].repository",
            ),
            (
                "installation_id: 1",
                "installation_id: 0",
                "github.installations[].installation_id",
            ),
            (
                "principal: 9d1f2b1c-3c71-4d51-9a6d-0c3b6a5f7a10",
                "principal: root",
                "github.bypass_attestations[].principal",
            ),
            (
                "recorded_at: '2026-10-28T09:00:00Z'",
                "recorded_at: yesterday",
                "github.bypass_attestations[].recorded_at",
            ),
            (
                "recorded_at: '2026-11-12T09:00:00Z'",
                "recorded_at: today",
                "github.workflow_exposure_acknowledgements[].recorded_at",
            ),
            (
                "workflows: ['.github/workflows/ci.yml']",
                "workflows: []",
                "github.workflow_exposure_acknowledgements[].workflows",
            ),
            (
                "workflows: ['.github/workflows/ci.yml']",
                "workflows: ['ci.yml']",
                "github.workflow_exposure_acknowledgements[].workflows",
            ),
            (
                "workflows: ['.github/workflows/ci.yml']",
                "workflows: ['.github/workflows/ci.yml', '.github/workflows/ci.yml']",
                "github.workflow_exposure_acknowledgements[].workflows",
            ),
            (
                "workflows: ['.github/workflows/ci.yml']",
                "workflows: ['.github/workflows/sub/ci.yml']",
                "github.workflow_exposure_acknowledgements[].workflows",
            ),
        ] {
            let text = with_world("local", &LOOPBACK_WORLD.replacen(from, to, 1));
            match FactoryConfig::from_yaml(&text) {
                Err(ConfigError::OutOfRange { field: found, .. }) => assert_eq!(found, field),
                other => panic!("{field}: {other:?}"),
            }
        }
    }

    #[test]
    fn break_the_registry_host_removed_from_the_egress_policy_is_refused_in_production() {
        // The stock policy lists `crates.io` (the entry `crates_api`). With that line taken out,
        // production refuses the registry client's address and names the key.
        let mut policy = crate::startup::tests_support::repository_security_policy();
        let registry = production_file(
            "github:\n  app_id: 7\n  key_file: /run/secrets/app\nregistry: { base_url: 'https://crates.io', user_agent: factory }\n",
        );
        let config = FactoryConfig::from_yaml(&registry).expect("loads");
        assert!(
            config.check_endpoints(&policy).is_ok(),
            "the stock policy lists it"
        );
        let before = policy.egress.profiles.fetch_deps.allow.len();
        policy
            .egress
            .profiles
            .fetch_deps
            .allow
            .retain(|entry| entry.host != "crates.io");
        assert_eq!(policy.egress.profiles.fetch_deps.allow.len(), before - 1);
        assert!(matches!(
            config.check_endpoints(&policy),
            Err(ConfigError::OutOfRange {
                field: "registry.base_url",
                ..
            })
        ));
    }

    #[test]
    fn the_production_hosts_are_checked_against_the_egress_policy() {
        let policy = crate::startup::tests_support::repository_security_policy();
        let listed = FactoryConfig::from_yaml(&production_file(
            "github:\n  app_id: 7\n  key_file: /run/secrets/app\n",
        ))
        .expect("loads");
        assert!(listed.check_endpoints(&policy).is_ok());
        // A provider host the policy does not list.
        let other = production_file("github:\n  app_id: 7\n  key_file: /run/secrets/app\n")
            .replace("https://api.anthropic.com", "https://models.example.org");
        assert!(matches!(
            FactoryConfig::from_yaml(&other)
                .expect("loads")
                .check_endpoints(&policy),
            Err(ConfigError::OutOfRange {
                field: "broker.upstreams[].base_url",
                ..
            })
        ));
        // The registry API of crates.io is among the cargo hosts of the stock policy (`crates_api`),
        // so production accepts it; a registry the policy does not list is refused.
        let registry = production_file(
            "github:\n  app_id: 7\n  key_file: /run/secrets/app\nregistry: { base_url: 'https://crates.io', user_agent: factory }\n",
        );
        assert!(
            FactoryConfig::from_yaml(&registry)
                .expect("loads")
                .check_endpoints(&policy)
                .is_ok()
        );
        let elsewhere = registry.replace("https://crates.io", "https://registry.example.org");
        assert!(matches!(
            FactoryConfig::from_yaml(&elsewhere)
                .expect("loads")
                .check_endpoints(&policy),
            Err(ConfigError::OutOfRange {
                field: "registry.base_url",
                ..
            })
        ));
        let index = registry.replace("https://crates.io", "https://index.crates.io");
        assert!(
            FactoryConfig::from_yaml(&index)
                .expect("loads")
                .check_endpoints(&policy)
                .is_ok()
        );
        // GitHub: only api.github.com in production.
        let ghe = production_file(
            "github:\n  app_id: 7\n  key_file: /run/secrets/app\n  api_base_url: https://ghe.example.org/api/v3\n",
        );
        assert!(matches!(
            FactoryConfig::from_yaml(&ghe)
                .expect("loads")
                .check_endpoints(&policy),
            Err(ConfigError::OutOfRange {
                field: "github.api_base_url",
                ..
            })
        ));
        // The other profiles are not held to the list.
        let local = FactoryConfig::from_yaml(&with_world("local", LOOPBACK_WORLD)).expect("loads");
        assert!(local.check_endpoints(&policy).is_ok());
    }

    /// `text` with `extra` added to the inline `sandbox` table of the files above.
    fn with_sandbox_keys(text: &str, extra: &str) -> String {
        let edited = text.replace(
            "workspace_root: /var/ws }",
            &format!("workspace_root: /var/ws, {extra} }}"),
        );
        assert_ne!(edited, text, "the edit applied");
        edited
    }

    fn refused_key(text: &str) -> &'static str {
        match FactoryConfig::from_yaml(text) {
            Err(ConfigError::OutOfRange { field, .. }) => field,
            other => panic!("expected a refusal that names a key: {other:?}"),
        }
    }

    #[test]
    fn the_docker_keys_default_to_the_clients_own_defaults() {
        let config = FactoryConfig::from_yaml(&minimal("local", "a", "b")).expect("loads");
        assert_eq!(config.sandbox.docker_host, None);
        assert_eq!(config.sandbox.docker_config, None);
        assert!(!config.sandbox.allow_remote_docker);
    }

    #[test]
    fn a_unix_socket_or_a_loopback_tcp_address_is_accepted_as_the_docker_host() {
        for host in [
            "unix:///var/run/docker.sock",
            "unix:///run/user/1000/docker.sock",
            "unix:///Users/someone/.colima/default/docker.sock",
            "tcp://127.0.0.1:2375",
            "tcp://localhost:2376",
            "tcp://[::1]:2375",
        ] {
            let text = with_sandbox_keys(
                &minimal("local", "a", "b"),
                &format!("docker_host: '{host}'"),
            );
            let config = FactoryConfig::from_yaml(&text).unwrap_or_else(|e| panic!("{host}: {e}"));
            assert_eq!(config.sandbox.docker_host.as_deref(), Some(host));
        }
    }

    #[test]
    fn a_docker_host_that_is_not_a_socket_or_a_loopback_address_is_refused_naming_the_key() {
        for host in [
            // A remote daemon without the explicit flag.
            "tcp://10.0.0.5:2375",
            "tcp://docker.example.org:2376",
            // Hosts that only look like the loopback interface.
            "tcp://127.0.0.1.example.org:2375",
            "tcp://localhost.example.org:2375",
            "tcp://127.0.0.1@example.org:2375",
            "tcp://0.0.0.0:2375",
            // A port is part of the address.
            "tcp://127.0.0.1",
            "tcp://127.0.0.1:0",
            "tcp://127.0.0.1:70000",
            "tcp://127.0.0.1:http",
            // Other transports, and shapes that are not an address at all.
            "ssh://user@127.0.0.1",
            "http://127.0.0.1:2375",
            "npipe:////./pipe/docker_engine",
            "fd://",
            "unix://docker.sock",
            "unix://",
            "unix:///",
            "unix:///var/run/../docker.sock",
            "/var/run/docker.sock",
            "",
            "unix:///var/run/docker .sock",
        ] {
            let text = with_sandbox_keys(
                &minimal("local", "a", "b"),
                &format!("docker_host: '{host}'"),
            );
            assert_eq!(refused_key(&text), "sandbox.docker_host", "{host:?}");
        }
    }

    #[test]
    fn a_remote_docker_host_needs_the_explicit_flag_and_the_production_profile_refuses_the_flag() {
        let remote = "docker_host: 'tcp://10.0.0.5:2375'";
        let local = minimal("local", "a", "b");
        assert_eq!(
            refused_key(&with_sandbox_keys(&local, remote)),
            "sandbox.docker_host"
        );
        let allowed = with_sandbox_keys(&local, &format!("{remote}, allow_remote_docker: true"));
        let config = FactoryConfig::from_yaml(&allowed).expect("the flag allows it");
        assert_eq!(
            config.sandbox.docker_host.as_deref(),
            Some("tcp://10.0.0.5:2375")
        );
        // Production: the flag is refused, with or without a remote address behind it.
        let baseline = production_file("github:\n  app_id: 7\n  key_file: /run/secrets/app\n");
        assert!(FactoryConfig::from_yaml(&baseline).is_ok());
        for extra in [
            format!("{remote}, allow_remote_docker: true"),
            "allow_remote_docker: true".to_owned(),
        ] {
            assert_eq!(
                refused_key(&with_sandbox_keys(&baseline, &extra)),
                "sandbox.allow_remote_docker",
                "{extra}"
            );
        }
        // Production still accepts the sockets and the loopback addresses.
        for host in ["unix:///var/run/docker.sock", "tcp://127.0.0.1:2375"] {
            let text = with_sandbox_keys(&baseline, &format!("docker_host: '{host}'"));
            FactoryConfig::from_yaml(&text).unwrap_or_else(|e| panic!("{host}: {e}"));
        }
        assert_eq!(
            refused_key(&with_sandbox_keys(
                &baseline,
                "docker_host: 'tcp://10.0.0.5:2375'"
            )),
            "sandbox.docker_host"
        );
    }

    #[test]
    fn the_docker_config_directory_must_be_an_absolute_path() {
        let local = minimal("local", "a", "b");
        let ok = with_sandbox_keys(&local, "docker_config: /home/factory/.docker");
        let config = FactoryConfig::from_yaml(&ok).expect("loads");
        assert_eq!(
            config.sandbox.docker_config,
            Some(PathBuf::from("/home/factory/.docker"))
        );
        for bad in [
            "'.docker'",
            "'~/.docker'",
            "'../docker'",
            "''",
            "/home/../etc/docker",
        ] {
            let text = with_sandbox_keys(&local, &format!("docker_config: {bad}"));
            assert_eq!(refused_key(&text), "sandbox.docker_config", "{bad}");
        }
    }

    // ---- the host of the links the factory writes (LB-08) -------------------------------------------

    fn web_world(web: &str) -> String {
        LOOPBACK_WORLD.replace(
            "  api_base_url: http://127.0.0.1:9\n",
            &format!("  api_base_url: http://127.0.0.1:9\n  web_base_url: '{web}'\n"),
        )
    }

    #[test]
    fn the_web_base_defaults_to_github_dot_com() {
        let config = FactoryConfig::from_yaml(&with_world("local", LOOPBACK_WORLD)).expect("loads");
        assert_eq!(
            config.github.expect("github").web_base_url,
            "https://github.com"
        );
    }

    #[test]
    fn a_github_enterprise_style_web_base_is_accepted() {
        for web in [
            "https://ghe.example.org",
            "https://ghe.example.org/",
            "https://ghe.example.org:8443",
            "https://git.corp.example.org",
        ] {
            let config = FactoryConfig::from_yaml(&with_world("local", &web_world(web)))
                .unwrap_or_else(|e| panic!("{web}: {e}"));
            assert_eq!(config.github.expect("github").web_base_url, web);
        }
        // The loopback interface may use plain http outside production, like every address here.
        let local =
            FactoryConfig::from_yaml(&with_world("local", &web_world("http://127.0.0.1:3000")));
        assert!(local.is_ok(), "{local:?}");
    }

    #[test]
    fn a_web_base_that_is_not_a_plain_host_url_is_refused_naming_the_key() {
        for web in [
            "http://ghe.example.org",
            "ghe.example.org",
            "ftp://ghe.example.org",
            "https://ghe.example.org/some/path",
            "https://ghe.example.org?x=1",
            "https://user@ghe.example.org",
            "https://ghe.example.org/#x",
            "https://",
        ] {
            let text = with_world("local", &web_world(web));
            assert_eq!(refused_key(&text), "github.web_base_url", "{web}");
        }
        // Production reaches the outside world over https only, the loopback interface included.
        let production = production_file(
            "github:\n  app_id: 7\n  key_file: /run/secrets/app\n  web_base_url: 'http://127.0.0.1:3000'\n",
        );
        assert_eq!(refused_key(&production), "github.web_base_url");
    }

    #[test]
    fn the_link_host_must_be_one_the_output_policy_allows_or_the_start_stops() {
        let mut policy = crate::startup::tests_support::repository_security_policy();
        assert_eq!(
            policy.output_hygiene.allow_link_domains,
            ["github.com".to_owned()]
        );
        let stock = FactoryConfig::from_yaml(&with_world("local", LOOPBACK_WORLD)).expect("loads");
        assert!(stock.check_link_host(&policy).is_ok());
        let enterprise = FactoryConfig::from_yaml(&with_world(
            "local",
            &web_world("https://ghe.example.org:8443"),
        ))
        .expect("loads");
        // The host is not on the list: the adapter would strip every link, and the start says so.
        assert!(matches!(
            enterprise.check_link_host(&policy),
            Err(ConfigError::OutOfRange {
                field: "github.web_base_url",
                ..
            })
        ));
        // A host that only ends like a listed one is not a subdomain of it.
        policy.output_hygiene.allow_link_domains = vec!["example.org".to_owned()];
        assert!(enterprise.check_link_host(&policy).is_ok(), "a subdomain");
        policy.output_hygiene.allow_link_domains = vec!["xample.org".to_owned()];
        assert!(enterprise.check_link_host(&policy).is_err());
        policy.output_hygiene.allow_link_domains = vec!["GHE.example.org".to_owned()];
        assert!(enterprise.check_link_host(&policy).is_ok(), "case");
    }

    // ---- the host of a link is read the way the adapter reads it (DR-9) -----------------------------

    #[test]
    fn a_web_base_that_the_adapters_link_filter_would_strip_is_refused_naming_the_key() {
        // The filter reads the host like a browser: a backslash ends it, user information and any
        // character that is not part of a name, a port or an address make it unknown. A start that
        // let such an address through would write comments with no link and say nothing (DR-9).
        for web in [
            "https://attacker.test\\.github.com",
            "https://github.com\\@attacker.test",
            "https://github.com\\.attacker.test:8443",
            "https://github.com\\",
            "https://attacker.test\\",
            "https://git%68ub.com",
            "https://github.com%2eattacker.test",
            "https://[::1]:3000",
            "https://gith\u{fb}b.com",
            "https://github.com;attacker.test",
            "https://github.com,attacker.test",
        ] {
            let text = with_world("local", &web_world(web));
            assert_eq!(refused_key(&text), "github.web_base_url", "{web:?}");
        }
        // Production is held to the same rule, with or without the other checks of its profile.
        let production = production_file(
            "github:\n  app_id: 7\n  key_file: /run/secrets/app\n  web_base_url: 'https://attacker.test\\.github.com'\n",
        );
        assert_eq!(refused_key(&production), "github.web_base_url");
    }

    #[test]
    fn the_link_host_check_uses_the_host_the_adapter_uses_so_a_backslash_cannot_hide_a_host() {
        // The parser of the start-up check once ended the authority at a slash only, so
        // `attacker.test\.github.com` looked like a subdomain of github.com. `check_link_host` is
        // the second line: it must refuse the address even if the first check is bypassed.
        let policy = crate::startup::tests_support::repository_security_policy();
        for web in [
            "https://attacker.test\\.github.com",
            "https://github.com\\@attacker.test",
            "https://attacker.test\\",
            "http://github.com",
            "https://git%68ub.com",
        ] {
            let mut config =
                FactoryConfig::from_yaml(&with_world("local", LOOPBACK_WORLD)).expect("loads");
            config.github.as_mut().expect("github").web_base_url = web.to_owned();
            assert!(
                matches!(
                    config.check_link_host(&policy),
                    Err(ConfigError::OutOfRange {
                        field: "github.web_base_url",
                        ..
                    })
                ),
                "{web:?}"
            );
        }
        // The stock address and a subdomain of a listed host still pass.
        let mut config =
            FactoryConfig::from_yaml(&with_world("local", LOOPBACK_WORLD)).expect("loads");
        for web in ["https://github.com", "https://GitHub.com:443"] {
            config.github.as_mut().expect("github").web_base_url = web.to_owned();
            assert!(config.check_link_host(&policy).is_ok(), "{web}");
        }
    }

    // ---- a Docker configuration directory that names a daemon (DR-6) ---------------------------------

    #[test]
    fn the_flag_that_allows_contexts_in_the_docker_config_defaults_to_off() {
        let config = FactoryConfig::from_yaml(&minimal("local", "a", "b")).expect("loads");
        assert!(!config.sandbox.allow_docker_config_contexts);
    }

    #[test]
    fn the_flag_for_contexts_in_the_docker_config_is_refused_in_production_with_or_without_a_directory()
     {
        let baseline = production_file("github:\n  app_id: 7\n  key_file: /run/secrets/app\n");
        for extra in [
            "allow_docker_config_contexts: true",
            "docker_config: /var/lib/factory/docker, allow_docker_config_contexts: true",
        ] {
            assert_eq!(
                refused_key(&with_sandbox_keys(&baseline, extra)),
                "sandbox.allow_docker_config_contexts",
                "{extra}"
            );
        }
        // Off, it is accepted, and so is a directory in production.
        let off = with_sandbox_keys(
            &baseline,
            "docker_config: /var/lib/factory/docker, allow_docker_config_contexts: false",
        );
        FactoryConfig::from_yaml(&off).expect("loads");
        // The other profiles may turn it on: it is an explicit choice.
        let local = with_sandbox_keys(
            &minimal("local", "a", "b"),
            "docker_config: /home/factory/.docker, allow_docker_config_contexts: true",
        );
        let config = FactoryConfig::from_yaml(&local).expect("loads");
        assert!(config.sandbox.allow_docker_config_contexts);
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
