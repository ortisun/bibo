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

/// An administrator's statement that the App is on no bypass list of a repository. The App cannot
/// read the bypass list itself (it may not hold the Administration permission), so a person says it
/// and the deployment records it here. Without a statement the repository runs at level L0.
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
}

fn default_github_api() -> String {
    "https://api.github.com".to_owned()
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
    /// Criticizes the design.
    #[serde(default = "agent_code_reviewer")]
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
            critic: agent_code_reviewer(),
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
            endpoint_problem(self.profile, &upstream.base_url)
                .map_or(Ok(()), |problem| {
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
            for installation in &github.installations {
                installation.tenant.parse::<uuid::Uuid>().map_err(|_| {
                    ConfigError::OutOfRange {
                        field: "github.installations[].tenant",
                        problem: "must be a UUID",
                    }
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
            let listed = policy
                .egress
                .profiles
                .fetch_deps
                .allow
                .iter()
                .any(|entry| {
                    entry.ecosystem.as_deref() == Some("cargo")
                        && Some(entry.host.as_str()) == host
                });
            if !listed {
                return Err(not_listed("registry.base_url"));
            }
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

    const LOOPBACK_WORLD: &str = "github:\n  app_id: 7\n  key_file: /run/secrets/app\n  api_base_url: http://127.0.0.1:9\n  installations:\n    - { tenant: 2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60, repository: example-org/fixture, installation_id: 1 }\n  bypass_attestations:\n    - { tenant: 2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60, repository: example-org/fixture, principal: 9d1f2b1c-3c71-4d51-9a6d-0c3b6a5f7a10, recorded_at: '2026-10-28T09:00:00Z' }\nregistry: { base_url: 'http://127.0.0.1:9', user_agent: factory-test }\nadvisory_database: { date_file: /srv/db/date }\nruntimes:\n  claude_code: { versions: ['2.1.311'] }\n  declare_capabilities: true\n";

    fn with_world(profile: &str, world: &str) -> String {
        format!("{}{world}", minimal(profile, "factory_worker", "factory_engine"))
    }

    #[test]
    fn a_complete_loopback_world_loads_in_the_local_profile() {
        let config = FactoryConfig::from_yaml(&with_world("local", LOOPBACK_WORLD)).expect("loads");
        let github = config.github.expect("github");
        assert_eq!(github.installations.len(), 1);
        assert_eq!(github.bypass_attestations.len(), 1);
        assert_eq!(config.registry.expect("registry").timeout_seconds, 10);
        assert!(config.runtimes.declare_capabilities);
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
        let elsewhere = with_world("local", LOOPBACK_WORLD).replace("http://127.0.0.1:9'", "http://example.org'");
        assert!(matches!(
            FactoryConfig::from_yaml(&elsewhere),
            Err(ConfigError::OutOfRange {
                field: "registry.base_url",
                ..
            })
        ));
        for bad in ["ftp://x", "https://user:x@host", "https://h/p?q=1", "https://h h", "host"] {
            assert!(endpoint_problem(Profile::Local, bad).is_some(), "{bad}");
        }
        assert!(endpoint_problem(Profile::Local, "http://[::1]:80").is_none());
        assert!(endpoint_problem(Profile::Production, "https://api.github.com").is_none());
    }

    #[test]
    fn an_installation_or_a_statement_with_a_bad_identifier_is_refused() {
        for (from, to, field) in [
            ("tenant: 2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60, repository: example-org/fixture, installation_id: 1", "tenant: nope, repository: example-org/fixture, installation_id: 1", "github.installations[].tenant"),
            ("repository: example-org/fixture, installation_id: 1", "repository: fixture, installation_id: 1", "github.installations[].repository"),
            ("installation_id: 1", "installation_id: 0", "github.installations[].installation_id"),
            ("principal: 9d1f2b1c-3c71-4d51-9a6d-0c3b6a5f7a10", "principal: root", "github.bypass_attestations[].principal"),
            ("recorded_at: '2026-10-28T09:00:00Z'", "recorded_at: yesterday", "github.bypass_attestations[].recorded_at"),
        ] {
            let text = with_world("local", &LOOPBACK_WORLD.replacen(from, to, 1));
            match FactoryConfig::from_yaml(&text) {
                Err(ConfigError::OutOfRange { field: found, .. }) => assert_eq!(found, field),
                other => panic!("{field}: {other:?}"),
            }
        }
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
            FactoryConfig::from_yaml(&other).expect("loads").check_endpoints(&policy),
            Err(ConfigError::OutOfRange { field: "broker.upstreams[].base_url", .. })
        ));
        // The registry API of crates.io is not among the cargo hosts the stock policy lists, so
        // production refuses it until a person adds the host.
        let registry = production_file(
            "github:\n  app_id: 7\n  key_file: /run/secrets/app\nregistry: { base_url: 'https://crates.io', user_agent: factory }\n",
        );
        assert!(matches!(
            FactoryConfig::from_yaml(&registry).expect("loads").check_endpoints(&policy),
            Err(ConfigError::OutOfRange { field: "registry.base_url", .. })
        ));
        let index = registry.replace("https://crates.io", "https://index.crates.io");
        assert!(FactoryConfig::from_yaml(&index).expect("loads").check_endpoints(&policy).is_ok());
        // GitHub: only api.github.com in production.
        let ghe = production_file(
            "github:\n  app_id: 7\n  key_file: /run/secrets/app\n  api_base_url: https://ghe.example.org/api/v3\n",
        );
        assert!(matches!(
            FactoryConfig::from_yaml(&ghe).expect("loads").check_endpoints(&policy),
            Err(ConfigError::OutOfRange { field: "github.api_base_url", .. })
        ));
        // The other profiles are not held to the list.
        let local = FactoryConfig::from_yaml(&with_world("local", LOOPBACK_WORLD)).expect("loads");
        assert!(local.check_endpoints(&policy).is_ok());
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
