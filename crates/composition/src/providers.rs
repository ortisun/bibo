//! The real providers, assembled from the configuration: the Docker sandbox, the host-side git
//! workspace and the Spec Kit provider, with the process runner they share.
//!
//! [`assemble`] builds only real adapters. A fake never comes from here: the fakes are in the
//! testkit, which no library of this workspace may link (DEP-03), so a test wiring that wants a
//! stand-in builds its own registry. What the profile decides is which adapters may stand in for
//! the ports a deployment cannot fill without a credential; [`crate::registry::PortRegistry::check`]
//! runs that decision for every port, and the production profile refuses all stand-ins.
//!
//! # What each provider is built from
//!
//! | Provider | Built from |
//! |---|---|
//! | Process runner | `SystemProcessRunner`: `docker` and `git` on a fixed path (the only code that starts a process, DEP-10) |
//! | Sandbox | the sandbox section of the policy (`sandbox_policy_from`), the image catalog text, the platform, the token root, the owner label, the sidecar arguments; wrapped by [`IndexingSandbox`] so command output is readable by the tenant |
//! | Workspace | the workspace root, the remote (`https` or, outside production, a local directory), the path rules of the policy and the compiled path policy as a second look; wrapped by [`IndexingWorkspaces`] so an exported patch is readable by the tenant |
//! | Specification | the host and separator of the Spec Kit installation in the protected checkout (`.specify/integration.json`), the execution mode of the profile |
//!
//! The AppArmor profile may be unavailable on the host in the `local` and `test` profiles (Docker
//! Desktop on a laptop). Production never accepts that.
//!
//! # What this does not do
//!
//! The workspace provider fetches with a credential the change host mints for each job. The change
//! host needs a registered GitHub App, so a deployment can assemble the provider and cannot fetch
//! from GitHub until the App exists. That is BLOCKED and stays so.

use std::sync::Arc;
use std::time::Duration;

use factory_domain::policy::paths::PathPolicy;
use factory_domain::policy::security::{AppliesTo, ProtectionMode};
use factory_domain::policy::{RepoKind, SecurityPolicy};
use factory_domain::redaction::Redactor;
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::paths::{PathMode, PathRule, PathRules, RepoGlob};
use factory_ports::process::ProcessRunner;
use factory_ports::sandbox::SandboxProvider;
use factory_ports::spec::SpecificationProvider;
use factory_ports::store::Store;
use factory_ports::workspace::WorkspaceProvider;
use factory_sandbox::container::docker::DockerSettings;
use factory_sandbox::workspace::PathPolicyLayer;
use factory_sandbox::workspace::RemoteLocation;
use factory_sandbox::{
    DockerSandboxProvider, GitWorkspaceProvider, ProviderConfig, SystemProcessRunner,
    WatchdogSettings, WorkspaceSettings,
};
use factory_spec_adapter::invocation::IntegrationConfig;
use factory_spec_adapter::{SpecKitConfig, SpecKitProvider};

use crate::config::{FactoryConfig, Remote, RemoteConfig, SandboxConfig};
use crate::indexing::{ActiveJobs, IndexingSandbox, IndexingWorkspaces};
use crate::profile::Profile;
use crate::sandbox_specs::sandbox_policy_from;
use crate::startup::LoadedPolicies;

/// The label every container, network and volume of this factory carries, with the configured
/// owner as its value. The janitor touches only objects that carry it. (It does not start with
/// `factory.`: that prefix is the telemetry attribute namespace, ST-07.)
pub const OWNER_LABEL: &str = "io.factory.owner";

/// Why the providers could not be assembled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderError {
    /// A limit in the sandbox section of the policy is zero or does not fit.
    #[error("the sandbox section of the policy cannot be turned into a sandbox policy")]
    SandboxPolicy,
    /// The image catalog file cannot be read.
    #[error("the image catalog {0} cannot be read")]
    Catalog(String),
    /// The compiled path policy cannot be built.
    #[error("the path policy cannot be compiled from the security policy")]
    PathPolicy,
    /// The remote names both an https host and a directory, or a directory that is not absolute.
    #[error("the remote of the workspaces is not a single, valid choice")]
    Remote,
    /// The Spec Kit installation file is missing or not the expected JSON.
    #[error("the Spec Kit installation at {0} cannot be read: {1}")]
    Installation(String, String),
    /// `sandbox.docker_config` is not a directory on this machine.
    #[error("sandbox.docker_config: {0} is not a directory on this machine")]
    DockerConfig(String),
    /// `sandbox.docker_config` is a directory that names a Docker daemon or a credential helper,
    /// or whose content cannot be judged (DR-6).
    #[error(
        "sandbox.docker_config: {0} {1}; a Docker configuration directory may not name a daemon or a credential helper unless sandbox.allow_docker_config_contexts is true (never in the production profile)"
    )]
    DockerConfigContent(String, &'static str),
}

/// The most bytes of `config.json` of the Docker client that are read. A larger file is not a
/// configuration file anyone wrote by hand, and it is refused rather than read.
const DOCKER_CONFIG_FILE_LIMIT: u64 = 1024 * 1024;

/// Why the Docker client's configuration directory may not be used, or `None` (DR-6). It is used
/// when it has no `contexts` entry, and its `config.json`, if it has one, names no `currentContext`
/// other than the default and no `credsStore` or `credHelpers`: a context can point the client at
/// a daemon on another machine whatever `docker_host` says, and a credential helper is a program
/// the client would run. Anything that cannot be read, or is not what it should be (a `contexts`
/// that is not a folder, a `config.json` that is a link, not an object or not JSON), is a reason:
/// the check fails closed.
fn docker_config_problem(directory: &std::path::Path) -> Option<&'static str> {
    use std::io::ErrorKind::NotFound;
    match std::fs::symlink_metadata(directory.join("contexts")) {
        Ok(found) if !found.is_dir() => return Some("has a contexts entry that is not a folder"),
        Ok(_) => match std::fs::read_dir(directory.join("contexts")) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    return Some("has a contexts folder with an entry, which can name a daemon");
                }
            }
            Err(_) => return Some("has a contexts folder that cannot be read"),
        },
        Err(error) if error.kind() == NotFound => {}
        Err(_) => return Some("has a contexts entry that cannot be read"),
    }
    let file = directory.join("config.json");
    match std::fs::symlink_metadata(&file) {
        Err(error) if error.kind() == NotFound => return None,
        Err(_) => return Some("has a config.json that cannot be read"),
        Ok(found) if !found.is_file() || found.len() > DOCKER_CONFIG_FILE_LIMIT => {
            return Some("has a config.json that is not a plain file of a sensible size");
        }
        Ok(_) => {}
    }
    let Ok(bytes) = std::fs::read(&file) else {
        return Some("has a config.json that cannot be read");
    };
    let Ok(serde_json::Value::Object(config)) = serde_json::from_slice(&bytes) else {
        return Some("has a config.json that is not a JSON object");
    };
    // The values that mean "none" are the ones the client itself reads as none.
    match config.get("currentContext") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::String(name)) if name.is_empty() || name == "default" => {}
        Some(_) => {
            return Some("has a config.json that names a currentContext other than the default");
        }
    }
    match config.get("credsStore") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::String(name)) if name.is_empty() => {}
        Some(_) => return Some("has a config.json that names a credential helper (credsStore)"),
    }
    match config.get("credHelpers") {
        None | Some(serde_json::Value::Null) => {}
        Some(serde_json::Value::Object(map)) if map.is_empty() => {}
        Some(_) => return Some("has a config.json that names credential helpers (credHelpers)"),
    }
    None
}

/// The settings of the `docker` client from the sandbox section of the configuration. The client
/// runs with an empty environment, so `DOCKER_HOST` and `DOCKER_CONFIG` reach it only through
/// here, and only when the configuration names them.
///
/// # Errors
/// [`ProviderError::DockerConfig`] when `sandbox.docker_config` is not a directory.
pub fn docker_settings_from(sandbox: &SandboxConfig) -> Result<DockerSettings, ProviderError> {
    let mut settings = DockerSettings::default();
    if let Some(host) = &sandbox.docker_host {
        settings.env.push(("DOCKER_HOST".to_owned(), host.clone()));
    }
    if let Some(directory) = &sandbox.docker_config {
        if !directory.is_dir() {
            return Err(ProviderError::DockerConfig(directory.display().to_string()));
        }
        if !sandbox.allow_docker_config_contexts {
            if let Some(problem) = docker_config_problem(directory) {
                return Err(ProviderError::DockerConfigContent(
                    directory.display().to_string(),
                    problem,
                ));
            }
        }
        settings
            .env
            .push(("DOCKER_CONFIG".to_owned(), directory.display().to_string()));
        if !sandbox.allow_docker_config_contexts {
            // What the directory holds when a command runs can differ from what it held at the
            // start. The default context is the one named by `DOCKER_HOST` or the default socket,
            // so a `currentContext` that appears later cannot redirect the client.
            settings
                .env
                .push(("DOCKER_CONTEXT".to_owned(), "default".to_owned()));
        }
    }
    Ok(settings)
}

/// What [`assemble`] needs from the rest of the start-up.
pub struct ProviderInputs<'a> {
    /// The configuration.
    pub config: &'a FactoryConfig,
    /// The loaded policies.
    pub policies: &'a LoadedPolicies,
    /// The one redactor of the process.
    pub redactor: Arc<Redactor>,
    /// Where blobs live.
    pub artifacts: Arc<dyn ArtifactStore>,
    /// Time.
    pub clock: Arc<dyn Clock>,
    /// Identifiers.
    pub ids: Arc<dyn IdGenerator>,
    /// The store, for the indexing wrappers.
    pub store: Arc<dyn Store>,
    /// The jobs the loop is working on, for the indexing wrappers.
    pub jobs: Arc<ActiveJobs>,
    /// The runner of host processes. Production passes [`SystemProcessRunner`]; a test that must
    /// watch what is started passes a recorder.
    pub runner: Arc<dyn ProcessRunner>,
}

/// The providers.
#[derive(Clone)]
pub struct Providers {
    /// The process runner the others use.
    pub process: Arc<dyn ProcessRunner>,
    /// The sandbox provider, indexing its output.
    pub sandbox: Arc<dyn SandboxProvider>,
    /// The workspace provider, indexing its patches.
    pub workspaces: Arc<dyn WorkspaceProvider>,
    /// The Spec Kit provider.
    pub specification: Arc<dyn SpecificationProvider>,
}

/// The real process runner.
#[must_use]
pub fn system_runner() -> Arc<dyn ProcessRunner> {
    Arc::new(SystemProcessRunner::new())
}

/// The ports rules of the agent view of a target repository, built from the protection groups of
/// the policy in the order the policy lists them.
#[must_use]
pub fn path_rules(policy: &SecurityPolicy) -> PathRules {
    let mut rules = Vec::new();
    for group in &policy.protected_paths.groups {
        if matches!(group.applies_to, AppliesTo::FactoryRepo) {
            continue;
        }
        let mode = match group.mode {
            ProtectionMode::Hidden => PathMode::Hidden,
            ProtectionMode::DenyWrite => PathMode::DenyWrite,
            ProtectionMode::AppendOnly => PathMode::AppendOnly,
            ProtectionMode::AdditionsOnly => PathMode::AdditionsOnly,
        };
        for glob in &group.globs {
            let Ok(parsed) = RepoGlob::new(glob.pattern()) else {
                continue;
            };
            let rule = if glob.is_reinclusion() {
                PathRule::Reinclude {
                    glob: parsed,
                    group: group.id.clone(),
                }
            } else {
                PathRule::Mode { glob: parsed, mode }
            };
            rules.push((group.id.clone(), rule));
        }
    }
    PathRules::new(rules)
}

/// The path rules of the specification stage: those of [`path_rules`], with the files that the
/// allowed Spec Kit skills write taken out of the protection groups.
///
/// The policy protects `.specify/**` (`factory_config`, `deny_write`), and the same policy lists
/// `.specify/feature.json` among the writes of `speckit.specify`
/// (`agent_stage_profiles.profiles[specification].skills.allowed`). With the plain rules the host
/// refuses the pointer the skill must leave, the audit says `protected-path-changed`, and the
/// stage is blocked on its first run. The policy marks the one skill that does need a person's
/// exception (`protected_path_exception_required`, the constitution); every other write it lists
/// is lifted here, for this stage only, and nothing else under `.specify/` is.
#[must_use]
pub fn specification_path_rules(policy: &SecurityPolicy) -> PathRules {
    let plain = path_rules(policy);
    let Some(skills) = policy
        .agent_stage_profiles
        .profiles
        .iter()
        .find(|profile| {
            profile
                .applies_to_stage_kinds
                .iter()
                .any(|kind| kind == "SPECIFICATION")
        })
        .and_then(|profile| profile.skills.as_ref())
    else {
        return plain;
    };
    let mut rules = plain.rules().to_vec();
    for skill in skills
        .allowed
        .iter()
        .filter(|skill| skill.protected_path_exception_required != Some(true))
    {
        for write in &skill.writes {
            let Ok(glob) = RepoGlob::new(write.pattern()) else {
                continue;
            };
            for group in &policy.protected_paths.groups {
                if matches!(group.applies_to, AppliesTo::FactoryRepo) {
                    continue;
                }
                rules.push((
                    group.id.clone(),
                    PathRule::Reinclude {
                        glob: glob.clone(),
                        group: group.id.clone(),
                    },
                ));
            }
        }
    }
    PathRules::new(rules)
}

fn remote_of(config: &RemoteConfig) -> Result<RemoteLocation, ProviderError> {
    Ok(match config.remote().map_err(|_| ProviderError::Remote)? {
        Remote::Https(host) => RemoteLocation::Https { host },
        Remote::Directory(base) => RemoteLocation::Directory { base },
    })
}

/// The policy the real workspace takes its second look at a change set with.
///
/// The workspace judges a change by the path rules of the request and by the compiled policy, and
/// the stricter answer stands ([`PathPolicyLayer`]). The rules of the specification stage lift the
/// writes the policy lists for its skills ([`specification_path_rules`]); the compiled policy did
/// not, so the real workspace refused the pointer the specify skill had just written and the stage
/// ended `BLOCKED` (found by the live-adapters run, not by the rigs, whose workspace had no second
/// look). Here the same writes are re-included in the protected groups of the policy that the
/// second look compiles. The rules of every other stage are the plain ones and still refuse those
/// paths, so only the stage that lifts them can write them; everything else under `.specify/`, the
/// constitution, the project configuration and the CI files stay refused by both looks.
#[must_use]
pub fn layer_policy(policy: &SecurityPolicy) -> SecurityPolicy {
    let mut lifted = policy.clone();
    let writes: Vec<String> = policy
        .agent_stage_profiles
        .profiles
        .iter()
        .find(|profile| {
            profile
                .applies_to_stage_kinds
                .iter()
                .any(|kind| kind == "SPECIFICATION")
        })
        .and_then(|profile| profile.skills.as_ref())
        .map(|skills| {
            skills
                .allowed
                .iter()
                .filter(|skill| skill.protected_path_exception_required != Some(true))
                .flat_map(|skill| skill.writes.iter().map(|write| write.pattern().to_owned()))
                .collect()
        })
        .unwrap_or_default();
    for group in &mut lifted.protected_paths.groups {
        if matches!(group.applies_to, AppliesTo::FactoryRepo) {
            continue;
        }
        for write in &writes {
            group
                .globs
                .push(factory_domain::policy::common::GlobText(format!(
                    "!{write}"
                )));
        }
    }
    lifted
}

/// The Spec Kit configuration for a profile, from the installation in the protected checkout.
///
/// # Errors
/// [`ProviderError::SpecKit`].
pub fn spec_kit_config(
    config: &FactoryConfig,
    profile: Profile,
) -> Result<SpecKitConfig, ProviderError> {
    spec_kit_config_at(&config.protected_checkout, profile.execution_mode())
}

/// The Spec Kit configuration for an execution mode, from the installation in `checkout`.
///
/// The same reading serves the assembly above and a test wiring that has no [`FactoryConfig`].
///
/// # Errors
/// [`ProviderError::Installation`].
pub fn spec_kit_config_at(
    checkout: &std::path::Path,
    mode: factory_domain::vocabulary::ExecutionMode,
) -> Result<SpecKitConfig, ProviderError> {
    let path = checkout.join(factory_spec_adapter::integrity::INTEGRATION);
    let shown = path.display().to_string();
    let bytes = std::fs::read(&path)
        .map_err(|error| ProviderError::Installation(shown.clone(), error.kind().to_string()))?;
    let integration = IntegrationConfig::parse(&bytes)
        .map_err(|error| ProviderError::Installation(shown, format!("{error:?}")))?;
    Ok(SpecKitConfig {
        host: integration.host,
        separator: integration.separator,
        mode,
        fallback_adapter: factory_domain::values::Slug::parse("claude-code")
            .map_err(|_| ProviderError::Installation(String::new(), "adapter name".to_owned()))?,
        fallback_adapter_version: integration.version,
    })
}

/// The Spec Kit provider for an installation in `checkout`.
///
/// # Errors
/// [`ProviderError::Installation`].
pub fn spec_kit_provider(
    checkout: &std::path::Path,
    mode: factory_domain::vocabulary::ExecutionMode,
) -> Result<Arc<dyn SpecificationProvider>, ProviderError> {
    Ok(Arc::new(SpecKitProvider::new(spec_kit_config_at(
        checkout, mode,
    )?)))
}

/// The files of the Spec Kit installation in `checkout`, as `(path, bytes)`: exactly the files
/// the adapter checks against its pins. A repository the factory works on must hold them before
/// the specification stage runs, and a test that builds such a repository in memory copies them
/// from here.
///
/// # Errors
/// [`ProviderError::Installation`] when the installation file is unreadable or a listed file is
/// missing.
pub fn spec_kit_installation(
    checkout: &std::path::Path,
) -> Result<Vec<(String, Vec<u8>)>, ProviderError> {
    let config = spec_kit_config_at(checkout, factory_domain::vocabulary::ExecutionMode::Test)?;
    factory_spec_adapter::integrity::installation_paths(config.host)
        .into_iter()
        .map(|path| {
            std::fs::read(checkout.join(path))
                .map(|bytes| (path.to_owned(), bytes))
                .map_err(|error| {
                    ProviderError::Installation(path.to_owned(), error.kind().to_string())
                })
        })
        .collect()
}

/// Assembles the real sandbox, workspace and specification providers.
///
/// # Errors
/// [`ProviderError`].
pub fn assemble(inputs: ProviderInputs<'_>) -> Result<Providers, ProviderError> {
    let ProviderInputs {
        config,
        policies,
        redactor,
        artifacts,
        clock,
        ids,
        store,
        jobs,
        runner,
    } = inputs;
    let profile = config.profile;
    let security = &policies.security;

    // The sandbox. AppArmor may be missing on a laptop; production never allows that.
    let policy = sandbox_policy_from(security, profile != Profile::Production)
        .ok_or(ProviderError::SandboxPolicy)?;
    let images_json = std::fs::read_to_string(&config.sandbox.images_catalog)
        .map_err(|_| ProviderError::Catalog(config.sandbox.images_catalog.display().to_string()))?;
    let docker = DockerSandboxProvider::new(
        ProviderConfig {
            policy,
            images_json,
            platform: config.sandbox.platform.clone(),
            token_root: config.sandbox.token_root.clone(),
            caches: Vec::new(),
            owner_labels: std::iter::once((OWNER_LABEL.to_owned(), config.sandbox.owner.clone()))
                .chain(config.sandbox.labels.clone())
                .collect(),
            sidecar_command: config.sandbox.sidecar_command.clone(),
            docker: docker_settings_from(&config.sandbox)?,
            watchdog: WatchdogSettings {
                disk_poll_interval: Duration::from_secs(5),
            },
        },
        Arc::clone(&runner),
        Arc::clone(&artifacts),
        Arc::clone(&redactor),
        Arc::clone(&clock),
        Arc::clone(&ids),
    );
    let sandbox: Arc<dyn SandboxProvider> = Arc::new(IndexingSandbox::new(
        Arc::new(docker),
        Arc::clone(&store),
        Arc::clone(&jobs),
    ));

    // The workspace.
    let layer = PathPolicyLayer::new(
        Arc::new(
            PathPolicy::from_policy(&layer_policy(security))
                .map_err(|_| ProviderError::PathPolicy)?,
        ),
        RepoKind::Target,
    );
    let git = GitWorkspaceProvider::new(
        WorkspaceSettings::new(
            config.sandbox.workspace_root.clone(),
            remote_of(&config.sandbox.remote)?,
        ),
        Arc::clone(&runner),
        Arc::clone(&artifacts),
        Arc::clone(&redactor),
        Arc::clone(&clock),
        path_rules(security),
    )
    .with_path_policy(layer);
    let workspaces: Arc<dyn WorkspaceProvider> = Arc::new(IndexingWorkspaces::new(
        Arc::new(git),
        Arc::clone(&store),
        Arc::clone(&jobs),
    ));

    let specification: Arc<dyn SpecificationProvider> =
        Arc::new(SpecKitProvider::new(spec_kit_config(config, profile)?));

    Ok(Providers {
        process: runner,
        sandbox,
        workspaces,
        specification,
    })
}
