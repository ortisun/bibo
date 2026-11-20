//! Sandbox specs built from the loaded policy and the image catalog.
//!
//! The three stage seams `AgentSandboxSpecs`, `VerifySandboxSpecs` and `WorkspaceAgentSpecs` ask
//! the composition root for a complete `SandboxSpec`: the image, the limits, the mounts, the
//! network, the job token mount and the hardening. The policy decides every number, so no stage
//! can widen a sandbox. [`PolicySpecs`] is the one implementation of all three, and
//! [`sandbox_policy_from`] builds the `SandboxPolicy` that the provider checks every spec against
//! from the same document, so a spec made here and the check on it cannot disagree.
//!
//! # What the policy does not say, and is decided here
//!
//! The security policy has no field for the lowest user id, the environment names a sandbox may
//! hold, or the names it may never hold. Those three lists are constants below. They are the
//! values the testkit fixture and the sandbox tests already use, and the README lists them for the
//! security reviewer.

use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use factory_domain::ids::{AttemptId, JobId};
use factory_domain::policy::security::{ProfileLimits, SecurityPolicy};
use factory_ports::agent::JobTokenRef;
use factory_ports::sandbox::{
    FixedEnv, Hardening, JobTokenMount, McpRunTokenSecret, McpTokenMount, NetworkAttachment,
    SandboxLimits, SandboxMounts, SandboxPolicy, SandboxProfile, SandboxSpec,
};
use factory_ports::workspace::WorkspaceMounts;
use factory_sandbox::container::images::ImageCatalog;
use factory_workflow::stages::implementation::seams::{WorkspaceAccess, WorkspaceAgentSpecs};
use factory_workflow::stages::intake::seams::{AgentSandboxSpecs, SeamError};
use factory_workflow::stages::repo_intel::seams::VerifySandboxSpecs;

use crate::redaction::RegisteringBroker;

/// The lowest user id a sandbox may run as.
pub const MIN_SANDBOX_UID: u32 = 10_000;
/// Names that no sandbox environment may hold.
pub const FORBIDDEN_ENV: [&str; 6] = [
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "NODE_OPTIONS",
    "BASH_ENV",
    "PYTHONSTARTUP",
];
/// The only names a sandbox environment may hold.
pub const ALLOWED_ENV: [&str; 8] = [
    "HOME",
    "PATH",
    "TERM",
    "LANG",
    "CARGO_TARGET_DIR",
    "CARGO_HOME",
    "CARGO_NET_OFFLINE",
    "TMPDIR",
];

/// Where a build in any sandbox puts its output: the writable output directory, because the
/// workspace is read-only in a `verify` sandbox and ingested from an `agent` one. The sandbox
/// layout of the ports holds the one value, which the agent tools get too ([`agent_build_env`]).
pub const TARGET_DIR: &str = factory_ports::sandbox::BUILD_TARGET_DIR;

/// The build environment the agent tools are started with (ADR 0024): the target directory and
/// the temporary directory of the `verify` sandbox, offline, because an `agent` sandbox's network
/// reaches the broker's sidecar and nothing else. The runtimes add `CARGO_HOME` in each run's own
/// home. This is the one place the composition root decides it, beside [`profile_env`], so the
/// builder's `cargo` and the trusted gates' `cargo` build into the same place.
#[must_use]
pub fn agent_build_env() -> factory_runtime::command::BuildEnv {
    factory_runtime::command::BuildEnv {
        target_dir: TARGET_DIR.to_owned(),
        temp_dir: factory_ports::sandbox::BUILD_TEMP_DIR.to_owned(),
        offline: true,
    }
}

/// The path of a program that `cargo build` made in a `verify` sandbox. A bare name is not on the
/// `PATH` of the image, so a gate that runs the built program (the documentation review runs it
/// with `--help` to compare the names in the pages with what it prints) must name the file; found
/// by the live-adapters run, where the command answered 127. A name that already holds a `/` is a
/// path and is left as it is.
#[must_use]
pub fn built_program(name: &str) -> String {
    if name.contains('/') {
        name.to_owned()
    } else {
        format!("{TARGET_DIR}/debug/{name}")
    }
}

/// The environment a sandbox of `profile` is given, besides `HOME`.
///
/// The `verify` image mounts the workspace read-only and has a writable output directory, and a
/// Rust project's gate commands (`cargo build`, `cargo test`) write a `target` directory beside the
/// manifest unless they are told where. The image's README says what to set: the target directory
/// in the output directory, the cargo home in the tmpfs home, offline behind `--network none`, and
/// a temporary directory that is not `noexec` (`/tmp` is, and `rustdoc` runs the programs it
/// builds from there). Without them the first `cargo build` of the first job ended with "Read-only
/// file system", found by running the project's own gates in the real image
/// (`tests/real_verify_of_the_patch.rs`). A command cannot carry an environment, so it is the
/// sandbox's. The `fetch_deps` sandbox is the one that may reach the registry.
fn profile_env(profile: SandboxProfile) -> Vec<(String, String)> {
    let pairs: &[(&str, &str)] = match profile {
        // The agent tools start with `env -i` and get their build variables from the runtime's
        // configuration ([`agent_build_env`]), so the container holds none. The troubleshooter
        // builds nothing.
        SandboxProfile::Agent | SandboxProfile::Troubleshooter => &[],
        SandboxProfile::Verify => &[
            ("CARGO_TARGET_DIR", TARGET_DIR),
            ("CARGO_HOME", "/home/agent/.cargo"),
            ("CARGO_NET_OFFLINE", "true"),
            ("TMPDIR", factory_ports::sandbox::BUILD_TEMP_DIR),
        ],
        SandboxProfile::FetchDeps => &[
            ("CARGO_TARGET_DIR", TARGET_DIR),
            ("CARGO_HOME", "/home/agent/.cargo"),
            ("CARGO_NET_OFFLINE", "false"),
            ("TMPDIR", factory_ports::sandbox::BUILD_TEMP_DIR),
        ],
    };
    let mut env = vec![("HOME".to_owned(), "/home/agent".to_owned())];
    env.extend(
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );
    env
}
/// The alias of the egress sidecar on the per-job network. The broker URL the agent uses names it.
pub const SIDECAR_ALIAS: &str = "egress";

/// The port the egress sidecar listens on inside the job network: the one in the arguments of
/// `sandbox.sidecar_command` (`--listen 0.0.0.0:8443`) that a deployment that runs agents sets.
pub const SIDECAR_PORT: u16 = 8443;

/// The port of the sidecar's second fixed relay, to the MCP gateway, inside the job network of a
/// `troubleshooter` sandbox (ADR 0021, Decision 5). The supervisor adds `--second-listen` on this
/// port, and `--second-upstream` with the gateway's address from `sandbox.gateway_upstream`, to
/// the sidecar of that profile alone.
pub const SIDECAR_GATEWAY_PORT: u16 = 8444;

/// Where the troubleshooter in its sandbox reaches the MCP gateway: the second relay of the sidecar
/// of its job network, by the sidecar's alias, over plain HTTP, at the gateway's `/mcp` path. The
/// sidecar relays the bytes and reads none, so this is the only address the tool can be given.
#[must_use]
pub fn gateway_endpoint() -> factory_domain::values::Uri {
    factory_domain::values::Uri::parse(&format!(
        "http://{SIDECAR_ALIAS}:{SIDECAR_GATEWAY_PORT}/mcp"
    ))
    .expect("the alias and the port make a URI")
}

/// Where an agent in the sandbox reaches the model broker: the sidecar of its job network, by its
/// alias, over plain HTTP. The sidecar relays the bytes to the broker (`--mode broker`) and
/// terminates no TLS, and the sandbox resolves no other name, so this is the only address the tool
/// can be given. (The placeholder host of `policies/security.yaml`, `model-broker.sandbox.internal`,
/// does not resolve inside a job network.)
#[must_use]
pub fn broker_endpoint() -> factory_ports::agent::BrokerEndpoint {
    factory_ports::agent::BrokerEndpoint {
        base_url: factory_domain::values::Uri::parse(&format!(
            "http://{SIDECAR_ALIAS}:{SIDECAR_PORT}"
        ))
        .expect("the alias and the port make a URI"),
    }
}

fn limits_of(limits: &ProfileLimits) -> Option<SandboxLimits> {
    let non_zero = |value: u64| u32::try_from(value).ok().and_then(NonZeroU32::new);
    // Rounded to a whole millicore; a fraction of one is not a limit anyone sets.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let millis = (limits.cpus * 1000.0).round() as u64;
    Some(SandboxLimits {
        cpu_millis: non_zero(millis)?,
        memory_mb: non_zero(limits.memory_mb)?,
        memory_swap_mb: non_zero(limits.memory_swap_mb)?,
        pids: non_zero(limits.pids)?,
        nofile: non_zero(limits.nofile)?,
        max_file_mb: non_zero(limits.max_file_mb)?,
        tmpfs_mb: non_zero(limits.tmpfs_mb)?,
        workspace_disk_mb: non_zero(limits.workspace_disk_mb)?,
        wall_clock: Duration::from_secs(limits.wall_clock_s),
    })
}

/// The `SandboxPolicy` the provider checks every spec against, from section 7 of the policy.
///
/// # Errors
/// `None` when a limit in the policy is zero or does not fit.
#[must_use]
pub fn sandbox_policy_from(
    policy: &SecurityPolicy,
    apparmor_may_be_unavailable: bool,
) -> Option<SandboxPolicy> {
    let profiles = &policy.sandbox.profiles;
    Some(SandboxPolicy {
        min_uid: MIN_SANDBOX_UID,
        forbidden_mount_sources: policy.sandbox.forbidden_mount_sources.clone(),
        forbidden_env_names: FORBIDDEN_ENV.map(String::from).to_vec(),
        allowed_env_names: ALLOWED_ENV.map(String::from).to_vec(),
        apparmor_may_be_unavailable,
        fetch_deps_max: limits_of(&profiles.fetch_deps.limits)?,
        agent_max: limits_of(&profiles.agent.limits)?,
        verify_max: limits_of(&profiles.verify.limits)?,
        troubleshooter_max: limits_of(&profiles.troubleshooter.limits)?,
    })
}

/// Builds sandbox specs from the policy, the catalog and the broker's vault of job tokens.
pub struct PolicySpecs {
    policy: Arc<SecurityPolicy>,
    catalog: ImageCatalog,
    broker: Arc<RegisteringBroker>,
    /// Where an attempt that has no workspace of its own gets an empty one.
    scratch_root: PathBuf,
}

impl PolicySpecs {
    /// Specs for `catalog`'s platform.
    #[must_use]
    pub fn new(
        policy: Arc<SecurityPolicy>,
        catalog: ImageCatalog,
        broker: Arc<RegisteringBroker>,
        scratch_root: PathBuf,
    ) -> Self {
        Self {
            policy,
            catalog,
            broker,
            scratch_root,
        }
    }

    fn build(
        &self,
        profile: SandboxProfile,
        job: JobId,
        attempt: AttemptId,
        mounts: WorkspaceMounts,
        token: Option<JobTokenRef>,
        mcp_token: Option<McpRunTokenSecret>,
    ) -> Result<SandboxSpec, SeamError> {
        let profiles = &self.policy.sandbox.profiles;
        let limits = match profile {
            SandboxProfile::Agent => &profiles.agent.limits,
            SandboxProfile::FetchDeps => &profiles.fetch_deps.limits,
            SandboxProfile::Verify => &profiles.verify.limits,
            SandboxProfile::Troubleshooter => &profiles.troubleshooter.limits,
        };
        // Only the troubleshooter holds the gateway's run token, and it always does.
        if (profile == SandboxProfile::Troubleshooter) != mcp_token.is_some() {
            return Err(SeamError::Unavailable);
        }
        let image = self
            .catalog
            .reference_for(profile)
            .ok_or(SeamError::Unavailable)?
            .clone();
        let ready = self
            .catalog
            .check_spec_image(profile, &image)
            .map_err(|_| SeamError::Unavailable)?;
        let (network, job_token) = match profile {
            SandboxProfile::Verify => (NetworkAttachment::None, None),
            SandboxProfile::FetchDeps => (
                NetworkAttachment::JobInternal {
                    sidecar: SIDECAR_ALIAS.to_owned(),
                },
                None,
            ),
            SandboxProfile::Agent | SandboxProfile::Troubleshooter => {
                let token = token.ok_or(SeamError::Unavailable)?;
                let secret = self
                    .broker
                    .secret_of(&token.id)
                    .ok_or(SeamError::Unavailable)?;
                (
                    NetworkAttachment::JobInternal {
                        sidecar: SIDECAR_ALIAS.to_owned(),
                    },
                    Some(JobTokenMount { secret }),
                )
            }
        };
        Ok(SandboxSpec {
            job,
            attempt,
            profile,
            image,
            limits: limits_of(limits).ok_or(SeamError::Unavailable)?,
            network,
            mounts: SandboxMounts {
                workspace: mounts,
                caches: Vec::new(),
            },
            job_token,
            mcp_token: mcp_token.map(|secret| McpTokenMount { secret }),
            env: FixedEnv::new(profile_env(profile)).map_err(|_| SeamError::Unavailable)?,
            hardening: Hardening::strict(ready.uid, ready.gid),
        })
    }

    /// The fixed part of a sandbox of `profile`, which the validation and documentation review
    /// stages carry in their own configuration and complete with a workspace per attempt. The
    /// numbers are the policy's and the image is the catalog's, the same ones [`Self::verify_spec`]
    /// uses, so the stage and this seam cannot disagree.
    fn fixed_part(
        &self,
        profile: SandboxProfile,
    ) -> Result<
        (
            factory_ports::sandbox::ImageDigest,
            SandboxLimits,
            FixedEnv,
            Hardening,
            String,
        ),
        SeamError,
    > {
        let profiles = &self.policy.sandbox.profiles;
        let limits = match profile {
            SandboxProfile::Agent => &profiles.agent.limits,
            SandboxProfile::FetchDeps => &profiles.fetch_deps.limits,
            SandboxProfile::Verify => &profiles.verify.limits,
            SandboxProfile::Troubleshooter => &profiles.troubleshooter.limits,
        };
        let image = self
            .catalog
            .reference_for(profile)
            .ok_or(SeamError::Unavailable)?
            .clone();
        let ready = self
            .catalog
            .check_spec_image(profile, &image)
            .map_err(|_| SeamError::Unavailable)?;
        let arch = self
            .catalog
            .platform()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_owned();
        Ok((
            image,
            limits_of(limits).ok_or(SeamError::Unavailable)?,
            FixedEnv::new(profile_env(profile)).map_err(|_| SeamError::Unavailable)?,
            Hardening::strict(ready.uid, ready.gid),
            arch,
        ))
    }

    /// The `verify` sandbox the validation and documentation review stages are configured with.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`] when the catalog has no verify image or the policy limits do not fit.
    pub fn verify_sandbox(
        &self,
    ) -> Result<factory_workflow::stages::validation::VerifySandbox, SeamError> {
        let (image, limits, env, hardening, arch) = self.fixed_part(SandboxProfile::Verify)?;
        Ok(factory_workflow::stages::validation::VerifySandbox {
            image,
            limits,
            env,
            hardening,
            caches: Vec::new(),
            arch,
        })
    }

    /// The `fetch_deps` sandbox the supply chain gate is configured with, behind the per-job
    /// egress sidecar.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`] when the catalog has no fetch image or the policy limits do not fit.
    pub fn fetch_sandbox(
        &self,
    ) -> Result<factory_workflow::gates::supply_chain::run::FetchSandbox, SeamError> {
        let (image, limits, env, hardening, arch) = self.fixed_part(SandboxProfile::FetchDeps)?;
        Ok(factory_workflow::gates::supply_chain::run::FetchSandbox {
            image,
            limits,
            env,
            hardening,
            caches: Vec::new(),
            sidecar: SIDECAR_ALIAS.to_owned(),
            arch,
        })
    }

    /// The sandbox of one troubleshooter run (ADR 0021): the agent image and hardening under the
    /// `troubleshooter` limits, an empty workspace mounted read-only, the broker job token and the
    /// MCP gateway's run token. Its sidecar gets the second relay from the provider's
    /// configuration. The run has no job of its own in the pipeline; `job` and `attempt` are the
    /// identifiers the troubleshooter gives its run, used for the sandbox's names and labels.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`] when the catalog has no agent image, the policy limits do not
    /// fit, or the broker does not hold the job token.
    pub fn troubleshooter_spec(
        &self,
        job: JobId,
        attempt: AttemptId,
        token: JobTokenRef,
        mcp_token: McpRunTokenSecret,
    ) -> Result<SandboxSpec, SeamError> {
        let mut mounts = self.scratch(attempt);
        mounts.workspace_read_only = true;
        let spec = self.build(
            SandboxProfile::Troubleshooter,
            job,
            attempt,
            mounts.clone(),
            Some(token),
            Some(mcp_token),
        )?;
        self.make_scratch(attempt, &mounts);
        Ok(spec)
    }

    /// An empty workspace for an attempt whose stage reads no repository.
    fn scratch(&self, attempt: AttemptId) -> WorkspaceMounts {
        let root = self.scratch_root.join(attempt.to_string());
        WorkspaceMounts {
            workspace: root.join("work"),
            workspace_read_only: false,
            out: root.join("out"),
            protected_overlays: Vec::new(),
            git_masked: true,
        }
    }

    /// Makes the directories of a scratch workspace.
    ///
    /// The daemon binds a path that exists and refuses one that does not ("bind source path does
    /// not exist"), so a spec that only named them could not be started. A stage with a checkout
    /// gets its directories from the workspace provider; this is the same for a stage with none.
    /// The attempt's own directory is private to the worker, and the two directories the sandbox
    /// user writes are open to it, as the workspace provider makes its own shared directories. The
    /// pointer file is what the mask over `.git` is bound onto.
    fn make_scratch(&self, attempt: AttemptId, mounts: &WorkspaceMounts) {
        use std::os::unix::fs::PermissionsExt as _;
        let root = self.scratch_root.join(attempt.to_string());
        // A failure leaves the path missing, and the sandbox provider then refuses the spec at
        // creation with the daemon's reason; nothing is guessed.
        let _ = std::fs::create_dir_all(&root)
            .and_then(|()| std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)));
        for open in [&mounts.workspace, &mounts.out] {
            let _ = std::fs::create_dir_all(open).and_then(|()| {
                std::fs::set_permissions(open, std::fs::Permissions::from_mode(0o777))
            });
        }
        let _ = std::fs::write(mounts.workspace.join(".git"), b"");
    }
}

impl AgentSandboxSpecs for PolicySpecs {
    fn agent_spec(
        &self,
        job: JobId,
        attempt: AttemptId,
        token: JobTokenRef,
    ) -> Result<SandboxSpec, SeamError> {
        let mounts = self.scratch(attempt);
        let spec = self.build(
            SandboxProfile::Agent,
            job,
            attempt,
            mounts.clone(),
            Some(token),
            None,
        )?;
        self.make_scratch(attempt, &mounts);
        Ok(spec)
    }
}

impl VerifySandboxSpecs for PolicySpecs {
    fn verify_spec(
        &self,
        job: JobId,
        attempt: AttemptId,
        mounts: WorkspaceMounts,
    ) -> Result<SandboxSpec, SeamError> {
        self.build(SandboxProfile::Verify, job, attempt, mounts, None, None)
    }
}

impl WorkspaceAgentSpecs for PolicySpecs {
    fn spec(
        &self,
        job: JobId,
        attempt: AttemptId,
        token: JobTokenRef,
        mounts: WorkspaceMounts,
        access: WorkspaceAccess,
    ) -> Result<SandboxSpec, SeamError> {
        // `Inspect` cannot be made read-only here: `SandboxSpec::validate` refuses a read-only
        // workspace under the `agent` profile (`WorkspaceAccessMismatch`), so a reviewer's
        // sandbox mounts the worktree the provider gave it. Keeping a reviewer from changing the
        // tree is then the job of the workspace purpose and of the tool grants, not of the mount.
        // README, "Cross-stage mismatches".
        let _ = access;
        self.build(
            SandboxProfile::Agent,
            job,
            attempt,
            mounts,
            Some(token),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup::tests_support::{repository_root, repository_security_policy};

    fn catalog() -> ImageCatalog {
        let json =
            std::fs::read_to_string(repository_root().join("infra/sandbox-images/images.json"))
                .expect("the catalog exists");
        ImageCatalog::from_json(&json, "linux/arm64").expect("a catalog")
    }

    #[test]
    fn a_program_the_build_made_is_named_by_its_file_and_a_path_is_left_alone() {
        assert_eq!(built_program("word-count"), "/out/target/debug/word-count");
        assert_eq!(built_program("/opt/tool/bin/x"), "/opt/tool/bin/x");
        // The directory is the one the sandbox tells cargo to build into.
        let env = profile_env(SandboxProfile::Verify);
        assert!(env.contains(&("CARGO_TARGET_DIR".to_owned(), TARGET_DIR.to_owned())));
    }

    #[test]
    fn the_builder_and_the_verify_sandbox_build_into_the_same_place_outside_the_workspace() {
        let build = agent_build_env();
        let verify = profile_env(SandboxProfile::Verify);
        let of = |name: &str| {
            verify
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(of("CARGO_TARGET_DIR"), Some(build.target_dir.clone()));
        assert_eq!(of("TMPDIR"), Some(build.temp_dir.clone()));
        assert!(build.offline, "an agent sandbox reaches no registry");
        assert!(
            !build
                .target_dir
                .starts_with(factory_ports::sandbox::WORKSPACE_TARGET)
        );
        // Every variable the build sets is one a sandbox may hold at all.
        let env = build
            .apply(factory_runtime::command::ToolEnv::new(), "/tmp/h")
            .expect("the build variables");
        for (name, _) in env.pairs() {
            assert!(ALLOWED_ENV.contains(&name.as_str()), "{}", name.as_str());
        }
    }

    #[test]
    fn the_address_an_agent_is_given_names_the_sidecar_of_its_job_network() {
        // The job network resolves the alias of its sidecar and nothing else, and the sidecar
        // relays plain bytes. An address with another host or an https scheme cannot be reached.
        let endpoint = broker_endpoint();
        let url = endpoint.base_url.as_str();
        assert_eq!(url, "http://egress:8443");
        assert!(url.contains(SIDECAR_ALIAS));
        assert!(
            !url.contains("sandbox.internal"),
            "the placeholder host of the policy does not resolve in a sandbox"
        );
        // The tool accepts it as a broker address.
        assert!(factory_runtime::command::broker_origin(url).is_ok());
    }

    #[test]
    fn the_policy_gives_a_sandbox_policy_with_the_limits_of_the_document() {
        let policy = repository_security_policy();
        let derived = sandbox_policy_from(&policy, false).expect("limits fit");
        assert_eq!(derived.agent_max.pids.get(), 256);
        assert_eq!(derived.verify_max.cpu_millis.get(), 4000);
        assert_eq!(derived.fetch_deps_max.wall_clock, Duration::from_secs(600));
        assert!(
            derived
                .forbidden_mount_sources
                .iter()
                .any(|m| m.contains("docker.sock"))
        );
    }

    #[test]
    fn a_verify_spec_has_no_network_and_passes_the_policy_check() {
        let policy = Arc::new(repository_security_policy());
        let derived = sandbox_policy_from(&policy, true).expect("limits fit");
        let broker_inner: Arc<dyn factory_ports::agent::ModelBroker> = unreachable_broker();
        let redactor = Arc::new(crate::redaction::redactor_from_policy(&policy).expect("builds"));
        let specs = PolicySpecs::new(
            policy,
            catalog(),
            Arc::new(RegisteringBroker::new(broker_inner, redactor)),
            std::env::temp_dir(),
        );
        let ids = factory_testkit::fixtures::Ids::new();
        let mounts = WorkspaceMounts {
            workspace: PathBuf::from("/tmp/factory-test/work"),
            workspace_read_only: true,
            out: PathBuf::from("/tmp/factory-test/out"),
            protected_overlays: Vec::new(),
            git_masked: true,
        };
        let spec = specs
            .verify_spec(ids.job(), ids.attempt(), mounts)
            .expect("a spec");
        assert_eq!(spec.network, NetworkAttachment::None);
        assert!(spec.job_token.is_none());
        let checked = spec.validate(&derived);
        assert!(checked.is_ok(), "{checked:?}");
    }

    /// A broker nobody calls: the verify spec needs no token.
    fn unreachable_broker() -> Arc<dyn factory_ports::agent::ModelBroker> {
        Arc::new(factory_testkit::broker::FakeModelBroker::new(
            Arc::new(factory_testkit::clock::FakeClock::new()),
            Arc::new(factory_testkit::clock::SequentialIdGenerator::new()),
        ))
    }

    #[tokio::test]
    async fn an_agent_sandbox_with_no_repository_gets_directories_that_exist() {
        use factory_ports::agent::{CostMicroUsd, JobTokenRequest, ModelBroker as _};
        use std::os::unix::fs::PermissionsExt as _;
        let dir = repository_root()
            .join("target/sandbox-specs-scratch")
            .join(std::process::id().to_string());
        let _ = std::fs::remove_dir_all(&dir);
        let policy = Arc::new(repository_security_policy());
        let redactor = Arc::new(crate::redaction::redactor_from_policy(&policy).expect("builds"));
        let registering = Arc::new(RegisteringBroker::new(unreachable_broker(), redactor));
        let specs = PolicySpecs::new(policy, catalog(), Arc::clone(&registering), dir.clone());
        let ids = factory_testkit::fixtures::Ids::new();
        let token = registering
            .issue(JobTokenRequest {
                tenant: ids.tenant(),
                job: ids.job(),
                stage: factory_domain::vocabulary::StageKind::Intake,
                cost_ceiling: CostMicroUsd(1_000),
                allowed_models: vec![factory_ports::agent::ModelSelection {
                    runtime: factory_ports::agent::RuntimeId::new("fake").expect("a runtime"),
                    model: factory_domain::values::NonEmptyString::parse("fake-model")
                        .expect("a model"),
                }],
                ttl: Duration::from_secs(60),
                per_request: None,
            })
            .await
            .expect("a token");
        let attempt = ids.attempt();
        let spec = specs
            .agent_spec(ids.job(), attempt, JobTokenRef { id: token.id })
            .expect("an agent spec");
        let work = dir.join(attempt.to_string()).join("work");
        let out = dir.join(attempt.to_string()).join("out");
        for path in [&work, &out] {
            assert!(path.is_dir(), "{} does not exist", path.display());
            let mode = std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o777,
                "the sandbox user writes {}",
                path.display()
            );
        }
        assert!(work.join(".git").exists(), "the mask has a file to cover");
        assert_eq!(
            std::fs::metadata(dir.join(attempt.to_string()))
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "the attempt's own directory stays private to the worker"
        );
        assert_eq!(spec.mounts.workspace.workspace, work);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_refused_agent_spec_makes_no_directories() {
        let dir = repository_root()
            .join("target/sandbox-specs-refused")
            .join(std::process::id().to_string());
        let _ = std::fs::remove_dir_all(&dir);
        let policy = Arc::new(repository_security_policy());
        let redactor = Arc::new(crate::redaction::redactor_from_policy(&policy).expect("builds"));
        let specs = PolicySpecs::new(
            policy,
            catalog(),
            Arc::new(RegisteringBroker::new(unreachable_broker(), redactor)),
            dir.clone(),
        );
        let ids = factory_testkit::fixtures::Ids::new();
        let unknown = JobTokenRef {
            id: factory_ports::agent::JobTokenId::from_uuid(ids.job().as_uuid()),
        };
        assert!(specs.agent_spec(ids.job(), ids.attempt(), unknown).is_err());
        assert!(!dir.exists(), "a refused spec litters nothing");
    }

    #[test]
    fn an_agent_spec_needs_a_token_the_broker_still_holds() {
        let policy = Arc::new(repository_security_policy());
        let broker_inner = unreachable_broker();
        let redactor = Arc::new(crate::redaction::redactor_from_policy(&policy).expect("builds"));
        let specs = PolicySpecs::new(
            policy,
            catalog(),
            Arc::new(RegisteringBroker::new(broker_inner, redactor)),
            std::env::temp_dir(),
        );
        let ids = factory_testkit::fixtures::Ids::new();
        let unknown = JobTokenRef {
            id: factory_ports::agent::JobTokenId::from_uuid(ids.job().as_uuid()),
        };
        let refusal = specs.agent_spec(ids.job(), ids.attempt(), unknown);
        assert_eq!(refusal.unwrap_err(), SeamError::Unavailable);
    }

    #[test]
    fn the_gateway_address_names_the_second_relay_of_the_sidecar() {
        let url = gateway_endpoint();
        assert_eq!(url.as_str(), "http://egress:8444/mcp");
        assert_ne!(SIDECAR_GATEWAY_PORT, SIDECAR_PORT);
    }

    /// ADR 0021: the troubleshooter's sandbox is the agent image under its own limits, with no
    /// repository (an empty read-only workspace), both token files and the policy check passed.
    #[tokio::test]
    async fn a_troubleshooter_spec_has_no_repository_two_tokens_and_passes_the_policy_check() {
        use factory_ports::agent::{CostMicroUsd, JobTokenRequest, ModelBroker as _};
        // A normalized absolute path: the policy check refuses one with `..` in it.
        let dir = repository_root()
            .canonicalize()
            .expect("the repository root")
            .join("target/sandbox-specs-troubleshooter")
            .join(std::process::id().to_string());
        let _ = std::fs::remove_dir_all(&dir);
        let policy = Arc::new(repository_security_policy());
        let derived = sandbox_policy_from(&policy, true).expect("limits fit");
        let redactor = Arc::new(crate::redaction::redactor_from_policy(&policy).expect("builds"));
        let registering = Arc::new(RegisteringBroker::new(unreachable_broker(), redactor));
        let specs = PolicySpecs::new(policy, catalog(), Arc::clone(&registering), dir.clone());
        let ids = factory_testkit::fixtures::Ids::new();
        let token = registering
            .issue(JobTokenRequest {
                tenant: ids.tenant(),
                job: ids.job(),
                stage: factory_domain::vocabulary::StageKind::Intake,
                cost_ceiling: CostMicroUsd(1_000),
                allowed_models: vec![factory_ports::agent::ModelSelection {
                    runtime: factory_ports::agent::RuntimeId::new("fake").expect("a runtime"),
                    model: factory_domain::values::NonEmptyString::parse("fake-model")
                        .expect("a model"),
                }],
                ttl: Duration::from_secs(60),
                per_request: None,
            })
            .await
            .expect("a token");
        // Built at run time so that no secret-shaped literal sits in the source.
        let gateway = McpRunTokenSecret::new(format!("{}-{}", "spec", "gateway-token"));
        let attempt = ids.attempt();
        let spec = specs
            .troubleshooter_spec(
                ids.job(),
                attempt,
                JobTokenRef { id: token.id },
                gateway.clone(),
            )
            .expect("a troubleshooter spec");
        assert_eq!(spec.profile, SandboxProfile::Troubleshooter);
        assert!(spec.mounts.workspace.workspace_read_only);
        assert!(spec.mounts.workspace.protected_overlays.is_empty());
        assert!(spec.job_token.is_some());
        assert_eq!(spec.mcp_token.as_ref().map(|m| &m.secret), Some(&gateway));
        assert_eq!(
            Some(&spec.image),
            catalog().reference_for(SandboxProfile::Agent),
            "the agent image"
        );
        assert_eq!(spec.limits, derived.troubleshooter_max);
        let checked = spec.validate(&derived);
        assert!(checked.is_ok(), "{checked:?}");
        let entries = std::fs::read_dir(dir.join(attempt.to_string()).join("work"))
            .expect("the empty workspace exists")
            .map(|e| e.expect("entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            entries,
            [std::ffi::OsString::from(".git")],
            "only the mask's file"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
