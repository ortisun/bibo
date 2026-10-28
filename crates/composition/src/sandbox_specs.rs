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
    FixedEnv, Hardening, JobTokenMount, NetworkAttachment, SandboxLimits, SandboxMounts,
    SandboxPolicy, SandboxProfile, SandboxSpec,
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
        SandboxProfile::Agent => &[],
        SandboxProfile::Verify => &[
            ("CARGO_TARGET_DIR", "/out/target"),
            ("CARGO_HOME", "/home/agent/.cargo"),
            ("CARGO_NET_OFFLINE", "true"),
            ("TMPDIR", "/out"),
        ],
        SandboxProfile::FetchDeps => &[
            ("CARGO_TARGET_DIR", "/out/target"),
            ("CARGO_HOME", "/home/agent/.cargo"),
            ("CARGO_NET_OFFLINE", "false"),
            ("TMPDIR", "/out"),
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
    ) -> Result<SandboxSpec, SeamError> {
        let profiles = &self.policy.sandbox.profiles;
        let limits = match profile {
            SandboxProfile::Agent => &profiles.agent.limits,
            SandboxProfile::FetchDeps => &profiles.fetch_deps.limits,
            SandboxProfile::Verify => &profiles.verify.limits,
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
        let (network, job_token) = match profile {
            SandboxProfile::Verify => (NetworkAttachment::None, None),
            SandboxProfile::FetchDeps => (
                NetworkAttachment::JobInternal {
                    sidecar: SIDECAR_ALIAS.to_owned(),
                },
                None,
            ),
            SandboxProfile::Agent => {
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
}

impl AgentSandboxSpecs for PolicySpecs {
    fn agent_spec(
        &self,
        job: JobId,
        attempt: AttemptId,
        token: JobTokenRef,
    ) -> Result<SandboxSpec, SeamError> {
        self.build(
            SandboxProfile::Agent,
            job,
            attempt,
            self.scratch(attempt),
            Some(token),
        )
    }
}

impl VerifySandboxSpecs for PolicySpecs {
    fn verify_spec(
        &self,
        job: JobId,
        attempt: AttemptId,
        mounts: WorkspaceMounts,
    ) -> Result<SandboxSpec, SeamError> {
        self.build(SandboxProfile::Verify, job, attempt, mounts, None)
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
        self.build(SandboxProfile::Agent, job, attempt, mounts, Some(token))
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
}
