//! The sandbox ports: hardened, ephemeral containers that run untrusted work (ADR 0003).
//!
//! A [`SandboxSpec`] says what to build. [`SandboxSpec::validate`] is a pure check against the
//! [`SandboxPolicy`] and rejects anything weaker. The provider then builds the container, reads
//! back what it actually built (the [`PostureReport`]), and hands out a session only if the two
//! agree. There is no downgrade to a weaker profile and no fallback to the host.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::{AttemptId, JobId};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::Fidelity;

use crate::clock::CancelSignal;
use crate::paths::RepoPath;
use crate::workspace::WorkspaceMounts;

/// The three kinds of sandbox (ADR 0003). Each has its own network and its own limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxProfile {
    /// Downloads dependencies through a relay to named registries. Runs no repository code.
    FetchDeps,
    /// Runs the agent tool. Reaches only the model broker, with one job token.
    Agent,
    /// Runs the trusted gates with no network, in a fresh container.
    Verify,
}

impl SandboxProfile {
    /// The name used in policy files and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FetchDeps => "fetch_deps",
            Self::Agent => "agent",
            Self::Verify => "verify",
        }
    }
}

/// An image reference pinned by digest: `name@sha256:` and 64 lowercase hex characters. A tag is
/// not a digest and cannot be wrapped, so a spec can never name a mutable image.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImageDigest(String);

/// An image reference that is not pinned by digest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("an image must be pinned by digest as `name@sha256:` and 64 lowercase hex characters")]
pub struct NotADigest;

impl ImageDigest {
    /// Checks that `reference` is `name@sha256:<64 hex>`.
    ///
    /// # Errors
    /// Returns [`NotADigest`] for a tag-only reference or a malformed digest.
    pub fn parse(reference: &str) -> Result<Self, NotADigest> {
        let (name, digest) = reference.split_once("@sha256:").ok_or(NotADigest)?;
        let digest_ok = digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        let name_ok = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-/:".contains(&b));
        if digest_ok && name_ok {
            Ok(Self(reference.to_owned()))
        } else {
            Err(NotADigest)
        }
    }

    /// The full reference.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.0
    }
}

/// Resource limits for one container. Values are whole units so they compare exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxLimits {
    /// CPU in thousandths of a core (2000 is two cores).
    pub cpu_millis: u32,
    /// Memory in MiB.
    pub memory_mb: u32,
    /// Memory plus swap in MiB. Equal to `memory_mb` means no swap.
    pub memory_swap_mb: u32,
    /// Maximum number of processes.
    pub pids: u32,
    /// Maximum number of open files.
    pub nofile: u32,
    /// Largest single file in MiB.
    pub max_file_mb: u32,
    /// Size of each tmpfs in MiB.
    pub tmpfs_mb: u32,
    /// Disk the workspace and output directories may use, in MiB.
    pub workspace_disk_mb: u32,
    /// How long the container may live. Docker has no such limit, so the supervisor enforces it.
    pub wall_clock: Duration,
}

/// How the container reaches the network. A host or shared network cannot be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkAttachment {
    /// No network at all.
    None,
    /// The job's internal network, with a sidecar that relays to the allowed hosts only.
    JobInternal {
        /// The name of the per-job sidecar.
        sidecar: String,
    },
}

/// The file that holds the job token, on a worker-side tmpfs. Mounted read-only into the agent
/// profile only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobTokenFile {
    /// Where the file is on the host.
    pub host_path: PathBuf,
}

/// A name was not a valid environment variable name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "an environment variable name is upper-case letters, digits and `_`, and does not start with a digit"
)]
pub struct BadEnvName;

/// The environment variables the supervisor sets, from a fixed list. The tool inside cannot add
/// names. Values never hold a secret: secrets go in files on a tmpfs, because the Docker daemon
/// shows the environment of a container to anyone who can inspect it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FixedEnv(Vec<(String, String)>);

impl FixedEnv {
    /// Checks every name and keeps the pairs in the given order.
    ///
    /// # Errors
    /// Returns [`BadEnvName`] for a name that is not an upper-case identifier.
    pub fn new(pairs: Vec<(String, String)>) -> Result<Self, BadEnvName> {
        let valid = |name: &str| {
            name.bytes()
                .next()
                .is_some_and(|first| first.is_ascii_uppercase() || first == b'_')
                && name
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        };
        if pairs.iter().all(|(name, _)| valid(name)) {
            Ok(Self(pairs))
        } else {
            Err(BadEnvName)
        }
    }

    /// The pairs, in order.
    #[must_use]
    pub fn pairs(&self) -> &[(String, String)] {
        &self.0
    }
}

/// How a security module (seccomp, AppArmor) is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confinement {
    /// The runtime's default profile, or one derived from it.
    RuntimeDefault,
    /// Turned off. The policy never allows this.
    Unconfined,
}

/// Which namespace a container shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    /// The container has its own.
    Private,
    /// The container uses the host's. The policy never allows this.
    Host,
}

/// The security settings of a container, as requested in a spec and as read back from the created
/// container. Comparing the two is the posture check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hardening {
    /// Privileged mode.
    pub privileged: bool,
    /// Numeric user id the process runs as.
    pub uid: u32,
    /// Numeric group id the process runs as.
    pub gid: u32,
    /// Read-only root filesystem.
    pub read_only_rootfs: bool,
    /// All capabilities dropped.
    pub cap_drop_all: bool,
    /// Capabilities added back.
    pub cap_add: Vec<String>,
    /// `no-new-privileges`.
    pub no_new_privileges: bool,
    /// Seccomp setting.
    pub seccomp: Confinement,
    /// AppArmor setting.
    pub apparmor: Confinement,
    /// Process id namespace.
    pub pid: Namespace,
    /// Inter-process communication namespace.
    pub ipc: Namespace,
    /// Host name namespace.
    pub uts: Namespace,
    /// User namespace.
    pub userns: Namespace,
    /// Devices passed through.
    pub devices: Vec<String>,
    /// Kernel parameter overrides.
    pub sysctls: Vec<String>,
    /// A minimal init process is PID 1.
    pub init: bool,
    /// The daemon keeps no copy of the logs (`--log-driver none`); the supervisor streams them.
    pub log_driver_none: bool,
}

impl Hardening {
    /// The strongest settings: what `policies/security.yaml` requires. Adapters start from this
    /// and never loosen a field.
    #[must_use]
    pub fn strict(uid: u32, gid: u32) -> Self {
        Self {
            privileged: false,
            uid,
            gid,
            read_only_rootfs: true,
            cap_drop_all: true,
            cap_add: Vec::new(),
            no_new_privileges: true,
            seccomp: Confinement::RuntimeDefault,
            apparmor: Confinement::RuntimeDefault,
            pid: Namespace::Private,
            ipc: Namespace::Private,
            uts: Namespace::Private,
            userns: Namespace::Private,
            devices: Vec::new(),
            sysctls: Vec::new(),
            init: true,
            log_driver_none: true,
        }
    }

    /// The names of the fields that differ between `self` (what was requested) and `observed`
    /// (what the created container reports). Empty means the posture matches.
    #[must_use]
    pub fn differences(&self, observed: &Hardening) -> PostureDiff {
        let mut fields = Vec::new();
        macro_rules! compare {
            ($($field:ident),+ $(,)?) => {
                $( if self.$field != observed.$field { fields.push(stringify!($field)); } )+
            };
        }
        compare!(
            privileged,
            uid,
            gid,
            read_only_rootfs,
            cap_drop_all,
            cap_add,
            no_new_privileges,
            seccomp,
            apparmor,
            pid,
            ipc,
            uts,
            userns,
            devices,
            sysctls,
            init,
            log_driver_none,
        );
        PostureDiff { fields }
    }
}

/// The settings that differ between the spec and the created container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureDiff {
    /// Names of the differing fields of [`Hardening`].
    pub fields: Vec<&'static str>,
}

impl PostureDiff {
    /// True when nothing differs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

/// A mount that is not one of the supervisor's own. A spec lists these only so the policy check
/// can refuse them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraMount {
    /// The host path.
    pub source: String,
    /// The path inside the container.
    pub target: String,
    /// True when mounted read-only.
    pub read_only: bool,
}

/// Everything needed to build one sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxSpec {
    /// The job the sandbox serves.
    pub job: JobId,
    /// The attempt the sandbox belongs to. A sandbox whose attempt is not live is an orphan.
    pub attempt: AttemptId,
    /// Which kind of sandbox.
    pub profile: SandboxProfile,
    /// The image, by digest.
    pub image: ImageDigest,
    /// Resource limits.
    pub limits: SandboxLimits,
    /// Network access.
    pub network: NetworkAttachment,
    /// `/workspace` and `/out` read-write, protected overlays, `.git` masked.
    pub mounts: WorkspaceMounts,
    /// The job token file. Agent profile only.
    pub job_token: Option<JobTokenFile>,
    /// The environment, set by the supervisor from a fixed list.
    pub env: FixedEnv,
    /// The security settings to build the container with.
    pub hardening: Hardening,
    /// Mounts beyond the supervisor's own. Normally empty.
    pub extra_mounts: Vec<ExtraMount>,
}

/// What the policy requires of every sandbox. The values are loaded from
/// `policies/security.yaml`; this crate holds no numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// The smallest user id and group id allowed. Ids below it are root-like.
    pub min_uid: u32,
    /// Host paths that may never be mounted, or lie under a path that is listed. The root path
    /// `/` forbids only a mount of the root itself.
    pub forbidden_mount_sources: Vec<String>,
    /// Environment names that may never be set.
    pub forbidden_env_names: Vec<String>,
    /// The only environment names the supervisor may set. Empty means no names are allowed.
    pub allowed_env_names: Vec<String>,
    /// The largest limits for the `fetch_deps` profile. Raising a limit is a human decision.
    pub fetch_deps_max: SandboxLimits,
    /// The largest limits for the `agent` profile.
    pub agent_max: SandboxLimits,
    /// The largest limits for the `verify` profile.
    pub verify_max: SandboxLimits,
}

impl SandboxPolicy {
    /// The largest limits allowed for `profile`.
    #[must_use]
    pub fn max_limits(&self, profile: SandboxProfile) -> &SandboxLimits {
        match profile {
            SandboxProfile::FetchDeps => &self.fetch_deps_max,
            SandboxProfile::Agent => &self.agent_max,
            SandboxProfile::Verify => &self.verify_max,
        }
    }
}

/// One way a spec is weaker than the policy. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxRule {
    /// Privileged mode.
    Privileged,
    /// A capability was added back.
    CapabilityAdded(String),
    /// Capabilities were not all dropped.
    CapabilitiesNotDropped,
    /// The user or group id is below the policy minimum (root or a system account).
    UserNotNonRoot,
    /// The root file system is writable.
    WritableRootFilesystem,
    /// `no-new-privileges` is off.
    PrivilegeEscalationPossible,
    /// Seccomp is off.
    SeccompUnconfined,
    /// AppArmor is off.
    AppArmorUnconfined,
    /// A host namespace is shared (process, IPC, host name or user).
    HostNamespace(&'static str),
    /// A device is passed through.
    DeviceAttached(String),
    /// A kernel parameter is overridden.
    SysctlOverride(String),
    /// There is no init process.
    NoInitProcess,
    /// The daemon would keep a copy of the logs.
    DaemonKeepsLogs,
    /// A host path that the policy forbids is mounted. The Docker socket is one.
    ForbiddenMountSource(String),
    /// An environment name the policy forbids.
    EnvNameForbidden(String),
    /// An environment name that is not on the supervisor's list.
    EnvNameNotAllowed(String),
    /// The network does not suit the profile: `verify` has none, the others use the job network.
    NetworkNotAllowedForProfile,
    /// A job token is present outside the agent profile, or missing from it.
    JobTokenMisplaced,
    /// A limit is above the policy maximum for the profile.
    LimitAboveMaximum(&'static str),
    /// `.git` is not masked.
    GitDirectoryNotMasked,
}

/// A spec was weaker than the policy. It lists every rule it broke.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the sandbox spec is weaker than the policy ({} rule(s) broken)", .rules.len())]
pub struct PolicyViolation {
    /// Every rule the spec broke, in a fixed order.
    pub rules: Vec<SandboxRule>,
}

impl SandboxSpec {
    /// Pure. Rejects anything weaker than the policy: privileged, added capabilities, host
    /// namespaces, the Docker socket, unconfined seccomp or AppArmor, user 0, a forbidden mount
    /// source, a network that does not suit the profile, a misplaced job token or a limit above
    /// the maximum. (A tag-only image cannot be written: [`ImageDigest`] refuses it.)
    ///
    /// # Errors
    /// Returns every broken rule, not only the first.
    pub fn validate(&self, policy: &SandboxPolicy) -> Result<(), PolicyViolation> {
        let mut rules = Vec::new();
        self.check_hardening(policy, &mut rules);
        self.check_mounts(policy, &mut rules);
        self.check_env(policy, &mut rules);
        self.check_profile_fit(&mut rules);
        self.check_limits(policy, &mut rules);
        if rules.is_empty() {
            Ok(())
        } else {
            Err(PolicyViolation { rules })
        }
    }

    fn check_hardening(&self, policy: &SandboxPolicy, rules: &mut Vec<SandboxRule>) {
        let h = &self.hardening;
        if h.privileged {
            rules.push(SandboxRule::Privileged);
        }
        rules.extend(h.cap_add.iter().cloned().map(SandboxRule::CapabilityAdded));
        if !h.cap_drop_all {
            rules.push(SandboxRule::CapabilitiesNotDropped);
        }
        if h.uid < policy.min_uid || h.gid < policy.min_uid {
            rules.push(SandboxRule::UserNotNonRoot);
        }
        if !h.read_only_rootfs {
            rules.push(SandboxRule::WritableRootFilesystem);
        }
        if !h.no_new_privileges {
            rules.push(SandboxRule::PrivilegeEscalationPossible);
        }
        if h.seccomp == Confinement::Unconfined {
            rules.push(SandboxRule::SeccompUnconfined);
        }
        if h.apparmor == Confinement::Unconfined {
            rules.push(SandboxRule::AppArmorUnconfined);
        }
        for (label, namespace) in [
            ("pid", h.pid),
            ("ipc", h.ipc),
            ("uts", h.uts),
            ("userns", h.userns),
        ] {
            if namespace == Namespace::Host {
                rules.push(SandboxRule::HostNamespace(label));
            }
        }
        rules.extend(h.devices.iter().cloned().map(SandboxRule::DeviceAttached));
        rules.extend(h.sysctls.iter().cloned().map(SandboxRule::SysctlOverride));
        if !h.init {
            rules.push(SandboxRule::NoInitProcess);
        }
        if !h.log_driver_none {
            rules.push(SandboxRule::DaemonKeepsLogs);
        }
    }

    fn check_mounts(&self, policy: &SandboxPolicy, rules: &mut Vec<SandboxRule>) {
        if !self.mounts.git_masked {
            rules.push(SandboxRule::GitDirectoryNotMasked);
        }
        for mount in &self.extra_mounts {
            let is_the_mask =
                mount.source == MASK_SOURCE && mount.target == MASK_TARGET && mount.read_only;
            let forbidden = policy.forbidden_mount_sources.iter().any(|listed| {
                mount.source == *listed
                    || (listed != "/" && mount.source.starts_with(&format!("{listed}/")))
            });
            if forbidden && !is_the_mask {
                rules.push(SandboxRule::ForbiddenMountSource(mount.source.clone()));
            }
        }
    }

    fn check_env(&self, policy: &SandboxPolicy, rules: &mut Vec<SandboxRule>) {
        for (name, _) in self.env.pairs() {
            if policy.forbidden_env_names.contains(name) {
                rules.push(SandboxRule::EnvNameForbidden(name.clone()));
            } else if !policy.allowed_env_names.contains(name) {
                rules.push(SandboxRule::EnvNameNotAllowed(name.clone()));
            }
        }
    }

    fn check_profile_fit(&self, rules: &mut Vec<SandboxRule>) {
        let network_fits = matches!(
            (self.profile, &self.network),
            (SandboxProfile::Verify, NetworkAttachment::None)
                | (
                    SandboxProfile::FetchDeps | SandboxProfile::Agent,
                    NetworkAttachment::JobInternal { .. }
                )
        );
        if !network_fits {
            rules.push(SandboxRule::NetworkNotAllowedForProfile);
        }
        let token_fits = (self.profile == SandboxProfile::Agent) == self.job_token.is_some();
        if !token_fits {
            rules.push(SandboxRule::JobTokenMisplaced);
        }
    }

    fn check_limits(&self, policy: &SandboxPolicy, rules: &mut Vec<SandboxRule>) {
        let max = policy.max_limits(self.profile);
        let own = &self.limits;
        macro_rules! at_most {
            ($($field:ident),+ $(,)?) => {
                $( if own.$field > max.$field {
                    rules.push(SandboxRule::LimitAboveMaximum(stringify!($field)));
                } )+
            };
        }
        at_most!(
            cpu_millis,
            memory_mb,
            memory_swap_mb,
            pids,
            nofile,
            max_file_mb,
            tmpfs_mb,
            workspace_disk_mb,
            wall_clock,
        );
    }
}

/// The one `/dev` mount the policy allows: this source, bound read-only over [`MASK_TARGET`].
/// It hides the checkout's version-control directory from the sandbox.
pub const MASK_SOURCE: &str = "/dev/null";

/// Where the mask is mounted inside the container.
pub const MASK_TARGET: &str = "/workspace/.git";

/// A sandbox, named by the supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SandboxId(String);

impl SandboxId {
    /// Wraps the supervisor's name for a sandbox.
    #[must_use]
    pub fn new(name: String) -> Self {
        Self(name)
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What the created container actually looked like when the supervisor inspected it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureReport {
    /// The security settings read back from the container.
    pub observed: Hardening,
    /// The image the container runs.
    pub image: ImageDigest,
    /// True when the runtime self-check inside the container passed.
    pub self_check_passed: bool,
    /// When the posture was verified.
    pub verified_at: Timestamp,
}

/// A command to run. There is no shell string: the program and its arguments are separate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecArgv(Vec<String>);

/// An argument vector was empty or held a NUL byte.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a command needs a program name and no argument may hold a NUL byte")]
pub struct BadArgv;

impl ExecArgv {
    /// The program followed by its arguments.
    ///
    /// # Errors
    /// Returns [`BadArgv`] for an empty vector, an empty program name or a NUL byte.
    pub fn new(argv: Vec<String>) -> Result<Self, BadArgv> {
        let usable = argv.first().is_some_and(|program| !program.is_empty())
            && !argv.iter().any(|a| a.contains('\0'));
        if usable { Ok(Self(argv)) } else { Err(BadArgv) }
    }

    /// The program and arguments.
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// The program name.
    #[must_use]
    pub fn program(&self) -> &str {
        self.0.first().map_or("", String::as_str)
    }
}

/// One command to run inside the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    /// The program and arguments. Never a shell string.
    pub argv: ExecArgv,
    /// The directory to run in, relative to the workspace. `None` is the workspace root.
    pub cwd: Option<RepoPath>,
    /// Bytes to send on standard input.
    pub stdin: Option<Vec<u8>>,
    /// How long the command may run before it is killed.
    pub timeout: Duration,
    /// How many bytes of each of standard output and standard error are kept. The rest is
    /// dropped and the result says so.
    pub max_output_bytes: u64,
}

/// What a command did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecResult {
    /// The exit code, when the process exited by itself.
    pub exit_code: Option<i32>,
    /// The signal that ended the process, when it was killed.
    pub signal: Option<i32>,
    /// True when the command ran past its timeout and was killed.
    pub timed_out: bool,
    /// True when the kernel killed it for using too much memory.
    pub oom_killed: bool,
    /// Standard output, stored in the artifact store after redaction.
    pub stdout: ArtifactRef,
    /// Standard error, stored in the artifact store after redaction.
    pub stderr: ArtifactRef,
    /// True when standard output was longer than `max_output_bytes` and was cut.
    pub stdout_truncated: bool,
    /// True when standard error was longer than `max_output_bytes` and was cut.
    pub stderr_truncated: bool,
    /// When the command started.
    pub started_at: Timestamp,
    /// When it ended.
    pub finished_at: Timestamp,
}

/// The resource a limit protects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    /// Memory.
    Memory,
    /// Number of processes.
    Pids,
    /// Disk space in the workspace or output directory.
    Disk,
}

/// Why a sandbox was torn down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownReason {
    /// The work finished.
    Completed,
    /// The work failed.
    Failed,
    /// The job or attempt was cancelled.
    Cancelled,
    /// The wall-clock limit passed.
    TimedOut,
    /// The posture check failed.
    PostureMismatch,
}

/// What teardown found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeardownReport {
    /// The sandbox that was removed.
    pub sandbox: SandboxId,
    /// Why it was removed.
    pub reason: TeardownReason,
    /// True when the kernel had killed it for memory.
    pub oom_killed: bool,
}

/// Why a sandbox call failed. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SandboxError {
    /// The spec is weaker than the policy. No container was made.
    #[error("the sandbox spec is weaker than the policy")]
    PolicyViolation(PolicyViolation),
    /// The container that was made differs from the spec. It was removed.
    #[error("the created container differs from the spec in: {}", .0.fields.join(", "))]
    PostureMismatch(PostureDiff),
    /// The image is not present on the host. Images are never pulled.
    #[error("the image is not available on this host")]
    ImageUnavailable,
    /// The container runtime cannot be reached. The job is blocked, never run on the host.
    #[error("the container runtime is unavailable")]
    DaemonUnavailable,
    /// The container could not be made or started. The text never includes secrets.
    #[error("the sandbox could not be provisioned: {0}")]
    ProvisionFailed(String),
    /// The sandbox lived past its wall-clock limit and was killed.
    #[error("the sandbox exceeded its wall-clock limit")]
    Timeout,
    /// A resource limit was hit.
    #[error("a resource limit was exceeded")]
    ResourceExceeded(Resource),
    /// The caller cancelled the command. The process was stopped.
    #[error("the command was cancelled")]
    Cancelled,
    /// The sandbox could not be fully removed. `leaked` says whether something may still run.
    #[error("teardown failed (leaked: {leaked})")]
    TeardownFailed {
        /// True when a container, network or sidecar may still exist.
        leaked: bool,
    },
}

/// Makes sandboxes.
///
/// # Preconditions
/// The spec's image is on the host, pinned by digest. The caller holds the attempt's lease.
///
/// # Postconditions
/// `create_verified` returns a session only for a container that was created, inspected, found to
/// match the spec and the policy, started, and found to pass the runtime self-check. A mismatch
/// removes the container and fails closed. `sweep_orphans` leaves no sandbox whose attempt is not
/// in `live`, and never touches one that is.
///
/// # Errors
/// [`SandboxError::PolicyViolation`] (checked before anything is built, with
/// [`SandboxSpec::validate`]), [`SandboxError::PostureMismatch`], [`SandboxError::ImageUnavailable`],
/// [`SandboxError::DaemonUnavailable`], [`SandboxError::ProvisionFailed`] and
/// [`SandboxError::TeardownFailed`] (from a sweep).
///
/// # Idempotency
/// `create_verified` is not idempotent: each call makes a new sandbox. `sweep_orphans` is
/// idempotent: a second sweep with the same `live` list finds nothing to remove.
#[async_trait]
pub trait SandboxProvider: Send + Sync {
    /// Says whether this provider starts real containers (`real`) or simulates them (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Create, inspect, compare with policy, start, run the runtime self-check. Never returns a
    /// container that did not pass. A mismatch removes it and fails closed.
    async fn create_verified(
        &self,
        spec: SandboxSpec,
    ) -> Result<Box<dyn SandboxSession>, SandboxError>;

    /// Removes containers, networks and sidecars whose attempt is not in `live`. Returns the
    /// sandboxes it removed.
    async fn sweep_orphans(&self, live: &[AttemptId]) -> Result<Vec<SandboxId>, SandboxError>;
}

/// One running sandbox.
///
/// # Preconditions
/// The session came from [`SandboxProvider::create_verified`], so its posture matched the policy.
///
/// # Postconditions
/// `exec` runs the argument vector as given, with no shell, and ends in one of four ways: it
/// finishes (exit code), it runs past its timeout and is killed (`timed_out`), the caller cancels
/// and the process is stopped ([`SandboxError::Cancelled`]), or the sandbox itself fails. Output
/// is capped at `max_output_bytes` and stored as artifacts. A cancel that is already set stops the
/// command before it starts. After `stop_and_remove` returns `Ok`, the container is gone.
///
/// # Errors
/// [`SandboxError::Cancelled`], [`SandboxError::Timeout`] (the sandbox's wall clock),
/// [`SandboxError::ResourceExceeded`], [`SandboxError::DaemonUnavailable`] and
/// [`SandboxError::TeardownFailed`].
///
/// # Idempotency
/// `exec` is not idempotent: each call runs the command again. `stop_and_remove` consumes the
/// session, so it is called once.
#[async_trait]
pub trait SandboxSession: Send {
    /// The sandbox's name.
    fn id(&self) -> &SandboxId;

    /// What the created container looked like when it was verified.
    fn posture(&self) -> &PostureReport;

    /// argv only. There is no shell string. Output is redacted before it is stored.
    async fn exec(
        &mut self,
        req: ExecRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<ExecResult, SandboxError>;

    /// The supervisor enforces the wall clock and the disk cap. Docker offers neither.
    async fn stop_and_remove(
        self: Box<Self>,
        reason: TeardownReason,
    ) -> Result<TeardownReport, SandboxError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::ids::{AttemptId, JobId};
    use std::path::PathBuf;

    const DIGEST: &str = "registry.local/factory/agent@sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn limits(scale: u32) -> SandboxLimits {
        SandboxLimits {
            cpu_millis: 1000 * scale,
            memory_mb: 1024 * scale,
            memory_swap_mb: 1024 * scale,
            pids: 128 * scale,
            nofile: 2048,
            max_file_mb: 512,
            tmpfs_mb: 256,
            workspace_disk_mb: 2048,
            wall_clock: Duration::from_secs(600 * u64::from(scale)),
        }
    }

    fn policy() -> SandboxPolicy {
        SandboxPolicy {
            min_uid: 10_000,
            forbidden_mount_sources: [
                "/var/run/docker.sock",
                "/run/docker.sock",
                "/",
                "/etc",
                "/var",
                "/dev",
            ]
            .map(String::from)
            .to_vec(),
            forbidden_env_names: ["LD_PRELOAD", "NODE_OPTIONS"].map(String::from).to_vec(),
            allowed_env_names: ["HOME", "PATH", "TERM"].map(String::from).to_vec(),
            fetch_deps_max: limits(1),
            agent_max: limits(2),
            verify_max: limits(4),
        }
    }

    fn spec(profile: SandboxProfile) -> SandboxSpec {
        let (network, job_token) = match profile {
            SandboxProfile::Verify => (NetworkAttachment::None, None),
            SandboxProfile::FetchDeps => (
                NetworkAttachment::JobInternal {
                    sidecar: "sidecar-1".to_owned(),
                },
                None,
            ),
            SandboxProfile::Agent => (
                NetworkAttachment::JobInternal {
                    sidecar: "sidecar-1".to_owned(),
                },
                Some(JobTokenFile {
                    host_path: PathBuf::from("/run/factory/token"),
                }),
            ),
        };
        SandboxSpec {
            job: JobId::from_uuid(uuid::Uuid::from_u128(1)),
            attempt: AttemptId::from_uuid(uuid::Uuid::from_u128(2)),
            profile,
            image: ImageDigest::parse(DIGEST).unwrap(),
            limits: limits(1),
            network,
            mounts: WorkspaceMounts {
                workspace: PathBuf::from("/jobs/1/worktree"),
                out: PathBuf::from("/jobs/1/out"),
                protected_overlays: Vec::new(),
                git_masked: true,
            },
            job_token,
            env: FixedEnv::new(vec![("HOME".to_owned(), "/home/agent".to_owned())]).unwrap(),
            hardening: Hardening::strict(10_001, 10_001),
            extra_mounts: Vec::new(),
        }
    }

    fn broken(spec: &SandboxSpec) -> Vec<SandboxRule> {
        spec.validate(&policy())
            .expect_err("the spec should be refused")
            .rules
    }

    #[test]
    fn a_policy_compliant_spec_passes_for_every_profile() {
        for profile in [
            SandboxProfile::FetchDeps,
            SandboxProfile::Agent,
            SandboxProfile::Verify,
        ] {
            assert_eq!(spec(profile).validate(&policy()), Ok(()), "{profile:?}");
        }
    }

    #[test]
    fn privileged_mode_is_refused() {
        let mut s = spec(SandboxProfile::Agent);
        s.hardening.privileged = true;
        assert!(broken(&s).contains(&SandboxRule::Privileged));
    }

    #[test]
    fn an_added_capability_is_refused_by_name() {
        let mut s = spec(SandboxProfile::Agent);
        s.hardening.cap_add = vec!["SYS_ADMIN".to_owned()];
        assert!(broken(&s).contains(&SandboxRule::CapabilityAdded("SYS_ADMIN".to_owned())));
    }

    #[test]
    fn capabilities_that_are_not_dropped_are_refused() {
        let mut s = spec(SandboxProfile::Agent);
        s.hardening.cap_drop_all = false;
        assert!(broken(&s).contains(&SandboxRule::CapabilitiesNotDropped));
    }

    #[test]
    fn root_and_system_users_are_refused() {
        for (uid, gid) in [
            (0, 0),
            (0, 10_001),
            (10_001, 0),
            (9_999, 10_001),
            (10_001, 9_999),
        ] {
            let mut s = spec(SandboxProfile::Agent);
            s.hardening.uid = uid;
            s.hardening.gid = gid;
            assert!(
                broken(&s).contains(&SandboxRule::UserNotNonRoot),
                "{uid}:{gid}"
            );
        }
    }

    #[test]
    fn a_writable_root_and_missing_no_new_privileges_are_refused() {
        let mut s = spec(SandboxProfile::Agent);
        s.hardening.read_only_rootfs = false;
        s.hardening.no_new_privileges = false;
        let rules = broken(&s);
        assert!(rules.contains(&SandboxRule::WritableRootFilesystem));
        assert!(rules.contains(&SandboxRule::PrivilegeEscalationPossible));
    }

    #[test]
    fn unconfined_seccomp_and_apparmor_are_refused() {
        let mut s = spec(SandboxProfile::Agent);
        s.hardening.seccomp = Confinement::Unconfined;
        s.hardening.apparmor = Confinement::Unconfined;
        let rules = broken(&s);
        assert!(rules.contains(&SandboxRule::SeccompUnconfined));
        assert!(rules.contains(&SandboxRule::AppArmorUnconfined));
    }

    #[test]
    fn every_host_namespace_is_refused() {
        for (label, edit) in [
            (
                "pid",
                (|h: &mut Hardening| h.pid = Namespace::Host) as fn(&mut Hardening),
            ),
            ("ipc", |h| h.ipc = Namespace::Host),
            ("uts", |h| h.uts = Namespace::Host),
            ("userns", |h| h.userns = Namespace::Host),
        ] {
            let mut s = spec(SandboxProfile::Agent);
            edit(&mut s.hardening);
            assert!(
                broken(&s).contains(&SandboxRule::HostNamespace(label)),
                "{label}"
            );
        }
    }

    #[test]
    fn devices_sysctls_and_a_missing_init_and_daemon_logs_are_refused() {
        let mut s = spec(SandboxProfile::Agent);
        s.hardening.devices = vec!["/dev/kvm".to_owned()];
        s.hardening.sysctls = vec!["net.ipv4.ip_forward=1".to_owned()];
        s.hardening.init = false;
        s.hardening.log_driver_none = false;
        let rules = broken(&s);
        assert!(rules.contains(&SandboxRule::DeviceAttached("/dev/kvm".to_owned())));
        assert!(rules.contains(&SandboxRule::SysctlOverride(
            "net.ipv4.ip_forward=1".to_owned()
        )));
        assert!(rules.contains(&SandboxRule::NoInitProcess));
        assert!(rules.contains(&SandboxRule::DaemonKeepsLogs));
    }

    #[test]
    fn the_docker_socket_and_other_forbidden_sources_are_refused() {
        for source in [
            "/var/run/docker.sock",
            "/etc",
            "/etc/ssh",
            "/var/lib/docker",
            "/",
            "/dev/sda",
        ] {
            let mut s = spec(SandboxProfile::Agent);
            s.extra_mounts = vec![ExtraMount {
                source: source.to_owned(),
                target: "/mnt/x".to_owned(),
                read_only: true,
            }];
            assert!(
                broken(&s).contains(&SandboxRule::ForbiddenMountSource(source.to_owned())),
                "{source}"
            );
        }
    }

    #[test]
    fn a_mount_next_to_a_forbidden_source_is_not_refused() {
        let mut s = spec(SandboxProfile::Agent);
        s.extra_mounts = vec![
            ExtraMount {
                source: "/etcetera/data".to_owned(),
                target: "/mnt/a".to_owned(),
                read_only: true,
            },
            ExtraMount {
                source: "/srv/cache".to_owned(),
                target: "/cache".to_owned(),
                read_only: true,
            },
        ];
        assert_eq!(s.validate(&policy()), Ok(()));
    }

    #[test]
    fn the_dev_null_mask_over_git_is_the_one_dev_mount_allowed() {
        let mut s = spec(SandboxProfile::Agent);
        s.extra_mounts = vec![ExtraMount {
            source: "/dev/null".to_owned(),
            target: "/workspace/.git".to_owned(),
            read_only: true,
        }];
        assert_eq!(s.validate(&policy()), Ok(()));
        s.extra_mounts[0].target = "/workspace/other".to_owned();
        assert!(broken(&s).contains(&SandboxRule::ForbiddenMountSource("/dev/null".to_owned())));
    }

    #[test]
    fn forbidden_and_unlisted_environment_names_are_refused() {
        let mut s = spec(SandboxProfile::Agent);
        s.env = FixedEnv::new(vec![
            ("HOME".to_owned(), "/home/agent".to_owned()),
            ("LD_PRELOAD".to_owned(), "/tmp/x.so".to_owned()),
            ("MY_OWN".to_owned(), "1".to_owned()),
        ])
        .unwrap();
        let rules = broken(&s);
        assert!(rules.contains(&SandboxRule::EnvNameForbidden("LD_PRELOAD".to_owned())));
        assert!(rules.contains(&SandboxRule::EnvNameNotAllowed("MY_OWN".to_owned())));
        assert!(!rules.contains(&SandboxRule::EnvNameNotAllowed("HOME".to_owned())));
    }

    #[test]
    fn the_network_must_suit_the_profile() {
        let mut verify = spec(SandboxProfile::Verify);
        verify.network = NetworkAttachment::JobInternal {
            sidecar: "s".to_owned(),
        };
        assert!(broken(&verify).contains(&SandboxRule::NetworkNotAllowedForProfile));

        let mut agent = spec(SandboxProfile::Agent);
        agent.network = NetworkAttachment::None;
        assert!(broken(&agent).contains(&SandboxRule::NetworkNotAllowedForProfile));
    }

    #[test]
    fn the_job_token_belongs_to_the_agent_profile_only() {
        let mut verify = spec(SandboxProfile::Verify);
        verify.job_token = Some(JobTokenFile {
            host_path: PathBuf::from("/run/t"),
        });
        assert!(broken(&verify).contains(&SandboxRule::JobTokenMisplaced));

        let mut agent = spec(SandboxProfile::Agent);
        agent.job_token = None;
        assert!(broken(&agent).contains(&SandboxRule::JobTokenMisplaced));
    }

    #[test]
    fn a_limit_above_the_profile_maximum_is_refused_by_field() {
        let mut s = spec(SandboxProfile::FetchDeps);
        s.limits.memory_mb = 4096;
        s.limits.pids = 10_000;
        s.limits.wall_clock = Duration::from_secs(99_999);
        let rules = broken(&s);
        assert!(rules.contains(&SandboxRule::LimitAboveMaximum("memory_mb")));
        assert!(rules.contains(&SandboxRule::LimitAboveMaximum("pids")));
        assert!(rules.contains(&SandboxRule::LimitAboveMaximum("wall_clock")));
        assert!(!rules.contains(&SandboxRule::LimitAboveMaximum("cpu_millis")));
    }

    #[test]
    fn an_unmasked_git_directory_is_refused() {
        let mut s = spec(SandboxProfile::Agent);
        s.mounts.git_masked = false;
        assert!(broken(&s).contains(&SandboxRule::GitDirectoryNotMasked));
    }

    #[test]
    fn every_broken_rule_is_reported_not_only_the_first() {
        let mut s = spec(SandboxProfile::Agent);
        s.hardening.privileged = true;
        s.hardening.uid = 0;
        s.mounts.git_masked = false;
        assert!(broken(&s).len() >= 3);
    }

    #[test]
    fn a_tag_is_not_an_image_digest() {
        for bad in [
            "alpine",
            "alpine:3.20",
            "alpine@sha256:abc",
            "@sha256:",
            "x@sha256:ZZ",
        ] {
            assert_eq!(ImageDigest::parse(bad), Err(NotADigest), "{bad}");
        }
        assert!(ImageDigest::parse(DIGEST).is_ok());
    }

    #[test]
    fn a_command_needs_a_program_and_no_nul_bytes() {
        assert!(ExecArgv::new(vec![]).is_err());
        assert!(ExecArgv::new(vec![String::new()]).is_err());
        assert!(ExecArgv::new(vec!["ls".into(), "a\0b".into()]).is_err());
        let ok = ExecArgv::new(vec!["echo".into(), "hi".into()]).unwrap();
        assert_eq!(ok.program(), "echo");
    }

    #[test]
    fn environment_names_must_be_upper_case_identifiers() {
        assert!(FixedEnv::new(vec![("HOME".into(), "x".into())]).is_ok());
        for bad in ["home", "1ABC", "A-B", "", "A B"] {
            assert!(
                FixedEnv::new(vec![(bad.into(), "x".into())]).is_err(),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn posture_differences_name_the_fields_that_changed() {
        let requested = Hardening::strict(10_001, 10_001);
        let mut observed = requested.clone();
        assert!(requested.differences(&observed).is_empty());
        observed.privileged = true;
        observed.cap_add = vec!["NET_ADMIN".to_owned()];
        assert_eq!(
            requested.differences(&observed).fields,
            vec!["privileged", "cap_add"]
        );
    }
}
