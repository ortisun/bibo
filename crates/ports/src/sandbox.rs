//! The sandbox ports: hardened, ephemeral containers that run untrusted work (ADR 0003, ADR 0014
//! decision 5).
//!
//! A [`SandboxSpec`] says what to build. [`SandboxSpec::validate`] is a pure check against the
//! [`SandboxPolicy`] and rejects anything weaker. The provider then builds the container, reads
//! back what it actually built (the [`PostureReport`]), and hands out a session only if the two
//! agree in every part ([`PostureReport::differences`]). There is no downgrade to a weaker profile
//! and no fallback to the host.
//!
//! The spec is an allow list by construction: [`SandboxMounts`] holds the workspace mounts and
//! named caches and nothing else, so a mount of the Docker socket or of a host directory cannot be
//! written. Eight limits are `NonZeroU32`, so "no limit" cannot be written either.

use std::fmt;
use std::num::NonZeroU32;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::{AttemptId, JobId};
use factory_domain::values::{Slug, Timestamp};

use crate::agent::JobTokenSecret;
use crate::clock::CancelSignal;
use crate::paths::RepoPath;
use crate::workspace::WorkspaceMounts;

/// The kinds of sandbox (ADR 0003, ADR 0021). Each has its own network and its own limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxProfile {
    /// Downloads dependencies through a relay to named registries. Runs no repository code.
    FetchDeps,
    /// Runs the agent tool. Reaches only the model broker, with one job token.
    Agent,
    /// Runs the trusted gates with no network, in a fresh container.
    Verify,
    /// Runs the troubleshooter's agent (ADR 0021): the agent image and hardening, no repository
    /// (an empty workspace, read-only), the job token and the MCP gateway's run token, and a
    /// sidecar that relays to the broker and, through its second fixed relay, to the gateway.
    Troubleshooter,
}

impl SandboxProfile {
    /// The name used in policy files and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FetchDeps => "fetch_deps",
            Self::Agent => "agent",
            Self::Verify => "verify",
            Self::Troubleshooter => "troubleshooter",
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

/// Where the job token file is mounted inside an `agent` container: read-only, at this fixed path.
/// The sandbox adapter writes the secret to a tmpfs it controls, mode 0400, and removes the file
/// when the sandbox is torn down, whatever the reason.
pub const JOB_TOKEN_TARGET: &str = "/run/factory/job-token";

/// Where the run token of the MCP gateway is mounted inside a `troubleshooter` container:
/// read-only, at this fixed path, written and removed by the sandbox adapter exactly like the job
/// token (ADR 0021). Only the runtime's launcher line reads it.
pub const MCP_TOKEN_TARGET: &str = "/run/factory/mcp-token";

/// Where the checkout is mounted inside the container.
pub const WORKSPACE_TARGET: &str = "/workspace";

/// Where the output directory is mounted, read-write.
pub const OUT_TARGET: &str = "/out";

/// Where a build inside any sandbox puts its target directory (`CARGO_TARGET_DIR`): under the
/// output directory, which every profile mounts writable and without `noexec`, which the disk
/// watchdog counts, and which the host never ingests. The checkout is no place for it: in a
/// `verify` sandbox it is read-only, and in an `agent` sandbox the ingestion audit refuses every
/// file under `target/` (real run 32 of scenario E1, ADR 0024).
pub const BUILD_TARGET_DIR: &str = "/out/target";

/// The temporary directory a build in a sandbox is given (`TMPDIR`). The scratch tmpfs (`/tmp`) and
/// the home are `noexec`, and `rustdoc` and some tests run the programs they write there, so the
/// temporary directory is the output directory, which allows it (ADR 0024).
pub const BUILD_TEMP_DIR: &str = OUT_TARGET;

/// The scratch tmpfs every container has, because the root file system is read-only. Its size is
/// `SandboxLimits::tmpfs_mb`.
pub const SCRATCH_TARGET: &str = "/tmp";

/// The directory under which a named cache is mounted: `/caches/<name>`.
pub const CACHE_ROOT: &str = "/caches";

/// What `source` shows for a tmpfs mount in an [`ObservedMount`].
pub const TMPFS_SOURCE: &str = "tmpfs";

/// Resource limits for one container. Every value is at least 1, so "no limit" cannot be written:
/// Docker reads 0 as unlimited for memory, CPUs and processes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxLimits {
    /// CPU in thousandths of a core (2000 is two cores).
    pub cpu_millis: NonZeroU32,
    /// Memory in MiB.
    pub memory_mb: NonZeroU32,
    /// Memory plus swap in MiB. At least `memory_mb`. Equal means no swap.
    pub memory_swap_mb: NonZeroU32,
    /// Maximum number of processes.
    pub pids: NonZeroU32,
    /// Maximum number of open files.
    pub nofile: NonZeroU32,
    /// Largest single file in MiB.
    pub max_file_mb: NonZeroU32,
    /// Size of each tmpfs in MiB.
    pub tmpfs_mb: NonZeroU32,
    /// Disk the workspace and output directories may use, in MiB.
    pub workspace_disk_mb: NonZeroU32,
    /// How long the container may live. Not zero. Docker has no such limit, so the supervisor
    /// enforces it.
    pub wall_clock: Duration,
}

/// A named read-only cache the supervisor owns, such as `cargo-registry`. The host directory
/// behind a name is the adapter's own business and is never in a spec.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheName(pub Slug);

/// A cache mounted into the container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheMount {
    /// Which cache.
    pub name: CacheName,
    /// True when the container may write to it. Only the `fetch_deps` profile may.
    pub writable: bool,
}

/// Everything mounted into the container. There is no free-form mount: a spec can name only
/// these kinds, so a mount of the Docker socket or of a host directory cannot be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxMounts {
    /// The checkout and output directories, protected overlays and the `.git` mask.
    pub workspace: WorkspaceMounts,
    /// The caches. Usually empty for `agent`.
    pub caches: Vec<CacheMount>,
}

/// The job token, as the secret itself. The sandbox adapter, and only it, writes the secret to a
/// file on a tmpfs it controls, mode 0400 and owned by the sandbox user, mounts the file
/// read-only at a fixed path, and removes it when the sandbox is torn down, whatever the reason.
/// The engine never writes a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobTokenMount {
    /// The token's secret. Never shown in `Debug` output.
    pub secret: JobTokenSecret,
}

/// The run token of the troubleshooter's MCP gateway, as the secret itself (ADR 0021). The sandbox
/// adapter handles it exactly like the job token: a 0400 file on a tmpfs it controls, mounted
/// read-only at [`MCP_TOKEN_TARGET`], registered with the redactor, removed at teardown. Its text
/// never appears in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct McpRunTokenSecret(String);

impl McpRunTokenSecret {
    /// Wraps a secret the gateway issued for one run.
    #[must_use]
    pub fn new(secret: String) -> Self {
        Self(secret)
    }

    /// The secret text. Write it to the token file and nowhere else.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for McpRunTokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("McpRunTokenSecret(<redacted>)")
    }
}

/// The MCP gateway's run token for a `troubleshooter` sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpTokenMount {
    /// The token's secret. Never shown in `Debug` output.
    pub secret: McpRunTokenSecret,
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
    /// The module does not exist on this daemon (AppArmor on Docker Desktop). Allowed only when
    /// [`SandboxPolicy::apparmor_may_be_unavailable`] is set, and only for AppArmor.
    NotAvailable,
}

/// Which namespace a container shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    /// The container has its own.
    Private,
    /// The container has none (`ipc: none`).
    None,
    /// The container uses the host's. The policy never allows this.
    Host,
}

/// The security settings of a container, as requested in a spec and as read back from the created
/// container. Fields and `Hardening::strict` are unchanged from ports-v1; only the types of
/// `seccomp`, `apparmor`, `pid`, `ipc`, `uts` and `userns` are the enums above.
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
    /// Inter-process communication namespace. `Namespace::None` is `ipc: none`.
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
    /// The daemon keeps no copy of the logs.
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

/// What the policy requires of every sandbox. The values are loaded from
/// `policies/security.yaml`; this crate holds no numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// The smallest user id and group id allowed.
    pub min_uid: u32,
    /// Host paths that may never be mounted or lie under a mount source. A second layer under the
    /// typed mounts: it checks the two host directories a workspace brings.
    pub forbidden_mount_sources: Vec<String>,
    /// Environment names that may never be set.
    pub forbidden_env_names: Vec<String>,
    /// The only environment names the supervisor may set.
    pub allowed_env_names: Vec<String>,
    /// True on a development host whose daemon has no AppArmor. The posture report then records
    /// `NotAvailable` and the reason. Production hosts set it to false.
    pub apparmor_may_be_unavailable: bool,
    /// The largest limits for the `fetch_deps` profile.
    pub fetch_deps_max: SandboxLimits,
    /// The largest limits for the `agent` profile.
    pub agent_max: SandboxLimits,
    /// The largest limits for the `verify` profile.
    pub verify_max: SandboxLimits,
    /// The largest limits for the `troubleshooter` profile.
    pub troubleshooter_max: SandboxLimits,
}

impl SandboxPolicy {
    /// The largest limits allowed for `profile`.
    #[must_use]
    pub fn max_limits(&self, profile: SandboxProfile) -> &SandboxLimits {
        match profile {
            SandboxProfile::FetchDeps => &self.fetch_deps_max,
            SandboxProfile::Agent => &self.agent_max,
            SandboxProfile::Verify => &self.verify_max,
            SandboxProfile::Troubleshooter => &self.troubleshooter_max,
        }
    }
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
    /// The mounts. Typed; nothing else can be mounted.
    pub mounts: SandboxMounts,
    /// The job token. `agent` and `troubleshooter` profiles only.
    pub job_token: Option<JobTokenMount>,
    /// The MCP gateway's run token. `troubleshooter` profile only, and required there.
    pub mcp_token: Option<McpTokenMount>,
    /// The environment, set by the supervisor from a fixed list.
    pub env: FixedEnv,
    /// The security settings to build the container with.
    pub hardening: Hardening,
}

/// One mount the spec asks for, as the posture check expects to find it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedMount {
    /// Where it is inside the container.
    pub target: String,
    /// True when it is read-only.
    pub read_only: bool,
    /// The host path, when the spec names one (the checkout and the output directory). `None`
    /// for mounts whose host side the adapter chooses (caches, the token file, tmpfs).
    pub source: Option<String>,
}

/// One mount of the created container, as `docker inspect` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedMount {
    /// Where it is inside the container.
    pub target: String,
    /// True when it is read-only.
    pub read_only: bool,
    /// The host path, or the kind for a tmpfs.
    pub source: String,
}

/// What the created container actually looked like when the supervisor inspected it.
/// Everything the spec asked for is read back here, so the engine can compare all of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureReport {
    /// The security settings read back from the container.
    pub observed: Hardening,
    /// The image the container runs.
    pub image: ImageDigest,
    /// The limits read back. `wall_clock` is the supervisor's deadline for the container.
    pub limits: SandboxLimits,
    /// The network the container is attached to.
    pub network: NetworkAttachment,
    /// Every mount of the container.
    pub mounts: Vec<ObservedMount>,
    /// The environment of the container as `Config.Env` reports it.
    pub env: Vec<(String, String)>,
    /// True when the runtime self-check inside the container passed.
    pub self_check_passed: bool,
    /// When the posture was verified.
    pub verified_at: Timestamp,
}

/// Which parts of the posture differ from the spec. Empty means the posture matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostureDiff {
    /// Names of the differing parts: the field names of `Hardening`, and `image`, `limits`,
    /// `network`, `mounts`, `env`, `self_check`.
    pub fields: Vec<&'static str>,
}

impl PostureDiff {
    /// True when nothing differs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }
}

impl PostureReport {
    /// Pure. Compares every part of the report with the spec and the policy:
    ///
    /// * `Hardening`: each field equal, except that `apparmor` may be `NotAvailable` against a
    ///   requested `RuntimeDefault` when the policy allows it.
    /// * `image` equal; `limits` equal; `network` equal.
    /// * `mounts`: the observed set equals [`SandboxSpec::expected_mounts`]. A mount that is not
    ///   expected is a difference, and so is a missing one or one whose read-only flag differs.
    /// * `env`: every pair of the spec is present with the same value, and every observed name is
    ///   on the policy's allowed list.
    /// * `self_check_passed` is true.
    #[must_use]
    pub fn differences(&self, spec: &SandboxSpec, policy: &SandboxPolicy) -> PostureDiff {
        let mut fields = spec.hardening.differences(&self.observed).fields;
        // A daemon without AppArmor reports `NotAvailable` for a requested default profile. That
        // is accepted only when the policy says so, which a development host does and a
        // production host does not.
        let apparmor_excused = policy.apparmor_may_be_unavailable
            && spec.hardening.apparmor == Confinement::RuntimeDefault
            && self.observed.apparmor == Confinement::NotAvailable;
        if apparmor_excused {
            fields.retain(|name| *name != "apparmor");
        }
        if self.image != spec.image {
            fields.push("image");
        }
        if self.limits != spec.limits {
            fields.push("limits");
        }
        if self.network != spec.network {
            fields.push("network");
        }
        if !self.mounts_match(&spec.expected_mounts()) {
            fields.push("mounts");
        }
        if !self.env_matches(spec, policy) {
            fields.push("env");
        }
        if !self.self_check_passed {
            fields.push("self_check");
        }
        PostureDiff { fields }
    }
}

impl SandboxSpec {
    /// Pure. Every mount the spec asks for, with the flags the policy requires.
    #[must_use]
    pub fn expected_mounts(&self) -> Vec<ExpectedMount> {
        let workspace = &self.mounts.workspace;
        let mut mounts = vec![
            ExpectedMount {
                target: WORKSPACE_TARGET.to_owned(),
                read_only: workspace.workspace_read_only,
                source: Some(workspace.workspace.to_string_lossy().into_owned()),
            },
            ExpectedMount {
                target: OUT_TARGET.to_owned(),
                read_only: false,
                source: Some(workspace.out.to_string_lossy().into_owned()),
            },
            ExpectedMount {
                target: SCRATCH_TARGET.to_owned(),
                read_only: false,
                source: Some(TMPFS_SOURCE.to_owned()),
            },
        ];
        for overlay in &workspace.protected_overlays {
            mounts.push(ExpectedMount {
                target: format!("{WORKSPACE_TARGET}/{}", overlay.as_str()),
                read_only: true,
                source: None,
            });
        }
        if workspace.git_masked {
            mounts.push(ExpectedMount {
                target: MASK_TARGET.to_owned(),
                read_only: true,
                source: Some(MASK_SOURCE.to_owned()),
            });
        }
        for cache in &self.mounts.caches {
            mounts.push(ExpectedMount {
                target: format!("{CACHE_ROOT}/{}", cache.name.0.as_str()),
                read_only: !cache.writable,
                source: None,
            });
        }
        if self.job_token.is_some() {
            mounts.push(ExpectedMount {
                target: JOB_TOKEN_TARGET.to_owned(),
                read_only: true,
                source: None,
            });
        }
        if self.mcp_token.is_some() {
            mounts.push(ExpectedMount {
                target: MCP_TOKEN_TARGET.to_owned(),
                read_only: true,
                source: None,
            });
        }
        mounts
    }

    /// Pure. Rejects anything weaker than the policy. In addition to the rules of ports-v1
    /// (privileged, capabilities, user, root file system, privilege escalation, seccomp, host
    /// namespaces, devices, sysctls, init, log driver, environment, network and token fit to the
    /// profile, limits at most the maximum, the `.git` mask), it rejects:
    ///
    /// * a zero wall clock, and `memory_swap_mb` below `memory_mb`;
    /// * AppArmor `NotAvailable` unless the policy allows it, and `NotAvailable` for seccomp;
    /// * a workspace or output directory that is not an absolute, normalized host path (no `..`,
    ///   no `.` or empty component, no trailing `/`) or that is, or lies under, a forbidden mount
    ///   source;
    /// * a `verify` workspace that is not read-only, and an `agent` or `fetch_deps` workspace that
    ///   is read-only;
    /// * a writable cache outside `fetch_deps`, and a cache named twice.
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
        // A seccomp profile that is not applied is the same as none.
        if matches!(
            h.seccomp,
            Confinement::Unconfined | Confinement::NotAvailable
        ) {
            rules.push(SandboxRule::SeccompUnconfined);
        }
        match h.apparmor {
            Confinement::RuntimeDefault => {}
            Confinement::Unconfined => rules.push(SandboxRule::AppArmorUnconfined),
            Confinement::NotAvailable => {
                if !policy.apparmor_may_be_unavailable {
                    rules.push(SandboxRule::AppArmorUnavailableNotPermitted);
                }
            }
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
        let workspace = &self.mounts.workspace;
        if !workspace.git_masked {
            rules.push(SandboxRule::GitDirectoryNotMasked);
        }
        for (label, path) in [("workspace", &workspace.workspace), ("out", &workspace.out)] {
            let text = path.to_string_lossy();
            if !is_absolute_and_normalized(&text) {
                rules.push(SandboxRule::HostPathNotNormalized(label));
                continue;
            }
            let forbidden = policy.forbidden_mount_sources.iter().any(|listed| {
                *text == **listed || (listed != "/" && text.starts_with(&format!("{listed}/")))
            });
            if forbidden {
                rules.push(SandboxRule::ForbiddenMountSource(text.into_owned()));
            }
        }
        let read_only_fits = match self.profile {
            SandboxProfile::Verify => workspace.workspace_read_only,
            SandboxProfile::Agent | SandboxProfile::FetchDeps => !workspace.workspace_read_only,
            // No repository: an empty workspace, read-only, with nothing laid over it.
            SandboxProfile::Troubleshooter => {
                workspace.workspace_read_only && workspace.protected_overlays.is_empty()
            }
        };
        if !read_only_fits {
            rules.push(SandboxRule::WorkspaceAccessMismatch);
        }
        if self.profile == SandboxProfile::Troubleshooter && !self.mounts.caches.is_empty() {
            rules.push(SandboxRule::CacheMisuse);
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut misuse = false;
        for cache in &self.mounts.caches {
            if cache.writable && self.profile != SandboxProfile::FetchDeps {
                misuse = true;
            }
            if !seen.insert(cache.name.0.as_str()) {
                misuse = true;
            }
        }
        if misuse {
            rules.push(SandboxRule::CacheMisuse);
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
                    SandboxProfile::FetchDeps
                        | SandboxProfile::Agent
                        | SandboxProfile::Troubleshooter,
                    NetworkAttachment::JobInternal { .. }
                )
        );
        if !network_fits {
            rules.push(SandboxRule::NetworkNotAllowedForProfile);
        }
        let runs_an_agent = matches!(
            self.profile,
            SandboxProfile::Agent | SandboxProfile::Troubleshooter
        );
        if runs_an_agent != self.job_token.is_some() {
            rules.push(SandboxRule::JobTokenMisplaced);
        }
        if (self.profile == SandboxProfile::Troubleshooter) != self.mcp_token.is_some() {
            rules.push(SandboxRule::McpTokenMisplaced);
        }
    }

    fn check_limits(&self, policy: &SandboxPolicy, rules: &mut Vec<SandboxRule>) {
        let max = policy.max_limits(self.profile);
        let own = &self.limits;
        if own.wall_clock.is_zero() {
            rules.push(SandboxRule::LimitIsZero("wall_clock"));
        }
        if own.memory_swap_mb < own.memory_mb {
            rules.push(SandboxRule::SwapBelowMemory);
        }
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

/// One way a spec is weaker than the policy. The set is closed. The first group is unchanged from
/// ports-v1 except `ForbiddenMountSource`, which now reports the host path of the workspace or
/// output directory; the second group is new.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxRule {
    /// Privileged mode.
    Privileged,
    /// A capability was added back.
    CapabilityAdded(String),
    /// Capabilities were not all dropped.
    CapabilitiesNotDropped,
    /// The user or group id is below the policy minimum.
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
    /// The workspace or output directory is, or lies under, a path the policy forbids.
    ForbiddenMountSource(String),
    /// An environment name the policy forbids.
    EnvNameForbidden(String),
    /// An environment name that is not on the supervisor's list.
    EnvNameNotAllowed(String),
    /// The network does not suit the profile.
    NetworkNotAllowedForProfile,
    /// A job token is present outside the agent and troubleshooter profiles, or missing from them.
    JobTokenMisplaced,
    /// The MCP gateway's run token is present outside the troubleshooter profile, or missing
    /// from it.
    McpTokenMisplaced,
    /// A limit is above the policy maximum for the profile.
    LimitAboveMaximum(&'static str),
    /// `.git` is not masked.
    GitDirectoryNotMasked,
    /// A limit is zero. Only the wall clock can be, because the others cannot be written as zero.
    LimitIsZero(&'static str),
    /// `memory_swap_mb` is below `memory_mb`.
    SwapBelowMemory,
    /// AppArmor is not available and the policy does not allow that.
    AppArmorUnavailableNotPermitted,
    /// A host path is not absolute and normalized.
    HostPathNotNormalized(&'static str),
    /// The workspace is writable in `verify` or `troubleshooter`, read-only elsewhere, or has
    /// protected overlays in `troubleshooter`, which has no repository.
    WorkspaceAccessMismatch,
    /// A cache is writable outside `fetch_deps`, listed twice, or mounted in `troubleshooter`.
    CacheMisuse,
}

/// A spec was weaker than the policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the sandbox spec is weaker than the policy")]
pub struct PolicyViolation {
    /// Every rule the spec broke, in a fixed order.
    pub rules: Vec<SandboxRule>,
}

/// Where provisioning stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvisionStage {
    /// Writing the job token file.
    TokenFile,
    /// Making the per-job network or the sidecar.
    Network,
    /// Creating the container.
    Create,
    /// Inspecting it.
    Inspect,
    /// Starting it.
    Start,
    /// Running the self-check.
    SelfCheck,
}

/// Why a sandbox call failed. The set is closed. Changes from ports-v1: `ProvisionFailed` names
/// the stage instead of carrying text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SandboxError {
    /// The spec is weaker than the policy. No container was made.
    #[error("the sandbox spec is weaker than the policy")]
    PolicyViolation(PolicyViolation),
    /// The created container differs from the spec. It was removed.
    #[error("the created container differs from the spec in: {}", .0.fields.join(", "))]
    PostureMismatch(PostureDiff),
    /// The image is not present on the host. Images are never pulled.
    #[error("the image is not available on this host")]
    ImageUnavailable,
    /// The container runtime cannot be reached. The stage run is blocked, never run on the host.
    #[error("the container runtime is unavailable")]
    DaemonUnavailable,
    /// The container could not be made or started. Anything made so far was removed.
    #[error("the sandbox could not be provisioned at {0:?}")]
    ProvisionFailed(ProvisionStage),
    /// The sandbox lived past its wall-clock limit and was killed.
    #[error("the sandbox exceeded its wall-clock limit")]
    Timeout,
    /// A resource limit was hit.
    #[error("a resource limit was exceeded")]
    ResourceExceeded(Resource),
    /// The caller cancelled the call. The process was stopped and anything made was removed.
    #[error("the call was cancelled")]
    Cancelled,
    /// The sandbox could not be fully removed. `leaked` says whether something may still run.
    #[error("teardown failed (leaked: {leaked})")]
    TeardownFailed {
        /// True when a container, network, sidecar or token file may still exist.
        leaked: bool,
    },
}

/// Makes sandboxes.
///
/// # Preconditions
/// The spec's image is on the host, pinned by digest. The caller holds the attempt's lease.
///
/// # Postconditions
/// `create_verified` returns a session only for a container that was created, inspected, found
/// to match the spec and the policy in every part of [`PostureReport::differences`], started, and
/// found to pass the runtime self-check. A mismatch removes the container and fails closed.
/// For an `agent` sandbox the job token file exists inside the container at the fixed path
/// and nowhere else on the host once the sandbox is torn down. `sweep_orphans` leaves no sandbox,
/// network, sidecar or token file whose attempt is not in `live`, and never touches one that is.
///
/// # Errors
/// [`SandboxError`].
///
/// # Idempotency
/// `create_verified` is not idempotent. `sweep_orphans` is.
///
/// # Cancellation and timeouts
/// `create_verified` takes a cancel signal. A cancelled or timed-out provisioning removes
/// everything it made before it returns, and reports `Cancelled` or `ProvisionFailed`. Dropping
/// the future is unsafe for resources, so the supervisor does the removal in a guard that runs on
/// drop; `sweep_orphans` is the backstop.
#[async_trait]
pub trait SandboxProvider: Send + Sync {
    /// Says whether this provider starts real containers (`real`) or simulates them (`fake`).
    fn fidelity(&self) -> factory_domain::vocabulary::Fidelity;

    /// Create, inspect, compare with policy, start, run the runtime self-check.
    async fn create_verified(
        &self,
        spec: SandboxSpec,
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn SandboxSession>, SandboxError>;

    /// Removes containers, networks, sidecars and token files whose attempt is not in `live`.
    async fn sweep_orphans(&self, live: &[AttemptId]) -> Result<Vec<SandboxId>, SandboxError>;
}

/// True for an absolute host path with no `.`, `..` or empty component and no trailing `/`.
/// The root `/` alone counts as normalized; the forbidden list refuses it.
fn is_absolute_and_normalized(text: &str) -> bool {
    let Some(rest) = text.strip_prefix('/') else {
        return false;
    };
    if text.contains('\0') {
        return false;
    }
    rest.is_empty()
        || rest
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

impl PostureReport {
    /// True when the observed mounts are exactly the expected ones: each target once, with the
    /// read-only flag, and the host source where the spec names one.
    fn mounts_match(&self, expected: &[ExpectedMount]) -> bool {
        self.mounts.len() == expected.len()
            && expected.iter().all(|want| {
                let mut found = self.mounts.iter().filter(|m| m.target == want.target);
                match (found.next(), found.next()) {
                    (Some(have), None) => {
                        have.read_only == want.read_only
                            && want
                                .source
                                .as_ref()
                                .is_none_or(|source| *source == have.source)
                    }
                    _ => false,
                }
            })
    }

    /// True when every pair of the spec is present with the same value and every observed name
    /// is on the policy's allowed list.
    fn env_matches(&self, spec: &SandboxSpec, policy: &SandboxPolicy) -> bool {
        let all_present = spec
            .env
            .pairs()
            .iter()
            .all(|(name, value)| self.env.iter().any(|(n, v)| n == name && v == value));
        let all_allowed = self
            .env
            .iter()
            .all(|(name, _)| policy.allowed_env_names.contains(name));
        all_present && all_allowed
    }
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
///
/// # Cancellation and timeouts
/// exec takes a cancel signal and stops the process within a second, reporting Cancelled. Each
/// command has its own timeout and the sandbox has a wall clock; running past either is reported,
/// never ignored. stop_and_remove runs to the end: a failure leaves a TeardownFailed that says
/// whether anything may still run.
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
    use std::path::PathBuf;

    const DIGEST: &str = "registry.local/factory/agent@sha256:0000000000000000000000000000000000000000000000000000000000000000";
    const OTHER_DIGEST: &str = "registry.local/factory/agent@sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn n(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).expect("a non-zero test value")
    }

    fn limits(scale: u32) -> SandboxLimits {
        SandboxLimits {
            cpu_millis: n(1000 * scale),
            memory_mb: n(1024 * scale),
            memory_swap_mb: n(1024 * scale),
            pids: n(128 * scale),
            nofile: n(2048),
            max_file_mb: n(512),
            tmpfs_mb: n(256),
            workspace_disk_mb: n(2048),
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
            apparmor_may_be_unavailable: false,
            fetch_deps_max: limits(1),
            agent_max: limits(2),
            verify_max: limits(4),
            troubleshooter_max: limits(1),
        }
    }

    fn mcp_token_mount() -> McpTokenMount {
        // Built at run time so that no secret-shaped literal sits in the source.
        McpTokenMount {
            secret: McpRunTokenSecret::new(format!("{}-{}", "test", "gateway-value")),
        }
    }

    fn token_mount() -> JobTokenMount {
        // Built at run time so that no secret-shaped literal sits in the source.
        JobTokenMount {
            secret: JobTokenSecret::new(format!("{}-{}", "test", "secret-value")),
        }
    }

    fn spec(profile: SandboxProfile) -> SandboxSpec {
        let troubleshooter = profile == SandboxProfile::Troubleshooter;
        let (network, job_token) = match profile {
            SandboxProfile::Verify => (NetworkAttachment::None, None),
            SandboxProfile::FetchDeps => (
                NetworkAttachment::JobInternal {
                    sidecar: "sidecar-1".to_owned(),
                },
                None,
            ),
            SandboxProfile::Agent | SandboxProfile::Troubleshooter => (
                NetworkAttachment::JobInternal {
                    sidecar: "sidecar-1".to_owned(),
                },
                Some(token_mount()),
            ),
        };
        SandboxSpec {
            job: JobId::from_uuid(uuid::Uuid::from_u128(1)),
            attempt: AttemptId::from_uuid(uuid::Uuid::from_u128(2)),
            profile,
            image: ImageDigest::parse(DIGEST).unwrap(),
            limits: limits(1),
            network,
            mounts: SandboxMounts {
                workspace: WorkspaceMounts {
                    workspace: PathBuf::from("/jobs/1/worktree"),
                    workspace_read_only: profile == SandboxProfile::Verify || troubleshooter,
                    out: PathBuf::from("/jobs/1/out"),
                    protected_overlays: if troubleshooter {
                        Vec::new()
                    } else {
                        vec![RepoPath::new(".github").unwrap()]
                    },
                    git_masked: true,
                },
                caches: Vec::new(),
            },
            job_token,
            mcp_token: troubleshooter.then(mcp_token_mount),
            env: FixedEnv::new(vec![("HOME".to_owned(), "/home/sandbox".to_owned())]).unwrap(),
            hardening: Hardening::strict(10_001, 10_001),
        }
    }

    /// A report that matches `spec` in every part.
    fn report(spec: &SandboxSpec) -> PostureReport {
        PostureReport {
            observed: spec.hardening.clone(),
            image: spec.image.clone(),
            limits: spec.limits.clone(),
            network: spec.network.clone(),
            mounts: spec
                .expected_mounts()
                .into_iter()
                .map(|m| ObservedMount {
                    source: m.source.unwrap_or_else(|| "host-chosen".to_owned()),
                    target: m.target,
                    read_only: m.read_only,
                })
                .collect(),
            env: spec.env.pairs().to_vec(),
            self_check_passed: true,
            verified_at: Timestamp::parse("2026-10-27T10:00:00Z").unwrap(),
        }
    }

    fn rules_of(spec: &SandboxSpec) -> Vec<SandboxRule> {
        spec.validate(&policy())
            .expect_err("the spec should be refused")
            .rules
    }

    // ---- validate: the rules of ports-v1 ------------------------------------------------------------

    #[test]
    fn a_strict_spec_passes_for_each_profile() {
        for profile in [
            SandboxProfile::FetchDeps,
            SandboxProfile::Agent,
            SandboxProfile::Verify,
        ] {
            assert_eq!(spec(profile).validate(&policy()), Ok(()), "{profile:?}");
        }
    }

    #[test]
    fn each_weaker_setting_is_refused_for_its_own_rule() {
        type Edit = fn(&mut SandboxSpec);
        let cases: [(&str, Edit, SandboxRule); 13] = [
            (
                "privileged",
                |s| s.hardening.privileged = true,
                SandboxRule::Privileged,
            ),
            (
                "capability",
                |s| s.hardening.cap_add.push("SYS_ADMIN".to_owned()),
                SandboxRule::CapabilityAdded("SYS_ADMIN".to_owned()),
            ),
            (
                "caps kept",
                |s| s.hardening.cap_drop_all = false,
                SandboxRule::CapabilitiesNotDropped,
            ),
            (
                "root user",
                |s| s.hardening.uid = 0,
                SandboxRule::UserNotNonRoot,
            ),
            (
                "writable root",
                |s| s.hardening.read_only_rootfs = false,
                SandboxRule::WritableRootFilesystem,
            ),
            (
                "escalation",
                |s| s.hardening.no_new_privileges = false,
                SandboxRule::PrivilegeEscalationPossible,
            ),
            (
                "seccomp off",
                |s| s.hardening.seccomp = Confinement::Unconfined,
                SandboxRule::SeccompUnconfined,
            ),
            (
                "apparmor off",
                |s| s.hardening.apparmor = Confinement::Unconfined,
                SandboxRule::AppArmorUnconfined,
            ),
            (
                "host pid",
                |s| s.hardening.pid = Namespace::Host,
                SandboxRule::HostNamespace("pid"),
            ),
            (
                "device",
                |s| s.hardening.devices.push("/dev/kvm".to_owned()),
                SandboxRule::DeviceAttached("/dev/kvm".to_owned()),
            ),
            (
                "no init",
                |s| s.hardening.init = false,
                SandboxRule::NoInitProcess,
            ),
            (
                "daemon logs",
                |s| s.hardening.log_driver_none = false,
                SandboxRule::DaemonKeepsLogs,
            ),
            (
                "git visible",
                |s| s.mounts.workspace.git_masked = false,
                SandboxRule::GitDirectoryNotMasked,
            ),
        ];
        for (name, edit, expected) in cases {
            let mut broken = spec(SandboxProfile::Agent);
            edit(&mut broken);
            assert!(rules_of(&broken).contains(&expected), "{name}");
        }
    }

    /// NT-SBX-01. The refusal of a privileged container has more than one layer: the rules a spec is
    /// held to here, before any container is made; the arguments the supervisor builds; and the
    /// look at the container after it was created. A test that creates a privileged container and
    /// sees it refused cannot tell which layer refused it, so each layer has a test of its own.
    /// This is the first: with no other layer in the way, a privileged spec is refused for that
    /// rule and no other, in every profile, and the same spec unprivileged is not.
    #[test]
    fn negative_nt_sbx_01_a_privileged_spec_is_refused_by_the_port_rules_in_every_profile() {
        for profile in [
            SandboxProfile::FetchDeps,
            SandboxProfile::Agent,
            SandboxProfile::Verify,
        ] {
            let mut broken = spec(profile);
            broken.hardening.privileged = true;
            assert_eq!(
                rules_of(&broken),
                vec![SandboxRule::Privileged],
                "{profile:?}: only the privileged rule, and no other, is broken"
            );
            broken.hardening.privileged = false;
            assert_eq!(broken.validate(&policy()), Ok(()), "{profile:?}");
        }
    }

    #[test]
    fn a_shared_inter_process_namespace_is_refused_but_ipc_none_is_allowed() {
        let mut host = spec(SandboxProfile::Agent);
        host.hardening.ipc = Namespace::Host;
        assert!(rules_of(&host).contains(&SandboxRule::HostNamespace("ipc")));
        let mut none = spec(SandboxProfile::Agent);
        none.hardening.ipc = Namespace::None;
        assert_eq!(none.validate(&policy()), Ok(()));
    }

    #[test]
    fn the_environment_network_and_token_must_fit_the_profile() {
        let mut env = spec(SandboxProfile::Agent);
        env.env = FixedEnv::new(vec![("LD_PRELOAD".to_owned(), "/x".to_owned())]).unwrap();
        assert!(rules_of(&env).contains(&SandboxRule::EnvNameForbidden("LD_PRELOAD".to_owned())));
        let mut unlisted = spec(SandboxProfile::Agent);
        unlisted.env = FixedEnv::new(vec![("SECRET_MODE".to_owned(), "1".to_owned())]).unwrap();
        assert!(
            rules_of(&unlisted).contains(&SandboxRule::EnvNameNotAllowed("SECRET_MODE".to_owned()))
        );

        let mut wrong_network = spec(SandboxProfile::Verify);
        wrong_network.network = NetworkAttachment::JobInternal {
            sidecar: "s".to_owned(),
        };
        assert!(rules_of(&wrong_network).contains(&SandboxRule::NetworkNotAllowedForProfile));

        let mut token_missing = spec(SandboxProfile::Agent);
        token_missing.job_token = None;
        assert!(rules_of(&token_missing).contains(&SandboxRule::JobTokenMisplaced));
        let mut token_extra = spec(SandboxProfile::Verify);
        token_extra.job_token = Some(token_mount());
        assert!(rules_of(&token_extra).contains(&SandboxRule::JobTokenMisplaced));
    }

    /// ADR 0021: only the troubleshooter holds the gateway's run token, it always does, and it
    /// has no repository: an empty read-only workspace with nothing laid over it and no cache.
    #[test]
    fn the_troubleshooter_alone_holds_the_gateway_token_and_mounts_no_repository() {
        let ok = spec(SandboxProfile::Troubleshooter);
        assert_eq!(ok.validate(&policy()), Ok(()));
        let mounts = ok.expected_mounts();
        let token = mounts
            .iter()
            .find(|m| m.target == MCP_TOKEN_TARGET)
            .expect("the gateway token file");
        assert!(token.read_only);
        assert!(mounts.iter().any(|m| m.target == JOB_TOKEN_TARGET));

        let mut missing = spec(SandboxProfile::Troubleshooter);
        missing.mcp_token = None;
        assert!(rules_of(&missing).contains(&SandboxRule::McpTokenMisplaced));
        for profile in [
            SandboxProfile::Agent,
            SandboxProfile::Verify,
            SandboxProfile::FetchDeps,
        ] {
            let mut extra = spec(profile);
            extra.mcp_token = Some(mcp_token_mount());
            assert!(
                rules_of(&extra).contains(&SandboxRule::McpTokenMisplaced),
                "{profile:?}"
            );
            assert!(
                !spec(profile)
                    .expected_mounts()
                    .iter()
                    .any(|m| m.target == MCP_TOKEN_TARGET)
            );
        }
        let mut no_job_token = spec(SandboxProfile::Troubleshooter);
        no_job_token.job_token = None;
        assert!(rules_of(&no_job_token).contains(&SandboxRule::JobTokenMisplaced));
        let mut offline = spec(SandboxProfile::Troubleshooter);
        offline.network = NetworkAttachment::None;
        assert!(rules_of(&offline).contains(&SandboxRule::NetworkNotAllowedForProfile));
        let mut writable = spec(SandboxProfile::Troubleshooter);
        writable.mounts.workspace.workspace_read_only = false;
        assert!(rules_of(&writable).contains(&SandboxRule::WorkspaceAccessMismatch));
        let mut overlaid = spec(SandboxProfile::Troubleshooter);
        overlaid.mounts.workspace.protected_overlays = vec![RepoPath::new(".github").unwrap()];
        assert!(rules_of(&overlaid).contains(&SandboxRule::WorkspaceAccessMismatch));
        let mut cached = spec(SandboxProfile::Troubleshooter);
        cached.mounts.caches = vec![CacheMount {
            name: CacheName(Slug::parse("cargo").unwrap()),
            writable: false,
        }];
        assert!(rules_of(&cached).contains(&SandboxRule::CacheMisuse));
        assert!(!format!("{:?}", ok.mcp_token).contains("gateway-value"));
    }

    #[test]
    fn a_limit_above_the_profile_maximum_is_refused_and_the_maximum_is_allowed() {
        let mut over = spec(SandboxProfile::Agent);
        over.limits.memory_mb = n(2049);
        over.limits.memory_swap_mb = n(2049);
        let rules = rules_of(&over);
        assert!(rules.contains(&SandboxRule::LimitAboveMaximum("memory_mb")));
        let mut at_max = spec(SandboxProfile::Agent);
        at_max.limits = limits(2);
        assert_eq!(at_max.validate(&policy()), Ok(()));
    }

    #[test]
    fn every_broken_rule_is_reported_not_only_the_first() {
        let mut broken = spec(SandboxProfile::Agent);
        broken.hardening.privileged = true;
        broken.hardening.uid = 0;
        broken.hardening.init = false;
        assert!(rules_of(&broken).len() >= 3);
    }

    // ---- validate: the rules of ports-v1.1 -----------------------------------------------------------

    #[test]
    fn a_zero_wall_clock_is_refused() {
        let mut zero = spec(SandboxProfile::Agent);
        zero.limits.wall_clock = Duration::ZERO;
        assert!(rules_of(&zero).contains(&SandboxRule::LimitIsZero("wall_clock")));
    }

    #[test]
    fn swap_below_memory_is_refused() {
        let mut broken = spec(SandboxProfile::Agent);
        broken.limits.memory_mb = n(1024);
        broken.limits.memory_swap_mb = n(512);
        assert!(rules_of(&broken).contains(&SandboxRule::SwapBelowMemory));
        let mut equal = spec(SandboxProfile::Agent);
        equal.limits.memory_swap_mb = equal.limits.memory_mb;
        assert_eq!(equal.validate(&policy()), Ok(()), "equal means no swap");
    }

    #[test]
    fn apparmor_not_available_is_accepted_only_by_policy() {
        let mut unavailable = spec(SandboxProfile::Agent);
        unavailable.hardening.apparmor = Confinement::NotAvailable;
        assert!(rules_of(&unavailable).contains(&SandboxRule::AppArmorUnavailableNotPermitted));
        let mut development = policy();
        development.apparmor_may_be_unavailable = true;
        assert_eq!(unavailable.validate(&development), Ok(()));
    }

    #[test]
    fn seccomp_not_available_is_never_accepted() {
        let mut broken = spec(SandboxProfile::Agent);
        broken.hardening.seccomp = Confinement::NotAvailable;
        let mut development = policy();
        development.apparmor_may_be_unavailable = true;
        assert!(broken.validate(&development).is_err());
        assert!(rules_of(&broken).contains(&SandboxRule::SeccompUnconfined));
    }

    #[test]
    fn a_host_path_must_be_absolute_and_normalized() {
        for bad in [
            "jobs/1/worktree",
            "/jobs/../etc",
            "/jobs/./1",
            "/jobs//1",
            "/jobs/1/",
            "",
        ] {
            let mut broken = spec(SandboxProfile::Agent);
            broken.mounts.workspace.workspace = PathBuf::from(bad);
            assert!(
                rules_of(&broken).contains(&SandboxRule::HostPathNotNormalized("workspace")),
                "{bad:?}"
            );
        }
        let mut out = spec(SandboxProfile::Agent);
        out.mounts.workspace.out = PathBuf::from("out/relative");
        assert!(rules_of(&out).contains(&SandboxRule::HostPathNotNormalized("out")));
    }

    #[test]
    fn the_workspace_may_not_be_a_forbidden_source_or_lie_under_one() {
        for bad in [
            "/var/run/docker.sock",
            "/var",
            "/var/lib/docker",
            "/etc/ssl",
            "/",
        ] {
            let mut broken = spec(SandboxProfile::Agent);
            broken.mounts.workspace.workspace = PathBuf::from(bad);
            assert!(
                rules_of(&broken)
                    .iter()
                    .any(|r| matches!(r, SandboxRule::ForbiddenMountSource(_))),
                "{bad:?}"
            );
        }
        let mut near = spec(SandboxProfile::Agent);
        near.mounts.workspace.workspace = PathBuf::from("/variable/work");
        assert_eq!(
            near.validate(&policy()),
            Ok(()),
            "a name that only starts like a forbidden one"
        );
    }

    #[test]
    fn the_workspace_access_must_fit_the_profile() {
        let mut writable_verify = spec(SandboxProfile::Verify);
        writable_verify.mounts.workspace.workspace_read_only = false;
        assert!(rules_of(&writable_verify).contains(&SandboxRule::WorkspaceAccessMismatch));
        let mut read_only_agent = spec(SandboxProfile::Agent);
        read_only_agent.mounts.workspace.workspace_read_only = true;
        assert!(rules_of(&read_only_agent).contains(&SandboxRule::WorkspaceAccessMismatch));
    }

    #[test]
    fn a_writable_cache_is_refused_outside_fetch_deps() {
        let cache = |writable| CacheMount {
            name: CacheName(Slug::parse("cargo-registry").unwrap()),
            writable,
        };
        let mut agent = spec(SandboxProfile::Agent);
        agent.mounts.caches = vec![cache(true)];
        assert!(rules_of(&agent).contains(&SandboxRule::CacheMisuse));
        let mut read_only = spec(SandboxProfile::Agent);
        read_only.mounts.caches = vec![cache(false)];
        assert_eq!(read_only.validate(&policy()), Ok(()));
        let mut fetch = spec(SandboxProfile::FetchDeps);
        fetch.mounts.caches = vec![cache(true)];
        assert_eq!(fetch.validate(&policy()), Ok(()));
    }

    #[test]
    fn a_cache_named_twice_is_refused() {
        let cache = || CacheMount {
            name: CacheName(Slug::parse("npm").unwrap()),
            writable: false,
        };
        let mut twice = spec(SandboxProfile::FetchDeps);
        twice.mounts.caches = vec![cache(), cache()];
        assert!(rules_of(&twice).contains(&SandboxRule::CacheMisuse));
    }

    #[test]
    fn a_job_token_secret_never_shows_in_debug_output() {
        let spec = spec(SandboxProfile::Agent);
        assert!(!format!("{spec:?}").contains("secret-value"));
    }

    // ---- expected mounts ------------------------------------------------------------------------------

    #[test]
    fn a_build_writes_under_the_output_directory_never_the_workspace_or_the_scratch() {
        assert!(BUILD_TARGET_DIR.starts_with(&format!("{OUT_TARGET}/")));
        assert!(!BUILD_TARGET_DIR.starts_with(WORKSPACE_TARGET));
        assert_eq!(BUILD_TEMP_DIR, OUT_TARGET);
        assert!(!BUILD_TEMP_DIR.starts_with(SCRATCH_TARGET));
    }

    #[test]
    fn the_expected_mounts_are_the_workspace_the_output_the_scratch_the_overlays_and_the_mask() {
        let mounts = spec(SandboxProfile::Agent).expected_mounts();
        let find = |target: &str| mounts.iter().find(|m| m.target == target).cloned();
        let workspace = find(WORKSPACE_TARGET).expect("the workspace");
        assert!(!workspace.read_only);
        assert_eq!(workspace.source.as_deref(), Some("/jobs/1/worktree"));
        let out = find(OUT_TARGET).expect("the output directory");
        assert!(!out.read_only);
        assert_eq!(out.source.as_deref(), Some("/jobs/1/out"));
        assert!(find(SCRATCH_TARGET).is_some());
        let overlay = find("/workspace/.github").expect("the protected overlay");
        assert!(overlay.read_only);
        let mask = find(MASK_TARGET).expect("the git mask");
        assert!(mask.read_only);
        assert_eq!(mask.source.as_deref(), Some(MASK_SOURCE));
        let token = find(JOB_TOKEN_TARGET).expect("the token file");
        assert!(token.read_only);
    }

    #[test]
    fn a_verify_workspace_is_expected_read_only_and_has_no_token() {
        let mounts = spec(SandboxProfile::Verify).expected_mounts();
        let workspace = mounts
            .iter()
            .find(|m| m.target == WORKSPACE_TARGET)
            .unwrap();
        assert!(workspace.read_only);
        assert!(mounts.iter().all(|m| m.target != JOB_TOKEN_TARGET));
    }

    // ---- the posture report ----------------------------------------------------------------------------

    #[test]
    fn a_report_that_matches_the_spec_has_no_differences() {
        for profile in [
            SandboxProfile::FetchDeps,
            SandboxProfile::Agent,
            SandboxProfile::Verify,
        ] {
            let spec = spec(profile);
            let diff = report(&spec).differences(&spec, &policy());
            assert!(diff.is_empty(), "{profile:?}: {diff:?}");
        }
    }

    fn drift(edit: impl FnOnce(&mut PostureReport)) -> Vec<&'static str> {
        let spec = spec(SandboxProfile::Agent);
        let mut observed = report(&spec);
        edit(&mut observed);
        observed.differences(&spec, &policy()).fields
    }

    #[test]
    fn a_drifted_hardening_field_is_named() {
        assert_eq!(drift(|r| r.observed.privileged = true), vec!["privileged"]);
        assert_eq!(drift(|r| r.observed.uid = 0), vec!["uid"]);
        assert_eq!(drift(|r| r.observed.ipc = Namespace::Host), vec!["ipc"]);
    }

    #[test]
    fn a_different_image_is_a_mismatch() {
        let fields = drift(|r| r.image = ImageDigest::parse(OTHER_DIGEST).unwrap());
        assert_eq!(fields, vec!["image"]);
    }

    #[test]
    fn a_drifted_limit_is_a_mismatch() {
        assert_eq!(drift(|r| r.limits.pids = n(100_000)), vec!["limits"]);
        assert_eq!(
            drift(|r| r.limits.wall_clock = Duration::from_secs(1)),
            vec!["limits"]
        );
    }

    #[test]
    fn a_drifted_network_is_a_mismatch() {
        assert_eq!(
            drift(|r| r.network = NetworkAttachment::None),
            vec!["network"]
        );
    }

    #[test]
    fn an_extra_mount_is_a_mismatch() {
        let fields = drift(|r| {
            r.mounts.push(ObservedMount {
                target: "/host".to_owned(),
                read_only: false,
                source: "/".to_owned(),
            });
        });
        assert_eq!(fields, vec!["mounts"]);
    }

    #[test]
    fn a_missing_mount_is_a_mismatch() {
        assert_eq!(drift(|r| drop(r.mounts.pop())), vec!["mounts"]);
    }

    #[test]
    fn a_writable_mount_that_should_be_read_only_is_a_mismatch() {
        let fields = drift(|r| {
            let mask = r
                .mounts
                .iter_mut()
                .find(|m| m.target == MASK_TARGET)
                .unwrap();
            mask.read_only = false;
        });
        assert_eq!(fields, vec!["mounts"]);
    }

    #[test]
    fn a_workspace_mounted_from_another_host_path_is_a_mismatch() {
        let fields = drift(|r| {
            let w = r
                .mounts
                .iter_mut()
                .find(|m| m.target == WORKSPACE_TARGET)
                .unwrap();
            w.source = "/jobs/other/worktree".to_owned();
        });
        assert_eq!(fields, vec!["mounts"]);
    }

    #[test]
    fn a_drifted_environment_is_a_mismatch() {
        // A changed value, a name the spec did not set and a missing pair.
        assert_eq!(
            drift(|r| r.env = vec![("HOME".to_owned(), "/root".to_owned())]),
            vec!["env"]
        );
        assert_eq!(
            drift(|r| r.env.push(("LD_PRELOAD".to_owned(), "/x".to_owned()))),
            vec!["env"]
        );
        assert_eq!(drift(|r| r.env.clear()), vec!["env"]);
    }

    #[test]
    fn a_failed_self_check_is_a_mismatch() {
        assert_eq!(drift(|r| r.self_check_passed = false), vec!["self_check"]);
    }

    #[test]
    fn several_drifts_are_all_named_in_a_fixed_order() {
        let fields = drift(|r| {
            r.self_check_passed = false;
            r.network = NetworkAttachment::None;
            r.observed.privileged = true;
        });
        assert_eq!(fields, vec!["privileged", "network", "self_check"]);
    }

    #[test]
    fn apparmor_not_available_is_excused_only_when_the_policy_allows_it() {
        let spec = spec(SandboxProfile::Agent);
        let mut observed = report(&spec);
        observed.observed.apparmor = Confinement::NotAvailable;
        assert_eq!(
            observed.differences(&spec, &policy()).fields,
            vec!["apparmor"]
        );
        let mut development = policy();
        development.apparmor_may_be_unavailable = true;
        assert!(observed.differences(&spec, &development).is_empty());
        // The excuse covers a requested default profile, not a profile that was switched off.
        observed.observed.apparmor = Confinement::Unconfined;
        assert_eq!(
            observed.differences(&spec, &development).fields,
            vec!["apparmor"]
        );
    }

    #[test]
    fn image_references_must_be_pinned_by_digest() {
        assert!(ImageDigest::parse(DIGEST).is_ok());
        assert!(ImageDigest::parse("registry.local/factory/agent:latest").is_err());
        assert!(ImageDigest::parse("agent@sha256:short").is_err());
    }

    #[test]
    fn the_error_set_names_a_stage_and_carries_no_text() {
        assert_eq!(
            SandboxError::ProvisionFailed(ProvisionStage::Inspect).to_string(),
            "the sandbox could not be provisioned at Inspect"
        );
        assert_eq!(
            SandboxError::PostureMismatch(PostureDiff {
                fields: vec!["limits", "env"]
            })
            .to_string(),
            "the created container differs from the spec in: limits, env"
        );
    }

    #[test]
    fn exec_argv_has_no_shell_string() {
        assert!(ExecArgv::new(vec!["cargo".to_owned(), "test".to_owned()]).is_ok());
        assert!(ExecArgv::new(vec![]).is_err());
        assert!(ExecArgv::new(vec![String::new()]).is_err());
        assert!(ExecArgv::new(vec!["a\0b".to_owned()]).is_err());
    }
}
