//! Shared helpers for the sandbox tests: a production-shaped policy, specs for each profile, host
//! directories for a workspace, and a provider built on a chosen process runner.
//!
//! Compiled into each test target with `mod support;`, so a target uses only part of it.
#![allow(dead_code)]

pub mod docker_lock;
pub mod sim;

use std::fs;
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use factory_domain::ids::{AttemptId, JobId};
use factory_domain::redaction::Redactor;
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::JobTokenSecret;
use factory_ports::clock::{IdGenerator, Uuid};
use factory_ports::paths::RepoPath;
use factory_ports::process::ProcessRunner;
use factory_ports::sandbox::{
    FixedEnv, Hardening, JobTokenMount, McpRunTokenSecret, McpTokenMount, NetworkAttachment,
    SandboxLimits, SandboxMounts, SandboxPolicy, SandboxProfile, SandboxSpec,
};
use factory_ports::workspace::WorkspaceMounts;
use factory_sandbox::container::docker::DockerSettings;
use factory_sandbox::container::images::ImageCatalog;
use factory_sandbox::{DockerSandboxProvider, ProviderConfig, WatchdogSettings};
use factory_testkit::artifact::InMemoryArtifactStore;
use factory_testkit::clock::FakeClock;

/// The image catalog the image build wrote.
pub const IMAGES_JSON: &str = include_str!("../../../../infra/sandbox-images/images.json");

/// The platform of the development machine's daemon.
pub const PLATFORM: &str = "linux/arm64";

/// The name of the sidecar in the specs of the `agent` and `fetch_deps` profiles.
pub const SIDECAR_ALIAS: &str = "egress";

/// A directory under the target directory, removed when dropped. It is under `/Users`, not
/// under `/var`, so the policy's forbidden mount sources do not reject it.
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    pub fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        // A folder the policy lets a sandbox mount on this host (`mountable_scratch`): the build's
        // temporary directory is under /home on most Linux hosts, which the policy forbids.
        let path = factory_testkit::fx::scratch::mountable_scratch("sandbox-tests").join(format!(
            "{label}-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&path).expect("a scratch directory");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// `images.json` with the egress sidecar entry turned into a stand-in that may run: the verify
/// image, which has `sleep`, in place of the sidecar program that does not exist yet. Only tests
/// that need a sidecar to start use this; the unmodified file is what proves the skeleton is
/// refused.
pub fn images_json_with_stand_in_sidecar() -> String {
    let mut root: serde_json::Value = serde_json::from_str(IMAGES_JSON).expect("images.json");
    let block = &mut root["platforms"][PLATFORM]["images"];
    let mut stand_in = block["verify"].clone();
    stand_in["status"] = "ready".into();
    block["egress-sidecar"] = stand_in;
    root.to_string()
}

/// `images.json` with the egress sidecar entry put back into the state it had before its program
/// existed: a skeleton that has no binary. The real file now lists a ready sidecar, so the tests
/// that prove a skeleton is REFUSED build their catalog from it with this function and no longer
/// depend on the state of the real file.
pub fn images_json_with_skeleton_sidecar() -> String {
    let mut root: serde_json::Value = serde_json::from_str(IMAGES_JSON).expect("images.json");
    let sidecar = &mut root["platforms"][PLATFORM]["images"]["egress-sidecar"];
    sidecar["status"] = "awaiting-binary".into();
    sidecar["binary_sha256"] = "".into();
    sidecar["tag"] = "skeleton".into();
    root.to_string()
}

pub fn catalog(json: &str) -> ImageCatalog {
    ImageCatalog::from_json(json, PLATFORM).expect("a catalog")
}

pub fn n(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("a non-zero test value")
}

/// Limits small enough for a laptop and large enough for the toolchain images.
pub fn limits(wall_clock: Duration) -> SandboxLimits {
    SandboxLimits {
        cpu_millis: n(1000),
        memory_mb: n(256),
        memory_swap_mb: n(256),
        pids: n(128),
        nofile: n(1024),
        max_file_mb: n(64),
        tmpfs_mb: n(64),
        workspace_disk_mb: n(512),
        wall_clock,
    }
}

fn scaled(base: &SandboxLimits, factor: u32) -> SandboxLimits {
    SandboxLimits {
        cpu_millis: n(base.cpu_millis.get() * factor),
        memory_mb: n(base.memory_mb.get() * factor),
        memory_swap_mb: n(base.memory_swap_mb.get() * factor),
        pids: n(base.pids.get() * factor),
        nofile: n(base.nofile.get() * factor),
        max_file_mb: n(base.max_file_mb.get() * factor),
        tmpfs_mb: n(base.tmpfs_mb.get() * factor),
        workspace_disk_mb: n(base.workspace_disk_mb.get() * factor),
        wall_clock: base.wall_clock * factor,
    }
}

/// A policy with the shape of `policies/security.yaml`: the forbidden mount sources and
/// environment names, the supervisor's fixed environment names, and per-profile maxima.
pub fn policy(apparmor_may_be_unavailable: bool) -> SandboxPolicy {
    let base = limits(Duration::from_secs(600));
    SandboxPolicy {
        min_uid: 10_000,
        forbidden_mount_sources: [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/",
            "/etc",
            "/root",
            "/home",
            "/var",
            "/usr",
            "/proc",
            "/sys",
            "/dev",
        ]
        .map(String::from)
        .to_vec(),
        forbidden_env_names: [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "RUSTFLAGS",
            "RUSTC_WRAPPER",
            "NODE_OPTIONS",
            "PYTHONPATH",
            "BASH_ENV",
            "GIT_SSH_COMMAND",
        ]
        .map(String::from)
        .to_vec(),
        allowed_env_names: ["HOME", "PATH"].map(String::from).to_vec(),
        apparmor_may_be_unavailable,
        fetch_deps_max: scaled(&base, 1),
        agent_max: scaled(&base, 2),
        verify_max: scaled(&base, 4),
        troubleshooter_max: scaled(&base, 1),
    }
}

pub fn attempt(n: u128) -> AttemptId {
    AttemptId::from_uuid(Uuid::from_u128(
        (n << 80) | (0x7_u128 << 76) | (0b10_u128 << 62),
    ))
}

pub fn job(n: u128) -> JobId {
    JobId::from_uuid(Uuid::from_u128(
        (n << 80) | (0x7_u128 << 76) | (0b10_u128 << 62) | 1,
    ))
}

/// The host side of one workspace: a checkout with the pointer file the `.git` mask needs, the
/// protected overlay targets, and an output directory.
pub struct HostWorkspace {
    pub mounts: WorkspaceMounts,
    _scratch: Scratch,
}

pub fn host_workspace(read_only: bool, overlays: &[&str]) -> HostWorkspace {
    let scratch = Scratch::new("ws");
    let worktree = scratch.path().join("worktree");
    let out = scratch.path().join("out");
    fs::create_dir_all(&worktree).expect("worktree");
    fs::create_dir_all(&out).expect("out");
    // A linked checkout always has this pointer file, and the runtime needs the mount point.
    fs::write(worktree.join(".git"), b"gitdir: /nonexistent\n").expect("pointer file");
    fs::write(worktree.join("README.txt"), b"fixture\n").expect("a file");
    for overlay in overlays {
        let dir = worktree.join(overlay);
        fs::create_dir_all(&dir).expect("overlay target");
        fs::write(dir.join("protected.txt"), b"protected\n").expect("a protected file");
    }
    for dir in [&worktree, &out] {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o777)).expect("open the directory");
    }
    HostWorkspace {
        mounts: WorkspaceMounts {
            workspace: worktree,
            workspace_read_only: read_only,
            out,
            protected_overlays: overlays
                .iter()
                .map(|o| RepoPath::new(o).expect("a repository path"))
                .collect(),
            git_masked: true,
        },
        _scratch: scratch,
    }
}

/// A job token secret made at run time, so that no secret-shaped literal sits in the source.
pub fn token_secret(tag: &str) -> JobTokenSecret {
    JobTokenSecret::new(format!("{}-{tag}-{}", "sfjt", "TESTTOKEN0123456789"))
}

/// A spec for `profile`. `image_json` decides which image digest the spec names.
pub fn spec(
    profile: SandboxProfile,
    catalog: &ImageCatalog,
    workspace: &WorkspaceMounts,
    attempt: AttemptId,
    wall_clock: Duration,
) -> SandboxSpec {
    let (network, job_token) = match profile {
        SandboxProfile::Verify => (NetworkAttachment::None, None),
        SandboxProfile::FetchDeps => (
            NetworkAttachment::JobInternal {
                sidecar: SIDECAR_ALIAS.to_owned(),
            },
            None,
        ),
        SandboxProfile::Agent | SandboxProfile::Troubleshooter => (
            NetworkAttachment::JobInternal {
                sidecar: SIDECAR_ALIAS.to_owned(),
            },
            Some(JobTokenMount {
                secret: token_secret("spec"),
            }),
        ),
    };
    let troubleshooter = profile == SandboxProfile::Troubleshooter;
    let mut mounts = workspace.clone();
    mounts.workspace_read_only = profile == SandboxProfile::Verify || troubleshooter;
    if troubleshooter {
        mounts.protected_overlays.clear();
    }
    SandboxSpec {
        job: job(1),
        attempt,
        profile,
        image: catalog
            .reference_for(profile)
            .expect("the catalog has this profile")
            .clone(),
        limits: limits(wall_clock),
        network,
        mounts: SandboxMounts {
            workspace: mounts,
            caches: Vec::new(),
        },
        job_token,
        mcp_token: troubleshooter.then(|| McpTokenMount {
            secret: McpRunTokenSecret::new(format!("{}-{}", "mcpt", "TESTTOKEN0123456789")),
        }),
        env: FixedEnv::new(vec![("HOME".to_owned(), "/tmp".to_owned())]).expect("an environment"),
        hardening: Hardening::strict(10_001, 10_001),
    }
}

/// Identifiers that are unique across processes and across calls.
///
/// The last eight hex digits of an identifier are the random part of a sandbox's name, so they
/// must differ for every sandbox of every lab, not only within one generator. The counter is
/// therefore shared by all generators of the process, and the process id keeps two processes
/// apart.
pub struct UniqueIds;

/// Counts the identifiers made by every generator of this process.
static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

impl UniqueIds {
    pub fn new() -> Self {
        Self
    }
}

impl IdGenerator for UniqueIds {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn new_uuid(&self) -> Uuid {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let counter = u128::from(ID_COUNTER.fetch_add(1, Ordering::SeqCst));
        Uuid::from_u128((nanos << 32) ^ (u128::from(std::process::id()) << 8) ^ counter)
    }
}

/// The provider configuration the tests share. `owner` labels every object so that the janitor
/// and the test harness can find them.
pub fn config(
    images_json: &str,
    token_root: PathBuf,
    owner: Vec<(String, String)>,
    apparmor_may_be_unavailable: bool,
) -> ProviderConfig {
    ProviderConfig {
        policy: policy(apparmor_may_be_unavailable),
        images_json: images_json.to_owned(),
        platform: Some(PLATFORM.to_owned()),
        token_root,
        caches: Vec::new(),
        owner_labels: owner,
        sidecar_command: vec!["sleep".to_owned(), "3600".to_owned()],
        gateway_relay: None,
        docker: DockerSettings::default(),
        watchdog: WatchdogSettings {
            disk_poll_interval: Duration::from_millis(500),
        },
    }
}

pub struct World {
    pub provider: DockerSandboxProvider,
    pub artifacts: Arc<InMemoryArtifactStore>,
    pub redactor: Arc<Redactor>,
}

/// A provider over `runner`.
pub fn provider(config: ProviderConfig, runner: Arc<dyn ProcessRunner>) -> World {
    provider_with(config, runner, Arc::new(InMemoryArtifactStore::new()))
}

/// A provider over `runner` that stores output in `artifacts`.
pub fn provider_with(
    config: ProviderConfig,
    runner: Arc<dyn ProcessRunner>,
    artifacts: Arc<InMemoryArtifactStore>,
) -> World {
    let redactor = Arc::new(Redactor::builder().build().expect("a redactor"));
    let provider = DockerSandboxProvider::new(
        config,
        runner,
        artifacts.clone(),
        Arc::clone(&redactor),
        Arc::new(FakeClock::new()),
        Arc::new(UniqueIds::new()),
    );
    World {
        provider,
        artifacts,
        redactor,
    }
}
