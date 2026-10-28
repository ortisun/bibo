//! The mapping from a [`SandboxSpec`] to the arguments of `docker create`, as an allow list.
//!
//! The function [`create_args`] reads the fields a spec can express and writes the flag for each,
//! and nothing else. There is no passthrough: the spec has no free-form mount, no free-form flag
//! and no field for a privilege, so a flag the list below does not write cannot reach Docker. A
//! field that asks for something weaker than the strict posture (a writable root, an added
//! capability, a host namespace) is not translated into the weaker flag; it is refused with
//! [`ArgsError::WeakerThanAllowed`], whatever the policy check upstream decided. The result goes
//! through the deny list in the posture module once more before it is run.
//!
//! The vector is an array of strings and is never joined into a line or handed to a shell. Host
//! paths and names go into `--mount` and `--label` values, which Docker reads as comma separated
//! fields, so a path or value with a comma, a quote or a line break is refused rather than
//! escaped: it could add a mount option of its own.
//!
//! What every container gets, in the order written:
//!
//! ```text
//! create --pull=never --name N --label ...
//!   --user UID:GID --read-only --cap-drop ALL --security-opt no-new-privileges --init
//!   --ipc private|none --pids-limit P --memory Mm --memory-swap Sm --cpus C
//!   --ulimit nofile=N:N --ulimit core=0 --ulimit fsize=B
//!   --network none|NET --log-driver none --stop-timeout 10 --restart no --workdir /workspace
//!   --env NAME=value ...
//!   --tmpfs /tmp:rw,noexec,nosuid,nodev,size=Tm,mode=1777
//!   --mount type=bind,src=...,dst=...[,readonly] ...
//!   IMAGE sleep SECONDS
//! ```
//!
//! The container's first process is `sleep`: the supervisor starts every command with
//! `docker exec`, so the container idles until it is told to work, and ends on its own a little
//! after its wall clock if the supervisor dies.

use std::path::Path;

use factory_ports::sandbox::{
    CACHE_ROOT, Confinement, JOB_TOKEN_TARGET, MASK_SOURCE, MASK_TARGET, Namespace,
    NetworkAttachment, OUT_TARGET, SCRATCH_TARGET, SandboxSpec, WORKSPACE_TARGET,
};

use super::posture::denied_flag_in;

/// The program the container runs as its first process.
pub const IDLE_PROGRAM: &str = "sleep";

/// Seconds the idle process lives past the wall clock, so it never ends before the supervisor's
/// own deadline does.
pub const IDLE_MARGIN_SECS: u64 = 30;

/// Why an argument vector could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArgsError {
    /// The spec asks for something weaker than the strict posture.
    #[error("the spec asks for a setting weaker than the allowed posture: {0}")]
    WeakerThanAllowed(&'static str),
    /// A host path or label cannot be written safely into a comma separated value.
    #[error("a host path or label cannot be written safely: {0}")]
    UnsafeValue(&'static str),
    /// The spec names a cache the adapter has no directory for.
    #[error("the spec names a cache this host does not provide")]
    UnknownCache,
    /// The spec's network does not match what the caller prepared.
    #[error("the network does not match the plan")]
    NetworkMismatch,
    /// The finished vector holds a flag on the deny list. A defect in this module.
    #[error("the builder produced a denied argument: {0}")]
    DeniedArgument(String),
}

/// What the builder needs besides the spec.
#[derive(Debug, Clone)]
pub struct CreatePlan<'a> {
    /// The container name.
    pub container: &'a str,
    /// The image, as `name@sha256:digest`.
    pub image: &'a str,
    /// The per-job network name, for a `JobInternal` spec.
    pub network: Option<&'a str>,
    /// The labels, as written by [`super::names::labels`].
    pub labels: &'a [(String, String)],
    /// The host path of the job token file, for an `agent` spec.
    pub token_file: Option<&'a Path>,
    /// For each cache the spec names, the host directory, in the spec's order.
    pub cache_dirs: &'a [(String, &'a Path)],
}

fn safe(text: &str, what: &'static str) -> Result<String, ArgsError> {
    if text.is_empty()
        || text
            .chars()
            .any(|c| matches!(c, ',' | '"' | '\'' | '\n' | '\r' | '\0'))
    {
        return Err(ArgsError::UnsafeValue(what));
    }
    Ok(text.to_owned())
}

fn host_path(path: &Path, what: &'static str) -> Result<String, ArgsError> {
    safe(path.to_str().ok_or(ArgsError::UnsafeValue(what))?, what)
}

fn bind(source: &str, target: &str, read_only: bool) -> Vec<String> {
    let mut value = format!("type=bind,src={source},dst={target}");
    if read_only {
        value.push_str(",readonly");
    }
    vec!["--mount".to_owned(), value]
}

/// The seconds the idle process sleeps.
#[must_use]
pub fn idle_seconds(wall_clock: std::time::Duration) -> u64 {
    wall_clock.as_secs().saturating_add(IDLE_MARGIN_SECS)
}

fn strict_posture(spec: &SandboxSpec) -> Result<(), ArgsError> {
    let h = &spec.hardening;
    let weaker = |reason| Err(ArgsError::WeakerThanAllowed(reason));
    if h.privileged {
        return weaker("privileged");
    }
    if !h.cap_add.is_empty() || !h.cap_drop_all {
        return weaker("capabilities");
    }
    if !h.read_only_rootfs {
        return weaker("writable root file system");
    }
    if !h.no_new_privileges {
        return weaker("privilege escalation");
    }
    if !h.init || !h.log_driver_none {
        return weaker("init or log driver");
    }
    if h.seccomp != Confinement::RuntimeDefault || h.apparmor == Confinement::Unconfined {
        return weaker("confinement");
    }
    if h.pid != Namespace::Private || h.uts != Namespace::Private || h.userns != Namespace::Private
    {
        return weaker("namespace");
    }
    if h.ipc == Namespace::Host {
        return weaker("ipc namespace");
    }
    if !h.devices.is_empty() || !h.sysctls.is_empty() {
        return weaker("devices or sysctls");
    }
    if h.uid == 0 || h.gid == 0 {
        return weaker("root user");
    }
    Ok(())
}

/// Builds the arguments of `docker create` for `spec`.
///
/// # Errors
/// [`ArgsError`] when the spec asks for more than the strict posture, a value cannot be written
/// safely, the plan does not fit the spec, or the result breaks the deny list.
pub fn create_args(spec: &SandboxSpec, plan: &CreatePlan<'_>) -> Result<Vec<String>, ArgsError> {
    strict_posture(spec)?;
    let h = &spec.hardening;
    let limits = &spec.limits;
    let mut out: Vec<String> = vec![
        "create".to_owned(),
        "--pull=never".to_owned(),
        "--name".to_owned(),
        safe(plan.container, "container name")?,
    ];
    for (key, value) in plan.labels {
        out.push("--label".to_owned());
        out.push(format!(
            "{}={}",
            safe(key, "label key")?,
            safe(value, "label value")?
        ));
    }
    out.extend([
        "--user".to_owned(),
        format!("{}:{}", h.uid, h.gid),
        "--read-only".to_owned(),
        "--cap-drop".to_owned(),
        "ALL".to_owned(),
        "--security-opt".to_owned(),
        "no-new-privileges".to_owned(),
        "--init".to_owned(),
        "--ipc".to_owned(),
        if h.ipc == Namespace::None {
            "none"
        } else {
            "private"
        }
        .to_owned(),
        "--pids-limit".to_owned(),
        limits.pids.get().to_string(),
        "--memory".to_owned(),
        format!("{}m", limits.memory_mb),
        "--memory-swap".to_owned(),
        format!("{}m", limits.memory_swap_mb),
        "--cpus".to_owned(),
        format!(
            "{}.{:03}",
            limits.cpu_millis.get() / 1000,
            limits.cpu_millis.get() % 1000
        ),
        "--ulimit".to_owned(),
        format!("nofile={0}:{0}", limits.nofile),
        "--ulimit".to_owned(),
        "core=0".to_owned(),
        "--ulimit".to_owned(),
        {
            let bytes = u64::from(limits.max_file_mb.get()) * 1024 * 1024;
            format!("fsize={bytes}:{bytes}")
        },
    ]);
    match (&spec.network, plan.network) {
        (NetworkAttachment::None, None) => {
            out.extend(["--network".to_owned(), "none".to_owned()]);
        }
        (NetworkAttachment::JobInternal { .. }, Some(network)) => {
            out.extend(["--network".to_owned(), safe(network, "network name")?]);
        }
        _ => return Err(ArgsError::NetworkMismatch),
    }
    out.extend([
        "--log-driver".to_owned(),
        "none".to_owned(),
        "--stop-timeout".to_owned(),
        "10".to_owned(),
        "--restart".to_owned(),
        "no".to_owned(),
        "--workdir".to_owned(),
        WORKSPACE_TARGET.to_owned(),
    ]);
    for (name, value) in spec.env.pairs() {
        out.push("--env".to_owned());
        out.push(format!("{name}={}", safe(value, "environment value")?));
    }
    out.extend([
        "--tmpfs".to_owned(),
        format!(
            "{SCRATCH_TARGET}:rw,noexec,nosuid,nodev,size={}m,mode=1777",
            limits.tmpfs_mb
        ),
    ]);

    let workspace = &spec.mounts.workspace;
    let workspace_dir = host_path(&workspace.workspace, "workspace path")?;
    out.extend(bind(
        &workspace_dir,
        WORKSPACE_TARGET,
        workspace.workspace_read_only,
    ));
    for overlay in &workspace.protected_overlays {
        let source = format!(
            "{workspace_dir}/{}",
            safe(overlay.as_str(), "overlay path")?
        );
        let target = format!("{WORKSPACE_TARGET}/{}", overlay.as_str());
        out.extend(bind(&source, &target, true));
    }
    if workspace.git_masked {
        out.extend(bind(MASK_SOURCE, MASK_TARGET, true));
    }
    out.extend(bind(
        &host_path(&workspace.out, "output path")?,
        OUT_TARGET,
        false,
    ));
    for cache in &spec.mounts.caches {
        let (_, directory) = plan
            .cache_dirs
            .iter()
            .find(|(name, _)| name == cache.name.0.as_str())
            .ok_or(ArgsError::UnknownCache)?;
        out.extend(bind(
            &host_path(directory, "cache path")?,
            &format!("{CACHE_ROOT}/{}", cache.name.0.as_str()),
            !cache.writable,
        ));
    }
    match (&spec.job_token, plan.token_file) {
        (Some(_), Some(file)) => {
            out.extend(bind(
                &host_path(file, "token path")?,
                JOB_TOKEN_TARGET,
                true,
            ));
        }
        (None, None) => {}
        _ => {
            return Err(ArgsError::WeakerThanAllowed(
                "token mount does not fit the spec",
            ));
        }
    }

    out.push(safe(plan.image, "image")?);
    out.push(IDLE_PROGRAM.to_owned());
    out.push(idle_seconds(limits.wall_clock).to_string());

    match denied_flag_in(&out) {
        Some(reason) => Err(ArgsError::DeniedArgument(reason)),
        None => Ok(out),
    }
}

/// What the sidecar's `docker create` needs.
#[derive(Debug, Clone)]
pub struct SidecarPlan<'a> {
    /// The container name.
    pub container: &'a str,
    /// The image, as `name@sha256:digest`.
    pub image: &'a str,
    /// The job's internal network.
    pub network: &'a str,
    /// The name the sandbox reaches the sidecar by.
    pub alias: &'a str,
    /// The numeric user and group of the sidecar image.
    pub ids: (u32, u32),
    /// The labels.
    pub labels: &'a [(String, String)],
    /// Words after the image: the arguments of the sidecar's program.
    pub command: &'a [String],
}

/// The arguments of `docker create` for the egress sidecar of a job: the strict posture, the
/// job's internal network, no mounts, a scratch tmpfs and the image's own entrypoint with
/// `plan.command` after it.
///
/// # Errors
/// [`ArgsError`] as for [`create_args`].
pub fn sidecar_args(plan: &SidecarPlan<'_>) -> Result<Vec<String>, ArgsError> {
    let mut out: Vec<String> = vec![
        "create".to_owned(),
        "--pull=never".to_owned(),
        "--name".to_owned(),
        safe(plan.container, "container name")?,
    ];
    for (key, value) in plan.labels {
        out.push("--label".to_owned());
        out.push(format!(
            "{}={}",
            safe(key, "label key")?,
            safe(value, "label value")?
        ));
    }
    out.extend([
        "--user".to_owned(),
        format!("{}:{}", plan.ids.0, plan.ids.1),
        "--read-only".to_owned(),
        "--cap-drop".to_owned(),
        "ALL".to_owned(),
        "--security-opt".to_owned(),
        "no-new-privileges".to_owned(),
        "--init".to_owned(),
        "--ipc".to_owned(),
        "private".to_owned(),
        "--pids-limit".to_owned(),
        "256".to_owned(),
        "--memory".to_owned(),
        "256m".to_owned(),
        "--memory-swap".to_owned(),
        "256m".to_owned(),
        "--cpus".to_owned(),
        "1.000".to_owned(),
        "--ulimit".to_owned(),
        "core=0".to_owned(),
        "--network".to_owned(),
        safe(plan.network, "network name")?,
        "--network-alias".to_owned(),
        safe(plan.alias, "sidecar alias")?,
        "--log-driver".to_owned(),
        "none".to_owned(),
        "--stop-timeout".to_owned(),
        "10".to_owned(),
        "--restart".to_owned(),
        "no".to_owned(),
        "--tmpfs".to_owned(),
        format!("{SCRATCH_TARGET}:rw,noexec,nosuid,nodev,size=64m,mode=1777"),
        safe(plan.image, "image")?,
    ]);
    if let Some(reason) = denied_flag_in(&out) {
        return Err(ArgsError::DeniedArgument(reason));
    }
    out.extend(plan.command.iter().cloned());
    Ok(out)
}
