//! The sandbox a tool may run in, checked before any bypass flag is written.
//!
//! The permission flags of both tools are a filter, not a boundary (spike section 4.8). Claude Code
//! with `--dangerously-skip-permissions` and Codex with
//! `--dangerously-bypass-approvals-and-sandbox` run every command the model asks for. That is
//! acceptable only because the container is the boundary: a non-root user, no capabilities, a
//! read-only root, seccomp, `no-new-privileges`, and a network that reaches only the broker. A
//! [`VerifiedTarget`] is the proof that the posture the sandbox adapter read back from the created
//! container has all of that. The argument builders take one, so a bypass flag cannot be written
//! for a container that was not checked (ADR 0005, "Argument safety").

use factory_ports::sandbox::{Confinement, Namespace, NetworkAttachment, PostureReport};

/// The smallest user id a tool may run as. It is the `min_uid` of the sandbox policy.
pub const MIN_AGENT_UID: u32 = 10_000;

/// Environment names that change how a program loads code or what it builds. A container created
/// with one of them is not a target (negative test NT-TOOL-06; the list is `forbidden_env_names`
/// of the sandbox policy).
pub const FORBIDDEN_ENV_NAMES: [&str; 9] = [
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "RUSTFLAGS",
    "RUSTC_WRAPPER",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "BASH_ENV",
    "GIT_SSH_COMMAND",
];

/// Why a sandbox cannot host a tool that runs with the bypass flags.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetRefusal {
    /// A security setting is weaker than the policy requires. The names are the settings.
    #[error("the sandbox is not hardened: {}", .0.join(", "))]
    NotHardened(Vec<&'static str>),
    /// The runtime self-check of the container did not pass.
    #[error("the runtime self-check of the sandbox did not pass")]
    SelfCheckFailed,
    /// The container is not attached to a job network with a sidecar, so it cannot reach the broker.
    #[error("the sandbox has no job network to reach the broker")]
    NoBrokerNetwork,
}

/// A sandbox whose posture check passed. It can only be made by [`VerifiedTarget::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTarget {
    uid: u32,
}

impl VerifiedTarget {
    /// Checks the posture the sandbox adapter read back from the created container.
    ///
    /// # Errors
    /// [`TargetRefusal`] naming what is weak.
    pub fn check(posture: &PostureReport) -> Result<Self, TargetRefusal> {
        let h = &posture.observed;
        let mut weak: Vec<&'static str> = Vec::new();
        let mut require = |ok: bool, name: &'static str| {
            if !ok {
                weak.push(name);
            }
        };
        require(!h.privileged, "privileged");
        require(h.uid >= MIN_AGENT_UID, "uid");
        require(h.gid != 0, "gid");
        require(h.read_only_rootfs, "read_only_rootfs");
        require(h.cap_drop_all, "cap_drop_all");
        require(h.cap_add.is_empty(), "cap_add");
        require(h.no_new_privileges, "no_new_privileges");
        require(h.seccomp == Confinement::RuntimeDefault, "seccomp");
        require(
            matches!(
                h.apparmor,
                Confinement::RuntimeDefault | Confinement::NotAvailable
            ),
            "apparmor",
        );
        require(h.pid != Namespace::Host, "pid");
        require(h.ipc != Namespace::Host, "ipc");
        require(h.uts != Namespace::Host, "uts");
        require(h.userns != Namespace::Host, "userns");
        require(h.devices.is_empty(), "devices");
        require(h.sysctls.is_empty(), "sysctls");
        require(h.init, "init");
        require(
            !posture
                .env
                .iter()
                .any(|(name, _)| FORBIDDEN_ENV_NAMES.contains(&name.as_str())),
            "env",
        );
        if !weak.is_empty() {
            return Err(TargetRefusal::NotHardened(weak));
        }
        if !posture.self_check_passed {
            return Err(TargetRefusal::SelfCheckFailed);
        }
        if !matches!(posture.network, NetworkAttachment::JobInternal { .. }) {
            return Err(TargetRefusal::NoBrokerNetwork);
        }
        Ok(Self { uid: h.uid })
    }

    /// The user id the tool runs as.
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }
}
