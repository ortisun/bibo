//! The host-side workspace: the job's trusted object store, the attempt's checkout over it, and
//! the ingestion of what the sandbox wrote (ports-v1.1, ADR 0003, ADR 0014 decision 4,
//! `docs/security/sandbox-policy.md` section 6).
//!
//! This is the boundary where files written inside the sandbox come back to the host, so it is
//! built around one rule: **git never touches a tree the sandbox can write.**
//!
//! # Layout on the host
//!
//! ```text
//! <root>/jobs/<job id>/
//!     store.git/                    the job's bare object store. Never mounted. Only host git
//!                                   reads or writes it, with a fixed environment.
//!     attempts/<attempt id>/
//!         checkout/                 mounted read-write (or read-only) at /workspace
//!         out/                      mounted read-write at /out
//!         meta/                     private to the host: temporary indexes. Never mounted.
//! ```
//!
//! # What each part does
//!
//! * `git`: the one wrapper that builds a `git` invocation. Arguments are separate strings, the
//!   configuration is hardened with `-c` overrides, the environment is the fixed one, and the
//!   credential travels in the environment of the child only.
//! * `repo`: [`JobRepo`](factory_ports::workspace::JobRepo) over the store: reads, patches and
//!   pushes.
//! * `checkout`: makes the attempt's directories. The files are written by this module from the
//!   blobs `git cat-file --batch` prints, each with `create_new`, so git is never given the
//!   checkout. The mount points for the `.git` mask and the protected overlays exist before the
//!   sandbox is built.
//! * `audit`: the no-follow walk of the writable tree. It uses `lstat` and never opens a link, a
//!   FIFO, a socket or a device.
//! * `ingest`: audit, then hashing the audited bytes **through git's standard input** (the
//!   writable tree is never a git argument), then the tree and the difference from the base
//!   commit, then the path rules, then the secret scan of the exact bytes that will be committed.
//! * `rules`: evaluates a change set against the path rules.
//! * `attempt`: [`Workspace`](factory_ports::workspace::Workspace) over all of the above.
//!
//! Every read of a path the sandbox controls lives under this directory (check ST-09). The only
//! other code in the crate that starts a process is `process.rs`; this directory starts `git`
//! through the [`ProcessRunner`](factory_ports::process::ProcessRunner) port and never through a
//! shell (rules DEP-10 and ST-03).

mod attempt;
mod audit;
mod basetree;
mod checkout;
mod git;
mod ingest;
mod layout;
mod provider;
mod repo;
mod rules;
mod secrets;

use std::path::PathBuf;
use std::time::Duration;

use factory_ports::paths::RepoRef;

pub use attempt::GitWorkspace;
pub use audit::{
    AuditKind, AuditReason, AuditReport, MAX_REASONS, OutputFile, audit_output, read_output_file,
};
pub use provider::{GitWorkspaceProvider, PathPolicyLayer};
pub use repo::GitJobRepo;

/// Where the repositories live, and with that, which transport git may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteLocation {
    /// `https://<host>/<owner>/<name>.git`. The only transport a production host allows.
    Https {
        /// The host name, for example `github.com`.
        host: String,
    },
    /// `file://<base>/<owner>/<name>.git`: bare repositories in a local directory. For tests and
    /// for a local mirror; the `file` transport is the only one git is allowed then.
    Directory {
        /// The directory that holds `<owner>/<name>.git`.
        base: PathBuf,
    },
}

impl RemoteLocation {
    /// The URL of a repository.
    #[must_use]
    pub fn url(&self, repo: &RepoRef) -> String {
        match self {
            Self::Https { host } => format!("https://{host}/{}/{}.git", repo.owner(), repo.name()),
            Self::Directory { base } => format!(
                "file://{}/{}/{}.git",
                base.display(),
                repo.owner(),
                repo.name()
            ),
        }
    }

    /// The one transport git may use for this location.
    #[must_use]
    pub(crate) fn protocol(&self) -> &'static str {
        match self {
            Self::Https { .. } => "https",
            Self::Directory { .. } => "file",
        }
    }
}

/// The limits of the audit walk (`path_access.workspace_audit` of `policies/security.yaml`) and
/// of one change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLimits {
    /// The largest single file (`max_file_bytes`).
    pub max_file_bytes: u64,
    /// The most bytes of all files together. A tree over it is refused before it is read.
    pub max_total_bytes: u64,
    /// The most entries (files, links and directories) the walk visits.
    pub max_entries: usize,
    /// The deepest path, in components.
    pub max_depth: usize,
    /// The longest path, in bytes.
    pub max_path_bytes: usize,
    /// The longest name, in bytes.
    pub max_name_bytes: usize,
    /// The most changed paths in one ingestion (`max_files_changed_per_task`).
    pub max_changed_files: usize,
}

impl Default for AuditLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 5 * 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_entries: 200_000,
            max_depth: 256,
            max_path_bytes: 4096,
            max_name_bytes: 255,
            max_changed_files: 200,
        }
    }
}

/// How long each kind of call may take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timeouts {
    /// A git call on the local store.
    pub local: Duration,
    /// A git call that talks to the remote (`fetch`, `ls-remote`, `push`).
    pub network: Duration,
    /// The whole of one ingestion.
    pub ingest: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            local: Duration::from_secs(120),
            network: Duration::from_secs(600),
            ingest: Duration::from_secs(300),
        }
    }
}

/// Everything the workspace provider is configured with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSettings {
    /// The host directory that holds every job's store and workspaces. It must not be inside a
    /// directory the sandbox mounts.
    pub root: PathBuf,
    /// Where repositories are fetched from and pushed to.
    pub remote: RemoteLocation,
    /// The audit limits.
    pub limits: AuditLimits,
    /// The timeouts.
    pub timeouts: Timeouts,
    /// The most bytes `list_at` reads from git.
    pub max_listing_bytes: u64,
    /// Opens the checkout and the output directory to the sandbox user (mode 0777 directories,
    /// 0666 or 0777 files). The job directory above them stays private to the host user. Turn it
    /// off when the sandbox user owns the directories by other means.
    pub open_to_sandbox_user: bool,
}

impl WorkspaceSettings {
    /// Settings with the policy's defaults for a root and a remote.
    #[must_use]
    pub fn new(root: PathBuf, remote: RemoteLocation) -> Self {
        Self {
            root,
            remote,
            limits: AuditLimits::default(),
            timeouts: Timeouts::default(),
            max_listing_bytes: 32 * 1024 * 1024,
            open_to_sandbox_user: true,
        }
    }
}
