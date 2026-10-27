//! The workspace ports: the host-side checkout of the repository, git hardening and the
//! ingestion of what the sandbox wrote (ADR 0003).
//!
//! The sandbox never sees the trusted git directory. All git runs on the host, with a fixed
//! environment, against a directory the sandbox cannot write. Everything the sandbox wrote is
//! hostile until [`Workspace::ingest`] has checked it.

use std::path::PathBuf;

use async_trait::async_trait;
use factory_domain::ids::JobId;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::Fidelity;

use crate::paths::{BranchName, CommitSha, Finding, RepoGlob, RepoPath, RepoRef};

/// What to check out and what to keep out of the sandbox's sight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRequest {
    /// The job the workspace belongs to.
    pub job: JobId,
    /// The repository.
    pub repo: RepoRef,
    /// The commit to check out. The checkout is detached: it is not on any branch.
    pub base: CommitSha,
    /// Paths that never exist in the checkout (held-out tests, files that hold secrets). The
    /// sandbox has nothing to mount or read.
    pub hidden: Vec<RepoGlob>,
    /// Paths the sandbox may read but must not change. A change to one is refused at ingestion.
    pub protected: Vec<RepoGlob>,
}

/// The host directories and masks the sandbox is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceMounts {
    /// The checkout, mounted read-write at `/workspace`.
    pub workspace: PathBuf,
    /// The output directory, mounted read-write at `/out`.
    pub out: PathBuf,
    /// Protected paths that are re-mounted read-only over the checkout.
    pub protected_overlays: Vec<RepoPath>,
    /// True when `/dev/null` is bound over `/workspace/.git`, so the sandbox sees no git data.
    pub git_masked: bool,
}

/// How a path differs from the base commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ChangeKind {
    /// The path did not exist at the base commit.
    Added,
    /// The path exists in both and its content or mode differs.
    Modified,
    /// The path existed at the base commit and is gone.
    Deleted,
}

/// One changed path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChangedPath {
    /// The path. A rename is reported as a deletion of the old path and an addition of the new
    /// one, so a protected-path rule sees both ends.
    pub path: RepoPath,
    /// What happened to it.
    pub kind: ChangeKind,
}

/// The sandbox's work after it was audited: the tree difference from the base commit.
///
/// Only [`Workspace::ingest`] makes one, so a value of this type is proof that the audit walk,
/// the protected-path check and the secret scan passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestedChange {
    base: CommitSha,
    changes: Vec<ChangedPath>,
    tree: Sha256Digest,
}

impl IngestedChange {
    /// Called by a workspace adapter when ingestion succeeded. `tree` is a hash of the resulting
    /// tree, so `commit` can refuse a change made for another workspace.
    #[must_use]
    pub fn new(base: CommitSha, mut changes: Vec<ChangedPath>, tree: Sha256Digest) -> Self {
        changes.sort();
        Self {
            base,
            changes,
            tree,
        }
    }

    /// The commit the change is relative to.
    #[must_use]
    pub fn base(&self) -> &CommitSha {
        &self.base
    }

    /// The changed paths, sorted by path.
    #[must_use]
    pub fn changes(&self) -> &[ChangedPath] {
        &self.changes
    }

    /// The hash of the resulting tree.
    #[must_use]
    pub fn tree(&self) -> &Sha256Digest {
        &self.tree
    }

    /// True when nothing differs from the base commit.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

/// Who a commit is by and what it says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRequest {
    /// The commit message.
    pub message: String,
    /// The author and committer name. It is the factory's fixed identity, never the agent's.
    pub author_name: String,
    /// The author and committer email.
    pub author_email: String,
}

/// An opaque credential for one push. It is short-lived and narrowed to one repository. Its text
/// never appears in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct PushCredential(String);

impl PushCredential {
    /// Wraps a credential issued by the code host adapter.
    #[must_use]
    pub fn new(secret: String) -> Self {
        Self(secret)
    }

    /// The credential text. Pass it to git through the environment, never on a command line.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for PushCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PushCredential(<redacted>)")
    }
}

/// Where to push and with what credential. `ChangeHost::push_target` makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushTarget {
    /// The repository to push to.
    pub repo: RepoRef,
    /// The branch to push to. Always under `factory/`.
    pub branch: BranchName,
    /// The credential for this push.
    pub credential: PushCredential,
}

/// Why a workspace call failed. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkspaceError {
    /// A hidden path exists in the sandbox's tree, so something made it or the checkout leaked.
    #[error("a hidden path exists in the sandbox tree: {0}")]
    HiddenPathPresent(RepoPath),
    /// A symbolic link points outside the workspace.
    #[error("a symbolic link points outside the workspace: {0}")]
    EscapingSymlink(RepoPath),
    /// A gitlink (a submodule entry) was found.
    #[error("a gitlink (submodule entry) was found: {0}")]
    Gitlink(RepoPath),
    /// A nested git directory was found.
    #[error("a nested git directory was found: {0}")]
    NestedGit(RepoPath),
    /// One or more protected paths changed.
    #[error("{} protected path(s) changed", .0.len())]
    ProtectedPathChanged(Vec<RepoPath>),
    /// The changed files hold something that looks like a secret. The findings name the rule and
    /// the place, never the text.
    #[error("{} possible secret(s) found in the change", .0.len())]
    SecretFound(Vec<Finding>),
    /// A file or the whole change is larger than the limit.
    #[error("the file or change is larger than the limit")]
    TooLarge,
    /// The path does not exist at the base commit, or it is a hidden path.
    #[error("no such path at the base commit: {0}")]
    PathNotFound(RepoPath),
    /// A push target is not under `factory/`. The factory pushes nowhere else.
    #[error("the factory may push only to branches under `factory/`")]
    BranchNotAllowed,
    /// A git command failed. The text never includes file content or a credential.
    #[error("git failed: {0}")]
    Git(String),
    /// Reading or writing the host directories failed.
    #[error("the host file system failed: {0}")]
    Io(String),
}

/// Makes workspaces.
///
/// # Preconditions
/// The request's repository and base commit exist in the trusted object store. Hidden and
/// protected patterns were taken from the project configuration and not from the repository
/// under work.
///
/// # Postconditions
/// The workspace is a detached, sparse checkout of the base commit. Paths that match a hidden
/// pattern are not in the checkout. The git directory is outside every mount.
///
/// # Errors
/// [`WorkspaceError::Git`] (the commit or repository is unavailable), [`WorkspaceError::Io`] (the
/// host directories could not be made).
///
/// # Idempotency
/// Not idempotent: each call makes a new workspace with its own directories.
#[async_trait]
pub trait WorkspaceProvider: Send + Sync {
    /// Says whether this provider runs real git (`real`) or an in-memory stand-in (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// A sparse, detached worktree of the base commit. Hidden paths are excluded from the
    /// checkout.
    async fn create(&self, req: WorkspaceRequest) -> Result<Box<dyn Workspace>, WorkspaceError>;
}

/// The host side of one job's repository. All git runs here with a fixed environment.
///
/// # Preconditions
/// `ingest` is called only after the sandbox container is gone, because a running container
/// could still change the tree. `commit` needs a change that `ingest` returned for this
/// workspace. `push` needs a commit this workspace made.
///
/// # Postconditions
/// `read_base_file` and `list_base` read the trusted object store at the base commit and never
/// the sandbox-writable tree, so what the sandbox wrote cannot change what they return. A hidden
/// path is neither listed nor readable: it is reported as not found. A successful `ingest` means
/// the no-follow audit walk found no hidden path, no escaping symlink, no gitlink and no nested
/// git directory, no protected path changed, and no secret was found. `commit` commits exactly
/// the tree that `ingest` audited, and refuses a change this workspace never ingested. A commit
/// made by `commit` has the base commit as its only parent. `push` sends only a commit this
/// workspace made, and only to a branch under `factory/`.
///
/// # Errors
/// [`WorkspaceError`]: `PathNotFound`, `TooLarge`, `HiddenPathPresent`, `EscapingSymlink`,
/// `Gitlink`, `NestedGit`, `ProtectedPathChanged` (with every changed protected path),
/// `SecretFound`, `BranchNotAllowed`, `Git` and `Io`.
///
/// # Idempotency
/// `read_base_file`, `list_base` and `ingest` do not change the repository and give the same
/// answer for the same tree. `commit` makes a new commit each time it is called. `push` of a
/// commit that is already on the remote branch succeeds without change. `dispose` ends the
/// workspace and removes its directories.
#[async_trait]
pub trait Workspace: Send + Sync {
    /// The host directories and masks to build the sandbox from.
    fn mounts(&self) -> WorkspaceMounts;

    /// Reads from the trusted object store at the base commit, never from the sandbox-writable
    /// tree.
    async fn read_base_file(
        &self,
        path: &RepoPath,
        max_bytes: u64,
    ) -> Result<Vec<u8>, WorkspaceError>;

    /// Paths at the base commit that match the glob, sorted, at most `limit`. Hidden paths are
    /// never listed.
    async fn list_base(
        &self,
        glob: &RepoGlob,
        limit: usize,
    ) -> Result<Vec<RepoPath>, WorkspaceError>;

    /// Call after the container is gone. No-follow audit walk, temporary-index tree diff,
    /// protected-path inputs, rejection of gitlinks and escaping symlinks, secret scan.
    async fn ingest(&self, base: &CommitSha) -> Result<IngestedChange, WorkspaceError>;

    /// Commits the audited change on top of the base commit.
    async fn commit(
        &self,
        change: &IngestedChange,
        req: CommitRequest,
    ) -> Result<CommitSha, WorkspaceError>;

    /// Pushes the commit to the target branch.
    async fn push(&self, target: &PushTarget, commit: &CommitSha) -> Result<(), WorkspaceError>;

    /// Ends the workspace and removes its directories.
    async fn dispose(self: Box<Self>) -> Result<(), WorkspaceError>;
}
