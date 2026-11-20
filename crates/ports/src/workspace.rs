//! The workspace ports: the job's trusted object store, the attempt's worktree over it, git
//! hardening and the ingestion of what the sandbox wrote (ADR 0003, ADR 0014 decision 4).
//!
//! The sandbox never sees the trusted git directory. All git runs on the host, with a fixed
//! environment, against a directory the sandbox cannot write. Everything the sandbox wrote is
//! hostile until [`Workspace::ingest`] has checked it.
//!
//! The repository belongs to the job; a workspace belongs to an attempt:
//!
//! * [`WorkspaceProvider::fetch`] puts a branch tip into the job's object store and returns the
//!   commit it fetched.
//! * [`WorkspaceProvider::create`] makes a sparse, detached worktree of a commit in that store,
//!   for one attempt.
//! * [`WorkspaceProvider::repo`] gives a [`JobRepo`]: reads, patches and pushes, all against the
//!   store, so they work after a restart and from a different workspace.
//! * [`Workspace::commit`] records the commit in the store. A commit survives any workspace.
//!
//! What the sandbox wrote is read back with `commit` first and [`JobRepo::read_file_at`] second.
//! There is no way to read uncommitted bytes through a second path.

use std::path::PathBuf;

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::{AttemptId, JobId};
use factory_domain::values::{GitSha, Sha256Digest};
use factory_domain::vocabulary::Fidelity;

use crate::clock::CancelSignal;
use crate::paths::{
    BranchName, CommitSha, Finding, PathMode, PathRules, RepoGlob, RepoPath, RepoRef,
};

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

/// An opaque credential for one fetch. Short-lived, read-only and narrowed to one repository. Its
/// text never appears in `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct FetchCredential(String);

impl FetchCredential {
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

impl std::fmt::Debug for FetchCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FetchCredential(<redacted>)")
    }
}

/// Where to fetch from and with what credential. `ChangeHost::fetch_target` makes one. The
/// mirror of `PushTarget`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchTarget {
    /// The repository.
    pub repo: RepoRef,
    /// The read credential for this fetch.
    pub credential: FetchCredential,
}

/// What `fetch` brought in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedBase {
    /// The branch that was fetched.
    pub branch: BranchName,
    /// The commit the branch pointed at when it was fetched. Now in the job's object store.
    pub commit: CommitSha,
}

/// What a workspace is for. It decides which paths exist in the checkout and whether the sandbox
/// may write to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspacePurpose {
    /// A checkout for an `agent` sandbox. Every path the rules classify as `Hidden` is absent.
    /// The checkout is writable.
    Agent,
    /// A checkout for a `verify` sandbox. It is read-only. Paths the rules classify as `Hidden`
    /// are absent, except those that match `holdouts`, which are present so the trusted gates
    /// can run held-out tests. The builder never had them.
    Verify {
        /// The held-out test globs from the policy (`evaluation_holdouts`).
        holdouts: Vec<RepoGlob>,
    },
}

/// What to check out and what to keep out of the sandbox's sight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRequest {
    /// The job. Its object store must exist (`WorkspaceProvider::fetch`).
    pub job: JobId,
    /// The attempt the workspace belongs to. A workspace whose attempt is not live is an orphan.
    pub attempt: AttemptId,
    /// The commit to check out, detached. It is the fetched base or a commit the factory made
    /// earlier in this job.
    pub base: CommitSha,
    /// The commit the job started from (the protected branch tip it fetched), when `base` is a
    /// commit the factory made later in the job: a later task, or a rework round.
    ///
    /// The path modes that protect what existed before the job (`append_only`, `additions_only`)
    /// judge a path by how it differs from this commit, not from `base`. A file absent here is
    /// an addition of this job, whatever an earlier task or round did to it; a file present here
    /// is compared with its content here, so a later round cannot remove a line that existed
    /// before the job even if an earlier round left it alone. `deny_write` stays absolute: any
    /// change since `base` is refused. `None` means `base` itself is the protected commit.
    ///
    /// The commit must be in the job's object store and an ancestor of `base` (or `base`
    /// itself); `create` refuses with `UnknownCommit` otherwise (ADR 0024).
    pub protected_base: Option<CommitSha>,
    /// The path rules from the policy. Adapters take every decision about a path from here.
    pub rules: PathRules,
    /// What the workspace is for.
    pub purpose: WorkspacePurpose,
}

/// The host directories and masks the sandbox is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceMounts {
    /// The checkout, mounted at `/workspace`.
    pub workspace: PathBuf,
    /// True for a `verify` workspace: `/workspace` is mounted read-only.
    pub workspace_read_only: bool,
    /// The output directory, mounted read-write at `/out`. Build output goes here.
    pub out: PathBuf,
    /// Paths the rules classify as `DenyWrite`, and `AppendOnly` paths that existed at the
    /// protected base, re-mounted read-only over the checkout (`protected_overlay_readonly`).
    pub protected_overlays: Vec<RepoPath>,
    /// True when `/dev/null` is bound over `/workspace/.git`, so the sandbox sees no git data.
    pub git_masked: bool,
}

/// A protected path that changed, and the rule it broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathViolation {
    /// The path. A rename reports both ends.
    pub path: RepoPath,
    /// The mode that applies to it.
    pub mode: PathMode,
}

/// Why a workspace call failed. The set is closed and carries no file content, no credential and
/// no text from git.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WorkspaceError {
    /// A hidden path exists in the sandbox's tree.
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
    /// One or more paths broke their mode.
    #[error("{} protected path(s) changed", .0.len())]
    ProtectedPathChanged(Vec<PathViolation>),
    /// The changed files hold something that looks like a secret.
    #[error("{} possible secret(s) found in the change", .0.len())]
    SecretFound(Vec<Finding>),
    /// A file or the whole change is larger than the limit.
    #[error("the file or change is larger than the limit")]
    TooLarge,
    /// The path does not exist at the commit, or it is hidden in this view.
    #[error("no such path at the commit: {0}")]
    PathNotFound(RepoPath),
    /// The commit is not in the job's object store.
    #[error("the commit is not in the job's object store")]
    UnknownCommit,
    /// The job has no object store yet. Call `fetch` first.
    #[error("the job has no object store; fetch the repository first")]
    NotFetched,
    /// The branch moved while it was being fetched, or the remote no longer has the commit.
    #[error("the remote branch moved while it was fetched")]
    BaseMoved,
    /// The remote branch has commits the push would drop. The factory never forces.
    #[error("the remote branch has commits that the push would drop")]
    NonFastForward,
    /// The commit was not made by the factory in this job, so it is not pushed.
    #[error("the commit was not made by the factory in this job")]
    NotMadeHere,
    /// A push target is not under `factory/`. The factory pushes nowhere else.
    #[error("the factory may push only to branches under `factory/`")]
    BranchNotAllowed,
    /// The remote refused the credential.
    #[error("the remote refused the credential")]
    Unauthorized,
    /// The caller cancelled the call. Nothing partial remains.
    #[error("the call was cancelled")]
    Cancelled,
    /// The call took longer than its limit. Nothing partial remains.
    #[error("the call timed out")]
    Timeout,
    /// A git command failed. Names the operation and the exit code, never git's text.
    #[error("git failed during {operation:?} (exit code {exit:?})")]
    Git {
        /// What the adapter was doing.
        operation: GitOperation,
        /// The exit code, when the process exited by itself.
        exit: Option<i32>,
    },
    /// Reading or writing the host directories failed.
    #[error("the host file system failed during {0:?}")]
    Io(IoOperation),
}

/// What the adapter was doing when git failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitOperation {
    /// Fetching objects.
    Fetch,
    /// Making the sparse worktree.
    Checkout,
    /// Computing the tree difference.
    Diff,
    /// Writing a commit.
    Commit,
    /// Pushing.
    Push,
    /// Reading an object.
    Read,
}

/// What the adapter was doing when a host file operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOperation {
    /// Making a directory.
    CreateDirectory,
    /// Walking the checkout.
    Walk,
    /// Removing a directory.
    Remove,
}

/// The sandbox's work after it was audited: the tree difference from the workspace's base commit.
///
/// Only [`Workspace::ingest`] makes one, so a value of this type is proof that the audit walk,
/// the path rules and the secret scan passed. `new` is for workspace adapters and the testkit
/// only; the static check ST-13 fails a call from anywhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestedChange {
    base: CommitSha,
    changes: Vec<ChangedPath>,
    sensitive: Vec<RepoPath>,
    tree: Sha256Digest,
}

impl IngestedChange {
    /// Called by a workspace adapter when ingestion succeeded.
    #[must_use]
    pub fn new(
        base: CommitSha,
        mut changes: Vec<ChangedPath>,
        sensitive: Vec<RepoPath>,
        tree: Sha256Digest,
    ) -> Self {
        changes.sort();
        Self {
            base,
            changes,
            sensitive,
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
    /// The changed paths the rules classify as `Sensitive`. They feed the semantic checks.
    #[must_use]
    pub fn sensitive(&self) -> &[RepoPath] {
        &self.sensitive
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

/// Which paths a read may see.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadView {
    /// What an agent may see. A path the rules classify as `Hidden` is `PathNotFound`.
    Agent,
    /// What the trusted control plane may see: everything in the commit.
    Trusted,
}

/// The diff between two commits, stored as an artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchExport {
    /// The unified diff, `text/x-diff`. Generated on the host from the object store, with a fixed
    /// context size of 3 lines and no external diff driver or textconv.
    pub patch: ArtifactRef,
    /// The changed paths, sorted. A rename is a deletion and an addition.
    pub changes: Vec<ChangedPath>,
}

/// Makes the job's object store and the workspaces over it.
///
/// # Preconditions
/// Path rules come from the project configuration at the protected base, not from the
/// repository under work.
///
/// # Postconditions
/// The job's object store is a directory outside every mount. `fetch` puts the remote branch tip
/// into it and nothing else. `create` returns a sparse, detached worktree of a commit in that
/// store, and the store, not the worktree, keeps every commit `Workspace::commit` makes. A new
/// provider value over the same host directory sees the same store, so a restart loses no
/// commit.
///
/// # Errors
/// [`WorkspaceError`].
///
/// # Idempotency
/// `fetch` is idempotent: a repeat fetches what is missing and returns the tip it found.
/// `create` is not idempotent. `dispose_job` and `sweep_orphans` are.
///
/// # Cancellation and timeouts
/// `fetch` and `create` take a cancel signal and stop within a second. A cancelled or timed-out
/// call leaves the store as it was, or with extra objects that the next call reuses. Dropping the
/// future is equivalent to cancelling and is safe.
#[async_trait]
pub trait WorkspaceProvider: Send + Sync {
    /// Says whether this provider runs real git (`real`) or an in-memory stand-in (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Fetches the branch into the job's object store, making the store when it does not exist,
    /// and returns the commit the branch pointed at. If the tip moved during the fetch the call
    /// returns `BaseMoved`.
    async fn fetch(
        &self,
        job: JobId,
        target: &FetchTarget,
        branch: &BranchName,
        cancel: &dyn CancelSignal,
    ) -> Result<FetchedBase, WorkspaceError>;

    /// A sparse, detached worktree of `req.base`. Paths the rules classify as `Hidden` are not in
    /// it, except in a `Verify` workspace for the holdout globs.
    async fn create(
        &self,
        req: WorkspaceRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn Workspace>, WorkspaceError>;

    /// The job's object store, for reads, patches and pushes.
    async fn repo(&self, job: JobId) -> Result<Box<dyn JobRepo>, WorkspaceError>;

    /// Removes the job's object store and every workspace of the job.
    async fn dispose_job(&self, job: JobId) -> Result<(), WorkspaceError>;

    /// Removes the workspaces whose attempt is not in `live`, and the stores of jobs not in
    /// `live_jobs`. Returns the attempts whose workspace it removed.
    async fn sweep_orphans(
        &self,
        live: &[AttemptId],
        live_jobs: &[JobId],
    ) -> Result<Vec<AttemptId>, WorkspaceError>;
}

/// The trusted object store of one job. Everything here reads or writes the store, never the
/// sandbox-writable tree.
///
/// # Postconditions
/// `read_file_at` and `list_at` return what the commit holds. `export_patch` is the difference
/// between two commits in the store. `push` sends a commit that `Workspace::commit` made in this
/// job, recorded durably in the store, so it works after a restart and in a workspace other than
/// the one that made it.
///
/// # Errors
/// [`WorkspaceError`]: `UnknownCommit`, `PathNotFound`, `TooLarge`, `NotMadeHere`, `NonFastForward`,
/// `BranchNotAllowed`, `Unauthorized`, `Cancelled`, `Timeout`, `Git`, `Io`.
///
/// # Idempotency
/// Every read is a read. `push` of a commit already on the remote branch succeeds without
/// change. `export_patch` of the same two commits gives the same artifact.
///
/// # Cancellation and timeouts
/// `push` and `export_patch` take a cancel signal. A cancelled push has either updated the remote
/// branch or not; the next `push` of the same commit settles it.
///
/// # Preconditions
/// The job has an object store (WorkspaceProvider::fetch was called). A commit the caller names is in
/// that store.
#[async_trait]
pub trait JobRepo: Send + Sync {
    /// The bytes of a file at a commit, at most `max_bytes`.
    async fn read_file_at(
        &self,
        commit: &CommitSha,
        path: &RepoPath,
        max_bytes: u64,
        view: ReadView,
    ) -> Result<Vec<u8>, WorkspaceError>;

    /// The paths at a commit that match the glob, sorted, at most `limit`.
    async fn list_at(
        &self,
        commit: &CommitSha,
        glob: &RepoGlob,
        limit: usize,
        view: ReadView,
    ) -> Result<Vec<RepoPath>, WorkspaceError>;

    /// The diff from `base` to `head` as a stored artifact. The caller indexes it for its tenant.
    async fn export_patch(
        &self,
        base: &CommitSha,
        head: &CommitSha,
        max_bytes: u64,
        cancel: &dyn CancelSignal,
    ) -> Result<PatchExport, WorkspaceError>;

    /// Pushes a commit the factory made in this job to the target branch.
    async fn push(
        &self,
        target: &PushTarget,
        commit: &CommitSha,
        cancel: &dyn CancelSignal,
    ) -> Result<(), WorkspaceError>;

    /// The identifier of the tree of a commit: the object that names the files the commit holds.
    /// Two commits with the same files have the same tree, which is what an approval of a pull
    /// request is bound to besides its head commit (ADR 0009). Read from the job's own object
    /// store; the code host is not asked.
    ///
    /// Added by the full run, pending architect confirmation (`docs/architecture/ports-v1.1.md`,
    /// "Additions after v1.1"): the binding checks of the delivery stage needed the tree and no
    /// port offered it.
    ///
    /// # Errors
    /// [`WorkspaceError::UnknownCommit`] for a commit the job's store does not hold,
    /// [`WorkspaceError::Git`] when the object store cannot be read.
    async fn tree_of(&self, commit: &CommitSha) -> Result<GitSha, WorkspaceError>;
}

/// The host side of one attempt's checkout. All git runs here with a fixed environment.
///
/// # Preconditions
/// `ingest` is called only after the sandbox container is gone, because a running container could
/// still change the tree. `commit` needs a change that `ingest` returned for this workspace.
///
/// # Postconditions
/// A successful `ingest` means the no-follow audit walk found no hidden path, no escaping
/// symlink, no gitlink and no nested git directory; the tree difference from the base commit,
/// computed on the host with a temporary index, passed every path rule; and no secret was found.
/// For each path in that difference, `deny_write` refuses any change, while `append_only` and
/// `additions_only` judge the path by its difference from the request's `protected_base` (the
/// base commit when there is none).
/// `commit` commits exactly the tree that `ingest` audited, with the base commit as its only
/// parent, and records the commit as made by the factory in this job. It refuses a change this
/// workspace never ingested.
///
/// # Errors
/// [`WorkspaceError`]: `HiddenPathPresent`, `EscapingSymlink`, `Gitlink`, `NestedGit`,
/// `ProtectedPathChanged`, `SecretFound`, `TooLarge`, `Cancelled`, `Timeout`, `Git`, `Io`.
///
/// # Idempotency
/// `ingest` gives the same answer for the same tree. `commit` of the same `IngestedChange` with
/// the same `CommitRequest` returns the same commit id and makes no second commit. `dispose`
/// removes the workspace's directories and can be followed by `sweep_orphans` safely.
///
/// # Cancellation and timeouts
/// `ingest` takes a cancel signal. Dropping `commit` is safe: it is atomic (a ref update).
#[async_trait]
pub trait Workspace: Send + Sync {
    /// The host directories and masks to build the sandbox from.
    fn mounts(&self) -> WorkspaceMounts;

    /// The commit the workspace was made from.
    fn base(&self) -> &CommitSha;

    /// Call after the container is gone. No-follow audit walk, temporary-index tree diff against
    /// `base()`, path rules, rejection of gitlinks and escaping symlinks, secret scan.
    async fn ingest(&self, cancel: &dyn CancelSignal) -> Result<IngestedChange, WorkspaceError>;

    /// Commits the audited change on top of the base commit, in the job's object store.
    async fn commit(
        &self,
        change: &IngestedChange,
        req: CommitRequest,
    ) -> Result<CommitSha, WorkspaceError>;

    /// Ends the workspace and removes its directories. The commits it made stay in the store.
    async fn dispose(self: Box<Self>) -> Result<(), WorkspaceError>;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn path(text: &str) -> RepoPath {
        RepoPath::new(text).expect("a valid path")
    }

    fn sha() -> CommitSha {
        CommitSha::parse(&"a".repeat(40)).expect("a valid commit id")
    }

    #[test]
    fn an_ingested_change_lists_its_paths_in_order() {
        let change = IngestedChange::new(
            sha(),
            vec![
                ChangedPath {
                    path: path("z.txt"),
                    kind: ChangeKind::Added,
                },
                ChangedPath {
                    path: path("a.txt"),
                    kind: ChangeKind::Deleted,
                },
            ],
            Vec::new(),
            Sha256Digest::of(b"tree"),
        );
        let paths: Vec<&str> = change.changes().iter().map(|c| c.path.as_str()).collect();
        assert_eq!(paths, vec!["a.txt", "z.txt"]);
        assert!(!change.is_empty());
        assert!(
            IngestedChange::new(sha(), Vec::new(), Vec::new(), Sha256Digest::of(b"tree"))
                .is_empty()
        );
    }

    #[test]
    fn an_ingested_change_reports_the_sensitive_paths_it_touched() {
        let change = IngestedChange::new(
            sha(),
            vec![ChangedPath {
                path: path("Cargo.toml"),
                kind: ChangeKind::Modified,
            }],
            vec![path("Cargo.toml")],
            Sha256Digest::of(b"tree"),
        );
        assert_eq!(change.sensitive(), [path("Cargo.toml")]);
        assert_eq!(change.base(), &sha());
        assert_eq!(change.tree(), &Sha256Digest::of(b"tree"));
    }

    #[test]
    fn a_credential_never_shows_in_debug_output() {
        // Built at run time so that no credential-shaped literal sits in the source.
        let secret = format!("{}-{}", "not", "for-logs");
        let push = PushCredential::new(secret.clone());
        let fetch = FetchCredential::new(secret.clone());
        for shown in [format!("{push:?}"), format!("{fetch:?}")] {
            assert!(!shown.contains(&secret), "{shown}");
            assert!(shown.contains("<redacted>"), "{shown}");
        }
        assert_eq!(push.expose(), secret);
        assert_eq!(fetch.expose(), secret);
    }

    #[test]
    fn a_fetch_target_does_not_leak_its_credential_through_debug() {
        let secret = format!("{}-{}", "read", "only-token");
        let target = FetchTarget {
            repo: RepoRef::parse("acme/widgets").unwrap(),
            credential: FetchCredential::new(secret.clone()),
        };
        assert!(!format!("{target:?}").contains(&secret));
    }

    #[test]
    fn a_workspace_error_carries_no_text_from_git() {
        let shown = WorkspaceError::Git {
            operation: GitOperation::Push,
            exit: Some(128),
        }
        .to_string();
        assert_eq!(shown, "git failed during Push (exit code Some(128))");
        assert_eq!(
            WorkspaceError::Io(IoOperation::Walk).to_string(),
            "the host file system failed during Walk"
        );
    }

    #[test]
    fn a_verify_workspace_names_its_holdouts_and_an_agent_workspace_has_none() {
        let holdouts = vec![RepoGlob::new("tests/holdout/**").unwrap()];
        let verify = WorkspacePurpose::Verify {
            holdouts: holdouts.clone(),
        };
        assert_ne!(verify, WorkspacePurpose::Agent);
        match verify {
            WorkspacePurpose::Verify { holdouts: listed } => assert_eq!(listed, holdouts),
            WorkspacePurpose::Agent => unreachable!(),
        }
    }
}
