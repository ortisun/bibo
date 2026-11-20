//! A workspace provider that keeps repositories in memory and runs no git (ports-v1.1).
//!
//! The pieces mirror the real ones:
//!
//! * [`FakeRemote`] is the code host's repository: commits and branch pointers. The fake change
//!   host shares it, so a push through the workspace is visible to the host.
//! * A job's **object store** holds the commits fetched from the remote and every commit the
//!   factory made in the job. It lives in the provider's shared state, so a new provider value
//!   over the same state (a restart) sees the same commits.
//! * A **workspace** is a sparse, detached worktree of one commit for one attempt. The sandbox's
//!   writable tree is a map a test edits through [`FakeWorkspaceProvider::edit_tree`]. `ingest`
//!   audits it and refuses what the real ingestion refuses. Every decision about a path is made
//!   by `PathRules::classify`, never by a glob match of this file.
//! * [`JobRepo`] reads, diffs and pushes against the object store only.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::ids::{AttemptId, JobId};
use factory_domain::values::{MediaType, Sha256Digest, Slug};
use factory_domain::vocabulary::Fidelity;
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{
    BranchName, CommitSha, Finding, PathMode, PathRule, PathRules, RepoGlob, RepoPath, RepoRef,
};
use factory_ports::workspace::{
    ChangeKind, ChangedPath, CommitRequest, FetchTarget, FetchedBase, GitOperation, IngestedChange,
    JobRepo, PatchExport, PathViolation, PushTarget, ReadView, Workspace, WorkspaceError,
    WorkspaceMounts, WorkspaceProvider, WorkspacePurpose, WorkspaceRequest,
};

use crate::contracts::workspace::{TreeEdit, WorkspaceSubject};

/// A deliberate fault, for proving that the contract suite can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceDefect {
    /// `read_file_at` for a workspace's commit reads the sandbox-writable tree.
    ReadsFromSandboxTree,
    /// Hidden paths are listed and readable in the agent view.
    ShowsHiddenPaths,
    /// Ingestion does not look for hidden paths in the tree.
    SkipsHiddenPathCheck,
    /// Ingestion does not apply the path modes at all.
    AllowsAnyEdit,
    /// Ingestion treats `additions_only` like a free path.
    TreatsAdditionsOnlyAsFree,
    /// Path matching is case-sensitive and not folded.
    IgnoresCaseFold,
    /// A re-inclusion lifts the protection of every group, not only its own.
    ReincludeIgnoresGroup,
    /// Ingestion accepts a symbolic link that points outside the workspace.
    FollowsEscapingSymlinks,
    /// Ingestion accepts a gitlink.
    SkipsGitlinkCheck,
    /// Ingestion accepts a nested git directory.
    SkipsNestedGitCheck,
    /// Ingestion does not scan for secrets.
    SkipsSecretScan,
    /// `push` accepts any branch.
    PushesAnyBranch,
    /// `push` accepts a commit the factory did not make.
    PushesForeignCommit,
    /// `commit` accepts a change that `ingest` never returned.
    CommitsUnauditedChanges,
    /// Every workspace shares one sandbox tree.
    SharesOneTree,
    /// A restart forgets which commits the factory made.
    ForgetsCommitsOnRestart,
    /// A commit is visible only in the workspace that made it.
    ScopesCommitsToWorkspace,
    /// `fetch` returns the commit before the tip it fetched.
    ReturnsWrongTip,
    /// `fetch` does not notice that the branch moved while it ran.
    IgnoresMovedBase,
    /// A verify workspace is writable.
    VerifyIsWritable,
    /// A verify workspace does not contain the held-out tests.
    IgnoresHoldouts,
    /// `export_patch` gives a different artifact for the same two commits.
    UnstablePatch,
    /// `ingest` ignores a cancel signal.
    IgnoresCancelOnIngest,
    /// The workspace's directories stay after `dispose`.
    LeavesDirectoriesOnDispose,
    /// The protected overlays are not reported.
    OmitsOverlays,
    /// Added files are reported as modified.
    MisreportsChangeKinds,
    /// A commit is built from the checkout, so it loses the paths the checkout never held.
    DropsHiddenPathsInCommit,
    /// `tree_of` answers with the commit's own identifier, so equal files give different trees.
    TreeIsTheCommit,
}

/// Each defect and the checks of `contracts::workspace` that must fail when the fake has it.
pub const DEFECTS: &[(WorkspaceDefect, &[&str])] = &[
    (
        WorkspaceDefect::ReadsFromSandboxTree,
        &["the_sandbox_cannot_change_what_the_host_reads_from_the_base"],
    ),
    (
        WorkspaceDefect::ShowsHiddenPaths,
        &[
            "a_hidden_path_is_not_found_in_the_agent_view_and_is_in_the_trusted_view",
            "listing_matches_a_glob_in_order_and_never_shows_hidden_paths",
        ],
    ),
    (
        WorkspaceDefect::SkipsHiddenPathCheck,
        &["a_hidden_path_in_the_tree_is_refused"],
    ),
    (
        WorkspaceDefect::AllowsAnyEdit,
        &[
            "a_change_to_a_protected_path_is_refused_with_every_changed_path",
            "an_added_test_is_allowed_and_an_edited_test_is_refused_under_additions_only",
        ],
    ),
    (
        WorkspaceDefect::TreatsAdditionsOnlyAsFree,
        &["an_added_test_is_allowed_and_an_edited_test_is_refused_under_additions_only"],
    ),
    (
        WorkspaceDefect::IgnoresCaseFold,
        &["a_case_variant_of_a_protected_path_is_refused"],
    ),
    (
        WorkspaceDefect::ReincludeIgnoresGroup,
        &["a_reincluded_path_is_allowed_only_in_its_own_group"],
    ),
    (
        WorkspaceDefect::FollowsEscapingSymlinks,
        &["a_symlink_that_leaves_the_workspace_is_refused"],
    ),
    (
        WorkspaceDefect::SkipsGitlinkCheck,
        &["a_gitlink_is_refused"],
    ),
    (
        WorkspaceDefect::SkipsNestedGitCheck,
        &["a_nested_git_directory_is_refused"],
    ),
    (
        WorkspaceDefect::SkipsSecretScan,
        &["a_secret_in_a_changed_file_is_refused_without_repeating_it"],
    ),
    (
        WorkspaceDefect::PushesAnyBranch,
        &["a_push_outside_factory_branches_is_refused"],
    ),
    (
        WorkspaceDefect::PushesForeignCommit,
        &["a_commit_the_factory_did_not_make_is_not_pushed"],
    ),
    (
        WorkspaceDefect::CommitsUnauditedChanges,
        &["a_change_the_workspace_never_ingested_is_not_committed"],
    ),
    (
        WorkspaceDefect::SharesOneTree,
        &["two_workspaces_do_not_share_a_tree"],
    ),
    (
        WorkspaceDefect::ForgetsCommitsOnRestart,
        &["push_works_after_a_restart"],
    ),
    (
        WorkspaceDefect::ScopesCommitsToWorkspace,
        &["a_second_workspace_can_start_at_a_commit_the_first_made"],
    ),
    (
        WorkspaceDefect::ReturnsWrongTip,
        &["fetch_returns_the_tip_it_fetched"],
    ),
    (
        WorkspaceDefect::IgnoresMovedBase,
        &["fetch_reports_a_moved_base"],
    ),
    (
        WorkspaceDefect::VerifyIsWritable,
        &["a_verify_workspace_is_read_only_and_holds_the_holdouts"],
    ),
    (
        WorkspaceDefect::IgnoresHoldouts,
        &["a_verify_workspace_is_read_only_and_holds_the_holdouts"],
    ),
    (
        WorkspaceDefect::UnstablePatch,
        &["export_patch_is_the_same_for_the_same_commits"],
    ),
    (
        WorkspaceDefect::IgnoresCancelOnIngest,
        &["a_cancelled_ingest_leaves_nothing_behind"],
    ),
    (
        WorkspaceDefect::LeavesDirectoriesOnDispose,
        &["disposing_removes_the_host_directories"],
    ),
    (
        WorkspaceDefect::OmitsOverlays,
        &["a_new_workspace_masks_git_and_overlays_the_protected_paths"],
    ),
    (
        WorkspaceDefect::MisreportsChangeKinds,
        &["additions_modifications_and_deletions_are_reported"],
    ),
    (
        WorkspaceDefect::DropsHiddenPathsInCommit,
        &["an_audited_change_can_be_committed_and_pushed"],
    ),
    (
        WorkspaceDefect::TreeIsTheCommit,
        &["a_commit_has_a_tree_and_the_tree_follows_the_files"],
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    File(Vec<u8>),
    Symlink(String),
    Gitlink,
    /// A directory that holds a `.git` directory of its own.
    NestedGit,
}

type Tree = BTreeMap<RepoPath, Entry>;

#[derive(Debug, Clone)]
struct CommitObject {
    tree: Tree,
    parent: Option<CommitSha>,
}

// ---------------------------------------------------------------------------------------------
// The code host's repository
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct RemoteState {
    commits: BTreeMap<CommitSha, CommitObject>,
    branches: BTreeMap<(RepoRef, BranchName), CommitSha>,
    /// When set, the next fetch of this branch sees the tip move to this commit mid-way.
    move_during_fetch: Option<(BranchName, CommitSha)>,
}

/// A commit on the fake remote, as the remote itself records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCommit {
    /// The commit.
    pub sha: CommitSha,
    /// The paths it adds, changes or deletes against its parent, sorted.
    pub paths: Vec<String>,
}

/// The code host's repository. The fake workspace provider and the fake change host share one, so
/// a push in one is visible in the other. It is not a port.
#[derive(Clone, Default)]
pub struct FakeRemote {
    state: Arc<Mutex<RemoteState>>,
}

fn sha_of(parent: Option<&CommitSha>, tree: &Tree, message: &str) -> CommitSha {
    let mut seed = Vec::new();
    if let Some(parent) = parent {
        seed.extend_from_slice(parent.as_str().as_bytes());
    }
    seed.extend_from_slice(tree_digest(tree).as_str().as_bytes());
    seed.extend_from_slice(message.as_bytes());
    CommitSha::parse(&Sha256Digest::of(&seed).hex()[..40]).expect("forty hex characters")
}

impl FakeRemote {
    /// An empty remote.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Puts a commit holding `files` on top of `branch` (or as its first commit) and points the
    /// branch at it. Returns the commit.
    ///
    /// # Panics
    /// Panics when a path is not a valid repository path. This is test code.
    pub fn commit_on_branch(
        &self,
        repo: &RepoRef,
        branch: &BranchName,
        files: &[(&str, &str)],
    ) -> CommitSha {
        let tree: Tree = files
            .iter()
            .map(|(path, text)| {
                (
                    RepoPath::new(path).expect("a valid fixture path"),
                    Entry::File(text.as_bytes().to_vec()),
                )
            })
            .collect();
        let mut state = self.state.lock().expect("the lock is never poisoned");
        let parent = state.branches.get(&(repo.clone(), branch.clone())).cloned();
        let sha = sha_of(parent.as_ref(), &tree, "remote commit");
        state
            .commits
            .insert(sha.clone(), CommitObject { tree, parent });
        state
            .branches
            .insert((repo.clone(), branch.clone()), sha.clone());
        sha
    }

    /// Arranges for the tip of `branch` to move to a new commit while the next fetch runs.
    pub fn move_branch_during_next_fetch(
        &self,
        repo: &RepoRef,
        branch: &BranchName,
        files: &[(&str, &str)],
    ) {
        let current = self.branch_tip(repo, branch);
        let tree: Tree = files
            .iter()
            .map(|(path, text)| {
                (
                    RepoPath::new(path).expect("a valid fixture path"),
                    Entry::File(text.as_bytes().to_vec()),
                )
            })
            .collect();
        let sha = sha_of(current.as_ref(), &tree, "moved while fetching");
        let mut state = self.state.lock().expect("the lock is never poisoned");
        state.commits.insert(
            sha.clone(),
            CommitObject {
                tree,
                parent: current,
            },
        );
        state.move_during_fetch = Some((branch.clone(), sha));
    }

    /// The commit a branch points at.
    #[must_use]
    pub fn branch_tip(&self, repo: &RepoRef, branch: &BranchName) -> Option<CommitSha> {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .branches
            .get(&(repo.clone(), branch.clone()))
            .cloned()
    }

    /// The commits on a branch above `base` (the base itself and everything below it are left out),
    /// oldest first, each with the paths it changes against its parent. This is the remote's own
    /// record of the branch: a check reads the commits a job pushed from here and not from what the
    /// stages said they pushed. A branch that does not exist has none.
    #[must_use]
    pub fn commits_above(
        &self,
        repo: &RepoRef,
        branch: &BranchName,
        base: Option<&CommitSha>,
    ) -> Vec<RemoteCommit> {
        let state = self.state.lock().expect("the lock is never poisoned");
        let mut chain = Vec::new();
        let mut at = state.branches.get(&(repo.clone(), branch.clone())).cloned();
        while let Some(sha) = at {
            if base == Some(&sha) {
                break;
            }
            let Some(object) = state.commits.get(&sha) else {
                break;
            };
            let before = object
                .parent
                .as_ref()
                .and_then(|parent| state.commits.get(parent))
                .map(|parent| &parent.tree);
            let mut paths: Vec<String> = object
                .tree
                .iter()
                .filter(|(path, entry)| before.and_then(|tree| tree.get(*path)) != Some(*entry))
                .map(|(path, _)| path.as_str().to_owned())
                .collect();
            if let Some(before) = before {
                paths.extend(
                    before
                        .keys()
                        .filter(|path| !object.tree.contains_key(*path))
                        .map(|path| path.as_str().to_owned()),
                );
            }
            paths.sort();
            chain.push(RemoteCommit {
                sha: sha.clone(),
                paths,
            });
            at = object.parent.clone();
        }
        chain.reverse();
        chain
    }

    /// True when the remote holds the commit.
    #[must_use]
    pub fn has_commit(&self, commit: &CommitSha) -> bool {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .commits
            .contains_key(commit)
    }

    /// True when `ancestor` is `descendant` or one of its parents, following the chain.
    fn is_ancestor(
        &self,
        ancestor: &CommitSha,
        descendant: &CommitSha,
        extra: &BTreeMap<CommitSha, CommitObject>,
    ) -> bool {
        let state = self.state.lock().expect("the lock is never poisoned");
        let mut at = Some(descendant.clone());
        while let Some(current) = at {
            if current == *ancestor {
                return true;
            }
            at = state
                .commits
                .get(&current)
                .or_else(|| extra.get(&current))
                .and_then(|object| object.parent.clone());
        }
        false
    }
}

// ---------------------------------------------------------------------------------------------
// The provider
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct JobStore {
    commits: BTreeMap<CommitSha, CommitObject>,
    made_here: BTreeSet<CommitSha>,
    /// For the defect `ScopesCommitsToWorkspace`: which workspace made which commit.
    made_by: BTreeMap<CommitSha, PathBuf>,
}

#[derive(Default)]
struct Host {
    jobs: BTreeMap<JobId, JobStore>,
    live_dirs: BTreeSet<PathBuf>,
    workspaces: BTreeMap<PathBuf, (JobId, AttemptId)>,
    sandbox_trees: BTreeMap<PathBuf, Arc<Mutex<Tree>>>,
    next: u64,
    patch_counter: u64,
}

/// A workspace provider over an in-memory repository. Reports fidelity `fake`.
#[derive(Clone)]
pub struct FakeWorkspaceProvider {
    repo: RepoRef,
    remote: FakeRemote,
    shared: Arc<Mutex<Host>>,
    artifacts: Arc<dyn ArtifactStore>,
    rules: PathRules,
    one_tree: Arc<Mutex<Tree>>,
    defect: Option<WorkspaceDefect>,
}

impl FakeWorkspaceProvider {
    /// A provider for `repo` that reads its remote from `remote`, applies `rules` to the agent
    /// view of the job store, and stores patches in `artifacts`.
    #[must_use]
    pub fn new(
        repo: RepoRef,
        remote: FakeRemote,
        artifacts: Arc<dyn ArtifactStore>,
        rules: PathRules,
    ) -> Self {
        Self::build(repo, remote, artifacts, rules, None)
    }

    /// A provider that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(
        repo: RepoRef,
        remote: FakeRemote,
        artifacts: Arc<dyn ArtifactStore>,
        rules: PathRules,
        defect: WorkspaceDefect,
    ) -> Self {
        Self::build(repo, remote, artifacts, rules, Some(defect))
    }

    fn build(
        repo: RepoRef,
        remote: FakeRemote,
        artifacts: Arc<dyn ArtifactStore>,
        rules: PathRules,
        defect: Option<WorkspaceDefect>,
    ) -> Self {
        Self {
            repo,
            remote,
            shared: Arc::new(Mutex::new(Host::default())),
            artifacts,
            rules,
            one_tree: Arc::new(Mutex::new(Tree::new())),
            defect,
        }
    }

    /// A new provider value over the same host: what a process restart leaves behind.
    #[must_use]
    pub fn restart(&self) -> Self {
        if self.has(WorkspaceDefect::ForgetsCommitsOnRestart) {
            for store in self
                .shared
                .lock()
                .expect("the lock is never poisoned")
                .jobs
                .values_mut()
            {
                store.made_here.clear();
            }
        }
        self.clone()
    }

    /// Changes the sandbox-writable tree of the workspace whose workspace directory is `dir`.
    ///
    /// # Errors
    /// Returns a message when no workspace has that directory.
    pub fn edit_tree(&self, dir: &Path, edit: TreeEdit) -> Result<(), String> {
        let tree = self
            .shared
            .lock()
            .expect("the lock is never poisoned")
            .sandbox_trees
            .get(dir)
            .cloned()
            .ok_or_else(|| format!("no workspace has the directory {}", dir.display()))?;
        let mut tree = tree.lock().expect("the lock is never poisoned");
        match edit {
            TreeEdit::Write(path, bytes) => {
                tree.insert(path, Entry::File(bytes));
            }
            TreeEdit::Delete(path) => {
                tree.remove(&path);
            }
            TreeEdit::Symlink { path, target } => {
                tree.insert(path, Entry::Symlink(target));
            }
            TreeEdit::Gitlink(path) => {
                tree.insert(path, Entry::Gitlink);
            }
            TreeEdit::NestedGit(dir) => {
                tree.insert(dir, Entry::NestedGit);
            }
        }
        Ok(())
    }

    /// The commit a remote branch points at.
    #[must_use]
    pub fn pushed_commit(&self, repo: &RepoRef, branch: &BranchName) -> Option<CommitSha> {
        self.remote.branch_tip(repo, branch)
    }

    /// True when the workspace directory is still in use.
    #[must_use]
    pub fn directory_exists(&self, dir: &Path) -> bool {
        self.shared
            .lock()
            .expect("the lock is never poisoned")
            .live_dirs
            .contains(dir)
    }

    fn has(&self, defect: WorkspaceDefect) -> bool {
        self.defect == Some(defect)
    }

    /// What the rules say about a path. The defects change how the rules are applied; they never
    /// bypass `PathRules` in the faithful fake.
    fn classify(&self, rules: &PathRules, path: &RepoPath) -> Option<PathMode> {
        if self.has(WorkspaceDefect::IgnoresCaseFold) {
            return classify_exact(rules, path, false);
        }
        if self.has(WorkspaceDefect::ReincludeIgnoresGroup) {
            return classify_exact(rules, path, true);
        }
        rules.classify(path)
    }
}

/// The wrong way to classify: exact, case-sensitive matching. With `any_group`, a re-inclusion
/// lifts every group's protection, and matching is still folded.
fn classify_exact(rules: &PathRules, path: &RepoPath, any_group: bool) -> Option<PathMode> {
    let mut matched: Vec<(&str, PathMode)> = Vec::new();
    for (group, rule) in rules.rules() {
        if let PathRule::Mode { glob, mode } = rule {
            let hit = if any_group {
                glob.matches_folded(path)
            } else {
                glob.matches(path)
            };
            if hit {
                matched.push((group.as_str(), *mode));
            }
        }
    }
    for (_, rule) in rules.rules() {
        if let PathRule::Reinclude { glob, group } = rule {
            let hit = if any_group {
                glob.matches_folded(path)
            } else {
                glob.matches(path)
            };
            if hit {
                if any_group {
                    matched.clear();
                } else {
                    matched.retain(|(g, _)| *g != group.as_str());
                }
            }
        }
    }
    matched.into_iter().map(|(_, mode)| mode).min()
}

fn mounts_for(number: u64, overlays: Vec<RepoPath>, read_only: bool) -> WorkspaceMounts {
    WorkspaceMounts {
        workspace: PathBuf::from(format!("/fake/workspace-{number}/worktree")),
        workspace_read_only: read_only,
        out: PathBuf::from(format!("/fake/workspace-{number}/out")),
        protected_overlays: overlays,
        git_masked: true,
    }
}

#[async_trait]
impl WorkspaceProvider for FakeWorkspaceProvider {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn list_branches(
        &self,
        _job: JobId,
        target: &FetchTarget,
        prefix: &str,
        cancel: &dyn CancelSignal,
    ) -> Result<Vec<BranchName>, WorkspaceError> {
        if cancel.is_cancelled() {
            return Err(WorkspaceError::Cancelled);
        }
        if target.repo != self.repo {
            return Err(WorkspaceError::Unauthorized);
        }
        let remote = self
            .remote
            .state
            .lock()
            .expect("the lock is never poisoned");
        Ok(remote
            .branches
            .keys()
            .filter(|(repo, branch)| *repo == target.repo && branch.as_str().starts_with(prefix))
            .map(|(_, branch)| branch.clone())
            .collect())
    }

    async fn fetch(
        &self,
        job: JobId,
        target: &FetchTarget,
        branch: &BranchName,
        cancel: &dyn CancelSignal,
    ) -> Result<FetchedBase, WorkspaceError> {
        if cancel.is_cancelled() {
            return Err(WorkspaceError::Cancelled);
        }
        if target.repo != self.repo {
            return Err(WorkspaceError::Unauthorized);
        }
        self.remote
            .branch_tip(&target.repo, branch)
            .ok_or(WorkspaceError::UnknownCommit)?;
        // The branch may move while objects are fetched.
        let moved = {
            let mut remote = self
                .remote
                .state
                .lock()
                .expect("the lock is never poisoned");
            match remote.move_during_fetch.take() {
                Some((moving, to)) if moving == *branch => {
                    remote
                        .branches
                        .insert((target.repo.clone(), branch.clone()), to);
                    true
                }
                other => {
                    remote.move_during_fetch = other;
                    false
                }
            }
        };
        if moved && !self.has(WorkspaceDefect::IgnoresMovedBase) {
            return Err(WorkspaceError::BaseMoved);
        }
        let tip = self
            .remote
            .branch_tip(&target.repo, branch)
            .ok_or(WorkspaceError::UnknownCommit)?;
        let wanted = if self.has(WorkspaceDefect::ReturnsWrongTip) {
            // The commit before the tip: the answer of a fetch that read the branch too early.
            self.remote
                .state
                .lock()
                .expect("the lock is never poisoned")
                .commits
                .get(&tip)
                .and_then(|object| object.parent.clone())
                .unwrap_or_else(|| tip.clone())
        } else {
            tip.clone()
        };
        // Copy the chain of commits into the job's store.
        let remote = self
            .remote
            .state
            .lock()
            .expect("the lock is never poisoned");
        let mut host = self.shared.lock().expect("the lock is never poisoned");
        let store = host.jobs.entry(job).or_default();
        let mut at = Some(tip);
        while let Some(current) = at {
            let Some(object) = remote.commits.get(&current) else {
                break;
            };
            store
                .commits
                .entry(current)
                .or_insert_with(|| object.clone());
            at = object.parent.clone();
        }
        Ok(FetchedBase {
            branch: branch.clone(),
            commit: wanted,
        })
    }

    async fn create(
        &self,
        req: WorkspaceRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn Workspace>, WorkspaceError> {
        if cancel.is_cancelled() {
            return Err(WorkspaceError::Cancelled);
        }
        let mut host = self.shared.lock().expect("the lock is never poisoned");
        let store = host.jobs.get(&req.job).ok_or(WorkspaceError::NotFetched)?;
        let object = store
            .commits
            .get(&req.base)
            .cloned()
            .ok_or(WorkspaceError::UnknownCommit)?;
        let own_commit = store.made_by.get(&req.base).cloned();
        if self.has(WorkspaceDefect::ScopesCommitsToWorkspace) && own_commit.is_some() {
            return Err(WorkspaceError::UnknownCommit);
        }
        host.next += 1;
        let number = host.next;
        let read_only = matches!(req.purpose, WorkspacePurpose::Verify { .. })
            && !self.has(WorkspaceDefect::VerifyIsWritable);
        // What the checkout holds: everything the rules do not hide, and for a verify workspace
        // also the held-out tests.
        let holdouts: Vec<RepoGlob> = match &req.purpose {
            WorkspacePurpose::Verify { holdouts }
                if !self.has(WorkspaceDefect::IgnoresHoldouts) =>
            {
                holdouts.clone()
            }
            _ => Vec::new(),
        };
        let visible: Tree = object
            .tree
            .iter()
            .filter(|(path, _)| {
                self.classify(&req.rules, path) != Some(PathMode::Hidden)
                    || holdouts.iter().any(|glob| glob.matches_folded(path))
            })
            .map(|(path, entry)| (path.clone(), entry.clone()))
            .collect();
        let overlays: Vec<RepoPath> = if self.has(WorkspaceDefect::OmitsOverlays) {
            Vec::new()
        } else {
            visible
                .keys()
                .filter(|path| {
                    matches!(
                        self.classify(&req.rules, path),
                        Some(PathMode::DenyWrite | PathMode::AppendOnly)
                    )
                })
                .cloned()
                .collect()
        };
        let mounts = mounts_for(number, overlays, read_only);
        host.live_dirs.insert(mounts.workspace.clone());
        host.workspaces
            .insert(mounts.workspace.clone(), (req.job, req.attempt));
        let sandbox = if self.has(WorkspaceDefect::SharesOneTree) {
            let mut shared = self.one_tree.lock().expect("the lock is never poisoned");
            if shared.is_empty() {
                *shared = visible.clone();
            }
            drop(shared);
            Arc::clone(&self.one_tree)
        } else {
            Arc::new(Mutex::new(visible.clone()))
        };
        host.sandbox_trees
            .insert(mounts.workspace.clone(), Arc::clone(&sandbox));
        drop(host);
        Ok(Box::new(FakeWorkspace {
            provider: self.clone(),
            job: req.job,
            base: req.base,
            base_tree: object.tree,
            visible,
            rules: req.rules,
            sandbox,
            mounts,
            audited: Mutex::new(BTreeMap::new()),
        }))
    }

    async fn repo(&self, job: JobId) -> Result<Box<dyn JobRepo>, WorkspaceError> {
        let host = self.shared.lock().expect("the lock is never poisoned");
        if !host.jobs.contains_key(&job) {
            return Err(WorkspaceError::NotFetched);
        }
        Ok(Box::new(FakeJobRepo {
            provider: self.clone(),
            job,
        }))
    }

    async fn dispose_job(&self, job: JobId) -> Result<(), WorkspaceError> {
        let mut host = self.shared.lock().expect("the lock is never poisoned");
        host.jobs.remove(&job);
        let dirs: Vec<PathBuf> = host
            .workspaces
            .iter()
            .filter(|(_, (j, _))| *j == job)
            .map(|(d, _)| d.clone())
            .collect();
        for dir in dirs {
            host.live_dirs.remove(&dir);
            host.sandbox_trees.remove(&dir);
            host.workspaces.remove(&dir);
        }
        Ok(())
    }

    async fn sweep_orphans(
        &self,
        live: &[AttemptId],
        live_jobs: &[JobId],
    ) -> Result<Vec<AttemptId>, WorkspaceError> {
        let mut host = self.shared.lock().expect("the lock is never poisoned");
        let orphans: Vec<(PathBuf, AttemptId)> = host
            .workspaces
            .iter()
            .filter(|(_, (_, attempt))| !live.contains(attempt))
            .map(|(dir, (_, attempt))| (dir.clone(), *attempt))
            .collect();
        for (dir, _) in &orphans {
            host.live_dirs.remove(dir);
            host.sandbox_trees.remove(dir);
            host.workspaces.remove(dir);
        }
        host.jobs.retain(|job, _| live_jobs.contains(job));
        Ok(orphans.into_iter().map(|(_, attempt)| attempt).collect())
    }
}

// ---------------------------------------------------------------------------------------------
// The job's repository
// ---------------------------------------------------------------------------------------------

struct FakeJobRepo {
    provider: FakeWorkspaceProvider,
    job: JobId,
}

impl FakeJobRepo {
    fn object(&self, commit: &CommitSha) -> Result<CommitObject, WorkspaceError> {
        let host = self
            .provider
            .shared
            .lock()
            .expect("the lock is never poisoned");
        host.jobs
            .get(&self.job)
            .and_then(|store| store.commits.get(commit))
            .cloned()
            .ok_or(WorkspaceError::UnknownCommit)
    }

    fn hidden(&self, path: &RepoPath, view: ReadView) -> bool {
        view == ReadView::Agent
            && !self.provider.has(WorkspaceDefect::ShowsHiddenPaths)
            && self.provider.classify(&self.provider.rules, path) == Some(PathMode::Hidden)
    }
}

#[async_trait]
impl JobRepo for FakeJobRepo {
    async fn tree_of(
        &self,
        commit: &CommitSha,
    ) -> Result<factory_domain::values::GitSha, WorkspaceError> {
        // A fake's tree id: forty hex characters of the digest of the files, so two commits with
        // the same files have the same tree and a different file gives a different one.
        let object = self.object(commit)?;
        if self.provider.has(WorkspaceDefect::TreeIsTheCommit) {
            return factory_domain::values::GitSha::parse(commit.as_str())
                .map_err(|_| WorkspaceError::UnknownCommit);
        }
        factory_domain::values::GitSha::parse(&tree_digest(&object.tree).hex()[..40])
            .map_err(|_| WorkspaceError::UnknownCommit)
    }

    async fn read_file_at(
        &self,
        commit: &CommitSha,
        path: &RepoPath,
        max_bytes: u64,
        view: ReadView,
    ) -> Result<Vec<u8>, WorkspaceError> {
        let object = self.object(commit)?;
        if self.hidden(path, view) {
            return Err(WorkspaceError::PathNotFound(path.clone()));
        }
        let entry = if self.provider.has(WorkspaceDefect::ReadsFromSandboxTree) {
            // The defect: read what the sandbox wrote, from any workspace of the job.
            let host = self
                .provider
                .shared
                .lock()
                .expect("the lock is never poisoned");
            host.sandbox_trees
                .values()
                .find_map(|tree| {
                    tree.lock()
                        .expect("the lock is never poisoned")
                        .get(path)
                        .cloned()
                })
                .or_else(|| object.tree.get(path).cloned())
        } else {
            object.tree.get(path).cloned()
        };
        match entry {
            Some(Entry::File(bytes)) if bytes.len() as u64 > max_bytes => {
                Err(WorkspaceError::TooLarge)
            }
            Some(Entry::File(bytes)) => Ok(bytes),
            _ => Err(WorkspaceError::PathNotFound(path.clone())),
        }
    }

    async fn list_at(
        &self,
        commit: &CommitSha,
        glob: &RepoGlob,
        limit: usize,
        view: ReadView,
    ) -> Result<Vec<RepoPath>, WorkspaceError> {
        let object = self.object(commit)?;
        Ok(object
            .tree
            .iter()
            .filter(|(path, entry)| {
                matches!(entry, Entry::File(_)) && glob.matches(path) && !self.hidden(path, view)
            })
            .map(|(path, _)| path.clone())
            .take(limit)
            .collect())
    }

    async fn export_patch(
        &self,
        base: &CommitSha,
        head: &CommitSha,
        max_bytes: u64,
        cancel: &dyn CancelSignal,
    ) -> Result<PatchExport, WorkspaceError> {
        if cancel.is_cancelled() {
            return Err(WorkspaceError::Cancelled);
        }
        let before = self.object(base)?.tree;
        let after = self.object(head)?.tree;
        let changes = diff(&before, &after);
        let mut text = String::new();
        if self.provider.has(WorkspaceDefect::UnstablePatch) {
            let mut host = self
                .provider
                .shared
                .lock()
                .expect("the lock is never poisoned");
            host.patch_counter += 1;
            text.push_str(&format!("# generated {}\n", host.patch_counter));
        }
        for change in &changes {
            text.push_str(&format!("--- a/{0}\n+++ b/{0}\n", change.path));
            let old = file_text(before.get(&change.path));
            let new = file_text(after.get(&change.path));
            for line in old.lines() {
                text.push_str(&format!("-{line}\n"));
            }
            for line in new.lines() {
                text.push_str(&format!("+{line}\n"));
            }
        }
        if text.len() as u64 > max_bytes {
            return Err(WorkspaceError::TooLarge);
        }
        let media = MediaType::parse("text/x-diff").expect("a media type");
        let patch = self
            .provider
            .artifacts
            .put(text.into_bytes(), media)
            .await
            .map_err(|_| WorkspaceError::Io(factory_ports::workspace::IoOperation::Walk))?;
        Ok(PatchExport { patch, changes })
    }

    async fn push(
        &self,
        target: &PushTarget,
        commit: &CommitSha,
        cancel: &dyn CancelSignal,
    ) -> Result<(), WorkspaceError> {
        if cancel.is_cancelled() {
            return Err(WorkspaceError::Cancelled);
        }
        if !target.branch.is_factory_branch()
            && !self.provider.has(WorkspaceDefect::PushesAnyBranch)
        {
            return Err(WorkspaceError::BranchNotAllowed);
        }
        let object = self.object(commit)?;
        {
            let host = self
                .provider
                .shared
                .lock()
                .expect("the lock is never poisoned");
            let made = host
                .jobs
                .get(&self.job)
                .is_some_and(|store| store.made_here.contains(commit));
            if !made && !self.provider.has(WorkspaceDefect::PushesForeignCommit) {
                return Err(WorkspaceError::NotMadeHere);
            }
        }
        let remote = &self.provider.remote;
        let key = (target.repo.clone(), target.branch.clone());
        let extra = {
            let host = self
                .provider
                .shared
                .lock()
                .expect("the lock is never poisoned");
            host.jobs
                .get(&self.job)
                .map(|store| store.commits.clone())
                .unwrap_or_default()
        };
        let current = remote.branch_tip(&target.repo, &target.branch);
        if let Some(tip) = &current
            && tip != commit
            && !remote.is_ancestor(tip, commit, &extra)
        {
            return Err(WorkspaceError::NonFastForward);
        }
        let mut state = remote.state.lock().expect("the lock is never poisoned");
        // The push brings the commit and its parents that the remote lacks.
        let mut at = Some((commit.clone(), object));
        while let Some((sha, obj)) = at {
            let parent = obj.parent.clone();
            state.commits.entry(sha).or_insert(obj);
            at = parent.and_then(|p| extra.get(&p).cloned().map(|o| (p, o)));
        }
        state.branches.insert(key, commit.clone());
        Ok(())
    }
}

fn file_text(entry: Option<&Entry>) -> String {
    match entry {
        Some(Entry::File(bytes)) => String::from_utf8_lossy(bytes).into_owned(),
        _ => String::new(),
    }
}

/// The changed paths between two trees, sorted. A rename is a deletion and an addition.
fn diff(before: &Tree, after: &Tree) -> Vec<ChangedPath> {
    let mut changes = Vec::new();
    for (path, entry) in after {
        match before.get(path) {
            None => changes.push(ChangedPath {
                path: path.clone(),
                kind: ChangeKind::Added,
            }),
            Some(old) if old != entry => {
                changes.push(ChangedPath {
                    path: path.clone(),
                    kind: ChangeKind::Modified,
                });
            }
            Some(_) => {}
        }
    }
    for path in before.keys() {
        if !after.contains_key(path) {
            changes.push(ChangedPath {
                path: path.clone(),
                kind: ChangeKind::Deleted,
            });
        }
    }
    changes.sort();
    changes
}

// ---------------------------------------------------------------------------------------------
// The workspace
// ---------------------------------------------------------------------------------------------

struct FakeWorkspace {
    provider: FakeWorkspaceProvider,
    job: JobId,
    base: CommitSha,
    /// Every path of the base commit, hidden or not.
    base_tree: Tree,
    /// What the checkout started as: the base commit without the hidden paths.
    visible: Tree,
    rules: PathRules,
    sandbox: Arc<Mutex<Tree>>,
    mounts: WorkspaceMounts,
    audited: Mutex<BTreeMap<Sha256Digest, (Tree, Vec<ChangedPath>)>>,
}

fn kind_label(entry: &Entry) -> &'static str {
    match entry {
        Entry::File(_) => "file",
        Entry::Symlink(_) => "symlink",
        Entry::Gitlink => "gitlink",
        Entry::NestedGit => "nested-git",
    }
}

fn tree_digest(tree: &Tree) -> Sha256Digest {
    let mut listing = Vec::new();
    for (path, entry) in tree {
        listing.extend_from_slice(path.as_str().as_bytes());
        listing.push(0);
        listing.extend_from_slice(kind_label(entry).as_bytes());
        listing.push(0);
        match entry {
            Entry::File(bytes) => {
                listing.extend_from_slice(Sha256Digest::of(bytes).as_str().as_bytes())
            }
            Entry::Symlink(target) => listing.extend_from_slice(target.as_bytes()),
            Entry::Gitlink | Entry::NestedGit => {}
        }
        listing.push(b'\n');
    }
    Sha256Digest::of(&listing)
}

/// True when a link at `link` with the given `target` ends outside the workspace.
fn escapes(link: &RepoPath, target: &str) -> bool {
    if target.starts_with('/') {
        return true;
    }
    let mut stack: Vec<&str> = link.components().collect();
    stack.pop();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if stack.pop().is_none() {
                    return true;
                }
            }
            other => stack.push(other),
        }
    }
    false
}

/// True when `text` holds `prefix` followed by at least `min` characters from `allowed`.
fn has_token(text: &str, prefix: &str, min: usize, allowed: impl Fn(char) -> bool) -> bool {
    text.match_indices(prefix).any(|(at, _)| {
        text[at + prefix.len()..]
            .chars()
            .take_while(|c| allowed(*c))
            .count()
            >= min
    })
}

/// The rules that match a line of text. The names are the contract's `rule` field.
fn secret_rules(line: &str) -> Vec<&'static str> {
    let mut rules = Vec::new();
    if has_token(line, "ghs_", 36, |c| c.is_ascii_alphanumeric()) {
        rules.push("github-token");
    }
    if has_token(line, "sk-ant-", 20, |c| {
        c.is_ascii_alphanumeric() || c == '-' || c == '_'
    }) {
        rules.push("anthropic-key");
    }
    if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
        rules.push("private-key");
    }
    rules
}

/// True when every line of `old` appears in `new` in order: the file only gained lines.
fn only_gained_lines(old: &[u8], new: &[u8]) -> bool {
    let old = String::from_utf8_lossy(old);
    let new = String::from_utf8_lossy(new);
    let mut remaining = new.lines();
    old.lines()
        .all(|line| remaining.any(|candidate| candidate == line))
}

impl FakeWorkspace {
    fn has(&self, defect: WorkspaceDefect) -> bool {
        self.provider.has(defect)
    }

    /// The audit walk over the sandbox tree, the path modes, and the difference from the base.
    fn audit(&self, tree: &Tree) -> Result<(Vec<ChangedPath>, Vec<RepoPath>), WorkspaceError> {
        if !self.has(WorkspaceDefect::SkipsHiddenPathCheck)
            && let Some(path) = tree.keys().find(|path| {
                self.provider.classify(&self.rules, path) == Some(PathMode::Hidden)
                    && !self.visible.contains_key(path)
            })
        {
            return Err(WorkspaceError::HiddenPathPresent(path.clone()));
        }
        if !self.has(WorkspaceDefect::SkipsNestedGitCheck)
            && let Some(path) = tree
                .iter()
                .find(|(_, e)| matches!(e, Entry::NestedGit))
                .map(|(p, _)| p)
        {
            return Err(WorkspaceError::NestedGit(path.clone()));
        }
        if !self.has(WorkspaceDefect::SkipsGitlinkCheck)
            && let Some(path) = tree
                .iter()
                .find(|(_, e)| matches!(e, Entry::Gitlink))
                .map(|(p, _)| p)
        {
            return Err(WorkspaceError::Gitlink(path.clone()));
        }
        if !self.has(WorkspaceDefect::FollowsEscapingSymlinks) {
            for (path, entry) in tree {
                if let Entry::Symlink(target) = entry
                    && escapes(path, target)
                {
                    return Err(WorkspaceError::EscapingSymlink(path.clone()));
                }
            }
        }

        let mut changes = diff(&self.visible, tree);
        if self.has(WorkspaceDefect::MisreportsChangeKinds) {
            for change in &mut changes {
                if change.kind == ChangeKind::Added {
                    change.kind = ChangeKind::Modified;
                }
            }
        }

        let mut violations = Vec::new();
        let mut sensitive = Vec::new();
        for change in &changes {
            let mode = self.provider.classify(&self.rules, &change.path);
            let broke = match mode {
                _ if self.has(WorkspaceDefect::AllowsAnyEdit) => false,
                Some(PathMode::DenyWrite) => true,
                Some(PathMode::AppendOnly) => change.kind != ChangeKind::Added,
                Some(PathMode::AdditionsOnly)
                    if self.has(WorkspaceDefect::TreatsAdditionsOnlyAsFree) =>
                {
                    false
                }
                Some(PathMode::AdditionsOnly) => {
                    match (self.visible.get(&change.path), tree.get(&change.path)) {
                        (Some(Entry::File(old)), Some(Entry::File(new))) => {
                            !only_gained_lines(old, new)
                        }
                        (Some(_), _) => true,
                        (None, _) => false,
                    }
                }
                Some(PathMode::Hidden) | Some(PathMode::Sensitive) | None => false,
            };
            if broke {
                violations.push(PathViolation {
                    path: change.path.clone(),
                    mode: mode.unwrap_or(PathMode::DenyWrite),
                });
            }
            if mode == Some(PathMode::Sensitive) {
                sensitive.push(change.path.clone());
            }
        }
        if !violations.is_empty() {
            return Err(WorkspaceError::ProtectedPathChanged(violations));
        }

        if !self.has(WorkspaceDefect::SkipsSecretScan) {
            let mut findings = Vec::new();
            for change in &changes {
                let Some(Entry::File(bytes)) = tree.get(&change.path) else {
                    continue;
                };
                let text = String::from_utf8_lossy(bytes);
                for (index, line) in text.lines().enumerate() {
                    for rule in secret_rules(line) {
                        findings.push(Finding {
                            rule: Slug::parse(rule).expect("a rule name is a slug"),
                            path: Some(change.path.clone()),
                            line: u32::try_from(index + 1).ok(),
                        });
                    }
                }
            }
            if !findings.is_empty() {
                return Err(WorkspaceError::SecretFound(findings));
            }
        }
        Ok((changes, sensitive))
    }
}

#[async_trait]
impl Workspace for FakeWorkspace {
    fn mounts(&self) -> WorkspaceMounts {
        self.mounts.clone()
    }

    fn base(&self) -> &CommitSha {
        &self.base
    }

    async fn ingest(&self, cancel: &dyn CancelSignal) -> Result<IngestedChange, WorkspaceError> {
        if cancel.is_cancelled() && !self.has(WorkspaceDefect::IgnoresCancelOnIngest) {
            return Err(WorkspaceError::Cancelled);
        }
        let tree = self
            .sandbox
            .lock()
            .expect("the lock is never poisoned")
            .clone();
        let (changes, sensitive) = self.audit(&tree)?;
        let digest = tree_digest(&tree);
        self.audited
            .lock()
            .expect("the lock is never poisoned")
            .insert(digest.clone(), (tree, changes.clone()));
        Ok(IngestedChange::new(
            self.base.clone(),
            changes,
            sensitive,
            digest,
        ))
    }

    async fn commit(
        &self,
        change: &IngestedChange,
        req: CommitRequest,
    ) -> Result<CommitSha, WorkspaceError> {
        let audited = self
            .audited
            .lock()
            .expect("the lock is never poisoned")
            .get(change.tree())
            .cloned();
        let (tree, changes) = match audited {
            Some(found) => found,
            None if self.has(WorkspaceDefect::CommitsUnauditedChanges) => {
                let tree = self
                    .sandbox
                    .lock()
                    .expect("the lock is never poisoned")
                    .clone();
                let changes = diff(&self.visible, &tree);
                (tree, changes)
            }
            None => {
                return Err(WorkspaceError::Git {
                    operation: GitOperation::Commit,
                    exit: Some(1),
                });
            }
        };
        // The new commit is the base commit with the audited changes applied. Hidden paths of the
        // base stay in it, because the checkout never held them.
        let mut new_tree = if self.has(WorkspaceDefect::DropsHiddenPathsInCommit) {
            self.visible.clone()
        } else {
            self.base_tree.clone()
        };
        for change in &changes {
            match tree.get(&change.path) {
                Some(entry) => {
                    new_tree.insert(change.path.clone(), entry.clone());
                }
                None => {
                    new_tree.remove(&change.path);
                }
            }
        }
        let commit = sha_of(Some(&self.base), &new_tree, &req.message);
        let mut host = self
            .provider
            .shared
            .lock()
            .expect("the lock is never poisoned");
        let store = host.jobs.entry(self.job).or_default();
        store.commits.entry(commit.clone()).or_insert(CommitObject {
            tree: new_tree,
            parent: Some(self.base.clone()),
        });
        store.made_here.insert(commit.clone());
        store
            .made_by
            .insert(commit.clone(), self.mounts.workspace.clone());
        Ok(commit)
    }

    async fn dispose(self: Box<Self>) -> Result<(), WorkspaceError> {
        if self.has(WorkspaceDefect::LeavesDirectoriesOnDispose) {
            return Ok(());
        }
        let mut state = self
            .provider
            .shared
            .lock()
            .expect("the lock is never poisoned");
        state.live_dirs.remove(&self.mounts.workspace);
        state.sandbox_trees.remove(&self.mounts.workspace);
        state.workspaces.remove(&self.mounts.workspace);
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// The subject for the contract suite
// ---------------------------------------------------------------------------------------------

/// The fake workspace packaged as a subject of the workspace contract suite.
pub struct FakeWorkspaceSubject {
    provider: FakeWorkspaceProvider,
    remote: FakeRemote,
    repo: RepoRef,
    branch: BranchName,
}

impl FakeWorkspaceSubject {
    /// A faithful fake over the contract's fixture repository.
    #[must_use]
    pub fn new() -> Self {
        Self::build(None)
    }

    /// A fake that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(defect: WorkspaceDefect) -> Self {
        Self::build(Some(defect))
    }

    fn build(defect: Option<WorkspaceDefect>) -> Self {
        let repo = RepoRef::parse("example-org/fixture").expect("a valid repository");
        let branch = BranchName::new("main").expect("a valid branch");
        let remote = FakeRemote::new();
        remote.commit_on_branch(&repo, &branch, &crate::contracts::workspace::FIXTURE_FILES);
        let artifacts: Arc<dyn ArtifactStore> =
            Arc::new(crate::artifact::InMemoryArtifactStore::new());
        let rules = crate::contracts::workspace::fixture_rules();
        let provider = match defect {
            Some(defect) => FakeWorkspaceProvider::with_defect(
                repo.clone(),
                remote.clone(),
                artifacts,
                rules,
                defect,
            ),
            None => FakeWorkspaceProvider::new(repo.clone(), remote.clone(), artifacts, rules),
        };
        Self {
            provider,
            remote,
            repo,
            branch,
        }
    }
}

impl Default for FakeWorkspaceSubject {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WorkspaceSubject for FakeWorkspaceSubject {
    fn provider(&self) -> &dyn WorkspaceProvider {
        &self.provider
    }

    fn repo(&self) -> RepoRef {
        self.repo.clone()
    }

    fn branch(&self) -> BranchName {
        self.branch.clone()
    }

    async fn edit_sandbox_tree(
        &self,
        workspace: &dyn Workspace,
        edit: TreeEdit,
    ) -> Result<(), String> {
        self.provider.edit_tree(&workspace.mounts().workspace, edit)
    }

    async fn pushed_commit(&self, repo: &RepoRef, branch: &BranchName) -> Option<CommitSha> {
        self.provider.pushed_commit(repo, branch)
    }

    async fn directories_exist(&self, mounts: &WorkspaceMounts) -> bool {
        self.provider.directory_exists(&mounts.workspace)
    }

    async fn restart(&self) -> Box<dyn WorkspaceProvider> {
        Box::new(self.provider.restart())
    }

    async fn advance_remote_branch(&self, files: &[(&str, &str)]) -> CommitSha {
        self.remote
            .commit_on_branch(&self.repo, &self.branch, files)
    }

    async fn move_remote_branch_during_next_fetch(&self, files: &[(&str, &str)]) -> bool {
        self.remote
            .move_branch_during_next_fetch(&self.repo, &self.branch, files);
        true
    }
}
