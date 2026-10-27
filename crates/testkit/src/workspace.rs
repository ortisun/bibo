//! A workspace that keeps a repository in memory and runs no git.
//!
//! The repository is a set of commits, each a map from path to entry. A workspace has two views
//! of it. The **trusted** view is the base commit in the object store, which `read_base_file` and
//! `list_base` read. The **sandbox** view is a writable copy that a test edits through
//! [`FakeWorkspaceProvider::edit_tree`], as the sandbox would. `ingest` audits the second against
//! the first and refuses what the real ingestion refuses: a hidden path, a nested git directory,
//! a gitlink, a symbolic link that leaves the workspace, a change to a protected path and a
//! secret. `commit` accepts only a change that `ingest` returned, and `push` accepts only a
//! commit the workspace made and only a branch under `factory/`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::values::{Sha256Digest, Slug};
use factory_domain::vocabulary::Fidelity;
use factory_ports::paths::{BranchName, CommitSha, Finding, RepoGlob, RepoPath, RepoRef};
use factory_ports::workspace::{
    ChangeKind, ChangedPath, CommitRequest, IngestedChange, PushTarget, Workspace, WorkspaceError,
    WorkspaceMounts, WorkspaceProvider, WorkspaceRequest,
};

use crate::contracts::workspace::{TreeEdit, WorkspaceSubject};

/// A deliberate fault, for proving that the contract suite can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceDefect {
    /// `read_base_file` reads the sandbox-writable tree, not the base commit.
    ReadsFromSandboxTree,
    /// Hidden paths are listed and readable.
    ShowsHiddenPaths,
    /// Ingestion does not look for hidden paths in the tree.
    SkipsHiddenPathCheck,
    /// Ingestion does not refuse a change to a protected path.
    SkipsProtectedPathCheck,
    /// Ingestion accepts a symbolic link that points outside the workspace.
    FollowsEscapingSymlinks,
    /// Ingestion does not scan for secrets.
    SkipsSecretScan,
    /// `push` accepts any branch.
    PushesAnyBranch,
    /// `commit` accepts a change that `ingest` never returned.
    CommitsUnauditedChanges,
    /// Every workspace shares one sandbox tree.
    SharesOneTree,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    File(Vec<u8>),
    Symlink(String),
    Gitlink,
    /// A directory that holds a `.git` directory of its own.
    NestedGit,
}

type Tree = BTreeMap<RepoPath, Entry>;

#[derive(Default)]
struct Repo {
    commits: BTreeMap<CommitSha, Tree>,
    remote: BTreeMap<(RepoRef, BranchName), CommitSha>,
    live_dirs: BTreeSet<PathBuf>,
    sandbox_trees: BTreeMap<PathBuf, Arc<Mutex<Tree>>>,
    next: u64,
}

/// A workspace provider over an in-memory repository. Reports fidelity `fake`.
#[derive(Clone)]
pub struct FakeWorkspaceProvider {
    repo: RepoRef,
    shared: Arc<Mutex<Repo>>,
    one_tree: Arc<Mutex<Tree>>,
    defect: Option<WorkspaceDefect>,
}

impl FakeWorkspaceProvider {
    /// A provider for `repo` whose `base` commit holds `files` (path and text).
    ///
    /// # Panics
    /// Panics when a path in `files` is not a valid repository path. This is test code.
    #[must_use]
    pub fn new(repo: RepoRef, base: CommitSha, files: &[(&str, &str)]) -> Self {
        Self::build(repo, base, files, None)
    }

    /// A provider that breaks one rule of the contract on purpose.
    ///
    /// # Panics
    /// Panics when a path in `files` is not a valid repository path. This is test code.
    #[must_use]
    pub fn with_defect(
        repo: RepoRef,
        base: CommitSha,
        files: &[(&str, &str)],
        defect: WorkspaceDefect,
    ) -> Self {
        Self::build(repo, base, files, Some(defect))
    }

    fn build(
        repo: RepoRef,
        base: CommitSha,
        files: &[(&str, &str)],
        defect: Option<WorkspaceDefect>,
    ) -> Self {
        let tree: Tree = files
            .iter()
            .map(|(path, text)| {
                (
                    RepoPath::new(path).expect("a valid fixture path"),
                    Entry::File(text.as_bytes().to_vec()),
                )
            })
            .collect();
        let mut state = Repo::default();
        state.commits.insert(base, tree);
        Self {
            repo,
            shared: Arc::new(Mutex::new(state)),
            one_tree: Arc::new(Mutex::new(Tree::new())),
            defect,
        }
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
        self.shared
            .lock()
            .expect("the lock is never poisoned")
            .remote
            .get(&(repo.clone(), branch.clone()))
            .cloned()
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
}

#[async_trait]
impl WorkspaceProvider for FakeWorkspaceProvider {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn create(&self, req: WorkspaceRequest) -> Result<Box<dyn Workspace>, WorkspaceError> {
        if req.repo != self.repo {
            return Err(WorkspaceError::Git(format!(
                "the repository {} is not available",
                req.repo
            )));
        }
        let mut state = self.shared.lock().expect("the lock is never poisoned");
        let base_tree = state.commits.get(&req.base).cloned().ok_or_else(|| {
            WorkspaceError::Git("the base commit is not in the object store".to_owned())
        })?;
        state.next += 1;
        let number = state.next;
        let workspace_dir = PathBuf::from(format!("/fake/workspace-{number}/worktree"));
        let out_dir = PathBuf::from(format!("/fake/workspace-{number}/out"));
        state.live_dirs.insert(workspace_dir.clone());

        let hidden_in_base = |path: &RepoPath| req.hidden.iter().any(|glob| glob.matches(path));
        let visible: Tree = base_tree
            .iter()
            .filter(|(path, _)| !hidden_in_base(path))
            .map(|(path, entry)| (path.clone(), entry.clone()))
            .collect();
        let overlays: Vec<RepoPath> = base_tree
            .keys()
            .filter(|path| req.protected.iter().any(|glob| glob.matches(path)))
            .cloned()
            .collect();
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
        state
            .sandbox_trees
            .insert(workspace_dir.clone(), Arc::clone(&sandbox));
        drop(state);

        Ok(Box::new(FakeWorkspace {
            provider: self.clone(),
            base: req.base,
            base_tree,
            visible,
            hidden: req.hidden,
            protected: req.protected,
            sandbox,
            mounts: WorkspaceMounts {
                workspace: workspace_dir,
                out: out_dir,
                protected_overlays: overlays,
                git_masked: true,
            },
            audited: Mutex::new(BTreeMap::new()),
            made: Mutex::new(BTreeSet::new()),
        }))
    }
}

struct FakeWorkspace {
    provider: FakeWorkspaceProvider,
    base: CommitSha,
    /// Every path of the base commit, hidden or not: the trusted object store.
    base_tree: Tree,
    /// The base commit minus the hidden paths: what the checkout started as.
    visible: Tree,
    hidden: Vec<RepoGlob>,
    protected: Vec<RepoGlob>,
    sandbox: Arc<Mutex<Tree>>,
    mounts: WorkspaceMounts,
    audited: Mutex<BTreeMap<Sha256Digest, Tree>>,
    made: Mutex<BTreeSet<CommitSha>>,
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

impl FakeWorkspace {
    fn has(&self, defect: WorkspaceDefect) -> bool {
        self.provider.has(defect)
    }

    fn is_hidden(&self, path: &RepoPath) -> bool {
        self.hidden.iter().any(|glob| glob.matches(path))
    }

    fn is_protected(&self, path: &RepoPath) -> bool {
        self.protected.iter().any(|glob| glob.matches(path))
    }

    /// The audit walk over the sandbox tree, and the difference from the base.
    fn audit(&self, tree: &Tree) -> Result<Vec<ChangedPath>, WorkspaceError> {
        if !self.has(WorkspaceDefect::SkipsHiddenPathCheck)
            && let Some(path) = tree.keys().find(|path| self.is_hidden(path))
        {
            return Err(WorkspaceError::HiddenPathPresent(path.clone()));
        }
        for (path, entry) in tree {
            if matches!(entry, Entry::NestedGit) {
                return Err(WorkspaceError::NestedGit(path.clone()));
            }
        }
        for (path, entry) in tree {
            if matches!(entry, Entry::Gitlink) {
                return Err(WorkspaceError::Gitlink(path.clone()));
            }
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

        let mut changes = Vec::new();
        for (path, entry) in tree {
            match self.visible.get(path) {
                None => changes.push(ChangedPath {
                    path: path.clone(),
                    kind: ChangeKind::Added,
                }),
                Some(before) if before != entry => changes.push(ChangedPath {
                    path: path.clone(),
                    kind: ChangeKind::Modified,
                }),
                Some(_) => {}
            }
        }
        for path in self.visible.keys() {
            if !tree.contains_key(path) {
                changes.push(ChangedPath {
                    path: path.clone(),
                    kind: ChangeKind::Deleted,
                });
            }
        }
        changes.sort();

        if !self.has(WorkspaceDefect::SkipsProtectedPathCheck) {
            let protected: Vec<RepoPath> = changes
                .iter()
                .filter(|change| self.is_protected(&change.path))
                .map(|change| change.path.clone())
                .collect();
            if !protected.is_empty() {
                return Err(WorkspaceError::ProtectedPathChanged(protected));
            }
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
        Ok(changes)
    }
}

#[async_trait]
impl Workspace for FakeWorkspace {
    fn mounts(&self) -> WorkspaceMounts {
        self.mounts.clone()
    }

    async fn read_base_file(
        &self,
        path: &RepoPath,
        max_bytes: u64,
    ) -> Result<Vec<u8>, WorkspaceError> {
        let entry = if self.has(WorkspaceDefect::ReadsFromSandboxTree) {
            self.sandbox
                .lock()
                .expect("the lock is never poisoned")
                .get(path)
                .cloned()
        } else if self.has(WorkspaceDefect::ShowsHiddenPaths) {
            self.base_tree.get(path).cloned()
        } else if self.is_hidden(path) {
            None
        } else {
            self.base_tree.get(path).cloned()
        };
        match entry {
            Some(Entry::File(bytes)) => {
                if bytes.len() as u64 > max_bytes {
                    Err(WorkspaceError::TooLarge)
                } else {
                    Ok(bytes)
                }
            }
            _ => Err(WorkspaceError::PathNotFound(path.clone())),
        }
    }

    async fn list_base(
        &self,
        glob: &RepoGlob,
        limit: usize,
    ) -> Result<Vec<RepoPath>, WorkspaceError> {
        let source = if self.has(WorkspaceDefect::ShowsHiddenPaths) {
            &self.base_tree
        } else {
            &self.visible
        };
        Ok(source
            .iter()
            .filter(|(path, entry)| matches!(entry, Entry::File(_)) && glob.matches(path))
            .map(|(path, _)| path.clone())
            .take(limit)
            .collect())
    }

    async fn ingest(&self, base: &CommitSha) -> Result<IngestedChange, WorkspaceError> {
        if *base != self.base {
            return Err(WorkspaceError::Git(
                "the base is not the commit this workspace was made from".to_owned(),
            ));
        }
        let tree = self
            .sandbox
            .lock()
            .expect("the lock is never poisoned")
            .clone();
        let changes = self.audit(&tree)?;
        let digest = tree_digest(&tree);
        self.audited
            .lock()
            .expect("the lock is never poisoned")
            .insert(digest.clone(), tree);
        Ok(IngestedChange::new(self.base.clone(), changes, digest))
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
        let tree = match audited {
            Some(tree) => tree,
            None if self.has(WorkspaceDefect::CommitsUnauditedChanges) => self
                .sandbox
                .lock()
                .expect("the lock is never poisoned")
                .clone(),
            None => {
                return Err(WorkspaceError::Git(
                    "the change was not ingested by this workspace".to_owned(),
                ));
            }
        };
        let mut seed = Vec::new();
        seed.extend_from_slice(self.base.as_str().as_bytes());
        seed.extend_from_slice(tree_digest(&tree).as_str().as_bytes());
        seed.extend_from_slice(req.message.as_bytes());
        let hash = Sha256Digest::of(&seed);
        let commit = CommitSha::parse(&hash.hex()[..40])
            .map_err(|_| WorkspaceError::Git("could not form a commit id".to_owned()))?;
        self.provider
            .shared
            .lock()
            .expect("the lock is never poisoned")
            .commits
            .insert(commit.clone(), tree);
        self.made
            .lock()
            .expect("the lock is never poisoned")
            .insert(commit.clone());
        Ok(commit)
    }

    async fn push(&self, target: &PushTarget, commit: &CommitSha) -> Result<(), WorkspaceError> {
        if !target.branch.is_factory_branch() && !self.has(WorkspaceDefect::PushesAnyBranch) {
            return Err(WorkspaceError::BranchNotAllowed);
        }
        if !self
            .made
            .lock()
            .expect("the lock is never poisoned")
            .contains(commit)
        {
            return Err(WorkspaceError::Git(
                "the commit was not made by this workspace".to_owned(),
            ));
        }
        self.provider
            .shared
            .lock()
            .expect("the lock is never poisoned")
            .remote
            .insert((target.repo.clone(), target.branch.clone()), commit.clone());
        Ok(())
    }

    async fn dispose(self: Box<Self>) -> Result<(), WorkspaceError> {
        let mut state = self
            .provider
            .shared
            .lock()
            .expect("the lock is never poisoned");
        state.live_dirs.remove(&self.mounts.workspace);
        state.sandbox_trees.remove(&self.mounts.workspace);
        Ok(())
    }
}

/// The fake workspace packaged as a subject of the workspace contract suite.
pub struct FakeWorkspaceSubject {
    provider: FakeWorkspaceProvider,
    repo: RepoRef,
    base: CommitSha,
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
        let base = CommitSha::parse(&"0123456789".repeat(4)).expect("a valid commit id");
        let files = crate::contracts::workspace::FIXTURE_FILES;
        let provider = match defect {
            Some(defect) => {
                FakeWorkspaceProvider::with_defect(repo.clone(), base.clone(), &files, defect)
            }
            None => FakeWorkspaceProvider::new(repo.clone(), base.clone(), &files),
        };
        Self {
            provider,
            repo,
            base,
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

    fn base(&self) -> CommitSha {
        self.base.clone()
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
}
