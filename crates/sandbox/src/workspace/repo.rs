//! The job's object store: fetching into it, reading from it, exporting a patch, and pushing.
//!
//! Everything here runs host git against `store.git` and nothing else. No call names a path in a
//! checkout. A path the caller gives (`read_file_at`) is passed after `--` with literal pathspecs,
//! and the answer is the blob git finds in the commit, never a file on disk.

use std::sync::Arc;

use factory_domain::ids::JobId;
use factory_domain::values::{GitSha, MediaType};
use factory_ports::artifact::ArtifactError;
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{BranchName, CommitSha, PathMode, RepoGlob, RepoPath};
use factory_ports::process::EnvValue;
use factory_ports::workspace::{
    ChangeKind, ChangedPath, FetchTarget, FetchedBase, GitOperation, IoOperation, JobRepo,
    PatchExport, PushTarget, ReadView, WorkspaceError,
};

use super::RemoteLocation;
use super::audit::report_path;
use super::basetree::{TreeLine, parse_ls_tree};
use super::git::{Invocation, NoCancel, credential_env};
use super::layout::JobDirs;
use super::provider::Shared;
use crate::race::BoxFuture;

/// The ref that records a commit the factory made in this job. It keeps the commit alive and is
/// how `push` knows a commit is the factory's own.
pub(super) fn made_ref(commit: &CommitSha) -> String {
    format!("refs/factory/made/{}", commit.as_str())
}

fn fetched_ref(branch: &BranchName) -> String {
    format!("refs/factory/fetched/{}", branch.as_str())
}

/// True when the commit is in the store.
pub(super) async fn commit_exists(
    shared: &Shared,
    dirs: &JobDirs,
    commit: &CommitSha,
    cancel: &dyn CancelSignal,
) -> Result<bool, WorkspaceError> {
    let spec = format!("{}^{{commit}}", commit.as_str());
    let out = shared
        .git
        .run(
            GitOperation::Read,
            Invocation::new(&dirs.store, &dirs.dir, &["cat-file", "-e", &spec]),
            cancel,
        )
        .await?;
    Ok(out.exit_code == Some(0))
}

/// True when `ancestor` is `descendant` or one of its ancestors in the store. Git answers 0 for
/// yes and 1 for no; any other answer is a failure, never a yes.
pub(super) async fn is_ancestor(
    shared: &Shared,
    dirs: &JobDirs,
    ancestor: &CommitSha,
    descendant: &CommitSha,
    cancel: &dyn CancelSignal,
) -> Result<bool, WorkspaceError> {
    let out = shared
        .git
        .run(
            GitOperation::Read,
            Invocation::new(
                &dirs.store,
                &dirs.dir,
                &[
                    "merge-base",
                    "--is-ancestor",
                    ancestor.as_str(),
                    descendant.as_str(),
                ],
            ),
            cancel,
        )
        .await?;
    match out.exit_code {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        exit => Err(WorkspaceError::Git {
            operation: GitOperation::Read,
            exit,
        }),
    }
}

/// Makes the store when the job has none.
async fn ensure_store(
    shared: &Shared,
    dirs: &JobDirs,
    cancel: &dyn CancelSignal,
) -> Result<(), WorkspaceError> {
    if dirs.has_store() {
        return Ok(());
    }
    std::fs::create_dir_all(&dirs.attempts)
        .map_err(|_| WorkspaceError::Io(IoOperation::CreateDirectory))?;
    let name = "store.git";
    let inv = Invocation {
        git_dir: None,
        ..Invocation::new(
            &dirs.store,
            &dirs.dir,
            &["init", "--bare", "--quiet", "--template=", name],
        )
    };
    shared
        .git
        .run_ok(GitOperation::Fetch, inv, cancel)
        .await
        .map(drop)?;
    if dirs.has_store() {
        Ok(())
    } else {
        Err(WorkspaceError::Io(IoOperation::CreateDirectory))
    }
}

fn credential(shared: &Shared, secret: &str) -> Vec<(String, EnvValue)> {
    match shared.settings.remote {
        RemoteLocation::Https { .. } => credential_env(secret),
        RemoteLocation::Directory { .. } => Vec::new(),
    }
}

fn looks_unauthorized(stderr: &[u8]) -> bool {
    let text = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    [
        "authentication failed",
        "invalid credentials",
        "could not read username",
        "terminal prompts disabled",
        "permission denied",
        "returned error: 401",
        "returned error: 403",
        "http 401",
        "http 403",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

/// The commit the remote branch points at, `None` when the remote has no such branch.
async fn remote_tip(
    shared: &Shared,
    dirs: &JobDirs,
    url: &str,
    env: &[(String, EnvValue)],
    branch: &BranchName,
    cancel: &dyn CancelSignal,
) -> Result<Option<String>, WorkspaceError> {
    let reference = format!("refs/heads/{}", branch.as_str());
    let mut inv = Invocation::new(
        &dirs.store,
        &dirs.dir,
        &["ls-remote", "--exit-code", "--", url, &reference],
    )
    .over_network();
    inv.env.extend(env.iter().cloned());
    let out = shared.git.run(GitOperation::Fetch, inv, cancel).await?;
    match out.exit_code {
        Some(0) => {
            let text = String::from_utf8_lossy(&out.stdout);
            let tip = text
                .lines()
                .find(|line| line.ends_with(&reference))
                .and_then(|line| line.split_whitespace().next())
                .map(str::to_owned);
            Ok(tip)
        }
        Some(2) => Ok(None),
        _ if looks_unauthorized(&out.stderr) => Err(WorkspaceError::Unauthorized),
        exit => Err(WorkspaceError::Git {
            operation: GitOperation::Fetch,
            exit,
        }),
    }
}

/// Fetches one branch into the job's store.
pub(super) async fn fetch_branch(
    shared: &Shared,
    job: JobId,
    target: &FetchTarget,
    branch: &BranchName,
    cancel: &dyn CancelSignal,
) -> Result<FetchedBase, WorkspaceError> {
    if cancel.is_cancelled() {
        return Err(WorkspaceError::Cancelled);
    }
    let dirs = shared.job_dirs(job);
    ensure_store(shared, &dirs, cancel).await?;
    let url = shared.settings.remote.url(&target.repo);
    let env = credential(shared, target.credential.expose());
    let refspec = format!("+refs/heads/{}:{}", branch.as_str(), fetched_ref(branch));
    let mut inv = Invocation::new(
        &dirs.store,
        &dirs.dir,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-recurse-submodules",
            "--no-write-fetch-head",
            "--no-auto-gc",
            "--force",
            "--",
            &url,
            &refspec,
        ],
    )
    .over_network();
    inv.env.extend(env.iter().cloned());
    let out = shared.git.run(GitOperation::Fetch, inv, cancel).await?;
    if out.exit_code != Some(0) {
        if looks_unauthorized(&out.stderr) {
            return Err(WorkspaceError::Unauthorized);
        }
        // Tell a branch the remote does not have apart from a fetch that failed for another reason.
        return match remote_tip(shared, &dirs, &url, &env, branch, cancel).await? {
            None => Err(WorkspaceError::UnknownCommit),
            Some(_) => Err(WorkspaceError::Git {
                operation: GitOperation::Fetch,
                exit: out.exit_code,
            }),
        };
    }
    let spec = format!("{}^{{commit}}", fetched_ref(branch));
    let tip = shared
        .git
        .run_ok(
            GitOperation::Fetch,
            Invocation::new(
                &dirs.store,
                &dirs.dir,
                &["rev-parse", "--verify", "--quiet", &spec],
            ),
            cancel,
        )
        .await?;
    let fetched = String::from_utf8_lossy(&tip).trim().to_owned();
    // The tip must still be the remote's: a branch that moved while it was fetched is not a base.
    let now = remote_tip(shared, &dirs, &url, &env, branch, cancel).await?;
    if now.as_deref() != Some(fetched.as_str()) {
        return Err(WorkspaceError::BaseMoved);
    }
    let commit = CommitSha::parse(&fetched).map_err(|_| WorkspaceError::Git {
        operation: GitOperation::Fetch,
        exit: None,
    })?;
    Ok(FetchedBase {
        branch: branch.clone(),
        commit,
    })
}

/// One line of `git diff-tree -r -z --raw`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RawChange {
    pub old_mode: String,
    pub new_mode: String,
    pub old_sha: String,
    pub new_sha: String,
    pub status: char,
    pub path: Vec<u8>,
}

impl RawChange {
    pub(super) fn kind(&self) -> ChangeKind {
        match self.status {
            'A' => ChangeKind::Added,
            'D' => ChangeKind::Deleted,
            _ => ChangeKind::Modified,
        }
    }
}

/// Parses `git diff-tree -r -z --raw --no-renames --no-abbrev`. `None` when the output is not in
/// the shape git documents.
pub(super) fn parse_raw_diff(output: &[u8]) -> Option<Vec<RawChange>> {
    let mut changes = Vec::new();
    let mut fields = output.split(|b| *b == 0).filter(|f| !f.is_empty());
    while let Some(meta) = fields.next() {
        let meta = std::str::from_utf8(meta).ok()?.strip_prefix(':')?;
        let path = fields.next()?;
        let mut parts = meta.split_whitespace();
        let old_mode = parts.next()?.to_owned();
        let new_mode = parts.next()?.to_owned();
        let old_sha = parts.next()?.to_owned();
        let new_sha = parts.next()?.to_owned();
        let status = parts.next()?.chars().next()?;
        changes.push(RawChange {
            old_mode,
            new_mode,
            old_sha,
            new_sha,
            status,
            path: path.to_vec(),
        });
    }
    Some(changes)
}

/// The object store of one job, for reads, patches and pushes.
pub struct GitJobRepo {
    shared: Arc<Shared>,
    dirs: JobDirs,
}

impl GitJobRepo {
    pub(super) fn new(shared: Arc<Shared>, dirs: JobDirs) -> Self {
        Self { shared, dirs }
    }

    async fn require_commit(
        &self,
        commit: &CommitSha,
        cancel: &dyn CancelSignal,
    ) -> Result<(), WorkspaceError> {
        if commit_exists(&self.shared, &self.dirs, commit, cancel).await? {
            Ok(())
        } else {
            Err(WorkspaceError::UnknownCommit)
        }
    }

    async fn tree_lines(
        &self,
        commit: &CommitSha,
        args: &[&str],
        max_output: u64,
    ) -> Result<Vec<TreeLine>, WorkspaceError> {
        let mut full = vec!["ls-tree", "-z", "--long"];
        full.extend_from_slice(args);
        full.push(commit.as_str());
        let inv =
            Invocation::new(&self.dirs.store, &self.dirs.dir, &full).with_max_output(max_output);
        let out = self
            .shared
            .git
            .run_ok(GitOperation::Read, inv, &NoCancel)
            .await?;
        parse_ls_tree(&out).ok_or(WorkspaceError::Git {
            operation: GitOperation::Read,
            exit: None,
        })
    }

    async fn read(
        &self,
        commit: &CommitSha,
        path: &RepoPath,
        max_bytes: u64,
        view: ReadView,
    ) -> Result<Vec<u8>, WorkspaceError> {
        self.require_commit(commit, &NoCancel).await?;
        if view == ReadView::Agent
            && self.shared.view_rules.classify(path) == Some(PathMode::Hidden)
        {
            return Err(WorkspaceError::PathNotFound(path.clone()));
        }
        let inv = Invocation::new(
            &self.dirs.store,
            &self.dirs.dir,
            &[
                "ls-tree",
                "-z",
                "--long",
                commit.as_str(),
                "--",
                path.as_str(),
            ],
        );
        let listing = self
            .shared
            .git
            .run_ok(GitOperation::Read, inv, &NoCancel)
            .await?;
        let lines = parse_ls_tree(&listing).ok_or(WorkspaceError::Git {
            operation: GitOperation::Read,
            exit: None,
        })?;
        let entry = lines
            .into_iter()
            .find(|line| line.path == path.as_str().as_bytes())
            .filter(|line| line.kind == "blob")
            .ok_or_else(|| WorkspaceError::PathNotFound(path.clone()))?;
        let size = entry.size.unwrap_or(0);
        if size > max_bytes {
            return Err(WorkspaceError::TooLarge);
        }
        let inv = Invocation::new(
            &self.dirs.store,
            &self.dirs.dir,
            &["cat-file", "blob", &entry.sha],
        )
        // The size git reported bounds the read: a blob that is bigger than it said is cut and
        // refused, never returned.
        .with_max_output(size.max(1));
        self.shared
            .git
            .run_ok(GitOperation::Read, inv, &NoCancel)
            .await
    }

    async fn tree(&self, commit: &CommitSha) -> Result<GitSha, WorkspaceError> {
        self.require_commit(commit, &NoCancel).await?;
        let spec = format!("{}^{{tree}}", commit.as_str());
        let inv = Invocation::new(
            &self.dirs.store,
            &self.dirs.dir,
            &["rev-parse", "--verify", "--quiet", &spec],
        );
        let out = self
            .shared
            .git
            .run_ok(GitOperation::Read, inv, &NoCancel)
            .await?;
        let text = String::from_utf8_lossy(&out);
        GitSha::parse(text.trim()).map_err(|_| WorkspaceError::Git {
            operation: GitOperation::Read,
            exit: None,
        })
    }

    async fn list(
        &self,
        commit: &CommitSha,
        glob: &RepoGlob,
        limit: usize,
        view: ReadView,
    ) -> Result<Vec<RepoPath>, WorkspaceError> {
        self.require_commit(commit, &NoCancel).await?;
        let lines = self
            .tree_lines(commit, &["-r"], self.shared.settings.max_listing_bytes)
            .await?;
        let mut found: Vec<RepoPath> = lines
            .into_iter()
            .filter(|line| line.kind == "blob")
            .filter_map(|line| String::from_utf8(line.path).ok())
            .filter_map(|text| RepoPath::new(&text).ok())
            .filter(|path| glob.matches(path))
            .filter(|path| {
                view == ReadView::Trusted
                    || self.shared.view_rules.classify(path) != Some(PathMode::Hidden)
            })
            .collect();
        found.sort();
        found.truncate(limit);
        Ok(found)
    }

    async fn export(
        &self,
        base: &CommitSha,
        head: &CommitSha,
        max_bytes: u64,
        cancel: &dyn CancelSignal,
    ) -> Result<PatchExport, WorkspaceError> {
        if cancel.is_cancelled() {
            return Err(WorkspaceError::Cancelled);
        }
        self.require_commit(base, cancel).await?;
        self.require_commit(head, cancel).await?;
        let git = &self.shared.git;
        let raw = git
            .run_ok(
                GitOperation::Diff,
                Invocation::new(
                    &self.dirs.store,
                    &self.dirs.dir,
                    &[
                        "diff-tree",
                        "-r",
                        "-z",
                        "--raw",
                        "--no-renames",
                        "--no-abbrev",
                        base.as_str(),
                        head.as_str(),
                    ],
                )
                .with_max_output(self.shared.settings.max_listing_bytes),
                cancel,
            )
            .await?;
        let mut changes: Vec<ChangedPath> = parse_raw_diff(&raw)
            .ok_or(WorkspaceError::Git {
                operation: GitOperation::Diff,
                exit: None,
            })?
            .iter()
            .map(|c| ChangedPath {
                path: report_path(&c.path),
                kind: c.kind(),
            })
            .collect();
        changes.sort();
        // Binary-safe and byte for byte the same for the same two commits: no color, no external
        // diff driver, no text conversion, no rename detection, full object ids, three lines of
        // context.
        let out = git
            .run(
                GitOperation::Diff,
                Invocation::new(
                    &self.dirs.store,
                    &self.dirs.dir,
                    &[
                        "diff",
                        "--binary",
                        "--full-index",
                        "--no-color",
                        "--no-ext-diff",
                        "--no-textconv",
                        "--no-renames",
                        "--src-prefix=a/",
                        "--dst-prefix=b/",
                        "-U3",
                        base.as_str(),
                        head.as_str(),
                        "--",
                    ],
                )
                .with_max_output(max_bytes.saturating_add(1)),
                cancel,
            )
            .await?;
        if out.exit_code != Some(0) {
            return Err(WorkspaceError::Git {
                operation: GitOperation::Diff,
                exit: out.exit_code,
            });
        }
        if out.truncated || out.stdout.len() as u64 > max_bytes {
            return Err(WorkspaceError::TooLarge);
        }
        let media = MediaType::parse("text/x-diff").map_err(|_| WorkspaceError::Git {
            operation: GitOperation::Diff,
            exit: None,
        })?;
        let patch =
            self.shared
                .artifacts
                .put(out.stdout, media)
                .await
                .map_err(|error| match error {
                    ArtifactError::TooLarge { .. } => WorkspaceError::TooLarge,
                    _ => WorkspaceError::Io(IoOperation::CreateDirectory),
                })?;
        Ok(PatchExport { patch, changes })
    }

    async fn push_commit(
        &self,
        target: &PushTarget,
        commit: &CommitSha,
        cancel: &dyn CancelSignal,
    ) -> Result<(), WorkspaceError> {
        if cancel.is_cancelled() {
            return Err(WorkspaceError::Cancelled);
        }
        if !target.branch.is_factory_branch() {
            return Err(WorkspaceError::BranchNotAllowed);
        }
        self.require_commit(commit, cancel).await?;
        let made = self
            .shared
            .git
            .run(
                GitOperation::Push,
                Invocation::new(
                    &self.dirs.store,
                    &self.dirs.dir,
                    &["rev-parse", "--verify", "--quiet", &made_ref(commit)],
                ),
                cancel,
            )
            .await?;
        if made.exit_code != Some(0) {
            return Err(WorkspaceError::NotMadeHere);
        }
        let url = self.shared.settings.remote.url(&target.repo);
        let refspec = format!("{}:refs/heads/{}", commit.as_str(), target.branch.as_str());
        let mut inv = Invocation::new(
            &self.dirs.store,
            &self.dirs.dir,
            &[
                "push",
                "--porcelain",
                "--no-follow-tags",
                "--no-recurse-submodules",
                "--no-verify",
                "--",
                &url,
                &refspec,
            ],
        )
        .over_network();
        inv.env
            .extend(credential(&self.shared, target.credential.expose()));
        let out = self.shared.git.run(GitOperation::Push, inv, cancel).await?;
        if out.exit_code == Some(0) {
            return Ok(());
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.lines().any(|line| {
            line.starts_with('!')
                && (line.contains("non-fast-forward")
                    || line.contains("fetch first")
                    || line.contains("already exists"))
        }) {
            return Err(WorkspaceError::NonFastForward);
        }
        if looks_unauthorized(&out.stderr) {
            return Err(WorkspaceError::Unauthorized);
        }
        Err(WorkspaceError::Git {
            operation: GitOperation::Push,
            exit: out.exit_code,
        })
    }
}

impl JobRepo for GitJobRepo {
    // The signatures `#[async_trait]` would write; see `crate::race`.
    fn read_file_at<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        commit: &'life1 CommitSha,
        path: &'life2 RepoPath,
        max_bytes: u64,
        view: ReadView,
    ) -> BoxFuture<'async_trait, Result<Vec<u8>, WorkspaceError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.read(commit, path, max_bytes, view))
    }

    fn list_at<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        commit: &'life1 CommitSha,
        glob: &'life2 RepoGlob,
        limit: usize,
        view: ReadView,
    ) -> BoxFuture<'async_trait, Result<Vec<RepoPath>, WorkspaceError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.list(commit, glob, limit, view))
    }

    fn export_patch<'life0, 'life1, 'life2, 'life3, 'async_trait>(
        &'life0 self,
        base: &'life1 CommitSha,
        head: &'life2 CommitSha,
        max_bytes: u64,
        cancel: &'life3 dyn CancelSignal,
    ) -> BoxFuture<'async_trait, Result<PatchExport, WorkspaceError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.export(base, head, max_bytes, cancel))
    }

    fn push<'life0, 'life1, 'life2, 'life3, 'async_trait>(
        &'life0 self,
        target: &'life1 PushTarget,
        commit: &'life2 CommitSha,
        cancel: &'life3 dyn CancelSignal,
    ) -> BoxFuture<'async_trait, Result<(), WorkspaceError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.push_commit(target, commit, cancel))
    }

    fn tree_of<'life0, 'life1, 'async_trait>(
        &'life0 self,
        commit: &'life1 CommitSha,
    ) -> BoxFuture<'async_trait, Result<GitSha, WorkspaceError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.tree(commit))
    }
}
