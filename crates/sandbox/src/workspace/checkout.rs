//! Making the attempt's directories: the checkout, the output directory and the private
//! directory, from a commit in the job's store.
//!
//! The files are written by this module from blobs that `git cat-file --batch` prints, each with
//! `create_new` (it fails on anything that exists, a link included) and into directories this
//! module made a moment earlier. Git is never given the checkout as a work tree, a working
//! directory or an argument: it cannot be tricked into writing through a link, and no attribute,
//! filter or line-ending rule of the repository touches the bytes.
//!
//! Before the sandbox exists, the mount points it needs exist: the empty file `.git` that the mask
//! covers, and every file a protected overlay covers (the files themselves, which are in the
//! base commit and are written here).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use factory_ports::clock::CancelSignal;
use factory_ports::paths::{CommitSha, PathMode, PathRules, RepoPath};
use factory_ports::workspace::{
    GitOperation, IoOperation, WorkspaceError, WorkspaceMounts, WorkspacePurpose, WorkspaceRequest,
};

use super::attempt::GitWorkspace;
use super::basetree::{BaseTree, BaseTreeError, TreeLine, parse_ls_tree};
use super::git::Invocation;
use super::layout::{AttemptDirs, JobDirs, remove_tree};
use super::provider::Shared;
use super::repo::{commit_exists, is_ancestor};

/// How many bytes of blobs one `cat-file` call reads.
const CHUNK_BYTES: u64 = 16 * 1024 * 1024;

/// The output of `git cat-file --batch`: for each requested object, `<sha> <type> <size>\n`, the
/// bytes, and a newline.
pub(super) fn parse_cat_batch(mut output: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
    let mut objects = Vec::new();
    while !output.is_empty() {
        let end = output.iter().position(|b| *b == b'\n')?;
        let header = std::str::from_utf8(&output[..end]).ok()?;
        let mut parts = header.split(' ');
        let sha = parts.next()?.to_owned();
        if parts.next()? != "blob" {
            return None;
        }
        let size: usize = parts.next()?.parse().ok()?;
        let body = output.get(end + 1..end + 1 + size)?;
        if *output.get(end + 1 + size)? != b'\n' {
            return None;
        }
        objects.push((sha, body.to_vec()));
        output = &output[end + size + 2..];
    }
    Some(objects)
}

/// Reads blobs from the store, in the order asked, one entry per sha asked (duplicates included).
pub(super) async fn read_blobs(
    shared: &Shared,
    store: &Path,
    cwd: &Path,
    shas: &[String],
    expected_bytes: u64,
    cancel: &dyn CancelSignal,
) -> Result<Vec<Vec<u8>>, WorkspaceError> {
    let mut stdin = Vec::new();
    for sha in shas {
        stdin.extend_from_slice(sha.as_bytes());
        stdin.push(b'\n');
    }
    let cap = expected_bytes
        .saturating_add(128 * shas.len() as u64)
        .saturating_add(1024);
    let inv = Invocation::new(store, cwd, &["cat-file", "--batch"])
        .with_stdin(stdin)
        .with_max_output(cap);
    let out = shared.git.run_ok(GitOperation::Read, inv, cancel).await?;
    let objects = parse_cat_batch(&out).ok_or(WorkspaceError::Git {
        operation: GitOperation::Read,
        exit: None,
    })?;
    if objects.len() != shas.len() || objects.iter().zip(shas).any(|((got, _), want)| got != want) {
        return Err(WorkspaceError::Git {
            operation: GitOperation::Read,
            exit: None,
        });
    }
    Ok(objects.into_iter().map(|(_, bytes)| bytes).collect())
}

/// One file or link to write.
#[derive(Debug, Clone)]
struct Planned {
    rel: String,
    mode: String,
    sha: String,
    size: u64,
}

fn sharing(shared: &Shared) -> bool {
    shared.settings.open_to_sandbox_user
}

fn io_error() -> WorkspaceError {
    WorkspaceError::Io(IoOperation::CreateDirectory)
}

/// Makes the attempt's directories and returns the workspace over them.
pub(super) async fn create(
    shared: &Arc<Shared>,
    req: WorkspaceRequest,
    cancel: &dyn CancelSignal,
) -> Result<GitWorkspace, WorkspaceError> {
    if cancel.is_cancelled() {
        return Err(WorkspaceError::Cancelled);
    }
    let job_dirs = shared.job_dirs(req.job);
    if !job_dirs.has_store() {
        return Err(WorkspaceError::NotFetched);
    }
    if !commit_exists(shared, &job_dirs, &req.base, cancel).await? {
        return Err(WorkspaceError::UnknownCommit);
    }
    // The protected base must be readable and on the base's own history, or nothing is judged
    // against it: fail closed (ADR 0024).
    let protected = match &req.protected_base {
        Some(commit) if commit != &req.base => {
            if !commit_exists(shared, &job_dirs, commit, cancel).await?
                || !is_ancestor(shared, &job_dirs, commit, &req.base, cancel).await?
            {
                return Err(WorkspaceError::UnknownCommit);
            }
            Some(commit.clone())
        }
        _ => None,
    };
    let lines = list_tree(shared, &job_dirs, &req.base, cancel).await?;
    let protected_paths: Option<BTreeSet<Vec<u8>>> = match &protected {
        Some(commit) => Some(
            list_tree(shared, &job_dirs, commit, cancel)
                .await?
                .into_iter()
                .map(|line| line.path)
                .collect(),
        ),
        None => None,
    };
    let links = read_links(shared, &job_dirs.store, &job_dirs.dir, &lines, cancel).await?;
    let tree = BaseTree::build(
        &lines,
        &links,
        &req.rules,
        &req.purpose,
        &shared.settings.limits,
    )
    .map_err(|error| match error {
        BaseTreeError::TooLarge => WorkspaceError::TooLarge,
        BaseTreeError::Collision => WorkspaceError::Git {
            operation: GitOperation::Checkout,
            exit: None,
        },
    })?;

    let dirs = job_dirs.attempt(req.attempt);
    make_directories(shared, &dirs).inspect_err(|_| {
        let _ = remove_tree(&dirs.dir);
    })?;
    let written = write_checkout(
        shared,
        &job_dirs.store,
        &job_dirs.dir,
        &dirs,
        &tree,
        &links,
        cancel,
    )
    .await;
    if let Err(error) = written {
        let _ = remove_tree(&dirs.dir);
        return Err(error);
    }

    let overlays = if matches!(req.purpose, WorkspacePurpose::Agent) {
        overlay_paths(&req.rules, &tree, protected_paths.as_ref())
    } else {
        Vec::new()
    };
    let mounts = WorkspaceMounts {
        workspace: dirs.checkout.clone(),
        workspace_read_only: matches!(req.purpose, WorkspacePurpose::Verify { .. }),
        out: dirs.out.clone(),
        protected_overlays: overlays,
        git_masked: true,
    };
    Ok(GitWorkspace::new(
        Arc::clone(shared),
        req,
        protected,
        job_dirs,
        dirs,
        tree,
        mounts,
    ))
}

/// Every entry of a commit's tree, from `git ls-tree -r -z --long`.
async fn list_tree(
    shared: &Shared,
    job_dirs: &JobDirs,
    commit: &CommitSha,
    cancel: &dyn CancelSignal,
) -> Result<Vec<TreeLine>, WorkspaceError> {
    let listing = shared
        .git
        .run_ok(
            GitOperation::Checkout,
            Invocation::new(
                &job_dirs.store,
                &job_dirs.dir,
                &["ls-tree", "-r", "-z", "--long", commit.as_str()],
            )
            .with_max_output(shared.settings.max_listing_bytes),
            cancel,
        )
        .await?;
    parse_ls_tree(&listing).ok_or(WorkspaceError::Git {
        operation: GitOperation::Checkout,
        exit: None,
    })
}

/// The target text of every link of the base.
async fn read_links(
    shared: &Shared,
    store: &Path,
    cwd: &Path,
    lines: &[TreeLine],
    cancel: &dyn CancelSignal,
) -> Result<BTreeMap<String, String>, WorkspaceError> {
    let links: Vec<&TreeLine> = lines
        .iter()
        .filter(|l| l.mode == "120000" && l.kind == "blob")
        .collect();
    if links.is_empty() {
        return Ok(BTreeMap::new());
    }
    let shas: Vec<String> = links.iter().map(|l| l.sha.clone()).collect();
    let total: u64 = links.iter().map(|l| l.size.unwrap_or(0)).sum();
    if total > 8 * 1024 * 1024 {
        return Err(WorkspaceError::TooLarge);
    }
    let blobs = read_blobs(shared, store, cwd, &shas, total, cancel).await?;
    let mut targets = BTreeMap::new();
    for (line, bytes) in links.iter().zip(blobs) {
        if let (Ok(path), Ok(target)) = (std::str::from_utf8(&line.path), String::from_utf8(bytes))
        {
            targets.insert(path.to_owned(), target);
        }
    }
    Ok(targets)
}

fn make_directories(shared: &Shared, dirs: &AttemptDirs) -> Result<(), WorkspaceError> {
    let open = sharing(shared);
    if let Some(parent) = dirs.dir.parent() {
        fs::create_dir_all(parent).map_err(|_| io_error())?;
    }
    // The attempt directory is made with `create_dir` so that a second `create` for the same
    // attempt fails and never reuses a tree.
    fs::create_dir(&dirs.dir).map_err(|_| io_error())?;
    fs::set_permissions(&dirs.dir, fs::Permissions::from_mode(0o700)).map_err(|_| io_error())?;
    for (dir, shared_mode) in [
        (&dirs.checkout, open),
        (&dirs.out, open),
        (&dirs.meta, false),
    ] {
        fs::create_dir(dir).map_err(|_| io_error())?;
        let mode = if shared_mode { 0o777 } else { 0o700 };
        fs::set_permissions(dir, fs::Permissions::from_mode(mode)).map_err(|_| io_error())?;
    }
    Ok(())
}

async fn write_checkout(
    shared: &Shared,
    store: &Path,
    cwd: &Path,
    dirs: &AttemptDirs,
    tree: &BaseTree,
    links: &BTreeMap<String, String>,
    cancel: &dyn CancelSignal,
) -> Result<(), WorkspaceError> {
    let open = sharing(shared);
    let planned: Vec<Planned> = tree
        .visible
        .iter()
        .map(|(rel, entry)| Planned {
            rel: rel.clone(),
            mode: entry.mode.clone(),
            sha: entry.sha.clone(),
            size: entry.size,
        })
        .collect();

    // Links first need no blob: their text is already known.
    let mut chunk: Vec<Planned> = Vec::new();
    let mut chunk_bytes = 0u64;
    let mut batches: Vec<Vec<Planned>> = Vec::new();
    let mut link_plans: Vec<(String, String)> = Vec::new();
    for plan in planned {
        if plan.mode == "120000" {
            if let Some(target) = links.get(&plan.rel) {
                link_plans.push((plan.rel, target.clone()));
            }
            continue;
        }
        if chunk_bytes + plan.size > CHUNK_BYTES && !chunk.is_empty() {
            batches.push(std::mem::take(&mut chunk));
            chunk_bytes = 0;
        }
        chunk_bytes += plan.size;
        chunk.push(plan);
    }
    if !chunk.is_empty() {
        batches.push(chunk);
    }

    for batch in batches {
        if cancel.is_cancelled() {
            return Err(WorkspaceError::Cancelled);
        }
        let shas: Vec<String> = batch.iter().map(|p| p.sha.clone()).collect();
        let bytes: u64 = batch.iter().map(|p| p.size).sum();
        let blobs = read_blobs(shared, store, cwd, &shas, bytes, cancel).await?;
        let root = dirs.checkout.clone();
        let sizes_ok = batch
            .iter()
            .zip(&blobs)
            .all(|(plan, blob)| blob.len() as u64 == plan.size);
        if !sizes_ok {
            return Err(WorkspaceError::Git {
                operation: GitOperation::Checkout,
                exit: None,
            });
        }
        tokio::task::spawn_blocking(move || write_files(&root, &batch, &blobs, open))
            .await
            .map_err(|_| io_error())??;
    }
    let root = dirs.checkout.clone();
    tokio::task::spawn_blocking(move || write_links_and_mask(&root, &link_plans, open))
        .await
        .map_err(|_| io_error())??;
    Ok(())
}

/// Makes every directory of `rel` below `root`, one component at a time, and refuses to go
/// through anything that is not a plain directory.
fn make_parents(root: &Path, rel: &str, open: bool) -> Result<PathBuf, WorkspaceError> {
    let mut current = root.to_path_buf();
    let mut components: Vec<&str> = rel.split('/').collect();
    let file = components.pop().unwrap_or_default();
    for component in components {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => return Err(io_error()),
            Err(_) => {
                fs::create_dir(&current).map_err(|_| io_error())?;
                let mode = if open { 0o777 } else { 0o755 };
                fs::set_permissions(&current, fs::Permissions::from_mode(mode))
                    .map_err(|_| io_error())?;
            }
        }
    }
    current.push(file);
    Ok(current)
}

fn write_files(
    root: &Path,
    batch: &[Planned],
    blobs: &[Vec<u8>],
    open: bool,
) -> Result<(), WorkspaceError> {
    for (plan, blob) in batch.iter().zip(blobs) {
        let target = make_parents(root, &plan.rel, open)?;
        let executable = plan.mode == "100755";
        let mode = match (executable, open) {
            (true, true) => 0o777,
            (true, false) => 0o755,
            (false, true) => 0o666,
            (false, false) => 0o644,
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&target)
            .map_err(|_| io_error())?;
        file.write_all(blob).map_err(|_| io_error())?;
        drop(file);
        // The umask may have taken bits away.
        fs::set_permissions(&target, fs::Permissions::from_mode(mode)).map_err(|_| io_error())?;
    }
    Ok(())
}

fn write_links_and_mask(
    root: &Path,
    links: &[(String, String)],
    open: bool,
) -> Result<(), WorkspaceError> {
    for (rel, target) in links {
        let at = make_parents(root, rel, open)?;
        symlink(target, &at).map_err(|_| io_error())?;
    }
    // The mount point of the mask. The runtime binds `/dev/null` over it.
    let mask = root.join(".git");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&mask)
        .map_err(|_| io_error())?;
    drop(file);
    Ok(())
}

/// The files the sandbox mounts read-only over the writable checkout: the existing files of the
/// `deny_write` paths, and those of the `append_only` paths that existed at the protected base
/// (`protected`, the paths of that commit; `None` when the base is the protected commit). An
/// `append_only` file the job itself added stays writable, as the ingestion allows its change.
fn overlay_paths(
    rules: &PathRules,
    tree: &BaseTree,
    protected: Option<&BTreeSet<Vec<u8>>>,
) -> Vec<RepoPath> {
    let mut overlays: Vec<RepoPath> = tree
        .visible
        .iter()
        .filter(|(_, entry)| entry.mode != "120000")
        .filter_map(|(rel, _)| RepoPath::new(rel).ok().map(|path| (rel, path)))
        .filter(|(rel, path)| match rules.classify(path) {
            Some(PathMode::DenyWrite) => true,
            Some(PathMode::AppendOnly) => {
                protected.is_none_or(|paths| paths.contains(rel.as_bytes()))
            }
            _ => false,
        })
        .map(|(_, path)| path)
        .collect();
    overlays.sort();
    overlays
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_batch_listing_is_split_by_its_declared_sizes() {
        let sha = "a".repeat(40);
        let mut out = Vec::new();
        out.extend_from_slice(format!("{sha} blob 3\nabc\n").as_bytes());
        out.extend_from_slice(format!("{sha} blob 2\n\n\n\n").as_bytes());
        let parsed = parse_cat_batch(&out).expect("parsed");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].1, b"abc");
        assert_eq!(parsed[1].1, b"\n\n");
    }

    #[test]
    fn a_missing_object_or_a_short_body_is_not_parsed() {
        assert!(parse_cat_batch(b"aaaa missing\n").is_none());
        assert!(parse_cat_batch(b"aaaa blob 10\nabc\n").is_none());
    }
}
