//! Ingestion: from a tree the sandbox wrote to an audited change set in the trusted store.
//!
//! The order is the point:
//!
//! 1. **Audit walk** of the writable tree (`audit`): `lstat` only, nothing opened.
//! 2. **Read** the accepted files with an identity check and a size cap, and hand the bytes to
//!    `git fast-import` **on its standard input**. Git never gets the writable tree as a path, a
//!    working directory or a work tree, so nothing in it (a `.git` directory, a configuration, a
//!    `.gitattributes`, a link) is ever read by git.
//! 3. **Tree**: a temporary index in the private directory starts from the base commit's tree;
//!    only the paths that differ are updated; `write-tree` makes the head tree.
//! 4. **Difference** between the two trees, computed by git from the store with rename detection
//!    off. A rename is a deletion and an addition; a mode or type change is a modification.
//! 5. **Rules** (`rules`): the path modes of the request, and the compiled policy when given.
//!    When the workspace starts later in the job than its protected base, a second difference,
//!    from the protected base to the same head tree, is what `append_only` and `additions_only`
//!    judge a changed path by (ADR 0025).
//! 6. **Secret scan** of the blobs as the store holds them, which are the bytes a commit will hold.
//!
//! Only after all six does `ingest` build an `IngestedChange`, and this is the only place in the
//! workspace code that does.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use factory_domain::values::Sha256Digest;
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{CommitSha, Finding, PathMode, PathRules};
use factory_ports::process::EnvValue;
use factory_ports::workspace::{
    ChangeKind, ChangedPath, GitOperation, IngestedChange, IoOperation, WorkspaceError,
};

use super::attempt::{Audited, GitWorkspace};
use super::audit::{
    AuditFailure, Entry, Manifest, ReadFailure, WalkContext, read_file, report_path, walk,
};
use super::basetree::BaseTree;
use super::checkout::read_blobs;
use super::git::{Invocation, NoCancel};
use super::repo::{RawChange, parse_raw_diff};
use super::rules::{ChangeFacts, evaluate};
use super::secrets;
use crate::race::{Either, race};

/// How many bytes of file content one `fast-import` call receives.
const CHUNK_BYTES: u64 = 16 * 1024 * 1024;

/// Audits the workspace and returns the change set. See the module documentation.
pub(super) async fn ingest(
    ws: &GitWorkspace,
    cancel: &dyn CancelSignal,
) -> Result<IngestedChange, WorkspaceError> {
    if cancel.is_cancelled() {
        return Err(WorkspaceError::Cancelled);
    }
    let timeout = ws.shared.settings.timeouts.ingest;
    match tokio::time::timeout(timeout, run(ws, cancel)).await {
        Ok(result) => result,
        Err(_) => Err(WorkspaceError::Timeout),
    }
}

async fn run(
    ws: &GitWorkspace,
    cancel: &dyn CancelSignal,
) -> Result<IngestedChange, WorkspaceError> {
    let shared = &ws.shared;
    let manifest = audit(ws, cancel).await?;

    let store = &ws.job_dirs.store;
    let meta = &ws.attempt_dirs.meta;

    // 2. Hash the audited bytes through git's standard input.
    let hashed = hash_entries(ws, &manifest, cancel).await?;

    // 3. The head tree, from a temporary index that starts at the base commit.
    let index = meta.join("ingest.index");
    let _ = std::fs::remove_file(&index);
    let index_text = index.to_string_lossy().into_owned();
    let with_index = |inv: Invocation| inv.with_env("GIT_INDEX_FILE", &index_text);
    shared
        .git
        .run_ok(
            GitOperation::Diff,
            with_index(Invocation::new(
                store,
                meta,
                &["read-tree", ws.base.as_str()],
            )),
            cancel,
        )
        .await?;
    let edits = index_edits(&ws.tree, &hashed, ws.base.as_str().len());
    if !edits.is_empty() {
        shared
            .git
            .run_ok(
                GitOperation::Diff,
                with_index(
                    Invocation::new(
                        store,
                        meta,
                        &["update-index", "--add", "--replace", "-z", "--index-info"],
                    )
                    .with_stdin(edits),
                ),
                cancel,
            )
            .await?;
    }
    let tree_out = shared
        .git
        .run_ok(
            GitOperation::Diff,
            with_index(Invocation::new(store, meta, &["write-tree"])),
            cancel,
        )
        .await?;
    let _ = std::fs::remove_file(&index);
    let tree_sha = String::from_utf8_lossy(&tree_out).trim().to_owned();

    // 4. The difference from the base commit, computed by git from the store.
    let facts = difference(ws, &ws.base, &tree_sha, &manifest, cancel).await?;
    if facts.len() > shared.settings.limits.max_changed_files {
        return Err(WorkspaceError::TooLarge);
    }
    // And from the job's protected base, when the workspace starts later in the job (ADR 0025).
    // A store that cannot give it fails the ingestion: nothing is judged without it.
    let protected = match &ws.protected {
        Some(commit) => Some(difference(ws, commit, &tree_sha, &manifest, cancel).await?),
        None => None,
    };

    // A path the sandbox never saw cannot be part of its change. A directory made where a hidden
    // file is would replace that file in the tree without a file ever being written there, so
    // the difference is checked against what the checkout held.
    for fact in &facts {
        let text = fact.path.as_str();
        if let Some(gitlink) = ws.tree.gitlink_above(text) {
            return Err(WorkspaceError::Gitlink(super::audit::report_path(
                gitlink.as_bytes(),
            )));
        }
        let unseen = ws.tree.absent.contains(text)
            || (ws.rules.classify(&fact.path) == Some(PathMode::Hidden)
                && !ws.tree.visible.contains_key(text));
        if unseen {
            return Err(WorkspaceError::HiddenPathPresent(fact.path.clone()));
        }
    }

    // 5. The rules.
    let evaluation = evaluate(
        &ws.rules,
        shared.layer.as_ref(),
        &facts,
        protected.as_deref(),
    );
    if let Some(path) = evaluation.gitlink {
        return Err(WorkspaceError::Gitlink(path));
    }
    if !evaluation.violations.is_empty() {
        return Err(WorkspaceError::ProtectedPathChanged(evaluation.violations));
    }

    // 6. The secret scan, on the blobs the store holds.
    let findings = scan_blobs(ws, &facts, cancel).await?;
    if !findings.is_empty() {
        return Err(WorkspaceError::SecretFound(findings));
    }

    let changes: Vec<ChangedPath> = facts.iter().map(ChangeFacts::changed_path).collect();
    let digest = Sha256Digest::of(tree_sha.as_bytes());
    ws.remember(
        digest.clone(),
        Audited {
            tree: tree_sha,
            base: ws.base.clone(),
            changes: changes.clone(),
        },
    );
    Ok(IngestedChange::new(
        ws.base.clone(),
        changes,
        evaluation.sensitive,
        digest,
    ))
}

/// Sets the stop flag when it is dropped, so that a walk whose caller went away (a timeout, a
/// dropped future) ends by itself.
struct StopOnDrop(Arc<AtomicBool>);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// The first 12 hex characters of the SHA-256 of `text`: short enough for a log line, long enough
/// to tell the entries of one tree apart. It is the digest the rest of the workspace uses
/// (`Sha256Digest`), cut for the log.
fn short_digest(text: &str) -> String {
    let digest = Sha256Digest::of(text.as_bytes());
    digest.hex().chars().take(12).collect()
}

/// Runs the walk on a blocking thread, under the caller's cancel signal.
async fn audit(ws: &GitWorkspace, cancel: &dyn CancelSignal) -> Result<Manifest, WorkspaceError> {
    let stop = Arc::new(AtomicBool::new(false));
    let _stop_on_drop = StopOnDrop(Arc::clone(&stop));
    let root = ws.attempt_dirs.checkout.clone();
    let limits = ws.shared.settings.limits.clone();
    let rules: PathRules = ws.rules.clone();
    let base: Arc<BaseTree> = Arc::clone(&ws.tree);
    let layer = ws.shared.layer.clone();
    let flag = Arc::clone(&stop);
    let handle = tokio::task::spawn_blocking(move || {
        walk(
            &root,
            &WalkContext {
                limits: &limits,
                rules: &rules,
                base: &base,
                policy: layer.as_ref(),
                mask_at_root: true,
                stop: &flag,
            },
        )
    });
    let joined = match race(handle, cancel.cancelled()).await {
        Either::First(joined) => joined,
        Either::Second(()) => return Err(WorkspaceError::Cancelled),
    };
    match joined {
        Ok(Ok(manifest)) => Ok(manifest),
        Ok(Err(AuditFailure::Rejected(report))) => {
            // A path is chosen by the repository's author, so the log gets the number of entries
            // rejected, the kind of each reason and a short digest of its path, enough to tell
            // two entries apart and to match two lines about one entry. The paths themselves are
            // in the report that `keep_report` keeps for the caller.
            tracing::warn!(
                rejected = report.reasons.len(),
                "the workspace audit rejected entries"
            );
            for reason in &report.reasons {
                tracing::warn!(
                    kind = ?reason.kind,
                    path_sha256 = short_digest(reason.path.as_str()),
                    "the workspace audit rejected an entry"
                );
            }
            let error = report.clone().into_error();
            ws.keep_report(report);
            Err(error)
        }
        Ok(Err(AuditFailure::Stopped)) => Err(WorkspaceError::Cancelled),
        Ok(Err(AuditFailure::Unreadable)) | Err(_) => Err(WorkspaceError::Io(IoOperation::Walk)),
    }
}

/// A path of the head tree: its git mode and blob.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Hashed {
    mode: &'static str,
    sha: String,
}

fn blob_stream(blobs: &[Vec<u8>]) -> Vec<u8> {
    let mut stream = Vec::new();
    for (index, blob) in blobs.iter().enumerate() {
        stream.extend_from_slice(
            format!("blob\nmark :{}\ndata {}\n", index + 1, blob.len()).as_bytes(),
        );
        stream.extend_from_slice(blob);
        stream.push(b'\n');
    }
    for index in 0..blobs.len() {
        stream.extend_from_slice(format!("get-mark :{}\n", index + 1).as_bytes());
    }
    stream.extend_from_slice(b"done\n");
    stream
}

async fn hash_entries(
    ws: &GitWorkspace,
    manifest: &Manifest,
    cancel: &dyn CancelSignal,
) -> Result<BTreeMap<String, Hashed>, WorkspaceError> {
    let mut hashed = BTreeMap::new();
    let mut batches: Vec<Vec<(String, Entry)>> = Vec::new();
    let mut current: Vec<(String, Entry)> = Vec::new();
    let mut bytes = 0u64;
    for (rel, entry) in &manifest.entries {
        let size = match entry {
            Entry::File { size, .. } => *size,
            Entry::Symlink { target } => target.len() as u64,
        };
        if bytes + size > CHUNK_BYTES && !current.is_empty() {
            batches.push(std::mem::take(&mut current));
            bytes = 0;
        }
        bytes += size;
        current.push((rel.clone(), entry.clone()));
    }
    if !current.is_empty() {
        batches.push(current);
    }
    for batch in batches {
        if cancel.is_cancelled() {
            return Err(WorkspaceError::Cancelled);
        }
        let root = ws.attempt_dirs.checkout.clone();
        let limit = ws.shared.settings.limits.max_file_bytes;
        let items = batch.clone();
        let blobs = tokio::task::spawn_blocking(move || read_all(&root, &items, limit))
            .await
            .map_err(|_| WorkspaceError::Io(IoOperation::Walk))??;
        let out = ws
            .shared
            .git
            .run_ok(
                GitOperation::Commit,
                Invocation::new(
                    &ws.job_dirs.store,
                    &ws.attempt_dirs.meta,
                    &["fast-import", "--quiet", "--done"],
                )
                .with_stdin(blob_stream(&blobs))
                .with_max_output(64 * 1024 + 128 * blobs.len() as u64),
                cancel,
            )
            .await?;
        let text = String::from_utf8_lossy(&out);
        let shas: Vec<&str> = text.lines().collect();
        if shas.len() != batch.len() || shas.iter().any(|s| !is_object_id(s)) {
            return Err(WorkspaceError::Git {
                operation: GitOperation::Commit,
                exit: None,
            });
        }
        for ((rel, entry), sha) in batch.iter().zip(shas) {
            let mode = match entry {
                Entry::Symlink { .. } => "120000",
                Entry::File { exec: true, .. } => "100755",
                Entry::File { exec: false, .. } => "100644",
            };
            hashed.insert(
                rel.clone(),
                Hashed {
                    mode,
                    sha: sha.to_owned(),
                },
            );
        }
    }
    Ok(hashed)
}

fn is_object_id(text: &str) -> bool {
    matches!(text.len(), 40 | 64) && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn read_all(
    root: &std::path::Path,
    items: &[(String, Entry)],
    limit: u64,
) -> Result<Vec<Vec<u8>>, WorkspaceError> {
    items
        .iter()
        .map(|(rel, entry)| match entry {
            Entry::Symlink { target } => Ok(target.as_bytes().to_vec()),
            Entry::File { identity, .. } => {
                read_file(&root.join(rel), *identity, limit).map_err(|failure| match failure {
                    ReadFailure::TooLarge => WorkspaceError::TooLarge,
                    ReadFailure::Changed | ReadFailure::Io => WorkspaceError::Io(IoOperation::Walk),
                })
            }
        })
        .collect()
}

/// The `update-index --index-info` input that turns the base tree into the head tree: first the
/// paths that are gone, then the paths that are new or different.
fn index_edits(base: &BaseTree, head: &BTreeMap<String, Hashed>, id_len: usize) -> Vec<u8> {
    let zeros = "0".repeat(id_len);
    let mut edits = Vec::new();
    for (path, entry) in &base.visible {
        let _ = entry;
        if !head.contains_key(path) {
            edits.extend_from_slice(format!("0 {zeros}\t{path}\0").as_bytes());
        }
    }
    for (path, now) in head {
        let unchanged = base
            .visible
            .get(path)
            .is_some_and(|before| before.mode == now.mode && before.sha == now.sha);
        if !unchanged {
            edits.extend_from_slice(format!("{} {}\t{path}\0", now.mode, now.sha).as_bytes());
        }
    }
    edits
}

/// The changed paths from the commit `from` to the head tree `tree`.
async fn difference(
    ws: &GitWorkspace,
    from: &CommitSha,
    tree: &str,
    manifest: &Manifest,
    cancel: &dyn CancelSignal,
) -> Result<Vec<ChangeFacts>, WorkspaceError> {
    let store = &ws.job_dirs.store;
    let meta = &ws.attempt_dirs.meta;
    let raw = ws
        .shared
        .git
        .run_ok(
            GitOperation::Diff,
            Invocation::new(
                store,
                meta,
                &[
                    "diff-tree",
                    "-r",
                    "-z",
                    "--raw",
                    "--no-renames",
                    "--no-abbrev",
                    from.as_str(),
                    tree,
                ],
            )
            .with_max_output(ws.shared.settings.max_listing_bytes),
            cancel,
        )
        .await?;
    let counts = ws
        .shared
        .git
        .run_ok(
            GitOperation::Diff,
            Invocation::new(
                store,
                meta,
                &[
                    "diff-tree",
                    "-r",
                    "-z",
                    "--numstat",
                    "--no-renames",
                    from.as_str(),
                    tree,
                ],
            )
            .with_max_output(ws.shared.settings.max_listing_bytes),
            cancel,
        )
        .await?;
    let changes = parse_raw_diff(&raw).ok_or(WorkspaceError::Git {
        operation: GitOperation::Diff,
        exit: None,
    })?;
    let numbers = parse_numstat(&counts);
    let mut facts: Vec<ChangeFacts> = changes
        .iter()
        .map(|change| facts_of(change, &numbers, manifest))
        .collect();
    facts.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(facts)
}

/// `(added, deleted)` per path from `git diff-tree --numstat -z`. A binary file has `None`.
fn parse_numstat(output: &[u8]) -> BTreeMap<Vec<u8>, Option<(u64, u64)>> {
    let mut numbers = BTreeMap::new();
    for record in output.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let mut parts = record.splitn(3, |b| *b == b'\t');
        let (Some(added), Some(deleted), Some(path)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let parse = |field: &[u8]| std::str::from_utf8(field).ok()?.parse::<u64>().ok();
        numbers.insert(path.to_vec(), parse(added).zip(parse(deleted)));
    }
    numbers
}

fn facts_of(
    change: &RawChange,
    numbers: &BTreeMap<Vec<u8>, Option<(u64, u64)>>,
    manifest: &Manifest,
) -> ChangeFacts {
    let path = report_path(&change.path);
    let absent = |mode: &str| mode.chars().all(|c| c == '0');
    let old_mode = (!absent(&change.old_mode)).then(|| change.old_mode.clone());
    let new_mode = (!absent(&change.new_mode)).then(|| change.new_mode.clone());
    let gained = matches!(numbers.get(&change.path), Some(Some((added, 0))) if *added > 0)
        && change.old_mode == change.new_mode;
    let link_target = std::str::from_utf8(&change.path)
        .ok()
        .and_then(|text| manifest.entries.get(text))
        .and_then(|entry| match entry {
            Entry::Symlink { target } => Some(target.clone()),
            Entry::File { .. } => None,
        });
    ChangeFacts {
        path,
        kind: change.kind(),
        old_mode,
        new_mode,
        old_sha: (!change.old_sha.chars().all(|c| c == '0')).then(|| change.old_sha.clone()),
        new_sha: (!change.new_sha.chars().all(|c| c == '0')).then(|| change.new_sha.clone()),
        gained_lines_only: gained,
        link_target,
    }
}

async fn scan_blobs(
    ws: &GitWorkspace,
    facts: &[ChangeFacts],
    cancel: &dyn CancelSignal,
) -> Result<Vec<Finding>, WorkspaceError> {
    let candidates: Vec<(&ChangeFacts, &String)> = facts
        .iter()
        .filter(|f| f.kind != ChangeKind::Deleted)
        .filter_map(|f| f.new_sha.as_ref().map(|sha| (f, sha)))
        .collect();
    let mut findings = Vec::new();
    let max = ws.shared.settings.limits.max_file_bytes;
    for group in candidates.chunks(64) {
        let shas: Vec<String> = group.iter().map(|(_, sha)| (*sha).clone()).collect();
        let blobs = read_blobs(
            &ws.shared,
            &ws.job_dirs.store,
            &ws.attempt_dirs.meta,
            &shas,
            max.saturating_mul(group.len() as u64),
            cancel,
        )
        .await?;
        for ((fact, _), bytes) in group.iter().zip(blobs) {
            let found = secrets::scan(&ws.shared.redactor, &fact.path, &bytes)
                .map_err(|_| WorkspaceError::TooLarge)?;
            findings.extend(found);
        }
    }
    Ok(findings)
}

/// The environment that dates and signs a commit as the factory.
pub(super) fn commit_env(name: &str, email: &str, unix_seconds: i64) -> Vec<(String, EnvValue)> {
    let date = format!("{unix_seconds} +0000");
    let plain = |key: &str, value: &str| (key.to_owned(), EnvValue::Plain(value.to_owned()));
    vec![
        plain("GIT_AUTHOR_NAME", name),
        plain("GIT_AUTHOR_EMAIL", email),
        plain("GIT_AUTHOR_DATE", &date),
        plain("GIT_COMMITTER_NAME", name),
        plain("GIT_COMMITTER_EMAIL", email),
        plain("GIT_COMMITTER_DATE", &date),
    ]
}

/// Commits the audited tree on top of the base commit and records the commit as the factory's.
pub(super) async fn make_commit(
    ws: &GitWorkspace,
    tree: &str,
    base: &CommitSha,
    message: &str,
    name: &str,
    email: &str,
) -> Result<CommitSha, WorkspaceError> {
    let seconds = ws.shared.clock.now().to_utc().unix_timestamp();
    let mut text = message.to_owned();
    if !text.ends_with('\n') {
        text.push('\n');
    }
    let mut inv = Invocation::new(
        &ws.job_dirs.store,
        &ws.attempt_dirs.meta,
        &["commit-tree", tree, "-p", base.as_str(), "-F", "-"],
    )
    .with_stdin(text.into_bytes());
    inv.env.extend(commit_env(name, email, seconds));
    let out = ws
        .shared
        .git
        .run_ok(GitOperation::Commit, inv, &NoCancel)
        .await?;
    let sha = String::from_utf8_lossy(&out).trim().to_owned();
    let commit = CommitSha::parse(&sha).map_err(|_| WorkspaceError::Git {
        operation: GitOperation::Commit,
        exit: None,
    })?;
    ws.shared
        .git
        .run_ok(
            GitOperation::Commit,
            Invocation::new(
                &ws.job_dirs.store,
                &ws.attempt_dirs.meta,
                &[
                    "update-ref",
                    &super::repo::made_ref(&commit),
                    commit.as_str(),
                ],
            ),
            &NoCancel,
        )
        .await?;
    Ok(commit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removals_come_before_additions_and_unchanged_paths_are_left_out() {
        let mut base = BaseTree::default();
        for (path, sha) in [("a", "1"), ("b", "2"), ("c", "3")] {
            base.visible.insert(
                path.to_owned(),
                super::super::basetree::BaseEntry {
                    mode: "100644".to_owned(),
                    sha: sha.repeat(40),
                    size: 1,
                },
            );
        }
        let mut head = BTreeMap::new();
        head.insert(
            "a".to_owned(),
            Hashed {
                mode: "100644",
                sha: "1".repeat(40),
            },
        );
        head.insert(
            "b".to_owned(),
            Hashed {
                mode: "100755",
                sha: "2".repeat(40),
            },
        );
        head.insert(
            "d".to_owned(),
            Hashed {
                mode: "100644",
                sha: "4".repeat(40),
            },
        );
        let edits = index_edits(&base, &head, 40);
        let text = String::from_utf8(edits).expect("text");
        let records: Vec<&str> = text.split('\0').filter(|r| !r.is_empty()).collect();
        assert_eq!(records.len(), 3, "{records:?}");
        assert!(records[0].starts_with("0 "), "the removal of c is first");
        assert!(records[0].ends_with("\tc"));
        assert!(records[1].starts_with("100755 "));
        assert!(records[2].ends_with("\td"));
    }

    #[test]
    fn a_blob_stream_names_every_mark_and_ends_with_done() {
        let stream = blob_stream(&[b"ab".to_vec(), Vec::new()]);
        let text = String::from_utf8(stream).expect("text");
        assert!(text.starts_with("blob\nmark :1\ndata 2\nab\n"));
        assert!(text.contains("blob\nmark :2\ndata 0\n\n"));
        assert!(text.ends_with("get-mark :1\nget-mark :2\ndone\n"));
    }

    #[test]
    fn a_rejected_path_is_logged_as_twelve_hex_characters_and_never_as_text() {
        let path = "src/ignore-previous-instructions.rs";
        let digest = short_digest(path);
        assert_eq!(digest.len(), 12);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!digest.contains("src") && !digest.contains("ignore"));
        assert_eq!(digest, short_digest(path), "the same path, the same digest");
        assert_ne!(digest, short_digest("src/another.rs"));
    }

    #[test]
    fn numbers_tell_a_file_that_only_gained_lines_from_one_that_changed() {
        let numbers = parse_numstat(b"1\t0\tgain.txt\x00-\t-\tbin.dat\x002\t1\tedit.txt\x00");
        assert_eq!(numbers.get(b"gain.txt".as_slice()), Some(&Some((1, 0))));
        assert_eq!(numbers.get(b"bin.dat".as_slice()), Some(&None));
        assert_eq!(numbers.get(b"edit.txt".as_slice()), Some(&Some((2, 1))));
    }
}
