//! Where things live on the host, and how they are removed.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use factory_domain::ids::{AttemptId, JobId};

/// The directories of one job.
#[derive(Debug, Clone)]
pub(crate) struct JobDirs {
    /// `<root>/jobs/<job>`.
    pub dir: PathBuf,
    /// The bare object store. Never mounted.
    pub store: PathBuf,
    /// `attempts/`, one directory per attempt.
    pub attempts: PathBuf,
}

impl JobDirs {
    pub(crate) fn new(root: &Path, job: JobId) -> Self {
        let dir = root.join("jobs").join(job.as_text());
        Self {
            store: dir.join("store.git"),
            attempts: dir.join("attempts"),
            dir,
        }
    }

    pub(crate) fn attempt(&self, attempt: AttemptId) -> AttemptDirs {
        let dir = self.attempts.join(attempt.as_text());
        AttemptDirs {
            checkout: dir.join("checkout"),
            out: dir.join("out"),
            meta: dir.join("meta"),
            dir,
        }
    }

    /// True when the job has an object store.
    pub(crate) fn has_store(&self) -> bool {
        // A store always has a `HEAD` file; a half-made directory does not count.
        self.store.join("HEAD").is_file()
    }
}

/// The directories of one attempt.
#[derive(Debug, Clone)]
pub(crate) struct AttemptDirs {
    /// `attempts/<attempt>`.
    pub dir: PathBuf,
    /// The checkout, mounted at `/workspace`.
    pub checkout: PathBuf,
    /// The output directory, mounted at `/out`.
    pub out: PathBuf,
    /// Private to the host: temporary indexes. Never mounted.
    pub meta: PathBuf,
}

/// Every job directory under the root whose name is a job id.
pub(crate) fn list_jobs(root: &Path) -> Vec<JobId> {
    list_ids(&root.join("jobs"), |name| JobId::parse(name).ok())
}

/// Every attempt directory of a job whose name is an attempt id.
pub(crate) fn list_attempts(job: &JobDirs) -> Vec<AttemptId> {
    list_ids(&job.attempts, |name| AttemptId::parse(name).ok())
}

fn list_ids<T: Ord>(dir: &Path, parse: impl Fn(&str) -> Option<T>) -> Vec<T> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut found: Vec<T> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str().and_then(&parse))
        .collect();
    found.sort();
    found
}

/// Removes a directory tree the sandbox may have written. A link is removed and never followed.
/// A directory the sandbox made unreadable or read-only gets its owner's permissions back first.
pub(crate) fn remove_tree(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    if fs::remove_dir_all(path).is_ok() {
        return Ok(());
    }
    reopen(path);
    match fs::remove_dir_all(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

fn reopen(path: &Path) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if !meta.file_type().is_dir() {
        return;
    }
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            reopen(&entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_ports::clock::Uuid;
    use factory_testkit::fx::tmpdir::FxTempDir;
    use std::os::unix::fs::symlink;

    fn job(n: u128) -> JobId {
        JobId::from_uuid(Uuid::from_u128(n << 8))
    }

    #[test]
    fn directories_are_named_by_the_ids_and_listed_back() {
        let root = FxTempDir::new("layout").expect("tmp");
        let dirs = JobDirs::new(root.path(), job(1));
        assert!(!dirs.has_store());
        fs::create_dir_all(&dirs.attempts).expect("dirs");
        let attempt = AttemptId::from_uuid(Uuid::from_u128(9 << 8));
        fs::create_dir_all(dirs.attempt(attempt).checkout).expect("checkout");
        fs::create_dir_all(dirs.attempts.join("not-an-id")).expect("stray");
        assert_eq!(list_attempts(&dirs), vec![attempt]);
        assert_eq!(list_jobs(root.path()), vec![job(1)]);
    }

    #[test]
    fn removing_a_tree_unlinks_links_and_survives_a_closed_directory() {
        let root = FxTempDir::new("layout-remove").expect("tmp");
        let outside = FxTempDir::new("layout-outside").expect("tmp");
        fs::write(outside.join("keep.txt"), b"keep").expect("file");
        let tree = root.join("tree");
        fs::create_dir_all(tree.join("locked/inner")).expect("dirs");
        fs::write(tree.join("locked/inner/f"), b"x").expect("file");
        symlink(outside.path(), tree.join("to-outside")).expect("link");
        fs::set_permissions(tree.join("locked"), fs::Permissions::from_mode(0o000)).expect("close");
        remove_tree(&tree).expect("removed");
        assert!(!tree.exists());
        assert!(
            outside.join("keep.txt").exists(),
            "the target of a link survives"
        );
    }
}
