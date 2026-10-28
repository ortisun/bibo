//! Copies of the fixture. A check or a command that might change files works on a copy, so the
//! fixture directory in the repository is never written to.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// A directory that is removed when the value is dropped.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

impl TempDir {
    /// Makes a new empty directory under the system temporary directory.
    ///
    /// # Errors
    /// The error of the file system when the directory cannot be made.
    pub fn new(label: &str) -> io::Result<Self> {
        let unique = format!(
            "word-count-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Copies the fixture into a new temporary directory, without `target`, `.git` and symbolic links.
///
/// # Errors
/// The error of the file system.
pub fn copy_fixture(source: &Path, label: &str) -> io::Result<TempDir> {
    let dir = TempDir::new(label)?;
    copy_tree(source, dir.path())?;
    Ok(dir)
}

fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let name = entry.file_name();
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            if name == "target" || name == ".git" {
                continue;
            }
            copy_tree(&entry.path(), &to.join(&name))?;
        } else {
            fs::copy(entry.path(), to.join(&name))?;
        }
    }
    Ok(())
}

/// Every file under `dir`, as paths relative to it with `/` separators, sorted. Skips `target`
/// and `.git`.
///
/// # Errors
/// The error of the file system.
pub fn list_files(dir: &Path) -> io::Result<Vec<String>> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) -> io::Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            let name = entry.file_name();
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                if name == "target" || name == ".git" {
                    continue;
                }
                walk(root, &entry.path(), out)?;
            } else if let Ok(relative) = entry.path().strip_prefix(root) {
                out.push(relative.to_string_lossy().replace('\\', "/"));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out)?;
    out.sort();
    Ok(out)
}
