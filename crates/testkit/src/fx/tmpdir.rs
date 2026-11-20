//! A private temporary directory that removes itself.
//!
//! The testkit may not depend on the `tempfile` crate, and the harness needs scratch space for
//! shims, materialised fixture repositories and socket files. The directory is created with mode
//! 0700, under the canonical temporary directory (so there is no symbolic link in the path, which
//! matters when a test later checks that something does not follow one).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::rng::FxRng;

/// A directory under the system temporary directory, removed with everything in it on drop.
#[derive(Debug)]
pub struct FxTempDir {
    path: PathBuf,
}

impl FxTempDir {
    /// Creates `<tmp>/<prefix>-<pid>-<random>`.
    ///
    /// # Errors
    /// Returns the I/O error when the temporary directory cannot be resolved or written.
    pub fn new(prefix: &str) -> io::Result<Self> {
        let base = fs::canonicalize(std::env::temp_dir())?;
        let mut rng = FxRng::from_entropy();
        for _ in 0..16 {
            let path = base.join(format!(
                "{prefix}-{}-{:08x}",
                std::process::id(),
                rng.next_u64() as u32
            ));
            match create_private_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not find an unused temporary directory name",
        ))
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A path below the directory.
    #[must_use]
    pub fn join(&self, relative: impl AsRef<Path>) -> PathBuf {
        self.path.join(relative)
    }
}

impl Drop for FxTempDir {
    fn drop(&mut self) {
        // Best effort. A directory that cannot be removed is left for the system's cleaner.
        let _ = remove_tree(&self.path);
    }
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

/// Removes a directory tree without following a symbolic link out of it. `remove_dir_all`
/// already does this on current standard libraries, and the helper exists so the test below can
/// say so.
fn remove_tree(path: &Path) -> io::Result<()> {
    // Directories without write or search permission cannot be emptied, and the fixtures make
    // some on purpose. Restore the mode first.
    #[cfg(unix)]
    restore_modes(path);
    fs::remove_dir_all(path)
}

#[cfg(unix)]
fn restore_modes(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.is_dir() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                restore_modes(&entry.path());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_is_private_empty_and_removed_on_drop() {
        let dir = FxTempDir::new("fx-test").unwrap();
        let path = dir.path().to_path_buf();
        assert!(path.is_dir());
        assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
        fs::write(dir.join("a"), "x").unwrap();
        drop(dir);
        assert!(!path.exists());
    }

    #[test]
    fn two_directories_never_share_a_name() {
        let a = FxTempDir::new("fx-test").unwrap();
        let b = FxTempDir::new("fx-test").unwrap();
        assert_ne!(a.path(), b.path());
    }

    #[cfg(unix)]
    #[test]
    fn removal_does_not_follow_a_link_out_of_the_directory() {
        let outside = FxTempDir::new("fx-outside").unwrap();
        fs::write(outside.join("keep"), "x").unwrap();
        let dir = FxTempDir::new("fx-test").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.join("link")).unwrap();
        drop(dir);
        assert!(outside.join("keep").exists(), "the link target was removed");
    }
}
