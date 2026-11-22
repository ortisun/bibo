//! The job token file: written by this adapter and nobody else, removed on every path.
//!
//! The job token is the one credential an `agent` sandbox holds, and it is delivered as a file,
//! never in the environment (the Docker daemon shows environment values to anyone who can inspect
//! the container). The layout, under a root the adapter controls:
//!
//! ```text
//! <root>/                 mode 0700
//!   <suffix>/             mode 0700, one per sandbox, named like the sandbox's Docker objects
//!     job-token           mode 0400, owned by the sandbox user, the secret and nothing else
//!     mcp-token           troubleshooter only (ADR 0021): the MCP gateway's run token, the same way
//! ```
//!
//! The file is bind-mounted read-only at [`factory_ports::sandbox::JOB_TOKEN_TARGET`]. On a Linux
//! host `root` should be on a tmpfs, so the secret never reaches a disk; this crate cannot make
//! one, so the choice of `root` is the deployment's. Removal is idempotent and runs from the
//! teardown of the session, from the failure paths of `create_verified`, and from the janitor.
//!
//! Ownership: the file is handed to the sandbox user with `chown` when the process may do that
//! (it is root, or already that user). When it may not, the file stays with its writer. On Docker
//! Desktop the file sharing layer shows it to the container as owned by the container user
//! anyway (experiment B1). The supervisor reads the file from inside the started container before
//! it releases the workload, so a host where neither holds fails at provisioning and not later.
//! On a Linux host the worker is given `CAP_CHOWN` for this, and nothing more (ADR 0035): the
//! first Linux CI run, as an unprivileged user, failed every agent sandbox here.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use factory_ports::agent::JobTokenSecret;
use factory_ports::sandbox::McpRunTokenSecret;

/// The name of the file inside a sandbox's directory.
pub const TOKEN_FILE_NAME: &str = "job-token";

/// The name of the MCP gateway's run token file, beside the job token (troubleshooter only).
pub const MCP_TOKEN_FILE_NAME: &str = "mcp-token";

/// Where token files live.
#[derive(Debug, Clone)]
pub struct TokenStore {
    root: PathBuf,
}

/// One token file that exists on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenFile {
    path: PathBuf,
    ownership_applied: bool,
}

impl TokenFile {
    /// The host path to bind-mount.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True when the file was handed to the sandbox user on the host.
    #[must_use]
    pub fn ownership_applied(&self) -> bool {
        self.ownership_applied
    }
}

impl TokenStore {
    /// A store under `root`. Nothing is created until the first file is written.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// The root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn directory(&self, suffix: &str) -> PathBuf {
        self.root.join(suffix)
    }

    /// Writes the secret for the sandbox named by `suffix`: a directory 0700, the file created
    /// new (an existing one is an error), made 0400 before a byte is written, then handed to
    /// `uid:gid` when that is allowed.
    ///
    /// # Errors
    /// The I/O error. Whatever was created is removed before the error returns.
    pub fn write(
        &self,
        suffix: &str,
        secret: &JobTokenSecret,
        uid: u32,
        gid: u32,
    ) -> io::Result<TokenFile> {
        if suffix.is_empty() || suffix.contains(['/', '\\', '\0']) || suffix.starts_with('.') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a token directory name is a plain name",
            ));
        }
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(&self.root)?;
        let directory = self.directory(suffix);
        let mut leaf = fs::DirBuilder::new();
        leaf.mode(0o700);
        leaf.create(&directory)?;
        let outcome = Self::fill(&directory, TOKEN_FILE_NAME, secret.expose(), uid, gid);
        if outcome.is_err() {
            let _ = fs::remove_dir_all(&directory);
        }
        outcome
    }

    /// Writes the MCP gateway's run token beside the job token of the sandbox named by `suffix`,
    /// the same way: created new, 0400 before a byte is written, handed to `uid:gid` when allowed.
    /// The directory must already exist ([`Self::write`] made it), and [`Self::remove`] removes
    /// both files with it.
    ///
    /// # Errors
    /// The I/O error. A file that was created is removed before the error returns.
    pub fn write_mcp(
        &self,
        suffix: &str,
        secret: &McpRunTokenSecret,
        uid: u32,
        gid: u32,
    ) -> io::Result<TokenFile> {
        if suffix.is_empty() || suffix.contains(['/', '\\', '\0']) || suffix.starts_with('.') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a token directory name is a plain name",
            ));
        }
        let directory = self.directory(suffix);
        let outcome = Self::fill(&directory, MCP_TOKEN_FILE_NAME, secret.expose(), uid, gid);
        if outcome.is_err() {
            let _ = fs::remove_file(directory.join(MCP_TOKEN_FILE_NAME));
        }
        outcome
    }

    fn fill(
        directory: &Path,
        name: &str,
        secret: &str,
        uid: u32,
        gid: u32,
    ) -> io::Result<TokenFile> {
        let path = directory.join(name);
        let mut file = fs::File::create_new(&path)?;
        // The directory is 0700, so nobody else can reach the file between these two calls, and
        // no byte has been written yet.
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
        file.write_all(secret.as_bytes())?;
        file.flush()?;
        drop(file);
        let ownership_applied = std::os::unix::fs::chown(&path, Some(uid), Some(gid)).is_ok();
        Ok(TokenFile {
            path,
            ownership_applied,
        })
    }

    /// Removes the directory of the sandbox named by `suffix`, with the file in it. Idempotent:
    /// a directory that is already gone is success.
    ///
    /// # Errors
    /// Any I/O error other than "not found".
    pub fn remove(&self, suffix: &str) -> io::Result<()> {
        if suffix.is_empty() || suffix.contains(['/', '\\', '\0']) || suffix.starts_with('.') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a token directory name is a plain name",
            ));
        }
        match fs::remove_dir_all(self.directory(suffix)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let dir = std::env::temp_dir()
                .join(format!("sbx-token-{label}-{}-{nanos}", std::process::id()));
            Self(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn secret() -> JobTokenSecret {
        // Built at run time so that no secret-shaped literal sits in the source.
        JobTokenSecret::new(format!("{}-{}", "unit", "token-value"))
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    /// The file's content, read as its writer. When the file was handed to the sandbox user (the
    /// writer is root or holds `CAP_CHOWN`, as a Linux worker does, ADR 0035), the writer can no
    /// longer read a `0400` file, so the test takes it back for the read and hands it over again.
    /// It also checks who owns it: the sandbox user when the hand-over was applied, the writer
    /// otherwise.
    fn read_back(file: &TokenFile, uid: u32, gid: u32) -> String {
        use std::os::unix::fs::MetadataExt;
        let writer = fs::metadata(file.path().parent().expect("parent")).expect("metadata");
        let owner = fs::metadata(file.path()).expect("metadata");
        if file.ownership_applied() {
            assert_eq!(
                (owner.uid(), owner.gid()),
                (uid, gid),
                "handed to the sandbox user"
            );
        } else {
            assert_eq!(owner.uid(), writer.uid(), "left with its writer");
        }
        match fs::read_to_string(file.path()) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                std::os::unix::fs::chown(file.path(), Some(writer.uid()), Some(writer.gid()))
                    .expect("take the file back");
                let text = fs::read_to_string(file.path()).expect("read");
                std::os::unix::fs::chown(file.path(), Some(uid), Some(gid))
                    .expect("hand it over again");
                text
            }
            Err(error) => panic!("read: {error}"),
        }
    }

    #[test]
    fn the_file_is_0400_in_a_0700_directory_and_holds_the_secret_only() {
        let scratch = Scratch::new("write");
        let store = TokenStore::new(scratch.0.join("tokens"));
        let secret = secret();
        let file = store
            .write("job-a", &secret, 10_001, 10_001)
            .expect("write");
        assert_eq!(mode(file.path()), 0o400);
        assert_eq!(mode(file.path().parent().expect("parent")), 0o700);
        assert_eq!(mode(store.root()), 0o700);
        assert_eq!(read_back(&file, 10_001, 10_001), secret.expose());
    }

    #[test]
    fn the_gateway_token_sits_beside_the_job_token_and_goes_with_it() {
        let scratch = Scratch::new("mcp");
        let store = TokenStore::new(scratch.0.join("tokens"));
        // Built at run time so that no secret-shaped literal sits in the source.
        let gateway = McpRunTokenSecret::new(format!("{}-{}", "unit", "gateway-value"));
        // There is no directory before the job token is written.
        assert!(store.write_mcp("job-m", &gateway, 10_001, 10_001).is_err());
        let job = store
            .write("job-m", &secret(), 10_001, 10_001)
            .expect("write");
        let file = store
            .write_mcp("job-m", &gateway, 10_001, 10_001)
            .expect("write the gateway token");
        assert_eq!(file.path().parent(), job.path().parent());
        assert_eq!(mode(file.path()), 0o400);
        assert_eq!(read_back(&file, 10_001, 10_001), gateway.expose());
        // A second write is refused: the file is created new.
        assert!(store.write_mcp("job-m", &gateway, 10_001, 10_001).is_err());
        store.remove("job-m").expect("remove");
        assert!(!file.path().exists());
        assert!(store.write_mcp("../x", &gateway, 10_001, 10_001).is_err());
    }

    #[test]
    fn removal_takes_the_file_and_is_idempotent() {
        let scratch = Scratch::new("remove");
        let store = TokenStore::new(scratch.0.join("tokens"));
        let file = store
            .write("job-b", &secret(), 10_001, 10_001)
            .expect("write");
        store.remove("job-b").expect("first removal");
        assert!(fs::metadata(file.path()).is_err(), "the file must be gone");
        store
            .remove("job-b")
            .expect("a second removal is not an error");
        store
            .remove("never-existed")
            .expect("nor is an unknown name");
    }

    #[test]
    fn a_second_write_for_one_sandbox_is_refused_and_keeps_the_first() {
        let scratch = Scratch::new("twice");
        let store = TokenStore::new(scratch.0.join("tokens"));
        let first = store
            .write("job-c", &secret(), 10_001, 10_001)
            .expect("write");
        let second = store.write("job-c", &secret(), 10_001, 10_001);
        assert!(second.is_err());
        assert!(fs::metadata(first.path()).is_ok());
    }

    #[test]
    fn a_name_that_leaves_the_directory_is_refused() {
        let scratch = Scratch::new("names");
        let store = TokenStore::new(scratch.0.join("tokens"));
        for bad in ["", "../x", "a/b", ".hidden", "a\0b"] {
            assert!(store.write(bad, &secret(), 1, 1).is_err(), "{bad:?}");
            assert!(store.remove(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_debug_output_of_a_file_shows_the_path_and_no_secret() {
        let scratch = Scratch::new("debug");
        let store = TokenStore::new(scratch.0.join("tokens"));
        let secret = secret();
        let file = store
            .write("job-d", &secret, 10_001, 10_001)
            .expect("write");
        assert!(!format!("{file:?}").contains(secret.expose()));
    }
}
