//! `LocalFsArtifactStore`: content-addressed blobs in a directory on the local disk (ADR 0008).
//!
//! This is the `local-fs` backend of Slice 1. It is not S3 and no document may call it that.
//! It is the one place of the `storage` crate that touches the file system (`clippy.toml` bans the
//! `std::fs` calls everywhere else).
//!
//! # Layout
//!
//! `<root>/sha256/ab/cd/<64 hex characters>`: the first two pairs of the digest name two
//! directories. The file name is the whole digest, so a blob is found from its hash alone.
//!
//! # What it guarantees
//!
//! * **Atomic writes.** The bytes go to a temporary file in the same directory, are flushed to
//!   disk (`fsync`), and are moved into place with `rename`. A reader sees the whole blob or none.
//!   The directory is flushed too, so the rename survives a crash.
//! * **Read-only blobs.** A blob is created with mode `0400`.
//! * **Idempotent put.** The same bytes give the same path. A blob that is already there is not
//!   written again. A damaged blob of another size is replaced by the correct bytes, which the
//!   address proves.
//! * **Verified reads.** `get` hashes the bytes it read and refuses a blob whose hash is not its
//!   address.
//! * **No path traversal.** A path is built only from the 64 hex characters of a `Sha256Digest`,
//!   which the type checks. No caller text becomes a path component.
//! * **No symbolic link is followed.** The store holds an open descriptor of its root and walks
//!   every step relative to the descriptor of the step before, with `O_NOFOLLOW`. A directory or a
//!   blob that has been replaced by a link is refused, not followed, so no link can lead out of
//!   the root, and there is no gap between a check and a use. The root path itself is resolved
//!   once, when the store is opened: that is configuration, written by the operator.
//! * **A size limit.** `put` refuses more than the limit, and `get` refuses to read a file that is
//!   larger than the limit.
//!
//! # Whose blob is it
//!
//! The blob store itself is not tenant-aware: a blob is shared by hash, and its `get` and `exists`
//! (the `ArtifactStore` port) answer for anyone who holds a reference. Code that acts for a tenant
//! uses [`TenantArtifacts`], which asks the tenant's artifact index first and answers "not found"
//! for a blob that only another tenant holds (architecture review F-15).
//!
//! Losing the disk loses the blobs. Backups of the directory are an `sre` item (ADR 0008).
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::values::{MediaType, NonNegativeInt, Sha256Digest};
use factory_domain::vocabulary::Fidelity;
use factory_ports::artifact::{ArtifactBackend, ArtifactError, ArtifactStore};
use rustix::fs::{AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;

mod scoped;

pub use scoped::TenantArtifacts;

/// A limit that fits the logs and reports of a gate run. A caller that stores larger objects
/// passes its own.
pub const DEFAULT_MAX_OBJECT_BYTES: u64 = 256 * 1024 * 1024;

/// The mode of a blob: readable by its owner, writable by nobody.
const BLOB_MODE: u32 = 0o400;

/// The mode of a directory of the store: only its owner may enter.
const DIRECTORY_MODE: u32 = 0o700;

struct Inner {
    root: OwnedFd,
    max_object_bytes: u64,
    temp_counter: AtomicU64,
}

/// Blobs in a directory, addressed by SHA-256. Cheap to clone: the clones share the root.
#[derive(Clone)]
pub struct LocalFsArtifactStore {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for LocalFsArtifactStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The path is not shown: the store holds a descriptor, not a path.
        f.debug_struct("LocalFsArtifactStore")
            .field("max_object_bytes", &self.inner.max_object_bytes)
            .finish_non_exhaustive()
    }
}

/// The error for a failed file system call. The text names the step and the operating system's
/// reason. It holds no path and no artifact content.
fn io_error(step: &str, errno: Errno) -> ArtifactError {
    ArtifactError::Io(format!("{step}: {errno}"))
}

fn plain_io_error(step: &str, error: &std::io::Error) -> ArtifactError {
    ArtifactError::Io(format!("{step}: {}", error.kind()))
}

fn unsafe_path() -> ArtifactError {
    ArtifactError::Io(
        "the artifact path is not a plain directory tree: a link or another kind of file is in the way"
            .to_owned(),
    )
}

/// The three path components of a blob: `ab`, `cd` and the whole digest in hex.
fn components(sha256: &Sha256Digest) -> [String; 3] {
    let hex = sha256.hex();
    [hex[0..2].to_owned(), hex[2..4].to_owned(), hex.to_owned()]
}

/// Opens `name` inside `parent` as a directory, never through a link.
fn open_directory(parent: &OwnedFd, name: &str) -> Result<OwnedFd, Errno> {
    rustix::fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

/// What a walk down the directories of a blob found.
enum Walk {
    /// Every directory exists and is a real directory. The innermost.
    Found(OwnedFd),
    /// A directory is missing.
    Missing,
}

/// Walks `sha256/ab/cd` from the root without creating anything.
fn walk(root: &OwnedFd, sha256: &Sha256Digest) -> Result<Walk, ArtifactError> {
    let [first, second, _] = components(sha256);
    let mut current = open_step(root, "sha256")?;
    for name in [first, second] {
        let Some(next) = current else {
            return Ok(Walk::Missing);
        };
        current = open_step(&next, &name)?;
    }
    Ok(current.map_or(Walk::Missing, Walk::Found))
}

/// Opens one directory. `None` when it does not exist, an error when a link or a file is there.
fn open_step(parent: &OwnedFd, name: &str) -> Result<Option<OwnedFd>, ArtifactError> {
    match open_directory(parent, name) {
        Ok(directory) => Ok(Some(directory)),
        Err(Errno::NOENT) => Ok(None),
        // A link (O_NOFOLLOW), or a file where a directory should be.
        Err(Errno::LOOP | Errno::NOTDIR | Errno::MLINK) => Err(unsafe_path()),
        Err(errno) => Err(io_error("open a directory of the store", errno)),
    }
}

/// Opens `sha256/ab/cd`, creating the directories that are missing. A link or a file where a
/// directory should be is refused.
fn walk_creating(root: &OwnedFd, sha256: &Sha256Digest) -> Result<OwnedFd, ArtifactError> {
    let [first, second, _] = components(sha256);
    let mut current = open_or_create(root, "sha256")?;
    for name in [first, second] {
        current = open_or_create(&current, &name)?;
    }
    Ok(current)
}

fn open_or_create(parent: &OwnedFd, name: &str) -> Result<OwnedFd, ArtifactError> {
    if let Some(directory) = open_step(parent, name)? {
        return Ok(directory);
    }
    match rustix::fs::mkdirat(
        parent,
        name,
        Mode::from_raw_mode(DIRECTORY_MODE.try_into().unwrap_or(0o700)),
    ) {
        // Another writer made it between our look and our call. That is fine.
        Ok(()) | Err(Errno::EXIST) => {}
        Err(errno) => return Err(io_error("make a directory of the store", errno)),
    }
    open_step(parent, name)?.ok_or_else(unsafe_path)
}

/// What is at a blob's path.
enum Present {
    /// A regular file, with its size.
    Regular(u64),
    /// Nothing.
    Absent,
    /// A link, a directory, a pipe or anything else that is not a plain file.
    NotAFile,
}

/// Looks at the blob's name in its directory without following a link and without blocking on a
/// pipe.
fn look(directory: &OwnedFd, name: &str) -> Result<Present, ArtifactError> {
    let opened = rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    );
    match opened {
        Ok(fd) => {
            let stat = rustix::fs::fstat(&fd).map_err(|errno| io_error("look at a blob", errno))?;
            if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
                Ok(Present::Regular(u64::try_from(stat.st_size).unwrap_or(0)))
            } else {
                Ok(Present::NotAFile)
            }
        }
        Err(Errno::NOENT) => Ok(Present::Absent),
        Err(Errno::LOOP | Errno::NOTDIR | Errno::MLINK) => Ok(Present::NotAFile),
        Err(errno) => Err(io_error("open a blob", errno)),
    }
}

impl LocalFsArtifactStore {
    /// Opens the store on `root`, creating the directory (mode `0700`) when it is missing.
    ///
    /// The path is resolved once, here, and the store keeps an open descriptor of the real
    /// directory. A later change to the path, such as a link put in its place, does not move the
    /// store.
    ///
    /// # Errors
    /// Returns [`ArtifactError::Io`] when the directory cannot be made or opened.
    pub fn open(root: impl AsRef<Path>, max_object_bytes: u64) -> Result<Self, ArtifactError> {
        use std::os::unix::fs::DirBuilderExt;
        let root = root.as_ref();
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(DIRECTORY_MODE)
            .create(root)
            .map_err(|error| plain_io_error("make the root directory", &error))?;
        let resolved = std::fs::canonicalize(root)
            .map_err(|error| plain_io_error("resolve the root directory", &error))?;
        let descriptor = rustix::fs::open(
            &resolved,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| io_error("open the root directory", errno))?;
        Ok(Self {
            inner: Arc::new(Inner {
                root: descriptor,
                max_object_bytes,
                temp_counter: AtomicU64::new(0),
            }),
        })
    }

    /// The largest object the store accepts, in bytes.
    #[must_use]
    pub fn max_object_bytes(&self) -> u64 {
        self.inner.max_object_bytes
    }
}

fn put_blocking(
    inner: &Inner,
    bytes: &[u8],
    media_type: MediaType,
) -> Result<ArtifactRef, ArtifactError> {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if length > inner.max_object_bytes {
        return Err(ArtifactError::TooLarge {
            limit: inner.max_object_bytes,
        });
    }
    let sha256 = Sha256Digest::of(bytes);
    let reference = ArtifactRef {
        sha256: sha256.clone(),
        media_type,
        size_bytes: NonNegativeInt::new(i64::try_from(length).unwrap_or(i64::MAX)).ok(),
    };
    let directory = walk_creating(&inner.root, &sha256)?;
    let [_, _, name] = components(&sha256);

    // A blob that is already there is not written again. If its size is wrong it is damaged, and
    // the bytes in hand replace it. A link or another kind of file in its place is replaced too:
    // the rename replaces the link itself and never touches what it pointed at.
    match look(&directory, &name)? {
        Present::Regular(size) if size == length => return Ok(reference),
        Present::Regular(_) | Present::NotAFile | Present::Absent => {}
    }

    let counter = inner.temp_counter.fetch_add(1, Ordering::Relaxed);
    let temporary = format!(".tmp-{}-{counter}", std::process::id());
    let created = rustix::fs::openat(
        &directory,
        temporary.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(BLOB_MODE.try_into().unwrap_or(0o400)),
    )
    .map_err(|errno| io_error("create the temporary file", errno))?;

    let written = (|| {
        let mut file = File::from(created);
        file.write_all(bytes)
            .map_err(|error| plain_io_error("write the blob", &error))?;
        // The bytes reach the disk before the name does.
        file.sync_all()
            .map_err(|error| plain_io_error("flush the blob", &error))?;
        rustix::fs::renameat(&directory, temporary.as_str(), &directory, name.as_str())
            .map_err(|errno| io_error("move the blob into place", errno))?;
        // And the name reaches the disk too.
        rustix::fs::fsync(&directory).map_err(|errno| io_error("flush the directory", errno))
    })();
    if let Err(error) = written {
        // Remove the temporary file. If the rename already happened there is nothing to remove.
        let _ = rustix::fs::unlinkat(&directory, temporary.as_str(), AtFlags::empty());
        return Err(error);
    }
    Ok(reference)
}

fn get_blocking(inner: &Inner, reference: &ArtifactRef) -> Result<Vec<u8>, ArtifactError> {
    let expected = &reference.sha256;
    let Walk::Found(directory) = walk(&inner.root, expected)? else {
        return Err(ArtifactError::NotFound);
    };
    let [_, _, name] = components(expected);
    let opened = rustix::fs::openat(
        &directory,
        name.as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    );
    let descriptor = match opened {
        Ok(descriptor) => descriptor,
        Err(Errno::NOENT) => return Err(ArtifactError::NotFound),
        Err(Errno::LOOP | Errno::NOTDIR | Errno::MLINK) => return Err(unsafe_path()),
        Err(errno) => return Err(io_error("open the blob", errno)),
    };
    let stat =
        rustix::fs::fstat(&descriptor).map_err(|errno| io_error("look at the blob", errno))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(unsafe_path());
    }
    if u64::try_from(stat.st_size).unwrap_or(u64::MAX) > inner.max_object_bytes {
        return Err(ArtifactError::Io(
            "the stored blob is larger than the limit of the store".to_owned(),
        ));
    }
    let mut bytes = Vec::new();
    File::from(descriptor)
        .take(inner.max_object_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| plain_io_error("read the blob", &error))?;
    let actual = Sha256Digest::of(&bytes);
    if &actual != expected {
        return Err(ArtifactError::HashMismatch {
            expected: expected.clone(),
            actual,
        });
    }
    Ok(bytes)
}

fn exists_blocking(inner: &Inner, reference: &ArtifactRef) -> Result<bool, ArtifactError> {
    let Walk::Found(directory) = walk(&inner.root, &reference.sha256)? else {
        return Ok(false);
    };
    let [_, _, name] = components(&reference.sha256);
    Ok(matches!(look(&directory, &name)?, Present::Regular(_)))
}

/// Runs a blocking file system call on the blocking pool, so the runtime keeps running.
async fn blocking<T: Send + 'static>(
    call: impl FnOnce() -> Result<T, ArtifactError> + Send + 'static,
) -> Result<T, ArtifactError> {
    tokio::task::spawn_blocking(call)
        .await
        .map_err(|_| ArtifactError::Io("the file system task did not finish".to_owned()))?
}

#[async_trait]
impl ArtifactStore for LocalFsArtifactStore {
    fn backend(&self) -> ArtifactBackend {
        ArtifactBackend::LocalFs
    }

    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn put(
        &self,
        bytes: Vec<u8>,
        media_type: MediaType,
    ) -> Result<ArtifactRef, ArtifactError> {
        let inner = self.inner.clone();
        blocking(move || put_blocking(&inner, &bytes, media_type)).await
    }

    async fn get(&self, reference: &ArtifactRef) -> Result<Vec<u8>, ArtifactError> {
        let inner = self.inner.clone();
        let reference = reference.clone();
        blocking(move || get_blocking(&inner, &reference)).await
    }

    async fn exists(&self, reference: &ArtifactRef) -> Result<bool, ArtifactError> {
        let inner = self.inner.clone();
        let reference = reference.clone();
        blocking(move || exists_blocking(&inner, &reference)).await
    }
}
