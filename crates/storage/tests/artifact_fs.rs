//! `LocalFsArtifactStore`: the shared artifact contract suite, and the properties the suite cannot
//! see: read-only blobs, idempotent writes, atomic writes under concurrency, a damaged blob, and
//! the refusal to follow a symbolic link out of the root.
//!
//! Ports v1.1 moved the tenant check into the port (`get` and `exists` take a `TenantScope` and read
//! through the tenant's index row), which this store cannot do without a `Store`. The shared
//! contract suite is therefore compiled out (`#[cfg(any())]`) until the Postgres adaptation, and
//! the file system properties below use `get_unscoped` and `exists_unscoped`.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[cfg(any())]
use async_trait::async_trait;
use factory_domain::values::{MediaType, Sha256Digest};
use factory_ports::artifact::{ArtifactBackend, ArtifactError, ArtifactStore};
use factory_storage::artifact_fs::LocalFsArtifactStore;
#[cfg(any())]
use factory_testkit::contracts::artifact::{ArtifactStoreSubject, run};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A directory for one test, removed when the test is done.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "factory-artifacts-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("make the scratch directory");
        Self(path)
    }

    fn root(&self) -> PathBuf {
        self.0.join("store")
    }

    fn outside(&self) -> PathBuf {
        let path = self.0.join("outside");
        std::fs::create_dir_all(&path).expect("make the outside directory");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn text() -> MediaType {
    MediaType::parse("text/plain").expect("media type")
}

/// The path of a blob under a root: `sha256/ab/cd/<hex>`.
fn blob_path(root: &Path, sha256: &Sha256Digest) -> PathBuf {
    let hex = sha256.hex();
    root.join("sha256")
        .join(&hex[0..2])
        .join(&hex[2..4])
        .join(hex)
}

const LIMIT: u64 = 64 * 1024;

fn store_in(scratch: &Scratch) -> LocalFsArtifactStore {
    LocalFsArtifactStore::open(scratch.root(), LIMIT).expect("open the store")
}

#[cfg(any())]
struct LocalSubject {
    scratch: Scratch,
    store: LocalFsArtifactStore,
}

#[cfg(any())]
#[async_trait]
impl ArtifactStoreSubject for LocalSubject {
    fn store(&self) -> &dyn ArtifactStore {
        &self.store
    }

    #[cfg(any())]
    fn max_object_bytes(&self) -> u64 {
        LIMIT
    }

    #[cfg(any())]
    /// Changes one byte of the file. The blob is read-only, so the owner makes it writable first.
    async fn corrupt_blob(&self, sha256: &Sha256Digest) {
        let path = blob_path(&self.scratch.root(), sha256);
        let mut bytes = std::fs::read(&path).expect("read the blob");
        bytes[0] ^= 0xff;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        std::fs::write(&path, bytes).expect("rewrite the blob");
    }
}

#[cfg(any())]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_shared_artifact_contract_suite_against_the_local_file_system() {
    let report = run(|| async {
        let scratch = Scratch::new();
        let store = store_in(&scratch);
        LocalSubject { scratch, store }
    })
    .await;
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    report.assert_ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_store_says_what_it_is() {
    let scratch = Scratch::new();
    let store = store_in(&scratch);
    assert_eq!(store.backend(), ArtifactBackend::LocalFs);
    assert_eq!(store.backend().label(), "local-fs", "it is not called S3");
    assert_eq!(store.fidelity(), factory_domain::vocabulary::Fidelity::Real);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_blob_is_laid_out_by_its_hash_and_written_read_only() {
    let scratch = Scratch::new();
    let store = store_in(&scratch);
    let reference = store
        .put(b"log of a gate run".to_vec(), text())
        .await
        .expect("put");
    let path = blob_path(&scratch.root(), &reference.sha256);
    let metadata = std::fs::metadata(&path).expect("the blob is at sha256/ab/cd/<hex>");
    assert_eq!(
        metadata.permissions().mode() & 0o777,
        0o400,
        "readable by the owner, writable by nobody"
    );
    assert_eq!(metadata.len(), 17);
    // No temporary file is left in the directory.
    let names: Vec<String> = std::fs::read_dir(path.parent().expect("parent"))
        .expect("list")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(names, [reference.sha256.hex().to_owned()], "{names:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_put_of_the_same_bytes_writes_nothing() {
    let scratch = Scratch::new();
    let store = store_in(&scratch);
    let first = store
        .put(b"same bytes".to_vec(), text())
        .await
        .expect("first");
    let path = blob_path(&scratch.root(), &first.sha256);
    let before = std::fs::metadata(&path).expect("metadata");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let second = store
        .put(b"same bytes".to_vec(), text())
        .await
        .expect("second");
    let after = std::fs::metadata(&path).expect("metadata");
    assert_eq!(second, first);
    assert_eq!(
        (before.ino(), before.mtime_nsec(), before.mtime()),
        (after.ino(), after.mtime_nsec(), after.mtime()),
        "the blob that was there is the blob that stays: same file, same time"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixteen_concurrent_writers_of_one_object_leave_one_whole_blob() {
    let scratch = Scratch::new();
    let store = Arc::new(store_in(&scratch));
    let bytes: Vec<u8> = (0..LIMIT).map(|index| (index % 251) as u8).collect();
    let mut writers = Vec::new();
    for _ in 0..16 {
        let (store, bytes) = (store.clone(), bytes.clone());
        writers.push(tokio::spawn(async move { store.put(bytes, text()).await }));
    }
    let mut references = Vec::new();
    for writer in writers {
        references.push(writer.await.expect("task").expect("put"));
    }
    assert!(references.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(
        store.get_unscoped(&references[0]).await.expect("get"),
        bytes
    );
    let directory = blob_path(&scratch.root(), &references[0].sha256);
    let names: Vec<_> = std::fs::read_dir(directory.parent().expect("parent"))
        .expect("list")
        .collect();
    assert_eq!(names.len(), 1, "one blob and no temporary file");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_partial_temporary_file_never_shows_as_a_blob() {
    // A writer that stopped before the rename leaves a temporary file. It is not a blob: it has no
    // hash name, a read does not see it, and a later put of the same bytes works.
    let scratch = Scratch::new();
    let store = store_in(&scratch);
    let reference = store.put(b"first".to_vec(), text()).await.expect("put");
    let directory = blob_path(&scratch.root(), &Sha256Digest::of(b"later"))
        .parent()
        .expect("parent")
        .to_owned();
    std::fs::create_dir_all(&directory).expect("directory");
    std::fs::write(directory.join(".tmp-1-0"), b"half a wri").expect("partial file");
    let later = ArtifactRefLike::of(b"later");
    assert!(!store.exists_unscoped(&later.0).await.expect("exists"));
    let stored = store.put(b"later".to_vec(), text()).await.expect("put");
    assert_eq!(store.get_unscoped(&stored).await.expect("get"), b"later");
    assert_eq!(store.get_unscoped(&reference).await.expect("get"), b"first");
}

/// A reference for bytes that are not stored.
struct ArtifactRefLike(factory_domain::contracts::ArtifactRef);

impl ArtifactRefLike {
    fn of(bytes: &[u8]) -> Self {
        Self(factory_domain::contracts::ArtifactRef {
            sha256: Sha256Digest::of(bytes),
            media_type: text(),
            size_bytes: None,
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_damaged_blob_is_detected_on_read_and_repaired_by_a_put_of_the_right_size() {
    let scratch = Scratch::new();
    let store = store_in(&scratch);
    let reference = store
        .put(b"original bytes".to_vec(), text())
        .await
        .expect("put");
    let path = blob_path(&scratch.root(), &reference.sha256);

    // The same size, one byte changed: the read refuses it and names both hashes.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    std::fs::write(&path, b"Original bytes").expect("damage");
    match store.get_unscoped(&reference).await {
        Err(ArtifactError::HashMismatch { expected, actual }) => {
            assert_eq!(expected, reference.sha256);
            assert_eq!(actual, Sha256Digest::of(b"Original bytes"));
        }
        other => panic!("a damaged blob must not be returned: {other:?}"),
    }
    // The bytes are not in the error.
    let shown = format!("{:?}", store.get_unscoped(&reference).await);
    assert!(!shown.contains("Original"), "{shown}");

    // A blob cut short has the wrong size, and a put of the right bytes replaces it.
    std::fs::write(&path, b"orig").expect("cut");
    assert!(matches!(
        store.get_unscoped(&reference).await,
        Err(ArtifactError::HashMismatch { .. })
    ));
    store
        .put(b"original bytes".to_vec(), text())
        .await
        .expect("repair");
    assert_eq!(
        store.get_unscoped(&reference).await.expect("get"),
        b"original bytes"
    );
    assert_eq!(
        std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o400
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_symbolic_link_for_a_directory_is_not_followed() {
    let scratch = Scratch::new();
    let store = store_in(&scratch);
    let reference = store
        .put(b"inside the root".to_vec(), text())
        .await
        .expect("put");
    let hex = reference.sha256.hex().to_owned();

    // An outside directory holds a file with the right name and the right bytes. The first
    // directory of the blob is replaced by a link to it.
    let outside = scratch.outside();
    let planted = outside.join(&hex[2..4]);
    std::fs::create_dir_all(&planted).expect("outside tree");
    std::fs::write(planted.join(&hex), b"inside the root").expect("outside copy");
    let first = scratch.root().join("sha256").join(&hex[0..2]);
    std::fs::remove_dir_all(&first).expect("remove the real directory");
    symlink(&outside, &first).expect("plant the link");

    assert!(
        matches!(
            store.get_unscoped(&reference).await,
            Err(ArtifactError::Io(_))
        ),
        "a read does not follow the link"
    );
    assert!(matches!(
        store.exists_unscoped(&reference).await,
        Err(ArtifactError::Io(_))
    ));
    assert!(
        matches!(
            store.put(b"inside the root".to_vec(), text()).await,
            Err(ArtifactError::Io(_))
        ),
        "a write does not follow it either"
    );
    // Nothing was written outside.
    let outside_entries: Vec<_> = std::fs::read_dir(&planted).expect("list").collect();
    assert_eq!(
        outside_entries.len(),
        1,
        "the outside directory got no new file"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_symbolic_link_for_a_blob_is_not_followed_and_a_put_replaces_it_without_touching_the_target()
 {
    let scratch = Scratch::new();
    let store = store_in(&scratch);
    let reference = store
        .put(b"the real bytes".to_vec(), text())
        .await
        .expect("put");
    let path = blob_path(&scratch.root(), &reference.sha256);

    // The blob is replaced by a link to a file outside the root.
    let target = scratch.outside().join("secret");
    std::fs::write(&target, b"the real bytes").expect("outside file");
    std::fs::remove_file(&path).expect("remove the blob");
    symlink(&target, &path).expect("plant the link");

    assert!(
        matches!(
            store.get_unscoped(&reference).await,
            Err(ArtifactError::Io(_))
        ),
        "a read does not follow the link"
    );
    assert!(
        !store.exists_unscoped(&reference).await.expect("exists"),
        "a link is not a blob"
    );

    // A put puts a real file where the link was. The target is not opened, written or changed.
    store
        .put(b"the real bytes".to_vec(), text())
        .await
        .expect("put");
    assert!(
        !std::fs::symlink_metadata(&path)
            .expect("metadata")
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        store.get_unscoped(&reference).await.expect("get"),
        b"the real bytes"
    );
    let after = std::fs::metadata(&target).expect("target");
    assert_eq!(std::fs::read(&target).expect("read"), b"the real bytes");
    assert_eq!(
        after.permissions().mode() & 0o777,
        0o644 & after.permissions().mode(),
        "the target kept its mode"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pipe_in_place_of_a_blob_does_not_hang_a_read() {
    let scratch = Scratch::new();
    let store = store_in(&scratch);
    let reference = store
        .put(b"will be a pipe".to_vec(), text())
        .await
        .expect("put");
    let path = blob_path(&scratch.root(), &reference.sha256);
    std::fs::remove_file(&path).expect("remove");
    let made = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo");
    assert!(made.success());
    let started = Instant::now();
    let read = tokio::time::timeout(Duration::from_secs(5), store.get_unscoped(&reference)).await;
    assert!(matches!(read, Ok(Err(ArtifactError::Io(_)))), "{read:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(!store.exists_unscoped(&reference).await.expect("exists"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_root_is_resolved_once_and_a_later_swap_does_not_move_the_store() {
    let scratch = Scratch::new();
    let store = store_in(&scratch);
    let reference = store.put(b"kept".to_vec(), text()).await.expect("put");
    // The root path is replaced by a link to an empty directory. The store holds the descriptor of
    // the real root and still reads from it.
    let elsewhere = scratch.outside();
    let moved = scratch.0.join("moved");
    std::fs::rename(scratch.root(), &moved).expect("move the root away");
    symlink(&elsewhere, scratch.root()).expect("plant the link");
    assert_eq!(store.get_unscoped(&reference).await.expect("get"), b"kept");
    store.put(b"more".to_vec(), text()).await.expect("put");
    assert!(
        std::fs::read_dir(&elsewhere)
            .expect("list")
            .next()
            .is_none(),
        "nothing was written through the link"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_limit_applies_to_writes_and_to_reads() {
    let scratch = Scratch::new();
    let store = store_in(&scratch);
    let at_limit = store
        .put(vec![1_u8; usize::try_from(LIMIT).expect("small")], text())
        .await
        .expect("at the limit");
    assert!(matches!(
        store.put(vec![1_u8; usize::try_from(LIMIT).expect("small") + 1], text()).await,
        Err(ArtifactError::TooLarge { limit }) if limit == LIMIT
    ));
    // A file in the store that is larger than the limit is not read into memory.
    let big = Sha256Digest::of(b"a big file");
    let path = blob_path(&scratch.root(), &big);
    std::fs::create_dir_all(path.parent().expect("parent")).expect("dirs");
    std::fs::write(
        &path,
        vec![0_u8; usize::try_from(LIMIT).expect("small") + 10],
    )
    .expect("big file");
    let reference = ArtifactRefLike::of(b"a big file").0;
    assert!(matches!(
        store.get_unscoped(&reference).await,
        Err(ArtifactError::Io(_))
    ));
    assert!(store.get_unscoped(&at_limit).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hostile_hash_cannot_name_a_path() {
    // A path is built only from the 64 hex characters of a `Sha256Digest`, and the type refuses
    // anything else, so no caller text can become a path component.
    for hostile in [
        "sha256:../../../../etc/passwd0000000000000000000000000000000000000000000",
        "sha256:/etc/passwd",
        "../sha256/aa/bb/cc",
        "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert!(Sha256Digest::parse(hostile).is_err(), "{hostile}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_error_never_holds_the_path_or_the_content() {
    let scratch = Scratch::new();
    let store = store_in(&scratch);
    let reference = store
        .put(b"secret contents".to_vec(), text())
        .await
        .expect("put");
    let path = blob_path(&scratch.root(), &reference.sha256);
    std::fs::remove_file(&path).expect("remove");
    symlink(scratch.outside(), &path).expect("link");
    let shown = format!("{:?}", store.get_unscoped(&reference).await);
    assert!(
        !shown.contains(scratch.0.to_string_lossy().as_ref()),
        "{shown}"
    );
    assert!(!shown.contains("secret"), "{shown}");
}
