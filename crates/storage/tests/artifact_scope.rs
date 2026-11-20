//! A tenant reads a blob only through its own row in the artifact index (ADR 0008, ports-v1.1
//! decision 9). A blob is stored once, by hash, and may be shared by tenants; the index row says
//! who may read it. A hash that only another tenant holds gives `NotFound` for `get` and `false`
//! for `exists`, the same answer as a hash nobody holds.
//!
//! The first test runs the scoping against the PostgreSQL store, where the index row is read under
//! row-level security. The second runs the same checks against the in-memory store, so the two
//! agree.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::TenantId;
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, NonNegativeInt, Sha256Digest};
use factory_ports::artifact::{ArtifactError, ArtifactStore};
use factory_ports::store::{NewArtifactIndexEntry, Store, StoreError};
use factory_storage::artifact_fs::LocalFsArtifactStore;
use factory_testkit::clock::FakeClock;
use factory_testkit::store::InMemoryStore;
use support::Scene;

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "factory-artifact-scope-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("make the scratch directory");
        Self(path)
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

fn absent() -> ArtifactRef {
    ArtifactRef {
        sha256: Sha256Digest::of(b"nobody stored this"),
        media_type: text(),
        size_bytes: None,
    }
}

/// Indexes the artifact for the tenant, as the transaction that uses it does.
async fn index(store: &dyn Store, tenant: TenantId, reference: &ArtifactRef) {
    let mut tx = store.begin(TenantScope::new(tenant)).await.expect("begin");
    tx.index_artifact(
        NewArtifactIndexEntry::from_reference(reference, None).expect("a reference with a size"),
    )
    .await
    .expect("index");
    tx.commit().await.expect("commit");
}

async fn check_scoping(store: Arc<dyn Store>, a: TenantId, b: TenantId) {
    let scratch = Scratch::new();
    let blobs =
        LocalFsArtifactStore::open(scratch.0.join("blobs"), 1 << 20, store.clone()).expect("open");
    let (scope_a, scope_b) = (TenantScope::new(a), TenantScope::new(b));

    // Tenant A stores and indexes a blob.
    let reference = blobs
        .put(b"a gate report".to_vec(), text())
        .await
        .expect("put");
    index(&*store, a, &reference).await;
    assert_eq!(
        blobs.get(&scope_a, &reference).await.expect("A reads it"),
        b"a gate report"
    );
    assert!(blobs.exists(&scope_a, &reference).await.expect("exists"));

    // Tenant B holds no row for the hash: the same answer as for a blob nobody stored.
    assert_eq!(
        blobs.get(&scope_b, &reference).await,
        Err(ArtifactError::NotFound)
    );
    assert_eq!(
        blobs.get(&scope_b, &absent()).await,
        Err(ArtifactError::NotFound)
    );
    assert!(!blobs.exists(&scope_b, &reference).await.expect("exists"));
    assert!(!blobs.exists(&scope_b, &absent()).await.expect("exists"));

    // Once B indexes the same bytes it reads them; A's row did not change.
    index(&*store, b, &reference).await;
    assert_eq!(
        blobs.get(&scope_b, &reference).await.expect("B reads it"),
        b"a gate report"
    );
    // A row without a blob reads as missing, not as an error of the index.
    let unstored = ArtifactRef {
        size_bytes: NonNegativeInt::new(5).ok(),
        ..absent()
    };
    index(&*store, a, &unstored).await;
    assert_eq!(
        blobs.get(&scope_a, &unstored).await,
        Err(ArtifactError::NotFound)
    );
    assert!(!blobs.exists(&scope_a, &unstored).await.expect("exists"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_are_scoped_to_the_tenant_with_postgres() {
    let scene = Scene::new().await;
    check_scoping(Arc::new(scene.store.clone()), scene.a, scene.b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_are_scoped_to_the_tenant_with_the_in_memory_store() {
    let ids = factory_testkit::fixtures::Ids::new();
    let store = Arc::new(InMemoryStore::new(Arc::new(FakeClock::new())));
    check_scoping(store, ids.tenant(), ids.tenant()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_index_row_is_the_tenants_own() {
    let scene = Scene::new().await;
    let reference = ArtifactRef {
        sha256: Sha256Digest::of(b"blob"),
        media_type: text(),
        size_bytes: NonNegativeInt::new(4).ok(),
    };
    index(&scene.store, scene.a, &reference).await;

    let mut mine = scene.tx(scene.a).await;
    let row = mine
        .get_artifact_index(&reference.sha256)
        .await
        .expect("A's row");
    assert_eq!(row.tenant_id, scene.a);
    assert_eq!(row.artifact.size_bytes.map(NonNegativeInt::get), Some(4));
    // A second index call returns the first row.
    let again = mine
        .index_artifact(NewArtifactIndexEntry::from_reference(&reference, None).expect("a size"))
        .await
        .expect("a replay");
    assert_eq!(again, row);
    drop(mine);

    let mut other = scene.tx(scene.b).await;
    assert_eq!(
        other.get_artifact_index(&reference.sha256).await,
        Err(StoreError::NotFound),
        "another tenant's artifact index row"
    );

    // The size is required by the table, and so by the entry: a reference without one cannot be
    // turned into an entry, so nothing can be stored as zero or invented by the adapter.
    let unsized_reference = ArtifactRef {
        size_bytes: None,
        sha256: Sha256Digest::of(b"no size"),
        ..reference
    };
    assert_eq!(
        NewArtifactIndexEntry::from_reference(&unsized_reference, None),
        None
    );
    assert_eq!(
        scene
            .db
            .number(&format!(
                "SELECT count(*) FROM artifacts WHERE content_sha256 = '{}'",
                unsized_reference.sha256
            ))
            .await,
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stage_run_of_another_tenant_is_refused_and_leaves_no_index_row() {
    let scene = Scene::new().await;
    let job = scene.active_job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    let reference = ArtifactRef {
        sha256: Sha256Digest::of(b"made by A"),
        media_type: text(),
        size_bytes: NonNegativeInt::new(9).ok(),
    };
    // Tenant B names tenant A's stage run as the origin of its artifact.
    let mut tx = scene.tx(scene.b).await;
    assert_eq!(
        tx.index_artifact(NewArtifactIndexEntry {
            origin: Some((job, run)),
            ..NewArtifactIndexEntry::from_reference(&reference, None).expect("a size")
        })
        .await,
        Err(StoreError::NotFound)
    );
    drop(tx);
    assert_eq!(
        scene
            .db
            .number(&format!(
                "SELECT count(*) FROM artifacts WHERE content_sha256 = '{}'",
                reference.sha256
            ))
            .await,
        0
    );
    // Tenant A may.
    let mut tx = scene.tx(scene.a).await;
    let row = tx
        .index_artifact(NewArtifactIndexEntry {
            origin: Some((job, run)),
            ..NewArtifactIndexEntry::from_reference(&reference, None).expect("a size")
        })
        .await
        .expect("A's own stage run");
    assert_eq!(row.origin, Some((job, run)));
}
