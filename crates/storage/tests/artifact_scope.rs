//! Tenant-scoped artifact reads (architecture review F-15): a tenant reads a blob only when its own
//! artifact index says it holds it, and a blob that only another tenant holds looks like a blob
//! that does not exist. The checks run against the in-memory store and against PostgreSQL.
#![allow(clippy::disallowed_methods, clippy::disallowed_types)]

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::TenantId;
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, Sha256Digest};
use factory_ports::artifact::{ArtifactError, ArtifactStore};
use factory_ports::store::Store;
use factory_storage::artifact_fs::{LocalFsArtifactStore, TenantArtifacts};
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

async fn check_scoping(store: Arc<dyn Store>, a: TenantId, b: TenantId) {
    let scratch = Scratch::new();
    let blobs =
        Arc::new(LocalFsArtifactStore::open(scratch.0.join("blobs"), 1 << 20).expect("open"));
    let artifacts = TenantArtifacts::new(blobs.clone(), store);
    let (scope_a, scope_b) = (TenantScope::new(a), TenantScope::new(b));

    // Tenant A stores a blob and reads it back.
    let reference = artifacts
        .put(scope_a, b"tenant a's evidence".to_vec(), text(), None)
        .await
        .expect("A puts");
    assert_eq!(
        artifacts.get(scope_a, &reference).await.expect("A gets"),
        b"tenant a's evidence"
    );
    assert!(
        artifacts
            .exists(scope_a, &reference)
            .await
            .expect("A exists")
    );

    // Tenant B holds the hash and cannot read the blob. It also cannot tell that A holds it: the
    // answers are exactly the answers for a blob that nobody stored.
    assert_eq!(
        artifacts.get(scope_b, &reference).await,
        Err(ArtifactError::NotFound)
    );
    assert_eq!(
        artifacts.get(scope_b, &absent()).await,
        Err(ArtifactError::NotFound)
    );
    assert_eq!(artifacts.exists(scope_b, &reference).await, Ok(false));
    assert_eq!(artifacts.exists(scope_b, &absent()).await, Ok(false));

    // The blob store itself is not scoped. The tenant-scoped layer is what keeps B out, and the
    // raw store is for the code that writes and verifies blobs.
    assert!(blobs.exists(&reference).await.expect("raw exists"));

    // When B stores the same bytes it holds them too, and reads them. The bytes are stored once.
    let again = artifacts
        .put(scope_b, b"tenant a's evidence".to_vec(), text(), None)
        .await
        .expect("B puts the same bytes");
    assert_eq!(again.sha256, reference.sha256);
    assert_eq!(
        artifacts.get(scope_b, &reference).await.expect("B gets"),
        b"tenant a's evidence"
    );
    let hex = reference.sha256.hex().to_owned();
    let directory = scratch
        .0
        .join("blobs")
        .join("sha256")
        .join(&hex[0..2])
        .join(&hex[2..4]);
    assert_eq!(
        std::fs::read_dir(directory).expect("list").count(),
        1,
        "one blob for two tenants"
    );

    // A third tenant that never stored it is still out.
    let outsider = TenantScope::new(TenantId::from_uuid(uuid::Uuid::from_u128(0xdead)));
    assert_eq!(
        artifacts
            .exists(outsider, &reference)
            .await
            .ok()
            .filter(|held| *held),
        None
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_are_scoped_to_the_tenant_with_the_in_memory_store() {
    let ids = factory_testkit::fixtures::Ids::new();
    let store: Arc<dyn Store> = Arc::new(InMemoryStore::new(Arc::new(FakeClock::new())));
    check_scoping(store, ids.tenant(), ids.tenant()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_are_scoped_to_the_tenant_with_postgres() {
    let scene = Scene::new().await;
    let store: Arc<dyn Store> = Arc::new(scene.store.clone());
    check_scoping(store, scene.a, scene.b).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stage_run_of_another_tenant_is_refused_and_leaves_no_index_row() {
    let scene = Scene::new().await;
    let scratch = Scratch::new();
    let blobs =
        Arc::new(LocalFsArtifactStore::open(scratch.0.join("blobs"), 1 << 20).expect("open"));
    let artifacts = TenantArtifacts::new(blobs, Arc::new(scene.store.clone()));
    let job = scene.job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;

    // Tenant B names tenant A's stage run. The index refuses, and B does not come to hold the blob.
    let refused = artifacts
        .put(
            TenantScope::new(scene.b),
            b"b names a's run".to_vec(),
            text(),
            Some(run),
        )
        .await;
    assert!(matches!(refused, Err(ArtifactError::Io(_))), "{refused:?}");
    let reference = ArtifactRef {
        sha256: Sha256Digest::of(b"b names a's run"),
        media_type: text(),
        size_bytes: None,
    };
    assert_eq!(
        artifacts
            .exists(TenantScope::new(scene.b), &reference)
            .await,
        Ok(false)
    );

    // Tenant A may name its own stage run, and the index records it.
    artifacts
        .put(
            TenantScope::new(scene.a),
            b"a names its run".to_vec(),
            text(),
            Some(run),
        )
        .await
        .expect("A names its own run");
    assert_eq!(
        scene
            .db
            .number(&format!(
                "SELECT count(*) FROM artifacts WHERE created_by_stage_run_id = '{}'",
                run.as_uuid()
            ))
            .await,
        1
    );
}
