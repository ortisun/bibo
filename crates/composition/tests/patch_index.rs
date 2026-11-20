//! A patch exported from the job's object store is readable by the tenant that owns the job only
//! after it is indexed for that tenant; the wrapper indexes it, and it fails closed for a job the
//! loop does not know.

mod support;

use std::sync::Arc;

use factory_composition::indexing::{ActiveJobs, IndexingWorkspaces};
use factory_composition::system::Shutdown;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::scope::TenantScope;
use factory_ports::artifact::ArtifactError;
use factory_ports::paths::{BranchName, RepoRef};
use factory_ports::workspace::{FetchCredential, FetchTarget, WorkspaceError, WorkspaceProvider};
use factory_testkit::contracts::workspace::fixture_rules;
use factory_testkit::workspace::{FakeRemote, FakeWorkspaceProvider};
use support::engine::PgWorld;
use support::pg_world;

struct Scene {
    _db: support::TestDb,
    world: PgWorld,
    tenant: TenantId,
    job: JobId,
    provider: Arc<FakeWorkspaceProvider>,
    base: factory_ports::paths::CommitSha,
    head: factory_ports::paths::CommitSha,
}

async fn scene() -> Scene {
    let (db, world, tenant) = pg_world().await;
    let job = world.admitted_job().await;
    let repo = RepoRef::parse("example-org/fixture").expect("a repository");
    let branch = BranchName::new("main").expect("a branch");
    let remote = FakeRemote::new();
    let base = remote.commit_on_branch(&repo, &branch, &[("src/lib.rs", "pub fn one() {}\n")]);
    let provider = Arc::new(FakeWorkspaceProvider::new(
        repo.clone(),
        remote.clone(),
        world.deps.artifacts.clone(),
        fixture_rules(),
    ));
    let head = remote.commit_on_branch(
        &repo,
        &branch,
        &[("src/lib.rs", "pub fn one() {}\npub fn two() {}\n")],
    );
    let target = FetchTarget {
        repo,
        credential: FetchCredential::new("fixture".to_owned()),
    };
    provider
        .fetch(job, &target, &branch, &Shutdown::new())
        .await
        .expect("fetched");
    Scene {
        _db: db,
        world,
        tenant,
        job,
        provider,
        base,
        head,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_patch_that_is_not_indexed_cannot_be_read_by_its_tenant() {
    let s = scene().await;
    // Without the wrapper: the provider stores the patch and makes no index row.
    let repo = s.provider.repo(s.job).await.expect("the job repository");
    let exported = repo
        .export_patch(&s.base, &s.head, 1 << 20, &Shutdown::new())
        .await
        .expect("a patch");
    let refused = s
        .world
        .deps
        .artifacts
        .get(&TenantScope::new(s.tenant), &exported.patch)
        .await;
    assert_eq!(refused, Err(ArtifactError::NotFound));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_wrapper_indexes_the_patch_for_the_tenant_and_for_no_other() {
    let s = scene().await;
    let jobs = Arc::new(ActiveJobs::new());
    jobs.enter(s.job, s.tenant);
    let wrapped = IndexingWorkspaces::new(s.provider.clone(), s.world.store.clone(), jobs);
    let repo = wrapped.repo(s.job).await.expect("the job repository");
    let exported = repo
        .export_patch(&s.base, &s.head, 1 << 20, &Shutdown::new())
        .await
        .expect("a patch");
    let bytes = s
        .world
        .deps
        .artifacts
        .get(&TenantScope::new(s.tenant), &exported.patch)
        .await
        .expect("the tenant that owns the job reads its patch");
    assert!(String::from_utf8_lossy(&bytes).contains("two"));
    // Another tenant cannot read it, whatever it knows of the hash.
    let stranger = TenantId::from_uuid(uuid::Uuid::from_u128(0xdead_beef));
    assert_eq!(
        s.world
            .deps
            .artifacts
            .get(&TenantScope::new(stranger), &exported.patch)
            .await,
        Err(ArtifactError::NotFound)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_wrapper_fails_closed_for_a_job_the_loop_does_not_know() {
    let s = scene().await;
    let wrapped = IndexingWorkspaces::new(
        s.provider.clone(),
        s.world.store.clone(),
        Arc::new(ActiveJobs::new()),
    );
    let repo = wrapped.repo(s.job).await.expect("the job repository");
    let refused = repo
        .export_patch(&s.base, &s.head, 1 << 20, &Shutdown::new())
        .await;
    assert!(
        matches!(refused, Err(WorkspaceError::Io(_))),
        "an unknown job must not export a patch nobody can read: {refused:?}"
    );
}
