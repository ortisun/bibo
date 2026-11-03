//! The repository of a job, as the registered row holds it (finding RH-3).
//!
//! The design gate judges the person who approved a design by the GitHub id of the registered
//! repository, so the seam that names the repository of a job must carry that id from the row and
//! from nowhere else. Real: `StoreRepositories`, the store's transactions. **Fake, and labelled
//! so:** the store (`InMemoryStore`) and the clock.

use std::sync::Arc;

use factory_composition::seams::StoreRepositories;
use factory_domain::ids::{CorrelationId, JobId, PrincipalId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::vocabulary::{AutonomyLevel, ExecutionMode, StageKind};
use factory_ports::clock::Uuid;
use factory_ports::store::{NewJob, NewPrincipal, PipelineScope, PrincipalKind, Store};
use factory_testkit::clock::FakeClock;
use factory_testkit::store::InMemoryStore;
use factory_workflow::stages::intake::SeamError;
use factory_workflow::stages::repo_intel::JobRepository;

fn uid(n: u128) -> Uuid {
    Uuid::from_u128(0x018f_3a00_0000_7000_8000_0000_0000_0000 + n)
}

struct Rig {
    store: Arc<InMemoryStore>,
    tenant: TenantId,
    job: JobId,
}

async fn rig() -> Rig {
    let clock = Arc::new(FakeClock::starting_at("2026-11-03T10:00:00Z"));
    let store = Arc::new(InMemoryStore::new(clock));
    let tenant = TenantId::from_uuid(uid(1));
    let repository = store.seed_repository(tenant);
    let principal = PrincipalId::from_uuid(uid(2));
    let job = JobId::from_uuid(uid(3));
    let mut tx = store.begin(TenantScope::new(tenant)).await.unwrap();
    tx.insert_principal(NewPrincipal {
        id: principal,
        kind: PrincipalKind::Human {
            github_user_id: 1001,
        },
        login: Some("octocat".to_owned()),
    })
    .await
    .unwrap();
    tx.insert_job(NewJob {
        id: job,
        correlation_id: CorrelationId::from_uuid(uid(4)),
        repository,
        requester: principal,
        execution_mode: ExecutionMode::Test,
        autonomy_level: AutonomyLevel::L1,
        pipeline_scope: PipelineScope::new(vec![StageKind::Intake]).unwrap(),
        origin: None,
    })
    .await
    .unwrap();
    tx.commit().await.unwrap();
    Rig { store, tenant, job }
}

#[tokio::test]
async fn the_repository_of_a_job_carries_the_github_id_of_the_registered_row() {
    let rig = rig().await;
    let seam = StoreRepositories::new(rig.store.clone());
    let target = seam
        .of(rig.tenant, rig.job)
        .await
        .expect("the row is found");
    assert_eq!(
        (target.repo.owner(), target.repo.name()),
        ("acme", "widgets"),
        "the name the row was registered under"
    );
    assert_eq!(target.branch.as_str(), "main");
    // `seed_repository` registers the first repository with the GitHub id 1001, and the name says
    // nothing of it: the id is read from the row.
    assert_eq!(target.github_repository_id, 1001);
}

#[tokio::test]
async fn a_job_the_tenant_does_not_have_has_no_repository_and_another_tenant_cannot_read_it() {
    let rig = rig().await;
    let seam = StoreRepositories::new(rig.store.clone());
    let unknown = JobId::from_uuid(uid(99));
    assert_eq!(
        seam.of(rig.tenant, unknown).await.map(|_| ()),
        Err(SeamError::NotFound)
    );
    let stranger = TenantId::from_uuid(uid(50));
    assert_eq!(
        seam.of(stranger, rig.job).await.map(|_| ()),
        Err(SeamError::NotFound),
        "a job is read by its own tenant only"
    );
}
