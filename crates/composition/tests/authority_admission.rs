//! `Authority::admission` is asked about the repository the job is for, so the three facts that are
//! about the repository are read from it: whether it is registered and enabled, whether its
//! protection preflight passed, and whether it has room for another job. Before this the question
//! carried no repository: the first fact was always true, the second always false and the quota
//! counted every job of the tenant.

mod support;

use std::path::PathBuf;
use std::sync::Arc;

use factory_composition::authority::StoreAuthority;
use factory_composition::seams::FileAllowlist;
use factory_composition::startup::load_policy;
use factory_domain::ids::RepositoryId;
use factory_domain::state::JobStatus;
use factory_ports::clock::IdGenerator;
use factory_workflow::commands::Authority;
use factory_workflow::engine::{Admission, Engine};
use support::pg_world;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_facts_about_the_repository_are_read_from_the_repository() {
    let (db, world, tenant) = pg_world().await;
    let policies = load_policy(&root(), &[]).expect("the real policies load");
    let checkout = root()
        .join("target/authority-admission")
        .join(world.ids.new_uuid().simple().to_string());
    std::fs::create_dir_all(checkout.join("allowlist")).expect("a directory");
    std::fs::write(
        checkout.join("allowlist/allowlist.yaml"),
        format!(
            "version: 1\nentries:\n  - tenant: {}\n    github_user_id: 1001\n    login: requester-one\n    designations: [requester]\n",
            tenant.as_uuid()
        ),
    )
    .expect("the allowlist file");
    let authority = Arc::new(StoreAuthority::new(
        world.store.clone(),
        Arc::new(FileAllowlist::in_checkout(&checkout)),
        Arc::clone(&policies.engine),
        world.deps.clock.clone(),
    ));
    let first = world.repository;
    let tenant_text = tenant.as_uuid();

    // A second repository of the same tenant.
    let second = RepositoryId::from_uuid(world.ids.new_uuid());
    db.run(&format!(
        "INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch) \
         VALUES ('{tenant_text}', '{}', 1000, 2999, 'org/repo-second', 'main');",
        second.as_uuid()
    ))
    .await;

    // 1. Registered, enabled, no preflight yet: the safe side.
    let facts = authority
        .admission(tenant, world.requester, first)
        .await
        .expect("facts");
    assert!(facts.requester_on_allowlist);
    assert!(facts.repository_registered_and_enabled);
    assert!(
        !facts.protection_preflight_passed,
        "no preflight is recorded"
    );
    assert!(facts.tenant_within_job_quota);

    // 2. The preflight passes: the fact follows the repository, and the other repository is not
    // touched by it.
    db.run(&format!(
        "UPDATE repositories SET protection_preflight_passed = true, version = version + 1 \
         WHERE tenant_id = '{tenant_text}' AND id = '{}'",
        first.as_uuid()
    ))
    .await;
    assert!(
        authority
            .admission(tenant, world.requester, first)
            .await
            .expect("facts")
            .protection_preflight_passed
    );
    assert!(
        !authority
            .admission(tenant, world.requester, second)
            .await
            .expect("facts")
            .protection_preflight_passed
    );

    // 3. A repository that is switched off, and one the tenant does not have.
    db.run(&format!(
        "UPDATE repositories SET enabled = false, version = version + 1 \
         WHERE tenant_id = '{tenant_text}' AND id = '{}'",
        second.as_uuid()
    ))
    .await;
    assert!(
        !authority
            .admission(tenant, world.requester, second)
            .await
            .expect("facts")
            .repository_registered_and_enabled
    );
    assert!(
        !authority
            .admission(
                tenant,
                world.requester,
                RepositoryId::from_uuid(world.ids.new_uuid())
            )
            .await
            .expect("facts")
            .repository_registered_and_enabled
    );

    // 4. The cap is per repository: the jobs of the first do not fill the second.
    let mut deps = world.deps.clone();
    deps.authority = authority.clone();
    let engine =
        Engine::new(deps, world.config.clone(), world.handlers.clone()).expect("an engine");
    let cap = policies.engine.budget.max_running_jobs_per_repo()
        + policies.engine.budget.max_queued_jobs_per_repo();
    for _ in 0..cap {
        engine
            .receive_job(tenant, world.requester, first)
            .await
            .expect("received");
    }
    assert!(
        !authority
            .admission(tenant, world.requester, first)
            .await
            .expect("facts")
            .tenant_within_job_quota,
        "the first repository is full"
    );
    db.run(&format!(
        "UPDATE repositories SET enabled = true, version = version + 1 \
         WHERE tenant_id = '{tenant_text}' AND id = '{}'",
        second.as_uuid()
    ))
    .await;
    assert!(
        authority
            .admission(tenant, world.requester, second)
            .await
            .expect("facts")
            .tenant_within_job_quota,
        "the second repository has room"
    );

    // 5. The engine acts on it: a job for a switched-off repository is rejected, not admitted.
    db.run(&format!(
        "UPDATE repositories SET enabled = false, version = version + 1 \
         WHERE tenant_id = '{tenant_text}' AND id = '{}'",
        second.as_uuid()
    ))
    .await;
    let job = engine
        .receive_job(tenant, world.requester, second)
        .await
        .expect("received");
    let admission = engine.admit_job(tenant, job).await.expect("a decision");
    assert_eq!(admission, Admission::Rejected);
    assert_eq!(
        engine.job_status(tenant, job).await.expect("a status"),
        JobStatus::Rejected
    );
    let _ = std::fs::remove_dir_all(&checkout);
}
