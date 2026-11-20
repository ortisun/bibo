//! Defects that the first meeting of the engine and the PostgreSQL store showed, written as tests
//! so that they cannot be forgotten and cannot be fixed without someone noticing.
//!
//! Each test first asserted the **defective** behaviour. Both causes are fixed in
//! `factory-workflow` (ADR 0014, amendments 1 and 2), and the assertions now state the intended
//! behaviour. The tests stay as the regression guard for the two defects.

mod support;

use factory_domain::state::JobStatus;
use factory_domain::vocabulary::{HumanRole, StageKind};
use factory_workflow::commands::{Decision, Subject};
use factory_workflow::engine::EngineError;
use support::engine::{Eval, PgWorld};
use support::{seed_tenant, seeded_repository, server, worker_config};

/// DEFECT 1, engine against `PgStore`: a person's approval was refused. FIXED.
///
/// `Engine::decide` approved a stage run with `GateRecord { outcome: Passed, report_sha256: None }`.
/// The port says a report hash is `None` only for `NOT_APPLICABLE` (`ports::store::GateRecord`), and
/// `PgStore::transition_stage_run` refused the move as `ConstraintRule::GateRecordRule`. The
/// in-memory store did not check, so the engine suite passed. Because a job completes only after
/// an approval that was recorded, no job could complete on PostgreSQL.
///
/// Now `decide` stores a `human-approval` document, indexes it for the tenant and passes its hash
/// as the report (ADR 0014, amendment 1). The approval applies and the job is `COMPLETED`.
#[tokio::test(flavor = "multi_thread")]
async fn defect_1_fixed_a_persons_approval_is_recorded_on_postgres_and_the_job_completes() {
    let db = server().clone_database().await;
    let ids = factory_composition::system::RandomIds::new().expect("random");
    let tenant =
        factory_domain::ids::TenantId::from_uuid(factory_ports::clock::IdGenerator::new_uuid(&ids));
    seed_tenant(&db, tenant, 0, "org/repo-0").await;
    let store = factory_storage::pg::PgStore::connect(worker_config(&db).await)
        .await
        .expect("ready");
    let world = PgWorld::new(store, tenant, seeded_repository(tenant), |_| {}).await;
    world
        .script(StageKind::Approval)
        .evals_otherwise(Eval::HumanGate);
    let job = world.admitted_job().await;
    for _ in 0..13 {
        let claimed = world
            .engine
            .claim_next(&PgWorld::worker("worker-1"))
            .await
            .expect("claim");
        for attempt in claimed.started {
            world.engine.run_attempt(&attempt).await.expect("runs");
        }
        // The scripted retries and back-offs are short; give the next stage run time to be ready.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    }
    let view = world.view(job).await;
    let run = view
        .newest(StageKind::Approval)
        .expect("an approval run")
        .id;
    let approver = world.person("approver-x", &[HumanRole::Approver]).await;
    let seen = world.head(job).await;
    world
        .engine
        .decide(
            &world.actor(approver),
            Subject {
                job,
                stage_run: run,
            },
            Decision::Approve {
                evidence_seen: seen,
                warnings_decided: true,
                proof: None,
            },
        )
        .await
        .expect("PostgreSQL records the approval");
    assert_eq!(world.view(job).await.status, JobStatus::Completed);
}

/// DEFECT 2, engine against `PgStore`: admitting a job twice was refused with a store constraint
/// and not with the typed error the in-memory suite expects. FIXED.
///
/// `a_job_cannot_be_admitted_twice` (engine suite) expects `EngineError::Illegal`. On PostgreSQL
/// the second admission reached the store, which refused the stage runs it was asked to insert as
/// `ConstraintRule::IdReusedWithDifferentContent`. The job was protected either way, but a caller
/// could not tell "already admitted" from a defect of the store.
///
/// Now the job moves first, and the state machine refuses the second admission as `Illegal` before
/// any stage run is planned (ADR 0014, amendment 2).
#[tokio::test(flavor = "multi_thread")]
async fn defect_2_fixed_a_second_admission_is_a_typed_illegal_error_on_postgres() {
    let db = server().clone_database().await;
    let ids = factory_composition::system::RandomIds::new().expect("random");
    let tenant =
        factory_domain::ids::TenantId::from_uuid(factory_ports::clock::IdGenerator::new_uuid(&ids));
    seed_tenant(&db, tenant, 0, "org/repo-0").await;
    let store = factory_storage::pg::PgStore::connect(worker_config(&db).await)
        .await
        .expect("ready");
    let world = PgWorld::new(store, tenant, seeded_repository(tenant), |_| {}).await;
    let job = world.admitted_job().await;
    let again = world.engine.admit_job(world.tenant, job).await;
    assert!(matches!(again, Err(EngineError::Illegal(_))), "{again:?}");
    assert_eq!(world.view(job).await.stage_runs.len(), 13);
}
