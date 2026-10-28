//! Defects that the first meeting of the engine and the PostgreSQL store showed, written as tests
//! so that they cannot be forgotten and cannot be fixed without someone noticing.
//!
//! Each test asserts the **defective** behaviour. When the owning package fixes the cause, the
//! test fails, and the person who fixes it changes the assertion to the intended behaviour (the
//! comment in each test says what that is).

mod support;

use factory_domain::vocabulary::{HumanRole, StageKind};
use factory_ports::store::{ConstraintRule, StoreError};
use factory_workflow::commands::{Decision, Subject};
use factory_workflow::engine::EngineError;
use support::engine::{Eval, PgWorld};
use support::{seed_tenant, seeded_repository, server, worker_config};

/// DEFECT 1, engine against `PgStore`: a person's approval is refused.
///
/// `Engine::decide` approves a stage run with `GateRecord { outcome: Passed, report_sha256: None }`
/// ("a person's approval has no gate report", `engine/decide.rs`). The port says a report hash is
/// `None` only for `NOT_APPLICABLE` (`ports::store::GateRecord`), and `PgStore::transition_stage_run`
/// refuses the move as `ConstraintRule::GateRecordRule`. The in-memory store does not check, so
/// the engine suite passes. Because a job completes only after an approval that was recorded, no
/// job can complete on PostgreSQL.
///
/// Intended behaviour after the fix: `decide` stores the approval record as an artifact, indexes
/// it for the tenant and passes its hash as the report; this test then expects `Ok`, and the job
/// to be `COMPLETED`.
#[tokio::test(flavor = "multi_thread")]
async fn defect_1_a_persons_approval_is_refused_by_the_postgres_store() {
    let db = server().clone_database().await;
    let ids = factory_worker::system::RandomIds::new().expect("random");
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
    let refusal = world
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
            },
        )
        .await
        .expect_err("PostgreSQL refuses the approval today");
    assert!(
        matches!(
            refusal,
            EngineError::Store(StoreError::Constraint(ConstraintRule::GateRecordRule))
        ),
        "{refusal:?}"
    );
}
