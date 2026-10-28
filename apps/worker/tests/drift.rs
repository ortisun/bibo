//! The evidence-drift seam over a real engine and PostgreSQL: the delivery stage reports that a
//! value the gate evidence is bound to changed, the loop that owns the engine makes the call, and
//! the stage runs that rested on the old value are replaced.

mod support;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use factory_composition::drift::channel;
use factory_composition::system::{RandomIds, Shutdown, TokioTicker};
use factory_domain::ids::{JobId, TenantId};
use factory_domain::state::StageRunStatus;
use factory_domain::vocabulary::StageKind;
use factory_ports::clock::IdGenerator;
use factory_worker::run::WorkerLoop;
use factory_workflow::engine::JobView;
use factory_workflow::stages::delivery::SeamError;
use factory_workflow::stages::delivery::seams::EvidenceDrift;
use support::engine::{Eval, PgWorld, Step};
use support::{TestDb, seed_tenant, seeded_repository, server, worker_config};
use tokio::task::LocalSet;

async fn world() -> (TestDb, PgWorld, TenantId) {
    let db = server().clone_database().await;
    let ids = RandomIds::new().expect("the random source opens");
    let tenant = TenantId::from_uuid(ids.new_uuid());
    seed_tenant(&db, tenant, 0, "org/repo-0").await;
    let store = factory_storage::pg::PgStore::connect(worker_config(&db).await)
        .await
        .expect("the store becomes ready");
    let world = PgWorld::new(store, tenant, seeded_repository(tenant), |_| {}).await;
    (db, world, tenant)
}

fn statuses_of(view: &JobView, kind: StageKind) -> Vec<StageRunStatus> {
    view.runs_of(kind).map(|run| run.status).collect()
}

/// Claims and runs stages one at a time until the approval has run and waits for a person.
async fn run_to_the_approval(world: &PgWorld) {
    world
        .script(StageKind::Approval)
        .evals_otherwise(Eval::HumanGate);
    loop {
        let claimed = world.claim_one("worker-a").await;
        world
            .engine
            .run_attempt(&claimed)
            .await
            .expect("the attempt runs");
        if claimed.kind == StageKind::Approval {
            return;
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_changed_binding_replaces_the_runs_that_rested_on_the_old_one() {
    LocalSet::new()
        .run_until(async {
            let (_db, world, tenant) = world().await;
            let job = world.admitted_job().await;
            run_to_the_approval(&world).await;
            let before = world.view(job).await;
            assert_eq!(
                statuses_of(&before, StageKind::Validation),
                vec![StageRunStatus::Passed]
            );

            let (drift, pump) = channel();
            let (answer, served) = tokio::join!(
                drift.binding_changed(tenant, job),
                pump.serve_next(&world.engine)
            );
            assert_eq!(answer, Ok(()));
            assert!(served);

            let after = world.view(job).await;
            // The gate evidence and everything after it is replaced; the code and the
            // documentation text did not change, so their runs stand.
            for kind in [
                StageKind::Validation,
                StageKind::Review,
                StageKind::DocumentationReview,
                StageKind::Delivery,
                StageKind::Approval,
            ] {
                let runs = statuses_of(&after, kind);
                assert_eq!(runs.len(), 2, "{kind}: {runs:?}");
                assert_eq!(runs[0], StageRunStatus::Superseded, "{kind}");
                assert_ne!(runs[1], StageRunStatus::Superseded, "{kind}");
            }
            assert_eq!(
                statuses_of(&after, StageKind::Implementation),
                vec![StageRunStatus::Passed]
            );
            assert_eq!(
                statuses_of(&after, StageKind::Documenting),
                vec![StageRunStatus::Passed]
            );
        })
        .await;
}

/// The deliberate break: a drift seam that says "done" and tells nobody. The stale evidence stays
/// valid, which is exactly what the previous test shows the real seam prevents.
struct IgnoresDrift;

#[async_trait]
impl EvidenceDrift for IgnoresDrift {
    async fn binding_changed(&self, _: TenantId, _: JobId) -> Result<(), SeamError> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn a_drift_seam_that_ignores_the_report_leaves_stale_evidence_standing() {
    LocalSet::new()
        .run_until(async {
            let (_db, world, tenant) = world().await;
            let job = world.admitted_job().await;
            run_to_the_approval(&world).await;
            IgnoresDrift
                .binding_changed(tenant, job)
                .await
                .expect("it always says done");
            let after = world.view(job).await;
            assert_eq!(
                statuses_of(&after, StageKind::Validation),
                vec![StageRunStatus::Passed],
                "nothing was replaced: the evidence bound to the old value still counts"
            );
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn the_loop_serves_a_report_while_an_attempt_is_running() {
    LocalSet::new()
        .run_until(async {
            let (_db, world, tenant) = world().await;
            // The first stage waits, as a stage does while it works.
            let release = Arc::new(tokio::sync::Notify::new());
            world
                .script(StageKind::Intake)
                .queue([Step::Hang(release.clone())]);
            let job = world.admitted_job().await;
            let (drift, pump) = channel();
            let shutdown = Shutdown::new();
            let worker_loop = WorkerLoop::new(
                world.restarted_engine(),
                Arc::new(TokioTicker),
                PgWorld::worker("worker-drift"),
                PgWorld::loop_settings(),
                shutdown.clone(),
            )
            .with_drift_pump(Arc::new(pump));
            let task = tokio::task::spawn_local(async move { worker_loop.run().await });
            let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
            while world.script(StageKind::Intake).executed().is_empty() {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the stage never started"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            // The handler's side: it reports, and the loop that owns the engine answers while the
            // attempt is still running.
            let answer =
                tokio::time::timeout(Duration::from_secs(30), drift.binding_changed(tenant, job))
                    .await
                    .expect("the loop answered in time");
            assert_eq!(answer, Ok(()));
            release.notify_waiters();
            shutdown.raise();
            let summary = task.await.expect("the loop ends");
            assert_eq!(summary.failure, None, "{summary:?}");
        })
        .await;
}
