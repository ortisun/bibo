//! The loop stays alive for everyone: it sweeps while it is busy.
//!
//! Real: PostgreSQL, the engine, the loop and the ticker. Scripted: the stage handlers (the engine
//! suite's), as in the other loop tests.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use factory_composition::system::{RandomIds, Shutdown, TokioTicker};
use factory_domain::ids::TenantId;
use factory_domain::state::AttemptStatus;
use factory_domain::vocabulary::StageKind;
use factory_ports::clock::IdGenerator;
use factory_storage::pg::PgStore;
use factory_worker::run::{Flow, Observer, WorkerLoop};
use factory_workflow::engine::{AttemptOutcome, EngineConfig};
use factory_workflow::scheduler::ClaimedAttempt;
use support::engine::{PgWorld, Step};
use support::{seed_tenant, seeded_repository, server, worker_config};

async fn world(tune: impl FnOnce(&mut EngineConfig)) -> (support::TestDb, PgWorld, TenantId) {
    let db = server().clone_database().await;
    let ids = RandomIds::new().expect("random");
    let tenant = TenantId::from_uuid(ids.new_uuid());
    seed_tenant(&db, tenant, 0, "org/repo-0").await;
    let store = PgStore::connect(worker_config(&db).await)
        .await
        .expect("ready");
    let world = PgWorld::new(store, tenant, seeded_repository(tenant), tune).await;
    (db, world, tenant)
}

// ------------------------------------------------------------------------------------------------
// The sweep runs while the queue is busy
// ------------------------------------------------------------------------------------------------

/// Stops the loop after a number of attempts, so the test ends while work is still waiting.
struct StopAfter {
    seen: AtomicU32,
    limit: u32,
}

impl Observer for StopAfter {
    fn after_attempt(&self, _: &ClaimedAttempt, _: &AttemptOutcome) -> Flow {
        if self.seen.fetch_add(1, Ordering::SeqCst) + 1 >= self.limit {
            Flow::Stop
        } else {
            Flow::Continue
        }
    }
}

/// A peer claimed an attempt and died. The loop that is left has work on every pass, so it never
/// waits. The lease of the dead peer is still recovered, because the sweep is due by time and not
/// by idleness.
#[tokio::test(flavor = "current_thread")]
async fn a_lost_lease_is_recovered_while_the_queue_never_empties() {
    const BUSY_ATTEMPTS: u32 = 12;
    tokio::task::LocalSet::new()
        .run_until(async {
            let (_db, world, _) = world(|config| {
                config.lease_ttl = Duration::from_secs(1);
                config.heartbeat_interval = Duration::from_millis(200);
            })
            .await;
            // Every intake attempt takes about 300 ms, and there are more of them than the loop is
            // allowed to run: the queue is never empty while the loop runs.
            let release = Arc::new(tokio::sync::Notify::new());
            world
                .script(StageKind::Intake)
                .otherwise(Step::Hang(release.clone()));
            let orphan = world.admitted_job().await;
            for _ in 0..(BUSY_ATTEMPTS + 4) {
                world.admitted_job().await;
            }
            let releaser = tokio::task::spawn_local(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    release.notify_one();
                }
            });
            // The peer that dies: it holds the lease of the first job and never runs it.
            let lost = world.claim_one("worker-that-died").await;
            assert_eq!(lost.job, orphan);

            let shutdown = Shutdown::new();
            let worker_loop = WorkerLoop::new(
                world.restarted_engine(),
                Arc::new(TokioTicker),
                PgWorld::worker("worker-busy"),
                PgWorld::loop_settings(),
                shutdown.clone(),
            )
            .with_observer(Arc::new(StopAfter {
                seen: AtomicU32::new(0),
                limit: BUSY_ATTEMPTS,
            }));
            let summary = tokio::time::timeout(Duration::from_secs(60), worker_loop.run())
                .await
                .expect("the loop reaches the attempt count");
            releaser.abort();

            assert!(summary.failure.is_none(), "{summary:?}");
            assert_eq!(summary.attempts_run, BUSY_ATTEMPTS, "{summary:?}");
            let view = world.view(orphan).await;
            let intake = view.newest(StageKind::Intake).expect("a run");
            assert_eq!(
                intake.attempts[0].status,
                AttemptStatus::LeaseLost,
                "the attempt of the dead peer was recovered although the loop never idled: \
                 {summary:?} {intake:#?}"
            );
            assert!(summary.sweeps >= 2, "{summary:?}");
        })
        .await;
}
