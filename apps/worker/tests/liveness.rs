//! The loop stays alive for everyone: it sweeps while it is busy, and one bad job does not stop
//! the others.
//!
//! Real: PostgreSQL, the engine, the loop and the ticker. Scripted: the stage handlers (the engine
//! suite's), as in the other loop tests.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use factory_composition::system::{RandomIds, Shutdown, TokioTicker};
use factory_domain::contracts::StageContract;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::state::{AttemptStatus, StageRunStatus};
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::agent::RoutingNeed;
use factory_ports::clock::IdGenerator;
use factory_storage::pg::PgStore;
use factory_worker::run::{Flow, LoopSummary, Observer, WorkerLoop};
use factory_workflow::engine::{AttemptOutcome, Engine, EngineConfig, JobView};
use factory_workflow::gates::framework::GateDecision;
use factory_workflow::handlers::{
    Applicability, ContractContext, GateContext, HandlerRegistry, StageContext, StageError,
    StageHandler, StageOutput,
};
use factory_workflow::scheduler::ClaimedAttempt;
use support::engine::{PgWorld, ScriptedHandler, Step};
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

/// Waits until `done` holds for the job, for at most `seconds`. Returns the last view.
async fn until(
    world: &PgWorld,
    job: JobId,
    seconds: u64,
    done: impl Fn(&JobView) -> bool,
) -> JobView {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    loop {
        let view = world.view(job).await;
        if done(&view) || tokio::time::Instant::now() > deadline {
            return view;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn stopped(shutdown: &Shutdown, task: tokio::task::JoinHandle<LoopSummary>) -> LoopSummary {
    shutdown.raise();
    tokio::time::timeout(Duration::from_secs(15), task)
        .await
        .expect("the loop stops")
        .expect("joins")
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

// ------------------------------------------------------------------------------------------------
// One bad job does not stop the others
// ------------------------------------------------------------------------------------------------

/// A registry with the scripted handler of every stage of the world, except where `replace` gives
/// another one (`Some(None)` leaves the stage without a handler).
fn registry(
    world: &PgWorld,
    replace: impl Fn(StageKind, Arc<dyn StageHandler>) -> Option<Arc<dyn StageHandler>>,
) -> HandlerRegistry {
    let mut handlers = HandlerRegistry::new();
    for kind in &world.config.scope {
        let scripted: Arc<dyn StageHandler> =
            Arc::new(ScriptedHandler::new(*kind, world.script(*kind).clone()));
        if let Some(handler) = replace(*kind, scripted) {
            handlers.register(handler).expect("one handler per stage");
        }
    }
    handlers
}

/// The first candidate of the queue cannot even be claimed: the worker has no handler for its
/// stage, which the claim reports as a hard error. A job behind it still runs.
#[tokio::test(flavor = "current_thread")]
async fn a_candidate_that_cannot_be_claimed_does_not_hold_back_the_job_behind_it() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (_db, world, _) = world(|_| {}).await;
            // The first job passes its intake, so its next stage run is the oldest ready one.
            let first = world.admitted_job().await;
            let intake = world.claim_one("worker-setup").await;
            let outcome = world
                .engine
                .run_attempt(&intake)
                .await
                .expect("intake runs");
            assert_eq!(outcome, AttemptOutcome::Succeeded);
            let view = world.view(first).await;
            let stuck = view
                .stage_runs
                .iter()
                .find(|run| run.status == StageRunStatus::Ready)
                .expect("the stage after intake is ready")
                .clone();
            let second = world.admitted_job().await;

            // The loop's engine has no handler for that stage.
            let handlers = registry(&world, |kind, scripted| {
                (kind != stuck.kind).then_some(scripted)
            });
            let engine = Engine::new(world.deps.clone(), world.config.clone(), handlers)
                .expect("the engine starts");
            let shutdown = Shutdown::new();
            let worker_loop = WorkerLoop::new(
                engine,
                Arc::new(TokioTicker),
                PgWorld::worker("worker-partial"),
                PgWorld::loop_settings(),
                shutdown.clone(),
            );
            let task = tokio::task::spawn_local(async move { worker_loop.run().await });

            let view = until(&world, second, 20, |view| {
                view.newest(StageKind::Intake)
                    .is_some_and(|run| run.status == StageRunStatus::Passed)
            })
            .await;
            assert!(!task.is_finished(), "the loop ended on its own");
            assert_eq!(
                view.newest(StageKind::Intake).map(|run| run.status),
                Some(StageRunStatus::Passed),
                "the job behind the bad candidate ran: {view:#?}"
            );
            let summary = stopped(&shutdown, task).await;
            assert!(summary.failure.is_none(), "{summary:?}");
            assert!(summary.stopped_cleanly, "{summary:?}");
            assert!(summary.set_aside >= 1, "{summary:?}");
            // Nothing was started on the stage the worker cannot run.
            let view = world.view(first).await;
            let run = view
                .stage_runs
                .iter()
                .find(|run| run.id == stuck.id)
                .expect("the run");
            assert_eq!(run.status, StageRunStatus::Ready, "{run:#?}");
            assert!(run.attempts.is_empty(), "{run:#?}");
        })
        .await;
}

/// The scripted handler of a stage, except that for one job the contract stops resolving after a
/// number of calls. The engine reads that at the start of an attempt as a damaged record
/// (`EngineError::Corrupt`), which is a hard error of `run_attempt`.
struct BreaksForOneJob {
    inner: Arc<dyn StageHandler>,
    job: std::sync::Mutex<Option<JobId>>,
    calls: AtomicU32,
    good_calls: AtomicU32,
}

impl BreaksForOneJob {
    fn new(inner: Arc<dyn StageHandler>) -> Self {
        Self {
            inner,
            job: std::sync::Mutex::new(None),
            calls: AtomicU32::new(0),
            good_calls: AtomicU32::new(u32::MAX),
        }
    }

    /// From now on the contract of `job` resolves `more` more times and then never again.
    fn break_after(&self, job: JobId, more: u32) {
        *self.job.lock().expect("the lock") = Some(job);
        self.calls.store(0, Ordering::SeqCst);
        self.good_calls.store(more, Ordering::SeqCst);
    }
}

#[async_trait]
impl StageHandler for BreaksForOneJob {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    fn kind(&self) -> StageKind {
        self.inner.kind()
    }

    fn applicability(&self, ctx: &ContractContext<'_>) -> Applicability {
        self.inner.applicability(ctx)
    }

    fn routing_need(&self, ctx: &ContractContext<'_>) -> Option<RoutingNeed> {
        self.inner.routing_need(ctx)
    }

    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError> {
        if *self.job.lock().expect("the lock") == Some(ctx.identity.job)
            && self.calls.fetch_add(1, Ordering::SeqCst) >= self.good_calls.load(Ordering::SeqCst)
        {
            return Err(StageError::Tool);
        }
        self.inner.contract(ctx)
    }

    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        self.inner.execute(ctx).await
    }

    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        self.inner.evaluate(ctx).await
    }
}

/// The first job is claimed and its attempt then raises a hard error. The failure is recorded
/// against that attempt, and the job behind it runs.
#[tokio::test(flavor = "current_thread")]
async fn an_attempt_that_raises_a_hard_error_is_failed_and_the_job_behind_it_runs() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let (_db, world, _) = world(|_| {}).await;
            let breaking: std::sync::Mutex<Option<Arc<BreaksForOneJob>>> =
                std::sync::Mutex::new(None);
            let handlers = registry(&world, |kind, scripted| {
                if kind == StageKind::Intake {
                    let handler = Arc::new(BreaksForOneJob::new(scripted));
                    *breaking.lock().expect("the lock") = Some(handler.clone());
                    Some(handler)
                } else {
                    Some(scripted)
                }
            });
            let breaking = breaking.lock().expect("the lock").clone().expect("intake");
            let first = world.admitted_job().await;
            // One more good answer, for the claim. The next one, at the start of the attempt, fails.
            breaking.break_after(first, 1);
            let second = world.admitted_job().await;

            let engine = Engine::new(world.deps.clone(), world.config.clone(), handlers)
                .expect("the engine starts");
            let shutdown = Shutdown::new();
            let worker_loop = WorkerLoop::new(
                engine,
                Arc::new(TokioTicker),
                PgWorld::worker("worker-hard-error"),
                PgWorld::loop_settings(),
                shutdown.clone(),
            );
            let task = tokio::task::spawn_local(async move { worker_loop.run().await });

            let view = until(&world, second, 20, |view| {
                view.newest(StageKind::Intake)
                    .is_some_and(|run| run.status == StageRunStatus::Passed)
            })
            .await;
            assert!(!task.is_finished(), "the loop ended on its own");
            assert_eq!(
                view.newest(StageKind::Intake).map(|run| run.status),
                Some(StageRunStatus::Passed),
                "the job behind the failing one ran: {view:#?}"
            );
            let summary = stopped(&shutdown, task).await;
            assert!(summary.failure.is_none(), "{summary:?}");
            assert_eq!(summary.faulted, 1, "{summary:?}");
            // The failure is in the store, against the attempt that raised it, and it is final:
            // a fault of the factory is never retried.
            let view = world.view(first).await;
            let intake = view.newest(StageKind::Intake).expect("a run");
            assert_eq!(intake.attempts.len(), 1, "{intake:#?}");
            assert_eq!(
                intake.attempts[0].status,
                AttemptStatus::Failed,
                "{intake:#?}"
            );
            assert_eq!(intake.status, StageRunStatus::Failed, "{intake:#?}");
        })
        .await;
}
