//! Killing the worker at every stage boundary, in test mode with the fake runtime, still ends in
//! a completed job: every earlier stage passed exactly once, then a person approves and the job
//! is `COMPLETED`.
//!
//! Until the engine stored a report for a person's approval (ADR 0014, amendment 1), these cases
//! could prove everything up to the approval and no further: `PgStore` refused the approval as
//! `GateRecordRule`. They now go on to the approval and the completed job.
//!
//! Each case has a database of its own and a job that runs the 13 stages of the Slice 1 scope on
//! the real PostgreSQL store. "Killing" is not a polite stop: the loop is dropped where it stands,
//! the engine with it, and a second engine, as in a new process, picks the job up from the rows.
//!
//! Two kinds of boundary, for each of the 13 stages:
//!
//! * **After**: the worker dies right after the result of stage `k` was committed and before it
//!   claims the next one. The next process finds stage `k + 1` ready.
//! * **During**: the worker dies while stage `k` is running (its attempt holds a lease, its
//!   handler is waiting). The next process finds an attempt whose lease lapses, the sweeper ends
//!   it as `LEASE_LOST`, and the stage run is retried.
//!
//! In every case the job reaches the approval, every earlier stage has exactly one `PASSED` run
//! and the ledger chain is intact.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use factory_domain::ids::{JobId, TenantId};
use factory_domain::state::{JobStatus, StageRunStatus};
use factory_domain::vocabulary::StageKind;
use factory_ports::clock::IdGenerator;
use factory_worker::run::{Flow, Observer, WorkerLoop};
use factory_worker::system::{RandomIds, Shutdown, TokioTicker};
use factory_workflow::engine::{AttemptOutcome, JobView};
use factory_workflow::scheduler::ClaimedAttempt;
use support::engine::{Eval, PgWorld, Step};
use support::{TestDb, seed_tenant, seeded_repository, server, worker_config};
use tokio::task::LocalSet;

/// Stops the loop after a number of attempts: the instant after a result was committed.
struct StopAfter {
    limit: u32,
    seen: AtomicU32,
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

async fn world() -> (TestDb, PgWorld, TenantId) {
    let db = server().clone_database().await;
    let ids = RandomIds::new().expect("the random source opens");
    let tenant = TenantId::from_uuid(ids.new_uuid());
    seed_tenant(&db, tenant, 0, "org/repo-0").await;
    let store = factory_storage::pg::PgStore::connect(worker_config(&db).await)
        .await
        .expect("the store becomes ready");
    let world = PgWorld::new(store, tenant, seeded_repository(tenant), |_| {}).await;
    // The approval waits for a person, as in production. A job completes only after a person's
    // approval, which the cases give once the job waits at it.
    world
        .script(StageKind::Approval)
        .evals_otherwise(Eval::HumanGate);
    (db, world, tenant)
}

fn is_at_approval(view: &JobView) -> bool {
    view.status == JobStatus::WaitingForHuman
        && view
            .newest(StageKind::Approval)
            .is_some_and(|run| run.status == StageRunStatus::WaitingForHuman)
}

/// Runs a fresh worker loop until the job waits at the approval, then stops it.
async fn run_to_completion(world: &PgWorld, job: JobId, name: &str) {
    let shutdown = Shutdown::new();
    let worker_loop = WorkerLoop::new(
        world.restarted_engine(),
        Arc::new(TokioTicker),
        PgWorld::worker(name),
        PgWorld::loop_settings(),
        shutdown.clone(),
    );
    let watcher = world.restarted_engine();
    let task = tokio::task::spawn_local(async move { worker_loop.run().await });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let view = watcher.job_view(world.tenant, job).await.expect("a view");
        if is_at_approval(&view) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the job did not reach the approval in time: {:?}",
            view.stage_runs
                .iter()
                .map(|r| (r.kind, r.status))
                .collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    shutdown.raise();
    let summary = task.await.expect("the loop task ends");
    assert!(summary.stopped_cleanly, "{summary:?}");
    assert!(summary.abandoned.is_empty(), "{summary:?}");
    assert_eq!(summary.failure, None);
}

async fn check_completed(world: &PgWorld, job: JobId) {
    let view = world.view(job).await;
    assert!(is_at_approval(&view), "{:?}", view.stage_runs);
    assert_eq!(
        factory_domain::ledger::verify_chain(&world.ledger(job).await),
        Ok(())
    );
    for kind in &world.config.scope {
        let passed = view
            .stage_runs
            .iter()
            .filter(|r| r.kind == *kind && r.status == StageRunStatus::Passed)
            .count();
        let expected = usize::from(*kind != StageKind::Approval);
        assert_eq!(
            passed, expected,
            "{kind} must have {expected} PASSED run(s) before the approval"
        );
    }
    // A person approves, and the store records it: the job completes.
    let approval = view
        .newest(StageKind::Approval)
        .expect("an approval run")
        .id;
    world
        .approve(&world.restarted_engine(), job, approval)
        .await;
    let done = world.view(job).await;
    assert_eq!(done.status, JobStatus::Completed, "{:?}", done.stage_runs);
    assert_eq!(
        done.newest(StageKind::Approval).map(|run| run.status),
        Some(StageRunStatus::Passed)
    );
    assert_eq!(
        factory_domain::ledger::verify_chain(&world.ledger(job).await),
        Ok(())
    );
}

async fn kill_after(k: u32) {
    let (_db, world, _) = world().await;
    let job = world.admitted_job().await;
    // First process: dies right after stage k committed.
    let first = WorkerLoop::new(
        world.restarted_engine(),
        Arc::new(TokioTicker),
        PgWorld::worker("worker-first"),
        PgWorld::loop_settings(),
        Shutdown::new(),
    )
    .with_observer(Arc::new(StopAfter {
        limit: k,
        seen: AtomicU32::new(0),
    }));
    let summary = first.run().await;
    assert_eq!(summary.attempts_run, k, "{summary:?}");
    drop(first);
    // Second process.
    run_to_completion(&world, job, "worker-second").await;
    check_completed(&world, job).await;
}

async fn kill_during(k: usize) {
    let (_db, world, _) = world().await;
    let kind = world.config.scope[k];
    // The first execution of stage k waits, holding its lease. Later executions succeed.
    let release = Arc::new(tokio::sync::Notify::new());
    world.script(kind).queue([Step::Hang(release.clone())]);
    let job = world.admitted_job().await;
    let first = WorkerLoop::new(
        world.restarted_engine(),
        Arc::new(TokioTicker),
        PgWorld::worker("worker-first"),
        PgWorld::loop_settings(),
        Shutdown::new(),
    );
    let task = tokio::task::spawn_local(async move { first.run().await });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while world.script(kind).executed().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "stage {kind} never started"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The process dies: the loop, its engine and the running handler are dropped on the spot.
    task.abort();
    let _ = task.await;
    // The new process finds a lapsed lease, ends it and retries.
    run_to_completion(&world, job, "worker-second").await;
    let view = world.view(job).await;
    let run = view
        .runs_of(kind)
        .next()
        .expect("a run of the killed stage");
    assert!(
        run.attempts.len() >= 2,
        "the killed stage must have been retried: {:?}",
        run.attempts
    );
    check_completed(&world, job).await;
}

#[tokio::test(flavor = "current_thread")]
async fn killing_the_worker_after_each_stage_still_completes_the_job() {
    LocalSet::new()
        .run_until(async {
            let mut cases = Vec::new();
            for k in 1..=13_u32 {
                cases.push(tokio::task::spawn_local(kill_after(k)));
            }
            for case in cases {
                case.await.expect("every boundary case completes the job");
            }
        })
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn killing_the_worker_during_each_stage_still_completes_the_job() {
    LocalSet::new()
        .run_until(async {
            let mut cases = Vec::new();
            for k in 0..13_usize {
                cases.push(tokio::task::spawn_local(kill_during(k)));
            }
            for case in cases {
                case.await.expect("every mid-stage case completes the job");
            }
        })
        .await;
}
