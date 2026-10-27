//! Scenario tests of the engine, over the in-memory store and the scripted stage handlers.
//!
//! Each test drives the engine through the public API only: it receives a job, admits it, claims
//! work, moves the fake clock, sweeps, and then reads the job back. The scenarios use the `Store`
//! trait and no detail of the in-memory store, so the same suite can run on another store.

mod support;

use factory_domain::state::{AttemptStatus, JobStatus, StageRunStatus};
use factory_domain::vocabulary::StageKind;
use factory_ports::store::LeaseEpoch;
use factory_workflow::engine::{Admission, EngineError};
use factory_workflow::scheduler::{Deferral, Pulse};
use support::World;

// ---- admission --------------------------------------------------------------------------------

#[tokio::test]
async fn admission_creates_one_stage_run_per_stage_and_readies_the_first() {
    let world = World::new().await;
    let job = world
        .engine
        .receive_job(world.tenant, world.requester)
        .await
        .expect("receive");
    assert_eq!(
        world.engine.job_status(world.tenant, job).await,
        Ok(JobStatus::Received)
    );

    let admission = world
        .engine
        .admit_job(world.tenant, job)
        .await
        .expect("admit");
    let Admission::Admitted { stage_runs } = admission else {
        panic!("the job should be admitted");
    };
    assert_eq!(stage_runs.len(), 13);

    let view = world.view(job).await;
    assert_eq!(view.status, JobStatus::Active);
    assert_eq!(view.stage_runs.len(), 13);
    // Only the intake has no upstream, so only it is ready.
    for run in &view.stage_runs {
        let expected = if run.kind == StageKind::Intake {
            StageRunStatus::Ready
        } else {
            StageRunStatus::Pending
        };
        assert_eq!(run.status, expected, "{}", run.kind);
    }
}

#[tokio::test]
async fn admission_rejects_an_unlisted_requester_and_does_not_say_why() {
    let world = World::new().await;
    world
        .authority
        .set_admission(|facts| facts.requester_on_allowlist = false);
    let job = world
        .engine
        .receive_job(world.tenant, world.requester)
        .await
        .expect("receive");

    let admission = world
        .engine
        .admit_job(world.tenant, job)
        .await
        .expect("admit");
    assert_eq!(admission, Admission::Rejected);
    assert_eq!(
        world.engine.job_status(world.tenant, job).await,
        Ok(JobStatus::Rejected)
    );
    assert!(world.view(job).await.stage_runs.is_empty());
    // The reason is for the audit log, which records the denial and not the reason.
    let audit = world.audit(job).await;
    assert_eq!(audit.len(), 1);
    assert_eq!(audit[0].action.as_str(), "authorization_decision.denied");
}

#[tokio::test]
async fn admission_fails_closed_when_the_protected_configuration_cannot_be_read() {
    let world = World::new().await;
    world.authority.set_unavailable(true);
    let job = world
        .engine
        .receive_job(world.tenant, world.requester)
        .await
        .expect("receive");

    let refused = world.engine.admit_job(world.tenant, job).await;
    assert!(
        matches!(refused, Err(EngineError::Refused(_))),
        "{refused:?}"
    );
    // The job is not rejected: a later call decides once the configuration is readable.
    assert_eq!(
        world.engine.job_status(world.tenant, job).await,
        Ok(JobStatus::Received)
    );
    world.authority.set_unavailable(false);
    assert!(matches!(
        world.engine.admit_job(world.tenant, job).await,
        Ok(Admission::Admitted { .. })
    ));
}

#[tokio::test]
async fn a_job_cannot_be_admitted_twice() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    let again = world.engine.admit_job(world.tenant, job).await;
    assert!(matches!(again, Err(EngineError::Illegal(_))), "{again:?}");
    assert_eq!(world.view(job).await.stage_runs.len(), 13);
}

// ---- the claim loop --------------------------------------------------------------------------

#[tokio::test]
async fn a_claim_starts_one_attempt_under_a_new_lease_epoch() {
    let world = World::new().await;
    let job = world.admitted_job().await;

    let claimed = world.claim_one("worker-1").await;
    assert_eq!(claimed.job, job);
    assert_eq!(claimed.kind, StageKind::Intake);
    assert_eq!(claimed.attempt_number, 1);
    assert_eq!(claimed.epoch, LeaseEpoch::new(1));

    let view = world.view(job).await;
    let intake = view.newest(StageKind::Intake).expect("an intake run");
    assert_eq!(intake.status, StageRunStatus::Running);
    assert_eq!(intake.lease_epoch, LeaseEpoch::new(1));
    assert_eq!(intake.attempts.len(), 1);
    assert_eq!(intake.attempts[0].status, AttemptStatus::Starting);
    assert_eq!(intake.attempts[0].epoch, LeaseEpoch::new(1));
}

#[tokio::test]
async fn a_second_claim_finds_nothing_while_the_work_is_taken() {
    let world = World::new().await;
    world.admitted_job().await;
    world.claim_one("worker-1").await;

    let second = world
        .engine
        .claim_next(&World::worker("worker-2"))
        .await
        .expect("claim");
    assert!(second.started.is_empty());
    assert!(second.deferred.is_empty());
}

#[tokio::test]
async fn a_crash_between_the_claim_and_the_start_loses_nothing_and_starts_once() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    // Claim from the store directly, as an engine that stopped right after the claim would.
    let mut tx = world.store_system().await;
    let work = tx
        .claim_ready(
            &World::worker("worker-1"),
            8,
            std::time::Duration::from_secs(60),
        )
        .await
        .expect("claim");
    assert_eq!(work.len(), 1);
    tx.commit().await.expect("commit");
    // The claim is committed and no attempt exists. A restarted engine sees a ready stage run
    // with a lease that has not run out, so it leaves it alone.
    let restarted = world.restarted_engine();
    let none = restarted
        .claim_next(&World::worker("worker-2"))
        .await
        .expect("claim");
    assert!(none.started.is_empty());
    // After the lease lapses the stage run is claimed again, at a higher epoch, and starts once.
    world.advance(61);
    let again = restarted
        .claim_next(&World::worker("worker-2"))
        .await
        .expect("claim");
    assert_eq!(again.started.len(), 1);
    assert_eq!(again.started[0].epoch, LeaseEpoch::new(2));
    let view = world.view(job).await;
    assert_eq!(
        view.newest(StageKind::Intake).expect("run").attempts.len(),
        1
    );
}

#[tokio::test]
async fn a_heartbeat_extends_the_lease_and_a_missing_one_loses_it() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    let claimed = world.claim_one("worker-1").await;

    // Heartbeats every 40 seconds keep a 60 second lease alive for 120 seconds.
    for _ in 0..3 {
        world.advance(40);
        assert_eq!(
            world.engine.heartbeat(&claimed).await,
            Ok(Pulse::Alive),
            "the lease should still be held"
        );
        let swept = world.engine.sweep().await.expect("sweep");
        assert!(swept.lease_lost.is_empty());
    }

    // Then the worker goes quiet. After the lease the sweeper takes the attempt.
    world.advance(61);
    let swept = world.engine.sweep().await.expect("sweep");
    assert_eq!(swept.lease_lost, vec![claimed.attempt]);
    let view = world.view(job).await;
    let intake = view.newest(StageKind::Intake).expect("run");
    assert_eq!(intake.attempts[0].status, AttemptStatus::LeaseLost);

    // The worker comes back. It is fenced, whatever it asks.
    let late = world.engine.heartbeat(&claimed).await;
    assert_eq!(late, Err(EngineError::LeaseFenced));
}

#[tokio::test]
async fn the_sweeper_leaves_a_live_lease_alone() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    let claimed = world.claim_one("worker-1").await;
    world.advance(59);
    let swept = world.engine.sweep().await.expect("sweep");
    assert!(swept.lease_lost.is_empty() && swept.skipped.is_empty());
    let view = world.view(job).await;
    assert_eq!(
        view.newest(StageKind::Intake).expect("run").attempts[0].status,
        AttemptStatus::Starting
    );
    assert_eq!(world.engine.heartbeat(&claimed).await, Ok(Pulse::Alive));
}

#[tokio::test]
async fn two_sweepers_at_once_end_the_attempt_once() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    let claimed = world.claim_one("worker-1").await;
    world.advance(61);
    let other = world.restarted_engine();
    let (a, b) = tokio::join!(world.engine.sweep(), other.sweep());
    let total = a.expect("sweep").lease_lost.len() + b.expect("sweep").lease_lost.len();
    assert_eq!(total, 1);
    let events = world.events(job).await;
    let lost = events
        .iter()
        .filter(|event| event.event_type.as_str() == "attempt.lease_lost")
        .count();
    assert_eq!(lost, 1, "the attempt {} is announced once", claimed.attempt);
}

#[tokio::test]
async fn two_engines_claiming_at_once_never_start_the_same_stage_run_twice() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    let other = world.restarted_engine();
    let (first, second) = (World::worker("worker-1"), World::worker("worker-2"));
    let (a, b) = tokio::join!(world.engine.claim_next(&first), other.claim_next(&second),);
    let started = a.expect("claim").started.len() + b.expect("claim").started.len();
    assert_eq!(started, 1);
    let view = world.view(job).await;
    assert_eq!(
        view.newest(StageKind::Intake).expect("run").attempts.len(),
        1
    );
}

#[tokio::test]
async fn a_job_over_its_concurrency_quota_does_not_start() {
    let world = World::new().await;
    world.admitted_job().await;
    world.authority.set_concurrency(false);
    let claimed = world
        .engine
        .claim_next(&World::worker("worker-1"))
        .await
        .expect("claim");
    assert!(claimed.started.is_empty());
    assert_eq!(claimed.deferred.len(), 1);
    assert_eq!(claimed.deferred[0].1, Deferral::QuotaExceeded);
}

#[tokio::test]
async fn a_job_whose_scope_has_a_stage_without_a_handler_is_not_admitted() {
    let mut world = World::new().await;
    // An engine whose registry lacks the review handler cannot finish any job, so it admits none.
    let mut handlers = factory_workflow::handlers::HandlerRegistry::new();
    for kind in &world.config.scope {
        if *kind != StageKind::Review {
            let script = support::ScriptHandle::default();
            handlers
                .register(std::sync::Arc::new(support::ScriptedHandler::new(
                    *kind, script,
                )))
                .expect("one handler per stage");
        }
    }
    world.engine =
        factory_workflow::engine::Engine::new(world.deps.clone(), world.config.clone(), handlers)
            .expect("an engine starts");
    let job = world
        .engine
        .receive_job(world.tenant, world.requester)
        .await
        .expect("receive");
    let refused = world.engine.admit_job(world.tenant, job).await;
    assert_eq!(refused, Err(EngineError::NoHandler(StageKind::Review)));
    assert_eq!(
        world.engine.job_status(world.tenant, job).await,
        Ok(JobStatus::Received)
    );
}
