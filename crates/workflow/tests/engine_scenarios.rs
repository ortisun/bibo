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

// ---- attempt results --------------------------------------------------------------------------

use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::retry::{AttemptDisposition, EscalationCause};
use factory_domain::values::Timestamp;
use factory_workflow::engine::AttemptOutcome;
use factory_workflow::handlers::StageError;
use support::Step;

fn intake(view: &factory_workflow::engine::JobView) -> &factory_workflow::engine::StageRunView {
    view.newest(StageKind::Intake).expect("an intake run")
}

#[tokio::test]
async fn a_valid_output_is_stored_by_hash_and_the_attempt_succeeds() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    let (claimed, outcome) = world.run_next("worker-1").await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);

    let view = world.view(job).await;
    let run = intake(&view);
    assert_eq!(run.attempts[0].status, AttemptStatus::Succeeded);
    assert_eq!(run.attempts[0].id, claimed.attempt);
    // The scripted gate passed, so the stage run is passed and the next stage is ready.
    assert_eq!(run.status, StageRunStatus::Passed);
    assert_eq!(
        view.newest(StageKind::RepositoryIntelligence)
            .expect("run")
            .status,
        StageRunStatus::Ready
    );

    // The output is in the artifact store under its hash, and the event says which.
    let events = world.events(job).await;
    let gating = events
        .iter()
        .find(|event| event.event_type.as_str() == "stage_run.gating")
        .expect("a gating event");
    let outputs = gating.payload["outputs"].as_array().expect("a list");
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0]["name"], "scripted-output");
}

#[tokio::test]
async fn an_output_that_breaks_its_schema_is_a_failure_and_never_a_pass() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .queue([Step::InvalidDocument]);
    let (_, outcome) = world.run_next("worker-1").await;
    assert_eq!(
        outcome,
        AttemptOutcome::Failed {
            class: FailureClass::InvalidOutput,
            then: AttemptDisposition::Retry
        }
    );
    let view = world.view(job).await;
    let run = intake(&view);
    assert_eq!(run.attempts[0].status, AttemptStatus::Failed);
    assert_eq!(run.status, StageRunStatus::Ready);
}

#[tokio::test]
async fn a_document_the_contract_does_not_declare_is_refused() {
    let world = World::new().await;
    world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .with(|s| s.extra_document = true);
    let (_, outcome) = world.run_next("worker-1").await;
    assert!(matches!(
        outcome,
        AttemptOutcome::Failed {
            class: FailureClass::InvalidOutput,
            ..
        }
    ));
}

#[tokio::test]
async fn a_missing_required_deliverable_is_an_invalid_output() {
    let world = World::new().await;
    world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .with(|s| s.omit_deliverable = true);
    let (_, outcome) = world.run_next("worker-1").await;
    assert!(matches!(
        outcome,
        AttemptOutcome::Failed {
            class: FailureClass::InvalidOutput,
            ..
        }
    ));
}

#[tokio::test]
async fn a_stage_that_never_reports_its_sandbox_fails_closed() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .with(|s| s.report_sandbox = false);
    let (_, outcome) = world.run_next("worker-1").await;
    assert!(matches!(
        outcome,
        AttemptOutcome::Failed {
            class: FailureClass::SandboxError,
            ..
        }
    ));
    let view = world.view(job).await;
    assert_eq!(intake(&view).attempts[0].status, AttemptStatus::Failed);
}

// ---- failures: retry, back-off, escalation ------------------------------------------------

#[tokio::test]
async fn a_tool_error_is_retried_after_a_back_off_that_the_claim_honours() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    // A back-off longer than the lease, so the lease of the failed attempt is not what waits.
    world.script(StageKind::Intake).with(|s| {
        s.tweaks.backoff_initial_ms = 90_000;
        s.steps.push_back(Step::Fail(StageError::Tool));
    });
    let (_, outcome) = world.run_next("worker-1").await;
    assert_eq!(
        outcome,
        AttemptOutcome::Failed {
            class: FailureClass::ToolError,
            then: AttemptDisposition::Retry
        }
    );
    let view = world.view(job).await;
    let run = intake(&view);
    assert_eq!(run.status, StageRunStatus::Ready);
    let not_before = run.not_before.expect("a back-off");
    assert_eq!(
        not_before,
        Timestamp::parse("2026-10-27T08:31:30Z").expect("an instant")
    );

    // The lease has lapsed and the back-off has not: the claim finds the run and leaves it.
    world.advance(80);
    let early = world
        .engine
        .claim_next(&World::worker("worker-2"))
        .await
        .expect("claim");
    assert!(early.started.is_empty());
    assert_eq!(early.deferred.len(), 1);
    assert_eq!(early.deferred[0].1, Deferral::BackingOff);
    // The deferred claim holds the lease until it lapses, because the Store port cannot give a
    // lease back. Once it has lapsed and the back-off is over, the retry starts as attempt 2
    // under a higher epoch.
    world.advance(70);
    let (second, outcome) = world.run_next("worker-2").await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    assert_eq!(second.attempt_number, 2);
    assert!(
        second.epoch > LeaseEpoch::new(2),
        "the deferred claim also raised the epoch"
    );
}

#[tokio::test]
async fn the_back_off_doubles_with_each_failure() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    world.script(StageKind::Intake).queue([
        Step::Fail(StageError::Provider),
        Step::Fail(StageError::Provider),
    ]);
    let wait_after_failure = |view: factory_workflow::engine::JobView| {
        let not_before = intake(&view).not_before.expect("a back-off");
        factory_ports::clock::duration_between(
            &factory_ports::clock::Clock::now(world.clock.as_ref()),
            &not_before,
        )
        .expect("in the future")
    };
    world.run_next("worker-1").await;
    assert_eq!(
        wait_after_failure(world.view(job).await),
        std::time::Duration::from_secs(5)
    );
    // The lease of the first attempt lapses, then the second attempt fails in turn.
    world.advance(61);
    world.run_next("worker-1").await;
    assert_eq!(
        wait_after_failure(world.view(job).await),
        std::time::Duration::from_secs(10)
    );
}

#[tokio::test]
async fn a_failure_that_retrying_cannot_fix_fails_the_stage_and_the_job() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .queue([Step::Fail(StageError::PolicyDenied)]);
    let (_, outcome) = world.run_next("worker-1").await;
    assert_eq!(
        outcome,
        AttemptOutcome::Failed {
            class: FailureClass::PolicyDenied,
            then: AttemptDisposition::Fail
        }
    );
    let view = world.view(job).await;
    assert_eq!(intake(&view).status, StageRunStatus::Failed);
    assert_eq!(view.status, JobStatus::Failed);
}

#[tokio::test]
async fn bounded_failure_escalates() {
    // INV-10: a runtime that always fails reaches WAITING_FOR_HUMAN in a bounded number of
    // steps, and the stage run does not fail.
    let world = World::new().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .otherwise(Step::Fail(StageError::Tool));
    let mut attempts = 0;
    loop {
        let view = world.view(job).await;
        if intake(&view).status == StageRunStatus::WaitingForHuman {
            break;
        }
        attempts += 1;
        assert!(attempts <= 3, "the loop must stop after the attempt limit");
        world.advance(600);
        world.run_next("worker-1").await;
    }
    let view = world.view(job).await;
    assert_eq!(attempts, 3, "three attempts is the default limit");
    assert_eq!(intake(&view).status, StageRunStatus::WaitingForHuman);
    assert_eq!(intake(&view).attempts.len(), 3);
    assert_eq!(view.status, JobStatus::WaitingForHuman);
}

#[tokio::test]
async fn a_budget_limit_asks_a_person_at_once_and_does_not_fail_the_stage() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .queue([Step::Fail(StageError::BudgetExhausted)]);
    let (_, outcome) = world.run_next("worker-1").await;
    assert_eq!(
        outcome,
        AttemptOutcome::Failed {
            class: FailureClass::BudgetExhausted,
            then: AttemptDisposition::Escalate(EscalationCause::BudgetLimit)
        }
    );
    let view = world.view(job).await;
    assert_eq!(intake(&view).status, StageRunStatus::WaitingForHuman);
    assert_eq!(view.status, JobStatus::WaitingForHuman);
}

#[tokio::test]
async fn repairs_after_an_invalid_output_stop_at_the_cap_of_two() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .with(|s| s.tweaks.max_attempts = 10);
    world
        .script(StageKind::Intake)
        .otherwise(Step::InvalidDocument);
    let mut failures = 0;
    loop {
        let view = world.view(job).await;
        if intake(&view).status == StageRunStatus::WaitingForHuman {
            break;
        }
        failures += 1;
        assert!(failures <= 3);
        world.advance(600);
        world.run_next("worker-1").await;
    }
    // Two repairs are allowed, so the third invalid output asks a person, long before the
    // attempt limit of ten.
    assert_eq!(failures, 3);
}

#[tokio::test]
async fn a_structured_request_for_a_person_is_escalated_and_not_retried() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    world.script(StageKind::Intake).queue([Step::NeedsHuman]);
    let (_, outcome) = world.run_next("worker-1").await;
    assert_eq!(outcome, AttemptOutcome::NeedsHuman);
    let view = world.view(job).await;
    assert_eq!(intake(&view).status, StageRunStatus::WaitingForHuman);
    assert_eq!(intake(&view).attempts[0].status, AttemptStatus::Succeeded);
    assert_eq!(view.status, JobStatus::WaitingForHuman);
}

#[tokio::test]
async fn a_blocked_stage_waits_for_a_person_and_is_never_retried() {
    use factory_domain::contracts::gate_report::BlockedCode;
    let world = World::new().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .queue([Step::Fail(StageError::Blocked(
            BlockedCode::ToolUnavailable,
        ))]);
    let (_, outcome) = world.run_next("worker-1").await;
    assert!(matches!(
        outcome,
        AttemptOutcome::Failed {
            class: FailureClass::PolicyDenied,
            ..
        }
    ));
    let view = world.view(job).await;
    assert_eq!(intake(&view).status, StageRunStatus::WaitingForHuman);
    assert_eq!(intake(&view).attempts.len(), 1);
}

#[tokio::test]
async fn a_lease_lost_attempt_is_retried_like_any_other_failure() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    world.claim_one("worker-1").await;
    world.advance(61);
    world.engine.sweep().await.expect("sweep");
    let view = world.view(job).await;
    assert_eq!(intake(&view).status, StageRunStatus::Ready);
    assert_eq!(intake(&view).attempts[0].status, AttemptStatus::LeaseLost);
    assert!(intake(&view).not_before.is_some());
}

// ---- a worker that lost its lease ---------------------------------------------------------

#[tokio::test]
async fn a_stale_worker_that_comes_back_changes_nothing() {
    // NT-LSE-01: worker A loses its lease and worker B takes over. A finishes and reports. The
    // report is refused and every state change comes from B's epoch.
    let world = World::new().await;
    let job = world.admitted_job().await;
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    world
        .script(StageKind::Intake)
        .queue([Step::Hang(release.clone())]);
    let claimed = world.claim_one("worker-a").await;

    let stale = async { world.engine.run_attempt(&claimed).await };
    let takeover = async {
        // The lease runs out while A is still busy, the sweeper ends the attempt, and B claims
        // the retry at a higher epoch.
        world.advance(61);
        world.engine.sweep().await.expect("sweep");
        world.advance(5);
        let second = world.claim_one("worker-b").await;
        assert!(second.epoch > claimed.epoch);
        // Only now does A finish.
        release.notify_one();
        second
    };
    let (outcome, second) = tokio::join!(stale, takeover);
    assert_eq!(
        outcome.expect("the attempt runs"),
        AttemptOutcome::LeaseLost
    );

    // B carries on, and its result stands.
    let finished = world
        .engine
        .run_attempt(&second)
        .await
        .expect("the second attempt runs");
    assert_eq!(finished, AttemptOutcome::Succeeded);
    let view = world.view(job).await;
    let run = intake(&view);
    assert_eq!(run.attempts.len(), 2);
    assert_eq!(run.attempts[0].status, AttemptStatus::LeaseLost);
    assert_eq!(run.attempts[1].status, AttemptStatus::Succeeded);
    // No event carries the stale epoch's work: one attempt succeeded.
    let events = world.events(job).await;
    let succeeded = events
        .iter()
        .filter(|event| event.event_type.as_str() == "attempt.succeeded")
        .count();
    assert_eq!(succeeded, 1);
}

#[tokio::test(start_paused = true)]
async fn heartbeats_during_a_long_stage_keep_the_lease() {
    let world = World::new().await;
    world.admitted_job().await;
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    world
        .script(StageKind::Intake)
        .queue([Step::Hang(release.clone())]);
    let claimed = world.claim_one("worker-a").await;

    let work = async { world.engine.run_attempt(&claimed).await };
    let driver = async {
        // The stage takes 120 seconds of database time, twice the lease. The runner's heartbeat
        // every 15 seconds keeps the lease, so the sweeper finds nothing to take.
        for _ in 0..6 {
            world.advance(20);
            tokio::time::sleep(std::time::Duration::from_secs(16)).await;
            let swept = world.engine.sweep().await.expect("sweep");
            assert!(swept.lease_lost.is_empty(), "the lease was kept alive");
        }
        release.notify_one();
    };
    let (outcome, ()) = tokio::join!(work, driver);
    assert_eq!(
        outcome.expect("the attempt runs"),
        AttemptOutcome::Succeeded
    );
}

#[tokio::test(start_paused = true)]
async fn an_attempt_past_its_deadline_is_stopped_and_timed_out() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    world.script(StageKind::Intake).with(|s| {
        s.tweaks.attempt_timeout_seconds = 30;
        s.steps.push_back(Step::Hang(release.clone()));
    });
    let claimed = world.claim_one("worker-a").await;
    let work = async { world.engine.run_attempt(&claimed).await };
    let driver = async {
        world.advance(40);
        // The next heartbeat sees the passed deadline and trips the signal. The handler stops.
        tokio::time::sleep(std::time::Duration::from_secs(16)).await;
    };
    let (outcome, ()) = tokio::join!(work, driver);
    assert_eq!(
        outcome.expect("the attempt runs"),
        AttemptOutcome::Failed {
            class: FailureClass::TimedOut,
            then: AttemptDisposition::Retry
        }
    );
    let view = world.view(job).await;
    assert_eq!(intake(&view).attempts[0].status, AttemptStatus::TimedOut);
    assert_eq!(intake(&view).status, StageRunStatus::Ready);
}

// ---- the gate, rework and supersession ---------------------------------------------------

use factory_domain::ids::StageRunId;
use factory_domain::machines::invalidation::ArtifactChange;
use factory_workflow::engine::JobView;
use support::Eval;

/// Claims and runs `count` stage runs, one after another, moving the clock past every lease and
/// back-off in between.
async fn run_stages(world: &World, count: usize) {
    for _ in 0..count {
        world.advance(400);
        let (_, outcome) = world.run_next("worker-1").await;
        assert_eq!(outcome, AttemptOutcome::Succeeded);
    }
}

fn status_of(view: &JobView, kind: StageKind) -> StageRunStatus {
    view.newest(kind).expect("a run").status
}

fn statuses_of(view: &JobView, kind: StageKind) -> Vec<StageRunStatus> {
    view.runs_of(kind).map(|run| run.status).collect()
}

#[tokio::test]
async fn a_job_runs_every_stage_in_order_and_waits_for_the_approval() {
    let world = World::new().await;
    world
        .script(StageKind::Approval)
        .evals_otherwise(Eval::HumanGate);
    let job = world.admitted_job().await;
    run_stages(&world, 13).await;

    let view = world.view(job).await;
    for kind in &world.config.scope {
        let expected = if *kind == StageKind::Approval {
            StageRunStatus::WaitingForHuman
        } else {
            StageRunStatus::Passed
        };
        assert_eq!(status_of(&view, *kind), expected, "{kind}");
    }
    assert_eq!(view.status, JobStatus::WaitingForHuman);

    // Every passed stage run has a ledger entry that cites its gate report, and the chain holds.
    let ledger = world.ledger(job).await;
    assert!(ledger.len() >= 12, "{} entries", ledger.len());
    assert_eq!(factory_domain::ledger::verify_chain(&ledger), Ok(()));
    // Every event of one aggregate has the next version, with no gap (ADR 0004).
    let events = world.events(job).await;
    let mut last: std::collections::HashMap<_, i64> = std::collections::HashMap::new();
    for event in &events {
        let key = (event.aggregate.kind, event.aggregate.id);
        let version = event.aggregate.version.get();
        if let Some(previous) = last.insert(key, version) {
            assert!(version > previous, "{} did not rise", event.event_type);
        }
    }
}

#[tokio::test]
async fn a_failed_gate_sends_the_work_back_by_the_route_of_the_stage() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    // Through IMPLEMENTATION (7 stages). VALIDATION is next, and its first gate fails.
    run_stages(&world, 7).await;
    world
        .script(StageKind::Validation)
        .queue_evals([Eval::Fail("tests-pass")]);
    world.advance(400);
    let (_, outcome) = world.run_next("worker-1").await;
    assert_eq!(
        outcome,
        AttemptOutcome::Succeeded,
        "the attempt itself succeeded"
    );

    let view = world.view(job).await;
    // The route of VALIDATION is IMPLEMENTATION: the passed run is replaced, the failing run is
    // marked for rework, and every stage after the target starts again.
    assert_eq!(
        statuses_of(&view, StageKind::Implementation),
        vec![StageRunStatus::Superseded, StageRunStatus::Ready]
    );
    assert_eq!(
        statuses_of(&view, StageKind::Validation),
        vec![StageRunStatus::ReworkRequested, StageRunStatus::Pending]
    );
    assert_eq!(view.code_rework_rounds, 1);
    assert_eq!(view.documentation_rework_rounds, 0);
    // The stages before the target keep their runs.
    assert_eq!(
        statuses_of(&view, StageKind::TaskPlanning),
        vec![StageRunStatus::Passed]
    );
    assert_eq!(view.status, JobStatus::Active);
}

#[tokio::test]
async fn rework_stops_at_the_cap_of_two_and_then_a_person_decides() {
    // NT-BUD-04: at most two rounds, then the stage waits. No automatic third round.
    let world = World::new().await;
    let job = world.admitted_job().await;
    run_stages(&world, 7).await;
    world.script(StageKind::Validation).queue_evals([
        Eval::Fail("first-check"),
        Eval::Fail("second-check"),
        Eval::Fail("third-check"),
    ]);
    // VALIDATION fails, IMPLEMENTATION reruns, VALIDATION fails, IMPLEMENTATION reruns, and
    // VALIDATION fails a third time.
    for _ in 0..5 {
        world.advance(400);
        world.run_next("worker-1").await;
    }
    let view = world.view(job).await;
    assert_eq!(view.code_rework_rounds, 2, "the cap is two rounds");
    assert_eq!(
        status_of(&view, StageKind::Validation),
        StageRunStatus::WaitingForHuman
    );
    assert_eq!(view.status, JobStatus::WaitingForHuman);
    assert_eq!(
        view.runs_of(StageKind::Implementation).count(),
        3,
        "the original run and two reworks, and no third round"
    );
}

#[tokio::test]
async fn negative_nt_bud_03_a_repeated_failure_asks_a_person_after_one_round() {
    // The same failing check twice means another round would not help.
    let world = World::new().await;
    let job = world.admitted_job().await;
    run_stages(&world, 7).await;
    world
        .script(StageKind::Validation)
        .queue_evals([Eval::Fail("same-check"), Eval::Fail("same-check")]);
    for _ in 0..3 {
        world.advance(400);
        world.run_next("worker-1").await;
    }
    let view = world.view(job).await;
    assert_eq!(
        view.code_rework_rounds, 1,
        "the second identical failure is not reworked"
    );
    assert_eq!(
        status_of(&view, StageKind::Validation),
        StageRunStatus::WaitingForHuman
    );
}

const TABLE: &str = include_str!("../../../docs/architecture/state-machine.json");

/// The invalidation rows of `state-machine.json`: the change, and the stages it supersedes.
fn table() -> Vec<(String, Vec<String>)> {
    let document: serde_json::Value = serde_json::from_str(TABLE).expect("the file is JSON");
    document["pipeline"]["invalidation_rules"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|row| {
            (
                row["when"].as_str().expect("text").to_owned(),
                row["supersedes"]
                    .as_array()
                    .expect("a list")
                    .iter()
                    .map(|stage| stage.as_str().expect("text").to_owned())
                    .collect(),
            )
        })
        .collect()
}

#[tokio::test]
async fn invalidation_follows_the_table() {
    // A documentation defect found at the documentation review reworks DOCUMENTING. The rows of
    // the file say that a new documentation commit supersedes the review, delivery and approval.
    let world = World::new().await;
    let job = world.admitted_job().await;
    run_stages(&world, 10).await; // INTAKE .. DOCUMENTING passed
    world
        .script(StageKind::DocumentationReview)
        .queue_evals([Eval::ChangesRequired("documentation")]);
    world.advance(400);
    world.run_next("worker-1").await;

    let view = world.view(job).await;
    let row = table()
        .into_iter()
        .find(|(when, _)| when == "DOCUMENTING produces a new documentation commit")
        .expect("the row exists")
        .1;
    for stage in &row {
        let kind = StageKind::parse(stage).expect("a stage");
        let statuses = statuses_of(&view, kind);
        let expected = if kind == StageKind::DocumentationReview {
            // The failing run takes the rework move instead.
            vec![StageRunStatus::ReworkRequested, StageRunStatus::Pending]
        } else {
            vec![StageRunStatus::Superseded, StageRunStatus::Pending]
        };
        assert_eq!(statuses, expected, "{kind}");
    }
    // The target is replaced as well, and nothing before it is touched.
    assert_eq!(
        statuses_of(&view, StageKind::Documenting),
        vec![StageRunStatus::Superseded, StageRunStatus::Ready]
    );
    assert_eq!(
        statuses_of(&view, StageKind::Review),
        vec![StageRunStatus::Passed]
    );
    assert_eq!(view.documentation_rework_rounds, 1);
    assert_eq!(view.code_rework_rounds, 0);
}

#[tokio::test]
async fn a_code_defect_at_review_supersedes_both_documentation_runs() {
    // INV-11: a new implementation commit supersedes DOCUMENTING and DOCUMENTATION_REVIEW.
    let world = World::new().await;
    let job = world.admitted_job().await;
    run_stages(&world, 11).await; // through DOCUMENTATION_REVIEW
    // A reviewer who comes late finds a code defect: the rework goes to IMPLEMENTATION.
    // The documentation review is the failing stage here, with a code_behavior finding.
    let view = world.view(job).await;
    assert_eq!(
        status_of(&view, StageKind::DocumentationReview),
        StageRunStatus::Passed
    );
    let world2 = World::new().await;
    let job2 = world2.admitted_job().await;
    run_stages(&world2, 10).await;
    world2
        .script(StageKind::DocumentationReview)
        .queue_evals([Eval::ChangesRequired("code_behavior")]);
    world2.advance(400);
    world2.run_next("worker-1").await;
    let view = world2.view(job2).await;
    assert_eq!(
        statuses_of(&view, StageKind::Documenting),
        vec![StageRunStatus::Superseded, StageRunStatus::Pending],
        "the passed documentation run is superseded"
    );
    assert_eq!(
        statuses_of(&view, StageKind::DocumentationReview),
        vec![StageRunStatus::ReworkRequested, StageRunStatus::Pending]
    );
    assert_eq!(
        statuses_of(&view, StageKind::Implementation),
        vec![StageRunStatus::Superseded, StageRunStatus::Ready]
    );
    assert_eq!(view.code_rework_rounds, 1);
}

#[tokio::test]
async fn external_changes_follow_the_table() {
    // Every row of the table, applied to a job whose first eleven stages passed, supersedes
    // exactly the runs the row lists, creates one new run for each, and cancels live attempts.
    for (when, listed) in table() {
        let change = ArtifactChange::parse(&when).expect("a known change");
        let world = World::new().await;
        let job = world.admitted_job().await;
        run_stages(&world, 11).await; // DELIVERY is ready, APPROVAL is pending
        // A worker holds DELIVERY: its attempt is live when the change arrives.
        world.advance(400);
        let live = world.claim_one("worker-live").await;
        assert_eq!(live.kind, StageKind::Delivery);

        let applied = world
            .engine
            .apply_change(world.tenant, job, change)
            .await
            .expect("the change applies");
        let mut superseded: Vec<String> = Vec::new();
        for id in &applied.superseded {
            let view = world.view(job).await;
            let run = view
                .stage_runs
                .iter()
                .find(|run| run.id == *id)
                .expect("a run");
            assert_eq!(
                run.status,
                StageRunStatus::Superseded,
                "{when}: {}",
                run.kind
            );
            superseded.push(run.kind.as_str().to_owned());
        }
        assert_eq!(superseded, listed, "{when}");
        assert_eq!(
            applied.created.len(),
            listed.len(),
            "{when}: one new run for each"
        );

        // The live attempt of DELIVERY, if the row lists it, was asked to cancel.
        let view = world.view(job).await;
        let delivery = view.runs_of(StageKind::Delivery).next().expect("a run");
        let expected_attempt = if listed.iter().any(|s| s == "DELIVERY") {
            AttemptStatus::Cancelling
        } else {
            AttemptStatus::Starting
        };
        assert_eq!(delivery.attempts[0].status, expected_attempt, "{when}");
    }
}

#[tokio::test]
async fn an_edited_request_restarts_the_job_from_the_intake() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    run_stages(&world, 3).await;
    let applied = world
        .engine
        .apply_change(world.tenant, job, ArtifactChange::RequestEdited)
        .await
        .expect("applies");
    assert_eq!(applied.superseded.len(), 13);
    let view = world.view(job).await;
    // The intake is superseded too, and its replacement is ready first.
    assert_eq!(
        statuses_of(&view, StageKind::Intake),
        vec![StageRunStatus::Superseded, StageRunStatus::Ready]
    );
    assert_eq!(
        status_of(&view, StageKind::Specification),
        StageRunStatus::Pending
    );
    assert_eq!(view.status, JobStatus::Active);
}

#[tokio::test]
async fn skipped_stage_does_not_stall_the_pipeline() {
    let world = World::new().await;
    world
        .script(StageKind::Approval)
        .evals_otherwise(Eval::HumanGate);
    world
        .script(StageKind::DomainDiscovery)
        .skip_by_rule("no-profile-needed");
    let job = world.admitted_job().await;
    // INTAKE, REPOSITORY_INTELLIGENCE and SPECIFICATION run; DOMAIN_DISCOVERY is skipped.
    run_stages(&world, 3).await;
    let view = world.view(job).await;
    assert_eq!(
        status_of(&view, StageKind::DomainDiscovery),
        StageRunStatus::Skipped
    );
    assert!(
        view.newest(StageKind::DomainDiscovery)
            .expect("run")
            .attempts
            .is_empty()
    );
    // The architecture stage requires the skipped stage, and it is ready.
    assert_eq!(
        status_of(&view, StageKind::Architecture),
        StageRunStatus::Ready
    );
    // The skip and its rule are in the ledger.
    let ledger = world.ledger(job).await;
    assert!(
        ledger
            .iter()
            .any(|entry| entry.claim.statement.as_str().contains("no-profile-needed"))
    );
    // The rest of the pipeline runs to the approval.
    run_stages(&world, 9).await;
    let view = world.view(job).await;
    assert_eq!(
        status_of(&view, StageKind::Approval),
        StageRunStatus::WaitingForHuman
    );
}

#[tokio::test]
async fn negative_nt_mrg_02_missing_or_blocked_evidence_never_passes_a_stage() {
    // Every way a gate can hand over less than a pass leaves the stage run unpromoted.
    let cases: [(Eval, &str); 5] = [
        (Eval::NoEvidence, "no evidence at all"),
        (Eval::Blocked, "a gate that could not run"),
        (Eval::CannotRun, "an evaluator that is missing a tool"),
        (Eval::WrongStageRun, "evidence about another stage run"),
        (Eval::PolicyViolation, "a policy violation"),
    ];
    for (eval, why) in cases {
        let world = World::new().await;
        let job = world.admitted_job().await;
        world.script(StageKind::Intake).queue_evals([eval]);
        let (_, outcome) = world.run_next("worker-1").await;
        assert_eq!(
            outcome,
            AttemptOutcome::Succeeded,
            "{why}: the attempt itself succeeded"
        );
        let view = world.view(job).await;
        assert_eq!(
            status_of(&view, StageKind::Intake),
            StageRunStatus::Blocked,
            "{why}"
        );
        assert_eq!(view.status, JobStatus::Blocked, "{why}");
        // Nothing downstream moved, and no event says the stage passed.
        assert_eq!(
            status_of(&view, StageKind::RepositoryIntelligence),
            StageRunStatus::Pending,
            "{why}"
        );
        let events = world.events(job).await;
        assert!(
            !events
                .iter()
                .any(|e| e.event_type.as_str() == "stage_run.passed"),
            "{why}"
        );
    }
}

#[tokio::test]
async fn evidence_refused_by_the_engine_is_never_cited_in_the_ledger() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .queue_evals([Eval::WrongStageRun]);
    world.run_next("worker-1").await;
    let ledger = world.ledger(job).await;
    assert!(
        ledger
            .iter()
            .all(|entry| !entry.claim.statement.as_str().contains("scripted-gate")),
        "a refused report is not recorded as evidence"
    );
}

#[tokio::test]
async fn a_reviewer_who_asks_for_a_person_or_a_human_gate_waits_for_one() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .queue_evals([Eval::ReviewerNeedsHuman]);
    world.run_next("worker-1").await;
    let view = world.view(job).await;
    assert_eq!(
        status_of(&view, StageKind::Intake),
        StageRunStatus::WaitingForHuman
    );
    assert_eq!(view.status, JobStatus::WaitingForHuman);

    let world = World::new().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .queue_evals([Eval::HumanGate]);
    world.run_next("worker-1").await;
    assert_eq!(
        status_of(&world.view(job).await, StageKind::Intake),
        StageRunStatus::WaitingForHuman
    );
}

#[tokio::test]
async fn a_specification_or_policy_defect_asks_a_person_and_uses_no_round() {
    // ADR 0010 decision 3: the builder cannot fix these, so no rework round is spent.
    let world = World::new().await;
    let job = world.admitted_job().await;
    run_stages(&world, 8).await; // through VALIDATION; REVIEW is next
    world
        .script(StageKind::Review)
        .queue_evals([Eval::ChangesRequired("specification")]);
    world.advance(400);
    world.run_next("worker-1").await;
    let view = world.view(job).await;
    assert_eq!(
        status_of(&view, StageKind::Review),
        StageRunStatus::WaitingForHuman
    );
    assert_eq!(view.code_rework_rounds, 0, "no round was used");
}

#[tokio::test]
async fn ids_of_runs_are_unique_across_a_rework() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    run_stages(&world, 7).await;
    world
        .script(StageKind::Validation)
        .queue_evals([Eval::Fail("tests-pass")]);
    world.advance(400);
    world.run_next("worker-1").await;
    let view = world.view(job).await;
    let ids: std::collections::HashSet<StageRunId> =
        view.stage_runs.iter().map(|run| run.id).collect();
    assert_eq!(ids.len(), view.stage_runs.len());
}
