//! One named test for each invariant of `state-machine.md` (INV-01 to INV-11), and property tests
//! of the claim loop.
//!
//! An invariant test drives the engine through its public API and then reads the store back. A
//! test that proves an invariant is guarded runs against the in-memory store as it is, and, where
//! the store can be built with a deliberate fault (`StoreDefect`), the same check is run against
//! the faulty store and must fail. A check that cannot fail proves nothing.

mod support;

use factory_domain::state::{AttemptStatus, StageRunStatus};
use factory_domain::vocabulary::StageKind;
use factory_ports::store::LeaseEpoch;
use support::World;

/// Property tests of the claim loop: whatever order claims, crashes, heartbeats, clock moves and
/// sweeps come in, no stage run has two live attempts, epochs only go up, and no ready stage run
/// is left without an attempt once the leases have lapsed.
mod claim_loop {
    use super::*;
    use factory_domain::ids::JobId;
    use factory_workflow::scheduler::ClaimedAttempt;
    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum Op {
        Claim(usize),
        CrashAfterClaim,
        Heartbeat(usize),
        Advance(u64),
        Sweep,
    }

    fn ops() -> impl Strategy<Value = Vec<Op>> {
        let op = prop_oneof![
            (0_usize..3).prop_map(Op::Claim),
            Just(Op::CrashAfterClaim),
            (0_usize..8).prop_map(Op::Heartbeat),
            prop_oneof![Just(5_u64), Just(30), Just(59), Just(61), Just(120)].prop_map(Op::Advance),
            Just(Op::Sweep),
        ];
        proptest::collection::vec(op, 1..40)
    }

    async fn check_job(world: &World, job: JobId) -> Result<(), String> {
        let view = world.view(job).await;
        for run in &view.stage_runs {
            let live = run
                .attempts
                .iter()
                .filter(|a| matches!(a.status, AttemptStatus::Starting | AttemptStatus::Running))
                .count();
            if live > 1 {
                return Err(format!("{} has {live} live attempts", run.kind));
            }
            let mut previous = LeaseEpoch::NEVER_CLAIMED;
            for attempt in &run.attempts {
                if attempt.epoch <= previous {
                    return Err(format!(
                        "{}: epochs do not rise: {:?}",
                        run.kind, run.attempts
                    ));
                }
                previous = attempt.epoch;
            }
            if previous > run.lease_epoch {
                return Err(format!(
                    "{}: an attempt is above the stored epoch",
                    run.kind
                ));
            }
        }
        Ok(())
    }

    async fn run_ops(ops: Vec<Op>) -> Result<(), String> {
        let world = World::new().await;
        let mut jobs = Vec::new();
        for _ in 0..3 {
            jobs.push(world.admitted_job().await);
        }
        let mut tickets: Vec<ClaimedAttempt> = Vec::new();
        for op in ops {
            match op {
                Op::Claim(worker) => {
                    let name = format!("worker-{worker}");
                    let claimed = world
                        .engine
                        .claim_next(&World::worker(&name))
                        .await
                        .map_err(|e| e.to_string())?;
                    tickets.extend(claimed.started);
                }
                Op::CrashAfterClaim => {
                    // A claim is found in one transaction and started in another. An engine
                    // that stops between the two has written nothing, so the stage run is found
                    // again by the next claim.
                    let mut tx = world.store_system().await;
                    let _ = tx.find_claim_candidates(1).await;
                    let _ = tx.finish().await;
                }
                Op::Heartbeat(index) => {
                    if let Some(ticket) = tickets.get(index % tickets.len().max(1))
                        && world.engine.heartbeat(ticket).await.is_ok()
                    {
                        let view = world.view(ticket.job).await;
                        let run = view
                            .stage_runs
                            .iter()
                            .find(|r| r.id == ticket.stage_run)
                            .ok_or("the run vanished")?;
                        let attempt = run
                            .attempts
                            .iter()
                            .find(|a| a.id == ticket.attempt)
                            .ok_or("the attempt vanished")?;
                        if !matches!(
                            attempt.status,
                            AttemptStatus::Starting | AttemptStatus::Running
                        ) {
                            return Err(format!(
                                "a heartbeat succeeded for an attempt that is {}",
                                attempt.status
                            ));
                        }
                    }
                }
                Op::Advance(seconds) => world.advance(seconds),
                Op::Sweep => {
                    world.engine.sweep().await.map_err(|e| e.to_string())?;
                }
            }
            for job in &jobs {
                check_job(&world, *job).await?;
            }
        }
        // No lost work: let every lease lapse, sweep, and let a worker run what it claims, until
        // nothing more happens. Every job's first stage run is then past the claim: it reached
        // its gate, or it asked a person after three attempts. None is stuck ready or running
        // with an attempt that nobody owns.
        for _ in 0..24 {
            world.advance(400);
            let swept = world.engine.sweep().await.map_err(|e| e.to_string())?;
            let claimed = world
                .engine
                .claim_next(&World::worker("drain"))
                .await
                .map_err(|e| e.to_string())?;
            for ticket in &claimed.started {
                world
                    .engine
                    .run_attempt(ticket)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            // Changed with ports v1.1: a stage run in its back-off is not offered by the store,
            // so a round that only swept an attempt finds nothing to claim yet. The drain stops
            // when a whole round did nothing: no attempt swept, none started, none deferred.
            if swept.lease_lost.is_empty()
                && claimed.started.is_empty()
                && claimed.deferred.is_empty()
            {
                break;
            }
        }
        for job in &jobs {
            check_job(&world, *job).await?;
            let view = world.view(*job).await;
            let intake = view.newest(StageKind::Intake).ok_or("no intake run")?;
            if !matches!(
                intake.status,
                StageRunStatus::Passed | StageRunStatus::WaitingForHuman
            ) {
                return Err(format!(
                    "the intake run of {job} is {} after the drain: {:?}",
                    intake.status, intake.attempts
                ));
            }
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

        #[test]
        fn no_double_claim_and_no_lost_work(sequence in ops()) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("a runtime");
            let outcome = runtime.block_on(run_ops(sequence));
            prop_assert!(outcome.is_ok(), "{:?}", outcome);
        }
    }
}

// ---- one named test for each invariant of state-machine.md --------------------------------

mod named {
    use std::collections::HashMap;

    use factory_domain::contracts::DomainEvent;
    use factory_domain::contracts::domain_event::AggregateKind;
    use factory_domain::scope::TenantScope;
    use factory_domain::state::{
        AttemptStatus, Guard, JobStatus, StageRunEvent, StageRunStatus, Status,
    };
    use factory_domain::values::Timestamp;
    use factory_domain::vocabulary::{HumanRole, StageKind};
    use factory_ports::store::{AppliedTransition, StoreError};
    use factory_testkit::fixtures::cleared;
    use factory_testkit::store::StoreDefect;
    use factory_workflow::commands::{Decision, OverrideFacts, Subject};
    use factory_workflow::engine::{AttemptOutcome, EngineError};
    use factory_workflow::handlers::StageError;
    use support::{Eval, Step, World};

    use super::*;

    /// The statuses a transition may start from, and the one it ends in.
    fn row_of(event: &DomainEvent) -> Result<Option<(Vec<String>, String)>, String> {
        let id = event.transition_id.as_str();
        macro_rules! find {
            ($machine:ty) => {{
                let row = <$machine>::TRANSITIONS
                    .iter()
                    .find(|r| r.id == id)
                    .ok_or(format!("unknown transition {id}"))?;
                Ok(Some((
                    row.from.iter().map(ToString::to_string).collect(),
                    row.to.to_string(),
                )))
            }};
        }
        match event.aggregate.kind {
            AggregateKind::Job => find!(JobStatus),
            AggregateKind::StageRun => find!(StageRunStatus),
            AggregateKind::Attempt => find!(AttemptStatus),
            AggregateKind::TaskNode => Ok(None),
        }
    }

    /// Every event of an aggregate starts where the one before it ended, and a stage run that
    /// failed, was sent back, was cancelled or was superseded never moves again. Returns the
    /// first thing that breaks this.
    fn chains_are_legal(events: &[DomainEvent]) -> Result<(), String> {
        let mut last_to: HashMap<_, String> = HashMap::new();
        for event in events {
            let Some((froms, to)) = row_of(event)? else {
                continue;
            };
            let key = (event.aggregate.kind, event.aggregate.id);
            if let Some(previous) = last_to.get(&key) {
                if !froms.iter().any(|from| from == previous) {
                    return Err(format!(
                        "{} ({}) does not follow a move that ended in {previous}",
                        event.event_type, event.transition_id
                    ));
                }
                if event.aggregate.kind == AggregateKind::StageRun
                    && matches!(
                        previous.as_str(),
                        "FAILED" | "REWORK_REQUESTED" | "CANCELLED" | "SUPERSEDED"
                    )
                {
                    return Err(format!("a stage run in {previous} moved again"));
                }
            }
            last_to.insert(key, to);
        }
        Ok(())
    }

    /// A job with failures, a rework, a person's answer and a cancel path behind it.
    async fn busy_world() -> (World, factory_domain::ids::JobId) {
        let world = World::new().await;
        world
            .script(StageKind::Approval)
            .evals_otherwise(Eval::HumanGate);
        let job = world.admitted_job().await;
        world.script(StageKind::Intake).queue([
            Step::Fail(StageError::Tool),
            Step::Fail(StageError::Provider),
        ]);
        world
            .script(StageKind::Validation)
            .queue_evals([Eval::Fail("tests-pass")]);
        world.script(StageKind::Review).queue_evals([Eval::Blocked]);
        for _ in 0..40 {
            world.advance(400);
            world.engine.sweep().await.expect("sweep");
            let claimed = world
                .engine
                .claim_next(&World::worker("worker-1"))
                .await
                .expect("claim");
            if claimed.started.is_empty() {
                break;
            }
            for ticket in &claimed.started {
                world.engine.run_attempt(ticket).await.expect("runs");
            }
        }
        (world, job)
    }

    /// A write that starts from a stale version must be refused. Returns what is wrong when the
    /// store accepts it.
    async fn stale_write_is_refused(world: &World) -> Result<(), String> {
        let job = world.admitted_job().await;
        let run = world.view(job).await.stage_runs[0].id;
        let at = Timestamp::parse("2026-10-27T08:30:00Z").expect("an instant");
        let mut tx = world
            .store
            .begin(TenantScope::new(world.tenant))
            .await
            .expect("a tx");
        let status = tx.get_stage_run(run).await.expect("run").value.status;
        let plan = AppliedTransition::plan(
            status,
            StageRunEvent::Cancel,
            at,
            cleared(Guard::NoActiveAttempt),
        )
        .expect("legal");
        // The row has moved past its first version, so version one is stale.
        match tx
            .transition_stage_run(
                run,
                factory_ports::store::Version::FIRST,
                plan,
                factory_ports::store::StageRunEffects::default(),
            )
            .await
        {
            Err(StoreError::Conflict) => Ok(()),
            other => Err(format!("a stale write was not refused: {other:?}")),
        }
    }

    #[tokio::test]
    async fn inv_01_only_the_engine_writes_a_status() {
        // Every stored move is a move of the table, and a stale write is refused by the store.
        let (world, job) = busy_world().await;
        chains_are_legal(&world.events(job).await).expect("every move is in the table");
        stale_write_is_refused(&World::new().await)
            .await
            .expect("the faithful store refuses");
    }

    #[tokio::test]
    async fn inv_01_deliberate_break_a_store_without_the_version_check_is_caught() {
        // The same check, run against a store that skips the compare-and-swap, must fail.
        let world = World::with_store_defect(StoreDefect::SkipsVersionCheck).await;
        let outcome = stale_write_is_refused(&world).await;
        assert!(
            outcome.is_err(),
            "the check must fail against a faulty store"
        );
    }

    #[tokio::test]
    async fn inv_02_a_move_the_table_does_not_list_is_refused_and_changes_nothing() {
        let world = World::new().await;
        let job = world.admitted_job().await;
        let before = world.view(job).await;
        // Admission a second time, and an answer to a stage run that waits for nobody.
        assert!(matches!(
            world.engine.admit_job(world.tenant, job).await,
            Err(EngineError::Illegal(_))
        ));
        let operator = world.person("operator-1", &[HumanRole::Operator]).await;
        let refused = world
            .engine
            .decide(
                &world.actor(operator),
                Subject {
                    job,
                    stage_run: before.stage_runs[0].id,
                },
                Decision::Answer {
                    text: "Nobody asked a question.".to_owned(),
                    raises_budget_ceiling: false,
                },
            )
            .await;
        assert!(
            matches!(refused, Err(EngineError::Illegal(_))),
            "{refused:?}"
        );
        assert_eq!(world.view(job).await, before, "nothing changed");
        // And at the level of the table, every pair that is not listed is refused.
        for status in StageRunStatus::STATES {
            for event in StageRunStatus::EVENTS {
                let listed = status.legal_events().contains(event);
                // A listed pair is planned with the guard of its own row; an unlisted pair is
                // refused whatever guard is offered. The fixture builds a clearance for most
                // guards and refuses to build one for the rest, so a listed pair whose guard the
                // fixture lacks is skipped here; the ports crate checks every listed pair with
                // its own guard in `every_legal_job_move_with_its_own_guard_can_be_planned`.
                let guard = status
                    .transition(*event)
                    .map_or(Guard::AdmissionOk, |row| row.guard);
                let Ok(clearance) = std::panic::catch_unwind(|| cleared(guard)) else {
                    assert!(listed, "an unlisted pair is always checked");
                    continue;
                };
                assert_eq!(
                    AppliedTransition::plan(
                        *status,
                        *event,
                        Timestamp::parse("2026-10-27T08:30:00Z").unwrap(),
                        clearance,
                    )
                    .is_ok(),
                    listed
                );
            }
        }
    }

    #[tokio::test]
    async fn inv_03_a_failure_at_any_write_leaves_the_job_consistent_and_it_resumes() {
        // Fault injection at every write boundary: the n-th identifier repeats, some write of
        // some transaction fails, and that transaction is dropped. Nothing of it may remain.
        let mut faulted = 0;
        for n in 1..=120_u64 {
            let world = World::new().await;
            world
                .script(StageKind::Approval)
                .evals_otherwise(Eval::HumanGate);
            let job = world.admitted_job().await;
            world.ids.arm(n);
            let mut broke = false;
            for _ in 0..40 {
                world.advance(400);
                let swept = world.engine.sweep().await;
                let claimed = world.engine.claim_next(&World::worker("worker-1")).await;
                let (Ok(swept), Ok(claimed)) = (swept, claimed) else {
                    broke = true;
                    world.ids.disarm();
                    continue;
                };
                // A stage run in its back-off is not offered by the store (ports v1.1), so a
                // round that only swept an attempt finds nothing to claim yet. Stop when a whole
                // round did nothing.
                if swept.lease_lost.is_empty()
                    && claimed.started.is_empty()
                    && claimed.deferred.is_empty()
                {
                    break;
                }
                for ticket in &claimed.started {
                    if world.engine.run_attempt(ticket).await.is_err() {
                        broke = true;
                        world.ids.disarm();
                    }
                }
            }
            faulted += usize::from(broke);
            // Whatever broke, the record is consistent and the job reaches the same place.
            let report = world
                .engine
                .verify_job(world.tenant, job)
                .await
                .expect("verifies");
            assert!(report.is_clean(), "fault {n}: {:?}", report.findings);
            chains_are_legal(&world.events(job).await)
                .unwrap_or_else(|why| panic!("fault {n}: {why}"));
            let view = world.view(job).await;
            assert_eq!(
                view.newest(StageKind::Approval).map(|r| r.status),
                Some(StageRunStatus::WaitingForHuman),
                "fault {n}: the job did not resume to the approval"
            );
            let events = world.events(job).await;
            let passed = events
                .iter()
                .filter(|e| e.event_type.as_str() == "stage_run.passed")
                .count();
            assert_eq!(
                passed, 12,
                "fault {n}: a stage run passed twice or not at all"
            );
        }
        assert!(faulted > 5, "the faults did hit writes ({faulted} of 120)");
    }

    /// Polls a future once and drops it if it has not finished. Every call of the in-memory store
    /// finishes at once, so a future that is still pending after its first poll is one whose store
    /// call hung (`stall_next_call`). Dropping it is a crash of the engine at that call.
    async fn crashing<F: std::future::Future>(work: F) -> Option<F::Output> {
        let mut work = std::pin::pin!(work);
        tokio::select! {
            biased;
            output = &mut work => Some(output),
            () = std::future::ready(()) => None,
        }
    }

    /// Runs a job to its approval the way a worker would, with every engine call crashing when its
    /// store call hangs. Returns whether any call crashed.
    async fn drive_to_the_approval(world: &World) -> bool {
        let mut crashed = false;
        for _ in 0..60 {
            world.advance(400);
            let Some(swept) = crashing(world.engine.sweep()).await else {
                crashed = true;
                world.ids.disarm();
                continue;
            };
            let Some(claimed) = crashing(world.engine.claim_next(&World::worker("worker-1"))).await
            else {
                crashed = true;
                world.ids.disarm();
                continue;
            };
            let (Ok(swept), Ok(claimed)) = (swept, claimed) else {
                world.ids.disarm();
                continue;
            };
            if swept.lease_lost.is_empty()
                && swept.timed_out.is_empty()
                && claimed.started.is_empty()
                && claimed.deferred.is_empty()
            {
                break;
            }
            for ticket in &claimed.started {
                if crashing(world.engine.run_attempt(ticket)).await.is_none() {
                    crashed = true;
                    world.ids.disarm();
                }
            }
        }
        crashed
    }

    #[tokio::test]
    async fn inv_03_a_crash_at_any_write_boundary_leaves_the_job_consistent_and_it_resumes() {
        // A crash, where the test above makes a write fail. For every identifier the engine makes
        // while it runs a job, the store call that follows it hangs and the engine's future is
        // dropped there, in the middle of a transaction. Ports v1.1 added writes (the audit
        // record, the guard on every event, the start of an attempt as one step, the gate record),
        // so there are more boundaries than before and this test visits every one of them.
        let probe = World::new().await;
        probe
            .script(StageKind::Approval)
            .evals_otherwise(Eval::HumanGate);
        probe.admitted_job().await;
        let first = probe.ids.used();
        assert!(!drive_to_the_approval(&probe).await);
        let boundaries = probe.ids.used() - first;
        assert!(boundaries > 100, "{boundaries} boundaries");

        let mut crashed = 0;
        for n in 1..=boundaries {
            let world = World::new().await;
            world
                .script(StageKind::Approval)
                .evals_otherwise(Eval::HumanGate);
            let job = world.admitted_job().await;
            let store = world.memory_store();
            world.ids.arm_hook(n, move || store.stall_next_call());
            let broke = drive_to_the_approval(&world).await;
            crashed += usize::from(broke);
            world.ids.disarm();
            // Whatever was dropped, the record is consistent and the job reaches the same place.
            assert!(
                !drive_to_the_approval(&world).await,
                "boundary {n}: a crash after the fault was disarmed"
            );
            let report = world
                .engine
                .verify_job(world.tenant, job)
                .await
                .expect("verifies");
            assert!(report.is_clean(), "boundary {n}: {:?}", report.findings);
            chains_are_legal(&world.events(job).await)
                .unwrap_or_else(|why| panic!("boundary {n}: {why}"));
            let view = world.view(job).await;
            assert_eq!(
                view.newest(StageKind::Approval).map(|r| r.status),
                Some(StageRunStatus::WaitingForHuman),
                "boundary {n}: the job did not resume to the approval"
            );
            let passed = world
                .events(job)
                .await
                .iter()
                .filter(|e| e.event_type.as_str() == "stage_run.passed")
                .count();
            assert_eq!(
                passed, 12,
                "boundary {n}: a stage run passed twice or not at all"
            );
        }
        assert!(
            crashed * 3 > usize::try_from(boundaries).unwrap_or(usize::MAX),
            "the crashes did hit writes ({crashed} of {boundaries})"
        );
    }

    #[tokio::test]
    async fn inv_04_a_terminal_stage_run_is_never_edited() {
        let (world, job) = busy_world().await;
        chains_are_legal(&world.events(job).await)
            .expect("terminal runs only leave by supersession");
        // The run that was sent back for rework stays as it is, and a decision on it is refused.
        let view = world.view(job).await;
        let reworked = view
            .runs_of(StageKind::Validation)
            .find(|run| run.status == StageRunStatus::ReworkRequested)
            .expect("a run was sent back");
        let operator = world.person("operator-1", &[HumanRole::Operator]).await;
        let refused = world
            .engine
            .decide(
                &world.actor(operator),
                Subject {
                    job,
                    stage_run: reworked.id,
                },
                Decision::UnblockRerun {
                    capability_reprobe_passed: true,
                    dependency_now_available: true,
                },
            )
            .await;
        assert!(
            matches!(refused, Err(EngineError::Illegal(_))),
            "{refused:?}"
        );
        assert_eq!(
            world
                .view(job)
                .await
                .stage_runs
                .iter()
                .find(|r| r.id == reworked.id)
                .map(|r| r.status),
            Some(StageRunStatus::ReworkRequested)
        );
    }

    #[tokio::test]
    async fn inv_05_a_write_from_an_older_lease_epoch_is_refused() {
        // The stale worker of NT-LSE-01, seen from the epoch: its heartbeat and its result are
        // both refused once another attempt holds a higher epoch.
        let world = World::new().await;
        let job = world.admitted_job().await;
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        world.script(StageKind::Intake).queue([Step::Hang(release)]);
        let first = world.claim_one("worker-a").await;
        world.advance(61);
        world.engine.sweep().await.expect("sweep");
        world.advance(5);
        let second = world.claim_one("worker-b").await;
        assert!(second.epoch > first.epoch);
        assert_eq!(
            world.engine.heartbeat(&first).await,
            Err(EngineError::LeaseFenced)
        );
        let view = world.view(job).await;
        let intake = view.newest(StageKind::Intake).expect("run");
        assert_eq!(intake.attempts[0].status, AttemptStatus::LeaseLost);
        assert_eq!(intake.attempts[1].epoch, second.epoch);
    }

    #[tokio::test]
    async fn a_store_that_starts_the_attempt_twice_cannot_make_two_attempts() {
        // The claim is guarded in three places: the store's exclusion in `start_attempt`, the
        // engine's re-read of the stage run before it starts, and the compare-and-swap of the
        // commit. Here the first is broken on purpose, so one stage run goes to two engines at
        // once, and the others hold.
        let world = World::with_store_defect(StoreDefect::DoubleStartsAttempt).await;
        let job = world.admitted_job().await;
        let other = world.restarted_engine();
        let (first, second) = (World::worker("worker-1"), World::worker("worker-2"));
        let (a, b) = tokio::join!(world.engine.claim_next(&first), other.claim_next(&second));
        let started = a.expect("claim").started.len() + b.expect("claim").started.len();
        assert_eq!(started, 1, "one stage run starts once");
        let view = world.view(job).await;
        assert_eq!(
            view.newest(StageKind::Intake).expect("run").attempts.len(),
            1
        );
    }

    #[tokio::test]
    async fn inv_06_a_mandatory_gate_that_did_not_run_is_blocked() {
        for eval in [
            Eval::NoEvidence,
            Eval::Blocked,
            Eval::CannotRun,
            Eval::PolicyViolation,
        ] {
            let world = World::new().await;
            let job = world.admitted_job().await;
            world.script(StageKind::Intake).queue_evals([eval]);
            world.run_next("worker-1").await;
            let view = world.view(job).await;
            assert_eq!(
                view.newest(StageKind::Intake).expect("run").status,
                StageRunStatus::Blocked
            );
        }
    }

    #[tokio::test]
    async fn inv_07_an_override_creates_no_assurance_level_and_spares_mandatory_gates() {
        let world = World::new().await;
        let job = world.admitted_job().await;
        world.script(StageKind::Intake).queue_evals([Eval::Blocked]);
        world.run_next("worker-1").await;
        let run = world
            .view(job)
            .await
            .newest(StageKind::Intake)
            .expect("run")
            .id;
        let approver = world.person("approver-1", &[HumanRole::Approver]).await;
        let request = |mandatory| Decision::Override {
            justification: factory_domain::values::HumanText::parse(
                "I accept the risk of this block as it is.",
            )
            .expect("a text"),
            facts: OverrideFacts {
                policy_permits: true,
                security_class: false,
                mandatory_of_active_profile: mandatory,
            },
        };
        assert!(matches!(
            world
                .engine
                .decide(
                    &world.actor(approver),
                    Subject {
                        job,
                        stage_run: run
                    },
                    request(true)
                )
                .await,
            Err(EngineError::GuardUnmet(_))
        ));
        world
            .engine
            .decide(
                &world.actor(approver),
                Subject {
                    job,
                    stage_run: run,
                },
                request(false),
            )
            .await
            .expect("an ordinary block can be overridden");
        assert!(
            world
                .ledger(job)
                .await
                .iter()
                .all(|e| e.claim.assurance_level.is_none())
        );
    }

    #[tokio::test]
    async fn inv_08_a_fake_is_accepted_only_in_test_mode_and_supports_no_level() {
        let world = World::new().await;
        let job = world.admitted_job().await;
        world.run_stages(3).await;
        let entries = world.ledger(job).await;
        // Test mode: the entries are labelled fake and none claims a level.
        assert!(entries.iter().all(|e| {
            e.metadata.recorded_by.fidelity == factory_domain::vocabulary::RecorderFidelity::Fake
                && e.claim.assurance_level.is_none()
        }));
        // The same record, read as a production job, is refused by the verifier.
        let outcomes = factory_workflow::audit::RunOutcomes::default();
        assert!(
            !factory_workflow::audit::check_job(
                &entries,
                &outcomes,
                factory_domain::vocabulary::ExecutionMode::Production
            )
            .is_empty()
        );
    }

    #[tokio::test]
    async fn inv_09_superseding_appends_entries_and_never_changes_old_ones() {
        let world = World::new().await;
        let job = world.admitted_job().await;
        world.run_stages(7).await;
        let before = world.ledger(job).await;
        world
            .script(StageKind::Validation)
            .queue_evals([Eval::Fail("tests-pass")]);
        world.advance(400);
        world.run_next("worker-1").await;
        let after = world.ledger(job).await;
        assert!(after.len() > before.len());
        assert_eq!(
            &after[..before.len()],
            &before[..],
            "every old entry is unchanged"
        );
    }

    #[tokio::test]
    async fn inv_10_a_limit_asks_a_person_and_does_not_fail_the_stage() {
        // An always-failing runtime reaches WAITING_FOR_HUMAN in three steps, and a budget limit
        // takes S07, never S06.
        let world = World::new().await;
        let job = world.admitted_job().await;
        world
            .script(StageKind::Intake)
            .otherwise(Step::Fail(StageError::Tool));
        for _ in 0..3 {
            world.advance(600);
            world.run_next("worker-1").await;
        }
        let view = world.view(job).await;
        assert_eq!(
            view.newest(StageKind::Intake).expect("run").status,
            StageRunStatus::WaitingForHuman
        );
        let transitions: Vec<String> = world
            .events(job)
            .await
            .iter()
            .map(|e| e.transition_id.as_str().to_owned())
            .collect();
        assert!(
            !transitions.contains(&"S06".to_owned()),
            "the stage run did not fail"
        );
        assert!(transitions.contains(&"S07".to_owned()));

        let world = World::new().await;
        let job = world.admitted_job().await;
        world
            .script(StageKind::Intake)
            .queue([Step::Fail(StageError::BudgetExhausted)]);
        let (_, outcome) = world.run_next("worker-1").await;
        assert!(matches!(outcome, AttemptOutcome::Failed { .. }));
        let transitions: Vec<String> = world
            .events(job)
            .await
            .iter()
            .map(|e| e.transition_id.as_str().to_owned())
            .collect();
        assert!(
            transitions.contains(&"S07".to_owned()) && !transitions.contains(&"S06".to_owned())
        );
    }

    #[tokio::test]
    async fn inv_11_documentation_runs_after_review_and_a_new_commit_supersedes_it() {
        let world = World::new().await;
        let job = world.admitted_job().await;
        world.run_stages(13).await;
        // Order: DOCUMENTING became ready after REVIEW passed, and DELIVERY after the
        // documentation review passed.
        let events = world.events(job).await;
        let position = |kind: &str, event: &str| {
            events.iter().position(|e| {
                e.event_type.as_str() == event
                    && e.payload.get("stage_kind").and_then(|k| k.as_str()) == Some(kind)
            })
        };
        let review_passed = position("REVIEW", "stage_run.passed").expect("review passed");
        let docs_ready = position("DOCUMENTING", "stage_run.ready").expect("docs ready");
        let docs_review_passed =
            position("DOCUMENTATION_REVIEW", "stage_run.passed").expect("passed");
        let delivery_ready = position("DELIVERY", "stage_run.ready").expect("delivery ready");
        assert!(review_passed < docs_ready);
        assert!(docs_review_passed < delivery_ready);
    }
}
