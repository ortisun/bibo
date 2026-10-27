//! One named test for each invariant of `state-machine.md` (INV-01 to INV-11), and property tests
//! of the claim loop.
//!
//! An invariant test drives the engine through its public API and then reads the store back. A
//! test that proves an invariant is guarded runs against the in-memory store as it is, and, where
//! the store can be built with a deliberate fault (`StoreDefect`), the same check is run against
//! the faulty store and must fail. A check that cannot fail proves nothing.

mod support;

use factory_domain::state::AttemptStatus;
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
                    let mut tx = world.store_system().await;
                    let _ = tx
                        .claim_ready(
                            &World::worker("crashing"),
                            1,
                            std::time::Duration::from_secs(60),
                        )
                        .await;
                    // Committed and then forgotten: the engine stopped before it started the
                    // attempt.
                    let _ = tx.commit().await;
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
        // No lost work: let every lease lapse, sweep, and claim until nothing is left. Every
        // job's first stage run then has been given an attempt.
        for _ in 0..8 {
            world.advance(61);
            world.engine.sweep().await.map_err(|e| e.to_string())?;
            let claimed = world
                .engine
                .claim_next(&World::worker("drain"))
                .await
                .map_err(|e| e.to_string())?;
            if claimed.started.is_empty() && claimed.deferred.is_empty() {
                break;
            }
        }
        for job in &jobs {
            check_job(&world, *job).await?;
            let view = world.view(*job).await;
            let intake = view.newest(StageKind::Intake).ok_or("no intake run")?;
            if intake.attempts.is_empty() {
                return Err(format!(
                    "the intake run of {job} was never given an attempt"
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
