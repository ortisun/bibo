//! Claims, leases, fencing and the lock mode, against a real PostgreSQL server.
//!
//! A claim here is the claim of the schema: one tenant transaction moves the stage run to
//! `RUNNING` with `lease_epoch + 1` and creates the attempt that carries the lease. The tests
//! find that attempt with a superuser query, because the port gives a caller no way to ask for
//! it. The shared contract checks that need the caller to name the attempt are excluded in
//! `store_contract.rs`, and these tests cover the same properties.

mod support;

use std::sync::Arc;
use std::time::Duration;

use diesel_async::SimpleAsyncConnection;
use factory_domain::state::{AttemptEvent, AttemptStatus, Status};
use factory_ports::clock::duration_between;
use factory_ports::store::{AppliedTransition, LeaseEpoch, StoreError};
use factory_testkit::clock::FakeClock;
use factory_testkit::fixtures::ledger_entry;
use support::{Scene, now};
use tokio::sync::Barrier;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_claim_has_one_winner() {
    let scene = Arc::new(Scene::new().await);
    let job = scene.job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;

    // Eight workers reach the claim at the same moment.
    let barrier = Arc::new(Barrier::new(8));
    let mut workers = Vec::new();
    for number in 0..8 {
        let (scene, barrier) = (scene.clone(), barrier.clone());
        workers.push(tokio::spawn(async move {
            barrier.wait().await;
            scene.claim(&format!("worker-{number}"), 5).await.len()
        }));
    }
    let mut winners = 0;
    for worker in workers {
        winners += worker.await.expect("a worker does not panic");
    }
    assert_eq!(winners, 1, "exactly one claimer wins the ready stage run");

    let attempts = scene.attempts_of(run).await;
    assert_eq!(
        attempts.len(),
        1,
        "one claim made one attempt: {attempts:?}"
    );
    assert_eq!(attempts[0].2, "STARTING");
    assert_eq!(
        scene
            .db
            .text(&format!(
                "SELECT status || ':' || lease_epoch FROM stage_runs WHERE id = '{}'",
                run.as_uuid()
            ))
            .await
            .as_deref(),
        Some("RUNNING:1"),
        "the stage run is RUNNING at epoch 1"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_claimers_holding_open_transactions_cannot_take_the_same_row() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    scene.ready_stage_run(scene.a, job).await;
    let worker = |name: &str| factory_ports::store::WorkerId::new(name).expect("worker");
    let mut first = scene.system_tx().await;
    let mut second = scene.system_tx().await;
    let ttl = Duration::from_secs(30);
    let got = first
        .claim_ready(&worker("worker-1"), 10, ttl)
        .await
        .expect("first");
    assert_eq!(got.len(), 1);
    // The first transaction has not committed. The second must skip the row, not wait for it.
    let skipped = second
        .claim_ready(&worker("worker-2"), 10, ttl)
        .await
        .expect("second");
    assert_eq!(skipped.len(), 0);
    first.commit().await.expect("commit");
    drop(second);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_sets_the_lease_and_raises_the_epoch() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    let mut system = scene.system_tx().await;
    let before = system.database_time().await.expect("time");
    drop(system);
    let ttl = Duration::from_secs(45);
    let claimed = scene.claim_for("worker-1", 10, ttl).await;
    assert_eq!(claimed.len(), 1);
    let work = &claimed[0];
    assert_eq!(work.stage_run.value.id, run);
    assert_eq!(work.lease.epoch, LeaseEpoch::new(1));
    assert_eq!(work.lease.worker.as_str(), "worker-1");
    assert_eq!(work.lease.ttl, ttl);
    let expires_in = duration_between(&before, &work.lease.expires_at).expect("after the claim");
    assert!(
        expires_in >= ttl && expires_in <= ttl + Duration::from_secs(2),
        "the lease ends one ttl after the database time: {expires_in:?}"
    );

    // What the claim stored is what a later read shows.
    let mut tx = scene.tenant_tx(scene.a).await;
    let stored = tx.get_stage_run(run).await.expect("get");
    assert_eq!(stored.value.lease_epoch, LeaseEpoch::new(1));
    assert_eq!(stored.value.lease.as_ref(), Some(&work.lease));

    // A second claim finds nothing while the lease lasts.
    assert!(scene.claim("worker-2", 10).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_lease_epoch_is_fenced() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;

    // Worker 1 claims with a lease of one second and goes quiet.
    let first = scene.claim_for("worker-1", 1, Duration::from_secs(1)).await;
    let old_epoch = first[0].lease.epoch;
    let (old_attempt, ..) = scene.newest_attempt(run).await;
    tokio::time::sleep(Duration::from_millis(1400)).await;

    // Worker 2 takes the run over. The old attempt is closed and the epoch rises.
    let second = scene
        .claim_for("worker-2", 1, Duration::from_secs(60))
        .await;
    assert_eq!(second.len(), 1, "an expired lease can be claimed again");
    let new_epoch = second[0].lease.epoch;
    assert!(
        new_epoch > old_epoch,
        "the epoch must rise: {old_epoch:?} then {new_epoch:?}"
    );
    let (new_attempt, number, status, _) = scene.newest_attempt(run).await;
    assert_eq!((number, status.as_str()), (2, "STARTING"));
    assert_eq!(
        scene.attempts_of(run).await[0].2,
        "LEASE_LOST",
        "the first attempt was closed by the takeover"
    );

    let mut tx = scene.tenant_tx(scene.a).await;
    // The zombie's heartbeat and status change are refused.
    assert_eq!(
        tx.heartbeat(old_attempt, old_epoch).await,
        Err(StoreError::LeaseFenced),
        "a heartbeat from the worker that lost its lease"
    );
    let ready = AppliedTransition::plan(AttemptStatus::INITIAL, AttemptEvent::SandboxReady, now())
        .expect("A01");
    let version = factory_ports::store::Version::FIRST;
    assert_eq!(
        tx.transition_attempt(old_attempt, version, old_epoch, ready)
            .await,
        Err(StoreError::LeaseFenced),
        "a status change from the worker that lost its lease"
    );
    // A write that carries the old epoch to the new attempt is refused as well. This is the case
    // that an epoch check in the code, and only there, stops.
    assert_eq!(
        tx.transition_attempt(new_attempt, version, old_epoch, ready)
            .await,
        Err(StoreError::LeaseFenced),
        "the old epoch against the new attempt"
    );
    assert_eq!(
        tx.heartbeat(new_attempt, old_epoch).await,
        Err(StoreError::LeaseFenced),
        "the old epoch against the new attempt's heartbeat"
    );
    // The new worker is not affected.
    tx.heartbeat(new_attempt, new_epoch)
        .await
        .expect("the new worker's heartbeat");
    let untouched = tx.get_attempt(new_attempt).await.expect("get");
    assert_eq!(untouched.value.status, AttemptStatus::Starting);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_lse_02() {
    let scene = Arc::new(Scene::new().await);
    let job = scene.job(scene.a).await;

    // 100 rounds. In each, two workers reach the claim of one ready stage run together.
    let mut winners_in_a_row = 0;
    let mut last = None;
    for round in 0..100 {
        let run = scene.ready_stage_run(scene.a, job).await;
        let barrier = Arc::new(Barrier::new(2));
        let mut racers = Vec::new();
        for name in ["worker-a", "worker-b"] {
            let (scene, barrier) = (scene.clone(), barrier.clone());
            racers.push(tokio::spawn(async move {
                barrier.wait().await;
                // A little jitter, so the two interleave differently from round to round.
                tokio::time::sleep(Duration::from_micros(((round * 37) % 500) as u64)).await;
                scene.claim(name, 5).await.len()
            }));
        }
        let mut winners = 0;
        for racer in racers {
            winners += racer.await.expect("racer");
        }
        assert_eq!(winners, 1, "round {round}: exactly one winner");
        let attempts = scene.attempts_of(run).await;
        assert_eq!(
            attempts.len(),
            1,
            "round {round}: one attempt, found {attempts:?}"
        );
        winners_in_a_row += 1;
        last = Some((run, attempts[0].0, attempts[0].3));
    }
    assert_eq!(winners_in_a_row, 100);

    // A renewal by the wrong tenant is refused. It cannot even see the attempt.
    let (_, attempt, epoch) = last.expect("a last round");
    let epoch = LeaseEpoch::new(u64::try_from(epoch).expect("epoch"));
    let mut stranger = scene.tenant_tx(scene.b).await;
    assert_eq!(
        stranger.heartbeat(attempt, epoch).await,
        Err(StoreError::NotFound)
    );
    // A renewal that carries another epoch is refused.
    let mut owner = scene.tenant_tx(scene.a).await;
    assert_eq!(
        owner.heartbeat(attempt, epoch.next()).await,
        Err(StoreError::LeaseFenced)
    );
    assert_eq!(
        owner.heartbeat(attempt, LeaseEpoch::NEVER_CLAIMED).await,
        Err(StoreError::LeaseFenced)
    );
    // The holder's own renewal works.
    owner
        .heartbeat(attempt, epoch)
        .await
        .expect("the holder renews");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_heartbeat_renews_the_lease_by_the_database_clock() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    let claimed = scene.claim_for("worker-1", 1, Duration::from_secs(3)).await;
    let epoch = claimed[0].lease.epoch;
    let first_expiry = claimed[0].lease.expires_at;
    let (attempt, ..) = scene.newest_attempt(run).await;

    tokio::time::sleep(Duration::from_millis(1500)).await;
    let mut tx = scene.tenant_tx(scene.a).await;
    tx.heartbeat(attempt, epoch).await.expect("heartbeat");
    let renewed = tx
        .get_stage_run(run)
        .await
        .expect("get")
        .value
        .lease
        .expect("lease");
    let gain = duration_between(&first_expiry, &renewed.expires_at).expect("later");
    assert!(
        gain >= Duration::from_millis(1400) && gain <= Duration::from_millis(3500),
        "the lease moved to now plus the ttl, about 1.5 seconds after the first expiry: {gain:?}"
    );
    assert_eq!(
        renewed.ttl,
        Duration::from_secs(3),
        "a renewal keeps the ttl"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ended_attempt_cannot_be_heartbeated() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    let claimed = scene.claim("worker-1", 1).await;
    let epoch = claimed[0].lease.epoch;
    let (attempt, ..) = scene.newest_attempt(run).await;
    let mut tx = scene.tenant_tx(scene.a).await;
    let failed =
        AppliedTransition::plan(AttemptStatus::INITIAL, AttemptEvent::ProvisionFailed, now())
            .expect("A02");
    tx.transition_attempt(attempt, factory_ports::store::Version::FIRST, epoch, failed)
        .await
        .expect("end the attempt");
    assert_eq!(
        tx.heartbeat(attempt, epoch).await,
        Err(StoreError::Conflict)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expired_leases_lists_only_attempts_past_their_lease() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let short = scene.ready_stage_run(scene.a, job).await;
    scene.claim_for("worker-1", 1, Duration::from_secs(1)).await;
    let long = scene.ready_stage_run(scene.a, job).await;
    scene
        .claim_for("worker-2", 1, Duration::from_secs(600))
        .await;
    let (short_attempt, ..) = scene.newest_attempt(short).await;
    let (long_attempt, ..) = scene.newest_attempt(long).await;

    let mut system = scene.system_tx().await;
    assert!(
        system.expired_leases(10).await.expect("list").is_empty(),
        "no lease has ended yet"
    );
    drop(system);
    tokio::time::sleep(Duration::from_millis(1400)).await;
    let mut system = scene.system_tx().await;
    let expired = system.expired_leases(10).await.expect("list");
    assert_eq!(
        expired,
        vec![short_attempt],
        "only the short lease has ended"
    );
    assert!(!expired.contains(&long_attempt));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lease_expiry_uses_database_time() {
    let scene = Scene::new().await;
    // The caller's clock is an hour behind the database. Everything the caller stamps is wrong
    // by an hour, and no lease may follow it.
    let skewed = FakeClock::new();
    let mut system = scene.system_tx().await;
    let database_now = system.database_time().await.expect("time");
    drop(system);
    let caller_now = factory_ports::clock::Clock::now(&skewed);
    let skew = duration_between(&caller_now, &database_now);
    assert!(
        skew.is_some_and(|gap| gap > Duration::from_secs(3600)),
        "the fake clock is far behind the database: {skew:?}"
    );

    let job = scene.job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    let claimed = scene.claim_for("worker-1", 1, Duration::from_secs(2)).await;
    let lease = &claimed[0].lease;
    let from_database = duration_between(&database_now, &lease.expires_at).expect("future");
    assert!(
        from_database <= Duration::from_secs(4),
        "the lease ends two seconds after the database time, not after the caller's clock: {from_database:?}"
    );
    let from_caller = duration_between(&caller_now, &lease.expires_at).expect("future");
    assert!(
        from_caller > Duration::from_secs(3600),
        "it is far from the caller's clock: {from_caller:?}"
    );

    // It expires by the database clock, whatever the caller's clock says.
    let (attempt, ..) = scene.newest_attempt(run).await;
    let mut tx = scene.tenant_tx(scene.a).await;
    tx.heartbeat(attempt, lease.epoch)
        .await
        .expect("alive at first");
    drop(tx);
    tokio::time::sleep(Duration::from_millis(2300)).await;
    let mut tx = scene.tenant_tx(scene.a).await;
    assert_eq!(
        tx.heartbeat(attempt, lease.epoch).await,
        Err(StoreError::LeaseFenced),
        "the caller's clock has not moved, and the lease has ended"
    );
    drop(tx);
    let mut system = scene.system_tx().await;
    assert_eq!(system.expired_leases(5).await.expect("list"), vec![attempt]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn claim_does_not_block_ledger_appends() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;

    // A claimer holds the stage run in an open transaction.
    let mut claimer = scene.system_tx().await;
    let claimed = claimer
        .claim_ready(
            &factory_ports::store::WorkerId::new("worker-1").expect("worker"),
            1,
            Duration::from_secs(60),
        )
        .await
        .expect("claim");
    assert_eq!(claimed.len(), 1);

    // A ledger entry for that stage run takes a KEY SHARE lock on it. It must not wait.
    let entry = ledger_entry(
        &scene.ids,
        job,
        run,
        1,
        None,
        &now(),
        "Recorded while a claim is open.",
    );
    let mut writer = scene.tenant_tx(scene.a).await;
    let appended =
        tokio::time::timeout(Duration::from_secs(5), writer.append_ledger_entry(entry)).await;
    assert!(
        matches!(appended, Ok(Ok(_))),
        "a ledger append is not blocked while a claimer holds the stage run: {appended:?}"
    );
    writer.commit().await.expect("commit the append");
    claimer.commit().await.expect("commit the claim");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lock_for_update_would_block_the_ledger_append() {
    // The control for the test above: with the stronger lock the same append waits. It shows that
    // the test above can fail, and why the claim uses FOR NO KEY UPDATE.
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    let mut holder = scene.db.admin().await;
    holder
        .batch_execute(&format!(
            "BEGIN; SELECT 1 FROM stage_runs WHERE id = '{}' FOR UPDATE;",
            run.as_uuid()
        ))
        .await
        .expect("hold the row");
    let entry = ledger_entry(
        &scene.ids,
        job,
        run,
        1,
        None,
        &now(),
        "Waits for the stronger lock.",
    );
    let mut writer = scene.tenant_tx(scene.a).await;
    let waited = tokio::time::timeout(
        Duration::from_millis(1500),
        writer.append_ledger_entry(entry),
    )
    .await;
    assert!(
        waited.is_err(),
        "an append waits for a row held FOR UPDATE: {waited:?}"
    );
    holder.batch_execute("ROLLBACK").await.expect("release");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_stage_runs_of_active_jobs_are_claimed_by_default() {
    let scene = Scene::with(|_| {}).await;
    let job = scene.job(scene.a).await;
    scene.ready_stage_run(scene.a, job).await;
    assert!(
        scene.claim("worker-1", 5).await.is_empty(),
        "a RECEIVED job is not claimed"
    );
    scene.admit(scene.a, job).await;
    assert_eq!(
        scene.claim("worker-1", 5).await.len(),
        1,
        "an ACTIVE job is"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_claim_frees_the_stage_run_for_the_next_begin() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    scene.ready_stage_run(scene.a, job).await;
    let mut tx = scene.system_tx().await;
    let worker = factory_ports::store::WorkerId::new("worker-1").expect("worker");
    assert_eq!(
        tx.claim_ready(&worker, 5, Duration::from_secs(60))
            .await
            .expect("claim")
            .len(),
        1
    );
    drop(tx);
    // The rollback of the dropped transaction has finished by the time the next one begins.
    assert_eq!(scene.claim("worker-2", 5).await.len(), 1);
}
