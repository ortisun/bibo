//! The claim protocol of ports v1.1 on a real PostgreSQL server: a read-only search in the system
//! scope, a start in the tenant scope, the lease on the attempt, the epoch that moves only when a
//! run goes from `READY` to `RUNNING`, and the lock modes that keep the ledger, audit and outbox
//! free while a start is open.
//!
//! The shared contract suite (`store_contract.rs`) runs the port's rules. This file adds what only
//! a database can show: eight real tasks racing for one candidate, two finders with open
//! transactions, the exact lock mode, and the database refusing a second live attempt by itself.

mod support;

use std::sync::Arc;
use std::time::Duration;

use diesel_async::SimpleAsyncConnection;
use factory_domain::state::{AttemptStatus, Guard, StageRunStatus};
use factory_domain::values::Slug;
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, ConstraintRule, Fence, NewAuditEvent, StoreError,
    WorkerId,
};
use factory_testkit::fixtures::cleared;
use support::{Scene, at, start_in};
use tokio::sync::Barrier;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claim_sets_the_lease_on_the_attempt_and_raises_the_epoch_once() {
    let scene = Scene::new().await;
    let job = scene.active_job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;

    let mut sys = scene.system().await;
    let found = sys.find_claim_candidates(10).await.expect("find");
    sys.finish().await.expect("finish");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].stage_run, run);

    let started = scene.start(scene.a, run, "worker-1").await.expect("start");
    assert_eq!(started.stage_run.value.status, StageRunStatus::Running);
    assert_eq!(started.stage_run.value.lease_epoch.get(), 1);
    assert_eq!(started.attempt.value.status, AttemptStatus::Starting);
    assert_eq!(started.attempt.value.epoch.get(), 1);
    assert_eq!(started.attempt.value.number, 1);
    assert_eq!(started.attempt.value.worker.as_str(), "worker-1");
    // The lease is on the attempt, taken from the database clock.
    let window = started
        .attempt
        .value
        .lease_expires_at
        .duration_since(&started.attempt.value.created_at)
        .expect("the lease ends after the attempt began");
    assert!(
        window >= Duration::from_secs(59) && window <= Duration::from_secs(61),
        "the lease lasts the 60 seconds asked for, not the caller's clock: {window:?}"
    );

    // The epoch moves with READY to RUNNING and with nothing else: a retry keeps it until the next
    // start.
    scene
        .fail_and_retry(scene.a, &started, Duration::ZERO)
        .await;
    assert_eq!(
        scene
            .db
            .number(&format!(
                "SELECT lease_epoch FROM stage_runs WHERE id = '{}'",
                run.as_uuid()
            ))
            .await,
        1,
        "ending the attempt and retrying does not raise the epoch"
    );
    let second = scene
        .start(scene.a, run, "worker-2")
        .await
        .expect("restart");
    assert_eq!(second.stage_run.value.lease_epoch.get(), 2);
    assert_eq!(second.attempt.value.number, 2);
    assert_eq!(second.attempt.value.epoch.get(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eight_workers_claim_one_stage_run_and_one_wins() {
    let scene = Arc::new(Scene::new().await);
    let job = scene.active_job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;

    let mut sys = scene.system().await;
    let candidate = sys
        .find_claim_candidates(1)
        .await
        .expect("find")
        .pop()
        .expect("a candidate");
    sys.finish().await.expect("finish");

    // Every worker holds the same candidate and starts it at the same moment.
    let barrier = Arc::new(Barrier::new(8));
    let mut tasks = Vec::new();
    for number in 0..8 {
        let (scene, barrier) = (scene.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            let mut tx = scene.tx(scene.a).await;
            barrier.wait().await;
            let outcome = start_in(
                &mut *tx,
                candidate.stage_run,
                candidate.version,
                &format!("worker-{number}"),
            )
            .await;
            match outcome {
                Ok(started) => {
                    tx.commit().await.expect("the winner commits");
                    Some(started)
                }
                Err(error) => {
                    assert_eq!(error, StoreError::Conflict, "every loser is told it lost");
                    None
                }
            }
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.expect("the task does not panic").is_some() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1, "exactly one worker wins");
    let attempts = scene.attempts_of(run).await;
    assert_eq!(attempts.len(), 1, "one attempt exists");
    assert_eq!(attempts[0].3, 1, "at epoch one");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_finders_with_open_transactions_do_not_take_the_same_row() {
    let scene = Scene::new().await;
    let job = scene.active_job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;

    let mut first = scene.system().await;
    let mut second = scene.system().await;
    let mine = first.find_claim_candidates(1).await.expect("find");
    assert_eq!(mine.len(), 1);
    // The row is locked `FOR NO KEY UPDATE SKIP LOCKED`: the second finder skips it.
    let theirs = second.find_claim_candidates(1).await.expect("find");
    assert!(theirs.is_empty(), "the second finder skips the locked row");
    first.finish().await.expect("finish");
    // The lock lasted to the end of the first transaction.
    let again = second.find_claim_candidates(1).await.expect("find");
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].stage_run, run);
    second.finish().await.expect("finish");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_live_attempt_is_refused() {
    let scene = Scene::new().await;
    let job = scene.active_job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    scene.start(scene.a, run, "worker-1").await.expect("start");

    // A fault the engine must not have, made by an operator with the triggers off: the run is
    // READY again while its attempt is still live. The commit rule would refuse this state, so it
    // is made directly and not through the port.
    scene
        .db
        .run(&format!(
            "BEGIN; SET LOCAL session_replication_role = replica; \
             UPDATE stage_runs SET status = 'READY' WHERE id = '{}'; COMMIT;",
            run.as_uuid()
        ))
        .await;
    let result = scene.start(scene.a, run, "worker-2").await;
    assert_eq!(
        result.map(|_| ()),
        Err(StoreError::Constraint(ConstraintRule::OneLiveAttempt))
    );

    // The database refuses it too, with no help from the code: the unique index of one live
    // attempt per stage run.
    let mut admin = scene.db.admin().await;
    let attempt = scene.attempts_of(run).await[0].0;
    let refused = admin
        .batch_execute(&format!(
            "INSERT INTO attempts (tenant_id, id, job_id, stage_run_id, attempt_number, lease_owner, \
                    lease_epoch, lease_expires_at, deadline_at) \
             SELECT tenant_id, '{}', job_id, stage_run_id, 2, 'worker-3', lease_epoch, \
                    now() + interval '1 minute', now() + interval '1 hour' \
               FROM attempts WHERE id = '{attempt}'",
            uuid::Uuid::from_u128(77)
        ))
        .await
        .expect_err("a second live attempt");
    assert!(
        refused
            .to_string()
            .contains("attempts_one_active_per_stage_run")
            || refused.to_string().contains("duplicate key"),
        "the unique index answers: {refused}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_epoch_is_fenced_at_the_statement_and_changes_nothing() {
    let scene = Scene::new().await;
    let job = scene.active_job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    let first = scene.start(scene.a, run, "worker-1").await.expect("start");
    scene.fail_and_retry(scene.a, &first, Duration::ZERO).await;
    let second = scene
        .start(scene.a, run, "worker-2")
        .await
        .expect("restart");

    let mut tx = scene.tx(scene.a).await;
    // The zombie holds the old attempt and the old epoch.
    let zombie = Fence {
        attempt: first.attempt.value.id,
        epoch: first.attempt.value.epoch,
        worker: WorkerId::new("worker-1").expect("name"),
    };
    let beat = tx.heartbeat(zombie, Duration::from_secs(60)).await;
    assert!(
        matches!(beat, Err(StoreError::LeaseFenced | StoreError::Conflict)),
        "the zombie's heartbeat is refused: {beat:?}"
    );
    // The zombie's epoch against the live attempt is fenced, not conflicted.
    let stale = Fence {
        attempt: second.attempt.value.id,
        epoch: first.attempt.value.epoch,
        worker: WorkerId::new("worker-2").expect("name"),
    };
    assert_eq!(
        tx.heartbeat(stale, Duration::from_secs(60)).await,
        Err(StoreError::LeaseFenced)
    );
    // A transition under the old epoch changes nothing.
    let current = tx.get_attempt(second.attempt.value.id).await.expect("read");
    let ready = factory_ports::store::AppliedTransition::plan(
        AttemptStatus::Starting,
        factory_domain::state::AttemptEvent::SandboxReady,
        at(),
        cleared(Guard::SandboxProvisioned),
    )
    .expect("A01");
    assert_eq!(
        tx.transition_attempt(
            current.value.id,
            current.version,
            first.attempt.value.epoch,
            ready,
            factory_ports::store::AttemptEnd::default()
        )
        .await,
        Err(StoreError::LeaseFenced)
    );
    let unchanged = tx.get_attempt(second.attempt.value.id).await.expect("read");
    assert_eq!(unchanged, current, "the attempt is as it was");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_heartbeat_renews_the_lease_by_the_database_clock() {
    let scene = Scene::new().await;
    let job = scene.active_job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    let started = scene.start(scene.a, run, "worker-1").await.expect("start");
    let mut tx = scene.tx(scene.a).await;
    let fence = Fence {
        attempt: started.attempt.value.id,
        epoch: started.attempt.value.epoch,
        worker: WorkerId::new("worker-1").expect("name"),
    };
    let renewal = tx
        .heartbeat(fence, Duration::from_secs(300))
        .await
        .expect("renew");
    let now = tx.database_time().await.expect("time");
    let ahead = renewal
        .lease_expires_at
        .duration_since(&now)
        .expect("the lease ends in the future");
    assert!(
        ahead >= Duration::from_secs(295) && ahead <= Duration::from_secs(301),
        "the lease ends 300 seconds after the database time: {ahead:?}"
    );
}

/// A `start_attempt` that is open holds the job `FOR SHARE` and the stage run `FOR NO KEY UPDATE`.
/// Neither stops an audit record (a `KEY SHARE` on both rows) from being written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_open_start_does_not_block_an_audit_insert() {
    let scene = Scene::new().await;
    let job = scene.active_job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;

    let mut start = scene.tx(scene.a).await;
    let version = start.get_stage_run(run).await.expect("read").version;
    start_in(&mut *start, run, version, "worker-1")
        .await
        .expect("start, not committed");

    let mut audit = scene.tx(scene.a).await;
    let event = NewAuditEvent {
        id: factory_domain::ids::AuditEventId::from_uuid(uuid::Uuid::from_u128(901)),
        actor: AuditActor::System(Slug::parse("workflow-engine").expect("slug")),
        action: AuditAction::new("stage_run.started").expect("action"),
        subject: "a stage run".to_owned(),
        decision: AuditDecision::Record,
        reason: "The start is open and holds its locks.".to_owned(),
        policy_hash: factory_domain::values::Sha256Digest::of(b"policy"),
        job: Some(job),
        stage_run: Some(run),
        correlation_id: scene.ids.correlation(),
    };
    tokio::time::timeout(Duration::from_secs(3), audit.record_audit(event))
        .await
        .expect("the audit insert is not blocked by the open start")
        .expect("recorded");
    audit.commit().await.expect("commit the audit");
    start.commit().await.expect("commit the start");
}

/// The negative control of the test above: `FOR UPDATE` on the stage run does block an audit
/// insert, which is why every lock in this crate is `FOR NO KEY UPDATE`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lock_for_update_would_block_the_audit_insert() {
    let scene = Scene::new().await;
    let job = scene.active_job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;

    let mut holder = scene.db.admin().await;
    holder
        .batch_execute(&format!(
            "BEGIN; SELECT 1 FROM stage_runs WHERE id = '{}' FOR UPDATE;",
            run.as_uuid()
        ))
        .await
        .expect("hold the lock");

    let mut audit = scene.tx(scene.a).await;
    let event = NewAuditEvent {
        id: factory_domain::ids::AuditEventId::from_uuid(uuid::Uuid::from_u128(902)),
        actor: AuditActor::System(Slug::parse("workflow-engine").expect("slug")),
        action: AuditAction::new("stage_run.started").expect("action"),
        subject: "a stage run".to_owned(),
        decision: AuditDecision::Record,
        reason: "A stronger lock is held on the row this record points at.".to_owned(),
        policy_hash: factory_domain::values::Sha256Digest::of(b"policy"),
        job: Some(job),
        stage_run: Some(run),
        correlation_id: scene.ids.correlation(),
    };
    let blocked = tokio::time::timeout(Duration::from_millis(700), audit.record_audit(event)).await;
    assert!(
        blocked.is_err(),
        "an audit insert waits for a FOR UPDATE lock on the stage run it points at"
    );
    drop(audit);
    holder.batch_execute("ROLLBACK").await.expect("release");
}
