//! The record of a refusal is in the store before the reply is tried (DR-3 of the review of the
//! design gate round two, with DG-9 part d).
//!
//! The stage used to note the record in memory, and the engine wrote the notes when the attempt
//! ended. An attempt that was cancelled, that lost its lease or whose process was killed never got
//! there, and the comment on the issue stayed with no record of the refusal. Now the record is
//! written through `StageContext::record_now`, in a transaction of its own, before the reply is
//! asked for. Each test here holds the reply in flight, does what ends an attempt without its notes,
//! and looks at the store.

use factory_domain::ids::JobId;
use factory_domain::state::JobStatus;
use factory_domain::vocabulary::HumanRole;
use factory_workflow::commands::JobCommand;
use factory_workflow::engine::AttemptOutcome;

use crate::harness::{LABEL, Options, ReplyMode, Rig, USUAL_REQUEST};

async fn rig() -> Rig {
    Rig::new().await
}

/// A job on a design-track issue that is not approved, so that intake refuses it and replies.
async fn refused_job(rig: &Rig) -> JobId {
    rig.host_shows_labels(&[LABEL, "design: proposed"]);
    rig.job(USUAL_REQUEST).await
}

/// The reasons of the audit records the store holds for the job now.
async fn held(rig: &Rig, job: JobId) -> Vec<String> {
    rig.world
        .audit(job)
        .await
        .into_iter()
        .map(|record| record.event.reason)
        .collect()
}

fn has_the_decision_with_the_reply_to_follow(reasons: &[String]) -> bool {
    reasons.iter().any(|reason| {
        reason.starts_with("design gate refused (DESIGN_NOT_APPROVED)")
            && reason.contains("reply to_follow")
    })
}

#[tokio::test]
async fn the_decision_record_is_in_the_store_when_the_reply_is_asked_for() {
    let rig = rig().await;
    let job = refused_job(&rig).await;
    rig.replies
        .look_in_the_store(rig.world.store.clone(), rig.world.tenant, job);
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    let seen = rig.replies.store_held_at_post();
    assert_eq!(seen.len(), 1, "the reply was asked for once: {seen:?}");
    assert!(
        has_the_decision_with_the_reply_to_follow(&seen[0]),
        "the store held, when the reply was asked for: {:?}",
        seen[0]
    );
    // The record of what became of the reply came after, with the attempt.
    let after = held(&rig, job).await;
    assert!(
        after
            .iter()
            .any(|reason| reason.starts_with("design gate reply for issue")
                && reason.ends_with("posted")),
        "{after:?}"
    );
}

#[tokio::test]
async fn a_cancel_while_the_reply_is_in_flight_leaves_the_decision_record() {
    let rig = rig().await;
    let job = refused_job(&rig).await;
    rig.replies.set(ReplyMode::InFlight);
    rig.world.advance(400);
    let claimed = rig
        .engine
        .claim_next(&crate::support::world::World::worker("worker-1"))
        .await
        .expect("claim")
        .started
        .remove(0);
    let operator = rig.world.person("operator-1", &[HumanRole::Operator]).await;
    let work = async { rig.engine.run_attempt(&claimed).await };
    let driver = async {
        rig.replies.entered.notified().await;
        rig.engine
            .control(&rig.world.actor(operator), job, JobCommand::Cancel)
            .await
            .expect("cancels");
        // The next heartbeat tells the worker to stop. The reply in flight does not listen, so the
        // worker is given the time to tear down (30 seconds), and then the attempt is dropped
        // where it stands.
        rig.world.tick(16).await;
        rig.world.tick(31).await;
    };
    let (outcome, ()) = tokio::join!(work, driver);
    assert_eq!(outcome.expect("runs"), AttemptOutcome::Cancelled);
    assert_eq!(rig.world.view(job).await.status, JobStatus::Cancelled);
    assert!(rig.replies.posted().is_empty(), "the reply never ended");
    // The attempt ended without committing its notes, and the decision is on the record anyway.
    let reasons = held(&rig, job).await;
    assert!(
        has_the_decision_with_the_reply_to_follow(&reasons),
        "{reasons:?}"
    );
}

#[tokio::test]
async fn a_crash_while_the_reply_is_in_flight_leaves_the_decision_record() {
    // The process is killed: the future of the attempt is dropped where it stands.
    let rig = rig().await;
    let job = refused_job(&rig).await;
    rig.replies.set(ReplyMode::InFlight);
    rig.world.advance(400);
    let claimed = rig
        .engine
        .claim_next(&crate::support::world::World::worker("worker-1"))
        .await
        .expect("claim")
        .started
        .remove(0);
    tokio::select! {
        _ = rig.engine.run_attempt(&claimed) => panic!("the reply is held in flight, so the attempt cannot end"),
        () = rig.replies.entered.notified() => {}
    }
    let reasons = held(&rig, job).await;
    assert!(
        has_the_decision_with_the_reply_to_follow(&reasons),
        "{reasons:?}"
    );
    assert!(rig.replies.posted().is_empty());
}

#[tokio::test]
async fn a_lease_lost_while_the_reply_is_in_flight_leaves_the_decision_record() {
    let rig = rig().await;
    let job = refused_job(&rig).await;
    rig.replies.set(ReplyMode::InFlight);
    rig.world.advance(400);
    let claimed = rig
        .engine
        .claim_next(&crate::support::world::World::worker("worker-a"))
        .await
        .expect("claim")
        .started
        .remove(0);
    let stale = async { rig.engine.run_attempt(&claimed).await };
    let takeover = async {
        rig.replies.entered.notified().await;
        // The lease runs out while the first worker is busy, and the sweeper ends its attempt.
        rig.world.advance_time(61).await;
        rig.engine.sweep().await.expect("sweep");
        rig.world.advance_time(5).await;
        rig.replies.release.notify_one();
    };
    let (outcome, ()) = tokio::join!(stale, takeover);
    assert_eq!(
        outcome.expect("the attempt runs"),
        AttemptOutcome::LeaseLost
    );
    let reasons = held(&rig, job).await;
    assert!(
        has_the_decision_with_the_reply_to_follow(&reasons),
        "{reasons:?}"
    );
}

#[tokio::test]
async fn the_record_that_a_notice_is_to_follow_is_in_the_store_before_the_environment_notice() {
    // LB-02: the notice about the environment is a reply too, and gets the same order.
    let rig = Rig::build(Options {
        sandbox_missing: true,
        ..Options::default()
    })
    .await;
    rig.host_shows_labels(&[LABEL]);
    let job = rig.job(USUAL_REQUEST).await;
    rig.replies
        .look_in_the_store(rig.world.store.clone(), rig.world.tenant, job);
    let (_, outcome) = rig.run_next().await;
    assert!(
        matches!(outcome, AttemptOutcome::Failed { .. }),
        "{outcome:?}"
    );
    let seen = rig.replies.store_held_at_post();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(
        seen[0].iter().any(|reason| reason.starts_with(
            "intake environment block: reply for issue example-org/fixture#12: to_follow"
        )),
        "{:?}",
        seen[0]
    );
}
