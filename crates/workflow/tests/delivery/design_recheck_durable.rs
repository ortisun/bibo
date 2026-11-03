//! The record of the re-check that stops the pull request is written at once, before the reply is
//! asked for (DR-3 of the review of the design gate round two, with DG-9 part d).
//!
//! The context of these tests has no engine, so the writer of the engine is replaced by a double that
//! keeps the records in the order the stage writes them (`Durable`); the engine's own writer is
//! tested with the real engine in `intake_repo/durable_record.rs`. What is checked here is that the
//! re-check goes through it, and in the right order.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::machines::guards::EnvironmentCause;
use factory_workflow::handlers::StageError;

use crate::design_fakes::{APPROVED, APPROVER_ID, LABEL, person};
use crate::world::World;

async fn run(world: &World) -> Result<(), StageError> {
    let (base, head) = world.commits().await;
    let handler = world.handler();
    let upstream = world.upstream(&base, &head).await;
    let contract = world
        .resolve_contract(&handler, &upstream)
        .expect("the contract resolves");
    world
        .execute(&handler, &contract, &upstream)
        .await
        .map(|_| ())
}

#[tokio::test]
async fn the_decision_of_a_re_check_that_stops_is_written_at_once_and_before_the_reply() {
    let world = World::new();
    world.issue_shows(&[LABEL, "design: in progress"]);
    world
        .label_applied_by(APPROVED, &person(APPROVER_ID, "approver-one"))
        .await;
    assert_eq!(
        run(&world).await,
        Err(StageError::Blocked(BlockedCode::DesignNotApproved))
    );
    // The decision, with the reply still to follow, was written at once; what became of the reply
    // was only noted for the end of the attempt.
    let written = world.durable.records();
    assert_eq!(written.len(), 1, "{written:?}");
    assert!(written[0].contains("design gate refused"), "{written:?}");
    assert!(written[0].contains("reply to_follow"), "{written:?}");
    let noted = world.noted_at_the_end.lock().expect("lock").clone();
    assert_eq!(noted.len(), 1, "{noted:?}");
    assert!(noted[0].contains("reply for issue"), "{noted:?}");
    // And it was already in the store when the reply was asked for.
    let at_post = world.design.replies.durable_at_post();
    assert_eq!(at_post.len(), 1, "{at_post:?}");
    assert_eq!(at_post[0], written);
}

#[tokio::test]
async fn the_decision_of_a_re_check_that_cannot_judge_is_written_at_once_and_before_the_reply() {
    let world = World::new();
    world.design.rule.break_it();
    assert_eq!(
        run(&world).await,
        Err(StageError::Environment(EnvironmentCause::PolicyUnloadable))
    );
    let written = world.durable.records();
    assert_eq!(written.len(), 1, "{written:?}");
    assert!(written[0].contains("degraded"), "{written:?}");
    assert!(written[0].contains("reply to_follow"), "{written:?}");
    let at_post = world.design.replies.durable_at_post();
    assert_eq!(at_post.len(), 1, "{at_post:?}");
    assert_eq!(at_post[0], written);
}

#[tokio::test]
async fn a_re_check_that_passes_writes_nothing_at_once() {
    // The sibling: nothing is going to be said on the issue, so nothing has to be in the store
    // ahead of it. The pass is noted with the attempt, as before.
    let world = World::new();
    world.issue_with_an_approved_design().await;
    let result = run(&world).await;
    assert_eq!(result, Ok(()));
    assert!(world.durable.records().is_empty());
    assert!(world.design.replies.durable_at_post().is_empty());
    let noted = world.noted_at_the_end.lock().expect("lock").clone();
    assert_eq!(noted.len(), 1, "{noted:?}");
    assert!(noted[0].contains("design gate passed"), "{noted:?}");
}
