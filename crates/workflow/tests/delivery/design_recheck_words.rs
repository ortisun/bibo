//! The approval does not cover words edited after it, and the re-check before the pull request
//! asks the same question as intake (DR-1 of the review of the design gate round two, with DG-8).
//!
//! The approver applied `design: approved` at 09:00. The author edits the body, or the title, after
//! that, while the job runs. The label is still on the issue and the approver is still an approver,
//! and the pull request is not opened. Each refusal has a sibling that passes: the same issue with
//! the one thing changed. Nothing here ran against the real GitHub.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::values::Timestamp;
use factory_ports::githost::{IssueRef, TextEdit};
use factory_workflow::gates::framework::Resolution;
use factory_workflow::handlers::StageError;

use crate::design_fakes::{APPROVED, APPROVER_ID, person};
use crate::spy::Call;
use crate::world::World;

/// The issue the job is for, as the world shows it.
fn the_issue(world: &World) -> IssueRef {
    world.sources.target.lock().expect("lock").issue.clone()
}

fn at(text: &str) -> Timestamp {
    Timestamp::parse(text).expect("a time")
}

/// Everything up to `execute`, so that a test sees its result and not a panic.
async fn execute_only(world: &World) -> Result<(), StageError> {
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

fn nothing_was_opened(world: &World) {
    let calls = world.host.calls();
    assert!(
        calls
            .iter()
            .all(|call| matches!(call, Call::ResolveBranch(_))),
        "only a read reached the host: {calls:?}"
    );
    assert!(world.host.opened().is_empty());
    assert!(world.host.checks().is_empty());
}

/// The decision record of a stop, and the comment, for a reason of the closed set.
fn stopped_because(world: &World, reason: &str) {
    let noted = world.noted.lock().expect("lock").clone();
    assert_eq!(noted.len(), 2, "the decision and the reply: {noted:?}");
    assert!(
        noted[0].contains(&format!("reason {reason}")),
        "{}",
        noted[0]
    );
    assert!(noted[0].contains("reply to_follow"), "{}", noted[0]);
    let comments = world.design.replies.texts();
    assert_eq!(comments.len(), 1, "{comments:?}");
    assert!(
        comments[0].starts_with("The factory stopped before it opened the pull request"),
        "{}",
        comments[0]
    );
    assert!(comments[0].contains("No pull request was opened."));
    assert!(comments[0].contains("edited after"), "{}", comments[0]);
}

#[tokio::test]
async fn the_recheck_reads_the_issue_with_the_narrow_intake_scope() {
    // DR-10. The judge only reads, so it reads with the class of the intake stage (`issues: read`
    // and `metadata: read`) and not with the delivery token, which can write.
    let world = World::new();
    world.issue_with_an_approved_design().await;
    let ran = world.run().await;
    assert_eq!(ran.resolution, Resolution::Pass);
    let stages = world.design.issues.read_as();
    assert!(!stages.is_empty(), "the issue was read");
    assert!(
        stages
            .iter()
            .all(|stage| *stage == factory_domain::vocabulary::StageKind::Intake),
        "{stages:?}"
    );
}

#[tokio::test]
async fn an_edit_after_the_approval_stops_the_pull_request_with_its_own_reason() {
    // The label at 09:00, the edit at 09:30.
    let world = World::new();
    world.issue_with_an_approved_design().await;
    world
        .design
        .issues
        .fake()
        .seed_text_edit(&the_issue(&world), TextEdit::At(at("2026-10-28T09:30:00Z")));
    let result = execute_only(&world).await;
    assert_eq!(
        result,
        Err(StageError::Blocked(BlockedCode::DesignNotApproved))
    );
    nothing_was_opened(&world);
    stopped_because(&world, "approval_older_than_text");
}

#[tokio::test]
async fn an_edit_in_the_same_second_as_the_approval_stops_the_pull_request() {
    let world = World::new();
    world.issue_with_an_approved_design().await;
    world
        .design
        .issues
        .fake()
        .seed_text_edit(&the_issue(&world), TextEdit::At(at("2026-10-28T09:00:00Z")));
    let result = execute_only(&world).await;
    assert_eq!(
        result,
        Err(StageError::Blocked(BlockedCode::DesignNotApproved))
    );
    nothing_was_opened(&world);
    stopped_because(&world, "approval_older_than_text");
}

#[tokio::test]
async fn an_edit_before_the_approval_lets_the_pull_request_open() {
    // The sibling: the same edit, half an hour before the label.
    let world = World::new();
    world.issue_with_an_approved_design().await;
    world
        .design
        .issues
        .fake()
        .seed_text_edit(&the_issue(&world), TextEdit::At(at("2026-10-28T08:30:00Z")));
    let ran = world.run().await;
    assert_eq!(ran.problem, None);
    assert_eq!(ran.resolution, Resolution::Pass);
    assert_eq!(world.host.opened().len(), 1);
    let noted = world.noted.lock().expect("lock").clone();
    assert!(noted[0].contains("design gate passed"), "{noted:?}");
    assert!(
        noted[0].contains("after the last edit of the title and the body"),
        "{noted:?}"
    );
}

#[tokio::test]
async fn an_edit_time_the_source_cannot_say_stops_the_pull_request() {
    // Fail closed: a source that cannot say when the words were last edited does not cover them.
    let world = World::new();
    world.issue_with_an_approved_design().await;
    world
        .design
        .issues
        .fake()
        .seed_text_edit(&the_issue(&world), TextEdit::Unknown);
    let result = execute_only(&world).await;
    assert_eq!(
        result,
        Err(StageError::Blocked(BlockedCode::DesignNotApproved))
    );
    nothing_was_opened(&world);
    let noted = world.noted.lock().expect("lock").clone();
    assert!(
        noted[0].contains("reason edit_time_unreadable"),
        "{noted:?}"
    );
}

#[tokio::test]
async fn a_host_that_cannot_answer_the_edit_time_opens_nothing_and_fails_the_attempt() {
    let world = World::new();
    world.issue_with_an_approved_design().await;
    world.design.issues.fake().make_the_edit_read_fail(true);
    let result = execute_only(&world).await;
    assert_eq!(result, Err(StageError::Tool));
    nothing_was_opened(&world);
}

#[tokio::test]
async fn the_label_applied_again_after_the_edit_lets_the_pull_request_open() {
    // The way through: the edit stopped the stage, the approver reads the issue and applies the
    // label again at 10:30, and the next attempt of the same stage run opens the pull request.
    let world = World::new();
    world.issue_with_an_approved_design().await;
    world
        .design
        .issues
        .fake()
        .seed_text_edit(&the_issue(&world), TextEdit::At(at("2026-10-28T09:30:00Z")));
    let (base, head) = world.commits().await;
    let handler = world.handler();
    let upstream = world.upstream(&base, &head).await;
    let contract = world
        .resolve_contract(&handler, &upstream)
        .expect("the contract resolves");
    let stopped = world.execute(&handler, &contract, &upstream).await;
    assert_eq!(
        stopped.err(),
        Some(StageError::Blocked(BlockedCode::DesignNotApproved))
    );
    nothing_was_opened(&world);
    world.design.issues.fake().seed_label_at(
        &the_issue(&world),
        APPROVED,
        &person(APPROVER_ID, "approver-one"),
        at("2026-10-28T10:30:00Z"),
    );
    world
        .execute(&handler, &contract, &upstream)
        .await
        .expect("the label was applied after the edit, so the pull request opens");
    assert_eq!(world.host.opened().len(), 1);
}
