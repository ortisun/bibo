//! The design is checked again right before the pull request is opened (DG-8, decided by the
//! product owner on 2026-11-02).
//!
//! Intake judged the issue when the job started. These tests change the issue after that, as an
//! approver or anybody with triage rights can while a job runs, and show that the delivery stage
//! asks again with the same judging code and opens nothing when the answer is no. Each refusal has
//! a sibling that passes: the same issue with the one thing put back.
//!
//! The code host is a fake that can be made unreachable (`design_fakes`), because the fake of the
//! testkit never fails a read. Nothing here ran against the real GitHub.

use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::machines::guards::EnvironmentCause;
use factory_workflow::gates::framework::Resolution;
use factory_workflow::handlers::StageError;

use crate::design_fakes::{APPROVED, APPROVER_ID, LABEL, REQUESTER_ID, person};
use crate::spy::Call;
use crate::world::{World, canary};

/// Everything up to `execute`, so that a test sees its result and not a panic.
async fn execute_only(world: &World) -> Result<Vec<String>, StageError> {
    let (base, head) = world.commits().await;
    let handler = world.handler();
    let upstream = world.upstream(&base, &head).await;
    let contract = world
        .resolve_contract(&handler, &upstream)
        .expect("the contract resolves");
    world
        .execute(&handler, &contract, &upstream)
        .await
        .map(|outputs| outputs.iter().map(|o| o.name.as_str().to_owned()).collect())
}

/// Nothing was pushed, no pull request was opened and no check was published: only reads reached
/// the host.
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

/// The one audit record the re-check wrote, as its reason reads. A re-check that passes, and one
/// that cannot read the issue, write one record and no reply.
fn recorded(world: &World) -> String {
    let noted = world.noted.lock().expect("lock").clone();
    assert_eq!(noted.len(), 1, "one record: {noted:?}");
    noted[0].clone()
}

/// The two records of a re-check that stops: the decision, written before the reply is tried, and
/// what became of the reply (DG-9).
fn recorded_pair(world: &World) -> (String, String) {
    let noted = world.noted.lock().expect("lock").clone();
    assert_eq!(noted.len(), 2, "the decision and the reply: {noted:?}");
    (noted[0].clone(), noted[1].clone())
}

/// The stage is blocked with the block code of a design that is not approved, nothing was opened,
/// and the person is told once. Returns the reason of the record.
async fn assert_stopped(world: &World) -> String {
    let result = execute_only(world).await;
    assert_eq!(
        result,
        Err(StageError::Blocked(BlockedCode::DesignNotApproved))
    );
    nothing_was_opened(world);
    let comments = world.design.replies.texts();
    assert_eq!(comments.len(), 1, "{comments:?}");
    assert!(
        comments[0].starts_with("The factory stopped before it opened the pull request"),
        "{}",
        comments[0]
    );
    assert!(comments[0].contains("No pull request was opened."));
    assert!(comments[0].contains("`design: approved`"));
    assert!(
        world.design.replies.keys()[0].starts_with("design-recheck-"),
        "{:?}",
        world.design.replies.keys()
    );
    let (reason, reply) = recorded_pair(world);
    assert!(
        reason.starts_with("design re-check before the pull request is opened: design gate refused (DESIGN_NOT_APPROVED)"),
        "{reason}"
    );
    // The decision comes first and says the reply is still to follow; the reply has its own record.
    assert!(reason.contains("reply to_follow"), "{reason}");
    assert!(
        reply.starts_with("design re-check before the pull request is opened: reply for issue example-org/word-count#12: posted"),
        "{reply}"
    );
    reason
}

// ---- a re-check that passes ----------------------------------------------------------------------

#[tokio::test]
async fn a_design_that_is_still_approved_lets_the_pull_request_open_and_the_record_says_so() {
    let world = World::new();
    world.issue_with_an_approved_design().await;
    let ran = world.run().await;
    assert_eq!(ran.problem, None);
    assert_eq!(ran.resolution, Resolution::Pass);
    assert_eq!(
        world.host.opened().len(),
        1,
        "the draft pull request was opened"
    );
    let reason = recorded(&world);
    assert!(
        reason.starts_with(
            "design re-check before the pull request is opened: design gate passed: issue example-org/word-count#12"
        ),
        "{reason}"
    );
    assert!(
        reason.contains("applied by user id 2002"),
        "the approver is named: {reason}"
    );
    assert!(world.design.replies.texts().is_empty(), "nobody is told");
    assert!(world.design.issues.reads() >= 2, "the issue was read again");
}

#[tokio::test]
async fn an_issue_off_the_design_track_passes_the_recheck_and_the_record_says_so() {
    let world = World::new();
    let ran = world.run().await;
    assert_eq!(ran.resolution, Resolution::Pass);
    assert_eq!(world.host.opened().len(), 1);
    let reason = recorded(&world);
    assert!(reason.contains("carries no design label"), "{reason}");
}

// ---- the approval was withdrawn after intake --------------------------------------------------------

#[tokio::test]
async fn an_approval_taken_back_after_intake_opens_no_pull_request() {
    let world = World::new();
    // At intake the design was approved. The approver reopened it: the approved label came off and
    // the design is in progress again.
    world.issue_shows(&[LABEL, "design: in progress"]);
    world
        .label_applied_by(APPROVED, &person(APPROVER_ID, "approver-one"))
        .await;
    let reason = assert_stopped(&world).await;
    assert!(reason.contains("reason not_approved"), "{reason}");
    assert!(reason.contains("text of the job compared with the live issue: not_compared"));
}

#[tokio::test]
async fn an_approval_label_taken_off_with_no_other_design_label_does_not_leave_the_track() {
    let world = World::new();
    // The label that had been applied is gone and nothing replaced it. The issue looks like a
    // small change, but it once carried a design label, so it is still on the track.
    world.issue_shows(&[LABEL]);
    world
        .label_applied_by(APPROVED, &person(APPROVER_ID, "approver-one"))
        .await;
    let reason = assert_stopped(&world).await;
    assert!(reason.contains("reason design_dropped"), "{reason}");
}

#[tokio::test]
async fn the_same_issue_with_the_approval_put_back_opens_the_pull_request() {
    // The way through, in one attempt after the other: the stage stops, the approver applies the
    // label again, and the next attempt of the same stage run opens the pull request.
    let world = World::new();
    world.issue_shows(&[LABEL, "design: in progress"]);
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

    world.issue_with_an_approved_design().await;
    world
        .execute(&handler, &contract, &upstream)
        .await
        .expect("the approval is back, so the pull request opens");
    assert_eq!(world.host.opened().len(), 1);
}

// ---- a second design label added after intake -------------------------------------------------------

#[tokio::test]
async fn a_second_design_label_added_after_intake_opens_no_pull_request() {
    let world = World::new();
    world.issue_shows(&[LABEL, APPROVED, "design: in progress"]);
    world
        .label_applied_by(APPROVED, &person(APPROVER_ID, "approver-one"))
        .await;
    let reason = assert_stopped(&world).await;
    assert!(
        reason.contains("reason more_than_one_design_label"),
        "{reason}"
    );
}

// ---- who applied the approval, now ----------------------------------------------------------------------

#[tokio::test]
async fn an_approval_applied_again_by_somebody_who_is_not_an_approver_opens_no_pull_request() {
    let world = World::new();
    world.issue_shows(&[LABEL, APPROVED]);
    // The requester removed the label and applied it again: the latest application is theirs.
    world
        .label_applied_by(APPROVED, &person(REQUESTER_ID, "requester-one"))
        .await;
    let reason = assert_stopped(&world).await;
    assert!(
        reason.contains("reason not_applied_by_an_approver"),
        "{reason}"
    );
}

#[tokio::test]
async fn an_approver_taken_off_the_allowlist_after_intake_opens_no_pull_request() {
    let world = World::new();
    world.issue_with_an_approved_design().await;
    world.design.people.remove_the_approver();
    let reason = assert_stopped(&world).await;
    assert!(
        reason.contains("reason not_applied_by_an_approver"),
        "{reason}"
    );
}

// ---- the code host cannot be read ---------------------------------------------------------------------

#[tokio::test]
async fn a_code_host_that_cannot_be_read_opens_no_pull_request_and_is_a_degraded_record() {
    let world = World::new();
    world.issue_with_an_approved_design().await;
    world.design.issues.go_down(true);
    let result = execute_only(&world).await;
    // The attempt fails as a failed read does, so that the engine tries again. It is never a pass.
    assert_eq!(result, Err(StageError::Tool));
    nothing_was_opened(&world);
    assert!(world.design.issues.reads() >= 1, "the stage did ask");
    let reason = recorded(&world);
    assert!(
        reason.starts_with("design re-check before the pull request is opened: degraded"),
        "{reason}"
    );
    assert!(
        reason.contains("the pull request was not opened"),
        "{reason}"
    );
    assert!(reason.contains("example-org/word-count#12"), "{reason}");
}

#[tokio::test]
async fn the_same_job_opens_its_pull_request_when_the_code_host_comes_back() {
    let world = World::new();
    world.issue_with_an_approved_design().await;
    world.design.issues.go_down(true);
    let (base, head) = world.commits().await;
    let handler = world.handler();
    let upstream = world.upstream(&base, &head).await;
    let contract = world
        .resolve_contract(&handler, &upstream)
        .expect("the contract resolves");
    assert_eq!(
        world.execute(&handler, &contract, &upstream).await.err(),
        Some(StageError::Tool)
    );
    nothing_was_opened(&world);
    world.design.issues.go_down(false);
    world
        .execute(&handler, &contract, &upstream)
        .await
        .expect("the host is back");
    assert_eq!(world.host.opened().len(), 1);
}

#[tokio::test]
async fn a_rule_that_cannot_be_read_blocks_the_run_and_says_the_factory_could_not_check() {
    let world = World::new();
    world.design.rule.break_it();
    let result = execute_only(&world).await;
    assert_eq!(
        result,
        Err(StageError::Environment(EnvironmentCause::PolicyUnloadable))
    );
    nothing_was_opened(&world);
    let comments = world.design.replies.texts();
    assert_eq!(comments.len(), 1, "{comments:?}");
    assert!(
        comments[0].contains("could not check again"),
        "{}",
        comments[0]
    );
    let (reason, reply) = recorded_pair(&world);
    assert!(reason.contains("degraded"), "{reason}");
    assert!(reply.contains("reply for issue"), "{reply}");
    // The rule is unreadable, so the cap is unknown: the reply is asked with the least one.
    assert_eq!(
        world.design.replies.caps(),
        [
            factory_domain::policy::issue_workflow::ReplyCap::when_the_policy_cannot_be_read(
                factory_domain::policy::issue_workflow::ReplyKind::Withdrawal
            )
        ]
    );
}

#[tokio::test]
async fn an_allowlist_that_cannot_be_read_blocks_the_run_too() {
    let world = World::new();
    world.design.people.break_it();
    let result = execute_only(&world).await;
    assert_eq!(
        result,
        Err(StageError::Environment(EnvironmentCause::PolicyUnloadable))
    );
    nothing_was_opened(&world);
    assert_eq!(world.design.replies.texts().len(), 1);
}

// ---- the record and the comment ---------------------------------------------------------------------------

#[tokio::test]
async fn a_comment_that_cannot_be_posted_does_not_change_the_block_and_the_record_says_so() {
    let world = World::new();
    world.issue_shows(&[LABEL, "design: in review"]);
    world.design.replies.go_down();
    let result = execute_only(&world).await;
    assert_eq!(
        result,
        Err(StageError::Blocked(BlockedCode::DesignNotApproved))
    );
    nothing_was_opened(&world);
    let (reason, reply) = recorded_pair(&world);
    assert!(reason.contains("reply to_follow"), "{reason}");
    assert!(reply.contains(": later"), "{reply}");
}

#[tokio::test]
async fn a_cap_that_is_reached_posts_nothing_and_the_block_stands_with_a_record_of_it() {
    // DG-9 (a). The issue already holds as many replies as the cap allows.
    let world = World::new();
    world.issue_shows(&[LABEL, "design: in review"]);
    world.design.replies.reach_the_cap();
    let result = execute_only(&world).await;
    assert_eq!(
        result,
        Err(StageError::Blocked(BlockedCode::DesignNotApproved))
    );
    nothing_was_opened(&world);
    assert!(world.design.replies.texts().is_empty());
    let (_, reply) = recorded_pair(&world);
    assert!(
        reply.contains(": capped (at most 2 in 24 hours)"),
        "{reply}"
    );
}

#[tokio::test]
async fn the_recheck_asks_with_the_cap_of_the_policy_and_writes_the_record_first() {
    // DG-9 (a) and (d).
    let world = World::new();
    world.issue_shows(&[LABEL, "design: in review"]);
    let _ = assert_stopped(&world).await;
    let caps = world.design.replies.caps();
    assert_eq!(caps.len(), 1);
    assert_eq!(
        caps[0].kind(),
        factory_domain::policy::issue_workflow::ReplyKind::Withdrawal
    );
    assert_eq!(caps[0].max(), 2);
    assert_eq!(caps[0].window(), std::time::Duration::from_secs(24 * 3600));
}

#[tokio::test]
async fn a_secret_shaped_label_name_does_not_reach_the_record_of_the_recheck() {
    let secret = canary();
    let label = format!("design: {secret}");
    let world = World::new();
    world.issue_shows(&[LABEL, &label]);
    let result = execute_only(&world).await;
    assert_eq!(
        result,
        Err(StageError::Blocked(BlockedCode::DesignNotApproved))
    );
    let (reason, reply) = recorded_pair(&world);
    assert!(!reason.contains(&secret), "{reason}");
    assert!(!reply.contains(&secret), "{reply}");
    assert!(reason.contains("design re-check"), "{reason}");
}

#[tokio::test]
async fn the_recheck_comes_after_the_evidence_is_checked_and_before_anything_is_pushed() {
    // A bound value changed: the stage tells the engine and stops, and does not ask the issue.
    let world = World::new();
    world.issue_shows(&[LABEL, "design: in progress"]);
    world
        .host
        .base_moves_to(factory_ports::paths::CommitSha::parse(&"f".repeat(40)).expect("a sha"));
    let result = execute_only(&world).await;
    assert_eq!(result, Err(StageError::Cancelled));
    assert_eq!(world.design.issues.reads(), 0, "the evidence came first");
    nothing_was_opened(&world);
}
