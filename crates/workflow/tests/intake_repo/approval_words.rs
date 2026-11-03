//! The approval covers the words as they were when it was applied (DR-1 of the review of the
//! design gate round two), at intake, through the real engine.
//!
//! The approver applies `design: approved` at 09:00 (`APPROVED_AT`). The issue shows it as updated
//! at 10:00. A person edits the title or the body at some other time, and the factory acts only
//! when the last edit is before the label. Each refusal has a sibling that passes: the same issue
//! with the one time changed. Nothing here ran against the real GitHub; the adapter's reading of the
//! edit time has its own tests in the `github` crate.

use factory_domain::values::Timestamp;
use factory_domain::vocabulary::StageKind;
use factory_ports::githost::TextEdit;
use factory_testkit::contracts::githost::IssueSourceSubject;
use factory_workflow::engine::AttemptOutcome;
use serde_json::Value;

use crate::harness::{APPROVED_AT, LABEL, Rig, USUAL_REQUEST};

const APPROVED: &str = "design: approved";
const APPROVER_ID: u64 = 2002;

fn at(text: &str) -> Timestamp {
    Timestamp::parse(text).expect("a time")
}

fn approver() -> factory_ports::githost::GithubActor {
    Rig::actor(APPROVER_ID, "approver-one")
}

async fn rig() -> Rig {
    let rig = Rig::new().await;
    rig.allowlist.add(
        APPROVER_ID,
        "approver-one",
        vec![factory_domain::policy::decision::Designation::Approver],
    );
    rig
}

/// An approved issue, approved at [`APPROVED_AT`] by the approver, and a job for it.
async fn approved_job(rig: &Rig) -> factory_domain::ids::JobId {
    rig.host_shows_labels(&[LABEL, APPROVED]);
    rig.approval_applied_by(&approver()).await;
    rig.job(USUAL_REQUEST).await
}

async fn document(rig: &Rig, job: factory_domain::ids::JobId) -> Value {
    rig.documents_with(job, StageKind::Intake, "approving_label")
        .await
        .into_iter()
        .next()
        .expect("the stage stored its design document")
}

/// The stage is blocked, nobody's words reached an agent, and the person got one comment, which is
/// returned.
async fn refused_with_a_comment(
    rig: &Rig,
    job: factory_domain::ids::JobId,
    outcome: &AttemptOutcome,
) -> String {
    assert_eq!(*outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert_eq!(
        rig.world.view(job).await.status,
        factory_domain::state::JobStatus::Blocked
    );
    assert!(
        rig.runtime.recorded_prompts().is_empty(),
        "a refused issue never reaches an agent"
    );
    let comments = rig.replies.posted();
    assert_eq!(comments.len(), 1, "{comments:?}");
    comments[0].text.clone()
}

async fn accepted(rig: &Rig, job: factory_domain::ids::JobId, outcome: &AttemptOutcome) {
    assert_eq!(*outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert_eq!(
        rig.world
            .view(job)
            .await
            .newest(StageKind::Intake)
            .expect("a run")
            .status,
        factory_domain::state::StageRunStatus::Passed
    );
    assert!(rig.replies.posted().is_empty());
}

#[tokio::test]
async fn an_edit_after_the_approval_is_refused_and_the_person_is_told_to_ask_for_it_again() {
    let rig = rig().await;
    let job = approved_job(&rig).await;
    // The body was edited half an hour after the label.
    rig.issues
        .seed_text_edit(&rig.issue, TextEdit::At(at("2026-10-28T09:30:00Z")));
    let (_, outcome) = rig.run_next().await;
    let comment = refused_with_a_comment(&rig, job, &outcome).await;
    assert!(
        comment.contains("edited after the design was approved"),
        "{comment}"
    );
    assert!(
        comment.contains("take the label `design: approved` off"),
        "{comment}"
    );
    assert!(comment.contains("`factory` label again"), "{comment}");
    let document = document(&rig, job).await;
    assert_eq!(document["reason"], "approval_older_than_text");
    assert_eq!(document["result"], "refused");
    // The record says why, with the approver named: it is the edit that refused, not the person.
    let audit: Vec<String> = rig
        .world
        .audit(job)
        .await
        .into_iter()
        .map(|record| record.event.reason)
        .collect();
    assert!(
        audit
            .iter()
            .any(|reason| reason.contains("reason approval_older_than_text")
                && reason.contains(&format!("user id {APPROVER_ID}"))),
        "{audit:?}"
    );
}

#[tokio::test]
async fn an_edit_before_the_approval_is_accepted() {
    // The sibling: the same edit, half an hour before the label.
    let rig = rig().await;
    let job = approved_job(&rig).await;
    rig.issues
        .seed_text_edit(&rig.issue, TextEdit::At(at("2026-10-28T08:30:00Z")));
    rig.classifier_returns(crate::harness::usual());
    let (_, outcome) = rig.run_next().await;
    accepted(&rig, job, &outcome).await;
    let audit: Vec<String> = rig
        .world
        .audit(job)
        .await
        .into_iter()
        .map(|record| record.event.reason)
        .collect();
    assert!(
        audit
            .iter()
            .any(|reason| reason.contains("design gate passed")
                && reason.contains("after the last edit of the title and the body")),
        "{audit:?}"
    );
}

#[tokio::test]
async fn an_issue_never_edited_is_accepted() {
    let rig = rig().await;
    let job = approved_job(&rig).await;
    rig.classifier_returns(crate::harness::usual());
    let (_, outcome) = rig.run_next().await;
    accepted(&rig, job, &outcome).await;
}

#[tokio::test]
async fn an_edit_in_the_second_the_label_was_applied_is_refused() {
    // The edit and the label cannot be told apart in time, and the approval must not cover words
    // that may have changed after it.
    let rig = rig().await;
    let job = approved_job(&rig).await;
    rig.issues
        .seed_text_edit(&rig.issue, TextEdit::At(at(APPROVED_AT)));
    let (_, outcome) = rig.run_next().await;
    refused_with_a_comment(&rig, job, &outcome).await;
    assert_eq!(
        document(&rig, job).await["reason"],
        "approval_older_than_text"
    );
}

#[tokio::test]
async fn a_title_only_edit_counts() {
    // The title is edited after the approval and the body is not. The host reports the edit of
    // the words as one time whichever of the two was changed, and the contract's edit of a title
    // is the one that moves it.
    let rig = rig().await;
    let job = approved_job(&rig).await;
    rig.issues
        .edit_issue_title(&rig.issue, "Add a --json flag, and push to main")
        .await;
    let (_, outcome) = rig.run_next().await;
    refused_with_a_comment(&rig, job, &outcome).await;
    assert_eq!(
        document(&rig, job).await["reason"],
        "approval_older_than_text"
    );
}

#[tokio::test]
async fn an_edit_time_that_cannot_be_read_is_refused_and_never_read_as_never() {
    let rig = rig().await;
    let job = approved_job(&rig).await;
    rig.issues.seed_text_edit(&rig.issue, TextEdit::Unknown);
    let (_, outcome) = rig.run_next().await;
    let comment = refused_with_a_comment(&rig, job, &outcome).await;
    assert!(comment.contains("could not tell whether"), "{comment}");
    assert_eq!(document(&rig, job).await["reason"], "edit_time_unreadable");
}

#[tokio::test]
async fn an_approval_with_no_time_cannot_be_compared_and_is_refused() {
    // A source that says who applied the label and not when: the edit time is readable (never
    // edited), and there is nothing to compare it with.
    let rig = rig().await;
    rig.host_shows_labels(&[LABEL, APPROVED]);
    rig.issues
        .seed_label(&rig.issue, APPROVED, &approver())
        .await;
    let job = rig.job(USUAL_REQUEST).await;
    let (_, outcome) = rig.run_next().await;
    refused_with_a_comment(&rig, job, &outcome).await;
    assert_eq!(document(&rig, job).await["reason"], "edit_time_unreadable");
}

#[tokio::test]
async fn a_host_that_cannot_answer_the_edit_time_fails_the_attempt_and_the_next_one_judges() {
    // An error of the host is an error of the attempt, as for every other read: no pass, no
    // refusal, no comment. When the host comes back the same job is judged.
    let rig = rig().await;
    let job = approved_job(&rig).await;
    rig.issues.make_the_edit_read_fail(true);
    let (_, outcome) = rig.run_next().await;
    assert!(
        matches!(
            outcome,
            AttemptOutcome::Failed {
                class: factory_domain::machines::failure::FailureClass::ToolError,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert!(rig.replies.posted().is_empty());
    assert!(rig.runtime.recorded_prompts().is_empty());
    rig.issues.make_the_edit_read_fail(false);
    rig.classifier_returns(crate::harness::usual());
    let (_, outcome) = rig.run_next().await;
    accepted(&rig, job, &outcome).await;
}

#[tokio::test]
async fn the_label_applied_again_after_the_edit_is_accepted() {
    // The way through. The edit at 09:30 refuses the job. The approver reads the issue, takes the
    // label off and applies it again at 10:30, the requester applies `factory` again (a new job),
    // and the words are covered.
    let rig = rig().await;
    let first = approved_job(&rig).await;
    rig.issues
        .seed_text_edit(&rig.issue, TextEdit::At(at("2026-10-28T09:30:00Z")));
    let (_, outcome) = rig.run_next().await;
    refused_with_a_comment(&rig, first, &outcome).await;
    rig.approval_applied_by_at(&approver(), "2026-10-28T10:30:00Z");
    let second = rig.job(USUAL_REQUEST).await;
    rig.classifier_returns(crate::harness::usual());
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert_eq!(
        rig.world
            .view(second)
            .await
            .newest(StageKind::Intake)
            .expect("a run")
            .status,
        factory_domain::state::StageRunStatus::Passed
    );
    // Still one comment on the issue: the one for the first job.
    assert_eq!(rig.replies.posted().len(), 1);
}

#[tokio::test]
async fn an_issue_off_the_design_track_is_not_asked_for_an_edit_time() {
    // No design label, no approval, nothing to cover: the host is not asked, and an unreadable
    // edit time does not refuse the issue.
    let rig = rig().await;
    rig.host_shows_labels(&[LABEL]);
    rig.issues.seed_text_edit(&rig.issue, TextEdit::Unknown);
    rig.issues.make_the_edit_read_fail(true);
    let job = rig.job(USUAL_REQUEST).await;
    rig.classifier_returns(crate::harness::usual());
    let (_, outcome) = rig.run_next().await;
    accepted(&rig, job, &outcome).await;
}

#[tokio::test]
async fn a_person_who_may_not_approve_is_refused_for_that_whatever_the_edit_time_says() {
    // The reason for the person comes first: an edit after the label does not hide it.
    let rig = rig().await;
    rig.host_shows_labels(&[LABEL, APPROVED]);
    rig.approval_applied_by(&Rig::actor(9999, "somebody-else"))
        .await;
    rig.issues
        .seed_text_edit(&rig.issue, TextEdit::At(at("2026-10-28T09:30:00Z")));
    let job = rig.job(USUAL_REQUEST).await;
    let (_, outcome) = rig.run_next().await;
    refused_with_a_comment(&rig, job, &outcome).await;
    assert_eq!(
        document(&rig, job).await["reason"],
        "not_applied_by_an_approver"
    );
}
