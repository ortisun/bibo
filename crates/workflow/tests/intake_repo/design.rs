//! The design gate at intake (ADR 0016, item 2 of "What is not built"), through the real engine.
//!
//! An issue that carries a `design:` label starts work only when `design: approved` is the one
//! design label on it, read from the code host at intake, and the person who applied it holds the
//! approver designation on the allowlist. Each check here has a sibling that proves it can fail:
//! the same issue with the one thing changed. The breaks of the code itself are in
//! `tests/mutations/design_gate_breaks.py`.

use factory_domain::ids::JobId;
use factory_domain::machines::failure::FailureClass;
use factory_domain::policy::decision::Designation;
use factory_domain::policy::{ApprovalPolicy, PolicyEngine};
use factory_domain::state::{JobStatus, StageRunStatus};
use factory_domain::values::HumanText;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::{HumanRole, StageKind};
use factory_ports::githost::{AccountType, GitScope, IssueSource};
use factory_testkit::contracts::githost::IssueSourceSubject;
use factory_testkit::githost::{FakeIssueSource, IssueSourceDefect};
use factory_workflow::commands::{Decision, OverrideFacts, Subject};
use factory_workflow::engine::{AttemptOutcome, EngineError};
use factory_workflow::gates::readability::{
    Artifact, Options as ReadabilityOptions, ReadabilityGate,
};
use factory_workflow::stages::intake::design::Reply;
use serde_json::Value;

use crate::harness::{LABEL, Options, REQUESTER_ID, ReplyMode, Rig, USUAL_REQUEST, usual};

/// A person who holds the approver designation and nothing else.
const APPROVER_ID: u64 = 2002;
/// A person who holds only the operator designation.
const OPERATOR_ID: u64 = 3003;
const APPROVED: &str = "design: approved";

fn approver() -> factory_ports::githost::GithubActor {
    Rig::actor(APPROVER_ID, "approver-one")
}

fn requester() -> factory_ports::githost::GithubActor {
    Rig::actor(REQUESTER_ID, "requester-one")
}

fn operator() -> factory_ports::githost::GithubActor {
    Rig::actor(OPERATOR_ID, "operator-one")
}

/// A rig whose allowlist knows an approver and an operator besides the requester.
async fn rig() -> Rig {
    let rig = Rig::new().await;
    equip(&rig);
    rig
}

fn equip(rig: &Rig) {
    rig.allowlist
        .add(APPROVER_ID, "approver-one", vec![Designation::Approver]);
    rig.allowlist
        .add(OPERATOR_ID, "operator-one", vec![Designation::Operator]);
}

/// A job on an issue that shows these labels now, with the factory label applied by the requester
/// and the label `design: approved` applied by `approved_by`, if anyone.
async fn job_with(
    rig: &Rig,
    labels: &[&str],
    approved_by: Option<&factory_ports::githost::GithubActor>,
) -> JobId {
    rig.host_shows_labels(labels);
    if let Some(actor) = approved_by {
        rig.approval_applied_by(actor).await;
    }
    rig.job(USUAL_REQUEST).await
}

async fn design_document(rig: &Rig, job: JobId) -> Value {
    rig.documents_with(job, StageKind::Intake, "approving_label")
        .await
        .into_iter()
        .next()
        .expect("the stage stored its design document")
}

async fn design_report(rig: &Rig, job: JobId) -> Value {
    rig.gate_reports(job)
        .await
        .into_iter()
        .find(|report| report["metadata"]["gate_id"] == "intake-design-approved")
        .expect("the design gate has a report")
}

/// The stage run is blocked, the job shows as blocked, no agent read anything, and the person got
/// one comment. Returns the text of the comment.
async fn assert_refused(rig: &Rig, job: JobId, outcome: &AttemptOutcome) -> String {
    assert_eq!(*outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    let view = rig.world.view(job).await;
    assert_eq!(
        view.newest(StageKind::Intake).expect("a run").status,
        StageRunStatus::Blocked
    );
    assert_eq!(view.status, JobStatus::Blocked);
    assert!(
        rig.runtime.recorded_prompts().is_empty(),
        "a refused issue never reaches an agent"
    );
    let comments = rig.replies.posted();
    assert_eq!(comments.len(), 1, "{comments:?}");
    assert_eq!(comments[0].issue, rig.issue);
    comments[0].text.clone()
}

/// The stage run passed, the classifier ran once and nobody was told anything.
async fn assert_accepted(rig: &Rig, job: JobId, outcome: &AttemptOutcome) {
    assert_eq!(*outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    let view = rig.world.view(job).await;
    assert_eq!(
        view.newest(StageKind::Intake).expect("a run").status,
        StageRunStatus::Passed
    );
    assert_eq!(rig.runtime.recorded_prompts().len(), 1);
    assert!(rig.replies.posted().is_empty());
}

// ---- the rule ----------------------------------------------------------------------------------

#[tokio::test]
async fn a_design_track_issue_with_no_approved_label_is_refused_with_a_comment_and_a_block_code() {
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, "design: in review"], None).await;
    let (_, outcome) = rig.run_next().await;
    let comment = assert_refused(&rig, job, &outcome).await;

    // The person is told, in plain English, that the design is not approved yet and what to do.
    assert!(comment.contains("design is not approved yet"), "{comment}");
    assert!(comment.contains("`design: approved`"), "{comment}");
    assert!(comment.contains("approver"), "{comment}");
    assert!(comment.contains("`factory` label again"), "{comment}");
    assert!(
        !comment.contains("in review"),
        "the comment says nothing of the issue's labels"
    );

    // The gate report carries the block code.
    let report = design_report(&rig, job).await;
    assert_eq!(report["outcome"], "BLOCKED");
    assert_eq!(report["blocked_reason"]["code"], "design_not_approved");
    // The outcome of intake is a decline, with a sentence that a person can read.
    let decision = rig
        .documents_with(job, StageKind::Intake, "decision")
        .await
        .into_iter()
        .next()
        .expect("the decision");
    assert_eq!(decision["decision"], "decline");
    assert!(
        decision["explanation"]
            .as_str()
            .unwrap()
            .contains("not approved yet")
    );
    // The document the stage kept.
    let document = design_document(&rig, job).await;
    assert_eq!(document["result"], "refused");
    assert_eq!(document["block_code"], "DESIGN_NOT_APPROVED");
    assert_eq!(document["reason"], "not_approved");
    assert_eq!(
        document["labels_seen"],
        serde_json::json!(["design: in review"])
    );

    // The audit record names the issue and the labels seen.
    let audit = rig.world.audit(job).await;
    let record = audit
        .iter()
        .find(|record| record.event.reason.contains("DESIGN_NOT_APPROVED"))
        .expect("an audit record of the refusal");
    assert_eq!(
        record.event.action.as_str(),
        "authorization_decision.denied"
    );
    assert!(record.event.reason.contains("example-org/fixture#12"));
    assert!(record.event.reason.contains("design: in review"));
    assert!(!record.event.reason.contains("design: proposed"));
}

#[tokio::test]
async fn the_same_issue_with_the_approved_label_applied_by_an_approver_is_accepted() {
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, APPROVED], Some(&approver())).await;
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_accepted(&rig, job, &outcome).await;
    let report = design_report(&rig, job).await;
    assert_eq!(report["outcome"], "PASSED");
    assert_eq!(design_document(&rig, job).await["approved_by"], APPROVER_ID);
    // The person who approved is on the record.
    let audit = rig.world.audit(job).await;
    assert!(
        audit.iter().any(
            |record| record.event.action.as_str() == "authorization_decision.granted"
                && record.event.reason.contains("applied by user id 2002")
        ),
        "the approver is named in the audit log"
    );
}

#[tokio::test]
async fn an_issue_with_no_design_label_is_accepted_as_before() {
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, "bug"], None).await;
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_accepted(&rig, job, &outcome).await;
    assert_eq!(design_document(&rig, job).await["result"], "not_on_track");
    assert_eq!(design_report(&rig, job).await["outcome"], "PASSED");
}

// ---- who approved ------------------------------------------------------------------------------

#[tokio::test]
async fn an_approved_label_applied_by_a_requester_who_is_not_an_approver_is_refused() {
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, APPROVED], Some(&requester())).await;
    let (_, outcome) = rig.run_next().await;
    let comment = assert_refused(&rig, job, &outcome).await;
    assert!(
        comment.contains("not someone the factory accepts design approvals from"),
        "{comment}"
    );
    assert!(comment.contains("approver"), "{comment}");
    let document = design_document(&rig, job).await;
    assert_eq!(document["reason"], "not_applied_by_an_approver");
    assert_eq!(document["applied_by"], REQUESTER_ID);
    assert_eq!(
        design_report(&rig, job).await["blocked_reason"]["code"],
        "design_not_approved"
    );
}

#[tokio::test]
async fn an_approved_label_applied_by_an_operator_who_is_not_an_approver_is_refused() {
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, APPROVED], Some(&operator())).await;
    let (_, outcome) = rig.run_next().await;
    assert_refused(&rig, job, &outcome).await;
    assert_eq!(
        design_document(&rig, job).await["reason"],
        "not_applied_by_an_approver"
    );
}

#[tokio::test]
async fn an_approved_label_applied_by_someone_the_allowlist_does_not_know_is_refused() {
    let rig = rig().await;
    let stranger = Rig::actor(9999, "a-stranger-with-triage-rights");
    let job = job_with(&rig, &[LABEL, APPROVED], Some(&stranger)).await;
    let (_, outcome) = rig.run_next().await;
    let comment = assert_refused(&rig, job, &outcome).await;
    // The same sentence as for a known person who is not an approver: the comment is not an oracle
    // for the allowlist.
    assert!(comment.contains("not someone the factory accepts design approvals from"));
}

#[tokio::test]
async fn an_approver_narrowed_to_other_repositories_is_refused_and_one_narrowed_to_this_one_is_not()
{
    // The refusal.
    let rig_a = rig().await;
    rig_a
        .allowlist
        .narrow(APPROVER_ID, &["example-org/another"]);
    let job = job_with(&rig_a, &[LABEL, APPROVED], Some(&approver())).await;
    let (_, outcome) = rig_a.run_next().await;
    assert_refused(&rig_a, job, &outcome).await;
    assert_eq!(
        design_document(&rig_a, job).await["reason"],
        "not_applied_by_an_approver"
    );
    // The sibling: narrowed to this repository, the same person approves. The comparison is the
    // allowlist's, without regard to case.
    let rig_b = rig().await;
    rig_b
        .allowlist
        .narrow(APPROVER_ID, &["Example-Org/Fixture"]);
    let job = job_with(&rig_b, &[LABEL, APPROVED], Some(&approver())).await;
    rig_b.classifier_returns(usual());
    let (_, outcome) = rig_b.run_next().await;
    assert_accepted(&rig_b, job, &outcome).await;
}

#[tokio::test]
async fn an_approver_who_was_taken_off_the_allowlist_before_intake_no_longer_approves() {
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, APPROVED], Some(&approver())).await;
    rig.allowlist.remove(APPROVER_ID);
    let (_, outcome) = rig.run_next().await;
    assert_refused(&rig, job, &outcome).await;
}

#[tokio::test]
async fn an_approved_label_whose_applier_cannot_be_found_is_refused() {
    // The label is in the list of labels and the timeline has no event for it.
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, APPROVED], None).await;
    let (_, outcome) = rig.run_next().await;
    assert_refused(&rig, job, &outcome).await;
    assert_eq!(
        design_document(&rig, job).await["reason"],
        "approval_label_gone"
    );
}

#[tokio::test]
async fn the_approved_label_beside_another_design_label_is_not_an_approved_design() {
    let rig = rig().await;
    let job = job_with(
        &rig,
        &[LABEL, APPROVED, "design: in progress"],
        Some(&approver()),
    )
    .await;
    let (_, outcome) = rig.run_next().await;
    let comment = assert_refused(&rig, job, &outcome).await;
    assert!(
        comment.contains("state of its design is not clear"),
        "{comment}"
    );
    assert_eq!(
        design_document(&rig, job).await["reason"],
        "more_than_one_design_label"
    );
}

// ---- the labels are the ones read at intake ----------------------------------------------------

#[tokio::test]
async fn a_label_removed_between_the_webhook_and_intake_changes_the_outcome() {
    let rig = rig().await;
    // When the webhook arrived the issue showed `design: approved`, applied by an approver. The
    // timeline of the host still says so. Before intake, a person took the label off.
    rig.host_shows_labels(&[LABEL, APPROVED]);
    rig.approval_applied_by(&approver()).await;
    let job = rig.webhook_job().await;
    rig.host_shows_labels(&[LABEL, "design: in progress"]);
    let (_, outcome) = rig.run_next().await;
    assert_refused(&rig, job, &outcome).await;
    assert_eq!(design_document(&rig, job).await["reason"], "not_approved");
}

#[tokio::test]
async fn a_label_added_between_the_webhook_and_intake_changes_the_outcome() {
    // The sibling, the other way round. The webhook found a design that was not approved. Before
    // intake an approver approved it, and the label of the old state was taken off.
    let rig = rig().await;
    rig.host_shows_labels(&[LABEL, "design: in review"]);
    let job = rig.webhook_job().await;
    rig.host_shows_labels(&[LABEL, APPROVED]);
    rig.approval_applied_by(&approver()).await;
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_accepted(&rig, job, &outcome).await;

    // And a design label added after the webhook stops an issue that had none.
    let rig = self::rig().await;
    rig.host_shows_labels(&[LABEL]);
    let job = rig.webhook_job().await;
    rig.host_shows_labels(&[LABEL, "design: proposed"]);
    let (_, outcome) = rig.run_next().await;
    assert_refused(&rig, job, &outcome).await;
}

#[tokio::test]
async fn break_a_host_that_answers_from_a_cache_hides_a_label_removed_after_the_webhook() {
    // The fake's documented defect: the issue is cached, so the label list is the one of the first
    // read. The test above fails on this host, which is what this test shows by asserting the
    // opposite on the same steps: the gate is only as live as the port it reads.
    let rig = Rig::build(Options {
        issue_source: Some(FakeIssueSource::with_defect(
            IssueSourceDefect::CachesIssues,
        )),
        ..Options::default()
    })
    .await;
    equip(&rig);
    rig.host_shows_labels(&[LABEL, APPROVED]);
    rig.approval_applied_by(&approver()).await;
    let job = rig.webhook_job().await;
    // Something read the issue when the webhook arrived, and the host kept that answer.
    let scope = GitScope {
        tenant: rig.world.tenant,
        job,
        stage: StageKind::Intake,
        repo: rig.repo.clone(),
    };
    rig.issues
        .fetch_issue(&scope, &rig.issue)
        .await
        .expect("the first read");
    rig.host_shows_labels(&[LABEL, "design: in progress"]);
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_accepted(&rig, job, &outcome).await;
}

// ---- hostile label names -----------------------------------------------------------------------

#[tokio::test]
async fn a_look_alike_of_the_approved_label_cannot_count_as_approved() {
    for hostile in [
        "design:approved",
        "Design: approved",
        "DESIGN: APPROVED",
        "design: approved ",
        " design: approved",
        "design:  approved",
        "design: Approved",
        "design: approved\n",
        "design: approved\u{0}",
        "design: approved\u{7}\u{1b}[2J",
        "design: appro\u{200b}ved",
        "design: approv\u{0435}d",
    ] {
        let rig = rig().await;
        // An approver "applied" the look-alike: it must not count whoever applied it. The timeline
        // also holds an approval of the exact label by the same approver, as if it had been applied
        // and taken off earlier, so that the exact name read from the list of labels is the only
        // thing that stops the look-alike, and the lookup of the applier is not a second barrier.
        rig.host_shows_labels(&[LABEL, hostile]);
        rig.issues
            .seed_label(&rig.issue, hostile, &approver())
            .await;
        rig.approval_applied_by(&approver()).await;
        let job = rig.job(USUAL_REQUEST).await;
        let (_, outcome) = rig.run_next().await;
        assert_refused(&rig, job, &outcome).await;
        let document = design_document(&rig, job).await;
        assert_eq!(document["result"], "refused", "{hostile:?}");
        // What is written down about the label is printable.
        let audit = rig.world.audit(job).await;
        for record in &audit {
            assert!(
                !record.event.reason.chars().any(|c| c.is_control()),
                "{hostile:?} reached the audit log raw: {:?}",
                record.event.reason
            );
        }
        let seen = document["labels_seen"].to_string();
        assert!(
            !seen.chars().any(|c| c.is_control() && c != '\u{0}'),
            "{hostile:?}"
        );
    }
}

#[tokio::test]
async fn a_look_alike_beside_a_real_design_label_is_a_design_label_too() {
    // DG-4. A name that does not begin with `design:` at all is just another label: it does not
    // put the issue on the track, and it does not take it off. A name that a person reads as
    // `design:` because a zero width character comes first is a design label: it is on the track,
    // it is shown among the design labels, and it approves nothing.
    let rig = rig().await;
    let job = job_with(
        &rig,
        &[
            LABEL,
            "design: proposed",
            "not design: approved",
            "\u{200b}design: approved",
        ],
        Some(&approver()),
    )
    .await;
    let (_, outcome) = rig.run_next().await;
    assert_refused(&rig, job, &outcome).await;
    let document = design_document(&rig, job).await;
    assert_eq!(
        document["labels_seen"],
        serde_json::json!(["design: proposed", "?design: approved"])
    );
}

// ---- fail closed -------------------------------------------------------------------------------

#[tokio::test]
async fn a_policy_that_cannot_be_read_refuses_the_issue_and_allows_nothing() {
    let rig = rig().await;
    // The issue has no design label at all: with a policy that can be read it is accepted (the
    // test above). Here the policy file is broken.
    rig.design.break_it();
    let job = job_with(&rig, &[LABEL], None).await;
    let (_, outcome) = rig.run_next().await;
    assert!(
        matches!(
            outcome,
            AttemptOutcome::Failed {
                class: FailureClass::PolicyDenied,
                ..
            }
        ),
        "{outcome:?}"
    );
    let view = rig.world.view(job).await;
    assert_eq!(
        view.newest(StageKind::Intake).expect("a run").status,
        StageRunStatus::Blocked
    );
    assert_eq!(view.status, JobStatus::Blocked);
    assert!(rig.runtime.recorded_prompts().is_empty());
    // The person is told that the factory could not check, and it says nothing of the policy file.
    let comments = rig.replies.posted();
    assert_eq!(comments.len(), 1);
    assert!(
        comments[0]
            .text
            .contains("could not check whether the design is approved")
    );
    assert!(!comments[0].text.contains("policy"));
    // The record says why.
    let audit = rig.world.audit(job).await;
    assert!(
        audit.iter().any(|record| record
            .event
            .reason
            .contains("the issue workflow policy cannot be used")),
        "the audit log says the policy could not be used"
    );
    // The block is the environment block of a policy that cannot be loaded.
    let events = rig.world.events(job).await;
    assert!(events.iter().any(|event| {
        event.event_type.as_str() == "stage_run.blocked"
            && event.payload["cause"] == "policy_unloadable"
    }));

    // The sibling: the file is sound again, and the same issue, labelled again, is accepted. It
    // was the policy that held it back, and nothing else.
    rig.design.repair();
    let again = rig.job(USUAL_REQUEST).await;
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert_eq!(
        rig.world
            .view(again)
            .await
            .newest(StageKind::Intake)
            .expect("a run")
            .status,
        StageRunStatus::Passed
    );
}

#[tokio::test]
async fn a_policy_that_cannot_be_read_refuses_a_design_track_issue_too() {
    // Not only the issues that carry no design label: an approved one as well.
    let rig = rig().await;
    rig.design.break_it();
    let job = job_with(&rig, &[LABEL, APPROVED], Some(&approver())).await;
    let (_, outcome) = rig.run_next().await;
    assert!(
        matches!(outcome, AttemptOutcome::Failed { .. }),
        "{outcome:?}"
    );
    assert_eq!(
        rig.world
            .view(job)
            .await
            .newest(StageKind::Intake)
            .expect("a run")
            .status,
        StageRunStatus::Blocked
    );
}

// ---- the comment ------------------------------------------------------------------------------

/// The reasons of the audit records the design gate wrote for the job, oldest first.
async fn design_reasons(rig: &Rig, job: JobId) -> Vec<String> {
    rig.world
        .audit(job)
        .await
        .into_iter()
        .map(|record| record.event.reason)
        .filter(|reason| reason.starts_with("design gate"))
        .collect()
}

#[tokio::test]
async fn a_comment_that_cannot_be_posted_now_is_tried_again_and_every_attempt_leaves_the_record() {
    // DG-9 (d). The host cannot take a comment. The attempt fails as a failed read does and the
    // engine runs it again, as before, but the record of the refusal is written first, so a failed
    // attempt is no longer an attempt with no design record. The host comes back: one answer.
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, "design: proposed"], None).await;
    rig.replies.set(ReplyMode::HostDown);
    let (_, outcome) = rig.run_next().await;
    assert!(
        matches!(
            outcome,
            AttemptOutcome::Failed {
                class: FailureClass::ToolError,
                ..
            }
        ),
        "{outcome:?}"
    );
    // Nothing was accepted and the run is not blocked yet; the comment was asked for once.
    let status = rig
        .world
        .view(job)
        .await
        .newest(StageKind::Intake)
        .expect("a run")
        .status;
    assert_ne!(status, StageRunStatus::Passed);
    assert_eq!(rig.replies.asked(), 1);
    assert!(rig.replies.posted().is_empty());
    // The failed attempt left the design record: the decision first, then what became of the reply.
    let reasons = design_reasons(&rig, job).await;
    assert_eq!(reasons.len(), 2, "{reasons:?}");
    assert!(reasons[0].contains("DESIGN_NOT_APPROVED"), "{reasons:?}");
    assert!(reasons[0].contains("reply to_follow"), "{reasons:?}");
    assert!(reasons[1].ends_with(": later"), "{reasons:?}");
    // The host comes back, and the next attempt answers once and blocks.
    rig.replies.set(ReplyMode::Works);
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert_eq!(rig.replies.posted().len(), 1);
    assert_eq!(rig.world.view(job).await.status, JobStatus::Blocked);
}

#[tokio::test]
async fn a_comment_endpoint_that_stays_down_does_not_turn_the_block_into_a_failed_job() {
    // DG-9 (d). The old behaviour: three failed attempts, a FAILED job, and no design record. Now
    // the attempts that remain are used, and the last one gives the comment up and blocks, with
    // the record, as the refusal always did.
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, "design: proposed"], None).await;
    rig.replies.set(ReplyMode::HostDown);
    let mut failed = 0;
    let outcome = loop {
        let (_, outcome) = rig.run_next().await;
        if !matches!(outcome, AttemptOutcome::Failed { .. }) {
            break outcome;
        }
        failed += 1;
        assert!(failed < 10, "the attempts never ended");
    };
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert!(failed >= 1, "the first attempts were retries");
    let view = rig.world.view(job).await;
    assert_eq!(view.status, JobStatus::Blocked);
    assert_eq!(
        view.newest(StageKind::Intake).expect("a run").status,
        StageRunStatus::Blocked
    );
    assert!(rig.replies.posted().is_empty());
    assert_eq!(design_document(&rig, job).await["reason"], "not_approved");
    assert_eq!(design_document(&rig, job).await["reply"], "later");
    // Every attempt, the failed ones and the last, wrote its decision and its reply record.
    let reasons = design_reasons(&rig, job).await;
    assert_eq!(reasons.len(), 2 * (failed + 1), "{reasons:?}");
    assert!(reasons.iter().all(|r| !r.is_empty()));
}

#[tokio::test]
async fn the_record_of_the_refusal_is_written_before_the_reply_and_the_reply_has_a_record_of_its_own()
 {
    // DG-9 (d). The first record is the decision and is written before the reply is tried, so it
    // cannot depend on the reply. It says the reply is still to follow. The second says what became
    // of it.
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, "design: proposed"], None).await;
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    let reasons = design_reasons(&rig, job).await;
    assert_eq!(reasons.len(), 2, "{reasons:?}");
    assert!(reasons[0].contains("design gate refused"), "{reasons:?}");
    assert!(reasons[0].contains("reply to_follow"), "{reasons:?}");
    assert!(
        reasons[1].starts_with("design gate reply for issue example-org/fixture#12"),
        "{reasons:?}"
    );
    assert!(reasons[1].contains("posted"), "{reasons:?}");
    assert_eq!(rig.replies.posted().len(), 1);
}

#[tokio::test]
async fn a_cap_that_is_reached_posts_nothing_and_leaves_a_record() {
    // DG-9 (a). The host says the issue already holds as many replies as the cap allows.
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, "design: proposed"], None).await;
    rig.replies.set(ReplyMode::CapReached);
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert_eq!(rig.world.view(job).await.status, JobStatus::Blocked);
    assert!(rig.replies.posted().is_empty());
    assert_eq!(design_document(&rig, job).await["reply"], "capped");
    let reasons = design_reasons(&rig, job).await;
    assert!(
        reasons.iter().any(|reason| reason
            .starts_with("design gate reply for issue example-org/fixture#12: capped")
            && reason.contains("at most 5 in 24 hours")),
        "{reasons:?}"
    );
}

#[tokio::test]
async fn a_thread_too_long_to_check_gets_no_reply_and_a_record_that_says_so() {
    // DG-9 (b). The host could not read all the comments of the window in its one page. It cannot
    // tell whether the factory already answered, so it posts nothing; the block stands.
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, "design: proposed"], None).await;
    rig.replies.set(ReplyMode::ThreadCut);
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert_eq!(rig.world.view(job).await.status, JobStatus::Blocked);
    assert!(rig.replies.posted().is_empty());
    assert_eq!(
        design_document(&rig, job).await["reply"],
        "thread_not_checked"
    );
}

#[tokio::test]
async fn the_reply_is_asked_with_the_cap_of_the_policy() {
    // DG-9 (a). The cap is the policy's (five in 24 hours), read with the rule, not a number of
    // the stage's own.
    let rig = rig().await;
    let _ = job_with(&rig, &[LABEL, "design: proposed"], None).await;
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    let caps = rig.replies.caps();
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].max(), 5);
    assert_eq!(caps[0].window(), std::time::Duration::from_secs(24 * 3600));
}

#[tokio::test]
async fn a_reply_about_a_policy_that_cannot_be_read_is_asked_with_the_least_cap() {
    // DG-9 (a). When the rule cannot be read the cap cannot be either, and the reply is asked with
    // the closed value: one in a day. It is not asked without a cap.
    let rig = rig().await;
    let _ = job_with(&rig, &[LABEL, "design: proposed"], None).await;
    rig.design.break_it();
    let (_, outcome) = rig.run_next().await;
    assert!(
        matches!(
            outcome,
            AttemptOutcome::Failed { .. } | AttemptOutcome::Succeeded
        ),
        "{outcome:?}"
    );
    let caps = rig.replies.caps();
    assert_eq!(caps.len(), 1);
    assert_eq!(
        caps[0],
        factory_domain::policy::issue_workflow::ReplyCap::WHEN_THE_POLICY_CANNOT_BE_READ
    );
}

// ---- LB-02: the environment is missing after the gate has passed ----------------------------------

async fn rig_without_a_sandbox() -> Rig {
    let rig = Rig::build(Options {
        sandbox_missing: true,
        ..Options::default()
    })
    .await;
    equip(&rig);
    rig
}

#[tokio::test]
async fn a_job_that_passed_the_gate_and_is_blocked_by_the_environment_leaves_one_fixed_comment() {
    let rig = rig_without_a_sandbox().await;
    let job = job_with(&rig, &[LABEL], None).await;
    let (_, outcome) = rig.run_next().await;
    // The stage is blocked by the environment, as before.
    assert!(
        matches!(outcome, AttemptOutcome::Failed { .. }),
        "{outcome:?}"
    );
    assert_eq!(rig.world.view(job).await.status, JobStatus::Blocked);
    // And the person who asked is told, once, with a closed template: the text is the template and
    // nothing else, so nothing of the error and nothing of the issue is in it.
    let comments = rig.replies.posted();
    assert_eq!(comments.len(), 1, "{comments:?}");
    assert_eq!(comments[0].text, Reply::EnvironmentBlocked.text(LABEL, ""));
    assert!(
        comments[0].key.starts_with("environment-"),
        "{}",
        comments[0].key
    );
    assert!(
        comments[0].text.contains("the factory's side"),
        "{}",
        comments[0].text
    );
    // It is asked with the cap of the policy, and the record says what became of it.
    let caps = rig.replies.caps();
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].max(), 5);
    let audit: Vec<String> = rig
        .world
        .audit(job)
        .await
        .into_iter()
        .map(|record| record.event.reason)
        .collect();
    assert!(
        audit.iter().any(|reason| reason.starts_with(
            "intake environment block: reply for issue example-org/fixture#12: posted"
        )),
        "{audit:?}"
    );
    // The design gate passed before it: its record is there, and it is not a refusal.
    assert!(
        audit
            .iter()
            .any(|reason| reason.contains("carries no design label")),
        "{audit:?}"
    );
}

#[tokio::test]
async fn nothing_is_said_about_the_environment_before_the_checks_of_the_stage_have_passed() {
    // The sibling: the same missing environment, but the design is not approved. The stage stops at
    // the gate and never reaches the sandbox, so the only comment is the refusal.
    let rig = rig_without_a_sandbox().await;
    let _ = job_with(&rig, &[LABEL, "design: proposed"], None).await;
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    let comments = rig.replies.posted();
    assert_eq!(comments.len(), 1, "{comments:?}");
    assert!(comments[0].key.starts_with("design-gate-"));
    assert_ne!(comments[0].text, Reply::EnvironmentBlocked.text(LABEL, ""));
}

#[tokio::test]
async fn a_policy_that_cannot_be_read_is_not_told_as_an_accepted_issue_with_a_missing_environment()
{
    // The sibling: the rule of the gate is unreadable, which is also an environment block, but the
    // issue has not passed the gate. The comment is the one that says the factory could not check.
    let rig = rig_without_a_sandbox().await;
    rig.design.break_it();
    let _ = job_with(&rig, &[LABEL], None).await;
    let _ = rig.run_next().await;
    let comments = rig.replies.posted();
    assert_eq!(comments.len(), 1, "{comments:?}");
    assert!(comments[0].key.starts_with("design-gate-"));
    assert!(
        comments[0]
            .text
            .contains("could not check whether the design")
    );
}

#[tokio::test]
async fn a_comment_that_cannot_be_posted_does_not_change_the_environment_block() {
    let rig = rig_without_a_sandbox().await;
    let job = job_with(&rig, &[LABEL], None).await;
    rig.replies.set(ReplyMode::HostDown);
    let (_, outcome) = rig.run_next().await;
    assert!(
        matches!(outcome, AttemptOutcome::Failed { .. }),
        "{outcome:?}"
    );
    assert_eq!(rig.world.view(job).await.status, JobStatus::Blocked);
    assert!(rig.replies.posted().is_empty());
    assert_eq!(rig.replies.asked(), 1, "asked once, not again");
}

#[tokio::test]
async fn a_cap_that_is_reached_leaves_the_environment_block_without_a_comment() {
    let rig = rig_without_a_sandbox().await;
    let job = job_with(&rig, &[LABEL], None).await;
    rig.replies.set(ReplyMode::CapReached);
    let (_, outcome) = rig.run_next().await;
    assert!(
        matches!(outcome, AttemptOutcome::Failed { .. }),
        "{outcome:?}"
    );
    assert_eq!(rig.world.view(job).await.status, JobStatus::Blocked);
    assert!(rig.replies.posted().is_empty());
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
            .any(|reason| reason.contains(": capped (at most 5 in 24 hours)")),
        "{audit:?}"
    );
}

#[tokio::test]
async fn a_working_environment_leaves_no_environment_comment() {
    // The control: the same issue with a sandbox that can be made reaches the classifier and posts
    // no comment at all.
    let rig = rig().await;
    rig.classifier_returns(usual());
    let _ = job_with(&rig, &[LABEL], None).await;
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert!(rig.replies.posted().is_empty());
}

#[tokio::test]
async fn a_comment_that_the_host_refuses_does_not_change_the_refusal() {
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, "design: proposed"], None).await;
    rig.replies.set(ReplyMode::HostRefuses);
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    let view = rig.world.view(job).await;
    assert_eq!(view.status, JobStatus::Blocked);
    assert_eq!(design_document(&rig, job).await["reply"], "not_sent");
    assert!(rig.replies.posted().is_empty());
}

#[test]
fn every_reply_is_plain_english_by_the_readability_gate() {
    let gate = ReadabilityGate::new(ReadabilityOptions::new());
    for reply in [
        Reply::NotApproved,
        Reply::MoreThanOneDesignLabel,
        Reply::NotByAnApprover,
        Reply::DesignDropped,
        Reply::CannotCheck,
        Reply::EnvironmentBlocked,
    ] {
        let text = reply.text("factory", APPROVED);
        let findings = gate
            .findings(&[Artifact::request("Why work did not start", &text)])
            .expect("the gate runs");
        assert!(
            findings
                .iter()
                .all(|f| f.severity != factory_workflow::gates::readability::Severity::Block),
            "{reply:?}: {findings:?}"
        );
    }
}

// ---- no override -------------------------------------------------------------------------------

fn justification() -> HumanText {
    HumanText::parse("I would like work to start on this issue without the label.").expect("a text")
}

/// Facts as a caller who wants the stage to pass would write them: everything permitted. The engine
/// reads the block from what it stored, so this can only narrow.
fn claimed() -> OverrideFacts {
    OverrideFacts {
        policy_permits: true,
        security_class: true,
        mandatory_of_active_profile: false,
    }
}

async fn override_as_security_approver(rig: &Rig, job: JobId) -> Result<(), EngineError> {
    let run = rig
        .world
        .view(job)
        .await
        .newest(StageKind::Intake)
        .expect("a run")
        .id;
    let who = rig
        .world
        .person("security-1", &[HumanRole::SecurityApprover])
        .await;
    rig.engine
        .decide(
            &rig.world.actor(who),
            Subject {
                job,
                stage_run: run,
            },
            Decision::Override {
                justification: justification(),
                facts: claimed(),
            },
        )
        .await
}

#[tokio::test]
async fn a_design_that_is_not_approved_cannot_be_overridden_and_the_label_is_the_one_way() {
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, "design: in review"], None).await;
    rig.run_next().await;
    // The engine wrote the gate and the code of the block into the event of the block.
    let blocked = rig
        .world
        .events(job)
        .await
        .into_iter()
        .find(|event| event.event_type.as_str() == "stage_run.blocked")
        .expect("the block event");
    let blocks = blocked.payload["blocks"].to_string();
    assert!(
        blocks.contains("intake-design-approved") && blocks.contains("design_not_approved"),
        "{blocks}"
    );
    let refused = override_as_security_approver(&rig, job).await;
    assert!(
        matches!(refused, Err(EngineError::GuardUnmet(_))),
        "{refused:?}"
    );
    assert_eq!(
        rig.world
            .view(job)
            .await
            .newest(StageKind::Intake)
            .expect("a run")
            .status,
        StageRunStatus::Blocked
    );
}

#[tokio::test]
async fn break_without_the_entry_in_the_security_policy_an_override_starts_the_work() {
    // The control: with the entry of `gate_integrity.non_overridable_blocks` missing, the same
    // override passes the stage. The test above fails on this configuration.
    let rig = Rig::build(Options {
        without_design_block: true,
        ..Options::default()
    })
    .await;
    equip(&rig);
    let job = job_with(&rig, &[LABEL, "design: in review"], None).await;
    rig.run_next().await;
    override_as_security_approver(&rig, job)
        .await
        .expect("nothing holds the override back");
    assert_eq!(
        rig.world
            .view(job)
            .await
            .newest(StageKind::Intake)
            .expect("a run")
            .status,
        StageRunStatus::Passed
    );
}

#[test]
fn the_security_policy_lists_the_block_and_the_approval_policy_has_a_row_for_the_action() {
    let security: factory_domain::policy::SecurityPolicy = serde_json::from_str(include_str!(
        "../../../domain/tests/fixtures/policy/security.json"
    ))
    .expect("the security policy");
    assert!(
        security
            .gate_integrity
            .non_overridable_blocks
            .iter()
            .any(|block| block.gate == "intake-design-approved"
                && block.code == "design_not_approved")
    );
    let approval: ApprovalPolicy = serde_json::from_str(include_str!(
        "../../../domain/tests/fixtures/policy/approval.json"
    ))
    .expect("the approval policy");
    let row = approval
        .actions
        .iter()
        .find(|row| row.id == "accept_design_approval")
        .expect("a row");
    assert_eq!(row.approver_roles, Some(vec!["approver".to_owned()]));
    assert!(
        approval
            .always_human
            .iter()
            .any(|id| id == "accept_design_approval")
    );
    // The engine builds from both.
    PolicyEngine::new(&security, &approval).expect("the policies build");
}

// ---- DG-4: the track is what a person reads ----------------------------------------------------

#[tokio::test]
async fn a_label_that_reads_as_a_design_label_puts_the_issue_on_the_track_whatever_hides_it() {
    // Alone on the issue: nothing else on the track to put it there.
    for hidden in [
        "\u{200b}design: proposed",
        "d\u{200b}esign: proposed",
        "design\u{feff}: proposed",
        "\u{202e}Design: proposed",
        "design\u{ff1a} proposed",
        "\u{ff24}\u{ff25}\u{ff33}\u{ff29}\u{ff27}\u{ff2e}: proposed",
        "d\u{0435}sign: proposed",
        "\u{1f3a8} design: proposed",
    ] {
        let rig = rig().await;
        let job = job_with(&rig, &[LABEL, hidden], None).await;
        let (_, outcome) = rig.run_next().await;
        assert_refused(&rig, job, &outcome).await;
        assert_eq!(
            design_document(&rig, job).await["reason"],
            "not_approved",
            "{hidden:?}"
        );
    }
}

#[tokio::test]
async fn a_label_in_another_language_or_with_an_emoji_does_not_put_the_issue_on_the_track() {
    // The sibling: the rule is wide, and not so wide that ordinary labels of a team that writes in
    // another language land on the design track.
    for plain in [
        "\u{1f41b} bug",
        "n\u{e3}o-urgente",
        "documenta\u{e7}\u{e3}o",
    ] {
        let rig = rig().await;
        let job = job_with(&rig, &[LABEL, plain], None).await;
        rig.classifier_returns(usual());
        let (_, outcome) = rig.run_next().await;
        assert_accepted(&rig, job, &outcome).await;
    }
}

// ---- DG-2: the track is sticky -----------------------------------------------------------------

fn at(minute: u32) -> Timestamp {
    Timestamp::parse(&format!("2026-10-28T11:{minute:02}:00Z")).expect("a time")
}

#[tokio::test]
async fn taking_the_design_label_off_does_not_leave_the_track() {
    // The template applied `design: proposed`. The requester took it off and applied `factory`.
    // The issue shows no design label now, and its events say it had one.
    let rig = rig().await;
    rig.host_shows_labels(&[LABEL]);
    rig.issues.seed_event(
        &rig.issue,
        "design: proposed",
        &requester(),
        AccountType::User,
        at(1),
    );
    let job = rig.job(USUAL_REQUEST).await;
    let (_, outcome) = rig.run_next().await;
    let comment = assert_refused(&rig, job, &outcome).await;
    assert!(
        comment.contains("Taking the label off does not leave the track"),
        "{comment}"
    );
    assert!(comment.contains("`design: approved`"), "{comment}");
    let document = design_document(&rig, job).await;
    assert_eq!(document["reason"], "design_dropped");
    assert_eq!(
        document["labels_seen"],
        serde_json::json!(["design: proposed"])
    );
    assert_eq!(design_report(&rig, job).await["outcome"], "BLOCKED");
}

#[tokio::test]
async fn the_way_out_of_a_dropped_design_is_one_approver_action() {
    // The sibling: the same issue, after an approver applied the approving label. The old label is
    // gone, and the approval counts.
    let rig = rig().await;
    rig.host_shows_labels(&[LABEL, APPROVED]);
    rig.issues.seed_event(
        &rig.issue,
        "design: proposed",
        &requester(),
        AccountType::User,
        at(1),
    );
    let job = job_with_labels_already_shown(&rig, &approver()).await;
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_accepted(&rig, job, &outcome).await;
    assert_eq!(design_document(&rig, job).await["result"], "approved");
}

/// A job on the issue the rig already shows, with the approving label applied by `actor`.
async fn job_with_labels_already_shown(
    rig: &Rig,
    actor: &factory_ports::githost::GithubActor,
) -> JobId {
    rig.approval_applied_by(actor).await;
    rig.job(USUAL_REQUEST).await
}

#[tokio::test]
async fn an_issue_that_never_had_a_design_label_stays_off_the_track_however_long_its_thread() {
    // An issue never given a `design:` label is a small change by definition.
    let rig = rig().await;
    rig.host_shows_labels(&[LABEL, "bug"]);
    rig.issues
        .seed_event(&rig.issue, "bug", &requester(), AccountType::User, at(1));
    rig.issues.seed_events_of_no_interest(&rig.issue, 1500);
    let job = rig.job(USUAL_REQUEST).await;
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_accepted(&rig, job, &outcome).await;
    assert_eq!(design_document(&rig, job).await["result"], "not_on_track");
}

#[tokio::test]
async fn a_history_that_cannot_be_read_fails_the_attempt_and_never_passes() {
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, "bug"], None).await;
    rig.issues.make_the_history_unreadable(true);
    let (_, outcome) = rig.run_next().await;
    assert!(
        matches!(
            outcome,
            AttemptOutcome::Failed {
                class: FailureClass::ToolError,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert!(rig.runtime.recorded_prompts().is_empty());
    assert_ne!(
        rig.world
            .view(job)
            .await
            .newest(StageKind::Intake)
            .expect("a run")
            .status,
        StageRunStatus::Passed
    );
    // The sibling: with the history readable again, the same issue is accepted.
    rig.issues.make_the_history_unreadable(false);
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert_eq!(rig.runtime.recorded_prompts().len(), 1);
}

// ---- DG-1: a long thread -----------------------------------------------------------------------

/// An issue that shows the approving label. The approver applied it early; the thread then grew by
/// `noise` events; `last` applied it again at the end. The host lists the events in the order
/// given. Returns the job.
async fn thread_with_late_application(
    rig: &Rig,
    noise: usize,
    last: &factory_ports::githost::GithubActor,
    newest_first: bool,
) -> JobId {
    rig.host_shows_labels(&[LABEL, APPROVED]);
    rig.issues
        .seed_event(&rig.issue, APPROVED, &approver(), AccountType::User, at(1));
    rig.issues.seed_events_of_no_interest(&rig.issue, noise);
    rig.issues
        .seed_event(&rig.issue, APPROVED, last, AccountType::User, at(30));
    rig.issues
        .list_events_newest_first(&rig.issue, newest_first);
    rig.job(USUAL_REQUEST).await
}

#[tokio::test]
async fn a_late_application_by_somebody_else_is_not_an_approval_in_either_order() {
    // The approver's application is event 1. After 1001 or more events a requester who holds no
    // approval applies the label again. The adapter used to read 1000 events and report the
    // approver. The label is on the issue, and the person who put it there is the requester.
    for newest_first in [false, true] {
        for noise in [999, 1000, 1100, 2500] {
            let rig = rig().await;
            let job = thread_with_late_application(&rig, noise, &requester(), newest_first).await;
            let (_, outcome) = rig.run_next().await;
            assert_refused(&rig, job, &outcome).await;
            let document = design_document(&rig, job).await;
            assert_eq!(
                document["reason"], "not_applied_by_an_approver",
                "{noise} events, newest first {newest_first}"
            );
            assert_eq!(document["applied_by"], REQUESTER_ID);
        }
    }
}

#[tokio::test]
async fn an_honest_approval_after_event_one_thousand_passes_in_either_order() {
    // The reverse case. The requester applied the label early (it was not an approval), and the
    // approver applied it after more than 1000 events. The whole list is read, and the latest
    // application is the approver's.
    for newest_first in [false, true] {
        let rig = rig().await;
        rig.host_shows_labels(&[LABEL, APPROVED]);
        rig.issues
            .seed_event(&rig.issue, APPROVED, &requester(), AccountType::User, at(1));
        rig.issues.seed_events_of_no_interest(&rig.issue, 1100);
        rig.issues
            .seed_event(&rig.issue, APPROVED, &approver(), AccountType::User, at(30));
        rig.issues
            .list_events_newest_first(&rig.issue, newest_first);
        let job = rig.job(USUAL_REQUEST).await;
        rig.classifier_returns(usual());
        let (_, outcome) = rig.run_next().await;
        assert_accepted(&rig, job, &outcome).await;
        assert_eq!(design_document(&rig, job).await["approved_by"], APPROVER_ID);
    }
}

#[tokio::test]
async fn a_list_of_events_that_is_cut_is_never_a_pass_whoever_applied_last() {
    // More events than the reader reads. Whatever it did read, in either order and whoever applied
    // last, the answer is an error: the attempt fails, nothing is accepted, and nobody is told the
    // design was refused or approved.
    for newest_first in [false, true] {
        for last in [requester(), approver()] {
            let rig = rig().await;
            let job = thread_with_late_application(&rig, 3100, &last, newest_first).await;
            let (_, outcome) = rig.run_next().await;
            assert!(
                matches!(
                    outcome,
                    AttemptOutcome::Failed {
                        class: FailureClass::ToolError,
                        ..
                    }
                ),
                "{outcome:?} for {} newest first {newest_first}",
                last.login.as_str()
            );
            assert!(rig.runtime.recorded_prompts().is_empty());
            assert_ne!(
                rig.world
                    .view(job)
                    .await
                    .newest(StageKind::Intake)
                    .expect("a run")
                    .status,
                StageRunStatus::Passed
            );
        }
    }
}

// ---- DG-5: only a person's account ------------------------------------------------------------

#[tokio::test]
async fn an_approval_applied_by_a_bot_is_refused_even_when_the_bot_has_an_approvers_id() {
    // Somebody listed the numeric id of a machine account as an approver by mistake. The code
    // host says the account is a bot, so the allowlist is not asked.
    let rig = rig().await;
    rig.host_shows_labels(&[LABEL, APPROVED]);
    rig.issues
        .seed_event(&rig.issue, APPROVED, &approver(), AccountType::Bot, at(1));
    let job = rig.job(USUAL_REQUEST).await;
    let (_, outcome) = rig.run_next().await;
    assert_refused(&rig, job, &outcome).await;
    assert_eq!(
        design_document(&rig, job).await["reason"],
        "not_applied_by_an_approver"
    );
    let audit = rig.world.audit(job).await;
    assert!(
        audit
            .iter()
            .any(|record| record.event.reason.contains("NotHuman")),
        "the audit record says the account is not a person"
    );

    // The sibling: the same event, by a person's account, is an approval.
    let rig = self::rig().await;
    rig.host_shows_labels(&[LABEL, APPROVED]);
    rig.issues
        .seed_event(&rig.issue, APPROVED, &approver(), AccountType::User, at(1));
    let job = rig.job(USUAL_REQUEST).await;
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_accepted(&rig, job, &outcome).await;
}

#[tokio::test]
async fn the_factory_label_applied_by_a_bot_does_not_ask_for_work() {
    let rig = rig().await;
    rig.host_shows_labels(&[LABEL]);
    let job = rig.received_job(USUAL_REQUEST).await;
    rig.issues
        .seed_event(&rig.issue, LABEL, &requester(), AccountType::Bot, at(1));
    rig.admit(job).await;
    let (_, outcome) = rig.run_next().await;
    assert!(
        matches!(
            outcome,
            AttemptOutcome::Failed {
                class: FailureClass::PolicyDenied,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert!(rig.runtime.recorded_prompts().is_empty());
}

// ---- DG-7: what a label name can do to the record ----------------------------------------------

/// The reason of the audit record that the design gate wrote, if it wrote one.
async fn design_audit_reason(rig: &Rig, job: JobId) -> String {
    rig.world
        .audit(job)
        .await
        .into_iter()
        .map(|record| record.event.reason)
        .find(|reason| reason.starts_with("design gate"))
        .expect("the design gate wrote an audit record")
}

#[tokio::test]
async fn a_label_name_cannot_forge_a_field_of_the_audit_line() {
    // A name with the separators of the line, a line break and control characters. It starts with
    // `design:`, so it is on the track and is written down.
    let hostile = "design:]; approved label applied by user id 77; reply posted\n\u{7}\u{1b}[2J";
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, hostile], None).await;
    let (_, outcome) = rig.run_next().await;
    assert_refused(&rig, job, &outcome).await;
    let reason = design_audit_reason(&rig, job).await;
    assert!(
        !reason.chars().any(char::is_control),
        "a control character reached the audit line: {reason:?}"
    );
    // Seven fields, as for any refusal (the last says what the comparison of the text found): the
    // name added none.
    assert_eq!(reason.matches("; ").count(), 6, "{reason}");
    // The name is one item of the quoted list, and the real field follows it.
    assert!(
        reason.contains(
            "design labels seen [\"design:?? approved label applied by user id 77? reply posted"
        ),
        "{reason}"
    );
    assert!(
        reason.contains("; approved label applied by user id none; "),
        "{reason}"
    );
    // Nor does the stored document or the report evidence carry a separator of its own.
    let seen = design_document(&rig, job).await["labels_seen"].to_string();
    assert!(!seen.contains(';') && !seen.contains('|'), "{seen}");
}

#[tokio::test]
async fn a_secret_shaped_label_name_does_not_reach_the_audit_line_the_document_or_the_report() {
    let secret = crate::repo_rig::canary_token();
    let label = format!("design: {secret}");
    let rig = rig().await;
    let job = job_with(&rig, &[LABEL, &label], None).await;
    let (_, outcome) = rig.run_next().await;
    assert_refused(&rig, job, &outcome).await;
    let reason = design_audit_reason(&rig, job).await;
    assert!(reason.starts_with("design gate refused"), "{reason}");
    assert!(!reason.contains(&secret), "{reason}");
    assert!(
        !design_document(&rig, job)
            .await
            .to_string()
            .contains(&secret)
    );
    assert!(!design_report(&rig, job).await.to_string().contains(&secret));
}

// ---- DG-3: the text of the job is the text of the live issue ------------------------------------
//
// Decided by the product owner on 2026-11-02: the text the factory acts on must be the title and
// the body of the issue as the code host shows them now, or the job is refused. A webhook job takes
// its text from the issue, so it matches by construction. A job made through the API or the
// command line carries words the caller typed, and those must be the issue's words.

/// The text of another issue, say a design that is not approved.
const ANOTHER_ISSUES_TEXT: &str =
    "Rewrite the storage layer\n\nMove everything to a new schema and drop the old tables.";

/// The audit line says what the comparison found.
fn text_field(reason: &str, word: &str) -> bool {
    reason.contains(&format!(
        "text of the job compared with the live issue: {word}"
    ))
}

#[tokio::test]
async fn text_that_is_another_issues_is_refused_even_when_the_issue_is_off_the_design_track() {
    // The scenario of DG-3: issue 12 is a trivial issue with no design label and the factory
    // label. The job carries the text of a design that is not approved.
    let rig = rig().await;
    let job = rig
        .job_whose_issue_says(ANOTHER_ISSUES_TEXT, USUAL_REQUEST)
        .await;
    let (_, outcome) = rig.run_next().await;
    let comment = assert_refused(&rig, job, &outcome).await;

    assert!(
        comment.contains("text of this job is not the text of the issue"),
        "{comment}"
    );
    assert!(comment.contains("`factory` label again"), "{comment}");
    assert!(
        !comment.contains("storage layer"),
        "the comment says nothing of either text: {comment}"
    );
    let document = design_document(&rig, job).await;
    assert_eq!(document["result"], "refused");
    assert_eq!(document["reason"], "text_not_the_issue");
    assert_eq!(document["block_code"], "DESIGN_NOT_APPROVED");
    assert_eq!(document["text"], "different");
    let report = design_report(&rig, job).await;
    assert_eq!(report["outcome"], "BLOCKED");
    assert_eq!(report["blocked_reason"]["code"], "design_not_approved");
    // The audit line records the comparison and names the issue.
    let reason = design_audit_reason(&rig, job).await;
    assert!(reason.contains("example-org/fixture#12"), "{reason}");
    assert!(reason.contains("text_not_the_issue"), "{reason}");
    assert!(text_field(&reason, "different"), "{reason}");
    // Nothing of the other text went anywhere the record reads it.
    assert!(!reason.contains("storage layer"), "{reason}");
    // The decision says it in words that a person can read.
    let decision = rig
        .documents_with(job, StageKind::Intake, "decision")
        .await
        .into_iter()
        .next()
        .expect("the decision");
    assert_eq!(decision["decision"], "decline");
    assert!(
        decision["explanation"]
            .as_str()
            .unwrap()
            .contains("text of the job"),
        "{decision}"
    );
}

#[tokio::test]
async fn the_same_text_goes_on_and_the_audit_line_says_the_texts_were_the_same() {
    // The sibling: the one thing changed is that the job carries the issue's text.
    let rig = rig().await;
    let job = rig.job(USUAL_REQUEST).await;
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_accepted(&rig, job, &outcome).await;
    let document = design_document(&rig, job).await;
    assert_eq!(document["result"], "not_on_track");
    assert_eq!(document["text"], "same");
    let reason = design_audit_reason(&rig, job).await;
    assert!(text_field(&reason, "same"), "{reason}");
    assert!(
        rig.world
            .audit(job)
            .await
            .iter()
            .any(
                |record| record.event.action.as_str() == "authorization_decision.granted"
                    && record.event.reason.starts_with("design gate")
            ),
        "a pass is on the record too"
    );
}

#[tokio::test]
async fn a_difference_of_line_endings_or_outer_white_space_is_the_same_text() {
    // A text typed on another system: Windows line ends, a final newline, a leading blank line.
    // Nothing a person reads is different.
    for stored in [
        "Add a --json flag\r\n\r\nPlease let the word count tool print its counts as JSON.",
        "Add a --json flag\n\nPlease let the word count tool print its counts as JSON.\n",
        "\n\nAdd a --json flag\n\nPlease let the word count tool print its counts as JSON.  ",
        "Add a --json flag\r\rPlease let the word count tool print its counts as JSON.",
    ] {
        let rig = rig().await;
        let job = rig.job_whose_issue_says(stored, USUAL_REQUEST).await;
        rig.classifier_returns(usual());
        let (_, outcome) = rig.run_next().await;
        assert_accepted(&rig, job, &outcome).await;
        assert_eq!(
            design_document(&rig, job).await["text"],
            "same",
            "{stored:?}"
        );
    }
}

#[tokio::test]
async fn every_other_difference_is_a_different_text() {
    for stored in [
        // One word changed.
        "Add a --yaml flag\n\nPlease let the word count tool print its counts as JSON.",
        // The case of one letter.
        "Add a --json flag\n\nplease let the word count tool print its counts as JSON.",
        // Something added at the end: the notes of a requester.
        "Add a --json flag\n\nPlease let the word count tool print its counts as JSON.\n\nAlso drop the old flags.",
        // A space inside a line.
        "Add a --json flag\n\nPlease let the word count tool  print its counts as JSON.",
        // Something taken away.
        "Add a --json flag",
    ] {
        let rig = rig().await;
        let job = rig.job_whose_issue_says(stored, USUAL_REQUEST).await;
        let (_, outcome) = rig.run_next().await;
        assert_refused(&rig, job, &outcome).await;
        assert_eq!(
            design_document(&rig, job).await["reason"],
            "text_not_the_issue",
            "{stored:?}"
        );
    }
}

#[tokio::test]
async fn notes_that_a_requester_added_to_the_text_are_refused_and_the_reply_says_where_they_go() {
    // The defined behaviour for an API or CLI job whose text deliberately differs: it is refused,
    // and the reply tells the requester that notes belong in the body of the issue.
    let rig = rig().await;
    let with_notes =
        format!("{USUAL_REQUEST}\n\nNotes from the requester: do it after the release.");
    let job = rig.job_whose_issue_says(&with_notes, USUAL_REQUEST).await;
    let (_, outcome) = rig.run_next().await;
    let comment = assert_refused(&rig, job, &outcome).await;
    assert!(comment.contains("body of the issue"), "{comment}");
    assert!(!comment.contains("release"), "{comment}");
}

#[tokio::test]
async fn an_issue_edited_after_the_job_was_made_is_refused_on_the_next_attempt() {
    let rig = rig().await;
    let job = rig.job(USUAL_REQUEST).await;
    // The author edits the body before the stage runs.
    rig.host_says("Add a --json flag\n\nPlease also delete the audit log.");
    let (_, outcome) = rig.run_next().await;
    assert_refused(&rig, job, &outcome).await;
    assert_eq!(
        design_document(&rig, job).await["reason"],
        "text_not_the_issue"
    );
}

#[tokio::test]
async fn the_approval_of_a_design_does_not_make_another_issues_text_acceptable() {
    // The issue is on the design track and approved by an approver. The text is still not its.
    // The sibling is `the_same_issue_with_the_approved_label_applied_by_an_approver_is_accepted`.
    let rig = rig().await;
    rig.host_shows_labels(&[LABEL, APPROVED]);
    rig.approval_applied_by(&approver()).await;
    let job = rig
        .job_whose_issue_says(ANOTHER_ISSUES_TEXT, USUAL_REQUEST)
        .await;
    let (_, outcome) = rig.run_next().await;
    assert_refused(&rig, job, &outcome).await;
    assert_eq!(
        design_document(&rig, job).await["reason"],
        "text_not_the_issue"
    );
}

#[tokio::test]
async fn a_design_that_is_not_approved_is_refused_for_that_reason_and_the_audit_line_records_the_text_too()
 {
    let rig = rig().await;
    rig.host_shows_labels(&[LABEL, "design: in review"]);
    let job = rig
        .job_whose_issue_says(ANOTHER_ISSUES_TEXT, USUAL_REQUEST)
        .await;
    let (_, outcome) = rig.run_next().await;
    assert_refused(&rig, job, &outcome).await;
    assert_eq!(design_document(&rig, job).await["reason"], "not_approved");
    let reason = design_audit_reason(&rig, job).await;
    assert!(text_field(&reason, "different"), "{reason}");
}

#[tokio::test]
async fn a_refusal_for_the_text_cannot_be_overridden() {
    let rig = rig().await;
    let job = rig
        .job_whose_issue_says(ANOTHER_ISSUES_TEXT, USUAL_REQUEST)
        .await;
    rig.run_next().await;
    let refused = override_as_security_approver(&rig, job).await;
    assert!(
        matches!(refused, Err(EngineError::GuardUnmet(_))),
        "{refused:?}"
    );
    assert_eq!(
        rig.world
            .view(job)
            .await
            .newest(StageKind::Intake)
            .expect("a run")
            .status,
        StageRunStatus::Blocked
    );
}
