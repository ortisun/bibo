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
use factory_domain::vocabulary::{HumanRole, StageKind};
use factory_ports::githost::{GitScope, IssueSource};
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
async fn a_look_alike_beside_a_real_design_label_does_not_hide_it() {
    // A name that does not begin with `design:` at all is just another label: it does not put the
    // issue on the track, and it does not take it off.
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
        serde_json::json!(["design: proposed"])
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

#[tokio::test]
async fn a_comment_that_cannot_be_posted_now_fails_the_attempt_and_is_tried_again() {
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
    // The run is not blocked and nothing was accepted: the attempt is retried.
    let status = rig
        .world
        .view(job)
        .await
        .newest(StageKind::Intake)
        .expect("a run")
        .status;
    assert_ne!(status, StageRunStatus::Passed);
    assert!(rig.replies.posted().is_empty());
    assert_eq!(rig.replies.asked(), 1);
    // The host comes back, and the retry answers once.
    rig.replies.set(ReplyMode::Works);
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert_eq!(rig.replies.posted().len(), 1);
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
        Reply::CannotCheck,
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
