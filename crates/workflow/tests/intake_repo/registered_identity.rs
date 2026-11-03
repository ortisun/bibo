//! RH-3: the person who applied `design: approved` is judged by the registered repository's GitHub
//! id first, the way the claim hook and the API judge a person (RR-28), and by the name only for an
//! allowlist entry that lists no id.
//!
//! Before the fix the design gate asked with the name alone (`RepositoryIdentity::by_name_only`), so
//! an entry with an id meant "the name recorded next to the id", and a person narrowed by id to a
//! repository that had been deleted kept the approval on a new repository registered under the old
//! name. In these tests the registered row of the rig is the repository `example-org/fixture` with
//! the id `REGISTERED_ID`, and a test edits the row to show a repository that was renamed,
//! transferred or re-created. Each refusal has a sibling that is accepted, so a refusal is for the
//! reason in its name and not because the setup is wrong.

use factory_domain::ids::JobId;
use factory_domain::machines::failure::FailureClass;
use factory_domain::policy::decision::Designation;
use factory_workflow::engine::AttemptOutcome;
use serde_json::Value;

use crate::harness::{LABEL, Rig, USUAL_REQUEST, usual};
use crate::repo_rig::REGISTERED_ID;

const APPROVER_ID: u64 = 2002;
const APPROVED: &str = "design: approved";
/// The name the repository had when the allowlist entry was written.
const OLD_NAME: &str = "example-org/old-name";
/// A repository that is not the registered one.
const ANOTHER_REPOSITORY: u64 = 9000;

async fn rig() -> Rig {
    let rig = Rig::new().await;
    rig.allowlist
        .add(APPROVER_ID, "approver-one", vec![Designation::Approver]);
    rig
}

/// A job on an issue that carries the approved label, applied by `by`.
async fn approved_by(rig: &Rig, by: &factory_ports::githost::GithubActor) -> JobId {
    rig.host_shows_labels(&[LABEL, APPROVED]);
    rig.approval_applied_by(by).await;
    rig.job(USUAL_REQUEST).await
}

fn approver() -> factory_ports::githost::GithubActor {
    Rig::actor(APPROVER_ID, "approver-one")
}

async fn accepted(rig: &Rig, job: JobId) {
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert_eq!(
        rig.runtime.recorded_prompts().len(),
        1,
        "the classifier ran"
    );
    assert!(
        rig.replies.posted().is_empty(),
        "{:?}",
        rig.replies.posted()
    );
    assert_eq!(
        rig.documents_with(
            job,
            factory_domain::vocabulary::StageKind::Intake,
            "approving_label"
        )
        .await
        .into_iter()
        .next()
        .expect("a design document")["approved_by"],
        APPROVER_ID
    );
}

/// The design is refused because the person is not an approver of this repository: the stage run
/// is blocked, no agent read anything, and the audit line names the repository as the reason.
async fn refused_as_not_listed(rig: &Rig, job: JobId) {
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert!(
        rig.runtime.recorded_prompts().is_empty(),
        "no agent read it"
    );
    let document: Value = rig
        .documents_with(
            job,
            factory_domain::vocabulary::StageKind::Intake,
            "approving_label",
        )
        .await
        .into_iter()
        .next()
        .expect("a design document");
    assert_eq!(document["reason"], "not_applied_by_an_approver");
    let audit = rig.world.audit(job).await;
    assert!(
        audit.iter().any(|record| record
            .event
            .reason
            .contains("not_applied_by_an_approver: RepositoryNotListed")),
        "the audit line says the entry is narrowed away from this repository"
    );
}

#[tokio::test]
async fn an_approver_narrowed_by_id_still_approves_after_the_repository_was_renamed() {
    // The entry was written under the old name. The registered row has the new name and the same id.
    let rig = rig().await;
    rig.allowlist
        .narrow_by_id(APPROVER_ID, &[(OLD_NAME, REGISTERED_ID)]);
    let job = approved_by(&rig, &approver()).await;
    accepted(&rig, job).await;
}

#[tokio::test]
async fn an_approver_narrowed_by_id_still_approves_after_the_repository_was_transferred() {
    // The owner changed too: nothing in the name is the same, the id is.
    let rig = rig().await;
    rig.allowlist
        .narrow_by_id(APPROVER_ID, &[(OLD_NAME, REGISTERED_ID)]);
    rig.registered.register_as("new-owner/moved", REGISTERED_ID);
    let job = approved_by(&rig, &approver()).await;
    accepted(&rig, job).await;
}

#[tokio::test]
async fn an_approver_narrowed_by_id_does_not_approve_a_new_repository_under_the_old_name() {
    // The control of the two tests above: the same entry, the registered row has the name of the
    // entry and another id. This is the RR-28 scenario at the one place of the design that had no
    // first layer.
    let rig = rig().await;
    rig.allowlist
        .narrow_by_id(APPROVER_ID, &[("example-org/fixture", REGISTERED_ID)]);
    rig.registered
        .register_as("example-org/fixture", ANOTHER_REPOSITORY);
    let job = approved_by(&rig, &approver()).await;
    refused_as_not_listed(&rig, job).await;
}

#[tokio::test]
async fn a_new_repository_that_took_the_old_name_is_refused_while_the_old_one_is_accepted() {
    // The same entry, the same name, two registered rows: only the one with the listed id approves.
    let listed = rig().await;
    listed
        .allowlist
        .narrow_by_id(APPROVER_ID, &[(OLD_NAME, REGISTERED_ID)]);
    listed.registered.register_as(OLD_NAME, REGISTERED_ID);
    let job = approved_by(&listed, &approver()).await;
    accepted(&listed, job).await;

    let recreated = rig().await;
    recreated
        .allowlist
        .narrow_by_id(APPROVER_ID, &[(OLD_NAME, REGISTERED_ID)]);
    recreated
        .registered
        .register_as(OLD_NAME, ANOTHER_REPOSITORY);
    let job = approved_by(&recreated, &approver()).await;
    refused_as_not_listed(&recreated, job).await;
}

#[tokio::test]
async fn an_approver_is_found_by_the_numeric_user_id_whatever_login_applied_the_label() {
    // The id is the person. The login of the entry is for display and the login on the label
    // decides nothing, with the narrowing by repository id on or off.
    let rig = rig().await;
    rig.allowlist
        .narrow_by_id(APPROVER_ID, &[("example-org/fixture", REGISTERED_ID)]);
    let renamed_person = Rig::actor(APPROVER_ID, "a-login-the-entry-never-heard-of");
    let job = approved_by(&rig, &renamed_person).await;
    accepted(&rig, job).await;

    // The converse: the login of the entry on an account with another id holds nothing.
    let rig = rig_for_a_namesake().await;
    let namesake = Rig::actor(APPROVER_ID + 1, "approver-one");
    let job = approved_by(&rig, &namesake).await;
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    assert!(rig.runtime.recorded_prompts().is_empty());
    let audit = rig.world.audit(job).await;
    assert!(
        audit.iter().any(|record| record
            .event
            .reason
            .contains("not_applied_by_an_approver: NotAllowed")),
        "a login is not an id"
    );
}

async fn rig_for_a_namesake() -> Rig {
    let rig = rig().await;
    rig.allowlist
        .narrow_by_id(APPROVER_ID, &[("example-org/fixture", REGISTERED_ID)]);
    rig
}

#[tokio::test]
async fn an_entry_with_no_id_is_judged_by_the_registered_name_without_regard_to_case() {
    // The weaker form of RR-28 is still honoured, and it follows the name of the registered row.
    let named = rig().await;
    named
        .allowlist
        .narrow(APPROVER_ID, &["Example-Org/Fixture"]);
    let job = approved_by(&named, &approver()).await;
    accepted(&named, job).await;

    // The registered row has another name now: the entry that names the old one does not follow
    // it. (The issue the job came from still says `example-org/fixture`; the row decides.)
    let moved = rig().await;
    moved
        .allowlist
        .narrow(APPROVER_ID, &["example-org/fixture"]);
    moved
        .registered
        .register_as("example-org/renamed", REGISTERED_ID);
    let job = approved_by(&moved, &approver()).await;
    refused_as_not_listed(&moved, job).await;
}

#[tokio::test]
async fn an_entry_that_is_not_narrowed_approves_whatever_the_row_says() {
    let rig = rig().await;
    rig.registered
        .register_as("anyone/anything", ANOTHER_REPOSITORY);
    let job = approved_by(&rig, &approver()).await;
    accepted(&rig, job).await;
}

#[tokio::test]
async fn a_registered_row_that_cannot_be_read_never_approves_and_the_attempt_is_tried_again() {
    let rig = rig().await;
    rig.allowlist
        .narrow_by_id(APPROVER_ID, &[(OLD_NAME, REGISTERED_ID)]);
    rig.registered.down();
    let job = approved_by(&rig, &approver()).await;
    let (_, outcome) = rig.run_next().await;
    assert!(
        matches!(
            outcome,
            AttemptOutcome::Failed {
                class: FailureClass::ToolError,
                ..
            }
        ),
        "the read failed, so the attempt failed: {outcome:?}"
    );
    assert!(
        rig.runtime.recorded_prompts().is_empty(),
        "no agent read it"
    );
    assert!(
        rig.world
            .audit(job)
            .await
            .iter()
            .all(|record| !record.event.reason.contains("design gate passed")),
        "nothing was approved"
    );
    // The control: the store answers again and the same job goes through.
    rig.registered
        .register_as("example-org/fixture", REGISTERED_ID);
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
}

#[tokio::test]
async fn a_job_whose_repository_has_no_row_never_approves() {
    // Not even an entry by name that matches the issue: with no row there is no registered
    // identity, and the gate does not fall back to the name of the issue.
    let rig = rig().await;
    rig.allowlist.narrow(APPROVER_ID, &["example-org/fixture"]);
    rig.registered.gone();
    let job = approved_by(&rig, &approver()).await;
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
    assert!(
        rig.world
            .audit(job)
            .await
            .iter()
            .all(|record| !record.event.reason.contains("design gate passed"))
    );
}

#[test]
fn the_pure_judgement_refuses_an_approval_it_was_given_no_registered_identity_for() {
    // `DesignJudge` always hands the identity over when an approval is asked about; the function
    // that decides must still not approve without it, and must not look for a name anywhere else.
    use factory_domain::ids::TenantId;
    use factory_domain::policy::authority::{Allowlist, AllowlistEntry, RepositoryIdentity};
    use factory_domain::policy::decision::GithubUserId;
    use factory_domain::policy::issue_workflow::DesignLabels;
    use factory_domain::values::Timestamp;
    use factory_ports::githost::AccountType;
    use factory_workflow::stages::intake::design::{
        ApprovalCoverage, DesignDecision, Judging, RefusalReason, TextCheck, judge,
    };
    use factory_workflow::stages::intake::{DenialReason, Labeller};

    let tenant = TenantId::parse("018f3a00-0000-7000-8000-00000000c001").expect("tenant");
    let now = Timestamp::parse("2026-11-03T12:00:00Z").expect("time");
    let list = Allowlist::new(
        "allowlist-v1-test",
        vec![AllowlistEntry {
            tenant,
            github_user_id: GithubUserId::new(APPROVER_ID).expect("an id"),
            login: "approver-one".to_owned(),
            designations: [Designation::Approver].into_iter().collect(),
            repositories: None,
            expires_at: None,
        }],
    )
    .expect("a list");
    let gate = factory_testkit::issue_status::design_gate();
    let policy = crate::harness::policy_engine();
    let person = Labeller {
        id: APPROVER_ID,
        login: "approver-one",
        account: AccountType::User,
    };
    let decide = |repository| {
        judge(
            &Judging {
                gate: &gate,
                authority: &policy.authority,
                allowlist: &list,
                tenant,
                repository,
                now: &now,
            },
            DesignLabels::ApprovalLabelOnly,
            Some(person),
            TextCheck::Same,
            ApprovalCoverage::Covers,
        )
    };

    // The control: with the registered identity this entry, which is not narrowed, approves.
    assert!(matches!(
        decide(Some(RepositoryIdentity::registered(
            "example-org/fixture",
            REGISTERED_ID
        ))),
        DesignDecision::Approved {
            approver: APPROVER_ID,
            ..
        }
    ));
    // Without it nothing is approved, for an entry that would have been, and the reason is the one
    // of a repository the entry does not reach.
    assert!(matches!(
        decide(None),
        DesignDecision::Refused {
            reason: RefusalReason::NotAnApprover(DenialReason::RepositoryNotListed),
            applied_by: Some(APPROVER_ID),
            ..
        }
    ));
}

#[tokio::test]
async fn an_issue_off_the_design_track_needs_no_row() {
    // The row is read for the judgement of an approver and for nothing else: an ordinary issue is
    // accepted when the store cannot be read, as it was before.
    let rig = rig().await;
    rig.registered.down();
    rig.host_shows_labels(&[LABEL, "bug"]);
    let job = rig.job(USUAL_REQUEST).await;
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
    let _ = job;
    assert_eq!(rig.runtime.recorded_prompts().len(), 1);
}
