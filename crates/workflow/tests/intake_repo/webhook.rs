//! A job that a webhook created has no issue text: the verified payload carries none and the API
//! holds no credential for the code host. The intake stage fetches the issue through the
//! `IssueSource` port when it runs and stores it as revision 1 of the original request.
//!
//! The issue source here is the testkit's fake (fidelity `fake`), and so is the request source of
//! the rig, over the in-memory store. What is real is the engine, the intake handler, the gates
//! and the readability check.

use factory_domain::state::{JobStatus, StageRunStatus};
use factory_domain::vocabulary::StageKind;
use factory_ports::store::RequestSource as StoreRequestSource;
use factory_testkit::githost::{FakeIssueSource, IssueSourceDefect};
use factory_workflow::engine::AttemptOutcome;
use factory_workflow::stages::intake::RequestSource as _;

use crate::harness::{Options, REQUESTER_ID, Rig, usual};

async fn stored_request(
    rig: &Rig,
    job: factory_domain::ids::JobId,
) -> Option<factory_ports::store::OriginalRequest> {
    let mut tx = rig
        .world
        .store
        .begin(factory_domain::scope::TenantScope::new(rig.world.tenant))
        .await
        .expect("a tx");
    let found = tx.get_original_request(job, None).await.ok();
    tx.rollback().await.expect("rollback");
    found
}

#[tokio::test]
async fn a_webhook_job_has_its_issue_fetched_and_recorded_as_revision_one() {
    let rig = Rig::new().await;
    rig.host_has_issue(
        "Add a --json flag",
        "Please let the word count tool print its counts as JSON.",
        REQUESTER_ID,
    );
    let job = rig.webhook_job().await;
    assert!(
        stored_request(&rig, job).await.is_none(),
        "the job starts with no text, as the API leaves it"
    );
    rig.classifier_returns(usual());

    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);

    // Revision 1 is the live issue, title and body as one text, byte for byte.
    let stored = stored_request(&rig, job).await.expect("a stored request");
    assert_eq!(stored.revision, 1);
    assert_eq!(
        stored.text,
        "Add a --json flag\n\nPlease let the word count tool print its counts as JSON."
    );
    assert_eq!(stored.source, StoreRequestSource::GithubIssue);
    assert_eq!(stored.source_ref.as_deref(), Some("example-org/fixture#12"));
    assert_eq!(stored.author_github_user_id, Some(REQUESTER_ID));

    // The stage went on as it does for any other job: the classifier read the fetched text and the
    // stage passed.
    let view = rig.world.view(job).await;
    assert_eq!(
        view.newest(StageKind::Intake).expect("a run").status,
        StageRunStatus::Passed
    );
    assert_eq!(rig.runtime.recorded_prompts().len(), 1);
    let normalized = rig.documents_with(job, StageKind::Intake, "original").await;
    assert_eq!(
        normalized[0]["original"]["sha256"],
        serde_json::json!(stored.content_sha256)
    );
    assert!(
        rig.requests.recorded(job).is_some(),
        "the hash is now known"
    );
}

#[tokio::test]
async fn a_job_that_already_has_text_is_not_fetched_again_and_is_refused_when_the_issue_says_other_words()
 {
    let rig = Rig::new().await;
    // The host holds other words than the stored request: they must not replace it (DG-3: and the
    // job does not go on with words that are not the issue's).
    rig.host_has_issue(
        "Other title",
        "Other words that must not be read.",
        REQUESTER_ID,
    );
    let job = rig
        .job("Add a --json flag\n\nPlease print counts as JSON.")
        .await;
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    let stored = stored_request(&rig, job).await.expect("a stored request");
    assert_eq!(
        stored.text,
        "Add a --json flag\n\nPlease print counts as JSON."
    );
    assert!(
        rig.runtime.recorded_prompts().is_empty(),
        "the classifier read nothing: the text is not the issue's"
    );
    assert_eq!(
        rig.world.view(job).await.status,
        JobStatus::Blocked,
        "the job is refused, visibly"
    );
}

#[tokio::test]
async fn a_webhook_job_matches_its_issue_by_construction_and_the_audit_line_says_so() {
    let rig = Rig::new().await;
    rig.host_has_issue(
        "Add a --json flag",
        "Please let the word count tool print its counts as JSON.",
        REQUESTER_ID,
    );
    let job = rig.webhook_job().await;
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    assert_eq!(
        rig.world
            .view(job)
            .await
            .newest(StageKind::Intake)
            .expect("a run")
            .status,
        StageRunStatus::Passed
    );
    let audit = rig.world.audit(job).await;
    assert!(
        audit.iter().any(|record| record
            .event
            .reason
            .contains("text of the job compared with the live issue: same")),
        "{:?}",
        audit
            .iter()
            .map(|record| record.event.reason.as_str())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_webhook_job_whose_issue_holds_a_secret_still_matches_because_both_sides_are_redacted() {
    // The text that is stored has each secret replaced. The live text is replaced the same way
    // before the two are compared, so an issue with a secret in it is not a different text.
    let secret = crate::repo_rig::canary_token();
    let rig = Rig::new().await;
    rig.host_has_issue(
        "Add a --json flag",
        &format!("Please print counts as JSON. The key is {secret}."),
        REQUESTER_ID,
    );
    let job = rig.webhook_job().await;
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    let stored = stored_request(&rig, job).await.expect("a stored request");
    assert!(
        !stored.text.contains(&secret),
        "the secret never reaches the store"
    );
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

#[tokio::test]
async fn a_webhook_job_whose_issue_cannot_be_fetched_never_reaches_the_classifier() {
    let rig = Rig::new().await;
    // The label is on the issue but the host has no such issue: deleted, or moved.
    let job = rig.webhook_job().await;
    let mut attempts = 0;
    for _ in 0..3 {
        rig.world.advance(400);
        let claimed = rig
            .engine
            .claim_next(&crate::support::world::World::worker("worker-1"))
            .await
            .expect("claim");
        for attempt in claimed.started {
            let outcome = rig.engine.run_attempt(&attempt).await.expect("it runs");
            assert_ne!(outcome, AttemptOutcome::Succeeded, "{outcome:?}");
            attempts += 1;
        }
    }
    assert!(
        attempts >= 1,
        "the stage was started and ended without the text, it was not just never offered"
    );
    assert!(
        rig.runtime.recorded_prompts().is_empty(),
        "no agent read anything"
    );
    assert!(
        stored_request(&rig, job).await.is_none(),
        "nothing was invented"
    );
    let view = rig.world.view(job).await;
    assert_ne!(
        view.newest(StageKind::Intake).expect("a run").status,
        StageRunStatus::Passed
    );
    assert_ne!(view.status, JobStatus::Completed);
}

#[tokio::test]
async fn a_webhook_job_whose_issue_is_empty_never_reaches_the_classifier() {
    let rig = Rig::new().await;
    rig.host_has_issue("", "", REQUESTER_ID);
    let job = rig.webhook_job().await;
    rig.world.advance(400);
    let claimed = rig
        .engine
        .claim_next(&crate::support::world::World::worker("worker-1"))
        .await
        .expect("claim");
    assert_eq!(
        claimed.started.len(),
        1,
        "the stage was offered and started"
    );
    for attempt in claimed.started {
        let outcome = rig.engine.run_attempt(&attempt).await.expect("it runs");
        assert_ne!(outcome, AttemptOutcome::Succeeded);
    }
    assert!(rig.runtime.recorded_prompts().is_empty());
    assert!(stored_request(&rig, job).await.is_none());
}

/// The break. An issue source that invents an issue for a reference it does not know (the fake's
/// documented defect, caught by `an_unknown_issue_is_not_found` in the contract suite of the
/// testkit) lets a webhook job proceed on words nobody wrote. The test above that expects the job
/// to stop is a real check: on the defective host it fails, which is what this test shows by
/// asserting the opposite on the same job.
#[tokio::test]
async fn break_an_issue_source_that_invents_an_issue_lets_the_job_proceed() {
    let rig = Rig::build(Options {
        issue_source: Some(FakeIssueSource::with_defect(
            IssueSourceDefect::InventsUnknownIssue,
        )),
        ..Options::default()
    })
    .await;
    let job = rig.webhook_job().await;
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_eq!(
        outcome,
        AttemptOutcome::Succeeded,
        "the defective host got the job through"
    );
    let stored = stored_request(&rig, job)
        .await
        .expect("invented text was stored");
    assert_eq!(stored.text, "invented");
    assert_eq!(rig.runtime.recorded_prompts().len(), 1);
}

// ---- AUT-11: the snapshot is checked against the label before it is stored ----------------------

/// Runs the intake attempt of a webhook job and says it did not pass: no agent read anything and no
/// text was stored.
async fn refused_and_nothing_stored(rig: &Rig, job: factory_domain::ids::JobId, why: &str) {
    rig.world.advance(400);
    let claimed = rig
        .engine
        .claim_next(&crate::support::world::World::worker("worker-1"))
        .await
        .expect("claim");
    assert_eq!(claimed.started.len(), 1, "{why}: the stage was started");
    for attempt in claimed.started {
        let outcome = rig.engine.run_attempt(&attempt).await.expect("it runs");
        assert_ne!(outcome, AttemptOutcome::Succeeded, "{why}: {outcome:?}");
    }
    assert!(
        rig.runtime.recorded_prompts().is_empty(),
        "{why}: no agent read it"
    );
    assert!(
        stored_request(rig, job).await.is_none(),
        "{why}: nothing was stored"
    );
}

fn at(text: &str) -> factory_domain::values::Timestamp {
    factory_domain::values::Timestamp::parse(text).expect("a time")
}

/// The issue was last changed at 10:00:00 (`host_has_issue`). The label went on at 09:00:00, so
/// someone changed the issue an hour after the person who applied it looked.
#[tokio::test]
async fn aut_11_an_issue_changed_after_the_label_is_refused_and_nothing_is_stored() {
    let rig = Rig::new().await;
    rig.host_has_issue("Add a --json flag", "Words the author put in later.", 4242);
    let job = rig.webhook_job().await;
    rig.issues.seed_label_at(
        &rig.issue,
        crate::harness::LABEL,
        &Rig::actor(REQUESTER_ID, "requester-one"),
        at("2026-10-28T09:00:00Z"),
    );
    rig.classifier_returns(usual());
    refused_and_nothing_stored(&rig, job, "edited after the label").await;
}

/// The label and the issue's last change are in the same second or a few seconds apart: applying a
/// label is a change to the issue. That is not an edit.
#[tokio::test]
async fn aut_11_an_issue_last_changed_when_the_label_went_on_is_recorded() {
    for applied in [
        "2026-10-28T10:00:00Z",
        "2026-10-28T09:59:57Z",
        "2026-10-28T10:00:03Z",
    ] {
        let rig = Rig::new().await;
        rig.host_has_issue(
            "Add a --json flag",
            "Please let the word count tool print its counts as JSON.",
            REQUESTER_ID,
        );
        let job = rig.webhook_job().await;
        rig.issues.seed_label_at(
            &rig.issue,
            crate::harness::LABEL,
            &Rig::actor(REQUESTER_ID, "requester-one"),
            at(applied),
        );
        rig.classifier_returns(usual());
        let (_, outcome) = rig.run_next().await;
        assert_eq!(outcome, AttemptOutcome::Succeeded, "{applied}");
        assert!(stored_request(&rig, job).await.is_some(), "{applied}");
    }
}

/// A host that cannot say when the label went on gives no time, and the time check is not made.
/// This is the case of every source that keeps no timeline; the code host adapter always has one.
#[tokio::test]
async fn aut_11_a_label_with_no_time_is_not_compared() {
    let rig = Rig::new().await;
    rig.host_has_issue(
        "Add a --json flag",
        "Please print counts as JSON.",
        REQUESTER_ID,
    );
    // `seed_label` records the actor and no time.
    let job = rig.webhook_job().await;
    rig.classifier_returns(usual());
    let (_, outcome) = rig.run_next().await;
    assert_eq!(outcome, AttemptOutcome::Succeeded);
    assert!(stored_request(&rig, job).await.is_some());
}

/// The label is not on the issue any more: nobody asked, and the text is not stored for later.
#[tokio::test]
async fn aut_11_an_issue_whose_label_is_gone_is_refused_and_nothing_is_stored() {
    let rig = Rig::new().await;
    rig.host_has_issue(
        "Add a --json flag",
        "Please print counts as JSON.",
        REQUESTER_ID,
    );
    let job = rig
        .engine
        .receive_job(rig.world.tenant, rig.world.requester, rig.world.repository)
        .await
        .expect("receive");
    rig.requests.await_issue(job, rig.issue.clone());
    // No `label_applied_by`: the host has no application of the label.
    rig.admit(job).await;
    rig.classifier_returns(usual());
    refused_and_nothing_stored(&rig, job, "no label").await;
}

/// The label was applied by a person who is not on the allowlist, by numeric id: the login on it is
/// the requester's, and the id is not.
#[tokio::test]
async fn aut_11_a_label_applied_by_someone_unlisted_is_refused_and_nothing_is_stored() {
    let rig = Rig::new().await;
    rig.host_has_issue(
        "Add a --json flag",
        "Please print counts as JSON.",
        REQUESTER_ID,
    );
    let job = rig
        .engine
        .receive_job(rig.world.tenant, rig.world.requester, rig.world.repository)
        .await
        .expect("receive");
    rig.requests.await_issue(job, rig.issue.clone());
    rig.label_applied_by(&Rig::actor(REQUESTER_ID + 1, "requester-one"))
        .await;
    rig.admit(job).await;
    rig.classifier_returns(usual());
    refused_and_nothing_stored(&rig, job, "an unlisted labeller").await;
}
