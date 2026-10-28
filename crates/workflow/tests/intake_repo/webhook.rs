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
async fn a_job_that_already_has_text_is_not_fetched_again() {
    let rig = Rig::new().await;
    // The host holds other words than the stored request: they must not replace it.
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
