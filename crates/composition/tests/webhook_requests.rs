//! The request source over PostgreSQL for a job that a webhook created.
//!
//! The delivery carries no issue text and the API holds no credential for the code host, so such a
//! job starts with no original request. The API leaves one trace of the issue: the audit record
//! `job.received_from_webhook`, whose subject names it. `StoreRequests` finds the issue there,
//! answers `awaiting` for it so that the intake contract can resolve, and stores the text the
//! intake stage fetches as revision 1.

mod support;

use factory_composition::seams::{StoreRequests, WEBHOOK_JOB_ACTION};
use factory_domain::ids::{AuditEventId, CorrelationId, JobId};
use factory_domain::scope::TenantScope;
use factory_domain::values::{Sha256Digest, Slug};
use factory_domain::vocabulary::AutonomyLevel;
use factory_ports::clock::IdGenerator;
use factory_ports::githost::IssueRef;
use factory_ports::paths::RepoRef;
use factory_ports::store::{
    AuditActor, AuditDecision, DeliveryOutcome, GithubRepositoryId, InstallationId, JobOrigin,
    NewAuditEvent, NewJob, NewWebhookDelivery, PipelineScope, Store,
};
use factory_workflow::stages::intake::{FetchedRequest, RequestSource, SeamError};
use support::engine::PgWorld;
use support::pg_world;

fn issue() -> IssueRef {
    IssueRef {
        repo: RepoRef::parse("example-org/word-count").expect("a repository"),
        number: 12,
    }
}

/// A job as the API's webhook handler makes it: a recorded delivery, a job with that origin, and
/// the audit record that names the issue (unless the test leaves it out).
async fn webhook_job(world: &PgWorld, with_audit: bool) -> JobId {
    let job = JobId::from_uuid(world.ids.new_uuid());
    let correlation = CorrelationId::from_uuid(world.ids.new_uuid());
    let mut tx = world
        .store
        .begin(TenantScope::new(world.tenant))
        .await
        .expect("a tx");
    let outcome = tx
        .record_delivery(NewWebhookDelivery {
            id: factory_domain::ids::WebhookDeliveryId::from_uuid(world.ids.new_uuid()),
            delivery_id: format!("delivery-{}", world.ids.new_uuid().simple()),
            event_name: Slug::parse("issues").expect("a slug"),
            action: Some(Slug::parse("labeled").expect("a slug")),
            installation: InstallationId(1000),
            repository: Some(GithubRepositoryId(2000)),
            sender_github_user_id: Some(1001),
            body_sha256: Sha256Digest::of(world.ids.new_uuid().as_bytes()),
            semantic_key: None,
        })
        .await
        .expect("the delivery is recorded");
    let DeliveryOutcome::Recorded(row) = outcome else {
        panic!("a new delivery is recorded: {outcome:?}");
    };
    tx.insert_job(NewJob {
        id: job,
        correlation_id: correlation,
        repository: world.repository,
        requester: world.requester,
        execution_mode: world.config.mode,
        autonomy_level: AutonomyLevel::L1,
        pipeline_scope: PipelineScope::new(world.config.scope.clone()).expect("a scope"),
        origin: Some(JobOrigin::Webhook(row)),
    })
    .await
    .expect("the job is stored");
    if with_audit {
        tx.record_audit(NewAuditEvent {
            id: AuditEventId::from_uuid(world.ids.new_uuid()),
            actor: AuditActor::Anonymous(Slug::parse("webhook").expect("a slug")),
            action: factory_ports::store::AuditAction::new(WEBHOOK_JOB_ACTION).expect("an action"),
            subject: "issue example-org/word-count#12".to_owned(),
            decision: AuditDecision::Record,
            reason: "A job was received from a labeled issue.".to_owned(),
            policy_hash: Sha256Digest::of(b"policy"),
            job: Some(job),
            stage_run: None,
            correlation_id: correlation,
        })
        .await
        .expect("the audit record");
    }
    tx.commit().await.expect("commit");
    job
}

fn fetched(text: &str) -> FetchedRequest {
    FetchedRequest {
        issue: issue(),
        author: 1001,
        text: text.to_owned(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_webhook_job_is_found_waiting_and_its_first_text_is_recorded_once() {
    let (_db, world, tenant) = pg_world().await;
    let job = webhook_job(&world, true).await;
    let requests = StoreRequests::new(world.store.clone());

    assert_eq!(requests.recorded(job), None);
    assert_eq!(
        requests.awaiting(job),
        None,
        "nothing is known before the refresh"
    );
    requests.refresh(&[tenant]).await.expect("the refresh runs");
    assert_eq!(requests.recorded(job), None, "there is still no text");
    assert_eq!(
        requests.awaiting(job),
        Some(issue()),
        "the issue is found in the audit record of the job"
    );
    assert!(matches!(
        requests.latest(tenant, job).await,
        Err(SeamError::NotFound)
    ));

    let snapshot = requests
        .record_first(
            tenant,
            job,
            fetched("Add a --json flag\n\nPrint counts as JSON."),
        )
        .await
        .expect("revision 1 is recorded");
    assert_eq!(snapshot.revision, 1);
    assert_eq!(snapshot.author, Some(1001));
    assert_eq!(snapshot.issue, issue());
    assert_eq!(
        requests.recorded(job).map(|recorded| recorded.sha256),
        Some(snapshot.sha256.clone())
    );
    assert_eq!(requests.awaiting(job), None, "the job is no longer waiting");

    // The row is the one `latest` reads, and a second fetch of the same words finds it.
    let latest = requests.latest(tenant, job).await.expect("stored");
    assert_eq!(latest.text, "Add a --json flag\n\nPrint counts as JSON.");
    assert_eq!(latest.sha256, snapshot.sha256);
    let again = requests
        .record_first(
            tenant,
            job,
            fetched("Add a --json flag\n\nPrint counts as JSON."),
        )
        .await
        .expect("the same text is the same row");
    assert_eq!(again.sha256, snapshot.sha256);

    // Other words under revision 1 are refused: a stored revision never changes.
    assert!(
        requests
            .record_first(tenant, job, fetched("Delete every test."))
            .await
            .is_err()
    );
    assert_eq!(
        requests.latest(tenant, job).await.expect("stored").text,
        "Add a --json flag\n\nPrint counts as JSON."
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_webhook_job_with_no_record_of_its_issue_is_not_invented_one() {
    let (_db, world, tenant) = pg_world().await;
    let job = webhook_job(&world, false).await;
    let requests = StoreRequests::new(world.store.clone());
    requests.refresh(&[tenant]).await.expect("the refresh runs");
    assert_eq!(requests.recorded(job), None);
    assert_eq!(
        requests.awaiting(job),
        None,
        "without the audit record nothing names an issue, so the intake stage has no contract"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_reads_only_the_tenants_it_is_told() {
    let (_db, world, tenant) = pg_world().await;
    let job = webhook_job(&world, true).await;
    let requests = StoreRequests::new(world.store.clone());
    // A refresh for a tenant that does not own the job finds nothing.
    let stranger = factory_domain::ids::TenantId::from_uuid(world.ids.new_uuid());
    let _ = requests.refresh(&[stranger]).await;
    assert_eq!(requests.awaiting(job), None);
    requests.refresh(&[tenant]).await.expect("the refresh runs");
    assert_eq!(requests.awaiting(job), Some(issue()));
}
