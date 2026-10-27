//! Error mapping: every database failure becomes a value of the closed `StoreError`, and the
//! message and detail text of the database never reaches a caller.
//!
//! A unique violation names the key value in its detail, and for the two global keys that value
//! belongs to another tenant. These tests provoke the failures that carry such text and check that
//! nothing but a constraint name comes out.

mod support;

use factory_domain::ids::JobId;
use factory_domain::state::{JobEvent, JobStatus};
use factory_domain::values::{NonEmptyString, Sha256Digest, Slug};
use factory_ports::store::{
    AppliedTransition, AuditActor, AuditEvent, NewJob, NewPrincipal, StoreError,
};
use factory_testkit::fixtures::{domain_event, ledger_entry};
use support::{Scene, now};

/// Text that only a database message or detail would contain.
const DATABASE_PHRASES: &[&str] = &[
    "Key (",
    "already exists",
    "violates",
    "DETAIL",
    "duplicate key value",
    "is not present in table",
    "permission denied",
    "row-level security",
    "new row",
    "relation \"",
    "ERROR:",
    "SQLSTATE",
];

/// What a caller could see of an error: its message and its debug form.
fn visible(error: &StoreError) -> String {
    format!("{error} {error:?}")
}

/// Checks that an error shows no database text and none of the values of the rows involved.
fn assert_clean(error: &StoreError, values: &[String]) {
    let shown = visible(error);
    for phrase in DATABASE_PHRASES {
        assert!(
            !shown.contains(phrase),
            "the error shows database text {phrase:?}: {shown}"
        );
    }
    for value in values {
        assert!(
            !shown.contains(value.as_str()),
            "the error shows the value {value}: {shown}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn database_text_never_reaches_a_caller() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let requester = scene.principal(scene.a).await;
    let stranger = scene.principal(scene.b).await;
    let values: Vec<String> = [
        job.as_uuid(),
        requester.as_uuid(),
        stranger.as_uuid(),
        scene.a.as_uuid(),
        scene.b.as_uuid(),
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let mut seen: Vec<StoreError> = Vec::new();

    // A unique violation: the job id is taken. The database detail names the id.
    let mut tx = scene.tenant_tx(scene.a).await;
    let error = tx
        .insert_job(NewJob {
            id: job,
            correlation_id: scene.ids.correlation(),
            requester,
            created_at: now(),
        })
        .await
        .expect_err("a second job with the same id");
    assert!(matches!(error, StoreError::Constraint(_)), "{error:?}");
    seen.push(error);
    drop(tx);

    // A foreign key violation: the requester belongs to another tenant. The detail names both.
    let mut tx = scene.tenant_tx(scene.a).await;
    let error = tx
        .insert_job(NewJob {
            id: scene.ids.job(),
            correlation_id: scene.ids.correlation(),
            requester: stranger,
            created_at: now(),
        })
        .await
        .expect_err("a foreign requester");
    assert!(matches!(error, StoreError::Constraint(_)), "{error:?}");
    seen.push(error);
    drop(tx);

    // A unique violation on an external reference.
    let mut tx = scene.tenant_tx(scene.a).await;
    let reference = NonEmptyString::parse("424242").expect("ref");
    tx.insert_principal(NewPrincipal {
        id: scene.ids.principal(),
        external_ref: reference.clone(),
        created_at: now(),
    })
    .await
    .expect("first");
    let error = tx
        .insert_principal(NewPrincipal {
            id: scene.ids.principal(),
            external_ref: reference,
            created_at: now(),
        })
        .await
        .expect_err("a repeated external reference");
    assert!(matches!(error, StoreError::Constraint(_)), "{error:?}");
    seen.push(error);
    drop(tx);

    // A foreign key violation on the ledger: the stage run does not exist.
    let mut tx = scene.tenant_tx(scene.a).await;
    let error = tx
        .append_ledger_entry(ledger_entry(
            &scene.ids,
            job,
            scene.ids.stage_run(),
            1,
            None,
            &now(),
            "No run.",
        ))
        .await
        .expect_err("a phantom stage run");
    seen.push(error);
    drop(tx);

    // A check violation: an audit action the table refuses.
    let mut tx = scene.tenant_tx(scene.a).await;
    let error = tx
        .record_audit(AuditEvent {
            job_id: job,
            actor: AuditActor::Component(Slug::parse("workflow.engine").expect("slug")),
            action: Slug::parse("not-a-valid-action").expect("slug"),
            policy_hash: Sha256Digest::of(b"policy"),
            correlation_id: scene.ids.correlation(),
            occurred_at: now(),
        })
        .await
        .expect_err("a bad audit action");
    seen.push(error);
    drop(tx);

    // A deferred check that fails at commit.
    let mut tx = scene.tenant_tx(scene.a).await;
    tx.enqueue_event(domain_event(&scene.ids, scene.a, job, 77, &now()))
        .await
        .expect("enqueue");
    seen.push(
        tx.commit()
            .await
            .expect_err("an event for a version never reached"),
    );

    // A privilege the login lacks: a bug of the deployment. It is reported as unavailable.
    scene
        .db
        .run("REVOKE INSERT ON outbox FROM factory_app")
        .await;
    let mut tx = scene.tenant_tx(scene.a).await;
    let error = tx
        .enqueue_event(domain_event(&scene.ids, scene.a, job, 1, &now()))
        .await
        .expect_err("a missing grant");
    assert_eq!(
        error,
        StoreError::Unavailable,
        "a missing grant is not the caller's error"
    );
    seen.push(error);
    drop(tx);
    scene.db.run("GRANT INSERT ON outbox TO factory_app").await;

    // A transaction that PostgreSQL has aborted refuses what follows, and says nothing about why.
    let mut tx = scene.tenant_tx(scene.a).await;
    let first = tx
        .insert_job(NewJob {
            id: job,
            correlation_id: scene.ids.correlation(),
            requester,
            created_at: now(),
        })
        .await;
    assert!(first.is_err());
    let after = tx
        .get_job(job)
        .await
        .expect_err("the transaction is aborted");
    seen.push(after);
    drop(tx);

    assert!(seen.len() >= 8);
    for error in &seen {
        assert_clean(error, &values);
    }

    // The constraint names are the only text that comes through.
    let unique = visible(&seen[0]);
    assert!(unique.contains("jobs_pkey"), "{unique}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_conflict_and_a_missing_row_say_nothing_about_the_other_row() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let admit = AppliedTransition::plan(JobStatus::Received, JobEvent::Admit, now()).expect("J01");
    // A stale version is a conflict, with no text. A job of another tenant is not found, with no
    // text, and the same as a job that does not exist.
    let mut tx = scene.tenant_tx(scene.a).await;
    let stale = factory_ports::store::Version::new(9).expect("version");
    assert_eq!(
        tx.transition_job(job, stale, admit).await,
        Err(StoreError::Conflict)
    );
    drop(tx);
    let mut other = scene.tenant_tx(scene.b).await;
    let foreign = other.get_job(job).await.expect_err("not found");
    let missing = other
        .get_job(JobId::from_uuid(uuid::Uuid::from_u128(5)))
        .await
        .expect_err("not found");
    assert_eq!(
        foreign, missing,
        "a row of another tenant looks exactly like a row that does not exist"
    );
    assert_eq!(visible(&foreign), visible(&missing));
}
