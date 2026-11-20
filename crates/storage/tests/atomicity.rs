//! One decision, one transaction: the status change, its ledger entry and its outbox event commit
//! together or not at all, an event must announce a version its aggregate has reached, and a lost
//! answer to `COMMIT` is settled by the witness.
//!
//! The events here announce versions the job really reached, as the fixtures of the shared contract
//! suite (`store_contract.rs`) do too.

mod support;

use factory_domain::ids::{EventId, JobId, StageRunId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::state::{Guard, JobEvent, JobStatus};
use factory_ports::store::{
    AppliedTransition, AuditAction, AuditActor, AuditDecision, ConstraintRule, JobFacts,
    NewAuditEvent, OutboxSeq, Store, StoreError, Witness,
};
use factory_testkit::fixtures::{cleared, domain_event, ledger_entry};
use support::{Scene, at};

/// What a job has in the three tables a decision writes, read as the superuser.
struct Footprint {
    status: String,
    version: i64,
    ledger_head: i64,
    events: i64,
}

async fn footprint(scene: &Scene, job: JobId) -> Footprint {
    let id = job.as_uuid();
    Footprint {
        status: scene
            .db
            .text(&format!("SELECT status FROM jobs WHERE id = '{id}'"))
            .await
            .expect("status"),
        version: scene
            .db
            .number(&format!("SELECT version FROM jobs WHERE id = '{id}'"))
            .await,
        ledger_head: scene
            .db
            .number(&format!(
                "SELECT ledger_head_sequence FROM jobs WHERE id = '{id}'"
            ))
            .await,
        events: scene
            .db
            .number(&format!(
                "SELECT count(*) FROM outbox WHERE job_id = '{id}'"
            ))
            .await,
    }
}

/// A job in `RECEIVED` with a stage run for the ledger entries to name.
async fn job_with_run(scene: &Scene, tenant: TenantId) -> (JobId, StageRunId) {
    let job = scene.job(tenant).await;
    let run = scene.ready_stage_run(tenant, job).await;
    (job, run)
}

fn admit() -> AppliedTransition<JobStatus> {
    AppliedTransition::plan(
        JobStatus::Received,
        JobEvent::Admit,
        at(),
        cleared(Guard::AdmissionOk),
    )
    .expect("J01")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_decision_commits_or_vanishes_as_one() {
    let scene = Scene::new().await;
    let (job, run) = job_with_run(&scene, scene.a).await;

    // Rolled back: none of the three remains.
    let mut tx = scene.tx(scene.a).await;
    let row = tx.get_job(job).await.expect("read");
    let version = tx
        .transition_job(job, row.version, admit())
        .await
        .expect("admit");
    tx.append_ledger_entry(ledger_entry(
        &scene.ids,
        job,
        run,
        1,
        None,
        &at(),
        "Admitted.",
    ))
    .await
    .expect("append");
    // An append does not move the job's version: the version the transition returned still holds.
    assert_eq!(tx.get_job(job).await.expect("read").version, version);
    tx.enqueue_event(domain_event(&scene.ids, scene.a, job, version.get(), &at()))
        .await
        .expect("enqueue");
    tx.rollback().await.expect("roll back");
    let after = footprint(&scene, job).await;
    assert_eq!(after.status, "RECEIVED");
    assert_eq!(after.version, 1);
    assert_eq!(after.ledger_head, 0);
    assert_eq!(after.events, 0);

    // Committed: all three are there, and the version moved once.
    let mut tx = scene.tx(scene.a).await;
    let row = tx.get_job(job).await.expect("read");
    let version = tx
        .transition_job(job, row.version, admit())
        .await
        .expect("admit");
    tx.append_ledger_entry(ledger_entry(
        &scene.ids,
        job,
        run,
        1,
        None,
        &at(),
        "Admitted.",
    ))
    .await
    .expect("append");
    tx.enqueue_event(domain_event(&scene.ids, scene.a, job, version.get(), &at()))
        .await
        .expect("enqueue");
    tx.commit().await.expect("commit");
    let after = footprint(&scene, job).await;
    assert_eq!(after.status, "ACTIVE");
    assert_eq!(after.version, 2, "one change of status, one version");
    assert_eq!(after.ledger_head, 1);
    assert_eq!(after.events, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_event_must_announce_a_version_the_job_has_reached() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let mut tx = scene.tx(scene.a).await;
    // The job is at version 1; the event announces version 5.
    tx.enqueue_event(domain_event(&scene.ids, scene.a, job, 5, &at()))
        .await
        .expect("the statement is accepted; the check is deferred to commit");
    assert_eq!(
        tx.commit().await,
        Err(StoreError::Constraint(
            ConstraintRule::EventAggregateMismatch
        )),
        "the database refuses the event at commit"
    );
    assert_eq!(footprint(&scene, job).await.events, 0, "nothing remains");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_outbox_reads_back_in_order_and_resumes() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let other = scene.job(scene.a).await;
    let mut tx = scene.tx(scene.a).await;
    // Bring both jobs to version 3: two facts, then the admission.
    for target in [job, other] {
        let request = support::index_blob(&mut *tx, b"request").await;
        let current = tx.get_job(target).await.expect("read").version;
        let v2 = tx
            .update_job_facts(
                target,
                current,
                JobFacts {
                    policy_hash: Some(factory_domain::values::Sha256Digest::of(b"policy")),
                    ..JobFacts::default()
                },
            )
            .await
            .expect("policy");
        tx.update_job_facts(
            target,
            v2,
            JobFacts {
                normalized_request: Some(request.clone()),
                ..JobFacts::default()
            },
        )
        .await
        .expect("request");
    }
    // Another job's event goes first, so that the last row of the transaction is this job's.
    tx.enqueue_event(domain_event(&scene.ids, scene.a, other, 3, &at()))
        .await
        .expect("another job's event");
    let mut queued = Vec::new();
    for version in 1..=3 {
        let event = domain_event(&scene.ids, scene.a, job, version, &at());
        queued.push(event.event_id);
        tx.enqueue_event(event).await.expect("enqueue");
    }
    tx.commit().await.expect("commit");

    let mut tx = scene.tx(scene.a).await;
    let rows = tx
        .read_events(job, OutboxSeq::START, 10)
        .await
        .expect("read");
    let ids: Vec<EventId> = rows.iter().map(|row| row.event.event_id).collect();
    assert_eq!(
        ids, queued,
        "this job's events, in the order they were queued"
    );
    assert!(rows.windows(2).all(|pair| pair[0].seq < pair[1].seq));
    let resumed = tx
        .read_events(job, OutboxSeq::new(rows[0].seq.get() + 1), 10)
        .await
        .expect("resume");
    assert_eq!(
        resumed.len(),
        2,
        "reading resumes after the last position seen"
    );
    assert_eq!(
        tx.read_events(job, OutboxSeq::START, 2)
            .await
            .expect("limit")
            .len(),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_commit_answer_is_settled_by_the_witness() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let event = domain_event(&scene.ids, scene.a, job, 1, &at());
    let witness = Witness::OutboxEvent(event.event_id);
    let audit = NewAuditEvent {
        id: factory_domain::ids::AuditEventId::from_uuid(uuid::Uuid::from_u128(4242)),
        actor: AuditActor::System(
            factory_domain::values::Slug::parse("workflow-engine").expect("slug"),
        ),
        action: AuditAction::new("job.admitted").expect("action"),
        subject: "a job".to_owned(),
        decision: AuditDecision::Record,
        reason: "A decision whose commit answer is lost.".to_owned(),
        policy_hash: factory_domain::values::Sha256Digest::of(b"policy"),
        job: Some(job),
        stage_run: None,
        correlation_id: scene.ids.correlation(),
    };
    let audit_witness = Witness::Audit(audit.id);
    let scope = TenantScope::new(scene.a);

    assert!(!scene.store.committed(scope, witness).await.expect("ask"));
    let mut tx = scene.tx(scene.a).await;
    tx.enqueue_event(event).await.expect("enqueue");
    tx.record_audit(audit).await.expect("audit");
    scene.store.lose_next_commit_answer();
    assert_eq!(tx.commit().await, Err(StoreError::CommitOutcomeUnknown));
    assert!(
        scene.store.committed(scope, witness).await.expect("ask"),
        "the event is stored"
    );
    assert!(
        scene
            .store
            .committed(scope, audit_witness)
            .await
            .expect("ask"),
        "so is the record"
    );
    assert!(
        !scene
            .store
            .committed(TenantScope::new(scene.b), witness)
            .await
            .expect("ask"),
        "another tenant cannot see the witness"
    );

    // A transaction that was rolled back leaves no witness.
    let rolled_back_job = scene.job(scene.a).await;
    let other = domain_event(&scene.ids, scene.a, rolled_back_job, 1, &at());
    let other_witness = Witness::OutboxEvent(other.event_id);
    let mut tx = scene.tx(scene.a).await;
    tx.enqueue_event(other).await.expect("enqueue");
    tx.rollback().await.expect("roll back");
    assert!(
        !scene
            .store
            .committed(scope, other_witness)
            .await
            .expect("ask")
    );
}
