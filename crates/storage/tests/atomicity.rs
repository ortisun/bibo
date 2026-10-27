//! One decision, one transaction (ADR 0004, invariant INV-03): the status change, the ledger entry,
//! the outbox row and the audit record commit together or not at all.
//!
//! PENDING ADAPTATION TO PORTS V1.1. These tests drive the old `Store` write model (`claim_ready`,
//! `insert_attempt`, event payloads, `ScopeNotAllowed`) and do not compile against the revised
//! traits, so the whole file is compiled out with `#![cfg(any())]`. The Postgres adaptation
//! package rewrites each test against the new traits and removes the attribute. The test names
//! below are the ones that package must account for.
//!
//! * `transition_is_atomic`
//! * `an_event_must_announce_a_version_the_job_has_reached`
//! * `the_outbox_reads_back_in_order_and_resumes`

#![cfg(any())]

mod support;

use factory_domain::ids::{JobId, StageRunId};
use factory_domain::state::{JobEvent, JobStatus};
use factory_domain::values::{Sha256Digest, Slug};
use factory_ports::store::{
    AppliedTransition, AuditActor, AuditEvent, OutboxSeq, StoreError, Tx, Version,
};
use factory_testkit::fixtures::{domain_event, ledger_entry};
use support::{Scene, now};

/// Everything the database holds about a job's decision, as one line.
async fn footprint(scene: &Scene, job: JobId) -> String {
    let job = job.as_uuid();
    scene
        .db
        .text(&format!(
            "SELECT (SELECT status || ':v' || version || ':head' || ledger_head_sequence FROM jobs WHERE id = '{job}') \
               || ' ledger=' || (SELECT count(*) FROM ledger_entries WHERE job_id = '{job}') \
               || ' outbox=' || (SELECT count(*) FROM outbox WHERE job_id = '{job}') \
               || ' audit=' || (SELECT count(*) FROM audit_events WHERE job_id = '{job}')"
        ))
        .await
        .expect("footprint")
}

const UNTOUCHED: &str = "RECEIVED:v1:head0 ledger=0 outbox=0 audit=0";

fn audit_event(scene: &Scene, job: JobId, action: &str) -> AuditEvent {
    AuditEvent {
        job_id: job,
        actor: AuditActor::Component(Slug::parse("workflow.engine").expect("slug")),
        action: Slug::parse(action).expect("slug"),
        policy_hash: Sha256Digest::of(b"policy"),
        correlation_id: scene.ids.correlation(),
        occurred_at: now(),
    }
}

/// The writes of one decision, up to but not including the commit. The event announces the
/// version the job has after the status change.
async fn decide(scene: &Scene, job: JobId, run: StageRunId, announce: Option<i64>) -> Box<dyn Tx> {
    let mut tx = scene.tenant_tx(scene.a).await;
    let read = tx.get_job(job).await.expect("get");
    let admit = AppliedTransition::plan(JobStatus::Received, JobEvent::Admit, now()).expect("J01");
    let next = tx
        .transition_job(job, read.version, admit)
        .await
        .expect("transition");
    tx.append_ledger_entry(ledger_entry(
        &scene.ids,
        job,
        run,
        1,
        None,
        &now(),
        "Admitted.",
    ))
    .await
    .expect("append");
    tx.enqueue_event(domain_event(
        &scene.ids,
        scene.a,
        job,
        announce.unwrap_or(next.get()),
        &now(),
    ))
    .await
    .expect("enqueue");
    tx
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transition_is_atomic() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    assert_eq!(footprint(&scene, job).await, UNTOUCHED);

    // Fault 1: the process stops after the outbox insert. The transaction is dropped.
    let tx = decide(&scene, job, run, None).await;
    drop(tx);
    assert_eq!(
        footprint(&scene, job).await,
        UNTOUCHED,
        "a dropped transaction leaves nothing"
    );

    // Fault 2: the caller rolls back after the outbox insert.
    let tx = decide(&scene, job, run, None).await;
    tx.rollback().await.expect("rollback");
    assert_eq!(
        footprint(&scene, job).await,
        UNTOUCHED,
        "a rollback leaves nothing"
    );

    // Fault 3: a statement fails after the outbox insert. The audit record has a bad action name.
    let mut tx = decide(&scene, job, run, None).await;
    let failed = tx
        .record_audit(audit_event(&scene, job, "not-a-valid-action"))
        .await;
    assert!(
        matches!(failed, Err(StoreError::Constraint(_))),
        "{failed:?}"
    );
    drop(tx);
    assert_eq!(
        footprint(&scene, job).await,
        UNTOUCHED,
        "a failed statement leaves nothing"
    );

    // Fault 4: the database refuses at commit, after every statement was accepted. The event
    // announces a version the job never reaches.
    let tx = decide(&scene, job, run, Some(99)).await;
    let refused = tx.commit().await;
    assert!(
        matches!(&refused, Err(StoreError::Constraint(text)) if text.contains("outbox_aggregate_has_reached_version")),
        "{refused:?}"
    );
    assert_eq!(
        footprint(&scene, job).await,
        UNTOUCHED,
        "a refused commit leaves no status change, no ledger entry and no outbox row"
    );

    // No fault: the same decision commits, and all four writes are there.
    let mut tx = decide(&scene, job, run, None).await;
    tx.record_audit(audit_event(&scene, job, "job.admitted"))
        .await
        .expect("audit");
    tx.commit().await.expect("commit");
    assert_eq!(
        footprint(&scene, job).await,
        "ACTIVE:v3:head1 ledger=1 outbox=1 audit=1",
        "the status, the ledger head, the entry, the event and the audit record"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_event_must_announce_a_version_the_job_has_reached() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let mut tx = scene.tenant_tx(scene.a).await;
    tx.enqueue_event(domain_event(&scene.ids, scene.a, job, 5, &now()))
        .await
        .expect("enqueue");
    let refused = tx.commit().await;
    assert!(
        matches!(&refused, Err(StoreError::Constraint(text)) if text.contains("outbox_aggregate_has_reached_version")),
        "{refused:?}"
    );
    assert_eq!(footprint(&scene, job).await, UNTOUCHED);

    // The version the job has is accepted.
    let mut tx = scene.tenant_tx(scene.a).await;
    tx.enqueue_event(domain_event(&scene.ids, scene.a, job, 1, &now()))
        .await
        .expect("enqueue");
    tx.commit()
        .await
        .expect("an event for the current version commits");

    // The same event twice is a constraint error at the second enqueue (the event id is unique).
    // A second event for the same version of the job is a replay, and says so with `Conflict`.
    let other = scene.job(scene.a).await;
    let event = domain_event(&scene.ids, scene.a, other, 1, &now());
    let mut tx = scene.tenant_tx(scene.a).await;
    tx.enqueue_event(event.clone()).await.expect("first");
    assert!(matches!(
        tx.enqueue_event(event).await,
        Err(StoreError::Constraint(_))
    ));
    drop(tx);
    let mut tx = scene.tenant_tx(scene.a).await;
    assert_eq!(
        tx.enqueue_event(domain_event(&scene.ids, scene.a, job, 1, &now()))
            .await,
        Err(StoreError::Conflict),
        "the version 1 event of the first job is already queued"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_outbox_reads_back_in_order_and_resumes() {
    let scene = Scene::new().await;
    let job_one = scene.job(scene.a).await;
    let job_two = scene.job(scene.a).await;

    // Move each job to version 4 with real transitions: admit, pause, resume.
    for job in [job_one, job_two] {
        let mut tx = scene.tenant_tx(scene.a).await;
        let mut version = Version::FIRST;
        let mut status = JobStatus::Received;
        for event in [JobEvent::Admit, JobEvent::Pause, JobEvent::Resume] {
            let plan = AppliedTransition::plan(status, event, now()).expect("legal");
            version = tx
                .transition_job(job, version, plan)
                .await
                .expect("transition");
            status = plan.to_status();
        }
        assert_eq!(version.get(), 4);
        tx.commit().await.expect("commit");
    }

    let mut queued = Vec::new();
    let mut tx = scene.tenant_tx(scene.a).await;
    for version in 2..=4 {
        let event = domain_event(&scene.ids, scene.a, job_one, version, &now());
        queued.push(event.event_id);
        tx.enqueue_event(event).await.expect("enqueue");
    }
    tx.enqueue_event(domain_event(&scene.ids, scene.a, job_two, 2, &now()))
        .await
        .expect("other job");
    tx.commit().await.expect("commit");

    let mut tx = scene.tenant_tx(scene.a).await;
    let rows = tx
        .read_events(job_one, OutboxSeq::START, 100)
        .await
        .expect("read");
    let read: Vec<_> = rows.iter().map(|row| row.event.event_id).collect();
    assert_eq!(
        read, queued,
        "events come back in the order they were queued"
    );
    assert!(
        rows.windows(2).all(|pair| pair[0].seq < pair[1].seq),
        "positions rise"
    );
    assert_eq!(
        tx.read_events(job_two, OutboxSeq::START, 100)
            .await
            .expect("read")
            .len(),
        1,
        "events are kept per job"
    );

    // Reading resumes from a position, and the position is inclusive.
    let page = tx
        .read_events(job_one, OutboxSeq::START, 2)
        .await
        .expect("page");
    assert_eq!(page.len(), 2);
    let last = page.last().expect("last").seq;
    let again = tx.read_events(job_one, last, 10).await.expect("resume");
    assert_eq!(again.first().map(|row| row.seq), Some(last));
    assert_eq!(again.len(), 2);
    assert_eq!(
        tx.read_events(job_one, OutboxSeq::new(last.get() + 1), 10)
            .await
            .expect("after")
            .len(),
        1
    );

    // The event comes back as it went in.
    let first = &rows[0].event;
    assert_eq!(first.aggregate.version.get(), 2);
    assert_eq!(first.tenant_id, scene.a);
    assert_eq!(first.transition_id.as_str(), "J01");
}
