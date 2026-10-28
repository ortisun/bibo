//! What a caller learns from an error, and what the log learns.
//!
//! Database text never reaches a caller: a unique violation names the key value in its detail, and
//! for the two keys that are global that value belongs to another tenant. The store answers with
//! the closed `StoreError`. This file provokes real failures of the database and checks that no
//! text of theirs appears in the error, in its `Debug` form, or in anything the store logs. A row
//! of another tenant and a row that does not exist give the same error.

mod support;

use std::fmt::Write as _;
use std::sync::{Mutex, Once, PoisonError};

use factory_domain::ids::{AuditEventId, PrincipalId};
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, ConstraintRule, NewAuditEvent, NewPrincipal,
    PrincipalKind, StoreError,
};
use factory_testkit::fixtures::ledger_entry;
use support::{Scene, at};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

/// Every event the store logs in this process, as text.
static LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Capture;

struct Text<'a>(&'a mut String);

impl Visit for Text<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, "{}={value:?} ", field.name());
    }
}

impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut line = String::new();
        event.record(&mut Text(&mut line));
        LOG.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line);
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

fn capture_logs() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(Capture);
    });
}

fn logged() -> String {
    LOG.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .join("\n")
}

/// A value that a database detail would carry and a caller must never see.
const SECRET_USER: u64 = 424_242;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn database_text_never_reaches_a_caller() {
    capture_logs();
    let scene = Scene::new().await;

    // 1. A unique violation: a second principal for one GitHub user. The database detail reads
    // `Key (tenant_id, github_user_id)=(..., 424242) already exists.`
    let mut tx = scene.tx(scene.a).await;
    tx.insert_principal(NewPrincipal {
        id: scene.ids.principal(),
        kind: PrincipalKind::Human {
            github_user_id: SECRET_USER,
        },
        login: Some("first".to_owned()),
    })
    .await
    .expect("the first principal");
    let taken = tx
        .insert_principal(NewPrincipal {
            id: scene.ids.principal(),
            kind: PrincipalKind::Human {
                github_user_id: SECRET_USER,
            },
            login: Some("second".to_owned()),
        })
        .await
        .map(|_| ());
    let mut shown = format!("{taken:?}");
    assert_eq!(
        taken,
        Err(StoreError::Constraint(
            ConstraintRule::ExternalReferenceTaken
        ))
    );
    drop(tx);

    // 2. A foreign key violation: a ledger entry for a stage run that does not exist.
    let job = scene.job(scene.a).await;
    let mut tx = scene.tx(scene.a).await;
    let refused = tx
        .append_ledger_entry(ledger_entry(
            &scene.ids,
            job,
            scene.ids.stage_run(),
            1,
            None,
            &at(),
            "No such run.",
        ))
        .await
        .map(|_| ());
    write!(shown, " {refused:?}").expect("write");
    drop(tx);

    // 3. A check violation: an audit reason longer than the column allows.
    let mut tx = scene.tx(scene.a).await;
    let too_long = tx
        .record_audit(NewAuditEvent {
            id: AuditEventId::from_uuid(uuid::Uuid::from_u128(31)),
            actor: AuditActor::Human(PrincipalId::from_uuid(uuid::Uuid::from_u128(32))),
            action: AuditAction::new("job.admitted").expect("action"),
            subject: "a job".to_owned(),
            decision: AuditDecision::Record,
            reason: "x".repeat(1001),
            policy_hash: factory_domain::values::Sha256Digest::of(b"policy"),
            job: Some(job),
            stage_run: None,
            correlation_id: scene.ids.correlation(),
        })
        .await
        .map(|_| ());
    write!(shown, " {too_long:?}").expect("write");
    assert_eq!(
        too_long,
        Err(StoreError::Constraint(ConstraintRule::TextBounds))
    );

    // What a caller sees is the closed error, with none of the database's words.
    for forbidden in [
        "424242",
        "already exists",
        "duplicate key",
        "violates",
        "Key (",
        "principals_",
        "ledger_entries",
        "audit_events",
        "constraint",
    ] {
        assert!(
            !shown.contains(forbidden),
            "{forbidden:?} reached a caller: {shown}"
        );
    }

    // And what the store logged names the class, never the value or the message.
    let log = logged();
    assert!(!log.is_empty(), "the failures were logged");
    for forbidden in ["424242", "already exists", "duplicate key value", "Key ("] {
        assert!(
            !log.contains(forbidden),
            "{forbidden:?} reached the log: {log}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_conflict_and_a_missing_row_say_nothing_about_the_other_row() {
    let scene = Scene::new().await;
    let job = scene.active_job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    let started = scene.start(scene.a, run, "worker-1").await.expect("start");
    let missing_job = scene.ids.job();
    let missing_run = scene.ids.stage_run();

    // Tenant B asks for tenant A's rows and for rows that do not exist. The answers are equal.
    let mut other = scene.tx(scene.b).await;
    assert_eq!(
        other.get_job(job).await.map(|_| ()),
        other.get_job(missing_job).await.map(|_| ())
    );
    assert_eq!(
        other.get_stage_run(run).await.map(|_| ()),
        other.get_stage_run(missing_run).await.map(|_| ())
    );
    assert_eq!(
        other.list_stage_runs(job).await.map(|_| ()),
        other.list_stage_runs(missing_job).await.map(|_| ())
    );
    assert_eq!(
        other
            .get_attempt(started.attempt.value.id)
            .await
            .map(|_| ()),
        other
            .get_attempt(factory_domain::ids::AttemptId::from_uuid(
                uuid::Uuid::from_u128(9)
            ))
            .await
            .map(|_| ())
    );
    assert_eq!(
        other
            .get_repository(scene.repository(scene.a))
            .await
            .map(|_| ()),
        Err(StoreError::NotFound)
    );
    // A write to a foreign row is a missing row, not a conflict: the version says nothing.
    let plan = factory_ports::store::AppliedTransition::plan(
        factory_domain::state::JobStatus::Active,
        factory_domain::state::JobEvent::Pause,
        at(),
        factory_testkit::fixtures::cleared(factory_domain::state::Guard::ActorMayPause),
    )
    .expect("J-pause");
    let version = factory_ports::store::Version::FIRST;
    assert_eq!(
        other.transition_job(job, version, plan.clone()).await,
        other
            .transition_job(missing_job, version, plan.clone())
            .await
    );
    assert_eq!(
        other.transition_job(job, version, plan).await,
        Err(StoreError::NotFound)
    );

    // On its own row a stale version is a conflict, and says so.
    let mut mine = scene.tx(scene.a).await;
    let pause = factory_ports::store::AppliedTransition::plan(
        factory_domain::state::JobStatus::Active,
        factory_domain::state::JobEvent::Pause,
        at(),
        factory_testkit::fixtures::cleared(factory_domain::state::Guard::ActorMayPause),
    )
    .expect("J-pause");
    assert_eq!(
        mine.transition_job(job, factory_ports::store::Version::FIRST, pause)
            .await,
        Err(StoreError::Conflict),
        "the job is past version one"
    );
}
