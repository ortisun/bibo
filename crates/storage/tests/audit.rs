//! The audit log and the evidence ledger are append only for the application role (NT-AUD-01), and
//! an audit event carries its actor, its policy hash and its correlation id.

mod support;

use factory_domain::values::{Sha256Digest, Slug};
use factory_ports::store::{AuditActor, AuditEvent};
use support::{Scene, as_login, now};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_aud_01() {
    let scene = Scene::new().await;
    let job = scene.job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    let correlation = scene.ids.correlation();
    let policy = Sha256Digest::of(b"the policy bundle");
    let requester = scene.principal(scene.a).await;

    // Three events: a component, a person, and a component again.
    let mut tx = scene.tenant_tx(scene.a).await;
    for (actor, action) in [
        (
            AuditActor::Component(Slug::parse("workflow.engine").expect("slug")),
            "job.admitted",
        ),
        (AuditActor::Principal(requester), "approval.recorded"),
        (
            AuditActor::Component(Slug::parse("workflow.engine").expect("slug")),
            "job.completed",
        ),
    ] {
        tx.record_audit(AuditEvent {
            job_id: job,
            actor,
            action: Slug::parse(action).expect("slug"),
            policy_hash: policy.clone(),
            correlation_id: correlation,
            // A time far in the past: the database must stamp its own.
            occurred_at: factory_domain::values::Timestamp::parse("2001-01-01T00:00:00Z")
                .expect("time"),
        })
        .await
        .expect("record");
    }
    // Facts about the job that the ledger needs for the second half of the test.
    tx.append_ledger_entry(factory_testkit::fixtures::ledger_entry(
        &scene.ids,
        job,
        run,
        1,
        None,
        &now(),
        "A claim.",
    ))
    .await
    .expect("append");
    tx.commit().await.expect("commit");

    // What a caller reads back.
    let mut tx = scene.tenant_tx(scene.a).await;
    let read = tx.read_audit(job, 10).await.expect("read");
    let actions: Vec<&str> = read.iter().map(|event| event.action.as_str()).collect();
    assert_eq!(
        actions,
        ["job.admitted", "approval.recorded", "job.completed"]
    );
    assert!(
        read.iter()
            .all(|event| event.policy_hash == policy && event.correlation_id == correlation)
    );
    assert_eq!(read[1].actor, AuditActor::Principal(requester));
    drop(tx);

    // What the table holds: an actor, the policy hash and the correlation id on every row, a chain
    // numbered from 1, and a time from the database clock, not the caller's.
    let a = scene.a.as_uuid();
    let rows = scene
        .db
        .text(&format!(
            "SELECT string_agg(sequence || '|' || actor_type || '|' || actor_id || '|' || policy_hash || '|' || correlation_id, ';' ORDER BY sequence) \
               FROM audit_events WHERE tenant_id = '{a}'"
        ))
        .await
        .expect("rows");
    let lines: Vec<&str> = rows.split(';').collect();
    assert_eq!(lines.len(), 3);
    for (position, line) in lines.iter().enumerate() {
        let parts: Vec<&str> = line.splitn(5, '|').collect();
        assert_eq!(
            parts[0],
            (position + 1).to_string(),
            "the chain is numbered from 1: {line}"
        );
        assert!(
            ["system", "human", "service"].contains(&parts[1]),
            "an actor type: {line}"
        );
        assert!(!parts[2].is_empty(), "an actor id: {line}");
        assert_eq!(parts[3], policy.as_str(), "the policy hash: {line}");
        assert_eq!(
            parts[4],
            correlation.to_string(),
            "the correlation id: {line}"
        );
    }
    assert_eq!(
        scene.db.number(&format!("SELECT count(*) FROM audit_events WHERE tenant_id = '{a}' AND created_at < '2020-01-01'")).await,
        0,
        "the database clock stamps the event, whatever the caller said"
    );
    assert_eq!(
        scene
            .db
            .text(&format!(
                "SELECT coalesce(audit_verify_chain('{a}')::text, 'sound')"
            ))
            .await
            .as_deref(),
        Some("sound"),
        "the chain verifies"
    );

    // The application login cannot change, remove, empty or drop either table.
    let worker = scene.db.server.logins().await.worker.clone();
    let tenant = a.to_string();
    for table in ["audit_events", "ledger_entries"] {
        for (what, sql) in [
            (
                "UPDATE",
                format!("UPDATE {table} SET tenant_id = tenant_id"),
            ),
            ("DELETE", format!("DELETE FROM {table}")),
            ("TRUNCATE", format!("TRUNCATE {table}")),
            ("DROP", format!("DROP TABLE {table}")),
            ("ALTER", format!("ALTER TABLE {table} DISABLE TRIGGER ALL")),
        ] {
            let outcome = as_login(&scene.db, &worker, Some(&tenant), &sql).await;
            assert!(
                outcome.as_ref().is_err_and(
                    |text| text.contains("permission denied") || text.contains("must be owner")
                ),
                "{what} on {table} must be refused to the application login: {outcome:?}"
            );
        }
    }
    assert_eq!(
        scene
            .db
            .number(&format!(
                "SELECT count(*) FROM audit_events WHERE tenant_id = '{a}'"
            ))
            .await,
        3
    );
    assert_eq!(
        scene
            .db
            .number(&format!(
                "SELECT count(*) FROM ledger_entries WHERE tenant_id = '{a}'"
            ))
            .await,
        1
    );
}
