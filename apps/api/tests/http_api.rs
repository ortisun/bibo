//! The API through the real server on a loopback port and a real PostgreSQL: health, submission,
//! status and timeline, authentication (NT-WEB-05), tenant isolation (NT-TEN-05), the roles of
//! the allowlist, decisions, the shape of every answer, and what the server does with input that
//! is hostile, oversized or slow.
//!
//! The database needs a PostgreSQL server (`docs/database/running.md`); a test that cannot get one
//! panics with `BLOCKED:` and is never a pass.

mod support;

use std::time::{Duration, Instant};

use factory_domain::ids::{JobId, StageRunId};
use factory_domain::scope::TenantScope;
use factory_domain::vocabulary::StageKind;
use factory_ports::store::{NewStageRun, Store};
use serde_json::{Value, json};
use support::{Env, Kind, Person, Req, Tenant, open, read_to_close};

macro_rules! env_test {
    ($name:ident, |$env:ident| $body:block) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn $name() {
            let $env = Env::start().await;
            $body
            $env.stop().await;
        }
    };
}

async fn submit(env: &Env, tenant: &Tenant, key: &str, text: &str) -> support::Reply {
    env.send(
        Req::post("/v1/jobs")
            .bearer(&tenant.requester.token)
            .header("Idempotency-Key", key)
            .json(&json!({"repository_id": tenant.repository.as_text(), "source_ref": format!("{}#1", tenant.full_name), "text": text})),
    )
    .await
}

async fn new_job(env: &Env, tenant: &Tenant, key: &str) -> String {
    let reply = submit(env, tenant, key, "Add a word count to the report.").await;
    assert_eq!(reply.status, 201, "{}", reply.text());
    reply.json()["job_id"].as_str().expect("job id").to_owned()
}

async fn stage_run(env: &Env, tenant: &Tenant, job: &str) -> StageRunId {
    let id = StageRunId::from_uuid(uuid::Uuid::from_u128(rand_u128()));
    let mut tx = env
        .worker
        .begin(TenantScope::new(tenant.id))
        .await
        .expect("begin");
    tx.insert_stage_run(NewStageRun {
        id,
        job_id: JobId::parse(job).expect("job id"),
        kind: StageKind::Approval,
        run_number: 1,
        max_attempts: 3,
        rework_of: None,
    })
    .await
    .expect("insert the stage run");
    tx.commit().await.expect("commit");
    id
}

fn rand_u128() -> u128 {
    use factory_ports::clock::IdGenerator;
    factory_composition::system::RandomIds::new()
        .expect("ids")
        .new_uuid()
        .as_u128()
}

fn decision(env_tenant: &Tenant, person: &Person, job: &str, key: &str, body: &Value) -> Req {
    let _ = env_tenant;
    Req::post(&format!("/v1/jobs/{job}/decisions"))
        .bearer(&person.token)
        .header("Idempotency-Key", key)
        .json(body)
}

// ---- health -------------------------------------------------------------------------------

env_test!(health_and_readiness_need_no_token, |env| {
    let live = env.send(Req::get("/healthz")).await;
    assert_eq!((live.status, live.json()), (200, json!({"status": "live"})));
    let ready = env.send(Req::get("/readyz")).await;
    assert_eq!(ready.status, 200, "{}", ready.text());
    let body = ready.json();
    assert_eq!(body["ready"], true);
    let names: Vec<&str> = body["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .map(|check| check["name"].as_str().expect("name"))
        .collect();
    assert_eq!(names, ["database schema", "policy", "ports"]);
    // No detail sentence reaches an anonymous caller.
    assert!(!ready.text().contains("migrations"));
});

env_test!(readiness_checks_schema_version, |env| {
    assert_eq!(env.send(Req::get("/readyz")).await.status, 200);
    // The database is put one migration behind the code, as a restore of an older backup would.
    env.db
        .run("DELETE FROM __diesel_schema_migrations WHERE version = (SELECT max(version) FROM __diesel_schema_migrations)")
        .await;
    let behind = env.send(Req::get("/readyz")).await;
    assert_eq!(behind.status, 503, "{}", behind.text());
    let body = behind.json();
    assert_eq!(body["ready"], false);
    assert_eq!(body["checks"][0]["name"], "database schema");
    assert_eq!(body["checks"][0]["status"], "fail");
    // Liveness does not depend on the database.
    assert_eq!(env.send(Req::get("/healthz")).await.status, 200);
});

// ---- submission, status, timeline ---------------------------------------------------------

env_test!(a_submitted_job_can_be_read_back_with_its_timeline, |env| {
    let reply = submit(&env, &env.a, "key-1", "Add a word count to the report.").await;
    assert_eq!(reply.status, 201, "{}", reply.text());
    let created = reply.json();
    assert_eq!(created["status"], "RECEIVED");
    assert_eq!(created["created"], true);
    let job = created["job_id"].as_str().expect("job id");

    let status = env
        .send(Req::get(&format!("/v1/jobs/{job}")).bearer(&env.a.requester.token))
        .await;
    assert_eq!(status.status, 200, "{}", status.text());
    let body = status.json();
    assert_eq!(body["job_id"], job);
    assert_eq!(body["status"], "RECEIVED");
    assert_eq!(body["repository_id"], env.a.repository.as_text());
    assert_eq!(body["requester_id"], env.a.requester.principal.as_text());
    assert_eq!(body["execution_mode"], "test");
    // No branch protection preflight has passed, so the repository runs at L0 whatever its ceiling.
    assert_eq!(body["autonomy_level"], "L0");
    assert_eq!(body["pipeline_scope"].as_array().expect("scope").len(), 13);

    let timeline = env
        .send(Req::get(&format!("/v1/jobs/{job}/timeline")).bearer(&env.a.requester.token))
        .await;
    assert_eq!(timeline.status, 200, "{}", timeline.text());
    let entries = timeline.json()["entries"].clone();
    assert_eq!(entries[0]["kind"], "audit");
    assert_eq!(entries[0]["action"], "job.submitted");
    assert_eq!(entries[0]["decision"], "record");

    // The request is stored exactly as received.
    let stored = env
        .db
        .text(&format!(
            "SELECT request_text FROM original_requests WHERE job_id = '{job}'"
        ))
        .await;
    assert_eq!(stored.as_deref(), Some("Add a word count to the report."));

    let listed = env
        .send(Req::get("/v1/jobs?limit=5").bearer(&env.a.requester.token))
        .await;
    assert_eq!(listed.status, 200);
    assert_eq!(listed.json()["jobs"][0]["job_id"], job);
});

env_test!(submitting_twice_with_one_key_makes_one_job, |env| {
    let first = submit(&env, &env.a, "retry-key", "The same request.").await;
    let second = submit(&env, &env.a, "retry-key", "The same request.").await;
    assert_eq!((first.status, second.status), (201, 200));
    assert_eq!(first.json()["job_id"], second.json()["job_id"]);
    assert_eq!(second.json()["created"], false);
    assert_eq!(env.db.number("SELECT count(*) FROM jobs").await, 1);
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM audit_events WHERE action = 'job.submitted'")
            .await,
        1
    );
    // The same key with another request is a conflict, and nothing changes.
    let other = submit(&env, &env.a, "retry-key", "A different request.").await;
    assert_eq!(other.status, 409, "{}", other.text());
    assert_eq!(env.db.number("SELECT count(*) FROM jobs").await, 1);
    // Another tenant using the same key is its own job.
    let theirs = submit(&env, &env.b, "retry-key", "The same request.").await;
    assert_eq!(theirs.status, 201);
    assert_ne!(theirs.json()["job_id"], first.json()["job_id"]);
});

env_test!(
    a_submission_needs_a_key_a_json_type_and_the_requester_designation,
    |env| {
        let body = json!({"repository_id": env.a.repository.as_text(), "source_ref": format!("{}#1", env.a.full_name), "text": "x"});
        let no_key = env
            .send(
                Req::post("/v1/jobs")
                    .bearer(&env.a.requester.token)
                    .json(&body),
            )
            .await;
        assert_eq!(
            (no_key.status, no_key.json()["field"].clone()),
            (400, json!("idempotency-key"))
        );
        let text_plain = env
            .send(
                Req::post("/v1/jobs")
                    .bearer(&env.a.requester.token)
                    .header("Idempotency-Key", "k")
                    .header("Content-Type", "text/plain")
                    .body(serde_json::to_vec(&body).expect("json")),
            )
            .await;
        assert_eq!(text_plain.status, 415);
        // An approver is not a requester; a principal that is not on the allowlist is nobody.
        for person in [&env.a.approver, &env.a.outsider] {
            let reply = env
                .send(
                    Req::post("/v1/jobs")
                        .bearer(&person.token)
                        .header("Idempotency-Key", "k")
                        .json(&body),
                )
                .await;
            assert_eq!(reply.status, 403, "{}", person.login);
        }
        assert_eq!(env.db.number("SELECT count(*) FROM jobs").await, 0);
        // A repository of another tenant is not found, whatever its id.
        let foreign = env
            .send(
                Req::post("/v1/jobs")
                    .bearer(&env.a.requester.token)
                    .header("Idempotency-Key", "k2")
                    .json(&json!({"repository_id": env.b.repository.as_text(), "source_ref": format!("{}#1", env.b.full_name), "text": "x"})),
            )
            .await;
        assert_eq!(foreign.status, 404);
    }
);

// ---- NT-WEB-05: authentication ------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_web_05() {
    let env = Env::start().await;
    let job = new_job(&env, &env.a, "k").await;
    let path = format!("/v1/jobs/{job}");
    let expired = env
        .issue_token(&env.a, &env.a.requester, Kind::Expired)
        .await;
    let revoked = env
        .issue_token(&env.a, &env.a.requester, Kind::Revoked)
        .await;
    let other_audience = env
        .issue_token(&env.a, &env.a.requester, Kind::WrongAudience)
        .await;
    // A token of the right shape that the table has never seen.
    let unknown = factory_api::tokens::format_token(&[9_u8; 32]);
    // Built from parts so that no token-shaped literal sits in the source.
    let jwt_none = [
        "eyJhbGci",
        "OiJub25lIiwidHlwIjoiSldUIn0",
        ".",
        "eyJzdWIiOiIxIiwidGVuYW50IjoiYSJ9",
        ".",
    ]
    .concat();
    let good = env.a.requester.token.clone();
    let cases: Vec<(&str, Req)> = vec![
        ("no header", Req::get(&path)),
        ("expired", Req::get(&path).bearer(&expired)),
        ("revoked", Req::get(&path).bearer(&revoked)),
        ("wrong audience", Req::get(&path).bearer(&other_audience)),
        ("unknown token", Req::get(&path).bearer(&unknown)),
        ("jwt with no algorithm", Req::get(&path).bearer(&jwt_none)),
        (
            "wrong scheme",
            Req::get(&path).header("Authorization", &format!("Basic {good}")),
        ),
        (
            "token without a scheme",
            Req::get(&path).header("Authorization", &good),
        ),
        (
            "two headers",
            Req::get(&path)
                .header("Authorization", &format!("Bearer {good}"))
                .header("Authorization", &format!("Bearer {good}")),
        ),
        (
            "empty bearer",
            Req::get(&path).header("Authorization", "Bearer "),
        ),
        (
            "a session cookie",
            Req::get(&path).header("Cookie", "session=abc"),
        ),
    ];
    let mut seen: Vec<(Vec<u8>, Vec<String>)> = Vec::new();
    for (name, request) in cases {
        let reply = env.send(request).await;
        assert_eq!(reply.status, 401, "{name}: {}", reply.text());
        assert_eq!(reply.json(), json!({"error": "unauthorized"}), "{name}");
        assert_eq!(reply.header("www-authenticate"), Some("Bearer"), "{name}");
        seen.push((reply.body.clone(), reply.header_names()));
    }
    // One answer for every reason: the bytes and the header names do not differ.
    assert!(seen.windows(2).all(|pair| pair[0] == pair[1]));
    // The control: the same request with a good token works.
    assert_eq!(env.send(Req::get(&path).bearer(&good)).await.status, 200);
    // A token valid in the database stops working when it is revoked after use.
    let live = env.issue_token(&env.a, &env.a.requester, Kind::Valid).await;
    assert_eq!(env.send(Req::get(&path).bearer(&live)).await.status, 200);
    env.db
        .run(&format!(
            "UPDATE api_tokens SET revoked_at = now() WHERE token_hash = decode('{}', 'hex')",
            factory_api::tokens::hash_token(&live)
                .0
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ))
        .await;
    assert_eq!(env.send(Req::get(&path).bearer(&live)).await.status, 401);
    // A disabled principal's token stops working too.
    env.db
        .run(&format!(
            "UPDATE principals SET disabled_at = now() WHERE id = '{}'",
            env.a.approver.principal.as_uuid()
        ))
        .await;
    assert_eq!(
        env.send(Req::get(&path).bearer(&env.a.approver.token))
            .await
            .status,
        401
    );
    env.stop().await;
}

// ---- NT-TEN-05: another tenant's objects --------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_ten_05() {
    let env = Env::start().await;
    let theirs = new_job(&env, &env.b, "kb").await;
    let run = stage_run(&env, &env.b, &theirs).await;
    let missing = JobId::from_uuid(uuid::Uuid::from_u128(rand_u128())).as_text();
    let token = env.a.requester.token.clone();

    let probes = |job: String| {
        vec![
            Req::get(&format!("/v1/jobs/{job}")).bearer(&token),
            Req::get(&format!("/v1/jobs/{job}/timeline")).bearer(&token),
            Req::post(&format!("/v1/jobs/{job}/decisions"))
                .bearer(&env.a.approver.token)
                .header("Idempotency-Key", "k")
                .json(&json!({"verb": "approve", "stage_run_id": run.as_text(),
                    "head": "a".repeat(40), "evidence": format!("sha256:{}", "b".repeat(64))})),
        ]
    };
    let mut foreign_times = Vec::new();
    let mut missing_times = Vec::new();
    for (foreign, absent) in probes(theirs.clone())
        .into_iter()
        .zip(probes(missing.clone()))
    {
        let started = Instant::now();
        let foreign = env.send(foreign).await;
        foreign_times.push(started.elapsed());
        let started = Instant::now();
        let absent = env.send(absent).await;
        missing_times.push(started.elapsed());
        // The same status, the same bytes, the same header names.
        assert_eq!(foreign.status, 404, "{}", foreign.text());
        assert_eq!(foreign.body, absent.body);
        assert_eq!(foreign.header_names(), absent.header_names());
    }
    // Sequential guesses next to the real id are not found either, and nothing was written.
    let base = uuid::Uuid::parse_str(&theirs).expect("uuid").as_u128();
    for step in 1..=5_u128 {
        let guess = uuid::Uuid::from_u128(base.wrapping_add(step))
            .hyphenated()
            .to_string();
        let reply = env
            .send(Req::get(&format!("/v1/jobs/{guess}")).bearer(&token))
            .await;
        assert_eq!(reply.status, 404);
    }
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM audit_events WHERE action LIKE 'decision.%'")
            .await,
        0
    );
    // The listing shows tenant A's jobs only.
    let _mine = new_job(&env, &env.a, "ka").await;
    let listed = env.send(Req::get("/v1/jobs").bearer(&token)).await.json();
    let ids: Vec<&str> = listed["jobs"]
        .as_array()
        .expect("jobs")
        .iter()
        .map(|job| job["job_id"].as_str().expect("id"))
        .collect();
    assert_eq!(ids.len(), 1);
    assert!(!ids.contains(&theirs.as_str()));
    // No timing oracle: a foreign object costs about what a missing one does.
    let median = |mut times: Vec<Duration>| {
        times.sort();
        times[times.len() / 2]
    };
    let (f, m) = (median(foreign_times), median(missing_times));
    let gap = f.abs_diff(m);
    assert!(
        gap < Duration::from_millis(100),
        "foreign {f:?}, missing {m:?}"
    );
    env.stop().await;
}

/// Row-level security alone: the API login, in a tenant transaction for A, with a query that has
/// no tenant predicate at all, sees none of B's rows. The application layer is not involved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rls_alone_hides_the_other_tenants_rows() {
    use diesel::sql_query;
    use diesel::sql_types::Text;
    use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
    let env = Env::start().await;
    let theirs = new_job(&env, &env.b, "kb").await;
    let logins = env.db.server.logins().await;
    let mut connection = env.db.connect_as(&logins.api).await;
    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        n: i64,
    }
    let _ = Text;
    connection.batch_execute("BEGIN").await.expect("begin");
    sql_query(format!(
        "SELECT set_config('factory.tenant_id', '{}', true)",
        env.a.id.as_uuid()
    ))
    .execute(&mut connection)
    .await
    .expect("set the tenant");
    let own: Count = sql_query("SELECT count(*) AS n FROM jobs")
        .get_result(&mut connection)
        .await
        .expect("count");
    let foreign: Count = sql_query(format!(
        "SELECT count(*) AS n FROM jobs WHERE id = '{theirs}'"
    ))
    .get_result(&mut connection)
    .await
    .expect("count");
    connection
        .batch_execute("ROLLBACK")
        .await
        .expect("rollback");
    assert_eq!(own.n, 0, "tenant A has no job, and B's are not counted");
    assert_eq!(
        foreign.n, 0,
        "B's job is invisible without any WHERE on the tenant"
    );
    env.stop().await;
}

/// The application layer alone: row-level security is switched off in the test database, as a
/// superuser can, and tenant A still does not get B's job, because every query is scoped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_application_scope_alone_hides_the_other_tenants_job() {
    let env = Env::start().await;
    let theirs = new_job(&env, &env.b, "kb").await;
    for table in ["jobs", "stage_runs", "audit_events", "outbox"] {
        env.db
            .run(&format!(
                "ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY; ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"
            ))
            .await;
    }
    // Control: with RLS off, the row is visible to a query with no tenant predicate.
    assert_eq!(
        env.db
            .number(&format!("SELECT count(*) FROM jobs WHERE id = '{theirs}'"))
            .await,
        1
    );
    for suffix in ["", "/timeline"] {
        let reply = env
            .send(Req::get(&format!("/v1/jobs/{theirs}{suffix}")).bearer(&env.a.requester.token))
            .await;
        assert_eq!(reply.status, 404, "{suffix}: {}", reply.text());
    }
    env.stop().await;
}

// ---- roles and decisions ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn decisions_follow_the_allowlist_by_numeric_id() {
    let env = Env::start().await;
    let job = new_job(&env, &env.a, "k").await;
    let run = stage_run(&env, &env.a, &job).await.as_text();
    let approve = json!({"verb": "approve", "stage_run_id": run,
        "head": "a".repeat(40), "evidence": format!("sha256:{}", "b".repeat(64))});

    // The approver may approve; the reply says the engine has not applied it.
    let ok = env
        .send(decision(&env.a, &env.a.approver, &job, "d1", &approve))
        .await;
    assert_eq!(ok.status, 202, "{}", ok.text());
    assert_eq!(ok.json()["status"], "recorded");
    assert_eq!(ok.json()["applied"], false);

    // The operator, the requester, and a principal who is not on the allowlist may not.
    for person in [&env.a.operator, &env.a.requester, &env.a.outsider] {
        let denied = env
            .send(decision(&env.a, person, &job, "d2", &approve))
            .await;
        assert_eq!(denied.status, 403, "{}", person.login);
        assert_eq!(denied.json(), json!({"error": "forbidden"}));
    }

    // A login string decides nothing: the outsider's login is rewritten to the approver's, and the
    // numeric id still is not on the list.
    env.db
        .run(&format!(
            "UPDATE principals SET login = '{}' WHERE id = '{}'",
            env.a.approver.login,
            env.a.outsider.principal.as_uuid()
        ))
        .await;
    let by_login = env
        .send(decision(&env.a, &env.a.outsider, &job, "d3", &approve))
        .await;
    assert_eq!(by_login.status, 403);

    // Pause, resume and cancel belong to the operator; the approver may not.
    let cancel = json!({"verb": "cancel", "reason": "The request was withdrawn."});
    assert_eq!(
        env.send(decision(&env.a, &env.a.approver, &job, "d4", &cancel))
            .await
            .status,
        403
    );
    assert_eq!(
        env.send(decision(&env.a, &env.a.operator, &job, "d4", &cancel))
            .await
            .status,
        202
    );

    // The attempts are in the audit trail: the allowed ones as requests, the others as denials.
    let requested = env
        .db
        .number("SELECT count(*) FROM audit_events WHERE action = 'decision.requested'")
        .await;
    let denied = env
        .db
        .number("SELECT count(*) FROM audit_events WHERE action = 'decision.denied'")
        .await;
    assert_eq!((requested, denied), (2, 5));
    // Nothing moved: the API applies no decision.
    assert_eq!(
        env.db
            .text(&format!("SELECT status FROM jobs WHERE id = '{job}'"))
            .await
            .as_deref(),
        Some("RECEIVED")
    );
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retried_decision_is_one_record_and_a_changed_one_is_a_conflict() {
    let env = Env::start().await;
    let job = new_job(&env, &env.a, "k").await;
    let run = stage_run(&env, &env.a, &job).await.as_text();
    let reject =
        json!({"verb": "reject", "stage_run_id": run, "reason": "It does not meet the request."});
    let first = env
        .send(decision(&env.a, &env.a.approver, &job, "same", &reject))
        .await;
    let second = env
        .send(decision(&env.a, &env.a.approver, &job, "same", &reject))
        .await;
    assert_eq!((first.status, second.status), (202, 202));
    assert_eq!(first.json()["decision_id"], second.json()["decision_id"]);
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM audit_events WHERE action = 'decision.requested'")
            .await,
        1
    );
    let changed = json!({"verb": "reject", "stage_run_id": run, "reason": "A different reason."});
    let conflict = env
        .send(decision(&env.a, &env.a.approver, &job, "same", &changed))
        .await;
    assert_eq!(conflict.status, 409, "{}", conflict.text());
    env.stop().await;
}

/// AUT-12. The record the API writes ends with the time of the request and the keyed word that only
/// the API can make, over the tenant, the person, the event id, the time and the other words.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recorded_decision_carries_the_apis_word() {
    use factory_composition::decision_signing::{Signing, SubjectKind, read_subject};
    use factory_domain::ids::AuditEventId;

    let env = Env::start().await;
    let job = new_job(&env, &env.a, "k").await;
    let run = stage_run(&env, &env.a, &job).await.as_text();
    let reject =
        json!({"verb": "reject", "stage_run_id": run, "reason": "It does not meet the request."});
    let reply = env
        .send(decision(&env.a, &env.a.approver, &job, "signed", &reject))
        .await;
    assert_eq!(reply.status, 202, "{}", reply.text());
    let event = AuditEventId::parse(reply.json()["decision_id"].as_str().expect("an id"))
        .expect("an event id");
    let subject = env
        .db
        .text("SELECT subject FROM audit_events WHERE action = 'decision.requested'")
        .await
        .expect("a request is recorded");
    let Some(SubjectKind::Signed {
        fields,
        requested_at,
        word,
    }) = read_subject(&subject)
    else {
        panic!("the record is not signed: {subject}");
    };
    let signing = Signing {
        tenant: env.a.id,
        actor: env.a.approver.principal,
        event,
        requested_at: &requested_at,
        fields: &fields,
    };
    let keys = &env.state.decision_keys;
    assert!(keys.verify(&signing, &word), "the word is the API's");
    // The word belongs to this tenant, this person and this event.
    for other in [
        Signing {
            tenant: env.b.id,
            ..signing
        },
        Signing {
            actor: env.a.operator.principal,
            ..signing
        },
        Signing {
            event: AuditEventId::from_uuid(uuid::Uuid::from_u128(rand_u128())),
            ..signing
        },
    ] {
        assert!(!keys.verify(&other, &word));
    }
    // A refusal is not a request and carries no word: nothing applies it.
    let cancel = json!({"verb": "cancel", "reason": "The request was withdrawn."});
    let denied = env
        .send(decision(&env.a, &env.a.approver, &job, "denied", &cancel))
        .await;
    assert_eq!(denied.status, 403);
    let refused = env
        .db
        .text("SELECT subject FROM audit_events WHERE action = 'decision.denied'")
        .await
        .expect("a refusal is recorded");
    assert!(!refused.contains("mac="), "{refused}");
    env.stop().await;
}

/// AUT-12. A retry has a later time and so another word. It finds the record it wrote and answers as
/// the first did; a changed request under the same key is still a conflict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_a_second_later_is_still_one_record() {
    let env = Env::start().await;
    let job = new_job(&env, &env.a, "k").await;
    let run = stage_run(&env, &env.a, &job).await.as_text();
    let reject =
        json!({"verb": "reject", "stage_run_id": run, "reason": "It does not meet the request."});
    let first = env
        .send(decision(&env.a, &env.a.approver, &job, "same", &reject))
        .await;
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let second = env
        .send(decision(&env.a, &env.a.approver, &job, "same", &reject))
        .await;
    assert_eq!(
        (first.status, second.status),
        (202, 202),
        "{}",
        second.text()
    );
    assert_eq!(first.json(), second.json());
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM audit_events WHERE action = 'decision.requested'")
            .await,
        1
    );
    let changed = json!({"verb": "reject", "stage_run_id": run, "reason": "A different reason."});
    let conflict = env
        .send(decision(&env.a, &env.a.approver, &job, "same", &changed))
        .await;
    assert_eq!(conflict.status, 409, "{}", conflict.text());
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_decision_is_read_by_the_grammar_every_channel_shares() {
    let env = Env::start().await;
    let job = new_job(&env, &env.a, "k").await;
    let run = stage_run(&env, &env.a, &job).await.as_text();
    let other_run = stage_run(&env, &env.b, &new_job(&env, &env.b, "kb").await)
        .await
        .as_text();
    let head = "a".repeat(40);
    let evidence = format!("sha256:{}", "b".repeat(64));
    let cases: Vec<(&str, Value, u16, &str)> = vec![
        (
            "merge is not a verb",
            json!({"verb": "merge", "stage_run_id": run, "reason": "go"}),
            400,
            "verb",
        ),
        (
            "deploy is not a verb",
            json!({"verb": "deploy", "reason": "go"}),
            400,
            "verb",
        ),
        (
            "verbs are lower case",
            json!({"verb": "Approve", "stage_run_id": run}),
            400,
            "verb",
        ),
        (
            "approve needs a head",
            json!({"verb": "approve", "stage_run_id": run, "evidence": evidence}),
            400,
            "head",
        ),
        (
            "approve needs the evidence",
            json!({"verb": "approve", "stage_run_id": run, "head": head}),
            400,
            "evidence",
        ),
        (
            "approve needs a stage run",
            json!({"verb": "approve", "head": head, "evidence": evidence}),
            400,
            "stage_run_id",
        ),
        (
            "a head is hex",
            json!({"verb": "approve", "stage_run_id": run, "head": "zz", "evidence": evidence}),
            400,
            "head",
        ),
        (
            "rework needs a target",
            json!({"verb": "rework", "stage_run_id": run, "reason": "again"}),
            400,
            "target",
        ),
        (
            "rework target is a stage",
            json!({"verb": "rework", "stage_run_id": run, "target": "NOT A STAGE", "reason": "again"}),
            400,
            "target",
        ),
        (
            "reject says why",
            json!({"verb": "reject", "stage_run_id": run}),
            400,
            "reason",
        ),
        (
            "unknown field",
            json!({"verb": "cancel", "reason": "x", "force": true}),
            400,
            "body",
        ),
        (
            "a stage run of another job",
            json!({"verb": "reject", "stage_run_id": other_run, "reason": "x"}),
            404,
            "",
        ),
        (
            "a stage run id that is not an id",
            json!({"verb": "reject", "stage_run_id": "1; DROP TABLE jobs", "reason": "x"}),
            400,
            "stage_run_id",
        ),
    ];
    for (index, (name, body, status, field)) in cases.into_iter().enumerate() {
        let reply = env
            .send(decision(
                &env.a,
                &env.a.approver,
                &job,
                &format!("k-{index}"),
                &body,
            ))
            .await;
        assert_eq!(reply.status, status, "{name}: {}", reply.text());
        if !field.is_empty() {
            assert_eq!(reply.json()["field"], field, "{name}");
        }
    }
    // A reason that holds a secret is refused, not stored. The key is built at run time.
    let secret = ["gh", "p_", &"A1b2".repeat(9)].concat();
    let refused = env
        .send(decision(
            &env.a,
            &env.a.approver,
            &job,
            "secret",
            &json!({"verb": "cancel", "reason": format!("see {secret}")}),
        ))
        .await;
    assert_eq!(
        (refused.status, refused.json()["field"].clone()),
        (400, json!("reason"))
    );
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM audit_events WHERE action = 'decision.requested'")
            .await,
        0
    );
    env.stop().await;
}

// ---- hostile input ------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_and_hostile_input_is_a_400_and_never_a_500() {
    let env = Env::start().await;
    let token = env.a.requester.token.clone();
    let repository = env.a.repository.as_text();
    let post = |body: Vec<u8>| {
        Req::post("/v1/jobs")
            .bearer(&token)
            .header("Idempotency-Key", "hostile")
            .header("Content-Type", "application/json")
            .body(body)
    };
    let deep = format!("{}1{}", "[".repeat(5000), "]".repeat(5000));
    let bodies: Vec<(&str, Vec<u8>)> = vec![
        ("not JSON", b"not json".to_vec()),
        ("empty", Vec::new()),
        ("truncated", br#"{"repository_id": "#.to_vec()),
        ("an array", b"[1, 2]".to_vec()),
        ("null", b"null".to_vec()),
        (
            "invalid UTF-8",
            vec![b'{', b'"', 0xff, 0xfe, b'"', b':', b'1', b'}'],
        ),
        ("deep nesting", deep.into_bytes()),
        (
            "a duplicate key",
            format!(r#"{{"repository_id": "{repository}", "text": "a", "text": "b"}}"#)
                .into_bytes(),
        ),
        (
            "an unknown field",
            format!(r#"{{"repository_id": "{repository}", "text": "a", "tenant_id": "x"}}"#)
                .into_bytes(),
        ),
        (
            "a number for the text",
            format!(r#"{{"repository_id": "{repository}", "text": 5}}"#).into_bytes(),
        ),
        (
            "an SQL repository id",
            br#"{"repository_id": "x' OR '1'='1", "text": "a"}"#.to_vec(),
        ),
        (
            "a NUL in the text",
            format!(r#"{{"repository_id": "{repository}", "text": "a\u0000b"}}"#).into_bytes(),
        ),
        (
            "an escape in the text",
            format!(r#"{{"repository_id": "{repository}", "text": "a\u001b[31mb"}}"#).into_bytes(),
        ),
        (
            "an empty text",
            format!(r#"{{"repository_id": "{repository}", "text": "   "}}"#).into_bytes(),
        ),
        (
            "a line break in the source reference",
            format!(r#"{{"repository_id": "{repository}", "text": "a", "source_ref": "x\ny"}}"#)
                .into_bytes(),
        ),
    ];
    for (name, body) in bodies {
        let reply = env.send(post(body)).await;
        assert_eq!(reply.status, 400, "{name}: {}", reply.text());
        assert_eq!(reply.json()["error"], "bad_request", "{name}");
    }
    // SQL-ish text and control characters that are allowed are stored verbatim, as data.
    let sqlish = "Robert'); DROP TABLE jobs;--\n\ttab and \"quotes\" and \\ backslash and 100% and $1 and {{x}}";
    let stored = submit(&env, &env.a, "sqlish", sqlish).await;
    assert_eq!(stored.status, 201, "{}", stored.text());
    let job = stored.json()["job_id"].as_str().expect("id").to_owned();
    assert_eq!(
        env.db
            .text(&format!(
                "SELECT request_text FROM original_requests WHERE job_id = '{job}'"
            ))
            .await
            .as_deref(),
        Some(sqlish)
    );
    assert_eq!(env.db.number("SELECT count(*) FROM jobs").await, 1);
    // Hostile values in headers and in the path.
    for key in ["a'; DROP TABLE jobs;--", "a b", "", &"k".repeat(200)] {
        let reply = env
            .send(
                Req::post("/v1/jobs")
                    .bearer(&token)
                    .header("Idempotency-Key", key)
                    .json(&json!({"repository_id": repository, "text": "x"})),
            )
            .await;
        assert_eq!(reply.status, 400, "key {key:?}");
    }
    for path in [
        "/v1/jobs/not-a-uuid",
        "/v1/jobs/%00",
        "/v1/jobs/..%2f..%2fetc",
        "/v1/jobs/1' OR '1'='1",
        "/v1/jobs/%ff%fe",
    ] {
        let reply = env.send(Req::get(path).bearer(&token)).await;
        assert!(
            matches!(reply.status, 400 | 404),
            "{path}: {}",
            reply.status
        );
        assert!(!reply.text().contains("rror:"), "{path}");
    }
    for query in [
        "limit=-1",
        "limit=1000000",
        "after=%00",
        "after=a'b",
        "x=1",
        "limit=1&limit=2&bad",
    ] {
        let reply = env
            .send(Req::get(&format!("/v1/jobs?{query}")).bearer(&token))
            .await;
        assert_eq!(reply.status, 400, "{query}");
    }
    env.stop().await;
}

// ---- the shape of every answer ------------------------------------------------------------

env_test!(
    an_unknown_route_a_wrong_method_and_a_refusal_share_one_shape,
    |env| {
        let unknown = env.send(Req::get("/v2/anything")).await;
        let wrong_method = env.send(Req::new("DELETE", "/v1/jobs")).await;
        let unauthorized = env.send(Req::get("/v1/jobs")).await;
        assert_eq!(
            (unknown.status, wrong_method.status, unauthorized.status),
            (404, 405, 401)
        );
        for reply in [&unknown, &wrong_method, &unauthorized] {
            let body = reply.json();
            assert_eq!(
                body.as_object().expect("object").keys().collect::<Vec<_>>(),
                ["error"]
            );
            assert_eq!(reply.header("content-type"), Some("application/json"));
            assert_eq!(reply.header("cache-control"), Some("no-store"));
            assert_eq!(reply.header("x-content-type-options"), Some("nosniff"));
            assert!(
                reply
                    .header("content-security-policy")
                    .is_some_and(|v| v.contains("frame-ancestors 'none'"))
            );
            assert_eq!(reply.header("referrer-policy"), Some("no-referrer"));
            assert!(reply.header("server").is_none());
            assert!(reply.header("x-powered-by").is_none());
        }
        assert_eq!(unknown.header_names(), wrong_method.header_names());
        assert_eq!(unknown.header_names(), unauthorized.header_names());
        // No stack trace, no SQL, no library text, no path of the source tree in any of them.
        for reply in [&unknown, &wrong_method, &unauthorized] {
            let text = reply.text().to_lowercase();
            for leak in [
                "panic", "sql", "diesel", "postgres", "src/", "stack", "axum", "hyper",
            ] {
                assert!(!text.contains(leak), "{leak}");
            }
        }
    }
);

env_test!(
    the_correlation_id_goes_in_and_out_and_is_never_a_free_string,
    |env| {
        let sent = "0190a3b2-7c4d-4e5f-8a6b-1c2d3e4f5a6b";
        let echoed = env
            .send(Req::get("/healthz").header("X-Correlation-Id", sent))
            .await;
        assert_eq!(echoed.header("x-correlation-id"), Some(sent));
        for bad in [
            "<script>alert(1)</script>",
            "not-a-uuid",
            "0190A3B2-7C4D-4E5F-8A6B-1C2D3E4F5A6B",
        ] {
            let reply = env
                .send(Req::get("/healthz").header("X-Correlation-Id", bad))
                .await;
            let given = reply.header("x-correlation-id").expect("always one");
            assert_ne!(given, bad);
            assert!(uuid::Uuid::parse_str(given).is_ok());
        }
        let job = env
            .send(
                Req::post("/v1/jobs")
                    .bearer(&env.a.requester.token)
                    .header("Idempotency-Key", "c")
                    .header("X-Correlation-Id", sent)
                    .json(&json!({"repository_id": env.a.repository.as_text(), "source_ref": format!("{}#1", env.a.full_name), "text": "x"})),
            )
            .await;
        assert_eq!(
            job.json()["correlation_id"],
            sent,
            "the job carries the caller's id"
        );
    }
);

// ---- limits and slow clients --------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_bodies_are_refused_before_and_while_they_are_read() {
    let env = Env::start().await;
    let token = env.a.requester.token.clone();
    let limit = env.state.limits.max_body_bytes;
    // A declared length over the limit: refused without waiting for the body.
    let mut stream = open(
        env.addr,
        format!(
            "POST /v1/jobs HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nIdempotency-Key: big\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            limit + 1
        )
        .as_bytes(),
    )
    .await;
    let raw = read_to_close(&mut stream, Duration::from_secs(5))
        .await
        .expect("answered");
    assert_eq!(support::parse_reply(&raw).status, 413);
    // A body that is over the limit and says nothing about it (chunked).
    let chunk = "a".repeat(limit + 10);
    let chunked = format!(
        "POST /v1/jobs HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nIdempotency-Key: big2\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{chunk}\r\n0\r\n\r\n",
        chunk.len()
    );
    let reply = support::send_bytes(env.addr, chunked.as_bytes()).await;
    assert_eq!(reply.status, 413, "{}", reply.text());
    // An anonymous caller cannot make the server read a body: the token is checked first.
    let anonymous = "POST /v1/jobs HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 50\r\n\r\n";
    let mut stream = open(env.addr, anonymous.as_bytes()).await;
    let raw = read_to_close(&mut stream, Duration::from_secs(5))
        .await
        .expect("answered without the body");
    assert_eq!(support::parse_reply(&raw).status, 401);
    // An oversized head is refused too.
    let big_head = format!(
        "GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\nX-Big: {}\r\n\r\n",
        "a".repeat(100_000)
    );
    let reply = support::send_bytes(env.addr, big_head.as_bytes()).await;
    assert!(matches!(reply.status, 431 | 400), "{}", reply.status);
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_sends_its_request_too_slowly_is_cut_off() {
    let limits = factory_api::config::Limits {
        header_timeout_ms: 400,
        body_timeout_ms: 400,
        ..factory_api::config::Limits::default()
    };
    let env = Env::start_with(support::Options {
        limits,
        ..support::Options::default()
    })
    .await;
    // Slow-loris: a head that never ends. The server closes the connection on its own.
    let mut stream = open(env.addr, b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-Slow: a").await;
    let started = Instant::now();
    let closed = read_to_close(&mut stream, Duration::from_secs(10)).await;
    assert!(closed.is_some(), "the connection was still open after 10 s");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    // A body that stalls after the head: 408, not a hung worker.
    let token = env.a.requester.token.clone();
    let mut stream = open(
        env.addr,
        format!(
            "POST /v1/jobs HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Bearer {token}\r\nIdempotency-Key: slow\r\nContent-Type: application/json\r\nContent-Length: 200\r\n\r\n{{\"repo"
        )
        .as_bytes(),
    )
    .await;
    let raw = read_to_close(&mut stream, Duration::from_secs(10))
        .await
        .expect("answered");
    assert_eq!(support::parse_reply(&raw).status, 408);
    // The server still serves everyone else.
    assert_eq!(env.send(Req::get("/healthz")).await.status, 200);
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connections_over_the_limit_are_closed_unread() {
    let limits = factory_api::config::Limits {
        max_connections: 2,
        header_timeout_ms: 5_000,
        ..factory_api::config::Limits::default()
    };
    let env = Env::start_with(support::Options {
        limits,
        ..support::Options::default()
    })
    .await;
    let _held_a = open(
        env.addr,
        b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-Partial: a",
    )
    .await;
    let _held_b = open(
        env.addr,
        b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-Partial: b",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut third = open(
        env.addr,
        b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    let raw = read_to_close(&mut third, Duration::from_secs(5))
        .await
        .expect("closed");
    assert!(raw.is_empty(), "a connection over the limit gets no answer");
    drop((_held_a, _held_b));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(env.send(Req::get("/healthz")).await.status, 200);
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forged_forwarding_header_changes_nothing() {
    let limits = factory_api::config::Limits {
        per_ip_per_minute: 4,
        ..factory_api::config::Limits::default()
    };
    let env = Env::start_with(support::Options {
        limits,
        ..support::Options::default()
    })
    .await;
    let mut statuses = Vec::new();
    for round in 0..7 {
        let reply = env
            .send(
                Req::get("/healthz")
                    .header("X-Forwarded-For", &format!("203.0.113.{round}"))
                    .header("X-Real-IP", &format!("198.51.100.{round}"))
                    .header("Forwarded", &format!("for=192.0.2.{round}"))
                    .header("X-Forwarded-Proto", "https")
                    .header("X-Forwarded-Host", "evil.example"),
            )
            .await;
        statuses.push(reply.status);
    }
    // Seven different claimed sources, one real peer: the fifth request is limited.
    assert_eq!(statuses, [200, 200, 200, 200, 429, 429, 429]);
    let limited = env.send(Req::get("/healthz")).await;
    assert_eq!(limited.header("retry-after"), Some("60"));
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_request_lets_an_open_request_finish_and_then_the_port_is_closed() {
    use tokio::io::AsyncWriteExt;
    let limits = factory_api::config::Limits {
        body_timeout_ms: 5_000,
        ..factory_api::config::Limits::default()
    };
    let env = Env::start_with(support::Options {
        limits,
        ..support::Options::default()
    })
    .await;
    let addr = env.addr;
    let body = serde_json::to_vec(&json!({
        "repository_id": env.a.repository.as_text(),
        "source_ref": format!("{}#1", env.a.full_name),
        "text": "A request that is still arriving when the stop request comes."
    }))
    .expect("json");
    let head = format!(
        "POST /v1/jobs HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Bearer {}\r\nIdempotency-Key: drain\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        env.a.requester.token,
        body.len()
    );
    let mut stream = open(addr, head.as_bytes()).await;
    stream.write_all(&body[..10]).await.expect("first part");
    tokio::time::sleep(Duration::from_millis(300)).await;
    env.shutdown.raise();
    tokio::time::sleep(Duration::from_millis(300)).await;
    stream.write_all(&body[10..]).await.expect("rest");
    let raw = read_to_close(&mut stream, Duration::from_secs(10))
        .await
        .expect("the open request is answered");
    assert_eq!(support::parse_reply(&raw).status, 201);
    env.stop().await;
    assert!(
        tokio::net::TcpStream::connect(addr).await.is_err(),
        "the port is still open after the stop"
    );
}

// A job is for one issue. Intake authorizes the person who labelled it and reads its text from the
// pointer, and delivery links the pull request to it, so a submission without a pointer that
// names an issue of the job's own repository is refused at the door and not left to fail in
// intake.
env_test!(
    a_submission_must_name_an_issue_of_its_own_repository,
    |env| {
        let repository = env.a.repository.as_text();
        let own = format!("{}#12", env.a.full_name);
        let post = |key: &'static str, body: serde_json::Value| {
            env.send(
                Req::post("/v1/jobs")
                    .bearer(&env.a.requester.token)
                    .header("Idempotency-Key", key)
                    .json(&body),
            )
        };

        // The honest submission.
        let ok = post(
            "source-ref-ok",
            json!({"repository_id": repository, "source_ref": own, "text": "Add a --json flag."}),
        )
        .await;
        assert_eq!(ok.status, 201, "{}", ok.text());

        // No pointer at all.
        let missing = post(
            "source-ref-missing",
            json!({"repository_id": repository, "text": "Add a --json flag."}),
        )
        .await;
        assert_eq!(missing.status, 400, "{}", missing.text());
        assert!(missing.text().contains("source_ref"), "{}", missing.text());

        // A pointer that does not name an issue.
        let keys = [
            "source-ref-bad-0",
            "source-ref-bad-1",
            "source-ref-bad-2",
            "source-ref-bad-3",
            "source-ref-bad-4",
        ];
        let bad_pointers = [
            "",
            "12",
            "org/repo-0",
            "org/repo-0#twelve",
            "https://example.test/issues/12",
        ];
        for (key, bad) in keys.into_iter().zip(bad_pointers) {
            let reply = post(
            key,
            json!({"repository_id": repository, "source_ref": bad, "text": "Add a --json flag."}),
        )
        .await;
            assert_eq!(reply.status, 400, "{bad:?}: {}", reply.text());
        }

        // An issue of another repository: the worker would ask the code host for something the job
        // has no right to.
        let elsewhere = post(
        "source-ref-elsewhere",
        json!({"repository_id": repository, "source_ref": format!("{}#12", env.b.full_name), "text": "Add a --json flag."}),
    )
    .await;
        assert_eq!(elsewhere.status, 400, "{}", elsewhere.text());
    }
);
