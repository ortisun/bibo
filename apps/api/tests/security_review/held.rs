//! Probes that were tried and held. They pass today; they are `#[ignore]`d only so that the
//! target stays out of the default run. Re-run them with `-- --ignored held_`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use diesel::sql_query;
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use factory_api::config::Limits;
use factory_domain::ids::{JobId, PrincipalId, RepositoryId, TenantId};
use factory_domain::machines::guards::AdmissionFacts;
use factory_domain::scope::TenantScope;
use factory_domain::values::{Sha256Digest, Slug};
use factory_domain::vocabulary::{Fidelity, HumanRole};
use factory_ports::store::{AuditAction, AuditActor, AuditDecision, NewAuditEvent, Store};
use factory_storage::pg::{PgStore, PgStoreConfig, TenantLogin};
use factory_workflow::commands::{Authority, AuthorityError};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::support::{Env, Kind, Options, Req, captured, send_bytes, small_pool};
use crate::util::{
    approval, decide, delivery_id, first_line, labeled, new_job, new_uuid, raw, responses,
    stage_run,
};

async fn counts(env: &Env) -> (i64, i64) {
    (
        env.db
            .number("SELECT count(*) FROM webhook_deliveries")
            .await,
        env.db.number("SELECT count(*) FROM jobs").await,
    )
}

// ---- HTTP/1.1 framing and routing ---------------------------------------------------------------

/// Hostile framing is refused by hyper before any handler sees it, and no request is smuggled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "held probe: passes today; hostile HTTP/1.1 framing"]
async fn held_hostile_framing_is_refused_and_nothing_is_smuggled() {
    let env = Env::start().await;
    let wait = Duration::from_millis(1500);
    let refused: Vec<(&str, &[u8])> = vec![
        ("two different Content-Length", b"POST /v1/webhooks/github HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\nConnection: close\r\n\r\nhello!"),
        ("Transfer-Encoding xchunked", b"POST /v1/webhooks/github HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: xchunked\r\nConnection: close\r\n\r\n0\r\n\r\n"),
        ("Transfer-Encoding chunked, identity", b"POST /v1/webhooks/github HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, identity\r\nConnection: close\r\n\r\n0\r\n\r\n"),
        ("space before the colon of TE", b"POST /v1/webhooks/github HTTP/1.1\r\nHost: x\r\nTransfer-Encoding : chunked\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0\r\n\r\n"),
        ("space before the colon of CL", b"POST /v1/webhooks/github HTTP/1.1\r\nHost: x\r\nContent-Length : 5\r\nConnection: close\r\n\r\nhello"),
        ("obsolete line folding", b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-A: b\r\n c\r\nConnection: close\r\n\r\n"),
        ("Content-Length with a plus sign", b"POST /v1/webhooks/github HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\nConnection: close\r\n\r\nhello"),
        ("Content-Length in hex", b"POST /v1/webhooks/github HTTP/1.1\r\nHost: x\r\nContent-Length: 0x5\r\nConnection: close\r\n\r\nhello"),
        ("Content-Length beyond u64", b"POST /v1/webhooks/github HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999999999\r\nConnection: close\r\n\r\nhello"),
        ("NUL in a header value", b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-A: a\x00b\r\nConnection: close\r\n\r\n"),
        ("chunk size overflow", b"POST /v1/webhooks/github HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nffffffffffffffffff\r\nhello\r\n0\r\n\r\n"),
    ];
    for (name, bytes) in refused {
        let (text, _) = raw(env.addr, bytes, wait).await;
        assert!(
            first_line(&text).contains(" 400 "),
            "{name}: {}",
            first_line(&text)
        );
    }
    // Content-Length and Transfer-Encoding together: one response, then the connection closes, so a
    // second request hidden after the "end" of the first is never run.
    let (text, closed) = raw(
        env.addr,
        b"POST /v1/webhooks/github HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        wait,
    )
    .await;
    assert_eq!((responses(&text), closed), (1, true), "{text}");
    // Too many headers.
    let mut many = b"GET /healthz HTTP/1.1\r\nHost: x\r\n".to_vec();
    for i in 0..200 {
        many.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
    }
    many.extend_from_slice(b"Connection: close\r\n\r\n");
    let (text, _) = raw(env.addr, &many, wait).await;
    assert!(first_line(&text).contains(" 431 "), "{}", first_line(&text));
    // HTTP/2 is not enabled: the connection preface is not an HTTP/1.1 request.
    let (text, _) = raw(env.addr, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", wait).await;
    assert!(!text.contains(" 200 "), "{text}");
    env.stop().await;
}

/// No cross-origin permission is ever granted, and the token travels only in the header.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "held probe: passes today; CORS, forwarded headers, query tokens"]
async fn held_no_cors_no_query_token_no_override() {
    let env = Env::start().await;
    let a = env.a.clone();
    let options = env
        .send(
            Req::new("OPTIONS", "/v1/jobs")
                .header("Origin", "https://evil.example")
                .header("Access-Control-Request-Method", "POST"),
        )
        .await;
    assert_eq!(options.status, 405);
    let get = env
        .send(
            Req::get("/v1/jobs")
                .bearer(&a.requester.token)
                .header("Origin", "https://evil.example"),
        )
        .await;
    assert_eq!(get.status, 200);
    for reply in [&options, &get] {
        assert!(
            !reply
                .header_names()
                .iter()
                .any(|name| name.starts_with("access-control-")
                    || name == "set-cookie"
                    || name == "server"),
            "{:?}",
            reply.header_names()
        );
    }
    let query = env
        .send(Req::get(&format!("/v1/jobs?token={}", a.requester.token)))
        .await;
    assert_eq!(query.status, 401);
    let override_header = env
        .send(
            Req::get("/v1/jobs")
                .bearer(&a.requester.token)
                .header("X-HTTP-Method-Override", "DELETE")
                .header("X-Forwarded-For", "203.0.113.9"),
        )
        .await;
    assert_eq!(override_header.status, 200);
    env.stop().await;
}

// ---- the webhook --------------------------------------------------------------------------------

/// Verification is over the raw bytes, and a body that is not exactly the bytes signed never reaches
/// a parser that could read it differently.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "held probe: passes today; webhook body encodings with a valid signature"]
async fn held_webhook_valid_signature_hostile_encodings_are_ignored() {
    let env = Env::start().await;
    let a = env.a.clone();
    let good = labeled(&a, "factory", a.requester.github_id, 1);
    let mut bom = vec![0xEF, 0xBB, 0xBF];
    bom.extend_from_slice(&good);
    let mut utf16 = Vec::new();
    for unit in String::from_utf8(good.clone())
        .expect("utf8")
        .encode_utf16()
    {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    let mut with_nul = good.clone();
    with_nul.push(0);
    let duplicate =
        br#"{"action":"labeled","action":"closed","installation":{"id":5000}}"#.to_vec();
    let escaped_duplicate = format!(
        r#"{{"action":"labeled","action":"closed","installation":{{"id":{}}}}}"#,
        a.installation
    )
    .into_bytes();
    let nested_duplicate = format!(
        r#"{{"action":"labeled","installation":{{"id":{},"id":1}},"repository":{{"id":{}}}}}"#,
        a.installation, a.github_repository
    )
    .into_bytes();
    for (n, (name, body)) in [
        ("byte order mark", bom),
        ("UTF-16", utf16),
        ("trailing NUL", with_nul),
        ("duplicate key", duplicate),
        ("duplicate key spelled with an escape", escaped_duplicate),
        ("duplicate key in a nested object", nested_duplicate),
    ]
    .into_iter()
    .enumerate()
    {
        let reply = env
            .send(env.delivery("issues", &delivery_id(10 + n as u64), &body))
            .await;
        assert_eq!(reply.status, 202, "{name}");
    }
    assert_eq!(
        counts(&env).await,
        (0, 0),
        "a hostile encoding was recorded"
    );

    // A Content-Encoding claim changes nothing: there is no decompression, so a bomb has nothing to
    // expand, and the signed bytes are the bytes parsed.
    let gz = env
        .send(
            env.delivery(
                "issues",
                &delivery_id(20),
                &labeled(&a, "other", a.requester.github_id, 2),
            )
            .header("Content-Encoding", "gzip"),
        )
        .await;
    assert_eq!(gz.status, 202);
    assert_eq!(counts(&env).await.0, 1, "the body was read as sent");

    // The control: the good delivery makes exactly one job.
    let ok = env
        .send(env.delivery("issues", &delivery_id(30), &good))
        .await;
    assert_eq!(ok.status, 202);
    assert_eq!(counts(&env).await, (2, 1));

    // A chunked body is the same bytes once reassembled, and verifies.
    let body = labeled(&a, "other", a.requester.github_id, 3);
    let (first, second) = body.split_at(20);
    let mut chunked = format!(
        "POST /v1/webhooks/github HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\
         Content-Type: application/json\r\nX-GitHub-Event: issues\r\nX-GitHub-Delivery: {}\r\nX-Hub-Signature-256: {}\r\n\r\n",
        delivery_id(40),
        env.sign(&body)
    )
    .into_bytes();
    for part in [first, second] {
        chunked.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
        chunked.extend_from_slice(part);
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let (text, _) = raw(env.addr, &chunked, Duration::from_secs(3)).await;
    assert!(first_line(&text).contains(" 202 "), "{text}");
    assert_eq!(counts(&env).await.0, 3);
    env.stop().await;
}

/// The installation and the repository pick the tenant, both are checked as a pair, and the sender
/// is looked up in that tenant only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "held probe: passes today; tenant selection by a signed payload"]
async fn held_webhook_cannot_select_another_tenant_or_borrow_its_people() {
    let env = Env::start().await;
    let (a, b) = (env.a.clone(), env.b.clone());
    let mut mixed_installation = serde_json::from_slice::<serde_json::Value>(&labeled(
        &a,
        "factory",
        a.requester.github_id,
        1,
    ))
    .expect("json");
    mixed_installation["installation"]["id"] = json!(b.installation);
    let mut mixed_repository = serde_json::from_slice::<serde_json::Value>(&labeled(
        &a,
        "factory",
        a.requester.github_id,
        2,
    ))
    .expect("json");
    mixed_repository["repository"]["id"] = json!(b.github_repository);
    let borrowed_sender = labeled(&a, "factory", b.requester.github_id, 3);
    let not_a_requester = labeled(&a, "factory", a.approver.github_id, 4);
    let mut bot = serde_json::from_slice::<serde_json::Value>(&labeled(
        &a,
        "factory",
        a.requester.github_id,
        5,
    ))
    .expect("json");
    bot["sender"]["type"] = json!("Bot");
    for (n, body) in [
        serde_json::to_vec(&mixed_installation).expect("json"),
        serde_json::to_vec(&mixed_repository).expect("json"),
        borrowed_sender,
        not_a_requester,
        serde_json::to_vec(&bot).expect("json"),
        labeled(&a, "Factory", a.requester.github_id, 6),
        labeled(&a, "factory\n", a.requester.github_id, 7),
    ]
    .into_iter()
    .enumerate()
    {
        let reply = env
            .send(env.delivery("issues", &delivery_id(100 + n as u64), &body))
            .await;
        assert_eq!(reply.status, 202, "case {n}");
    }
    assert_eq!(
        env.db.number("SELECT count(*) FROM jobs").await,
        0,
        "a hostile payload made a job"
    );
    let ok = labeled(&a, "factory", a.requester.github_id, 8);
    assert_eq!(
        env.send(env.delivery("issues", &delivery_id(200), &ok))
            .await
            .status,
        202
    );
    assert_eq!(
        env.db
            .number(&format!(
                "SELECT count(*) FROM jobs WHERE tenant_id = '{}'",
                a.id.as_uuid()
            ))
            .await,
        1
    );
    assert_eq!(
        env.db
            .number(&format!(
                "SELECT count(*) FROM jobs WHERE tenant_id = '{}'",
                b.id.as_uuid()
            ))
            .await,
        0
    );
    env.stop().await;
}

/// The same delivery id with another body, the same body under a new id, and thirty concurrent
/// copies each give one delivery and one job.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "held probe: passes today; replay and concurrent duplicates"]
async fn held_webhook_replays_make_one_delivery() {
    // Thirty copies arrive at once from this machine, more than one source may hold by default
    // (API-6): the share is a setting, and this probe is about replay.
    let env = Env::start_with(Options {
        limits: Limits {
            max_connections_per_source: Some(256),
            ..Limits::default()
        },
        ..Options::default()
    })
    .await;
    let a = env.a.clone();
    let first = labeled(&a, "other", a.requester.github_id, 50);
    let second = labeled(&a, "other", a.requester.github_id, 51);
    assert_eq!(
        env.send(env.delivery("issues", &delivery_id(1), &first))
            .await
            .status,
        202
    );
    assert_eq!(
        env.send(env.delivery("issues", &delivery_id(1), &second))
            .await
            .status,
        202
    );
    assert_eq!(
        env.send(env.delivery("issues", &delivery_id(2), &first))
            .await
            .status,
        202
    );
    assert_eq!(
        counts(&env).await.0,
        1,
        "a reused id or a reused body was recorded again"
    );

    let body = labeled(&a, "factory", a.requester.github_id, 60);
    let request = env.delivery("issues", &delivery_id(3), &body).build();
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..30 {
        let (addr, bytes) = (env.addr, request.clone());
        set.spawn(async move { send_bytes(addr, &bytes).await.status });
    }
    while let Some(status) = set.join_next().await {
        assert_eq!(status.expect("task"), 202);
    }
    assert_eq!(
        counts(&env).await,
        (2, 1),
        "thirty copies made more than one job"
    );
    env.stop().await;
}

// ---- tokens -------------------------------------------------------------------------------------

/// A revoked, expired or wrong-audience token stops working on the next request, and no token
/// appears in anything the process logs, whatever the request looked like.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "held probe: passes today; revocation without a cache, and no token in the logs"]
async fn held_tokens_are_revoked_at_once_and_never_logged() {
    let lines = captured();
    let env = Env::start().await;
    let a = env.a.clone();
    let token = env.issue_token(&a, &a.requester, Kind::Valid).await;
    assert_eq!(
        env.send(Req::get("/v1/jobs").bearer(&token)).await.status,
        200
    );
    let hash: String = factory_api::tokens::hash_token(&token)
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    env.db
        .run(&format!(
            "UPDATE api_tokens SET revoked_at = now() WHERE token_hash = decode('{hash}', 'hex')"
        ))
        .await;
    assert_eq!(
        env.send(Req::get("/v1/jobs").bearer(&token)).await.status,
        401,
        "a revoked token worked on the next request"
    );
    for kind in [Kind::Expired, Kind::Revoked, Kind::WrongAudience] {
        let bad = env.issue_token(&a, &a.requester, kind).await;
        let reply = env.send(Req::get("/v1/jobs").bearer(&bad)).await;
        assert_eq!(
            (reply.status, reply.text()),
            (401, "{\"error\":\"unauthorized\"}".to_owned()),
            "{kind:?}"
        );
    }

    // Requests that carry a token in every place a careless server might log it.
    let live = env.a.requester.token.clone();
    for request in [
        Req::get("/v1/jobs").bearer(&live),
        Req::get(&format!("/v1/jobs/{live}")).bearer(&live),
        Req::get(&format!("/v1/jobs?after={live}")).bearer(&live),
        Req::get("/v1/jobs").header("X-Api-Key", &live),
        Req::get("/v1/jobs")
            .header("X-Correlation-Id", &live)
            .bearer(&live),
        Req::get("/v1/jobs").header("Authorization", &format!("Bearer  {live}")),
        Req::post("/v1/jobs")
            .bearer(&live)
            .header("Idempotency-Key", &live)
            .json(&json!({"repository_id": live, "text": live})),
        Req::post(&format!("/v1/jobs/{}/decisions", new_uuid()))
            .bearer(&live)
            .header("Idempotency-Key", "k")
            .json(&json!({"verb": live})),
    ] {
        let reply = env.send(request).await;
        assert!(
            !reply.text().contains(&live),
            "a token was echoed in a body"
        );
        assert!(
            reply
                .headers
                .iter()
                .all(|(_, value)| !value.contains(&live)),
            "a token was echoed in a header"
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let seen = lines
        .lock()
        .expect("the capture")
        .iter()
        .filter(|line| line.contains(&live) || line.contains(&token))
        .cloned()
        .collect::<Vec<_>>();
    assert!(seen.is_empty(), "a token reached the logs: {seen:?}");
    env.stop().await;
}

// ---- authorization ------------------------------------------------------------------------------

/// Every route for every designation, across tenants and for objects that do not exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "held probe: passes today; role x route x tenant matrix"]
async fn held_authorization_matrix() {
    let env = Env::start().await;
    let (a, b) = (env.a.clone(), env.b.clone());
    let job = new_job(&env, &a, "m").await;
    let job_b = new_job(&env, &b, "m").await;
    let run = stage_run(&env, &a, &job).await;
    let missing = new_uuid().to_string();
    let approve = approval(&run);
    let cancel = json!({"verb": "cancel", "reason": "withdrawn"});
    type Row<'a> = (&'a str, &'a crate::support::Person, Vec<u16>);
    // list, get A, get B, get missing, timeline A, submit to A, submit to B, approve A, cancel A,
    // approve B's job, cancel a missing job
    let rows: Vec<Row<'_>> = vec![
        (
            "A.requester",
            &a.requester,
            vec![200, 200, 404, 404, 200, 201, 404, 403, 403, 403, 403],
        ),
        (
            "A.approver",
            &a.approver,
            vec![200, 200, 404, 404, 200, 403, 403, 202, 403, 404, 403],
        ),
        (
            "A.operator",
            &a.operator,
            vec![200, 200, 404, 404, 200, 403, 403, 403, 202, 403, 404],
        ),
        ("A.outsider", &a.outsider, vec![403; 11]),
        (
            "B.requester",
            &b.requester,
            vec![200, 404, 200, 404, 404, 404, 201, 403, 403, 403, 403],
        ),
    ];
    for (name, person, expected) in rows {
        let mut seen = Vec::new();
        for request in [
            Req::get("/v1/jobs").bearer(&person.token),
            Req::get(&format!("/v1/jobs/{job}")).bearer(&person.token),
            Req::get(&format!("/v1/jobs/{job_b}")).bearer(&person.token),
            Req::get(&format!("/v1/jobs/{missing}")).bearer(&person.token),
            Req::get(&format!("/v1/jobs/{job}/timeline")).bearer(&person.token),
            Req::post("/v1/jobs")
                .bearer(&person.token)
                .header("Idempotency-Key", &format!("sa-{name}"))
                .json(&json!({"repository_id": a.repository.as_text(), "text": "x"})),
            Req::post("/v1/jobs")
                .bearer(&person.token)
                .header("Idempotency-Key", &format!("sb-{name}"))
                .json(&json!({"repository_id": b.repository.as_text(), "text": "x"})),
            decide(person, &job, &format!("ap-{name}"), &approve),
            decide(person, &job, &format!("ca-{name}"), &cancel),
            decide(person, &job_b, &format!("ab-{name}"), &approve),
            decide(person, &missing, &format!("am-{name}"), &cancel),
        ] {
            seen.push(env.send(request).await.status);
        }
        assert_eq!(seen, expected, "{name}");
    }
    // A foreign stage run and a stage run of another job of the same tenant are both "not found".
    let other_job = new_job(&env, &a, "m2").await;
    let other_run = stage_run(&env, &a, &other_job).await;
    for wrong_run in [other_run, stage_run(&env, &b, &job_b).await] {
        let reply = env
            .send(decide(
                &a.approver,
                &job,
                &format!("wr-{wrong_run}"),
                &approval(&wrong_run),
            ))
            .await;
        assert_eq!(reply.status, 404, "{wrong_run}");
    }
    // Unknown fields, repeated keys and a login in the body decide nothing.
    for body in [
        br#"{"verb":"cancel","reason":"x","actor":"someone"}"#.to_vec(),
        br#"{"verb":"cancel","verb":"approve","reason":"x"}"#.to_vec(),
        br#"{"verb":"cancel","reason":"x","tenant_id":"00000000-0000-0000-0000-000000000000"}"#
            .to_vec(),
    ] {
        let reply = env
            .send(
                Req::post(&format!("/v1/jobs/{job}/decisions"))
                    .bearer(&a.operator.token)
                    .header("Idempotency-Key", "odd")
                    .header("Content-Type", "application/json")
                    .body(body),
            )
            .await;
        assert_eq!(reply.status, 400);
    }
    env.stop().await;
}

// ---- the database -------------------------------------------------------------------------------

/// What the API login cannot do, over a raw connection with its own credentials.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "held probe: passes today; limits of the API login"]
async fn held_the_service_database_login_is_neither_the_engine_nor_a_bypass() {
    let env = Env::start().await;
    let (a, b) = (env.a.clone(), env.b.clone());
    new_job(&env, &a, "db").await;
    new_job(&env, &b, "db").await;
    let logins = env.db.server.logins().await;
    let mut api = env.db.connect_as(&logins.api).await;

    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        n: i64,
    }
    #[derive(diesel::QueryableByName)]
    struct Name {
        #[diesel(sql_type = diesel::sql_types::Text)]
        n: String,
    }
    let none: Count = sql_query("SELECT count(*) AS n FROM jobs")
        .get_result(&mut api)
        .await
        .expect("count");
    assert_eq!(none.n, 0, "with no tenant named, rows are visible");
    for statement in [
        "SET ROLE factory_system",
        "ALTER TABLE jobs DISABLE ROW LEVEL SECURITY",
        "ALTER ROLE CURRENT_USER BYPASSRLS",
        "CREATE POLICY everything ON jobs USING (true)",
        "UPDATE audit_events SET reason = 'x'",
        "DELETE FROM audit_events",
        "TRUNCATE ledger_entries",
        "DROP TABLE jobs",
        "CREATE TABLE review_probe (x int)",
        "CREATE ROLE review_probe LOGIN",
        "GRANT factory_system TO CURRENT_USER",
        "COPY jobs TO PROGRAM 'id'",
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT lo_import('/etc/passwd')",
    ] {
        assert!(
            api.batch_execute(statement).await.is_err(),
            "the API login ran: {statement}"
        );
    }
    // A foreign row cannot be written under the other tenant's name from inside a transaction of
    // this one, and the other tenant's rows cannot be read.
    api.batch_execute("BEGIN").await.expect("begin");
    sql_query(format!(
        "SELECT set_config('factory.tenant_id', '{}', true)",
        a.id.as_uuid()
    ))
    .execute(&mut api)
    .await
    .expect("set");
    let own: Count = sql_query("SELECT count(*) AS n FROM jobs")
        .get_result(&mut api)
        .await
        .expect("count");
    assert_eq!(own.n, 1);
    let insert = |tenant: &str| {
        format!(
            "INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, correlation_id) \
             VALUES ('{tenant}', '{}', 'anonymous', 'review', 'review.probe', 's', 'record', 'r', 'sha256:{}', '{}')",
            new_uuid(),
            "0".repeat(64),
            new_uuid()
        )
    };
    api.batch_execute(&insert(&a.id.as_uuid().to_string()))
        .await
        .expect("control: a row for the tenant that is named works");
    let foreign = api
        .batch_execute(&insert(&b.id.as_uuid().to_string()))
        .await;
    assert!(
        foreign.is_err(),
        "a row for tenant B was written in a transaction of tenant A"
    );
    api.batch_execute("ROLLBACK").await.expect("rollback");
    // No function that finds work across tenants or moves the engine's rows is executable.
    let names: Vec<Name> = sql_query(
        "SELECT p.proname::text AS n FROM pg_proc p JOIN pg_namespace s ON s.oid = p.pronamespace \
         WHERE s.nspname = 'public' AND p.prorettype <> 'pg_catalog.trigger'::regtype \
           AND has_function_privilege(current_user, p.oid, 'EXECUTE')",
    )
    .load(&mut api)
    .await
    .expect("functions");
    assert!(!names.is_empty(), "the lookups at least are executable");
    for name in names {
        for forbidden in ["claim", "sweep", "lease", "relay", "publish", "admit"] {
            assert!(!name.n.contains(forbidden), "executable: {}", name.n);
        }
    }
    env.stop().await;
}

/// A transaction dropped at a random moment (as hyper does when a client hangs up) never leaves a
/// connection that mixes tenants or loses the next caller's commit, with a pool of one connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "held probe: passes today; pool reuse under cancellation"]
async fn held_a_cancelled_transaction_does_not_leak_into_the_next_borrower() {
    let env = Env::start().await;
    let logins = env.db.server.logins().await;
    let mut settings = small_pool(env.db.url(&logins.api));
    settings.max_connections = 1;
    let mut config = PgStoreConfig::new(settings);
    config.tenant_login = TenantLogin::Api;
    config.system = None;
    let store: Arc<PgStore> = Arc::new(PgStore::connect(config).await.expect("store"));
    let event = |label: &str| NewAuditEvent {
        id: factory_domain::ids::AuditEventId::from_uuid(new_uuid()),
        actor: AuditActor::Anonymous(Slug::parse("review").expect("slug")),
        action: AuditAction::new("review.probe").expect("action"),
        subject: label.to_owned(),
        decision: AuditDecision::Record,
        reason: "A probe of the pool.".to_owned(),
        policy_hash: Sha256Digest::of(b"x"),
        job: None,
        stage_run: None,
        correlation_id: factory_domain::ids::CorrelationId::from_uuid(new_uuid()),
    };
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut committed_b = 0_i64;
    for round in 0..300_u64 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let (store_a, tenant_a, probe) =
            (Arc::clone(&store), env.a.id, event(&format!("a-{round}")));
        let _ = tokio::time::timeout(Duration::from_micros(state % 3000), async move {
            let mut tx = store_a.begin(TenantScope::new(tenant_a)).await?;
            tx.record_audit(probe).await?;
            tx.commit().await
        })
        .await;
        let mut written = false;
        for _ in 0..50 {
            let attempt = async {
                let mut tx = store.begin(TenantScope::new(env.b.id)).await?;
                tx.record_audit(event(&format!("b-{round}"))).await?;
                tx.commit().await
            }
            .await;
            if attempt.is_ok() {
                committed_b += 1;
                written = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(written, "tenant B could not write in round {round}");
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let b_rows = env
        .db
        .number(&format!(
            "SELECT count(*) FROM audit_events WHERE subject LIKE 'b-%' AND tenant_id = '{}'",
            env.b.id.as_uuid()
        ))
        .await;
    let wrong = env
        .db
        .number(&format!(
            "SELECT count(*) FROM audit_events WHERE (subject LIKE 'a-%' AND tenant_id <> '{}') OR (subject LIKE 'b-%' AND tenant_id <> '{}')",
            env.a.id.as_uuid(),
            env.b.id.as_uuid()
        ))
        .await;
    env.stop().await;
    assert_eq!((b_rows, wrong), (committed_b, 0));
}

// ---- panic, slow and silent clients -------------------------------------------------------------

struct PanickingAuthority;

#[async_trait]
impl Authority for PanickingAuthority {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn admission(
        &self,
        _: TenantId,
        _: PrincipalId,
        _: RepositoryId,
    ) -> Result<AdmissionFacts, AuthorityError> {
        Err(AuthorityError::Unavailable)
    }

    #[allow(clippy::panic)]
    async fn roles(&self, _: TenantId, _: PrincipalId) -> Result<Vec<HumanRole>, AuthorityError> {
        panic!("a simulated fault in a handler")
    }

    async fn concurrency_allows(&self, _: TenantId, _: JobId) -> Result<bool, AuthorityError> {
        Ok(true)
    }
}

/// A panic in a handler ends that connection and nothing else: the slot is given back and the
/// server keeps answering.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "held probe: passes today; a panic in a handler"]
async fn held_a_panic_in_a_handler_costs_one_connection() {
    let env = Env::start_with(Options {
        authority: Some(Arc::new(PanickingAuthority)),
        limits: Limits {
            max_connections: 2,
            ..Limits::default()
        },
        ..Options::default()
    })
    .await;
    for _ in 0..6 {
        let (text, closed) = raw(
            env.addr,
            format!("GET /v1/jobs HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n", env.a.requester.token).as_bytes(),
            Duration::from_secs(3),
        )
        .await;
        assert!(closed && !text.contains(" 200 "), "{text}");
    }
    assert_eq!(
        env.send(Req::get("/healthz")).await.status,
        200,
        "a panic leaked a connection slot"
    );
    env.stop().await;
}

/// Silent, trickling and slow-body clients are cut off at the configured deadlines.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "held probe: passes today; slow and silent clients"]
async fn held_silent_trickling_and_slow_clients_are_cut_off() {
    let env = Env::start_with(Options {
        limits: Limits {
            header_timeout_ms: 1_000,
            body_timeout_ms: 1_500,
            ..Limits::default()
        },
        ..Options::default()
    })
    .await;
    let mut buffer = [0_u8; 64];
    // No byte at all.
    let started = Instant::now();
    let mut silent = TcpStream::connect(env.addr).await.expect("connect");
    let read = tokio::time::timeout(Duration::from_secs(5), silent.read(&mut buffer)).await;
    assert!(matches!(read, Ok(Ok(0))), "{read:?}");
    assert!(started.elapsed() < Duration::from_secs(3));
    // One byte every 100 ms does not extend the header deadline.
    let started = Instant::now();
    let mut trickle = TcpStream::connect(env.addr).await.expect("connect");
    let head = b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-A: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for byte in head {
        if trickle.write_all(&[*byte]).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the trickle was not cut off"
    );
    // An idle keep-alive connection is closed too.
    let mut idle = TcpStream::connect(env.addr).await.expect("connect");
    idle.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .expect("write");
    let mut first = [0_u8; 1024];
    let _ = idle.read(&mut first).await.expect("answer");
    let read = tokio::time::timeout(Duration::from_secs(5), idle.read(&mut first)).await;
    assert!(
        matches!(read, Ok(Ok(0))),
        "an idle keep-alive connection was kept: {read:?}"
    );
    // A body that never arrives, on the unauthenticated webhook route.
    let (text, _) = raw(
        env.addr,
        b"POST /v1/webhooks/github HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\nContent-Type: application/json\r\n\r\nabc",
        Duration::from_secs(5),
    )
    .await;
    assert!(first_line(&text).contains(" 408 "), "{text}");
    env.stop().await;
}

/// A request whose handler never uses the correlation id of the client verbatim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "held probe: passes today; the correlation id is validated, not echoed"]
async fn held_a_hostile_correlation_id_is_replaced() {
    let env = Env::start().await;
    for hostile in [
        "not-a-uuid",
        "<script>alert(1)</script>",
        &"a".repeat(500),
        "0000",
    ] {
        let reply = env
            .send(Req::get("/healthz").header("X-Correlation-Id", hostile))
            .await;
        let echoed = reply.header("x-correlation-id").unwrap_or("").to_owned();
        assert_ne!(echoed, hostile);
        assert_eq!(echoed.len(), 36, "{echoed}");
    }
    env.stop().await;
}
