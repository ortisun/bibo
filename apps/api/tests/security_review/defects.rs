//! Confirmed defects. Each test asserts what the design requires and fails today.
//!
//! Run one with
//! `cargo test -p factory-api --test security_review -- --ignored <name> --exact`
//! (the names are `defects::<name>`).

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use diesel::sql_query;
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use factory_api::config::Limits;
use factory_api::limits::{Key, RateLimiter};
use factory_api::routes::router;
use factory_api::server::serve;
use factory_composition::redaction::redactor_from_policy;
use factory_composition::startup::load_policy;
use factory_composition::system::Shutdown;
use factory_domain::redaction::{PatternAction, Redactor};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::support::{Env, Req, eventually, repository_root};
use crate::util::{
    allowlist_with, approval, decide, delivery_id, entry_of, labeled, new_job, new_uuid,
    runtime_token, second_repository, stage_run, write_allowlist,
};

fn policy_redactor() -> Redactor {
    let policies = load_policy(&repository_root(), &[]).expect("the real policies load");
    redactor_from_policy(&policies.security).expect("the redactor builds")
}

// ---- API-1 -------------------------------------------------------------------------------------

/// API-1. `policies/approval.yaml` says an allowlist entry "may be narrowed to listed repositories".
/// `StoreAuthority::designations` reads the entry's `repositories` and drops it, so the narrowing
/// grants nothing less than the whole tenant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_1_a_designation_narrowed_to_one_repository_does_not_reach_another() {
    let env = Env::start().await;
    let a = env.a.clone();
    let other = second_repository(&env, &a).await;

    // A job on the second repository, made while nobody is narrowed.
    let reply = env
        .send(
            Req::post("/v1/jobs")
                .bearer(&a.requester.token)
                .header("Idempotency-Key", "api1-first")
                .json(&json!({"repository_id": other, "text": "A job on the other repository."})),
        )
        .await;
    assert_eq!(reply.status, 201, "{}", reply.text());
    let job = reply.json()["job_id"].as_str().expect("job").to_owned();
    let run = stage_run(&env, &a, &job).await;

    // Now the requester and the approver are each narrowed to org/repo-0 only.
    let narrow = |tenant: &crate::support::Tenant, person: &crate::support::Person, d: &str| {
        let plain = entry_of(tenant, person, d);
        (
            plain.clone(),
            format!("{plain}    repositories: [\"org/repo-0\"]\n"),
        )
    };
    let (req_plain, req_narrow) = narrow(&a, &a.requester, "requester");
    let (app_plain, app_narrow) = narrow(&a, &a.approver, "approver");
    let text = allowlist_with(&env, |t| {
        t.replacen(&req_plain, &req_narrow, 1)
            .replacen(&app_plain, &app_narrow, 1)
    });
    write_allowlist(&env, &text);

    let mut failures = Vec::new();
    let submit = env
        .send(
            Req::post("/v1/jobs")
                .bearer(&a.requester.token)
                .header("Idempotency-Key", "api1-second")
                .json(&json!({"repository_id": other, "text": "Outside my repositories."})),
        )
        .await;
    if !matches!(submit.status, 403 | 404) {
        failures.push(format!(
            "a requester narrowed to org/repo-0 submitted to org/other-repo: {}",
            submit.status
        ));
    }
    let decision = env
        .send(decide(&a.approver, &job, "api1-decide", &approval(&run)))
        .await;
    if decision.status != 403 {
        failures.push(format!(
            "an approver narrowed to org/repo-0 approved a job on org/other-repo: {}",
            decision.status
        ));
    }
    env.stop().await;
    assert!(failures.is_empty(), "{failures:#?}");
}

// ---- API-2 -------------------------------------------------------------------------------------

/// API-2. `jobs` has `UNIQUE (tenant_id, idempotency_key)`: the key belongs to the tenant, not to
/// the caller. A second requester who sends the same key and the same text is handed the first
/// requester's job (`200`, `created: false`), which is attributed to the first requester.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "confirmed defect API-2: an idempotency key is shared by every caller of the tenant, so another user is answered with the first user's job"]
async fn api_2_an_idempotency_key_of_one_caller_does_not_find_the_job_of_another() {
    let env = Env::start().await;
    let a = env.a.clone();
    // The operator also becomes a requester.
    let plain = entry_of(&a, &a.operator, "operator");
    let both = entry_of(&a, &a.operator, "operator, requester");
    write_allowlist(
        &env,
        &allowlist_with(&env, |t| t.replacen(&plain, &both, 1)),
    );

    let body = json!({"repository_id": a.repository.as_text(), "text": "Add a word count."});
    let first = env
        .send(
            Req::post("/v1/jobs")
                .bearer(&a.requester.token)
                .header("Idempotency-Key", "shared")
                .json(&body),
        )
        .await;
    let second = env
        .send(
            Req::post("/v1/jobs")
                .bearer(&a.operator.token)
                .header("Idempotency-Key", "shared")
                .json(&body),
        )
        .await;
    assert_eq!(first.status, 201, "{}", first.text());
    let first_job = first.json()["job_id"].as_str().expect("job").to_owned();
    let handed = second.json()["job_id"].as_str().map(str::to_owned);
    env.stop().await;
    assert_ne!(
        handed.as_deref(),
        Some(first_job.as_str()),
        "the second caller was answered with the first caller's job (status {})",
        second.status
    );
}

// ---- API-3 -------------------------------------------------------------------------------------

#[derive(diesel::QueryableByName)]
struct Flag {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    yes: bool,
}

/// API-3a. The API login used to be a member of `factory_app`, which holds `INSERT` on 17 tables.
/// The API writes four of them (`jobs`, `original_requests`, `audit_events`,
/// `webhook_deliveries`). The rest are the worker's and the operator's. Fixed by migration
/// `2026-10-28-002000_api_login_narrow_group`: the API login belongs to `factory_api_app` and
/// `factory_resolver` and not to `factory_app`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_3a_the_api_login_holds_only_the_insert_privileges_the_api_uses() {
    let env = Env::start().await;
    let logins = env.db.server.logins().await;
    let mut api = env.db.connect_as(&logins.api).await;
    let mut held = Vec::new();
    for table in [
        "api_tokens",
        "principals",
        "approvals",
        "ledger_entries",
        "outbox",
        "inbox",
        "stage_runs",
        "attempts",
        "task_nodes",
        "task_node_dependencies",
        "artifacts",
        "stage_run_artifacts",
        "repositories",
    ] {
        let flag: Flag = sql_query(format!(
            "SELECT has_table_privilege(current_user, '{table}', 'INSERT') AS yes"
        ))
        .get_result(&mut api)
        .await
        .expect("privilege");
        if flag.yes {
            held.push(table);
        }
    }
    env.stop().await;
    assert!(held.is_empty(), "the API login may INSERT into {held:?}");
}

/// API-3b. The same fact end to end: the API login names a tenant by hand, inserts a token for
/// that tenant's approver, and the new token authenticates over HTTP.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_3b_the_api_login_cannot_mint_a_token() {
    let env = Env::start().await;
    let logins = env.db.server.logins().await;
    let mut api = env.db.connect_as(&logins.api).await;
    let token = runtime_token();
    let hash: String = factory_api::tokens::hash_token(&token)
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let sql = format!(
        "BEGIN; SELECT set_config('factory.tenant_id', '{tenant}', true); \
         INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, created_at, expires_at) \
         VALUES ('{tenant}', '{id}', '{principal}', decode('{hash}', 'hex'), 'factory-api', now(), now() + interval '30 days'); \
         COMMIT;",
        tenant = env.b.id.as_uuid(),
        id = new_uuid(),
        principal = env.b.approver.principal.as_uuid(),
    );
    let minted = api.batch_execute(&sql).await;
    let used = env.send(Req::get("/v1/jobs").bearer(&token)).await;
    env.stop().await;
    assert!(
        minted.is_err() && used.status == 401,
        "the API login minted a token for tenant B's approver (insert: {minted:?}); GET /v1/jobs with it answered {}",
        used.status
    );
}

// ---- API-4 -------------------------------------------------------------------------------------

/// API-4a. The README says the `sfat_` prefix "makes a token recognizable to a secret scanner".
/// `policies/security.yaml` has a rule for the job token (`sfjt_`) and none for the API token.
#[test]
fn api_4a_the_redactor_recognises_an_api_token() {
    let redactor = policy_redactor();
    let token = runtime_token();
    let mut missed = Vec::new();
    for (name, text) in [
        ("bare", token.clone()),
        (
            "in a log line",
            format!("level=info msg=\"seen\" credential={token}"),
        ),
        ("in JSON", format!("{{\"note\":\"{token}\"}}")),
        (
            "after Bearer, no header name",
            format!("got Bearer {token} from a client"),
        ),
    ] {
        if !redactor.contains_secret(text.as_bytes()).expect("scans") {
            missed.push(name);
        }
    }
    assert!(
        missed.is_empty(),
        "an API token was not recognised: {missed:?}"
    );
}

/// API-4b. `jobs::submit` refuses "a secret in a request" so that it is not stored. An API token
/// pasted into the text is stored, and later goes wherever the request text goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_4b_a_job_request_that_contains_an_api_token_is_refused() {
    let env = Env::start().await;
    let token = runtime_token();
    let reply = env
        .send(
            Req::post("/v1/jobs")
                .bearer(&env.a.requester.token)
                .header("Idempotency-Key", "api4b")
                .json(&json!({
                    "repository_id": env.a.repository.as_text(),
                    "text": format!("Please use this credential: {token}"),
                })),
        )
        .await;
    let stored = env
        .db
        .number(&format!(
            "SELECT count(*) FROM original_requests WHERE request_text LIKE '%{token}%'"
        ))
        .await;
    env.stop().await;
    assert_eq!(
        (reply.status, stored),
        (400, 0),
        "the request was answered {} and {stored} stored copies hold the token",
        reply.status
    );
}

// ---- API-5 -------------------------------------------------------------------------------------

/// API-5. Shapes of a URL with credentials that `url_with_credentials` misses. The first group was
/// caught before commit 8215375 and is not now (a regression of the OBS-1 change); the second group
/// was never caught.
#[test]
fn api_5_url_credentials_the_policy_pattern_misses() {
    const OLD: &str = r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@/]{3,}@[^\s/]+";
    let current = policy_redactor();
    let before_obs_1 = Redactor::builder()
        .pattern("url_with_credentials", OLD, PatternAction::Block)
        .build()
        .expect("the earlier pattern builds");
    // The marker is made at run time, and every URL is joined from pieces, so that no line of this
    // file is itself a URL with a password (the repository's own secret scan would flag it).
    let secret = format!("Zq{}", &new_uuid().simple().to_string()[..10]);
    let secret = secret.as_str();
    let (sep, colon, at) = ("://", ":", "@");
    let url = |scheme: &str, user: &str, password: &str, host: &str| {
        format!("{scheme}{sep}{user}{colon}{password}{at}{host}")
    };
    let shapes: Vec<(&str, String)> = vec![
        (
            "quote inside the password (double)",
            url("postgres", "app", &format!("{secret}\"x"), "db:5432/x"),
        ),
        (
            "quote inside the password (single)",
            url("postgres", "app", &format!("{secret}'x"), "db:5432/x"),
        ),
        (
            "quote at the start of the password",
            url("postgres", "app", &format!("\"{secret}"), "db:5432/x"),
        ),
        (
            "slash inside the password (base64)",
            url("postgres", "app", &format!("{secret}+x/y=="), "db:5432/x"),
        ),
        (
            "slash at the start of the password",
            url("postgres", "app", &format!("/{secret}"), "db:5432/x"),
        ),
        (
            "no user name (redis style)",
            url("redis", "", secret, "cache:6379/0"),
        ),
        (
            "token as user name, no password",
            format!("https{sep}{secret}{at}github.com/org/repo.git"),
        ),
        ("upper-case scheme", url("HTTPS", "app", secret, "db/x")),
        ("capitalised scheme", url("Postgres", "app", secret, "db/x")),
        (
            "slashes escaped for JSON",
            format!("{{\"url\":\"postgres:\\/\\/app{colon}{secret}{at}db\\/x\"}}"),
        ),
        (
            "whole URL percent-encoded",
            url("postgres", "app", secret, "db/x")
                .bytes()
                .map(|byte| {
                    if byte.is_ascii_alphanumeric() {
                        char::from(byte).to_string()
                    } else {
                        format!("%{byte:02X}")
                    }
                })
                .collect::<String>(),
        ),
    ];
    let mut missed = Vec::new();
    for (name, line) in &shapes {
        let now = current.redact_str(line).expect("redacts");
        if now.output.contains(secret) {
            let then = before_obs_1.redact_str(line).expect("redacts");
            let note = if then.output.contains(secret) {
                "never caught"
            } else {
                "REGRESSION: caught before 8215375"
            };
            missed.push(format!("{name}: {note}"));
        }
    }
    assert!(missed.is_empty(), "{missed:#?}");
}

// ---- API-6 -------------------------------------------------------------------------------------

/// API-6. The connection limit is global. One peer opens as many silent connections as there are
/// slots; each costs the attacker nothing (no request is counted by the rate limiter) and is closed
/// after the header timeout (10 s by default), so a reconnecting loop holds all of them for good.
/// A second peer, here `::1` against the attacker's `127.0.0.1` on a dual-stack listener, is
/// closed unread.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "confirmed defect API-6: one source address can occupy every connection slot; there is no per-peer cap"]
async fn api_6_one_peer_cannot_take_every_connection_slot() {
    let env = Env::start().await;
    let limits = Limits {
        max_connections: 16,
        header_timeout_ms: 30_000,
        ..Limits::default()
    };
    let listener = TcpListener::bind("[::]:0")
        .await
        .expect("BLOCKED: a dual-stack IPv6 listener is needed");
    let port = listener.local_addr().expect("address").port();
    let shutdown = Shutdown::new();
    let server = tokio::spawn(serve(
        listener,
        router(Arc::clone(&env.state)),
        limits,
        shutdown.clone(),
    ));

    let mut held = Vec::new();
    for _ in 0..16 {
        held.push(
            TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("attacker connects"),
        );
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut victim = TcpStream::connect(("::1", port))
        .await
        .expect("victim connects");
    let _ = victim
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), victim.read_to_end(&mut answer)).await;
    let text = String::from_utf8_lossy(&answer).into_owned();

    drop(held);
    shutdown.raise();
    let _ = tokio::time::timeout(Duration::from_secs(20), server).await;
    env.stop().await;
    assert!(
        text.starts_with("HTTP/1.1 200"),
        "a second source was not served while one source held every slot: {text:?}"
    );
}

// ---- API-7 -------------------------------------------------------------------------------------

/// API-7. The platform audit trail takes at most 60 events a minute from every unauthenticated
/// source together. Sixty forged deliveries fill the minute, and the audit record of a genuine
/// delivery for an unregistered installation (NT-AUTHZ-08, "dropped, audited, acknowledged") is
/// then dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "confirmed defect API-7: an unauthenticated flood of forged deliveries uses up the shared platform audit budget and a genuine unbound delivery is no longer audited"]
async fn api_7_forged_deliveries_do_not_use_up_the_audit_of_a_real_one() {
    let env = Env::start().await;
    let a = env.a.clone();
    let forged_signature = format!("sha256={}", "0".repeat(64));
    for n in 0..70 {
        let reply = env
            .send(
                Req::post("/v1/webhooks/github")
                    .header("X-GitHub-Event", "issues")
                    .header("X-GitHub-Delivery", &delivery_id(n))
                    .header("X-Hub-Signature-256", &forged_signature)
                    .header("Content-Type", "application/json")
                    .body(labeled(&a, "factory", a.requester.github_id, n)),
            )
            .await;
        assert_eq!(reply.status, 401);
    }
    let filled = eventually(Duration::from_secs(15), || async {
        env.db
            .number("SELECT count(*) FROM audit_events WHERE action = 'webhook.rejected'")
            .await
            >= 60
    })
    .await;
    assert!(
        filled,
        "the precondition failed: the forged deliveries were not audited"
    );

    // A genuine, correctly signed delivery for an installation nobody registered.
    let genuine = serde_json::to_vec(&json!({
        "action": "labeled",
        "installation": {"id": 987_654},
        "repository": {"id": 987_655, "full_name": "stranger/repo"},
        "sender": {"id": 1, "login": "someone", "type": "User"},
        "issue": {"number": 1, "node_id": "I_1", "updated_at": "2026-10-28T10:00:00Z"},
        "label": {"name": "factory"},
    }))
    .expect("json");
    let reply = env
        .send(env.delivery("issues", &delivery_id(900), &genuine))
        .await;
    assert_eq!(reply.status, 202);
    let audited = eventually(Duration::from_secs(5), || async {
        env.db
            .number("SELECT count(*) FROM audit_events WHERE action = 'webhook.unbound'")
            .await
            >= 1
    })
    .await;
    env.stop().await;
    assert!(
        audited,
        "the unbound delivery left no audit record: the minute's budget of 60 was spent on forgeries"
    );
}

// ---- API-8 -------------------------------------------------------------------------------------

/// API-8. Every refused decision writes an audit row with a fresh id. A token holder who is not on
/// the allowlist can write as many as the per-address rate limit lets through (600 a minute).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "confirmed defect API-8: an authenticated caller with no designation writes one audit row per refused request, without a bound per principal"]
async fn api_8_refused_decisions_of_one_principal_are_bounded() {
    let env = Env::start().await;
    let a = env.a.clone();
    let job = new_job(&env, &a, "api8").await;
    let run = stage_run(&env, &a, &job).await;
    for n in 0..60 {
        let reply = env
            .send(decide(
                &a.outsider,
                &job,
                &format!("flood-{n}"),
                &approval(&run),
            ))
            .await;
        assert_eq!(reply.status, 403);
    }
    let rows = env
        .db
        .number("SELECT count(*) FROM audit_events WHERE action = 'decision.denied'")
        .await;
    env.stop().await;
    assert!(
        rows <= 10,
        "60 refused requests from one unlisted principal wrote {rows} audit rows"
    );
}

// ---- API-9 -------------------------------------------------------------------------------------

/// API-9. The rate limiter keys on the whole address. A client that holds an IPv6 /64 has 2^64 of
/// them, so the per-address limit never applies, and the map grows by one entry per address.
#[test]
#[ignore = "confirmed defect API-9: the per-source rate limit is per IPv6 address, not per prefix, and does not apply to a client with a /64"]
fn api_9_the_rate_limit_holds_for_a_client_with_a_whole_ipv6_prefix() {
    let limiter = RateLimiter::new();
    let now = Instant::now();
    let limit = 600;
    let allowed = (0..2000_u16)
        .filter(|i| {
            let address = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 1, 0, 0, 0, *i));
            limiter.allow(Key::Ip(address), limit, now)
        })
        .count();
    assert!(
        allowed <= limit as usize,
        "2000 requests from one /64 were all within a limit of {limit} a minute per source: {allowed} allowed"
    );
}

// ---- API-11 ------------------------------------------------------------------------------------

/// API-11. Two mistakes of the caller are answered `503 unavailable` and logged as a store fault.
/// `X-Correlation-Id` is taken from the client when it is a UUID and the job keeps it, but `jobs`
/// is unique on `(tenant_id, correlation_id)`, so a repeated one is a unique violation. And a
/// `GET /v1/jobs?after=` value that passes the character check but is not a cursor fails in the
/// store. Any caller with a token can produce either at will, which is a way to raise 5xx rates
/// and warnings (and, behind a proxy that ejects a host on consecutive 5xx, to take the host out).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "confirmed defect API-11: a repeated X-Correlation-Id and a malformed pagination cursor are answered 503 and logged as store faults"]
async fn api_11_a_repeated_correlation_id_is_the_callers_error_not_the_services() {
    let env = Env::start().await;
    let a = env.a.clone();
    let first = env
        .send(
            Req::post("/v1/jobs")
                .bearer(&a.requester.token)
                .header("Idempotency-Key", "api12-1")
                .json(&json!({"repository_id": a.repository.as_text(), "text": "one"})),
        )
        .await;
    assert_eq!(first.status, 201, "{}", first.text());
    let taken = first.json()["correlation_id"]
        .as_str()
        .expect("correlation")
        .to_owned();
    let second = env
        .send(
            Req::post("/v1/jobs")
                .bearer(&a.requester.token)
                .header("Idempotency-Key", "api12-2")
                .header("X-Correlation-Id", &taken)
                .json(&json!({"repository_id": a.repository.as_text(), "text": "two"})),
        )
        .await;
    // A cursor that has the characters of one and is not one: `parse_cursor` fails in the store.
    let cursor = env
        .send(Req::get("/v1/jobs?after=abc").bearer(&a.requester.token))
        .await;
    env.stop().await;
    let mut wrong = Vec::new();
    if !matches!(second.status, 400 | 409) {
        wrong.push(format!(
            "a repeated correlation id was answered {}",
            second.status
        ));
    }
    if cursor.status != 400 {
        wrong.push(format!("a malformed cursor was answered {}", cursor.status));
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}
