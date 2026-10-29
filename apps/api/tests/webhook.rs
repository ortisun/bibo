//! The webhook endpoint through the real server and a real PostgreSQL: signature verification
//! on the raw body (NT-WH-01 to NT-WH-03), replay (NT-WH-04), malformed and oversized input and
//! slow bodies (NT-WH-07), secret rotation (NT-WH-08), floods (NT-WH-10), an unknown tenant binding
//! (NT-AUTHZ-08), and what a verified delivery does.

mod support;

use std::sync::Arc;
use std::time::Duration;

use factory_composition::config::SecretFile;
use factory_composition::redaction::{FactorySecrets, redactor_from_policy};
use factory_composition::startup::load_policy;
use serde_json::json;
use support::{
    Env, Options, Req, Tenant, counting, eventually, open, read_to_close, repository_root,
};

fn payload(tenant: &Tenant, label: &str, sender: u64, issue: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "action": "labeled",
        "installation": {"id": tenant.installation},
        "repository": {"id": tenant.github_repository, "full_name": tenant.full_name},
        "sender": {"id": sender, "login": "someone", "type": "User"},
        "issue": {"number": issue, "node_id": format!("I_{issue}"), "updated_at": "2026-10-28T10:00:00Z"},
        "label": {"name": label},
    }))
    .expect("json")
}

fn delivery_id(n: u64) -> String {
    format!("0190a3b2-7c4d-4e5f-8a6b-{n:012}")
}

async fn rows(env: &Env, table: &str) -> i64 {
    env.db
        .number(&format!("SELECT count(*) FROM {table}"))
        .await
}

// ---- NT-WH-01 and NT-WH-02: a delivery that is not signed is refused before anything else ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_wh_01() {
    let (options, counts) = counting(Options::default());
    let env = Env::start_with(options).await;
    let body = payload(&env.a, "factory", env.a.requester.github_id, 1);
    let base = |name: &str, signature: Option<&str>| {
        let mut request = Req::post("/v1/webhooks/github")
            .header("X-GitHub-Event", "issues")
            .header("X-GitHub-Delivery", &delivery_id(1))
            .header("Content-Type", "application/json")
            .body(body.clone());
        if let Some(value) = signature {
            request = request.header("X-Hub-Signature-256", value);
        }
        (name.to_owned(), request)
    };
    let garbage = Req::post("/v1/webhooks/github")
        .header("X-GitHub-Event", "issues")
        .header("X-GitHub-Delivery", &delivery_id(2))
        .header("Content-Type", "application/json")
        .body(b"this is not json {{{".to_vec());
    let cases = vec![
        base("no signature", None),
        base("empty signature", Some("")),
        (
            "no signature and a body that is not JSON".to_owned(),
            garbage,
        ),
    ];
    let before = counts.touches();
    for (name, request) in cases {
        let reply = env.send(request).await;
        assert_eq!(reply.status, 401, "{name}: {}", reply.text());
        assert_eq!(reply.json(), json!({"error": "unauthorized"}), "{name}");
        // Nothing was parsed: a body that is not JSON is the same 401, not a 400.
    }
    assert_eq!(
        counts.touches(),
        before,
        "an unsigned delivery touched the database"
    );
    assert_eq!(rows(&env, "webhook_deliveries").await, 0);
    // The refusal is audited, rate limited, by the background task and not by the request.
    assert!(
        eventually(Duration::from_secs(10), || async {
            env.db
                .number("SELECT count(*) FROM audit_events WHERE action = 'webhook_accepted_or_rejected.denied'")
                .await
                >= 3
        })
        .await,
        "the rejections were not audited"
    );
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_wh_02() {
    let env = Env::start().await;
    let body = payload(&env.a, "factory", env.a.requester.github_id, 1);
    let good = env.sign(&body);
    let digits = good.strip_prefix("sha256=").expect("prefix").to_owned();
    let wrong_secret = format!(
        "sha256={}",
        factory_testkit::webhook::hmac_sha256_hex(
            b"a-different-secret-of-sufficient-length-1",
            &body
        )
    );
    let mut changed = body.clone();
    changed[10] ^= 0x01;
    let request = |signature: &str, payload: &[u8]| {
        Req::post("/v1/webhooks/github")
            .header("X-GitHub-Event", "issues")
            .header("X-GitHub-Delivery", &delivery_id(7))
            .header("X-Hub-Signature-256", signature)
            .header("Content-Type", "application/json")
            .body(payload.to_vec())
    };
    let mut cases = vec![
        ("wrong secret", request(&wrong_secret, &body)),
        ("truncated", request(&good[..good.len() - 2], &body)),
        (
            "not hex",
            request(&format!("sha256={}", "z".repeat(64)), &body),
        ),
        (
            "upper case prefix",
            request(&format!("SHA256={digits}"), &body),
        ),
        ("no prefix", request(&digits, &body)),
        // (Whitespace around a header value is not part of it: the HTTP layer trims it, so only
        // whitespace inside the value can reach the check.)
        (
            "whitespace inside",
            request(&format!("sha256= {digits}"), &body),
        ),
        (
            "whitespace in the digits",
            request(
                &format!("sha256={} {}", &digits[..32], &digits[32..]),
                &body,
            ),
        ),
        (
            "upper case digits",
            request(&format!("sha256={}", digits.to_uppercase()), &body),
        ),
        ("a body changed by one byte", request(&good, &changed)),
        (
            "two signature headers",
            request(&good, &body).header("X-Hub-Signature-256", &good),
        ),
    ];
    cases.push((
        "only the legacy sha1 header",
        Req::post("/v1/webhooks/github")
            .header("X-GitHub-Event", "issues")
            .header("X-GitHub-Delivery", &delivery_id(7))
            .header(
                "X-Hub-Signature",
                "sha1=0123456789abcdef0123456789abcdef01234567",
            )
            .header("Content-Type", "application/json")
            .body(body.clone()),
    ));
    let mut seen = Vec::new();
    for (name, case) in cases {
        let reply = env.send(case).await;
        assert_eq!(reply.status, 401, "{name}: {}", reply.text());
        seen.push((reply.body.clone(), reply.header_names()));
    }
    assert!(
        seen.windows(2).all(|pair| pair[0] == pair[1]),
        "the answers differ"
    );
    assert_eq!(rows(&env, "webhook_deliveries").await, 0);
    // The control: the right signature on the right bytes is accepted.
    let accepted = env.send(request(&good, &body)).await;
    assert_eq!(accepted.status, 202, "{}", accepted.text());
    env.stop().await;
}

/// NT-WH-03: the signature is over the raw bytes. The same JSON written differently is a
/// different message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_signature_is_checked_on_the_raw_bytes() {
    let env = Env::start().await;
    let original = payload(&env.a, "factory", env.a.requester.github_id, 1);
    let value: serde_json::Value = serde_json::from_slice(&original).expect("json");
    let reserialized = serde_json::to_vec_pretty(&value).expect("json");
    assert_ne!(original, reserialized);
    let signature = env.sign(&original);
    let send = |body: &[u8]| {
        Req::post("/v1/webhooks/github")
            .header("X-GitHub-Event", "issues")
            .header("X-GitHub-Delivery", &delivery_id(3))
            .header("X-Hub-Signature-256", &signature)
            .header("Content-Type", "application/json")
            .body(body.to_vec())
    };
    assert_eq!(env.send(send(&reserialized)).await.status, 401);
    assert_eq!(env.send(send(&original)).await.status, 202);
    // A validly signed body with a repeated key is read as malformed and acknowledged without effect.
    let duplicate = br#"{"action":"labeled","action":"closed","installation":{"id":1}}"#;
    let reply = env
        .send(env.delivery("issues", &delivery_id(4), duplicate))
        .await;
    assert_eq!(reply.status, 202);
    assert_eq!(rows(&env, "webhook_deliveries").await, 1);
    env.stop().await;
}

// ---- NT-WH-04: replay ------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_wh_04() {
    // Fifty copies arrive at once from one address (this machine), which is more connections than
    // one source may hold by default (API-6). The cap is a setting; this test is about replay.
    let env = Arc::new(
        Env::start_with(Options {
            limits: factory_api::config::Limits {
                max_connections_per_source: Some(256),
                ..factory_api::config::Limits::default()
            },
            ..Options::default()
        })
        .await,
    );
    let body = payload(&env.a, "factory", env.a.requester.github_id, 11);
    let id = delivery_id(11);

    // Once: accepted, one delivery, one job. Twice: a repeat. Both are 202.
    let first = env.send(env.delivery("issues", &id, &body)).await;
    assert_eq!(first.status, 202, "{}", first.text());
    assert_eq!(rows(&env, "jobs").await, 1);
    let second = env.send(env.delivery("issues", &id, &body)).await;
    assert_eq!(second.status, 202);
    assert_eq!(
        second.body, first.body,
        "a replay is answered as the first was"
    );
    assert_eq!(rows(&env, "jobs").await, 1);

    // A new delivery id with the same body is the same message.
    let renamed = env
        .send(env.delivery("issues", &delivery_id(12), &body))
        .await;
    assert_eq!(renamed.status, 202);
    assert_eq!(rows(&env, "webhook_deliveries").await, 1);
    assert_eq!(rows(&env, "jobs").await, 1);

    // Fifty copies of a fresh delivery at the same time: one job, one delivery, 49 repeats.
    let fresh = payload(&env.a, "factory", env.a.requester.github_id, 12);
    let fresh_id = delivery_id(13);
    let mut tasks = Vec::new();
    for _ in 0..50 {
        let env = Arc::clone(&env);
        let (fresh, fresh_id) = (fresh.clone(), fresh_id.clone());
        tasks.push(tokio::spawn(async move {
            env.send(env.delivery("issues", &fresh_id, &fresh))
                .await
                .status
        }));
    }
    for task in tasks {
        assert_eq!(task.await.expect("task"), 202);
    }
    assert_eq!(rows(&env, "webhook_deliveries").await, 2);
    assert_eq!(
        rows(&env, "jobs").await,
        2,
        "one job for the first delivery, one for the fifty"
    );
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM audit_events WHERE action = 'job.received_from_webhook'")
            .await,
        2
    );
    // 49 repeats of the fifty, plus the replay and the renamed copy of the first.
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM audit_events WHERE action = 'webhook.duplicate_delivery'")
            .await,
        49 + 2
    );
    assert_eq!(
        env.db
            .number("SELECT count(*) FROM audit_events WHERE action = 'webhook_accepted_or_rejected.granted'")
            .await,
        2
    );
    // The API writes no outbox event: the first event of a job is `job.admitted`, which the
    // engine writes at admission (state-machine.json has no event for a received job).
    assert_eq!(rows(&env, "outbox").await, 0);
    Arc::try_unwrap(env).ok().expect("one owner").stop().await;
}

// ---- what a verified delivery does --------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_label_from_an_allowlisted_requester_makes_a_job_and_nothing_else_does() {
    let env = Env::start().await;
    let a = &env.a;
    // Not the factory label, a sender who is not on the allowlist, a sender the tenant does not
    // know, and a bot: each is recorded as a delivery and starts no job.
    let cases = [
        (
            "another label",
            payload(a, "bug", a.requester.github_id, 21),
        ),
        (
            "a sender not on the allowlist",
            payload(a, "factory", a.outsider.github_id, 22),
        ),
        (
            "an approver, who is not a requester",
            payload(a, "factory", a.approver.github_id, 23),
        ),
        (
            "a sender the tenant does not know",
            payload(a, "factory", 999_999, 24),
        ),
        ("a bot", {
            let mut value: serde_json::Value =
                serde_json::from_slice(&payload(a, "factory", a.requester.github_id, 25))
                    .expect("json");
            value["sender"]["type"] = json!("Bot");
            serde_json::to_vec(&value).expect("json")
        }),
    ];
    for (n, (name, body)) in cases.iter().enumerate() {
        let reply = env
            .send(env.delivery("issues", &delivery_id(30 + n as u64), body))
            .await;
        assert_eq!(reply.status, 202, "{name}");
    }
    assert_eq!(rows(&env, "webhook_deliveries").await, 5);
    assert_eq!(rows(&env, "jobs").await, 0);
    // The one that should.
    let reply = env
        .send(env.delivery(
            "issues",
            &delivery_id(40),
            &payload(a, "factory", a.requester.github_id, 26),
        ))
        .await;
    assert_eq!(reply.status, 202);
    assert_eq!(rows(&env, "jobs").await, 1);
    assert_eq!(
        env.db
            .text("SELECT status || ' ' || requester_principal_id::text FROM jobs")
            .await,
        Some(format!("RECEIVED {}", a.requester.principal.as_uuid()))
    );
    // The job came from the delivery, and it has no original request: the text of the issue is
    // not in the payload, and the API holds no GitHub credential to fetch it.
    assert_eq!(rows(&env, "original_requests").await, 0);
    env.stop().await;
}

/// SF-02 (the other half). The audit record of a job made from a webhook carries the correlation
/// id of the job, so that one search finds the record, the events and the log lines of the job.
/// It carried an id of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_audit_record_of_a_job_made_from_a_webhook_carries_the_correlation_id_of_the_job() {
    let env = Env::start().await;
    let reply = env
        .send(env.delivery(
            "issues",
            &delivery_id(60),
            &payload(&env.a, "factory", env.a.requester.github_id, 41),
        ))
        .await;
    assert_eq!(reply.status, 202);
    let job_correlation = env
        .db
        .text("SELECT correlation_id::text FROM jobs")
        .await
        .expect("a job");
    let record_correlation = env
        .db
        .text("SELECT correlation_id::text FROM audit_events WHERE action = 'job.received_from_webhook'")
        .await
        .expect("a record");
    assert_eq!(record_correlation, job_correlation);
    env.stop().await;
}

/// The requests the API left for the worker to answer: the audit records with the action
/// `webhook_accepted_or_rejected.denied`, read by the worker login.
async fn rejection_requests(env: &Env) -> Vec<factory_ports::store::AuditRecord> {
    use factory_ports::store::{AuditFilter, Store as _};
    let mut tx = env
        .worker
        .begin(factory_domain::scope::TenantScope::new(env.a.id))
        .await
        .expect("a tx");
    let all = tx
        .read_audit(AuditFilter::Tenant, 0, 500)
        .await
        .expect("audit");
    let _ = tx.rollback().await;
    all.into_iter()
        .filter(|record| record.event.action.as_str() == "webhook_accepted_or_rejected.denied")
        .collect()
}

/// FR-002 and SC-002 (finding SF-01). A factory label from someone who may not ask makes no job
/// and leaves one signed request for the worker to answer: the API holds no GitHub credential, so
/// the reply and the record of the rejection are the worker's. The request is for every kind of
/// sender who is not an authorized requester, and for no other delivery.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_label_from_someone_who_may_not_ask_leaves_one_signed_request_and_no_job() {
    use factory_composition::decision_signing::{RejectionSigning, read_rejection_subject};
    let env = Env::start().await;
    let a = &env.a;
    let bot = {
        let mut value: serde_json::Value =
            serde_json::from_slice(&payload(a, "factory", a.requester.github_id, 25))
                .expect("json");
        value["sender"]["type"] = json!("Bot");
        serde_json::to_vec(&value).expect("json")
    };
    let refused = [
        (
            "a sender not on the allowlist",
            payload(a, "factory", a.outsider.github_id, 22),
            Some(a.outsider.github_id),
        ),
        (
            "an approver, who is not a requester",
            payload(a, "factory", a.approver.github_id, 23),
            Some(a.approver.github_id),
        ),
        (
            "a sender the tenant does not know",
            payload(a, "factory", 999_999, 24),
            Some(999_999),
        ),
    ];
    let not_a_request = [
        ("another label", payload(a, "bug", a.outsider.github_id, 21)),
        // A bot, which includes the factory's own App, is never answered: the verifier reads its
        // delivery as one the factory does not act on, so there is no reply to loop on.
        ("a bot", bot),
        (
            "an authorized requester",
            payload(a, "factory", a.requester.github_id, 26),
        ),
    ];
    for (n, (name, body, _)) in refused.iter().enumerate() {
        let reply = env
            .send(env.delivery("issues", &delivery_id(70 + n as u64), body))
            .await;
        assert_eq!(reply.status, 202, "{name}");
        // The answer is the one everybody gets.
        assert_eq!(reply.json(), json!({"status": "accepted"}), "{name}");
    }
    for (n, (name, body)) in not_a_request.iter().enumerate() {
        let reply = env
            .send(env.delivery("issues", &delivery_id(80 + n as u64), body))
            .await;
        assert_eq!(reply.status, 202, "{name}");
    }
    // One job, for the requester. None for the four who may not ask.
    assert_eq!(rows(&env, "jobs").await, 1);

    let requests = rejection_requests(&env).await;
    assert_eq!(
        requests.len(),
        refused.len(),
        "one request for each refused label and none for the others: {requests:#?}"
    );
    for (record, (name, _, sender)) in requests.iter().zip(refused.iter()) {
        let parsed = read_rejection_subject(&record.event.subject)
            .unwrap_or_else(|| panic!("{name}: no signed request in {}", record.event.subject));
        // The word is the API's: it verifies under the key the API signs with.
        assert!(
            env.state.decision_keys.verify_rejection(
                &RejectionSigning {
                    tenant: a.id,
                    event: record.event.id,
                    requested_at: &parsed.requested_at,
                    fields: &parsed.fields,
                },
                &parsed.word
            ),
            "{name}"
        );
        assert_eq!(parsed.fields.sender, *sender, "{name}");
        assert_eq!(
            parsed.fields.repository, a.repository,
            "{name}: the registered repository"
        );
        assert!(record.event.job.is_none(), "{name}: no job");
        // Nothing the sender or the payload wrote is in the record: not the login, not the node id.
        assert!(
            !record.event.subject.contains("someone") && !record.event.subject.contains("I_"),
            "{name}: {}",
            record.event.subject
        );
        assert!(
            !record.event.reason.contains("someone"),
            "{name}: {}",
            record.event.reason
        );
    }
    // The record of each delivery says which delivery it is.
    let deliveries: Vec<String> = requests
        .iter()
        .filter_map(|r| read_rejection_subject(&r.event.subject).map(|p| p.fields.delivery))
        .collect();
    assert_eq!(
        deliveries,
        (0..3).map(|n| delivery_id(70 + n)).collect::<Vec<_>>()
    );
    env.stop().await;
}

/// A delivery that GitHub sends again is a repeat. It leaves no second request, so the reply is
/// sent once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_redelivered_label_from_someone_who_may_not_ask_leaves_no_second_request() {
    let env = Env::start().await;
    let body = payload(&env.a, "factory", env.a.outsider.github_id, 31);
    for _ in 0..5 {
        let reply = env
            .send(env.delivery("issues", &delivery_id(90), &body))
            .await;
        assert_eq!(reply.status, 202);
    }
    // The same label again, as a new delivery of the same event on the same revision of the issue.
    let reply = env
        .send(env.delivery("issues", &delivery_id(91), &body))
        .await;
    assert_eq!(reply.status, 202);
    assert_eq!(rows(&env, "jobs").await, 0);
    assert_eq!(
        rejection_requests(&env).await.len(),
        1,
        "five copies of one delivery and a copy of its event leave one request"
    );
    env.stop().await;
}

/// A repository the factory is switched off for has no one to answer: a label there leaves no
/// request, and no job.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_label_in_a_repository_that_is_switched_off_leaves_no_request() {
    let env = Env::start().await;
    env.db
        .run(&format!(
            "UPDATE repositories SET enabled = false, version = version + 1 WHERE tenant_id = '{}'",
            env.a.id.as_uuid()
        ))
        .await;
    let reply = env
        .send(env.delivery(
            "issues",
            &delivery_id(95),
            &payload(&env.a, "factory", env.a.outsider.github_id, 32),
        ))
        .await;
    assert_eq!(reply.status, 202);
    assert_eq!(rows(&env, "jobs").await, 0);
    assert!(rejection_requests(&env).await.is_empty());
    env.stop().await;
}

/// API-1 on the webhook path: a requester whose allowlist entry is narrowed to other repositories
/// labels an issue of this one, and no job is made. Narrowed to this repository, the label works.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_label_from_a_requester_narrowed_to_another_repository_makes_no_job() {
    let env = Env::start().await;
    let a = &env.a;
    let plain = format!(
        "  - tenant: {}\n    github_user_id: {}\n    login: {}\n    designations: [requester]\n",
        a.id.as_uuid(),
        a.requester.github_id,
        a.requester.login
    );
    let all = support::allowlist_text(&[&env.a, &env.b]);
    assert!(all.contains(&plain), "the entry to narrow is in the file");
    let narrowed = |repository: &str| {
        all.replacen(
            &plain,
            &format!("{plain}    repositories: [\"{repository}\"]\n"),
            1,
        )
    };
    let path = env.checkout.join("allowlist/allowlist.yaml");

    std::fs::write(&path, narrowed("org/elsewhere")).expect("narrowed elsewhere");
    let reply = env
        .send(env.delivery(
            "issues",
            &delivery_id(50),
            &payload(a, "factory", a.requester.github_id, 61),
        ))
        .await;
    assert_eq!(reply.status, 202);
    assert_eq!(rows(&env, "webhook_deliveries").await, 1, "it is recorded");
    assert_eq!(rows(&env, "jobs").await, 0, "and starts no job");
    assert_eq!(
        rejection_requests(&env).await.len(),
        1,
        "a requester who may not ask here is answered like anyone else who may not"
    );

    std::fs::write(&path, narrowed(&a.full_name.to_ascii_uppercase())).expect("narrowed here");
    let reply = env
        .send(env.delivery(
            "issues",
            &delivery_id(51),
            &payload(a, "factory", a.requester.github_id, 62),
        ))
        .await;
    assert_eq!(reply.status, 202);
    assert_eq!(rows(&env, "jobs").await, 1);
    env.stop().await;
}

/// R-15. The issue a webhook job comes from is named by the registered repository row, resolved from
/// the installation and repository ids, and not by the `full_name` in the payload, which is stale
/// after a rename and is text the sender chose.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_webhook_job_names_the_registered_repository_and_not_the_one_in_the_payload() {
    let env = Env::start().await;
    let a = &env.a.clone();
    let mut value: serde_json::Value =
        serde_json::from_slice(&payload(a, "factory", a.requester.github_id, 71)).expect("json");
    value["repository"]["full_name"] = json!("renamed-since/elsewhere");
    let reply = env
        .send(env.delivery(
            "issues",
            &delivery_id(60),
            &serde_json::to_vec(&value).expect("json"),
        ))
        .await;
    assert_eq!(reply.status, 202);
    assert_eq!(rows(&env, "jobs").await, 1);
    let subject = env
        .db
        .text("SELECT subject FROM audit_events WHERE action = 'job.received_from_webhook'")
        .await;
    env.stop().await;
    assert_eq!(
        subject,
        Some(format!("issue {}#71", a.full_name)),
        "the registered name, with the number of the issue"
    );
}

// ---- NT-AUTHZ-08: an unknown binding -----------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_authz_08() {
    let env = Env::start().await;
    let mut unknown = payload(&env.a, "factory", env.a.requester.github_id, 1);
    let mut value: serde_json::Value = serde_json::from_slice(&unknown).expect("json");
    value["installation"]["id"] = json!(987_654);
    unknown = serde_json::to_vec(&value).expect("json");
    // A repository that moved to an installation of someone else: the pair does not belong together.
    let mut transferred: serde_json::Value =
        serde_json::from_slice(&payload(&env.a, "factory", env.a.requester.github_id, 2))
            .expect("json");
    transferred["installation"]["id"] = json!(env.b.installation);
    let transferred = serde_json::to_vec(&transferred).expect("json");
    // No repository in the payload at all.
    let none = serde_json::to_vec(&json!({"action": "labeled", "installation": {"id": env.a.installation},
        "sender": {"id": 1, "type": "User"}, "issue": {"number": 1, "node_id": "I_1", "updated_at": "2026-10-28T10:00:00Z"},
        "label": {"name": "factory"}}))
    .expect("json");
    let mut answers = Vec::new();
    for (n, body) in [unknown, transferred, none].iter().enumerate() {
        let reply = env
            .send(env.delivery("issues", &delivery_id(50 + n as u64), body))
            .await;
        assert_eq!(reply.status, 202, "{}", reply.text());
        answers.push(reply.body);
    }
    // The answer is the one a bound delivery gets: the sender learns nothing about bindings.
    let bound = env
        .send(env.delivery("issues", &delivery_id(60), &payload(&env.a, "bug", 1, 3)))
        .await;
    assert!(answers.iter().all(|body| *body == bound.body));
    // No row in any tenant for the unbound ones; the bound one made one delivery.
    assert_eq!(rows(&env, "webhook_deliveries").await, 1);
    assert_eq!(rows(&env, "jobs").await, 0);
    // They are audited under the platform tenant.
    assert!(
        eventually(Duration::from_secs(10), || async {
            env.db
                .number("SELECT count(*) FROM audit_events WHERE action = 'webhook.unbound' AND tenant_id = '00000000-0000-0000-0000-000000000001'")
                .await
                == 3
        })
        .await,
        "the dropped deliveries were not audited"
    );
    env.stop().await;
}

// ---- NT-WH-07: malformed, oversized and slow ----------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_oversized_and_slow_deliveries_are_bounded() {
    let limits = factory_api::config::Limits {
        body_timeout_ms: 500,
        ..factory_api::config::Limits::default()
    };
    let env = Env::start_with(Options {
        limits,
        ..Options::default()
    })
    .await;
    // 2 MiB: refused on the declared length.
    let big = vec![b'a'; 2 * 1024 * 1024];
    let reply = env
        .send(
            Req::post("/v1/webhooks/github")
                .header("X-GitHub-Event", "issues")
                .header("X-GitHub-Delivery", &delivery_id(70))
                .header("X-Hub-Signature-256", &env.sign(&big))
                .header("Content-Type", "application/json")
                .body(big),
        )
        .await;
    assert_eq!(reply.status, 413);
    // A wrong content type, with a signature that is right for the bytes: the same 401.
    let body = payload(&env.a, "factory", env.a.requester.github_id, 1);
    let wrong_type = env
        .send(
            Req::post("/v1/webhooks/github")
                .header("X-GitHub-Event", "issues")
                .header("X-GitHub-Delivery", &delivery_id(71))
                .header("X-Hub-Signature-256", &env.sign(&body))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(body.clone()),
        )
        .await;
    assert_eq!(wrong_type.status, 401);
    // Signed and not JSON, signed and nested a thousand deep, signed and an event the factory does
    // not act on: all acknowledged, none with an effect, none a panic.
    let deep = format!("{}{}", "[".repeat(1000), "]".repeat(1000)).into_bytes();
    for (n, (event, payload)) in [
        ("issues", b"not json".to_vec()),
        ("issues", deep),
        ("push", body.clone()),
        ("ping", b"{}".to_vec()),
    ]
    .into_iter()
    .enumerate()
    {
        let reply = env
            .send(env.delivery(event, &delivery_id(72 + n as u64), &payload))
            .await;
        assert_eq!(reply.status, 202, "{event} {n}");
    }
    assert_eq!(rows(&env, "webhook_deliveries").await, 0);
    // A body that stalls: the deadline answers it.
    let signature = env.sign(&body);
    let mut stream = open(
        env.addr,
        format!(
            "POST /v1/webhooks/github HTTP/1.1\r\nHost: x\r\nConnection: close\r\nX-GitHub-Event: issues\r\nX-GitHub-Delivery: {}\r\nX-Hub-Signature-256: {signature}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{{\"act",
            delivery_id(80),
            body.len()
        )
        .as_bytes(),
    )
    .await;
    let raw = read_to_close(&mut stream, Duration::from_secs(10))
        .await
        .expect("answered");
    assert_eq!(support::parse_reply(&raw).status, 408);
    env.stop().await;
}

// ---- NT-WH-08: rotation ---------------------------------------------------------------------------

fn verifier_of(
    dir: &std::path::Path,
    secrets: &[&str],
) -> Arc<dyn factory_ports::githost::WebhookVerifier> {
    use std::os::unix::fs::PermissionsExt;
    let policies = load_policy(&repository_root(), &[]).expect("policies");
    let redactor = Arc::new(redactor_from_policy(&policies.security).expect("redactor"));
    let mut registry = FactorySecrets::new(redactor, &policies.security);
    let files: Vec<SecretFile> = secrets
        .iter()
        .enumerate()
        .map(|(index, secret)| {
            let path = dir.join(format!("secret-{index}"));
            std::fs::write(&path, secret).expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
            SecretFile::at(path)
        })
        .collect();
    factory_composition::webhook::verifier_from_files(&files, &mut registry).expect("verifier")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_secrets_are_accepted_during_a_rotation_and_the_old_one_after_it_is_not() {
    let dir = std::env::temp_dir().join(format!("factory-api-rotation-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let old = "old-secret-0123456789-0123456789-0123456789";
    let new = "new-secret-0123456789-0123456789-0123456789";
    // During the overlap both are in the window.
    let overlap = Env::start_with(Options {
        webhooks: Some(Some(verifier_of(&dir, &[old, new]))),
        ..Options::default()
    })
    .await;
    let body = payload(&overlap.a, "bug", 1, 1);
    let signed_with = |secret: &str, id: u64| {
        Req::post("/v1/webhooks/github")
            .header("X-GitHub-Event", "issues")
            .header("X-GitHub-Delivery", &delivery_id(id))
            .header(
                "X-Hub-Signature-256",
                &format!(
                    "sha256={}",
                    factory_testkit::webhook::hmac_sha256_hex(secret.as_bytes(), &body)
                ),
            )
            .header("Content-Type", "application/json")
            .body(body.clone())
    };
    assert_eq!(overlap.send(signed_with(old, 90)).await.status, 202);
    assert_eq!(overlap.send(signed_with(new, 91)).await.status, 202);
    overlap.stop().await;
    // After the old one is removed, it is refused.
    let after = Env::start_with(Options {
        webhooks: Some(Some(verifier_of(&dir, &[new]))),
        ..Options::default()
    })
    .await;
    assert_eq!(after.send(signed_with(old, 92)).await.status, 401);
    assert_eq!(after.send(signed_with(new, 93)).await.status, 202);
    after.stop().await;
    let _ = std::fs::remove_dir_all(dir);
}

// ---- NT-WH-10: floods -----------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flood_is_limited_and_does_not_become_a_flood_of_audit_rows() {
    let limits = factory_api::config::Limits {
        webhook_per_installation_per_minute: 5,
        per_ip_per_minute: 100,
        ..factory_api::config::Limits::default()
    };
    let env = Env::start_with(Options {
        limits,
        ..Options::default()
    })
    .await;
    // Valid deliveries for one installation: the sixth is limited, and nothing else is.
    let mut statuses = Vec::new();
    for n in 0..8_u64 {
        let reply = env
            .send(env.delivery(
                "issues",
                &delivery_id(100 + n),
                &payload(&env.a, "bug", 1, 100 + n),
            ))
            .await;
        statuses.push(reply.status);
    }
    assert_eq!(statuses, [202, 202, 202, 202, 202, 429, 429, 429]);
    // The other tenant's installation has its own count.
    let other = env
        .send(env.delivery("issues", &delivery_id(120), &payload(&env.b, "bug", 1, 1)))
        .await;
    assert_eq!(other.status, 202);
    // Invalid deliveries: each is a 401 until the address is limited; the audit trail is bounded.
    let body = payload(&env.a, "bug", 1, 1);
    let mut unauthorized = 0;
    let mut limited = 0;
    for n in 0..140_u64 {
        let reply = env
            .send(
                Req::post("/v1/webhooks/github")
                    .header("X-GitHub-Event", "issues")
                    .header("X-GitHub-Delivery", &delivery_id(200 + n))
                    .header("X-Hub-Signature-256", "sha256=00")
                    .header("Content-Type", "application/json")
                    .body(body.clone()),
            )
            .await;
        match reply.status {
            401 => unauthorized += 1,
            429 => limited += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert!(limited > 0, "the source address was never limited");
    assert!(unauthorized > 60);
    assert!(
        eventually(Duration::from_secs(15), || async {
            env.db
                .number("SELECT count(*) FROM audit_events WHERE action = 'webhook_accepted_or_rejected.denied'")
                .await
                > 0
        })
        .await
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    let audited = env
        .db
        .number("SELECT count(*) FROM audit_events WHERE action = 'webhook_accepted_or_rejected.denied'")
        .await;
    assert!(
        audited <= 60,
        "{audited} rejection rows for {unauthorized} rejections"
    );
    env.stop().await;
}
