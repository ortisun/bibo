//! Deliberate breaks, shown caught.
//!
//! Each safeguard is written once as a check that returns `Ok(())` when it holds and an `Err` that
//! says what went wrong when it does not. A test runs the check on the real wiring and expects
//! `Ok`, and a second test runs the same check on a wiring with the safeguard broken and expects
//! the `Err`. A check that passes on a broken wiring would prove nothing, so the second test is
//! what makes the first one worth reading.
//!
//! | Break | Check |
//! |---|---|
//! | skip signature verification | `a_forged_delivery_is_refused` |
//! | compare a token or a signature with `==` | `no_secret_is_compared_with_equals` (a scan of the source) |
//! | log a token | `no_token_is_logged` |
//! | accept a decision authenticated by login | `a_login_does_not_make_an_approver` |
//! | serve tenant B's job to tenant A | `tenant_a_cannot_read_tenant_b_job` |
//! | answer readiness OK while the schema is behind | `readiness_fails_when_the_schema_is_behind` |
//! | route a webhook through the engine login | `tests/database_logins.rs`, the store refuses to start |

mod support;

use std::sync::{Arc, PoisonError};

use factory_testkit::webhook::{FakeWebhookVerifier, WebhookDefect};
use serde_json::json;
use support::{Env, Options, Req, captured};

type Check = Result<(), String>;

// ---- 1. skip signature verification ------------------------------------------------------------

async fn a_forged_delivery_is_refused(env: &Env) -> Check {
    let body = serde_json::to_vec(&json!({
        "action": "labeled",
        "installation": {"id": env.a.installation},
        "repository": {"id": env.a.github_repository, "full_name": env.a.full_name},
        "sender": {"id": env.a.requester.github_id, "login": "x", "type": "User"},
        "issue": {"number": 1, "node_id": "I_1", "updated_at": "2026-10-28T10:00:00Z"},
        "label": {"name": "factory"},
    }))
    .map_err(|e| e.to_string())?;
    let forged = Req::post("/v1/webhooks/github")
        .header("X-GitHub-Event", "issues")
        .header("X-GitHub-Delivery", "0190a3b2-7c4d-4e5f-8a6b-000000000001")
        .header(
            "X-Hub-Signature-256",
            &format!("sha256={}", "00".repeat(32)),
        )
        .header("Content-Type", "application/json")
        .body(body);
    let reply = env.send(forged).await;
    if reply.status != 401 {
        return Err(format!("a forged delivery was answered {}", reply.status));
    }
    let jobs = env.db.number("SELECT count(*) FROM jobs").await;
    let deliveries = env
        .db
        .number("SELECT count(*) FROM webhook_deliveries")
        .await;
    if jobs + deliveries != 0 {
        return Err(format!(
            "a forged delivery left {jobs} job(s) and {deliveries} delivery row(s)"
        ));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signatures_are_verified() {
    let env = Env::start().await;
    assert_eq!(a_forged_delivery_is_refused(&env).await, Ok(()));
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_skipping_signature_verification_is_caught() {
    let skipping = Arc::new(FakeWebhookVerifier::with_defect(
        WebhookDefect::AcceptsAnySignature,
    ));
    let env = Env::start_with(Options {
        webhooks: Some(Some(skipping)),
        ..Options::default()
    })
    .await;
    let caught = a_forged_delivery_is_refused(&env).await;
    assert!(
        caught.as_ref().is_err_and(|why| why.contains("202")),
        "{caught:?}"
    );
    env.stop().await;
}

// ---- 2. compare a secret in constant time ---------------------------------------------------------

/// Lines of API code that compare something that looks like a secret with `==` or `!=`. The API
/// compares no token (the database finds it by hash) and no signature (the verifier does that, in
/// constant time, in the github adapter). A comparison appearing here is a finding.
fn compared_with_equals(source: &str) -> Vec<String> {
    let code = source.split("#[cfg(test)]").next().unwrap_or(source);
    code.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//") && !line.starts_with("///") && !line.starts_with("//!"))
        .filter(|line| line.contains(" == ") || line.contains(" != "))
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            ["token", "secret", "signature", "hmac", "password"]
                .iter()
                .any(|word| lower.contains(word))
        })
        // The route table names a kind of authentication; it is not a comparison of a credential.
        .filter(|line| !line.contains("Auth::Token") && !line.contains("Auth::Signature") && !line.contains("Profile::"))
        .map(str::to_owned)
        .collect()
}

#[test]
fn no_secret_is_compared_with_equals() {
    let mut found = Vec::new();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(&root).expect("src") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            let source = std::fs::read_to_string(&path).expect("read");
            for line in compared_with_equals(&source) {
                found.push(format!("{}: {line}", path.display()));
            }
        }
    }
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn break_comparing_a_token_with_equals_is_caught() {
    let broken = "fn same(presented: &str, stored_token: &str) -> bool {\n    presented == stored_token\n}\n";
    assert_eq!(compared_with_equals(broken).len(), 1);
    let broken_signature = "if signature != expected { return false; }";
    assert_eq!(compared_with_equals(broken_signature).len(), 1);
    // A comparison of something else is not a finding.
    assert!(compared_with_equals("if label == other_label { }").is_empty());
}

// ---- 3. log a token ----------------------------------------------------------------------------------

async fn no_token_is_logged(env: &Env, leak: impl FnOnce(&str)) -> Check {
    let lines = captured();
    let token = env.a.requester.token.clone();
    let unknown = factory_api::tokens::format_token(&[3_u8; 32]);
    let job = env
        .send(
            Req::post("/v1/jobs")
                .bearer(&token)
                .header("Idempotency-Key", "log")
                .json(&json!({"repository_id": env.a.repository.as_text(), "text": "x"})),
        )
        .await;
    let id = job.json()["job_id"].as_str().unwrap_or_default().to_owned();
    for request in [
        Req::get(&format!("/v1/jobs/{id}")).bearer(&token),
        Req::get(&format!("/v1/jobs/{id}")).bearer(&unknown),
        Req::get(&format!("/v1/jobs/{id}")).header("Authorization", "Bearer not-a-token"),
        Req::get(&format!("/v1/jobs/{id}/timeline")).bearer(&env.a.outsider.token),
        Req::get("/v1/jobs/not-an-id").bearer(&token),
    ] {
        env.send(request).await;
    }
    leak(&token);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let all = lines
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .join("\n");
    let body = &token[factory_api::tokens::PREFIX.len()..];
    if all.contains(body) || all.contains(&unknown[factory_api::tokens::PREFIX.len()..]) {
        return Err("a token is in the log".to_owned());
    }
    if all.to_ascii_lowercase().contains("bearer ") {
        return Err("an Authorization header is in the log".to_owned());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_token_reaches_the_log() {
    let env = Env::start().await;
    // The capture works: an event the test emits itself is in it.
    let _ = captured();
    tracing::info!(marker = "capture-self-test", "the capture is installed");
    assert_eq!(no_token_is_logged(&env, |_| {}).await, Ok(()));
    let seen = captured()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .join("\n");
    assert!(
        seen.contains("capture-self-test"),
        "the capture saw nothing"
    );
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_logging_a_token_is_caught() {
    let env = Env::start().await;
    // A handler that logs the credential, once as a field and once as a whole header map.
    let caught = no_token_is_logged(&env, |token| {
        tracing::warn!(token = %token, "authenticating");
    })
    .await;
    assert_eq!(caught, Err("a token is in the log".to_owned()));
    let env_headers = Env::start().await;
    let caught = no_token_is_logged(&env_headers, |token| {
        let mut headers = axum_headers();
        headers.insert(
            "authorization",
            format!("Bearer {token}").parse().expect("value"),
        );
        tracing::info!(headers = ?headers, "request");
    })
    .await;
    assert!(caught.is_err(), "{caught:?}");
    env.stop().await;
    env_headers.stop().await;
}

fn axum_headers() -> axum::http::HeaderMap {
    axum::http::HeaderMap::new()
}

// ---- 4. a login does not make an approver ----------------------------------------------------------------

async fn a_login_does_not_make_an_approver(env: &Env) -> Check {
    // The outsider's numeric id is not on the allowlist. Its login is rewritten to the approver's.
    env.db
        .run(&format!(
            "UPDATE principals SET login = '{}' WHERE id = '{}'",
            env.a.approver.login,
            env.a.outsider.principal.as_uuid()
        ))
        .await;
    let job = env
        .send(
            Req::post("/v1/jobs")
                .bearer(&env.a.requester.token)
                .header("Idempotency-Key", "j")
                .json(&json!({"repository_id": env.a.repository.as_text(), "text": "x"})),
        )
        .await;
    let id = job.json()["job_id"].as_str().unwrap_or_default().to_owned();
    let reply = env
        .send(
            Req::post(&format!("/v1/jobs/{id}/decisions"))
                .bearer(&env.a.outsider.token)
                .header("Idempotency-Key", "d")
                .json(&json!({"verb": "cancel", "reason": "No longer needed."})),
        )
        .await;
    if reply.status != 403 {
        return Err(format!("a decision by login was answered {}", reply.status));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authority_is_the_numeric_id_on_the_allowlist() {
    let env = Env::start().await;
    assert_eq!(a_login_does_not_make_an_approver(&env).await, Ok(()));
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_deciding_by_login_is_caught() {
    // An authority that reads the login string of the principal row and calls "approver-one" an
    // approver. The outsider's numeric id is not listed, but its login is the approver's.
    let env = Env::start_with(Options {
        authority_by_login: Some(vec!["approver-one".to_owned(), "requester-one".to_owned()]),
        ..Options::default()
    })
    .await;
    let caught = a_login_does_not_make_an_approver(&env).await;
    assert_eq!(
        caught,
        Err("a decision by login was answered 202".to_owned())
    );
    env.stop().await;
}

// ---- 5. serve tenant B's job to tenant A --------------------------------------------------------------------

async fn tenant_a_cannot_read_tenant_b_job(env: &Env) -> Check {
    let theirs = env
        .send(
            Req::post("/v1/jobs")
                .bearer(&env.b.requester.token)
                .header("Idempotency-Key", "b")
                .json(
                    &json!({"repository_id": env.b.repository.as_text(), "text": "B's request."}),
                ),
        )
        .await;
    let id = theirs.json()["job_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    if id.is_empty() {
        return Err(format!(
            "tenant B's own submission failed: {}",
            theirs.status
        ));
    }
    let reply = env
        .send(Req::get(&format!("/v1/jobs/{id}")).bearer(&env.a.requester.token))
        .await;
    if reply.status != 404 {
        return Err(format!("tenant A read tenant B's job: {}", reply.status));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tenant_reads_its_own_jobs_only() {
    let env = Env::start().await;
    assert_eq!(tenant_a_cannot_read_tenant_b_job(&env).await, Ok(()));
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_serving_tenant_b_to_tenant_a_is_caught() {
    // Every transaction is opened for tenant B, whoever asked. Row-level security cannot help: the
    // transaction really is B's. For the request to get as far as the handler, tenant B must hold a
    // copy of A's requester principal (the key is the tenant and the id, so the same id can exist
    // in both), which is what a bug that mixes the two would find.
    let env = Env::start_with(Options {
        serve_tenant_b_to_everyone: true,
        ..Options::default()
    })
    .await;
    env.db
        .run(&format!(
            "INSERT INTO principals (tenant_id, id, kind, github_user_id, login) VALUES ('{}', '{}', 'human', {}, 'copy')",
            env.b.id.as_uuid(),
            env.a.requester.principal.as_uuid(),
            env.a.requester.github_id,
        ))
        .await;
    let caught = tenant_a_cannot_read_tenant_b_job(&env).await;
    assert_eq!(caught, Err("tenant A read tenant B's job: 200".to_owned()));
    env.stop().await;
}

// ---- 6. readiness while the schema is behind -----------------------------------------------------------------------

async fn readiness_fails_when_the_schema_is_behind(env: &Env) -> Check {
    env.db
        .run("DELETE FROM __diesel_schema_migrations WHERE version = (SELECT max(version) FROM __diesel_schema_migrations)")
        .await;
    let reply = env.send(Req::get("/readyz")).await;
    if reply.status == 200 {
        return Err("readiness answered OK with the schema behind".to_owned());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn readiness_notices_a_schema_that_is_behind() {
    let env = Env::start().await;
    assert_eq!(
        readiness_fails_when_the_schema_is_behind(&env).await,
        Ok(())
    );
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_readiness_that_ignores_the_schema_is_caught() {
    // The store reports the schema the code expects whatever the database holds.
    let env = Env::start_with(Options {
        report_schema: Some(factory_composition::health::EXPECTED_SCHEMA_VERSION),
        ..Options::default()
    })
    .await;
    let caught = readiness_fails_when_the_schema_is_behind(&env).await;
    assert_eq!(
        caught,
        Err("readiness answered OK with the schema behind".to_owned())
    );
    env.stop().await;
}
