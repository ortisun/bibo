//! Small helpers shared by the review tests.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::support::{Env, Person, Req, Tenant};

/// Sends `bytes` on a fresh connection and returns everything the server sends back until it closes
/// the connection or `wait` passes, as lossy text, together with whether the server closed first.
pub async fn raw(addr: SocketAddr, bytes: &[u8], wait: Duration) -> (String, bool) {
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let _ = stream.write_all(bytes).await;
    let mut out = Vec::new();
    let mut chunk = [0_u8; 8192];
    let deadline = tokio::time::Instant::now() + wait;
    let closed = loop {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break true,
            Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
            Err(_) => break false,
        }
    };
    (String::from_utf8_lossy(&out).into_owned(), closed)
}

/// How many responses a raw answer holds.
pub fn responses(raw: &str) -> usize {
    raw.matches("HTTP/1.1 ").count()
}

/// The first line of a raw answer.
pub fn first_line(raw: &str) -> &str {
    raw.lines().next().unwrap_or("")
}

/// A random UUID from the operating system (the test crate has no `v4` feature of `uuid`).
pub fn new_uuid() -> uuid::Uuid {
    use factory_ports::clock::IdGenerator;
    factory_composition::system::RandomIds::new()
        .expect("the random source opens")
        .new_uuid()
}

/// A token built at run time from 32 random bytes, so that no secret-shaped literal is written.
pub fn runtime_token() -> String {
    let mut secret = [0_u8; 32];
    secret[..16].copy_from_slice(new_uuid().as_bytes());
    secret[16..].copy_from_slice(new_uuid().as_bytes());
    factory_api::tokens::format_token(&secret)
}

/// Submits a job as the tenant's requester and returns its id.
pub async fn new_job(env: &Env, tenant: &Tenant, key: &str) -> String {
    let reply = env
        .send(
            Req::post("/v1/jobs")
                .bearer(&tenant.requester.token)
                .header("Idempotency-Key", key)
                .json(&json!({"repository_id": tenant.repository.as_text(), "text": "Add a word count."})),
        )
        .await;
    assert_eq!(reply.status, 201, "{}", reply.text());
    reply.json()["job_id"].as_str().expect("job id").to_owned()
}

/// Gives a job an approval-stage run, as the store would, and returns its id.
pub async fn stage_run(env: &Env, tenant: &Tenant, job: &str) -> String {
    use factory_domain::ids::{JobId, StageRunId};
    use factory_domain::scope::TenantScope;
    use factory_domain::vocabulary::StageKind;
    use factory_ports::store::{NewStageRun, Store};
    let id = StageRunId::from_uuid(new_uuid());
    let mut tx = env
        .store
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
    id.as_text()
}

/// `POST /v1/jobs/{job}/decisions` as `person`.
pub fn decide(person: &Person, job: &str, key: &str, body: &Value) -> Req {
    Req::post(&format!("/v1/jobs/{job}/decisions"))
        .bearer(&person.token)
        .header("Idempotency-Key", key)
        .json(body)
}

/// The body of an approval that names a head and an evidence digest.
pub fn approval(run: &str) -> Value {
    json!({
        "verb": "approve",
        "stage_run_id": run,
        "head": "a".repeat(40),
        "evidence": format!("sha256:{}", "b".repeat(64)),
    })
}

/// The allowlist file for both tenants (a requester, an approver and an operator each), with
/// `extra` entries appended and `edit` applied to the text.
pub fn allowlist_with(env: &Env, edit: impl Fn(String) -> String) -> String {
    let mut text = String::from("version: 1\nentries:\n");
    for tenant in [&env.a, &env.b] {
        for (person, designation) in [
            (&tenant.requester, "requester"),
            (&tenant.approver, "approver"),
            (&tenant.operator, "operator"),
        ] {
            text.push_str(&format!(
                "  - tenant: {}\n    github_user_id: {}\n    login: {}\n    designations: [{designation}]\n",
                tenant.id.as_uuid(),
                person.github_id,
                person.login,
            ));
        }
    }
    edit(text)
}

/// Replaces the allowlist the running API reads on every request.
pub fn write_allowlist(env: &Env, text: &str) {
    std::fs::write(env.checkout.join("allowlist/allowlist.yaml"), text).expect("the allowlist");
}

/// The line of an allowlist entry for one person, as `allowlist_with` writes it.
pub fn entry_of(tenant: &Tenant, person: &Person, designation: &str) -> String {
    format!(
        "  - tenant: {}\n    github_user_id: {}\n    login: {}\n    designations: [{designation}]\n",
        tenant.id.as_uuid(),
        person.github_id,
        person.login,
    )
}

/// A second repository in the tenant, made as the superuser. Returns its id.
pub async fn second_repository(env: &Env, tenant: &Tenant) -> String {
    let id = new_uuid();
    env.db
        .run(&format!(
            "INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, full_name, default_branch, autonomy_ceiling) \
             VALUES ('{}', '{id}', {}, 6999, 'org/other-repo', 'main', 'L1')",
            tenant.id.as_uuid(),
            tenant.installation
        ))
        .await;
    id.to_string()
}

/// A webhook payload for an issue labeled by `sender` in the tenant's repository.
pub fn labeled(tenant: &Tenant, label: &str, sender: u64, issue: u64) -> Vec<u8> {
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

/// A delivery id of the accepted shape.
pub fn delivery_id(n: u64) -> String {
    format!("0190a3b2-7c4d-4e5f-8a6b-{n:012}")
}
