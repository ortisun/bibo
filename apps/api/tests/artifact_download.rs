//! `GET /v1/jobs/{job_id}/artifacts/{sha256}`: the download of one stored document of a job.
//!
//! What these tests show: a document is served as text or as bytes under a type the API chooses,
//! never as a page, always as an attachment and with `nosniff`; a hash that names no document of
//! the job is `404`; a document over the cap is `413` and is not cut; and a tenant cannot read
//! another tenant's document, by the database's row-level security and by the application's own
//! scope, each shown on its own. The last test is the deliberate break: a store that opens every
//! transaction for tenant B, which the first of the two checks catches.
//!
//! The documents are put in the artifact store and linked to a stage run the way the engine does
//! it, so the API reads what the worker would have left. The job and the stage run are real rows.

mod support;

use std::sync::Arc;

use factory_domain::ids::{JobId, StageRunId};
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, Sha256Digest, Slug};
use factory_domain::vocabulary::StageKind;
use factory_ports::artifact::ArtifactStore;
use factory_ports::store::{
    ArtifactDirection, NewArtifactIndexEntry, NewStageRun, Store, StoreError,
};
use factory_storage::artifact_fs::LocalFsArtifactStore;
use serde_json::json;
use support::{Env, Options, Req, Tenant};

type Check = Result<(), String>;

async fn new_job(env: &Env, tenant: &Tenant, key: &str) -> JobId {
    let reply = env
        .send(
            Req::post("/v1/jobs")
                .bearer(&tenant.requester.token)
                .header("Idempotency-Key", key)
                .json(&json!({
                    "repository_id": tenant.repository.as_text(),
                    "source_ref": format!("{}#1", tenant.full_name),
                    "text": "Add a word count to the report.",
                })),
        )
        .await;
    assert_eq!(reply.status, 201, "{}", reply.text());
    JobId::parse(reply.json()["job_id"].as_str().expect("job id")).expect("a job id")
}

async fn stage_run(env: &Env, tenant: &Tenant, job: JobId) -> StageRunId {
    let id = StageRunId::from_uuid(uuid::Uuid::from_u128(
        factory_composition::system::RandomIds::new()
            .map(|ids| factory_ports::clock::IdGenerator::new_uuid(&ids).as_u128())
            .expect("ids"),
    ));
    let mut tx = env
        .worker
        .begin(TenantScope::new(tenant.id))
        .await
        .expect("begin");
    tx.insert_stage_run(NewStageRun {
        id,
        job_id: job,
        kind: StageKind::Validation,
        run_number: 1,
        max_attempts: 3,
        rework_of: None,
    })
    .await
    .expect("insert the stage run");
    tx.commit().await.expect("commit");
    id
}

/// Puts a document in the artifact store, indexes it for the tenant and links it to the stage run
/// as an output, as the engine does. Returns its hash.
async fn keep(
    env: &Env,
    tenant: &Tenant,
    (job, run): (JobId, StageRunId),
    role: &str,
    (bytes, media): (Vec<u8>, &str),
) -> Sha256Digest {
    let index: Arc<dyn Store> = env.worker.clone();
    let artifacts = LocalFsArtifactStore::open(env.artifacts_root.clone(), 64 * 1024 * 1024, index)
        .expect("the artifact root opens");
    let reference = artifacts
        .put(bytes, MediaType::parse(media).expect("a media type"))
        .await
        .expect("the document is stored");
    let mut tx = env
        .worker
        .begin(TenantScope::new(tenant.id))
        .await
        .expect("begin");
    tx.index_artifact(
        NewArtifactIndexEntry::from_reference(&reference, Some((job, run))).expect("a size"),
    )
    .await
    .expect("indexed");
    tx.link_stage_run_artifact(
        run,
        ArtifactDirection::Output,
        Slug::parse(role).expect("a role"),
        reference.sha256.clone(),
    )
    .await
    .expect("linked");
    tx.commit().await.expect("commit");
    reference.sha256
}

fn path(job: JobId, hash: &Sha256Digest) -> String {
    format!("/v1/jobs/{job}/artifacts/{}", hash.hex())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_document_is_served_as_text_or_bytes_never_as_a_page_and_always_as_an_attachment() {
    let env = Env::start().await;
    let job = new_job(&env, &env.a, "download").await;
    let run = stage_run(&env, &env.a, job).await;
    for (role, bytes, media, served, extension) in [
        (
            "note-a1",
            b"hello\n".to_vec(),
            "text/plain",
            "text/plain; charset=utf-8",
            "txt",
        ),
        (
            "page-a1",
            b"<script>alert(1)</script>".to_vec(),
            "text/html",
            "text/plain; charset=utf-8",
            "txt",
        ),
        (
            "report-a1",
            b"{\"a\":1}".to_vec(),
            "application/json",
            "text/plain; charset=utf-8",
            "txt",
        ),
        (
            "image-a1",
            b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>".to_vec(),
            "image/svg+xml",
            "application/octet-stream",
            "bin",
        ),
        (
            "blob-a1",
            vec![0, 159, 146, 150, 255],
            "application/octet-stream",
            "application/octet-stream",
            "bin",
        ),
    ] {
        let hash = keep(&env, &env.a, (job, run), role, (bytes.clone(), media)).await;
        let reply = env
            .send(Req::get(&path(job, &hash)).bearer(&env.a.approver.token))
            .await;
        assert_eq!(reply.status, 200, "{media}: {}", reply.text());
        assert_eq!(reply.header("content-type"), Some(served), "{media}");
        assert_eq!(
            reply.header("x-content-type-options"),
            Some("nosniff"),
            "{media}"
        );
        let disposition = reply.header("content-disposition").unwrap_or_default();
        assert!(
            disposition.starts_with("attachment; filename=\"")
                && disposition.ends_with(&format!(".{extension}\"")),
            "{media}: {disposition}"
        );
        assert_eq!(reply.header("cache-control"), Some("no-store"), "{media}");
        assert!(
            reply
                .header("content-security-policy")
                .is_some_and(|policy| policy.contains("default-src 'none'")),
            "{media}"
        );
        assert_eq!(
            reply.body, bytes,
            "{media}: the bytes are served as they are"
        );
    }
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hash_that_names_no_document_of_the_job_and_a_caller_who_may_not_read_are_refused() {
    let env = Env::start().await;
    let job = new_job(&env, &env.a, "refusals").await;
    let run = stage_run(&env, &env.a, job).await;
    let hash = keep(
        &env,
        &env.a,
        (job, run),
        "note-a1",
        (b"hello\n".to_vec(), "text/plain"),
    )
    .await;
    let token = &env.a.approver.token;
    // A hash is 64 lower case hexadecimal digits, and nothing else names a document.
    let upper = hash.hex().to_ascii_uppercase();
    for bad in [
        String::new(),
        "abc".to_owned(),
        hash.hex()[..63].to_owned(),
        format!("{}0", hash.hex()),
        upper,
        format!("sha256:{}", hash.hex()),
        "../../etc/passwd".to_owned(),
        "0".repeat(64),
    ] {
        let reply = env
            .send(Req::get(&format!("/v1/jobs/{job}/artifacts/{bad}")).bearer(token))
            .await;
        assert_eq!(reply.status, 404, "{bad}: {}", reply.text());
        assert_eq!(reply.json()["error"], "not_found", "{bad}");
    }
    // A job that does not exist, and an id that is not one.
    let elsewhere = JobId::from_uuid(uuid::Uuid::from_u128(0x1234));
    for bad_job in [elsewhere.to_string(), "not-a-job".to_owned()] {
        let reply = env
            .send(Req::get(&format!("/v1/jobs/{bad_job}/artifacts/{}", hash.hex())).bearer(token))
            .await;
        assert_eq!(reply.status, 404, "{bad_job}");
    }
    // No token is 401, and a principal that is on no list is 403 with no reason.
    let anonymous = env.send(Req::get(&path(job, &hash))).await;
    assert_eq!(anonymous.status, 401);
    let outsider = env
        .send(Req::get(&path(job, &hash)).bearer(&env.a.outsider.token))
        .await;
    assert_eq!(outsider.status, 403, "{}", outsider.text());
    assert_eq!(outsider.json(), json!({"error": "forbidden"}));
    // Every designation of the tenant may read.
    for person in [
        &env.a.requester,
        &env.a.approver,
        &env.a.operator,
        &env.a.security,
    ] {
        let reply = env
            .send(Req::get(&path(job, &hash)).bearer(&person.token))
            .await;
        assert_eq!(reply.status, 200, "{}", person.login);
    }
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_document_over_the_cap_is_refused_and_not_cut() {
    let env = Env::start().await;
    let job = new_job(&env, &env.a, "cap").await;
    let run = stage_run(&env, &env.a, job).await;
    let at_the_cap = keep(
        &env,
        &env.a,
        (job, run),
        "full-a1",
        (
            vec![b'x'; usize::try_from(factory_api::reads::MAX_DOWNLOAD_BYTES).expect("fits")],
            "text/plain",
        ),
    )
    .await;
    let over = keep(
        &env,
        &env.a,
        (job, run),
        "over-a1",
        (
            vec![b'y'; usize::try_from(factory_api::reads::MAX_DOWNLOAD_BYTES).expect("fits") + 1],
            "text/plain",
        ),
    )
    .await;
    let token = &env.a.approver.token;
    let reply = env
        .send(Req::get(&path(job, &at_the_cap)).bearer(token))
        .await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.body.len() as u64,
        factory_api::reads::MAX_DOWNLOAD_BYTES
    );
    let refused = env.send(Req::get(&path(job, &over)).bearer(token)).await;
    assert_eq!(refused.status, 413, "{}", refused.text());
    assert_eq!(refused.json()["error"], "payload_too_large");
    env.stop().await;
}

/// Tenant A's approver asks for a document of tenant B's job. The check is the one the deliberate
/// break puts to the test.
async fn tenant_a_cannot_read_tenant_b_document(env: &Env) -> Check {
    let job = new_job(env, &env.b, "isolation").await;
    let run = stage_run(env, &env.b, job).await;
    let hash = keep(
        env,
        &env.b,
        (job, run),
        "secret-b1",
        (b"tenant B only\n".to_vec(), "text/plain"),
    )
    .await;
    let reply = env
        .send(Req::get(&path(job, &hash)).bearer(&env.a.approver.token))
        .await;
    if reply.status != 404 || reply.body.windows(8).any(|w| w == b"tenant B") {
        return Err(format!(
            "tenant A read tenant B's document: {}",
            reply.status
        ));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_tenant_cannot_read_the_document() {
    let env = Env::start().await;
    assert_eq!(tenant_a_cannot_read_tenant_b_document(&env).await, Ok(()));
    env.stop().await;
}

/// The two layers on their own. Row-level security: a transaction opened for tenant B sees no row
/// of tenant A, so neither the index nor the job is there to find. The application's scope: a
/// document that tenant A's index holds is served only for a job whose stage runs are linked to
/// it, so a second job of the same tenant cannot read it, and no database rule stops that.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_database_scope_and_the_application_scope_each_keep_a_document_to_its_job() {
    let env = Env::start().await;
    let job = new_job(&env, &env.a, "first").await;
    let run = stage_run(&env, &env.a, job).await;
    let hash = keep(
        &env,
        &env.a,
        (job, run),
        "note-a1",
        (b"hello\n".to_vec(), "text/plain"),
    )
    .await;

    // 1. The database: tenant B's transaction cannot see tenant A's index row or job, whatever the
    // application asks.
    let mut theirs = env
        .worker
        .begin(TenantScope::new(env.b.id))
        .await
        .expect("begin as tenant B");
    assert!(matches!(
        theirs.get_artifact_index(&hash).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        theirs.get_job(job).await,
        Err(StoreError::NotFound)
    ));
    let _ = theirs.rollback().await;
    let mut ours = env
        .worker
        .begin(TenantScope::new(env.a.id))
        .await
        .expect("begin as tenant A");
    assert!(ours.get_artifact_index(&hash).await.is_ok());
    let _ = ours.rollback().await;

    // 2. The artifact store: it answers only for a hash the scope's own tenant has indexed.
    let index: Arc<dyn Store> = env.worker.clone();
    let store = LocalFsArtifactStore::open(env.artifacts_root.clone(), 64 * 1024 * 1024, index)
        .expect("opens");
    let reference = factory_domain::contracts::ArtifactRef {
        sha256: hash.clone(),
        media_type: MediaType::parse("text/plain").expect("a type"),
        size_bytes: None,
    };
    assert!(
        store
            .get(&TenantScope::new(env.b.id), &reference)
            .await
            .is_err(),
        "the store does not answer for tenant B"
    );
    assert!(
        store
            .get(&TenantScope::new(env.a.id), &reference)
            .await
            .is_ok()
    );

    // 3. The application: a second job of tenant A is in the same tenant, so the database lets
    // its transaction see the index row, and the API still refuses, because no stage run of the
    // second job is linked to the document.
    let second = new_job(&env, &env.a, "second").await;
    let _ = stage_run(&env, &env.a, second).await;
    let refused = env
        .send(Req::get(&path(second, &hash)).bearer(&env.a.approver.token))
        .await;
    assert_eq!(refused.status, 404, "{}", refused.text());
    let served = env
        .send(Req::get(&path(job, &hash)).bearer(&env.a.approver.token))
        .await;
    assert_eq!(served.status, 200);
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_serving_tenant_b_to_tenant_a_documents_is_caught() {
    // Every transaction is opened for tenant B, whoever asked, so row-level security cannot help:
    // the transaction really is B's. For the request to get as far as the handler, tenant B must
    // hold a copy of A's approver principal (the key is the tenant and the id), which is what a bug
    // that mixes the two tenants would find. The check must see the leak.
    let env = Env::start_with(Options {
        serve_tenant_b_to_everyone: true,
        ..Options::default()
    })
    .await;
    env.db
        .run(&format!(
            "INSERT INTO principals (tenant_id, id, kind, github_user_id, login) VALUES ('{}', '{}', 'human', {}, 'copy')",
            env.b.id.as_uuid(),
            env.a.approver.principal.as_uuid(),
            env.a.approver.github_id,
        ))
        .await;
    assert_eq!(
        tenant_a_cannot_read_tenant_b_document(&env).await,
        Err("tenant A read tenant B's document: 200".to_owned())
    );
    env.stop().await;
}
