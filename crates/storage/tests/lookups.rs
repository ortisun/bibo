//! The lookups that happen before a tenant is known (ADR 0012, section 4), as methods of the `Store`
//! port: `resolve_token`, `resolve_installation` and `record_platform_audit`.
//!
//! A miss gives no reason. Every way a token or an installation can fail to match answers
//! `Ok(None)`, so a caller cannot tell an unknown token from an expired one, a revoked one, one
//! for another audience, a disabled owner or a disabled tenant. Only the API login may run them.

mod support;

use factory_domain::scope::PlatformScope;
use factory_domain::values::{Sha256Digest, Slug};
use factory_ports::store::{
    Audience, AuditAction, AuditActor, AuditDecision, FaultCode, GithubRepositoryId,
    InstallationId, NewAuditEvent, Store, StoreError, TokenHash,
};
use factory_storage::pg::PgStore;
use support::{Scene, as_login, worker_config_for};

fn audience() -> Audience {
    Audience(Slug::parse("factory-api").expect("slug"))
}

fn hex(hash: &TokenHash) -> String {
    hash.0.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A token row for `principal` of `tenant`, with the SQL that decides its state.
async fn token(
    scene: &Scene,
    number: u8,
    tenant: factory_domain::ids::TenantId,
    principal: factory_domain::ids::PrincipalId,
    created: &str,
    expires: &str,
    revoked: &str,
) -> TokenHash {
    let hash = TokenHash([number; 32]);
    scene
        .db
        .run(&format!(
            "INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, created_at, \
                    expires_at, revoked_at) \
             VALUES ('{}', '{}', '{}', decode('{}', 'hex'), 'factory-api', {created}, {expires}, {revoked})",
            tenant.as_uuid(),
            uuid::Uuid::from_u128(5000 + u128::from(number)),
            principal.as_uuid(),
            hex(&hash)
        ))
        .await;
    hash
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookups_hide_the_reason() {
    let scene = Scene::new().await;
    let owner = scene.principal(scene.a).await;
    let gone = scene.principal(scene.a).await;
    scene
        .db
        .run(&format!(
            "UPDATE principals SET disabled_at = now() WHERE id = '{}'",
            gone.as_uuid()
        ))
        .await;
    let other_owner = scene.principal(scene.b).await;

    let good = token(
        &scene,
        1,
        scene.a,
        owner,
        "now()",
        "now() + interval '1 day'",
        "NULL",
    )
    .await;
    let expired = token(
        &scene,
        2,
        scene.a,
        owner,
        "now() - interval '2 days'",
        "now() - interval '1 day'",
        "NULL",
    )
    .await;
    let revoked = token(
        &scene,
        3,
        scene.a,
        owner,
        "now()",
        "now() + interval '1 day'",
        "now()",
    )
    .await;
    let disabled_owner = token(
        &scene,
        4,
        scene.a,
        gone,
        "now()",
        "now() + interval '1 day'",
        "NULL",
    )
    .await;
    let disabled_tenant = token(
        &scene,
        5,
        scene.b,
        other_owner,
        "now()",
        "now() + interval '1 day'",
        "NULL",
    )
    .await;
    scene
        .db
        .run(&format!(
            "UPDATE tenants SET disabled_at = now() WHERE id = '{}'",
            scene.b.as_uuid()
        ))
        .await;

    let store = &scene.store;
    let found = store
        .resolve_token(&good, &audience())
        .await
        .expect("resolve");
    assert_eq!(
        found.map(|who| (who.tenant, who.principal)),
        Some((scene.a, owner))
    );

    // Every miss is the same answer: `None`, with nothing to tell which reason it was.
    let wrong_audience = Audience(Slug::parse("other-api").expect("slug"));
    let misses = [
        store.resolve_token(&TokenHash([99; 32]), &audience()).await,
        store.resolve_token(&expired, &audience()).await,
        store.resolve_token(&revoked, &audience()).await,
        store.resolve_token(&good, &wrong_audience).await,
        store.resolve_token(&disabled_owner, &audience()).await,
        store.resolve_token(&disabled_tenant, &audience()).await,
    ];
    for (position, miss) in misses.iter().enumerate() {
        assert_eq!(miss, &Ok(None), "miss number {position}");
    }

    // The same for the webhook binding. The seeded repository of tenant A is installation 1000.
    let installation = InstallationId(1000);
    let repository = GithubRepositoryId(2000);
    let known = store
        .resolve_installation(installation, repository)
        .await
        .expect("resolve");
    assert_eq!(
        known.map(|bound| (bound.tenant, bound.repository)),
        Some((scene.a, scene.repository(scene.a)))
    );
    scene
        .db
        .run(&format!(
            "UPDATE repositories SET enabled = false, version = version + 1 WHERE tenant_id = '{}'",
            scene.a.as_uuid()
        ))
        .await;
    let misses = [
        store
            .resolve_installation(InstallationId(9999), repository)
            .await,
        store
            .resolve_installation(installation, GithubRepositoryId(9999))
            .await,
        // The pair of another tenant's installation and this repository does not belong together.
        store
            .resolve_installation(InstallationId(1001), repository)
            .await,
        // The repository is disabled now.
        store.resolve_installation(installation, repository).await,
        // The tenant of installation 1001 is disabled.
        store
            .resolve_installation(InstallationId(1001), GithubRepositoryId(2001))
            .await,
        // No number can name a row above the largest signed value.
        store
            .resolve_installation(InstallationId(u64::MAX), repository)
            .await,
    ];
    for (position, miss) in misses.iter().enumerate() {
        assert_eq!(miss, &Ok(None), "installation miss number {position}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_api_login_may_run_the_lookups() {
    let scene = Scene::new().await;
    // A store connected as the worker login refuses all three without asking the database.
    let worker = PgStore::connect(worker_config_for(&scene.db).await)
        .await
        .expect("a worker store is ready");
    let refusal = Err(StoreError::Internal(FaultCode::PermissionDenied));
    assert_eq!(
        worker.resolve_token(&TokenHash([1; 32]), &audience()).await,
        refusal.clone().map(|()| None)
    );
    assert_eq!(
        worker
            .resolve_installation(InstallationId(1000), GithubRepositoryId(2000))
            .await,
        refusal.clone().map(|()| None)
    );
    let event = NewAuditEvent {
        id: factory_domain::ids::AuditEventId::from_uuid(uuid::Uuid::from_u128(77)),
        actor: AuditActor::Anonymous(Slug::parse("webhook").expect("slug")),
        action: AuditAction::new("webhook.rejected").expect("action"),
        subject: "a delivery".to_owned(),
        decision: AuditDecision::Deny,
        reason: "The signature did not verify.".to_owned(),
        policy_hash: Sha256Digest::of(b"policy"),
        job: None,
        stage_run: None,
        correlation_id: scene.ids.correlation(),
    };
    assert_eq!(
        worker
            .record_platform_audit(PlatformScope::receiver(), event)
            .await
            .map(|_| ()),
        refusal
    );

    // And the database says the same if the store did not: neither the worker login nor the
    // engine login holds the grant on the two functions.
    let logins = scene.db.server.logins().await;
    for login in [&logins.worker, &logins.engine] {
        let outcome = as_login(
            &scene.db,
            login,
            None,
            "SELECT tenant_id::text AS v FROM resolve_token(decode(repeat('01', 32), 'hex'), 'factory-api')",
        )
        .await;
        assert!(
            outcome
                .as_ref()
                .is_err_and(|text| text.contains("permission denied")),
            "{}: {outcome:?}",
            login.name
        );
    }
}
