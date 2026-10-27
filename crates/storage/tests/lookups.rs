//! The two lookups that run before a tenant is known (ADR 0012, section 4). A miss gives no reason:
//! a caller cannot tell an unknown token from an expired one.

mod support;

use factory_domain::values::Sha256Digest;
use factory_ports::store::StoreError;
use factory_storage::pg::{PgStore, ResolvedRepository, ResolvedToken, TenantLogin};
use support::{Scene, as_login, config_for, small_pool};

/// The 32 bytes of a SHA-256 digest.
fn digest_bytes(digest: &Sha256Digest) -> [u8; 32] {
    let hex = digest.hex();
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).expect("hex");
    }
    bytes
}

async fn api_store(scene: &Scene) -> PgStore {
    let logins = scene.db.server.logins().await;
    let mut config = config_for(&scene.db).await;
    config.tenant = small_pool(scene.db.url(&logins.api));
    config.tenant_login = TenantLogin::Api;
    PgStore::connect(config)
        .await
        .expect("the API store is ready")
}

/// One token row, as the owner would write it. `lifetime` is given in SQL.
async fn token(
    scene: &Scene,
    tenant: factory_domain::ids::TenantId,
    name: &str,
    columns: &str,
    values: &str,
) -> [u8; 32] {
    let hash = Sha256Digest::of(format!("token {name}").as_bytes());
    let principal = scene
        .db
        .text(&format!(
            "SELECT id FROM principals WHERE tenant_id = '{}' LIMIT 1",
            tenant.as_uuid()
        ))
        .await
        .expect("a principal");
    scene
        .db
        .run(&format!(
            "INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, audience, {columns}) \
             VALUES ('{}', gen_random_uuid(), '{principal}', decode('{}', 'hex'), 'api', {values})",
            tenant.as_uuid(),
            hash.hex(),
        ))
        .await;
    digest_bytes(&hash)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lookups_hide_the_reason() {
    let scene = Scene::new().await;
    let (a, b) = (scene.a, scene.b);
    let principal_a = scene.principal(a).await;
    scene.principal(b).await;
    let store = api_store(&scene).await;

    let valid = token(
        &scene,
        a,
        "valid",
        "created_at, expires_at",
        "now() - interval '1 minute', now() + interval '1 hour'",
    )
    .await;
    let expired = token(
        &scene,
        a,
        "expired",
        "created_at, expires_at",
        "now() - interval '2 hours', now() - interval '1 hour'",
    )
    .await;
    let revoked = token(
        &scene,
        a,
        "revoked",
        "created_at, expires_at, revoked_at",
        "now() - interval '2 hours', now() + interval '1 hour', now() - interval '1 hour'",
    )
    .await;
    let tenant_b = token(
        &scene,
        b,
        "tenant b",
        "created_at, expires_at",
        "now() - interval '1 minute', now() + interval '1 hour'",
    )
    .await;
    let unknown = digest_bytes(&Sha256Digest::of(b"never stored"));

    // The valid token answers with its tenant and principal.
    assert_eq!(
        store.resolve_token(&valid, "api").await,
        Ok(Some(ResolvedToken {
            tenant: a,
            principal: principal_a
        }))
    );
    // Every kind of miss gives the same answer: nothing. A caller cannot tell them apart.
    let wrong_audience = store.resolve_token(&valid, "dashboard").await;
    let misses = [
        ("unknown", store.resolve_token(&unknown, "api").await),
        ("expired", store.resolve_token(&expired, "api").await),
        ("revoked", store.resolve_token(&revoked, "api").await),
        ("wrong audience", wrong_audience),
    ];
    for (reason, answer) in &misses {
        assert_eq!(answer, &Ok(None), "{reason}");
    }
    // A disabled owner and a disabled tenant give the same answer.
    scene
        .db
        .run(&format!(
            "UPDATE principals SET disabled_at = now() WHERE tenant_id = '{}'",
            b.as_uuid()
        ))
        .await;
    assert_eq!(
        store.resolve_token(&tenant_b, "api").await,
        Ok(None),
        "disabled principal"
    );
    scene
        .db
        .run(&format!(
            "UPDATE principals SET disabled_at = NULL WHERE tenant_id = '{}'",
            b.as_uuid()
        ))
        .await;
    assert_eq!(
        store
            .resolve_token(&tenant_b, "api")
            .await
            .map(|found| found.is_some()),
        Ok(true),
        "the token of tenant B works while nothing is disabled"
    );
    scene
        .db
        .run(&format!(
            "UPDATE tenants SET disabled_at = now() WHERE id = '{}'",
            b.as_uuid()
        ))
        .await;
    assert_eq!(
        store.resolve_token(&tenant_b, "api").await,
        Ok(None),
        "disabled tenant"
    );
    // The answers for all the misses are one and the same value.
    let debug: Vec<String> = misses
        .iter()
        .map(|(_, answer)| format!("{answer:?}"))
        .collect();
    assert!(debug.windows(2).all(|pair| pair[0] == pair[1]), "{debug:?}");

    // The installation lookup: a registered pair answers, every other case gives nothing.
    let repository_a = scene
        .db
        .text(&format!(
            "SELECT id FROM repositories WHERE tenant_id = '{}'",
            a.as_uuid()
        ))
        .await
        .expect("repository");
    assert_eq!(
        store.resolve_installation(1000, 2000).await,
        Ok(Some(ResolvedRepository {
            tenant: a,
            repository: repository_a.parse().expect("uuid")
        }))
    );
    assert_eq!(
        store.resolve_installation(999, 2000).await,
        Ok(None),
        "an unknown installation"
    );
    assert_eq!(
        store.resolve_installation(1000, 2001).await,
        Ok(None),
        "a pair that does not belong together"
    );
    assert_eq!(
        store.resolve_installation(1000, 4242).await,
        Ok(None),
        "an unknown repository"
    );
    scene
        .db
        .run(&format!(
            "UPDATE repositories SET enabled = false, version = version + 1 WHERE tenant_id = '{}'",
            a.as_uuid()
        ))
        .await;
    assert_eq!(
        store.resolve_installation(1000, 2000).await,
        Ok(None),
        "a disabled repository"
    );
    assert_eq!(
        store.resolve_installation(1001, 2001).await,
        Ok(None),
        "a repository of a disabled tenant"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_api_login_may_run_the_lookups() {
    let scene = Scene::new().await;
    // A store built on the worker login refuses to offer the lookups at all.
    assert_eq!(
        scene.store.resolve_token(&[0_u8; 32], "api").await,
        Err(StoreError::ScopeNotAllowed)
    );
    assert_eq!(
        scene.store.resolve_installation(1, 1).await,
        Err(StoreError::ScopeNotAllowed)
    );
    // And the database refuses the worker login that tries them with raw SQL: a compromised worker
    // cannot test token hashes or ask which tenant holds an installation.
    let logins = scene.db.server.logins().await;
    for sql in [
        "SELECT tenant_id::text AS v FROM resolve_token('\\x00'::bytea, 'api')",
        "SELECT tenant_id::text AS v FROM resolve_installation(1000, 2000)",
    ] {
        for login in [&logins.worker, &logins.engine] {
            let refused = as_login(&scene.db, login, None, sql).await;
            assert!(
                refused
                    .as_ref()
                    .is_err_and(|text| text.contains("permission denied")),
                "{} may not run {sql}: {refused:?}",
                login.name
            );
        }
    }
    // The API login can.
    assert!(
        as_login(
            &scene.db,
            &logins.api,
            None,
            "SELECT tenant_id::text AS v FROM resolve_installation(1000, 2000)"
        )
        .await
        .is_ok()
    );
}
