//! The two pools, the role checks and the readiness report, against a real PostgreSQL server.

mod support;

use factory_domain::vocabulary::Fidelity;
use factory_ports::store::Store;
use factory_storage::pg::{PgStore, RoleProblem, StartupError};
use factory_worker::database::pools;
use factory_worker::health::{CheckStatus, EXPECTED_SCHEMA_VERSION, check_schema};
use support::{Scene, server, small_pool, worker_config};

#[tokio::test(flavor = "multi_thread")]
async fn two_pools_two_roles_connect_as_two_different_logins() {
    let scene = Scene::new().await;
    // The store is real, and its tenant pool and system pool were accepted with the logins the
    // worker uses. Each login really is a different role in the database.
    assert_eq!(scene.store.fidelity(), Fidelity::Real);
    let logins = scene.db.server.logins().await;
    assert_ne!(logins.worker.name, logins.engine.name);
    let roles = scene
        .db
        .text("SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles WHERE rolname LIKE 'dbtest_%'")
        .await
        .expect("roles");
    assert!(roles.contains(&logins.worker.name) && roles.contains(&logins.engine.name));
}

#[tokio::test(flavor = "multi_thread")]
async fn two_pools_two_roles_refuse_the_engine_login_on_the_tenant_pool() {
    let db = server().clone_database().await;
    let logins = db.server.logins().await;
    // The pools swapped: the system login on the tenant pool, the worker login on the system pool.
    let swapped = pools(
        small_pool(db.url(&logins.engine)),
        small_pool(db.url(&logins.worker)),
    );
    let refusal = PgStore::connect(swapped).await.expect_err("must refuse");
    assert!(
        matches!(
            refusal,
            StartupError::RoleNotAllowed {
                problem: RoleProblem::MissingGroup | RoleProblem::ForbiddenGroup,
                ..
            }
        ),
        "{refusal:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn two_pools_two_roles_refuse_a_superuser_on_either_pool() {
    let db = server().clone_database().await;
    let logins = db.server.logins().await;
    let mut config = worker_config(&db).await;
    config.tenant = small_pool(db.server.admin_url(&db.name));
    let refusal = PgStore::connect(config).await.expect_err("must refuse");
    assert!(
        matches!(
            refusal,
            StartupError::RoleNotAllowed {
                problem: RoleProblem::Superuser,
                ..
            }
        ),
        "{refusal:?}"
    );
    let mut config = worker_config(&db).await;
    config.system = Some(small_pool(db.server.admin_url(&db.name)));
    let refusal = PgStore::connect(config).await.expect_err("must refuse");
    assert!(
        matches!(
            refusal,
            StartupError::RoleNotAllowed {
                problem: RoleProblem::Superuser,
                ..
            }
        ),
        "{refusal:?}"
    );
    let _ = logins;
}

#[tokio::test(flavor = "multi_thread")]
async fn readiness_checks_schema_version_against_the_build() {
    let scene = Scene::new().await;
    let ready = check_schema(&scene.store, EXPECTED_SCHEMA_VERSION).await;
    assert_eq!(ready.status, CheckStatus::Pass, "{ready:?}");

    // A restore brings back an older schema: the newest migration record disappears.
    scene
        .db
        .run("DELETE FROM __diesel_schema_migrations WHERE version = (SELECT max(version) FROM __diesel_schema_migrations)")
        .await;
    let behind = check_schema(&scene.store, EXPECTED_SCHEMA_VERSION).await;
    assert_eq!(behind.status, CheckStatus::Fail, "{behind:?}");
    assert!(behind.detail.contains("behind the code"));

    // A new process refuses to start on that database at all.
    let refusal = PgStore::connect(worker_config(&scene.db).await)
        .await
        .expect_err("start-up must refuse");
    assert!(
        matches!(refusal, StartupError::SchemaBehind { missing: 1 }),
        "{refusal:?}"
    );
}
