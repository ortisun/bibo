//! The three-logins rule (ADR 0012) as the API meets it: the API connects as the API login, a
//! member of `factory_app` and `factory_resolver`, and cannot do what the engine login does. The
//! reverse holds too, so a webhook cannot be routed through the engine login.

mod support;

use factory_ports::store::{Audience, FaultCode, Store, StoreError};
use factory_storage::pg::{PgStore, PgStoreConfig, StartupError, TenantLogin};
use support::{Env, Login, small_pool};

async fn store_as(env: &Env, login: &Login, kind: TenantLogin) -> Result<PgStore, StartupError> {
    let mut config = PgStoreConfig::new(small_pool(env.db.url(login)));
    config.tenant_login = kind;
    PgStore::connect(config).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_api_connects_as_the_api_login_and_no_other_login_is_accepted_for_it() {
    let env = Env::start().await;
    let logins = env.db.server.logins().await;
    // The API login, declared as the API's, starts.
    assert!(store_as(&env, &logins.api, TenantLogin::Api).await.is_ok());
    // A webhook routed through the engine login: the store refuses to start on it.
    let engine = store_as(&env, &logins.engine, TenantLogin::Api).await;
    assert!(
        matches!(engine, Err(StartupError::RoleNotAllowed { .. })),
        "{engine:?}"
    );
    // The worker login has no resolver group, so it cannot be the API's.
    let worker = store_as(&env, &logins.worker, TenantLogin::Api).await;
    assert!(
        matches!(worker, Err(StartupError::RoleNotAllowed { .. })),
        "{worker:?}"
    );
    // The API login is one login in two groups, which the worker's declaration does not allow.
    let api_as_worker = store_as(&env, &logins.api, TenantLogin::Worker).await;
    assert!(
        matches!(api_as_worker, Err(StartupError::RoleNotAllowed { .. })),
        "{api_as_worker:?}"
    );
    // A superuser is refused whatever it is declared as.
    let admin = PgStore::connect({
        let mut config = PgStoreConfig::new(small_pool(env.db.server.admin_url(&env.db.name)));
        config.tenant_login = TenantLogin::Api;
        config
    })
    .await;
    assert!(
        matches!(admin, Err(StartupError::RoleNotAllowed { .. })),
        "{admin:?}"
    );
    env.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_worker_store_cannot_make_the_lookups_that_only_the_api_login_may() {
    let env = Env::start().await;
    let logins = env.db.server.logins().await;
    let worker = store_as(&env, &logins.worker, TenantLogin::Worker)
        .await
        .expect("starts");
    let audience = Audience(factory_domain::values::Slug::parse("factory-api").expect("slug"));
    let hash = factory_api::tokens::hash_token(&env.a.requester.token);
    assert_eq!(
        worker.resolve_token(&hash, &audience).await.unwrap_err(),
        StoreError::Internal(FaultCode::PermissionDenied)
    );
    // The API's own store makes the same call.
    assert!(
        env.store
            .resolve_token(&hash, &audience)
            .await
            .expect("resolves")
            .is_some()
    );
    env.stop().await;
}

/// In the database itself, as each login: what one can do, the other cannot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_api_login_cannot_do_what_the_engine_login_does_and_the_reverse() {
    use diesel::sql_query;
    use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
    let env = Env::start().await;
    let logins = env.db.server.logins().await;
    // Something for the engine to find: a job of each tenant.
    for tenant in [&env.a, &env.b] {
        let reply = env
            .send(
                support::Req::post("/v1/jobs")
                    .bearer(&tenant.requester.token)
                    .header("Idempotency-Key", "k")
                    .json(&serde_json::json!({"repository_id": tenant.repository.as_text(), "text": "x"})),
            )
            .await;
        assert_eq!(reply.status, 201, "{}", reply.text());
    }

    #[derive(diesel::QueryableByName)]
    struct Count {
        #[diesel(sql_type = diesel::sql_types::BigInt)]
        n: i64,
    }
    #[derive(diesel::QueryableByName)]
    struct Flag {
        #[diesel(sql_type = diesel::sql_types::Bool)]
        yes: bool,
    }
    async fn flag(connection: &mut diesel_async::AsyncPgConnection, sql: &str) -> bool {
        sql_query(format!("SELECT ({sql}) AS yes"))
            .get_result::<Flag>(connection)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
            .yes
    }

    // The API login: sees no tenant's rows without naming one, is not the system scope, and the
    // statements that would make it one are refused.
    let mut api = env.db.connect_as(&logins.api).await;
    let all: Count = sql_query("SELECT count(*) AS n FROM jobs")
        .get_result(&mut api)
        .await
        .expect("count");
    assert_eq!(
        all.n, 0,
        "with no tenant named the API login sees nothing, though two jobs exist"
    );
    assert!(
        !flag(
            &mut api,
            "pg_has_role(current_user, 'factory_system', 'MEMBER')"
        )
        .await
    );
    assert!(
        flag(
            &mut api,
            "pg_has_role(current_user, 'factory_resolver', 'MEMBER')"
        )
        .await
    );
    assert!(
        flag(
            &mut api,
            "has_function_privilege(current_user, 'resolve_token(bytea, text)', 'EXECUTE')"
        )
        .await
    );
    let become_engine = format!("SET SESSION AUTHORIZATION \"{}\"", logins.engine.name);
    for statement in [
        "SET ROLE factory_system",
        become_engine.as_str(),
        "ALTER TABLE jobs DISABLE ROW LEVEL SECURITY",
        "CREATE POLICY everything ON jobs USING (true)",
        "DELETE FROM audit_events",
        "UPDATE audit_events SET reason = 'x'",
        "TRUNCATE jobs",
    ] {
        let refused = api.batch_execute(statement).await;
        assert!(refused.is_err(), "the API login ran: {statement}");
    }

    // The engine login: it is the system scope, and holds none of the API's powers.
    let mut engine = env.db.connect_as(&logins.engine).await;
    assert!(
        flag(
            &mut engine,
            "pg_has_role(current_user, 'factory_system', 'MEMBER')"
        )
        .await
    );
    assert!(
        !flag(
            &mut engine,
            "pg_has_role(current_user, 'factory_resolver', 'MEMBER')"
        )
        .await
    );
    for function in [
        "resolve_token(bytea, text)",
        "resolve_installation(bigint, bigint)",
    ] {
        let sql = format!("has_function_privilege(current_user, '{function}', 'EXECUTE')");
        assert!(
            !flag(&mut engine, &sql).await,
            "the engine login may run {function}"
        );
    }
    for (table, privilege) in [
        ("webhook_deliveries", "INSERT"),
        ("audit_events", "INSERT"),
        ("audit_events", "SELECT"),
        ("api_tokens", "SELECT"),
        ("original_requests", "SELECT"),
        ("jobs", "INSERT"),
    ] {
        let sql = format!("has_table_privilege(current_user, '{table}', '{privilege}')");
        assert!(
            !flag(&mut engine, &sql).await,
            "the engine login holds {privilege} on {table}"
        );
    }
    let lookup = "SELECT * FROM resolve_token(decode('00', 'hex'), 'factory-api')";
    assert!(
        engine.batch_execute(lookup).await.is_err(),
        "the engine login made the lookup"
    );
    env.stop().await;
}
