//! Tenant isolation on a real database, through the adapter and through raw logins: a session with
//! no setting, an empty one or a malformed one sees nothing or fails loudly; a pooled connection
//! carries no tenant into the next transaction; a login that could bypass row-level security is
//! refused at start-up; and every method of the transaction answers a foreign row as it answers a
//! missing one.

mod support;

use std::time::Duration;

use diesel::sql_query;
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use factory_domain::values::{GitSha, Sha256Digest};
use factory_ports::sandbox::SandboxId;
use factory_ports::store::{
    ApprovalInvalidation, AuditFilter, Fence, OutboxSeq, SandboxRecord, StoreError, Version,
    WorkerId,
};
use factory_storage::pg::{PgPool, PgStore, PoolSettings, RoleProblem, StartupError};
use factory_testkit::fixtures::{domain_event, ledger_entry};
use support::{Scene, as_login, at, config_for, server, small_pool};
use uuid::Uuid;

fn count(value: Result<Option<String>, String>) -> String {
    value.expect("the statement runs").expect("a row")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_ten_01() {
    let scene = Scene::new().await;
    let worker = scene.db.server.logins().await.worker.clone();
    let (a, b) = (scene.a.as_uuid(), scene.b.as_uuid());
    scene.job(scene.a).await;
    scene.job(scene.a).await;
    scene.job(scene.b).await;
    let jobs = |filter: &str| format!("SELECT count(*)::text AS v FROM jobs {filter}");

    // A call that makes no tenant setting sees nothing, and gets no error.
    assert_eq!(
        count(as_login(&scene.db, &worker, None, &jobs("")).await),
        "0"
    );
    // The setting names tenant A: A's rows only.
    assert_eq!(
        count(as_login(&scene.db, &worker, Some(&a.to_string()), &jobs("")).await),
        "2"
    );
    assert_eq!(
        count(as_login(&scene.db, &worker, Some(&b.to_string()), &jobs("")).await),
        "1"
    );
    // Asking for the other tenant's rows by name does not help.
    assert_eq!(
        count(
            as_login(
                &scene.db,
                &worker,
                Some(&a.to_string()),
                &jobs(&format!("WHERE tenant_id = '{b}'"))
            )
            .await
        ),
        "0"
    );
    // An empty setting sees nothing and gets no error.
    assert_eq!(
        count(as_login(&scene.db, &worker, Some(""), &jobs("")).await),
        "0"
    );
    // A setting that is not a uuid fails loudly: a bug in the caller is not quietly empty.
    let garbage = as_login(&scene.db, &worker, Some("not-a-uuid"), &jobs("")).await;
    assert!(
        garbage.as_ref().is_err_and(|text| text.contains("uuid")),
        "a setting that is not a uuid is an error: {garbage:?}"
    );

    // Writes. Tenant A's session cannot add a row for B, and cannot change B's rows.
    let insert_for_b = format!(
        "WITH i AS (INSERT INTO principals (tenant_id, id, kind, login) VALUES ('{b}', '{}', 'service', 'intruder') RETURNING 1) \
         SELECT count(*)::text AS v FROM i",
        Uuid::from_u128(77)
    );
    let refused = as_login(&scene.db, &worker, Some(&a.to_string()), &insert_for_b).await;
    assert!(
        refused
            .as_ref()
            .is_err_and(|text| text.contains("row-level security")),
        "an insert for another tenant is refused by the policy: {refused:?}"
    );
    // The control: the same statement works for B itself, so the policy is what stopped A.
    assert_eq!(
        count(as_login(&scene.db, &worker, Some(&b.to_string()), &insert_for_b).await),
        "1"
    );
    let update_b = format!(
        "WITH u AS (UPDATE jobs SET version = version + 1 WHERE tenant_id = '{b}' RETURNING 1) SELECT count(*)::text AS v FROM u"
    );
    assert_eq!(
        count(as_login(&scene.db, &worker, Some(&a.to_string()), &update_b).await),
        "0"
    );
    assert_eq!(
        count(as_login(&scene.db, &worker, Some(&b.to_string()), &update_b).await),
        "1"
    );
    let move_to_b = format!(
        "WITH u AS (UPDATE jobs SET tenant_id = '{b}' WHERE tenant_id = '{a}' RETURNING 1) SELECT count(*)::text AS v FROM u"
    );
    assert!(
        as_login(&scene.db, &worker, Some(&a.to_string()), &move_to_b)
            .await
            .is_err()
    );

    // The same through the store: a transaction for A reads A's job and never B's.
    let mut tx_a = scene.tx(scene.a).await;
    let mut tx_b = scene.tx(scene.b).await;
    let first_job_of_b = scene
        .db
        .text(&format!("SELECT id FROM jobs WHERE tenant_id = '{b}'"))
        .await
        .expect("a job of B");
    let job_b = factory_domain::ids::JobId::parse(&first_job_of_b).expect("id");
    assert_eq!(tx_a.get_job(job_b).await, Err(StoreError::NotFound));
    assert!(tx_b.get_job(job_b).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reused_connection_carries_no_tenant_into_the_next_transaction() {
    let scene = Scene::new().await;
    let worker = scene.db.server.logins().await.worker.clone();
    scene.job(scene.a).await;
    let mut connection = scene.db.connect_as(&worker).await;

    // The first transaction makes the setting for A and commits.
    connection.batch_execute("BEGIN").await.expect("begin");
    connection
        .batch_execute(&format!(
            "SELECT set_config('factory.tenant_id', '{}', true)",
            scene.a.as_uuid()
        ))
        .await
        .expect("set");
    let row = sql_query("SELECT count(*)::text AS v FROM jobs")
        .get_result::<support::server::Scalar>(&mut connection)
        .await
        .expect("count");
    assert_eq!(row.v, "1");
    connection.batch_execute("COMMIT").await.expect("commit");

    // The next transaction, on the same connection, reads the setting as an empty string and sees
    // nothing. It is not NULL, which is why the policy has NULLIF (docs/database/tenancy.md).
    connection.batch_execute("BEGIN").await.expect("begin");
    let setting =
        sql_query("SELECT coalesce(current_setting('factory.tenant_id', true), '<null>') AS v")
            .get_result::<support::server::Scalar>(&mut connection)
            .await
            .expect("setting");
    assert_eq!(
        setting.v, "",
        "after a transaction that made it, the setting reads as an empty string"
    );
    let row = sql_query("SELECT count(*)::text AS v FROM jobs")
        .get_result::<support::server::Scalar>(&mut connection)
        .await
        .expect("count, no error");
    assert_eq!(row.v, "0");
    connection
        .batch_execute("ROLLBACK")
        .await
        .expect("rollback");

    // And through the store, on a pool of one connection: A, then B, then A again.
    let db = &scene.db;
    let mut config = config_for(db).await;
    config.tenant = {
        let mut one = small_pool(config.tenant.url.clone());
        one.max_connections = 1;
        one
    };
    let store = PgStore::connect(config).await.expect("ready");
    let job_a = scene.job(scene.a).await;
    let job_b = scene.job(scene.b).await;
    for (tenant, own, other) in [
        (scene.a, job_a, job_b),
        (scene.b, job_b, job_a),
        (scene.a, job_a, job_b),
    ] {
        let mut tx = factory_ports::store::Store::begin(
            &store,
            factory_domain::scope::TenantScope::new(tenant),
        )
        .await
        .expect("begin");
        assert!(tx.get_job(own).await.is_ok());
        assert_eq!(tx.get_job(other).await, Err(StoreError::NotFound));
        tx.rollback().await.expect("rollback");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pool_resets_a_session_level_tenant_when_a_connection_is_reused() {
    // A session-level SET survives a transaction on a pooled connection and shows its tenant to the
    // next borrower. The store never makes one. The pool still resets the setting before it hands
    // a connection out again (docs/database/for-the-storage-crate.md, step 6).
    let scene = Scene::new().await;
    let config = config_for(&scene.db).await;
    let mut one = config.tenant.clone();
    one.max_connections = 1;
    let pool = PgPool::new("tenant", &one).expect("pool");
    {
        let mut poisoned = pool.raw_connection_for_tests().await.expect("connection");
        poisoned
            .batch_execute(&format!("SET factory.tenant_id = '{}'", scene.a.as_uuid()))
            .await
            .expect("session-level set");
        let seen = sql_query("SELECT current_setting('factory.tenant_id', true) AS v")
            .get_result::<support::server::Scalar>(&mut *poisoned)
            .await
            .expect("read");
        assert_eq!(
            seen.v,
            scene.a.as_uuid().to_string(),
            "the poison is in place"
        );
    }
    let mut next = pool
        .raw_connection_for_tests()
        .await
        .expect("the same connection again");
    let seen =
        sql_query("SELECT coalesce(current_setting('factory.tenant_id', true), '<null>') AS v")
            .get_result::<support::server::Scalar>(&mut *next)
            .await
            .expect("read");
    assert!(
        seen.v.is_empty() || seen.v == "<null>",
        "the next borrower gets a connection with no tenant: {:?}",
        seen.v
    );
    let jobs = sql_query("SELECT count(*)::text AS v FROM jobs")
        .get_result::<support::server::Scalar>(&mut *next)
        .await
        .expect("count");
    assert_eq!(jobs.v, "0", "and sees nothing");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refuses_a_role_that_bypasses_rls() {
    let scene = Scene::new().await;
    let server = server();
    let db = &scene.db;
    let ready = |login_url: factory_storage::pg::DatabaseUrl| async move {
        let config = factory_storage::pg::PgStoreConfig::new(PoolSettings::new(login_url));
        PgStore::connect(config).await.map(|_| ())
    };
    let refused = |problem: RoleProblem| {
        Err::<(), StartupError>(StartupError::RoleNotAllowed {
            pool: "tenant",
            problem,
        })
    };

    // A superuser bypasses every policy.
    assert_eq!(
        ready(server.admin_url(&db.name)).await,
        refused(RoleProblem::Superuser)
    );

    // A login with the BYPASSRLS attribute.
    let bypass = server.create_login("bypass", &["factory_app"]).await;
    db.run(&format!("ALTER ROLE \"{}\" BYPASSRLS", bypass.name))
        .await;
    assert_eq!(
        ready(server.url(&bypass, &db.name)).await,
        refused(RoleProblem::BypassesRowLevelSecurity)
    );

    // A login that owns the tables.
    let owner = server.create_login("owner", &["factory_app"]).await;
    db.run(&format!("ALTER TABLE jobs OWNER TO \"{}\"", owner.name))
        .await;
    assert_eq!(
        ready(server.url(&owner, &db.name)).await,
        refused(RoleProblem::OwnsRelations)
    );

    // A login in both the tenant and the system group would see every tenant's rows.
    let both = server
        .create_login("both", &["factory_app", "factory_system"])
        .await;
    assert_eq!(
        ready(server.url(&both, &db.name)).await,
        refused(RoleProblem::ForbiddenGroup)
    );

    // A login in no group.
    let nobody = server.create_login("nobody", &[]).await;
    assert_eq!(
        ready(server.url(&nobody, &db.name)).await,
        refused(RoleProblem::MissingGroup)
    );

    // The system pool must hold the system login, and the tenant pool must not.
    let logins = server.logins().await;
    let mut wrong_system = config_for(db).await;
    wrong_system.system = Some(small_pool(db.url(&logins.worker)));
    assert_eq!(
        PgStore::connect(wrong_system).await.map(|_| ()),
        Err(StartupError::RoleNotAllowed {
            pool: "system",
            problem: RoleProblem::ForbiddenGroup
        })
    );
    let mut wrong_tenant = config_for(db).await;
    wrong_tenant.tenant = small_pool(db.url(&logins.engine));
    assert_eq!(
        PgStore::connect(wrong_tenant).await.map(|_| ()),
        Err(StartupError::RoleNotAllowed {
            pool: "tenant",
            problem: RoleProblem::MissingGroup
        })
    );

    // A worker login is not an API login.
    let mut api_expected = support::worker_config_for(db).await;
    api_expected.tenant_login = factory_storage::pg::TenantLogin::Api;
    assert_eq!(
        PgStore::connect(api_expected).await.map(|_| ()),
        Err(StartupError::RoleNotAllowed {
            pool: "tenant",
            problem: RoleProblem::ForbiddenGroup
        })
    );

    // The old shape of the API login, a member of the worker's group and the resolver's, held every
    // privilege of the worker (finding API-3). It is refused as the API's login, and so is the new
    // shape with the worker's group added back.
    let old_api = server
        .create_login("old_api", &["factory_app", "factory_resolver"])
        .await;
    let as_api = |login: &support::Login| {
        let mut config =
            factory_storage::pg::PgStoreConfig::new(small_pool(server.url(login, &db.name)));
        config.tenant_login = factory_storage::pg::TenantLogin::Api;
        config
    };
    assert_eq!(
        PgStore::connect(as_api(&old_api)).await.map(|_| ()),
        Err(StartupError::RoleNotAllowed {
            pool: "tenant",
            problem: RoleProblem::ForbiddenGroup
        })
    );
    let api_and_worker = server
        .create_login(
            "api_and_worker",
            &["factory_api_app", "factory_app", "factory_resolver"],
        )
        .await;
    assert_eq!(
        PgStore::connect(as_api(&api_and_worker)).await.map(|_| ()),
        Err(StartupError::RoleNotAllowed {
            pool: "tenant",
            problem: RoleProblem::ForbiddenGroup
        })
    );

    // The logins of the design are accepted.
    PgStore::connect(config_for(db).await)
        .await
        .expect("the deployment's logins are ready");
    PgStore::connect(support::api_config_for(db).await)
        .await
        .expect("the API login is ready");

    // A database that is behind the code is refused.
    db.run("DELETE FROM __diesel_schema_migrations WHERE version = (SELECT max(version) FROM __diesel_schema_migrations)").await;
    assert_eq!(
        PgStore::connect(config_for(db).await).await.map(|_| ()),
        Err(StartupError::SchemaBehind { missing: 1 })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_schema_version_is_the_number_of_applied_migrations() {
    let scene = Scene::new().await;
    let version = factory_ports::store::Store::schema_version(&scene.store)
        .await
        .expect("version");
    assert_eq!(
        usize::try_from(version.get()).expect("small"),
        support::server::Server::migration_versions().len()
    );
    assert_eq!(
        factory_ports::store::Store::fidelity(&scene.store),
        factory_domain::vocabulary::Fidelity::Real
    );
}

/// Every method of the transaction, called by tenant B on the rows of tenant A. Each answers as
/// for a row that does not exist, and A's rows are as they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_method_refuses_another_tenants_rows() {
    let scene = Scene::new().await;
    let job = scene.active_job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    let started = scene.start(scene.a, run, "worker-1").await.expect("start");
    let attempt = started.attempt.value.id;
    let hash = Sha256Digest::of(b"a blob of A");
    let principal_a = scene.principal(scene.a).await;
    let before = scene
        .db
        .text(&format!(
            "SELECT version || '|' || status FROM jobs WHERE id = '{}'",
            job.as_uuid()
        ))
        .await;

    // A fresh transaction of B for every call: a failure of the database aborts a transaction.
    macro_rules! as_b {
        ($tx:ident => $call:expr, $expected:expr, $what:expr) => {{
            let mut $tx = scene.tx(scene.b).await;
            assert_eq!($call.await.map(|_| ()), $expected, $what);
        }};
    }
    let refused = Err(StoreError::NotFound);
    let mut tx = scene.tx(scene.b).await;
    assert_eq!(tx.get_job(job).await.map(|_| ()), refused.clone());
    drop(tx);
    as_b!(tx => tx.list_stage_runs(job), refused.clone(), "list_stage_runs");
    as_b!(tx => tx.get_stage_run(run), refused.clone(), "get_stage_run");
    as_b!(tx => tx.postpone_stage_run(run, Version::FIRST, Duration::from_secs(1)), refused.clone(), "postpone");
    as_b!(tx => tx.get_attempt(attempt), refused.clone(), "get_attempt");
    as_b!(tx => tx.list_attempts(run), refused.clone(), "list_attempts");
    as_b!(
        tx => tx.heartbeat(
            Fence {
                attempt,
                epoch: started.attempt.value.epoch,
                worker: WorkerId::new("worker-1").expect("name"),
            },
            Duration::from_secs(60),
        ),
        Err(StoreError::LeaseFenced),
        "heartbeat"
    );
    as_b!(
        tx => tx.record_sandbox(
            attempt,
            SandboxRecord { sandbox: SandboxId::new("sandbox-1".to_owned()), leaked: true },
        ),
        refused.clone(),
        "record_sandbox"
    );
    as_b!(tx => tx.list_task_nodes(run), refused.clone(), "list_task_nodes");
    as_b!(tx => tx.task_dependencies(run), refused.clone(), "task_dependencies");
    as_b!(tx => tx.list_stage_run_artifacts(run), refused.clone(), "list_stage_run_artifacts");
    as_b!(tx => tx.list_approvals(job), refused.clone(), "list_approvals");
    as_b!(
        tx => tx.valid_approvals(job, &GitSha::parse(&"a".repeat(40)).expect("sha")),
        refused.clone(),
        "valid_approvals"
    );
    as_b!(tx => tx.invalidate_approvals(job, ApprovalInvalidation::NewCommit), refused.clone(), "invalidate_approvals");
    as_b!(tx => tx.ledger_head(job), refused.clone(), "ledger_head");
    as_b!(tx => tx.read_ledger(job, 1, 10), refused.clone(), "read_ledger");
    as_b!(tx => tx.read_events(job, OutboxSeq::START, 10), refused.clone(), "read_events");
    as_b!(tx => tx.read_audit(AuditFilter::Job(job), 0, 10), refused.clone(), "read_audit");
    as_b!(tx => tx.get_original_request(job, None), refused.clone(), "get_original_request");
    as_b!(tx => tx.get_repository(scene.repository(scene.a)), refused.clone(), "get_repository");
    as_b!(
        tx => tx.record_protection_preflight(scene.repository(scene.a), Version::FIRST, true),
        refused.clone(),
        "record_protection_preflight"
    );
    as_b!(tx => tx.get_principal(principal_a), refused.clone(), "get_principal");
    as_b!(tx => tx.get_artifact_index(&hash), refused.clone(), "get_artifact_index");
    // Lookups by a number a tenant may not learn.
    let mut tx = scene.tx(scene.b).await;
    assert_eq!(tx.stage_runs_consuming(job, &hash).await, Ok(Vec::new()));
    assert_eq!(tx.find_principal_by_github_user(1).await, Ok(None));
    drop(tx);
    // Writes that name A's job, with B's own tenant on the value, find no such job.
    let event = domain_event(&scene.ids, scene.b, job, 1, &at());
    as_b!(tx => tx.enqueue_event(event), refused.clone(), "enqueue_event");
    // And a value that names A as its tenant, sent through B's transaction, is a mismatch.
    let event = domain_event(&scene.ids, scene.a, job, 1, &at());
    as_b!(
        tx => tx.enqueue_event(event),
        Err(StoreError::TenantMismatch),
        "an event naming another tenant"
    );
    let entry = ledger_entry(&scene.ids, job, run, 1, None, &at(), "Not B's.");
    as_b!(tx => tx.append_ledger_entry(entry), refused.clone(), "append_ledger_entry");
    let request = factory_ports::store::NewOriginalRequest {
        id: scene.ids.uuid7(),
        job,
        revision: 1,
        source: factory_ports::store::RequestSource::Api,
        source_ref: None,
        author_github_user_id: None,
        text: "Not B's.".to_owned(),
    };
    as_b!(tx => tx.record_original_request(request), refused.clone(), "record_original_request");

    // A's rows are as they were.
    let after = scene
        .db
        .text(&format!(
            "SELECT version || '|' || status FROM jobs WHERE id = '{}'",
            job.as_uuid()
        ))
        .await;
    assert_eq!(before, after, "the job of A did not change");
    assert_eq!(scene.attempts_of(run).await.len(), 1);
    assert_eq!(
        scene
            .db
            .number(&format!(
                "SELECT count(*) FROM ledger_entries WHERE tenant_id = '{}'",
                scene.b.as_uuid()
            ))
            .await,
        0
    );
}

/// The system login finds work and writes nothing: a tenant write on the system pool is refused
/// by the database before any policy is asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_system_login_cannot_write_a_tenant_row() {
    let scene = Scene::new().await;
    let job = scene.active_job(scene.a).await;
    let run = scene.ready_stage_run(scene.a, job).await;
    scene.start(scene.a, run, "worker-1").await.expect("start");
    let engine = scene.db.server.logins().await.engine.clone();
    for (what, sql) in [
        (
            "UPDATE of a stage run",
            format!(
                "UPDATE stage_runs SET version = version + 1 WHERE id = '{}'",
                run.as_uuid()
            ),
        ),
        (
            "UPDATE of an attempt",
            "UPDATE attempts SET status = 'FAILED'".to_owned(),
        ),
        (
            "INSERT of a job",
            format!(
                "INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, \
                        autonomy_level, pipeline_scope, correlation_id) \
                 SELECT tenant_id, '{}', repository_id, requester_principal_id, execution_mode, \
                        autonomy_level, pipeline_scope, '{}' FROM jobs LIMIT 1",
                uuid::Uuid::from_u128(11),
                uuid::Uuid::from_u128(12)
            ),
        ),
        ("DELETE of a job", "DELETE FROM jobs".to_owned()),
    ] {
        let outcome = as_login(
            &scene.db,
            &engine,
            None,
            &format!("WITH w AS ({sql} RETURNING 1) SELECT count(*)::text AS v FROM w"),
        )
        .await;
        assert!(
            outcome
                .as_ref()
                .is_err_and(|text| text.contains("permission denied")),
            "{what} must be refused to the system login: {outcome:?}"
        );
    }
    // What it may do: find, by the named columns of the grant.
    let found = as_login(
        &scene.db,
        &engine,
        None,
        "SELECT count(*)::text AS v FROM (SELECT tenant_id, id, version, not_before FROM stage_runs) s",
    )
    .await;
    assert_eq!(found, Ok(Some("1".to_owned())));
    // But not every column: the system role reads named columns only.
    let all = as_login(
        &scene.db,
        &engine,
        None,
        "SELECT count(*)::text AS v FROM (SELECT * FROM stage_runs) s",
    )
    .await;
    assert!(all.is_err_and(|text| text.contains("permission denied")));
}
