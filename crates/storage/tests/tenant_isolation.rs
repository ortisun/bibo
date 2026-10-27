//! Tenant isolation through the adapter, as the application login (NT-TEN-01, the Rust part), and
//! the start-up checks that keep a login with too many rights out.
//!
//! Every test here connects as an application login, never as the table owner or a superuser: those
//! bypass the policies silently, and a test that did not connect as the login would prove nothing.
//! The superuser is used only to put fixtures in place and to look.

mod support;

use std::time::Duration;

use diesel::sql_query;
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use factory_domain::contracts::ArtifactRef;
use factory_domain::state::{
    AttemptEvent, AttemptStatus, JobEvent, JobStatus, Status, TaskNodeEvent, TaskNodeStatus,
};
use factory_domain::values::{MediaType, NonEmptyString, Sha256Digest, Slug};
use factory_domain::vocabulary::StageKind;
use factory_ports::store::{
    AppliedTransition, AuditActor, AuditEvent, LeaseEpoch, NewArtifactIndexEntry, NewAttempt,
    NewJob, NewPrincipal, NewStageRun, NewTaskNode, OutboxSeq, StoreError, Version,
};
use factory_storage::pg::{PgPool, PgStore, PoolSettings, RoleProblem, StartupError};
use factory_testkit::fixtures::{domain_event, ledger_entry};
use support::{Scene, as_login, config_for, now, server, small_pool};
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
    let mut tx_a = scene.tenant_tx(scene.a).await;
    let mut tx_b = scene.tenant_tx(scene.b).await;
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
    config.claim_only_active_jobs = false;
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
    let mut api_expected = config_for(db).await;
    api_expected.tenant_login = factory_storage::pg::TenantLogin::Api;
    assert_eq!(
        PgStore::connect(api_expected).await.map(|_| ()),
        Err(StartupError::RoleNotAllowed {
            pool: "tenant",
            problem: RoleProblem::MissingGroup
        })
    );

    // The logins of the design are accepted.
    PgStore::connect(config_for(db).await)
        .await
        .expect("the deployment's logins are ready");

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

/// Every method of the transaction, called by tenant A on the rows of tenant B. Each answers as for
/// a row that does not exist, and B's rows are as they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_repository_method_refuses_another_tenants_rows() {
    let scene = Scene::new().await;
    let (a, b) = (scene.a, scene.b);

    // Tenant B has one of everything.
    let job_b = scene.job(b).await;
    let principal_b = scene.principal(b).await;
    let run_b = scene.ready_stage_run(b, job_b).await;
    scene.claim("worker-1", 5).await;
    let (attempt_b, ..) = scene.newest_attempt(run_b).await;
    let artifact = ArtifactRef {
        sha256: Sha256Digest::of(b"tenant b only"),
        media_type: MediaType::parse("text/plain").expect("media type"),
        size_bytes: None,
    };
    {
        let mut tx = scene.tenant_tx(b).await;
        tx.index_artifact(NewArtifactIndexEntry {
            artifact: artifact.clone(),
            stage_run_id: Some(run_b),
            created_at: now(),
        })
        .await
        .expect("index");
        let entry = ledger_entry(
            &scene.ids,
            job_b,
            run_b,
            1,
            None,
            &now(),
            "Tenant B's claim.",
        );
        tx.append_ledger_entry(entry).await.expect("append");
        let version = tx.get_job(job_b).await.expect("job").version;
        let admit =
            AppliedTransition::plan(JobStatus::Received, JobEvent::Admit, now()).expect("J01");
        let next = tx
            .transition_job(job_b, version, admit)
            .await
            .expect("admit");
        tx.enqueue_event(domain_event(&scene.ids, b, job_b, next.get(), &now()))
            .await
            .expect("event");
        tx.record_audit(AuditEvent {
            job_id: job_b,
            actor: AuditActor::Component(Slug::parse("workflow.engine").expect("slug")),
            action: Slug::parse("job.admitted").expect("slug"),
            policy_hash: Sha256Digest::of(b"policy"),
            correlation_id: scene.ids.correlation(),
            occurred_at: now(),
        })
        .await
        .expect("audit");
        tx.commit().await.expect("commit");
    }
    let node_b = scene.ids.task_node();
    scene
        .db
        .run(&format!(
            "INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend) \
               VALUES ('{b}', 'sha256:{}', 0, 'application/json', 'local-fs'); \
             INSERT INTO task_nodes (tenant_id, id, job_id, stage_run_id, task_key, plan_sha256) \
               VALUES ('{b}', '{node_b}', '{job_b}', '{run_b}', 't-001', 'sha256:{}');",
            "c".repeat(64),
            "c".repeat(64),
            b = b.as_uuid(),
            node_b = node_b.as_uuid(),
            job_b = job_b.as_uuid(),
            run_b = run_b.as_uuid(),
        ))
        .await;
    let state_of_b = || async {
        scene
            .db
            .text(&format!(
                "SELECT (SELECT string_agg(status || version, ',') FROM jobs WHERE tenant_id = '{b}') || '|' || \
                        (SELECT string_agg(status || version, ',') FROM stage_runs WHERE tenant_id = '{b}') || '|' || \
                        (SELECT string_agg(status || version, ',') FROM attempts WHERE tenant_id = '{b}') || '|' || \
                        (SELECT string_agg(status || version, ',') FROM task_nodes WHERE tenant_id = '{b}') || '|' || \
                        (SELECT count(*) FROM ledger_entries WHERE tenant_id = '{b}') || '|' || \
                        (SELECT count(*) FROM outbox WHERE tenant_id = '{b}') || '|' || \
                        (SELECT count(*) FROM audit_events WHERE tenant_id = '{b}') || '|' || \
                        (SELECT count(*) FROM artifacts WHERE tenant_id = '{b}')",
                b = b.as_uuid()
            ))
            .await
            .expect("state")
    };
    let before = state_of_b().await;

    // Tenant A calls every method with B's identifiers.
    let mut tx = scene.tenant_tx(a).await;
    let version = Version::FIRST;
    let stale_epoch = LeaseEpoch::new(1);
    assert_eq!(
        tx.get_job(job_b).await,
        Err(StoreError::NotFound),
        "get_job"
    );
    let admit = AppliedTransition::plan(JobStatus::Received, JobEvent::Admit, now()).expect("J01");
    assert_eq!(
        tx.transition_job(job_b, version, admit).await,
        Err(StoreError::NotFound),
        "transition_job"
    );
    assert_eq!(
        tx.insert_stage_run(NewStageRun {
            id: scene.ids.stage_run(),
            job_id: job_b,
            kind: StageKind::Intake,
            created_at: now()
        })
        .await,
        Err(StoreError::NotFound),
        "insert_stage_run under B's job"
    );
    assert_eq!(
        tx.get_stage_run(run_b).await,
        Err(StoreError::NotFound),
        "get_stage_run"
    );
    let ready = AppliedTransition::plan(
        factory_domain::state::StageRunStatus::Pending,
        factory_domain::state::StageRunEvent::PreconditionsMet,
        now(),
    )
    .expect("S01");
    assert_eq!(
        tx.transition_stage_run(run_b, version, ready).await,
        Err(StoreError::NotFound),
        "transition_stage_run"
    );
    assert_eq!(
        tx.claim_ready(
            &factory_ports::store::WorkerId::new("w").expect("w"),
            1,
            Duration::from_secs(1)
        )
        .await
        .map(|_| ()),
        Err(StoreError::ScopeNotAllowed)
    );
    assert_eq!(
        tx.expired_leases(1).await.map(|_| ()),
        Err(StoreError::ScopeNotAllowed)
    );
    assert_eq!(
        tx.insert_attempt(NewAttempt {
            id: scene.ids.attempt(),
            stage_run_id: run_b,
            epoch: stale_epoch,
            created_at: now()
        })
        .await
        .map(|_| ()),
        Err(StoreError::NotFound),
        "insert_attempt"
    );
    assert_eq!(
        tx.get_attempt(attempt_b).await.map(|_| ()),
        Err(StoreError::NotFound),
        "get_attempt"
    );
    assert_eq!(
        tx.heartbeat(attempt_b, stale_epoch).await,
        Err(StoreError::NotFound),
        "heartbeat"
    );
    let started =
        AppliedTransition::plan(AttemptStatus::INITIAL, AttemptEvent::SandboxReady, now())
            .expect("A01");
    assert_eq!(
        tx.transition_attempt(attempt_b, version, stale_epoch, started)
            .await,
        Err(StoreError::NotFound),
        "transition_attempt"
    );
    assert_eq!(
        tx.get_task_node(node_b).await.map(|_| ()),
        Err(StoreError::NotFound),
        "get_task_node"
    );
    let ready_node = AppliedTransition::plan(
        TaskNodeStatus::Pending,
        TaskNodeEvent::DependenciesSatisfied,
        now(),
    )
    .expect("T01");
    assert_eq!(
        tx.transition_task_node(node_b, version, ready_node).await,
        Err(StoreError::NotFound),
        "transition_task_node"
    );
    assert_eq!(
        tx.insert_task_node(NewTaskNode {
            id: scene.ids.task_node(),
            job_id: job_b,
            key: Slug::parse("t-002").expect("slug"),
            created_at: now()
        })
        .await
        .map(|_| ()),
        Err(StoreError::NotFound),
        "insert_task_node under B's job"
    );
    let entry = ledger_entry(
        &scene.ids,
        job_b,
        run_b,
        1,
        None,
        &now(),
        "A tries B's chain.",
    );
    assert_eq!(
        tx.append_ledger_entry(entry).await.map(|_| ()),
        Err(StoreError::NotFound),
        "append_ledger_entry"
    );
    assert_eq!(
        tx.ledger_head(job_b).await,
        Err(StoreError::NotFound),
        "ledger_head"
    );
    assert_eq!(
        tx.read_ledger(job_b, 1, 10).await.map(|_| ()),
        Err(StoreError::NotFound),
        "read_ledger"
    );
    assert_eq!(
        tx.enqueue_event(domain_event(&scene.ids, b, job_b, 2, &now()))
            .await,
        Err(StoreError::TenantMismatch),
        "an event naming B"
    );
    assert_eq!(
        tx.enqueue_event(domain_event(&scene.ids, a, job_b, 2, &now()))
            .await,
        Err(StoreError::NotFound),
        "an event of A for B's job"
    );
    assert_eq!(
        tx.read_events(job_b, OutboxSeq::START, 10)
            .await
            .map(|_| ()),
        Err(StoreError::NotFound),
        "read_events"
    );
    let audit = AuditEvent {
        job_id: job_b,
        actor: AuditActor::Component(Slug::parse("workflow.engine").expect("slug")),
        action: Slug::parse("job.admitted").expect("slug"),
        policy_hash: Sha256Digest::of(b"policy"),
        correlation_id: scene.ids.correlation(),
        occurred_at: now(),
    };
    assert_eq!(
        tx.record_audit(audit).await,
        Err(StoreError::NotFound),
        "record_audit"
    );
    assert_eq!(
        tx.read_audit(job_b, 10).await.map(|_| ()),
        Err(StoreError::NotFound),
        "read_audit"
    );
    assert_eq!(
        tx.get_artifact_index(&artifact.sha256).await.map(|_| ()),
        Err(StoreError::NotFound),
        "get_artifact_index"
    );
    assert_eq!(
        tx.get_principal(principal_b).await.map(|_| ()),
        Err(StoreError::NotFound),
        "get_principal"
    );
    // A job for A cannot name B's principal as its requester.
    assert!(matches!(
        tx.insert_job(NewJob {
            id: scene.ids.job(),
            correlation_id: scene.ids.correlation(),
            requester: principal_b,
            created_at: now()
        })
        .await
        .map(|_| ()),
        Err(StoreError::Constraint(_))
    ));
    drop(tx);

    // Tenant A may use the same external reference as B: references are unique per tenant.
    let mut tx = scene.tenant_tx(a).await;
    let reference = scene
        .db
        .text(&format!(
            "SELECT coalesce(login, github_user_id::text) FROM principals WHERE id = '{}'",
            principal_b.as_uuid()
        ))
        .await
        .expect("ref");
    tx.insert_principal(NewPrincipal {
        id: scene.ids.principal(),
        external_ref: NonEmptyString::parse(&reference).expect("ref"),
        created_at: now(),
    })
    .await
    .expect("the same reference in another tenant");
    drop(tx);

    assert_eq!(
        state_of_b().await,
        before,
        "tenant B's rows are as they were"
    );
}
