//! The group `factory_observer` (migration 2026-11-20-002900_observer_role), checked on a migrated
//! database with a login of the deployment's shape. These tests use the driver directly, not the
//! MCP server: they show what the database itself refuses.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use support::TestDb;

/// The classification file: (table, column) -> "operational" or "sensitive".
fn classification() -> BTreeMap<(String, String), String> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/database/observer-columns.txt");
    #[allow(clippy::disallowed_methods)]
    let text = std::fs::read_to_string(&path).expect("read docs/database/observer-columns.txt");
    let mut map = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        assert!(
            fields.len() == 3 && matches!(fields[2], "operational" | "sensitive"),
            "observer-columns.txt line {}: expected `<table> <column> operational|sensitive`, got {line:?}",
            number + 1
        );
        let previous = map.insert(
            (fields[0].to_owned(), fields[1].to_owned()),
            fields[2].to_owned(),
        );
        assert!(
            previous.is_none(),
            "observer-columns.txt lists {}.{} twice",
            fields[0],
            fields[1]
        );
    }
    map
}

#[tokio::test(flavor = "multi_thread")]
async fn observer_columns_match_the_classification() {
    let db = TestDb::fresh().await;
    let admin = db.admin().await;
    // Every column of every table in public the group can read at least one column of.
    let rows = admin
        .query(
            "SELECT c.relname::text, a.attname::text, \
                    has_column_privilege('factory_observer', c.oid, a.attnum, 'SELECT') AS readable \
               FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid \
              WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p', 'v', 'm') \
                AND a.attnum > 0 AND NOT a.attisdropped \
                AND has_any_column_privilege('factory_observer', c.oid, 'SELECT') \
              ORDER BY 1, a.attnum",
            &[],
        )
        .await
        .expect("list the columns");
    let classes = classification();
    let mut problems = Vec::new();
    let mut seen = BTreeSet::new();
    for row in rows {
        let table: String = row.get(0);
        let column: String = row.get(1);
        let readable: bool = row.get(2);
        let key = (table.clone(), column.clone());
        seen.insert(key.clone());
        match (classes.get(&key).map(String::as_str), readable) {
            (None, true) => problems.push(format!(
                "{table}.{column} is readable by factory_observer but not classified in observer-columns.txt"
            )),
            (None, false) => problems.push(format!(
                "{table}.{column} is a new column of a table factory_observer reads; classify it in observer-columns.txt"
            )),
            (Some("sensitive"), true) => problems.push(format!(
                "{table}.{column} is classified sensitive but factory_observer can read it"
            )),
            (Some("operational"), false) => problems.push(format!(
                "{table}.{column} is classified operational but factory_observer cannot read it"
            )),
            _ => {}
        }
    }
    for (table, column) in classes.keys() {
        if !seen.contains(&(table.clone(), column.clone())) {
            problems.push(format!(
                "observer-columns.txt lists {table}.{column}, which is not a column of a table factory_observer reads"
            ));
        }
    }
    // No table-wide grant: a table grant would cover every future column.
    let whole: i64 = admin
        .query_one(
            "SELECT count(*) FROM information_schema.role_table_grants \
              WHERE grantee = 'factory_observer' AND table_schema = 'public' AND table_name NOT LIKE 'state_machine_%'",
            &[],
        )
        .await
        .expect("count table grants")
        .get(0);
    if whole != 0 {
        problems.push(format!(
            "factory_observer has {whole} table-level grants outside the reference tables"
        ));
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_group_has_no_power_beyond_reading() {
    let db = TestDb::fresh().await;
    let admin = db.admin().await;
    let row = admin
        .query_one(
            "SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication \
               FROM pg_roles WHERE rolname = 'factory_observer'",
            &[],
        )
        .await
        .expect("the group exists");
    for index in 0..6 {
        assert!(
            !row.get::<_, bool>(index),
            "attribute {index} of factory_observer is set"
        );
    }
    // Migration 003100 took pg_read_all_stats away (TR-3) and made the group NOINHERIT, so that a
    // grant made again by migration 002900 in another database of the cluster passes nothing on.
    // The check is on privileges, not on the membership row, for that reason.
    let stats: bool = admin
        .query_one(
            "SELECT pg_has_role('factory_observer', 'pg_read_all_stats', 'USAGE') \
                 OR EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'factory_observer' AND rolinherit)",
            &[],
        )
        .await
        .expect("the group's statistics privilege")
        .get(0);
    assert!(
        !stats,
        "factory_observer must not hold the privileges of pg_read_all_stats"
    );
    let memberships: Vec<String> = admin
        .query(
            "SELECT g.rolname::text FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid \
              WHERE m.member = 'factory_observer'::regrole AND g.rolname <> 'pg_read_all_stats' ORDER BY 1",
            &[],
        )
        .await
        .expect("memberships")
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert!(memberships.is_empty(), "{memberships:?}");
    let writes: i64 = admin
        .query_one(
            "SELECT count(*) FROM information_schema.column_privileges \
              WHERE grantee = 'factory_observer' AND privilege_type <> 'SELECT'",
            &[],
        )
        .await
        .expect("count write grants")
        .get(0);
    assert_eq!(writes, 0);
    let routines: Vec<String> = admin
        .query(
            "SELECT DISTINCT routine_name::text FROM information_schema.role_routine_grants \
              WHERE grantee = 'factory_observer' ORDER BY 1",
            &[],
        )
        .await
        .expect("list routine grants")
        .iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        routines,
        [
            "observer_activity",
            "observer_lock_waits",
            "observer_normalize_query",
            "observer_statements"
        ],
        "EXECUTE is granted to factory_observer on the observer functions of migration 003100 only"
    );
    // The functions run as factory_observer_stats, a role that has no member, can not log in, and
    // is a member of pg_read_all_stats and of nothing else.
    let definer = admin
        .query_one(
            "SELECT r.rolcanlogin, r.rolsuper, r.rolbypassrls, \
                    (SELECT count(*) FROM pg_auth_members m WHERE m.roleid = r.oid), \
                    (SELECT array_agg(g.rolname::text) FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid \
                      WHERE m.member = r.oid), \
                    (SELECT bool_and(p.prosecdef AND p.proowner = r.oid \
                                     AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']) \
                       FROM pg_proc p WHERE p.proname IN ('observer_activity', 'observer_lock_waits', 'observer_statements')) \
               FROM pg_roles r WHERE r.rolname = 'factory_observer_stats'",
            &[],
        )
        .await
        .expect("the definer role");
    assert!(!definer.get::<_, bool>(0) && !definer.get::<_, bool>(1) && !definer.get::<_, bool>(2));
    assert_eq!(
        definer.get::<_, i64>(3),
        0,
        "factory_observer_stats has no member"
    );
    assert_eq!(
        definer.get::<_, Vec<String>>(4),
        ["pg_read_all_stats"],
        "factory_observer_stats is a member of pg_read_all_stats only"
    );
    assert!(
        definer.get::<_, bool>(5),
        "the three functions are SECURITY DEFINER, owned by factory_observer_stats, with a pinned search_path"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_observer_cannot_take_an_advisory_lock_and_the_writers_still_can() {
    let db = TestDb::fresh().await;
    let observer = db.observer().await;
    let client = db.connect_as(&observer).await;
    // The audit chain lock of every tenant (TR-4), and the other forms.
    for statement in [
        "SELECT pg_advisory_xact_lock(hashtextextended('factory.audit_events:' || id::text, 0)) FROM tenants",
        "SELECT pg_try_advisory_xact_lock(hashtextextended('factory.audit_events:' || id::text, 0)) FROM tenants",
        "SELECT pg_advisory_lock(4242)",
        "SELECT pg_try_advisory_lock(4242)",
        "SELECT pg_advisory_lock_shared(4242)",
        "SELECT pg_advisory_xact_lock(1, 2)",
    ] {
        let error = client
            .batch_execute(&format!("BEGIN READ ONLY; {statement}; ROLLBACK"))
            .await
            .expect_err(statement);
        let _ = client.batch_execute("ROLLBACK").await;
        assert_eq!(
            error
                .code()
                .map(|c| c.code().to_owned())
                .unwrap_or_default(),
            "42501",
            "{statement}: {error}"
        );
    }
    // The two groups that insert audit events still take the lock the audit trigger takes, and only
    // that one function is granted back.
    for group in ["factory_app", "factory_api_app"] {
        let writer = db.login(&format!("writer_{group}"), &[group], false).await;
        let writer = db.connect_as(&writer).await;
        let waited: i32 = writer
            .query_one(
                "SELECT 1 FROM (SELECT pg_advisory_xact_lock(hashtextextended('factory.audit_events:y', 0))) q",
                &[],
            )
            .await
            .unwrap_or_else(|error| panic!("{group}: {error:?}"))
            .get(0);
        assert_eq!(waited, 1, "{group} takes the audit chain lock");
        let other = writer
            .query_one("SELECT pg_try_advisory_lock(4242)", &[])
            .await
            .expect_err("only pg_advisory_xact_lock(bigint) is granted back");
        assert_eq!(
            other
                .code()
                .map(|c| c.code().to_owned())
                .unwrap_or_default(),
            "42501"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_observer_cannot_write_even_in_a_read_write_transaction() {
    let db = TestDb::fresh().await;
    let login = db.observer().await;
    let client = db.connect_as(&login).await;
    // The login's default is read-only; ask for read-write so that the privilege answers.
    for statement in [
        "INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, execution_mode, autonomy_level, pipeline_scope, correlation_id) \
         SELECT tenant_id, gen_random_uuid(), repository_id, requester_principal_id, execution_mode, autonomy_level, pipeline_scope, gen_random_uuid() FROM jobs LIMIT 1",
        "UPDATE jobs SET status = 'FAILED'",
        "DELETE FROM jobs",
        "TRUNCATE jobs",
        "UPDATE attempts SET lease_owner = 'x'",
        "INSERT INTO audit_events (tenant_id) VALUES (gen_random_uuid())",
    ] {
        let error = client
            .batch_execute(&format!("BEGIN READ WRITE; {statement}; COMMIT"))
            .await
            .expect_err(statement);
        let code = error
            .code()
            .map(|c| c.code().to_owned())
            .unwrap_or_default();
        let _ = client.batch_execute("ROLLBACK").await;
        assert_eq!(code, "42501", "{statement}: {error}");
    }
    assert_eq!(db.number("SELECT count(*) FROM jobs").await, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_observer_cannot_read_a_sensitive_column() {
    let db = TestDb::fresh().await;
    let login = db.observer().await;
    let client = db.connect_as(&login).await;
    for statement in [
        "SELECT request_text FROM original_requests",
        "SELECT token_hash FROM api_tokens",
        "SELECT payload FROM outbox",
        "SELECT canonical_json FROM ledger_entries",
        "SELECT login FROM principals",
        "SELECT full_name FROM repositories",
        "SELECT github_repository_id FROM repositories",
        "SELECT github_installation_id FROM webhook_deliveries",
        "SELECT * FROM jobs",
        "SELECT reason FROM approvals",
    ] {
        let error = client.query(statement, &[]).await.expect_err(statement);
        let code = error
            .code()
            .map(|c| c.code().to_owned())
            .unwrap_or_default();
        assert_eq!(code, "42501", "{statement}: {error}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_observer_sees_every_tenant_under_forced_row_level_security() {
    let db = TestDb::fresh().await;
    let forced: bool = db
        .admin()
        .await
        .query_one(
            "SELECT relforcerowsecurity FROM pg_class WHERE oid = 'public.jobs'::regclass",
            &[],
        )
        .await
        .expect("read the flag")
        .get(0);
    assert!(forced, "jobs has FORCE ROW LEVEL SECURITY");
    let observer = db.observer().await;
    let client = db.connect_as(&observer).await;
    for table in ["jobs", "repositories", "principals"] {
        let tenants: i64 = client
            .query_one(
                &format!("SELECT count(DISTINCT tenant_id) FROM {table}"),
                &[],
            )
            .await
            .unwrap_or_else(|error| panic!("{table}: {error}"))
            .get(0);
        assert_eq!(tenants, 2, "the observer sees both tenants in {table}");
    }
    // The control: a tenant login with no tenant setting sees nothing, so the policy is what
    // shows the observer the rows.
    let worker = db.login("app", &["factory_app"], false).await;
    let seen: i64 = db
        .connect_as(&worker)
        .await
        .query_one("SELECT count(*) FROM jobs", &[])
        .await
        .expect("count as the worker")
        .get(0);
    assert_eq!(seen, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_observer_cannot_end_another_roles_session() {
    let db = TestDb::fresh().await;
    let worker = db.login("app", &["factory_app"], false).await;
    let victim = db.connect_as(&worker).await;
    let pid: i32 = victim
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("the worker's pid")
        .get(0);
    let observer = db.observer().await;
    let client = db.connect_as(&observer).await;
    for function in ["pg_terminate_backend", "pg_cancel_backend"] {
        let result = client
            .query_one(&format!("SELECT {function}($1)"), &[&pid])
            .await;
        match result {
            Err(error) => assert_eq!(
                error
                    .code()
                    .map(|c| c.code().to_owned())
                    .unwrap_or_default(),
                "42501",
                "{function}: {error}"
            ),
            Ok(row) => assert!(!row.get::<_, bool>(0), "{function} returned true"),
        }
    }
    let alive: i32 = victim
        .query_one("SELECT 1", &[])
        .await
        .expect("the worker's session is still alive")
        .get(0);
    assert_eq!(alive, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_migration_refuses_a_group_with_too_many_powers() {
    // Run on a role of another name with the migration's own check, so that the shared group of
    // the test server is never changed.
    let db = TestDb::fresh().await;
    let admin = db.admin().await;
    let up = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../migrations/2026-11-20-002900_observer_role/up.sql"),
    )
    .expect("read the migration");
    let start = up.find("DO $$").expect("the role check");
    let end = up[start..].find("$$;").expect("its end") + start + 3;
    let probe_role = format!(
        "dbtest_powerful_{}",
        db.name.trim_start_matches("factory_t_mcp_")
    );
    let check = up[start..end].replace("factory_observer", &probe_role);
    admin
        .batch_execute(&format!("CREATE ROLE \"{probe_role}\" NOLOGIN CREATEDB"))
        .await
        .expect("make a powerful role");
    let refused = admin.batch_execute(&check).await;
    let _ = admin
        .batch_execute(&format!("DROP ROLE IF EXISTS \"{probe_role}\""))
        .await;
    let error = refused.expect_err("the check refuses the role");
    assert!(
        error.to_string().contains("too many powers")
            || format!("{error:?}").contains("too many powers"),
        "{error:?}"
    );
}
