//! What a holder of the API's database login can still do after the grant narrowing (migration
//! `2026-10-28-002000_api_login_narrow_group`), tried on a real database as that login.

use diesel::sql_query;
use diesel_async::{RunQueryDsl, SimpleAsyncConnection};
use factory_ports::clock::IdGenerator;

use crate::support::Env;

fn new_uuid() -> uuid::Uuid {
    factory_composition::system::RandomIds::new()
        .expect("the random source opens")
        .new_uuid()
}

#[derive(diesel::QueryableByName)]
struct Flag {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    yes: bool,
}

#[derive(diesel::QueryableByName)]
struct Name {
    #[diesel(sql_type = diesel::sql_types::Text)]
    name: String,
}

/// The hook ends a request when it reads a `decision.applied` or `decision.rejected` record that names
/// it, whoever wrote the record (RR-8 in `crates/composition/tests/security_rereview/hook.rs`). The
/// ground of that is here: the API's login may insert an audit row that says it was written by the
/// worker, with the words the worker writes. The database cannot tell the two writers apart, because
/// both go through the one table and the one trigger.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "confirmed defect RR-8 (needs PostgreSQL): the API login can write a record in the name of the worker; cargo test -p factory-api --test security_rereview --locked -- --ignored rr_8 --exact"]
async fn rr_8_the_api_login_cannot_write_a_record_in_the_name_of_the_worker() {
    let env = Env::start().await;
    let logins = env.db.server.logins().await;
    let mut api = env.db.connect_as(&logins.api).await;
    let sql = format!(
        "BEGIN; SELECT set_config('factory.tenant_id', '{tenant}', true); \
         INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, reason, policy_hash, correlation_id) \
         VALUES ('{tenant}', '{id}', 'system', 'worker.decisions', 'decision.rejected', \
                 'decision={request} code=not_authorized actor=none allowlist=none', 'deny', 'not applied', \
                 'sha256:{zeros}', '{correlation}'); \
         COMMIT;",
        tenant = env.a.id.as_uuid(),
        id = new_uuid(),
        request = new_uuid().hyphenated(),
        zeros = "0".repeat(64),
        correlation = new_uuid(),
    );
    let written = api.batch_execute(&sql).await;
    env.stop().await;
    assert!(
        written.is_err(),
        "the API login wrote a worker-looking marker into tenant A's audit log"
    );
}

/// The audit log refuses a change and a removal from the API login, and no table lets the login
/// update, delete or truncate. The login inserts into the four tables the API writes and no other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs PostgreSQL (docs/database/running.md)"]
async fn held_the_api_login_only_inserts_into_four_tables_and_changes_nothing() {
    let env = Env::start().await;
    let logins = env.db.server.logins().await;
    let mut api = env.db.connect_as(&logins.api).await;

    let tables: Vec<Name> = sql_query(
        "SELECT c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') ORDER BY 1",
    )
    .get_results(&mut api)
    .await
    .expect("the tables");
    assert!(tables.len() > 10, "the schema has its tables");
    let mut inserts = Vec::new();
    let mut changes = Vec::new();
    for table in &tables {
        for privilege in ["UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"] {
            let flag: Flag = sql_query(format!(
                "SELECT has_table_privilege(current_user, '{}', '{privilege}') AS yes",
                table.name
            ))
            .get_result(&mut api)
            .await
            .expect("privilege");
            if flag.yes {
                changes.push(format!("{}:{privilege}", table.name));
            }
        }
        let flag: Flag = sql_query(format!(
            "SELECT has_table_privilege(current_user, '{}', 'INSERT') AS yes",
            table.name
        ))
        .get_result(&mut api)
        .await
        .expect("privilege");
        if flag.yes {
            inserts.push(table.name.clone());
        }
        // A column grant would let the login write a table it holds no table-wide privilege on.
        let column: Flag = sql_query(format!(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns c \
              WHERE c.table_schema = 'public' AND c.table_name = '{0}' \
                AND (has_column_privilege(current_user, '{0}', c.column_name, 'INSERT') \
                  OR has_column_privilege(current_user, '{0}', c.column_name, 'UPDATE'))) AS yes",
            table.name
        ))
        .get_result(&mut api)
        .await
        .expect("column privilege");
        if column.yes && !flag.yes {
            changes.push(format!("{}:column", table.name));
        }
    }
    inserts.sort();
    assert_eq!(
        inserts,
        [
            "audit_events",
            "jobs",
            "original_requests",
            "webhook_deliveries"
        ],
        "the tables the API login may insert into"
    );
    assert!(changes.is_empty(), "the login may also change: {changes:?}");

    // The audit log answers an attempt to change or remove a row with an error.
    for statement in [
        "UPDATE audit_events SET reason = 'changed'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ] {
        let sql = format!(
            "BEGIN; SELECT set_config('factory.tenant_id', '{}', true); {statement}; COMMIT;",
            env.a.id.as_uuid()
        );
        assert!(
            api.batch_execute(&sql).await.is_err(),
            "{statement} was accepted"
        );
        let _ = api.batch_execute("ROLLBACK").await;
    }
    env.stop().await;
}

/// The signing key is a file of the API process and the worker process. The login has no way to read
/// a file of the database server's host, to run a program there, or to list a directory: it is not a
/// superuser and holds none of the file roles.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs PostgreSQL (docs/database/running.md)"]
async fn held_the_api_login_cannot_read_a_file_or_run_a_program() {
    let env = Env::start().await;
    let logins = env.db.server.logins().await;
    let mut api = env.db.connect_as(&logins.api).await;
    for statement in [
        "SELECT pg_read_file('/etc/hosts')",
        "SELECT pg_read_binary_file('/etc/hosts')",
        "SELECT pg_ls_dir('/')",
        "COPY (SELECT 1) TO PROGRAM 'id'",
        "COPY (SELECT 1) TO '/tmp/rereview-probe'",
        "CREATE TABLE rereview_probe (a int)",
        "CREATE ROLE rereview_probe",
        "SET ROLE factory_app",
        "SELECT set_config('session_replication_role', 'replica', false)",
    ] {
        assert!(
            api.batch_execute(statement).await.is_err(),
            "the API login ran: {statement}"
        );
        let _ = api.batch_execute("ROLLBACK").await;
    }
    let superuser: Flag = sql_query(
        "SELECT (SELECT rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb FROM pg_roles \
                  WHERE rolname = current_user) AS yes",
    )
    .get_result(&mut api)
    .await
    .expect("the role");
    assert!(!superuser.yes, "the API login holds a powerful attribute");
    env.stop().await;
}
