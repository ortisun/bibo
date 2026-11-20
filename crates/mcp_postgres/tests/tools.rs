//! The MCP server against a real database: the tools, and the attempts that must fail safely.

mod support;

use std::time::{Duration, Instant};

use factory_mcp_postgres::{Limits, PostgresMcp, TOOL_NAMES, ToolFailure};
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use serde_json::Value;
use support::{PLANTED_VALUE, TestDb, quick_limits};

fn json(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|error| panic!("not JSON ({error}): {text}"))
}

fn database_code(failure: &ToolFailure) -> &str {
    match failure {
        ToolFailure::Database { code, .. } => code,
        _ => "",
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_query_reads_both_tenants_as_json_rows() {
    let db = TestDb::fresh().await;
    let login = db.observer().await;
    let inspector = db.inspector(&login, quick_limits());
    assert_eq!(inspector.check_login().await, Ok(login.name.clone()));
    let text = inspector
        .query(
            "SELECT tenant_id, status, created_at FROM jobs ORDER BY tenant_id;",
            None,
        )
        .await
        .expect("the query runs");
    let value = json(&text);
    assert_eq!(value["returned_rows"], Value::from(2));
    assert_eq!(value["rows"][0]["status"], Value::from("RECEIVED"));
    assert_ne!(value["rows"][0]["tenant_id"], value["rows"][1]["tenant_id"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn writes_and_second_statements_fail_and_change_nothing() {
    let db = TestDb::fresh().await;
    let login = db.observer().await;
    let inspector = db.inspector(&login, quick_limits());
    let attempts = [
        "INSERT INTO jobs (tenant_id) VALUES (gen_random_uuid())",
        "UPDATE jobs SET status = 'FAILED'",
        "DELETE FROM jobs",
        "SELECT 1; DROP TABLE jobs",
        "SELECT 1; DELETE FROM jobs",
        "WITH d AS (DELETE FROM jobs RETURNING id) SELECT * FROM d",
        "SELECT 1) q; DELETE FROM jobs --",
        "SELECT 1) AS q; DELETE FROM jobs; SELECT (1",
        "COPY jobs TO STDOUT",
        "COPY (SELECT 1) TO PROGRAM 'true'",
        "CREATE TABLE stolen AS SELECT 1",
        "DROP TABLE jobs",
        "SELECT id FROM jobs FOR UPDATE",
        "NOTIFY factory, 'x'",
        // pg_notify() itself is accepted in a read-only transaction; a notification is delivered
        // only at commit, and every call ends with ROLLBACK, so it never leaves the session.
        "SELECT set_config('transaction_read_only', 'off', true)",
        "SELECT lo_create(0)",
    ];
    for attempt in attempts {
        let failure = inspector.query(attempt, None).await.expect_err(attempt);
        assert!(
            matches!(failure, ToolFailure::Database { .. }),
            "{attempt}: {failure}"
        );
    }
    assert_eq!(db.number("SELECT count(*) FROM jobs").await, 2);
    assert_eq!(
        db.number("SELECT count(*) FROM jobs WHERE status = 'RECEIVED'")
            .await,
        2
    );
    assert_eq!(
        db.number("SELECT count(*) FROM pg_class WHERE relname = 'stolen'")
            .await,
        0
    );
    assert_eq!(
        db.number("SELECT count(*) FROM pg_largeobject_metadata")
            .await,
        0
    );
    // The second statement is refused by the protocol, not run.
    let failure = inspector
        .query("SELECT 1; DROP TABLE jobs", None)
        .await
        .expect_err("refused");
    assert_eq!(database_code(&failure), "42601", "{failure}");
}

#[tokio::test(flavor = "multi_thread")]
async fn nextval_fails_and_the_sequence_does_not_move() {
    let db = TestDb::fresh().await;
    let login = db.observer().await;
    let inspector = db.inspector(&login, quick_limits());
    let before = db
        .number("SELECT coalesce((SELECT last_value FROM pg_sequences WHERE schemaname = 'public' AND sequencename = split_part(pg_get_serial_sequence('public.outbox', 'seq'), '.', 2)), 0)")
        .await;
    let failure = inspector
        .query(
            "SELECT nextval(pg_get_serial_sequence('public.outbox', 'seq'))",
            None,
        )
        .await
        .expect_err("nextval is refused");
    assert!(matches!(failure, ToolFailure::Database { .. }), "{failure}");
    let after = db
        .number("SELECT coalesce((SELECT last_value FROM pg_sequences WHERE schemaname = 'public' AND sequencename = split_part(pg_get_serial_sequence('public.outbox', 'seq'), '.', 2)), 0)")
        .await;
    assert_eq!(before, after);
}

#[tokio::test(flavor = "multi_thread")]
async fn another_session_cannot_be_terminated() {
    let db = TestDb::fresh().await;
    let worker = db.login("app", &["factory_app"], false).await;
    let victim = db.connect_as(&worker).await;
    let pid: i32 = victim
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("pid")
        .get(0);
    let login = db.observer().await;
    let inspector = db.inspector(&login, quick_limits());
    let result = inspector
        .query(
            &format!("SELECT pg_terminate_backend({pid}) AS ended"),
            None,
        )
        .await;
    match result {
        Err(failure) => assert_eq!(database_code(&failure), "42501", "{failure}"),
        Ok(text) => assert_eq!(json(&text)["rows"][0]["ended"], Value::from(false)),
    }
    victim
        .query_one("SELECT 1", &[])
        .await
        .expect("the other session is alive");
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_do_not_outlive_a_call_and_advisory_locks_are_refused() {
    let db = TestDb::fresh().await;
    let login = db.observer().await;
    let inspector = db.inspector(&login, quick_limits());
    inspector
        .query(
            "SELECT set_config('statement_timeout', '0', false) AS a, \
                    set_config('factory.tenant_id', '00000000-0000-7000-8000-000000000001', false) AS b",
            None,
        )
        .await
        .expect("set_config is allowed in a read-only transaction");
    let text = inspector
        .query(
            "SELECT current_setting('statement_timeout') AS timeout, \
                    coalesce(current_setting('factory.tenant_id', true), '') AS tenant",
            None,
        )
        .await
        .expect("read the settings back");
    let row = &json(&text)["rows"][0];
    assert_eq!(row["timeout"], Value::from("1s"), "{text}");
    assert_eq!(row["tenant"], Value::from(""), "{text}");
    // Migration 003100 (TR-4): the observer may not take an advisory lock at all, so it cannot
    // hold the audit chain lock of a tenant either.
    for sql in [
        "SELECT pg_advisory_lock(4242) AS c",
        "SELECT pg_advisory_xact_lock(hashtextextended('factory.audit_events:' || id::text, 0)) AS c FROM tenants",
    ] {
        let failure = inspector.query(sql, None).await.expect_err(sql);
        assert_eq!(database_code(&failure), "42501", "{sql}: {failure}");
    }
    let held = db
        .number(
            "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' \
              AND database = (SELECT oid FROM pg_database WHERE datname = current_database())",
        )
        .await;
    assert_eq!(held, 0, "no advisory lock is held");
}

#[tokio::test(flavor = "multi_thread")]
async fn free_sql_cannot_read_another_roles_query_text() {
    let db = TestDb::fresh().await;
    let worker = db.login("app", &["factory_app"], false).await;
    let busy = db.connect_as(&worker).await;
    let running = tokio::spawn(async move {
        let _ = busy
            .batch_execute("SELECT 'customer-literal-31337' AS v, pg_sleep(3) /* note-31337 */")
            .await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let login = db.observer().await;
    let inspector = db.inspector(&login, quick_limits());
    // The review's own query (TR-3): an alias, a transformation, and a cut in pieces.
    let text = inspector
        .query(
            &format!(
                "SELECT pid, query AS text_of_session, reverse(query) AS backwards, \
                        encode(convert_to(query, 'UTF8'), 'base64') AS encoded, state \
                   FROM pg_stat_activity WHERE usename = '{}'",
                worker.name
            ),
            None,
        )
        .await
        .expect("pg_stat_activity is readable");
    assert!(!text.contains("31337"), "{text}");
    assert!(text.contains("<insufficient privilege>"), "{text}");
    // The same session through the observer function: listed, its text normalized.
    let text = inspector
        .query(
            &format!(
                "SELECT query AS t FROM observer_activity() WHERE login = '{}'",
                worker.name
            ),
            None,
        )
        .await
        .expect("observer_activity is readable");
    assert!(text.contains("pg_sleep(?)"), "{text}");
    assert!(!text.contains("31337"), "{text}");
    let _ = running.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_slow_statement_is_cancelled_at_the_timeout() {
    let db = TestDb::fresh().await;
    let login = db.observer().await;
    let inspector = db.inspector(&login, quick_limits());
    let started = Instant::now();
    let failure = inspector
        .query("SELECT pg_sleep(10)", None)
        .await
        .expect_err("cancelled");
    assert_eq!(failure, ToolFailure::Timeout);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    // The connection is fit for the next call.
    inspector
        .query("SELECT 1 AS one", None)
        .await
        .expect("next call");
}

#[tokio::test(flavor = "multi_thread")]
async fn huge_results_are_capped_in_rows_and_bytes() {
    let db = TestDb::fresh().await;
    let login = db.observer().await;
    let inspector = db.inspector(&login, quick_limits());
    let text = inspector
        .query(
            "SELECT g, repeat('x', 1000) AS pad FROM generate_series(1, 100000) g",
            Some(10_000),
        )
        .await
        .expect("the query runs");
    assert!(text.len() <= 64 * 1024, "{} bytes", text.len());
    let value = json(&text);
    assert_eq!(value["more_rows_than_limit"], Value::from(true));
    let kept = value["returned_rows"].as_u64().expect("kept");
    let omitted = value["truncated"]["omitted_rows"]
        .as_u64()
        .expect("omitted");
    assert_eq!(
        kept + omitted,
        200,
        "the row cap is 200 whatever the caller asks"
    );
    assert!(value["truncated"]["omitted_bytes"].as_u64().expect("bytes") > 0);
    let small = inspector
        .query("SELECT g FROM generate_series(1, 10) g", Some(3))
        .await
        .expect("runs");
    let small = json(&small);
    assert_eq!(small["returned_rows"], Value::from(3));
    assert_eq!(small["more_rows_than_limit"], Value::from(true));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sensitive_column_is_permission_denied() {
    let db = TestDb::fresh().await;
    let login = db.observer().await;
    let inspector = db.inspector(&login, quick_limits());
    for sql in [
        "SELECT request_text FROM original_requests",
        "SELECT token_hash FROM api_tokens",
        "SELECT * FROM jobs",
    ] {
        let failure = inspector.query(sql, None).await.expect_err(sql);
        assert_eq!(database_code(&failure), "42501", "{sql}: {failure}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn results_and_error_messages_are_redacted() {
    let db = TestDb::fresh().await;
    let login = db.observer().await;
    let inspector = db.inspector(&login, quick_limits());
    let text = inspector
        .query(&format!("SELECT 'before {PLANTED_VALUE} after' AS v"), None)
        .await
        .expect("runs");
    assert!(!text.contains(PLANTED_VALUE), "{text}");
    assert!(text.contains("[REDACTED:planted]"), "{text}");
    let failure = inspector
        .query(&format!("SELECT '{PLANTED_VALUE}'::int"), None)
        .await
        .expect_err("not a number");
    let shown = failure.to_string();
    assert!(!shown.contains(PLANTED_VALUE), "{shown}");
    assert!(shown.contains("22P02"), "{shown}");
}

#[tokio::test(flavor = "multi_thread")]
async fn activity_shows_other_sessions_without_their_literals() {
    let db = TestDb::fresh().await;
    let worker = db.login("app", &["factory_app"], false).await;
    let busy = db.connect_as(&worker).await;
    let running = tokio::spawn(async move {
        let _ = busy
            .batch_execute("SELECT 'customer-literal-31337' AS v, pg_sleep(3)")
            .await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let login = db.observer().await;
    let inspector = db.inspector(&login, quick_limits());
    let text = inspector.activity().await.expect("activity");
    assert!(
        text.contains(&worker.name),
        "the worker's session is listed: {text}"
    );
    assert!(text.contains("pg_sleep(?)"), "{text}");
    assert!(!text.contains("customer-literal-31337"), "{text}");
    let _ = running.await;
}

#[tokio::test(flavor = "multi_thread")]
async fn curated_tools_answer() {
    let db = TestDb::fresh().await;
    let login = db.observer().await;
    let inspector = db.inspector(&login, quick_limits());

    let relations = json(
        &inspector
            .list_relations("public", Some("job%"))
            .await
            .expect("list"),
    );
    assert_eq!(relations["rows"][0]["name"], Value::from("jobs"));
    assert_eq!(
        relations["rows"][0]["can_read_some_columns"],
        Value::from(true)
    );
    assert_eq!(
        relations["rows"][0]["can_read_every_column"],
        Value::from(false)
    );

    let described = json(
        &inspector
            .describe_relation("public", "original_requests")
            .await
            .expect("describe"),
    );
    let columns = described["columns"]["rows"].as_array().expect("columns");
    let request_text = columns
        .iter()
        .find(|c| c["column"] == "request_text")
        .expect("the column is listed");
    assert_eq!(request_text["readable"], Value::from(false));
    assert!(matches!(
        inspector.describe_relation("public", "no_such_table").await,
        Err(ToolFailure::Refused(_))
    ));

    let plan = inspector
        .explain("SELECT id, status FROM jobs WHERE status = 'ACTIVE'")
        .await
        .expect("explain");
    assert!(plan.contains("Plan"), "{plan}");
    assert!(inspector.explain("DELETE FROM jobs").await.is_err());
    assert!(
        inspector
            .explain("SELECT 1; DELETE FROM jobs")
            .await
            .is_err()
    );

    let health = json(&inspector.factory_health(24).await.expect("factory health"));
    for section in [
        "jobs_by_status",
        "attempts_past_deadline",
        "leases_past_expiry",
        "waiting_for_a_person",
        "failures_in_window",
        "outbox_backlog",
    ] {
        assert!(health[section]["rows"].is_array(), "{section}: {health}");
    }
    assert_eq!(health["jobs_by_status"]["rows"][0]["jobs"], Value::from(2));

    let tables = json(
        &inspector
            .table_health("public")
            .await
            .expect("table health"),
    );
    assert!(tables["returned_rows"].as_u64().expect("count") > 10);

    let locks = json(&inspector.locks().await.expect("locks"));
    assert!(locks["blocked"]["rows"].is_array());
    assert!(locks["lock_counts"]["rows"].is_array());
    assert_eq!(db.number("SELECT count(*) FROM jobs").await, 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_call_budget_is_enforced() {
    let db = TestDb::fresh().await;
    let login = db.observer().await;
    let inspector = db.inspector(
        &login,
        Limits {
            max_calls: 2,
            ..quick_limits()
        },
    );
    inspector.query("SELECT 1 AS a", None).await.expect("first");
    inspector.activity().await.expect("second");
    assert_eq!(
        inspector.query("SELECT 1 AS a", None).await,
        Err(ToolFailure::CallBudgetSpent { limit: 2 })
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_login_that_can_write_is_refused() {
    let db = TestDb::fresh().await;
    let both = db
        .login("both", &["factory_observer", "factory_app"], true)
        .await;
    let inspector = db.inspector(&both, quick_limits());
    assert!(matches!(
        inspector.check_login().await,
        Err(ToolFailure::Refused(_))
    ));
    let bare = db.login("bare", &[], true).await;
    let inspector = db.inspector(&bare, quick_limits());
    assert!(matches!(
        inspector.check_login().await,
        Err(ToolFailure::Refused(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_database_is_a_short_error_without_the_settings() {
    let mut settings =
        factory_mcp_postgres::ConnectSettings::new("127.0.0.1", 1, "nobody", "nowhere")
            .with_password(factory_mcp_postgres::Password::new(
                PLANTED_VALUE.to_owned(),
            ));
    settings.host = "127.0.0.1".to_owned();
    let inspector =
        factory_mcp_postgres::Inspector::new(settings, quick_limits(), support::planted_redactor());
    let failure = inspector
        .query("SELECT 1", None)
        .await
        .expect_err("no server");
    assert_eq!(failure, ToolFailure::Unavailable);
    let shown = failure.to_string();
    assert!(
        !shown.contains("127.0.0.1") && !shown.contains(PLANTED_VALUE),
        "{shown}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_server_speaks_mcp_over_a_pipe() {
    let db = TestDb::fresh().await;
    let login = db.observer().await;
    let server = PostgresMcp::new(db.inspector(&login, quick_limits()));
    let (server_end, client_end) = tokio::io::duplex(64 * 1024);
    let serving = tokio::spawn(async move {
        let running = server.serve(server_end).await.expect("serve");
        let _ = running.waiting().await;
    });
    let client = ().serve(client_end).await.expect("client");
    let tools = client.list_all_tools().await.expect("list tools");
    let mut names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    let mut expected: Vec<String> = TOOL_NAMES.iter().map(|n| (*n).to_owned()).collect();
    expected.sort();
    assert_eq!(names, expected);
    for tool in &tools {
        assert!(
            tool.annotations
                .as_ref()
                .and_then(|a| a.read_only_hint)
                .unwrap_or(false),
            "{} is marked read-only",
            tool.name
        );
    }

    let mut arguments = serde_json::Map::new();
    arguments.insert(
        "sql".to_owned(),
        Value::from("SELECT count(*) AS jobs FROM jobs"),
    );
    let answer = client
        .call_tool(CallToolRequestParams::new("pg_query").with_arguments(arguments))
        .await
        .expect("call");
    assert_ne!(answer.is_error, Some(true));
    let text = answer.content[0].as_text().expect("text").text.clone();
    assert_eq!(json(&text)["rows"][0]["jobs"], Value::from(2));

    let mut arguments = serde_json::Map::new();
    arguments.insert("sql".to_owned(), Value::from("DELETE FROM jobs"));
    let refused = client
        .call_tool(CallToolRequestParams::new("pg_query").with_arguments(arguments))
        .await
        .expect("a tool error is still an answer");
    assert_eq!(refused.is_error, Some(true));
    assert_eq!(db.number("SELECT count(*) FROM jobs").await, 2);

    let _ = client.cancel().await;
    let _ = serving.await;
}
