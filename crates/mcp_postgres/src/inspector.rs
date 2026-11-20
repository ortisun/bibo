//! The database side: one connection, one read-only transaction per call, caps and redaction.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::sync::Mutex;
use tokio_postgres::types::{FromSql, ToSql, Type};
use tokio_postgres::{Client, NoTls, Transaction};

use crate::sql::{self, CUT_ROW_KEY, render_read, render_sections, scrub_literals, wrap_fixed};
use crate::{ConnectSettings, Limits, Redact, ToolFailure, redact_json};

/// The keys whose string values are query texts of other sessions. The database already returns
/// them normalized (`observer_normalize_query`); their literals are scrubbed here again before
/// redaction, as a second layer. Free SQL cannot read a raw query text of another role at all.
const QUERY_TEXT_KEYS: [&str; 3] = ["query", "blocked_query", "blocking_query"];

/// The check of [`Inspector::check_login`], one row: what the login is, not a list of what it
/// must not be.
const LOGIN_CHECK: &str = include_str!("login_check.sql");

/// Rows fetched from a portal at a time. Each row is cut at the byte cap by the SQL wrapper, so
/// one fetch holds at most this many rows of the cap's size (four bytes a character at worst).
const FETCH_ROWS: i32 = 16;

/// The rows of one statement, as far as they were read.
#[derive(Debug, Default)]
struct ReadSet {
    rows: Vec<Value>,
    /// Reading stopped at the byte cap: more rows or bytes may exist that were never fetched.
    stopped: bool,
}

/// One statement and its text parameters. Every fixed statement casts its parameters from text.
struct Statement {
    sql: String,
    params: Vec<Option<String>>,
}

impl Statement {
    fn new(sql: String) -> Self {
        Self {
            sql,
            params: Vec::new(),
        }
    }

    fn with(sql: String, params: Vec<Option<String>>) -> Self {
        Self { sql, params }
    }
}

/// A text, JSON or JSONB column read as its JSON text.
struct JsonText(String);

impl<'a> FromSql<'a> for JsonText {
    fn from_sql(
        ty: &Type,
        raw: &'a [u8],
    ) -> Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        let bytes = if *ty == Type::JSONB {
            raw.strip_prefix(&[1_u8])
                .ok_or("an unknown jsonb binary version")?
        } else {
            raw
        };
        Ok(Self(std::str::from_utf8(bytes)?.to_owned()))
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::TEXT || *ty == Type::JSON || *ty == Type::JSONB
    }
}

/// The read-only inspector of the factory's database. Shared by every session of a server.
pub struct Inspector {
    settings: ConnectSettings,
    limits: Limits,
    redactor: Arc<dyn Redact>,
    client: Mutex<Option<Client>>,
    calls: AtomicU64,
    bytes_read: AtomicU64,
}

impl std::fmt::Debug for Inspector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inspector")
            .field("limits", &self.limits)
            .field("calls", &self.calls.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Inspector {
    /// An inspector that connects on its first call.
    pub fn new(settings: ConnectSettings, limits: Limits, redactor: Arc<dyn Redact>) -> Self {
        Self {
            settings,
            limits,
            redactor,
            client: Mutex::new(None),
            calls: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
        }
    }

    /// The caps of this inspector.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Calls made so far (every call, whatever budget it was charged to).
    pub fn calls_made(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }

    /// Bytes of result rows this inspector has received from the database in its life. Reading
    /// stops at the byte cap, so one call adds at most the cap plus one fetch of cut rows.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    /// Connects and checks that the login is fit to serve. An allowlist of what the login is
    /// (`login_check.sql`):
    ///
    /// - not a superuser, and no `BYPASSRLS`, `CREATEROLE`, `CREATEDB` or `REPLICATION`;
    /// - a member of `factory_observer`, and directly of no other role, so that everything it
    ///   holds comes through that group, and the group passes on the privileges of no role;
    /// - a member of no predefined role (`pg_read_all_data`, `pg_write_all_data`,
    ///   `pg_read_server_files`, `pg_execute_server_program`, `pg_signal_backend`, `pg_monitor`,
    ///   `pg_database_owner` and every other `pg_*` role) by effective membership. For
    ///   `pg_read_all_stats` the test is on its privileges: migration 002900, run again for another
    ///   database of the cluster, grants it for a moment to the group, which is NOINHERIT;
    /// - the owner of nothing in this database, and a member of no role that owns something;
    /// - able to read no column the group cannot read and to write to no table or sequence,
    ///   whatever role or `PUBLIC` grant gives it: the property itself.
    ///
    /// Does not count against any call budget. Returns the login's name.
    ///
    /// # Errors
    /// [`ToolFailure::Unavailable`] when the database cannot be reached, and
    /// [`ToolFailure::Refused`] naming what is wrong with the login.
    pub async fn check_login(&self) -> Result<String, ToolFailure> {
        let mut sets = self
            .read_uncharged(&[Statement::new(self.fixed(LOGIN_CHECK))])
            .await?;
        let row = sets
            .pop()
            .and_then(|mut set| set.rows.pop())
            .ok_or_else(|| ToolFailure::Refused("the login could not be checked".to_owned()))?;
        let flag = |key: &str| row.get(key).and_then(Value::as_bool).unwrap_or(true);
        let login = row
            .get("login")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let refused = |why: String| {
            ToolFailure::Refused(format!(
                "the login {login} {why}; use a login made as docs/database/observer-login.sql makes it, a member of factory_observer and of nothing else"
            ))
        };
        if flag("superuser") || flag("bypassrls") {
            return Err(refused(
                "is a superuser or bypasses row-level security".to_owned(),
            ));
        }
        if flag("createrole") || flag("createdb") || flag("replication") {
            return Err(refused(
                "may create roles or databases, or replicate".to_owned(),
            ));
        }
        if !row
            .get("observer")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(refused("is not a member of factory_observer".to_owned()));
        }
        for (key, why) in [
            ("other_groups", "is also a member of"),
            (
                "group_inherits",
                "belongs to factory_observer, which passes on the privileges of",
            ),
            ("predefined", "holds the predefined roles"),
            ("owns", ""),
            (
                "reads_more",
                "can read columns factory_observer may not read, in",
            ),
            ("writes", "can write to"),
            ("sequences", "can use or set the sequences"),
        ] {
            if key == "owns" {
                if flag(key) {
                    return Err(refused(
                        "owns objects in this database, or is a member of a role that does"
                            .to_owned(),
                    ));
                }
                continue;
            }
            // A missing value counts as found: the check refuses what it cannot read.
            let found = row
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or("(the check gave no answer)");
            if !found.is_empty() {
                return Err(refused(format!("{why} {found}")));
            }
        }
        Ok(login)
    }

    /// `pg_query`: free SQL, boxed in as a subquery of a read-only transaction.
    ///
    /// # Errors
    /// A [`ToolFailure`].
    pub async fn query(&self, sql: &str, max_rows: Option<usize>) -> Result<String, ToolFailure> {
        let cap = max_rows.map_or(self.limits.max_rows, |n| n.clamp(1, self.limits.max_rows));
        let wrapped = sql::wrap_query(
            sql,
            cap,
            self.limits.max_sql_bytes,
            self.limits.max_result_bytes,
        )?;
        let rows = self.single(Statement::new(wrapped)).await?;
        self.render_capped(rows, cap)
    }

    /// `pg_explain`: the plan of a query, `EXPLAIN (FORMAT JSON)` without `ANALYZE`.
    ///
    /// # Errors
    /// A [`ToolFailure`].
    pub async fn explain(&self, sql: &str) -> Result<String, ToolFailure> {
        let wrapped = sql::wrap_explain(sql, self.limits.max_sql_bytes)?;
        let ReadSet { mut rows, stopped } = self.single(Statement::new(wrapped)).await?;
        self.clean(&mut rows)?;
        Ok(render_read(
            &rows,
            false,
            stopped,
            self.limits.max_result_bytes,
        ))
    }

    /// `pg_list_relations`: tables and views of a schema, with size, estimated rows and what the
    /// login may read.
    ///
    /// # Errors
    /// A [`ToolFailure`].
    pub async fn list_relations(
        &self,
        schema: &str,
        name_like: Option<&str>,
    ) -> Result<String, ToolFailure> {
        let cap = self.limits.max_rows;
        let fixed = format!(
            "SELECT n.nspname AS schema, c.relname AS name, \
                    CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned table' WHEN 'v' THEN 'view' \
                                   WHEN 'm' THEN 'materialized view' WHEN 'f' THEN 'foreign table' END AS kind, \
                    c.reltuples::bigint AS estimated_rows, pg_catalog.pg_total_relation_size(c.oid) AS total_bytes, \
                    pg_catalog.has_table_privilege(c.oid, 'SELECT') AS can_read_every_column, \
                    pg_catalog.has_any_column_privilege(c.oid, 'SELECT') AS can_read_some_columns, \
                    c.relrowsecurity AS row_level_security \
               FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
              WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname = $1::text \
                AND ($2::text IS NULL OR c.relname LIKE $2::text) \
              ORDER BY c.relname LIMIT {}",
            cap + 1
        );
        let rows = self
            .single(Statement::with(
                self.fixed(&fixed),
                vec![Some(schema.to_owned()), name_like.map(str::to_owned)],
            ))
            .await?;
        self.render_capped(rows, cap)
    }

    /// `pg_describe_relation`: the columns (type, nullability, readable by this login) and the
    /// indexes of one table or view.
    ///
    /// # Errors
    /// A [`ToolFailure`]; [`ToolFailure::Refused`] when no such relation is visible.
    pub async fn describe_relation(&self, schema: &str, name: &str) -> Result<String, ToolFailure> {
        let columns = "SELECT a.attnum AS position, a.attname AS column, \
                              pg_catalog.format_type(a.atttypid, a.atttypmod) AS type, NOT a.attnotnull AS nullable, \
                              pg_catalog.has_column_privilege(c.oid, a.attnum, 'SELECT') AS readable \
                         FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid \
                         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
                        WHERE n.nspname = $1::text AND c.relname = $2::text AND a.attnum > 0 AND NOT a.attisdropped \
                        ORDER BY a.attnum";
        let indexes = "SELECT indexname AS name, indexdef AS definition FROM pg_catalog.pg_indexes \
                        WHERE schemaname = $1::text AND tablename = $2::text ORDER BY indexname";
        let params = vec![Some(schema.to_owned()), Some(name.to_owned())];
        let mut sets = self
            .read(&[
                Statement::with(self.fixed(columns), params.clone()),
                Statement::with(self.fixed(indexes), params),
            ])
            .await?;
        let mut index_rows = sets.pop().unwrap_or_default().rows;
        let mut column_rows = sets.pop().unwrap_or_default().rows;
        if column_rows.is_empty() {
            return Err(ToolFailure::Refused(format!(
                "no table or view {schema}.{name} is visible; pg_list_relations lists them"
            )));
        }
        self.clean(&mut column_rows)?;
        self.clean(&mut index_rows)?;
        Ok(render_sections(
            &[
                ("columns", column_rows, false),
                ("indexes", index_rows, false),
            ],
            self.limits.max_result_bytes,
        ))
    }

    /// `pg_activity`: the other sessions, what they wait on and how old their transaction is,
    /// oldest transaction first. Query texts come back with their literals scrubbed.
    ///
    /// # Errors
    /// A [`ToolFailure`].
    pub async fn activity(&self) -> Result<String, ToolFailure> {
        let cap = self.limits.max_rows;
        // The sessions come from observer_activity() (migration 2026-11-20-003100): factory_observer has no
        // pg_read_all_stats, so the function, owned by a role that has it, returns the query texts with their
        // literals and comments already replaced and only this database's sessions.
        let fixed = format!(
            "SELECT pid, login, application_name, backend_type, state, wait_event_type, wait_event, \
                    backend_start, xact_start, query_start, state_change, \
                    (now() - xact_start)::text AS transaction_age, (now() - query_start)::text AS query_age, \
                    backend_xmin, query \
               FROM public.observer_activity() \
              ORDER BY xact_start NULLS LAST, backend_start LIMIT {}",
            cap + 1
        );
        let rows = self.single(Statement::new(self.fixed(&fixed))).await?;
        self.render_capped(rows, cap)
    }

    /// `pg_locks`: who blocks whom, and the locks held and awaited by mode.
    ///
    /// # Errors
    /// A [`ToolFailure`].
    pub async fn locks(&self) -> Result<String, ToolFailure> {
        let cap = self.limits.max_rows;
        let blocked = format!(
            "SELECT blocked_pid, blocked_login, wait_event_type, wait_event, \
                    (now() - blocked_since)::text AS blocked_for, blocked_query, blocking_pid, blocking_login, \
                    blocking_state, (now() - blocking_xact_start)::text AS blocking_transaction_age, blocking_query \
               FROM public.observer_lock_waits() \
              ORDER BY blocked_since NULLS LAST LIMIT {}",
            cap + 1
        );
        let summary = format!(
            "SELECT locktype, mode, granted, count(*) AS locks FROM pg_catalog.pg_locks \
              GROUP BY locktype, mode, granted ORDER BY granted, count(*) DESC LIMIT {}",
            cap + 1
        );
        let sets = self
            .read(&[
                Statement::new(self.fixed(&blocked)),
                Statement::new(self.fixed(&summary)),
            ])
            .await?;
        self.render_named(&["blocked", "lock_counts"], sets, cap)
    }

    /// `pg_table_health`: dead tuples, the last vacuum and analyze, sequential and index scans.
    ///
    /// # Errors
    /// A [`ToolFailure`].
    pub async fn table_health(&self, schema: &str) -> Result<String, ToolFailure> {
        let cap = self.limits.max_rows;
        let fixed = format!(
            "SELECT schemaname AS schema, relname AS table, n_live_tup AS live_rows, n_dead_tup AS dead_rows, \
                    round(n_dead_tup::numeric / nullif(n_live_tup + n_dead_tup, 0), 3) AS dead_ratio, \
                    seq_scan, seq_tup_read, idx_scan, n_tup_ins AS inserts, n_tup_upd AS updates, \
                    n_tup_hot_upd AS hot_updates, n_tup_del AS deletes, last_vacuum, last_autovacuum, \
                    last_analyze, last_autoanalyze, vacuum_count, autovacuum_count, \
                    pg_catalog.pg_total_relation_size(relid) AS total_bytes \
               FROM pg_catalog.pg_stat_user_tables WHERE schemaname = $1::text \
              ORDER BY n_dead_tup DESC, relname LIMIT {}",
            cap + 1
        );
        let rows = self
            .single(Statement::with(
                self.fixed(&fixed),
                vec![Some(schema.to_owned())],
            ))
            .await?;
        self.render_capped(rows, cap)
    }

    /// `pg_factory_health`: fixed questions over the observer's columns of the factory tables.
    ///
    /// # Errors
    /// A [`ToolFailure`].
    pub async fn factory_health(&self, window_hours: u32) -> Result<String, ToolFailure> {
        let cap = self.limits.max_rows.min(50);
        let window = Some(window_hours.clamp(1, 720).to_string());
        let statements = [
            // Open jobs by state, and jobs that ended in the window.
            "SELECT status, count(*) AS jobs, min(updated_at) AS oldest_change, max(updated_at) AS newest_change \
               FROM public.jobs WHERE terminal_at IS NULL OR terminal_at > now() - make_interval(hours => $1::text::int) \
              GROUP BY status ORDER BY status",
            // Live attempts past their wall-clock deadline.
            "SELECT tenant_id, job_id, stage_run_id, id AS attempt_id, status, deadline_at, \
                    (now() - deadline_at)::text AS overdue_by, lease_owner, last_heartbeat_at \
               FROM public.attempts WHERE status IN ('STARTING', 'RUNNING', 'CANCELLING') AND deadline_at < now() \
              ORDER BY deadline_at LIMIT 51",
            // Live attempts whose lease expired: the worker holding them stopped renewing.
            "SELECT tenant_id, job_id, stage_run_id, id AS attempt_id, status, lease_owner, lease_epoch, \
                    lease_expires_at, (now() - lease_expires_at)::text AS expired_for, last_heartbeat_at \
               FROM public.attempts WHERE status IN ('STARTING', 'RUNNING', 'CANCELLING') AND lease_expires_at < now() \
              ORDER BY lease_expires_at LIMIT 51",
            // Stage runs waiting for a person, longest wait first, and approvals that expired unused.
            "SELECT s.tenant_id, s.job_id, s.id AS stage_run_id, s.stage_kind, s.updated_at AS waiting_since, \
                    (now() - s.updated_at)::text AS waited, \
                    EXISTS (SELECT 1 FROM public.approvals a WHERE a.tenant_id = s.tenant_id AND a.stage_run_id = s.id \
                               AND a.invalidated_at IS NULL AND a.expires_at < now()) AS has_expired_approval \
               FROM public.stage_runs s WHERE s.status = 'WAITING_FOR_HUMAN' ORDER BY s.updated_at LIMIT 51",
            // Failures in the window, by kind and reason.
            "SELECT 'attempt' AS what, status, coalesce(failure_class, '') AS reason, count(*) AS failures, \
                    max(ended_at) AS last_seen \
               FROM public.attempts WHERE status IN ('FAILED', 'TIMED_OUT', 'LEASE_LOST') \
                AND ended_at > now() - make_interval(hours => $1::text::int) GROUP BY status, failure_class \
             UNION ALL \
             SELECT 'stage_run', stage_kind || ':' || status, coalesce(gate_outcome, ''), count(*), max(finished_at) \
               FROM public.stage_runs WHERE status IN ('FAILED', 'REWORK_REQUESTED') \
                AND finished_at > now() - make_interval(hours => $1::text::int) GROUP BY stage_kind, status, gate_outcome \
             ORDER BY failures DESC LIMIT 51",
            // The outbox: events not yet published.
            "SELECT count(*) AS unpublished, min(created_at) AS oldest_unpublished, \
                    coalesce(max(publish_attempts), 0) AS most_publish_attempts \
               FROM public.outbox WHERE published_at IS NULL",
        ];
        let uses_window = [true, false, false, false, true, false];
        let prepared: Vec<Statement> = statements
            .iter()
            .zip(uses_window)
            .map(|(text, windowed)| {
                if windowed {
                    Statement::with(self.fixed(text), vec![window.clone()])
                } else {
                    Statement::new(self.fixed(text))
                }
            })
            .collect();
        let sets = self.read(&prepared).await?;
        self.render_named(
            &[
                "jobs_by_status",
                "attempts_past_deadline",
                "leases_past_expiry",
                "waiting_for_a_person",
                "failures_in_window",
                "outbox_backlog",
            ],
            sets,
            cap,
        )
    }

    // ---------------------------------------------------------------------------------------

    /// A fixed statement of this crate, wrapped so that each row is JSON text cut at the byte cap.
    fn fixed(&self, sql: &str) -> String {
        wrap_fixed(sql, self.limits.max_result_bytes)
    }

    fn render_capped(&self, set: ReadSet, cap: usize) -> Result<String, ToolFailure> {
        let ReadSet { mut rows, stopped } = set;
        let more = rows.len() > cap;
        rows.truncate(cap);
        self.clean(&mut rows)?;
        Ok(render_read(
            &rows,
            more,
            stopped,
            self.limits.max_result_bytes,
        ))
    }

    fn render_named(
        &self,
        names: &[&str],
        sets: Vec<ReadSet>,
        cap: usize,
    ) -> Result<String, ToolFailure> {
        let mut sections = Vec::with_capacity(names.len());
        for (name, set) in names.iter().zip(sets) {
            let ReadSet { mut rows, stopped } = set;
            let more = rows.len() > cap;
            rows.truncate(cap);
            self.clean(&mut rows)?;
            sections.push((*name, rows, more || stopped));
        }
        Ok(render_sections(&sections, self.limits.max_result_bytes))
    }

    /// Scrubs the literals of query texts, then redacts every string.
    fn clean(&self, rows: &mut [Value]) -> Result<(), ToolFailure> {
        for row in rows.iter_mut() {
            if let Value::Object(map) = row {
                for key in QUERY_TEXT_KEYS {
                    if let Some(Value::String(text)) = map.get_mut(key) {
                        *text = scrub_literals(text);
                    }
                }
            }
            redact_json(row, self.redactor.as_ref()).map_err(|_| ToolFailure::RedactionFailed)?;
        }
        Ok(())
    }

    async fn single(&self, statement: Statement) -> Result<ReadSet, ToolFailure> {
        let mut sets = self.read(&[statement]).await?;
        Ok(sets.pop().unwrap_or_default())
    }

    /// Runs the statements in one read-only transaction, counting one call. The call budget is
    /// not here: [`crate::PostgresMcp`] charges it per run or per window before it calls.
    async fn read(&self, statements: &[Statement]) -> Result<Vec<ReadSet>, ToolFailure> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.read_uncharged(statements).await
    }

    async fn read_uncharged(&self, statements: &[Statement]) -> Result<Vec<ReadSet>, ToolFailure> {
        let mut slot = self.client.lock().await;
        let deadline = self.limits.call_deadline();
        match tokio::time::timeout(deadline, self.run(&mut slot, statements)).await {
            Ok(result) => result,
            Err(_) => {
                // The call outlived its deadline. Cancel what runs and drop the connection, so the
                // next call starts on a clean session.
                if let Some(client) = slot.take() {
                    let token = client.cancel_token();
                    drop(client);
                    let _ = tokio::time::timeout(Duration::from_secs(2), token.cancel_query(NoTls))
                        .await;
                }
                Err(ToolFailure::Timeout)
            }
        }
    }

    async fn run(
        &self,
        slot: &mut Option<Client>,
        statements: &[Statement],
    ) -> Result<Vec<ReadSet>, ToolFailure> {
        if slot.as_ref().is_none_or(Client::is_closed) {
            *slot = Some(self.connect().await?);
        }
        let Some(client) = slot.as_mut() else {
            return Err(ToolFailure::Unavailable);
        };
        let (result, ended) = self.transaction(client, statements).await;
        // Reset the session: an advisory lock or a setting taken at session level does not outlive
        // the call. A session that cannot be reset is dropped.
        let clean = ended && client.batch_execute("DISCARD ALL").await.is_ok();
        if !clean {
            *slot = None;
        }
        result
    }

    /// One `BEGIN READ ONLY` ... `ROLLBACK` around the statements. The second value says whether
    /// the transaction was ended cleanly.
    async fn transaction(
        &self,
        client: &mut Client,
        statements: &[Statement],
    ) -> (Result<Vec<ReadSet>, ToolFailure>, bool) {
        let tx = match client.build_transaction().read_only(true).start().await {
            Ok(tx) => tx,
            Err(error) => return (Err(self.map_error(&error)), false),
        };
        // Fixed text: the numbers come from the limits, never from a caller.
        let settings = format!(
            "SET LOCAL statement_timeout = {}; SET LOCAL lock_timeout = {}",
            self.limits.statement_timeout_ms(),
            self.limits.lock_timeout_ms()
        );
        if let Err(error) = tx.batch_execute(&settings).await {
            let failure = self.map_error(&error);
            let ended = tx.rollback().await.is_ok();
            return (Err(failure), ended);
        }
        let started = Instant::now();
        let mut sets = Vec::with_capacity(statements.len());
        let mut failure = None;
        for statement in statements {
            match self.read_one(&tx, statement, started).await {
                Ok(set) => sets.push(set),
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        // End the transaction whatever happened. The rollback also closes the portal of a
        // statement whose rows were not all read.
        let ended = tx.rollback().await.is_ok();
        (failure.map_or(Ok(sets), Err), ended)
    }

    /// Reads one statement through a portal, [`FETCH_ROWS`] rows at a time, and stops as soon as
    /// the rows read pass the byte cap: the rest is never fetched, so what this process holds is
    /// bounded by the caps whatever the query would return (TR-2). Each row arrives already cut
    /// at the byte cap by the SQL wrapper, so one fetch holds at most [`FETCH_ROWS`] cut rows.
    async fn read_one(
        &self,
        tx: &Transaction<'_>,
        statement: &Statement,
        started: Instant,
    ) -> Result<ReadSet, ToolFailure> {
        let params: Vec<&(dyn ToSql + Sync)> = statement
            .params
            .iter()
            .map(|param| param as &(dyn ToSql + Sync))
            .collect();
        // `bind` prepares the text first (the extended protocol), which takes one statement.
        let portal = tx
            .bind(statement.sql.as_str(), &params)
            .await
            .map_err(|error| self.map_error(&error))?;
        let byte_cap = self.limits.max_result_bytes;
        let mut set = ReadSet::default();
        let mut used = 0usize;
        let mut first = true;
        loop {
            if !first {
                // Each fetch is a statement of its own for statement_timeout, so the time left
                // of the call's one timeout is set again before it.
                let left = self
                    .limits
                    .statement_timeout
                    .saturating_sub(started.elapsed());
                if left.is_zero() {
                    return Err(ToolFailure::Timeout);
                }
                tx.batch_execute(&format!(
                    "SET LOCAL statement_timeout = {}",
                    left.as_millis().max(1)
                ))
                .await
                .map_err(|error| self.map_error(&error))?;
            }
            first = false;
            let rows = tx
                .query_portal(&portal, FETCH_ROWS)
                .await
                .map_err(|error| self.map_error(&error))?;
            let fetched = rows.len();
            for row in rows {
                let text = row
                    .try_get::<_, JsonText>(0)
                    .map_err(|_| {
                        ToolFailure::Refused("a result row could not be read as JSON".to_owned())
                    })?
                    .0;
                self.bytes_read.fetch_add(
                    u64::try_from(text.len()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
                used = used.saturating_add(text.len());
                if set.stopped {
                    continue;
                }
                if text.chars().count() > byte_cap {
                    // Cut by the wrapper: this row alone is over the cap. Its first bytes stand
                    // for it, and nothing after it is read.
                    let mut cut = serde_json::Map::new();
                    cut.insert(CUT_ROW_KEY.to_owned(), Value::String(text));
                    set.rows.push(Value::Object(cut));
                    set.stopped = true;
                    continue;
                }
                let value = serde_json::from_str::<Value>(&text).map_err(|_| {
                    ToolFailure::Refused("a result row could not be read as JSON".to_owned())
                })?;
                set.rows.push(value);
                if used > byte_cap {
                    set.stopped = true;
                }
            }
            if set.stopped || fetched < usize::try_from(FETCH_ROWS).unwrap_or(usize::MAX) {
                return Ok(set);
            }
        }
    }

    async fn connect(&self) -> Result<Client, ToolFailure> {
        let config = self.settings.driver_config(&self.limits);
        // The driver's error may name the host; the caller gets a fixed sentence instead.
        let (client, connection) = config
            .connect(NoTls)
            .await
            .map_err(|_| ToolFailure::Unavailable)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(client)
    }

    fn map_error(&self, error: &tokio_postgres::Error) -> ToolFailure {
        let Some(db) = error.as_db_error() else {
            return ToolFailure::Unavailable;
        };
        let code = db.code().code();
        if code == "57014" {
            return ToolFailure::Timeout;
        }
        let message = self
            .redactor
            .redact(db.message())
            .unwrap_or_else(|_| "the message was withheld".to_owned());
        ToolFailure::Database {
            code: code.to_owned(),
            message,
        }
    }
}
