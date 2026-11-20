//! The read-only PostgreSQL MCP server of the factory (ADR 0021, decision 4).
//!
//! It lets a model (the troubleshooter, or an engineer's Claude Code) look at the factory's own
//! database: which jobs are stuck, which leases expired, which sessions wait on a lock, which
//! tables need a vacuum, and any question the curated tools did not foresee, as free SQL.
//!
//! # Read-only by the database, not by parsing SQL
//!
//! The controls, in the order PostgreSQL applies them:
//!
//! 1. **The role.** The login is a member of `factory_observer` (migrations
//!    `2026-11-20-002900_observer_role` and `2026-11-20-003100_observer_hardening`): `SELECT` on
//!    named operational columns only, one read policy per table under row-level security,
//!    `EXECUTE` on the observer functions that return other sessions' query texts normalized, and
//!    nothing else: no `pg_read_all_stats`, no advisory lock. [`Inspector::check_login`] refuses a
//!    login that is anything more (an allowlist: no other membership, no predefined role, no
//!    ownership, no column or write beyond the group's).
//! 2. **Every call runs in `BEGIN READ ONLY` and ends with `ROLLBACK`**, with `SET LOCAL
//!    statement_timeout` and `lock_timeout`. A write, `nextval`, `NOTIFY` or a data-modifying
//!    CTE fails. After the rollback the session runs `DISCARD ALL`, so a session-level advisory
//!    lock or setting taken by one call does not survive into the next.
//! 3. **Free SQL is wrapped as a subquery** and sent with the extended protocol, which accepts one
//!    statement only: `SELECT to_jsonb(q)::text FROM (\n<sql>\n) AS q LIMIT <max_rows + 1>`. A
//!    subquery can only be a query: `INSERT`, `UPDATE`, `DELETE`, `MERGE`, `COPY`, DDL and a
//!    data-modifying `WITH` do not parse there, and a second statement after a `;` is refused by
//!    the protocol. The newlines keep a trailing `--` comment from swallowing the closing
//!    parenthesis. `pg_explain` wraps the same way: `EXPLAIN (FORMAT JSON) SELECT * FROM (...)`,
//!    never `ANALYZE`, so nothing is executed.
//! 4. **Caps**: rows ([`Limits::max_rows`], 200), result bytes ([`Limits::max_result_bytes`],
//!    64 KiB, with a truncation marker that says how many rows and bytes were cut), statement time
//!    and calls per server ([`Limits::max_calls`]), enforced here whether or not a gateway in front
//!    enforces them too.
//! 5. **Redaction** of every string in a result through the [`Redact`] seam that the caller
//!    injects (the factory's [`factory_domain::redaction::Redactor`] implements it), and literal
//!    scrubbing of the `query` texts that `pg_activity` and `pg_locks` return.
//!
//! Errors come back as MCP tool errors with a short reason. The connection settings, the
//! password and any driver message about the connection never appear in one.
//!
//! # Use
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use factory_mcp_postgres::{ConnectSettings, Inspector, Limits, Password, PostgresMcp};
//! # fn redactor() -> Arc<dyn factory_mcp_postgres::Redact> { unimplemented!() }
//! let settings = ConnectSettings::new("127.0.0.1", 5432, "factory_troubleshooter", "factory")
//!     .with_password(Password::new("read from a file at start".to_owned()));
//! let inspector = Arc::new(Inspector::new(settings, Limits::default(), redactor()));
//! let server = PostgresMcp::new(inspector);
//! // Serve `server` with any rmcp transport: stdio, Streamable HTTP or an in-memory pipe.
//! ```

mod failure;
mod inspector;
mod limits;
mod redact;
mod settings;
pub mod sql;
mod tools;

pub use failure::ToolFailure;
pub use inspector::Inspector;
pub use limits::Limits;
pub use redact::{Redact, RedactionFailed, redact_json};
pub use settings::{ConnectSettings, Password};
pub use tools::{
    DescribeRelationParams, ExplainParams, FactoryHealthParams, ListRelationsParams, PostgresMcp,
    QueryParams, TOOL_NAMES, TableHealthParams,
};
