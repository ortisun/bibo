//! The first half of every compare and swap: lock the row without waiting.
//!
//! A row is locked with `FOR NO KEY UPDATE SKIP LOCKED` (ADR 0007, rule 6). `NO KEY UPDATE` and
//! not `UPDATE`, because a ledger, audit or outbox insert takes a `KEY SHARE` lock on the rows it
//! points at, and `FOR UPDATE` conflicts with that. `SKIP LOCKED` and not a wait, because the port
//! says a row held by another open transaction is skipped, not waited for: a writer that finds the
//! row busy reports `Conflict` at once, and its own transaction stays usable. A plain `UPDATE` would
//! wait for the other transaction and, when the two are driven by one task, never return.

use diesel::sql_types::{BigInt, Text, Uuid as SqlUuid};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_ports::store::StoreError;
use uuid::Uuid;

use super::error::generic;

/// A table that holds a state machine: it has `tenant_id`, `id`, `status` and `version`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Machine {
    Job,
    StageRun,
    Attempt,
    TaskNode,
}

impl Machine {
    pub(super) const fn table(self) -> &'static str {
        match self {
            Self::Job => "jobs",
            Self::StageRun => "stage_runs",
            Self::Attempt => "attempts",
            Self::TaskNode => "task_nodes",
        }
    }
}

#[derive(QueryableByName)]
struct StatusAndVersion {
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = BigInt)]
    version: i64,
}

#[derive(QueryableByName)]
struct Present {
    #[diesel(sql_type = BigInt)]
    #[allow(dead_code)]
    one: i64,
}

/// The result of trying to lock a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Locked {
    /// The row is visible to this transaction and now locked. Its status and version.
    Row { status: String, version: i64 },
    /// The row is visible but another open transaction holds it. Report `Conflict`.
    Busy,
    /// No such row for this tenant. A row of another tenant looks the same (NT-TEN-05).
    Missing,
}

/// Locks one row of `machine` for the tenant.
pub(super) async fn lock(
    connection: &mut AsyncPgConnection,
    machine: Machine,
    tenant: Uuid,
    id: Uuid,
    operation: &'static str,
) -> Result<Locked, StoreError> {
    let table = machine.table();
    let locked = sql_query(format!(
        "SELECT status, version FROM {table} WHERE tenant_id = $1 AND id = $2 \
         FOR NO KEY UPDATE SKIP LOCKED"
    ))
    .bind::<SqlUuid, _>(tenant)
    .bind::<SqlUuid, _>(id)
    .get_result::<StatusAndVersion>(connection)
    .await
    .optional()
    .map_err(|error| generic(operation, &error))?;
    if let Some(row) = locked {
        return Ok(Locked::Row {
            status: row.status,
            version: row.version,
        });
    }
    if exists(connection, machine, tenant, id, operation).await? {
        Ok(Locked::Busy)
    } else {
        Ok(Locked::Missing)
    }
}

/// True when the tenant has a row with this id. A plain read: it does not lock and does not wait.
pub(super) async fn exists(
    connection: &mut AsyncPgConnection,
    machine: Machine,
    tenant: Uuid,
    id: Uuid,
    operation: &'static str,
) -> Result<bool, StoreError> {
    let table = machine.table();
    sql_query(format!(
        "SELECT 1::bigint AS one FROM {table} WHERE tenant_id = $1 AND id = $2"
    ))
    .bind::<SqlUuid, _>(tenant)
    .bind::<SqlUuid, _>(id)
    .get_result::<Present>(connection)
    .await
    .optional()
    .map(|row| row.is_some())
    .map_err(|error| generic(operation, &error))
}
