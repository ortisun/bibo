//! What the compare and swap updates share: telling a stale version from a missing row.
//!
//! Every update names the version it read: `WHERE tenant_id = $1 AND id = $2 AND version = $3`.
//! When it changes no row there are only two reasons, and the caller must be told which one.
//! A row that exists means somebody changed it first (`Conflict`). A row that does not exist
//! means the id is unknown, or belongs to another tenant, and those two look the same on purpose
//! (`NotFound`, NT-TEN-05). The statement that decides runs after the update in the same
//! transaction, under the same tenant setting.

use diesel::sql_types::{Bool, Uuid as SqlUuid};
use diesel::{QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::TenantId;
use factory_ports::store::StoreError;
use uuid::Uuid;

use super::error::database;

/// A table with a `(tenant_id, id)` key whose rows are changed by compare and swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Table {
    Jobs,
    StageRuns,
    TaskNodes,
    Repositories,
}

impl Table {
    const fn exists_sql(self) -> &'static str {
        match self {
            Self::Jobs => {
                "SELECT EXISTS (SELECT 1 FROM jobs WHERE tenant_id = $1 AND id = $2) AS found"
            }
            Self::StageRuns => {
                "SELECT EXISTS (SELECT 1 FROM stage_runs WHERE tenant_id = $1 AND id = $2) AS found"
            }
            Self::TaskNodes => {
                "SELECT EXISTS (SELECT 1 FROM task_nodes WHERE tenant_id = $1 AND id = $2) AS found"
            }
            Self::Repositories => {
                "SELECT EXISTS (SELECT 1 FROM repositories WHERE tenant_id = $1 AND id = $2) AS found"
            }
        }
    }
}

#[derive(QueryableByName)]
struct Found {
    #[diesel(sql_type = Bool)]
    found: bool,
}

/// True when the tenant has a row with this id. A plain read: it does not lock and does not wait.
pub(super) async fn exists(
    connection: &mut AsyncPgConnection,
    table: Table,
    tenant: TenantId,
    id: Uuid,
    operation: &'static str,
) -> Result<bool, StoreError> {
    sql_query(table.exists_sql())
        .bind::<SqlUuid, _>(tenant.as_uuid())
        .bind::<SqlUuid, _>(id)
        .get_result::<Found>(connection)
        .await
        .map(|row| row.found)
        .map_err(|error| database(operation, &error))
}

/// The error for an update that changed no row: `Conflict` when the row exists, `NotFound` when
/// it does not.
pub(super) async fn no_row_changed(
    connection: &mut AsyncPgConnection,
    table: Table,
    tenant: TenantId,
    id: Uuid,
    operation: &'static str,
) -> Result<StoreError, StoreError> {
    Ok(if exists(connection, table, tenant, id, operation).await? {
        StoreError::Conflict
    } else {
        StoreError::NotFound
    })
}
