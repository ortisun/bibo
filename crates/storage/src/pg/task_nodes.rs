//! Nodes of the task graph.
//!
//! # What the port cannot carry
//!
//! A row of `task_nodes` names the stage run it belongs to and the hash of the task plan it came
//! from (`plan_sha256`, a key to `artifacts`). The port's `NewTaskNode` carries neither: it has an
//! id, a job, a key and a time. The store cannot invent a plan artifact, so `insert` refuses with
//! `Constraint` once the job is known to exist, and says why. Reading and moving a node, which
//! need only the row, work as for any other aggregate.

use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Bool, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::{TaskNodeId, TenantId};
use factory_domain::state::{Status, TaskNodeStatus};
use factory_domain::values::Slug;
use factory_ports::store::{
    AppliedTransition, NewTaskNode, StoreError, TaskNode, Version, Versioned,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::cas::{Locked, Machine, lock};
use super::conv::{
    corrupt, from_column, job_from_column, status_from_column, task_node_from_column,
    task_node_to_column, tenant_from_column, tenant_to_column, to_column, version_from_column,
};
use super::error::{Failure, constraint, generic};
use super::jobs::job_exists;
use crate::schema::task_nodes;

type NodeRow = (Uuid, Uuid, Uuid, String, String, i64, OffsetDateTime);

const NODE_COLUMNS: (
    task_nodes::tenant_id,
    task_nodes::id,
    task_nodes::job_id,
    task_nodes::task_key,
    task_nodes::status,
    task_nodes::version,
    task_nodes::created_at,
) = (
    task_nodes::tenant_id,
    task_nodes::id,
    task_nodes::job_id,
    task_nodes::task_key,
    task_nodes::status,
    task_nodes::version,
    task_nodes::created_at,
);

pub(super) async fn insert(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    new: NewTaskNode,
) -> Result<Versioned<TaskNode>, StoreError> {
    if !job_exists(connection, tenant, new.job_id, "insert_task_node").await? {
        return Err(StoreError::NotFound);
    }
    Err(constraint(
        "a task node needs a stage run and a plan artifact, which the port does not carry",
        None,
    ))
}

pub(super) async fn get(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: TaskNodeId,
) -> Result<Versioned<TaskNode>, StoreError> {
    let row: Option<NodeRow> = task_nodes::table
        .filter(task_nodes::tenant_id.eq(tenant_to_column(tenant)))
        .filter(task_nodes::id.eq(task_node_to_column(id)))
        .select(NODE_COLUMNS)
        .first(connection)
        .await
        .optional()
        .map_err(|error| generic("get_task_node", &error))?;
    let Some((tenant_id, id, job, key, status, version, created_at)) = row else {
        return Err(StoreError::NotFound);
    };
    Ok(Versioned {
        value: TaskNode {
            id: task_node_from_column(id),
            tenant_id: tenant_from_column(tenant_id),
            job_id: job_from_column(job),
            key: Slug::parse(&key).map_err(|_| corrupt("task key"))?,
            status: status_from_column::<TaskNodeStatus>(&status)?,
            created_at: from_column(created_at),
        },
        version: version_from_column(version)?,
    })
}

pub(super) async fn transition(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: TaskNodeId,
    expected: Version,
    plan: AppliedTransition<TaskNodeStatus>,
) -> Result<Version, StoreError> {
    let current = match lock(
        connection,
        Machine::TaskNode,
        tenant_to_column(tenant),
        task_node_to_column(id),
        "transition_task_node",
    )
    .await?
    {
        Locked::Missing => return Err(StoreError::NotFound),
        Locked::Busy => return Err(StoreError::Conflict),
        Locked::Row { status, version } => (status, version),
    };
    if current.1 != expected.get() || current.0 != plan.from_status().to_string() {
        return Err(StoreError::Conflict);
    }
    let next = expected.next().map_err(|_| corrupt("version"))?;
    let finishes = plan.to_status().is_terminal();
    let retries = plan.transition_id() == "T06";
    let changed = sql_query(
        "UPDATE task_nodes SET status = $4, version = $5, \
                finished_at = CASE WHEN $6 THEN $7 ELSE finished_at END, \
                retry_count = retry_count + $8 \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = $9",
    )
    .bind::<SqlUuid, _>(tenant_to_column(tenant))
    .bind::<SqlUuid, _>(task_node_to_column(id))
    .bind::<BigInt, _>(expected.get())
    .bind::<Text, _>(plan.to_status().to_string())
    .bind::<BigInt, _>(next.get())
    .bind::<Bool, _>(finishes)
    .bind::<Timestamptz, _>(to_column(&plan.at()))
    .bind::<diesel::sql_types::SmallInt, _>(i16::from(retries))
    .bind::<Text, _>(plan.from_status().to_string())
    .execute(connection)
    .await
    .map_err(|error| match Failure::of(&error) {
        Failure::Check(name) => constraint("check violation", name.as_deref()),
        _ => generic("transition_task_node", &error),
    })?;
    if changed == 1 {
        Ok(next)
    } else {
        Err(StoreError::Conflict)
    }
}
