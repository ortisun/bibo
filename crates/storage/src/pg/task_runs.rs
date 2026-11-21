//! The runs of the builder on the task nodes of a stage run (ports v1.5).
//!
//! One row for each time an attempt ran the builder on a task node: the runtime, the model and
//! the tier the router chose, and what the model broker metered for that run. A row is written
//! once. The login of the store holds `INSERT` and `SELECT` on the table and nothing else, so no
//! statement can change or remove one.
//!
//! # The fence
//!
//! The write carries the fence of the attempt that ran the task, as the moves of a task node do
//! (`T02` to `T05`): the attempt must be live, held by that worker, at that epoch. A worker that
//! lost its lease records nothing.
//!
//! # What is checked before the write
//!
//! The length of the model name, the fence, that the task node belongs to the stage run of the
//! attempt, and whether the row is there already. Each is a read, so a refusal leaves the
//! transaction usable. The foreign keys of the table say the same as the last line.

use async_trait::async_trait;
use diesel::sql_types::{BigInt, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::ids::{AttemptId, JobId, StageRunId, TaskNodeId, TenantId};
use factory_domain::values::NonEmptyString;
use factory_ports::agent::RuntimeId;
use factory_ports::store::{ConstraintRule, Fence, NewTaskRun, StoreError, TaskRun, TaskRunOps};
use time::OffsetDateTime;
use uuid::Uuid;

use super::cas::{Table, exists};
use super::conv::{corrupt, from_column, metered_from_columns, metered_to_columns};
use super::error::database;
use super::task_nodes::fence_is_current;
use super::tx::{PgTx, call};

/// The longest model name the table keeps (`task_runs.model`).
const MODEL_MAX_CHARS: usize = 200;

const COLUMNS: &str = "tenant_id, task_node_id, attempt_id, job_id, stage_run_id, runtime, model, \
    model_tier, input_tokens, output_tokens, cost_micro_usd, model_requests, recorded_at";

#[derive(QueryableByName)]
struct RunRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    task_node_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    attempt_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    job_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    stage_run_id: Uuid,
    #[diesel(sql_type = Text)]
    runtime: String,
    #[diesel(sql_type = Text)]
    model: String,
    #[diesel(sql_type = Text)]
    model_tier: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    input_tokens: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    output_tokens: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    cost_micro_usd: Option<i64>,
    #[diesel(sql_type = Nullable<BigInt>)]
    model_requests: Option<i64>,
    #[diesel(sql_type = Timestamptz)]
    recorded_at: OffsetDateTime,
}

fn run_from_row(row: RunRow) -> Result<TaskRun, StoreError> {
    Ok(TaskRun {
        tenant_id: TenantId::from_uuid(row.tenant_id),
        job_id: JobId::from_uuid(row.job_id),
        stage_run_id: StageRunId::from_uuid(row.stage_run_id),
        task_node_id: TaskNodeId::from_uuid(row.task_node_id),
        attempt_id: AttemptId::from_uuid(row.attempt_id),
        runtime: RuntimeId::new(&row.runtime).map_err(|_| corrupt("runtime"))?,
        model: NonEmptyString::parse(&row.model).map_err(|_| corrupt("model"))?,
        tier: RecommendedTier::parse(&row.model_tier).map_err(|_| corrupt("model tier"))?,
        metered: metered_from_columns(
            row.input_tokens,
            row.output_tokens,
            row.cost_micro_usd,
            row.model_requests,
        )?,
        recorded_at: from_column(row.recorded_at),
    })
}

/// Where a task node and an attempt stand, to see that they belong together.
#[derive(QueryableByName)]
struct Place {
    #[diesel(sql_type = SqlUuid)]
    job_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    stage_run_id: Uuid,
}

async fn record(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    by: Fence,
    run: NewTaskRun,
) -> Result<(), StoreError> {
    let operation = "record_task_run";
    if run.model.as_str().chars().count() > MODEL_MAX_CHARS {
        return Err(StoreError::Constraint(ConstraintRule::TextBounds));
    }
    if !fence_is_current(connection, tenant, &by).await? {
        return Err(StoreError::LeaseFenced);
    }
    // The task node must be one of the stage run the attempt of the fence works on.
    let place = sql_query(
        "SELECT n.job_id, n.stage_run_id FROM task_nodes n \
           JOIN attempts a ON a.tenant_id = n.tenant_id AND a.stage_run_id = n.stage_run_id \
          WHERE n.tenant_id = $1 AND n.id = $2 AND a.id = $3",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(run.task_node.as_uuid())
    .bind::<SqlUuid, _>(by.attempt.as_uuid())
    .get_result::<Place>(connection)
    .await
    .optional()
    .map_err(|error| database(operation, &error))?
    .ok_or(StoreError::NotFound)?;

    let existing = sql_query(format!(
        "SELECT {COLUMNS} FROM task_runs \
          WHERE tenant_id = $1 AND task_node_id = $2 AND attempt_id = $3"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(run.task_node.as_uuid())
    .bind::<SqlUuid, _>(by.attempt.as_uuid())
    .get_result::<RunRow>(connection)
    .await
    .optional()
    .map_err(|error| database(operation, &error))?;
    if let Some(row) = existing {
        let stored = run_from_row(row)?;
        let same = stored.runtime == run.runtime
            && stored.model == run.model
            && stored.tier == run.tier
            && stored.metered == run.metered;
        return if same {
            Ok(())
        } else {
            Err(StoreError::Constraint(
                ConstraintRule::IdReusedWithDifferentContent,
            ))
        };
    }

    let [input_tokens, output_tokens, cost_micro_usd, model_requests] =
        metered_to_columns(run.metered);
    sql_query(
        "INSERT INTO task_runs (tenant_id, task_node_id, attempt_id, job_id, stage_run_id, runtime, \
                                model, model_tier, input_tokens, output_tokens, cost_micro_usd, \
                                model_requests) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(run.task_node.as_uuid())
    .bind::<SqlUuid, _>(by.attempt.as_uuid())
    .bind::<SqlUuid, _>(place.job_id)
    .bind::<SqlUuid, _>(place.stage_run_id)
    .bind::<Text, _>(run.runtime.as_str())
    .bind::<Text, _>(run.model.as_str())
    .bind::<Text, _>(run.tier.as_str())
    .bind::<Nullable<BigInt>, _>(input_tokens)
    .bind::<Nullable<BigInt>, _>(output_tokens)
    .bind::<Nullable<BigInt>, _>(cost_micro_usd)
    .bind::<Nullable<BigInt>, _>(model_requests)
    .execute(connection)
    .await
    .map_err(|error| database(operation, &error))?;
    Ok(())
}

async fn list(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    stage_run: StageRunId,
) -> Result<Vec<TaskRun>, StoreError> {
    let operation = "list_task_runs";
    let rows = sql_query(format!(
        "SELECT {COLUMNS} FROM task_runs WHERE tenant_id = $1 AND stage_run_id = $2 \
          ORDER BY recorded_at, attempt_id, task_node_id"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(stage_run.as_uuid())
    .load::<RunRow>(connection)
    .await
    .map_err(|error| database(operation, &error))?;
    // No row can mean no run yet, or a stage run that is not the tenant's: the two must not look
    // the same (NT-TEN-05).
    if rows.is_empty()
        && !exists(
            connection,
            Table::StageRuns,
            tenant,
            stage_run.as_uuid(),
            operation,
        )
        .await?
    {
        return Err(StoreError::NotFound);
    }
    rows.into_iter().map(run_from_row).collect()
}

#[async_trait]
impl TaskRunOps for PgTx {
    async fn record_task_run(&mut self, by: Fence, run: NewTaskRun) -> Result<(), StoreError> {
        call!(self, connection, tenant => record(connection, tenant, by, run))
    }

    async fn list_task_runs(&mut self, stage_run: StageRunId) -> Result<Vec<TaskRun>, StoreError> {
        call!(self, connection, tenant => list(connection, tenant, stage_run))
    }
}
