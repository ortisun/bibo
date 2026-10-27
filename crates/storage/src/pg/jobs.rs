//! Jobs.
//!
//! # What the port cannot carry
//!
//! The port's `NewJob` holds an id, a correlation id, a requester and a creation time. The `jobs`
//! table also requires a repository, an execution mode, an autonomy level and a pipeline scope.
//! Until the port carries them (the handover report lists this), a new job takes:
//!
//! * the **repository** of the tenant: its oldest enabled one. A tenant with none cannot get a
//!   job (`Constraint`);
//! * the **execution mode** of the process, the **autonomy level** and the **pipeline scope** from
//!   [`super::config::JobDefaults`].

use diesel::prelude::*;
use diesel::sql_query;
use diesel::sql_types::{Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::{JobId, TenantId};
use factory_domain::state::{JobStatus, Status};
use factory_ports::store::{AppliedTransition, Job, NewJob, StoreError, Version, Versioned};
use time::OffsetDateTime;
use uuid::Uuid;

use super::cas::{Locked, Machine, exists, lock};
use super::conv::{
    correlation_from_column, correlation_to_column, corrupt, from_column, job_from_column,
    job_to_column, principal_from_column, principal_to_column, status_from_column,
    tenant_from_column, tenant_to_column, to_column, version_from_column,
};
use super::error::{Failure, constraint, generic};
use super::store::Settings;
use crate::schema::{jobs, repositories};

type JobRow = (Uuid, Uuid, Uuid, Uuid, String, i64, OffsetDateTime);

const JOB_COLUMNS: (
    jobs::tenant_id,
    jobs::id,
    jobs::correlation_id,
    jobs::requester_principal_id,
    jobs::status,
    jobs::version,
    jobs::created_at,
) = (
    jobs::tenant_id,
    jobs::id,
    jobs::correlation_id,
    jobs::requester_principal_id,
    jobs::status,
    jobs::version,
    jobs::created_at,
);

fn job_from_row(row: JobRow) -> Result<Versioned<Job>, StoreError> {
    let (tenant, id, correlation, requester, status, version, created_at) = row;
    Ok(Versioned {
        value: Job {
            id: job_from_column(id),
            tenant_id: tenant_from_column(tenant),
            correlation_id: correlation_from_column(correlation),
            requester: principal_from_column(requester),
            status: status_from_column::<JobStatus>(&status)?,
            created_at: from_column(created_at),
        },
        version: version_from_column(version)?,
    })
}

pub(super) async fn insert(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    settings: &Settings,
    new: NewJob,
) -> Result<Versioned<Job>, StoreError> {
    let repository: Option<Uuid> = repositories::table
        .filter(repositories::tenant_id.eq(tenant_to_column(tenant)))
        .filter(repositories::enabled.eq(true))
        .order((repositories::created_at.asc(), repositories::id.asc()))
        .select(repositories::id)
        .first(connection)
        .await
        .optional()
        .map_err(|error| generic("insert_job", &error))?;
    let Some(repository) = repository else {
        return Err(constraint("the tenant has no enabled repository", None));
    };
    let scope: Vec<Option<String>> = settings
        .pipeline_scope
        .iter()
        .map(|kind| Some(kind.as_str().to_owned()))
        .collect();
    let inserted = diesel::insert_into(jobs::table)
        .values((
            jobs::tenant_id.eq(tenant_to_column(tenant)),
            jobs::id.eq(job_to_column(new.id)),
            jobs::repository_id.eq(repository),
            jobs::requester_principal_id.eq(principal_to_column(new.requester)),
            jobs::status.eq(JobStatus::INITIAL.to_string()),
            jobs::execution_mode.eq(settings.execution_mode.as_str()),
            jobs::autonomy_level.eq(settings.autonomy_level),
            jobs::pipeline_scope.eq(scope),
            jobs::correlation_id.eq(correlation_to_column(new.correlation_id)),
            jobs::created_at.eq(to_column(&new.created_at)),
        ))
        .execute(connection)
        .await;
    if let Err(error) = inserted {
        return Err(match Failure::of(&error) {
            Failure::Unique(name) => constraint("unique violation", name.as_deref()),
            Failure::ForeignKey(name) => constraint("foreign key violation", name.as_deref()),
            _ => generic("insert_job", &error),
        });
    }
    get(connection, tenant, new.id).await
}

pub(super) async fn get(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: JobId,
) -> Result<Versioned<Job>, StoreError> {
    let row: Option<JobRow> = jobs::table
        .filter(jobs::tenant_id.eq(tenant_to_column(tenant)))
        .filter(jobs::id.eq(job_to_column(id)))
        .select(JOB_COLUMNS)
        .first(connection)
        .await
        .optional()
        .map_err(|error| generic("get_job", &error))?;
    row.map_or(Err(StoreError::NotFound), job_from_row)
}

/// True when the tenant has the job.
pub(super) async fn job_exists(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: JobId,
    operation: &'static str,
) -> Result<bool, StoreError> {
    exists(
        connection,
        Machine::Job,
        tenant_to_column(tenant),
        job_to_column(id),
        operation,
    )
    .await
}

pub(super) async fn transition(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: JobId,
    expected: Version,
    plan: AppliedTransition<JobStatus>,
) -> Result<Version, StoreError> {
    let current = match lock(
        connection,
        Machine::Job,
        tenant_to_column(tenant),
        job_to_column(id),
        "transition_job",
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
    let finished = plan
        .to_status()
        .is_terminal()
        .then(|| to_column(&plan.at()));
    let changed = sql_query(
        "UPDATE jobs SET status = $4, version = $5, terminal_at = $6 \
         WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = $7",
    )
    .bind::<SqlUuid, _>(tenant_to_column(tenant))
    .bind::<SqlUuid, _>(job_to_column(id))
    .bind::<diesel::sql_types::BigInt, _>(expected.get())
    .bind::<Text, _>(plan.to_status().to_string())
    .bind::<diesel::sql_types::BigInt, _>(next.get())
    .bind::<Nullable<Timestamptz>, _>(finished)
    .bind::<Text, _>(plan.from_status().to_string())
    .execute(connection)
    .await
    .map_err(|error| match Failure::of(&error) {
        Failure::Check(name) => constraint("check violation", name.as_deref()),
        _ => generic("transition_job", &error),
    })?;
    if changed == 1 {
        Ok(next)
    } else {
        Err(StoreError::Conflict)
    }
}
