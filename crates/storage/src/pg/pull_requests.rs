//! The pull requests the factory opened, and what became of them (ports v1.5).
//!
//! The delivery stage opens a draft pull request, and the engine records it here in the
//! transaction that records the attempt. A person merges or closes it later, and a step of the
//! worker reads that from the code host and records the sighting.
//!
//! # The first decision is final
//!
//! A sighting sets the fate only while the row is still open. The statement says so
//! (`fate = 'open'` in every `CASE`), and the trigger `pull_requests_guard` refuses any other
//! statement that tries. The time of the look is set by every sighting.
//!
//! # Two clocks
//!
//! `decided_at` is the time the code host gives for the merge or the close. `opened_at`,
//! `fate_recorded_at` and `last_checked_at` are the database's clock. A snapshot of the process
//! metrics cuts its window by `fate_recorded_at`, never by `decided_at`.

use async_trait::async_trait;
use diesel::sql_types::{BigInt, Bool, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::{JobId, RepositoryId, TenantId};
use factory_domain::values::Timestamp;
use factory_ports::store::{
    ConstraintRule, MAX_METERED, NewPullRequest, PullRequestOps, PullRequestRecord,
    PullRequestSighting, StoreError, StoredFate,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::cas::{Table, exists};
use super::conv::{corrupt, from_column, signed_to_column};
use super::error::database;
use super::tx::{PgTx, call};

const COLUMNS: &str = "tenant_id, repository_id, pr_number, job_id, opened_at, fate, decided_at, \
    fate_recorded_at, last_checked_at";

#[derive(QueryableByName)]
struct PullRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    repository_id: Uuid,
    #[diesel(sql_type = BigInt)]
    pr_number: i64,
    #[diesel(sql_type = SqlUuid)]
    job_id: Uuid,
    #[diesel(sql_type = Timestamptz)]
    opened_at: OffsetDateTime,
    #[diesel(sql_type = Text)]
    fate: String,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    decided_at: Option<OffsetDateTime>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    fate_recorded_at: Option<OffsetDateTime>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    last_checked_at: Option<OffsetDateTime>,
}

fn record_from_row(row: PullRow) -> Result<PullRequestRecord, StoreError> {
    let fate = match (row.fate.as_str(), row.decided_at, row.fate_recorded_at) {
        ("open", None, None) => StoredFate::Open,
        ("merged", Some(decided), Some(recorded)) => StoredFate::Merged {
            decided_at: from_column(decided),
            recorded_at: from_column(recorded),
        },
        ("closed", Some(decided), Some(recorded)) => StoredFate::Closed {
            decided_at: from_column(decided),
            recorded_at: from_column(recorded),
        },
        _ => return Err(corrupt("pull request fate")),
    };
    Ok(PullRequestRecord {
        tenant_id: TenantId::from_uuid(row.tenant_id),
        job_id: JobId::from_uuid(row.job_id),
        repository: RepositoryId::from_uuid(row.repository_id),
        number: u64::try_from(row.pr_number).map_err(|_| corrupt("pull request number"))?,
        opened_at: from_column(row.opened_at),
        fate,
        last_checked_at: row.last_checked_at.map(from_column),
    })
}

/// The number as the column type, or `TextBounds` for a number the table refuses.
fn number_to_column(number: u64) -> Result<i64, StoreError> {
    if number == 0 || number > MAX_METERED {
        return Err(StoreError::Constraint(ConstraintRule::TextBounds));
    }
    Ok(signed_to_column(number))
}

#[derive(QueryableByName)]
struct Owner {
    #[diesel(sql_type = SqlUuid)]
    job_id: Uuid,
}

#[derive(QueryableByName)]
struct Found {
    #[diesel(sql_type = Bool)]
    found: bool,
}

async fn record_opened(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    new: NewPullRequest,
) -> Result<(), StoreError> {
    let operation = "record_pull_request_opened";
    let number = number_to_column(new.number)?;
    // The job must be the tenant's, and the repository the job's.
    let job = sql_query(
        "SELECT EXISTS (SELECT 1 FROM jobs \
                         WHERE tenant_id = $1 AND id = $2 AND repository_id = $3) AS found",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(new.job.as_uuid())
    .bind::<SqlUuid, _>(new.repository.as_uuid())
    .get_result::<Found>(connection)
    .await
    .map_err(|error| database(operation, &error))?;
    if !job.found {
        return Err(StoreError::NotFound);
    }
    // ON CONFLICT DO NOTHING makes two writers of one pull request take turns without an error
    // of the database; the read after it says whose row it is.
    sql_query(
        "INSERT INTO pull_requests (tenant_id, repository_id, pr_number, job_id) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, repository_id, pr_number) DO NOTHING",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(new.repository.as_uuid())
    .bind::<BigInt, _>(number)
    .bind::<SqlUuid, _>(new.job.as_uuid())
    .execute(connection)
    .await
    .map_err(|error| database(operation, &error))?;
    let owner = sql_query(
        "SELECT job_id FROM pull_requests \
          WHERE tenant_id = $1 AND repository_id = $2 AND pr_number = $3",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(new.repository.as_uuid())
    .bind::<BigInt, _>(number)
    .get_result::<Owner>(connection)
    .await
    .map_err(|error| database(operation, &error))?;
    if owner.job_id == new.job.as_uuid() {
        Ok(())
    } else {
        Err(StoreError::Constraint(
            ConstraintRule::IdReusedWithDifferentContent,
        ))
    }
}

async fn list_of_job(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    job: JobId,
) -> Result<Vec<PullRequestRecord>, StoreError> {
    let operation = "list_pull_requests";
    let rows = sql_query(format!(
        "SELECT {COLUMNS} FROM pull_requests WHERE tenant_id = $1 AND job_id = $2 \
          ORDER BY opened_at, pr_number"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(job.as_uuid())
    .load::<PullRow>(connection)
    .await
    .map_err(|error| database(operation, &error))?;
    // No row can mean no pull request yet, or a job that is not the tenant's: the two must not
    // look the same (NT-TEN-05).
    if rows.is_empty() && !exists(connection, Table::Jobs, tenant, job.as_uuid(), operation).await?
    {
        return Err(StoreError::NotFound);
    }
    rows.into_iter().map(record_from_row).collect()
}

async fn list_to_check(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    before: Timestamp,
    limit: u32,
) -> Result<Vec<PullRequestRecord>, StoreError> {
    sql_query(format!(
        "SELECT {COLUMNS} FROM pull_requests \
          WHERE tenant_id = $1 AND fate = 'open' \
            AND (last_checked_at IS NULL OR last_checked_at < $2) \
          ORDER BY last_checked_at NULLS FIRST, opened_at, repository_id, pr_number \
          LIMIT $3"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<Timestamptz, _>(before.to_utc())
    .bind::<BigInt, _>(i64::from(limit))
    .load::<PullRow>(connection)
    .await
    .map_err(|error| database("list_pull_requests_to_check", &error))?
    .into_iter()
    .map(record_from_row)
    .collect()
}

async fn record_sighting(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    repository: RepositoryId,
    number: u64,
    sighting: PullRequestSighting,
) -> Result<PullRequestRecord, StoreError> {
    // A number the table cannot hold names no row.
    let Ok(number) = number_to_column(number) else {
        return Err(StoreError::NotFound);
    };
    let (fate, decided_at) = match sighting {
        PullRequestSighting::Open | PullRequestSighting::Unread => (None, None),
        PullRequestSighting::Merged(at) => (Some("merged"), Some(at.to_utc())),
        PullRequestSighting::Closed(at) => (Some("closed"), Some(at.to_utc())),
    };
    // Every right-hand side reads the row as it was before the statement, so the three columns of
    // the fate change together or not at all.
    sql_query(format!(
        "UPDATE pull_requests SET last_checked_at = now(), \
                fate = CASE WHEN fate = 'open' AND $4::text IS NOT NULL THEN $4 ELSE fate END, \
                decided_at = CASE WHEN fate = 'open' AND $4::text IS NOT NULL THEN $5 \
                                  ELSE decided_at END, \
                fate_recorded_at = CASE WHEN fate = 'open' AND $4::text IS NOT NULL THEN now() \
                                        ELSE fate_recorded_at END \
          WHERE tenant_id = $1 AND repository_id = $2 AND pr_number = $3 \
          RETURNING {COLUMNS}"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(repository.as_uuid())
    .bind::<BigInt, _>(number)
    .bind::<Nullable<Text>, _>(fate)
    .bind::<Nullable<Timestamptz>, _>(decided_at)
    .get_result::<PullRow>(connection)
    .await
    .optional()
    .map_err(|error| database("record_pull_request_sighting", &error))?
    .ok_or(StoreError::NotFound)
    .and_then(record_from_row)
}

#[async_trait]
impl PullRequestOps for PgTx {
    async fn record_pull_request_opened(&mut self, new: NewPullRequest) -> Result<(), StoreError> {
        call!(self, connection, tenant => record_opened(connection, tenant, new))
    }

    async fn list_pull_requests(
        &mut self,
        job: JobId,
    ) -> Result<Vec<PullRequestRecord>, StoreError> {
        call!(self, connection, tenant => list_of_job(connection, tenant, job))
    }

    async fn list_pull_requests_to_check(
        &mut self,
        before: Timestamp,
        limit: u32,
    ) -> Result<Vec<PullRequestRecord>, StoreError> {
        call!(self, connection, tenant => list_to_check(connection, tenant, before, limit))
    }

    async fn record_pull_request_sighting(
        &mut self,
        repository: RepositoryId,
        number: u64,
        sighting: PullRequestSighting,
    ) -> Result<PullRequestRecord, StoreError> {
        call!(self, connection, tenant => {
            record_sighting(connection, tenant, repository, number, sighting)
        })
    }
}
