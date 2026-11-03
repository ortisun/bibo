//! Jobs, original requests, webhook deliveries and the repository record.
//!
//! # Idempotent inserts
//!
//! An insert is `INSERT ... ON CONFLICT DO NOTHING RETURNING ...`. A row back means the row is new.
//! No row back means a unique key was taken, and the code reads the row it clashed with and
//! decides: the same id and content is a replay (`created: false`), a job with the same origin
//! under another id is the first job (`created: false`), and anything else is
//! `Constraint(IdReusedWithDifferentContent)`. No database error is raised on the way, so the
//! transaction stays usable.
//!
//! # What the database computes
//!
//! `created_at` and `terminal_at` come from `now()` in the statement. The caller's clock is never
//! written (`AppliedTransition::at` is the engine's plan, not a column).

use async_trait::async_trait;
use diesel::sql_types::{
    Array, BigInt, Bool, Integer, Nullable, Text, Timestamptz, Uuid as SqlUuid,
};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::{
    CorrelationId, JobId, PrincipalId, RepositoryId, TenantId, WebhookDeliveryId,
};
use factory_domain::state::{JobStatus, Status};
use factory_domain::vocabulary::{AutonomyLevel, ExecutionMode, StageKind};
use factory_ports::store::{
    AppliedTransition, ConstraintRule, DeliveryOps, DeliveryOutcome, DuplicateOf, EnabledFor,
    IdempotencyKey, Inserted, Job, JobFacts, JobFilter, JobOps, JobOrigin, NewJob,
    NewOriginalRequest, NewRepository, NewWebhookDelivery, OriginalRequest, Page, PageCursor,
    PipelineScope, ProjectMapAttestation, ProjectMapCommit, RepositoryOps, RequestOps,
    RequestSource, StoreError, Version, Versioned,
};
use factory_ports::store::{GithubRepositoryId, InstallationId, Repository};
use time::OffsetDateTime;
use uuid::Uuid;

use super::cas::{Table, no_row_changed};
use super::conv::{
    corrupt, digest_from_column, from_column, status_from_column, unsigned_from_column,
    version_from_column,
};
use super::error::database;
use super::tx::{PgTx, call};

fn id_reused() -> StoreError {
    StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent)
}

// ---------------------------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------------------------

const JOB_COLUMNS: &str = "tenant_id, id, repository_id, requester_principal_id, status, version, \
    execution_mode, autonomy_level, pipeline_scope, correlation_id, idempotency_key, \
    webhook_delivery_id, policy_hash, normalized_request_sha256, created_at, terminal_at";

#[derive(QueryableByName)]
struct JobRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    repository_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    requester_principal_id: Uuid,
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = Text)]
    execution_mode: String,
    #[diesel(sql_type = Text)]
    autonomy_level: String,
    #[diesel(sql_type = Array<Nullable<Text>>)]
    pipeline_scope: Vec<Option<String>>,
    #[diesel(sql_type = SqlUuid)]
    correlation_id: Uuid,
    #[diesel(sql_type = Nullable<Text>)]
    idempotency_key: Option<String>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    webhook_delivery_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Text>)]
    policy_hash: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    normalized_request_sha256: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: OffsetDateTime,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    terminal_at: Option<OffsetDateTime>,
}

fn job_from_row(row: JobRow) -> Result<Versioned<Job>, StoreError> {
    let kinds = row
        .pipeline_scope
        .iter()
        .map(|kind| {
            kind.as_deref()
                .and_then(|name| StageKind::parse(name).ok())
                .ok_or_else(|| corrupt("pipeline scope"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let origin = match (row.webhook_delivery_id, row.idempotency_key.as_deref()) {
        (Some(delivery), _) => Some(JobOrigin::Webhook(WebhookDeliveryId::from_uuid(delivery))),
        (None, Some(key)) => Some(JobOrigin::Request(
            IdempotencyKey::new(key).map_err(|_| corrupt("idempotency key"))?,
        )),
        (None, None) => None,
    };
    Ok(Versioned {
        value: Job {
            id: JobId::from_uuid(row.id),
            tenant_id: TenantId::from_uuid(row.tenant_id),
            correlation_id: CorrelationId::from_uuid(row.correlation_id),
            repository: RepositoryId::from_uuid(row.repository_id),
            requester: PrincipalId::from_uuid(row.requester_principal_id),
            status: status_from_column::<JobStatus>(&row.status)?,
            execution_mode: ExecutionMode::parse(&row.execution_mode)
                .map_err(|_| corrupt("execution mode"))?,
            autonomy_level: AutonomyLevel::parse(&row.autonomy_level)
                .map_err(|_| corrupt("autonomy level"))?,
            pipeline_scope: PipelineScope::new(kinds).map_err(|_| corrupt("pipeline scope"))?,
            origin,
            policy_hash: row
                .policy_hash
                .as_deref()
                .map(digest_from_column)
                .transpose()?,
            normalized_request: row
                .normalized_request_sha256
                .as_deref()
                .map(digest_from_column)
                .transpose()?,
            created_at: from_column(row.created_at),
            terminal_at: row.terminal_at.map(from_column),
        },
        version: version_from_column(row.version)?,
    })
}

async fn find_job(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: JobId,
) -> Result<Option<Versioned<Job>>, StoreError> {
    sql_query(format!(
        "SELECT {JOB_COLUMNS} FROM jobs WHERE tenant_id = $1 AND id = $2"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .get_result::<JobRow>(connection)
    .await
    .optional()
    .map_err(|error| database("get_job", &error))?
    .map(job_from_row)
    .transpose()
}

/// The job that was made for this origin, if one was.
async fn find_job_by_origin(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    origin: &JobOrigin,
) -> Result<Option<Versioned<Job>>, StoreError> {
    let row =
        match origin {
            JobOrigin::Webhook(delivery) => sql_query(format!(
                "SELECT {JOB_COLUMNS} FROM jobs WHERE tenant_id = $1 AND webhook_delivery_id = $2"
            ))
            .bind::<SqlUuid, _>(tenant.as_uuid())
            .bind::<SqlUuid, _>(delivery.as_uuid())
            .get_result::<JobRow>(connection)
            .await,
            JobOrigin::Request(key) => {
                sql_query(format!(
                    "SELECT {JOB_COLUMNS} FROM jobs WHERE tenant_id = $1 AND idempotency_key = $2"
                ))
                .bind::<SqlUuid, _>(tenant.as_uuid())
                .bind::<Text, _>(key.as_str())
                .get_result::<JobRow>(connection)
                .await
            }
        }
        .optional()
        .map_err(|error| database("insert_job", &error))?;
    row.map(job_from_row).transpose()
}

/// True when the stored job is the job the caller offered. The status, the version and the times
/// are not compared: they move after the insert.
fn same_job(stored: &Job, new: &NewJob) -> bool {
    stored.repository == new.repository
        && stored.requester == new.requester
        && stored.correlation_id == new.correlation_id
        && stored.execution_mode == new.execution_mode
        && stored.autonomy_level == new.autonomy_level
        && stored.pipeline_scope == new.pipeline_scope
        && stored.origin == new.origin
}

async fn insert_job(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    new: NewJob,
) -> Result<Inserted<Job>, StoreError> {
    let scope: Vec<String> = new
        .pipeline_scope
        .kinds()
        .iter()
        .map(|kind| kind.as_str().to_owned())
        .collect();
    let (key, delivery) = match &new.origin {
        Some(JobOrigin::Request(key)) => (Some(key.as_str().to_owned()), None),
        Some(JobOrigin::Webhook(delivery)) => (None, Some(delivery.as_uuid())),
        None => (None, None),
    };
    let inserted = sql_query(format!(
        "INSERT INTO jobs (tenant_id, id, repository_id, requester_principal_id, status, \
                execution_mode, autonomy_level, pipeline_scope, correlation_id, idempotency_key, \
                webhook_delivery_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
         ON CONFLICT DO NOTHING RETURNING {JOB_COLUMNS}"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(new.id.as_uuid())
    .bind::<SqlUuid, _>(new.repository.as_uuid())
    .bind::<SqlUuid, _>(new.requester.as_uuid())
    .bind::<Text, _>(JobStatus::INITIAL.to_string())
    .bind::<Text, _>(new.execution_mode.as_str())
    .bind::<Text, _>(new.autonomy_level.as_str())
    .bind::<Array<Text>, _>(scope)
    .bind::<SqlUuid, _>(new.correlation_id.as_uuid())
    .bind::<Nullable<Text>, _>(key)
    .bind::<Nullable<SqlUuid>, _>(delivery)
    .get_result::<JobRow>(connection)
    .await
    .optional()
    .map_err(|error| database("insert_job", &error))?;
    if let Some(row) = inserted {
        return Ok(Inserted {
            row: job_from_row(row)?,
            created: true,
        });
    }
    // A unique key was taken. By the id: a replay, or a reuse of the id.
    if let Some(found) = find_job(connection, tenant, new.id).await? {
        return if same_job(&found.value, &new) {
            Ok(Inserted {
                row: found,
                created: false,
            })
        } else {
            Err(id_reused())
        };
    }
    // By the origin: the first job made for it, under another id.
    if let Some(origin) = &new.origin
        && let Some(first) = find_job_by_origin(connection, tenant, origin).await?
    {
        return Ok(Inserted {
            row: first,
            created: false,
        });
    }
    // The clash was on the correlation id alone, and the id was never used.
    Err(id_reused())
}

/// A listing position: the creation time in microseconds and the id of the last row of a page.
fn cursor_for(job: &Job) -> PageCursor {
    let micros = job.created_at.to_utc().unix_timestamp_nanos() / 1_000;
    PageCursor::new(format!("{micros}:{}", job.id.as_uuid().hyphenated()))
}

fn parse_cursor(cursor: &PageCursor) -> Result<(OffsetDateTime, Uuid), StoreError> {
    let bad = || StoreError::Constraint(ConstraintRule::TextBounds);
    let (micros, id) = cursor.as_str().split_once(':').ok_or_else(bad)?;
    let micros: i128 = micros.parse().map_err(|_| bad())?;
    let at = OffsetDateTime::from_unix_timestamp_nanos(micros * 1_000).map_err(|_| bad())?;
    Ok((at, Uuid::parse_str(id).map_err(|_| bad())?))
}

async fn list_jobs(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    filter: JobFilter,
    after: Option<PageCursor>,
    limit: u32,
) -> Result<Page<Versioned<Job>>, StoreError> {
    let statuses: Vec<String> = filter.statuses.iter().map(ToString::to_string).collect();
    let (after_at, after_id) = match after.as_ref().map(parse_cursor).transpose()? {
        Some((at, id)) => (Some(at), Some(id)),
        None => (None, None),
    };
    // One more row than asked for says whether there is a next page.
    let rows = sql_query(format!(
        "SELECT {JOB_COLUMNS} FROM jobs \
          WHERE tenant_id = $1 \
            AND (cardinality($2::text[]) = 0 OR status = ANY($2)) \
            AND ($3::uuid IS NULL OR repository_id = $3) \
            AND ($4::timestamptz IS NULL OR (created_at, id) < ($4, $5::uuid)) \
          ORDER BY created_at DESC, id DESC LIMIT $6"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<Array<Text>, _>(statuses)
    .bind::<Nullable<SqlUuid>, _>(filter.repository.map(|repository| repository.as_uuid()))
    .bind::<Nullable<Timestamptz>, _>(after_at)
    .bind::<Nullable<SqlUuid>, _>(after_id)
    .bind::<BigInt, _>(i64::from(limit) + 1)
    .load::<JobRow>(connection)
    .await
    .map_err(|error| database("list_jobs", &error))?;
    let mut jobs = rows
        .into_iter()
        .map(job_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let more = jobs.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    jobs.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    let next = if more {
        jobs.last().map(|last| cursor_for(&last.value))
    } else {
        None
    };
    Ok(Page { rows: jobs, next })
}

async fn transition_job(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: JobId,
    expected: Version,
    t: AppliedTransition<JobStatus>,
) -> Result<Version, StoreError> {
    let moved = sql_query(
        "UPDATE jobs SET status = $4, version = version + 1, \
                terminal_at = CASE WHEN $5 THEN now() ELSE terminal_at END \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 AND status = $6 \
          RETURNING version",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .bind::<BigInt, _>(expected.get())
    .bind::<Text, _>(t.to_status().to_string())
    .bind::<Bool, _>(t.to_status().is_terminal())
    .bind::<Text, _>(t.from_status().to_string())
    .get_result::<NewVersion>(connection)
    .await
    .optional()
    .map_err(|error| database("transition_job", &error))?;
    match moved {
        Some(row) => version_from_column(row.version),
        None => Err(no_row_changed(
            connection,
            Table::Jobs,
            tenant,
            id.as_uuid(),
            "transition_job",
        )
        .await?),
    }
}

#[derive(QueryableByName)]
struct NewVersion {
    #[diesel(sql_type = BigInt)]
    version: i64,
}

#[derive(QueryableByName)]
struct FactsRow {
    #[diesel(sql_type = Text)]
    status: String,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = Nullable<Text>)]
    policy_hash: Option<String>,
    #[diesel(sql_type = Nullable<Text>)]
    normalized_request_sha256: Option<String>,
}

async fn update_job_facts(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: JobId,
    expected: Version,
    facts: JobFacts,
) -> Result<Version, StoreError> {
    let current = sql_query(
        "SELECT status, version, policy_hash, normalized_request_sha256 FROM jobs \
          WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .get_result::<FactsRow>(connection)
    .await
    .optional()
    .map_err(|error| database("update_job_facts", &error))?
    .ok_or(StoreError::NotFound)?;
    if current.version != expected.get() {
        return Err(StoreError::Conflict);
    }
    if status_from_column::<JobStatus>(&current.status)?.is_terminal() {
        return Err(StoreError::Constraint(ConstraintRule::TerminalRowImmutable));
    }
    // A fact is written once. The same value again changes nothing; another value is refused.
    let mut changed = false;
    for (have, offered) in [
        (&current.policy_hash, &facts.policy_hash),
        (
            &current.normalized_request_sha256,
            &facts.normalized_request,
        ),
    ] {
        match (have.as_deref(), offered) {
            (_, None) => {}
            (None, Some(_)) => changed = true,
            (Some(have), Some(offered)) if have == offered.as_str() => {}
            (Some(_), Some(_)) => return Err(id_reused()),
        }
    }
    if !changed {
        return version_from_column(current.version);
    }
    let updated = sql_query(
        "UPDATE jobs SET policy_hash = coalesce(policy_hash, $4), \
                normalized_request_sha256 = coalesce(normalized_request_sha256, $5), \
                version = version + 1 \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 RETURNING version",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .bind::<BigInt, _>(expected.get())
    .bind::<Nullable<Text>, _>(
        facts
            .policy_hash
            .as_ref()
            .map(|hash| hash.as_str().to_owned()),
    )
    .bind::<Nullable<Text>, _>(
        facts
            .normalized_request
            .as_ref()
            .map(|hash| hash.as_str().to_owned()),
    )
    .get_result::<NewVersion>(connection)
    .await
    .optional()
    .map_err(|error| database("update_job_facts", &error))?;
    match updated {
        Some(row) => version_from_column(row.version),
        None => Err(StoreError::Conflict),
    }
}

#[async_trait]
impl JobOps for PgTx {
    async fn insert_job(&mut self, new: NewJob) -> Result<Inserted<Job>, StoreError> {
        call!(self, connection, tenant => insert_job(connection, tenant, new))
    }

    async fn get_job(&mut self, id: JobId) -> Result<Versioned<Job>, StoreError> {
        call!(self, connection, tenant => async {
            find_job(connection, tenant, id).await?.ok_or(StoreError::NotFound)
        })
    }

    async fn list_jobs(
        &mut self,
        filter: JobFilter,
        after: Option<PageCursor>,
        limit: u32,
    ) -> Result<Page<Versioned<Job>>, StoreError> {
        call!(self, connection, tenant => list_jobs(connection, tenant, filter, after, limit))
    }

    async fn transition_job(
        &mut self,
        id: JobId,
        expected: Version,
        t: AppliedTransition<JobStatus>,
    ) -> Result<Version, StoreError> {
        call!(self, connection, tenant => transition_job(connection, tenant, id, expected, t))
    }

    async fn update_job_facts(
        &mut self,
        id: JobId,
        expected: Version,
        facts: JobFacts,
    ) -> Result<Version, StoreError> {
        call!(self, connection, tenant => update_job_facts(connection, tenant, id, expected, facts))
    }
}

// ---------------------------------------------------------------------------------------------
// Original requests
// ---------------------------------------------------------------------------------------------

const REQUEST_COLUMNS: &str = "id, job_id, revision, source, source_ref, author_github_user_id, \
    request_text, content_sha256, captured_at";

#[derive(QueryableByName)]
struct RequestRow {
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    job_id: Uuid,
    #[diesel(sql_type = Integer)]
    revision: i32,
    #[diesel(sql_type = Text)]
    source: String,
    #[diesel(sql_type = Nullable<Text>)]
    source_ref: Option<String>,
    #[diesel(sql_type = Nullable<BigInt>)]
    author_github_user_id: Option<i64>,
    #[diesel(sql_type = Text)]
    request_text: String,
    #[diesel(sql_type = Text)]
    content_sha256: String,
    #[diesel(sql_type = Timestamptz)]
    captured_at: OffsetDateTime,
}

const fn source_name(source: RequestSource) -> &'static str {
    match source {
        RequestSource::GithubIssue => "github_issue",
        RequestSource::Api => "api",
        RequestSource::Cli => "cli",
    }
}

fn source_from_column(name: &str) -> Result<RequestSource, StoreError> {
    match name {
        "github_issue" => Ok(RequestSource::GithubIssue),
        "api" => Ok(RequestSource::Api),
        "cli" => Ok(RequestSource::Cli),
        _ => Err(corrupt("request source")),
    }
}

fn request_from_row(row: RequestRow) -> Result<OriginalRequest, StoreError> {
    Ok(OriginalRequest {
        id: row.id,
        job: JobId::from_uuid(row.job_id),
        revision: u32::try_from(row.revision).map_err(|_| corrupt("revision"))?,
        source: source_from_column(&row.source)?,
        source_ref: row.source_ref,
        author_github_user_id: row
            .author_github_user_id
            .map(|id| unsigned_from_column(id, "author"))
            .transpose()?,
        text: row.request_text,
        content_sha256: digest_from_column(&row.content_sha256)?,
        captured_at: from_column(row.captured_at),
    })
}

fn same_request(stored: &OriginalRequest, new: &NewOriginalRequest) -> bool {
    stored.job == new.job
        && stored.revision == new.revision
        && stored.source == new.source
        && stored.source_ref == new.source_ref
        && stored.author_github_user_id == new.author_github_user_id
        && stored.text == new.text
}

async fn record_original_request(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    new: NewOriginalRequest,
) -> Result<Inserted<OriginalRequest>, StoreError> {
    let revision = i32::try_from(new.revision)
        .map_err(|_| StoreError::Constraint(ConstraintRule::TextBounds))?;
    let author = new
        .author_github_user_id
        .map(i64::try_from)
        .transpose()
        .map_err(|_| StoreError::Constraint(ConstraintRule::TextBounds))?;
    // The database refuses a hash that is not the hash of the text, so the hash is of the exact
    // bytes that are stored.
    let hash = factory_domain::values::Sha256Digest::of(new.text.as_bytes());
    let inserted = sql_query(format!(
        "INSERT INTO original_requests (tenant_id, id, job_id, revision, source, source_ref, \
                author_github_user_id, request_text, content_sha256) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (tenant_id, id) DO NOTHING RETURNING {REQUEST_COLUMNS}"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(new.id)
    .bind::<SqlUuid, _>(new.job.as_uuid())
    .bind::<Integer, _>(revision)
    .bind::<Text, _>(source_name(new.source))
    .bind::<Nullable<Text>, _>(new.source_ref.as_deref())
    .bind::<Nullable<BigInt>, _>(author)
    .bind::<Text, _>(new.text.as_str())
    .bind::<Text, _>(hash.as_str())
    .get_result::<RequestRow>(connection)
    .await
    .optional()
    .map_err(|error| database("record_original_request", &error))?;
    if let Some(row) = inserted {
        return Ok(Inserted {
            row: Versioned {
                value: request_from_row(row)?,
                version: Version::FIRST,
            },
            created: true,
        });
    }
    let stored = sql_query(format!(
        "SELECT {REQUEST_COLUMNS} FROM original_requests WHERE tenant_id = $1 AND id = $2"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(new.id)
    .get_result::<RequestRow>(connection)
    .await
    .optional()
    .map_err(|error| database("record_original_request", &error))?
    .map(request_from_row)
    .transpose()?
    .ok_or(StoreError::NotFound)?;
    if same_request(&stored, &new) {
        Ok(Inserted {
            row: Versioned {
                value: stored,
                version: Version::FIRST,
            },
            created: false,
        })
    } else {
        Err(id_reused())
    }
}

async fn get_original_request(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    job: JobId,
    revision: Option<u32>,
) -> Result<OriginalRequest, StoreError> {
    let revision = revision.map(i32::try_from).transpose();
    let Ok(revision) = revision else {
        return Err(StoreError::NotFound);
    };
    sql_query(format!(
        "SELECT {REQUEST_COLUMNS} FROM original_requests \
          WHERE tenant_id = $1 AND job_id = $2 AND ($3::int IS NULL OR revision = $3) \
          ORDER BY revision DESC LIMIT 1"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(job.as_uuid())
    .bind::<Nullable<Integer>, _>(revision)
    .get_result::<RequestRow>(connection)
    .await
    .optional()
    .map_err(|error| database("get_original_request", &error))?
    .map(request_from_row)
    .transpose()?
    .ok_or(StoreError::NotFound)
}

#[async_trait]
impl RequestOps for PgTx {
    async fn record_original_request(
        &mut self,
        new: NewOriginalRequest,
    ) -> Result<Inserted<OriginalRequest>, StoreError> {
        call!(self, connection, tenant => record_original_request(connection, tenant, new))
    }

    async fn get_original_request(
        &mut self,
        job: JobId,
        revision: Option<u32>,
    ) -> Result<OriginalRequest, StoreError> {
        call!(self, connection, tenant => get_original_request(connection, tenant, job, revision))
    }
}

// ---------------------------------------------------------------------------------------------
// Webhook deliveries
// ---------------------------------------------------------------------------------------------

#[derive(QueryableByName)]
struct Which {
    #[diesel(sql_type = Text)]
    key: String,
}

fn column_number(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::Constraint(ConstraintRule::TextBounds))
}

async fn record_delivery(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    new: NewWebhookDelivery,
) -> Result<DeliveryOutcome, StoreError> {
    let installation = column_number(new.installation.0)?;
    let repository = new.repository.map(|id| column_number(id.0)).transpose()?;
    let sender = new.sender_github_user_id.map(column_number).transpose()?;
    let semantic = new.semantic_key.as_ref().map(|key| key.as_str().to_owned());
    // The three unique keys are absorbed by the one `ON CONFLICT DO NOTHING`.
    let inserted = sql_query(
        "INSERT INTO webhook_deliveries (tenant_id, id, delivery_id, event_name, action, \
                github_installation_id, github_repository_id, sender_github_user_id, \
                body_sha256, semantic_key) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT DO NOTHING RETURNING id",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(new.id.as_uuid())
    .bind::<Text, _>(new.delivery_id.as_str())
    .bind::<Text, _>(new.event_name.as_str())
    .bind::<Nullable<Text>, _>(new.action.as_ref().map(|action| action.as_str().to_owned()))
    .bind::<BigInt, _>(installation)
    .bind::<Nullable<BigInt>, _>(repository)
    .bind::<Nullable<BigInt>, _>(sender)
    .bind::<Text, _>(new.body_sha256.as_str())
    .bind::<Nullable<Text>, _>(semantic.clone())
    .execute(connection)
    .await
    .map_err(|error| database("record_delivery", &error))?;
    if inserted == 1 {
        return Ok(DeliveryOutcome::Recorded(new.id));
    }
    // A repeat. One statement says which key found the earlier delivery.
    let found = sql_query(
        "SELECT CASE WHEN delivery_id = $2 THEN 'delivery_id' \
                     WHEN body_sha256 = $3 THEN 'body' ELSE 'semantic' END AS key \
           FROM webhook_deliveries \
          WHERE tenant_id = $1 AND (delivery_id = $2 OR body_sha256 = $3 OR semantic_key = $4) \
          ORDER BY (delivery_id = $2) DESC, (body_sha256 = $3) DESC LIMIT 1",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<Text, _>(new.delivery_id.as_str())
    .bind::<Text, _>(new.body_sha256.as_str())
    .bind::<Nullable<Text>, _>(semantic)
    .get_result::<Which>(connection)
    .await
    .optional()
    .map_err(|error| database("record_delivery", &error))?;
    match found.as_ref().map(|row| row.key.as_str()) {
        Some("delivery_id") => Ok(DeliveryOutcome::Duplicate(DuplicateOf::DeliveryId)),
        Some("body") => Ok(DeliveryOutcome::Duplicate(DuplicateOf::Body)),
        Some(_) => Ok(DeliveryOutcome::Duplicate(DuplicateOf::Semantic)),
        // Only the row id clashed, with a delivery that has none of the three keys.
        None => Err(id_reused()),
    }
}

#[async_trait]
impl DeliveryOps for PgTx {
    async fn record_delivery(
        &mut self,
        new: NewWebhookDelivery,
    ) -> Result<DeliveryOutcome, StoreError> {
        call!(self, connection, tenant => record_delivery(connection, tenant, new))
    }
}

// ---------------------------------------------------------------------------------------------
// Repositories
// ---------------------------------------------------------------------------------------------

#[derive(QueryableByName)]
struct RepositoryRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = BigInt)]
    github_installation_id: i64,
    #[diesel(sql_type = BigInt)]
    github_repository_id: i64,
    #[diesel(sql_type = Text)]
    full_name: String,
    #[diesel(sql_type = Text)]
    default_branch: String,
    #[diesel(sql_type = Bool)]
    enabled: bool,
    #[diesel(sql_type = Bool)]
    protection_preflight_passed: bool,
    #[diesel(sql_type = Text)]
    effective_ceiling: String,
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = Nullable<Text>)]
    project_map_commit: Option<String>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    project_map_attested_by_principal_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    project_map_attested_at: Option<OffsetDateTime>,
    #[diesel(sql_type = Nullable<Text>)]
    enabled_project_map_commit: Option<String>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    enabled_by_principal_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    enabled_at: Option<OffsetDateTime>,
    #[diesel(sql_type = Bool)]
    single_maintainer: bool,
    #[diesel(sql_type = Bool)]
    attestor_is_active: bool,
    #[diesel(sql_type = Bool)]
    enabler_is_active: bool,
}

/// The columns of a repository as the domain reads them. The ceiling an organization admin set is
/// one fact, the result of the preflight another. The level the repository may run at is the lower
/// of the two, computed here on every read, so a later passing preflight gives back what the admin
/// set (ADR 0009).
///
/// `attestor_is_active` and `enabler_is_active` are computed on every read too (finding REG-6): a
/// person who attested the map or enabled the repository and is no longer an active human principal
/// of the tenant makes the repository fail the standing test, whatever the stored flag says. A
/// column that is empty is not judged: nobody is named.
const REPOSITORY_COLUMNS: &str = "tenant_id, id, github_installation_id, github_repository_id, \
    full_name, default_branch, enabled, protection_preflight_passed, \
    CASE WHEN protection_preflight_passed THEN autonomy_ceiling ELSE 'L0' END AS effective_ceiling, \
    version, project_map_commit, project_map_attested_by_principal_id, project_map_attested_at, \
    enabled_project_map_commit, enabled_by_principal_id, enabled_at, single_maintainer, \
    (project_map_attested_by_principal_id IS NULL OR EXISTS (SELECT 1 FROM principals p \
        WHERE p.tenant_id = repositories.tenant_id AND p.id = project_map_attested_by_principal_id \
          AND p.kind = 'human' AND p.disabled_at IS NULL)) AS attestor_is_active, \
    (enabled_by_principal_id IS NULL OR EXISTS (SELECT 1 FROM principals p \
        WHERE p.tenant_id = repositories.tenant_id AND p.id = enabled_by_principal_id \
          AND p.kind = 'human' AND p.disabled_at IS NULL)) AS enabler_is_active";

fn repository_from_row(row: RepositoryRow) -> Result<Versioned<Repository>, StoreError> {
    // The three columns of the attestation are all set or all empty (a CHECK says so). A row that
    // breaks it is corrupt, and it is not read as "no map".
    let project_map = match (
        row.project_map_commit,
        row.project_map_attested_by_principal_id,
        row.project_map_attested_at,
    ) {
        (None, None, None) => None,
        (Some(commit), Some(by), Some(at)) => Some(ProjectMapAttestation {
            commit: ProjectMapCommit::new(&commit).map_err(|_| corrupt("project map commit"))?,
            attested_by: PrincipalId::from_uuid(by),
            attested_at: from_column(at),
        }),
        _ => return Err(corrupt("project map attestation")),
    };
    // The record of the enabling exists exactly while the repository is enabled, and a CHECK says
    // so. A row that breaks it is corrupt, and it is not read as "enabled for nothing".
    let enabled_for = match (row.enabled, row.enabled_project_map_commit, row.enabled_at) {
        (false, None, None) if row.enabled_by_principal_id.is_none() => None,
        (true, Some(commit), Some(at)) => Some(EnabledFor {
            commit: ProjectMapCommit::new(&commit)
                .map_err(|_| corrupt("enabled project map commit"))?,
            enabled_by: row.enabled_by_principal_id.map(PrincipalId::from_uuid),
            enabled_at: from_column(at),
        }),
        _ => return Err(corrupt("enabled record")),
    };
    Ok(Versioned {
        value: Repository {
            id: RepositoryId::from_uuid(row.id),
            tenant_id: TenantId::from_uuid(row.tenant_id),
            installation: InstallationId(unsigned_from_column(
                row.github_installation_id,
                "installation",
            )?),
            github_repository_id: GithubRepositoryId(unsigned_from_column(
                row.github_repository_id,
                "repository",
            )?),
            full_name: row.full_name,
            default_branch: row.default_branch,
            enabled: row.enabled,
            protection_preflight_passed: row.protection_preflight_passed,
            autonomy_ceiling: AutonomyLevel::parse(&row.effective_ceiling)
                .map_err(|_| corrupt("autonomy ceiling"))?,
            project_map,
            enabled_for,
            single_maintainer: row.single_maintainer,
            attestor_is_active: row.attestor_is_active,
            enabler_is_active: row.enabler_is_active,
        },
        version: version_from_column(row.version)?,
    })
}

async fn find_repository(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: RepositoryId,
    operation: &'static str,
) -> Result<Option<Versioned<Repository>>, StoreError> {
    sql_query(format!(
        "SELECT {REPOSITORY_COLUMNS} FROM repositories WHERE tenant_id = $1 AND id = $2"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .get_result::<RepositoryRow>(connection)
    .await
    .optional()
    .map_err(|error| database(operation, &error))?
    .map(repository_from_row)
    .transpose()
}

async fn get_repository(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: RepositoryId,
) -> Result<Versioned<Repository>, StoreError> {
    find_repository(connection, tenant, id, "get_repository")
        .await?
        .ok_or(StoreError::NotFound)
}

/// True when the stored repository is the one the caller offered to register. The flags, the
/// version and the project map move after the insert and are not compared. The single-maintainer
/// flag is part of the registration and is compared: the same id with the other rule is another
/// request.
fn same_registration(stored: &Repository, new: &NewRepository) -> bool {
    stored.installation == new.installation
        && stored.github_repository_id == new.github_repository_id
        && stored.full_name == new.full_name
        && stored.default_branch == new.default_branch
        && stored.single_maintainer == new.single_maintainer
}

/// Registers a repository. The row starts disabled, at level L0, with no protection result and no
/// map, because the statement names seven columns and the API's grant allows no more.
async fn register_repository(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    new: NewRepository,
) -> Result<Inserted<Repository>, StoreError> {
    let installation = i64::try_from(new.installation.0).map_err(|_| id_reused())?;
    let hosted = i64::try_from(new.github_repository_id.0).map_err(|_| id_reused())?;
    // A hosted repository that is taken answers with a unique violation on a global key, which
    // `database` reports as `NotFound` (NT-TEN-05). That aborts the transaction, so the caller
    // rolls back; nothing is written.
    let inserted = sql_query(format!(
        "INSERT INTO repositories (tenant_id, id, github_installation_id, github_repository_id, \
                full_name, default_branch, single_maintainer) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (tenant_id, id) DO NOTHING RETURNING {REPOSITORY_COLUMNS}"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(new.id.as_uuid())
    .bind::<BigInt, _>(installation)
    .bind::<BigInt, _>(hosted)
    .bind::<Text, _>(new.full_name.as_str())
    .bind::<Text, _>(new.default_branch.as_str())
    .bind::<Bool, _>(new.single_maintainer)
    .get_result::<RepositoryRow>(connection)
    .await
    .optional()
    .map_err(|error| database("register_repository", &error))?;
    if let Some(row) = inserted {
        return Ok(Inserted {
            row: repository_from_row(row)?,
            created: true,
        });
    }
    // The id exists. The same content is a replay, and anything else is a reuse of the id.
    let found = find_repository(connection, tenant, new.id, "register_repository")
        .await?
        .ok_or_else(id_reused)?;
    if same_registration(&found.value, &new) {
        Ok(Inserted {
            row: found,
            created: false,
        })
    } else {
        Err(id_reused())
    }
}

#[derive(QueryableByName)]
struct Standing {
    #[diesel(sql_type = BigInt)]
    version: i64,
    #[diesel(sql_type = Nullable<Text>)]
    map_commit: Option<String>,
    #[diesel(sql_type = Bool)]
    person_ok: bool,
    #[diesel(sql_type = Bool)]
    single_maintainer: bool,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    attested_by: Option<Uuid>,
}

/// What a change of a repository was, for the answer when it changed no row.
enum RepositoryChange<'a> {
    /// A person attests the map: the attestor must be an active human of the tenant.
    Attest(PrincipalId),
    /// A person enables the repository for the commit they name.
    Enable {
        commit: &'a ProjectMapCommit,
        by: PrincipalId,
    },
    /// The repository is switched off.
    Disable,
}

impl RepositoryChange<'_> {
    fn person(&self) -> Option<PrincipalId> {
        match self {
            Self::Attest(by) | Self::Enable { by, .. } => Some(*by),
            Self::Disable => None,
        }
    }
}

/// Why an update of a repository changed no row. A row that does not exist is `NotFound`. A row at
/// another version is `Conflict`. A row at the right version means a rule stopped the change:
/// enabling without a map, enabling for a commit that is not the one attested now, or a person who
/// is not an active human of the tenant.
async fn repository_not_changed(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: RepositoryId,
    expected: Version,
    change: RepositoryChange<'_>,
    operation: &'static str,
) -> Result<StoreError, StoreError> {
    let standing = sql_query(
        "SELECT r.version, r.project_map_commit AS map_commit, \
                EXISTS (SELECT 1 FROM principals p \
                         WHERE p.tenant_id = r.tenant_id AND p.id = $3 AND p.kind = 'human' \
                           AND p.disabled_at IS NULL) AS person_ok, \
                r.single_maintainer, r.project_map_attested_by_principal_id AS attested_by \
           FROM repositories r WHERE r.tenant_id = $1 AND r.id = $2",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .bind::<Nullable<SqlUuid>, _>(change.person().map(|principal| principal.as_uuid()))
    .get_result::<Standing>(connection)
    .await
    .optional()
    .map_err(|error| database(operation, &error))?;
    Ok(match (standing, &change) {
        (None, _) => StoreError::NotFound,
        (Some(row), _) if row.version != expected.get() => StoreError::Conflict,
        (Some(row), RepositoryChange::Attest(_)) if !row.person_ok => {
            StoreError::Constraint(ConstraintRule::ProjectMapRule)
        }
        (Some(row), RepositoryChange::Enable { commit, by }) => match row.map_commit {
            None => StoreError::Constraint(ConstraintRule::ProjectMapRule),
            Some(on_file) if on_file != commit.as_str() => {
                StoreError::Constraint(ConstraintRule::ProjectMapChanged)
            }
            Some(_) if !row.person_ok => StoreError::Constraint(ConstraintRule::ProjectMapRule),
            // The enabler is the attestor of this map and the repository is not a single-maintainer
            // one (finding REG-6).
            Some(_) if !row.single_maintainer && row.attested_by == Some(by.as_uuid()) => {
                StoreError::Constraint(ConstraintRule::EnablerIsAttestor)
            }
            // The version is current and the rules hold: a concurrent change slipped in between.
            Some(_) => StoreError::Conflict,
        },
        // The version is current and the rules hold: a concurrent change slipped in between.
        (Some(_), _) => StoreError::Conflict,
    })
}

async fn attest_project_map(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: RepositoryId,
    expected: Version,
    commit: &ProjectMapCommit,
    attested_by: PrincipalId,
) -> Result<Version, StoreError> {
    // The attestor is checked in the statement, so that a refusal does not abort the transaction.
    // The trigger checks the same thing again, and so does the CHECK on the shape of the commit.
    let updated = sql_query(
        "UPDATE repositories SET project_map_commit = $4, \
                project_map_attested_by_principal_id = $5, version = version + 1 \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 \
            AND EXISTS (SELECT 1 FROM principals p \
                         WHERE p.tenant_id = $1 AND p.id = $5 AND p.kind = 'human' \
                           AND p.disabled_at IS NULL) \
        RETURNING version",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .bind::<BigInt, _>(expected.get())
    .bind::<Text, _>(commit.as_str())
    .bind::<SqlUuid, _>(attested_by.as_uuid())
    .get_result::<NewVersion>(connection)
    .await
    .optional()
    .map_err(|error| database("attest_project_map", &error))?;
    match updated {
        Some(row) => version_from_column(row.version),
        None => Err(repository_not_changed(
            connection,
            tenant,
            id,
            expected,
            RepositoryChange::Attest(attested_by),
            "attest_project_map",
        )
        .await?),
    }
}

/// Switches the repository on for `commit`. The statement names the commit and the person, so the
/// table holds them to the map on file (REG-1) and a refusal does not abort the transaction. It also
/// leaves a strict repository alone when the person is the one who attested the map (REG-6), for the
/// same reason: the table refuses it too, with an error that would abort the transaction. A repository that is
/// enabled already is left alone (finding RH-7): the table keeps the record of the first enabler, so a second
/// "enable" that changed the version and nothing else would only put a second name in the audit log.
async fn enable_repository(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: RepositoryId,
    expected: Version,
    commit: &ProjectMapCommit,
    enabled_by: PrincipalId,
) -> Result<Version, StoreError> {
    let updated = sql_query(
        "UPDATE repositories SET enabled = true, enabled_project_map_commit = $4, \
                enabled_by_principal_id = $5, version = version + 1 \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 AND project_map_commit = $4 \
            AND NOT enabled \
            AND (single_maintainer OR project_map_attested_by_principal_id IS DISTINCT FROM $5) \
            AND EXISTS (SELECT 1 FROM principals p \
                         WHERE p.tenant_id = $1 AND p.id = $5 AND p.kind = 'human' \
                           AND p.disabled_at IS NULL) \
        RETURNING version",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .bind::<BigInt, _>(expected.get())
    .bind::<Text, _>(commit.as_str())
    .bind::<SqlUuid, _>(enabled_by.as_uuid())
    .get_result::<NewVersion>(connection)
    .await
    .optional()
    .map_err(|error| database("enable_repository", &error))?;
    match updated {
        Some(row) => version_from_column(row.version),
        None => Err(repository_not_changed(
            connection,
            tenant,
            id,
            expected,
            RepositoryChange::Enable {
                commit,
                by: enabled_by,
            },
            "enable_repository",
        )
        .await?),
    }
}

/// Switches the repository off. The table empties the record of the enabling.
async fn disable_repository(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: RepositoryId,
    expected: Version,
) -> Result<Version, StoreError> {
    let updated = sql_query(
        "UPDATE repositories SET enabled = false, version = version + 1 \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 \
        RETURNING version",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .bind::<BigInt, _>(expected.get())
    .get_result::<NewVersion>(connection)
    .await
    .optional()
    .map_err(|error| database("disable_repository", &error))?;
    match updated {
        Some(row) => version_from_column(row.version),
        None => Err(repository_not_changed(
            connection,
            tenant,
            id,
            expected,
            RepositoryChange::Disable,
            "disable_repository",
        )
        .await?),
    }
}

async fn record_protection_preflight(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: RepositoryId,
    expected: Version,
    passed: bool,
) -> Result<Version, StoreError> {
    let updated = sql_query(
        "UPDATE repositories SET protection_preflight_passed = $4, version = version + 1 \
          WHERE tenant_id = $1 AND id = $2 AND version = $3 RETURNING version",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .bind::<BigInt, _>(expected.get())
    .bind::<Bool, _>(passed)
    .get_result::<NewVersion>(connection)
    .await
    .optional()
    .map_err(|error| database("record_protection_preflight", &error))?;
    match updated {
        Some(row) => version_from_column(row.version),
        None => Err(no_row_changed(
            connection,
            Table::Repositories,
            tenant,
            id.as_uuid(),
            "record_protection_preflight",
        )
        .await?),
    }
}

#[async_trait]
impl RepositoryOps for PgTx {
    async fn get_repository(
        &mut self,
        id: RepositoryId,
    ) -> Result<Versioned<Repository>, StoreError> {
        call!(self, connection, tenant => get_repository(connection, tenant, id))
    }

    async fn record_protection_preflight(
        &mut self,
        id: RepositoryId,
        expected: Version,
        passed: bool,
    ) -> Result<Version, StoreError> {
        call!(self, connection, tenant => {
            record_protection_preflight(connection, tenant, id, expected, passed)
        })
    }

    async fn register_repository(
        &mut self,
        new: NewRepository,
    ) -> Result<Inserted<Repository>, StoreError> {
        call!(self, connection, tenant => register_repository(connection, tenant, new))
    }

    async fn attest_project_map(
        &mut self,
        id: RepositoryId,
        expected: Version,
        commit: ProjectMapCommit,
        attested_by: PrincipalId,
    ) -> Result<Version, StoreError> {
        call!(self, connection, tenant => {
            attest_project_map(connection, tenant, id, expected, &commit, attested_by)
        })
    }

    async fn enable_repository(
        &mut self,
        id: RepositoryId,
        expected: Version,
        commit: ProjectMapCommit,
        enabled_by: PrincipalId,
    ) -> Result<Version, StoreError> {
        call!(self, connection, tenant => {
            enable_repository(connection, tenant, id, expected, &commit, enabled_by)
        })
    }

    async fn disable_repository(
        &mut self,
        id: RepositoryId,
        expected: Version,
    ) -> Result<Version, StoreError> {
        call!(self, connection, tenant => {
            disable_repository(connection, tenant, id, expected)
        })
    }
}
