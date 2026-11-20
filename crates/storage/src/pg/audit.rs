//! The audit log: append only, one hash chain per tenant (NT-AUD-01).
//!
//! The database assigns the sequence, the time and the hash. The caller supplies the event and
//! never a time. An event with no job is allowed (a rejected issue, FR-002); an event that names a
//! stage run needs a job. The platform audit (`Store::record_platform_audit`) is the same
//! statement in a transaction for the platform tenant, and has no job.
//!
//! A replay of the same event id and content is a no-op that returns the stored record. It takes no
//! sequence number, so the chain has no gap.

use async_trait::async_trait;
use diesel::sql_types::{BigInt, Bool, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::{AuditEventId, CorrelationId, JobId, PrincipalId, StageRunId, TenantId};
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, AuditFilter, AuditOps, AuditRecord, ConstraintRule,
    NewAuditEvent, StoreError,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::cas::{Table, exists};
use super::conv::{
    corrupt, digest_from_column, from_column, signed_to_column, slug_from_column,
    unsigned_from_column,
};
use super::error::database;
use super::tx::{PgTx, call};

const COLUMNS: &str = "sequence, event_id, actor_type, actor_id, action, subject, decision, \
    reason, policy_hash, job_id, stage_run_id, correlation_id, created_at, hash";

#[derive(QueryableByName)]
struct AuditRow {
    #[diesel(sql_type = BigInt)]
    sequence: i64,
    #[diesel(sql_type = SqlUuid)]
    event_id: Uuid,
    #[diesel(sql_type = Text)]
    actor_type: String,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = Text)]
    action: String,
    #[diesel(sql_type = Text)]
    subject: String,
    #[diesel(sql_type = Text)]
    decision: String,
    #[diesel(sql_type = Text)]
    reason: String,
    #[diesel(sql_type = Text)]
    policy_hash: String,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    job_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    stage_run_id: Option<Uuid>,
    #[diesel(sql_type = SqlUuid)]
    correlation_id: Uuid,
    #[diesel(sql_type = Timestamptz)]
    created_at: OffsetDateTime,
    #[diesel(sql_type = Text)]
    hash: String,
}

fn actor_columns(actor: &AuditActor) -> (&'static str, String) {
    match actor {
        AuditActor::Human(id) => ("human", id.as_uuid().hyphenated().to_string()),
        AuditActor::Service(id) => ("service", id.as_uuid().hyphenated().to_string()),
        AuditActor::System(label) => ("system", label.as_str().to_owned()),
        AuditActor::Anonymous(label) => ("anonymous", label.as_str().to_owned()),
    }
}

fn actor_from_columns(kind: &str, id: &str) -> Result<AuditActor, StoreError> {
    let principal = || {
        Uuid::parse_str(id)
            .map(PrincipalId::from_uuid)
            .map_err(|_| corrupt("audit actor"))
    };
    Ok(match kind {
        "human" => AuditActor::Human(principal()?),
        "service" => AuditActor::Service(principal()?),
        "system" => AuditActor::System(slug_from_column(id)?),
        "anonymous" => AuditActor::Anonymous(slug_from_column(id)?),
        _ => return Err(corrupt("audit actor")),
    })
}

const fn decision_name(decision: AuditDecision) -> &'static str {
    match decision {
        AuditDecision::Allow => "allow",
        AuditDecision::Deny => "deny",
        AuditDecision::Record => "record",
    }
}

fn decision_from_column(name: &str) -> Result<AuditDecision, StoreError> {
    Ok(match name {
        "allow" => AuditDecision::Allow,
        "deny" => AuditDecision::Deny,
        "record" => AuditDecision::Record,
        _ => return Err(corrupt("audit decision")),
    })
}

fn record_from_row(row: AuditRow) -> Result<AuditRecord, StoreError> {
    Ok(AuditRecord {
        sequence: unsigned_from_column(row.sequence, "audit sequence")?,
        event: NewAuditEvent {
            id: AuditEventId::from_uuid(row.event_id),
            actor: actor_from_columns(&row.actor_type, &row.actor_id)?,
            action: AuditAction::new(&row.action).map_err(|_| corrupt("audit action"))?,
            subject: row.subject,
            decision: decision_from_column(&row.decision)?,
            reason: row.reason,
            policy_hash: digest_from_column(&row.policy_hash)?,
            job: row.job_id.map(JobId::from_uuid),
            stage_run: row.stage_run_id.map(StageRunId::from_uuid),
            correlation_id: CorrelationId::from_uuid(row.correlation_id),
        },
        created_at: from_column(row.created_at),
        hash: digest_from_column(&row.hash)?,
    })
}

#[derive(QueryableByName)]
struct Found {
    #[diesel(sql_type = Bool)]
    found: bool,
}

async fn record(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    event: NewAuditEvent,
) -> Result<AuditRecord, StoreError> {
    let operation = "record_audit";
    // A stage run needs a job, and both must be the tenant's. Checked here, so that a refusal
    // does not abort the transaction; the schema checks the same (`audit_events_stage_run_needs_job`
    // and the composite keys).
    if event.stage_run.is_some() && event.job.is_none() {
        return Err(StoreError::Constraint(ConstraintRule::TextBounds));
    }
    if let Some(job) = event.job {
        let named = sql_query(
            "SELECT CASE WHEN $3::uuid IS NULL \
                    THEN EXISTS (SELECT 1 FROM jobs WHERE tenant_id = $1 AND id = $2) \
                    ELSE EXISTS (SELECT 1 FROM stage_runs \
                                  WHERE tenant_id = $1 AND job_id = $2 AND id = $3) END AS found",
        )
        .bind::<SqlUuid, _>(tenant.as_uuid())
        .bind::<SqlUuid, _>(job.as_uuid())
        .bind::<Nullable<SqlUuid>, _>(event.stage_run.map(|run| run.as_uuid()))
        .get_result::<Found>(connection)
        .await
        .map_err(|error| database(operation, &error))?;
        if !named.found {
            return Err(StoreError::NotFound);
        }
    }
    let (actor_type, actor_id) = actor_columns(&event.actor);
    let inserted = sql_query(format!(
        "INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, \
                decision, reason, policy_hash, job_id, stage_run_id, correlation_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
         ON CONFLICT (tenant_id, event_id) DO NOTHING RETURNING {COLUMNS}"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(event.id.as_uuid())
    .bind::<Text, _>(actor_type)
    .bind::<Text, _>(actor_id)
    .bind::<Text, _>(event.action.as_str())
    .bind::<Text, _>(event.subject.as_str())
    .bind::<Text, _>(decision_name(event.decision))
    .bind::<Text, _>(event.reason.as_str())
    .bind::<Text, _>(event.policy_hash.as_str())
    .bind::<Nullable<SqlUuid>, _>(event.job.map(|job| job.as_uuid()))
    .bind::<Nullable<SqlUuid>, _>(event.stage_run.map(|run| run.as_uuid()))
    .bind::<SqlUuid, _>(event.correlation_id.as_uuid())
    .get_result::<AuditRow>(connection)
    .await
    .optional()
    .map_err(|error| database(operation, &error))?;
    if let Some(row) = inserted {
        return record_from_row(row);
    }
    // A replay: the same id and content gives the stored record, other content is a reuse.
    let stored = sql_query(format!(
        "SELECT {COLUMNS} FROM audit_events WHERE tenant_id = $1 AND event_id = $2"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(event.id.as_uuid())
    .get_result::<AuditRow>(connection)
    .await
    .map_err(|error| database(operation, &error))
    .and_then(record_from_row)?;
    if stored.event == event {
        Ok(stored)
    } else {
        Err(StoreError::Constraint(
            ConstraintRule::IdReusedWithDifferentContent,
        ))
    }
}

async fn find(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: AuditEventId,
) -> Result<Option<AuditRecord>, StoreError> {
    sql_query(format!(
        "SELECT {COLUMNS} FROM audit_events WHERE tenant_id = $1 AND event_id = $2"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .get_result::<AuditRow>(connection)
    .await
    .optional()
    .map_err(|error| database("find_audit", &error))?
    .map(record_from_row)
    .transpose()
}

async fn read(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    filter: AuditFilter,
    after_sequence: u64,
    limit: u32,
) -> Result<Vec<AuditRecord>, StoreError> {
    let job = match filter {
        AuditFilter::Tenant => None,
        AuditFilter::Job(job) => {
            if !exists(connection, Table::Jobs, tenant, job.as_uuid(), "read_audit").await? {
                return Err(StoreError::NotFound);
            }
            Some(job.as_uuid())
        }
    };
    sql_query(format!(
        "SELECT {COLUMNS} FROM audit_events \
          WHERE tenant_id = $1 AND ($2::uuid IS NULL OR job_id = $2) AND sequence > $3 \
          ORDER BY sequence LIMIT $4"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<Nullable<SqlUuid>, _>(job)
    .bind::<BigInt, _>(signed_to_column(after_sequence))
    .bind::<BigInt, _>(i64::from(limit))
    .load::<AuditRow>(connection)
    .await
    .map_err(|error| database("read_audit", &error))?
    .into_iter()
    .map(record_from_row)
    .collect()
}

#[async_trait]
impl AuditOps for PgTx {
    async fn record_audit(&mut self, event: NewAuditEvent) -> Result<AuditRecord, StoreError> {
        call!(self, connection, tenant => record(connection, tenant, event))
    }

    async fn find_audit(&mut self, id: AuditEventId) -> Result<Option<AuditRecord>, StoreError> {
        call!(self, connection, tenant => find(connection, tenant, id))
    }

    async fn read_audit(
        &mut self,
        filter: AuditFilter,
        after_sequence: u64,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        call!(self, connection, tenant => read(connection, tenant, filter, after_sequence, limit))
    }
}
