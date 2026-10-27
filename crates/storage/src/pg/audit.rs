//! The audit log: append and read.
//!
//! The database assigns the sequence, the time, the links and the hash (negative test NT-AUD-04),
//! so this module supplies only the facts of the event. The port's `AuditEvent` has no decision
//! and no reason, and the table requires both: every event is stored with the decision `record`
//! and the reason `recorded by the store`, because the port records that something happened and
//! not a policy verdict.
//!
//! The audit trigger takes a per-tenant advisory lock that lasts until the transaction ends. A
//! transaction should write its audit events last (`docs/database/ledger-and-audit.md`).

use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::{JobId, PrincipalId, TenantId};
use factory_domain::values::Slug;
use factory_ports::store::{AuditActor, AuditEvent, StoreError};
use time::OffsetDateTime;
use uuid::Uuid;

use super::cas::{Machine, exists};
use super::conv::{
    correlation_from_column, correlation_to_column, corrupt, digest_from_column, from_column,
    job_to_column, principal_to_column, tenant_to_column,
};
use super::error::{Failure, constraint, generic};

const DECISION: &str = "record";
const REASON: &str = "recorded by the store";

#[derive(QueryableByName)]
struct KindRow {
    #[diesel(sql_type = Text)]
    kind: String,
}

pub(super) async fn record(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    event: AuditEvent,
) -> Result<(), StoreError> {
    let tenant_raw = tenant_to_column(tenant);
    let job_raw = job_to_column(event.job_id);
    if !exists(
        connection,
        Machine::Job,
        tenant_raw,
        job_raw,
        "record_audit",
    )
    .await?
    {
        return Err(StoreError::NotFound);
    }
    let (actor_type, actor_id) = match &event.actor {
        AuditActor::Component(name) => ("system".to_owned(), name.as_str().to_owned()),
        AuditActor::Principal(id) => {
            let kind = sql_query("SELECT kind FROM principals WHERE tenant_id = $1 AND id = $2")
                .bind::<SqlUuid, _>(tenant_raw)
                .bind::<SqlUuid, _>(principal_to_column(*id))
                .load::<KindRow>(connection)
                .await
                .map_err(|error| generic("record_audit", &error))?
                .into_iter()
                .next()
                .ok_or(StoreError::NotFound)?
                .kind;
            (kind, id.to_string())
        }
    };
    sql_query(
        "INSERT INTO audit_events (tenant_id, event_id, actor_type, actor_id, action, subject, decision, \
                reason, policy_hash, job_id, correlation_id) \
         VALUES ($1, uuidv7(), $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<Text, _>(actor_type)
    .bind::<Text, _>(actor_id)
    .bind::<Text, _>(event.action.as_str())
    .bind::<Text, _>(format!("job:{}", event.job_id))
    .bind::<Text, _>(DECISION)
    .bind::<Text, _>(REASON)
    .bind::<Text, _>(event.policy_hash.as_str())
    .bind::<SqlUuid, _>(job_raw)
    .bind::<SqlUuid, _>(correlation_to_column(event.correlation_id))
    .execute(connection)
    .await
    .map_err(|error| match Failure::of(&error) {
        Failure::Check(name) => constraint("check violation", name.as_deref()),
        Failure::ForeignKey(name) => constraint("foreign key violation", name.as_deref()),
        Failure::Unique(name) => constraint("unique violation", name.as_deref()),
        _ => generic("record_audit", &error),
    })?;
    Ok(())
}

#[derive(QueryableByName)]
struct AuditRow {
    #[diesel(sql_type = Text)]
    actor_type: String,
    #[diesel(sql_type = Text)]
    actor_id: String,
    #[diesel(sql_type = Text)]
    action: String,
    #[diesel(sql_type = Text)]
    policy_hash: String,
    #[diesel(sql_type = SqlUuid)]
    correlation_id: Uuid,
    #[diesel(sql_type = Timestamptz)]
    created_at: OffsetDateTime,
}

pub(super) async fn read(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    job: JobId,
    limit: u32,
) -> Result<Vec<AuditEvent>, StoreError> {
    let tenant_raw = tenant_to_column(tenant);
    let job_raw = job_to_column(job);
    if !exists(connection, Machine::Job, tenant_raw, job_raw, "read_audit").await? {
        return Err(StoreError::NotFound);
    }
    let rows = sql_query(
        "SELECT actor_type, actor_id, action, policy_hash, correlation_id, created_at \
           FROM audit_events WHERE tenant_id = $1 AND job_id = $2 ORDER BY sequence LIMIT $3",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<SqlUuid, _>(job_raw)
    .bind::<diesel::sql_types::BigInt, _>(i64::from(limit))
    .load::<AuditRow>(connection)
    .await
    .map_err(|error| generic("read_audit", &error))?;
    rows.into_iter()
        .map(|row| {
            let actor = if row.actor_type == "system" {
                AuditActor::Component(
                    Slug::parse(&row.actor_id).map_err(|_| corrupt("audit actor"))?,
                )
            } else {
                AuditActor::Principal(
                    PrincipalId::parse(&row.actor_id).map_err(|_| corrupt("audit actor"))?,
                )
            };
            Ok(AuditEvent {
                job_id: job,
                actor,
                action: Slug::parse(&row.action).map_err(|_| corrupt("audit action"))?,
                policy_hash: digest_from_column(&row.policy_hash)?,
                correlation_id: correlation_from_column(row.correlation_id),
                occurred_at: from_column(row.created_at),
            })
        })
        .collect()
}
