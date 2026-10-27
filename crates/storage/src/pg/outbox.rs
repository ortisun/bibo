//! The transactional outbox (ADR 0004).
//!
//! An event is written in the same transaction as the state change it announces, so both commit
//! or neither does. The database checks, at commit, that the event's aggregate exists, belongs to
//! the event's job, and has reached the version the event announces
//! (`outbox_aggregate_has_reached_version`). Those checks are deferred, so they fire when
//! `commit` runs, and `commit` maps them.

use diesel::QueryableByName;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Integer, Jsonb, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::contracts::{Contract, DomainEvent};
use factory_domain::ids::{JobId, TenantId};
use factory_domain::values::Timestamp;
use factory_ports::store::{OutboxRow, OutboxSeq, StoreError};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use super::cas::{Machine, exists};
use super::conv::{corrupt, from_column, job_to_column, tenant_to_column};
use super::error::{Failure, constraint, generic};

fn text(document: &Value, path: &[&str]) -> Option<String> {
    let mut node = document;
    for key in path {
        node = node.get(*key)?;
    }
    node.as_str().map(str::to_owned)
}

pub(super) async fn enqueue(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    event: DomainEvent,
) -> Result<(), StoreError> {
    if event.tenant_id != tenant {
        return Err(StoreError::TenantMismatch);
    }
    let tenant_raw = tenant_to_column(tenant);
    let job_raw = job_to_column(event.job_id);
    if !exists(
        connection,
        Machine::Job,
        tenant_raw,
        job_raw,
        "enqueue_event",
    )
    .await?
    {
        return Err(StoreError::NotFound);
    }
    let document = serde_json::to_value(&event).map_err(|_| corrupt("domain event"))?;
    let bad = || constraint("the event does not have the fields of the schema", None);
    let uuid_at = |path: &[&str]| -> Result<Option<Uuid>, StoreError> {
        match text(&document, path) {
            Some(value) => Uuid::parse_str(&value).map(Some).map_err(|_| bad()),
            None => Ok(None),
        }
    };
    let payload = Value::Object(event.payload.clone());
    let (schema_name, schema_version) = match &event.payload_schema {
        Some(schema) => (
            Some(schema.name.as_str().to_owned()),
            Some(i32::try_from(schema.version.get()).map_err(|_| bad())?),
        ),
        None => (None, None),
    };
    sql_query(
        "INSERT INTO outbox (tenant_id, event_id, event_type, event_version, job_id, aggregate_type, \
                aggregate_id, aggregate_version, transition_id, reason_code, correlation_id, causation_id, \
                occurred_at, producer, traceparent, payload, payload_schema_name, payload_schema_version) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::timestamptz, $14, $15, $16, $17, $18)",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<SqlUuid, _>(uuid_at(&["event_id"])?.ok_or_else(bad)?)
    .bind::<Text, _>(event.event_type.as_str())
    .bind::<Integer, _>(i32::try_from(event.event_version.get()).map_err(|_| bad())?)
    .bind::<SqlUuid, _>(job_raw)
    .bind::<Text, _>(text(&document, &["aggregate", "type"]).ok_or_else(bad)?)
    .bind::<SqlUuid, _>(uuid_at(&["aggregate", "id"])?.ok_or_else(bad)?)
    .bind::<BigInt, _>(event.aggregate.version.get())
    .bind::<Text, _>(event.transition_id.as_str())
    .bind::<Nullable<Text>, _>(event.reason_code.as_ref().map(|code| code.as_str().to_owned()))
    .bind::<SqlUuid, _>(uuid_at(&["correlation_id"])?.ok_or_else(bad)?)
    .bind::<Nullable<SqlUuid>, _>(uuid_at(&["causation_id"])?)
    .bind::<Text, _>(event.occurred_at.to_string())
    .bind::<Text, _>(event.producer.as_str())
    .bind::<Nullable<Text>, _>(event.traceparent.as_ref().map(|value| value.as_str().to_owned()))
    .bind::<Jsonb, _>(payload)
    .bind::<Nullable<Text>, _>(schema_name)
    .bind::<Nullable<Integer>, _>(schema_version)
    .execute(connection)
    .await
    .map_err(|error| match Failure::of(&error) {
        Failure::Unique(Some(name)) if name == "outbox_one_event_per_aggregate_version" => {
            StoreError::Conflict
        }
        Failure::Unique(name) => constraint("unique violation", name.as_deref()),
        Failure::ForeignKey(name) => constraint("foreign key violation", name.as_deref()),
        Failure::Check(name) => constraint("check violation", name.as_deref()),
        _ => generic("enqueue_event", &error),
    })?;
    Ok(())
}

#[derive(QueryableByName)]
struct EventRow {
    #[diesel(sql_type = BigInt)]
    seq: i64,
    #[diesel(sql_type = SqlUuid)]
    event_id: Uuid,
    #[diesel(sql_type = Text)]
    event_type: String,
    #[diesel(sql_type = Integer)]
    event_version: i32,
    #[diesel(sql_type = SqlUuid)]
    job_id: Uuid,
    #[diesel(sql_type = Text)]
    aggregate_type: String,
    #[diesel(sql_type = SqlUuid)]
    aggregate_id: Uuid,
    #[diesel(sql_type = BigInt)]
    aggregate_version: i64,
    #[diesel(sql_type = Text)]
    transition_id: String,
    #[diesel(sql_type = Nullable<Text>)]
    reason_code: Option<String>,
    #[diesel(sql_type = SqlUuid)]
    correlation_id: Uuid,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    causation_id: Option<Uuid>,
    #[diesel(sql_type = Timestamptz)]
    occurred_at: OffsetDateTime,
    #[diesel(sql_type = Text)]
    producer: String,
    #[diesel(sql_type = Nullable<Text>)]
    traceparent: Option<String>,
    #[diesel(sql_type = Jsonb)]
    payload: Value,
    #[diesel(sql_type = Nullable<Text>)]
    payload_schema_name: Option<String>,
    #[diesel(sql_type = Nullable<Integer>)]
    payload_schema_version: Option<i32>,
}

/// Events of a job from position `from`, in order.
pub(super) async fn read(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    job: JobId,
    from: OutboxSeq,
    limit: u32,
) -> Result<Vec<OutboxRow>, StoreError> {
    let tenant_raw = tenant_to_column(tenant);
    let job_raw = job_to_column(job);
    if !exists(connection, Machine::Job, tenant_raw, job_raw, "read_events").await? {
        return Err(StoreError::NotFound);
    }
    let rows = sql_query(
        "SELECT seq, event_id, event_type, event_version, job_id, aggregate_type, aggregate_id, \
                aggregate_version, transition_id, reason_code, correlation_id, causation_id, \
                occurred_at, producer, traceparent, payload, payload_schema_name, payload_schema_version \
           FROM outbox WHERE tenant_id = $1 AND job_id = $2 AND seq >= $3 ORDER BY seq LIMIT $4",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<SqlUuid, _>(job_raw)
    .bind::<BigInt, _>(i64::try_from(from.get()).unwrap_or(i64::MAX))
    .bind::<BigInt, _>(i64::from(limit))
    .load::<EventRow>(connection)
    .await
    .map_err(|error| generic("read_events", &error))?;
    rows.into_iter()
        .map(|row| row_to_event(tenant, row))
        .collect()
}

fn row_to_event(tenant: TenantId, row: EventRow) -> Result<OutboxRow, StoreError> {
    let mut document = Map::new();
    document.insert("schema_version".into(), json!(1));
    document.insert(
        "event_id".into(),
        json!(row.event_id.hyphenated().to_string()),
    );
    document.insert("event_type".into(), json!(row.event_type));
    document.insert("event_version".into(), json!(row.event_version));
    document.insert("tenant_id".into(), json!(tenant.to_string()));
    document.insert("job_id".into(), json!(row.job_id.hyphenated().to_string()));
    document.insert(
        "aggregate".into(),
        json!({
            "type": row.aggregate_type,
            "id": row.aggregate_id.hyphenated().to_string(),
            "version": row.aggregate_version,
        }),
    );
    document.insert("transition_id".into(), json!(row.transition_id));
    if let Some(code) = row.reason_code {
        document.insert("reason_code".into(), json!(code));
    }
    document.insert(
        "correlation_id".into(),
        json!(row.correlation_id.hyphenated().to_string()),
    );
    document.insert(
        "causation_id".into(),
        row.causation_id
            .map_or(Value::Null, |id| json!(id.hyphenated().to_string())),
    );
    document.insert(
        "occurred_at".into(),
        json!(Timestamp::to_string(&from_column(row.occurred_at))),
    );
    document.insert("producer".into(), json!(row.producer));
    if let Some(traceparent) = row.traceparent {
        document.insert("traceparent".into(), json!(traceparent));
    }
    document.insert("payload".into(), row.payload);
    if let (Some(name), Some(version)) = (row.payload_schema_name, row.payload_schema_version) {
        document.insert(
            "payload_schema".into(),
            json!({ "name": name, "version": version }),
        );
    }
    let event = DomainEvent::from_json_value(Value::Object(document))
        .map_err(|_| corrupt("outbox event"))?;
    Ok(OutboxRow {
        seq: OutboxSeq::new(u64::try_from(row.seq).map_err(|_| corrupt("outbox position"))?),
        event,
    })
}
