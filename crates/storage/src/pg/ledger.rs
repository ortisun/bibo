//! The evidence ledger: append, head and read (ADR 0008).
//!
//! The domain computes the hash. This module checks it again before it writes, because the port
//! says the store checks the chain, and the database checks it a third time with its own
//! trigger. All three use the same text: `canonical_json` is the entry as RFC 8785 canonical JSON
//! without its `entry_hash`, produced by the domain function `canonical_form`, and the hash is
//! SHA-256 over the previous hash, a newline and that text. The two vectors in
//! `docs/database/ledger-and-audit.md` are reproduced by a test (`ledger_vectors_from_the_database_docs`).
//!
//! # The job head
//!
//! The job row holds the head of its chain (`ledger_head_sequence`, `ledger_head_hash`). An append
//! moves the head without raising the job's version (migration 17): `append_ledger_entry` returns
//! the chain head and no version, and `transition_job` takes the version the caller read, so a
//! transition after an append in the same transaction must not find the version moved. The head
//! never moves back, and a head move together with any other change of the job still raises the
//! version by one.
//!
//! # Concurrent appends
//!
//! The append locks the job row with `FOR NO KEY UPDATE` (never `FOR UPDATE`: a ledger insert
//! takes a `KEY SHARE` lock on the job), reads the head under the lock, and checks the entry
//! against it. A second writer waits for the first to end, then reads the head the first one left
//! and finds its own position taken. Two writers can never both extend the chain at one position:
//! the primary key of `ledger_entries` and the key to the predecessor allow one entry at each.

use diesel::sql_types::{Array, BigInt, Nullable, Text, Uuid as SqlUuid};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::contracts::{Contract, EvidenceLedgerEntry};
use factory_domain::ids::{JobId, TenantId};
use factory_domain::ledger::{ChainHead, canonical_form, chain_hash};
use factory_domain::values::Sha256Digest;
use factory_ports::store::{LedgerOps, Sequence, StoreError};
use serde_json::Value;
use uuid::Uuid;

use async_trait::async_trait;

use super::cas::{Table, exists};
use super::conv::{corrupt, digest_from_column, signed_to_column, unsigned_from_column};
use super::error::database;
use super::tx::{PgTx, call};

#[derive(QueryableByName)]
struct HeadRow {
    #[diesel(sql_type = BigInt)]
    sequence: i64,
    #[diesel(sql_type = Nullable<Text>)]
    hash: Option<String>,
}

fn head_from(sequence: i64, hash: Option<&str>) -> Result<Option<ChainHead>, StoreError> {
    if sequence == 0 {
        return Ok(None);
    }
    let hash = hash.ok_or_else(|| corrupt("ledger head without a hash"))?;
    Ok(Some(ChainHead {
        sequence: unsigned_from_column(sequence, "ledger head sequence")?,
        hash: digest_from_column(hash)?,
    }))
}

/// The head of a job's chain, or `None` for a job with no entries.
async fn head(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    job: JobId,
) -> Result<Option<ChainHead>, StoreError> {
    let row = sql_query(
        "SELECT ledger_head_sequence AS sequence, ledger_head_hash AS hash \
           FROM jobs WHERE tenant_id = $1 AND id = $2",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(job.as_uuid())
    .get_result::<HeadRow>(connection)
    .await
    .optional()
    .map_err(|error| database("ledger_head", &error))?
    .ok_or(StoreError::NotFound)?;
    head_from(row.sequence, row.hash.as_deref())
}

/// The fields of an entry that the table keeps as columns, read from the same JSON the hash was
/// computed over, so the columns and the hashed text cannot differ.
struct Columns {
    entry_id: Uuid,
    stage_run_id: Uuid,
    attempt_id: Option<Uuid>,
    recorded_at: String,
    execution_mode: String,
    component: String,
    fidelity: String,
    claim_kind: String,
    assurance_level: Option<String>,
    confidence_level: String,
    invalidates: Vec<Uuid>,
}

fn text_at(document: &Value, path: &[&str]) -> Option<String> {
    let mut node = document;
    for key in path {
        node = node.get(*key)?;
    }
    node.as_str().map(str::to_owned)
}

fn columns_of(document: &Value) -> Result<Columns, StoreError> {
    // An entry the schema of the document does not describe cannot be stored. The domain type
    // makes this unreachable, so the answer is the one for a chain that cannot take the entry.
    let bad = || StoreError::ChainBroken;
    let uuid_at = |path: &[&str]| -> Result<Option<Uuid>, StoreError> {
        match text_at(document, path) {
            Some(text) => Uuid::parse_str(&text).map(Some).map_err(|_| bad()),
            None => Ok(None),
        }
    };
    let invalidates = match document.get("invalidates").and_then(Value::as_array) {
        Some(items) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .and_then(|text| Uuid::parse_str(text).ok())
                    .ok_or_else(bad)
            })
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
    };
    Ok(Columns {
        entry_id: uuid_at(&["metadata", "entry_id"])?.ok_or_else(bad)?,
        stage_run_id: uuid_at(&["metadata", "stage_run_id"])?.ok_or_else(bad)?,
        attempt_id: uuid_at(&["metadata", "attempt_id"])?,
        recorded_at: text_at(document, &["metadata", "recorded_at"]).ok_or_else(bad)?,
        execution_mode: text_at(document, &["metadata", "execution_mode"]).ok_or_else(bad)?,
        component: text_at(document, &["metadata", "recorded_by", "component"]).ok_or_else(bad)?,
        fidelity: text_at(document, &["metadata", "recorded_by", "fidelity"]).ok_or_else(bad)?,
        claim_kind: text_at(document, &["claim", "kind"]).ok_or_else(bad)?,
        assurance_level: text_at(document, &["claim", "assurance_level"]),
        confidence_level: text_at(document, &["confidence", "level"]).ok_or_else(bad)?,
        invalidates,
    })
}

/// Appends one entry at head + 1.
async fn append(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    entry: EvidenceLedgerEntry,
) -> Result<ChainHead, StoreError> {
    let operation = "append_ledger_entry";
    let job = entry.metadata.job_id;

    // 1. The job: it must be the tenant's, and nobody else may extend its chain meanwhile.
    let locked = sql_query(
        "SELECT ledger_head_sequence AS sequence, ledger_head_hash AS hash \
           FROM jobs WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(job.as_uuid())
    .get_result::<HeadRow>(connection)
    .await
    .optional()
    .map_err(|error| database(operation, &error))?
    .ok_or(StoreError::NotFound)?;
    let current = head_from(locked.sequence, locked.hash.as_deref())?;

    // 2. The chain rules, in the order the port documents them.
    let sequence = entry.sequence();
    let head_sequence = current.as_ref().map_or(0, |head| head.sequence);
    if sequence <= head_sequence {
        return Err(StoreError::Conflict);
    }
    if sequence != head_sequence + 1 {
        return Err(StoreError::ChainBroken);
    }
    if entry.prev_entry_hash.as_ref() != current.as_ref().map(|head| &head.hash) {
        return Err(StoreError::ChainBroken);
    }
    let canonical = canonical_form(&entry).map_err(|_| StoreError::ChainBroken)?;
    if chain_hash(entry.prev_entry_hash.as_ref(), &canonical) != entry.entry_hash {
        return Err(StoreError::ChainBroken);
    }
    let canonical_text = String::from_utf8(canonical).map_err(|_| StoreError::ChainBroken)?;
    let document = serde_json::to_value(&entry).map_err(|_| StoreError::ChainBroken)?;
    let columns = columns_of(&document)?;
    let number = signed_to_column(sequence);

    // 3. The entry. `prev_sequence` is left out: the trigger sets it.
    sql_query(
        "INSERT INTO ledger_entries (tenant_id, job_id, sequence, entry_id, stage_run_id, \
                attempt_id, recorded_at, execution_mode, recorded_component, recorded_fidelity, \
                claim_kind, assurance_level, confidence_level, invalidates, prev_entry_hash, \
                entry_hash, canonical_json) \
         VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz, $8, $9, $10, $11, $12, $13, $14, $15, \
                 $16, $17)",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(job.as_uuid())
    .bind::<BigInt, _>(number)
    .bind::<SqlUuid, _>(columns.entry_id)
    .bind::<SqlUuid, _>(columns.stage_run_id)
    .bind::<Nullable<SqlUuid>, _>(columns.attempt_id)
    .bind::<Text, _>(columns.recorded_at)
    .bind::<Text, _>(columns.execution_mode)
    .bind::<Text, _>(columns.component)
    .bind::<Text, _>(columns.fidelity)
    .bind::<Text, _>(columns.claim_kind)
    .bind::<Nullable<Text>, _>(columns.assurance_level)
    .bind::<Text, _>(columns.confidence_level)
    .bind::<Array<SqlUuid>, _>(columns.invalidates)
    .bind::<Nullable<Text>, _>(
        entry
            .prev_entry_hash
            .as_ref()
            .map(|hash| hash.as_str().to_owned()),
    )
    .bind::<Text, _>(entry.entry_hash.as_str())
    .bind::<Text, _>(canonical_text)
    .execute(connection)
    .await
    .map_err(|error| database(operation, &error))?;

    // 4. Move the head, in the same transaction, without a version bump. It moves from the
    // position before this one only, so a head that is not where it was read is a lost race.
    let moved = sql_query(
        "UPDATE jobs SET ledger_head_sequence = $3, ledger_head_hash = $4 \
          WHERE tenant_id = $1 AND id = $2 AND ledger_head_sequence = $5",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(job.as_uuid())
    .bind::<BigInt, _>(number)
    .bind::<Text, _>(entry.entry_hash.as_str())
    .bind::<BigInt, _>(number - 1)
    .execute(connection)
    .await
    .map_err(|error| database(operation, &error))?;
    if moved != 1 {
        return Err(StoreError::Conflict);
    }
    Ok(ChainHead {
        sequence,
        hash: entry.entry_hash,
    })
}

#[derive(QueryableByName)]
struct EntryRow {
    #[diesel(sql_type = Text)]
    canonical_json: String,
    #[diesel(sql_type = Text)]
    entry_hash: String,
}

/// Entries of a job from `from` (inclusive), in order.
async fn read(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    job: JobId,
    from: Sequence,
    limit: u32,
) -> Result<Vec<EvidenceLedgerEntry>, StoreError> {
    if !exists(
        connection,
        Table::Jobs,
        tenant,
        job.as_uuid(),
        "read_ledger",
    )
    .await?
    {
        return Err(StoreError::NotFound);
    }
    let rows = sql_query(
        "SELECT canonical_json, entry_hash FROM ledger_entries \
          WHERE tenant_id = $1 AND job_id = $2 AND sequence >= $3 ORDER BY sequence LIMIT $4",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(job.as_uuid())
    .bind::<BigInt, _>(signed_to_column(from))
    .bind::<BigInt, _>(i64::from(limit))
    .load::<EntryRow>(connection)
    .await
    .map_err(|error| database("read_ledger", &error))?;
    rows.into_iter().map(entry_from_row).collect()
}

fn entry_from_row(row: EntryRow) -> Result<EvidenceLedgerEntry, StoreError> {
    let mut document: Value =
        serde_json::from_str(&row.canonical_json).map_err(|_| corrupt("ledger document"))?;
    let object = document
        .as_object_mut()
        .ok_or_else(|| corrupt("ledger document"))?;
    // The stored text is the entry without its hash. The hash is a column of its own.
    let hash: Sha256Digest = digest_from_column(&row.entry_hash)?;
    object.insert(
        "entry_hash".to_owned(),
        Value::String(hash.as_str().to_owned()),
    );
    EvidenceLedgerEntry::from_json_value(document).map_err(|_| corrupt("ledger entry"))
}

#[async_trait]
impl LedgerOps for PgTx {
    async fn append_ledger_entry(
        &mut self,
        entry: EvidenceLedgerEntry,
    ) -> Result<ChainHead, StoreError> {
        call!(self, connection, tenant => append(connection, tenant, entry))
    }

    async fn ledger_head(&mut self, job: JobId) -> Result<Option<ChainHead>, StoreError> {
        call!(self, connection, tenant => head(connection, tenant, job))
    }

    async fn read_ledger(
        &mut self,
        job: JobId,
        from: Sequence,
        limit: u32,
    ) -> Result<Vec<EvidenceLedgerEntry>, StoreError> {
        call!(self, connection, tenant => read(connection, tenant, job, from, limit))
    }
}
