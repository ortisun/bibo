//! The tenant's index of the artifacts it holds (ADR 0008, ports-v1.1 decision 9).
//!
//! The bytes live behind the `ArtifactStore` port. This table says which tenant may read which
//! hash: a tenant reads a blob only through its own row, and a hash that only another tenant holds
//! looks the same as a hash nobody holds.
//!
//! The size is required by the table (`NOT NULL`: quota and accounting need it), and the entry the
//! port takes ([`NewArtifactIndexEntry`]) carries it as a mandatory field, so there is no entry
//! without one to refuse and the adapter never has to invent a size.

use async_trait::async_trait;
use diesel::sql_types::{BigInt, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::{JobId, StageRunId, TenantId};
use factory_domain::values::{MediaType, NonNegativeInt, Sha256Digest};
use factory_ports::artifact::ArtifactBackend;
use factory_ports::store::{
    ArtifactIndexEntry, ArtifactIndexOps, NewArtifactIndexEntry, StoreError,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::conv::{corrupt, digest_from_column, from_column};
use super::error::database;
use super::tx::{PgTx, call};

const COLUMNS: &str = "tenant_id, content_sha256, size_bytes, media_type, created_by_job_id, \
    created_by_stage_run_id, created_at";

#[derive(QueryableByName)]
struct ArtifactRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = Text)]
    content_sha256: String,
    #[diesel(sql_type = BigInt)]
    size_bytes: i64,
    #[diesel(sql_type = Text)]
    media_type: String,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    created_by_job_id: Option<Uuid>,
    #[diesel(sql_type = Nullable<SqlUuid>)]
    created_by_stage_run_id: Option<Uuid>,
    #[diesel(sql_type = Timestamptz)]
    created_at: OffsetDateTime,
}

#[derive(QueryableByName)]
struct Found {
    #[diesel(sql_type = diesel::sql_types::Bool)]
    found: bool,
}

fn entry_from_row(row: ArtifactRow) -> Result<ArtifactIndexEntry, StoreError> {
    let origin = match (row.created_by_job_id, row.created_by_stage_run_id) {
        (Some(job), Some(run)) => Some((JobId::from_uuid(job), StageRunId::from_uuid(run))),
        _ => None,
    };
    Ok(ArtifactIndexEntry {
        tenant_id: TenantId::from_uuid(row.tenant_id),
        artifact: ArtifactRef {
            sha256: digest_from_column(&row.content_sha256)?,
            media_type: MediaType::parse(&row.media_type).map_err(|_| corrupt("media type"))?,
            size_bytes: Some(NonNegativeInt::new(row.size_bytes).map_err(|_| corrupt("size"))?),
        },
        origin,
        created_at: from_column(row.created_at),
    })
}

async fn get(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    sha256: &Sha256Digest,
) -> Result<Option<ArtifactIndexEntry>, StoreError> {
    sql_query(format!(
        "SELECT {COLUMNS} FROM artifacts WHERE tenant_id = $1 AND content_sha256 = $2"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<Text, _>(sha256.as_str())
    .get_result::<ArtifactRow>(connection)
    .await
    .optional()
    .map_err(|error| database("get_artifact_index", &error))?
    .map(entry_from_row)
    .transpose()
}

async fn index(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    backend: ArtifactBackend,
    new: NewArtifactIndexEntry,
) -> Result<ArtifactIndexEntry, StoreError> {
    let operation = "index_artifact";
    // A job and stage run named as the origin must be the tenant's. Checked here so that a refusal
    // does not abort the transaction; the composite key checks the same.
    if let Some((job, run)) = new.origin {
        let named = sql_query(
            "SELECT EXISTS (SELECT 1 FROM stage_runs \
                             WHERE tenant_id = $1 AND job_id = $2 AND id = $3) AS found",
        )
        .bind::<SqlUuid, _>(tenant.as_uuid())
        .bind::<SqlUuid, _>(job.as_uuid())
        .bind::<SqlUuid, _>(run.as_uuid())
        .get_result::<Found>(connection)
        .await
        .map_err(|error| database(operation, &error))?;
        if !named.found {
            return Err(StoreError::NotFound);
        }
    }
    sql_query(
        "INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend, \
                created_by_job_id, created_by_stage_run_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (tenant_id, content_sha256) DO NOTHING",
    )
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<Text, _>(new.sha256.as_str())
    .bind::<BigInt, _>(new.size_bytes.get())
    .bind::<Text, _>(new.media_type.as_str())
    .bind::<Text, _>(backend.label())
    .bind::<Nullable<SqlUuid>, _>(new.origin.map(|(job, _)| job.as_uuid()))
    .bind::<Nullable<SqlUuid>, _>(new.origin.map(|(_, run)| run.as_uuid()))
    .execute(connection)
    .await
    .map_err(|error| database(operation, &error))?;
    // The first row wins: a second index call for the same hash returns it.
    get(connection, tenant, &new.sha256)
        .await?
        .ok_or(StoreError::NotFound)
}

#[async_trait]
impl ArtifactIndexOps for PgTx {
    async fn index_artifact(
        &mut self,
        new: NewArtifactIndexEntry,
    ) -> Result<ArtifactIndexEntry, StoreError> {
        let backend = self.artifact_backend();
        call!(self, connection, tenant => index(connection, tenant, backend, new))
    }

    async fn get_artifact_index(
        &mut self,
        sha256: &Sha256Digest,
    ) -> Result<ArtifactIndexEntry, StoreError> {
        call!(self, connection, tenant => async {
            get(connection, tenant, sha256).await?.ok_or(StoreError::NotFound)
        })
    }
}
