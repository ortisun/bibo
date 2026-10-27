//! The tenant's index of the artifacts it holds (ADR 0008).
//!
//! The bytes live behind the `ArtifactStore` port. This table says which tenant may read which
//! hash. A reference with no size is stored with size 0, because the column is `NOT NULL`, and it
//! is read back with that size.

use diesel::sql_query;
use diesel::sql_types::{BigInt, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel::{OptionalExtension, QueryableByName};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::TenantId;
use factory_domain::values::{MediaType, NonNegativeInt, Sha256Digest};
use factory_ports::store::{ArtifactIndexEntry, NewArtifactIndexEntry, StoreError};
use time::OffsetDateTime;
use uuid::Uuid;

use super::conv::{
    corrupt, digest_from_column, from_column, job_from_column, stage_run_from_column,
    stage_run_to_column, tenant_from_column, tenant_to_column, to_column,
};
use super::error::{Failure, constraint, generic};
use super::store::Settings;

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
    created_by_stage_run_id: Option<Uuid>,
    #[diesel(sql_type = Timestamptz)]
    created_at: OffsetDateTime,
}

#[derive(QueryableByName)]
struct JobOfRun {
    #[diesel(sql_type = SqlUuid)]
    job_id: Uuid,
}

fn entry_from_row(row: ArtifactRow) -> Result<ArtifactIndexEntry, StoreError> {
    Ok(ArtifactIndexEntry {
        tenant_id: tenant_from_column(row.tenant_id),
        artifact: ArtifactRef {
            sha256: digest_from_column(&row.content_sha256)?,
            media_type: MediaType::parse(&row.media_type).map_err(|_| corrupt("media type"))?,
            size_bytes: Some(NonNegativeInt::new(row.size_bytes).map_err(|_| corrupt("size"))?),
        },
        stage_run_id: row.created_by_stage_run_id.map(stage_run_from_column),
        created_at: from_column(row.created_at),
    })
}

pub(super) async fn index(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    settings: &Settings,
    new: NewArtifactIndexEntry,
) -> Result<ArtifactIndexEntry, StoreError> {
    let tenant_raw = tenant_to_column(tenant);
    // A stage run, when given, must be the tenant's. Its job is recorded with it.
    let (job, run) = match new.stage_run_id {
        Some(run) => {
            let found = sql_query("SELECT job_id FROM stage_runs WHERE tenant_id = $1 AND id = $2")
                .bind::<SqlUuid, _>(tenant_raw)
                .bind::<SqlUuid, _>(stage_run_to_column(run))
                .get_result::<JobOfRun>(connection)
                .await
                .optional()
                .map_err(|error| generic("index_artifact", &error))?;
            let Some(found) = found else {
                return Err(StoreError::NotFound);
            };
            (
                Some(job_from_column(found.job_id)),
                Some(stage_run_to_column(run)),
            )
        }
        None => (None, None),
    };
    let size = new.artifact.size_bytes.map_or(0, |size| size.get());
    sql_query(
        "INSERT INTO artifacts (tenant_id, content_sha256, size_bytes, media_type, backend, \
                created_by_job_id, created_by_stage_run_id, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (tenant_id, content_sha256) DO NOTHING",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<Text, _>(new.artifact.sha256.as_str())
    .bind::<BigInt, _>(size)
    .bind::<Text, _>(new.artifact.media_type.as_str())
    .bind::<Text, _>(settings.artifact_backend.label())
    .bind::<Nullable<SqlUuid>, _>(job.map(|job| job.as_uuid()))
    .bind::<Nullable<SqlUuid>, _>(run)
    .bind::<Timestamptz, _>(to_column(&new.created_at))
    .execute(connection)
    .await
    .map_err(|error| match Failure::of(&error) {
        Failure::Check(name) => constraint("check violation", name.as_deref()),
        Failure::ForeignKey(name) => constraint("foreign key violation", name.as_deref()),
        _ => generic("index_artifact", &error),
    })?;
    get(connection, tenant, &new.artifact.sha256).await
}

pub(super) async fn get(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    sha256: &Sha256Digest,
) -> Result<ArtifactIndexEntry, StoreError> {
    let row = sql_query(
        "SELECT tenant_id, content_sha256, size_bytes, media_type, created_by_stage_run_id, created_at \
           FROM artifacts WHERE tenant_id = $1 AND content_sha256 = $2",
    )
    .bind::<SqlUuid, _>(tenant_to_column(tenant))
    .bind::<Text, _>(sha256.as_str())
    .get_result::<ArtifactRow>(connection)
    .await
    .optional()
    .map_err(|error| generic("get_artifact_index", &error))?;
    row.map_or(Err(StoreError::NotFound), entry_from_row)
}
