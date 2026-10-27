//! Tenant-scoped access to artifact blobs (architecture review F-15).
//!
//! A blob is stored once, by hash, and may be shared by tenants. ADR 0008 says a tenant reaches it
//! only through its own row in the artifact index, so that one tenant cannot learn that another
//! holds a given blob. The `ArtifactStore` port takes only a reference: anyone who holds a hash can
//! read the blob, and `exists` tells whether anyone holds those bytes. The port does not check the
//! index, and it is not changed here.
//!
//! [`TenantArtifacts`] is the way in for code that acts for a tenant. Its methods take a
//! [`TenantScope`], which cannot be made from request text, and every read first asks the store for
//! the tenant's index row in a transaction for that tenant (so row-level security applies). With no
//! row the answer is the same as for a blob that does not exist:
//!
//! * `get` gives `NotFound`;
//! * `exists` gives `false`.
//!
//! A caller cannot tell "no such blob" from "a blob that another tenant holds". The raw blob store
//! stays available to the code that writes and verifies blobs, and its `get` is documented as
//! unscoped. Only the composition root can reach it.
//!
//! The layer works with any `Store`, the PostgreSQL one or the in-memory fake.

use std::sync::Arc;

use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::StageRunId;
use factory_domain::scope::TenantScope;
use factory_domain::values::MediaType;
use factory_ports::artifact::{ArtifactError, ArtifactStore};
use factory_ports::store::{NewArtifactIndexEntry, Store, StoreError};

/// What a failed index call means for an artifact call. `NotFound` stays `NotFound`. Every other
/// failure is reported without the store's text.
fn from_store(error: &StoreError) -> ArtifactError {
    match error {
        StoreError::NotFound => ArtifactError::NotFound,
        StoreError::Unavailable => {
            ArtifactError::Io("the artifact index is unavailable".to_owned())
        }
        _ => ArtifactError::Io("the artifact index refused the call".to_owned()),
    }
}

/// Reads and writes artifact blobs for one tenant at a time.
#[derive(Clone)]
pub struct TenantArtifacts {
    blobs: Arc<dyn ArtifactStore>,
    store: Arc<dyn Store>,
}

impl std::fmt::Debug for TenantArtifacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantArtifacts").finish_non_exhaustive()
    }
}

impl TenantArtifacts {
    /// Joins a blob store and the store that holds the tenants' artifact index.
    #[must_use]
    pub fn new(blobs: Arc<dyn ArtifactStore>, store: Arc<dyn Store>) -> Self {
        Self { blobs, store }
    }

    /// Whether the tenant's index has a row for the hash. The transaction is read only and is
    /// rolled back.
    async fn indexed(
        &self,
        scope: TenantScope,
        reference: &ArtifactRef,
    ) -> Result<bool, ArtifactError> {
        let mut tx = self
            .store
            .begin(scope)
            .await
            .map_err(|error| from_store(&error))?;
        let found = match tx.get_artifact_index(&reference.sha256).await {
            Ok(_) => Ok(true),
            Err(StoreError::NotFound) => Ok(false),
            Err(error) => Err(from_store(&error)),
        };
        // A failed rollback of a read-only transaction changes nothing for the caller.
        let _ = tx.rollback().await;
        found
    }

    /// Stores the bytes and records, in the tenant's index, that the tenant holds them.
    ///
    /// The blob is written first. If the index row cannot be committed the blob stays, unreferenced
    /// and harmless: it is addressed by its hash, and a later call with the same bytes finishes the
    /// job.
    ///
    /// # Errors
    /// The errors of the blob store, and [`ArtifactError::Io`] when the index cannot take the row
    /// (including a stage run that is not the tenant's).
    pub async fn put(
        &self,
        scope: TenantScope,
        bytes: Vec<u8>,
        media_type: MediaType,
        stage_run: Option<StageRunId>,
    ) -> Result<ArtifactRef, ArtifactError> {
        let reference = self.blobs.put(bytes, media_type).await?;
        let mut tx = self
            .store
            .begin(scope)
            .await
            .map_err(|error| from_store(&error))?;
        let created_at = tx
            .database_time()
            .await
            .map_err(|error| from_store(&error))?;
        tx.index_artifact(NewArtifactIndexEntry {
            artifact: reference.clone(),
            stage_run_id: stage_run,
            created_at,
        })
        .await
        .map_err(|error| match error {
            StoreError::NotFound => {
                ArtifactError::Io("the stage run is not the tenant's".to_owned())
            }
            other => from_store(&other),
        })?;
        tx.commit().await.map_err(|error| from_store(&error))?;
        Ok(reference)
    }

    /// Returns the bytes, if the tenant's index says the tenant holds them.
    ///
    /// # Errors
    /// [`ArtifactError::NotFound`] when the tenant has no index row for the hash, which is also
    /// what a blob that does not exist gives. Otherwise the errors of the blob store.
    pub async fn get(
        &self,
        scope: TenantScope,
        reference: &ArtifactRef,
    ) -> Result<Vec<u8>, ArtifactError> {
        if !self.indexed(scope, reference).await? {
            return Err(ArtifactError::NotFound);
        }
        self.blobs.get(reference).await
    }

    /// True when the tenant's index has a row for the hash and the blob is stored. A hash that
    /// only another tenant holds gives `false`, so this is no oracle for other tenants' content.
    ///
    /// # Errors
    /// The errors of the blob store and [`ArtifactError::Io`] when the index is unavailable.
    pub async fn exists(
        &self,
        scope: TenantScope,
        reference: &ArtifactRef,
    ) -> Result<bool, ArtifactError> {
        if !self.indexed(scope, reference).await? {
            return Ok(false);
        }
        self.blobs.exists(reference).await
    }
}
