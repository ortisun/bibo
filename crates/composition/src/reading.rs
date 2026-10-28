//! Reading what the engine stored, for the seams that answer from stored evidence.
//!
//! The engine keeps a stage run's outputs as links (`StageArtifactOps`) under the role
//! `<deliverable>.a<attempt>`, keeps each gate decision as ledger entries, and keeps every blob in
//! the artifact store under its hash, indexed for the tenant. These helpers read those three
//! places and nothing else. Every method opens a tenant transaction that the caller rolls back:
//! a seam only reads.

use std::collections::BTreeMap;
use std::sync::Arc;

use factory_domain::contracts::{ArtifactRef, EvidenceLedgerEntry};
use factory_domain::ids::{JobId, StageRunId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::values::Sha256Digest;
use factory_ports::artifact::ArtifactStore;
use factory_ports::store::{ArtifactDirection, Store, Tx};
use factory_workflow::engine::links::parse_output_role;
use factory_workflow::stages::intake::seams::SeamError;

/// The ledger is read in pages of this many entries.
const PAGE: u32 = 500;

/// Reads stage run outputs, ledger entries and blobs for one tenant at a time.
#[derive(Clone)]
pub struct Reader {
    store: Arc<dyn Store>,
    artifacts: Arc<dyn ArtifactStore>,
}

impl Reader {
    /// A reader over the store and the artifact store.
    #[must_use]
    pub fn new(store: Arc<dyn Store>, artifacts: Arc<dyn ArtifactStore>) -> Self {
        Self { store, artifacts }
    }

    /// The store, for a seam that also writes.
    #[must_use]
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    /// The artifact store.
    #[must_use]
    pub fn artifacts(&self) -> &Arc<dyn ArtifactStore> {
        &self.artifacts
    }

    /// A tenant transaction.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`].
    pub async fn begin(&self, tenant: TenantId) -> Result<Box<dyn Tx>, SeamError> {
        self.store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| SeamError::Unavailable)
    }

    /// What a stage run produced: each deliverable name with the hash of the newest attempt's
    /// version. A role that does not follow the engine's form was not written by the engine and is
    /// skipped.
    ///
    /// # Errors
    /// [`SeamError::NotFound`] when the stage run is not the tenant's, [`SeamError::Unavailable`].
    pub async fn outputs(
        tx: &mut dyn Tx,
        stage_run: StageRunId,
    ) -> Result<BTreeMap<String, Sha256Digest>, SeamError> {
        let links = tx
            .list_stage_run_artifacts(stage_run)
            .await
            .map_err(|error| match error {
                factory_ports::store::StoreError::NotFound => SeamError::NotFound,
                _ => SeamError::Unavailable,
            })?;
        let mut newest: BTreeMap<String, (u32, Sha256Digest)> = BTreeMap::new();
        for link in links {
            if link.direction != ArtifactDirection::Output {
                continue;
            }
            let Some((name, attempt)) = parse_output_role(link.role.as_str()) else {
                continue;
            };
            let slot = newest
                .entry(name.as_str().to_owned())
                .or_insert((attempt, link.sha256.clone()));
            if attempt >= slot.0 {
                *slot = (attempt, link.sha256);
            }
        }
        Ok(newest
            .into_iter()
            .map(|(name, (_, sha256))| (name, sha256))
            .collect())
    }

    /// The reference of an artifact the tenant has indexed.
    ///
    /// # Errors
    /// [`SeamError::NotFound`] when the tenant has not indexed the hash.
    pub async fn reference(
        tx: &mut dyn Tx,
        sha256: &Sha256Digest,
    ) -> Result<ArtifactRef, SeamError> {
        tx.get_artifact_index(sha256)
            .await
            .map(|entry| entry.artifact)
            .map_err(|error| match error {
                factory_ports::store::StoreError::NotFound => SeamError::NotFound,
                _ => SeamError::Unavailable,
            })
    }

    /// The bytes of an artifact the tenant has indexed.
    ///
    /// # Errors
    /// [`SeamError::NotFound`], [`SeamError::Unavailable`].
    pub async fn bytes(
        &self,
        tx: &mut dyn Tx,
        tenant: TenantId,
        sha256: &Sha256Digest,
    ) -> Result<Vec<u8>, SeamError> {
        let reference = Self::reference(tx, sha256).await?;
        self.artifacts
            .get(&TenantScope::new(tenant), &reference)
            .await
            .map_err(|error| match error {
                factory_ports::artifact::ArtifactError::NotFound => SeamError::NotFound,
                _ => SeamError::Unavailable,
            })
    }

    /// Every ledger entry of the job, oldest first.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`].
    pub async fn job_ledger(
        tx: &mut dyn Tx,
        job: JobId,
    ) -> Result<Vec<EvidenceLedgerEntry>, SeamError> {
        let mut found = Vec::new();
        let mut from = 1_u64;
        loop {
            let page = tx
                .read_ledger(job, from, PAGE)
                .await
                .map_err(|_| SeamError::Unavailable)?;
            let count = page.len();
            let last = page.last().map(|entry| entry.metadata.sequence.get());
            found.extend(page);
            match last {
                Some(last) if count == PAGE as usize => {
                    from = u64::try_from(last).unwrap_or(u64::MAX).saturating_add(1);
                }
                _ => break,
            }
        }
        Ok(found)
    }

    /// The ledger entries of one stage run, oldest first.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`].
    pub async fn run_ledger(
        tx: &mut dyn Tx,
        job: JobId,
        stage_run: StageRunId,
    ) -> Result<Vec<EvidenceLedgerEntry>, SeamError> {
        Ok(Self::job_ledger(tx, job)
            .await?
            .into_iter()
            .filter(|entry| entry.metadata.stage_run_id == stage_run)
            .collect())
    }
}
