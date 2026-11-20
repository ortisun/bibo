//! An in-memory `ArtifactStore`.
//!
//! Blobs are kept in a map under the SHA-256 of their bytes, written once and never replaced,
//! re-hashed on every read, and refused above a size limit. That is what the content-addressed
//! store of ADR 0008 promises, without a disk.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::TenantId;
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, NonNegativeInt, Sha256Digest};
use factory_domain::vocabulary::Fidelity;
use factory_ports::artifact::{ArtifactBackend, ArtifactError, ArtifactStore, BackendStep};

use crate::contracts::artifact::ArtifactStoreSubject;
use crate::store::InMemoryStore;

/// The size limit of a store built with [`InMemoryArtifactStore::new`]: 1 MiB.
pub const DEFAULT_LIMIT: u64 = 1024 * 1024;

/// A deliberate fault, for proving that the contract suite can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactDefect {
    /// The address is a running counter, not the hash of the bytes.
    NotContentAddressed,
    /// `get` returns the stored bytes without re-hashing them.
    SkipsRehashOnGet,
    /// `put` accepts any size.
    IgnoresSizeLimit,
    /// The reference of a repeated write keeps the media type of the first write.
    KeepsFirstMediaType,
    /// `get` and `exists` ignore the tenant's index row.
    IgnoresTenantIndex,
    /// The address is the hash of the length, so equal-length objects collide.
    AddressesByLength,
    /// `get` of an unknown hash returns an empty blob instead of `NotFound`.
    ReadsUnknownAsEmpty,
}

/// Each defect and the checks of `contracts::artifact` that must fail when the fake has it.
pub const DEFECTS: &[(ArtifactDefect, &[&str])] = &[
    (
        ArtifactDefect::NotContentAddressed,
        &[
            "stored_bytes_come_back_unchanged_with_a_reference_that_describes_them",
            "the_same_bytes_give_the_same_reference",
            "empty_content_can_be_stored",
            "concurrent_writes_of_the_same_bytes_agree",
        ],
    ),
    (
        ArtifactDefect::AddressesByLength,
        &["different_objects_are_kept_apart"],
    ),
    (
        ArtifactDefect::ReadsUnknownAsEmpty,
        &["an_unknown_hash_is_not_found_and_does_not_exist"],
    ),
    (
        ArtifactDefect::SkipsRehashOnGet,
        &["a_damaged_blob_is_never_returned"],
    ),
    (
        ArtifactDefect::IgnoresSizeLimit,
        &["an_object_over_the_limit_is_refused"],
    ),
    (
        ArtifactDefect::KeepsFirstMediaType,
        &["the_same_bytes_with_another_media_type_share_one_hash"],
    ),
    (
        ArtifactDefect::IgnoresTenantIndex,
        &["a_blob_is_readable_only_through_the_tenants_index_row"],
    ),
];

#[derive(Default)]
struct State {
    blobs: HashMap<String, Vec<u8>>,
    media_types: HashMap<String, MediaType>,
    counter: u64,
    indexed: BTreeSet<(TenantId, String)>,
}

/// An in-memory artifact store. Reports fidelity `fake` and the `local-fs` backend label, because
/// it stands in for the Slice 1 adapter.
pub struct InMemoryArtifactStore {
    state: Mutex<State>,
    limit: u64,
    defect: Option<ArtifactDefect>,
    index: Option<InMemoryStore>,
}

impl InMemoryArtifactStore {
    /// A store with the default size limit.
    #[must_use]
    pub fn new() -> Self {
        Self::with_limit(DEFAULT_LIMIT)
    }

    /// A store that refuses objects larger than `limit` bytes.
    #[must_use]
    pub fn with_limit(limit: u64) -> Self {
        Self {
            state: Mutex::new(State::default()),
            limit,
            defect: None,
            index: None,
        }
    }

    /// A store that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(limit: u64, defect: ArtifactDefect) -> Self {
        Self {
            defect: Some(defect),
            ..Self::with_limit(limit)
        }
    }

    /// Damages the blob stored under `sha256` by flipping its first byte (or adding one to an
    /// empty blob). A test uses this to prove that a damaged blob is never returned.
    pub fn corrupt(&self, sha256: &Sha256Digest) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        if let Some(blob) = state.blobs.get_mut(sha256.as_str()) {
            match blob.first_mut() {
                Some(first) => *first ^= 0xff,
                None => blob.push(0xff),
            }
        }
    }

    /// Records that the tenant's index row names the artifact.
    pub fn grant(&self, tenant: TenantId, sha256: &Sha256Digest) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        state.indexed.insert((tenant, sha256.to_string()));
    }

    /// Makes the tenant's index rows in `store` decide who may read, as the database adapter does
    /// (ports-v1.1, `ArtifactStore`: "reads the index through the same store"). A row that a
    /// transaction of `store` committed grants the tenant its artifact with no call to
    /// [`grant`](Self::grant). Rows granted by hand still count.
    #[must_use]
    pub fn indexed_by(mut self, store: InMemoryStore) -> Self {
        self.index = Some(store);
        self
    }

    fn allowed(&self, state: &State, tenant: TenantId, sha256: &Sha256Digest) -> bool {
        self.is(ArtifactDefect::IgnoresTenantIndex)
            || state.indexed.contains(&(tenant, sha256.to_string()))
            || self
                .index
                .as_ref()
                .is_some_and(|store| store.holds_artifact(tenant, sha256))
    }

    fn is(&self, defect: ArtifactDefect) -> bool {
        self.defect == Some(defect)
    }
}

impl Default for InMemoryArtifactStore {
    fn default() -> Self {
        Self::new()
    }
}

fn size_of(bytes: &[u8]) -> Result<NonNegativeInt, ArtifactError> {
    i64::try_from(bytes.len())
        .ok()
        .and_then(|size| NonNegativeInt::new(size).ok())
        .ok_or(ArtifactError::Io(BackendStep::Write))
}

#[async_trait]
impl ArtifactStore for InMemoryArtifactStore {
    fn backend(&self) -> ArtifactBackend {
        ArtifactBackend::LocalFs
    }

    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn put(
        &self,
        bytes: Vec<u8>,
        media_type: MediaType,
    ) -> Result<ArtifactRef, ArtifactError> {
        if !self.is(ArtifactDefect::IgnoresSizeLimit) && bytes.len() as u64 > self.limit {
            return Err(ArtifactError::TooLarge { limit: self.limit });
        }
        let size = size_of(&bytes)?;
        let mut state = self.state.lock().expect("the lock is never poisoned");
        let sha256 = if self.is(ArtifactDefect::NotContentAddressed) {
            state.counter += 1;
            Sha256Digest::of(&state.counter.to_be_bytes())
        } else if self.is(ArtifactDefect::AddressesByLength) {
            Sha256Digest::of(&(bytes.len() as u64).to_be_bytes())
        } else {
            Sha256Digest::of(&bytes)
        };
        let key = sha256.to_string();
        // Never overwrite: the first write of a hash is the only one that stores.
        state.blobs.entry(key.clone()).or_insert(bytes);
        let first_media_type = state
            .media_types
            .entry(key)
            .or_insert_with(|| media_type.clone())
            .clone();
        let media_type = if self.is(ArtifactDefect::KeepsFirstMediaType) {
            first_media_type
        } else {
            media_type
        };
        Ok(ArtifactRef {
            sha256,
            media_type,
            size_bytes: Some(size),
        })
    }

    async fn get(
        &self,
        scope: &TenantScope,
        reference: &ArtifactRef,
    ) -> Result<Vec<u8>, ArtifactError> {
        let state = self.state.lock().expect("the lock is never poisoned");
        if !self.allowed(&state, scope.tenant_id(), &reference.sha256) {
            return Err(ArtifactError::NotFound);
        }
        if self.is(ArtifactDefect::ReadsUnknownAsEmpty)
            && !state.blobs.contains_key(reference.sha256.as_str())
        {
            return Ok(Vec::new());
        }
        let blob = state
            .blobs
            .get(reference.sha256.as_str())
            .ok_or(ArtifactError::NotFound)?;
        if !self.is(ArtifactDefect::SkipsRehashOnGet) {
            let actual = Sha256Digest::of(blob);
            if actual != reference.sha256 {
                return Err(ArtifactError::HashMismatch {
                    expected: reference.sha256.clone(),
                    actual,
                });
            }
        }
        Ok(blob.clone())
    }

    async fn exists(
        &self,
        scope: &TenantScope,
        reference: &ArtifactRef,
    ) -> Result<bool, ArtifactError> {
        let state = self.state.lock().expect("the lock is never poisoned");
        Ok(self.allowed(&state, scope.tenant_id(), &reference.sha256)
            && (state.blobs.contains_key(reference.sha256.as_str())
                || self.is(ArtifactDefect::ReadsUnknownAsEmpty)))
    }
}

/// The in-memory artifact store packaged as a subject of the contract suite.
pub struct InMemoryArtifactSubject {
    store: InMemoryArtifactStore,
    limit: u64,
}

impl InMemoryArtifactSubject {
    /// The size limit the subject's store uses. It is small so the limit check is quick.
    pub const LIMIT: u64 = 4096;

    /// A faithful store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: InMemoryArtifactStore::with_limit(Self::LIMIT),
            limit: Self::LIMIT,
        }
    }

    /// A store that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(defect: ArtifactDefect) -> Self {
        Self {
            store: InMemoryArtifactStore::with_defect(Self::LIMIT, defect),
            limit: Self::LIMIT,
        }
    }
}

impl Default for InMemoryArtifactSubject {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ArtifactStoreSubject for InMemoryArtifactSubject {
    fn store(&self) -> &dyn ArtifactStore {
        &self.store
    }

    fn max_object_bytes(&self) -> u64 {
        self.limit
    }

    async fn corrupt_blob(&self, sha256: &Sha256Digest) {
        self.store.corrupt(sha256);
    }

    fn scope(&self) -> TenantScope {
        TenantScope::new(Self::tenant())
    }

    fn other_scope(&self) -> TenantScope {
        TenantScope::new(Self::other_tenant())
    }

    async fn index_for(&self, scope: &TenantScope, reference: &ArtifactRef) {
        self.store.grant(scope.tenant_id(), &reference.sha256);
    }
}

impl InMemoryArtifactSubject {
    fn tenant() -> TenantId {
        TenantId::parse("00000000-0000-7000-8000-00000000000a").expect("a valid tenant id")
    }

    fn other_tenant() -> TenantId {
        TenantId::parse("00000000-0000-7000-8000-00000000000b").expect("a valid tenant id")
    }
}
