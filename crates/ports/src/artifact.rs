//! The artifact store port: immutable blobs addressed by their content hash (ADR 0008).
//!
//! Logs, transcripts, diffs and reports are artifacts. A blob is written once and never changes,
//! so a hash in the ledger or in a pull request body keeps meaning the same bytes. Who may read a
//! blob is decided here: `get` and `exists` take the tenant's scope and answer only for a hash
//! that the tenant's index row names (`ArtifactIndexOps`, ports-v1.1 decision 9).

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, Sha256Digest};
use factory_domain::vocabulary::Fidelity;

/// Where the bytes physically live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactBackend {
    /// A directory on the local file system (Slice 1). It is not S3 and no document may call it
    /// that.
    LocalFs,
    /// An S3-compatible object store (Slice 2).
    S3Compatible,
}

impl ArtifactBackend {
    /// The label stored in metadata.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::LocalFs => "local-fs",
            Self::S3Compatible => "s3-compatible",
        }
    }
}

/// What the adapter was doing when the backend failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendStep {
    /// Writing a blob.
    Write,
    /// Reading a blob.
    Read,
    /// Reading the tenant's index row.
    Index,
}

/// Why an artifact call failed. The set is closed. `Io` names the step instead of carrying text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactError {
    /// No blob has this hash, or the tenant has no index row for it. The two look the same.
    #[error("no artifact has this content hash")]
    NotFound,
    /// The stored bytes no longer hash to the address they are stored under: the blob was changed
    /// or damaged. The bytes are not returned.
    #[error(
        "the stored bytes do not match their content hash; expected {expected}, found {actual}"
    )]
    HashMismatch {
        /// The hash the blob is stored under.
        expected: Sha256Digest,
        /// The hash the stored bytes actually have.
        actual: Sha256Digest,
    },
    /// The bytes are larger than the store accepts.
    #[error("the artifact is larger than the limit of {limit} bytes")]
    TooLarge {
        /// The largest size the store accepts, in bytes.
        limit: u64,
    },
    /// The backend failed.
    #[error("the artifact backend failed at {0:?}")]
    Io(BackendStep),
}

/// Content-addressed storage for immutable blobs.
///
/// # Preconditions
/// For `put`, the bytes are no larger than the store's limit. Secrets have already been redacted
/// from logs and transcripts; this port stores exactly what it is given.
///
/// # Postconditions
/// After `put` returns a reference, the blob is stored once, whoever else holds the same bytes.
/// `get` and `exists` answer only for a tenant whose index row (`ArtifactIndexOps`) names the
/// hash: for any other tenant `get` is `NotFound` and `exists` is `false`, so a hash held by
/// another tenant cannot be read and its existence cannot be tested. `get` never returns bytes
/// whose hash differs from the address. The implementation of this port lives with the database
/// adapter and reads the index through the same store.
///
/// # Errors
/// [`ArtifactError::NotFound`] (`get` of an unknown hash, or of a hash the tenant has not
/// indexed), [`ArtifactError::HashMismatch`] (the stored bytes were damaged),
/// [`ArtifactError::TooLarge`] (`put` over the limit) and [`ArtifactError::Io`] (the backend
/// failed, naming the step).
///
/// # Idempotency
/// `put` is idempotent: the same bytes always give the same hash, a second `put` stores nothing
/// new, and an earlier blob is never replaced. The reference carries the media type of the call
/// that made it, so the same bytes put with two media types give two references with one hash.
/// `get` and `exists` are reads.
///
/// # Cancellation and timeouts
/// Every call is safe to drop. A `put` that was dropped may have stored the blob; the next `put`
/// of the same bytes is a no-op. An adapter sets a timeout on every backend call and reports it
/// as `Io` with the step that timed out.
#[async_trait]
pub trait ArtifactStore: Send + Sync {
    /// Where the bytes live: the local file system now, an S3-compatible store in Slice 2.
    fn backend(&self) -> ArtifactBackend;

    /// Says whether this store is the real backend (`real`) or an in-memory stand-in (`fake`).
    /// A production run refuses a store that reports `fake`.
    fn fidelity(&self) -> Fidelity;

    /// Stores the bytes and returns their reference. Never overwrites. Makes no index row: the
    /// caller indexes the artifact for its tenant in the transaction that uses it.
    async fn put(
        &self,
        bytes: Vec<u8>,
        media_type: MediaType,
    ) -> Result<ArtifactRef, ArtifactError>;

    /// Returns the bytes if the tenant's index row names the hash. Re-hashes them on the way out.
    async fn get(
        &self,
        scope: &TenantScope,
        reference: &ArtifactRef,
    ) -> Result<Vec<u8>, ArtifactError>;

    /// True when the tenant's index row names the hash and the blob is stored.
    async fn exists(
        &self,
        scope: &TenantScope,
        reference: &ArtifactRef,
    ) -> Result<bool, ArtifactError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backends_have_distinct_labels_and_the_local_one_is_not_called_s3() {
        assert_eq!(ArtifactBackend::LocalFs.label(), "local-fs");
        assert_eq!(ArtifactBackend::S3Compatible.label(), "s3-compatible");
    }

    #[test]
    fn a_hash_mismatch_names_both_hashes() {
        let error = ArtifactError::HashMismatch {
            expected: Sha256Digest::of(b"a"),
            actual: Sha256Digest::of(b"b"),
        };
        let text = error.to_string();
        assert!(text.contains(Sha256Digest::of(b"a").as_str()));
        assert!(text.contains(Sha256Digest::of(b"b").as_str()));
    }

    #[test]
    fn a_backend_failure_names_the_step_and_nothing_else() {
        let text = ArtifactError::Io(BackendStep::Index).to_string();
        assert_eq!(text, "the artifact backend failed at Index");
    }
}
