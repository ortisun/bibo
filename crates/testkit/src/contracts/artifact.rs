//! The contract suite for the `ArtifactStore` port: content addressing, idempotent writes,
//! integrity on read and the size limit.

use std::future::Future;

use async_trait::async_trait;
use factory_domain::values::{MediaType, Sha256Digest};
use factory_ports::artifact::{ArtifactError, ArtifactStore};

use super::{Check, Context, Report, check_list, ensure, ensure_eq, ensure_err, run_checks};

/// What the suite needs beyond the `ArtifactStore` port itself.
#[async_trait]
pub trait ArtifactStoreSubject: Send + Sync {
    /// The store under test. It starts empty and is used by one check only.
    fn store(&self) -> &dyn ArtifactStore;

    /// The largest object the store accepts, in bytes.
    fn max_object_bytes(&self) -> u64;

    /// Damages the stored blob for `sha256`, so its bytes no longer hash to its address. A fake
    /// edits its map. A file store flips a byte in the file.
    async fn corrupt_blob(&self, sha256: &Sha256Digest);
}

/// A check of the artifact store contract.
pub type ArtifactCheck = Check<dyn ArtifactStoreSubject>;

/// Runs the whole suite. `make` builds a fresh, empty subject for every check.
pub async fn run<S, F, Fut>(make: F) -> Report
where
    S: ArtifactStoreSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&checks(), || async {
        Box::new(make().await) as Box<dyn ArtifactStoreSubject>
    })
    .await
}

/// Every check of the artifact store contract.
#[must_use]
pub fn checks() -> Vec<ArtifactCheck> {
    check_list![dyn ArtifactStoreSubject;
        stored_bytes_come_back_unchanged_with_a_reference_that_describes_them,
        the_same_bytes_give_the_same_reference,
        the_same_bytes_with_another_media_type_share_one_hash,
        empty_content_can_be_stored,
        an_unknown_hash_is_not_found_and_does_not_exist,
        a_damaged_blob_is_never_returned,
        an_object_over_the_limit_is_refused,
        concurrent_writes_of_the_same_bytes_agree,
        different_objects_are_kept_apart,
    ]
}

fn text() -> Result<MediaType, String> {
    MediaType::parse("text/plain").ctx("media type")
}

async fn stored_bytes_come_back_unchanged_with_a_reference_that_describes_them(
    subject: &dyn ArtifactStoreSubject,
) -> Result<(), String> {
    let store = subject.store();
    let bytes = b"stdout of a gate run\n".to_vec();
    let reference = store.put(bytes.clone(), text()?).await.ctx("put")?;
    ensure_eq!(
        reference.sha256,
        Sha256Digest::of(&bytes),
        "the reference's hash must be the SHA-256 of the bytes"
    );
    ensure_eq!(
        reference.size_bytes.map(|size| size.get()),
        Some(i64::try_from(bytes.len()).ctx("length")?),
        "the reference's size"
    );
    ensure_eq!(reference.media_type, text()?, "the reference's media type");
    ensure_eq!(
        store.get(&reference).await.ctx("get")?,
        bytes,
        "the bytes read back"
    );
    ensure!(
        store.exists(&reference).await.ctx("exists")?,
        "a stored artifact must exist"
    );
    Ok(())
}

async fn the_same_bytes_give_the_same_reference(
    subject: &dyn ArtifactStoreSubject,
) -> Result<(), String> {
    let store = subject.store();
    let first = store
        .put(b"same".to_vec(), text()?)
        .await
        .ctx("first put")?;
    let second = store
        .put(b"same".to_vec(), text()?)
        .await
        .ctx("second put")?;
    ensure_eq!(second, first, "the reference of the same bytes put twice");
    Ok(())
}

async fn the_same_bytes_with_another_media_type_share_one_hash(
    subject: &dyn ArtifactStoreSubject,
) -> Result<(), String> {
    let store = subject.store();
    let json = MediaType::parse("application/json").ctx("media type")?;
    let as_text = store
        .put(b"{}".to_vec(), text()?)
        .await
        .ctx("put as text")?;
    let as_json = store
        .put(b"{}".to_vec(), json.clone())
        .await
        .ctx("put as json")?;
    ensure_eq!(as_json.sha256, as_text.sha256, "the hash of the same bytes");
    ensure_eq!(
        as_text.media_type,
        text()?,
        "the first reference keeps its media type"
    );
    ensure_eq!(
        as_json.media_type,
        json,
        "the second reference carries its own media type"
    );
    ensure_eq!(
        store.get(&as_json).await.ctx("get")?,
        b"{}".to_vec(),
        "the bytes read through the second reference"
    );
    Ok(())
}

async fn empty_content_can_be_stored(subject: &dyn ArtifactStoreSubject) -> Result<(), String> {
    let store = subject.store();
    let reference = store.put(Vec::new(), text()?).await.ctx("put")?;
    ensure_eq!(
        reference.sha256,
        Sha256Digest::of(&[]),
        "the hash of nothing"
    );
    ensure_eq!(
        store.get(&reference).await.ctx("get")?,
        Vec::<u8>::new(),
        "the bytes read back"
    );
    Ok(())
}

async fn an_unknown_hash_is_not_found_and_does_not_exist(
    subject: &dyn ArtifactStoreSubject,
) -> Result<(), String> {
    let store = subject.store();
    // A reference to bytes that were never stored.
    let stored = store.put(b"present".to_vec(), text()?).await.ctx("put")?;
    let mut unknown = stored.clone();
    unknown.sha256 = Sha256Digest::of(b"absent");
    ensure_err!(
        store.get(&unknown).await,
        ArtifactError::NotFound,
        "get of an unknown hash"
    );
    ensure!(
        !store.exists(&unknown).await.ctx("exists")?,
        "an unknown hash must not exist"
    );
    Ok(())
}

async fn a_damaged_blob_is_never_returned(
    subject: &dyn ArtifactStoreSubject,
) -> Result<(), String> {
    let store = subject.store();
    let reference = store
        .put(b"original bytes".to_vec(), text()?)
        .await
        .ctx("put")?;
    subject.corrupt_blob(&reference.sha256).await;
    match store.get(&reference).await {
        Err(ArtifactError::HashMismatch { expected, actual }) => {
            ensure_eq!(
                expected,
                reference.sha256.clone(),
                "the hash the blob is stored under"
            );
            ensure!(
                actual != expected,
                "the reported actual hash must differ from the expected one"
            );
            Ok(())
        }
        Err(other) => Err(format!(
            "a damaged blob: expected HashMismatch but found {other:?}"
        )),
        Ok(bytes) => Err(format!(
            "a damaged blob: expected HashMismatch but the store returned {} byte(s)",
            bytes.len()
        )),
    }
}

async fn an_object_over_the_limit_is_refused(
    subject: &dyn ArtifactStoreSubject,
) -> Result<(), String> {
    let store = subject.store();
    let limit = subject.max_object_bytes();
    let size = usize::try_from(limit).ctx("limit as a length")?;
    let at_limit = store
        .put(vec![7_u8; size], text()?)
        .await
        .ctx("an object exactly at the limit")?;
    ensure!(
        store.exists(&at_limit).await.ctx("exists")?,
        "an object at the limit must be stored"
    );
    ensure_err!(
        store.put(vec![7_u8; size + 1], text()?).await,
        ArtifactError::TooLarge { .. },
        "an object one byte over the limit"
    );
    Ok(())
}

async fn concurrent_writes_of_the_same_bytes_agree(
    subject: &dyn ArtifactStoreSubject,
) -> Result<(), String> {
    let store = subject.store();
    let media = text()?;
    let (one, two) = tokio::join!(
        store.put(b"raced".to_vec(), media.clone()),
        store.put(b"raced".to_vec(), media.clone()),
    );
    let (one, two) = (one.ctx("first writer")?, two.ctx("second writer")?);
    ensure_eq!(
        one,
        two,
        "the references of two concurrent writes of the same bytes"
    );
    ensure_eq!(
        store.get(&one).await.ctx("get")?,
        b"raced".to_vec(),
        "the stored bytes"
    );
    Ok(())
}

async fn different_objects_are_kept_apart(
    subject: &dyn ArtifactStoreSubject,
) -> Result<(), String> {
    let store = subject.store();
    let mut references = Vec::new();
    for number in 0..20_u8 {
        let bytes = vec![number; usize::from(number) + 1];
        references.push((store.put(bytes.clone(), text()?).await.ctx("put")?, bytes));
    }
    for (reference, bytes) in &references {
        ensure_eq!(
            store.get(reference).await.ctx("get")?,
            bytes.clone(),
            "an object read back"
        );
    }
    Ok(())
}
