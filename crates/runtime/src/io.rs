//! What the adapters share with the outside: the artifact store the sandbox wrote the tool's output
//! to, the tenant that may read it, and the redactor every byte passes before it leaves.
//!
//! `SandboxSession::exec` hands back references to the redacted standard output and standard error
//! of the command. The adapter reads them here. The tenant scope is supplied by the composition
//! root: this crate may not make one (rule ST-13), and the composition root must index the
//! sandbox's output artifacts for that tenant, or `get` answers `NotFound`.

use std::sync::Arc;

use factory_domain::contracts::ArtifactRef;
use factory_domain::redaction::{RedactionError, Redactor};
use factory_domain::scope::TenantScope;
use factory_domain::values::MediaType;
use factory_ports::artifact::{ArtifactError, ArtifactStore};

/// The media type of a stored transcript: one JSON document per line.
pub const TRANSCRIPT_MEDIA_TYPE: &str = "application/x-ndjson";

/// How many bytes of standard error the transcript keeps.
const STDERR_KEPT_BYTES: usize = 64 * 1024;

/// The adapter's view of the artifact store, the tenant and the redactor.
#[derive(Clone)]
pub struct RunIo {
    store: Arc<dyn ArtifactStore>,
    scope: TenantScope,
    redactor: Arc<Redactor>,
}

impl std::fmt::Debug for RunIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunIo").finish_non_exhaustive()
    }
}

impl RunIo {
    /// Wraps the store, the scope of the tenant that owns the runs, and the redactor. The redactor
    /// must have every job token registered by the composition root.
    #[must_use]
    pub fn new(store: Arc<dyn ArtifactStore>, scope: TenantScope, redactor: Arc<Redactor>) -> Self {
        Self {
            store,
            scope,
            redactor,
        }
    }

    /// Reads a stored blob.
    ///
    /// # Errors
    /// The store's [`ArtifactError`].
    pub async fn read(&self, reference: &ArtifactRef) -> Result<Vec<u8>, ArtifactError> {
        self.store.get(&self.scope, reference).await
    }

    /// The bytes with every secret replaced, or `None` when the redactor could not finish. The
    /// policy says raw text is never written because the redactor failed, so a caller drops the
    /// content on `None`.
    #[must_use]
    pub fn redact(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        redact_all(&self.redactor, bytes).ok()
    }

    /// Text with every secret replaced. When the redactor fails the text is dropped.
    #[must_use]
    pub fn redact_text(&self, text: &str) -> String {
        match redact_all(&self.redactor, text.as_bytes()) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(_) => "[text dropped: the redactor could not finish]".to_owned(),
        }
    }

    /// Stores a transcript: the tool's event lines, then one `factory` line with the end of
    /// standard error and a note. Everything is redacted first. If the redactor fails, a notice
    /// is stored in its place.
    pub async fn store_transcript(
        &self,
        stdout: &[u8],
        stderr: &[u8],
        note: &str,
    ) -> Option<ArtifactRef> {
        let mut document = stdout.to_vec();
        if !document.is_empty() && !document.ends_with(b"\n") {
            document.push(b'\n');
        }
        let kept = stderr.len().saturating_sub(STDERR_KEPT_BYTES);
        let stderr_tail = String::from_utf8_lossy(&stderr[kept..]).into_owned();
        let trailer = serde_json::json!({
            "type": "factory",
            "note": note,
            "stderr_tail": stderr_tail,
        });
        document.extend_from_slice(trailer.to_string().as_bytes());
        document.push(b'\n');
        let bytes = self.redact(&document).unwrap_or_else(|| {
            serde_json::json!({
                "type": "factory",
                "note": "transcript dropped: the redactor could not finish",
            })
            .to_string()
            .into_bytes()
        });
        let media_type = MediaType::parse(TRANSCRIPT_MEDIA_TYPE).ok()?;
        match self.store.put(bytes, media_type).await {
            Ok(reference) => Some(reference),
            Err(error) => {
                tracing::warn!(?error, "the transcript could not be stored");
                None
            }
        }
    }
}

/// Redacts any amount of input by streaming it through the redactor.
fn redact_all(redactor: &Redactor, bytes: &[u8]) -> Result<Vec<u8>, RedactionError> {
    let mut stream = redactor.stream();
    let mut out = Vec::with_capacity(bytes.len());
    for chunk in bytes.chunks(8 * 1024) {
        stream.push(chunk, &mut out)?;
    }
    stream.finish(&mut out)?;
    Ok(out)
}
