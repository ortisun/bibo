//! An artifact store that a test can make refuse writes, around the one a backend provides.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::scope::TenantScope;
use factory_domain::values::MediaType;
use factory_domain::vocabulary::Fidelity;
use factory_ports::artifact::{ArtifactBackend, ArtifactError, ArtifactStore, BackendStep};

/// Delegates to another artifact store, and refuses every `put` while `refusing` is set.
pub struct SwitchedArtifacts {
    inner: Arc<dyn ArtifactStore>,
    refusing: AtomicBool,
}

impl SwitchedArtifacts {
    pub fn new(inner: Arc<dyn ArtifactStore>) -> Self {
        Self {
            inner,
            refusing: AtomicBool::new(false),
        }
    }

    /// While `refuse` is true, `put` fails as a backend that cannot write does.
    pub fn refuse_writes(&self, refuse: bool) {
        self.refusing.store(refuse, Ordering::SeqCst);
    }
}

#[async_trait]
impl ArtifactStore for SwitchedArtifacts {
    fn backend(&self) -> ArtifactBackend {
        self.inner.backend()
    }

    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    async fn put(
        &self,
        bytes: Vec<u8>,
        media_type: MediaType,
    ) -> Result<ArtifactRef, ArtifactError> {
        if self.refusing.load(Ordering::SeqCst) {
            return Err(ArtifactError::Io(BackendStep::Write));
        }
        self.inner.put(bytes, media_type).await
    }

    async fn get(
        &self,
        scope: &TenantScope,
        reference: &ArtifactRef,
    ) -> Result<Vec<u8>, ArtifactError> {
        self.inner.get(scope, reference).await
    }

    async fn exists(
        &self,
        scope: &TenantScope,
        reference: &ArtifactRef,
    ) -> Result<bool, ArtifactError> {
        self.inner.exists(scope, reference).await
    }
}
