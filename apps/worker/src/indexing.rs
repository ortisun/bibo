//! Index the artifacts a sandbox writes, for the tenant, when they are written.
//!
//! # The gap this closes
//!
//! `SandboxSession::exec` returns the standard output and error of a command as `ArtifactRef`s
//! that the sandbox adapter wrote with `ArtifactStore::put`. `put` takes no tenant, so it writes
//! the blob and no index row. `ArtifactStore::get(scope, reference)` answers only for a hash
//! that is indexed for the scope's tenant (the cross-tenant rule of ADR 0008). Until the engine
//! indexes the outputs a stage declares, a handler that wants to read what a command printed
//! gets `NotFound`.
//!
//! [`IndexingSandbox`] wraps the sandbox provider. After each `exec` it indexes `stdout` and
//! `stderr` for the tenant that owns the job, in one short tenant transaction, so the handler
//! can read them at once. The tenant comes from [`ActiveJobs`], which the worker loop fills when
//! it claims an attempt: the sandbox spec carries the job and not the tenant, and the composition
//! root is the only place that knows both.
//!
//! The same applies to the workspace patch (`Workspace::ingest`, `JobRepo::export_patch`). This
//! package wraps the sandbox only; the workspace wrapper is not written yet and is listed in the
//! README.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use factory_domain::contracts::ArtifactRef;
use factory_domain::ids::{AttemptId, JobId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::{
    ExecRequest, ExecResult, PostureReport, Resource, SandboxError, SandboxId, SandboxProvider,
    SandboxSession, SandboxSpec, TeardownReason, TeardownReport,
};
use factory_ports::store::{NewArtifactIndexEntry, Store};

/// The jobs this process is working on and the tenant of each.
#[derive(Debug, Default)]
pub struct ActiveJobs {
    tenants: Mutex<HashMap<JobId, TenantId>>,
}

impl ActiveJobs {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Notes that a job is being worked on for a tenant.
    pub fn enter(&self, job: JobId, tenant: TenantId) {
        self.tenants
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(job, tenant);
    }

    /// Notes that the work on a job ended.
    pub fn leave(&self, job: JobId) {
        self.tenants
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&job);
    }

    /// The tenant of a job being worked on.
    #[must_use]
    pub fn tenant_of(&self, job: JobId) -> Option<TenantId> {
        self.tenants
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&job)
            .copied()
    }
}

/// A sandbox provider whose sessions index their outputs.
pub struct IndexingSandbox {
    inner: Arc<dyn SandboxProvider>,
    store: Arc<dyn Store>,
    jobs: Arc<ActiveJobs>,
}

impl IndexingSandbox {
    /// Wraps `inner`.
    #[must_use]
    pub fn new(
        inner: Arc<dyn SandboxProvider>,
        store: Arc<dyn Store>,
        jobs: Arc<ActiveJobs>,
    ) -> Self {
        Self { inner, store, jobs }
    }
}

#[async_trait]
impl SandboxProvider for IndexingSandbox {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    async fn create_verified(
        &self,
        spec: SandboxSpec,
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn SandboxSession>, SandboxError> {
        let job = spec.job;
        let session = self.inner.create_verified(spec, cancel).await?;
        Ok(Box::new(IndexingSession {
            inner: session,
            store: Arc::clone(&self.store),
            jobs: Arc::clone(&self.jobs),
            job,
        }))
    }

    async fn sweep_orphans(&self, live: &[AttemptId]) -> Result<Vec<SandboxId>, SandboxError> {
        self.inner.sweep_orphans(live).await
    }
}

struct IndexingSession {
    inner: Box<dyn SandboxSession>,
    store: Arc<dyn Store>,
    jobs: Arc<ActiveJobs>,
    job: JobId,
}

impl IndexingSession {
    /// Indexes one reference for the job's tenant. A job with no known tenant fails closed.
    async fn index(
        store: &dyn Store,
        jobs: &ActiveJobs,
        job: JobId,
        reference: &ArtifactRef,
    ) -> Result<(), SandboxError> {
        let tenant = jobs
            .tenant_of(job)
            .ok_or(SandboxError::ResourceExceeded(Resource::Disk))?;
        // A reference without a size cannot be indexed; the sandbox adapter always sets one.
        let entry = NewArtifactIndexEntry::from_reference(reference, None)
            .ok_or(SandboxError::ResourceExceeded(Resource::Disk))?;
        let mut tx = store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| SandboxError::ResourceExceeded(Resource::Disk))?;
        let indexed = tx.index_artifact(entry).await;
        match indexed {
            Ok(_) => tx
                .commit()
                .await
                .map_err(|_| SandboxError::ResourceExceeded(Resource::Disk)),
            Err(_) => {
                let _ = tx.rollback().await;
                Err(SandboxError::ResourceExceeded(Resource::Disk))
            }
        }
    }
}

#[async_trait]
impl SandboxSession for IndexingSession {
    fn id(&self) -> &SandboxId {
        self.inner.id()
    }

    fn posture(&self) -> &PostureReport {
        self.inner.posture()
    }

    async fn exec(
        &mut self,
        req: ExecRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<ExecResult, SandboxError> {
        let result = self.inner.exec(req, cancel).await?;
        Self::index(self.store.as_ref(), &self.jobs, self.job, &result.stdout).await?;
        Self::index(self.store.as_ref(), &self.jobs, self.job, &result.stderr).await?;
        Ok(result)
    }

    async fn stop_and_remove(
        self: Box<Self>,
        reason: TeardownReason,
    ) -> Result<TeardownReport, SandboxError> {
        self.inner.stop_and_remove(reason).await
    }
}
