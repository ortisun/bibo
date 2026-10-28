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
//! The same applies to the workspace patch (`JobRepo::export_patch`): [`IndexingWorkspaces`]
//! wraps the workspace provider and indexes the patch when it is exported.

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

// ------------------------------------------------------------------------------------------
// The workspace patch
// ------------------------------------------------------------------------------------------

use factory_ports::paths::{CommitSha, RepoGlob, RepoPath};
use factory_ports::workspace::{
    FetchTarget, FetchedBase, IoOperation, JobRepo, PatchExport, PushTarget, ReadView, Workspace,
    WorkspaceError, WorkspaceProvider, WorkspaceRequest,
};

/// A workspace provider whose job repositories index the patches they export.
///
/// `JobRepo::export_patch` stores the unified diff with `ArtifactStore::put` and returns the
/// reference, and says "the caller indexes it for its tenant". `put` makes no index row, so until
/// somebody indexes the patch, `ArtifactStore::get` answers `NotFound` for the tenant that owns
/// the job: the review and documentation stages could not read the diff they are asked to judge.
/// This wrapper indexes the patch in a short tenant transaction as soon as it is exported, the
/// same way [`IndexingSandbox`] does for command output. The tenant comes from [`ActiveJobs`];
/// a job the loop does not know fails closed.
///
/// `WorkspaceError` has no variant for "the artifact could not be indexed" (the same gap as
/// `SandboxError`, README mismatch 10), so the failure is reported as the closest host failure,
/// `Io(CreateDirectory)`.
pub struct IndexingWorkspaces {
    inner: Arc<dyn WorkspaceProvider>,
    store: Arc<dyn Store>,
    jobs: Arc<ActiveJobs>,
}

impl IndexingWorkspaces {
    /// Wraps `inner`.
    #[must_use]
    pub fn new(
        inner: Arc<dyn WorkspaceProvider>,
        store: Arc<dyn Store>,
        jobs: Arc<ActiveJobs>,
    ) -> Self {
        Self { inner, store, jobs }
    }
}

#[async_trait]
impl WorkspaceProvider for IndexingWorkspaces {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    async fn fetch(
        &self,
        job: JobId,
        target: &FetchTarget,
        branch: &factory_ports::paths::BranchName,
        cancel: &dyn CancelSignal,
    ) -> Result<FetchedBase, WorkspaceError> {
        self.inner.fetch(job, target, branch, cancel).await
    }

    async fn create(
        &self,
        req: WorkspaceRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<Box<dyn Workspace>, WorkspaceError> {
        self.inner.create(req, cancel).await
    }

    async fn repo(&self, job: JobId) -> Result<Box<dyn JobRepo>, WorkspaceError> {
        let inner = self.inner.repo(job).await?;
        Ok(Box::new(IndexingRepo {
            inner,
            store: Arc::clone(&self.store),
            jobs: Arc::clone(&self.jobs),
            job,
        }))
    }

    async fn dispose_job(&self, job: JobId) -> Result<(), WorkspaceError> {
        self.inner.dispose_job(job).await
    }

    async fn sweep_orphans(
        &self,
        live: &[AttemptId],
        live_jobs: &[JobId],
    ) -> Result<Vec<AttemptId>, WorkspaceError> {
        self.inner.sweep_orphans(live, live_jobs).await
    }
}

struct IndexingRepo {
    inner: Box<dyn JobRepo>,
    store: Arc<dyn Store>,
    jobs: Arc<ActiveJobs>,
    job: JobId,
}

impl IndexingRepo {
    async fn index(&self, patch: &ArtifactRef) -> Result<(), WorkspaceError> {
        let failed = || WorkspaceError::Io(IoOperation::CreateDirectory);
        let tenant = self.jobs.tenant_of(self.job).ok_or_else(failed)?;
        // A reference without a size cannot be indexed; the workspace adapter always sets one.
        let entry = NewArtifactIndexEntry::from_reference(patch, None).ok_or_else(failed)?;
        let mut tx = self
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| failed())?;
        match tx.index_artifact(entry).await {
            Ok(_) => tx.commit().await.map_err(|_| failed()),
            Err(_) => {
                let _ = tx.rollback().await;
                Err(failed())
            }
        }
    }
}

#[async_trait]
impl JobRepo for IndexingRepo {
    async fn read_file_at(
        &self,
        commit: &CommitSha,
        path: &RepoPath,
        max_bytes: u64,
        view: ReadView,
    ) -> Result<Vec<u8>, WorkspaceError> {
        self.inner.read_file_at(commit, path, max_bytes, view).await
    }

    async fn list_at(
        &self,
        commit: &CommitSha,
        glob: &RepoGlob,
        limit: usize,
        view: ReadView,
    ) -> Result<Vec<RepoPath>, WorkspaceError> {
        self.inner.list_at(commit, glob, limit, view).await
    }

    async fn export_patch(
        &self,
        base: &CommitSha,
        head: &CommitSha,
        max_bytes: u64,
        cancel: &dyn CancelSignal,
    ) -> Result<PatchExport, WorkspaceError> {
        let exported = self
            .inner
            .export_patch(base, head, max_bytes, cancel)
            .await?;
        self.index(&exported.patch).await?;
        Ok(exported)
    }

    async fn push(
        &self,
        target: &PushTarget,
        commit: &CommitSha,
        cancel: &dyn CancelSignal,
    ) -> Result<(), WorkspaceError> {
        self.inner.push(target, commit, cancel).await
    }
}
