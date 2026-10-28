//! [`GitWorkspaceProvider`]: the `WorkspaceProvider` over host-side git.

use std::path::Path;
use std::sync::Arc;

use factory_domain::ids::{AttemptId, JobId};
use factory_domain::policy::RepoKind;
use factory_domain::policy::paths::{DiffEntry, DiffVerdict, PathPolicy};
use factory_domain::redaction::Redactor;
use factory_domain::vocabulary::Fidelity;
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::{CancelSignal, Clock};
use factory_ports::paths::{BranchName, PathRules};
use factory_ports::process::ProcessRunner;
use factory_ports::workspace::{
    FetchTarget, FetchedBase, IoOperation, JobRepo, Workspace, WorkspaceError, WorkspaceProvider,
    WorkspaceRequest,
};

use super::attempt::GitWorkspace;
use super::git::Git;
use super::layout::{JobDirs, list_attempts, list_jobs, remove_tree};
use super::repo::{self, GitJobRepo};
use super::{WorkspaceSettings, checkout};
use crate::race::BoxFuture;

/// The compiled policy, for the second look at a change set and at symbolic links.
///
/// The path rules of a request decide every path (they are the contract of the port). When this
/// layer is set, the same change also goes through [`PathPolicy::check_diff`] and each link
/// through [`PathPolicy::check_symlink`], and the stricter answer stands.
#[derive(Debug, Clone)]
pub struct PathPolicyLayer {
    policy: Arc<PathPolicy>,
    repo: RepoKind,
}

impl PathPolicyLayer {
    /// Wraps the compiled policy for one kind of repository.
    #[must_use]
    pub fn new(policy: Arc<PathPolicy>, repo: RepoKind) -> Self {
        Self { policy, repo }
    }

    pub(crate) fn denies_symlink(&self, link: &str, target: &str) -> bool {
        !self
            .policy
            .check_symlink(self.repo, link, target)
            .is_allowed()
    }

    pub(crate) fn check_diff(&self, entries: &[DiffEntry]) -> DiffVerdict {
        self.policy
            .check_diff(self.repo, entries, None, &Default::default())
    }
}

/// What every call of the provider shares.
pub(crate) struct Shared {
    pub settings: WorkspaceSettings,
    pub git: Git,
    pub artifacts: Arc<dyn ArtifactStore>,
    pub redactor: Arc<Redactor>,
    pub clock: Arc<dyn Clock>,
    /// The rules of the agent view of the job store (`JobRepo`), from the project configuration.
    pub view_rules: PathRules,
    pub layer: Option<PathPolicyLayer>,
}

impl Shared {
    pub(crate) fn job_dirs(&self, job: JobId) -> JobDirs {
        JobDirs::new(&self.settings.root, job)
    }
}

/// The workspace provider over host-side git. A new value over the same root sees the same job
/// stores, so a restart loses no commit.
#[derive(Clone)]
pub struct GitWorkspaceProvider {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for GitWorkspaceProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitWorkspaceProvider")
            .field("root", &self.shared.settings.root)
            .finish_non_exhaustive()
    }
}

impl GitWorkspaceProvider {
    /// A provider. `runner` starts git (the path of the executable is the runner's), `artifacts`
    /// stores patches, `redactor` finds secrets in changed files, and `clock` dates commits.
    /// `view_rules` are the project's path rules, applied to the agent view of a job's store.
    #[must_use]
    pub fn new(
        settings: WorkspaceSettings,
        runner: Arc<dyn ProcessRunner>,
        artifacts: Arc<dyn ArtifactStore>,
        redactor: Arc<Redactor>,
        clock: Arc<dyn Clock>,
        view_rules: PathRules,
    ) -> Self {
        let git = Git::new(
            runner,
            settings.remote.protocol(),
            settings.timeouts.local,
            settings.timeouts.network,
        );
        Self {
            shared: Arc::new(Shared {
                settings,
                git,
                artifacts,
                redactor,
                clock,
                view_rules,
                layer: None,
            }),
        }
    }

    /// Adds the compiled policy as a second look at every change set and every link.
    #[must_use]
    pub fn with_path_policy(mut self, layer: PathPolicyLayer) -> Self {
        if let Some(shared) = Arc::get_mut(&mut self.shared) {
            shared.layer = Some(layer);
        }
        self
    }

    /// Makes a workspace and returns the concrete type, which also reports why an audit
    /// rejected a tree. [`WorkspaceProvider::create`] boxes the same value.
    ///
    /// # Errors
    /// [`WorkspaceError`].
    pub async fn create_workspace(
        &self,
        req: WorkspaceRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<GitWorkspace, WorkspaceError> {
        checkout::create(&self.shared, req, cancel).await
    }

    async fn do_fetch(
        &self,
        job: JobId,
        target: &FetchTarget,
        branch: &BranchName,
        cancel: &dyn CancelSignal,
    ) -> Result<FetchedBase, WorkspaceError> {
        repo::fetch_branch(&self.shared, job, target, branch, cancel).await
    }

    async fn do_repo(&self, job: JobId) -> Result<Box<dyn JobRepo>, WorkspaceError> {
        let dirs = self.shared.job_dirs(job);
        if !dirs.has_store() {
            return Err(WorkspaceError::NotFetched);
        }
        Ok(Box::new(GitJobRepo::new(Arc::clone(&self.shared), dirs)))
    }

    async fn do_dispose_job(&self, job: JobId) -> Result<(), WorkspaceError> {
        let dirs = self.shared.job_dirs(job);
        remove_tree(&dirs.dir).map_err(|_| WorkspaceError::Io(IoOperation::Remove))
    }

    async fn do_sweep(
        &self,
        live: &[AttemptId],
        live_jobs: &[JobId],
    ) -> Result<Vec<AttemptId>, WorkspaceError> {
        let mut removed = Vec::new();
        for job in list_jobs(&self.shared.settings.root) {
            let dirs = self.shared.job_dirs(job);
            if !live_jobs.contains(&job) {
                removed.extend(list_attempts(&dirs));
                remove_tree(&dirs.dir).map_err(|_| WorkspaceError::Io(IoOperation::Remove))?;
                continue;
            }
            for attempt in list_attempts(&dirs) {
                if !live.contains(&attempt) {
                    remove_tree(&dirs.attempt(attempt).dir)
                        .map_err(|_| WorkspaceError::Io(IoOperation::Remove))?;
                    removed.push(attempt);
                }
            }
        }
        removed.sort();
        removed.dedup();
        Ok(removed)
    }

    /// The root directory the provider works in.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.shared.settings.root
    }
}

impl WorkspaceProvider for GitWorkspaceProvider {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    // The signatures `#[async_trait]` would write; see `crate::race`.
    fn fetch<'life0, 'life1, 'life2, 'life3, 'async_trait>(
        &'life0 self,
        job: JobId,
        target: &'life1 FetchTarget,
        branch: &'life2 BranchName,
        cancel: &'life3 dyn CancelSignal,
    ) -> BoxFuture<'async_trait, Result<FetchedBase, WorkspaceError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        'life3: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.do_fetch(job, target, branch, cancel))
    }

    fn create<'life0, 'life1, 'async_trait>(
        &'life0 self,
        req: WorkspaceRequest,
        cancel: &'life1 dyn CancelSignal,
    ) -> BoxFuture<'async_trait, Result<Box<dyn Workspace>, WorkspaceError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let workspace = self.create_workspace(req, cancel).await?;
            Ok(Box::new(workspace) as Box<dyn Workspace>)
        })
    }

    fn repo<'life0, 'async_trait>(
        &'life0 self,
        job: JobId,
    ) -> BoxFuture<'async_trait, Result<Box<dyn JobRepo>, WorkspaceError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.do_repo(job))
    }

    fn dispose_job<'life0, 'async_trait>(
        &'life0 self,
        job: JobId,
    ) -> BoxFuture<'async_trait, Result<(), WorkspaceError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.do_dispose_job(job))
    }

    fn sweep_orphans<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        live: &'life1 [AttemptId],
        live_jobs: &'life2 [JobId],
    ) -> BoxFuture<'async_trait, Result<Vec<AttemptId>, WorkspaceError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.do_sweep(live, live_jobs))
    }
}
