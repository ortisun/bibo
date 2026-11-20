//! A fake workspace provider whose exported patch has the shape of `git diff --no-renames`.
//!
//! The testkit's fake exports its patch as a list of changes with no diff text a reader could
//! parse, and the documenting stage derives its plan from `diff --git` headers and `+` and `-`
//! lines. With the fake as it is, the stage reads no changed file, finds nothing to document and
//! passes without calling the writer: a pass that proves nothing. The stage tests of the workflow
//! crate wrap the fake the same way (`GitShapedRepo` in their rigs); this is that wrapper for the
//! full run. A whole file is shown as removed and added, which a real `git diff` would not do for
//! a small edit, and the stage needs no more than the names and the lines.
//!
//! **Request, owner `testkit`:** give `FakeJobRepo::export_patch` this shape, so that no rig needs
//! its own copy. The testkit is outside the paths of this work.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::ids::{AttemptId, JobId};
use factory_domain::values::{GitSha, MediaType};
use factory_domain::vocabulary::Fidelity;
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{BranchName, CommitSha, RepoGlob, RepoPath};
use factory_ports::workspace::{
    ChangeKind, FetchTarget, FetchedBase, JobRepo, PatchExport, PushTarget, ReadView, Workspace,
    WorkspaceError, WorkspaceProvider, WorkspaceRequest,
};

pub struct GitShapedWorkspaces {
    pub inner: Arc<dyn WorkspaceProvider>,
    pub artifacts: Arc<dyn ArtifactStore>,
}

struct GitShapedRepo {
    inner: Box<dyn JobRepo>,
    artifacts: Arc<dyn ArtifactStore>,
}

fn render(path: &str, before: Option<&str>, after: Option<&str>) -> String {
    let mut text = format!("diff --git a/{path} b/{path}\n");
    let (old_name, new_name) = match (before, after) {
        (None, Some(_)) => {
            text.push_str("new file mode 100644\n");
            ("/dev/null".to_owned(), format!("b/{path}"))
        }
        (Some(_), None) => {
            text.push_str("deleted file mode 100644\n");
            (format!("a/{path}"), "/dev/null".to_owned())
        }
        _ => (format!("a/{path}"), format!("b/{path}")),
    };
    text.push_str(&format!("--- {old_name}\n+++ {new_name}\n"));
    let old: Vec<&str> = before.map(|t| t.lines().collect()).unwrap_or_default();
    let new: Vec<&str> = after.map(|t| t.lines().collect()).unwrap_or_default();
    let start = |lines: &Vec<&str>| if lines.is_empty() { 0 } else { 1 };
    text.push_str(&format!(
        "@@ -{},{} +{},{} @@\n",
        start(&old),
        old.len(),
        start(&new),
        new.len()
    ));
    for line in &old {
        text.push_str(&format!("-{line}\n"));
    }
    for line in &new {
        text.push_str(&format!("+{line}\n"));
    }
    text
}

#[async_trait]
impl WorkspaceProvider for GitShapedWorkspaces {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }
    async fn fetch(
        &self,
        job: JobId,
        target: &FetchTarget,
        branch: &BranchName,
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
        Ok(Box::new(GitShapedRepo {
            inner: self.inner.repo(job).await?,
            artifacts: self.artifacts.clone(),
        }))
    }
    async fn list_branches(
        &self,
        job: JobId,
        target: &FetchTarget,
        prefix: &str,
        cancel: &dyn CancelSignal,
    ) -> Result<Vec<BranchName>, WorkspaceError> {
        self.inner.list_branches(job, target, prefix, cancel).await
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

#[async_trait]
impl JobRepo for GitShapedRepo {
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
        let mut text = String::new();
        for change in &exported.changes {
            let read = |commit: &CommitSha| {
                let inner = &self.inner;
                let path = change.path.clone();
                let commit = commit.clone();
                async move {
                    inner
                        .read_file_at(&commit, &path, max_bytes, ReadView::Trusted)
                        .await
                        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                }
            };
            let before = match change.kind {
                ChangeKind::Added => None,
                _ => Some(read(base).await?),
            };
            let after = match change.kind {
                ChangeKind::Deleted => None,
                _ => Some(read(head).await?),
            };
            text.push_str(&render(
                change.path.as_str(),
                before.as_deref(),
                after.as_deref(),
            ));
        }
        let patch = self
            .artifacts
            .put(
                text.into_bytes(),
                MediaType::parse("text/x-diff").expect("a media type"),
            )
            .await
            .map_err(|_| WorkspaceError::Io(factory_ports::workspace::IoOperation::Walk))?;
        Ok(PatchExport {
            patch,
            changes: exported.changes,
        })
    }
    async fn push(
        &self,
        target: &PushTarget,
        commit: &CommitSha,
        cancel: &dyn CancelSignal,
    ) -> Result<(), WorkspaceError> {
        self.inner.push(target, commit, cancel).await
    }
    async fn tree_of(&self, commit: &CommitSha) -> Result<GitSha, WorkspaceError> {
        self.inner.tree_of(commit).await
    }
}
