//! Reading the change from the job's object store, on the host.
//!
//! The protected-path, test-protection and secret rules need the changed paths, both versions of
//! each file and the extended headers of the patch. All of it comes from `JobRepo`, which reads
//! the committed trees of the object store, and never from the sandbox-writable tree. The
//! sandbox that built the change is gone before this runs.

use factory_domain::scope::TenantScope;
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{CommitSha, RepoPath};
use factory_ports::workspace::{ChangeKind, JobRepo, ReadView, WorkspaceError};

use super::config::Bounds;
use crate::gates::scope::{Facts, FileChange, patch};
use crate::handlers::StageError;

/// The change, as far as the control plane could read it.
#[derive(Debug, Clone, Default)]
pub struct Gathered {
    /// The changed paths with both versions of each file.
    pub files: Vec<FileChange>,
    /// The extended headers of the patch, or `None` when the patch could not be read.
    pub facts: Option<Facts>,
    /// False when the list of changed paths could not be made.
    pub listed: bool,
}

impl Gathered {
    /// True when every changed file was read in full.
    #[must_use]
    pub fn all_readable(&self) -> bool {
        self.listed && self.files.iter().all(|file| file.readable)
    }
}

/// Reads the difference between `base` and `head`.
///
/// # Errors
/// [`StageError::Cancelled`] when the engine cancelled the attempt. Any other failure to read is
/// recorded in the result, so that the gate that needed it is `BLOCKED` and says why.
pub async fn gather(
    repo: &dyn JobRepo,
    artifacts: &dyn ArtifactStore,
    scope: &TenantScope,
    base: &CommitSha,
    head: &CommitSha,
    bounds: &Bounds,
    cancel: &dyn CancelSignal,
) -> Result<Gathered, StageError> {
    let export = match repo
        .export_patch(base, head, bounds.max_patch_bytes, cancel)
        .await
    {
        Ok(export) => export,
        Err(WorkspaceError::Cancelled) => return Err(StageError::Cancelled),
        Err(_) => return Ok(Gathered::default()),
    };
    let facts = match artifacts.get(scope, &export.patch).await {
        Ok(bytes) => Some(patch::parse(&bytes)),
        Err(_) => None,
    };
    let mut files = Vec::with_capacity(export.changes.len());
    for change in &export.changes {
        let mut readable = true;
        let before = if change.kind == ChangeKind::Added {
            None
        } else {
            read(repo, base, &change.path, bounds, &mut readable).await?
        };
        let after = if change.kind == ChangeKind::Deleted {
            None
        } else {
            read(repo, head, &change.path, bounds, &mut readable).await?
        };
        files.push(FileChange {
            path: change.path.as_str().to_owned(),
            kind: change.kind,
            before,
            after,
            readable,
        });
    }
    Ok(Gathered {
        files,
        facts,
        listed: true,
    })
}

async fn read(
    repo: &dyn JobRepo,
    commit: &CommitSha,
    path: &RepoPath,
    bounds: &Bounds,
    readable: &mut bool,
) -> Result<Option<Vec<u8>>, StageError> {
    match repo
        .read_file_at(commit, path, bounds.max_file_bytes, ReadView::Trusted)
        .await
    {
        Ok(bytes) => Ok(Some(bytes)),
        Err(WorkspaceError::Cancelled) => Err(StageError::Cancelled),
        Err(_) => {
            *readable = false;
            Ok(None)
        }
    }
}
