//! [`GitWorkspace`]: the `Workspace` over one attempt's checkout.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use factory_domain::ids::{AttemptId, JobId};
use factory_domain::values::Sha256Digest;
use factory_ports::clock::CancelSignal;
use factory_ports::paths::{CommitSha, PathRules};
use factory_ports::workspace::{
    ChangedPath, CommitRequest, GitOperation, IngestedChange, IoOperation, Workspace,
    WorkspaceError, WorkspaceMounts, WorkspacePurpose, WorkspaceRequest,
};

use super::audit::AuditReport;
use super::basetree::BaseTree;
use super::ingest;
use super::layout::{AttemptDirs, JobDirs, remove_tree};
use super::provider::Shared;
use crate::race::BoxFuture;

/// What `ingest` audited: the tree it wrote to the store and the change set it found.
#[derive(Debug, Clone)]
pub(super) struct Audited {
    pub tree: String,
    pub base: CommitSha,
    pub changes: Vec<ChangedPath>,
}

type CommitKey = (Sha256Digest, String, String, String);

/// The host side of one attempt's checkout.
pub struct GitWorkspace {
    pub(super) shared: Arc<Shared>,
    pub(super) job_dirs: JobDirs,
    pub(super) attempt_dirs: AttemptDirs,
    pub(super) base: CommitSha,
    /// The job's protected base when it is not `base` (ADR 0024): the commit `append_only` and
    /// `additions_only` judge a changed path against. `None` when `base` is that commit.
    pub(super) protected: Option<CommitSha>,
    pub(super) rules: PathRules,
    pub(super) tree: Arc<BaseTree>,
    mounts: WorkspaceMounts,
    job: JobId,
    attempt: AttemptId,
    purpose: WorkspacePurpose,
    audited: Mutex<HashMap<Sha256Digest, Audited>>,
    made: Mutex<HashMap<CommitKey, CommitSha>>,
    report: Mutex<Option<AuditReport>>,
}

impl std::fmt::Debug for GitWorkspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitWorkspace")
            .field("job", &self.job)
            .field("attempt", &self.attempt)
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl GitWorkspace {
    pub(super) fn new(
        shared: Arc<Shared>,
        req: WorkspaceRequest,
        protected: Option<CommitSha>,
        job_dirs: JobDirs,
        attempt_dirs: AttemptDirs,
        tree: BaseTree,
        mounts: WorkspaceMounts,
    ) -> Self {
        Self {
            shared,
            job_dirs,
            attempt_dirs,
            base: req.base,
            protected,
            rules: req.rules,
            tree: Arc::new(tree),
            mounts,
            job: req.job,
            attempt: req.attempt,
            purpose: req.purpose,
            audited: Mutex::new(HashMap::new()),
            made: Mutex::new(HashMap::new()),
            report: Mutex::new(None),
        }
    }

    /// The job the workspace belongs to.
    #[must_use]
    pub fn job(&self) -> JobId {
        self.job
    }

    /// The attempt the workspace belongs to.
    #[must_use]
    pub fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// What the workspace is for.
    #[must_use]
    pub fn purpose(&self) -> &WorkspacePurpose {
        &self.purpose
    }

    /// Why the last audit rejected the tree, entry by entry. The port's error set is closed, so
    /// this is where the specific reasons are.
    #[must_use]
    pub fn last_audit_report(&self) -> Option<AuditReport> {
        self.report.lock().ok().and_then(|r| r.clone())
    }

    pub(super) fn keep_report(&self, report: AuditReport) {
        if let Ok(mut slot) = self.report.lock() {
            *slot = Some(report);
        }
    }

    pub(super) fn remember(&self, digest: Sha256Digest, audited: Audited) {
        if let Ok(mut map) = self.audited.lock() {
            map.insert(digest, audited);
        }
    }

    fn recall(&self, digest: &Sha256Digest) -> Option<Audited> {
        self.audited
            .lock()
            .ok()
            .and_then(|m| m.get(digest).cloned())
    }

    async fn do_commit(
        &self,
        change: &IngestedChange,
        req: CommitRequest,
    ) -> Result<CommitSha, WorkspaceError> {
        let refused = || WorkspaceError::Git {
            operation: GitOperation::Commit,
            exit: None,
        };
        // Only a change this workspace ingested, unchanged since.
        let audited = self.recall(change.tree()).ok_or_else(refused)?;
        if &audited.base != change.base() || audited.changes != change.changes() {
            return Err(refused());
        }
        if !identity_is_plain(&req.author_name)
            || !identity_is_plain(&req.author_email)
            || req.message.contains('\0')
        {
            return Err(refused());
        }
        let key: CommitKey = (
            change.tree().clone(),
            req.message.clone(),
            req.author_name.clone(),
            req.author_email.clone(),
        );
        if let Some(found) = self.made.lock().ok().and_then(|m| m.get(&key).cloned()) {
            return Ok(found);
        }
        let commit = ingest::make_commit(
            self,
            &audited.tree,
            &audited.base,
            &req.message,
            &req.author_name,
            &req.author_email,
        )
        .await?;
        if let Ok(mut map) = self.made.lock() {
            map.insert(key, commit.clone());
        }
        Ok(commit)
    }

    async fn do_dispose(self: Box<Self>) -> Result<(), WorkspaceError> {
        remove_tree(&self.attempt_dirs.dir).map_err(|_| WorkspaceError::Io(IoOperation::Remove))
    }
}

/// A name or an email that cannot break out of its header line.
fn identity_is_plain(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 256
        && !text.chars().any(|c| c.is_control() || c == '<' || c == '>')
}

impl Workspace for GitWorkspace {
    fn mounts(&self) -> WorkspaceMounts {
        self.mounts.clone()
    }

    fn base(&self) -> &CommitSha {
        &self.base
    }

    // The signatures `#[async_trait]` would write; see `crate::race`.
    fn ingest<'life0, 'life1, 'async_trait>(
        &'life0 self,
        cancel: &'life1 dyn CancelSignal,
    ) -> BoxFuture<'async_trait, Result<IngestedChange, WorkspaceError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(ingest::ingest(self, cancel))
    }

    fn commit<'life0, 'life1, 'async_trait>(
        &'life0 self,
        change: &'life1 IngestedChange,
        req: CommitRequest,
    ) -> BoxFuture<'async_trait, Result<CommitSha, WorkspaceError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(self.do_commit(change, req))
    }

    fn dispose<'async_trait>(self: Box<Self>) -> BoxFuture<'async_trait, Result<(), WorkspaceError>>
    where
        Self: 'async_trait,
    {
        Box::pin(self.do_dispose())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identity_with_a_line_break_or_an_angle_bracket_is_not_plain() {
        assert!(identity_is_plain("Factory"));
        assert!(identity_is_plain("factory@example.invalid"));
        assert!(!identity_is_plain("Factory\nAuthor: x"));
        assert!(!identity_is_plain("a<b"));
        assert!(!identity_is_plain(""));
    }
}
