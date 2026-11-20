//! Opening and keeping up the triage issues of the troubleshooter (ports v1.3, ADR 0021 Decision 7).
//!
//! A troubleshooting run is not a job. It has no stage, and its credential must not be a job's:
//! [`RunScope`] names a tenant, a run and the one repository the issues go to, and the adapter
//! mints a credential of its own for it (`issues: write` and `metadata: read`) that no job stage can
//! ask for. [`GitScope`](crate::githost::GitScope) is unchanged.
//!
//! What this port writes was decided before it is called. The text comes from the closed template
//! of `factory_domain::troubleshooting::issue` (the types have private fields, so nothing else can
//! make one), and the caps on new issues and comments a day are counted by the caller in its own
//! store. The port does not enforce them.

use async_trait::async_trait;
use factory_domain::ids::TenantId;
use factory_domain::troubleshooting::issue::{SeenAgainComment, TriageIssue};
use factory_domain::troubleshooting::{FindingFingerprint, TroubleshootingRunId};
use factory_domain::vocabulary::Fidelity;

use crate::githost::{CommentRef, GitHostError, IssueRef};
use crate::paths::RepoRef;

/// What a troubleshooting run is allowed to touch. A credential is minted for exactly this.
///
/// Unlike [`GitScope`](crate::githost::GitScope) it names a run, not a job, and no stage: the
/// credential of a run does not depend on a stage and ends with the run.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RunScope {
    /// The tenant whose installation covers the issue repository.
    pub tenant: TenantId,
    /// The run. Its credential is kept under it and ended by
    /// [`TriageIssueWriter::revoke_run_tokens`].
    pub run: TroubleshootingRunId,
    /// The one repository the issues go to, `troubleshooting.issue_repository` of the
    /// configuration. An adapter refuses any other.
    pub repo: RepoRef,
}

/// What became of an open call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenedIssue {
    /// A new issue.
    Opened(IssueRef),
    /// An open issue of the factory with the same fingerprint was already there. Nothing was
    /// written. This makes a retry after a lost answer safe.
    AlreadyOpen(IssueRef),
}

/// What became of a comment call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeenAgainPost {
    /// The comment was posted.
    Posted(CommentRef),
    /// The factory's comment with the same key (run and fingerprint) was already on the issue.
    /// Nothing was posted.
    AlreadyThere(CommentRef),
}

/// Opens the troubleshooter's triage issues and comments on them.
///
/// # Preconditions
/// The scope names the tenant, the run and the configured issue repository; an issue passed in is
/// in that repository. The caller has decided what to do (open, comment, or nothing) and has
/// counted the day's caps in its own store; this port authorizes nothing. The issue and the comment
/// come from the renderer of `factory_domain::troubleshooting::issue`, the labels from the policy.
///
/// # Postconditions
/// `find_open_issue` returns the open issue whose **body** carries the fingerprint marker on a line
/// of its own, among the open issues that carry the label `troubleshooter` and were opened by the
/// factory's own account; a marker in a comment, in an issue someone else opened, or inside other
/// text does not count. When several match, the lowest number wins. It reads issue listings, not
/// the search API. `open_issue` looks first and opens only when no such issue is open, with the
/// title, body and labels given and nothing else. `post_seen_again` posts the comment unless the
/// factory's comment with the same key is already there. Text is checked for secrets before it is
/// sent. Calls that change something are paced (at least one second apart).
///
/// # Errors
/// [`GitHostError`]. `Forbidden` for a scope whose repository is not the configured one (nothing is
/// sent, not even a token request) and when the credential lacks `issues: write`; `NotFound` for an
/// issue outside the scope; `Rejected(LabelNotAllowed)` for a label outside the troubleshooter
/// namespace, before anything is sent; `UnsafeText` for text that looks like a secret;
/// `Unavailable` when a listing was cut short at the page cap and the marker was not found in the
/// part read (absence is not proven, and a second issue is worse than a late one); `RateLimited`
/// and `Unavailable` for the host.
///
/// # Idempotency
/// `find_open_issue` is a read. `open_issue` and `post_seen_again` look before they write, so a
/// retry after an answer that was lost does not make a second issue or comment, except when two
/// callers race, which the caller prevents by running one troubleshooter at a time.
/// `revoke_run_tokens` is idempotent.
///
/// # Cancellation and timeouts
/// Every call is safe to drop, with the effect of a request already sent being possible (an issue
/// opened whose answer was lost: the next `open_issue` finds it). The adapter sets a request
/// timeout of 30 seconds and reports `Unavailable` when it is exceeded.
#[async_trait]
pub trait TriageIssueWriter: Send + Sync {
    /// Says whether this writer talks to the real code host (`real`) or is scripted (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// The open triage issue of this fingerprint, if there is one.
    async fn find_open_issue(
        &self,
        scope: &RunScope,
        fingerprint: &FindingFingerprint,
    ) -> Result<Option<IssueRef>, GitHostError>;

    /// Opens the issue, unless an open one of the same fingerprint is there.
    async fn open_issue(
        &self,
        scope: &RunScope,
        issue: &TriageIssue,
    ) -> Result<OpenedIssue, GitHostError>;

    /// Adds the "seen again" comment to an open triage issue.
    async fn post_seen_again(
        &self,
        scope: &RunScope,
        issue: &IssueRef,
        comment: &SeenAgainComment,
    ) -> Result<SeenAgainPost, GitHostError>;

    /// Ends the run's credential. Called when the run ends; a later call for the run mints none.
    async fn revoke_run_tokens(&self, run: &TroubleshootingRunId) -> Result<(), GitHostError>;
}
