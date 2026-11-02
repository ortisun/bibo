//! Writing the state of a job onto the issue it came from (ports v1.2, ADR 0017).
//!
//! The factory shows a job's state on its issue in two places: exactly one `factory: <state>`
//! label, and exactly one status comment that it keeps up to date. The labels and the comment are
//! observability. They never decide anything, and a failure to write them must never stop, fail or
//! undo a job.
//!
//! # Why this is its own port
//!
//! * [`IssueSource`](crate::githost::IssueSource) only reads. [`ChangeHost`](crate::githost::ChangeHost)
//!   writes through the token of a stage, and a stage token is narrowed to what that stage needs:
//!   intake and analysis hold `issues: read`, and the delivery stage holds much more. Writing a
//!   status must not widen a stage token, and must not borrow the delivery token either. This port
//!   has its own credential: `issues: write` for one repository, minted for this purpose only.
//! * The label argument is a [`StatusLabel`], a type that only the policy can make. The wrong call
//!   (the trigger label, a `design:` label, any label outside the `factory: ` namespace) cannot be
//!   written, and an adapter refuses it once more.
//!
//! # What is open to a later board
//!
//! Nothing here names a GitHub Projects board. A board that mirrors the labels can be a second
//! implementation of the same idea (set one status, find one item), and the stamp below gives it
//! the same "newest wins" rule. No board is built.

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::policy::issue_workflow::StatusLabel;
use factory_domain::values::{AggregateVersion, Timestamp};
use factory_domain::vocabulary::Fidelity;

use crate::githost::{CommentRef, GitHostError, IssueRef};
use crate::paths::RepoRef;

/// The most bytes a status comment may have before the marker is added.
pub const MAX_STATUS_COMMENT_BYTES: usize = 4_000;

/// The start of the hidden marker that makes the status comment findable.
pub const STATUS_MARKER_PREFIX: &str = "<!-- factory-status ";

/// What a status call is allowed to touch. A credential is minted for exactly this.
///
/// Unlike [`GitScope`](crate::githost::GitScope) it names no stage: the credential of a status call
/// does not depend on a stage, and a field that was ignored would mislead.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StatusScope {
    /// The tenant.
    pub tenant: TenantId,
    /// The identifier the credential is kept under and ended by
    /// ([`ChangeHost::revoke_job_tokens`](crate::githost::ChangeHost::revoke_job_tokens)). It is
    /// **not** the job whose state is written: the tokens of a job end with the job, and its last
    /// state is written after that. The caller uses a fresh identifier for each round of writes.
    pub session: JobId,
    /// The one repository the credential works on.
    pub repo: RepoRef,
}

/// Which version of which job a status comment shows. The adapter keeps the newest.
///
/// The order is the job's start time first, then the job's version, then the job's identifier. A
/// later job on the same issue therefore replaces the comment of an earlier one, and within one job
/// a higher version replaces a lower one. Two updates that race end with the newer one on the
/// issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatusStamp {
    /// When the database created the job.
    pub started: Timestamp,
    /// The version of the job row the comment shows.
    pub version: AggregateVersion,
    /// The job.
    pub job: JobId,
}

impl StatusStamp {
    /// The hidden marker for a comment that carries this stamp: `<!-- factory-status job=<id>
    /// started=<time> version=<n> -->`. It holds an identifier, a time and a number, and no text.
    #[must_use]
    pub fn marker(&self) -> String {
        format!(
            "{STATUS_MARKER_PREFIX}job={} started={} version={} -->",
            self.job.as_text(),
            self.started.as_text(),
            self.version.get()
        )
    }

    /// Reads the last marker of a comment body. `None` when the text has no marker or when the
    /// marker is not exactly the form [`marker`](Self::marker) writes.
    #[must_use]
    pub fn from_text(text: &str) -> Option<Self> {
        let start = text.rfind(STATUS_MARKER_PREFIX)?;
        let rest = text.get(start + STATUS_MARKER_PREFIX.len()..)?;
        let inner = rest.get(..rest.find(" -->")?)?;
        let mut words = inner.split(' ');
        let job = JobId::parse(words.next()?.strip_prefix("job=")?).ok()?;
        let started = Timestamp::parse(words.next()?.strip_prefix("started=")?).ok()?;
        let version =
            AggregateVersion::new(words.next()?.strip_prefix("version=")?.parse().ok()?).ok()?;
        if words.next().is_some() {
            return None;
        }
        let stamp = Self {
            started,
            version,
            job,
        };
        (stamp.marker() == format!("{STATUS_MARKER_PREFIX}{inner} -->")).then_some(stamp)
    }

    /// True when `text` holds the start of a status marker, well formed or not.
    #[must_use]
    pub fn mentions_marker(text: &str) -> bool {
        text.contains(STATUS_MARKER_PREFIX)
    }
}

/// Why a status comment was refused before anything was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BadStatusComment {
    /// The text is empty.
    #[error("a status comment needs text")]
    Empty,
    /// The text is longer than [`MAX_STATUS_COMMENT_BYTES`].
    #[error("a status comment is at most 4000 bytes")]
    TooLong,
}

/// The text of the status comment and the stamp that says which state it shows. The text comes
/// from a closed template (state, stage, links) and never from a model or from the issue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusComment {
    stamp: StatusStamp,
    body: String,
}

impl StatusComment {
    /// Checks the length of the text.
    ///
    /// # Errors
    /// [`BadStatusComment`].
    pub fn new(stamp: StatusStamp, body: String) -> Result<Self, BadStatusComment> {
        if body.trim().is_empty() {
            Err(BadStatusComment::Empty)
        } else if body.len() > MAX_STATUS_COMMENT_BYTES {
            Err(BadStatusComment::TooLong)
        } else {
            Ok(Self { stamp, body })
        }
    }

    /// The stamp.
    #[must_use]
    pub fn stamp(&self) -> &StatusStamp {
        &self.stamp
    }

    /// The text, without the marker.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }
}

/// What a label call changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelOutcome {
    /// True when the label was not on the issue and is now.
    pub added: bool,
    /// How many other `factory: ` labels were taken off.
    pub removed: u32,
}

/// What a comment call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommentWrite {
    /// There was no status comment. This is the first.
    Created(CommentRef),
    /// The status comment was edited in place.
    Updated(CommentRef),
    /// The status comment already said this. Nothing was written.
    Unchanged(CommentRef),
    /// The status comment shows a newer stamp. Nothing was written, and the caller should not
    /// write the label either: the newer update owns the issue.
    Superseded(CommentRef),
}

/// Writes the state of a job onto its issue: one label and one comment.
///
/// # Preconditions
/// The scope names the tenant and the one repository; the issue is in that repository. The caller
/// has checked that the repository is enabled and that the factory accepted this issue for a job
/// (this port authorizes nothing). The label comes from the policy
/// ([`IssueWorkflowPolicy::status_labels`](factory_domain::policy::issue_workflow::IssueWorkflowPolicy::status_labels));
/// the comment text comes from a closed template.
///
/// # Postconditions
/// `set_status_label` leaves exactly one label of the `factory: ` namespace on the issue, the one
/// given, and touches no label outside that namespace: not the trigger label, not a `design:`
/// label, not any other. `upsert_status_comment` leaves exactly one status comment of the factory
/// on the issue, found by its hidden marker among the comments the factory's own App wrote, and
/// edits it in place; a marker pasted by someone else is not a status comment. A comment whose
/// stamp is newer than the one given is never overwritten ([`CommentWrite::Superseded`]). Text sent
/// to the host is checked for secrets and made safe to render first. Calls are paced: the adapter
/// leaves at least one second between two requests that change something.
///
/// # Errors
/// [`GitHostError`]. A label that is not a status label is `Rejected(LabelNotAllowed)` and nothing
/// is sent. `NotFound` for an issue or repository the scope does not cover, `Forbidden` when the
/// credential does not hold `issues: write`, `RateLimited` and `Unavailable` for the host.
///
/// # Idempotency
/// Both operations are idempotent: the same label call a second time adds and removes nothing, and
/// the same comment call a second time writes nothing. A label that is not on the issue is not an
/// error when it is removed. A retry after a call that may have been sent is safe, and it never
/// makes a second comment.
///
/// # Cancellation and timeouts
/// Every call is safe to drop, with the effect of a request that was already sent being possible
/// (a label added and the old one not yet taken off; the next call finishes the job). The adapter
/// sets a request timeout of 30 seconds and reports `Unavailable` when it is exceeded.
#[async_trait]
pub trait IssueStatusWriter: Send + Sync {
    /// Says whether this writer talks to the real code host (`real`) or is scripted (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Puts `label` on the issue and takes every other `factory: ` label off it.
    async fn set_status_label(
        &self,
        scope: &StatusScope,
        issue: &IssueRef,
        label: &StatusLabel,
    ) -> Result<LabelOutcome, GitHostError>;

    /// Creates the status comment, or edits it in place when it exists and `comment` is not older
    /// than what it shows.
    async fn upsert_status_comment(
        &self,
        scope: &StatusScope,
        issue: &IssueRef,
        comment: &StatusComment,
    ) -> Result<CommentWrite, GitHostError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stamp(started: &str, version: i64, job: u128) -> StatusStamp {
        StatusStamp {
            started: Timestamp::parse(started).unwrap(),
            version: AggregateVersion::new(version).unwrap(),
            job: JobId::from_uuid(uuid::Uuid::from_u128(job)),
        }
    }

    #[test]
    fn a_marker_reads_back_as_the_stamp_that_wrote_it() {
        let s = stamp("2026-11-02T10:00:00Z", 7, 1);
        let text = format!("The work is under way.\n\n{}", s.marker());
        assert_eq!(StatusStamp::from_text(&text), Some(s));
    }

    #[test]
    fn a_marker_that_is_not_exactly_the_written_form_reads_as_nothing() {
        let s = stamp("2026-11-02T10:00:00Z", 7, 1);
        let good = s.marker();
        for bad in [
            good.replace("version=7", "version=07"),
            good.replace("version=7", "version=0"),
            good.replace("version=7", "version=-1"),
            good.replace(" -->", " extra=1 -->"),
            good.replace("job=", "who="),
            good.replace("started=2026-11-02T10:00:00Z", "started=yesterday"),
            good.replace(" -->", ""),
            "no marker at all".to_owned(),
        ] {
            assert_eq!(StatusStamp::from_text(&bad), None, "{bad}");
        }
    }

    #[test]
    fn the_last_marker_of_a_text_is_the_one_that_counts() {
        let old = stamp("2026-11-02T10:00:00Z", 1, 1);
        let new = stamp("2026-11-02T10:00:00Z", 2, 1);
        let text = format!("{}\nmore\n{}", old.marker(), new.marker());
        assert_eq!(StatusStamp::from_text(&text), Some(new));
    }

    #[test]
    fn stamps_order_by_start_time_then_version_then_job() {
        let early = stamp("2026-11-02T09:00:00Z", 9, 1);
        let late = stamp("2026-11-02T10:00:00Z", 1, 1);
        assert!(late > early, "a later job wins whatever its version");
        let v1 = stamp("2026-11-02T10:00:00Z", 1, 1);
        let v2 = stamp("2026-11-02T10:00:00Z", 2, 1);
        assert!(v2 > v1, "within one job the higher version wins");
        let other = stamp("2026-11-02T10:00:00Z", 2, 2);
        assert!(
            other > v2,
            "the job id breaks an exact tie, the same way every time"
        );
    }

    #[test]
    fn a_status_comment_needs_text_of_a_sensible_size() {
        let s = stamp("2026-11-02T10:00:00Z", 1, 1);
        assert_eq!(
            StatusComment::new(s, "  \n".to_owned()),
            Err(BadStatusComment::Empty)
        );
        assert_eq!(
            StatusComment::new(s, "x".repeat(MAX_STATUS_COMMENT_BYTES + 1)),
            Err(BadStatusComment::TooLong)
        );
        assert!(StatusComment::new(s, "x".repeat(MAX_STATUS_COMMENT_BYTES)).is_ok());
    }
}
