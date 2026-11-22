//! Reading what became of a pull request the factory opened (ports v1.5, ADR 0029).
//!
//! The factory opens a draft pull request and never merges it. A person merges it or closes it,
//! often days after the job that opened it has ended. The process metrics need that fate, so a
//! step of the worker asks the code host for each pull request that is still open in the store.
//!
//! # Why this is its own port
//!
//! [`ChangeHost::pull_request_state`](crate::githost::ChangeHost::pull_request_state) reads
//! through the token of a stage, in a scope that names a job, and a job that has ended can never
//! mint a token again. The fate is read after the job has ended, so this port has a credential of
//! its own that belongs to no job and no stage: `metadata: read` and `pull_requests: read`, for
//! one repository (the same reasoning as [`ProposalHost`](crate::proposal::ProposalHost),
//! ADR 0026). It can write nothing.
//!
//! # The contract
//!
//! The preconditions, postconditions, errors, idempotency and cancellation are in
//! `docs/architecture/ports-v1.5.md`, section 3. In short: one read, a merged or closed pull
//! request always comes with the time the code host gives for it, and an answer without that time
//! is an error and not a fate.

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::Fidelity;

use crate::githost::{GitHostError, PullRequestLifecycle, PullRequestRef};
use crate::paths::RepoRef;

/// What a look may touch. A credential is minted for exactly this. No stage and no job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FateScope {
    /// The tenant that owns the pull request.
    pub tenant: TenantId,
    /// The identifier the credential is kept under and ended by (`revoke_job_tokens`). Not a job:
    /// a fresh identifier for each pass.
    pub session: JobId,
    /// The repository of the pull request.
    pub repo: RepoRef,
}

/// What the code host says about a pull request now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedPullRequest {
    lifecycle: PullRequestLifecycle,
    decided_at: Option<Timestamp>,
}

impl ObservedPullRequest {
    /// A pull request nobody decided about.
    pub const OPEN: Self = Self {
        lifecycle: PullRequestLifecycle::Open,
        decided_at: None,
    };

    /// A pull request a person merged at `at`.
    #[must_use]
    pub const fn merged(at: Timestamp) -> Self {
        Self {
            lifecycle: PullRequestLifecycle::Merged,
            decided_at: Some(at),
        }
    }

    /// A pull request that was closed without a merge at `at`.
    #[must_use]
    pub const fn closed(at: Timestamp) -> Self {
        Self {
            lifecycle: PullRequestLifecycle::Closed,
            decided_at: Some(at),
        }
    }

    /// Open, closed or merged.
    #[must_use]
    pub const fn lifecycle(&self) -> PullRequestLifecycle {
        self.lifecycle
    }

    /// When it was merged or closed, as the code host says. `None` exactly while it is open: the
    /// constructors allow no other combination.
    #[must_use]
    pub const fn decided_at(&self) -> Option<Timestamp> {
        self.decided_at
    }
}

/// Reads the fate of a pull request, outside any job.
///
/// # Preconditions
/// The scope names the tenant and the repository of the pull request.
///
/// # Postconditions
/// A merged pull request is reported as merged with the time of the merge, one closed without a
/// merge as closed with the time of the close, an open one as open with no time. Nothing is
/// written on the code host.
///
/// # Errors
/// [`GitHostError`]: `NotFound` for a pull request or a repository the scope does not cover,
/// `Forbidden` when the credential lacks the permission, `RateLimited` and `Unavailable` for the
/// host, and `Unavailable` for an answer that cannot be read, such as a merged pull request with
/// no time.
///
/// # Idempotency
/// A read.
///
/// # Cancellation and timeouts
/// Safe to drop. The adapter sets a request timeout and reports `Unavailable` when it is exceeded.
#[async_trait]
pub trait PullRequestFateSource: Send + Sync {
    /// Says whether this reads the real code host (`real`) or a list (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Reads one pull request.
    async fn observe(
        &self,
        scope: &FateScope,
        pr: &PullRequestRef,
    ) -> Result<ObservedPullRequest, GitHostError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_observation_has_a_time_exactly_when_the_pull_request_was_decided() {
        let at = Timestamp::parse("2026-11-21T10:00:00Z").expect("a time");
        assert_eq!(
            ObservedPullRequest::OPEN.lifecycle(),
            PullRequestLifecycle::Open
        );
        assert_eq!(ObservedPullRequest::OPEN.decided_at(), None);
        let merged = ObservedPullRequest::merged(at);
        assert_eq!(merged.lifecycle(), PullRequestLifecycle::Merged);
        assert_eq!(merged.decided_at(), Some(at));
        let closed = ObservedPullRequest::closed(at);
        assert_eq!(closed.lifecycle(), PullRequestLifecycle::Closed);
        assert_eq!(closed.decided_at(), Some(at));
    }
}
