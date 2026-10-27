//! The code host ports: reading issues and opening draft pull requests (ADR 0009).
//!
//! The factory reads issues, pushes branches under `factory/`, opens **draft** pull requests and
//! comments. It never merges: [`ChangeHost`] has no method whose name starts with `merge`, which
//! `cargo xtask check-architecture` checks (rule DEP-09). A person merges.
//!
//! Every call carries a [`GitScope`]. A token is minted for exactly that tenant, job, stage and
//! repository, with the permissions of the stage, so a call can never reach beyond its scope.

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::values::{Slug, Timestamp, Uri};
use factory_domain::vocabulary::{Fidelity, StageKind};
use std::time::Duration;

use crate::paths::{BranchName, CommitSha, RepoRef};
use crate::workspace::PushTarget;

/// What a call is allowed to touch. A token is minted for exactly this.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GitScope {
    /// The tenant.
    pub tenant: TenantId,
    /// The job.
    pub job: JobId,
    /// The stage, which decides the permissions of the token.
    pub stage: StageKind,
    /// The one repository the token works on.
    pub repo: RepoRef,
}

/// A login on the code host, such as `octocat`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ActorLogin(String);

impl ActorLogin {
    /// Checks a login: 1 to 39 letters, digits and single hyphens, not starting or ending with a
    /// hyphen.
    ///
    /// # Errors
    /// Returns [`BadLogin`] for any other shape.
    pub fn new(login: &str) -> Result<Self, BadLogin> {
        let shape_ok = !login.is_empty()
            && login.len() <= 39
            && login
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !login.starts_with('-')
            && !login.ends_with('-')
            && !login.contains("--");
        if shape_ok {
            Ok(Self(login.to_owned()))
        } else {
            Err(BadLogin)
        }
    }

    /// The login.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A login was empty, too long or used characters the code host does not allow.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "a login is 1 to 39 letters, digits and single hyphens, and does not start or end with a hyphen"
)]
pub struct BadLogin;

/// An issue, by repository and number.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IssueRef {
    /// The repository.
    pub repo: RepoRef,
    /// The issue number.
    pub number: u64,
}

/// An issue as fetched live. Its text is untrusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// Which issue.
    pub reference: IssueRef,
    /// The title, as written.
    pub title: String,
    /// The body, as written.
    pub body: String,
    /// Who opened it.
    pub author: ActorLogin,
    /// The labels on it.
    pub labels: Vec<String>,
    /// When it was fetched.
    pub fetched_at: Timestamp,
}

/// What the repository's protection looks like. The factory opens pull requests only when it is
/// strong enough; otherwise the job runs at level L0 and opens none (ADR 0009).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionReport {
    /// The default branch has a protection rule.
    pub default_branch_protected: bool,
    /// The required checks are pinned to the factory's app, so no one else can satisfy them.
    pub required_checks_pinned_to_app: bool,
    /// The app is on a bypass list. It must not be.
    pub app_can_bypass: bool,
}

impl ProtectionReport {
    /// True when the factory may open draft pull requests in this repository.
    #[must_use]
    pub const fn allows_pull_requests(&self) -> bool {
        self.default_branch_protected && self.required_checks_pinned_to_app && !self.app_can_bypass
    }
}

/// A draft pull request to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftPrRequest {
    /// The branch with the changes. Under `factory/`.
    pub head: BranchName,
    /// The branch to merge into, later, by a person.
    pub base: BranchName,
    /// The title.
    pub title: String,
    /// The body, including the evidence manifest.
    pub body: String,
}

/// A pull request, by repository and number.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PullRequestRef {
    /// The repository.
    pub repo: RepoRef,
    /// The pull request number.
    pub number: u64,
}

/// Where a pull request stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullRequestLifecycle {
    /// Open.
    Open,
    /// Closed without a merge.
    Closed,
    /// Merged by a person.
    Merged,
}

/// A pull request as read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequestState {
    /// Open, closed or merged.
    pub lifecycle: PullRequestLifecycle,
    /// True while it is a draft.
    pub draft: bool,
    /// The head branch.
    pub head: BranchName,
    /// The tag of the current body. Send it back to update the body only if it did not change.
    pub body_etag: String,
}

/// Where a comment goes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CommentTarget {
    /// An issue.
    Issue(IssueRef),
    /// A pull request.
    PullRequest(PullRequestRef),
}

/// A comment that was posted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommentRef {
    /// Where it is.
    pub target: CommentTarget,
    /// Its id on the code host.
    pub id: u64,
}

/// The state of a commit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusState {
    /// Running.
    Pending,
    /// Passed.
    Success,
    /// Failed.
    Failure,
    /// Could not run.
    Error,
}

/// A commit status to set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusRequest {
    /// The commit.
    pub commit: CommitSha,
    /// The status name, such as `factory/validation`.
    pub context: Slug,
    /// The state.
    pub state: StatusState,
    /// A short description.
    pub description: String,
    /// A link to the evidence.
    pub target_url: Option<Uri>,
}

/// Why a code host call failed. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GitHostError {
    /// No such issue, pull request or repository for this scope.
    #[error("no such item for this scope")]
    NotFound,
    /// The token is revoked, expired or was never valid for this scope.
    #[error("the credential is not valid for this scope")]
    Unauthorized,
    /// The code host refused the action for this token's permissions.
    #[error("the code host refused the action")]
    Forbidden,
    /// The item changed since the caller read it (a stale tag).
    #[error("the item changed since it was read")]
    Conflict,
    /// The branch is not under `factory/`.
    #[error("the factory may push only to branches under `factory/`")]
    BranchNotAllowed,
    /// The text to post holds something that looks like a secret. Nothing was posted.
    #[error("the text holds something that looks like a secret and was not posted")]
    UnsafeText,
    /// The code host asked the caller to slow down.
    #[error("the code host is rate limiting this caller")]
    RateLimited {
        /// How long the host asked to wait, when it said.
        retry_after: Option<Duration>,
    },
    /// The code host cannot be reached.
    #[error("the code host is unavailable")]
    Unavailable,
    /// The code host rejected the request as malformed. The text never includes secrets.
    #[error("the code host rejected the request: {0}")]
    Rejected(String),
}

/// Reads issues and the repository's protection.
///
/// # Preconditions
/// The scope names the tenant, job, stage and repository the call is for. The requester was
/// authorized by the named allowlist before the job was admitted: nothing here authorizes anyone.
///
/// # Postconditions
/// `fetch_issue` is always a live fetch; a webhook payload is only a hint. `label_actor` returns
/// the person who applied the label, or `None` when the label is not on the issue.
/// `repository_protection` reports what the repository enforces, and a failure to find out is an
/// error, which the engine treats as level L0.
///
/// # Errors
/// [`GitHostError::NotFound`], [`GitHostError::Unauthorized`], [`GitHostError::Forbidden`],
/// [`GitHostError::RateLimited`], [`GitHostError::Unavailable`].
///
/// # Idempotency
/// Every method is a read.
#[async_trait]
pub trait IssueSource: Send + Sync {
    /// Says whether this source talks to the real code host (`real`) or is scripted (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Always a live fetch. A webhook payload is a hint.
    async fn fetch_issue(&self, scope: &GitScope, issue: &IssueRef) -> Result<Issue, GitHostError>;

    /// The person who applied `label` to the issue, or `None` when it is not on the issue.
    async fn label_actor(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
        label: &str,
    ) -> Result<Option<ActorLogin>, GitHostError>;

    /// Branch protection, checks pinned to the App, no bypass for the App. A failure means level
    /// L0.
    async fn repository_protection(
        &self,
        scope: &GitScope,
    ) -> Result<ProtectionReport, GitHostError>;
}

/// Pushes branches, opens draft pull requests and posts comments. It never merges.
///
/// # Preconditions
/// The scope's job has not ended: after `revoke_job_tokens` for the job, every call with that
/// job in its scope is refused. Branches are under `factory/`. Text sent to the host is plain
/// English with no secret in it.
///
/// # Postconditions
/// `push_target` returns a target for a branch under `factory/` only. `open_draft_pull_request`
/// opens a pull request in the **draft** state and never merges it. A comment is posted at most
/// once per idempotency key. Text is checked for secrets inside the adapter before it is sent.
/// A call for one tenant's scope never reads or changes another tenant's items.
///
/// # Errors
/// [`GitHostError`]: `NotFound`, `Unauthorized` (also for a revoked job), `Forbidden`, `Conflict`
/// (stale body tag), `BranchNotAllowed`, `UnsafeText`, `RateLimited`, `Unavailable` and
/// `Rejected`.
///
/// # Idempotency
/// `open_draft_pull_request` is idempotent for the same head branch: a second call returns the
/// first pull request and opens no second one. `post_comment` is idempotent by key: the same key
/// returns the first comment. `update_pull_request_body` with the same body and a current tag
/// changes nothing visible. `set_status` is idempotent for the same commit, context and state.
/// `revoke_job_tokens` is idempotent. `pull_request_state` is a read.
#[async_trait]
pub trait ChangeHost: Send + Sync {
    /// Says whether this host adapter talks to the real code host (`real`) or is scripted
    /// (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Where to push. `factory/*` branches only.
    async fn push_target(
        &self,
        scope: &GitScope,
        branch: &BranchName,
    ) -> Result<PushTarget, GitHostError>;

    /// Opens a draft pull request. Idempotent for the same head branch.
    async fn open_draft_pull_request(
        &self,
        scope: &GitScope,
        req: DraftPrRequest,
    ) -> Result<PullRequestRef, GitHostError>;

    /// Replaces the body. With `etag`, only if the body did not change since it was read.
    async fn update_pull_request_body(
        &self,
        scope: &GitScope,
        pr: &PullRequestRef,
        body: &str,
        etag: Option<&str>,
    ) -> Result<(), GitHostError>;

    /// Sanitized and secret-checked inside the adapter. Idempotent by key.
    async fn post_comment(
        &self,
        scope: &GitScope,
        target: &CommentTarget,
        body: &str,
        idempotency_key: &str,
    ) -> Result<CommentRef, GitHostError>;

    /// Sets a commit status.
    async fn set_status(&self, scope: &GitScope, req: StatusRequest) -> Result<(), GitHostError>;

    /// Reads a pull request.
    async fn pull_request_state(
        &self,
        scope: &GitScope,
        pr: &PullRequestRef,
    ) -> Result<PullRequestState, GitHostError>;

    /// Called at job end, failure and cancel, and by the cleanup sweep.
    async fn revoke_job_tokens(&self, job: JobId) -> Result<(), GitHostError>;
    // There is no merge method and none whose name starts with merge (rule DEP-09).
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pull_requests_need_protection_pinned_checks_and_no_bypass() {
        let strong = ProtectionReport {
            default_branch_protected: true,
            required_checks_pinned_to_app: true,
            app_can_bypass: false,
        };
        assert!(strong.allows_pull_requests());
        for weaker in [
            ProtectionReport {
                default_branch_protected: false,
                ..strong.clone()
            },
            ProtectionReport {
                required_checks_pinned_to_app: false,
                ..strong.clone()
            },
            ProtectionReport {
                app_can_bypass: true,
                ..strong.clone()
            },
        ] {
            assert!(!weaker.allows_pull_requests(), "{weaker:?}");
        }
    }

    #[test]
    fn logins_follow_the_code_host_rules() {
        for good in ["octocat", "a", "a-b", "A1-b2", &"x".repeat(39)] {
            assert!(ActorLogin::new(good).is_ok(), "{good}");
        }
        for bad in ["", "-a", "a-", "a--b", "a b", "a_b", "a/b", &"x".repeat(40)] {
            assert!(ActorLogin::new(bad).is_err(), "{bad:?}");
        }
    }
}
