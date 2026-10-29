//! The code host ports: reading issues and opening draft pull requests (ADR 0009).
//!
//! The factory reads issues, pushes branches under `factory/`, opens **draft** pull requests and
//! comments. It never merges: [`ChangeHost`] has no method whose name starts with `merge`, which
//! `cargo xtask check-architecture` checks (rule DEP-09). A person merges.
//!
//! Every call carries a [`GitScope`]. A token is minted for exactly that tenant, job, stage and
//! repository, with the permissions of the stage, so a call can never reach beyond its scope.
//!
//! Gate results reach the code host as **check runs**, not commit statuses: a check run carries
//! the identity of the App that made it, so a ruleset can pin a required check to the App. The
//! factory never marks a pull request ready for review (ADR 0014 decision 7). Incoming webhooks are
//! checked by [`WebhookVerifier`], a pure port, before anything is parsed or stored.

use std::time::Duration;

use async_trait::async_trait;
use factory_domain::ids::{JobId, PrincipalId, TenantId};
use factory_domain::values::{Sha256Digest, Slug, Timestamp, Uri};
use factory_domain::vocabulary::{Fidelity, StageKind};

use crate::paths::{BranchName, CommitSha, RepoRef};
use crate::store::{GithubRepositoryId, InstallationId};
use crate::workspace::{FetchTarget, PushTarget};

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
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IssueRef {
    /// The repository.
    pub repo: RepoRef,
    /// The issue number.
    pub number: u64,
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
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

/// Where a comment goes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CommentTarget {
    /// An issue.
    Issue(IssueRef),
    /// A pull request.
    PullRequest(PullRequestRef),
}

/// A comment that was posted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CommentRef {
    /// Where it is.
    pub target: CommentTarget,
    /// Its id on the code host.
    pub id: u64,
}

/// A person or service on the code host. Authority comes from the numeric id, never from the
/// login: a login can be renamed or re-registered by someone else.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GithubActor {
    /// The immutable numeric id.
    pub id: u64,
    /// The login at the time of the call. Display only.
    pub login: ActorLogin,
}

/// Who applied a label, and when the code host says it did.
///
/// Added after v1.1, pending architect confirmation (`docs/architecture/ports-v1.1.md`, "Additions
/// after v1.1"): the intake stage compares the time with the time the issue was last changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelApplication {
    /// The person who applied the label now on the issue.
    pub actor: GithubActor,
    /// When the code host recorded it. `None` when the source cannot say; a caller then has no
    /// time to compare and must not pretend it has.
    pub applied_at: Option<Timestamp>,
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
    pub author: GithubActor,
    /// The labels on it.
    pub labels: Vec<String>,
    /// When it was last edited, as the host reports. A change after the intake snapshot is an
    /// external change (ADR 0010).
    pub updated_at: Timestamp,
    /// When it was fetched.
    pub fetched_at: Timestamp,
}

/// A comment as fetched live. Its text is untrusted. An operator command comes this way (FR-029).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    /// Which comment.
    pub reference: CommentRef,
    /// Who wrote it.
    pub author: GithubActor,
    /// The text, as written.
    pub body: String,
    /// When it was written.
    pub created_at: Timestamp,
    /// When it was last edited, if it was.
    pub edited_at: Option<Timestamp>,
}

/// The id of the factory's own GitHub App.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AppId(pub u64);

/// A required status check of a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredCheck {
    /// The check's name.
    pub context: String,
    /// The App the check must come from, when the rule pins one.
    pub integration_id: Option<u64>,
}

/// How much of the repository's protection the App could read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionSource {
    /// Rules of active rulesets that apply to the default branch (`GET .../rules/branches/{b}`,
    /// Metadata read).
    Rulesets,
    /// The default branch has no active ruleset rule. It may have classic branch protection, which
    /// needs the Administration permission to read and which the App must not hold.
    NoRulesetRules,
}

/// What the repository's protection looks like, as far as the App can read it without the
/// Administration permission. It cannot read the bypass list; see [`BypassAttestation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectionReport {
    /// The default branch the rules were read for.
    pub default_branch: BranchName,
    /// Where the rules came from.
    pub source: ProtectionSource,
    /// A rule requires a pull request before merging.
    pub requires_pull_request: bool,
    /// A rule requires code owner review.
    pub requires_code_owner_review: bool,
    /// A rule dismisses approvals when new commits are pushed.
    pub dismisses_stale_approvals: bool,
    /// A rule blocks force pushes (non-fast-forward updates).
    pub blocks_force_push: bool,
    /// A rule blocks deletion of the branch.
    pub blocks_deletion: bool,
    /// The required status checks.
    pub required_checks: Vec<RequiredCheck>,
}

/// A recorded statement by an organization admin that the factory's App is on no bypass list of
/// the repository. The App cannot check this itself without the Administration permission, which
/// the policy forbids, so a person says it and the record is part of the audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BypassAttestation {
    /// The admin who made the statement.
    pub by: PrincipalId,
    /// When it was recorded.
    pub at: Timestamp,
}

/// What the preflight found missing. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightFailure {
    /// No ruleset rule applies to the default branch.
    NoRulesetRules,
    /// A pull request is not required.
    PullRequestNotRequired,
    /// Code owner review is not required.
    CodeOwnerReviewMissing,
    /// Approvals are kept when new commits are pushed.
    StaleApprovalsKept,
    /// Force pushes are allowed.
    ForcePushAllowed,
    /// Deleting the branch is allowed.
    DeletionAllowed,
    /// A check the factory posts is not required.
    FactoryCheckNotRequired(String),
    /// A check the factory posts is required but not pinned to the factory's App.
    FactoryCheckNotPinned(String),
    /// Nobody attested that the App is on no bypass list.
    BypassNotAttested,
}

/// The outcome of the protection preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreflightVerdict {
    /// The repository may run above L0.
    Pass,
    /// The repository runs at L0 only, for these reasons.
    CapAtL0(Vec<PreflightFailure>),
}

impl ProtectionReport {
    /// Pure. `Pass` only when every item of `policies/security.yaml`
    /// `credentials.repository_requirements` holds: rules apply to the default branch, a pull
    /// request is required, code owner review is required, stale approvals are dismissed, force
    /// pushes and deletion are blocked, every name in `factory_checks` is required and pinned to
    /// `app`, and `attestation` is present. Every failure is listed, not only the first.
    #[must_use]
    pub fn evaluate(
        &self,
        app: AppId,
        factory_checks: &[Slug],
        attestation: Option<&BypassAttestation>,
    ) -> PreflightVerdict {
        let mut failures = Vec::new();
        if self.source == ProtectionSource::NoRulesetRules {
            failures.push(PreflightFailure::NoRulesetRules);
        }
        if !self.requires_pull_request {
            failures.push(PreflightFailure::PullRequestNotRequired);
        }
        if !self.requires_code_owner_review {
            failures.push(PreflightFailure::CodeOwnerReviewMissing);
        }
        if !self.dismisses_stale_approvals {
            failures.push(PreflightFailure::StaleApprovalsKept);
        }
        if !self.blocks_force_push {
            failures.push(PreflightFailure::ForcePushAllowed);
        }
        if !self.blocks_deletion {
            failures.push(PreflightFailure::DeletionAllowed);
        }
        for name in factory_checks {
            let mut named = self
                .required_checks
                .iter()
                .filter(|check| check.context == name.as_str())
                .peekable();
            if named.peek().is_none() {
                failures.push(PreflightFailure::FactoryCheckNotRequired(
                    name.as_str().to_owned(),
                ));
            } else if !named.any(|check| check.integration_id == Some(app.0)) {
                failures.push(PreflightFailure::FactoryCheckNotPinned(
                    name.as_str().to_owned(),
                ));
            }
        }
        if attestation.is_none() {
            failures.push(PreflightFailure::BypassNotAttested);
        }
        if failures.is_empty() {
            PreflightVerdict::Pass
        } else {
            PreflightVerdict::CapAtL0(failures)
        }
    }
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
    /// The commit the head branch points at now. An approval binds to it.
    pub head_sha: CommitSha,
    /// The base branch.
    pub base: BranchName,
    /// The tag of the current body.
    pub body_etag: String,
}

/// The state of a check run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// Running.
    InProgress,
    /// Finished with a conclusion.
    Completed(CheckConclusion),
}

/// How a finished check run ended. The names follow what a required check accepts: success,
/// skipped and neutral count as passing, the others do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckConclusion {
    /// Every gate passed.
    Success,
    /// A gate failed or could not run.
    Failure,
    /// The stage does not apply (a `SKIPPED` stage run).
    Neutral,
    /// A person must act.
    ActionRequired,
    /// The job was cancelled.
    Cancelled,
}

/// A check run to create or update. Gate results reach the code host as check runs, because a
/// check run carries the identity of the App that made it and a commit status does not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRequest {
    /// The commit the check is about.
    pub commit: CommitSha,
    /// The check's name, such as `factory-validation`. This is the name a ruleset requires.
    pub name: Slug,
    /// Which run of which stage: the same `(commit, name, external_id)` updates one check run.
    pub external_id: Slug,
    /// Running or finished.
    pub status: CheckStatus,
    /// A short title, 1 to 100 bytes.
    pub title: String,
    /// A summary, 1 to 4000 bytes. Checked for secrets.
    pub summary: String,
    /// A link to the evidence.
    pub details_url: Option<Uri>,
}

/// A check run that was created or updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckRef {
    /// Its id on the code host.
    pub id: u64,
}

/// Why a request was rejected as malformed. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// The head branch is not on the remote. Push it first.
    HeadNotPushed,
    /// The head and the base are the same branch.
    HeadIsBase,
    /// There is nothing to compare: the branches have no difference.
    NoDifference,
    /// A text field is empty or longer than the host allows.
    TextBounds,
    /// The host refused for a reason the adapter could not classify.
    Other,
}

/// Why a code host call failed. The set is closed. `Rejected` names the reason.
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
    /// The code host rejected the request as malformed.
    #[error("the code host rejected the request: {0:?}")]
    Rejected(Rejection),
}

/// Reads issues, comments and the repository's protection.
///
/// # Preconditions
/// The scope names the tenant, job, stage and repository the call is for. Nothing here
/// authorizes anyone: the caller matches `GithubActor::id` against the named allowlist.
///
/// # Postconditions
/// Every fetch is live; a webhook payload is only a hint. `label_actor` returns the person who
/// applied the label, or `None` when the label is not on the issue. `repository_protection`
/// reads rulesets only, with the permissions the policy allows (Metadata read), and reports
/// `ProtectionSource::NoRulesetRules` when none applies; it never asks for the Administration
/// permission.
///
/// # Errors
/// [`GitHostError`]: `NotFound`, `Unauthorized`, `Forbidden`, `RateLimited`, `Unavailable`.
///
/// # Idempotency
/// Every method is a read.
///
/// # Cancellation and timeouts
/// Every call is safe to drop. The adapter sets a request timeout of 30 seconds and reports
/// `Unavailable` when it is exceeded.
#[async_trait]
pub trait IssueSource: Send + Sync {
    /// Says whether this source talks to the real code host (`real`) or is scripted (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Always a live fetch.
    async fn fetch_issue(&self, scope: &GitScope, issue: &IssueRef) -> Result<Issue, GitHostError>;

    /// Always a live fetch. The comment of an operator command, with its author's numeric id.
    async fn fetch_comment(
        &self,
        scope: &GitScope,
        comment: &CommentRef,
    ) -> Result<Comment, GitHostError>;

    /// The person who applied `label` to the issue, or `None` when it is not on the issue.
    async fn label_actor(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
        label: &str,
    ) -> Result<Option<GithubActor>, GitHostError>;

    /// Like [`label_actor`](Self::label_actor), with the time the host recorded for the label that
    /// is on the issue now. A label that was applied, removed and applied again is the later
    /// application. The default is the actor with no time, which is all a source that keeps no
    /// timeline can say; the code host adapter answers with the time of the `labeled` event.
    async fn label_application(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
        label: &str,
    ) -> Result<Option<LabelApplication>, GitHostError> {
        Ok(self
            .label_actor(scope, issue, label)
            .await?
            .map(|actor| LabelApplication {
                actor,
                applied_at: None,
            }))
    }

    /// Reads the rules that apply to the default branch. A failure to read is an error, which the
    /// engine treats as level L0.
    async fn repository_protection(
        &self,
        scope: &GitScope,
    ) -> Result<ProtectionReport, GitHostError>;
}

/// Pushes branches, opens draft pull requests, posts comments and check runs. It never merges and
/// never marks a pull request ready for review.
///
/// # Preconditions
/// The scope's job has not ended: after `revoke_job_tokens` for the job, every call with that
/// job in its scope is refused. Branches are under `factory/`. Text sent to the host is plain
/// English with no secret in it.
///
/// # Postconditions
/// `fetch_target` and `push_target` return credentials narrowed to one repository, read-only and
/// write for a `factory/*` branch only. `resolve_branch` returns the commit a branch points at
/// now. `open_draft_pull_request` opens a pull request in the **draft** state and never merges
/// it; if the head branch is not on the remote it returns `Rejected(HeadNotPushed)`. A comment
/// is posted **at least once** per idempotency key: the adapter embeds a marker derived from the
/// key and looks for it before posting, which reduces duplicates and does not rule them out (ADR
/// 0004). `publish_check` creates or updates one check run per `(commit, name, external_id)` as
/// the App. A call for one tenant's scope never reads or changes another tenant's items.
///
/// # Errors
/// [`GitHostError`].
///
/// # Idempotency
/// `open_draft_pull_request` is idempotent for the same open head branch: a second call returns
/// the first pull request; for a closed one it opens a new one. `post_comment` is at least once
/// by key. `update_pull_request_body` with the same body and a current tag changes nothing
/// visible. `publish_check` is idempotent by `(commit, name, external_id)`.
/// `revoke_job_tokens`is idempotent. The rest are reads.
///
/// # Cancellation and timeouts
/// Every call is safe to drop, with the effect of a call that was sent being possible. The
/// adapter sets a request timeout of 30 seconds and reports `Unavailable` when it is exceeded.
#[async_trait]
pub trait ChangeHost: Send + Sync {
    /// Says whether this host adapter talks to the real code host (`real`) or is scripted
    /// (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// A read credential for fetching the repository.
    async fn fetch_target(&self, scope: &GitScope) -> Result<FetchTarget, GitHostError>;

    /// Where to push. `factory/*` branches only.
    async fn push_target(
        &self,
        scope: &GitScope,
        branch: &BranchName,
    ) -> Result<PushTarget, GitHostError>;

    /// The commit the branch points at on the host now. A cheap call, for the checks that
    /// ask whether the base moved (ADR 0010) without fetching objects.
    async fn resolve_branch(
        &self,
        scope: &GitScope,
        branch: &BranchName,
    ) -> Result<CommitSha, GitHostError>;

    /// Opens a draft pull request. Idempotent for the same open head branch.
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

    /// Sanitized and secret-checked inside the adapter. At least once by key.
    async fn post_comment(
        &self,
        scope: &GitScope,
        target: &CommentTarget,
        body: &str,
        idempotency_key: &str,
    ) -> Result<CommentRef, GitHostError>;

    /// Creates or updates the check run for a gate result.
    async fn publish_check(
        &self,
        scope: &GitScope,
        req: CheckRequest,
    ) -> Result<CheckRef, GitHostError>;

    /// Reads a pull request.
    async fn pull_request_state(
        &self,
        scope: &GitScope,
        pr: &PullRequestRef,
    ) -> Result<PullRequestState, GitHostError>;

    /// Called at job end, failure and cancel, and by the cleanup sweep.
    async fn revoke_job_tokens(&self, job: JobId) -> Result<(), GitHostError>;
    // There is no merge method, no method that marks a pull request ready, and none whose name
    // starts with `merge`, `ready` or `undraft` (rule DEP-09, extended by ADR 0014).
}

/// The headers of a webhook request that matter. Missing ones are `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebhookHeaders {
    /// `X-GitHub-Event`.
    pub event: Option<String>,
    /// `X-GitHub-Delivery`.
    pub delivery: Option<String>,
    /// `X-Hub-Signature-256`.
    pub signature_256: Option<String>,
    /// `Content-Type`.
    pub content_type: Option<String>,
    /// True when the request also had the legacy `X-Hub-Signature` header.
    pub has_legacy_signature: bool,
}

/// What the payload hints at. The engine fetches the real state before it acts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookHint {
    /// A label was applied to an issue.
    IssueLabeled {
        /// The issue.
        issue: IssueRef,
        /// The label.
        label: String,
    },
    /// An issue was edited.
    IssueEdited {
        /// The issue.
        issue: IssueRef,
    },
    /// A comment was created on an issue or pull request.
    CommentCreated {
        /// The comment.
        comment: CommentRef,
    },
    /// A pull request changed (pushed to, closed, reopened).
    PullRequestChanged {
        /// The pull request.
        pr: PullRequestRef,
    },
    /// An event the factory does not act on. It is still recorded as a delivery.
    Other,
}

/// A delivery whose signature checked out. Everything in it is still untrusted except the
/// fact that GitHub sent it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDelivery {
    /// `X-GitHub-Delivery`, 8 to 128 bytes.
    pub delivery_id: String,
    /// The event name.
    pub event: Slug,
    /// The action, when the payload has one.
    pub action: Option<Slug>,
    /// The installation the delivery came through.
    pub installation: InstallationId,
    /// The repository, when the payload names one.
    pub repository: Option<GithubRepositoryId>,
    /// The numeric id of the sender.
    pub sender_github_user_id: Option<u64>,
    /// The hash of the raw body.
    pub body_sha256: Sha256Digest,
    /// The hash of event, action, installation, repository, subject, subject update time and
    /// sender.
    pub semantic_key: Option<Sha256Digest>,
    /// What the payload hints at.
    pub hint: WebhookHint,
}

/// Why a delivery was refused. The reply to GitHub is the same for every variant; only the audit
/// record differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WebhookRejection {
    /// The body is larger than the limit (1 MiB).
    #[error("the body is too large")]
    TooLarge,
    /// A required header is missing.
    #[error("the header {0} is missing")]
    MissingHeader(&'static str),
    /// The content type is not `application/json`.
    #[error("the content type is not accepted")]
    BadContentType,
    /// The signature does not match, or is not in the `sha256=` form.
    #[error("the signature does not match")]
    BadSignature,
    /// Only the legacy SHA-1 header was present.
    #[error("only the legacy signature header was present")]
    LegacySignatureOnly,
    /// The signature matched and the payload is not a JSON object of the expected shape.
    #[error("the payload is malformed")]
    Malformed,
    /// The event is not on the `webhook.accepted_events` list.
    #[error("the event is not accepted")]
    UnsupportedEvent,
}

/// Verifies a webhook delivery before anything reads it (`policies/security.yaml`,
/// `webhook`). Pure and synchronous: the secrets are loaded when it is built. The `api` binary
/// depends on this port, not on the `github` crate.
///
/// # Preconditions
/// `raw_body` is the request body exactly as received, before any parse or re-serialization.
///
/// # Postconditions
/// The signature is `HMAC-SHA256(secret, raw_body)` compared in constant time with the value of
/// `X-Hub-Signature-256`, against every secret in the rotation window. The check happens before
/// the body is parsed. A delivery with only the legacy header is refused. No store call has been
/// made by the time this returns, so a forged request touches no database.
///
/// # Errors
/// [`WebhookRejection`].
///
/// # Idempotency
/// Pure: the same input gives the same result.
///
/// # Cancellation and timeouts
/// Pure and synchronous. The body size limit bounds the work, so there is nothing to cancel and no
/// timeout.
pub trait WebhookVerifier: Send + Sync {
    /// Says whether this verifier holds the real secrets (`real`) or a fixed test secret (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Checks size, headers, content type and signature, then reads the fields the engine needs.
    fn verify(
        &self,
        raw_body: &[u8],
        headers: &WebhookHeaders,
    ) -> Result<VerifiedDelivery, WebhookRejection>;
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: AppId = AppId(4242);

    fn slug(text: &str) -> Slug {
        Slug::parse(text).unwrap()
    }

    fn strong() -> ProtectionReport {
        ProtectionReport {
            default_branch: BranchName::new("main").unwrap(),
            source: ProtectionSource::Rulesets,
            requires_pull_request: true,
            requires_code_owner_review: true,
            dismisses_stale_approvals: true,
            blocks_force_push: true,
            blocks_deletion: true,
            required_checks: vec![
                RequiredCheck {
                    context: "factory-validation".to_owned(),
                    integration_id: Some(APP.0),
                },
                RequiredCheck {
                    context: "factory-review".to_owned(),
                    integration_id: Some(APP.0),
                },
            ],
        }
    }

    fn checks() -> Vec<Slug> {
        vec![slug("factory-validation"), slug("factory-review")]
    }

    fn attested() -> BypassAttestation {
        BypassAttestation {
            by: PrincipalId::from_uuid(uuid::Uuid::from_u128(9)),
            at: Timestamp::parse("2026-10-27T10:00:00Z").unwrap(),
        }
    }

    fn failures(
        report: &ProtectionReport,
        attestation: Option<&BypassAttestation>,
    ) -> Vec<PreflightFailure> {
        match report.evaluate(APP, &checks(), attestation) {
            PreflightVerdict::Pass => Vec::new(),
            PreflightVerdict::CapAtL0(list) => list,
        }
    }

    #[test]
    fn a_strong_pinned_and_attested_repository_passes() {
        assert_eq!(
            strong().evaluate(APP, &checks(), Some(&attested())),
            PreflightVerdict::Pass
        );
    }

    #[test]
    fn each_missing_item_is_listed_on_its_own() {
        type Weaken = fn(&mut ProtectionReport);
        let cases: [(Weaken, PreflightFailure); 5] = [
            (
                |r| r.requires_pull_request = false,
                PreflightFailure::PullRequestNotRequired,
            ),
            (
                |r| r.requires_code_owner_review = false,
                PreflightFailure::CodeOwnerReviewMissing,
            ),
            (
                |r| r.dismisses_stale_approvals = false,
                PreflightFailure::StaleApprovalsKept,
            ),
            (
                |r| r.blocks_force_push = false,
                PreflightFailure::ForcePushAllowed,
            ),
            (
                |r| r.blocks_deletion = false,
                PreflightFailure::DeletionAllowed,
            ),
        ];
        for (weaken, expected) in cases {
            let mut report = strong();
            weaken(&mut report);
            assert_eq!(failures(&report, Some(&attested())), vec![expected]);
        }
    }

    #[test]
    fn a_missing_attestation_caps_the_repository_at_l0() {
        assert_eq!(
            failures(&strong(), None),
            vec![PreflightFailure::BypassNotAttested]
        );
    }

    #[test]
    fn a_factory_check_that_is_not_required_is_named() {
        let mut report = strong();
        report
            .required_checks
            .retain(|c| c.context != "factory-review");
        assert_eq!(
            failures(&report, Some(&attested())),
            vec![PreflightFailure::FactoryCheckNotRequired(
                "factory-review".to_owned()
            )]
        );
    }

    #[test]
    fn a_factory_check_that_any_app_may_provide_is_not_pinned() {
        let mut report = strong();
        report.required_checks[0].integration_id = None;
        assert_eq!(
            failures(&report, Some(&attested())),
            vec![PreflightFailure::FactoryCheckNotPinned(
                "factory-validation".to_owned()
            )]
        );
        // Pinned to another App is not pinned to this one either.
        report.required_checks[0].integration_id = Some(APP.0 + 1);
        assert_eq!(
            failures(&report, Some(&attested())),
            vec![PreflightFailure::FactoryCheckNotPinned(
                "factory-validation".to_owned()
            )]
        );
    }

    #[test]
    fn a_repository_with_only_classic_protection_is_capped_with_every_reason() {
        let report = ProtectionReport {
            source: ProtectionSource::NoRulesetRules,
            requires_pull_request: false,
            requires_code_owner_review: false,
            dismisses_stale_approvals: false,
            blocks_force_push: false,
            blocks_deletion: false,
            required_checks: Vec::new(),
            ..strong()
        };
        let listed = failures(&report, None);
        assert_eq!(listed.first(), Some(&PreflightFailure::NoRulesetRules));
        assert!(listed.contains(&PreflightFailure::PullRequestNotRequired));
        assert!(listed.contains(&PreflightFailure::FactoryCheckNotRequired(
            "factory-review".to_owned()
        )));
        assert!(listed.contains(&PreflightFailure::BypassNotAttested));
        assert_eq!(listed.len(), 9, "{listed:?}");
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

    #[test]
    fn an_actor_carries_the_numeric_id_that_authority_is_matched_on() {
        let a = GithubActor {
            id: 1,
            login: ActorLogin::new("octocat").unwrap(),
        };
        let renamed = GithubActor {
            id: 1,
            login: ActorLogin::new("someone-else").unwrap(),
        };
        assert_ne!(a, renamed, "the whole value differs");
        assert_eq!(
            a.id, renamed.id,
            "the numeric id is what identifies the person"
        );
    }

    #[test]
    fn a_webhook_rejection_says_nothing_about_which_part_was_wrong_beyond_its_name() {
        assert_eq!(
            WebhookRejection::MissingHeader("X-GitHub-Delivery").to_string(),
            "the header X-GitHub-Delivery is missing"
        );
        assert_eq!(
            WebhookRejection::BadSignature.to_string(),
            "the signature does not match"
        );
    }

    #[test]
    fn check_conclusions_and_statuses_are_distinct_values() {
        assert_ne!(
            CheckStatus::InProgress,
            CheckStatus::Completed(CheckConclusion::Success)
        );
        assert_ne!(
            CheckStatus::Completed(CheckConclusion::Success),
            CheckStatus::Completed(CheckConclusion::Failure)
        );
    }
}
