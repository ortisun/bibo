//! The contract suites for `ChangeHost` and `IssueSource`: draft-only pull requests, factory
//! branches only, idempotent opening and commenting, text checked for secrets, tag-checked body
//! updates, tenant and repository scope, and refusal after a job's tokens are revoked.
//!
//! `ChangeHost` has no method to merge. The suite gives the subject [`ChangeHostSubject::person_merges`]
//! so a test can play the person who merges outside the factory.

use std::future::Future;

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::StageKind;
use factory_ports::clock::Uuid;
use factory_ports::githost::{
    ActorLogin, AppId, ChangeHost, CheckConclusion, CheckRef, CheckRequest, CheckStatus, Comment,
    CommentRef, CommentTarget, DraftPrRequest, GitHostError, GitScope, GithubActor, Issue,
    IssueRef, IssueSource, ProtectionReport, ProtectionSource, PullRequestLifecycle,
    PullRequestRef, Rejection, RequiredCheck,
};
use factory_ports::paths::{BranchName, CommitSha, RepoRef};

use super::{
    Check, Context, Report, Waiver, check_list, ensure, ensure_eq, ensure_err, run_checks,
};

/// A GitHub installation token in the format of FX-CANARY: `ghs_` and 36 letters and digits.
pub const TOKEN_CANARY: &str = "ghs_a1B2c3D4e5a1B2c3D4e5a1B2c3D4e5a1B2c3";

/// The repository the suites work in.
///
/// # Panics
/// Never in practice: the literal is a valid repository name.
#[must_use]
pub fn repo() -> RepoRef {
    RepoRef::parse("example-org/fixture").expect("a valid repository")
}

fn tenant(n: u128) -> TenantId {
    TenantId::from_uuid(Uuid::from_u128(
        (n << 80) | (0x7_u128 << 76) | (0b10_u128 << 62),
    ))
}

fn job(n: u128) -> JobId {
    JobId::from_uuid(Uuid::from_u128(
        ((100 + n) << 80) | (0x7_u128 << 76) | (0b10_u128 << 62),
    ))
}

/// A scope for tenant number `tenant_n` and job number `job_n` in [`repo`], at the delivery
/// stage.
#[must_use]
pub fn scope(tenant_n: u128, job_n: u128) -> GitScope {
    GitScope {
        tenant: tenant(tenant_n),
        job: job(job_n),
        stage: StageKind::Delivery,
        repo: repo(),
    }
}

fn branch(name: &str) -> Result<BranchName, String> {
    BranchName::new(name).ctx(&format!("branch {name}"))
}

fn draft(head: &str) -> Result<DraftPrRequest, String> {
    Ok(DraftPrRequest {
        head: branch(head)?,
        base: branch("main")?,
        title: "Add a word count command".to_owned(),
        body: "Evidence manifest follows.".to_owned(),
    })
}

// ---------------------------------------------------------------------------------------------
// ChangeHost

/// What the suite needs beyond the `ChangeHost` port itself.
#[async_trait]
pub trait ChangeHostSubject: Send + Sync {
    /// The change host under test.
    fn host(&self) -> &dyn ChangeHost;

    /// How many comments the host holds for the target.
    async fn comment_count(&self, target: &CommentTarget) -> usize;

    /// A person merges the pull request on the code host, outside the factory.
    async fn person_merges(&self, pr: &PullRequestRef);

    /// A person closes the pull request without merging it.
    async fn person_closes(&self, pr: &PullRequestRef);

    /// The id of the App the host makes check runs as.
    fn app_id(&self) -> AppId;

    /// How many check runs the host holds for the commit and name.
    async fn check_run_count(&self, commit: &CommitSha, name: &str) -> usize;

    /// The App a check run was made as, as the code host records it.
    async fn check_run_app(&self, check: &CheckRef) -> Option<AppId>;

    /// The commit a branch of the remote points at. The branches `factory/job-1`,
    /// `factory/job-2`, `factory/job-3` and `main` exist before a check starts.
    async fn branch_tip(&self, repo: &RepoRef, branch: &BranchName) -> Option<CommitSha>;
}

/// A check of the change host contract.
pub type ChangeHostCheck = Check<dyn ChangeHostSubject>;

/// Runs the whole change host suite. `make` builds a fresh subject for every check.
pub async fn run_change_host<S, F, Fut>(make: F) -> Report
where
    S: ChangeHostSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&change_host_checks(), || async {
        Box::new(make().await) as Box<dyn ChangeHostSubject>
    })
    .await
}

/// Every check of the change host contract.
#[must_use]
pub fn change_host_checks() -> Vec<ChangeHostCheck> {
    check_list![dyn ChangeHostSubject;
        push_targets_are_for_factory_branches_only,
        a_pull_request_is_opened_as_a_draft_and_stays_open,
        opening_for_the_same_head_twice_returns_the_same_pull_request,
        a_pull_request_from_a_head_outside_factory_is_refused,
        the_body_is_updated_only_if_its_tag_is_current,
        a_comment_is_posted_once_per_key,
        text_with_a_secret_is_not_posted,
        a_check_run_is_updated_not_duplicated,
        a_check_run_carries_the_apps_identity,
        after_a_job_ends_its_calls_are_refused,
        another_tenant_cannot_reach_a_pull_request,
        a_scope_for_another_repository_cannot_reach_a_pull_request,
        a_pull_request_merged_by_a_person_reads_as_merged,
        a_pull_request_needs_a_pushed_head,
        a_closed_pull_request_is_not_reused,
        base_is_honoured,
        a_comment_is_found_by_its_marker_before_posting,
    ]
}

/// No waivers: every check has a defect.
pub const WAIVERS: &[Waiver] = &[];

async fn push_targets_are_for_factory_branches_only(
    subject: &dyn ChangeHostSubject,
) -> Result<(), String> {
    let host = subject.host();
    let scope = scope(1, 1);
    let target = host
        .push_target(&scope, &branch("factory/job-1")?)
        .await
        .ctx("a factory branch")?;
    ensure_eq!(
        target.branch.clone(),
        branch("factory/job-1")?,
        "the target's branch"
    );
    ensure_eq!(
        target.repo.clone(),
        scope.repo.clone(),
        "the target's repository"
    );
    ensure!(
        !target.credential.expose().is_empty(),
        "a target needs a credential"
    );
    ensure!(
        !format!("{target:?}").contains(target.credential.expose()),
        "the debug output of a push target must not show the credential"
    );
    for name in ["main", "release/1.0", "factory-evil/x", "feature/factory/x"] {
        ensure_err!(
            host.push_target(&scope, &branch(name)?).await,
            GitHostError::BranchNotAllowed,
            "a push target for {name}"
        );
    }
    Ok(())
}

async fn a_pull_request_is_opened_as_a_draft_and_stays_open(
    subject: &dyn ChangeHostSubject,
) -> Result<(), String> {
    let host = subject.host();
    let scope = scope(1, 1);
    let pr = host
        .open_draft_pull_request(&scope, draft("factory/job-1")?)
        .await
        .ctx("open")?;
    let state = host.pull_request_state(&scope, &pr).await.ctx("state")?;
    ensure!(state.draft, "the pull request must be a draft");
    ensure_eq!(
        state.lifecycle,
        PullRequestLifecycle::Open,
        "the lifecycle of a new pull request"
    );
    ensure_eq!(state.head, branch("factory/job-1")?, "the head branch");
    ensure_eq!(
        pr.repo.clone(),
        scope.repo.clone(),
        "the repository of the pull request"
    );
    Ok(())
}

async fn opening_for_the_same_head_twice_returns_the_same_pull_request(
    subject: &dyn ChangeHostSubject,
) -> Result<(), String> {
    let host = subject.host();
    let scope = scope(1, 1);
    let first = host
        .open_draft_pull_request(&scope, draft("factory/job-1")?)
        .await
        .ctx("first open")?;
    let second = host
        .open_draft_pull_request(&scope, draft("factory/job-1")?)
        .await
        .ctx("second open")?;
    ensure_eq!(
        second,
        first,
        "the pull request from opening the same head twice"
    );
    let other = host
        .open_draft_pull_request(&scope, draft("factory/job-2")?)
        .await
        .ctx("a different head")?;
    ensure!(
        other != first,
        "a different head branch must give a different pull request"
    );
    Ok(())
}

async fn a_pull_request_from_a_head_outside_factory_is_refused(
    subject: &dyn ChangeHostSubject,
) -> Result<(), String> {
    ensure_err!(
        subject
            .host()
            .open_draft_pull_request(&scope(1, 1), draft("feature/mine")?)
            .await,
        GitHostError::BranchNotAllowed,
        "a pull request from a branch outside factory/"
    );
    Ok(())
}

async fn the_body_is_updated_only_if_its_tag_is_current(
    subject: &dyn ChangeHostSubject,
) -> Result<(), String> {
    let host = subject.host();
    let scope = scope(1, 1);
    let pr = host
        .open_draft_pull_request(&scope, draft("factory/job-1")?)
        .await
        .ctx("open")?;
    let first_tag = host
        .pull_request_state(&scope, &pr)
        .await
        .ctx("state")?
        .body_etag;
    host.update_pull_request_body(&scope, &pr, "Second body.", Some(&first_tag))
        .await
        .ctx("update with the current tag")?;
    let second_tag = host
        .pull_request_state(&scope, &pr)
        .await
        .ctx("state")?
        .body_etag;
    ensure!(
        second_tag != first_tag,
        "a changed body must have a new tag"
    );
    ensure_err!(
        host.update_pull_request_body(&scope, &pr, "Third body.", Some(&first_tag))
            .await,
        GitHostError::Conflict,
        "an update with a tag that is no longer current"
    );
    host.update_pull_request_body(&scope, &pr, "Fourth body.", None)
        .await
        .ctx("an update with no tag")?;
    Ok(())
}

async fn a_comment_is_posted_once_per_key(subject: &dyn ChangeHostSubject) -> Result<(), String> {
    let host = subject.host();
    let scope = scope(1, 1);
    let pr = host
        .open_draft_pull_request(&scope, draft("factory/job-1")?)
        .await
        .ctx("open")?;
    let target = CommentTarget::PullRequest(pr);
    let first = host
        .post_comment(&scope, &target, "Validation passed.", "validation-passed")
        .await
        .ctx("first post")?;
    let again = host
        .post_comment(&scope, &target, "Validation passed.", "validation-passed")
        .await
        .ctx("repeat post")?;
    ensure_eq!(again, first, "the comment from posting the same key twice");
    ensure_eq!(
        subject.comment_count(&target).await,
        1,
        "comments after posting one key twice"
    );
    let other = host
        .post_comment(&scope, &target, "Review passed.", "review-passed")
        .await
        .ctx("second key")?;
    ensure!(
        other != first,
        "a different key must give a different comment"
    );
    ensure_eq!(
        subject.comment_count(&target).await,
        2,
        "comments after two keys"
    );
    Ok(())
}

async fn text_with_a_secret_is_not_posted(subject: &dyn ChangeHostSubject) -> Result<(), String> {
    let host = subject.host();
    let scope = scope(1, 1);
    let pr = host
        .open_draft_pull_request(&scope, draft("factory/job-1")?)
        .await
        .ctx("open")?;
    let target = CommentTarget::PullRequest(pr.clone());
    let unsafe_text = format!("Debug output: {TOKEN_CANARY}");
    ensure_err!(
        host.post_comment(&scope, &target, &unsafe_text, "leak")
            .await,
        GitHostError::UnsafeText,
        "a comment that holds a token"
    );
    ensure_eq!(
        subject.comment_count(&target).await,
        0,
        "comments after the refused post"
    );
    ensure_err!(
        host.update_pull_request_body(&scope, &pr, &unsafe_text, None)
            .await,
        GitHostError::UnsafeText,
        "a body that holds a token"
    );
    let mut request = draft("factory/job-9")?;
    request.body = unsafe_text;
    ensure_err!(
        host.open_draft_pull_request(&scope, request).await,
        GitHostError::UnsafeText,
        "a pull request whose body holds a token"
    );
    Ok(())
}

async fn check(
    subject: &dyn ChangeHostSubject,
    external: &str,
    status: CheckStatus,
) -> Result<CheckRef, String> {
    let commit = subject
        .branch_tip(&repo(), &branch("factory/job-1")?)
        .await
        .ok_or("the branch factory/job-1 should exist on the remote")?;
    subject
        .host()
        .publish_check(
            &scope(1, 1),
            CheckRequest {
                commit,
                name: factory_domain::values::Slug::parse("factory-validation").ctx("name")?,
                external_id: factory_domain::values::Slug::parse(external).ctx("external id")?,
                status,
                title: "Validation".to_owned(),
                summary: "Every gate ran.".to_owned(),
                details_url: None,
            },
        )
        .await
        .ctx("publish a check")
}

async fn a_check_run_is_updated_not_duplicated(
    subject: &dyn ChangeHostSubject,
) -> Result<(), String> {
    let running = check(subject, "run-1", CheckStatus::InProgress).await?;
    let done = check(
        subject,
        "run-1",
        CheckStatus::Completed(CheckConclusion::Success),
    )
    .await?;
    ensure_eq!(
        done,
        running,
        "publishing the same (commit, name, external id) again"
    );
    let commit = subject
        .branch_tip(&repo(), &branch("factory/job-1")?)
        .await
        .ok_or("the branch should exist")?;
    ensure_eq!(
        subject.check_run_count(&commit, "factory-validation").await,
        1,
        "check runs for the name"
    );
    // Another run of the same stage is a second check run.
    let second = check(subject, "run-2", CheckStatus::InProgress).await?;
    ensure!(
        second != running,
        "a different external id makes a different check run"
    );
    Ok(())
}

async fn a_check_run_carries_the_apps_identity(
    subject: &dyn ChangeHostSubject,
) -> Result<(), String> {
    let made = check(subject, "run-1", CheckStatus::InProgress).await?;
    ensure_eq!(
        subject.check_run_app(&made).await,
        Some(subject.app_id()),
        "the App a check run was made as (only an App can make one)"
    );
    Ok(())
}

async fn a_pull_request_needs_a_pushed_head(subject: &dyn ChangeHostSubject) -> Result<(), String> {
    ensure_err!(
        subject
            .host()
            .open_draft_pull_request(&scope(1, 1), draft("factory/never-pushed")?)
            .await,
        GitHostError::Rejected(Rejection::HeadNotPushed),
        "a pull request from a branch that is not on the remote"
    );
    Ok(())
}

async fn a_closed_pull_request_is_not_reused(
    subject: &dyn ChangeHostSubject,
) -> Result<(), String> {
    let host = subject.host();
    let scope = scope(1, 1);
    let first = host
        .open_draft_pull_request(&scope, draft("factory/job-1")?)
        .await
        .ctx("open")?;
    subject.person_closes(&first).await;
    let second = host
        .open_draft_pull_request(&scope, draft("factory/job-1")?)
        .await
        .ctx("open again")?;
    ensure!(
        second != first,
        "a closed pull request must not be returned for a new open call"
    );
    let state = host
        .pull_request_state(&scope, &second)
        .await
        .ctx("state")?;
    ensure_eq!(
        state.lifecycle,
        PullRequestLifecycle::Open,
        "the new pull request is open"
    );
    Ok(())
}

async fn base_is_honoured(subject: &dyn ChangeHostSubject) -> Result<(), String> {
    let host = subject.host();
    let scope = scope(1, 1);
    let mut request = draft("factory/job-1")?;
    request.base = branch("factory/job-2")?;
    let pr = host
        .open_draft_pull_request(&scope, request)
        .await
        .ctx("open")?;
    let state = host.pull_request_state(&scope, &pr).await.ctx("state")?;
    ensure_eq!(
        state.base,
        branch("factory/job-2")?,
        "the base branch of the request"
    );
    let head = subject.branch_tip(&repo(), &branch("factory/job-1")?).await;
    ensure_eq!(
        Some(state.head_sha),
        head,
        "the head commit the host reports"
    );
    Ok(())
}

async fn a_comment_is_found_by_its_marker_before_posting(
    subject: &dyn ChangeHostSubject,
) -> Result<(), String> {
    let host = subject.host();
    let scope = scope(1, 1);
    let pr = host
        .open_draft_pull_request(&scope, draft("factory/job-1")?)
        .await
        .ctx("open")?;
    let target = CommentTarget::PullRequest(pr);
    let first = host
        .post_comment(&scope, &target, "Evidence attached.", "evidence-1")
        .await
        .ctx("post")?;
    // The first answer was lost; the retry carries the same key and finds the comment.
    let retry = host
        .post_comment(&scope, &target, "Evidence attached.", "evidence-1")
        .await
        .ctx("retry")?;
    ensure_eq!(retry, first, "the same key finds the same comment");
    let other = host
        .post_comment(&scope, &target, "Second note.", "evidence-2")
        .await
        .ctx("another key")?;
    ensure!(other != first, "a different key is a different comment");
    ensure_eq!(
        subject.comment_count(&target).await,
        2,
        "two keys, two comments"
    );
    Ok(())
}

async fn after_a_job_ends_its_calls_are_refused(
    subject: &dyn ChangeHostSubject,
) -> Result<(), String> {
    let host = subject.host();
    let ended = scope(1, 1);
    let running = scope(1, 2);
    let pr = host
        .open_draft_pull_request(&ended, draft("factory/job-1")?)
        .await
        .ctx("open")?;
    host.revoke_job_tokens(ended.job).await.ctx("revoke")?;
    host.revoke_job_tokens(ended.job)
        .await
        .ctx("a second revoke")?;

    let target = CommentTarget::PullRequest(pr.clone());
    ensure_err!(
        host.push_target(&ended, &branch("factory/job-1")?).await,
        GitHostError::Unauthorized,
        "push_target after the job's tokens were revoked"
    );
    ensure_err!(
        host.open_draft_pull_request(&ended, draft("factory/job-3")?)
            .await,
        GitHostError::Unauthorized,
        "open_draft_pull_request after the revoke"
    );
    ensure_err!(
        host.update_pull_request_body(&ended, &pr, "Late body.", None)
            .await,
        GitHostError::Unauthorized,
        "update_pull_request_body after the revoke"
    );
    ensure_err!(
        host.post_comment(&ended, &target, "Late comment.", "late")
            .await,
        GitHostError::Unauthorized,
        "post_comment after the revoke"
    );
    ensure_err!(
        host.pull_request_state(&ended, &pr).await,
        GitHostError::Unauthorized,
        "pull_request_state after the revoke"
    );
    // Another job of the same tenant is not affected.
    host.push_target(&running, &branch("factory/job-2")?)
        .await
        .ctx("a job whose tokens were not revoked")?;
    Ok(())
}

async fn another_tenant_cannot_reach_a_pull_request(
    subject: &dyn ChangeHostSubject,
) -> Result<(), String> {
    let host = subject.host();
    let owner = scope(1, 1);
    let stranger = scope(2, 7);
    let pr = host
        .open_draft_pull_request(&owner, draft("factory/job-1")?)
        .await
        .ctx("open")?;
    ensure_err!(
        host.pull_request_state(&stranger, &pr).await,
        GitHostError::NotFound,
        "reading another tenant's pull request"
    );
    ensure_err!(
        host.update_pull_request_body(&stranger, &pr, "Hijacked.", None)
            .await,
        GitHostError::NotFound,
        "changing another tenant's pull request"
    );
    ensure_err!(
        host.post_comment(
            &stranger,
            &CommentTarget::PullRequest(pr.clone()),
            "Hi.",
            "k"
        )
        .await,
        GitHostError::NotFound,
        "commenting on another tenant's pull request"
    );
    let state = host
        .pull_request_state(&owner, &pr)
        .await
        .ctx("the owner's read")?;
    ensure!(state.draft, "the owner's pull request is untouched");
    Ok(())
}

async fn a_scope_for_another_repository_cannot_reach_a_pull_request(
    subject: &dyn ChangeHostSubject,
) -> Result<(), String> {
    let host = subject.host();
    let owner = scope(1, 1);
    let pr = host
        .open_draft_pull_request(&owner, draft("factory/job-1")?)
        .await
        .ctx("open")?;
    let mut elsewhere = scope(1, 2);
    elsewhere.repo = RepoRef::parse("example-org/other").ctx("repo")?;
    ensure_err!(
        host.pull_request_state(&elsewhere, &pr).await,
        GitHostError::NotFound,
        "reading a pull request through a token for another repository"
    );
    Ok(())
}

async fn a_pull_request_merged_by_a_person_reads_as_merged(
    subject: &dyn ChangeHostSubject,
) -> Result<(), String> {
    let host = subject.host();
    let scope = scope(1, 1);
    let pr = host
        .open_draft_pull_request(&scope, draft("factory/job-1")?)
        .await
        .ctx("open")?;
    subject.person_merges(&pr).await;
    let state = host.pull_request_state(&scope, &pr).await.ctx("state")?;
    ensure_eq!(
        state.lifecycle,
        PullRequestLifecycle::Merged,
        "the lifecycle after a person merged"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// IssueSource

/// What the suite needs beyond the `IssueSource` port itself.
#[async_trait]
pub trait IssueSourceSubject: Send + Sync {
    /// The issue source under test.
    fn source(&self) -> &dyn IssueSource;

    /// Puts an issue on the code host.
    async fn seed_issue(&self, issue: Issue);

    /// Changes the title of an issue on the code host.
    async fn edit_issue_title(&self, issue: &IssueRef, title: &str);

    /// Records that `actor` applied `label` to the issue.
    async fn seed_label(&self, issue: &IssueRef, label: &str, actor: &GithubActor);

    /// Puts a comment on the code host.
    async fn seed_comment(&self, comment: Comment);

    /// The permissions the source asked the code host for so far.
    async fn permissions_asked(&self) -> Vec<String>;

    /// Sets what the repository's protection looks like.
    async fn seed_protection(&self, repo: &RepoRef, report: ProtectionReport);
}

/// A check of the issue source contract.
pub type IssueSourceCheck = Check<dyn IssueSourceSubject>;

/// Runs the whole issue source suite. `make` builds a fresh subject for every check.
pub async fn run_issue_source<S, F, Fut>(make: F) -> Report
where
    S: IssueSourceSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&issue_source_checks(), || async {
        Box::new(make().await) as Box<dyn IssueSourceSubject>
    })
    .await
}

/// Every check of the issue source contract.
#[must_use]
pub fn issue_source_checks() -> Vec<IssueSourceCheck> {
    check_list![dyn IssueSourceSubject;
        an_issue_is_fetched_live,
        an_unknown_issue_is_not_found,
        the_label_actor_is_the_person_who_applied_it,
        protection_is_reported_as_the_repository_has_it,
        a_scope_for_another_repository_cannot_read_an_issue,
        fetch_comment_returns_the_numeric_author_id,
        repository_protection_never_asks_for_administration,
    ]
}

/// No waivers: every check has a defect.
pub const ISSUE_SOURCE_WAIVERS: &[Waiver] = &[];

fn actor(id: u64, login: &str) -> Result<GithubActor, String> {
    Ok(GithubActor {
        id,
        login: ActorLogin::new(login).ctx("login")?,
    })
}

fn issue_ref(number: u64) -> IssueRef {
    IssueRef {
        repo: repo(),
        number,
    }
}

fn issue(number: u64, title: &str) -> Result<Issue, String> {
    Ok(Issue {
        reference: issue_ref(number),
        title: title.to_owned(),
        body: "Please add a word count command.".to_owned(),
        author: actor(1, "octocat")?,
        labels: vec!["factory".to_owned()],
        updated_at: Timestamp::parse("2026-10-27T08:00:00Z").ctx("timestamp")?,
        fetched_at: Timestamp::parse("2026-10-27T08:30:00Z").ctx("timestamp")?,
    })
}

async fn an_issue_is_fetched_live(subject: &dyn IssueSourceSubject) -> Result<(), String> {
    subject.seed_issue(issue(12, "Add word count")?).await;
    let scope = scope(1, 1);
    let first = subject
        .source()
        .fetch_issue(&scope, &issue_ref(12))
        .await
        .ctx("first fetch")?;
    ensure_eq!(first.reference.clone(), issue_ref(12), "the issue fetched");
    ensure_eq!(
        first.title.clone(),
        "Add word count".to_owned(),
        "the title"
    );
    ensure_eq!(
        first.labels.clone(),
        vec!["factory".to_owned()],
        "the labels"
    );
    subject
        .edit_issue_title(&issue_ref(12), "Add word count, edited")
        .await;
    let second = subject
        .source()
        .fetch_issue(&scope, &issue_ref(12))
        .await
        .ctx("second fetch")?;
    ensure_eq!(
        second.title.clone(),
        "Add word count, edited".to_owned(),
        "the title on a second fetch (a fetch is always live, never cached)"
    );
    Ok(())
}

async fn an_unknown_issue_is_not_found(subject: &dyn IssueSourceSubject) -> Result<(), String> {
    ensure_err!(
        subject
            .source()
            .fetch_issue(&scope(1, 1), &issue_ref(404))
            .await,
        GitHostError::NotFound,
        "an issue that does not exist"
    );
    Ok(())
}

async fn the_label_actor_is_the_person_who_applied_it(
    subject: &dyn IssueSourceSubject,
) -> Result<(), String> {
    subject.seed_issue(issue(12, "Add word count")?).await;
    let actor = actor(77, "maintainer")?;
    subject
        .seed_label(&issue_ref(12), "factory:run", &actor)
        .await;
    let scope = scope(1, 1);
    ensure_eq!(
        subject
            .source()
            .label_actor(&scope, &issue_ref(12), "factory:run")
            .await
            .ctx("label_actor")?,
        Some(actor.clone()),
        "who applied the label"
    );
    ensure_eq!(
        subject
            .source()
            .label_actor(&scope, &issue_ref(12), "no-such-label")
            .await
            .ctx("label_actor")?,
        None,
        "who applied a label that is not on the issue"
    );
    // The application says the same person, with or without a time, and says nothing for a label
    // that is not there.
    let application = subject
        .source()
        .label_application(&scope, &issue_ref(12), "factory:run")
        .await
        .ctx("label_application")?;
    ensure_eq!(
        application.map(|found| found.actor),
        Some(actor),
        "who applied the label, with the time"
    );
    ensure_eq!(
        subject
            .source()
            .label_application(&scope, &issue_ref(12), "no-such-label")
            .await
            .ctx("label_application")?,
        None,
        "the application of a label that is not on the issue"
    );
    Ok(())
}

fn report(strong: bool) -> Result<ProtectionReport, String> {
    Ok(ProtectionReport {
        default_branch: branch("main")?,
        source: if strong {
            ProtectionSource::Rulesets
        } else {
            ProtectionSource::NoRulesetRules
        },
        requires_pull_request: strong,
        requires_code_owner_review: strong,
        dismisses_stale_approvals: strong,
        blocks_force_push: strong,
        blocks_deletion: strong,
        required_checks: if strong {
            vec![RequiredCheck {
                context: "factory-validation".to_owned(),
                integration_id: Some(4242),
            }]
        } else {
            Vec::new()
        },
    })
}

async fn protection_is_reported_as_the_repository_has_it(
    subject: &dyn IssueSourceSubject,
) -> Result<(), String> {
    let scope = scope(1, 1);
    subject.seed_protection(&repo(), report(true)?).await;
    let found = subject
        .source()
        .repository_protection(&scope)
        .await
        .ctx("strong")?;
    ensure_eq!(
        found,
        report(true)?,
        "the protection of a well protected repository"
    );
    subject.seed_protection(&repo(), report(false)?).await;
    let found = subject
        .source()
        .repository_protection(&scope)
        .await
        .ctx("weak")?;
    ensure_eq!(
        found.clone(),
        report(false)?,
        "the protection of a repository with no ruleset rules"
    );
    ensure_eq!(
        found.source,
        ProtectionSource::NoRulesetRules,
        "where the rules came from"
    );
    ensure!(
        !found.requires_pull_request,
        "a repository with no rules does not require a pull request"
    );
    Ok(())
}

async fn fetch_comment_returns_the_numeric_author_id(
    subject: &dyn IssueSourceSubject,
) -> Result<(), String> {
    let reference = CommentRef {
        target: CommentTarget::Issue(issue_ref(12)),
        id: 501,
    };
    subject
        .seed_comment(Comment {
            reference: reference.clone(),
            author: actor(4242, "maintainer")?,
            body: "factory approve".to_owned(),
            created_at: Timestamp::parse("2026-10-27T08:30:00Z").ctx("timestamp")?,
            edited_at: None,
        })
        .await;
    let found = subject
        .source()
        .fetch_comment(&scope(1, 1), &reference)
        .await
        .ctx("fetch the comment")?;
    ensure_eq!(found.author.id, 4242, "the numeric id of the author");
    ensure_err!(
        subject
            .source()
            .fetch_comment(
                &scope(1, 1),
                &CommentRef {
                    target: CommentTarget::Issue(issue_ref(12)),
                    id: 999
                }
            )
            .await,
        GitHostError::NotFound,
        "a comment that does not exist"
    );
    Ok(())
}

async fn repository_protection_never_asks_for_administration(
    subject: &dyn IssueSourceSubject,
) -> Result<(), String> {
    subject.seed_protection(&repo(), report(true)?).await;
    subject
        .source()
        .repository_protection(&scope(1, 1))
        .await
        .ctx("read the protection")?;
    let asked = subject.permissions_asked().await;
    ensure!(
        !asked.is_empty(),
        "the source should say which permissions it used"
    );
    ensure!(
        !asked
            .iter()
            .any(|permission| permission.to_lowercase().contains("administration")),
        "the App must never hold the Administration permission, but {asked:?} were asked for"
    );
    Ok(())
}

async fn a_scope_for_another_repository_cannot_read_an_issue(
    subject: &dyn IssueSourceSubject,
) -> Result<(), String> {
    subject.seed_issue(issue(12, "Add word count")?).await;
    let mut elsewhere = scope(1, 1);
    elsewhere.repo = RepoRef::parse("example-org/other").ctx("repo")?;
    ensure_err!(
        subject
            .source()
            .fetch_issue(&elsewhere, &issue_ref(12))
            .await,
        GitHostError::NotFound,
        "an issue of one repository read through a token for another"
    );
    Ok(())
}
