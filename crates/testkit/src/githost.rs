//! A code host kept in memory: `FakeChangeHost` and `FakeIssueSource` (ports-v1.1).
//!
//! The change host opens only draft pull requests, from branches under `factory/` that are on the
//! remote, once per open head branch. It has no way to merge and none to mark a pull request
//! ready, as the port has none: a test plays the person who merges or closes with
//! [`FakeChangeHost::mark_merged_by_person`] and [`FakeChangeHost::mark_closed_by_person`]. Gate
//! results are check runs, one per `(commit, name, external_id)`, made as the factory's App. It
//! checks text for token-shaped secrets before posting, applies the body tag check, keeps tenants
//! and repositories apart, and refuses every call for a job whose tokens were revoked.
//!
//! The change host shares a [`FakeRemote`] with the fake workspace provider, so a push through the
//! workspace makes the head branch exist for the pull request.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::Fidelity;
use factory_ports::githost::{
    ActorLogin, AppId, ChangeHost, CheckRef, CheckRequest, Comment, CommentRef, CommentTarget,
    DraftPrRequest, GitHostError, GitScope, GithubActor, Issue, IssueRef, IssueSource,
    LabelApplication, ProtectionReport, ProtectionSource, PullRequestLifecycle, PullRequestRef,
    PullRequestState, Rejection, RequiredCheck,
};
use factory_ports::paths::{BranchName, CommitSha, RepoRef};
use factory_ports::workspace::{FetchCredential, FetchTarget, PushCredential, PushTarget};

use crate::contracts::githost::{ChangeHostSubject, IssueSourceSubject};
use crate::workspace::FakeRemote;

/// The id of the App the fake publishes check runs as.
pub const FAKE_APP_ID: AppId = AppId(4242);

/// A deliberate fault, for proving that the contract suite can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeHostDefect {
    /// Any branch is accepted, for a push target and for a pull request head.
    AcceptsAnyBranch,
    /// A second call for the same head opens a second pull request.
    DuplicatePullRequests,
    /// Pull requests are opened ready for review, not as drafts.
    OpensReadyForReview,
    /// The body tag is not compared.
    IgnoresBodyTag,
    /// A comment key does not make a comment unique.
    DuplicateComments,
    /// Text is not checked for secrets.
    SkipsSecretCheck,
    /// `revoke_job_tokens` does nothing.
    RevokeDoesNothing,
    /// A pull request can be reached from any tenant.
    SharesAcrossTenants,
    /// A pull request opens although the head branch is not on the remote.
    OpensForUnpushedHead,
    /// An open call for a head whose pull request was closed returns the closed one.
    ReusesClosed,
    /// A second publish of a check makes a second check run.
    DuplicatesChecks,
    /// A check run is recorded as made by another App.
    ForgesAppIdentity,
    /// The base branch of the request is ignored.
    IgnoresBase,
    /// One comment is kept for every key of a target.
    OneCommentForAllKeys,
    /// A pull request a person merged reads as open.
    MergedReadsAsOpen,
}

/// Each defect and the checks of `contracts::githost` (change host) that must fail with it.
pub const CHANGE_HOST_DEFECTS: &[(ChangeHostDefect, &[&str])] = &[
    (
        ChangeHostDefect::AcceptsAnyBranch,
        &[
            "push_targets_are_for_factory_branches_only",
            "a_pull_request_from_a_head_outside_factory_is_refused",
        ],
    ),
    (
        ChangeHostDefect::DuplicatePullRequests,
        &["opening_for_the_same_head_twice_returns_the_same_pull_request"],
    ),
    (
        ChangeHostDefect::OpensReadyForReview,
        &["a_pull_request_is_opened_as_a_draft_and_stays_open"],
    ),
    (
        ChangeHostDefect::IgnoresBodyTag,
        &["the_body_is_updated_only_if_its_tag_is_current"],
    ),
    (
        ChangeHostDefect::DuplicateComments,
        &[
            "a_comment_is_posted_once_per_key",
            "a_comment_is_found_by_its_marker_before_posting",
        ],
    ),
    (
        ChangeHostDefect::SkipsSecretCheck,
        &["text_with_a_secret_is_not_posted"],
    ),
    (
        ChangeHostDefect::RevokeDoesNothing,
        &["after_a_job_ends_its_calls_are_refused"],
    ),
    (
        ChangeHostDefect::SharesAcrossTenants,
        &[
            "another_tenant_cannot_reach_a_pull_request",
            "a_scope_for_another_repository_cannot_reach_a_pull_request",
        ],
    ),
    (
        ChangeHostDefect::OpensForUnpushedHead,
        &["a_pull_request_needs_a_pushed_head"],
    ),
    (
        ChangeHostDefect::ReusesClosed,
        &["a_closed_pull_request_is_not_reused"],
    ),
    (
        ChangeHostDefect::MergedReadsAsOpen,
        &["a_pull_request_merged_by_a_person_reads_as_merged"],
    ),
    (
        ChangeHostDefect::DuplicatesChecks,
        &["a_check_run_is_updated_not_duplicated"],
    ),
    (
        ChangeHostDefect::ForgesAppIdentity,
        &["a_check_run_carries_the_apps_identity"],
    ),
    (ChangeHostDefect::IgnoresBase, &["base_is_honoured"]),
    (
        ChangeHostDefect::OneCommentForAllKeys,
        &["a_comment_is_found_by_its_marker_before_posting"],
    ),
];

/// True when `text` holds something that looks like a GitHub installation token, an Anthropic key
/// or a private key. The same shapes as the canary generator (FX-CANARY).
#[must_use]
pub fn looks_like_a_secret(text: &str) -> bool {
    let token = |prefix: &str, min: usize, allowed: fn(char) -> bool| {
        text.match_indices(prefix).any(|(at, _)| {
            text[at + prefix.len()..]
                .chars()
                .take_while(|c| allowed(*c))
                .count()
                >= min
        })
    };
    token("ghs_", 36, |c| c.is_ascii_alphanumeric())
        || token("sk-ant-", 20, |c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_'
        })
        || (text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----"))
}

struct PullRecord {
    tenant: TenantId,
    head: BranchName,
    base: BranchName,
    head_sha: CommitSha,
    body: String,
    revision: u64,
    lifecycle: PullRequestLifecycle,
    draft: bool,
}

#[derive(Default)]
struct HostState {
    revoked: BTreeSet<JobId>,
    pulls: BTreeMap<PullRequestRef, PullRecord>,
    heads: BTreeMap<(RepoRef, BranchName), PullRequestRef>,
    next_pull: u64,
    comments: BTreeMap<(CommentTarget, String), CommentRef>,
    next_comment: u64,
    checks: BTreeMap<(String, String, String, u64), (CheckRef, AppId)>,
    next_check: u64,
}

/// An in-memory change host. Reports fidelity `fake`.
pub struct FakeChangeHost {
    state: Mutex<HostState>,
    remote: FakeRemote,
    defect: Option<ChangeHostDefect>,
}

impl FakeChangeHost {
    /// A faithful fake over its own remote, on which the branches `factory/job-1`, `factory/job-2`
    /// and `factory/job-3` of the suite's repository already exist.
    #[must_use]
    pub fn new() -> Self {
        Self::over(Self::seeded_remote(), None)
    }

    /// A fake that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(defect: ChangeHostDefect) -> Self {
        Self::over(Self::seeded_remote(), Some(defect))
    }

    /// A fake over a remote it shares with a workspace provider.
    #[must_use]
    pub fn sharing(remote: FakeRemote) -> Self {
        Self::over(remote, None)
    }

    fn over(remote: FakeRemote, defect: Option<ChangeHostDefect>) -> Self {
        Self {
            state: Mutex::new(HostState::default()),
            remote,
            defect,
        }
    }

    fn seeded_remote() -> FakeRemote {
        let remote = FakeRemote::new();
        let repo = crate::contracts::githost::repo();
        for name in ["main", "factory/job-1", "factory/job-2", "factory/job-3"] {
            let branch = BranchName::new(name).expect("a valid branch");
            remote.commit_on_branch(&repo, &branch, &[("README.md", name)]);
        }
        remote
    }

    /// The remote the host reads, which a workspace provider may share.
    #[must_use]
    pub fn remote(&self) -> FakeRemote {
        self.remote.clone()
    }

    /// Plays a person merging the pull request on the code host. The factory has no such call.
    pub fn mark_merged_by_person(&self, pr: &PullRequestRef) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        if let Some(record) = state.pulls.get_mut(pr) {
            record.lifecycle = PullRequestLifecycle::Merged;
        }
    }

    /// Plays a person closing the pull request without merging it.
    pub fn mark_closed_by_person(&self, pr: &PullRequestRef) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        if let Some(record) = state.pulls.get_mut(pr) {
            record.lifecycle = PullRequestLifecycle::Closed;
        }
    }

    /// How many comments the target holds.
    #[must_use]
    pub fn comment_count(&self, target: &CommentTarget) -> usize {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .comments
            .keys()
            .filter(|(held, _)| held == target)
            .count()
    }

    /// How many check runs exist for the commit and name.
    #[must_use]
    pub fn check_run_count(&self, commit: &CommitSha, name: &str) -> usize {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .checks
            .keys()
            .filter(|(sha, held, _, _)| sha == commit.as_str() && held == name)
            .count()
    }

    /// The App a check run was made as.
    #[must_use]
    pub fn check_run_app(&self, check: &CheckRef) -> Option<AppId> {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .checks
            .values()
            .find(|(held, _)| held == check)
            .map(|(_, app)| *app)
    }

    fn has(&self, defect: ChangeHostDefect) -> bool {
        self.defect == Some(defect)
    }

    fn live(&self, state: &HostState, scope: &GitScope) -> Result<(), GitHostError> {
        if state.revoked.contains(&scope.job) && !self.has(ChangeHostDefect::RevokeDoesNothing) {
            Err(GitHostError::Unauthorized)
        } else {
            Ok(())
        }
    }

    fn branch_ok(&self, branch: &BranchName) -> bool {
        branch.is_factory_branch() || self.has(ChangeHostDefect::AcceptsAnyBranch)
    }

    fn text_ok(&self, text: &str) -> bool {
        self.has(ChangeHostDefect::SkipsSecretCheck) || !looks_like_a_secret(text)
    }

    /// The pull request, if the scope may see it.
    fn pull<'a>(
        &self,
        state: &'a mut HostState,
        scope: &GitScope,
        pr: &PullRequestRef,
    ) -> Result<&'a mut PullRecord, GitHostError> {
        let shared = self.has(ChangeHostDefect::SharesAcrossTenants);
        if pr.repo != scope.repo && !shared {
            return Err(GitHostError::NotFound);
        }
        match state.pulls.get_mut(pr) {
            Some(record) if record.tenant == scope.tenant || shared => Ok(record),
            _ => Err(GitHostError::NotFound),
        }
    }
}

impl Default for FakeChangeHost {
    fn default() -> Self {
        Self::new()
    }
}

fn etag(revision: u64) -> String {
    format!("\"rev-{revision}\"")
}

/// The marker a comment carries so that a repeated post finds it.
fn marker(key: &str) -> String {
    format!("<!-- factory-key:{key} -->")
}

#[async_trait]
impl ChangeHost for FakeChangeHost {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn fetch_target(&self, scope: &GitScope) -> Result<FetchTarget, GitHostError> {
        let state = self.state.lock().expect("the lock is never poisoned");
        self.live(&state, scope)?;
        Ok(FetchTarget {
            repo: scope.repo.clone(),
            credential: FetchCredential::new(format!("fake-read-credential-{}", scope.job)),
        })
    }

    async fn push_target(
        &self,
        scope: &GitScope,
        branch: &BranchName,
    ) -> Result<PushTarget, GitHostError> {
        let state = self.state.lock().expect("the lock is never poisoned");
        self.live(&state, scope)?;
        if !self.branch_ok(branch) {
            return Err(GitHostError::BranchNotAllowed);
        }
        Ok(PushTarget {
            repo: scope.repo.clone(),
            branch: branch.clone(),
            credential: PushCredential::new(format!("fake-push-credential-{}", scope.job)),
        })
    }

    async fn resolve_branch(
        &self,
        scope: &GitScope,
        branch: &BranchName,
    ) -> Result<CommitSha, GitHostError> {
        let state = self.state.lock().expect("the lock is never poisoned");
        self.live(&state, scope)?;
        self.remote
            .branch_tip(&scope.repo, branch)
            .ok_or(GitHostError::NotFound)
    }

    async fn open_draft_pull_request(
        &self,
        scope: &GitScope,
        req: DraftPrRequest,
    ) -> Result<PullRequestRef, GitHostError> {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        self.live(&state, scope)?;
        if !self.branch_ok(&req.head) {
            return Err(GitHostError::BranchNotAllowed);
        }
        if !self.text_ok(&req.body) || !self.text_ok(&req.title) {
            return Err(GitHostError::UnsafeText);
        }
        let tip = self.remote.branch_tip(&scope.repo, &req.head);
        if tip.is_none() && !self.has(ChangeHostDefect::OpensForUnpushedHead) {
            return Err(GitHostError::Rejected(Rejection::HeadNotPushed));
        }
        if req.head == req.base {
            return Err(GitHostError::Rejected(Rejection::HeadIsBase));
        }
        let key = (scope.repo.clone(), req.head.clone());
        if !self.has(ChangeHostDefect::DuplicatePullRequests)
            && let Some(existing) = state.heads.get(&key).cloned()
        {
            let still_open = state
                .pulls
                .get(&existing)
                .is_some_and(|record| record.lifecycle == PullRequestLifecycle::Open);
            if still_open || self.has(ChangeHostDefect::ReusesClosed) {
                return Ok(existing);
            }
        }
        state.next_pull += 1;
        let pr = PullRequestRef {
            repo: scope.repo.clone(),
            number: state.next_pull,
        };
        let head_sha = tip.unwrap_or_else(|| CommitSha::parse(&"0".repeat(40)).expect("a sha"));
        let base = if self.has(ChangeHostDefect::IgnoresBase) {
            BranchName::new("main").expect("a branch")
        } else {
            req.base
        };
        state.pulls.insert(
            pr.clone(),
            PullRecord {
                tenant: scope.tenant,
                head: req.head,
                base,
                head_sha,
                body: req.body,
                revision: 1,
                lifecycle: PullRequestLifecycle::Open,
                draft: !self.has(ChangeHostDefect::OpensReadyForReview),
            },
        );
        state.heads.insert(key, pr.clone());
        Ok(pr)
    }

    async fn update_pull_request_body(
        &self,
        scope: &GitScope,
        pr: &PullRequestRef,
        body: &str,
        etag_precondition: Option<&str>,
    ) -> Result<(), GitHostError> {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        self.live(&state, scope)?;
        let record = self.pull(&mut state, scope, pr)?;
        if !self.text_ok(body) {
            return Err(GitHostError::UnsafeText);
        }
        if let Some(wanted) = etag_precondition
            && wanted != etag(record.revision)
            && !self.has(ChangeHostDefect::IgnoresBodyTag)
        {
            return Err(GitHostError::Conflict);
        }
        body.clone_into(&mut record.body);
        record.revision += 1;
        Ok(())
    }

    async fn post_comment(
        &self,
        scope: &GitScope,
        target: &CommentTarget,
        body: &str,
        idempotency_key: &str,
    ) -> Result<CommentRef, GitHostError> {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        self.live(&state, scope)?;
        match target {
            CommentTarget::PullRequest(pr) => {
                self.pull(&mut state, scope, pr)?;
            }
            CommentTarget::Issue(issue) => {
                if issue.repo != scope.repo {
                    return Err(GitHostError::NotFound);
                }
            }
        }
        if !self.text_ok(body) {
            return Err(GitHostError::UnsafeText);
        }
        // The adapter finds its marker before posting: the same key finds the same comment.
        let lookup = if self.has(ChangeHostDefect::OneCommentForAllKeys) {
            "all".to_owned()
        } else {
            marker(idempotency_key)
        };
        let key = (target.clone(), lookup);
        if !self.has(ChangeHostDefect::DuplicateComments)
            && let Some(existing) = state.comments.get(&key)
        {
            return Ok(existing.clone());
        }
        state.next_comment += 1;
        let comment = CommentRef {
            target: target.clone(),
            id: state.next_comment,
        };
        // With the duplicate defect the key is made unique, so every call keeps its own comment.
        let stored_key = if self.has(ChangeHostDefect::DuplicateComments) {
            (target.clone(), format!("{}#{}", key.1, comment.id))
        } else {
            key
        };
        state.comments.insert(stored_key, comment.clone());
        Ok(comment)
    }

    async fn publish_check(
        &self,
        scope: &GitScope,
        req: CheckRequest,
    ) -> Result<CheckRef, GitHostError> {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        self.live(&state, scope)?;
        if !self.text_ok(&req.summary) || !self.text_ok(&req.title) {
            return Err(GitHostError::UnsafeText);
        }
        let duplicate_suffix = if self.has(ChangeHostDefect::DuplicatesChecks) {
            state.next_check + 1
        } else {
            0
        };
        let key = (
            req.commit.as_str().to_owned(),
            req.name.as_str().to_owned(),
            req.external_id.as_str().to_owned(),
            duplicate_suffix,
        );
        if let Some((existing, _)) = state.checks.get(&key) {
            return Ok(*existing);
        }
        state.next_check += 1;
        let check = CheckRef {
            id: state.next_check,
        };
        let app = if self.has(ChangeHostDefect::ForgesAppIdentity) {
            AppId(1)
        } else {
            FAKE_APP_ID
        };
        state.checks.insert(key, (check, app));
        Ok(check)
    }

    async fn pull_request_state(
        &self,
        scope: &GitScope,
        pr: &PullRequestRef,
    ) -> Result<PullRequestState, GitHostError> {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        self.live(&state, scope)?;
        let record = self.pull(&mut state, scope, pr)?;
        Ok(PullRequestState {
            lifecycle: if self.has(ChangeHostDefect::MergedReadsAsOpen) {
                PullRequestLifecycle::Open
            } else {
                record.lifecycle
            },
            draft: record.draft,
            head: record.head.clone(),
            head_sha: record.head_sha.clone(),
            base: record.base.clone(),
            body_etag: etag(record.revision),
        })
    }

    async fn revoke_job_tokens(&self, job: JobId) -> Result<(), GitHostError> {
        if !self.has(ChangeHostDefect::RevokeDoesNothing) {
            self.state
                .lock()
                .expect("the lock is never poisoned")
                .revoked
                .insert(job);
        }
        Ok(())
    }
}

#[async_trait]
impl ChangeHostSubject for FakeChangeHost {
    fn host(&self) -> &dyn ChangeHost {
        self
    }

    fn app_id(&self) -> AppId {
        FAKE_APP_ID
    }

    async fn comment_count(&self, target: &CommentTarget) -> usize {
        FakeChangeHost::comment_count(self, target)
    }

    async fn check_run_count(&self, commit: &CommitSha, name: &str) -> usize {
        FakeChangeHost::check_run_count(self, commit, name)
    }

    async fn check_run_app(&self, check: &CheckRef) -> Option<AppId> {
        FakeChangeHost::check_run_app(self, check)
    }

    async fn person_merges(&self, pr: &PullRequestRef) {
        self.mark_merged_by_person(pr);
    }

    async fn person_closes(&self, pr: &PullRequestRef) {
        self.mark_closed_by_person(pr);
    }

    async fn branch_tip(&self, repo: &RepoRef, branch: &BranchName) -> Option<CommitSha> {
        self.remote.branch_tip(repo, branch)
    }
}

/// A deliberate fault in the issue source, for proving that the contract suite can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueSourceDefect {
    /// The first fetch of an issue is remembered and returned for ever.
    CachesIssues,
    /// Any label is reported as applied by the first person who ever applied one.
    GuessesLabelActor,
    /// Every repository is reported as fully protected.
    AlwaysProtected,
    /// An issue can be read through a scope for any repository.
    IgnoresRepositoryScope,
    /// A fetched comment names its author by a number that is not the author's id.
    ForgesAuthorId,
    /// `repository_protection` asks for the Administration permission.
    AsksForAdministration,
    /// An issue that does not exist is invented.
    InventsUnknownIssue,
}

/// Each defect and the checks of `contracts::githost` (issue source) that must fail with it.
pub const ISSUE_SOURCE_DEFECTS: &[(IssueSourceDefect, &[&str])] = &[
    (
        IssueSourceDefect::CachesIssues,
        &["an_issue_is_fetched_live"],
    ),
    (
        IssueSourceDefect::GuessesLabelActor,
        &["the_label_actor_is_the_person_who_applied_it"],
    ),
    (
        IssueSourceDefect::AlwaysProtected,
        &["protection_is_reported_as_the_repository_has_it"],
    ),
    (
        IssueSourceDefect::IgnoresRepositoryScope,
        &["a_scope_for_another_repository_cannot_read_an_issue"],
    ),
    (
        IssueSourceDefect::ForgesAuthorId,
        &["fetch_comment_returns_the_numeric_author_id"],
    ),
    (
        IssueSourceDefect::InventsUnknownIssue,
        &["an_unknown_issue_is_not_found"],
    ),
    (
        IssueSourceDefect::AsksForAdministration,
        &["repository_protection_never_asks_for_administration"],
    ),
];

#[derive(Default)]
struct IssueState {
    issues: BTreeMap<IssueRef, Issue>,
    cache: BTreeMap<IssueRef, Issue>,
    labels: BTreeMap<(IssueRef, String), GithubActor>,
    label_times: BTreeMap<(IssueRef, String), Timestamp>,
    comments: BTreeMap<CommentRef, Comment>,
    protection: BTreeMap<RepoRef, ProtectionReport>,
    permissions_asked: Vec<String>,
}

/// An in-memory issue source. Reports fidelity `fake`.
pub struct FakeIssueSource {
    state: Mutex<IssueState>,
    defect: Option<IssueSourceDefect>,
}

impl FakeIssueSource {
    /// A faithful fake.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(IssueState::default()),
            defect: None,
        }
    }

    /// A fake that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(defect: IssueSourceDefect) -> Self {
        Self {
            defect: Some(defect),
            ..Self::new()
        }
    }

    /// Puts an issue on the fake host.
    pub fn put_issue(&self, issue: Issue) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        state.issues.insert(issue.reference.clone(), issue);
    }

    /// Records that `actor` applied `label` to the issue at `at`. `seed_label` records the same
    /// with no time, as a source that keeps no timeline would.
    pub fn seed_label_at(&self, issue: &IssueRef, label: &str, actor: &GithubActor, at: Timestamp) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        let key = (issue.clone(), label.to_owned());
        state.labels.insert(key.clone(), actor.clone());
        state.label_times.insert(key, at);
    }

    fn has(&self, defect: IssueSourceDefect) -> bool {
        self.defect == Some(defect)
    }

    fn in_scope(&self, scope: &GitScope, repo: &RepoRef) -> Result<(), GitHostError> {
        if scope.repo == *repo || self.has(IssueSourceDefect::IgnoresRepositoryScope) {
            Ok(())
        } else {
            Err(GitHostError::NotFound)
        }
    }
}

impl Default for FakeIssueSource {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IssueSource for FakeIssueSource {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn fetch_issue(&self, scope: &GitScope, issue: &IssueRef) -> Result<Issue, GitHostError> {
        self.in_scope(scope, &issue.repo)?;
        let mut state = self.state.lock().expect("the lock is never poisoned");
        if self.has(IssueSourceDefect::CachesIssues)
            && let Some(cached) = state.cache.get(issue)
        {
            return Ok(cached.clone());
        }
        if self.has(IssueSourceDefect::InventsUnknownIssue) && !state.issues.contains_key(issue) {
            return Ok(Issue {
                reference: issue.clone(),
                title: "invented".to_owned(),
                body: String::new(),
                author: GithubActor {
                    id: 0,
                    login: ActorLogin::new("nobody").expect("a login"),
                },
                labels: Vec::new(),
                updated_at: Timestamp::parse("2026-01-01T00:00:00Z").expect("a time"),
                fetched_at: Timestamp::parse("2026-01-01T00:00:00Z").expect("a time"),
            });
        }
        let live = state
            .issues
            .get(issue)
            .cloned()
            .ok_or(GitHostError::NotFound)?;
        state.cache.insert(issue.clone(), live.clone());
        Ok(live)
    }

    async fn fetch_comment(
        &self,
        scope: &GitScope,
        comment: &CommentRef,
    ) -> Result<Comment, GitHostError> {
        let repo = match &comment.target {
            CommentTarget::PullRequest(pr) => pr.repo.clone(),
            CommentTarget::Issue(issue) => issue.repo.clone(),
        };
        self.in_scope(scope, &repo)?;
        let state = self.state.lock().expect("the lock is never poisoned");
        let mut found = state
            .comments
            .get(comment)
            .cloned()
            .ok_or(GitHostError::NotFound)?;
        if self.has(IssueSourceDefect::ForgesAuthorId) {
            found.author.id += 1;
        }
        Ok(found)
    }

    async fn label_actor(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
        label: &str,
    ) -> Result<Option<GithubActor>, GitHostError> {
        self.in_scope(scope, &issue.repo)?;
        let state = self.state.lock().expect("the lock is never poisoned");
        if self.has(IssueSourceDefect::GuessesLabelActor) {
            return Ok(state.labels.values().next().cloned());
        }
        Ok(state
            .labels
            .get(&(issue.clone(), label.to_owned()))
            .cloned())
    }

    async fn label_application(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
        label: &str,
    ) -> Result<Option<LabelApplication>, GitHostError> {
        self.in_scope(scope, &issue.repo)?;
        let state = self.state.lock().expect("the lock is never poisoned");
        let key = (issue.clone(), label.to_owned());
        let found = if self.has(IssueSourceDefect::GuessesLabelActor) {
            state.labels.iter().next()
        } else {
            state.labels.get_key_value(&key)
        };
        Ok(found.map(|(held, actor)| LabelApplication {
            actor: actor.clone(),
            applied_at: state.label_times.get(held).copied(),
        }))
    }

    async fn repository_protection(
        &self,
        scope: &GitScope,
    ) -> Result<ProtectionReport, GitHostError> {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        state.permissions_asked.push("metadata".to_owned());
        if self.has(IssueSourceDefect::AsksForAdministration) {
            state.permissions_asked.push("administration".to_owned());
        }
        if self.has(IssueSourceDefect::AlwaysProtected) {
            return Ok(strong_protection());
        }
        state
            .protection
            .get(&scope.repo)
            .cloned()
            .ok_or(GitHostError::NotFound)
    }
}

/// A report for a repository protected the way the policy wants, with the factory's checks pinned.
fn strong_protection() -> ProtectionReport {
    ProtectionReport {
        default_branch: BranchName::new("main").expect("a branch"),
        source: ProtectionSource::Rulesets,
        requires_pull_request: true,
        requires_code_owner_review: true,
        dismisses_stale_approvals: true,
        blocks_force_push: true,
        blocks_deletion: true,
        required_checks: vec![RequiredCheck {
            context: "factory-validation".to_owned(),
            integration_id: Some(FAKE_APP_ID.0),
        }],
    }
}

#[async_trait]
impl IssueSourceSubject for FakeIssueSource {
    fn source(&self) -> &dyn IssueSource {
        self
    }

    async fn seed_issue(&self, issue: Issue) {
        self.put_issue(issue);
    }

    async fn edit_issue_title(&self, issue: &IssueRef, title: &str) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        if let Some(held) = state.issues.get_mut(issue) {
            title.clone_into(&mut held.title);
        }
    }

    async fn seed_label(&self, issue: &IssueRef, label: &str, actor: &GithubActor) {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .labels
            .insert((issue.clone(), label.to_owned()), actor.clone());
    }

    async fn seed_comment(&self, comment: Comment) {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .comments
            .insert(comment.reference.clone(), comment);
    }

    async fn seed_protection(&self, repo: &RepoRef, report: ProtectionReport) {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .protection
            .insert(repo.clone(), report);
    }

    async fn permissions_asked(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .permissions_asked
            .clone()
    }
}
