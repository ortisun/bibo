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
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::githost::{
    AccountType, ActorLogin, AppId, CappedPost, ChangeHost, CheckRef, CheckRequest, Comment,
    CommentCap, CommentRef, CommentTarget, DraftPrRequest, GitHostError, GitScope, GithubActor,
    Issue, IssueRef, IssueSource, LabelApplication, LabelTimeline, LabeledEvent, ProtectionReport,
    ProtectionSource, PullRequestLifecycle, PullRequestRef, PullRequestState, Rejection,
    RequiredCheck, TextEdit, WorkflowFile,
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

/// The kind of installation token a call needs. The real adapter mints one token for each kind,
/// each repository and each permission set, and keeps it for a job until it is revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TokenKind {
    /// For the calls a stage makes to the code host: the permissions depend on the stage.
    Stage,
    /// For fetching the repository: contents read.
    Fetch,
    /// For pushing a factory branch: contents write.
    Push,
}

/// An installation token the fake minted, as the real adapter would have asked for it. It is a
/// label and a record of what was asked for. It is not a credential and it opens nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedToken {
    /// A label for the token, `fake-token-N`. Never a value.
    pub id: String,
    /// The job it was minted for.
    pub job: JobId,
    /// The stage that asked.
    pub stage: StageKind,
    /// What it is for.
    pub kind: TokenKind,
    /// The one repository it is narrowed to.
    pub repository: RepoRef,
    /// The permissions it carries, by GitHub's names, sorted.
    pub permissions: Vec<(&'static str, &'static str)>,
    /// True once the tokens of the job were revoked.
    pub revoked: bool,
}

/// One request the real adapter would have sent for a call to the fake, in its own method and path
/// form. The fake sends nothing: this is the record of what the port call stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    /// The HTTP method.
    pub method: &'static str,
    /// The path, with the ids in it.
    pub path: String,
}

/// The permissions the real adapter asks for, by stage and kind of token. This is a copy of
/// `PermissionSet` in the `github` crate, which this crate may not depend on. A test in that crate
/// (`the_fake_asks_for_what_the_adapter_asks_for`) compares the two, so they cannot drift apart.
#[must_use]
pub fn permissions_asked(stage: StageKind, kind: TokenKind) -> Vec<(&'static str, &'static str)> {
    match (kind, stage) {
        (TokenKind::Fetch, _) => vec![("contents", "read"), ("metadata", "read")],
        (TokenKind::Push, _) => vec![("contents", "write"), ("metadata", "read")],
        (TokenKind::Stage, StageKind::Delivery) => vec![
            ("checks", "write"),
            ("contents", "write"),
            ("issues", "write"),
            ("metadata", "read"),
            ("pull_requests", "write"),
        ],
        (TokenKind::Stage, StageKind::Intake) => vec![("issues", "read"), ("metadata", "read")],
        (TokenKind::Stage, StageKind::Approval) => vec![
            ("contents", "read"),
            ("issues", "write"),
            ("metadata", "read"),
            ("pull_requests", "read"),
        ],
        (TokenKind::Stage, _) => vec![
            ("contents", "read"),
            ("issues", "read"),
            ("metadata", "read"),
            ("pull_requests", "read"),
        ],
    }
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
    /// The text of each comment, by the id of the comment.
    comment_text: BTreeMap<u64, String>,
    /// The comments posted under a cap, by thread and family (DG-9). The fake keeps no time, so
    /// every one of them is inside the window.
    capped: BTreeMap<(CommentTarget, String), Vec<CommentRef>>,
    next_comment: u64,
    tokens: Vec<MintedToken>,
    requests: Vec<RecordedRequest>,
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

    /// The text of the comments the target holds, in the order they were posted. The text is what
    /// was sent, without the marker the real adapter adds.
    #[must_use]
    pub fn comments_on(&self, target: &CommentTarget) -> Vec<String> {
        let state = self.state.lock().expect("the lock is never poisoned");
        let mut found: Vec<(u64, String)> = state
            .comments
            .iter()
            .filter(|((held, _), _)| held == target)
            .filter_map(|(_, comment)| {
                state
                    .comment_text
                    .get(&comment.id)
                    .map(|text| (comment.id, text.clone()))
            })
            .collect();
        found.sort_by_key(|(id, _)| *id);
        found.into_iter().map(|(_, text)| text).collect()
    }

    /// The description of every pull request the host holds, as it was last sent, by number. A
    /// test that sweeps the sinks of a run for a secret reads the pull request through this.
    #[must_use]
    pub fn pull_request_bodies(&self) -> Vec<(PullRequestRef, String)> {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .pulls
            .iter()
            .map(|(pr, record)| (pr.clone(), record.body.clone()))
            .collect()
    }

    /// The installation tokens the fake minted, in order: one for each job, kind of token,
    /// repository and permission set, as the real adapter keeps them. Labels, never values.
    #[must_use]
    pub fn minted_tokens(&self) -> Vec<MintedToken> {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .tokens
            .clone()
    }

    /// The requests the real adapter would have sent for the calls so far, in order.
    #[must_use]
    pub fn recorded_requests(&self) -> Vec<RecordedRequest> {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .requests
            .clone()
    }

    /// Notes the token a call needs and the request the real adapter would send for it. A token
    /// that the job already holds for the same repository, kind and permissions is not minted
    /// again.
    fn note(
        state: &mut HostState,
        scope: &GitScope,
        kind: TokenKind,
        request: Option<(&'static str, String)>,
    ) {
        let permissions = permissions_asked(scope.stage, kind);
        let held = state.tokens.iter().any(|token| {
            token.job == scope.job
                && token.kind == kind
                && token.repository == scope.repo
                && token.permissions == permissions
                && !token.revoked
        });
        if !held {
            let id = format!("fake-token-{}", state.tokens.len() + 1);
            state.tokens.push(MintedToken {
                id,
                job: scope.job,
                stage: scope.stage,
                kind,
                repository: scope.repo.clone(),
                permissions,
                revoked: false,
            });
        }
        if let Some((method, path)) = request {
            state.requests.push(RecordedRequest { method, path });
        }
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

/// The path of a repository, `/repos/owner/name`, as the real adapter writes it.
fn repo_path(repo: &RepoRef) -> String {
    format!("/repos/{}/{}", repo.owner(), repo.name())
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
        let mut state = self.state.lock().expect("the lock is never poisoned");
        self.live(&state, scope)?;
        Self::note(&mut state, scope, TokenKind::Fetch, None);
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
        let mut state = self.state.lock().expect("the lock is never poisoned");
        self.live(&state, scope)?;
        if !self.branch_ok(branch) {
            return Err(GitHostError::BranchNotAllowed);
        }
        Self::note(&mut state, scope, TokenKind::Push, None);
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
        let mut state = self.state.lock().expect("the lock is never poisoned");
        self.live(&state, scope)?;
        Self::note(
            &mut state,
            scope,
            TokenKind::Stage,
            Some((
                "GET",
                format!("{}/branches/{}", repo_path(&scope.repo), branch),
            )),
        );
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
        Self::note(
            &mut state,
            scope,
            TokenKind::Stage,
            Some(("POST", format!("{}/pulls", repo_path(&scope.repo)))),
        );
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
        Self::note(
            &mut state,
            scope,
            TokenKind::Stage,
            Some((
                "PATCH",
                format!("{}/pulls/{}", repo_path(&pr.repo), pr.number),
            )),
        );
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
        let number = match target {
            CommentTarget::Issue(issue) => issue.number,
            CommentTarget::PullRequest(pr) => pr.number,
        };
        let comments_path = format!("{}/issues/{number}/comments", repo_path(&scope.repo));
        Self::note(
            &mut state,
            scope,
            TokenKind::Stage,
            Some(("GET", comments_path.clone())),
        );
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
        state.requests.push(RecordedRequest {
            method: "POST",
            path: comments_path,
        });
        state.comment_text.insert(comment.id, body.to_owned());
        // With the duplicate defect the key is made unique, so every call keeps its own comment.
        let stored_key = if self.has(ChangeHostDefect::DuplicateComments) {
            (target.clone(), format!("{}#{}", key.1, comment.id))
        } else {
            key
        };
        state.comments.insert(stored_key, comment.clone());
        Ok(comment)
    }

    async fn post_capped_comment(
        &self,
        scope: &GitScope,
        target: &CommentTarget,
        body: &str,
        idempotency_key: &str,
        cap: &CommentCap,
    ) -> Result<CappedPost, GitHostError> {
        {
            let state = self.state.lock().expect("the lock is never poisoned");
            self.live(&state, scope)?;
            // The same key finds the same comment, whatever the cap says.
            let key = (target.clone(), marker(idempotency_key));
            if !self.has(ChangeHostDefect::DuplicateComments)
                && let Some(existing) = state.comments.get(&key)
            {
                return Ok(CappedPost::AlreadyThere(existing.clone()));
            }
            let held = state
                .capped
                .get(&(target.clone(), cap.family().to_owned()))
                .map_or(0, Vec::len);
            if u32::try_from(held).map_or(true, |held| held >= cap.max()) {
                return Ok(CappedPost::CapReached);
            }
        }
        let posted = self
            .post_comment(scope, target, body, idempotency_key)
            .await?;
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .capped
            .entry((target.clone(), cap.family().to_owned()))
            .or_default()
            .push(posted.clone());
        Ok(CappedPost::Posted(posted))
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
        Self::note(
            &mut state,
            scope,
            TokenKind::Stage,
            Some(("POST", format!("{}/check-runs", repo_path(&scope.repo)))),
        );
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
        Self::note(
            &mut state,
            scope,
            TokenKind::Stage,
            Some((
                "GET",
                format!("{}/pulls/{}", repo_path(&pr.repo), pr.number),
            )),
        );
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
            let mut state = self.state.lock().expect("the lock is never poisoned");
            state.revoked.insert(job);
            for token in state.tokens.iter_mut().filter(|token| token.job == job) {
                token.revoked = true;
            }
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
    /// `repository_protection` asks for `administration: write`, above the ceiling of the policy.
    AsksForAdministrationWrite,
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
        IssueSourceDefect::AsksForAdministrationWrite,
        &["repository_protection_reads_administration_at_most"],
    ),
];

#[derive(Default)]
struct IssueState {
    issues: BTreeMap<IssueRef, Issue>,
    cache: BTreeMap<IssueRef, Issue>,
    labels: BTreeMap<(IssueRef, String), GithubActor>,
    label_times: BTreeMap<(IssueRef, String), Timestamp>,
    timelines: BTreeMap<IssueRef, FakeTimeline>,
    history_unreadable: bool,
    /// What `text_edit` answers for an issue. An issue with no entry was never edited.
    text_edits: BTreeMap<IssueRef, TextEdit>,
    /// Makes `text_edit` fail with `Unavailable`, as a host that is down does.
    text_edit_read_fails: bool,
    comments: BTreeMap<CommentRef, Comment>,
    protection: BTreeMap<RepoRef, ProtectionReport>,
    /// The workflow files of the default branch of a repository. A repository with no entry has
    /// none.
    workflows: BTreeMap<RepoRef, Vec<WorkflowFile>>,
    /// Makes `workflow_files` fail with `Unavailable`, as a host that is down does.
    workflow_read_fails: bool,
    /// Makes `repository_protection` fail with `Forbidden`, as a refused classic protection read.
    protection_read_refused: bool,
    permissions_asked: Vec<String>,
}

/// One entry of the event list of a fake issue.
#[derive(Debug, Clone)]
enum FakeEvent {
    /// A `labeled` event.
    Labeled(LabeledEvent),
    /// Any other event (the issue was closed, subscribed to, renamed). It takes a place in the
    /// list and means nothing to the gates.
    Other,
}

/// The event list of a fake issue, with the order and the pages the code host would give.
///
/// Every `seed_label` also adds a `labeled` event here, so that a test can add more events to an
/// issue the rig has already labelled. The list answers the questions about labels only once a
/// test has asked for it with `seed_event`, `seed_events_of_no_interest` or
/// `list_events_newest_first`; until then the plain record of `seed_label` answers, as it always did.
#[derive(Debug, Clone)]
struct FakeTimeline {
    events: Vec<FakeEvent>,
    newest_first: bool,
    asked_for: bool,
    next_id: u64,
}

impl Default for FakeTimeline {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            newest_first: false,
            asked_for: false,
            next_id: 1,
        }
    }
}

/// How many events one page holds and how many pages a reader of the fake reads, like the adapter
/// (100 and 30). Events past the last page are not given, and the list is then incomplete.
const FAKE_EVENTS_PER_PAGE: usize = 100;
const FAKE_EVENT_PAGES: usize = 30;

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
        push_labeled(&mut state, issue, label, actor, AccountType::User, at);
    }

    /// Adds a `labeled` event to the event list of the issue, by an account of this type, and
    /// makes the list the one that answers (see [`FakeTimeline`]). The events are listed in the
    /// order they were added unless `list_events_newest_first` says otherwise; a later event does
    /// not need a later time, and the ids keep the order.
    pub fn seed_event(
        &self,
        issue: &IssueRef,
        label: &str,
        actor: &GithubActor,
        actor_type: AccountType,
        at: Timestamp,
    ) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        push_labeled(&mut state, issue, label, actor, actor_type, at);
        state.timelines.entry(issue.clone()).or_default().asked_for = true;
    }

    /// Adds `count` events that are not about labels, as a long thread has, so that the list runs
    /// past the pages a reader is willing to read.
    pub fn seed_events_of_no_interest(&self, issue: &IssueRef, count: usize) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        let timeline = state.timelines.entry(issue.clone()).or_default();
        timeline.asked_for = true;
        timeline
            .events
            .extend(std::iter::repeat_n(FakeEvent::Other, count));
    }

    /// Makes `labels_ever_applied` answer `Unavailable`, as a host does that cannot give the list
    /// of events to the end, while `label_application` goes on answering. It lets a test show that
    /// a caller that needs the history refuses when it has none.
    pub fn make_the_history_unreadable(&self, unreadable: bool) {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .history_unreadable = unreadable;
    }

    /// Sets what `text_edit` answers for the issue: [`TextEdit::At`] a time, [`TextEdit::Never`],
    /// or [`TextEdit::Unknown`] as a source does that cannot read the time (DR-1). An issue that
    /// was never given an entry was never edited.
    pub fn seed_text_edit(&self, issue: &IssueRef, edit: TextEdit) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        state.text_edits.insert(issue.clone(), edit);
    }

    /// Puts a workflow file on the default branch of the repository (threat T-48). A `text` of
    /// `None` is a file the host lists and cannot give the text of. A second file at the same path
    /// replaces the first.
    pub fn seed_workflow(&self, repo: &RepoRef, path: &str, text: Option<&str>) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        let files = state.workflows.entry(repo.clone()).or_default();
        files.retain(|file| file.path != path);
        files.push(WorkflowFile {
            path: path.to_owned(),
            text: text.map(str::to_owned),
        });
    }

    /// Makes the read of the workflow files fail with `Unavailable`, as a code host that is down
    /// does.
    pub fn make_the_workflow_read_fail(&self, fails: bool) {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .workflow_read_fails = fails;
    }

    /// Makes the read of the protection fail with `Forbidden`, as the real adapter does when the
    /// App lacks `administration: read` for classic branch protection.
    pub fn refuse_the_protection_read(&self, refused: bool) {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .protection_read_refused = refused;
    }

    /// Makes the read of the edit time fail with `Unavailable`, as a code host that is down does.
    pub fn make_the_edit_read_fail(&self, fails: bool) {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .text_edit_read_fails = fails;
    }

    /// Lists the events of the issue newest first, which GitHub may or may not do. The answers
    /// must not change.
    pub fn list_events_newest_first(&self, issue: &IssueRef, newest_first: bool) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        let timeline = state.timelines.entry(issue.clone()).or_default();
        timeline.asked_for = true;
        timeline.newest_first = newest_first;
    }

    /// The events a reader of the fake gets: in the order of the list, cut after the pages it
    /// reads, with a flag that says whether it saw the end. `None` when no test asked for a list.
    fn timeline_of(state: &IssueState, issue: &IssueRef) -> Option<LabelTimeline> {
        let timeline = state.timelines.get(issue).filter(|t| t.asked_for)?;
        let mut listed: Vec<&FakeEvent> = timeline.events.iter().collect();
        if timeline.newest_first {
            listed.reverse();
        }
        let reach = FAKE_EVENTS_PER_PAGE * FAKE_EVENT_PAGES;
        let complete = listed.len() <= reach;
        let labeled = listed
            .into_iter()
            .take(reach)
            .filter_map(|event| match event {
                FakeEvent::Labeled(labeled) => Some(labeled.clone()),
                FakeEvent::Other => None,
            })
            .collect();
        Some(LabelTimeline::new(labeled, complete))
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

/// The time given to a label that a test seeded without one, where a time is needed to order the
/// events. The events keep their order by id.
fn seeded_at() -> Timestamp {
    Timestamp::parse("2026-10-28T10:00:00Z").expect("a time")
}

/// Adds a `labeled` event to the list of the issue.
fn push_labeled(
    state: &mut IssueState,
    issue: &IssueRef,
    label: &str,
    actor: &GithubActor,
    actor_type: AccountType,
    at: Timestamp,
) {
    let timeline = state.timelines.entry(issue.clone()).or_default();
    let id = timeline.next_id;
    timeline.next_id += 1;
    timeline.events.push(FakeEvent::Labeled(LabeledEvent {
        id: Some(id),
        at,
        label: label.to_owned(),
        actor: Some((actor.clone(), actor_type)),
    }));
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
        if let Some(timeline) = Self::timeline_of(&state, issue) {
            return Ok(timeline
                .latest_application(label)?
                .map(|application| application.actor));
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
        } else if let Some(timeline) = Self::timeline_of(&state, issue) {
            return timeline.latest_application(label);
        } else {
            state.labels.get_key_value(&key)
        };
        Ok(found.map(|(held, actor)| LabelApplication {
            actor: actor.clone(),
            applied_at: state.label_times.get(held).copied(),
            actor_type: AccountType::User,
        }))
    }

    async fn labels_ever_applied(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
    ) -> Result<Vec<String>, GitHostError> {
        self.in_scope(scope, &issue.repo)?;
        let state = self.state.lock().expect("the lock is never poisoned");
        if state.history_unreadable {
            return Err(GitHostError::Unavailable);
        }
        if let Some(timeline) = Self::timeline_of(&state, issue) {
            return timeline.labels_ever_applied();
        }
        // No list was asked for: every label the test recorded an application of, and the labels
        // the issue shows now (each was applied by somebody).
        let mut names: std::collections::BTreeSet<String> = state
            .labels
            .keys()
            .filter(|(held, _)| held == issue)
            .map(|(_, name)| name.clone())
            .collect();
        if let Some(live) = state.issues.get(issue) {
            names.extend(live.labels.iter().cloned());
        }
        Ok(names.into_iter().collect())
    }

    async fn text_edit(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
    ) -> Result<TextEdit, GitHostError> {
        self.in_scope(scope, &issue.repo)?;
        let state = self.state.lock().expect("the lock is never poisoned");
        if state.text_edit_read_fails {
            return Err(GitHostError::Unavailable);
        }
        if !state.issues.contains_key(issue) {
            return Err(GitHostError::NotFound);
        }
        Ok(state
            .text_edits
            .get(issue)
            .copied()
            .unwrap_or(TextEdit::Never))
    }

    async fn repository_protection(
        &self,
        scope: &GitScope,
    ) -> Result<ProtectionReport, GitHostError> {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        state.permissions_asked.push("metadata:read".to_owned());
        state
            .permissions_asked
            .push("administration:read".to_owned());
        if self.has(IssueSourceDefect::AsksForAdministrationWrite) {
            state
                .permissions_asked
                .push("administration:write".to_owned());
        }
        if self.has(IssueSourceDefect::AlwaysProtected) {
            return Ok(strong_protection());
        }
        if state.protection_read_refused {
            return Err(GitHostError::Forbidden);
        }
        state
            .protection
            .get(&scope.repo)
            .cloned()
            .ok_or(GitHostError::NotFound)
    }

    async fn workflow_files(&self, scope: &GitScope) -> Result<Vec<WorkflowFile>, GitHostError> {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        state.permissions_asked.push("contents:read".to_owned());
        if state.workflow_read_fails {
            return Err(GitHostError::Unavailable);
        }
        Ok(state
            .workflows
            .get(&scope.repo)
            .cloned()
            .unwrap_or_default())
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
        required_approving_reviews: Some(1),
        required_checks: vec![RequiredCheck {
            context: "factory-validation".to_owned(),
            integration_id: Some(FAKE_APP_ID.0),
        }],
        // The workflows are a read of their own (`workflow_files`), judged by the preflight.
        exposed_workflows: None,
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
        let mut edited_at = None;
        if let Some(held) = state.issues.get_mut(issue) {
            title.clone_into(&mut held.title);
            edited_at = Some(held.updated_at);
        }
        // An edit is an edit of the words: the host now knows a time for it.
        if let Some(at) = edited_at {
            state.text_edits.insert(issue.clone(), TextEdit::At(at));
        }
    }

    async fn seed_label(&self, issue: &IssueRef, label: &str, actor: &GithubActor) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        state
            .labels
            .insert((issue.clone(), label.to_owned()), actor.clone());
        push_labeled(
            &mut state,
            issue,
            label,
            actor,
            AccountType::User,
            seeded_at(),
        );
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
