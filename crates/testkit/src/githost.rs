//! A code host kept in memory: `FakeChangeHost` and `FakeIssueSource`.
//!
//! The change host opens only draft pull requests, from branches under `factory/`, once per head
//! branch. It has no way to merge, as the port has none: a test plays the person who merges with
//! [`FakeChangeHost::mark_merged_by_person`]. It checks text for token-shaped secrets before
//! posting, applies the body tag check, keeps tenants and repositories apart, and refuses every
//! call for a job whose tokens were revoked.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::vocabulary::Fidelity;
use factory_ports::githost::{
    ActorLogin, ChangeHost, CommentRef, CommentTarget, DraftPrRequest, GitHostError, GitScope,
    Issue, IssueRef, IssueSource, ProtectionReport, PullRequestLifecycle, PullRequestRef,
    PullRequestState, StatusRequest,
};
use factory_ports::paths::{BranchName, RepoRef};
use factory_ports::workspace::{PushCredential, PushTarget};

use crate::contracts::githost::{ChangeHostSubject, IssueSourceSubject};

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
}

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
    statuses: BTreeMap<(String, String), StatusRequest>,
}

/// An in-memory change host. Reports fidelity `fake`.
pub struct FakeChangeHost {
    state: Mutex<HostState>,
    defect: Option<ChangeHostDefect>,
}

impl FakeChangeHost {
    /// A faithful fake.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(HostState::default()),
            defect: None,
        }
    }

    /// A fake that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(defect: ChangeHostDefect) -> Self {
        Self {
            defect: Some(defect),
            ..Self::new()
        }
    }

    /// Plays a person merging the pull request on the code host. The factory has no such call.
    pub fn mark_merged_by_person(&self, pr: &PullRequestRef) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        if let Some(record) = state.pulls.get_mut(pr) {
            record.lifecycle = PullRequestLifecycle::Merged;
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
        if pr.repo != scope.repo {
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

#[async_trait]
impl ChangeHost for FakeChangeHost {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
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
        let key = (scope.repo.clone(), req.head.clone());
        if !self.has(ChangeHostDefect::DuplicatePullRequests)
            && let Some(existing) = state.heads.get(&key)
        {
            return Ok(existing.clone());
        }
        state.next_pull += 1;
        let pr = PullRequestRef {
            repo: scope.repo.clone(),
            number: state.next_pull,
        };
        state.pulls.insert(
            pr.clone(),
            PullRecord {
                tenant: scope.tenant,
                head: req.head,
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
        let key = (target.clone(), idempotency_key.to_owned());
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
            (target.clone(), format!("{idempotency_key}#{}", comment.id))
        } else {
            key
        };
        state.comments.insert(stored_key, comment.clone());
        Ok(comment)
    }

    async fn set_status(&self, scope: &GitScope, req: StatusRequest) -> Result<(), GitHostError> {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        self.live(&state, scope)?;
        let key = (req.commit.to_string(), req.context.to_string());
        state.statuses.insert(key, req);
        Ok(())
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
            lifecycle: record.lifecycle,
            draft: record.draft,
            head: record.head.clone(),
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

    async fn comment_count(&self, target: &CommentTarget) -> usize {
        FakeChangeHost::comment_count(self, target)
    }

    async fn person_merges(&self, pr: &PullRequestRef) {
        self.mark_merged_by_person(pr);
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
}

#[derive(Default)]
struct IssueState {
    issues: BTreeMap<IssueRef, Issue>,
    cache: BTreeMap<IssueRef, Issue>,
    labels: BTreeMap<(IssueRef, String), ActorLogin>,
    protection: BTreeMap<RepoRef, ProtectionReport>,
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
        let live = state
            .issues
            .get(issue)
            .cloned()
            .ok_or(GitHostError::NotFound)?;
        state.cache.insert(issue.clone(), live.clone());
        Ok(live)
    }

    async fn label_actor(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
        label: &str,
    ) -> Result<Option<ActorLogin>, GitHostError> {
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

    async fn repository_protection(
        &self,
        scope: &GitScope,
    ) -> Result<ProtectionReport, GitHostError> {
        if self.has(IssueSourceDefect::AlwaysProtected) {
            return Ok(ProtectionReport {
                default_branch_protected: true,
                required_checks_pinned_to_app: true,
                app_can_bypass: false,
            });
        }
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .protection
            .get(&scope.repo)
            .cloned()
            .ok_or(GitHostError::NotFound)
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

    async fn seed_label(&self, issue: &IssueRef, label: &str, actor: &ActorLogin) {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .labels
            .insert((issue.clone(), label.to_owned()), actor.clone());
    }

    async fn seed_protection(&self, repo: &RepoRef, report: ProtectionReport) {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .protection
            .insert(repo.clone(), report);
    }
}
