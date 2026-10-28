//! A code host that records what the stage asked of it.
//!
//! It wraps the in-memory `FakeChangeHost` (the fake of the GitHub adapter's contract) and keeps
//! a log of every call and the requests that carry text or a conclusion. The tests read the log
//! to prove what reached the host: that the pull request was a draft, what its body said, and
//! which conclusion each check run had. The port has no call that merges or marks a pull request
//! ready, so the log can only hold the calls below; a test still asserts the list, so a new call
//! added to the port by mistake would show up here.

use std::sync::Mutex;

use async_trait::async_trait;
use factory_domain::ids::JobId;
use factory_domain::vocabulary::Fidelity;
use factory_ports::githost::{
    ChangeHost, CheckRef, CheckRequest, CommentTarget, DraftPrRequest, GitHostError, GitScope,
    PullRequestRef, PullRequestState,
};
use factory_ports::paths::{BranchName, CommitSha};
use factory_ports::workspace::{FetchTarget, PushTarget};
use factory_testkit::githost::FakeChangeHost;

/// A call that reached the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    PushTarget(String),
    ResolveBranch(String),
    Open { head: String, base: String },
    UpdateBody,
    Comment(String),
    Check(String),
    State,
}

pub struct Spy {
    inner: FakeChangeHost,
    calls: Mutex<Vec<Call>>,
    opened: Mutex<Vec<DraftPrRequest>>,
    checks: Mutex<Vec<CheckRequest>>,
    /// Replaces what `pull_request_state` reports as the head commit, to play a push by a person.
    head_override: Mutex<Option<CommitSha>>,
    /// Replaces the `draft` flag of the state, to play a pull request that was marked ready.
    draft_override: Mutex<Option<bool>>,
    /// Replaces what `resolve_branch` returns for the base.
    base_override: Mutex<Option<CommitSha>>,
    /// The next `open_draft_pull_request` fails as if the host were down, after the push.
    fail_open_once: Mutex<bool>,
}

impl Spy {
    pub fn new(inner: FakeChangeHost) -> Self {
        Self {
            inner,
            calls: Mutex::default(),
            opened: Mutex::default(),
            checks: Mutex::default(),
            head_override: Mutex::default(),
            draft_override: Mutex::default(),
            base_override: Mutex::default(),
            fail_open_once: Mutex::default(),
        }
    }

    pub fn inner(&self) -> &FakeChangeHost {
        &self.inner
    }

    pub fn calls(&self) -> Vec<Call> {
        self.calls.lock().expect("lock").clone()
    }

    pub fn opened(&self) -> Vec<DraftPrRequest> {
        self.opened.lock().expect("lock").clone()
    }

    pub fn checks(&self) -> Vec<CheckRequest> {
        self.checks.lock().expect("lock").clone()
    }

    pub fn count(&self, wanted: fn(&Call) -> bool) -> usize {
        self.calls().iter().filter(|call| wanted(call)).count()
    }

    pub fn head_moves_to(&self, commit: CommitSha) {
        *self.head_override.lock().expect("lock") = Some(commit);
    }

    pub fn pull_request_reads_as_ready(&self) {
        *self.draft_override.lock().expect("lock") = Some(false);
    }

    pub fn the_next_open_fails(&self) {
        *self.fail_open_once.lock().expect("lock") = true;
    }

    pub fn base_moves_to(&self, commit: CommitSha) {
        *self.base_override.lock().expect("lock") = Some(commit);
    }

    fn note(&self, call: Call) {
        self.calls.lock().expect("lock").push(call);
    }
}

#[async_trait]
impl ChangeHost for Spy {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    async fn fetch_target(&self, scope: &GitScope) -> Result<FetchTarget, GitHostError> {
        self.inner.fetch_target(scope).await
    }

    async fn push_target(
        &self,
        scope: &GitScope,
        branch: &BranchName,
    ) -> Result<PushTarget, GitHostError> {
        self.note(Call::PushTarget(branch.as_str().to_owned()));
        self.inner.push_target(scope, branch).await
    }

    async fn resolve_branch(
        &self,
        scope: &GitScope,
        branch: &BranchName,
    ) -> Result<CommitSha, GitHostError> {
        self.note(Call::ResolveBranch(branch.as_str().to_owned()));
        if branch.as_str() == "main"
            && let Some(moved) = self.base_override.lock().expect("lock").clone()
        {
            return Ok(moved);
        }
        self.inner.resolve_branch(scope, branch).await
    }

    async fn open_draft_pull_request(
        &self,
        scope: &GitScope,
        req: DraftPrRequest,
    ) -> Result<PullRequestRef, GitHostError> {
        self.note(Call::Open {
            head: req.head.as_str().to_owned(),
            base: req.base.as_str().to_owned(),
        });
        self.opened.lock().expect("lock").push(req.clone());
        if std::mem::take(&mut *self.fail_open_once.lock().expect("lock")) {
            return Err(GitHostError::Unavailable);
        }
        self.inner.open_draft_pull_request(scope, req).await
    }

    async fn update_pull_request_body(
        &self,
        scope: &GitScope,
        pr: &PullRequestRef,
        body: &str,
        etag: Option<&str>,
    ) -> Result<(), GitHostError> {
        self.note(Call::UpdateBody);
        self.inner
            .update_pull_request_body(scope, pr, body, etag)
            .await
    }

    async fn post_comment(
        &self,
        scope: &GitScope,
        target: &CommentTarget,
        body: &str,
        idempotency_key: &str,
    ) -> Result<factory_ports::githost::CommentRef, GitHostError> {
        self.note(Call::Comment(idempotency_key.to_owned()));
        self.inner
            .post_comment(scope, target, body, idempotency_key)
            .await
    }

    async fn publish_check(
        &self,
        scope: &GitScope,
        req: CheckRequest,
    ) -> Result<CheckRef, GitHostError> {
        self.note(Call::Check(req.name.as_str().to_owned()));
        self.checks.lock().expect("lock").push(req.clone());
        self.inner.publish_check(scope, req).await
    }

    async fn pull_request_state(
        &self,
        scope: &GitScope,
        pr: &PullRequestRef,
    ) -> Result<PullRequestState, GitHostError> {
        self.note(Call::State);
        let mut state = self.inner.pull_request_state(scope, pr).await?;
        if let Some(head) = self.head_override.lock().expect("lock").clone() {
            state.head_sha = head;
        }
        if let Some(draft) = *self.draft_override.lock().expect("lock") {
            state.draft = draft;
        }
        Ok(state)
    }

    async fn revoke_job_tokens(&self, job: JobId) -> Result<(), GitHostError> {
        self.inner.revoke_job_tokens(job).await
    }
}
