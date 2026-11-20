//! The troubleshooter's triage issues (ports v1.3, ADR 0021 Decision 7): find the open issue of a
//! fingerprint, open one, and say "seen again" on it.
//!
//! # What this code does and does not do
//!
//! * **A run's credential.** Every request uses a token minted for the troubleshooting run, not for
//!   a job: `issues: write` and `metadata: read` for the one configured issue repository
//!   (`PermissionSet::troubleshoot_issue`). A scope that names another repository is `Forbidden`
//!   before anything is sent, a token request included. No job stage can ask for this class.
//! * **Listings, not search.** The open issues that carry the label `troubleshooter` are listed
//!   (`GET /repos/{owner}/{repo}/issues?state=open&labels=troubleshooter`), pull requests are left
//!   out, and only an issue the factory's own App opened counts. Its fingerprint is read from its
//!   **body** only, and only from a line that is exactly the marker. A marker in a comment, or in an
//!   issue a person opened, is not one. The search API is not used: its index lags and it has a
//!   rate limit of its own.
//! * **Look before writing.** `open_issue` looks for an open issue of the same fingerprint first,
//!   and `post_seen_again` for its own comment with the same key, so a retry after a lost answer
//!   does not write twice. A listing cut short at the page cap without a match is `Unavailable`:
//!   absence is not proven.
//! * **Only the troubleshooter's labels.** Every label is checked again before anything is sent
//!   (`Rejected(LabelNotAllowed)`): never `factory`, a `factory:` label or a `design:` label.
//! * **Text.** The title and body come from the closed template of
//!   `factory_domain::troubleshooting::issue`, which already put every agent-written field on one
//!   line, defanged it and shut it in a code span. This code checks the rendered text **and** the
//!   agent's raw words for secrets (defanging can hide a secret's shape) and refuses with
//!   `UnsafeText`. It does not run the Markdown cleaner of `text.rs` over the body: that cleaner
//!   does not know code spans, and rewriting a link that spans two of them could move a backtick
//!   and let quoted text out of its span.
//! * **Paced.** At least one second between two requests that change something, as for the status
//!   writer.
//!
//! # UNVERIFIED against the real GitHub
//!
//! Read from the REST reference on 2026-11-20 and not exercised against the real service:
//!
//! * that `GET /repos/{owner}/{repo}/issues` with `labels=troubleshooter` matches the label name
//!   without regard to letter case, and lists pull requests too (they carry `pull_request`);
//! * that `POST /repos/{owner}/{repo}/issues` with `labels` applies labels that exist and what it
//!   does with one that does not (the installer is expected to create both labels first);
//! * that an App's issue lists `user.login` as `<slug>[bot]`, as for comments.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::troubleshooting::issue::{SeenAgainComment, TriageIssue};
use factory_domain::troubleshooting::{
    FindingFingerprint, TRIAGE_LABEL, TroubleshootingRunId, check_triage_label_name,
};
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::Clock;
use factory_ports::githost::{CommentRef, CommentTarget, GitHostError, IssueRef, Rejection};
use factory_ports::paths::RepoRef;
use factory_ports::triage_issue::{OpenedIssue, RunScope, SeenAgainPost, TriageIssueWriter};
use serde_json::{Value, json};

use crate::client::Client;
use crate::core::Sleeper;
use crate::encoding::percent_encode_component;
use crate::parse::repo_path;
use crate::status::Pacer;
use crate::text::{Outbound, TextKind};
use crate::token::Caller;
use crate::wire::Method;

/// The most pages of open triage issues read when looking for a fingerprint. With 100 a page,
/// a thousand open issues; the troubleshooter opens at most a few a day.
const ISSUE_PAGES: u32 = 10;

/// The triage issue writer of the GitHub adapter.
#[derive(Clone)]
pub struct GithubTriageIssues {
    client: Arc<Client>,
    outbound: Arc<Outbound>,
    pacer: Arc<Pacer>,
    repository: RepoRef,
}

impl std::fmt::Debug for GithubTriageIssues {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubTriageIssues")
            .field("repository", &self.repository)
            .finish_non_exhaustive()
    }
}

impl GithubTriageIssues {
    pub(crate) fn new(
        client: Arc<Client>,
        outbound: Arc<Outbound>,
        sleeper: Arc<dyn Sleeper>,
        clock: Arc<dyn Clock>,
        repository: RepoRef,
    ) -> Self {
        Self {
            client,
            outbound,
            pacer: Arc::new(Pacer::new(sleeper, clock)),
            repository,
        }
    }

    /// The configured issue repository is the only one a run may touch. The scope that comes back
    /// names it as configured, so that a name in another letter case reaches the same installation
    /// and paths.
    fn bound(&self, scope: &RunScope) -> Result<RunScope, GitHostError> {
        if scope.repo.same_repository(&self.repository) {
            Ok(RunScope {
                repo: self.repository.clone(),
                ..scope.clone()
            })
        } else {
            Err(GitHostError::Forbidden)
        }
    }

    async fn change(
        &self,
        scope: &RunScope,
        method: Method,
        target: &str,
        body: &Value,
    ) -> Result<Value, GitHostError> {
        self.pacer.before_change().await;
        let result = self
            .client
            .call_as(Caller::Run(scope), method, target, Some(body), false)
            .await;
        self.pacer.changed();
        result.map(|reply| reply.json)
    }

    async fn bot_login(&self) -> Result<String, GitHostError> {
        Ok(self.client.minter().app_identity().await?.bot_login)
    }

    /// Fails with `UnsafeText` when the text, or the agent's words behind it, hold a secret.
    fn guard_all(&self, texts: &[&str]) -> Result<(), GitHostError> {
        texts.iter().try_for_each(|text| self.outbound.guard(text))
    }
}

#[async_trait]
impl TriageIssueWriter for GithubTriageIssues {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn find_open_issue(
        &self,
        scope: &RunScope,
        fingerprint: &FindingFingerprint,
    ) -> Result<Option<IssueRef>, GitHostError> {
        let scope = &self.bound(scope)?;
        let bot = self.bot_login().await?;
        let path = format!(
            "{}/issues?state=open&labels={}&sort=created&direction=asc",
            repo_path(&scope.repo),
            percent_encode_component(TRIAGE_LABEL)
        );
        let pages = self
            .client
            .pages_as(Caller::Run(scope), &path, ISSUE_PAGES)
            .await?;
        let found = pages
            .items
            .iter()
            .filter(|item| item.get("pull_request").is_none())
            .filter(|item| item["state"].as_str().is_none_or(|s| s == "open"))
            .filter(|item| item["user"]["login"].as_str() == Some(bot.as_str()))
            .filter(|item| {
                item["body"]
                    .as_str()
                    .and_then(FindingFingerprint::from_body)
                    .as_ref()
                    == Some(fingerprint)
            })
            .filter_map(|item| item["number"].as_u64())
            .min();
        match found {
            Some(number) => Ok(Some(IssueRef {
                repo: scope.repo.clone(),
                number,
            })),
            // Not found in a listing that was cut short is not proof that it is not there.
            None if pages.truncated => Err(GitHostError::Unavailable),
            None => Ok(None),
        }
    }

    async fn open_issue(
        &self,
        scope: &RunScope,
        issue: &TriageIssue,
    ) -> Result<OpenedIssue, GitHostError> {
        // The second check of the labels, before anything is sent, a token request included.
        let labels = issue.labels().names();
        for name in &labels {
            check_triage_label_name(name)
                .map_err(|_| GitHostError::Rejected(Rejection::LabelNotAllowed))?;
        }
        let scope = &self.bound(scope)?;
        self.guard_all(&[issue.title(), issue.body(), issue.agent_text()])?;
        let title = self.outbound.prepare(TextKind::Title, issue.title())?;
        let body = format!(
            "{}\n\n{}\n",
            issue.body_before_marker().trim_end(),
            issue.fingerprint().marker()
        );
        if let Some(open) = self.find_open_issue(scope, issue.fingerprint()).await? {
            return Ok(OpenedIssue::AlreadyOpen(open));
        }
        let path = format!("{}/issues", repo_path(&scope.repo));
        let made = self
            .change(
                scope,
                Method::Post,
                &path,
                &json!({ "title": title, "body": body, "labels": labels }),
            )
            .await?;
        let number = made["number"].as_u64().ok_or(GitHostError::Unavailable)?;
        Ok(OpenedIssue::Opened(IssueRef {
            repo: scope.repo.clone(),
            number,
        }))
    }

    async fn post_seen_again(
        &self,
        scope: &RunScope,
        issue: &IssueRef,
        comment: &SeenAgainComment,
    ) -> Result<SeenAgainPost, GitHostError> {
        let scope = &self.bound(scope)?;
        if !scope.repo.same_repository(&issue.repo) {
            return Err(GitHostError::NotFound);
        }
        self.guard_all(&[comment.body(), comment.agent_text()])?;
        let reference = |id: u64| CommentRef {
            target: CommentTarget::Issue(issue.clone()),
            id,
        };
        let bot = self.bot_login().await?;
        let path = format!(
            "{}/issues/{}/comments",
            repo_path(&scope.repo),
            issue.number
        );
        let pages = self
            .client
            .pages_as(Caller::Run(scope), &path, ISSUE_PAGES)
            .await?;
        let mine = pages
            .items
            .iter()
            .filter(|c| c["user"]["login"].as_str() == Some(bot.as_str()))
            .filter(|c| {
                c["body"]
                    .as_str()
                    .is_some_and(|body| body.lines().any(|line| line.trim_end() == comment.key()))
            })
            .filter_map(|c| c["id"].as_u64())
            .min();
        if let Some(id) = mine {
            return Ok(SeenAgainPost::AlreadyThere(reference(id)));
        }
        if pages.truncated {
            return Err(GitHostError::Unavailable);
        }
        let body = format!(
            "{}\n\n{}\n",
            comment.body_before_key().trim_end(),
            comment.key()
        );
        let made = self
            .change(scope, Method::Post, &path, &json!({ "body": body }))
            .await?;
        let id = made["id"].as_u64().ok_or(GitHostError::Unavailable)?;
        Ok(SeenAgainPost::Posted(reference(id)))
    }

    async fn revoke_run_tokens(&self, run: &TroubleshootingRunId) -> Result<(), GitHostError> {
        self.client.minter().revoke_run(run).await
    }
}
