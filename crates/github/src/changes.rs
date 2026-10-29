//! The change host: credentials for fetch and push, draft pull requests, comments, check runs.
//!
//! What this code does not have: a call that merges, a call that marks a pull request ready for
//! review, a call that writes a workflow file, and a call that deletes a branch. A person merges
//! (ADR 0009). The factory's gate results are check runs made as the App, so a ruleset can pin a
//! required check to the App's id (ADR 0014, decision 7).
//!
//! * **Scope.** Every call names one tenant, job, stage and repository. A reference to another
//!   repository is `NotFound` before any call is made. A tenant without a binding to the
//!   repository reaches nothing. After `revoke_job_tokens`, every call for the job is
//!   `Unauthorized`.
//! * **Draft only.** A pull request is opened with `draft: true`, and the answer is checked: one
//!   that came back as ready is closed at once and reported as rejected.
//! * **Idempotent.** An open pull request for the same head branch is returned, not duplicated. A
//!   comment carries a hidden marker derived from its idempotency key and is looked for, among
//!   the App's own comments, before it is posted. A check run is found by commit, name, App and
//!   external id and updated, not duplicated.
//! * **Text.** Everything sent is checked for secrets and made safe to render first.
//! * **The body tag.** The tag that guards `update_pull_request_body` covers the text of the body
//!   and the commit the pull request pointed at when it was read. A push after the read makes the
//!   tag stale, so an evidence manifest written for one commit cannot overwrite the page of
//!   another.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::ids::JobId;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::{Fidelity, GateOutcome};
use factory_ports::githost::{
    AppId, ChangeHost, CheckConclusion, CheckRef, CheckRequest, CheckStatus, CommentRef,
    CommentTarget, DraftPrRequest, GitHostError, GitScope, PullRequestLifecycle, PullRequestRef,
    PullRequestState, Rejection,
};
use factory_ports::paths::{BranchName, CommitSha, RepoRef};
use factory_ports::workspace::{FetchCredential, FetchTarget, PushCredential, PushTarget};
use serde_json::{Value, json};

use crate::client::Client;
use crate::encoding::percent_encode_component;
use crate::parse::repo_path;
use crate::text::{Outbound, TextKind};
use crate::token::TokenClass;
use crate::wire::Method;

/// How a gate outcome is shown to the code host. A gate that did not run is never a success.
///
/// | Gate outcome | Check conclusion |
/// |---|---|
/// | `PASSED` | success |
/// | `FAILED` | failure |
/// | `BLOCKED` | action required |
/// | `NOT_APPLICABLE` | neutral |
#[must_use]
pub const fn conclusion_for_gate(outcome: GateOutcome) -> CheckConclusion {
    match outcome {
        GateOutcome::Passed => CheckConclusion::Success,
        GateOutcome::Failed => CheckConclusion::Failure,
        GateOutcome::Blocked => CheckConclusion::ActionRequired,
        GateOutcome::NotApplicable => CheckConclusion::Neutral,
    }
}

/// The conclusion of a stage from all its gates: any failure fails it, else any blocked gate
/// needs a person, else it passes when at least one gate passed. A set with no gate at all, and a
/// set in which no gate applied, has shown nothing: it needs a person and is never `neutral`,
/// because a required check accepts `neutral` as passing (AUT-8).
#[must_use]
pub fn conclusion_for_gates(outcomes: &[GateOutcome]) -> CheckConclusion {
    if outcomes.contains(&GateOutcome::Failed) {
        CheckConclusion::Failure
    } else if outcomes.contains(&GateOutcome::Blocked) {
        CheckConclusion::ActionRequired
    } else if outcomes.contains(&GateOutcome::Passed) {
        CheckConclusion::Success
    } else {
        CheckConclusion::ActionRequired
    }
}

const fn conclusion_name(conclusion: CheckConclusion) -> &'static str {
    match conclusion {
        CheckConclusion::Success => "success",
        CheckConclusion::Failure => "failure",
        CheckConclusion::Neutral => "neutral",
        CheckConclusion::ActionRequired => "action_required",
        CheckConclusion::Cancelled => "cancelled",
    }
}

const CHECK_TITLE_LIMIT: usize = 100;
const CHECK_SUMMARY_LIMIT: usize = 4000;

/// The hidden marker that makes a comment findable by its idempotency key. The key is hashed, so
/// the marker reveals nothing about it.
fn marker_for(key: &str) -> String {
    let digest = Sha256Digest::of(key.as_bytes());
    format!(
        "<!-- factory-comment:{} -->",
        digest.hex().get(..32).unwrap_or_default()
    )
}

/// The change host of the GitHub adapter.
#[derive(Clone)]
pub struct GithubChangeHost {
    client: Arc<Client>,
    outbound: Arc<Outbound>,
    app: AppId,
}

impl std::fmt::Debug for GithubChangeHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GithubChangeHost")
    }
}

impl GithubChangeHost {
    pub(crate) fn new(client: Arc<Client>, outbound: Arc<Outbound>, app: AppId) -> Self {
        Self {
            client,
            outbound,
            app,
        }
    }

    fn own_repository(scope: &GitScope, repo: &RepoRef) -> Result<(), GitHostError> {
        if &scope.repo == repo {
            Ok(())
        } else {
            Err(GitHostError::NotFound)
        }
    }

    fn factory_branch(&self, branch: &BranchName) -> Result<(), GitHostError> {
        if !branch.is_factory_branch() {
            return Err(GitHostError::BranchNotAllowed);
        }
        // The branch name is text bound for GitHub too.
        self.outbound.guard(branch.as_str())
    }

    async fn pull_json(
        &self,
        scope: &GitScope,
        pr: &PullRequestRef,
        conditional: bool,
    ) -> Result<Value, GitHostError> {
        Self::own_repository(scope, &pr.repo)?;
        let target = format!("{}/pulls/{}", repo_path(&pr.repo), pr.number);
        let reply = self
            .client
            .call(
                scope,
                TokenClass::Stage,
                Method::Get,
                &target,
                None,
                conditional,
            )
            .await?;
        Ok(reply.json)
    }

    /// The open pull request of this repository whose head is `head`, if there is one.
    async fn find_open(
        &self,
        scope: &GitScope,
        head: &BranchName,
    ) -> Result<Option<PullRequestRef>, GitHostError> {
        let filter = percent_encode_component(&format!("{}:{}", scope.repo.owner(), head.as_str()));
        let found = self
            .client
            .get_pages(
                scope,
                &format!("{}/pulls?state=open&head={filter}", repo_path(&scope.repo)),
            )
            .await?;
        let full_name = format!("{}/{}", scope.repo.owner(), scope.repo.name());
        Ok(found.items.iter().find_map(|pull| {
            let from_here = pull["head"]["ref"].as_str() == Some(head.as_str())
                && pull["head"]["repo"]["full_name"]
                    .as_str()
                    .is_none_or(|name| name.eq_ignore_ascii_case(&full_name));
            from_here
                .then(|| pull["number"].as_u64())
                .flatten()
                .map(|number| PullRequestRef {
                    repo: scope.repo.clone(),
                    number,
                })
        }))
    }

    fn body_tag(head_sha: &str, body: &str) -> String {
        let digest = Sha256Digest::of(body.as_bytes());
        format!("{head_sha}:{}", digest.hex().get(..32).unwrap_or_default())
    }

    fn clean_body(&self, body: &str) -> Result<String, GitHostError> {
        if body.trim().is_empty() {
            Ok(String::new())
        } else {
            self.outbound.prepare(TextKind::Markdown, body)
        }
    }
}

#[async_trait]
impl ChangeHost for GithubChangeHost {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn fetch_target(&self, scope: &GitScope) -> Result<FetchTarget, GitHostError> {
        let bearer = self
            .client
            .minter()
            .token_for(scope, TokenClass::Fetch)
            .await?;
        Ok(FetchTarget {
            repo: scope.repo.clone(),
            credential: FetchCredential::new(bearer.expose().to_owned()),
        })
    }

    async fn push_target(
        &self,
        scope: &GitScope,
        branch: &BranchName,
    ) -> Result<PushTarget, GitHostError> {
        self.factory_branch(branch)?;
        let bearer = self
            .client
            .minter()
            .token_for(scope, TokenClass::Push)
            .await?;
        Ok(PushTarget {
            repo: scope.repo.clone(),
            branch: branch.clone(),
            credential: PushCredential::new(bearer.expose().to_owned()),
        })
    }

    async fn resolve_branch(
        &self,
        scope: &GitScope,
        branch: &BranchName,
    ) -> Result<CommitSha, GitHostError> {
        let reply = self
            .client
            .call(
                scope,
                TokenClass::Stage,
                Method::Get,
                &format!(
                    "{}/branches/{}",
                    repo_path(&scope.repo),
                    percent_encode_component(branch.as_str())
                ),
                None,
                false,
            )
            .await?;
        reply.json["commit"]["sha"]
            .as_str()
            .and_then(|sha| CommitSha::parse(sha).ok())
            .ok_or(GitHostError::Unavailable)
    }

    async fn open_draft_pull_request(
        &self,
        scope: &GitScope,
        req: DraftPrRequest,
    ) -> Result<PullRequestRef, GitHostError> {
        self.factory_branch(&req.head)?;
        self.outbound.guard(req.base.as_str())?;
        if req.head == req.base {
            return Err(GitHostError::Rejected(Rejection::HeadIsBase));
        }
        let title = self.outbound.prepare(TextKind::Title, &req.title)?;
        let body = self.clean_body(&req.body)?;
        if let Some(existing) = self.find_open(scope, &req.head).await? {
            return Ok(existing);
        }
        let payload = json!({
            "title": title,
            "head": req.head.as_str(),
            "base": req.base.as_str(),
            "body": body,
            "draft": true,
        });
        let created = self
            .client
            .call(
                scope,
                TokenClass::Stage,
                Method::Post,
                &format!("{}/pulls", repo_path(&scope.repo)),
                Some(&payload),
                false,
            )
            .await;
        let value = match created {
            Ok(reply) => reply.json,
            // A second caller won the race: its pull request is the one.
            Err(GitHostError::Rejected(Rejection::Other)) => {
                return self
                    .find_open(scope, &req.head)
                    .await?
                    .ok_or(GitHostError::Rejected(Rejection::Other));
            }
            Err(error) => return Err(error),
        };
        let number = value["number"].as_u64().ok_or(GitHostError::Unavailable)?;
        let pr = PullRequestRef {
            repo: scope.repo.clone(),
            number,
        };
        if value["draft"].as_bool() != Some(true) {
            // A repository that cannot hold drafts made a ready pull request. Close it: the
            // factory never leaves one open.
            let close = json!({ "state": "closed" });
            let _ = self
                .client
                .call(
                    scope,
                    TokenClass::Stage,
                    Method::Patch,
                    &format!("{}/pulls/{number}", repo_path(&scope.repo)),
                    Some(&close),
                    false,
                )
                .await;
            return Err(GitHostError::Rejected(Rejection::Other));
        }
        Ok(pr)
    }

    async fn update_pull_request_body(
        &self,
        scope: &GitScope,
        pr: &PullRequestRef,
        body: &str,
        etag: Option<&str>,
    ) -> Result<(), GitHostError> {
        let cleaned = self.clean_body(body)?;
        let current = self.pull_json(scope, pr, false).await?;
        let head_sha = current["head"]["sha"]
            .as_str()
            .ok_or(GitHostError::Unavailable)?;
        let current_tag = Self::body_tag(head_sha, current["body"].as_str().unwrap_or_default());
        if etag.is_some_and(|expected| expected != current_tag) {
            return Err(GitHostError::Conflict);
        }
        if current["body"].as_str().unwrap_or_default() == cleaned {
            return Ok(());
        }
        let payload = json!({ "body": cleaned });
        self.client
            .call(
                scope,
                TokenClass::Stage,
                Method::Patch,
                &format!("{}/pulls/{}", repo_path(&pr.repo), pr.number),
                Some(&payload),
                false,
            )
            .await
            .map(|_| ())
    }

    async fn post_comment(
        &self,
        scope: &GitScope,
        target: &CommentTarget,
        body: &str,
        idempotency_key: &str,
    ) -> Result<CommentRef, GitHostError> {
        let number = match target {
            CommentTarget::Issue(issue) => {
                Self::own_repository(scope, &issue.repo)?;
                issue.number
            }
            CommentTarget::PullRequest(pr) => {
                Self::own_repository(scope, &pr.repo)?;
                pr.number
            }
        };
        let cleaned = self.outbound.prepare(TextKind::Markdown, body)?;
        let marker = marker_for(idempotency_key);
        let path = format!("{}/issues/{number}/comments", repo_path(&scope.repo));
        let bot = self.client.minter().app_identity().await?.bot_login;
        let existing = self
            .client
            .get_pages_as(scope, TokenClass::Comment, &path)
            .await?;
        // Only the App's own comment counts: a marker pasted by someone else must not stop the
        // factory from reporting.
        let found = existing.items.iter().find(|comment| {
            comment["body"]
                .as_str()
                .is_some_and(|text| text.contains(&marker))
                && comment["user"]["login"].as_str() == Some(bot.as_str())
        });
        if let Some(id) = found.and_then(|comment| comment["id"].as_u64()) {
            return Ok(CommentRef {
                target: target.clone(),
                id,
            });
        }
        let payload = json!({ "body": format!("{cleaned}\n\n{marker}") });
        let reply = self
            .client
            .call(
                scope,
                TokenClass::Comment,
                Method::Post,
                &path,
                Some(&payload),
                false,
            )
            .await?;
        let id = reply.json["id"].as_u64().ok_or(GitHostError::Unavailable)?;
        Ok(CommentRef {
            target: target.clone(),
            id,
        })
    }

    async fn publish_check(
        &self,
        scope: &GitScope,
        req: CheckRequest,
    ) -> Result<CheckRef, GitHostError> {
        let title = self.outbound.prepare(TextKind::Title, &req.title)?;
        let summary = self.outbound.prepare(TextKind::Markdown, &req.summary)?;
        if title.len() > CHECK_TITLE_LIMIT || summary.len() > CHECK_SUMMARY_LIMIT {
            return Err(GitHostError::Rejected(Rejection::TextBounds));
        }
        if let Some(url) = &req.details_url
            && !self.outbound.link_is_allowed(url.as_str())
        {
            return Err(GitHostError::Rejected(Rejection::Other));
        }
        let (status, conclusion) = match req.status {
            CheckStatus::InProgress => ("in_progress", None),
            CheckStatus::Completed(conclusion) => ("completed", Some(conclusion_name(conclusion))),
        };
        let mut payload = json!({
            "status": status,
            "external_id": req.external_id.as_str(),
            "output": { "title": title, "summary": summary },
        });
        if let Some(conclusion) = conclusion {
            payload["conclusion"] = json!(conclusion);
        }
        if let Some(url) = &req.details_url {
            payload["details_url"] = json!(url.as_str());
        }

        let base = repo_path(&scope.repo);
        let listing = format!(
            "{base}/commits/{}/check-runs?check_name={}&app_id={}&per_page=100",
            req.commit.as_str(),
            percent_encode_component(req.name.as_str()),
            self.app.0
        );
        let existing = self
            .client
            .call(scope, TokenClass::Stage, Method::Get, &listing, None, false)
            .await?;
        let found = existing.json["check_runs"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|run| {
                // Only this App's own check run is updated, never another App's of the same name.
                run["external_id"].as_str() == Some(req.external_id.as_str())
                    && run["name"].as_str() == Some(req.name.as_str())
                    && run["app"]["id"].as_u64() == Some(self.app.0)
            })
            .and_then(|run| run["id"].as_u64());
        let reply = match found {
            Some(id) => {
                self.client
                    .call(
                        scope,
                        TokenClass::Stage,
                        Method::Patch,
                        &format!("{base}/check-runs/{id}"),
                        Some(&payload),
                        false,
                    )
                    .await?
            }
            None => {
                payload["name"] = json!(req.name.as_str());
                payload["head_sha"] = json!(req.commit.as_str());
                self.client
                    .call(
                        scope,
                        TokenClass::Stage,
                        Method::Post,
                        &format!("{base}/check-runs"),
                        Some(&payload),
                        false,
                    )
                    .await?
            }
        };
        reply.json["id"]
            .as_u64()
            .map(|id| CheckRef { id })
            .ok_or(GitHostError::Unavailable)
    }

    async fn pull_request_state(
        &self,
        scope: &GitScope,
        pr: &PullRequestRef,
    ) -> Result<PullRequestState, GitHostError> {
        let value = self.pull_json(scope, pr, true).await?;
        let lifecycle = if value["merged"].as_bool() == Some(true) {
            PullRequestLifecycle::Merged
        } else if value["state"].as_str() == Some("closed") {
            PullRequestLifecycle::Closed
        } else {
            PullRequestLifecycle::Open
        };
        let branch = |v: &Value| {
            BranchName::new(v.as_str().unwrap_or_default()).map_err(|_| GitHostError::Unavailable)
        };
        let head_sha = value["head"]["sha"]
            .as_str()
            .ok_or(GitHostError::Unavailable)?;
        Ok(PullRequestState {
            lifecycle,
            draft: value["draft"].as_bool().unwrap_or(false),
            head: branch(&value["head"]["ref"])?,
            head_sha: CommitSha::parse(head_sha).map_err(|_| GitHostError::Unavailable)?,
            base: branch(&value["base"]["ref"])?,
            body_etag: Self::body_tag(head_sha, value["body"].as_str().unwrap_or_default()),
        })
    }

    async fn revoke_job_tokens(&self, job: JobId) -> Result<(), GitHostError> {
        self.client.minter().revoke_job(job).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gate_that_did_not_run_is_never_a_success() {
        assert_eq!(
            conclusion_for_gate(GateOutcome::Passed),
            CheckConclusion::Success
        );
        assert_eq!(
            conclusion_for_gate(GateOutcome::Failed),
            CheckConclusion::Failure
        );
        assert_eq!(
            conclusion_for_gate(GateOutcome::Blocked),
            CheckConclusion::ActionRequired
        );
        assert_eq!(
            conclusion_for_gate(GateOutcome::NotApplicable),
            CheckConclusion::Neutral
        );
    }

    #[test]
    fn a_stage_conclusion_is_the_worst_of_its_gates() {
        use GateOutcome::{Blocked, Failed, NotApplicable, Passed};
        assert_eq!(
            conclusion_for_gates(&[Passed, Passed]),
            CheckConclusion::Success
        );
        assert_eq!(
            conclusion_for_gates(&[Passed, Blocked]),
            CheckConclusion::ActionRequired
        );
        assert_eq!(
            conclusion_for_gates(&[Blocked, Failed, Passed]),
            CheckConclusion::Failure
        );
        assert_eq!(
            conclusion_for_gates(&[NotApplicable, Passed]),
            CheckConclusion::Success
        );
        // Nothing passed, so nothing was shown: a person is asked, and a required check does not
        // accept it (AUT-8).
        assert_eq!(
            conclusion_for_gates(&[NotApplicable]),
            CheckConclusion::ActionRequired
        );
        assert_eq!(
            conclusion_for_gates(&[NotApplicable, NotApplicable]),
            CheckConclusion::ActionRequired
        );
        assert_eq!(conclusion_for_gates(&[]), CheckConclusion::ActionRequired);
        assert_eq!(
            conclusion_for_gates(&[Blocked]),
            CheckConclusion::ActionRequired
        );
    }

    #[test]
    fn conclusions_use_the_names_a_required_check_accepts() {
        assert_eq!(conclusion_name(CheckConclusion::Success), "success");
        assert_eq!(
            conclusion_name(CheckConclusion::ActionRequired),
            "action_required"
        );
        assert_eq!(conclusion_name(CheckConclusion::Neutral), "neutral");
        assert_eq!(conclusion_name(CheckConclusion::Failure), "failure");
        assert_eq!(conclusion_name(CheckConclusion::Cancelled), "cancelled");
    }

    #[test]
    fn the_comment_marker_depends_on_the_key_and_reveals_nothing_of_it() {
        let marker = marker_for("validation-passed");
        assert_eq!(marker, marker_for("validation-passed"));
        assert_ne!(marker, marker_for("validation-failed"));
        assert!(!marker.contains("validation"));
        assert!(marker.starts_with("<!-- factory-comment:") && marker.ends_with(" -->"));
    }

    #[test]
    fn the_body_tag_changes_with_the_head_and_with_the_text() {
        let a = GithubChangeHost::body_tag("aaaa", "body");
        assert_ne!(a, GithubChangeHost::body_tag("bbbb", "body"));
        assert_ne!(a, GithubChangeHost::body_tag("aaaa", "other"));
        assert_eq!(a, GithubChangeHost::body_tag("aaaa", "body"));
    }
}
