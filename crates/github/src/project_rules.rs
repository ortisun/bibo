//! The project rules host: the draft pull request that installs or updates the project's rules
//! for agents in `AGENTS.md` (ports v1.3, ADR 0026).
//!
//! # What this code does and does not do
//!
//! * **Its own credential.** Every request uses a token narrowed to one repository and to
//!   `contents: write`, `pull_requests: write` and `metadata: read`, minted for this purpose
//!   (`PermissionSet::project_rules`). No stage token is widened and the delivery token is not
//!   borrowed.
//! * **One branch.** Every write names the branch [`RULES_BRANCH`] and no other: the reference
//!   calls are built from that constant, and a file is written with `branch` set to it. The
//!   default branch is only ever the base of the pull request. A base that names the rules branch
//!   itself is refused before any request.
//! * **No merge.** The one `PUT` is [`Method::PutContents`], which the client refuses for any
//!   path but a file of the contents API. The pull request is opened as a draft and never marked
//!   ready.
//! * **Only the factory's own pull requests.** A pull request on the rules branch counts only when
//!   the factory's App opened it (its bot login), so a person cannot steer the decision with a
//!   pull request from a branch of the same name.
//! * **Text is checked first.** The title and the body pass the secret check and the output
//!   hygiene rules before anything is written. The version marker is added after the cleaning,
//!   because the cleaning removes HTML comments.
//! * **Paced.** Every request that changes something waits for the one-second gap GitHub asks of
//!   an integration (the status writer's pacer).
//!
//! # UNVERIFIED against the real GitHub
//!
//! The paths and the answers were read from the REST reference on 2026-11-20 and are tested
//! against the fake GitHub server of the test kit only: `GET /repos/{o}/{r}/branches/{b}`,
//! `GET` and `PUT /repos/{o}/{r}/contents/{path}`, `GET /repos/{o}/{r}/git/ref/heads/{b}`,
//! `POST /repos/{o}/{r}/git/refs`, `PATCH /repos/{o}/{r}/git/refs/heads/{b}`,
//! `GET /repos/{o}/{r}/pulls?state=all&head=...`, `POST` and `PATCH /repos/{o}/{r}/pulls`. Not
//! verified: that a file of more than 1 MB answers with an empty `content` and the encoding `none`
//! (the code reads that as too large either way), and that `merged_at` is set on a merged pull
//! request in the list (the code also accepts `merged: true`).

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::clock::Clock;
use factory_ports::githost::{
    GitHostError, GitScope, PullRequestLifecycle, PullRequestRef, Rejection,
};
use factory_ports::paths::{BranchName, CommitSha, RepoPath};
use factory_ports::project_rules::{
    DefaultBranch, FileAt, ProjectRulesHost, RULES_BRANCH, RulesProposal, RulesPullRequest,
    RulesScope, proposal_marker, proposed_version,
};
use serde_json::{Value, json};

use crate::client::Client;
use crate::core::Sleeper;
use crate::encoding::{base64_decode, base64_encode, percent_encode_component};
use crate::parse::repo_path;
use crate::status::Pacer;
use crate::text::{Outbound, TextKind};
use crate::token::TokenClass;
use crate::wire::Method;

/// The project rules host of the GitHub adapter.
#[derive(Clone)]
pub struct GithubProjectRules {
    client: Arc<Client>,
    outbound: Arc<Outbound>,
    pacer: Arc<Pacer>,
}

impl std::fmt::Debug for GithubProjectRules {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GithubProjectRules")
    }
}

/// A file as the contents API showed it on a branch: its blob id and its bytes.
struct Existing {
    sha: String,
    bytes: Option<Vec<u8>>,
}

impl GithubProjectRules {
    pub(crate) fn new(
        client: Arc<Client>,
        outbound: Arc<Outbound>,
        sleeper: Arc<dyn Sleeper>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            client,
            outbound,
            pacer: Arc::new(Pacer::new(sleeper, clock)),
        }
    }

    /// The scope the token minter sees. `TokenClass::ProjectRules` ignores the stage; the
    /// delivery stage is not named so that nothing can read it as a grant.
    fn git_scope(scope: &RulesScope) -> GitScope {
        GitScope {
            tenant: scope.tenant,
            job: scope.session,
            stage: StageKind::Approval,
            repo: scope.repo.clone(),
        }
    }

    async fn read(&self, scope: &GitScope, target: &str) -> Result<Value, GitHostError> {
        self.client
            .call(
                scope,
                TokenClass::ProjectRules,
                Method::Get,
                target,
                None,
                false,
            )
            .await
            .map(|reply| reply.json)
    }

    async fn change(
        &self,
        scope: &GitScope,
        method: Method,
        target: &str,
        body: &Value,
    ) -> Result<Value, GitHostError> {
        self.pacer.before_change().await;
        let result = self
            .client
            .call(
                scope,
                TokenClass::ProjectRules,
                method,
                target,
                Some(body),
                false,
            )
            .await;
        self.pacer.changed();
        result.map(|reply| reply.json)
    }

    /// The path of a file of the contents API, each segment percent-encoded.
    fn contents_path(scope: &GitScope, path: &RepoPath) -> String {
        let encoded: Vec<String> = path
            .as_str()
            .split('/')
            .map(percent_encode_component)
            .collect();
        format!("{}/contents/{}", repo_path(&scope.repo), encoded.join("/"))
    }

    /// The file at `path` on the commit or branch `reference`, or `None`.
    async fn existing(
        &self,
        scope: &GitScope,
        reference: &str,
        path: &RepoPath,
    ) -> Result<Option<Existing>, GitHostError> {
        let target = format!(
            "{}?ref={}",
            Self::contents_path(scope, path),
            percent_encode_component(reference)
        );
        let value = match self.read(scope, &target).await {
            Ok(value) => value,
            Err(GitHostError::NotFound) => return Ok(None),
            Err(other) => return Err(other),
        };
        if value["type"].as_str() != Some("file") {
            // A directory (a list) or a link: not a file of this name.
            return Ok(None);
        }
        let sha = value["sha"]
            .as_str()
            .ok_or(GitHostError::Unavailable)?
            .to_owned();
        let bytes = if value["encoding"].as_str() == Some("base64") {
            value["content"].as_str().and_then(base64_decode)
        } else {
            None
        };
        Ok(Some(Existing { sha, bytes }))
    }

    /// The newest pull request of the factory's own App on the rules branch.
    async fn latest(&self, scope: &GitScope) -> Result<Option<Value>, GitHostError> {
        let bot = self.client.minter().app_identity().await?.bot_login;
        let target = format!(
            "{}/pulls?state=all&head={}&per_page=100",
            repo_path(&scope.repo),
            percent_encode_component(&format!("{}:{RULES_BRANCH}", scope.repo.owner()))
        );
        let pages = self
            .client
            .get_pages_as(scope, TokenClass::ProjectRules, &target)
            .await?;
        if pages.truncated {
            // A list cut short cannot say which one is the newest.
            return Err(GitHostError::Unavailable);
        }
        Ok(pages
            .items
            .into_iter()
            .filter(|pull| pull["head"]["ref"].as_str() == Some(RULES_BRANCH))
            .filter(|pull| pull["user"]["login"].as_str() == Some(bot.as_str()))
            .filter(|pull| pull["number"].as_u64().is_some())
            .max_by_key(|pull| pull["number"].as_u64().unwrap_or(0)))
    }

    /// Points the rules branch at `commit`: creates it, or moves it there.
    async fn reset_branch(&self, scope: &GitScope, commit: &CommitSha) -> Result<(), GitHostError> {
        let encoded = percent_encode_component(RULES_BRANCH);
        let lookup = format!("{}/git/ref/heads/{encoded}", repo_path(&scope.repo));
        match self.read(scope, &lookup).await {
            Ok(_) => {
                let target = format!("{}/git/refs/heads/{encoded}", repo_path(&scope.repo));
                self.change(
                    scope,
                    Method::Patch,
                    &target,
                    &json!({ "sha": commit.as_str(), "force": true }),
                )
                .await?;
            }
            Err(GitHostError::NotFound) => {
                let target = format!("{}/git/refs", repo_path(&scope.repo));
                self.change(
                    scope,
                    Method::Post,
                    &target,
                    &json!({ "ref": format!("refs/heads/{RULES_BRANCH}"), "sha": commit.as_str() }),
                )
                .await?;
            }
            Err(other) => return Err(other),
        }
        Ok(())
    }
}

fn lifecycle_of(pull: &Value) -> PullRequestLifecycle {
    if pull["state"].as_str() == Some("open") {
        PullRequestLifecycle::Open
    } else if pull["merged"].as_bool() == Some(true) || pull["merged_at"].is_string() {
        PullRequestLifecycle::Merged
    } else {
        PullRequestLifecycle::Closed
    }
}

#[async_trait]
impl ProjectRulesHost for GithubProjectRules {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn default_branch(&self, scope: &RulesScope) -> Result<DefaultBranch, GitHostError> {
        let git = Self::git_scope(scope);
        let repository = self.read(&git, &repo_path(&scope.repo)).await?;
        let name = repository["default_branch"]
            .as_str()
            .and_then(|name| BranchName::new(name).ok())
            .ok_or(GitHostError::Unavailable)?;
        let target = format!(
            "{}/branches/{}",
            repo_path(&scope.repo),
            percent_encode_component(name.as_str())
        );
        let branch = self.read(&git, &target).await?;
        let commit = branch["commit"]["sha"]
            .as_str()
            .and_then(|sha| CommitSha::parse(sha).ok())
            .ok_or(GitHostError::Unavailable)?;
        Ok(DefaultBranch { name, commit })
    }

    async fn read_file(
        &self,
        scope: &RulesScope,
        commit: &CommitSha,
        path: &RepoPath,
        max_bytes: u64,
    ) -> Result<FileAt, GitHostError> {
        let git = Self::git_scope(scope);
        let Some(found) = self.existing(&git, commit.as_str(), path).await? else {
            return Ok(FileAt::Missing);
        };
        // No text (a file over 1 MB answers without one) is too large for any limit we use.
        let Some(bytes) = found.bytes else {
            return Ok(FileAt::TooLarge);
        };
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
            return Ok(FileAt::TooLarge);
        }
        Ok(FileAt::Found(bytes))
    }

    async fn latest_rules_pull_request(
        &self,
        scope: &RulesScope,
    ) -> Result<Option<RulesPullRequest>, GitHostError> {
        let git = Self::git_scope(scope);
        Ok(self.latest(&git).await?.map(|pull| RulesPullRequest {
            pr: PullRequestRef {
                repo: scope.repo.clone(),
                number: pull["number"].as_u64().unwrap_or(0),
            },
            lifecycle: lifecycle_of(&pull),
            proposed_version: pull["body"].as_str().and_then(proposed_version),
        }))
    }

    async fn propose(
        &self,
        scope: &RulesScope,
        proposal: &RulesProposal,
    ) -> Result<PullRequestRef, GitHostError> {
        if proposal.title.trim().is_empty()
            || proposal.body.trim().is_empty()
            || proposal.files.is_empty()
        {
            return Err(GitHostError::Rejected(Rejection::TextBounds));
        }
        if proposal.base.name.as_str() == RULES_BRANCH {
            return Err(GitHostError::BranchNotAllowed);
        }
        // The text first: nothing is written when it holds a secret.
        let title = self.outbound.prepare(TextKind::Title, &proposal.title)?;
        let cleaned = self.outbound.prepare(TextKind::Markdown, &proposal.body)?;
        let body = format!("{cleaned}\n\n{}", proposal_marker(proposal.version));
        let git = Self::git_scope(scope);

        let open = self
            .latest(&git)
            .await?
            .filter(|pull| lifecycle_of(pull) == PullRequestLifecycle::Open)
            .and_then(|pull| pull["number"].as_u64());
        if open.is_none() {
            // A branch left from a merged or declined proposal starts again from the tip.
            self.reset_branch(&git, &proposal.base.commit).await?;
        }
        for file in &proposal.files {
            let existing = self.existing(&git, RULES_BRANCH, &file.path).await?;
            if existing
                .as_ref()
                .is_some_and(|e| e.bytes.as_deref() == Some(file.bytes.as_slice()))
            {
                continue;
            }
            let mut request = json!({
                "message": format!(
                    "Install the factory's rules for agents, version {}: {}",
                    proposal.version,
                    file.path.as_str()
                ),
                "content": base64_encode(&file.bytes),
                "branch": RULES_BRANCH,
            });
            if let (Some(existing), Some(object)) = (existing, request.as_object_mut()) {
                object.insert("sha".into(), json!(existing.sha));
            }
            self.change(
                &git,
                Method::PutContents,
                &Self::contents_path(&git, &file.path),
                &request,
            )
            .await?;
        }

        let pulls = format!("{}/pulls", repo_path(&scope.repo));
        let number = match open {
            Some(number) => number,
            None => {
                let opened = self
                    .change(
                        &git,
                        Method::Post,
                        &pulls,
                        &json!({
                            "title": title,
                            "head": RULES_BRANCH,
                            "base": proposal.base.name.as_str(),
                            "body": body,
                            "draft": true,
                        }),
                    )
                    .await;
                match opened {
                    Ok(made) => {
                        return made["number"]
                            .as_u64()
                            .map(|number| PullRequestRef {
                                repo: scope.repo.clone(),
                                number,
                            })
                            .ok_or(GitHostError::Unavailable);
                    }
                    // Another worker opened it between the look and the open: update that one.
                    Err(GitHostError::Rejected(_)) => self
                        .latest(&git)
                        .await?
                        .filter(|pull| lifecycle_of(pull) == PullRequestLifecycle::Open)
                        .and_then(|pull| pull["number"].as_u64())
                        .ok_or(GitHostError::Rejected(Rejection::Other))?,
                    Err(other) => return Err(other),
                }
            }
        };
        self.change(
            &git,
            Method::Patch,
            &format!("{pulls}/{number}"),
            &json!({ "title": title, "body": body }),
        )
        .await?;
        Ok(PullRequestRef {
            repo: scope.repo.clone(),
            number,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pull_request_is_open_merged_or_closed() {
        assert_eq!(
            lifecycle_of(&json!({"state": "open"})),
            PullRequestLifecycle::Open
        );
        assert_eq!(
            lifecycle_of(&json!({"state": "closed", "merged": true})),
            PullRequestLifecycle::Merged
        );
        assert_eq!(
            lifecycle_of(&json!({"state": "closed", "merged_at": "2026-11-20T10:00:00Z"})),
            PullRequestLifecycle::Merged
        );
        assert_eq!(
            lifecycle_of(&json!({"state": "closed", "merged": false, "merged_at": null})),
            PullRequestLifecycle::Closed
        );
    }
}
