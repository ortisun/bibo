//! The issue source: issues, comments, label authors and the repository's rules, always read live.
//!
//! Nothing here authorizes anyone. The caller matches [`GithubActor::id`] against the named
//! allowlist. This code only reports, faithfully, the numeric id of the person.
//!
//! * `fetch_issue` returns the title and body exactly as GitHub holds them. Cleaning text for
//!   display or for a prompt is a separate step ([`normalize_untrusted_text`]); the original is
//!   never replaced by it.
//! * `label_actor` reads the issue's event list, the only place the API says who applied a label.
//!   The webhook's `sender` is never used for this.
//! * `repository_protection` reads the rulesets with the Metadata permission only.
//!
//! A scope names one repository. A reference to another repository is `NotFound` before any call
//! is made, and a token for one repository cannot read another in any case.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::Clock;
use factory_ports::githost::{
    Comment, CommentRef, CommentTarget, GitHostError, GitScope, GithubActor, Issue, IssueRef,
    IssueSource, LabelApplication, ProtectionReport,
};
use factory_ports::paths::BranchName;

use crate::client::Client;
use crate::encoding::percent_encode_component;
use crate::parse::{actor, repo_path, timestamp};
use crate::protection::protection_from_rules;

/// Issue text as read, next to the cleaned form that is safe to put in front of a model or a
/// person. The original is the record; the cleaned form is never used to decide anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedText {
    /// The text exactly as written.
    pub original: String,
    /// The text with hidden characters and control characters removed and line endings made
    /// uniform.
    pub normalized: String,
}

/// Removes zero-width and bidirectional characters, control characters other than newline and
/// tab, and turns every line ending into `\n`. Keeps the original beside the result.
#[must_use]
pub fn normalize_untrusted_text(original: &str) -> NormalizedText {
    let unified = original.replace("\r\n", "\n").replace('\r', "\n");
    let normalized = unified
        .chars()
        .filter(|c| {
            !matches!(c,
                '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}' | '\u{061c}' | '\u{feff}' | '\u{00ad}')
                && (!c.is_control() || *c == '\n' || *c == '\t')
        })
        .collect();
    NormalizedText {
        original: original.to_owned(),
        normalized,
    }
}

/// The issue source of the GitHub adapter.
#[derive(Clone)]
pub struct GithubIssueSource {
    client: Arc<Client>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for GithubIssueSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GithubIssueSource")
    }
}

impl GithubIssueSource {
    pub(crate) fn new(client: Arc<Client>, clock: Arc<dyn Clock>) -> Self {
        Self { client, clock }
    }
}

fn same_repository(
    scope: &GitScope,
    repo: &factory_ports::paths::RepoRef,
) -> Result<(), GitHostError> {
    if &scope.repo == repo {
        Ok(())
    } else {
        Err(GitHostError::NotFound)
    }
}

#[async_trait]
impl IssueSource for GithubIssueSource {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn fetch_issue(&self, scope: &GitScope, issue: &IssueRef) -> Result<Issue, GitHostError> {
        same_repository(scope, &issue.repo)?;
        let reply = self
            .client
            .get(
                scope,
                &format!("{}/issues/{}", repo_path(&issue.repo), issue.number),
            )
            .await?;
        let value = reply.json;
        // GitHub keeps an issue record for every pull request. A pull request is not an issue.
        if value.get("pull_request").is_some() {
            return Err(GitHostError::NotFound);
        }
        Ok(Issue {
            reference: issue.clone(),
            title: value["title"].as_str().unwrap_or_default().to_owned(),
            body: value["body"].as_str().unwrap_or_default().to_owned(),
            author: actor(&value["user"])?,
            labels: value["labels"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|label| label["name"].as_str().map(str::to_owned))
                .collect(),
            updated_at: timestamp(&value["updated_at"])?,
            fetched_at: self.clock.now(),
        })
    }

    async fn fetch_comment(
        &self,
        scope: &GitScope,
        comment: &CommentRef,
    ) -> Result<Comment, GitHostError> {
        let number = match &comment.target {
            CommentTarget::Issue(issue) => {
                same_repository(scope, &issue.repo)?;
                issue.number
            }
            CommentTarget::PullRequest(pr) => {
                same_repository(scope, &pr.repo)?;
                pr.number
            }
        };
        let reply = self
            .client
            .get(
                scope,
                &format!("{}/issues/comments/{}", repo_path(&scope.repo), comment.id),
            )
            .await?;
        let value = reply.json;
        // The comment must belong to the issue or pull request the caller names. Without this a
        // command comment could be replayed on another item.
        let belongs = value["issue_url"]
            .as_str()
            .and_then(|url| url.rsplit('/').next())
            .and_then(|last| last.parse::<u64>().ok())
            == Some(number);
        if !belongs || value["id"].as_u64() != Some(comment.id) {
            return Err(GitHostError::NotFound);
        }
        Ok(Comment {
            reference: comment.clone(),
            author: actor(&value["user"])?,
            body: value["body"].as_str().unwrap_or_default().to_owned(),
            created_at: timestamp(&value["created_at"])?,
            edited_at: edited_at(&value)?,
        })
    }

    async fn label_actor(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
        label: &str,
    ) -> Result<Option<GithubActor>, GitHostError> {
        Ok(self
            .label_application(scope, issue, label)
            .await?
            .map(|application| application.actor))
    }

    async fn label_application(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
        label: &str,
    ) -> Result<Option<LabelApplication>, GitHostError> {
        same_repository(scope, &issue.repo)?;
        let base = format!("{}/issues/{}", repo_path(&issue.repo), issue.number);
        // The label must be on the issue now. A label that was applied and removed is not one.
        let current = self.client.get(scope, &base).await?;
        let present = current.json["labels"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|l| l["name"].as_str() == Some(label));
        if !present {
            return Ok(None);
        }
        let events = self
            .client
            .get_pages(scope, &format!("{base}/events"))
            .await?;
        // The latest `labeled` event for this label is the one that put it there now.
        let latest = events.items.iter().rev().find(|e| {
            e["event"].as_str() == Some("labeled") && e["label"]["name"].as_str() == Some(label)
        });
        match latest {
            Some(event) if !event["actor"].is_null() => Ok(Some(LabelApplication {
                actor: actor(&event["actor"])?,
                applied_at: Some(timestamp(&event["created_at"])?),
            })),
            // Present, but nobody is named for it: nobody is credited with it.
            Some(_) => Ok(None),
            // The list was cut short and the event may be further on: do not guess.
            None if events.truncated => Err(GitHostError::Unavailable),
            None => Ok(None),
        }
    }

    async fn repository_protection(
        &self,
        scope: &GitScope,
    ) -> Result<ProtectionReport, GitHostError> {
        let repo = self.client.get(scope, &repo_path(&scope.repo)).await?;
        let default_branch = repo.json["default_branch"]
            .as_str()
            .and_then(|name| BranchName::new(name).ok())
            .ok_or(GitHostError::Unavailable)?;
        let rules = self
            .client
            .get_pages(
                scope,
                &format!(
                    "{}/rules/branches/{}",
                    repo_path(&scope.repo),
                    percent_encode_component(default_branch.as_str())
                ),
            )
            .await?;
        if rules.truncated {
            // Rules we could not read are rules we cannot rely on.
            return Err(GitHostError::Unavailable);
        }
        protection_from_rules(default_branch, &serde_json::Value::Array(rules.items))
    }
}

fn edited_at(
    value: &serde_json::Value,
) -> Result<Option<factory_domain::values::Timestamp>, GitHostError> {
    let created = timestamp(&value["created_at"])?;
    let updated = timestamp(&value["updated_at"])?;
    Ok((updated > created).then_some(updated))
}
