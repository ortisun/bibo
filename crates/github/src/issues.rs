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
//! * `repository_protection` reads the rulesets with the stage token (Metadata read) and classic
//!   branch protection with a token of its own class (`administration: read`, `metadata: read`),
//!   and combines them (see `protection.rs`).
//! * `workflow_files` reads the workflow files of the default branch with the fetch credential
//!   (`contents: read`), never with the stage token (threat T-48; see `workflows.rs`).
//!
//! A scope names one repository. A reference to another repository is `NotFound` before any call
//! is made, and a token for one repository cannot read another in any case.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::Clock;
use factory_ports::githost::{
    Comment, CommentRef, CommentTarget, GitHostError, GitScope, GithubActor, Issue, IssueRef,
    IssueSource, LabelApplication, LabelTimeline, LabeledEvent, ProtectionReport, TextEdit,
    WorkflowFile,
};
use factory_ports::paths::BranchName;

use crate::client::Client;
use crate::edits;
use crate::encoding::percent_encode_component;
use crate::parse::{actor, actor_type, repo_path, timestamp};
use crate::protection::{protection_from_rules, with_classic_protection};
use crate::token::TokenClass;
use crate::wire::Method;
use crate::workflows::{WORKFLOW_DIRECTORY, listed_workflows, text_of, workflow_file};

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

    /// Reads the events of an issue as far as the event page cap allows (30 pages of 100 by
    /// default, three times the cap of other listings, because the design gate has to see the end
    /// of the list). A list that is still not finished then is marked incomplete, and every
    /// question put to it is `Unavailable`.
    async fn label_timeline(
        &self,
        scope: &GitScope,
        issue_path: &str,
    ) -> Result<LabelTimeline, GitHostError> {
        let events = self
            .client
            .get_pages_up_to(
                scope,
                TokenClass::Stage,
                &format!("{issue_path}/events"),
                self.client.event_pages(),
            )
            .await?;
        let labeled = events
            .items
            .iter()
            .map(labeled_event)
            .collect::<Result<Vec<Option<LabeledEvent>>, GitHostError>>()?
            .into_iter()
            .flatten()
            .collect();
        Ok(LabelTimeline::new(labeled, !events.truncated))
    }
}

/// The label names of the `labels` member of an issue. The member must be an array whose items
/// are objects with a string `name`, or strings (the form the API documents for some calls). A
/// member that is missing, null or of another type, or an item of another shape, is an answer that
/// cannot be trusted: it must not read as "no labels", which would put the issue off the design
/// track.
fn label_names(value: &serde_json::Value) -> Result<Vec<String>, GitHostError> {
    value
        .as_array()
        .ok_or(GitHostError::Unavailable)?
        .iter()
        .map(|item| match item {
            serde_json::Value::String(name) => Ok(name.clone()),
            serde_json::Value::Object(_) => item["name"]
                .as_str()
                .map(str::to_owned)
                .ok_or(GitHostError::Unavailable),
            _ => Err(GitHostError::Unavailable),
        })
        .collect()
}

/// One entry of the event list as a `labeled` event, or `None` for an event of another kind. An
/// entry that is not an object, has no `event` string, or is a `labeled` event without a label
/// name or a time, is malformed and fails the whole read.
fn labeled_event(item: &serde_json::Value) -> Result<Option<LabeledEvent>, GitHostError> {
    if !item.is_object() {
        return Err(GitHostError::Unavailable);
    }
    let kind = item["event"].as_str().ok_or(GitHostError::Unavailable)?;
    if kind != "labeled" {
        return Ok(None);
    }
    Ok(Some(LabeledEvent {
        id: item["id"].as_u64(),
        at: timestamp(&item["created_at"])?,
        label: item["label"]["name"]
            .as_str()
            .ok_or(GitHostError::Unavailable)?
            .to_owned(),
        actor: if item["actor"].is_null() {
            None
        } else {
            Some((actor(&item["actor"])?, actor_type(&item["actor"])))
        },
    }))
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
            labels: label_names(&value["labels"])?,
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
        if !label_names(&current.json["labels"])?
            .iter()
            .any(|name| name == label)
        {
            return Ok(None);
        }
        self.label_timeline(scope, &base)
            .await?
            .latest_application(label)
    }

    async fn labels_ever_applied(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
    ) -> Result<Vec<String>, GitHostError> {
        same_repository(scope, &issue.repo)?;
        let base = format!("{}/issues/{}", repo_path(&issue.repo), issue.number);
        self.label_timeline(scope, &base)
            .await?
            .labels_ever_applied()
    }

    async fn text_edit(
        &self,
        scope: &GitScope,
        issue: &IssueRef,
    ) -> Result<TextEdit, GitHostError> {
        same_repository(scope, &issue.repo)?;
        // The body: the one read of GraphQL (see `edits`). A call that fails is an error of the
        // host. An answer that is not a time or an explicit null is not an error of the host and
        // retrying will not change it, so it is "unknown", which the gate refuses on.
        let answer = self
            .client
            .call(
                scope,
                TokenClass::Stage,
                Method::Post,
                edits::ROUTE,
                Some(&edits::request(issue)),
                false,
            )
            .await?;
        let Ok(body) = edits::body_edit(&answer.json) else {
            return Ok(TextEdit::Unknown);
        };
        // The title: the `renamed` events of the issue, read to the end. A list that is cut may
        // hide a later rename, so it answers nothing.
        let base = format!("{}/issues/{}", repo_path(&issue.repo), issue.number);
        let events = self
            .client
            .get_pages_up_to(
                scope,
                TokenClass::Stage,
                &format!("{base}/events"),
                self.client.event_pages(),
            )
            .await?;
        if events.truncated {
            return Ok(TextEdit::Unknown);
        }
        let Ok(title) = edits::title_edit(&events.items) else {
            return Ok(TextEdit::Unknown);
        };
        Ok(edits::later_of(body, title))
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
        let classic_target = format!(
            "{}/branches/{}/protection",
            repo_path(&scope.repo),
            percent_encode_component(default_branch.as_str())
        );
        let report = protection_from_rules(default_branch, &serde_json::Value::Array(rules.items))?;
        // Classic branch protection, with the token of its own class (`administration: read`,
        // `metadata: read`), whatever the stage of the scope. UNVERIFIED against the real GitHub:
        // a 404 is taken for "Branch not protected", the answer the documentation gives for a
        // branch without classic protection. A 403, or a token the code host would not mint
        // because the App lacks the permission, is `Forbidden` and stays an error: a protection
        // the App may not read is never taken for "not protected".
        let classic = match self
            .client
            .call(
                scope,
                TokenClass::ProtectionRead,
                Method::Get,
                &classic_target,
                None,
                true,
            )
            .await
        {
            Ok(reply) => Some(reply.json),
            Err(GitHostError::NotFound) => None,
            Err(error) => return Err(error),
        };
        with_classic_protection(report, classic.as_ref())
    }

    async fn workflow_files(&self, scope: &GitScope) -> Result<Vec<WorkflowFile>, GitHostError> {
        // Every read here carries the fetch credential (`contents: read`), whatever the stage of
        // the scope: the intake token of the preflight cannot read contents and is not widened.
        // The reads are conditional: the preflight repeats them at every job start, and an answer
        // that has not changed does not count against the rate limit.
        let read = |target: String| async move {
            self.client
                .call(scope, TokenClass::Fetch, Method::Get, &target, None, true)
                .await
        };
        let repo = read(repo_path(&scope.repo)).await?;
        let default_branch = repo.json["default_branch"]
            .as_str()
            .and_then(|name| BranchName::new(name).ok())
            .ok_or(GitHostError::Unavailable)?;
        let branch = read(format!(
            "{}/branches/{}",
            repo_path(&scope.repo),
            percent_encode_component(default_branch.as_str())
        ))
        .await?;
        // The list and every file are read at this one commit.
        let commit = branch.json["commit"]["sha"]
            .as_str()
            .filter(|sha| sha.len() >= 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or(GitHostError::Unavailable)?
            .to_owned();
        let contents = |path: &str| {
            let encoded: Vec<String> = path.split('/').map(percent_encode_component).collect();
            format!(
                "{}/contents/{}?ref={commit}",
                repo_path(&scope.repo),
                encoded.join("/")
            )
        };
        let listing = match read(contents(WORKFLOW_DIRECTORY)).await {
            Ok(reply) => reply.json,
            // The branch was read with the same credential, so this is "no such directory".
            Err(GitHostError::NotFound) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut files = Vec::new();
        for listed in listed_workflows(&listing)? {
            let text = if listed.is_file {
                match read(contents(&listed.path)).await {
                    Ok(reply) => text_of(&reply.json),
                    // Listed a moment ago at this commit and gone now: no text, so it counts as
                    // exposed. Any other failure fails the whole read.
                    Err(GitHostError::NotFound) => None,
                    Err(error) => return Err(error),
                }
            } else {
                None
            };
            files.push(workflow_file(&listed, text));
        }
        Ok(files)
    }
}

fn edited_at(
    value: &serde_json::Value,
) -> Result<Option<factory_domain::values::Timestamp>, GitHostError> {
    let created = timestamp(&value["created_at"])?;
    let updated = timestamp(&value["updated_at"])?;
    Ok((updated > created).then_some(updated))
}
