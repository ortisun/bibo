//! The status writer: one `factory: <state>` label and one status comment on the issue a job came
//! from (ports v1.2, ADR 0017).
//!
//! # What this code does and does not do
//!
//! * **Its own credential.** Every request here uses a token narrowed to one repository and to
//!   `issues: write` (and the `metadata: read` that every installation token carries), minted for
//!   this purpose by the same minter as every other token. A stage token is never widened and the
//!   delivery token is never borrowed. See `PermissionSet::issue_status`.
//! * **Only the factory namespace.** The label is a `StatusLabel`, a type that only the policy can
//!   make. This code refuses a name that is not a status label once more before it sends anything
//!   (`Rejected(LabelNotAllowed)`), and it removes only labels that start with `factory: `. The
//!   trigger label `factory` and every `design:` label are never touched.
//! * **One comment, edited in place.** The status comment is found by a hidden marker among the
//!   comments written by the factory's own App. A marker pasted by someone else is not a status
//!   comment: authorship is checked on the login of the App's bot account. If two writers create a
//!   comment at once, both find the lowest-numbered one afterwards and the others delete theirs.
//! * **Newest wins.** The marker carries the stamp of the job version the comment shows. A comment
//!   with a newer stamp is never overwritten ([`CommentWrite::Superseded`]).
//! * **Paced.** GitHub asks an integration that makes many changes to wait at least one second
//!   between requests that change something and to make them one after another, not at once.
//!   Every change here waits for that gap (through the `Sleeper` seam, so a test records the
//!   waits and does not sleep), and the rate-limit back-off of `HttpCore` applies as for every
//!   other call.
//! * **Text is checked first.** The comment passes the secret check and the output hygiene rules
//!   (`text.rs`) before any request. The marker is added after the cleaning, as for every comment
//!   of this crate, because the cleaning removes HTML comments.
//!
//! # UNVERIFIED against the real GitHub
//!
//! The paths and the status codes were read from the REST reference pages on 2026-11-02. Not
//! verified, because no App is registered and nothing here has run against the real service:
//!
//! * that adding a label that does not exist in the repository creates it (the installer creates
//!   the labels first, so this code does not depend on it);
//! * which status `DELETE .../labels/{name}` answers for a label that exists but is not on the
//!   issue (this code treats every 404 as "already gone");
//! * that the comment list always carries `user.login` of an App as `<slug>[bot]` (the adapter's
//!   comment lookup already relies on it);
//! * the secondary rate limit numbers. The page gives none; the pause and the budget of the
//!   worker are conservative guesses.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::policy::issue_workflow::{STATUS_PREFIX, StatusLabel, check_status_label_name};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::clock::Clock;
use factory_ports::githost::{
    CommentRef, CommentTarget, GitHostError, GitScope, IssueRef, Rejection,
};
use factory_ports::issue_status::{
    CommentWrite, IssueStatusWriter, LabelOutcome, StatusComment, StatusScope, StatusStamp,
};
use serde_json::{Value, json};

use crate::client::Client;
use crate::core::Sleeper;
use crate::encoding::percent_encode_component;
use crate::parse::repo_path;
use crate::text::{Outbound, TextKind};
use crate::token::TokenClass;
use crate::wire::Method;

/// The gap left between two requests that change something.
pub const MUTATION_PAUSE: Duration = Duration::from_secs(1);

/// One comment of the factory's own App that carries a status marker.
#[derive(Debug, Clone)]
struct OwnComment {
    id: u64,
    body: String,
}

/// Leaves a gap between requests that change something. The triage issue writer (`triage.rs`)
/// and the rules host (`project_rules.rs`) pace their writes with it too.
pub(crate) struct Pacer {
    sleeper: Arc<dyn Sleeper>,
    clock: Arc<dyn Clock>,
    last_change: Mutex<Option<Timestamp>>,
}

impl Pacer {
    /// A pacer that has made no change yet.
    pub(crate) fn new(sleeper: Arc<dyn Sleeper>, clock: Arc<dyn Clock>) -> Self {
        Self {
            sleeper,
            clock,
            last_change: Mutex::new(None),
        }
    }

    pub(crate) async fn before_change(&self) {
        let last = *self
            .last_change
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(last) = last {
            let waited = self.clock.now().duration_since(&last).unwrap_or_default();
            if waited < MUTATION_PAUSE {
                self.sleeper.sleep(MUTATION_PAUSE - waited).await;
            }
        }
    }

    pub(crate) fn changed(&self) {
        *self
            .last_change
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(self.clock.now());
    }
}

/// The status writer of the GitHub adapter.
#[derive(Clone)]
pub struct GithubIssueStatus {
    client: Arc<Client>,
    outbound: Arc<Outbound>,
    pacer: Arc<Pacer>,
}

impl std::fmt::Debug for GithubIssueStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GithubIssueStatus")
    }
}

impl GithubIssueStatus {
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

    /// The scope the token minter sees. The stage is not used for the credential of this port
    /// (`TokenClass::IssueStatus` ignores it); the delivery stage is not named so that nothing can
    /// read it as a grant.
    fn git_scope(scope: &StatusScope, issue: &IssueRef) -> Result<GitScope, GitHostError> {
        // Names on GitHub are not case sensitive; the comparison is not either (STS-8).
        if !scope.repo.same_repository(&issue.repo) {
            return Err(GitHostError::NotFound);
        }
        Ok(GitScope {
            tenant: scope.tenant,
            job: scope.session,
            stage: StageKind::Approval,
            repo: scope.repo.clone(),
        })
    }

    async fn change(
        &self,
        scope: &GitScope,
        method: Method,
        target: &str,
        body: Option<&Value>,
    ) -> Result<Value, GitHostError> {
        self.pacer.before_change().await;
        let result = self
            .client
            .call(scope, TokenClass::IssueStatus, method, target, body, false)
            .await;
        // A request that was sent counts, whatever the answer: the gap is measured from it.
        self.pacer.changed();
        result.map(|reply| reply.json)
    }

    /// The status comments of the App's own account on the issue, lowest id first. `truncated`
    /// is true when the listing is longer than the page cap.
    async fn own_comments(
        &self,
        scope: &GitScope,
        number: u64,
        bot: &str,
    ) -> Result<(Vec<OwnComment>, bool), GitHostError> {
        let path = format!("{}/issues/{number}/comments", repo_path(&scope.repo));
        let pages = self
            .client
            .get_pages_as(scope, TokenClass::IssueStatus, &path)
            .await?;
        let mut own: Vec<OwnComment> = pages
            .items
            .iter()
            .filter(|comment| comment["user"]["login"].as_str() == Some(bot))
            .filter_map(|comment| {
                let body = comment["body"].as_str()?;
                StatusStamp::mentions_marker(body).then(|| OwnComment {
                    id: comment["id"].as_u64().unwrap_or(0),
                    body: body.to_owned(),
                })
            })
            .filter(|comment| comment.id != 0)
            .collect();
        own.sort_by_key(|comment| comment.id);
        Ok((own, pages.truncated))
    }

    async fn delete_comment(&self, scope: &GitScope, id: u64) {
        let target = format!("{}/issues/comments/{id}", repo_path(&scope.repo));
        // Best effort. A comment that stays is found again by the next call.
        let _ = self.change(scope, Method::Delete, &target, None).await;
    }
}

/// Line endings and trailing space are not content.
fn same_text(a: &str, b: &str) -> bool {
    a.replace("\r\n", "\n").trim_end() == b.replace("\r\n", "\n").trim_end()
}

#[async_trait]
impl IssueStatusWriter for GithubIssueStatus {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn set_status_label(
        &self,
        scope: &StatusScope,
        issue: &IssueRef,
        label: &StatusLabel,
    ) -> Result<LabelOutcome, GitHostError> {
        // The second check. The type already keeps a wrong label out; this one stops a value
        // that got past it, and it runs before any request, including the one for a token.
        check_status_label_name(label.as_str())
            .map_err(|_| GitHostError::Rejected(Rejection::LabelNotAllowed))?;
        let git = Self::git_scope(scope, issue)?;
        let path = format!("{}/issues/{}/labels", repo_path(&scope.repo), issue.number);
        let current = self
            .client
            .get_pages_as(&git, TokenClass::IssueStatus, &path)
            .await?;
        if current.truncated {
            // A list that is cut short cannot say which labels to take off.
            return Err(GitHostError::Unavailable);
        }
        let names: Vec<&str> = current
            .items
            .iter()
            .filter_map(|item| item["name"].as_str())
            .collect();
        let wanted = label.as_str();

        // Add first, then take off: the issue is never left without a status label.
        let present = names.iter().any(|name| name.eq_ignore_ascii_case(wanted));
        if !present {
            self.change(
                &git,
                Method::Post,
                &path,
                Some(&json!({ "labels": [wanted] })),
            )
            .await?;
        }
        let mut removed = 0_u32;
        for name in names {
            let in_namespace = name
                .get(..STATUS_PREFIX.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(STATUS_PREFIX));
            if !in_namespace || name.eq_ignore_ascii_case(wanted) {
                continue;
            }
            let target = format!("{path}/{}", percent_encode_component(name));
            match self.change(&git, Method::Delete, &target, None).await {
                Ok(_) => removed += 1,
                // Already gone: someone took it off, or an earlier call did.
                Err(GitHostError::NotFound) => {}
                Err(other) => return Err(other),
            }
        }
        Ok(LabelOutcome {
            added: !present,
            removed,
        })
    }

    async fn upsert_status_comment(
        &self,
        scope: &StatusScope,
        issue: &IssueRef,
        comment: &StatusComment,
    ) -> Result<CommentWrite, GitHostError> {
        let git = Self::git_scope(scope, issue)?;
        let cleaned = self.outbound.prepare(TextKind::Markdown, comment.body())?;
        let stamp = *comment.stamp();
        let full = format!("{cleaned}\n\n{}", stamp.marker());
        let reference = |id: u64| CommentRef {
            target: CommentTarget::Issue(issue.clone()),
            id,
        };
        let bot = self.client.minter().app_identity().await?.bot_login;
        let comments_path = format!(
            "{}/issues/{}/comments",
            repo_path(&scope.repo),
            issue.number
        );

        let (mut own, truncated) = self.own_comments(&git, issue.number, &bot).await?;
        if own.is_empty() {
            if truncated {
                // Not finding the comment in a listing that was cut short is not proof that it is
                // not there. A second comment is worse than a missing update.
                return Err(GitHostError::Unavailable);
            }
            let made = self
                .change(
                    &git,
                    Method::Post,
                    &comments_path,
                    Some(&json!({ "body": full })),
                )
                .await?;
            let id = made["id"].as_u64().ok_or(GitHostError::Unavailable)?;
            // Another writer may have made one at the same moment. Look again: the lowest id is
            // the status comment, and the others are deleted by whoever finds them.
            let (again, _) = self.own_comments(&git, issue.number, &bot).await?;
            match again.first() {
                Some(first) if first.id != id => {
                    self.delete_comment(&git, id).await;
                    own = again;
                }
                _ => return Ok(CommentWrite::Created(reference(id))),
            }
        }

        let Some(canonical) = own.first().cloned() else {
            return Err(GitHostError::Unavailable);
        };
        for extra in own.iter().skip(1) {
            self.delete_comment(&git, extra.id).await;
        }
        Ok(match StatusStamp::from_text(&canonical.body) {
            Some(shown) if shown > stamp => CommentWrite::Superseded(reference(canonical.id)),
            Some(shown) if shown == stamp && same_text(&canonical.body, &full) => {
                CommentWrite::Unchanged(reference(canonical.id))
            }
            _ => {
                let target = format!(
                    "{}/issues/comments/{}",
                    repo_path(&scope.repo),
                    canonical.id
                );
                match self
                    .change(&git, Method::Patch, &target, Some(&json!({ "body": full })))
                    .await
                {
                    Ok(_) => CommentWrite::Updated(reference(canonical.id)),
                    // Deleted between the listing and the edit. The next call makes a new one.
                    Err(GitHostError::NotFound) => return Err(GitHostError::Conflict),
                    Err(other) => return Err(other),
                }
            }
        })
    }
}
