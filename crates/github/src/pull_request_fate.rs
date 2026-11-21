//! [`PullRequestFateSource`] for GitHub: what became of a pull request the factory opened (ports
//! v1.5, ADR 0029).
//!
//! # One read, and nothing else
//!
//! `GET /repos/{owner}/{repo}/pulls/{number}` with a token of [`TokenClass::PullRequestFate`]:
//! `metadata: read` and `pull_requests: read` for the one repository of the scope
//! ([`PermissionSet::pull_request_reader`](crate::permissions::PermissionSet::pull_request_reader)).
//! The class does not depend on a stage, and the scope names a session and not a job, because the
//! fate is read after the job has ended and a job that has ended can never mint again. This type
//! has no method that writes.
//!
//! # How the answer is read
//!
//! | The answer | The fate |
//! |---|---|
//! | `state` is `open` | open, with no time |
//! | `merged` is true, or `merged_at` is a time | merged, at `merged_at` |
//! | `state` is `closed` and it was not merged | closed, at `closed_at` |
//!
//! A merged or closed pull request whose time is missing or cannot be read is `Unavailable`: a
//! fate without its time is not reported. Any other `state` is `Unavailable` too.
//!
//! # What was checked, and what was not
//!
//! Against the fake GitHub server of the test kit (FX-GH) only. **Not verified against the real
//! GitHub.** The fields come from GitHub's REST documentation of "Get a pull request": `state`,
//! `merged`, `merged_at` and `closed_at`, the times in ISO 8601 with a `Z`.

use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::githost::{GitHostError, GitScope, PullRequestRef};
use factory_ports::pull_request_fate::{FateScope, ObservedPullRequest, PullRequestFateSource};
use serde_json::Value;

use crate::client::Client;
use crate::parse::repo_path;
use crate::token::TokenClass;
use crate::wire::Method;

/// The fate reader of the GitHub adapter.
#[derive(Clone)]
pub struct GithubPullRequestFates {
    client: Arc<Client>,
}

impl std::fmt::Debug for GithubPullRequestFates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GithubPullRequestFates")
    }
}

impl GithubPullRequestFates {
    pub(crate) fn new(client: Arc<Client>) -> Self {
        Self { client }
    }

    /// The scope the token minter sees. `TokenClass::PullRequestFate` ignores the stage; the
    /// delivery stage is not named so that nothing can read it as a grant.
    fn git_scope(scope: &FateScope) -> GitScope {
        GitScope {
            tenant: scope.tenant,
            job: scope.session,
            stage: StageKind::Approval,
            repo: scope.repo.clone(),
        }
    }
}

/// The time in `field` of a pull request, or `Unavailable` when it is missing or not a time.
fn time_of(pull: &Value, field: &str) -> Result<Timestamp, GitHostError> {
    pull[field]
        .as_str()
        .and_then(|text| Timestamp::parse(text).ok())
        .ok_or(GitHostError::Unavailable)
}

/// Reads the fate from the answer of `GET /repos/{owner}/{repo}/pulls/{number}`.
pub(crate) fn fate_of(pull: &Value) -> Result<ObservedPullRequest, GitHostError> {
    match pull["state"].as_str() {
        Some("open") => Ok(ObservedPullRequest::OPEN),
        Some("closed") => {
            if pull["merged"].as_bool() == Some(true) || pull["merged_at"].is_string() {
                time_of(pull, "merged_at").map(ObservedPullRequest::merged)
            } else {
                time_of(pull, "closed_at").map(ObservedPullRequest::closed)
            }
        }
        _ => Err(GitHostError::Unavailable),
    }
}

#[async_trait]
impl PullRequestFateSource for GithubPullRequestFates {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    async fn observe(
        &self,
        scope: &FateScope,
        pr: &PullRequestRef,
    ) -> Result<ObservedPullRequest, GitHostError> {
        // The credential covers the repository of the scope and no other.
        if pr.repo != scope.repo {
            return Err(GitHostError::NotFound);
        }
        let target = format!("{}/pulls/{}", repo_path(&pr.repo), pr.number);
        let reply = self
            .client
            .call(
                &Self::git_scope(scope),
                TokenClass::PullRequestFate,
                Method::Get,
                &target,
                None,
                false,
            )
            .await?;
        fate_of(&reply.json)
    }
}

#[cfg(test)]
mod tests {
    use factory_ports::githost::PullRequestLifecycle;
    use serde_json::json;

    use super::*;

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a time")
    }

    #[test]
    fn an_open_pull_request_has_no_time() {
        let seen = fate_of(&json!({ "state": "open", "merged": false, "merged_at": null }));
        assert_eq!(seen, Ok(ObservedPullRequest::OPEN));
    }

    #[test]
    fn a_merged_pull_request_carries_the_time_of_the_merge_not_of_the_close() {
        let pull = json!({
            "state": "closed", "merged": true,
            "merged_at": "2026-11-20T08:00:00Z", "closed_at": "2026-11-20T08:00:01Z",
        });
        let seen = fate_of(&pull).expect("a fate");
        assert_eq!(seen.lifecycle(), PullRequestLifecycle::Merged);
        assert_eq!(seen.decided_at(), Some(at("2026-11-20T08:00:00Z")));
        // The list form of a pull request has no `merged` member; `merged_at` alone says it.
        let listed = json!({ "state": "closed", "merged_at": "2026-11-20T08:00:00Z" });
        assert_eq!(fate_of(&listed), Ok(seen));
    }

    #[test]
    fn a_pull_request_closed_without_a_merge_carries_the_time_of_the_close() {
        let pull = json!({
            "state": "closed", "merged": false, "merged_at": null,
            "closed_at": "2026-11-20T09:30:00Z",
        });
        let seen = fate_of(&pull).expect("a fate");
        assert_eq!(seen.lifecycle(), PullRequestLifecycle::Closed);
        assert_eq!(seen.decided_at(), Some(at("2026-11-20T09:30:00Z")));
    }

    #[test]
    fn a_fate_without_its_time_or_with_an_unknown_state_is_not_reported() {
        for pull in [
            json!({ "state": "closed", "merged": true, "merged_at": null }),
            json!({ "state": "closed", "merged": true }),
            json!({ "state": "closed", "merged": false, "closed_at": null }),
            json!({ "state": "closed", "merged": false, "closed_at": "yesterday" }),
            json!({ "state": "closed", "merged": false, "closed_at": 5 }),
            json!({ "state": "draft" }),
            json!({ "state": null }),
            json!({}),
            json!([]),
        ] {
            assert_eq!(fate_of(&pull), Err(GitHostError::Unavailable), "{pull}");
        }
    }
}
