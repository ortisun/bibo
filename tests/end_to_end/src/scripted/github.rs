//! The fake GitHub server (FX-GH) as the scripted wiring uses it: the fixture repository, its
//! protection, the issue, the installation tokens, the pull request and the comments.
//!
//! What the evidence says about GitHub is read back from the fake's own records, not from what the
//! scripted stages report. FX-GH labels itself a fake (`X-Factory-Fidelity: fake`).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use factory_testkit::fx::github::{FakeGithub, GithubServer, Protection, User};
use factory_testkit::fx::http::send_request;
use serde_json::{Value, json};

use crate::evidence::{
    CheckRun, Commit, GithubEvidence, GithubRequest, ProtectionFacts, PullRequest,
    RequiredCheckFacts, TokenRecord,
};

/// The fixture repository on the fake.
pub const REPO: &str = "example-org/word-count";
/// The login of the person who files the issue.
pub const REQUESTER: &str = "requester-bruno";
/// The login of a person who is not on the allowlist.
pub const STRANGER: &str = "stranger-carla";

/// The fake server and what the scripted run did to it.
pub struct Remote {
    fake: FakeGithub,
    server: GithubServer,
    app_id: u64,
    base_before: String,
    commits: Vec<Commit>,
    head_files: BTreeMap<String, String>,
    check_runs: Vec<CheckRun>,
    code_owner_review: bool,
    protection: Protection,
    /// The token the harness reads with, and the requests it made. They are not the factory's and
    /// are left out of the evidence.
    harness_token: RefCell<Option<(String, u64)>>,
    harness_requests: RefCell<BTreeSet<u64>>,
}

impl Remote {
    /// A fake GitHub with the fixture repository, its installation and the given protection.
    ///
    /// # Panics
    /// When the loopback server cannot start.
    #[must_use]
    pub fn new(protection: impl FnOnce(u64) -> Protection) -> Self {
        let fake = FakeGithub::new();
        let app_id = fake.app().id;
        fake.add_repo(REPO, "main");
        fake.add_installation(1, "example-org", &[REPO]);
        fake.add_user(User::person(REQUESTER, 1001, "write", "MEMBER"));
        fake.add_user(User::person(STRANGER, 1002, "read", "NONE"));
        let protection = protection(app_id);
        fake.protect_branch(REPO, "main", protection.clone());
        let server = fake.serve().expect("the loopback server starts");
        let base_before = fake.branch_sha(REPO, "main").unwrap_or_default();
        Self {
            fake,
            server,
            app_id,
            base_before,
            commits: Vec::new(),
            head_files: BTreeMap::new(),
            check_runs: Vec::new(),
            // FX-GH does not model the code owner review rule, so the scripted wiring states it.
            code_owner_review: true,
            protection,
            harness_token: RefCell::new(None),
            harness_requests: RefCell::new(BTreeSet::new()),
        }
    }

    /// The fake itself, for the canary sweep and the recorders.
    #[must_use]
    pub fn fake(&self) -> &FakeGithub {
        &self.fake
    }

    /// The protection of the base branch, as the fake holds it.
    ///
    /// The fake answers a protection request only for a token with the administration permission,
    /// which the factory's App must not hold, so the scripted wiring keeps the protection it
    /// installed and reads the facts from that. The code owner rule is stated by the scripted
    /// wiring because the fake does not model it.
    #[must_use]
    pub fn protection(&self) -> ProtectionFacts {
        let p = &self.protection;
        ProtectionFacts {
            require_pull_request: p.require_pull_request,
            required_approvals: p.required_approvals,
            required_checks: p
                .required_checks
                .iter()
                .map(|check| RequiredCheckFacts {
                    context: check.context.clone(),
                    pinned_to_app: check.app_id == Some(self.app_id),
                })
                .collect(),
            dismiss_stale_reviews: p.dismiss_stale_reviews,
            enforce_admins: p.enforce_admins,
            allow_force_pushes: p.allow_force_pushes,
            allow_deletions: p.allow_deletions,
            require_code_owner_review: self.code_owner_review,
            app_may_bypass: !p.bypass_apps.is_empty(),
        }
    }

    /// Files an issue as `author`, with the labels, and returns its number.
    #[must_use]
    pub fn file_issue(&self, title: &str, body: &str, author: &str, labels: &[&str]) -> u64 {
        self.fake.add_issue(REPO, title, body, author, labels)
    }

    /// The body of an issue as GitHub holds it, read with the harness's own token.
    #[must_use]
    pub fn issue_body(&self, number: u64) -> String {
        let response = self.harness_get(&format!("/repos/{REPO}/issues/{number}"));
        response
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    fn last_request_seq(&self) -> u64 {
        self.fake.requests().last().map_or(0, |record| record.seq)
    }

    /// Reads with a token that belongs to the harness, not to the factory. The token and the
    /// requests are remembered so that the evidence leaves them out.
    fn harness_get(&self, path: &str) -> Value {
        if self.harness_token.borrow().is_none() {
            let token = self.mint_token(&[("metadata", "read"), ("issues", "read")]);
            let mint_seq = self.last_request_seq();
            let id = self.fake.tokens().last().map_or(0, |t| t.id);
            self.harness_requests.borrow_mut().insert(mint_seq);
            *self.harness_token.borrow_mut() = Some((token, id));
        }
        let token = self
            .harness_token
            .borrow()
            .as_ref()
            .map(|(token, _)| token.clone())
            .unwrap_or_default();
        let auth = format!("token {token}");
        let value = send_request(
            self.server.addr(),
            "GET",
            path,
            &[
                ("Authorization", auth.as_str()),
                ("Accept", "application/vnd.github+json"),
            ],
            b"",
        )
        .ok()
        .and_then(|response| response.json())
        .unwrap_or(Value::Null);
        let seq = self.last_request_seq();
        self.harness_requests.borrow_mut().insert(seq);
        value
    }

    /// Mints an installation token narrowed to the fixture repository and the given permissions,
    /// as the factory does for one stage.
    ///
    /// # Panics
    /// When the fake refuses the request.
    #[must_use]
    pub fn mint_token(&self, permissions: &[(&str, &str)]) -> String {
        let jwt = self.fake.sample_app_jwt();
        let bearer = format!("Bearer {jwt}");
        let permissions: BTreeMap<&str, &str> = permissions.iter().copied().collect();
        let body = json!({ "repositories": ["word-count"], "permissions": permissions });
        let response = send_request(
            self.server.addr(),
            "POST",
            "/app/installations/1/access_tokens",
            &[
                ("Authorization", bearer.as_str()),
                ("Accept", "application/vnd.github+json"),
                ("Content-Type", "application/json"),
            ],
            body.to_string().as_bytes(),
        )
        .expect("the fake answers");
        assert_eq!(response.status, 201, "token mint: {}", response.text());
        response
            .json()
            .and_then(|v| v.get("token").and_then(Value::as_str).map(str::to_owned))
            .expect("a token in the answer")
    }

    fn post(&self, path: &str, token: &str, body: &Value) -> Value {
        let auth = format!("token {token}");
        let response = send_request(
            self.server.addr(),
            "POST",
            path,
            &[
                ("Authorization", auth.as_str()),
                ("Accept", "application/vnd.github+json"),
                ("Content-Type", "application/json"),
            ],
            body.to_string().as_bytes(),
        )
        .expect("the fake answers");
        response.json().unwrap_or(Value::Null)
    }

    /// Posts a comment on an issue or a pull request, with the token.
    pub fn comment(&self, token: &str, number: u64, text: &str) {
        let _ = self.post(
            &format!("/repos/{REPO}/issues/{number}/comments"),
            token,
            &json!({ "body": text }),
        );
    }

    /// Pushes a commit to the head branch and remembers which paths it changes.
    pub fn push(&mut self, branch: &str, message: &str, paths: &[&str]) -> String {
        let sha = self.fake.push_commit(REPO, branch);
        self.commits.push(Commit {
            sha: sha.clone(),
            message: message.to_owned(),
            paths: paths.iter().map(|p| (*p).to_owned()).collect(),
        });
        sha
    }

    /// Remembers the hash of a file on the head branch.
    pub fn remember_file(&mut self, path: &str, sha256: &str) {
        self.head_files.insert(path.to_owned(), sha256.to_owned());
    }

    /// Opens a draft pull request from `branch` and returns its number.
    pub fn open_draft_pull(&self, token: &str, branch: &str, title: &str, body: &str) -> u64 {
        let answer = self.post(
            &format!("/repos/{REPO}/pulls"),
            token,
            &json!({ "title": title, "head": branch, "base": "main", "body": body, "draft": true }),
        );
        answer.get("number").and_then(Value::as_u64).unwrap_or(0)
    }

    /// Records a passing check run on the head commit, as the factory's App does.
    pub fn check_run(&mut self, sha: &str, name: &str, conclusion: &str) {
        self.fake
            .add_check_run(REPO, sha, name, conclusion, self.app_id);
        self.check_runs.push(CheckRun {
            name: name.to_owned(),
            conclusion: conclusion.to_owned(),
            head_sha: sha.to_owned(),
        });
    }

    /// What GitHub holds now, read back from the fake.
    #[must_use]
    pub fn evidence(&self, issue_number: u64) -> GithubEvidence {
        let mut pull_requests = Vec::new();
        let mut comments = self.fake.comments(REPO, issue_number);
        for number in self.fake.pull_numbers(REPO) {
            if let Some(pull) = self.fake.pull_json(REPO, number) {
                pull_requests.push(PullRequest {
                    number,
                    draft: pull.get("draft").and_then(Value::as_bool).unwrap_or(false),
                    merged: pull.get("merged").and_then(Value::as_bool).unwrap_or(false),
                    state: pull
                        .get("state")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    head_branch: pull
                        .pointer("/head/ref")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    head_sha: pull
                        .pointer("/head/sha")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    title: pull
                        .get("title")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    body: pull
                        .get("body")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                });
                comments.extend(self.fake.comments(REPO, number));
            }
        }
        let changed_paths: Vec<String> = {
            let mut paths: Vec<String> =
                self.commits.iter().flat_map(|c| c.paths.clone()).collect();
            paths.sort();
            paths.dedup();
            paths
        };
        GithubEvidence {
            repository: REPO.to_owned(),
            base_branch: "main".to_owned(),
            base_sha_before: self.base_before.clone(),
            base_sha_after: self.fake.branch_sha(REPO, "main").unwrap_or_default(),
            pull_requests,
            head_commits: self.commits.clone(),
            head_files: self.head_files.clone(),
            changed_paths,
            check_runs: self.check_runs.clone(),
            comments,
            requests: self
                .fake
                .requests()
                .into_iter()
                .filter(|record| !self.harness_requests.borrow().contains(&record.seq))
                .map(|record| GithubRequest {
                    method: record.method,
                    path: record.path,
                })
                .collect(),
            tokens: self
                .fake
                .tokens()
                .into_iter()
                .filter(|token| {
                    self.harness_token
                        .borrow()
                        .as_ref()
                        .is_none_or(|(_, id)| *id != token.id)
                })
                .map(|token| TokenRecord {
                    id: format!("token-{}", token.id),
                    permissions: token.permissions,
                    repositories: token.repositories,
                })
                .collect(),
            protection: Some(self.protection()),
        }
    }
}
