//! The shared contract suites need a subject: the thing under test and a few levers the port
//! does not have. These subjects wrap the adapter in the world of the harness.

use std::sync::PoisonError;

use async_trait::async_trait;
use factory_github::{GithubChangeHost, GithubIssueSource};
use factory_ports::githost::{
    AppId, ChangeHost, CheckRef, Comment, CommentTarget, GithubActor, Issue, IssueRef, IssueSource,
    ProtectionReport, PullRequestRef,
};
use factory_ports::paths::{BranchName, CommitSha, RepoRef};
use factory_testkit::contracts::githost::{ChangeHostSubject, IssueSourceSubject};
use factory_testkit::fx::http::send_request;
use serde_json::{Value, json};

use super::harness::{FIXTURE, World};

fn full_name(repo: &RepoRef) -> String {
    format!("{}/{}", repo.owner(), repo.name())
}

fn target_number(target: &CommentTarget) -> u64 {
    match target {
        CommentTarget::Issue(issue) => issue.number,
        CommentTarget::PullRequest(pr) => pr.number,
    }
}

/// A person with write access acts outside the factory (merging or closing a pull request).
fn as_a_person(world: &World, method: &str, target: &str, body: &Value) {
    let jwt = world.fake.sample_app_jwt();
    let auth = format!("Bearer {jwt}");
    let minted = send_request(
        world.addr(),
        "POST",
        "/app/installations/1/access_tokens",
        &[("Authorization", auth.as_str())],
        json!({"repositories": ["fixture"], "permissions": {"pull_requests": "write", "contents": "write", "metadata": "read"}})
            .to_string()
            .as_bytes(),
    )
    .expect("the person's token request");
    let token = minted.json().expect("a token answer")["token"]
        .as_str()
        .expect("a token")
        .to_owned();
    let auth = format!("Bearer {token}");
    let done = send_request(
        world.addr(),
        method,
        target,
        &[("Authorization", auth.as_str())],
        body.to_string().as_bytes(),
    )
    .expect("the person's request");
    assert!(
        done.status < 300,
        "the person's {method} {target} got {}",
        done.status
    );
}

pub struct ChangeHostWorld {
    pub world: World,
    host: GithubChangeHost,
}

impl ChangeHostWorld {
    pub fn new() -> Self {
        Self::from(World::new())
    }
}

impl From<World> for ChangeHostWorld {
    fn from(world: World) -> Self {
        let host = world.adapter.change_host();
        Self { world, host }
    }
}

#[async_trait]
impl ChangeHostSubject for ChangeHostWorld {
    fn host(&self) -> &dyn ChangeHost {
        &self.host
    }

    async fn comment_count(&self, target: &CommentTarget) -> usize {
        self.world
            .fake
            .comments(FIXTURE, target_number(target))
            .len()
    }

    async fn person_merges(&self, pr: &PullRequestRef) {
        self.world.fake.mark_ready(FIXTURE, pr.number);
        as_a_person(
            &self.world,
            "PUT",
            &format!("/repos/{FIXTURE}/pulls/{}/merge", pr.number),
            &json!({}),
        );
    }

    async fn person_closes(&self, pr: &PullRequestRef) {
        as_a_person(
            &self.world,
            "PATCH",
            &format!("/repos/{FIXTURE}/pulls/{}", pr.number),
            &json!({"state": "closed"}),
        );
    }

    fn app_id(&self) -> AppId {
        AppId(self.world.fake.app().id)
    }

    async fn check_run_count(&self, commit: &CommitSha, name: &str) -> usize {
        self.world
            .extras
            .checks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|c| c.head_sha == commit.as_str() && c.name == name)
            .count()
    }

    async fn check_run_app(&self, check: &CheckRef) -> Option<AppId> {
        self.world
            .extras
            .checks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .find(|c| c.id == check.id)
            .map(|c| AppId(c.app_id))
    }

    async fn branch_tip(&self, repo: &RepoRef, branch: &BranchName) -> Option<CommitSha> {
        self.world
            .fake
            .branch_sha(&full_name(repo), branch.as_str())
            .and_then(|sha| CommitSha::parse(&sha).ok())
    }
}

pub struct IssueSourceWorld {
    pub world: World,
    source: GithubIssueSource,
}

impl IssueSourceWorld {
    pub fn new() -> Self {
        let world = World::new();
        let source = world.adapter.issue_source();
        Self { world, source }
    }
}

#[async_trait]
impl IssueSourceSubject for IssueSourceWorld {
    fn source(&self) -> &dyn IssueSource {
        &self.source
    }

    async fn seed_issue(&self, issue: Issue) {
        let repo = full_name(&issue.reference.repo);
        let mut counters = self
            .world
            .extras
            .issue_counters
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let next = counters.entry(repo.clone()).or_insert(1);
        // The fake numbers issues from 1; fill the numbers below the wanted one.
        while *next < issue.reference.number {
            self.world
                .fake
                .add_issue(&repo, "filler", "", "octocat", &[]);
            *next += 1;
        }
        if *next == issue.reference.number {
            let labels: Vec<&str> = issue.labels.iter().map(String::as_str).collect();
            self.world.fake.add_issue(
                &repo,
                &issue.title,
                &issue.body,
                issue.author.login.as_str(),
                &labels,
            );
            *next += 1;
        }
    }

    async fn edit_issue_title(&self, issue: &IssueRef, title: &str) {
        self.world
            .extras
            .titles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((full_name(&issue.repo), issue.number), title.to_owned());
    }

    async fn seed_label(&self, issue: &IssueRef, label: &str, actor: &GithubActor) {
        self.world.fake.label_issue(
            &full_name(&issue.repo),
            issue.number,
            label,
            actor.login.as_str(),
        );
    }

    async fn seed_comment(&self, comment: Comment) {
        let (repo, number) = match &comment.reference.target {
            CommentTarget::Issue(issue) => (full_name(&issue.repo), issue.number),
            CommentTarget::PullRequest(pr) => (full_name(&pr.repo), pr.number),
        };
        let value = json!({
            "id": comment.reference.id,
            "body": comment.body,
            "user": {"id": comment.author.id, "login": comment.author.login.as_str(), "type": "User"},
            "created_at": comment.created_at.as_text(),
            "updated_at": comment.edited_at.map_or_else(|| comment.created_at.as_text(), |t| t.as_text()),
            "issue_url": format!("https://api.github.test/repos/{repo}/issues/{number}"),
        });
        self.world
            .extras
            .comments
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((repo, comment.reference.id), value);
    }

    async fn permissions_asked(&self) -> Vec<String> {
        self.world
            .fake
            .mints()
            .iter()
            .flat_map(|mint| mint.requested_permissions.clone().unwrap_or_default())
            .map(|(name, level)| format!("{name}:{level}"))
            .collect()
    }

    async fn seed_protection(&self, repo: &RepoRef, report: ProtectionReport) {
        let mut rules = Vec::new();
        if report.requires_pull_request {
            rules.push(json!({"type": "pull_request", "parameters": {
                "dismiss_stale_reviews_on_push": report.dismisses_stale_approvals,
                "require_code_owner_review": report.requires_code_owner_review}}));
        }
        if !report.required_checks.is_empty() {
            let checks: Vec<Value> = report
                .required_checks
                .iter()
                .map(|c| json!({"context": c.context, "integration_id": c.integration_id}))
                .collect();
            rules.push(json!({"type": "required_status_checks", "parameters": {"required_status_checks": checks}}));
        }
        if report.blocks_force_push {
            rules.push(json!({"type": "non_fast_forward"}));
        }
        if report.blocks_deletion {
            rules.push(json!({"type": "deletion"}));
        }
        self.world
            .extras
            .rules
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(full_name(repo), Value::Array(rules));
    }
}
