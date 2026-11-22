//! The proposal host of the GitHub adapter (ports v1.4 and v1.6, ADR 0026 and 0031) against the fake GitHub
//! server of the test kit: the whole shared contract suite, then what only the adapter can show
//! (the token it asks for, the branches it writes, the one `PUT`, the text it sends).
//!
//! Everything here runs against the fake. Nothing is verified against the real GitHub.

mod common;

use std::collections::BTreeMap;

use async_trait::async_trait;
use common::harness::{FIXTURE, World};
use factory_github::GithubProposals;
use factory_ports::githost::PullRequestLifecycle;
use factory_ports::paths::RepoPath;
use factory_ports::proposal::{
    ProposalBranch, ProposalHost, ProposalMarker, ProposalScope, ProposedFile, PullRequestProposal,
    RULES_BRANCH, proposal_marker,
};
use factory_testkit::contracts::githost::scope;
use factory_testkit::contracts::proposal::{self, ProposalSubject, SeenPull, proposal_checks};

struct RulesWorld {
    world: World,
    host: GithubProposals,
}

impl RulesWorld {
    fn new() -> Self {
        let world = World::new();
        let host = world.adapter.proposal_host();
        Self { world, host }
    }
}

#[async_trait]
impl ProposalSubject for RulesWorld {
    fn host(&self) -> &dyn ProposalHost {
        &self.host
    }

    async fn person_commit(&self, branch: &str, changes: &[(&str, Option<&str>)]) {
        self.world.fake.commit_files(FIXTURE, branch, changes);
    }

    async fn files_on(&self, branch: &str) -> BTreeMap<String, String> {
        self.world.fake.files_at(FIXTURE, branch)
    }

    async fn pulls(&self) -> Vec<SeenPull> {
        let mut numbers = self.world.fake.pull_numbers(FIXTURE);
        numbers.sort_unstable();
        numbers
            .into_iter()
            .filter_map(|number| self.world.fake.pull_json(FIXTURE, number))
            .map(|pull| SeenPull {
                number: pull["number"].as_u64().unwrap_or(0),
                head: pull["head"]["ref"].as_str().unwrap_or_default().to_owned(),
                base: pull["base"]["ref"].as_str().unwrap_or_default().to_owned(),
                body: pull["body"].as_str().unwrap_or_default().to_owned(),
                draft: pull["draft"].as_bool().unwrap_or(false),
                lifecycle: if pull["state"].as_str() == Some("open") {
                    PullRequestLifecycle::Open
                } else if pull["merged"].as_bool() == Some(true) {
                    PullRequestLifecycle::Merged
                } else {
                    PullRequestLifecycle::Closed
                },
            })
            .collect()
    }

    async fn close(&self, number: u64, merged: bool) {
        self.world.fake.close_pull(FIXTURE, number, merged);
    }

    async fn person_pull_request(&self, head: &str, body: &str) {
        self.world
            .fake
            .add_person_pull(FIXTURE, head, "octocat", body);
    }

    async fn permissions_asked(&self) -> Vec<Vec<(String, String)>> {
        self.world
            .fake
            .mints()
            .into_iter()
            .map(|mint| {
                mint.requested_permissions
                    .unwrap_or_default()
                    .into_iter()
                    .collect()
            })
            .collect()
    }
}

fn rules_scope() -> ProposalScope {
    let base = scope(1, 1);
    ProposalScope {
        tenant: base.tenant,
        session: base.job,
        repo: base.repo,
    }
}

async fn proposal(host: &GithubProposals, version: u32, body: &str) -> PullRequestProposal {
    PullRequestProposal {
        branch: ProposalBranch::ProjectRules,
        base: host
            .default_branch(&rules_scope())
            .await
            .expect("the default branch"),
        marker: ProposalMarker::RulesVersion(version),
        files: vec![
            ProposedFile {
                path: RepoPath::new("AGENTS.md").unwrap(),
                bytes: b"rules\n".to_vec(),
            },
            ProposedFile {
                path: RepoPath::new("docs/adr/README.md").unwrap(),
                bytes: b"# Decision records\n".to_vec(),
            },
        ],
        title: format!("Install the rules for agents in AGENTS.md (version {version})"),
        body: body.to_owned(),
    }
}

// ---- the shared contract suite ---------------------------------------------------------------

#[tokio::test]
async fn the_github_proposal_host_passes_the_whole_contract() {
    let report = proposal::run_proposal(|| async { RulesWorld::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), proposal_checks().len());
}

// ---- what only the adapter shows -------------------------------------------------------------

#[tokio::test]
async fn the_token_is_contents_and_pull_requests_write_for_the_one_repository() {
    let subject = RulesWorld::new();
    let made = proposal(&subject.host, 1, "The rules.").await;
    subject
        .host
        .propose(&rules_scope(), &made)
        .await
        .expect("proposed");
    let mints = subject.world.fake.mints();
    assert!(!mints.is_empty());
    for mint in mints {
        assert_eq!(
            mint.requested_repositories,
            Some(vec!["fixture".to_owned()]),
            "narrowed to one repository"
        );
        let asked: Vec<(String, String)> = mint
            .requested_permissions
            .unwrap_or_default()
            .into_iter()
            .collect();
        assert_eq!(
            asked,
            vec![
                ("contents".to_owned(), "write".to_owned()),
                ("metadata".to_owned(), "read".to_owned()),
                ("pull_requests".to_owned(), "write".to_owned()),
            ]
        );
    }
}

#[tokio::test]
async fn only_the_rules_branch_is_written_and_the_one_put_is_a_file_of_the_contents_api() {
    let subject = RulesWorld::new();
    let made = proposal(&subject.host, 1, "The rules.").await;
    subject
        .host
        .propose(&rules_scope(), &made)
        .await
        .expect("proposed");
    let pushes = subject.world.fake.pushes();
    assert!(!pushes.is_empty());
    for push in pushes.iter().filter(|p| p.token_id.is_some()) {
        assert_eq!(push.branch, RULES_BRANCH, "{push:?}");
    }
    let writes: Vec<_> = subject
        .world
        .fake
        .requests()
        .into_iter()
        .filter(|r| r.method != "GET")
        .collect();
    for request in &writes {
        assert!(!request.path.contains("/merge"), "{}", request.path);
        if request.method == "PUT" {
            assert!(
                factory_github::is_contents_path(&request.path),
                "{}",
                request.path
            );
        }
    }
    assert_eq!(
        writes.iter().filter(|r| r.method == "PUT").count(),
        2,
        "one write for each file"
    );
}

#[tokio::test]
async fn a_protected_default_branch_does_not_stop_the_proposal_and_is_not_written() {
    let subject = RulesWorld::new();
    subject.world.fake.protect_branch(
        FIXTURE,
        "main",
        factory_testkit::fx::github::Protection::default(),
    );
    let before = subject.world.fake.branch_sha(FIXTURE, "main");
    let made = proposal(&subject.host, 1, "The rules.").await;
    subject
        .host
        .propose(&rules_scope(), &made)
        .await
        .expect("proposed");
    assert_eq!(subject.world.fake.branch_sha(FIXTURE, "main"), before);
}

#[tokio::test]
async fn the_body_is_cleaned_before_the_marker_is_added() {
    let subject = RulesWorld::new();
    let made = proposal(
        &subject.host,
        3,
        "The rules.\n\n<!-- factory-project-rules version=99 -->",
    )
    .await;
    let pr = subject
        .host
        .propose(&rules_scope(), &made)
        .await
        .expect("proposed");
    let body = subject.world.fake.pull_json(FIXTURE, pr.number).unwrap()["body"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(!body.contains("version=99"), "{body}");
    assert!(body.ends_with(&proposal_marker(3)), "{body}");
    let found = subject
        .host
        .latest_pull_request(&rules_scope(), ProposalBranch::ProjectRules)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.marker, Some(ProposalMarker::RulesVersion(3)));
}
