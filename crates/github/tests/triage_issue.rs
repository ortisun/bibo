//! The troubleshooter's triage issue writer of the GitHub adapter (ports v1.3, ADR 0021 Decision
//! 7): the shared contract suite, the run's own credential (refused for another repository, never
//! a job's, untouched by the sweeps of jobs), the marker among several open issues, a listing cut
//! short, and pull requests left out.
//!
//! **Everything here runs against the fake GitHub server of the test kit (FX-GH) over the loopback
//! interface. None of it ran against the real GitHub** (see the module notes of
//! `crates/github/src/triage.rs`).

mod common;

use std::collections::HashSet;

use async_trait::async_trait;
use common::harness::{FIXTURE, OTHER, Options, World};
use factory_domain::troubleshooting::issue::{Investigation, render_issue};
use factory_domain::troubleshooting::{FindingFingerprint, TroubleshootingRunId};
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::StageKind;
use factory_github::{GithubTriageIssues, PageLimits};
use factory_ports::githost::{ChangeHost, GitHostError, IssueRef, IssueSource};
use factory_ports::paths::RepoRef;
use factory_ports::triage_issue::{OpenedIssue, RunScope, TriageIssueWriter};
use factory_testkit::contracts::githost::scope;
use factory_testkit::contracts::triage_issue::{
    self, TriageIssueSubject, finding, run_triage_issue,
};
use factory_testkit::triage_issue::triage_labels;

const ISSUES_CREATE: &str = "POST /repos/{owner}/{repo}/issues";
const ISSUES_LIST: &str = "GET /repos/{owner}/{repo}/issues";
const LABELS: [&str; 2] = ["troubleshooter", "troubleshooter: triage"];

struct TriageWorld {
    world: World,
    writer: GithubTriageIssues,
}

impl TriageWorld {
    fn new() -> Self {
        Self::from(World::new())
    }
}

impl From<World> for TriageWorld {
    fn from(world: World) -> Self {
        let writer = world
            .adapter
            .triage_issue_writer(RepoRef::parse(FIXTURE).unwrap());
        Self { world, writer }
    }
}

#[async_trait]
impl TriageIssueSubject for TriageWorld {
    fn writer(&self) -> &dyn TriageIssueWriter {
        &self.writer
    }

    fn repository(&self) -> RepoRef {
        RepoRef::parse(FIXTURE).unwrap()
    }

    fn other_repository(&self) -> RepoRef {
        RepoRef::parse(OTHER).unwrap()
    }

    async fn seed_app_issue(&self, body: &str, labels: &[&str]) -> u64 {
        self.world
            .fake
            .add_app_issue(FIXTURE, "Seeded", body, labels)
    }

    async fn seed_person_issue(&self, body: &str, labels: &[&str]) -> u64 {
        self.world
            .fake
            .add_issue(FIXTURE, "By a person", body, "octocat", labels)
    }

    async fn seed_person_comment(&self, number: u64, body: &str) {
        self.world
            .fake
            .add_comment(FIXTURE, number, "octocat", body);
    }

    async fn close(&self, number: u64) {
        self.world.fake.close_issue(FIXTURE, number);
    }

    async fn open_issues(&self) -> Vec<u64> {
        self.world
            .fake
            .issue_numbers(FIXTURE)
            .into_iter()
            .filter(|n| {
                self.world
                    .fake
                    .issue_json(FIXTURE, *n)
                    .is_some_and(|i| i["state"] == "open" && i.get("pull_request").is_none())
            })
            .collect()
    }

    async fn issue(&self, number: u64) -> Option<(String, Vec<String>)> {
        let json = self.world.fake.issue_json(FIXTURE, number)?;
        Some((
            json["body"].as_str()?.to_owned(),
            self.world.fake.labels_of(FIXTURE, number),
        ))
    }

    async fn app_comments(&self, number: u64) -> Vec<String> {
        let bot = self.world.fake.app().bot_login();
        self.world
            .fake
            .comments_by_author(FIXTURE, number)
            .into_iter()
            .filter(|(author, _)| *author == bot)
            .map(|(_, body)| body)
            .collect()
    }

    async fn permissions_asked(&self) -> Vec<Vec<(String, String)>> {
        self.world
            .fake
            .mints()
            .into_iter()
            .map(|m| {
                let mut set: Vec<(String, String)> = m
                    .requested_permissions
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                set.sort();
                set
            })
            .collect()
    }
}

fn run_scope(run: &str) -> RunScope {
    RunScope {
        tenant: scope(1, 1).tenant,
        run: TroubleshootingRunId::parse(run).unwrap(),
        repo: RepoRef::parse(FIXTURE).unwrap(),
    }
}

fn issue_for(probe: &str) -> factory_domain::troubleshooting::issue::TriageIssue {
    let run = TroubleshootingRunId::parse("run-1").unwrap();
    render_issue(
        &finding(probe, "Stage failures rose"),
        &Investigation {
            run: &run,
            window_from: Timestamp::parse("2026-11-20T09:00:00Z").unwrap(),
            window_to: Timestamp::parse("2026-11-20T10:00:00Z").unwrap(),
            earlier_closed_issue: None,
            held_back: &[],
        },
        &triage_labels(),
    )
    .unwrap()
}

// ---- the shared contract suite ---------------------------------------------------------------

#[tokio::test]
async fn the_github_triage_writer_passes_the_whole_triage_issue_contract() {
    let report = run_triage_issue(|| async { TriageWorld::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(
        report.passed.len(),
        triage_issue::triage_issue_checks().len()
    );
}

// ---- the request ------------------------------------------------------------------------------

#[tokio::test]
async fn an_issue_is_opened_with_the_title_body_and_policy_labels_and_one_narrow_token() {
    let world = TriageWorld::new();
    let issue = issue_for("stage-failure-rate");
    let opened = world
        .writer
        .open_issue(&run_scope("run-1"), &issue)
        .await
        .unwrap();
    let OpenedIssue::Opened(made) = opened else {
        panic!("{opened:?}")
    };
    let sent = world.world.fake.requests_to(ISSUES_CREATE);
    assert_eq!(sent.len(), 1);
    let body = sent[0].body_json().unwrap();
    assert_eq!(body["title"], "Troubleshooter: Stage failures rose");
    assert_eq!(body["labels"], serde_json::json!(LABELS));
    let text = body["body"].as_str().unwrap();
    assert_eq!(
        FindingFingerprint::from_body(text).as_ref(),
        Some(issue.fingerprint())
    );
    assert!(text.starts_with("**The troubleshooter wrote this issue"));
    // The search API is never used; the listing names the label and asks for open issues only.
    let lists = world.world.fake.requests_to(ISSUES_LIST);
    assert!(!lists.is_empty());
    for list in &lists {
        let query = list.query.clone().unwrap_or_default();
        assert!(query.contains("state=open"), "{query}");
        assert!(query.contains("labels=troubleshooter"), "{query}");
    }
    assert!(
        world
            .world
            .fake
            .requests()
            .iter()
            .all(|r| !r.path.starts_with("/search"))
    );
    let mints = world.world.fake.mints();
    assert_eq!(mints.len(), 1, "one token served the look and the write");
    assert_eq!(
        mints[0].requested_repositories,
        Some(vec!["fixture".to_owned()])
    );
    assert_eq!(mints[0].granted_repositories, vec![FIXTURE.to_owned()]);
    assert_eq!(made.number, world.world.fake.issue_numbers(FIXTURE)[0]);
}

#[tokio::test]
async fn the_marker_is_found_among_several_open_issues_and_a_spoof_in_a_comment_does_not_count() {
    let world = TriageWorld::new();
    let wanted = issue_for("db-latency");
    let marker = wanted.fingerprint().marker();
    let fake = &world.world.fake;
    // Several open triage issues of other problems.
    let mut others = Vec::new();
    for probe in ["queue-depth", "spend-rate", "worker-heartbeat"] {
        others.push(fake.add_app_issue(FIXTURE, "Other", issue_for(probe).body(), &LABELS));
    }
    // A spoof: the wanted marker pasted into a comment on one of them, by a person and by the
    // App's own account.
    fake.add_comment(FIXTURE, others[0], "octocat", &format!("Same?\n{marker}"));
    let scope = run_scope("run-1");
    assert_eq!(
        world
            .writer
            .find_open_issue(&scope, wanted.fingerprint())
            .await,
        Ok(None)
    );
    let real = fake.add_app_issue(FIXTURE, "Real", wanted.body(), &LABELS);
    assert_eq!(
        world
            .writer
            .find_open_issue(&scope, wanted.fingerprint())
            .await,
        Ok(Some(IssueRef {
            repo: RepoRef::parse(FIXTURE).unwrap(),
            number: real,
        }))
    );
    // Each of the others is found by its own fingerprint.
    for (probe, number) in ["queue-depth", "spend-rate", "worker-heartbeat"]
        .into_iter()
        .zip(&others)
    {
        let found = world
            .writer
            .find_open_issue(&scope, issue_for(probe).fingerprint())
            .await
            .unwrap();
        assert_eq!(found.map(|i| i.number), Some(*number), "{probe}");
    }
}

#[tokio::test]
async fn a_listing_cut_short_without_the_marker_is_unavailable_and_opens_nothing() {
    let world = TriageWorld::from(World::with(Options {
        configure: Some(Box::new(|config| {
            config.pages = PageLimits {
                per_page: 1,
                ..PageLimits::default()
            };
        })),
        ..Options::default()
    }));
    for _ in 0..12 {
        world
            .world
            .fake
            .add_app_issue(FIXTURE, "Other", "No marker.", &LABELS);
    }
    let issue = issue_for("db-latency");
    assert_eq!(
        world.writer.open_issue(&run_scope("run-1"), &issue).await,
        Err(GitHostError::Unavailable)
    );
    assert_eq!(world.world.fake.count(ISSUES_CREATE), 0);
}

// ---- the credential ---------------------------------------------------------------------------

#[tokio::test]
async fn another_repository_is_refused_before_any_token_is_asked_for() {
    let world = TriageWorld::new();
    let mut scope = run_scope("run-1");
    scope.repo = RepoRef::parse(OTHER).unwrap();
    let issue = issue_for("db-latency");
    assert_eq!(
        world.writer.open_issue(&scope, &issue).await,
        Err(GitHostError::Forbidden)
    );
    assert_eq!(
        world
            .writer
            .find_open_issue(&scope, issue.fingerprint())
            .await,
        Err(GitHostError::Forbidden)
    );
    assert!(world.world.fake.mints().is_empty());
    assert!(world.world.fake.requests().is_empty(), "nothing was sent");
    // The same name in another letter case is the same repository, as on GitHub.
    let mut upper = run_scope("run-1");
    upper.repo = RepoRef::parse("Example-Org/Fixture").unwrap();
    assert!(
        world
            .writer
            .find_open_issue(&upper, issue.fingerprint())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn the_run_token_is_not_a_job_token_and_the_job_sweeps_leave_it_alone() {
    let world = TriageWorld::new();
    let scope = run_scope("run-1");
    let issue = issue_for("db-latency");
    world.writer.open_issue(&scope, &issue).await.unwrap();
    // A job of the intake stage reads the same repository with its own narrow token.
    let mut intake = factory_testkit::contracts::githost::scope(1, 1);
    intake.stage = StageKind::Intake;
    let number = world.world.fake.issue_numbers(FIXTURE)[0];
    world
        .world
        .adapter
        .issue_source()
        .fetch_issue(
            &intake,
            &IssueRef {
                repo: RepoRef::parse(FIXTURE).unwrap(),
                number,
            },
        )
        .await
        .unwrap();
    let mints = world.world.fake.mints();
    assert_eq!(mints.len(), 2, "{mints:?}");
    let asked: Vec<Vec<(String, String)>> = mints
        .iter()
        .map(|m| {
            m.requested_permissions
                .clone()
                .unwrap()
                .into_iter()
                .collect()
        })
        .collect();
    let pairs = |p: &[(&str, &str)]| -> Vec<(String, String)> {
        p.iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    };
    assert_eq!(
        asked[0],
        pairs(&[("issues", "write"), ("metadata", "read")])
    );
    assert_eq!(
        asked[1],
        pairs(&[("issues", "read"), ("metadata", "read")]),
        "the intake token stays at issues read (LB-03)"
    );
    // Ending the job, and sweeping every job, leaves the run's token alone.
    world
        .world
        .adapter
        .change_host()
        .revoke_job_tokens(intake.job)
        .await
        .unwrap();
    world.world.adapter.sweep_orphans(&HashSet::new()).await;
    assert_eq!(world.world.fake.revocations().len(), 1, "only the job's");
    // The run still works without minting again, until the run ends.
    world
        .writer
        .find_open_issue(&scope, issue.fingerprint())
        .await
        .unwrap();
    assert_eq!(world.world.fake.mints().len(), 2);
    world.writer.revoke_run_tokens(&scope.run).await.unwrap();
    assert_eq!(world.world.fake.revocations().len(), 2);
    assert_eq!(
        world
            .writer
            .find_open_issue(&scope, issue.fingerprint())
            .await,
        Err(GitHostError::Unauthorized)
    );
    // Another run is a new holder and gets its own token.
    assert!(
        world
            .writer
            .find_open_issue(&run_scope("run-2"), issue.fingerprint())
            .await
            .is_ok()
    );
}
