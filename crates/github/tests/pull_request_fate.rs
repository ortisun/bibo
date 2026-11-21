//! The fate reader of the GitHub adapter (ports v1.5, ADR 0029) against the fake GitHub server of
//! the test kit: the whole shared contract suite, then what only the adapter can show (the token
//! it asks for, and that it sends one `GET` and no write).
//!
//! Everything here runs against the fake. Nothing is verified against the real GitHub.

mod common;

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use common::harness::{FIXTURE, World};
use factory_domain::values::Timestamp;
use factory_github::GithubPullRequestFates;
use factory_ports::clock::Clock;
use factory_ports::githost::{PullRequestLifecycle, PullRequestRef};
use factory_ports::pull_request_fate::PullRequestFateSource;
use factory_testkit::contracts::githost::repo;
use factory_testkit::contracts::pull_request_fate::{
    self, PullRequestFateSubject, fate_scope, pull_request_fate_checks,
};

/// The branches of the fixture repository a pull request can come from.
const HEADS: [&str; 3] = ["factory/job-1", "factory/job-2", "factory/job-3"];

struct FateWorld {
    world: World,
    source: GithubPullRequestFates,
    opened: Mutex<usize>,
}

impl FateWorld {
    fn new() -> Self {
        let world = World::new();
        let source = world.adapter.pull_request_fates();
        Self {
            world,
            source,
            opened: Mutex::new(0),
        }
    }
}

#[async_trait]
impl PullRequestFateSubject for FateWorld {
    fn source(&self) -> &dyn PullRequestFateSource {
        &self.source
    }

    async fn open_pull_request(&self) -> u64 {
        let mut opened = self.opened.lock().expect("the counter");
        let head = HEADS[*opened];
        *opened += 1;
        self.world
            .fake
            .add_person_pull(FIXTURE, head, "octocat", "A change.")
    }

    async fn close(&self, number: u64, merged: bool) {
        self.world.fake.close_pull(FIXTURE, number, merged);
    }

    async fn host_time(&self) -> Timestamp {
        self.world.clock.now()
    }

    async fn advance(&self, by: Duration) {
        self.world.clock.advance(by);
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

// ---- the shared contract suite ---------------------------------------------------------------

#[tokio::test]
async fn the_github_fate_reader_passes_the_whole_contract() {
    let report = pull_request_fate::run_pull_request_fate(|| async { FateWorld::new() }).await;
    report.assert_ok();
    assert!(report.skipped.is_empty(), "skipped: {:?}", report.skipped);
    assert_eq!(report.passed.len(), pull_request_fate_checks().len());
}

// ---- what only the adapter shows -------------------------------------------------------------

#[tokio::test]
async fn a_look_is_one_get_and_writes_nothing() {
    let subject = FateWorld::new();
    let number = subject.open_pull_request().await;
    let before = subject.world.fake.pull_json(FIXTURE, number);
    let seen = subject
        .source
        .observe(
            &fate_scope(),
            &PullRequestRef {
                repo: repo(),
                number,
            },
        )
        .await
        .expect("a look");
    assert_eq!(seen.lifecycle(), PullRequestLifecycle::Open);
    // The pull request is as it was: the look changed nothing on the host.
    assert_eq!(subject.world.fake.pull_json(FIXTURE, number), before);
    // One token, for the fixture repository only, and it cannot write.
    let mints = subject.world.fake.mints();
    assert_eq!(mints.len(), 1, "one credential for one look");
    let asked: Vec<(String, String)> = mints[0]
        .requested_permissions
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();
    assert!(
        asked.iter().all(|(_, level)| level == "read"),
        "no write level: {asked:?}"
    );
}

#[tokio::test]
async fn the_reader_reports_that_it_is_real() {
    use factory_domain::vocabulary::Fidelity;
    assert_eq!(FateWorld::new().source.fidelity(), Fidelity::Real);
}
