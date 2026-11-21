//! The step that follows the pull requests of the factory (ADR 0029, ports v1.5) over the
//! in-memory store and the fake fate source of the test kit: what one pass records, the hour
//! between two looks at one pull request, the five minutes between two passes, the limit of a
//! pass, a look that fails, and the credential that ends with each pass.
//!
//! **Fake, and labelled so:** the store (`InMemoryStore`), the code host (`FakePullRequestFates`,
//! `FakeChangeHost`) and the clock. Nothing here reaches GitHub.

use std::sync::Arc;
use std::time::Duration;

use factory_composition::hooks::BeforeClaim as _;
use factory_composition::indexing::ActiveJobs;
use factory_composition::pull_request_fates::{
    PASS_EVERY, PER_PASS, Pass, PassOutcome, PullRequestFateSync, PullRequestFateSyncDeps,
    RECHECK_AFTER,
};
use factory_domain::ids::{CorrelationId, JobId, PrincipalId, RepositoryId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::{AutonomyLevel, ExecutionMode, StageKind};
use factory_ports::clock::{Clock as _, Uuid};
use factory_ports::githost::GitHostError;
use factory_ports::paths::RepoRef;
use factory_ports::store::{
    NewJob, NewPrincipal, NewPullRequest, PipelineScope, PrincipalKind, PullRequestRecord, Store,
    StoredFate,
};
use factory_testkit::clock::{FakeClock, SequentialIdGenerator};
use factory_testkit::githost::FakeChangeHost;
use factory_testkit::pull_request_fate::FakePullRequestFates;
use factory_testkit::store::InMemoryStore;

fn uid(n: u128) -> Uuid {
    Uuid::from_u128((n << 80) | (0x7_u128 << 76) | (0b10_u128 << 62) | n)
}

/// The name `InMemoryStore::seed_repository` gives every repository.
fn repo() -> RepoRef {
    RepoRef::parse("acme/widgets").unwrap()
}

struct Rig {
    clock: Arc<FakeClock>,
    store: Arc<InMemoryStore>,
    host: Arc<FakePullRequestFates>,
    changes: Arc<FakeChangeHost>,
    jobs: Arc<ActiveJobs>,
    tenant: TenantId,
    repository: RepositoryId,
    job: JobId,
}

impl Rig {
    async fn new() -> Self {
        let clock = Arc::new(FakeClock::starting_at("2026-11-20T10:00:00Z"));
        let store = Arc::new(InMemoryStore::new(clock.clone()));
        let tenant = TenantId::from_uuid(uid(1));
        let repository = store.seed_repository(tenant);
        let principal = PrincipalId::from_uuid(uid(50));
        let job = JobId::from_uuid(uid(51));
        let mut tx = store.begin(TenantScope::new(tenant)).await.unwrap();
        tx.insert_principal(NewPrincipal {
            id: principal,
            kind: PrincipalKind::Human { github_user_id: 7 },
            login: Some("octocat".to_owned()),
        })
        .await
        .unwrap();
        tx.insert_job(NewJob {
            id: job,
            correlation_id: CorrelationId::from_uuid(uid(52)),
            repository,
            requester: principal,
            execution_mode: ExecutionMode::Test,
            autonomy_level: AutonomyLevel::L1,
            pipeline_scope: PipelineScope::new(vec![StageKind::Intake]).unwrap(),
            origin: None,
        })
        .await
        .unwrap();
        tx.commit().await.unwrap();
        Self {
            host: Arc::new(FakePullRequestFates::on_clock(repo(), clock.clone())),
            clock,
            store,
            changes: Arc::new(FakeChangeHost::new()),
            jobs: Arc::new(ActiveJobs::new()),
            tenant,
            repository,
            job,
        }
    }

    fn sync(&self) -> PullRequestFateSync {
        PullRequestFateSync::new(PullRequestFateSyncDeps {
            store: self.store.clone(),
            source: self.host.clone(),
            changes: self.changes.clone(),
            jobs: Arc::clone(&self.jobs),
            clock: self.clock.clone(),
            ids: Arc::new(SequentialIdGenerator::new()),
            tenants: vec![self.tenant],
        })
    }

    /// The delivery stage opened pull request `number`: it exists on the host and in the store.
    async fn opened(&self, number: u64) {
        self.host.open(number);
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .unwrap();
        tx.record_pull_request_opened(NewPullRequest {
            job: self.job,
            repository: self.repository,
            number,
        })
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    async fn stored(&self) -> Vec<PullRequestRecord> {
        let mut tx = self
            .store
            .begin(TenantScope::new(self.tenant))
            .await
            .unwrap();
        let rows = tx.list_pull_requests(self.job).await.unwrap();
        let _ = tx.rollback().await;
        rows
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }
}

fn ran(outcome: PassOutcome) -> Pass {
    match outcome {
        PassOutcome::Ran(pass) => pass,
        other => panic!("the pass did not run: {other:?}"),
    }
}

#[tokio::test]
async fn a_pass_records_a_merge_a_close_and_an_open_one_each_with_its_times() {
    let rig = Rig::new().await;
    for number in [1, 2, 3] {
        rig.opened(number).await;
    }
    rig.clock.advance(Duration::from_secs(600));
    let merged_at = rig.now();
    rig.host.close_pull(1, true);
    rig.clock.advance(Duration::from_secs(600));
    let closed_at = rig.now();
    rig.host.close_pull(2, false);
    rig.clock.advance(Duration::from_secs(600));
    let looked_at = rig.now();

    let pass = ran(rig.sync().pass(rig.tenant).await);
    assert_eq!(
        pass,
        Pass {
            merged: 1,
            closed: 1,
            still_open: 1,
            unread: 0
        }
    );
    assert_eq!(pass.looked_at(), 3);
    let rows = rig.stored().await;
    // The time of the decision is the code host's; the time of the recording is the store's.
    assert_eq!(
        rows[0].fate,
        StoredFate::Merged {
            decided_at: merged_at,
            recorded_at: looked_at
        }
    );
    assert_eq!(
        rows[1].fate,
        StoredFate::Closed {
            decided_at: closed_at,
            recorded_at: looked_at
        }
    );
    assert_eq!(rows[2].fate, StoredFate::Open);
    for row in &rows {
        assert_eq!(row.last_checked_at, Some(looked_at));
    }
}

#[tokio::test]
async fn an_open_pull_request_is_looked_at_again_only_after_the_hour() {
    let rig = Rig::new().await;
    rig.opened(1).await;
    let sync = rig.sync();
    assert_eq!(ran(sync.pass_now(rig.tenant).await).still_open, 1);
    assert_eq!(rig.host.looks(), 1);

    // One second short of the hour: nothing is due, and nothing is asked.
    rig.clock.advance(RECHECK_AFTER - Duration::from_secs(1));
    assert_eq!(ran(sync.pass_now(rig.tenant).await), Pass::default());
    // Exactly the hour: the look was not "more than an hour ago" yet.
    rig.clock.advance(Duration::from_secs(1));
    assert_eq!(ran(sync.pass_now(rig.tenant).await), Pass::default());
    assert_eq!(rig.host.looks(), 1);

    // One second past the hour: it is asked again, and this time it was merged.
    rig.host.close_pull(1, true);
    rig.clock.advance(Duration::from_secs(1));
    assert_eq!(ran(sync.pass_now(rig.tenant).await).merged, 1);
    assert_eq!(rig.host.looks(), 2);

    // A decided pull request is never asked about again, however long the worker runs.
    rig.clock.advance(RECHECK_AFTER * 48);
    assert_eq!(ran(sync.pass_now(rig.tenant).await), Pass::default());
    assert_eq!(rig.host.looks(), 2);
}

#[tokio::test]
async fn two_passes_for_a_tenant_are_five_minutes_apart() {
    let rig = Rig::new().await;
    let sync = rig.sync();
    assert_eq!(ran(sync.pass(rig.tenant).await), Pass::default());
    // A pull request opened right after the pass waits for the next one.
    rig.opened(1).await;
    rig.clock.advance(PASS_EVERY - Duration::from_secs(1));
    assert_eq!(sync.pass(rig.tenant).await, PassOutcome::Recently);
    sync.before_claim().await;
    assert_eq!(rig.host.looks(), 0);
    rig.clock.advance(Duration::from_secs(1));
    sync.before_claim().await;
    assert_eq!(rig.host.looks(), 1);
    assert_eq!(sync.pass(rig.tenant).await, PassOutcome::Recently);
}

#[tokio::test]
async fn a_pass_looks_at_no_more_than_its_limit_and_the_next_one_takes_the_rest() {
    let rig = Rig::new().await;
    let total = u64::from(PER_PASS) + 1;
    for number in 1..=total {
        rig.opened(number).await;
    }
    let sync = rig.sync();
    assert_eq!(ran(sync.pass_now(rig.tenant).await).looked_at(), PER_PASS);
    // The one that was left over was never looked at, so it comes first in the next pass.
    assert_eq!(ran(sync.pass_now(rig.tenant).await).looked_at(), 1);
    assert_eq!(rig.host.looks() as u64, total);
    assert!(
        rig.stored()
            .await
            .iter()
            .all(|row| row.last_checked_at.is_some())
    );
}

#[tokio::test]
async fn a_look_that_fails_is_recorded_as_a_look_and_tried_again_after_the_hour() {
    let rig = Rig::new().await;
    rig.opened(1).await;
    rig.host.close_pull(1, true);
    let sync = rig.sync();

    rig.host.fail_next_look(GitHostError::Unavailable);
    let failed_at = rig.now();
    assert_eq!(
        ran(sync.pass_now(rig.tenant).await),
        Pass {
            unread: 1,
            ..Pass::default()
        }
    );
    let rows = rig.stored().await;
    assert_eq!(rows[0].fate, StoredFate::Open, "nothing is invented");
    assert_eq!(rows[0].last_checked_at, Some(failed_at));

    // It is not asked again at once: a host that is down is not asked at every pass.
    assert_eq!(ran(sync.pass_now(rig.tenant).await), Pass::default());
    rig.clock.advance(RECHECK_AFTER + Duration::from_secs(1));
    assert_eq!(ran(sync.pass_now(rig.tenant).await).merged, 1);
}

#[tokio::test]
async fn a_pull_request_the_host_does_not_know_stays_open_and_fails_nothing() {
    let rig = Rig::new().await;
    // Recorded in the store, and unknown to the host: the repository was deleted, say.
    let mut tx = rig.store.begin(TenantScope::new(rig.tenant)).await.unwrap();
    tx.record_pull_request_opened(NewPullRequest {
        job: rig.job,
        repository: rig.repository,
        number: 9,
    })
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(ran(rig.sync().pass_now(rig.tenant).await).unread, 1);
    assert_eq!(rig.stored().await[0].fate, StoredFate::Open);
}

#[tokio::test]
async fn the_credential_of_a_pass_is_ended_and_a_pass_with_nothing_to_do_asks_for_none() {
    let rig = Rig::new().await;
    let sync = rig.sync();
    // Nothing is open: no session, no credential, nothing to end.
    assert_eq!(ran(sync.pass_now(rig.tenant).await), Pass::default());
    assert!(rig.changes.revoked_jobs().is_empty());

    rig.opened(1).await;
    assert_eq!(ran(sync.pass_now(rig.tenant).await).still_open, 1);
    assert_eq!(rig.changes.revoked_jobs().len(), 1, "one session, ended");
    // The session is not left among the jobs the process is working on.
    let session = rig.changes.revoked_jobs()[0];
    assert!(rig.jobs.tenant_of(session).is_none());
}
