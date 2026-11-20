//! The troubleshooter's store (migration `2026-11-20-003000_troubleshooting_runs`) on a real
//! database, as the worker login: runs, probe states, the issue map, the day counters, tenant
//! isolation, and the advisory lock that lets one troubleshooter be active at a time.

mod support;

use factory_domain::troubleshooting::{GatewayCallId, TroubleshootingRunId};
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_ports::store::StoreError;
use factory_storage::pg::troubleshooting::{
    DayIncrement, NewRun, ProbeOutcome, ProbeResult, RunEnd, RunOutcome, RunTrigger,
    TroubleshooterLock, TroubleshootingStore, utc_day,
};
use support::{Scene, small_pool};

fn at(text: &str) -> Timestamp {
    Timestamp::parse(text).expect("a time")
}

fn run_id(text: &str) -> TroubleshootingRunId {
    TroubleshootingRunId::parse(text).expect("a run id")
}

async fn stores(scene: &Scene) -> (TroubleshootingStore, TroubleshootingStore) {
    let logins = scene.db.server.logins().await;
    let settings = small_pool(scene.db.url(&logins.worker));
    let a = TroubleshootingStore::connect(&settings, scene.a)
        .await
        .expect("the store is ready");
    let b = TroubleshootingStore::connect(&settings, scene.b)
        .await
        .expect("the store is ready");
    (a, b)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_run_is_recorded_when_it_starts_and_once_when_it_ends() {
    let scene = Scene::new().await;
    let (store, other) = stores(&scene).await;
    let id = run_id("tr-1");
    store
        .begin_run(&NewRun {
            id: id.clone(),
            trigger: RunTrigger::Probe,
            started_at: at("2026-11-20T09:00:00Z"),
            dry_run: false,
            datadog_enabled: false,
        })
        .await
        .expect("begin");
    assert_eq!(store.unfinished_runs().await.expect("unfinished").len(), 1);
    let end = RunEnd {
        id: id.clone(),
        ended_at: at("2026-11-20T09:05:00Z"),
        outcome: RunOutcome::Findings,
        spend_micro_usd: 120_000,
        report_sha256: Some(Sha256Digest::of(b"report")),
        gateway_record_sha256: Some(Sha256Digest::of(b"record")),
        agent_ran: true,
        issues_opened: 1,
        comments_posted: 0,
        deferred: vec![Sha256Digest::of(b"later")],
    };
    store.finish_run(&end).await.expect("finish");
    assert_eq!(
        store.finish_run(&end).await,
        Err(StoreError::NotFound),
        "a run ends once"
    );
    let stored = store.run(&id).await.expect("read");
    assert_eq!(stored.outcome, Some(RunOutcome::Findings));
    assert_eq!(stored.spend_micro_usd, 120_000);
    assert_eq!(stored.deferred, vec![Sha256Digest::of(b"later")]);
    assert!(
        store
            .unfinished_runs()
            .await
            .expect("unfinished")
            .is_empty()
    );
    assert_eq!(
        other.run(&id).await,
        Err(StoreError::NotFound),
        "another tenant does not see the run"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn probe_states_keep_the_last_trip_and_the_cooldown() {
    let scene = Scene::new().await;
    let (store, _) = stores(&scene).await;
    let tripped = ProbeResult {
        probe_id: "retries".to_owned(),
        outcome: ProbeOutcome::Tripped,
        value: Some("12".to_owned()),
        call_id: Some(GatewayCallId::parse("call-1").expect("id")),
        run: Some(run_id("tr-1")),
        checked_at: at("2026-11-20T09:00:00Z"),
    };
    store.record_probe(&tripped).await.expect("record");
    store
        .start_cooldown(&["retries".to_owned()], &at("2026-11-20T15:00:00Z"))
        .await
        .expect("cooldown");
    let ok = ProbeResult {
        outcome: ProbeOutcome::Ok,
        value: Some("3".to_owned()),
        checked_at: at("2026-11-20T09:05:00Z"),
        ..tripped
    };
    store.record_probe(&ok).await.expect("record");
    let states = store.probe_states().await.expect("states");
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].last_outcome, ProbeOutcome::Ok);
    assert_eq!(states[0].last_value.as_deref(), Some("3"));
    assert_eq!(
        states[0].last_tripped_at,
        Some(at("2026-11-20T09:00:00Z")),
        "the last trip stays"
    );
    assert_eq!(states[0].cooldown_until, Some(at("2026-11-20T15:00:00Z")));
}

#[tokio::test(flavor = "multi_thread")]
async fn day_counters_add_up_per_utc_day() {
    let scene = Scene::new().await;
    let (store, other) = stores(&scene).await;
    let late = at("2026-11-20T23:59:59Z");
    let next = at("2026-11-21T00:00:00Z");
    assert_eq!(utc_day(&late), "2026-11-20");
    assert_eq!(utc_day(&next), "2026-11-21");
    let one = DayIncrement {
        agent_runs: 1,
        spend_micro_usd: 250_000,
        ..DayIncrement::default()
    };
    store.add_to_day(&late, one).await.expect("add");
    let counted = store.add_to_day(&late, one).await.expect("add");
    assert_eq!(counted.agent_runs, 2);
    assert_eq!(counted.spend_micro_usd, 500_000);
    assert_eq!(
        store.day_counters(&next).await.expect("read").agent_runs,
        0,
        "the next day starts at zero"
    );
    assert_eq!(
        other.day_counters(&late).await.expect("read").agent_runs,
        0,
        "another tenant's day is its own"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_issue_map_counts_comments_per_day() {
    let scene = Scene::new().await;
    let (store, _) = stores(&scene).await;
    let fingerprint = Sha256Digest::of(b"finding");
    assert_eq!(store.issue_for(&fingerprint).await.expect("read"), None);
    assert_eq!(
        store
            .record_comment(&fingerprint, &at("2026-11-20T10:00:00Z"))
            .await,
        Err(StoreError::NotFound)
    );
    store
        .record_issue(
            &fingerprint,
            "example-org/fixture",
            7,
            &at("2026-11-20T09:00:00Z"),
        )
        .await
        .expect("record");
    store
        .record_comment(&fingerprint, &at("2026-11-20T10:00:00Z"))
        .await
        .expect("comment");
    store
        .record_comment(&fingerprint, &at("2026-11-20T11:00:00Z"))
        .await
        .expect("comment");
    let entry = store
        .issue_for(&fingerprint)
        .await
        .expect("read")
        .expect("an entry");
    assert_eq!(entry.issue_number, 7);
    assert_eq!(entry.last_comment_day.as_deref(), Some("2026-11-20"));
    assert_eq!(entry.comments_on_last_day, 2);
    store
        .record_comment(&fingerprint, &at("2026-11-21T00:00:01Z"))
        .await
        .expect("comment");
    let entry = store
        .issue_for(&fingerprint)
        .await
        .expect("read")
        .expect("an entry");
    assert_eq!(entry.comments_on_last_day, 1, "a new day counts again");
    store
        .record_issue(
            &fingerprint,
            "example-org/fixture",
            9,
            &at("2026-11-22T09:00:00Z"),
        )
        .await
        .expect("a new issue replaces a closed one");
    let entry = store
        .issue_for(&fingerprint)
        .await
        .expect("read")
        .expect("an entry");
    assert_eq!(
        (entry.issue_number, entry.last_comment_day),
        (9, None),
        "the replacement starts with no comment"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn only_one_session_holds_the_troubleshooter_lock() {
    let scene = Scene::new().await;
    let logins = scene.db.server.logins().await;
    let url = scene.db.url(&logins.worker);
    let mut first = TroubleshooterLock::try_acquire(&url)
        .await
        .expect("reachable")
        .expect("the first instance holds the lock");
    assert!(first.still_held().await);
    assert!(
        TroubleshooterLock::try_acquire(&url)
            .await
            .expect("reachable")
            .is_none(),
        "a second instance idles"
    );
    first.release().await;
    let second = TroubleshooterLock::try_acquire(&url)
        .await
        .expect("reachable");
    assert!(second.is_some(), "after a release the next one takes over");
    drop(second);
    // Dropping the connection ends the lock too.
    let third = TroubleshooterLock::try_acquire(&url)
        .await
        .expect("reachable");
    assert!(third.is_some(), "a dropped holder gives the lock up");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_store_refuses_a_login_that_is_not_a_worker() {
    let scene = Scene::new().await;
    let logins = scene.db.server.logins().await;
    let refused = TroubleshootingStore::connect(&small_pool(scene.db.url(&logins.engine)), scene.a)
        .await
        .expect_err("the engine login is refused");
    assert!(refused.to_string().contains("not allowed"), "{refused}");
}
