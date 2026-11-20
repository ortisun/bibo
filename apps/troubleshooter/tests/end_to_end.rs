//! The troubleshooter end to end, offline: real probes through the real gateway against a fake
//! VictoriaMetrics and the real database, the real store, a scripted agent and the in-memory
//! issue writer. Needs `FACTORY_DB_ADMIN_URL` (the database test convention of the storage crate).

mod support;

use std::time::Duration;

use factory_storage::pg::troubleshooting::{DayIncrement, ProbeOutcome, RunOutcome};
use factory_troubleshooter::scheduler::{Activation, activate};
use factory_troubleshooter::troubleshooter::{IssueAction, PassOptions, PassReport};
use support::{RUN_COST, Scene, SceneOptions, Script, VmAnswer, finding, report};

const HOUR: Duration = Duration::from_secs(3600);

fn probe(report: &PassReport, id: &str) -> ProbeOutcome {
    report
        .probes
        .iter()
        .find(|(probe, _)| probe == id)
        .map(|(_, outcome)| *outcome)
        .unwrap_or_else(|| panic!("no probe {id}"))
}

/// The retries probe runs first, so its gateway call is `call-1`; the leases probe is `call-2`.
fn valid_report() -> Vec<u8> {
    report(
        "findings",
        vec![finding(&["retries"], "call-1", "vm_query")],
    )
}

async fn pass(scene: &Scene) -> PassReport {
    scene
        .troubleshooter
        .pass(PassOptions::default())
        .await
        .expect("the pass runs")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tripped_probe_runs_the_agent_once_and_opens_one_issue() {
    let scene = Scene::new(SceneOptions::default()).await;
    scene.agent.queue(Script::Report(valid_report()));
    let done = pass(&scene).await;
    assert_eq!(probe(&done, "retries"), ProbeOutcome::Tripped);
    assert_eq!(probe(&done, "leases_past_expiry"), ProbeOutcome::Ok);
    assert_eq!(probe(&done, "datadog_alerting"), ProbeOutcome::Disabled);
    assert_eq!(done.outcome, Some(RunOutcome::Findings));
    assert!(
        matches!(done.issues.as_slice(), [IssueAction::Opened(_)]),
        "{done:?}"
    );
    assert_eq!(scene.issues.opened(), 1);

    let asked = scene.agent.asked();
    assert_eq!(asked.len(), 1);
    assert!(asked[0].tools.contains(&"vm_query".to_owned()));
    assert!(asked[0].tools.contains(&"pg_factory_health".to_owned()));
    assert!(
        !asked[0].tools.iter().any(|t| t.starts_with("datadog_")),
        "Datadog is not configured, so its tools are not offered"
    );
    assert_eq!(asked[0].ceiling, 750_000, "the role's per-run ceiling");

    let run = scene
        .store
        .run(done.run.as_ref().expect("a run"))
        .await
        .expect("the run is stored");
    assert_eq!(run.outcome, Some(RunOutcome::Findings));
    assert!(run.agent_ran && run.report_sha256.is_some() && run.gateway_record_sha256.is_some());
    assert_eq!(run.spend_micro_usd, RUN_COST);
    assert!(!run.datadog_enabled, "the run record says Datadog was off");
    let today = scene
        .store
        .day_counters(&factory_domain::values::Timestamp::parse("2026-11-20T00:00:00Z").expect("t"))
        .await
        .expect("counters");
    assert_eq!(
        (today.agent_runs, today.new_issues, today.spend_micro_usd),
        (1, 1, RUN_COST)
    );
    let states = scene.store.probe_states().await.expect("states");
    let retries = states
        .iter()
        .find(|s| s.probe_id == "retries")
        .expect("state");
    assert_eq!(retries.last_value.as_deref(), Some("12"));
    assert_eq!(
        retries.last_call_id.as_ref().map(|c| c.as_str()),
        Some("call-1")
    );
    assert!(retries.cooldown_until.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_same_problem_again_comments_once_a_day_and_opens_no_second_issue() {
    let scene = Scene::new(SceneOptions::default()).await;
    for _ in 0..4 {
        scene.agent.queue(Script::Report(valid_report()));
    }
    let first = pass(&scene).await;
    let number = match first.issues.as_slice() {
        [IssueAction::Opened(number)] => *number,
        other => panic!("{other:?}"),
    };
    // Past the six-hour cool-down, the same day: one comment.
    scene.advance(7 * HOUR);
    let second = pass(&scene).await;
    assert_eq!(second.issues, vec![IssueAction::Commented(number)]);
    // Again the same day: nothing.
    scene.advance(7 * HOUR);
    let third = pass(&scene).await;
    assert_eq!(third.issues, vec![IssueAction::Unchanged(number)]);
    assert_eq!((scene.issues.opened(), scene.issues.comments()), (1, 1));
    // The next UTC day: a comment again.
    scene.advance(11 * HOUR);
    let fourth = pass(&scene).await;
    assert_eq!(fourth.issues, vec![IssueAction::Commented(number)]);
    assert_eq!((scene.issues.opened(), scene.issues.comments()), (1, 2));
}

#[tokio::test(flavor = "multi_thread")]
async fn past_the_new_issue_cap_a_finding_is_deferred_and_named_in_the_run() {
    let scene = Scene::new(SceneOptions::default()).await;
    scene
        .spend_the_day(DayIncrement {
            new_issues: 3,
            ..DayIncrement::default()
        })
        .await;
    scene.agent.queue(Script::Report(valid_report()));
    let done = pass(&scene).await;
    assert!(
        matches!(done.issues.as_slice(), [IssueAction::Deferred(_)]),
        "{done:?}"
    );
    assert_eq!(scene.issues.opened(), 0);
    let run = scene
        .store
        .run(done.run.as_ref().expect("a run"))
        .await
        .expect("run");
    assert_eq!(
        run.deferred.len(),
        1,
        "the deferred finding is named in the run record"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_source_that_is_down_is_filed_without_any_agent_run() {
    let scene = Scene::new(SceneOptions::default()).await;
    scene.vm.stop();
    let done = pass(&scene).await;
    assert_eq!(probe(&done, "retries"), ProbeOutcome::SourceUnavailable);
    assert_eq!(done.outcome, Some(RunOutcome::SourceUnavailable));
    assert!(!done.agent_ran);
    assert!(
        scene.agent.asked().is_empty(),
        "no model for a source that is down"
    );
    assert!(
        matches!(done.issues.as_slice(), [IssueAction::Opened(_)]),
        "{done:?}"
    );
    assert_eq!(scene.issues.opened(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_report_that_cites_an_unknown_call_is_refused_and_files_nothing() {
    let scene = Scene::new(SceneOptions::default()).await;
    scene.agent.queue(Script::Report(report(
        "findings",
        vec![finding(&["retries"], "call-99", "vm_query")],
    )));
    let done = pass(&scene).await;
    assert_eq!(done.outcome, Some(RunOutcome::EvidenceMismatch));
    assert!(done.issues.is_empty());
    assert_eq!(scene.issues.calls(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_report_that_cites_a_call_of_another_tool_is_refused() {
    let scene = Scene::new(SceneOptions::default()).await;
    // call-2 was the leases probe's `pg_factory_health`, not `vm_query`.
    scene.agent.queue(Script::Report(report(
        "findings",
        vec![finding(&["retries"], "call-2", "vm_query")],
    )));
    let done = pass(&scene).await;
    assert_eq!(done.outcome, Some(RunOutcome::EvidenceMismatch));
    assert!(done.issues.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_report_that_cites_a_failed_call_is_refused() {
    let scene = Scene::new(SceneOptions {
        vm: VmAnswer::ToolError,
        ..SceneOptions::default()
    })
    .await;
    // The sweep runs the agent; the retries probe's call-1 ended tool_error and showed nothing.
    scene.agent.queue(Script::Report(report(
        "findings",
        vec![finding(&[], "call-1", "vm_query")],
    )));
    let done = scene
        .troubleshooter
        .pass(PassOptions { sweep_now: true })
        .await
        .expect("pass");
    assert_eq!(probe(&done, "retries"), ProbeOutcome::SourceUnavailable);
    assert!(done.agent_ran);
    assert_eq!(done.outcome, Some(RunOutcome::EvidenceMismatch));
    // Only the source_unavailable finding, which code wrote, is filed.
    assert_eq!(done.issues.len(), 1);
    assert_eq!(scene.issues.opened(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_healthy_report_files_nothing() {
    let scene = Scene::new(SceneOptions::default()).await;
    scene.agent.queue(Script::Report(report("healthy", vec![])));
    let done = pass(&scene).await;
    assert_eq!(done.outcome, Some(RunOutcome::Healthy));
    assert!(done.issues.is_empty());
    assert_eq!(scene.issues.calls(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_report_that_is_not_json_is_refused() {
    let scene = Scene::new(SceneOptions::default()).await;
    scene
        .agent
        .queue(Script::Report(b"{\"status\": \"findings\", oops".to_vec()));
    let done = pass(&scene).await;
    assert_eq!(done.outcome, Some(RunOutcome::ReportInvalid));
    assert!(done.issues.is_empty());
    let run = scene
        .store
        .run(done.run.as_ref().expect("a run"))
        .await
        .expect("run");
    assert!(
        run.report_sha256.is_some(),
        "the refused bytes are still accounted for"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_daily_agent_run_cap_stops_the_agent_at_the_cap_and_not_one_before() {
    let scene = Scene::new(SceneOptions::default()).await;
    scene
        .spend_the_day(DayIncrement {
            agent_runs: 7,
            ..DayIncrement::default()
        })
        .await;
    scene.agent.queue(Script::Report(report("healthy", vec![])));
    let eighth = pass(&scene).await;
    assert!(eighth.agent_ran, "the eighth run of the day is allowed");
    // Past the cool-down, same day: the ninth would be over the cap.
    scene.advance(7 * HOUR);
    let ninth = pass(&scene).await;
    assert_eq!(ninth.outcome, Some(RunOutcome::CapReached));
    assert!(!ninth.agent_ran);
    assert_eq!(scene.agent.asked().len(), 1);
    // A new UTC day starts at zero.
    scene.advance(18 * HOUR);
    scene.agent.queue(Script::Report(report("healthy", vec![])));
    let next_day = pass(&scene).await;
    assert!(next_day.agent_ran);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_probe_in_its_cooldown_starts_no_run_until_it_ends() {
    let scene = Scene::new(SceneOptions::default()).await;
    scene.agent.queue(Script::Report(report("healthy", vec![])));
    let first = pass(&scene).await;
    assert!(first.agent_ran);
    scene.advance(Duration::from_secs(300));
    let quiet = pass(&scene).await;
    assert_eq!(probe(&quiet, "retries"), ProbeOutcome::Tripped);
    assert_eq!(
        quiet.run, None,
        "a tripped probe in its cool-down makes no run"
    );
    // One second before the cool-down ends, still nothing; at its end, a run.
    scene.advance(6 * HOUR - Duration::from_secs(301));
    assert_eq!(pass(&scene).await.run, None);
    scene.advance(Duration::from_secs(1));
    scene.agent.queue(Script::Report(report("healthy", vec![])));
    assert!(pass(&scene).await.agent_ran);
    assert_eq!(scene.agent.asked().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_value_equal_to_the_threshold_does_not_trip_and_no_data_is_recorded() {
    let scene = Scene::new(SceneOptions {
        vm: VmAnswer::Sample("10".to_owned()),
        ..SceneOptions::default()
    })
    .await;
    let done = pass(&scene).await;
    assert_eq!(probe(&done, "retries"), ProbeOutcome::Ok);
    assert_eq!(done.run, None);
    scene
        .vm
        .set(VmAnswer::Sample("10.000000000000002".to_owned()));
    scene.agent.queue(Script::Report(report("healthy", vec![])));
    scene.advance(Duration::from_secs(300));
    assert_eq!(probe(&pass(&scene).await, "retries"), ProbeOutcome::Tripped);
    scene.vm.set(VmAnswer::Empty);
    scene.advance(Duration::from_secs(300));
    let empty = pass(&scene).await;
    assert_eq!(probe(&empty, "retries"), ProbeOutcome::NoData);
    assert_eq!(empty.run, None, "no data is not a trip");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dry_run_writes_nothing_to_github() {
    let scene = Scene::new(SceneOptions {
        dry_run: true,
        ..SceneOptions::default()
    })
    .await;
    scene.agent.queue(Script::Report(valid_report()));
    let done = pass(&scene).await;
    assert_eq!(done.outcome, Some(RunOutcome::Findings));
    assert!(
        matches!(done.issues.as_slice(), [IssueAction::DryRun(_)]),
        "{done:?}"
    );
    assert_eq!(scene.issues.calls(), 0, "no call reached GitHub");
    let run = scene
        .store
        .run(done.run.as_ref().expect("a run"))
        .await
        .expect("run");
    assert!(run.dry_run);
    assert!(scene.store.issues(10).await.expect("issues").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn only_one_of_two_instances_is_active() {
    let scene = Scene::new(SceneOptions::default()).await;
    let first = activate(&scene.worker_url).await.expect("reachable");
    let second = activate(&scene.worker_url).await.expect("reachable");
    assert!(matches!(first, Activation::Active(_)));
    assert!(
        matches!(second, Activation::Idle),
        "the second instance idles"
    );
    if let Activation::Active(lock) = first {
        lock.release().await;
    }
    assert!(matches!(
        activate(&scene.worker_url).await.expect("reachable"),
        Activation::Active(_)
    ));
}
