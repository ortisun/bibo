//! The snapshot job of the process metrics, over a job the real engine ran on the in-memory store.
//!
//! The scenario is one job that runs its thirteen stages, waits one hour for an approval and
//! completes. The fake clock moves 400 seconds before each stage, so every number below can be
//! computed by hand:
//!
//! * the job is created at 08:30:00 and its delivery stage run ends at 09:50:00;
//! * each stage starts and ends at the same instant, except the approval, which starts at
//!   09:56:40, waits, and ends at 10:56:40, when the job completes.
//!
//! The rules that the scenario cannot reach (tasks, rework, a fact that cannot be right) are
//! checked on copies of its records with one field changed.

mod support;

use factory_domain::metrics::{
    ComparisonSettings, Metric, MetricError, Milliseconds, Samples, Window, WindowFacts,
};
use factory_domain::scope::TenantScope;
use factory_domain::state::{StageRunStatus, TaskNodeStatus};
use factory_domain::values::{GitSha, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::{GateOutcome, StageKind};
use factory_ports::store::{Store, TaskNode};
use factory_workflow::process_metrics::{
    JobRecord, QUERY_VERSION, SnapshotError, process_snapshot, read_job_records, window_facts,
};
use support::World;

fn at(text: &str) -> Timestamp {
    Timestamp::parse(text).expect("valid timestamp")
}

fn window(from: &str, to: &str) -> Window {
    Window::new(at(from), at(to)).expect("ordered window")
}

fn ms(value: u64) -> Milliseconds {
    Milliseconds::new(value).expect("valid duration")
}

/// The whole day of the scenario.
fn day() -> Window {
    window("2026-10-27T00:00:00Z", "2026-10-28T00:00:00Z")
}

/// One completed job with a one-hour approval wait, and the records the snapshot reads of it.
async fn completed_job() -> (World, Vec<JobRecord>) {
    let world = World::new().await;
    assert_eq!(world.database_time().await, at("2026-10-27T08:30:00Z"));
    let (job, run) = world.at_approval().await;
    world.advance(3_600);
    world.approve(job, run).await;
    let records = records(&world).await;
    (world, records)
}

async fn records(world: &World) -> Vec<JobRecord> {
    let store = world.memory_store();
    let mut tx = store
        .begin(TenantScope::new(world.tenant))
        .await
        .expect("a tx");
    read_job_records(tx.as_mut())
        .await
        .expect("the records are read")
}

fn durations(facts: &WindowFacts, metric: Metric) -> Vec<Milliseconds> {
    match &facts[&metric] {
        Samples::Durations(samples) => samples.clone(),
        other => panic!("{metric:?} is not a list of durations: {other:?}"),
    }
}

#[tokio::test]
async fn the_facts_of_a_completed_job_are_the_ones_computed_by_hand() {
    let (_world, records) = completed_job().await;
    assert_eq!(records.len(), 1);
    let facts = window_facts(&records, day()).expect("the facts fit");

    // 08:30:00 to 09:50:00 is 80 minutes.
    assert_eq!(
        durations(&facts, Metric::LeadTimeToPullRequest),
        [ms(4_800_000)]
    );
    // Twelve stages of no measurable length and the approval, which lasted its one-hour wait.
    let mut stages = durations(&facts, Metric::StageDuration);
    stages.sort();
    assert_eq!(stages.len(), 13);
    assert_eq!(stages[..12], [ms(0); 12]);
    assert_eq!(stages[12], ms(3_600_000));
    assert_eq!(durations(&facts, Metric::HumanWaitTime), [ms(3_600_000)]);
    // The scripted stages plan no tasks, and nothing was sent back.
    assert_eq!(
        facts[&Metric::FirstPassGateSuccess],
        Samples::Rate { part: 0, whole: 0 }
    );
    assert_eq!(
        facts[&Metric::ReworkRounds],
        Samples::Total {
            count: 0,
            samples: 1
        }
    );
    // Exactly the metrics whose facts are stored, no other.
    let stored: Vec<Metric> = Metric::ALL
        .iter()
        .copied()
        .filter(|metric| metric.definition().facts == factory_domain::metrics::Facts::Stored)
        .collect();
    assert_eq!(facts.keys().copied().collect::<Vec<_>>(), stored);
}

#[tokio::test]
async fn a_window_holds_its_first_instant_and_not_its_last() {
    let (_world, records) = completed_job().await;
    let count = |from: &str, to: &str, metric: Metric| {
        durations(
            &window_facts(&records, window(from, to)).expect("fits"),
            metric,
        )
        .len()
    };
    // The delivery ended at 09:50:00 and the job at 10:56:40.
    assert_eq!(
        count(
            "2026-10-27T09:50:00Z",
            "2026-10-27T09:50:01Z",
            Metric::LeadTimeToPullRequest
        ),
        1
    );
    assert_eq!(
        count(
            "2026-10-27T08:30:00Z",
            "2026-10-27T09:50:00Z",
            Metric::LeadTimeToPullRequest
        ),
        0
    );
    assert_eq!(
        count(
            "2026-10-27T09:50:01Z",
            "2026-10-28T00:00:00Z",
            Metric::LeadTimeToPullRequest
        ),
        0
    );
    assert_eq!(
        count(
            "2026-10-27T10:56:40Z",
            "2026-10-27T10:56:41Z",
            Metric::HumanWaitTime
        ),
        1
    );
    assert_eq!(
        count(
            "2026-10-27T08:30:00Z",
            "2026-10-27T10:56:40Z",
            Metric::HumanWaitTime
        ),
        0
    );
    // Up to the end of the job, without it: twelve stage runs, and the approval is left out.
    assert_eq!(
        count(
            "2026-10-27T08:30:00Z",
            "2026-10-27T10:56:40Z",
            Metric::StageDuration
        ),
        12
    );
    // The window before the job holds nothing, and every metric is still there.
    let empty = window_facts(
        &records,
        window("2026-10-26T00:00:00Z", "2026-10-27T00:00:00Z"),
    )
    .expect("fits");
    assert_eq!(empty.len(), 5);
    assert_eq!(
        empty[&Metric::ReworkRounds],
        Samples::Total {
            count: 0,
            samples: 0
        }
    );
}

#[tokio::test]
async fn a_job_that_is_still_waiting_is_not_counted_yet() {
    let world = World::new().await;
    let (_job, _run) = world.at_approval().await;
    world.advance(3_600);
    let facts = window_facts(&records(&world).await, day()).expect("fits");
    // The pull request is open, so the lead time is known; the job has not ended.
    assert_eq!(
        durations(&facts, Metric::LeadTimeToPullRequest),
        [ms(4_800_000)]
    );
    assert_eq!(durations(&facts, Metric::StageDuration).len(), 12);
    assert!(durations(&facts, Metric::HumanWaitTime).is_empty());
    assert_eq!(
        facts[&Metric::ReworkRounds],
        Samples::Total {
            count: 0,
            samples: 0
        }
    );
}

/// A task node of `record`'s implementation stage run.
fn task(record: &JobRecord, key: &str, status: TaskNodeStatus, retry_count: u32) -> TaskNode {
    let run = record
        .stage_runs
        .iter()
        .find(|run| run.kind == StageKind::Implementation)
        .expect("an implementation run");
    let ids = factory_testkit::fixtures::Ids::new();
    TaskNode {
        id: ids.task_node(),
        tenant_id: run.tenant_id,
        job_id: run.job_id,
        stage_run_id: run.id,
        key: Slug::parse(key).expect("valid key"),
        plan_sha256: Sha256Digest::parse(&format!("sha256:{}", "a".repeat(64))).expect("valid"),
        status,
        retry_count,
        current_attempt: None,
        commit: None,
        created_at: run.created_at,
    }
}

fn implementation(record: &mut JobRecord) -> &mut factory_ports::store::StageRun {
    record
        .stage_runs
        .iter_mut()
        .find(|run| run.kind == StageKind::Implementation)
        .expect("an implementation run")
}

#[tokio::test]
async fn a_task_passes_at_once_only_without_a_retry_in_a_stage_that_passed_its_gate() {
    let (_world, mut records) = completed_job().await;
    let record = &mut records[0];
    record.task_nodes = vec![
        task(record, "t-1", TaskNodeStatus::Succeeded, 0),
        task(record, "t-2", TaskNodeStatus::Succeeded, 0),
        task(record, "t-3", TaskNodeStatus::Succeeded, 1), // needed a retry
        task(record, "t-4", TaskNodeStatus::Failed, 0),
        task(record, "t-5", TaskNodeStatus::Cancelled, 0), // never judged: not a sample
        task(record, "t-6", TaskNodeStatus::Pending, 0),   // not a sample either
    ];
    let rate = |records: &[JobRecord]| {
        window_facts(records, day()).expect("fits")[&Metric::FirstPassGateSuccess].clone()
    };
    assert_eq!(rate(&records), Samples::Rate { part: 2, whole: 4 });

    // The stage was sent back: none of its tasks passed every gate at once.
    let mut sent_back = records.clone();
    implementation(&mut sent_back[0]).status = StageRunStatus::ReworkRequested;
    assert_eq!(rate(&sent_back), Samples::Rate { part: 0, whole: 4 });
    let mut failed_gate = records.clone();
    implementation(&mut failed_gate[0])
        .gate
        .as_mut()
        .expect("a gate")
        .outcome = GateOutcome::Failed;
    assert_eq!(rate(&failed_gate), Samples::Rate { part: 0, whole: 4 });

    // The tasks of a second run of the stage are the same tasks again: not samples.
    let mut second_run = records.clone();
    implementation(&mut second_run[0]).run_number = 2;
    assert_eq!(rate(&second_run), Samples::Rate { part: 0, whole: 0 });

    // A stage run that has not finished has no tasks to count yet.
    let mut unfinished = records.clone();
    implementation(&mut unfinished[0]).finished_at = None;
    assert_eq!(rate(&unfinished), Samples::Rate { part: 0, whole: 0 });
}

#[tokio::test]
async fn a_run_that_replaces_another_is_a_rework_round() {
    let (_world, mut records) = completed_job().await;
    let record = &mut records[0];
    // A round that targeted the implementation replaces it and every later stage of its set. Here
    // only the implementation run is copied, so the round is charged to it once.
    let mut again = implementation(record).clone();
    again.rework_of = Some(again.id);
    again.id = factory_testkit::fixtures::Ids::new().stage_run();
    again.run_number = 2;
    record.stage_runs.push(again);
    let facts = window_facts(&records, day()).expect("fits");
    assert_eq!(
        facts[&Metric::ReworkRounds],
        Samples::Total {
            count: 1,
            samples: 1
        }
    );
}

#[tokio::test]
async fn a_fact_that_cannot_be_right_stops_the_snapshot() {
    let (_world, mut records) = completed_job().await;
    let job = records[0].job.id.to_string();
    // The job is created after its delivery ended.
    records[0].job.created_at = at("2026-10-27T09:50:00.001Z");
    assert_eq!(
        window_facts(&records, day()),
        Err(SnapshotError::EndsBeforeItStarts {
            what: "the lead time",
            job: job.clone()
        })
    );

    // An event of a stage run that is older than the event that opened its wait.
    let (_world, mut records) = completed_job().await;
    let job = records[0].job.id.to_string();
    let last = records[0]
        .events
        .iter()
        .rposition(|event| event.event_type.as_str() == "stage_run.passed")
        .expect("the approval passed");
    records[0].events[last].occurred_at = at("2026-10-27T09:00:00Z");
    assert!(matches!(
        window_facts(&records, day()),
        Err(SnapshotError::EndsBeforeItStarts { job: named, .. }) if named == job
    ));
}

#[tokio::test]
async fn the_snapshot_of_a_week_is_the_measurement_entry() {
    let (world, _records) = completed_job().await;
    let week = window("2026-10-26T00:00:00Z", "2026-11-02T00:00:00Z");
    let before = window("2026-10-19T00:00:00Z", "2026-10-26T00:00:00Z");
    let commit = GitSha::parse("3f2a9c1d5e7b9a1c3e5f7a9b1c3d5e7f9a1b3c5d").expect("valid");

    let store = world.memory_store();
    let mut tx = store
        .begin(TenantScope::new(world.tenant))
        .await
        .expect("a tx");
    let measurement = process_snapshot(
        tx.as_mut(),
        week,
        Some(before),
        commit.clone(),
        ComparisonSettings::default(),
    )
    .await
    .expect("the snapshot is built");

    assert_eq!(measurement.query_version, QUERY_VERSION);
    assert_eq!(measurement.entry_path(), "measurements/M-2026-W44.md");
    let entry = measurement.render_entry().expect("renders");
    assert!(entry.starts_with(
        "---\n\
         id: M-2026-W44\n\
         kind: measurement\n\
         title: Process numbers, week 44 of 2026\n\
         window: { from: 2026-10-26T00:00:00Z, to: 2026-11-02T00:00:00Z }\n\
         query_version: 1\n\
         computed_at_commit: 3f2a9c1d5e7b9a1c3e5f7a9b1c3d5e7f9a1b3c5d\n\
         ---\n"
    ));
    // One job is far below the minimum of twenty samples, so no number is shown, only how many
    // samples there are; the week before has none.
    for row in [
        "| MT-0001 lead-time-to-pull-request, median | too few samples | 1 | too few samples |",
        "| MT-0002 stage-duration, 90th percentile | too few samples | 13 | too few samples |",
        "| MT-0003 human-wait-time, median | too few samples | 1 | too few samples |",
        "| MT-0006 first-pass-gate-success | too few samples | 0 | too few samples |",
        "| MT-0007 rework-rounds | too few samples | 1 | too few samples |",
        "| MT-0012 cost-per-accepted-pull-request | not measured yet | | not measured yet |",
    ] {
        assert!(entry.contains(row), "missing row: {row}\n{entry}");
    }
    assert!(entry.ends_with("Nothing: no comparison of this window shows a clear change.\n"));

    // Without a window before, the previous column says so.
    let first = process_snapshot(
        tx.as_mut(),
        week,
        None,
        commit,
        ComparisonSettings::default(),
    )
    .await
    .expect("the snapshot is built");
    assert!(
        first
            .render_entry()
            .expect("renders")
            .contains("| MT-0007 rework-rounds | too few samples | 1 | n/a |")
    );
    // A window that is refused before anything is read.
    assert_eq!(
        Window::new(at("2026-11-02T00:00:00Z"), at("2026-10-26T00:00:00Z")),
        Err(MetricError::WindowOutOfOrder)
    );
}
