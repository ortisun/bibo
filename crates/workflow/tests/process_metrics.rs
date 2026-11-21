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
//!
//! Query version 2 adds four metrics. A second scenario lets the real engine store their facts:
//! the implementation stage uses 1200 input and 300 output tokens for 4500 millionths of a
//! dollar, and the delivery stage opens pull request 17. The engine writes the use on the row of
//! the attempt and the pull request in its table; the merge is then recorded as the worker's step
//! records it. The runs of a task are written by the real implementation stage, which the
//! scripted stages of this world replace, so their rules are checked on records
//! (`crates/workflow/tests/implementation` shows the stage recording a run, and
//! `crates/composition/tests/ledger.rs` shows the row it becomes).

mod support;

use factory_domain::contracts::agent_manifest::RecommendedTier;
use factory_domain::metrics::{
    ComparisonSettings, Metric, MetricError, MicroUsd, Milliseconds, Samples, Window, WindowFacts,
};
use factory_domain::scope::TenantScope;
use factory_domain::state::{StageRunStatus, TaskNodeStatus};
use factory_domain::values::{GitSha, NonEmptyString, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::{GateOutcome, StageKind};
use factory_ports::agent::RuntimeId;
use factory_ports::store::{
    Attempt, MAX_METERED, MeteredUsage, PullRequestRecord, PullRequestSighting, Store, StoredFate,
    TaskNode, TaskRun,
};
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
    assert_eq!(empty.len(), 9);
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
         query_version: 2\n\
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
        // The four metrics of query version 2 are measured: with no fact yet, they have too few
        // samples, and they no longer say "not measured yet".
        "| MT-0011 human-rejection-rate | too few samples | 0 | too few samples |",
        "| MT-0012 cost-per-accepted-pull-request | too few samples | 0 | too few samples |",
        "| MT-0013 tokens-per-task | too few samples | 0 | too few samples |",
        "| MT-0014 escalations-to-the-larger-model | too few samples | 0 | too few samples |",
        // A metric whose facts are still not stored says so.
        "| MT-0009 escaped-defects | not measured yet | | not measured yet |",
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

// ---- query version 2: the fate of a pull request, the spend, the runs of a task ----------------

/// Identifiers for the rows these tests add to the records of the scenario. One generator for
/// the whole file, so that no two rows share an identifier.
fn fresh() -> &'static factory_testkit::fixtures::Ids {
    static IDS: std::sync::OnceLock<factory_testkit::fixtures::Ids> = std::sync::OnceLock::new();
    IDS.get_or_init(factory_testkit::fixtures::Ids::new)
}

/// A task node of the implementation stage run with an identifier of its own.
fn node(record: &JobRecord, key: &str, status: TaskNodeStatus, retry_count: u32) -> TaskNode {
    TaskNode {
        id: fresh().task_node(),
        ..task(record, key, status, retry_count)
    }
}

fn usage(input: u64, output: u64, cost: u64, requests: u64) -> MeteredUsage {
    MeteredUsage::new(input, output, cost, requests).expect("a use in range")
}

fn money(micro_usd: i64) -> MicroUsd {
    MicroUsd::new(micro_usd).expect("an amount in range")
}

/// A pull request of `record`'s job with this fate.
fn pull(record: &JobRecord, number: u64, fate: StoredFate) -> PullRequestRecord {
    PullRequestRecord {
        tenant_id: record.job.tenant_id,
        job_id: record.job.id,
        repository: record.job.repository,
        number,
        opened_at: at("2026-10-27T09:50:00Z"),
        fate,
        last_checked_at: fate.recorded_at(),
    }
}

fn merged(recorded: &str) -> StoredFate {
    StoredFate::Merged {
        // The code host's time is far from the window on purpose: it must not decide.
        decided_at: at("2026-01-01T00:00:00Z"),
        recorded_at: at(recorded),
    }
}

fn closed(recorded: &str) -> StoredFate {
    StoredFate::Closed {
        decided_at: at("2026-01-01T00:00:00Z"),
        recorded_at: at(recorded),
    }
}

/// An attempt of `record`'s implementation stage run that ended at `ended` with this use.
fn attempt(record: &JobRecord, ended: Option<&str>, metered: Option<MeteredUsage>) -> Attempt {
    let mut copy = record
        .attempts
        .iter()
        .find(|attempt| attempt.ended_at.is_some())
        .expect("the scenario has an attempt that ended")
        .clone();
    copy.id = fresh().attempt();
    copy.ended_at = ended.map(at);
    copy.metered = metered;
    copy
}

/// A run of the builder on `node`, recorded at `recorded` on `tier` with this use.
fn task_run(
    node: &TaskNode,
    recorded: &str,
    tier: RecommendedTier,
    metered: Option<MeteredUsage>,
) -> TaskRun {
    TaskRun {
        tenant_id: node.tenant_id,
        job_id: node.job_id,
        stage_run_id: node.stage_run_id,
        task_node_id: node.id,
        attempt_id: fresh().attempt(),
        runtime: RuntimeId::new("claude-code-cli").expect("a runtime"),
        model: NonEmptyString::parse("claude-sonnet-5-5").expect("a model"),
        tier,
        metered,
        recorded_at: at(recorded),
    }
}

fn facts_of(records: &[JobRecord]) -> WindowFacts {
    window_facts(records, day()).expect("the facts fit")
}

#[tokio::test]
async fn the_rejection_rate_counts_the_pull_requests_decided_in_the_window() {
    let (_world, mut records) = completed_job().await;
    let rate = |records: &[JobRecord]| facts_of(records)[&Metric::HumanRejectionRate].clone();

    // Zero: no pull request, and then one that nobody decided about.
    assert_eq!(rate(&records), Samples::Rate { part: 0, whole: 0 });
    records[0].pull_requests = vec![pull(&records[0], 1, StoredFate::Open)];
    assert_eq!(rate(&records), Samples::Rate { part: 0, whole: 0 });

    // One merged, then one closed without a merge.
    records[0].pull_requests = vec![pull(&records[0], 1, merged("2026-10-27T12:00:00Z"))];
    assert_eq!(rate(&records), Samples::Rate { part: 0, whole: 1 });
    records[0].pull_requests = vec![pull(&records[0], 1, closed("2026-10-27T12:00:00Z"))];
    assert_eq!(rate(&records), Samples::Rate { part: 1, whole: 1 });

    // The window is cut by the time the factory recorded the fate: its first instant is inside,
    // its last is not, and the time the code host gave is never looked at.
    records[0].pull_requests = vec![
        pull(&records[0], 1, closed("2026-10-27T00:00:00Z")),
        pull(&records[0], 2, merged("2026-10-27T23:59:59.999Z")),
        pull(&records[0], 3, closed("2026-10-28T00:00:00Z")),
        pull(&records[0], 4, merged("2026-10-26T23:59:59.999Z")),
        pull(&records[0], 5, StoredFate::Open),
    ];
    assert_eq!(rate(&records), Samples::Rate { part: 1, whole: 2 });
}

#[tokio::test]
async fn the_cost_of_an_accepted_pull_request_is_the_metered_spend_over_the_merges() {
    let (_world, mut records) = completed_job().await;
    let cost =
        |records: &[JobRecord]| facts_of(records)[&Metric::CostPerAcceptedPullRequest].clone();
    // The scripted stages run no agent: every attempt used nothing, and that is known.
    assert!(
        records[0]
            .attempts
            .iter()
            .all(|attempt| attempt.metered == Some(MeteredUsage::ZERO))
    );
    assert_eq!(
        cost(&records),
        Samples::Amount {
            total: MicroUsd::ZERO,
            items: 0
        }
    );

    // The attempts that ended in the window, by the same rule of the two ends.
    let inside = "2026-10-27T12:00:00Z";
    let spent = |micro_usd| Some(usage(10, 5, micro_usd, 1));
    let extra = vec![
        attempt(&records[0], Some("2026-10-27T00:00:00Z"), spent(1)),
        attempt(&records[0], Some(inside), spent(7)),
        attempt(&records[0], Some("2026-10-27T23:59:59.999Z"), spent(100)),
        // Outside the window, and one that has not ended.
        attempt(&records[0], Some("2026-10-28T00:00:00Z"), spent(1_000)),
        attempt(&records[0], Some("2026-10-26T23:59:59.999Z"), spent(10_000)),
        attempt(&records[0], None, None),
        // A meter that was not read adds nothing: it is not known, and it is not zero either.
        attempt(&records[0], Some(inside), None),
    ];
    records[0].attempts.extend(extra);
    assert_eq!(
        cost(&records),
        Samples::Amount {
            total: money(108),
            items: 0
        }
    );

    // The items are the merges recorded in the window; a close and an open one are not items.
    records[0].pull_requests = vec![
        pull(&records[0], 1, merged(inside)),
        pull(&records[0], 2, merged(inside)),
        pull(&records[0], 3, closed(inside)),
        pull(&records[0], 4, StoredFate::Open),
        pull(&records[0], 5, merged("2026-10-28T00:00:00Z")),
    ];
    assert_eq!(
        cost(&records),
        Samples::Amount {
            total: money(108),
            items: 2
        }
    );
}

#[tokio::test]
async fn a_spend_at_the_largest_amount_is_kept_and_one_millionth_more_stops_the_snapshot() {
    let (_world, mut records) = completed_job().await;
    let inside = "2026-10-27T12:00:00Z";
    // One attempt at the largest value the store keeps: 2^53 - 1 millionths.
    let largest = attempt(&records[0], Some(inside), Some(usage(0, 0, MAX_METERED, 1)));
    records[0].attempts.push(largest);
    assert_eq!(
        facts_of(&records)[&Metric::CostPerAcceptedPullRequest],
        Samples::Amount {
            total: MicroUsd::MAX,
            items: 0
        }
    );
    // One millionth more leaves the valid range of money: no saturated total is shown.
    let one_more = attempt(&records[0], Some(inside), Some(usage(0, 0, 1, 1)));
    records[0].attempts.push(one_more);
    assert!(matches!(
        window_facts(&records, day()),
        Err(SnapshotError::Metric(MetricError::OutOfRange { .. }))
    ));
}

#[tokio::test]
async fn the_tokens_of_a_task_are_the_sum_over_its_runs_and_an_unknown_run_leaves_it_out() {
    let (_world, mut records) = completed_job().await;
    let record = &mut records[0];
    let nodes = vec![
        node(record, "t-1", TaskNodeStatus::Succeeded, 0), // one run
        node(record, "t-2", TaskNodeStatus::Succeeded, 1), // two runs
        node(record, "t-3", TaskNodeStatus::Failed, 0),    // a run that used nothing
        node(record, "t-4", TaskNodeStatus::Succeeded, 1), // one of its runs is not known
        node(record, "t-5", TaskNodeStatus::Succeeded, 0), // never run by the builder
        node(record, "t-6", TaskNodeStatus::Pending, 0),   // not judged: not a sample
        node(record, "t-7", TaskNodeStatus::Cancelled, 0), // not a sample either
    ];
    let standard = RecommendedTier::Standard;
    record.task_runs = vec![
        task_run(
            &nodes[0],
            "2026-10-27T09:00:00Z",
            standard,
            Some(usage(1200, 300, 9, 2)),
        ),
        task_run(
            &nodes[1],
            "2026-10-27T09:01:00Z",
            standard,
            Some(usage(1, 0, 0, 1)),
        ),
        task_run(
            &nodes[1],
            "2026-10-27T09:02:00Z",
            standard,
            Some(usage(0, 1, 0, 1)),
        ),
        task_run(
            &nodes[2],
            "2026-10-27T09:03:00Z",
            standard,
            Some(MeteredUsage::ZERO),
        ),
        task_run(
            &nodes[3],
            "2026-10-27T09:04:00Z",
            standard,
            Some(usage(500, 500, 3, 1)),
        ),
        task_run(&nodes[3], "2026-10-27T09:05:00Z", standard, None),
        task_run(
            &nodes[5],
            "2026-10-27T09:06:00Z",
            standard,
            Some(usage(9, 9, 9, 9)),
        ),
        task_run(
            &nodes[6],
            "2026-10-27T09:07:00Z",
            standard,
            Some(usage(9, 9, 9, 9)),
        ),
    ];
    record.task_nodes = nodes;
    let facts = facts_of(&records);
    // 1200 + 300; 1 + 1; zero. The task with a run that is not known is left out: a sum with a
    // hole in it would be shown as less than the truth.
    assert_eq!(
        facts[&Metric::TokensPerTask],
        Samples::Counts(vec![1500, 2, 0])
    );
    // It is still a task that was run, as are the three above: four, none on a higher tier.
    assert_eq!(
        facts[&Metric::EscalationsToTheLargerModel],
        Samples::Rate { part: 0, whole: 4 }
    );

    // The tasks of a second run of the stage count too: they are other tasks, with tokens of
    // their own (MT-0006 counts the first run only).
    let mut second_run = records.clone();
    implementation(&mut second_run[0]).run_number = 2;
    assert_eq!(
        facts_of(&second_run)[&Metric::TokensPerTask],
        Samples::Counts(vec![1500, 2, 0])
    );
    // A stage run that has not finished has no task to count yet.
    let mut unfinished = records.clone();
    implementation(&mut unfinished[0]).finished_at = None;
    let facts = facts_of(&unfinished);
    assert_eq!(facts[&Metric::TokensPerTask], Samples::Counts(Vec::new()));
    assert_eq!(
        facts[&Metric::EscalationsToTheLargerModel],
        Samples::Rate { part: 0, whole: 0 }
    );
}

#[tokio::test]
async fn the_tokens_of_a_task_at_the_largest_count_are_kept_and_one_more_stops_the_snapshot() {
    let (_world, mut records) = completed_job().await;
    let record = &mut records[0];
    let node = node(record, "t-1", TaskNodeStatus::Succeeded, 1);
    let standard = RecommendedTier::Standard;
    // Two runs that add up to exactly 2^53 - 1 tokens.
    record.task_runs = vec![
        task_run(
            &node,
            "2026-10-27T09:00:00Z",
            standard,
            Some(usage(MAX_METERED - 1, 0, 0, 1)),
        ),
        task_run(
            &node,
            "2026-10-27T09:01:00Z",
            standard,
            Some(usage(0, 1, 0, 1)),
        ),
    ];
    record.task_nodes = vec![node.clone()];
    assert_eq!(
        facts_of(&records)[&Metric::TokensPerTask],
        Samples::Counts(vec![MAX_METERED])
    );
    // One token more is outside the valid range of a count.
    records[0].task_runs.push(task_run(
        &node,
        "2026-10-27T09:02:00Z",
        standard,
        Some(usage(1, 0, 0, 1)),
    ));
    assert!(matches!(
        window_facts(&records, day()),
        Err(SnapshotError::Metric(MetricError::OutOfRange { .. }))
    ));
    // One run alone can hold 2^54 - 2 tokens (both counts at their largest): refused as well.
    records[0].task_runs = vec![task_run(
        &node,
        "2026-10-27T09:00:00Z",
        standard,
        Some(usage(MAX_METERED, MAX_METERED, 0, 1)),
    )];
    assert!(matches!(
        window_facts(&records, day()),
        Err(SnapshotError::Metric(MetricError::OutOfRange { .. }))
    ));
}

#[tokio::test]
async fn an_escalation_is_a_run_on_a_higher_tier_than_the_first_run_of_the_task() {
    use RecommendedTier::{Large, Small, Standard};
    let (_world, mut records) = completed_job().await;
    let record = &mut records[0];
    let nodes: Vec<TaskNode> = (1..=7)
        .map(|n| node(record, &format!("t-{n}"), TaskNodeStatus::Succeeded, 1))
        .collect();
    let run = |node: usize, minute: u32, tier| {
        task_run(
            &nodes[node],
            &format!("2026-10-27T09:{minute:02}:00Z"),
            tier,
            None,
        )
    };
    record.task_runs = vec![
        // One run: nothing to compare with.
        run(0, 0, Large),
        // The same tier twice: no escalation.
        run(1, 1, Standard),
        run(1, 2, Standard),
        // Up one tier, and up two: escalations.
        run(2, 3, Standard),
        run(2, 4, Large),
        run(3, 5, Small),
        run(3, 6, Large),
        // Down: not an escalation.
        run(4, 7, Large),
        run(4, 8, Standard),
        // Up and back down: one of its runs was higher than the first.
        run(5, 9, Small),
        run(5, 10, Standard),
        run(5, 11, Small),
        // Down and back to the first tier: never above it.
        run(6, 12, Standard),
        run(6, 13, Small),
        run(6, 14, Standard),
    ];
    record.task_nodes = nodes;
    assert_eq!(
        facts_of(&records)[&Metric::EscalationsToTheLargerModel],
        Samples::Rate { part: 3, whole: 7 }
    );
    // The use of every run is unknown here, so no task is a sample of the tokens.
    assert_eq!(
        facts_of(&records)[&Metric::TokensPerTask],
        Samples::Counts(Vec::new())
    );
}

#[tokio::test]
async fn the_engine_stores_the_use_of_an_attempt_and_the_pull_request_and_the_snapshot_reads_them()
{
    let world = World::new().await;
    world
        .script(StageKind::Implementation)
        .agent_using(1200, 300, 4_500);
    world.script(StageKind::Delivery).opens_pull_request(17);
    let (job, run) = world.at_approval().await;
    world.advance(3_600);
    world.approve(job, run).await;

    // What the engine stored: the use of the one attempt that ran an agent, a known zero for the
    // others, and the pull request of the delivery stage, still open.
    let records_before = records(&world).await;
    let record = &records_before[0];
    let implementation_run = record
        .stage_runs
        .iter()
        .find(|run| run.kind == StageKind::Implementation)
        .expect("an implementation run")
        .id;
    for attempt in &record.attempts {
        let expected = if attempt.stage_run_id == implementation_run {
            usage(1200, 300, 4_500, 1)
        } else {
            MeteredUsage::ZERO
        };
        assert_eq!(attempt.metered, Some(expected));
    }
    assert_eq!(record.attempts.len(), 13);
    assert_eq!(record.pull_requests.len(), 1);
    let stored = record.pull_requests[0];
    assert_eq!((stored.number, stored.fate), (17, StoredFate::Open));
    assert_eq!((stored.job_id, stored.repository), (job, world.repository));
    // The delivery stage ended at 09:50:00, and the engine recorded the pull request with it.
    assert_eq!(stored.opened_at, at("2026-10-27T09:50:00Z"));

    // Nobody decided yet: the spend of the day is there, with no merge to share it over.
    let facts = facts_of(&records_before);
    assert_eq!(
        facts[&Metric::HumanRejectionRate],
        Samples::Rate { part: 0, whole: 0 }
    );
    assert_eq!(
        facts[&Metric::CostPerAcceptedPullRequest],
        Samples::Amount {
            total: money(4_500),
            items: 0
        }
    );

    // A person merges it; the worker's step records what the code host says, two hours later.
    world.advance(7_200);
    let store = world.memory_store();
    let mut tx = store
        .begin(TenantScope::new(world.tenant))
        .await
        .expect("a tx");
    tx.record_pull_request_sighting(
        world.repository,
        17,
        PullRequestSighting::Merged(at("2026-10-27T11:30:00Z")),
    )
    .await
    .expect("the sighting is recorded");
    tx.commit().await.expect("commit");

    let facts = facts_of(&records(&world).await);
    assert_eq!(
        facts[&Metric::HumanRejectionRate],
        Samples::Rate { part: 0, whole: 1 }
    );
    assert_eq!(
        facts[&Metric::CostPerAcceptedPullRequest],
        Samples::Amount {
            total: money(4_500),
            items: 1
        }
    );

    // The entry of the week shows the four metrics as measured. One pull request is far below
    // the twenty samples a number needs, so the entry says how many there are.
    let week = window("2026-10-26T00:00:00Z", "2026-11-02T00:00:00Z");
    let mut tx = store
        .begin(TenantScope::new(world.tenant))
        .await
        .expect("a tx");
    let entry = process_snapshot(
        tx.as_mut(),
        week,
        None,
        GitSha::parse("3f2a9c1d5e7b9a1c3e5f7a9b1c3d5e7f9a1b3c5d").expect("valid"),
        ComparisonSettings::default(),
    )
    .await
    .expect("the snapshot is built")
    .render_entry()
    .expect("renders");
    for row in [
        "| MT-0011 human-rejection-rate | too few samples | 1 | n/a |",
        "| MT-0012 cost-per-accepted-pull-request | too few samples | 1 | n/a |",
        "| MT-0013 tokens-per-task | too few samples | 0 | n/a |",
        "| MT-0014 escalations-to-the-larger-model | too few samples | 0 | n/a |",
    ] {
        assert!(entry.contains(row), "missing row: {row}\n{entry}");
    }
}

#[tokio::test]
async fn twenty_merges_show_the_cost_and_the_rate_as_numbers() {
    // Twenty decided pull requests is the fewest from which a number is shown: 19 merged and one
    // closed for the rate, and 20 merged for the cost in a second set.
    let (world, mut records) = completed_job().await;
    let inside = "2026-10-27T12:00:00Z";
    let mut pulls: Vec<PullRequestRecord> = (1..=19)
        .map(|number| pull(&records[0], number, merged(inside)))
        .collect();
    pulls.push(pull(&records[0], 20, closed(inside)));
    records[0].pull_requests = pulls.clone();
    let spent = attempt(&records[0], Some(inside), Some(usage(0, 0, 250_000_001, 1)));
    records[0].attempts.push(spent);
    let entry = |records: &[JobRecord]| {
        factory_domain::metrics::snapshot(
            day(),
            QUERY_VERSION,
            GitSha::parse("3f2a9c1d5e7b9a1c3e5f7a9b1c3d5e7f9a1b3c5d").expect("valid"),
            &facts_of(records),
            None,
            ComparisonSettings::default(),
        )
        .expect("the snapshot is built")
    };
    let shown = entry(&records);
    let text = shown.render_entry().expect("renders");
    assert!(
        text.contains("| MT-0011 human-rejection-rate | 5.0 % (1 of 20) | 20 | n/a |"),
        "{text}"
    );
    // Nineteen merges are one short of the minimum for the cost.
    assert!(
        text.contains("| MT-0012 cost-per-accepted-pull-request | too few samples | 19 | n/a |"),
        "{text}"
    );

    // With the twentieth merged too: 250.000001 / 20 = 12.50000005, half to even to 12.500000.
    pulls[19] = pull(&records[0], 20, merged(inside));
    records[0].pull_requests = pulls;
    assert_eq!(
        facts_of(&records)[&Metric::CostPerAcceptedPullRequest],
        Samples::Amount {
            total: money(250_000_001),
            items: 20
        }
    );
    let text = entry(&records).render_entry().expect("renders");
    assert!(
        text.contains("| MT-0011 human-rejection-rate | 0.0 % (0 of 20) | 20 | n/a |"),
        "{text}"
    );
    let cost_row = text
        .lines()
        .find(|line| line.starts_with("| MT-0012 "))
        .expect("the cost row");
    assert_eq!(
        cost_row, "| MT-0012 cost-per-accepted-pull-request | 12.50 USD | 20 | n/a |",
        "{text}"
    );
    drop(world);
}
