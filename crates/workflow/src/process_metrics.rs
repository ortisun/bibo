//! The snapshot job of the process metrics (ADR 0029): it reads the facts of a tenant from the
//! store and builds the `measurement` entry of a window.
//!
//! The contract is the section "The snapshot job" of
//! `docs/architecture/process-metrics-and-improvement.md`. This module holds query version 1:
//!
//! * [`read_job_records`] reads every job of the tenant with its stage runs, task nodes and
//!   events, through the listing operations of the `Store` port.
//! * [`window_facts`] is the pure half: from those records to the samples of each metric whose
//!   facts are stored.
//! * [`process_snapshot`] puts the two together and hands the samples of the window, and of the
//!   window before, to `factory_domain::metrics::snapshot`.
//!
//! Every number is an integer, and a fact that cannot be right (an end before its start) stops
//! the snapshot with an error that names the row.

use std::collections::HashMap;

use factory_domain::contracts::domain_event::{AggregateKind, DomainEvent};
use factory_domain::machines::limits::ReworkTrack;
use factory_domain::metrics::{
    ComparisonSettings, Measurement, Metric, MetricError, Milliseconds, Samples, Window,
    WindowFacts, snapshot,
};
use factory_domain::state::{StageRunStatus, TaskNodeStatus};
use factory_domain::values::{GitSha, Timestamp};
use factory_domain::vocabulary::{GateOutcome, StageKind};
use factory_ports::store::{Job, JobFilter, OutboxSeq, StageRun, StoreError, TaskNode, Tx};

use crate::engine::timeline::rework_ledger;

/// The version of the queries of this module. It goes up whenever the samples or the value of a
/// metric change, so that two snapshots can be told apart.
pub const QUERY_VERSION: u32 = 1;

/// The event a stage run emits when a worker starts it.
const STARTED: &str = "stage_run.started";

/// The event a stage run emits when it starts to wait for a person.
const WAITING_FOR_HUMAN: &str = "stage_run.waiting_for_human";

/// How many rows one read of a listing asks for.
const PAGE: u32 = 500;

/// Everything the snapshot reads about one job.
#[derive(Debug, Clone, PartialEq)]
pub struct JobRecord {
    /// The job.
    pub job: Job,
    /// Its stage runs, oldest first.
    pub stage_runs: Vec<StageRun>,
    /// The task nodes of all its stage runs.
    pub task_nodes: Vec<TaskNode>,
    /// Its events, in the order of the outbox.
    pub events: Vec<DomainEvent>,
}

/// Why a snapshot could not be built.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum SnapshotError {
    /// The store could not be read.
    #[error("the facts could not be read from the store: {0}")]
    Store(#[from] StoreError),
    /// A number left its valid range, or the facts did not fit the catalogue.
    #[error(transparent)]
    Metric(#[from] MetricError),
    /// A stored fact cannot be right. The snapshot stops: a wrong number is worse than none.
    #[error("{what} of job {job} ends before it starts; the snapshot is refused")]
    EndsBeforeItStarts {
        /// What was being measured.
        what: &'static str,
        /// The job the fact belongs to.
        job: String,
    },
}

/// The time from `start` to `end` in whole milliseconds; a part of a millisecond is dropped.
fn elapsed(
    start: Timestamp,
    end: Timestamp,
    what: &'static str,
    job: &Job,
) -> Result<Milliseconds, SnapshotError> {
    let gap = end
        .duration_since(&start)
        .ok_or_else(|| SnapshotError::EndsBeforeItStarts {
            what,
            job: job.id.to_string(),
        })?;
    let milliseconds = u64::try_from(gap.as_millis()).map_err(|_| MetricError::OutOfRange {
        what: "a duration in milliseconds",
    })?;
    Ok(Milliseconds::new(milliseconds)?)
}

/// The sum of the waits of a job for a person. A wait starts at an event
/// `stage_run.waiting_for_human` and ends at the next event of the same stage run. A wait with no
/// later event of its stage run ends at the last event of the job.
fn human_wait(record: &JobRecord) -> Result<Milliseconds, SnapshotError> {
    let what = "a wait for a person";
    let mut open: HashMap<String, Timestamp> = HashMap::new();
    let mut total = Milliseconds::ZERO;
    for event in &record.events {
        if event.aggregate.kind != AggregateKind::StageRun {
            continue;
        }
        let stage_run = event.aggregate.id.to_string();
        if let Some(since) = open.remove(&stage_run) {
            total = total.checked_add(elapsed(since, event.occurred_at, what, &record.job)?)?;
        }
        if event.event_type.as_str() == WAITING_FOR_HUMAN {
            open.insert(stage_run, event.occurred_at);
        }
    }
    if let Some(last) = record.events.last() {
        for since in open.into_values() {
            total = total.checked_add(elapsed(since, last.occurred_at, what, &record.job)?)?;
        }
    }
    Ok(total)
}

/// For each stage run of a job that a worker started: its first `stage_run.started` event and its
/// last event, both on the engine's clock. The engine creates the rows of every stage run when it
/// admits the job, so the creation of the row is not the start of the work.
fn worked_spans(record: &JobRecord) -> HashMap<String, (Timestamp, Timestamp)> {
    let mut spans: HashMap<String, (Timestamp, Timestamp)> = HashMap::new();
    for event in &record.events {
        if event.aggregate.kind != AggregateKind::StageRun {
            continue;
        }
        let stage_run = event.aggregate.id.to_string();
        match spans.get_mut(&stage_run) {
            Some(span) => span.1 = event.occurred_at,
            None if event.event_type.as_str() == STARTED => {
                spans.insert(stage_run, (event.occurred_at, event.occurred_at));
            }
            None => {}
        }
    }
    spans
}

/// The rework rounds of a job on every count, by the engine's own rule.
fn rework_rounds(record: &JobRecord) -> u64 {
    let ledger = rework_ledger(record.stage_runs.iter());
    ReworkTrack::ALL
        .iter()
        .map(|track| u64::from(ledger.used(*track)))
        .sum()
}

/// The samples of query version 1 over `window`, from the records of every job of a tenant.
pub fn window_facts(records: &[JobRecord], window: Window) -> Result<WindowFacts, SnapshotError> {
    let inside = |instant: Timestamp| window.from() <= instant && instant < window.to();
    let overflow = || MetricError::OutOfRange {
        what: "a count of the snapshot",
    };

    let mut lead_times = Vec::new();
    let mut stage_durations = Vec::new();
    let mut human_waits = Vec::new();
    let (mut tasks, mut tasks_first_pass) = (0u64, 0u64);
    let (mut rounds, mut jobs_ended) = (0u64, 0u64);

    for record in records {
        let job = &record.job;

        // MT-0001: the first delivery stage run that passed.
        let delivered = record
            .stage_runs
            .iter()
            .filter(|run| run.kind == StageKind::Delivery && run.status == StageRunStatus::Passed)
            .filter_map(|run| run.finished_at)
            .min();
        if let Some(delivered) = delivered.filter(|instant| inside(*instant)) {
            lead_times.push(elapsed(job.created_at, delivered, "the lead time", job)?);
        }

        let spans = worked_spans(record);
        for run in &record.stage_runs {
            let Some(_finished) = run.finished_at.filter(|instant| inside(*instant)) else {
                continue;
            };
            // MT-0002: every stage run that a worker started and that finished in the window.
            if let Some((started, ended)) = spans.get(&run.id.to_string()) {
                stage_durations.push(elapsed(*started, *ended, "a stage run", job)?);
            }

            // MT-0006: the tasks of the first run of a stage.
            if run.run_number != 1 {
                continue;
            }
            let passed_its_gate = run.status == StageRunStatus::Passed
                && run
                    .gate
                    .as_ref()
                    .is_some_and(|gate| gate.outcome == GateOutcome::Passed);
            for node in record
                .task_nodes
                .iter()
                .filter(|node| node.stage_run_id == run.id)
            {
                let succeeded = node.status == TaskNodeStatus::Succeeded;
                if !succeeded && node.status != TaskNodeStatus::Failed {
                    continue;
                }
                tasks = tasks.checked_add(1).ok_or_else(overflow)?;
                if succeeded && node.retry_count == 0 && passed_its_gate {
                    tasks_first_pass = tasks_first_pass.checked_add(1).ok_or_else(overflow)?;
                }
            }
        }

        // MT-0003 and MT-0007: the jobs that ended in the window.
        if job.terminal_at.is_some_and(inside) {
            human_waits.push(human_wait(record)?);
            rounds = rounds
                .checked_add(rework_rounds(record))
                .ok_or_else(overflow)?;
            jobs_ended = jobs_ended.checked_add(1).ok_or_else(overflow)?;
        }
    }

    Ok(WindowFacts::from([
        (
            Metric::LeadTimeToPullRequest,
            Samples::Durations(lead_times),
        ),
        (Metric::StageDuration, Samples::Durations(stage_durations)),
        (Metric::HumanWaitTime, Samples::Durations(human_waits)),
        (
            Metric::FirstPassGateSuccess,
            Samples::Rate {
                part: tasks_first_pass,
                whole: tasks,
            },
        ),
        (
            Metric::ReworkRounds,
            Samples::Total {
                count: rounds,
                samples: jobs_ended,
            },
        ),
    ]))
}

/// Reads every job of the transaction's tenant with its stage runs, task nodes and events.
pub async fn read_job_records(tx: &mut dyn Tx) -> Result<Vec<JobRecord>, StoreError> {
    let mut jobs = Vec::new();
    let mut after = None;
    loop {
        let page = tx.list_jobs(JobFilter::default(), after, PAGE).await?;
        jobs.extend(page.rows.into_iter().map(|job| job.value));
        match page.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }

    let mut records = Vec::with_capacity(jobs.len());
    for job in jobs {
        let stage_runs: Vec<StageRun> = tx
            .list_stage_runs(job.id)
            .await?
            .into_iter()
            .map(|run| run.value)
            .collect();
        let mut task_nodes = Vec::new();
        for run in &stage_runs {
            task_nodes.extend(
                tx.list_task_nodes(run.id)
                    .await?
                    .into_iter()
                    .map(|node| node.value),
            );
        }
        let mut events = Vec::new();
        let mut from = OutboxSeq::START;
        loop {
            let rows = tx.read_events(job.id, from, PAGE).await?;
            let full_page = rows.len() == PAGE as usize;
            if let Some(last) = rows.last() {
                from = OutboxSeq::new(last.seq.get().saturating_add(1));
            }
            events.extend(rows.into_iter().map(|row| row.event));
            if !full_page {
                break;
            }
        }
        records.push(JobRecord {
            job,
            stage_runs,
            task_nodes,
            events,
        });
    }
    Ok(records)
}

/// Builds the snapshot of `window` for the transaction's tenant. `previous` is the window to
/// compare with, when there is one. `computed_at_commit` is the commit of the factory that runs.
pub async fn process_snapshot(
    tx: &mut dyn Tx,
    window: Window,
    previous: Option<Window>,
    computed_at_commit: GitSha,
    settings: ComparisonSettings,
) -> Result<Measurement, SnapshotError> {
    let records = read_job_records(tx).await?;
    let current = window_facts(&records, window)?;
    let before = previous
        .map(|previous| window_facts(&records, previous))
        .transpose()?;
    Ok(snapshot(
        window,
        QUERY_VERSION,
        computed_at_commit,
        &current,
        before.as_ref(),
        settings,
    )?)
}
