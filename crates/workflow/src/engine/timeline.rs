//! The engine's view of one job, read from the store.
//!
//! The rows are the source of truth, and the listing operations of the `Store` port give them:
//! `list_stage_runs` for the stage runs, `list_attempts` for the attempts of each one, and
//! `list_stage_run_artifacts` for what each one produced and which answers a person gave it. The
//! status of a stage run, an attempt and a job is read from its row, so a new process reads the
//! same view and the view cannot drift from the rows.
//!
//! A few facts are still read from the outbox in [`Timeline::load`], because the store has no row
//! for them yet. Each is named in the code that reads it, with what is missing.

use std::collections::{BTreeMap, BTreeSet};

use factory_domain::contracts::{ArtifactRef, DomainEvent};
use factory_domain::ids::{AttemptId, CausationId, JobId, StageRunId};
use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::limits::{ReworkLedger, ReworkTrack};
use factory_domain::machines::retry::{AttemptWindow, WindowEvent};
use factory_domain::state::{AttemptStatus, StageRunStatus};
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::StageKind;
use factory_ports::store::{
    ArtifactDirection, Attempt, OutboxRow, OutboxSeq, StageRun, StageRunArtifact, Tx, Versioned,
};
use serde_json::Value;

use super::config::position;
use super::error::EngineError;
use super::links;
use super::payload::key;
use crate::handlers::NamedArtifact;

/// How many events one read asks for.
const PAGE: u32 = 500;

/// How one attempt ended, as far as the retry rules care.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttemptEnd {
    /// The attempt produced a valid output.
    Succeeded,
    /// The attempt ended badly, with this class.
    Failed(FailureClass),
    /// The attempt was cancelled. This is not a failure.
    Cancelled,
}

/// One attempt of a stage run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttemptRecord {
    pub(crate) id: AttemptId,
    pub(crate) number: u32,
    /// `None` while the attempt is live (`STARTING`, `RUNNING`, `CANCELLING`).
    pub(crate) end: Option<AttemptEnd>,
}

impl AttemptRecord {
    /// Reads the end of an attempt from its row. `TIMED_OUT` and `LEASE_LOST` are statuses and not
    /// failure classes in the column (`attempt_end_rule`), so the status names the class.
    fn from_row(row: &Attempt) -> Result<Self, EngineError> {
        let end = match row.status {
            AttemptStatus::Starting | AttemptStatus::Running | AttemptStatus::Cancelling => None,
            AttemptStatus::Succeeded => Some(AttemptEnd::Succeeded),
            AttemptStatus::Failed => Some(AttemptEnd::Failed(row.failure_class.ok_or(
                EngineError::Corrupt("a failed attempt has no failure class"),
            )?)),
            AttemptStatus::TimedOut => Some(AttemptEnd::Failed(FailureClass::TimedOut)),
            AttemptStatus::LeaseLost => Some(AttemptEnd::Failed(FailureClass::LeaseLost)),
            AttemptStatus::Cancelled => Some(AttemptEnd::Cancelled),
        };
        Ok(Self {
            id: row.id,
            number: row.number,
            end,
        })
    }
}

/// An answer a person gave a stage run, as its input link says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnswerRecord {
    /// How many attempts the stage run had when the person answered.
    pub(crate) attempts_before: u32,
    pub(crate) artifact: ArtifactRef,
}

/// One stage run of the job and what the engine knows about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunRecord {
    /// The row, as it was read.
    pub(crate) row: Versioned<StageRun>,
    pub(crate) id: StageRunId,
    pub(crate) kind: StageKind,
    /// The attempts, by number.
    pub(crate) attempts: Vec<AttemptRecord>,
    /// The answers people gave, oldest first.
    pub(crate) answers: Vec<AnswerRecord>,
    /// What the last successful attempt produced.
    pub(crate) outputs: Vec<NamedArtifact>,
    /// The answers as artifacts, oldest first.
    pub(crate) human_inputs: Vec<ArtifactRef>,
    /// The source request was edited after the intake snapshot, so this `INTAKE` run, which
    /// replaced an earlier one, must ask for re-authorization before an agent reads the new text
    /// (NT-AUTHZ-05). Only an edit of the request replaces an `INTAKE` run: it consumes nothing
    /// that the pipeline produces, and no rework route leads to it.
    pub(crate) reauthorize: bool,
    /// An approver approved the run (`S14`).
    pub(crate) approved: bool,
    /// An approver rejected the run (`S16`).
    pub(crate) rejected: bool,
}

impl RunRecord {
    /// Reads the attempts and the links of a stage run row.
    async fn read(tx: &mut dyn Tx, row: Versioned<StageRun>) -> Result<Self, EngineError> {
        let (id, kind) = (row.value.id, row.value.kind);
        // A `PENDING` run has never started, so it has no attempt and no link.
        let (attempt_rows, linked) = if row.value.status == StageRunStatus::Pending {
            (Vec::new(), Vec::new())
        } else {
            (
                tx.list_attempts(id).await?,
                tx.list_stage_run_artifacts(id).await?,
            )
        };
        let mut attempts = attempt_rows
            .iter()
            .map(|attempt| AttemptRecord::from_row(&attempt.value))
            .collect::<Result<Vec<_>, _>>()?;
        attempts.sort_by_key(|attempt| attempt.number);
        let answers = read_answers(tx, &linked).await?;
        let human_inputs = answers
            .iter()
            .map(|answer| answer.artifact.clone())
            .collect();
        let outputs = read_outputs(tx, &linked).await?;
        let reauthorize =
            kind == StageKind::Intake && row.value.run_number > 1 && row.value.rework_of.is_none();
        Ok(Self {
            row,
            id,
            kind,
            attempts,
            answers,
            outputs,
            human_inputs,
            reauthorize,
            approved: false,
            rejected: false,
        })
    }

    /// The attempts and invalid outputs counted since the last human answer.
    pub(crate) fn window(&self) -> AttemptWindow {
        window_of(&self.attempts, &self.answers)
    }

    /// The attempt with this id.
    pub(crate) fn attempt(&self, id: AttemptId) -> Option<&AttemptRecord> {
        self.attempts.iter().find(|attempt| attempt.id == id)
    }
}

/// The answers among the links of a stage run, oldest first. An answer given after `k` attempts
/// comes before one given after `k + 1`; two with the same `k` keep the order of the links.
async fn read_answers(
    tx: &mut dyn Tx,
    linked: &[StageRunArtifact],
) -> Result<Vec<AnswerRecord>, EngineError> {
    let mut answers = Vec::new();
    for link in linked
        .iter()
        .filter(|link| link.direction == ArtifactDirection::Input)
    {
        if let Some(attempts_before) = links::answer_attempts_before(link.role.as_str()) {
            let entry = tx.get_artifact_index(&link.sha256).await?;
            answers.push(AnswerRecord {
                attempts_before,
                artifact: entry.artifact,
            });
        }
    }
    answers.sort_by_key(|answer| answer.attempts_before);
    Ok(answers)
}

/// What the last successful attempt produced: the output links of the highest attempt number.
async fn read_outputs(
    tx: &mut dyn Tx,
    linked: &[StageRunArtifact],
) -> Result<Vec<NamedArtifact>, EngineError> {
    let mut produced: Vec<(u32, &StageRunArtifact, factory_domain::values::Slug)> = linked
        .iter()
        .filter(|link| link.direction == ArtifactDirection::Output)
        .filter_map(|link| {
            links::parse_output_role(link.role.as_str())
                .map(|(name, attempt)| (attempt, link, name))
        })
        .collect();
    let Some(last) = produced.iter().map(|(attempt, ..)| *attempt).max() else {
        return Ok(Vec::new());
    };
    produced.retain(|(attempt, ..)| *attempt == last);
    let mut outputs = Vec::with_capacity(produced.len());
    for (_, link, name) in produced {
        let entry = tx.get_artifact_index(&link.sha256).await?;
        outputs.push(NamedArtifact {
            name,
            artifact: entry.artifact,
        });
    }
    Ok(outputs)
}

/// The window of attempts since the last answer, for `attempts` (by number) and `answers` (by
/// the attempts that came before each).
///
/// An answer that came after `k` attempts sits between attempt `k` and attempt `k + 1`. The
/// domain's [`AttemptWindow`] then starts again at it, so the restart at an answer is one rule in
/// one place (INV-10).
pub(crate) fn window_of(attempts: &[AttemptRecord], answers: &[AnswerRecord]) -> AttemptWindow {
    let mut history = Vec::new();
    let mut pending = answers
        .iter()
        .map(|answer| answer.attempts_before)
        .peekable();
    for attempt in attempts {
        while pending.next_if(|before| *before < attempt.number).is_some() {
            history.push(WindowEvent::HumanAnswered);
        }
        if let Some(AttemptEnd::Failed(class)) = attempt.end {
            history.push(WindowEvent::AttemptFailed(class));
        }
    }
    history.extend(pending.map(|_| WindowEvent::HumanAnswered));
    AttemptWindow::from_history(&history)
}

/// Everything the engine knows about one job.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Timeline {
    /// The stage runs, in the order the store lists them (oldest first).
    pub(crate) runs: Vec<RunRecord>,
    /// Rework rounds used by the job, for each count.
    pub(crate) rework: ReworkLedger,
    /// What the job's attempts spent, in millionths of a US dollar.
    pub(crate) spent_micro_usd: u64,
    /// The digest of what failed in the last rework round of each stage kind.
    pub(crate) failing_sets: BTreeMap<usize, Sha256Digest>,
    /// The ids of the commands already applied, for duplicate detection.
    pub(crate) commands: BTreeSet<CausationId>,
}

impl Timeline {
    /// Reads the job from the store: its stage runs, their attempts and their links, and then the
    /// events the store has no row for.
    ///
    /// # Errors
    /// [`EngineError::Corrupt`] when a row or an event the engine wrote cannot be read back, and
    /// the store errors of the reads.
    pub(crate) async fn load(tx: &mut dyn Tx, job: JobId) -> Result<Self, EngineError> {
        let rows = tx.list_stage_runs(job).await?;
        let mut runs = Vec::with_capacity(rows.len());
        for row in rows {
            runs.push(RunRecord::read(tx, row).await?);
        }
        let mut timeline = Self {
            runs,
            ..Self::default()
        };
        let mut from = OutboxSeq::START;
        loop {
            let rows = tx.read_events(job, from, PAGE).await?;
            let count = rows.len();
            for row in &rows {
                timeline.apply(row)?;
            }
            match rows.last() {
                Some(last) if count == PAGE as usize => {
                    from = OutboxSeq::new(last.seq.get().saturating_add(1));
                }
                _ => break,
            }
        }
        Ok(timeline)
    }

    /// The record of a stage run.
    pub(crate) fn run(&self, id: StageRunId) -> Option<&RunRecord> {
        self.runs.iter().find(|run| run.id == id)
    }

    fn run_mut(&mut self, id: StageRunId) -> Result<&mut RunRecord, EngineError> {
        self.runs
            .iter_mut()
            .find(|run| run.id == id)
            .ok_or(EngineError::Corrupt(
                "an event names a stage run the job does not list",
            ))
    }

    /// The run that replaced a superseded run: the next run of the same stage kind. `None` for a
    /// run that was not superseded.
    pub(crate) fn replacement_of(&self, record: &RunRecord) -> Option<StageRunId> {
        if record.row.value.status != StageRunStatus::Superseded {
            return None;
        }
        self.runs_of(record.kind)
            .filter(|run| run.row.value.run_number > record.row.value.run_number)
            .min_by_key(|run| run.row.value.run_number)
            .map(|run| run.id)
    }

    /// The stage runs of one stage kind, oldest first.
    pub(crate) fn runs_of(&self, kind: StageKind) -> impl Iterator<Item = &RunRecord> {
        self.runs.iter().filter(move |run| run.kind == kind)
    }

    /// The digest of what failed in the last rework round of `kind`.
    pub(crate) fn last_failing_set(&self, kind: StageKind) -> Option<&Sha256Digest> {
        self.failing_sets.get(&position(kind))
    }

    /// True when a command with this id was already applied.
    pub(crate) fn has_applied(&self, command: CausationId) -> bool {
        self.commands.contains(&command)
    }

    /// Folds one event. An event type that the engine does not know is skipped, so events that a
    /// later version adds do not break an older reader.
    fn apply(&mut self, row: &OutboxRow) -> Result<(), EngineError> {
        let event = &row.event;
        if let Some(cause) = event.causation_id {
            self.commands.insert(cause);
        }
        let transition = event.transition_id.as_str();
        match (event.event_type.as_str(), transition) {
            ("stage_run.rework_requested", _) => self.rework_requested(event),
            ("stage_run.passed", "S14") => {
                let id = aggregate_run(event);
                self.run_mut(id)?.approved = true;
                Ok(())
            }
            ("stage_run.failed", "S16") => {
                let id = aggregate_run(event);
                self.run_mut(id)?.rejected = true;
                Ok(())
            }
            (
                "attempt.succeeded" | "attempt.failed" | "attempt.timed_out" | "attempt.lease_lost"
                | "attempt.cancelled",
                _,
            ) => {
                self.spent_micro_usd = self.spent_micro_usd.saturating_add(
                    event
                        .payload
                        .get(key::COST)
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                );
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn rework_requested(&mut self, event: &DomainEvent) -> Result<(), EngineError> {
        let id = aggregate_run(event);
        if let Some(Value::String(track)) = event.payload.get(key::REWORK_TRACK) {
            let track = ReworkTrack::parse(track)
                .map_err(|_| EngineError::Corrupt("a rework track in an event is unknown"))?;
            let (code, documentation) = (
                self.rework.used(ReworkTrack::Code),
                self.rework.used(ReworkTrack::Documentation),
            );
            self.rework = match track {
                ReworkTrack::Code => ReworkLedger::new(code.saturating_add(1), documentation),
                ReworkTrack::Documentation => {
                    ReworkLedger::new(code, documentation.saturating_add(1))
                }
            };
        }
        if let Some(Value::String(text)) = event.payload.get(key::FAILING_SET) {
            let digest = Sha256Digest::parse(text)
                .map_err(|_| EngineError::Corrupt("a failing set digest in an event is invalid"))?;
            let kind = self.run_mut(id)?.kind;
            self.failing_sets.insert(position(kind), digest);
        }
        Ok(())
    }
}

fn aggregate_run(event: &DomainEvent) -> StageRunId {
    StageRunId::from_uuid(event.aggregate.id.as_uuid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::values::MediaType;

    fn attempt(number: u32, end: Option<AttemptEnd>) -> AttemptRecord {
        AttemptRecord {
            id: AttemptId::from_uuid(uuid::Uuid::from_u128(u128::from(number))),
            number,
            end,
        }
    }

    fn failed(number: u32, class: FailureClass) -> AttemptRecord {
        attempt(number, Some(AttemptEnd::Failed(class)))
    }

    fn answer(attempts_before: u32) -> AnswerRecord {
        AnswerRecord {
            attempts_before,
            artifact: ArtifactRef {
                sha256: Sha256Digest::of(b"an answer"),
                media_type: MediaType::parse("text/plain").expect("a media type"),
                size_bytes: None,
            },
        }
    }

    #[test]
    fn failures_count_in_the_window() {
        let attempts = [
            failed(1, FailureClass::ToolError),
            failed(2, FailureClass::InvalidOutput),
        ];
        let window = window_of(&attempts, &[]);
        assert_eq!(window.attempts_used(), 2);
        assert_eq!(window.invalid_output_failures(), 1);
    }

    #[test]
    fn an_answer_starts_the_window_again() {
        let attempts = [
            failed(1, FailureClass::ToolError),
            failed(2, FailureClass::ToolError),
        ];
        let window = window_of(&attempts, &[answer(2)]);
        assert_eq!(window.attempts_used(), 0, "the window starts again");
    }

    #[test]
    fn only_the_attempts_after_the_last_answer_count() {
        let attempts = [
            failed(1, FailureClass::ToolError),
            failed(2, FailureClass::ToolError),
            failed(3, FailureClass::InvalidOutput),
            failed(4, FailureClass::ToolError),
        ];
        // One answer after attempt 2 and a later one after attempt 3.
        let window = window_of(&attempts, &[answer(2), answer(3)]);
        assert_eq!(window.attempts_used(), 1);
        assert_eq!(window.invalid_output_failures(), 0);
        let window = window_of(&attempts, &[answer(2)]);
        assert_eq!(window.attempts_used(), 2);
        assert_eq!(window.invalid_output_failures(), 1);
    }

    #[test]
    fn an_answer_before_any_attempt_leaves_the_window_empty_for_the_first_try() {
        let attempts = [failed(1, FailureClass::ToolError)];
        let window = window_of(&attempts, &[answer(0)]);
        assert_eq!(window.attempts_used(), 1);
    }

    #[test]
    fn a_cancelled_or_live_attempt_is_not_a_failure() {
        let attempts = [
            attempt(1, Some(AttemptEnd::Cancelled)),
            attempt(2, None),
            attempt(3, Some(AttemptEnd::Succeeded)),
        ];
        assert_eq!(window_of(&attempts, &[]).attempts_used(), 0);
    }

    #[test]
    fn a_timed_out_or_lease_lost_status_is_the_failure_class_of_the_same_name() {
        let row = |status, failure_class| Attempt {
            id: AttemptId::from_uuid(uuid::Uuid::from_u128(1)),
            tenant_id: factory_domain::ids::TenantId::from_uuid(uuid::Uuid::from_u128(2)),
            job_id: JobId::from_uuid(uuid::Uuid::from_u128(3)),
            stage_run_id: StageRunId::from_uuid(uuid::Uuid::from_u128(4)),
            number: 1,
            status,
            worker: factory_ports::store::WorkerId::new("worker-1").expect("a worker"),
            epoch: factory_ports::store::LeaseEpoch::new(1),
            lease_expires_at: factory_domain::values::Timestamp::parse("2026-10-27T08:30:00Z")
                .expect("a time"),
            last_heartbeat_at: None,
            deadline_at: factory_domain::values::Timestamp::parse("2026-10-27T08:45:00Z")
                .expect("a time"),
            teardown_deadline_at: None,
            failure_class,
            output: None,
            sandbox: None,
            created_at: factory_domain::values::Timestamp::parse("2026-10-27T08:00:00Z")
                .expect("a time"),
            ended_at: None,
        };
        let end = |status, class| AttemptRecord::from_row(&row(status, class)).map(|a| a.end);
        assert_eq!(
            end(AttemptStatus::TimedOut, None),
            Ok(Some(AttemptEnd::Failed(FailureClass::TimedOut)))
        );
        assert_eq!(
            end(AttemptStatus::LeaseLost, None),
            Ok(Some(AttemptEnd::Failed(FailureClass::LeaseLost)))
        );
        assert_eq!(
            end(AttemptStatus::Failed, Some(FailureClass::ToolError)),
            Ok(Some(AttemptEnd::Failed(FailureClass::ToolError)))
        );
        assert_eq!(end(AttemptStatus::Cancelling, None), Ok(None));
        assert!(matches!(
            end(AttemptStatus::Failed, None),
            Err(EngineError::Corrupt(_))
        ));
    }
}
