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
use factory_domain::machines::invalidation::rework_stages;
use factory_domain::machines::limits::{ReworkLedger, ReworkTrack};
use factory_domain::machines::retry::{AttemptWindow, WindowEvent};
use factory_domain::state::{AttemptStatus, StageRunStatus};
use factory_domain::values::{Sha256Digest, Timestamp};
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
    /// How many attempts the run had when each decision on a dependency was recorded
    /// ([`links::decision_attempts_before`]), in the order of the links.
    pub(crate) dependency_decisions: Vec<u32>,
    /// The blocks that stopped the run at its latest block, as (gate, block code), read from the
    /// block event the engine itself wrote. Empty for a run that never blocked, and for a block
    /// whose event carries none, which no override may then pass.
    pub(crate) blocks: Vec<(String, String)>,
    /// The reason code of the run's latest move to `WAITING_FOR_HUMAN`, read from the event the
    /// engine wrote, such as `independent-reviewer-unavailable`. `None` for a run that never
    /// waited, or whose latest wait names no reason.
    pub(crate) wait_reason: Option<String>,
    /// When the run last moved to `BLOCKED` (transitions S11 and S21): the `occurred_at` of the
    /// newest `stage_run.blocked` event. The milestone of the solo mode's wait for a decision on a
    /// dependency or on build code (ADR 0022). `None` when no such event is readable.
    pub(crate) blocked_at: Option<Timestamp>,
    /// When the run last moved to `WAITING_FOR_HUMAN` (transitions S07, S10 and S22): the
    /// `occurred_at` of the newest `stage_run.waiting_for_human` event. The milestone of the solo
    /// mode's wait for an approval or a translation warning. `None` when none is readable.
    pub(crate) waiting_for_human_at: Option<Timestamp>,
}

impl RunRecord {
    /// True when a decision on a dependency was recorded after the latest attempt of the run, that
    /// is, while the run was blocked by that attempt. A decision recorded before an earlier block
    /// does not count for a later one.
    pub(crate) fn dependency_decision_since_last_attempt(&self) -> bool {
        let latest = self
            .attempts
            .iter()
            .map(|attempt| attempt.number)
            .max()
            .unwrap_or(0);
        self.dependency_decisions.contains(&latest)
    }
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
        let dependency_decisions = linked
            .iter()
            .filter(|link| link.direction == ArtifactDirection::Input)
            .filter_map(|link| links::decision_attempts_before(link.role.as_str()))
            .collect();
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
            dependency_decisions,
            blocks: Vec::new(),
            wait_reason: None,
            blocked_at: None,
            waiting_for_human_at: None,
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

/// What the last successful attempt produced, with its media types from the tenant's index.
async fn read_outputs(
    tx: &mut dyn Tx,
    linked: &[StageRunArtifact],
) -> Result<Vec<NamedArtifact>, EngineError> {
    let mut outputs = Vec::new();
    for (name, link) in last_outputs(linked) {
        let entry = tx.get_artifact_index(&link.sha256).await?;
        outputs.push(NamedArtifact {
            name,
            artifact: entry.artifact,
        });
    }
    Ok(outputs)
}

/// The output links of the highest attempt number, with the deliverable name each one carries. A
/// stage run can reach its gate more than once, and each attempt that did has its own links.
fn last_outputs(
    linked: &[StageRunArtifact],
) -> Vec<(factory_domain::values::Slug, &StageRunArtifact)> {
    let produced: Vec<_> = linked
        .iter()
        .filter(|link| link.direction == ArtifactDirection::Output)
        .filter_map(|link| {
            links::parse_output_role(link.role.as_str())
                .map(|(name, attempt)| (attempt, name, link))
        })
        .collect();
    let Some(last) = produced.iter().map(|(attempt, ..)| *attempt).max() else {
        return Vec::new();
    };
    produced
        .into_iter()
        .filter(|(attempt, ..)| *attempt == last)
        .map(|(_, name, link)| (name, link))
        .collect()
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

/// The rework rounds a job has used, for each count, read from its stage runs.
///
/// A round that sends work back to `target` creates one new run for each stage of
/// `rework_stages(target)`, and each of them names the run it replaces (`rework_of`). A change from
/// outside the pipeline creates runs too, but names none (`Why::External`, `Why::ArtifactChanged`
/// in `replace`), so it is not a round. For one stage, the runs that name a predecessor are
/// therefore the rounds whose set holds that stage, and a round is charged to the stage it
/// targeted: walking the stages in pipeline order, the rounds that targeted a stage are the runs
/// it has with a predecessor, less the rounds of earlier targets that also replaced it. The count
/// it is charged to is `ReworkTrack::for_target`. Nothing about the count is stored with a run, so
/// a job created before a change to that rule (ADR 0023 split the specification and the design
/// off the code count) is counted under the rule in force, the same as a new job: its rounds are
/// all still counted, each on the count its target now belongs to.
///
/// This inverts `rework_stages`, the function that created the runs, and holds while every target
/// replaces only itself and the stages after it (the `rework_stages_replace_only_later_stages`
/// test pins that). A stage that a round replaced but the job never ran has no predecessor, and
/// the subtraction saturates at zero for it.
pub(crate) fn rework_ledger<'a>(runs: impl IntoIterator<Item = &'a StageRun>) -> ReworkLedger {
    let mut replaced: BTreeMap<usize, u32> = BTreeMap::new();
    for run in runs {
        if run.rework_of.is_some() {
            *replaced.entry(position(run.kind)).or_default() += 1;
        }
    }
    // Rounds on each count, in the order of `ReworkTrack::ALL`. A `u32` sum that saturates, then
    // a saturating narrowing to the ledger's `u8`: a count past 255 reads as 255, which is above
    // every cap, so it can only refuse a round, never grant one.
    let mut used: BTreeMap<ReworkTrack, u32> = BTreeMap::new();
    let mut rounds: Vec<(StageKind, u32)> = Vec::new();
    for kind in StageKind::ALL.iter().copied() {
        let seen = replaced.get(&position(kind)).copied().unwrap_or(0);
        let carried: u32 = rounds
            .iter()
            .filter(|(target, _)| rework_stages(*target).contains(&kind))
            .map(|(_, count)| *count)
            .sum();
        let targeted = seen.saturating_sub(carried);
        let count = used.entry(ReworkTrack::for_target(kind)).or_default();
        *count = count.saturating_add(targeted);
        rounds.push((kind, targeted));
    }
    used.into_iter()
        .fold(ReworkLedger::default(), |ledger, (track, rounds)| {
            ledger.with_used(track, u8::try_from(rounds).unwrap_or(u8::MAX))
        })
}

/// The digest of what failed in the last rework round of each stage kind, by pipeline position.
/// The run that sent work back records it with its gate outcome (`GateRecord::failing_set_sha256`),
/// and the newest such run of a kind is its last round.
fn failing_sets_of<'a>(
    runs: impl IntoIterator<Item = &'a StageRun>,
) -> BTreeMap<usize, Sha256Digest> {
    let mut newest: BTreeMap<usize, (u32, Sha256Digest)> = BTreeMap::new();
    for run in runs {
        if run.status != StageRunStatus::ReworkRequested {
            continue;
        }
        let Some(digest) = run
            .gate
            .as_ref()
            .and_then(|gate| gate.failing_set_sha256.as_ref())
        else {
            continue;
        };
        let slot = newest
            .entry(position(run.kind))
            .or_insert((0, digest.clone()));
        if run.run_number >= slot.0 {
            *slot = (run.run_number, digest.clone());
        }
    }
    newest
        .into_iter()
        .map(|(at, (_, digest))| (at, digest))
        .collect()
}

/// Everything the engine knows about one job.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Timeline {
    /// The stage runs, in the order the store lists them (oldest first).
    pub(crate) runs: Vec<RunRecord>,
    /// Rework rounds used by the job, for each count. Derived from the stage runs
    /// ([`rework_ledger`]).
    pub(crate) rework: ReworkLedger,
    /// What the job's attempts spent, in millionths of a US dollar. Read from the outbox, because
    /// the store has no cost on an attempt ([`Timeline::read_outbox`]).
    pub(crate) spent_micro_usd: u64,
    /// The digest of what failed in the last rework round of each stage kind, from the stage runs.
    pub(crate) failing_sets: BTreeMap<usize, Sha256Digest>,
    /// The ids of the commands already applied, for duplicate detection. Read from the outbox
    /// ([`Timeline::read_outbox`]).
    pub(crate) commands: BTreeSet<CausationId>,
}

impl Timeline {
    /// Reads the job from the store: its stage runs, their attempts and their links, and then the
    /// events for the few facts the store has no row for ([`Self::read_outbox`]).
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
        let rework = rework_ledger(runs.iter().map(|record| &record.row.value));
        let failing_sets = failing_sets_of(runs.iter().map(|record| &record.row.value));
        let mut timeline = Self {
            runs,
            rework,
            failing_sets,
            ..Self::default()
        };
        timeline.read_outbox(tx, job).await?;
        Ok(timeline)
    }

    /// Reads the three facts that the store has no row for yet, from the job's outbox events.
    /// Everything else in the timeline comes from rows, so these are the only reads of events, and
    /// each is a plain fold that skips an event type it does not know.
    ///
    /// | Fact | Read from | What the store lacks |
    /// |---|---|---|
    /// | Commands already applied | `causation_id` of every event: the envelope, not the payload | A record of applied commands that outlives the outbox. The event is written in the same transaction as the move (INV-03), so it is as durable as the move; it stops being enough if old events are ever archived. |
    /// | What the job spent | `cost_micro_usd` in the payload of each attempt event | A cost on the attempt: `Attempt::cost_micro_usd`, written by `AttemptEnd::cost_micro_usd` in the transition that ends it (column `attempts.cost_micro_usd bigint not null default 0`). The job's spend is then the sum over `list_attempts`. The broker meters each token, but the store does not link an attempt to its token, so the broker cannot be summed per job either. |
    /// | Who approved or rejected | `transition_id` (`S14`, `S16`) of the stage run events: the envelope | The row says `PASSED` or `FAILED`, not whether a person decided. `ApprovalOps::record_approval` is the place, and an approval needs the pull request binding (head, tree, base) that Slice 1 does not have yet. |
    async fn read_outbox(&mut self, tx: &mut dyn Tx, job: JobId) -> Result<(), EngineError> {
        let mut from = OutboxSeq::START;
        loop {
            let rows = tx.read_events(job, from, PAGE).await?;
            let count = rows.len();
            for row in &rows {
                self.apply(row)?;
            }
            match rows.last() {
                Some(last) if count == PAGE as usize => {
                    from = OutboxSeq::new(last.seq.get().saturating_add(1));
                }
                _ => return Ok(()),
            }
        }
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
            // Every wait for a person names its reason in the event's reason code, when it has
            // one. The newest wait of a run replaces an older one: events are read in order.
            ("stage_run.waiting_for_human", _) => {
                let id = aggregate_run(event);
                let run = self.run_mut(id)?;
                run.wait_reason = event
                    .reason_code
                    .as_ref()
                    .map(|code| code.as_str().to_owned());
                run.waiting_for_human_at = Some(event.occurred_at);
                Ok(())
            }
            // The block event names the gate and the code of each block. The newest block of a
            // run replaces an older one: events are read in order.
            ("stage_run.blocked", "S11") => {
                let id = aggregate_run(event);
                let run = self.run_mut(id)?;
                run.blocks = blocks_of(&event.payload);
                run.blocked_at = Some(event.occurred_at);
                Ok(())
            }
            // Every other move to `BLOCKED` (S21) starts a new wait of the solo mode too.
            ("stage_run.blocked", _) => {
                let id = aggregate_run(event);
                self.run_mut(id)?.blocked_at = Some(event.occurred_at);
                Ok(())
            }
            (
                "attempt.succeeded" | "attempt.failed" | "attempt.timed_out" | "attempt.lease_lost"
                | "attempt.cancelled",
                _,
            ) => {
                self.spent_micro_usd = self
                    .spent_micro_usd
                    .saturating_add(super::payload::attempt_cost_micro_usd(event).unwrap_or(0));
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// The (gate, code) pairs a block event carries. A payload without them, or with an entry that
/// is not a pair of words, yields nothing for that entry.
fn blocks_of(payload: &serde_json::Map<String, Value>) -> Vec<(String, String)> {
    payload
        .get(key::BLOCKS)
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| {
                    Some((
                        entry.get("gate")?.as_str()?.to_owned(),
                        entry.get("code")?.as_str()?.to_owned(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn aggregate_run(event: &DomainEvent) -> StageRunId {
    StageRunId::from_uuid(event.aggregate.id.as_uuid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::contracts::Contract;
    use factory_domain::values::{MediaType, Slug};

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

    fn run(kind: StageKind, run_number: u32, rework_of: bool, status: StageRunStatus) -> StageRun {
        let at = factory_domain::values::Timestamp::parse("2026-10-27T08:00:00Z").expect("a time");
        StageRun {
            id: StageRunId::from_uuid(uuid::Uuid::from_u128(
                (u128::from(run_number) << 8) | position(kind) as u128,
            )),
            tenant_id: factory_domain::ids::TenantId::from_uuid(uuid::Uuid::from_u128(1)),
            job_id: JobId::from_uuid(uuid::Uuid::from_u128(2)),
            kind,
            run_number,
            status,
            lease_epoch: factory_ports::store::LeaseEpoch::new(0),
            max_attempts: 20,
            not_before: at,
            rework_of: rework_of.then(|| StageRunId::from_uuid(uuid::Uuid::from_u128(3))),
            contract_sha256: None,
            gate: None,
            created_at: at,
            finished_at: None,
            superseded_at: None,
        }
    }

    /// The first run of every stage, then a round for each target in `targets`: one new run of
    /// each stage of `rework_stages(target)`, naming a predecessor, as `supersede_and_replace`
    /// makes them.
    fn job_with_rounds(targets: &[StageKind]) -> Vec<StageRun> {
        let mut runs: Vec<StageRun> = StageKind::ALL
            .iter()
            .map(|kind| run(*kind, 1, false, StageRunStatus::Superseded))
            .collect();
        for target in targets {
            for kind in rework_stages(*target) {
                let number = u32::try_from(runs.iter().filter(|r| r.kind == kind).count())
                    .expect("a small count")
                    + 1;
                runs.push(run(kind, number, true, StageRunStatus::Superseded));
            }
        }
        runs
    }

    /// Rounds used as (specification, design, code, documentation).
    fn used(runs: &[StageRun]) -> (u8, u8, u8, u8) {
        let ledger = rework_ledger(runs);
        (
            ledger.used(ReworkTrack::Specification),
            ledger.used(ReworkTrack::Design),
            ledger.used(ReworkTrack::Code),
            ledger.used(ReworkTrack::Documentation),
        )
    }

    #[test]
    fn a_job_that_was_never_sent_back_has_used_no_round() {
        assert_eq!(used(&job_with_rounds(&[])), (0, 0, 0, 0));
    }

    #[test]
    fn a_round_is_charged_to_the_count_of_its_target() {
        assert_eq!(
            used(&job_with_rounds(&[StageKind::Specification])),
            (1, 0, 0, 0)
        );
        assert_eq!(
            used(&job_with_rounds(&[StageKind::Architecture])),
            (0, 1, 0, 0)
        );
        assert_eq!(
            used(&job_with_rounds(&[StageKind::TaskPlanning])),
            (0, 1, 0, 0)
        );
        assert_eq!(
            used(&job_with_rounds(&[StageKind::Implementation])),
            (0, 0, 1, 0)
        );
        assert_eq!(
            used(&job_with_rounds(&[StageKind::Documenting])),
            (0, 0, 0, 1)
        );
    }

    #[test]
    fn specification_rounds_are_not_charged_to_the_design_or_the_code() {
        // Run 29 of scenario E1: two specification rounds, then the architecture was sent back.
        // A specification round replaces every later stage, the architecture and the
        // implementation included, and still only the specification count moves.
        let runs = job_with_rounds(&[
            StageKind::Specification,
            StageKind::Specification,
            StageKind::Architecture,
        ]);
        assert_eq!(used(&runs), (2, 1, 0, 0));
        let runs = job_with_rounds(&[
            StageKind::Specification,
            StageKind::Specification,
            StageKind::Architecture,
            StageKind::TaskPlanning,
            StageKind::Implementation,
            StageKind::Implementation,
            StageKind::Documenting,
        ]);
        assert_eq!(used(&runs), (2, 2, 2, 1));
    }

    #[test]
    fn a_count_past_what_a_byte_holds_saturates_and_never_wraps() {
        // 300 rounds read back as 255, which is above every cap and so refuses the next round.
        let runs = job_with_rounds(&[StageKind::Documenting; 300]);
        assert_eq!(used(&runs), (0, 0, 0, u8::MAX));
    }

    #[test]
    fn rounds_of_different_targets_are_told_apart_although_they_replace_the_same_later_stages() {
        // A round that targets IMPLEMENTATION replaces DOCUMENTING too, and so does one that
        // targets DOCUMENTING. Only the second is a documentation round.
        let runs = job_with_rounds(&[
            StageKind::Implementation,
            StageKind::Documenting,
            StageKind::Implementation,
            StageKind::TaskPlanning,
        ]);
        assert_eq!(used(&runs), (0, 1, 2, 1));
    }

    #[test]
    fn a_change_from_outside_the_pipeline_is_not_a_round() {
        // A new run that names no predecessor was made by an external change.
        let mut runs = job_with_rounds(&[StageKind::Implementation]);
        runs.push(run(StageKind::Intake, 2, false, StageRunStatus::Passed));
        runs.push(run(
            StageKind::Specification,
            2,
            false,
            StageRunStatus::Passed,
        ));
        runs.push(run(
            StageKind::Implementation,
            3,
            false,
            StageRunStatus::Passed,
        ));
        assert_eq!(used(&runs), (0, 0, 1, 0));
    }

    #[test]
    fn a_stage_a_round_replaced_but_the_job_never_ran_does_not_make_a_negative_count() {
        // The round replaced IMPLEMENTATION and the stages after it, but only IMPLEMENTATION has a
        // run that names a predecessor.
        let mut runs = vec![run(
            StageKind::Implementation,
            1,
            false,
            StageRunStatus::Superseded,
        )];
        runs.push(run(
            StageKind::Implementation,
            2,
            true,
            StageRunStatus::Passed,
        ));
        runs.push(run(
            StageKind::Validation,
            1,
            false,
            StageRunStatus::Pending,
        ));
        assert_eq!(used(&runs), (0, 0, 1, 0));
    }

    #[test]
    fn rework_stages_replace_only_later_stages() {
        // `rework_ledger` walks the stages in pipeline order and subtracts what earlier targets
        // replaced. That is exact only while no target replaces an earlier stage.
        for target in StageKind::ALL.iter().copied() {
            for replaced in rework_stages(target) {
                assert!(
                    position(replaced) >= position(target),
                    "a round that targets {target} replaces the earlier stage {replaced}"
                );
            }
        }
    }

    #[test]
    fn the_failing_set_of_a_kind_is_the_newest_rework_requested_run_that_recorded_one() {
        let failed = |digest: &[u8]| {
            Some(factory_ports::store::GateRecord {
                outcome: factory_domain::vocabulary::GateOutcome::Failed,
                report_sha256: None,
                failing_set_sha256: Some(Sha256Digest::of(digest)),
            })
        };
        let mut first = run(
            StageKind::Validation,
            1,
            false,
            StageRunStatus::ReworkRequested,
        );
        first.gate = failed(b"first");
        let mut second = run(
            StageKind::Validation,
            2,
            true,
            StageRunStatus::ReworkRequested,
        );
        second.gate = failed(b"second");
        // A person's rework has no gate record and leaves the digest of the last gate round.
        let by_person = run(
            StageKind::Validation,
            3,
            true,
            StageRunStatus::ReworkRequested,
        );
        // A run that failed for good also recorded a digest, but it is not a rework round.
        let mut final_failure = run(StageKind::Review, 1, false, StageRunStatus::Failed);
        final_failure.gate = failed(b"final");
        let sets = failing_sets_of([&second, &first, &by_person, &final_failure]);
        assert_eq!(
            sets.get(&position(StageKind::Validation)),
            Some(&Sha256Digest::of(b"second"))
        );
        assert_eq!(sets.get(&position(StageKind::Review)), None);
    }

    const JOB: &str = "00000000-0000-7000-8000-000000000001";
    const RUN_A: &str = "00000000-0000-7000-8000-0000000000a1";
    const RUN_C: &str = "00000000-0000-7000-8000-0000000000c1";
    const ATTEMPT_1: &str = "00000000-0000-7000-8000-0000000000d1";

    fn event(
        seq: u64,
        event_type: &str,
        transition: &str,
        aggregate: (&str, &str),
        payload: serde_json::Value,
        causation: Option<&str>,
    ) -> OutboxRow {
        let document = serde_json::json!({
            "schema_version": 1,
            "event_id": format!("00000000-0000-7000-8000-{seq:012x}"),
            "event_type": event_type,
            "event_version": 1,
            "tenant_id": "00000000-0000-7000-8000-0000000000ff",
            "job_id": JOB,
            "aggregate": { "type": aggregate.0, "id": aggregate.1, "version": 2 },
            "transition_id": transition,
            "correlation_id": JOB,
            "causation_id": causation,
            "occurred_at": "2026-10-27T08:30:00Z",
            "producer": "workflow.engine",
            "payload": payload,
        });
        OutboxRow {
            seq: OutboxSeq::new(seq),
            event: DomainEvent::from_json_value(document).expect("a valid event"),
        }
    }

    /// A timeline that lists one run, `RUN_A`, as the store would.
    fn timeline_with_run_a() -> Timeline {
        let mut row = run(StageKind::Approval, 1, false, StageRunStatus::Passed);
        row.id = StageRunId::parse(RUN_A).expect("an id");
        Timeline {
            runs: vec![RunRecord {
                id: row.id,
                kind: row.kind,
                row: Versioned {
                    value: row,
                    version: factory_ports::store::Version::FIRST,
                },
                attempts: Vec::new(),
                answers: Vec::new(),
                outputs: Vec::new(),
                human_inputs: Vec::new(),
                reauthorize: false,
                approved: false,
                rejected: false,
                dependency_decisions: Vec::new(),
                blocks: Vec::new(),
                wait_reason: None,
                blocked_at: None,
                waiting_for_human_at: None,
            }],
            ..Timeline::default()
        }
    }

    #[test]
    fn a_repeated_command_is_recognised_by_its_id() {
        let command = "00000000-0000-7000-8000-0000000000e1";
        let mut timeline = Timeline::default();
        timeline
            .apply(&event(
                1,
                "job.admitted",
                "J01",
                ("job", JOB),
                serde_json::json!({}),
                Some(command),
            ))
            .expect("folds");
        assert!(timeline.has_applied(CausationId::parse(command).expect("id")));
        assert!(
            !timeline.has_applied(
                CausationId::parse("00000000-0000-7000-8000-0000000000e2").expect("id")
            )
        );
    }

    #[test]
    fn what_attempts_spent_is_the_sum_of_the_costs_of_their_events() {
        let mut timeline = Timeline::default();
        for (seq, kind, cost) in [
            (1, "attempt.failed", 300),
            (2, "attempt.succeeded", 700),
            (3, "attempt.cancelled", 0),
        ] {
            timeline
                .apply(&event(
                    seq,
                    kind,
                    "A05",
                    ("attempt", ATTEMPT_1),
                    serde_json::json!({ "cost_micro_usd": cost }),
                    None,
                ))
                .expect("folds");
        }
        // Another event type with the same key is not spend.
        timeline
            .apply(&event(
                4,
                "job.admitted",
                "J01",
                ("job", JOB),
                serde_json::json!({ "cost_micro_usd": 5_000 }),
                None,
            ))
            .expect("folds");
        assert_eq!(timeline.spent_micro_usd, 1_000);
    }

    #[test]
    fn a_person_s_approval_and_rejection_are_read_from_the_transition_of_the_event() {
        let mut timeline = timeline_with_run_a();
        timeline
            .apply(&event(
                1,
                "stage_run.passed",
                "S08",
                ("stage_run", RUN_A),
                serde_json::json!({}),
                None,
            ))
            .expect("folds");
        assert!(!timeline.runs[0].approved, "a gate pass is not an approval");
        timeline
            .apply(&event(
                2,
                "stage_run.passed",
                "S14",
                ("stage_run", RUN_A),
                serde_json::json!({}),
                None,
            ))
            .expect("folds");
        assert!(timeline.runs[0].approved);
        timeline
            .apply(&event(
                3,
                "stage_run.failed",
                "S16",
                ("stage_run", RUN_A),
                serde_json::json!({}),
                None,
            ))
            .expect("folds");
        assert!(timeline.runs[0].rejected);
    }

    #[test]
    fn an_event_that_names_a_run_the_store_does_not_list_is_a_corrupt_timeline() {
        let mut timeline = timeline_with_run_a();
        let orphan = event(
            1,
            "stage_run.passed",
            "S14",
            ("stage_run", RUN_C),
            serde_json::json!({}),
            None,
        );
        assert!(matches!(
            timeline.apply(&orphan),
            Err(EngineError::Corrupt(_))
        ));
    }

    #[test]
    fn an_event_type_the_engine_does_not_know_is_skipped() {
        let mut timeline = Timeline::default();
        let unknown = event(
            2,
            "task_node.ready",
            "T01",
            ("task_node", RUN_C),
            serde_json::json!({}),
            None,
        );
        assert!(timeline.apply(&unknown).is_ok());
    }

    fn link(direction: ArtifactDirection, role: &str, content: &[u8]) -> StageRunArtifact {
        StageRunArtifact {
            stage_run: StageRunId::from_uuid(uuid::Uuid::from_u128(1)),
            direction,
            role: Slug::parse(role).expect("a role"),
            sha256: Sha256Digest::of(content),
            created_at: factory_domain::values::Timestamp::parse("2026-10-27T08:00:00Z")
                .expect("a time"),
        }
    }

    #[test]
    fn the_outputs_of_a_stage_run_are_those_of_its_last_attempt_that_produced_any() {
        let links = [
            link(ArtifactDirection::Output, "spec.a1", b"first spec"),
            link(ArtifactDirection::Output, "plan.a1", b"first plan"),
            link(ArtifactDirection::Input, "human-answer-1", b"an answer"),
            link(ArtifactDirection::Output, "spec.a3", b"third spec"),
            link(ArtifactDirection::Output, "plan.a3", b"third plan"),
            // Not a role of the engine's: skipped.
            link(ArtifactDirection::Output, "other", b"foreign"),
        ];
        let last: Vec<_> = last_outputs(&links)
            .into_iter()
            .map(|(name, link)| (name.as_str().to_owned(), link.sha256.clone()))
            .collect();
        assert_eq!(
            last,
            [
                ("spec".to_owned(), Sha256Digest::of(b"third spec")),
                ("plan".to_owned(), Sha256Digest::of(b"third plan")),
            ]
        );
        assert!(last_outputs(&[]).is_empty());
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
