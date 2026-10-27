//! The engine's view of one job, rebuilt by reading that job's outbox events in order.
//!
//! The status of each stage run, attempt and job is read from its row, which is the source of
//! truth. What the rows cannot say, the events do: which stage runs the job has, which attempts
//! each one had and how they ended, when a retry back-off ends, how many rework rounds the job
//! has used, what each stage run produced and which answers a person gave it. Each transition
//! writes those facts into its own event in the same transaction (see [`payload`]), so the view
//! is exactly as durable as the transition, and a new process rebuilds the same view.
//!
//! [`Timeline::fold`] is a pure function of the events. An event type that it does not know is
//! skipped, which keeps the engine compatible with events that a later version adds.

use std::collections::{BTreeMap, BTreeSet};

use factory_domain::contracts::{ArtifactRef, DomainEvent};
use factory_domain::ids::{AttemptId, CausationId, JobId, StageRunId};
use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::limits::{ReworkLedger, ReworkTrack};
use factory_domain::machines::retry::{AttemptWindow, WindowEvent};
use factory_domain::values::{MediaType, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::StageKind;
use factory_ports::store::{OutboxRow, OutboxSeq, Tx};
use serde_json::{Map, Value};

use super::config::position;
use super::error::EngineError;
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
    pub(crate) deadline_at: Option<Timestamp>,
    /// When the engine asked the attempt to stop (`A08`).
    pub(crate) cancel_requested_at: Option<Timestamp>,
    pub(crate) end: Option<AttemptEnd>,
}

/// One stage run of the job and what the engine recorded about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunRecord {
    pub(crate) id: StageRunId,
    pub(crate) kind: StageKind,
    pub(crate) attempts: Vec<AttemptRecord>,
    /// Attempt failures and human answers, in order. The attempt window starts at the last answer.
    pub(crate) window: Vec<WindowEvent>,
    /// The earliest instant the run may start again, while a retry back-off runs.
    pub(crate) not_before: Option<Timestamp>,
    /// What the last successful attempt produced.
    pub(crate) outputs: Vec<NamedArtifact>,
    /// The answers people gave, oldest first.
    pub(crate) human_inputs: Vec<ArtifactRef>,
    /// The run that replaced this one after a supersession.
    pub(crate) replaced_by: Option<StageRunId>,
    /// The source request was edited after the intake snapshot, so this run must ask for
    /// re-authorization before an agent reads the new text (NT-AUTHZ-05).
    pub(crate) reauthorize: bool,
    /// An approver approved the run (`S14`).
    pub(crate) approved: bool,
    /// An approver rejected the run (`S16`).
    pub(crate) rejected: bool,
}

impl RunRecord {
    fn new(id: StageRunId, kind: StageKind) -> Self {
        Self {
            id,
            kind,
            attempts: Vec::new(),
            window: Vec::new(),
            not_before: None,
            outputs: Vec::new(),
            human_inputs: Vec::new(),
            replaced_by: None,
            reauthorize: false,
            approved: false,
            rejected: false,
        }
    }

    /// The attempts and invalid outputs counted since the last human answer.
    pub(crate) fn window(&self) -> AttemptWindow {
        AttemptWindow::from_history(&self.window)
    }

    /// The attempt with this id.
    pub(crate) fn attempt(&self, id: AttemptId) -> Option<&AttemptRecord> {
        self.attempts.iter().find(|attempt| attempt.id == id)
    }
}

/// Everything the engine knows about one job from its events.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct Timeline {
    /// The stage runs, in the order they were created.
    pub(crate) runs: Vec<RunRecord>,
    /// Rework rounds used by the job, for each count.
    pub(crate) rework: ReworkLedger,
    /// The digest of what failed in the last rework round of each stage kind.
    pub(crate) failing_sets: BTreeMap<usize, Sha256Digest>,
    /// The ids of the commands already applied, for duplicate detection.
    pub(crate) commands: BTreeSet<CausationId>,
}

impl Timeline {
    /// Reads every event of `job` and folds them.
    ///
    /// # Errors
    /// [`EngineError::Corrupt`] when an event the engine wrote cannot be read back, and the store
    /// errors of the read.
    pub(crate) async fn load(tx: &mut dyn Tx, job: JobId) -> Result<Self, EngineError> {
        let mut timeline = Self::default();
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

    /// Folds a list of rows, oldest first. Used by the tests.
    #[cfg(test)]
    pub(crate) fn fold(rows: &[OutboxRow]) -> Result<Self, EngineError> {
        let mut timeline = Self::default();
        for row in rows {
            timeline.apply(row)?;
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
                "an event names a stage run the job never created",
            ))
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
    #[allow(dead_code)] // The command handling of a later increment reads it.
    pub(crate) fn has_applied(&self, command: CausationId) -> bool {
        self.commands.contains(&command)
    }

    fn apply(&mut self, row: &OutboxRow) -> Result<(), EngineError> {
        let event = &row.event;
        if let Some(cause) = event.causation_id {
            self.commands.insert(cause);
        }
        let transition = event.transition_id.as_str();
        match (event.event_type.as_str(), transition) {
            ("job.admitted", _) => self.create_runs(&event.payload, key::STAGE_RUNS),
            ("stage_run.started", _) => self.attempt_started(event),
            ("stage_run.retry_scheduled", _) => self.retry_scheduled(event),
            ("stage_run.gating", _) => self.gating(event),
            ("stage_run.rework_requested", _) => self.rework_requested(event),
            ("stage_run.superseded", _) => self.superseded(event),
            ("stage_run.ready", "S13") => self.answered(event),
            ("stage_run.passed", "S14") => {
                let id = aggregate_run(event)?;
                self.run_mut(id)?.approved = true;
                Ok(())
            }
            ("stage_run.failed", "S16") => {
                let id = aggregate_run(event)?;
                self.run_mut(id)?.rejected = true;
                Ok(())
            }
            ("attempt.succeeded", _) => self.attempt_ended(event, AttemptEnd::Succeeded),
            ("attempt.failed" | "attempt.timed_out" | "attempt.lease_lost", _) => {
                let class = failure_class(&event.payload)?;
                self.attempt_ended(event, AttemptEnd::Failed(class))
            }
            ("attempt.cancel_requested", _) => self.cancel_requested(event),
            ("attempt.cancelled", _) => self.attempt_ended(event, AttemptEnd::Cancelled),
            _ => Ok(()),
        }
    }

    fn create_runs(&mut self, payload: &Map<String, Value>, name: &str) -> Result<(), EngineError> {
        let Some(list) = payload.get(name) else {
            return Ok(());
        };
        let list = list.as_array().ok_or(EngineError::Corrupt(
            "a list of stage runs in an event is not a list",
        ))?;
        for entry in list {
            let (id, kind) = parse_run_ref(entry)?;
            if self.run(id).is_none() {
                self.runs.push(RunRecord::new(id, kind));
            }
        }
        Ok(())
    }

    fn attempt_started(&mut self, event: &DomainEvent) -> Result<(), EngineError> {
        let id = aggregate_run(event)?;
        let attempt = parse_attempt_id(&event.payload, key::ATTEMPT)?;
        let number = u32::try_from(number(&event.payload, key::ATTEMPT_NUMBER)?)
            .map_err(|_| EngineError::Corrupt("an attempt number is out of range"))?;
        let deadline_at = match event.payload.get(key::DEADLINE) {
            Some(Value::String(text)) => Some(parse_instant(text)?),
            _ => None,
        };
        let run = self.run_mut(id)?;
        run.not_before = None;
        if run.attempt(attempt).is_none() {
            run.attempts.push(AttemptRecord {
                id: attempt,
                number,
                deadline_at,
                cancel_requested_at: None,
                end: None,
            });
        }
        Ok(())
    }

    fn retry_scheduled(&mut self, event: &DomainEvent) -> Result<(), EngineError> {
        let id = aggregate_run(event)?;
        let not_before = match event.payload.get(key::NOT_BEFORE) {
            Some(Value::String(text)) => Some(parse_instant(text)?),
            _ => None,
        };
        self.run_mut(id)?.not_before = not_before;
        Ok(())
    }

    fn gating(&mut self, event: &DomainEvent) -> Result<(), EngineError> {
        let id = aggregate_run(event)?;
        let mut outputs = Vec::new();
        if let Some(Value::Array(list)) = event.payload.get(key::OUTPUTS) {
            for entry in list {
                outputs.push(parse_output(entry)?);
            }
        }
        self.run_mut(id)?.outputs = outputs;
        Ok(())
    }

    fn rework_requested(&mut self, event: &DomainEvent) -> Result<(), EngineError> {
        let id = aggregate_run(event)?;
        self.create_runs(&event.payload, key::CREATED)?;
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

    fn superseded(&mut self, event: &DomainEvent) -> Result<(), EngineError> {
        let id = aggregate_run(event)?;
        if let Some(entry) = event.payload.get(key::REPLACED_BY) {
            let (replacement, kind) = parse_run_ref(entry)?;
            if self.run(replacement).is_none() {
                self.runs.push(RunRecord::new(replacement, kind));
            }
            self.run_mut(id)?.replaced_by = Some(replacement);
            let edited =
                event.payload.get(key::CAUSE) == Some(&Value::String("request-edited".to_owned()));
            if edited {
                self.run_mut(replacement)?.reauthorize = true;
            }
        }
        Ok(())
    }

    fn answered(&mut self, event: &DomainEvent) -> Result<(), EngineError> {
        let id = aggregate_run(event)?;
        let run = self.run_mut(id)?;
        run.window.push(WindowEvent::HumanAnswered);
        if let Some(Value::String(text)) = event.payload.get(key::ANSWER) {
            let sha256 = Sha256Digest::parse(text)
                .map_err(|_| EngineError::Corrupt("an answer digest in an event is invalid"))?;
            let media = match event.payload.get(key::ANSWER_MEDIA_TYPE) {
                Some(Value::String(media)) => MediaType::parse(media)
                    .map_err(|_| EngineError::Corrupt("an answer media type is invalid"))?,
                _ => MediaType::parse("text/plain")?,
            };
            run.human_inputs.push(ArtifactRef {
                sha256,
                media_type: media,
                size_bytes: None,
            });
        }
        Ok(())
    }

    fn cancel_requested(&mut self, event: &DomainEvent) -> Result<(), EngineError> {
        let run_id = parse_run_id(&event.payload, key::STAGE_RUN)?;
        let attempt_id = AttemptId::from_uuid(event.aggregate.id.as_uuid());
        let run = self.run_mut(run_id)?;
        if let Some(attempt) = run.attempts.iter_mut().find(|a| a.id == attempt_id) {
            attempt.cancel_requested_at = Some(event.occurred_at);
        }
        Ok(())
    }

    fn attempt_ended(&mut self, event: &DomainEvent, end: AttemptEnd) -> Result<(), EngineError> {
        let run_id = parse_run_id(&event.payload, key::STAGE_RUN)?;
        let attempt_id = AttemptId::from_uuid(event.aggregate.id.as_uuid());
        let run = self.run_mut(run_id)?;
        if let Some(attempt) = run.attempts.iter_mut().find(|a| a.id == attempt_id) {
            attempt.end = Some(end);
        }
        if let AttemptEnd::Failed(class) = end {
            run.window.push(WindowEvent::AttemptFailed(class));
        }
        Ok(())
    }
}

// ---- reading payload values -------------------------------------------------------------------

fn aggregate_run(event: &DomainEvent) -> Result<StageRunId, EngineError> {
    Ok(StageRunId::from_uuid(event.aggregate.id.as_uuid()))
}

fn number(payload: &Map<String, Value>, name: &str) -> Result<u64, EngineError> {
    payload
        .get(name)
        .and_then(Value::as_u64)
        .ok_or(EngineError::Corrupt("a number in an event is missing"))
}

fn parse_instant(text: &str) -> Result<Timestamp, EngineError> {
    Timestamp::parse(text).map_err(|_| EngineError::Corrupt("an instant in an event is invalid"))
}

fn parse_run_id(payload: &Map<String, Value>, name: &str) -> Result<StageRunId, EngineError> {
    match payload.get(name) {
        Some(Value::String(text)) => StageRunId::parse(text)
            .map_err(|_| EngineError::Corrupt("a stage run id in an event is invalid")),
        _ => Err(EngineError::Corrupt(
            "a stage run id in an event is missing",
        )),
    }
}

fn parse_attempt_id(payload: &Map<String, Value>, name: &str) -> Result<AttemptId, EngineError> {
    match payload.get(name) {
        Some(Value::String(text)) => AttemptId::parse(text)
            .map_err(|_| EngineError::Corrupt("an attempt id in an event is invalid")),
        _ => Err(EngineError::Corrupt("an attempt id in an event is missing")),
    }
}

fn parse_run_ref(entry: &Value) -> Result<(StageRunId, StageKind), EngineError> {
    let id = entry
        .get("id")
        .and_then(Value::as_str)
        .ok_or(EngineError::Corrupt("a stage run reference has no id"))?;
    let kind = entry
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(EngineError::Corrupt("a stage run reference has no kind"))?;
    Ok((
        StageRunId::parse(id).map_err(|_| EngineError::Corrupt("a stage run id is invalid"))?,
        StageKind::parse(kind).map_err(|_| EngineError::Corrupt("a stage kind is unknown"))?,
    ))
}

fn parse_output(entry: &Value) -> Result<NamedArtifact, EngineError> {
    let field = |name: &str| {
        entry
            .get(name)
            .and_then(Value::as_str)
            .ok_or(EngineError::Corrupt("an output reference is incomplete"))
    };
    Ok(NamedArtifact {
        name: Slug::parse(field("name")?)
            .map_err(|_| EngineError::Corrupt("an output name is invalid"))?,
        artifact: ArtifactRef {
            sha256: Sha256Digest::parse(field("sha256")?)
                .map_err(|_| EngineError::Corrupt("an output digest is invalid"))?,
            media_type: MediaType::parse(field("media_type")?)
                .map_err(|_| EngineError::Corrupt("an output media type is invalid"))?,
            size_bytes: None,
        },
    })
}

fn failure_class(payload: &Map<String, Value>) -> Result<FailureClass, EngineError> {
    match payload.get(key::FAILURE_CLASS) {
        Some(Value::String(text)) => FailureClass::parse(text)
            .map_err(|_| EngineError::Corrupt("a failure class in an event is unknown")),
        _ => Err(EngineError::Corrupt(
            "a failure class in an event is missing",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::contracts::Contract;
    use serde_json::json;

    const JOB: &str = "00000000-0000-7000-8000-000000000001";
    const RUN_A: &str = "00000000-0000-7000-8000-0000000000a1";
    const RUN_B: &str = "00000000-0000-7000-8000-0000000000b1";
    const RUN_C: &str = "00000000-0000-7000-8000-0000000000c1";
    const ATTEMPT_1: &str = "00000000-0000-7000-8000-0000000000d1";
    const ATTEMPT_2: &str = "00000000-0000-7000-8000-0000000000d2";

    fn row(
        seq: u64,
        event_type: &str,
        transition: &str,
        aggregate: (&str, &str),
        payload: Value,
        causation: Option<&str>,
    ) -> OutboxRow {
        let document = json!({
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

    fn admitted() -> OutboxRow {
        row(
            1,
            "job.admitted",
            "J01",
            ("job", JOB),
            json!({ "stage_runs": [
                { "id": RUN_A, "kind": "INTAKE" },
                { "id": RUN_B, "kind": "REPOSITORY_INTELLIGENCE" },
            ]}),
            None,
        )
    }

    fn started(seq: u64, attempt: &str, number: u32) -> OutboxRow {
        row(
            seq,
            "stage_run.started",
            "S03",
            ("stage_run", RUN_A),
            json!({
                "attempt_id": attempt,
                "attempt_number": number,
                "deadline_at": "2026-10-27T08:45:00Z",
            }),
            None,
        )
    }

    fn failed(seq: u64, attempt: &str, class: &str) -> OutboxRow {
        row(
            seq,
            "attempt.failed",
            "A05",
            ("attempt", attempt),
            json!({ "stage_run_id": RUN_A, "failure_class": class }),
            None,
        )
    }

    #[test]
    fn admission_lists_the_stage_runs_in_order() {
        let timeline = Timeline::fold(&[admitted()]).expect("folds");
        let kinds: Vec<_> = timeline.runs.iter().map(|run| run.kind).collect();
        assert_eq!(
            kinds,
            vec![StageKind::Intake, StageKind::RepositoryIntelligence]
        );
    }

    #[test]
    fn failures_count_in_the_window_and_an_answer_starts_it_again() {
        let rows = [
            admitted(),
            started(2, ATTEMPT_1, 1),
            failed(3, ATTEMPT_1, "TOOL_ERROR"),
            started(4, ATTEMPT_2, 2),
            failed(5, ATTEMPT_2, "INVALID_OUTPUT"),
        ];
        let timeline = Timeline::fold(&rows).expect("folds");
        let run = timeline
            .run(StageRunId::parse(RUN_A).expect("id"))
            .expect("run");
        assert_eq!(run.window().attempts_used(), 2);
        assert_eq!(run.window().invalid_output_failures(), 1);
        assert_eq!(run.attempts.len(), 2);

        let mut with_answer = rows.to_vec();
        with_answer.push(row(
            6,
            "stage_run.ready",
            "S13",
            ("stage_run", RUN_A),
            json!({ "answer_sha256": Sha256Digest::of(b"more time").to_string() }),
            None,
        ));
        let timeline = Timeline::fold(&with_answer).expect("folds");
        let run = timeline
            .run(StageRunId::parse(RUN_A).expect("id"))
            .expect("run");
        assert_eq!(run.window().attempts_used(), 0, "the window starts again");
        assert_eq!(run.human_inputs.len(), 1);
    }

    #[test]
    fn a_cancelled_attempt_is_not_a_failure() {
        let rows = [
            admitted(),
            started(2, ATTEMPT_1, 1),
            row(
                3,
                "attempt.cancelled",
                "A09",
                ("attempt", ATTEMPT_1),
                json!({ "stage_run_id": RUN_A }),
                None,
            ),
        ];
        let timeline = Timeline::fold(&rows).expect("folds");
        let run = timeline
            .run(StageRunId::parse(RUN_A).expect("id"))
            .expect("run");
        assert_eq!(run.window().attempts_used(), 0);
        assert_eq!(run.attempts[0].end, Some(AttemptEnd::Cancelled));
    }

    #[test]
    fn a_retry_sets_the_back_off_and_the_next_start_clears_it() {
        let retry = row(
            3,
            "stage_run.retry_scheduled",
            "S05",
            ("stage_run", RUN_A),
            json!({ "not_before": "2026-10-27T08:30:05Z" }),
            None,
        );
        let rows = [admitted(), started(2, ATTEMPT_1, 1), retry.clone()];
        let timeline = Timeline::fold(&rows).expect("folds");
        let run = timeline
            .run(StageRunId::parse(RUN_A).expect("id"))
            .expect("run");
        assert_eq!(
            run.not_before,
            Some(Timestamp::parse("2026-10-27T08:30:05Z").expect("an instant"))
        );
        let mut later = rows.to_vec();
        later.push(started(4, ATTEMPT_2, 2));
        let timeline = Timeline::fold(&later).expect("folds");
        let run = timeline
            .run(StageRunId::parse(RUN_A).expect("id"))
            .expect("run");
        assert_eq!(run.not_before, None);
    }

    #[test]
    fn rework_charges_a_round_to_its_count_and_lists_the_new_run() {
        let rework = row(
            2,
            "stage_run.rework_requested",
            "S09",
            ("stage_run", RUN_B),
            json!({
                "rework_track": "documentation",
                "failing_set_sha256": Sha256Digest::of(b"links").to_string(),
                "created_stage_runs": [ { "id": RUN_C, "kind": "REPOSITORY_INTELLIGENCE" } ],
            }),
            None,
        );
        let timeline = Timeline::fold(&[admitted(), rework]).expect("folds");
        assert_eq!(timeline.rework.used(ReworkTrack::Documentation), 1);
        assert_eq!(timeline.rework.used(ReworkTrack::Code), 0);
        assert_eq!(timeline.runs.len(), 3);
        assert_eq!(
            timeline.last_failing_set(StageKind::RepositoryIntelligence),
            Some(&Sha256Digest::of(b"links"))
        );
    }

    #[test]
    fn a_supersession_links_the_old_run_to_its_replacement() {
        let superseded = row(
            2,
            "stage_run.superseded",
            "S20",
            ("stage_run", RUN_B),
            json!({ "replaced_by": { "id": RUN_C, "kind": "REPOSITORY_INTELLIGENCE" } }),
            None,
        );
        let timeline = Timeline::fold(&[admitted(), superseded]).expect("folds");
        let old = timeline
            .run(StageRunId::parse(RUN_B).expect("id"))
            .expect("run");
        assert_eq!(old.replaced_by, Some(StageRunId::parse(RUN_C).expect("id")));
        assert_eq!(
            timeline.runs_of(StageKind::RepositoryIntelligence).count(),
            2
        );
    }

    #[test]
    fn a_repeated_command_is_recognised_by_its_id() {
        let command = "00000000-0000-7000-8000-0000000000e1";
        let rows = [row(
            1,
            "job.admitted",
            "J01",
            ("job", JOB),
            json!({ "stage_runs": [] }),
            Some(command),
        )];
        let timeline = Timeline::fold(&rows).expect("folds");
        assert!(timeline.has_applied(CausationId::parse(command).expect("id")));
        assert!(
            !timeline.has_applied(
                CausationId::parse("00000000-0000-7000-8000-0000000000e2").expect("id")
            )
        );
    }

    #[test]
    fn an_event_that_names_an_unknown_run_is_a_corrupt_timeline() {
        let orphan = row(
            1,
            "stage_run.retry_scheduled",
            "S05",
            ("stage_run", RUN_A),
            json!({}),
            None,
        );
        assert!(matches!(
            Timeline::fold(&[orphan]),
            Err(EngineError::Corrupt(_))
        ));
    }

    #[test]
    fn an_event_type_the_engine_does_not_know_is_skipped() {
        let unknown = row(
            2,
            "task_node.ready",
            "T01",
            ("task_node", RUN_C),
            json!({}),
            None,
        );
        assert!(Timeline::fold(&[admitted(), unknown]).is_ok());
    }
}
