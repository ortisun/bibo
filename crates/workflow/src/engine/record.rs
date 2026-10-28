//! Writing a decision: the status change, the outbox event, the audit record and the ledger
//! entry, through one transaction.
//!
//! [`Cx`] carries what every write of one decision shares: the tenant, the job, the correlation id
//! that every event and log line of the job carries, the id of the command that caused the
//! decision, and the time. A move is planned by `AppliedTransition::plan`, which asks the domain's
//! transition table and needs the `GuardCleared` that `guards::evaluate` returned, so this module
//! cannot write a status that the table does not list (INV-02) and cannot write a move whose
//! guard was not checked (ADR 0014, decision 3). The event type and the transition id of an event
//! come from the same table row, and the event also names the guard and the digest of its facts.

use factory_domain::contracts::domain_event::AggregateKind;
use factory_domain::contracts::{Contract, DomainEvent};
use std::cell::Cell;
use std::time::Duration;

use factory_domain::ids::{AttemptId, AuditEventId, CausationId, CorrelationId, JobId, TenantId};
use factory_domain::machines::guards::GuardCleared;
use factory_domain::scope::TenantScope;
use factory_domain::state::{
    AttemptEvent, AttemptStatus, JobEvent, JobStatus, StageRunEvent, StageRunStatus, Status,
};
use factory_domain::values::{Slug, Timestamp, Traceparent};
use factory_ports::store::{
    AppliedTransition, Attempt, AttemptEnd, AuditAction as PortAuditAction, AuditActor,
    AuditDecision as PortAuditDecision, Job, LeaseEpoch, NewAuditEvent, StageRun, StageRunEffects,
    StartAttempt, StartedAttempt, StoreError, Tx, Version, Versioned, Witness, WorkerId,
};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::Engine;
use super::error::EngineError;
use crate::audit::{AuditAction, AuditDecision};

/// The name the engine gives itself as the producer of events and the actor of audit records.
pub(crate) const COMPONENT: &str = "workflow.engine";

/// What the writes of one decision share.
pub(crate) struct Cx<'e> {
    pub(crate) engine: &'e Engine,
    pub(crate) tenant: TenantId,
    pub(crate) job: JobId,
    pub(crate) correlation: CorrelationId,
    /// The command that caused the decision. Every event of the decision names it, so a repeated
    /// command is recognised (state-machine.md, ground rule 7).
    pub(crate) causation: CausationId,
    pub(crate) now: Timestamp,
    /// What the attempt that this decision records spent, in millionths of a US dollar. An
    /// attempt event carries it, so the job's spend can be rebuilt from its events.
    pub(crate) cost_micro_usd: u64,
    /// The last outbox event or audit record this decision wrote. If the answer to the commit is
    /// lost, the store is asked whether this is stored (`Store::committed`), and that settles
    /// whether the whole decision was applied.
    witness: Cell<Option<Witness>>,
}

/// One move of an aggregate: the event that asks for it, the proof that its guard held, why it
/// happened and what the outbox event carries. The proof is required, so a move cannot be written
/// without its guard having been checked.
pub(crate) struct Step<'a, E> {
    event: E,
    cleared: GuardCleared,
    cause: Option<&'a str>,
    payload: Map<String, Value>,
}

impl<'a, E> Step<'a, E> {
    /// A move caused by `event`, whose guard held as `cleared` says.
    pub(crate) fn new(event: E, cleared: GuardCleared) -> Self {
        Self {
            event,
            cleared,
            cause: None,
            payload: Map::new(),
        }
    }

    /// The short machine code for why the move happened.
    pub(crate) fn cause(mut self, cause: &'a str) -> Self {
        self.cause = Some(cause);
        self
    }

    /// The payload of the event that announces the move.
    pub(crate) fn payload(mut self, payload: Map<String, Value>) -> Self {
        self.payload = payload;
        self
    }
}

/// What `start_stage_run` needs besides the proof that the guard held.
pub(crate) struct Launch {
    /// The new attempt's id.
    pub(crate) attempt: AttemptId,
    /// The worker that takes the lease.
    pub(crate) worker: WorkerId,
    /// How long the lease lasts, and how long each heartbeat extends it.
    pub(crate) lease_ttl: Duration,
    /// How long the attempt may run.
    pub(crate) attempt_timeout: Duration,
}

impl<'e> Cx<'e> {
    /// A context for a decision about `job`, caused by `causation`.
    pub(crate) fn new(engine: &'e Engine, job: &Job, causation: CausationId) -> Self {
        Self {
            engine,
            tenant: job.tenant_id,
            job: job.id,
            correlation: job.correlation_id,
            causation,
            now: engine.deps.clock.now(),
            cost_micro_usd: 0,
            witness: Cell::new(None),
        }
    }

    /// Commits the decision. When the commit was sent and its answer was lost
    /// (`CommitOutcomeUnknown`), the transaction may or may not be applied, and the engine does
    /// not guess: it asks the store whether the last thing the decision wrote is stored.
    ///
    /// # Errors
    /// * The error of the commit, when it is not an unknown outcome. A `Conflict` or
    ///   `Unavailable` means nothing was applied.
    /// * [`StoreError::Unavailable`], as `EngineError::Store`, when the store says the decision
    ///   was not applied. Nothing changed, and the caller may repeat the call.
    /// * `CommitOutcomeUnknown`, as `EngineError::Store`, when the decision wrote nothing that can
    ///   be asked about, or the question itself could not be answered. The caller must not act
    ///   again on this job until it has read the state.
    pub(crate) async fn commit(&self, tx: Box<dyn Tx>) -> Result<(), EngineError> {
        match tx.commit().await {
            Ok(()) => Ok(()),
            Err(StoreError::CommitOutcomeUnknown) => {
                let applied = match self.witness.get() {
                    Some(witness) => {
                        self.engine
                            .deps
                            .store
                            .committed(TenantScope::new(self.tenant), witness)
                            .await
                    }
                    None => Err(StoreError::CommitOutcomeUnknown),
                };
                settle_unknown_commit(applied)
            }
            Err(other) => Err(other.into()),
        }
    }

    /// The same context, recording what an attempt spent.
    pub(crate) const fn with_cost(mut self, micro_usd: u64) -> Self {
        self.cost_micro_usd = micro_usd;
        self
    }

    /// The component name as a slug.
    fn component() -> Result<Slug, EngineError> {
        Ok(Slug::parse(COMPONENT)?)
    }

    /// Moves a job and announces it. Returns the version after the move.
    pub(crate) async fn move_job(
        &self,
        tx: &mut dyn Tx,
        job: &Versioned<Job>,
        step: Step<'_, JobEvent>,
    ) -> Result<Version, EngineError> {
        let planned =
            AppliedTransition::plan(job.value.status, step.event, self.now, step.cleared)?;
        let seal = Seal::of(&planned);
        let version = tx
            .transition_job(job.value.id, job.version, planned)
            .await?;
        self.enqueue::<JobStatus>(
            tx,
            AggregateKind::Job,
            job.value.id.as_uuid(),
            version,
            &seal,
            step.cause,
            step.payload,
        )
        .await?;
        Ok(version)
    }

    /// Moves a stage run and announces it. Returns the version after the move. `effects` holds the
    /// records the transition requires (`stage_run_effects_rule`).
    pub(crate) async fn move_stage_run(
        &self,
        tx: &mut dyn Tx,
        run: &Versioned<StageRun>,
        step: Step<'_, StageRunEvent>,
        effects: StageRunEffects,
    ) -> Result<Version, EngineError> {
        let planned =
            AppliedTransition::plan(run.value.status, step.event, self.now, step.cleared)?;
        let seal = Seal::of(&planned);
        let version = tx
            .transition_stage_run(run.value.id, run.version, planned, effects)
            .await?;
        self.enqueue::<StageRunStatus>(
            tx,
            AggregateKind::StageRun,
            run.value.id.as_uuid(),
            version,
            &seal,
            step.cause,
            step.payload,
        )
        .await?;
        Ok(version)
    }

    /// Starts the stage run: `S03` and the attempt that holds the lease, in the one atomic step the
    /// store offers (`AttemptOps::start_attempt`), and announces it. Nothing else creates an
    /// attempt or raises the lease epoch (ADR 0014, rules R1 to R3).
    ///
    /// # Errors
    /// The store errors of the start: `Conflict` when another worker won, `NotReady` when the job
    /// is not active or the back-off has not ended, `Constraint` at a limit.
    pub(crate) async fn start_stage_run(
        &self,
        tx: &mut dyn Tx,
        run: &Versioned<StageRun>,
        cleared: GuardCleared,
        launch: Launch,
    ) -> Result<StartedAttempt, EngineError> {
        let planned =
            AppliedTransition::plan(run.value.status, StageRunEvent::Start, self.now, cleared)?;
        let seal = Seal::of(&planned);
        let started = tx
            .start_attempt(StartAttempt {
                attempt: launch.attempt,
                stage_run: run.value.id,
                expected: run.version,
                worker: launch.worker,
                lease_ttl: launch.lease_ttl,
                attempt_timeout: launch.attempt_timeout,
                transition: planned,
            })
            .await?;
        let payload = super::payload::attempt_started(
            run.value.kind,
            run.value.id,
            launch.attempt,
            started.attempt.value.number,
        );
        self.enqueue::<StageRunStatus>(
            tx,
            AggregateKind::StageRun,
            run.value.id.as_uuid(),
            started.stage_run.version,
            &seal,
            None,
            payload,
        )
        .await?;
        Ok(started)
    }

    /// Moves an attempt and announces it. `epoch` is the lease epoch the move is written under.
    /// The store refuses a move whose epoch is not current (INV-05). `end` holds the records the
    /// transition requires (`attempt_end_rule`).
    pub(crate) async fn move_attempt(
        &self,
        tx: &mut dyn Tx,
        attempt: &Versioned<Attempt>,
        epoch: LeaseEpoch,
        step: Step<'_, AttemptEvent>,
        end: AttemptEnd,
    ) -> Result<Version, EngineError> {
        let planned =
            AppliedTransition::plan(attempt.value.status, step.event, self.now, step.cleared)?;
        let seal = Seal::of(&planned);
        let version = tx
            .transition_attempt(attempt.value.id, attempt.version, epoch, planned, end)
            .await?;
        let mut payload = step.payload;
        if self.cost_micro_usd > 0 {
            payload.insert(
                super::payload::key::COST.to_owned(),
                serde_json::json!(self.cost_micro_usd),
            );
        }
        self.enqueue::<AttemptStatus>(
            tx,
            AggregateKind::Attempt,
            attempt.value.id.as_uuid(),
            version,
            &seal,
            step.cause,
            payload,
        )
        .await?;
        Ok(version)
    }

    /// Writes the outbox event that a transition emits, in the same transaction as the move.
    /// The event type comes from the transition row, so it cannot name a move that did not happen.
    /// The payload also names the guard that held and the digest of the facts it held on.
    #[allow(clippy::too_many_arguments)]
    async fn enqueue<S: Status>(
        &self,
        tx: &mut dyn Tx,
        kind: AggregateKind,
        aggregate: Uuid,
        version: Version,
        seal: &Seal,
        cause: Option<&str>,
        mut payload: Map<String, Value>,
    ) -> Result<(), EngineError> {
        let transition_id = seal.transition_id;
        let row = S::TRANSITIONS
            .iter()
            .find(|row| row.id == transition_id)
            .ok_or(EngineError::Corrupt(
                "the engine planned an unknown transition",
            ))?;
        let Some(emits) = row.emits else {
            // A heartbeat has no event (ADR 0004). The engine does not plan one through here.
            return Ok(());
        };
        payload.insert(super::payload::key::GUARD.to_owned(), json!(seal.guard));
        payload.insert(
            super::payload::key::GUARD_FACTS.to_owned(),
            json!(seal.facts_sha256),
        );
        let mut document = json!({
            "schema_version": 1,
            "event_id": self.engine.new_event_id().to_string(),
            "event_type": emits,
            "event_version": 1,
            "tenant_id": self.tenant.to_string(),
            "job_id": self.job.to_string(),
            "aggregate": { "type": kind.as_str(), "id": aggregate.hyphenated().to_string(), "version": version.get() },
            "transition_id": transition_id,
            "correlation_id": self.correlation.to_string(),
            "causation_id": self.causation.to_string(),
            "occurred_at": self.now.to_string(),
            "producer": COMPONENT,
            "traceparent": Traceparent::for_job(self.job).as_str(),
            "payload": Value::Object(payload),
        });
        if let (Some(cause), Some(object)) = (cause, document.as_object_mut()) {
            object.insert("reason_code".to_owned(), json!(cause));
        }
        let event = DomainEvent::from_json_value(document)
            .map_err(|error| EngineError::Invalid(error.to_string()))?;
        let event_id = event.event_id;
        tx.enqueue_event(event).await?;
        self.witness.set(Some(Witness::OutboxEvent(event_id)));
        Ok(())
    }

    /// Records an audit event of the engine: the actor, the action, the policy hash in force and
    /// the correlation id. The store assigns the time.
    pub(crate) async fn audit(
        &self,
        tx: &mut dyn Tx,
        actor: AuditActor,
        action: AuditAction,
    ) -> Result<(), EngineError> {
        let text = action.slug()?;
        let id = AuditEventId::from_uuid(self.engine.deps.ids.new_uuid());
        tx.record_audit(NewAuditEvent {
            id,
            actor,
            action: PortAuditAction::new(text.as_str())?,
            subject: format!("job {}", self.job),
            decision: match action.decision {
                AuditDecision::Granted => PortAuditDecision::Allow,
                AuditDecision::Denied => PortAuditDecision::Deny,
                AuditDecision::Ended | AuditDecision::Noted => PortAuditDecision::Record,
            },
            reason: format!("the engine recorded {}", text.as_str()),
            policy_hash: self.engine.config.policy_hash.clone(),
            job: Some(self.job),
            stage_run: None,
            correlation_id: self.correlation,
        })
        .await?;
        self.witness.set(Some(Witness::Audit(id)));
        Ok(())
    }

    /// Records an audit event with the engine as the actor.
    pub(crate) async fn audit_engine(
        &self,
        tx: &mut dyn Tx,
        action: AuditAction,
    ) -> Result<(), EngineError> {
        self.audit(tx, AuditActor::System(Self::component()?), action)
            .await
    }
}

/// What the store's answer about a witness means for a commit whose answer was lost.
///
/// * The witness is stored: the whole decision was applied, and the call succeeded.
/// * The witness is not stored: nothing was applied. The call reports a failure that can be
///   repeated, and never a success.
/// * The question could not be answered: the outcome stays unknown, and the call says so.
pub(crate) fn settle_unknown_commit(applied: Result<bool, StoreError>) -> Result<(), EngineError> {
    match applied {
        Ok(true) => Ok(()),
        Ok(false) => Err(EngineError::Store(StoreError::Unavailable)),
        Err(_) => Err(EngineError::Store(StoreError::CommitOutcomeUnknown)),
    }
}

/// What an event states about the move it announces: the transition, the guard that held and the
/// digest of the facts it held on. Taken before the planned move goes to the store.
struct Seal {
    transition_id: &'static str,
    guard: String,
    facts_sha256: String,
}

impl Seal {
    fn of<S: Status>(planned: &AppliedTransition<S>) -> Self {
        Self {
            transition_id: planned.transition_id(),
            guard: planned.guard().to_string(),
            facts_sha256: planned.facts_sha256().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stored_witness_means_the_decision_was_applied() {
        assert_eq!(settle_unknown_commit(Ok(true)), Ok(()));
    }

    #[test]
    fn a_missing_witness_is_never_a_success() {
        let outcome = settle_unknown_commit(Ok(false));
        assert_eq!(outcome, Err(EngineError::Store(StoreError::Unavailable)));
        assert!(outcome.is_err_and(|error| error.is_retryable()));
    }

    #[test]
    fn a_question_that_cannot_be_answered_leaves_the_outcome_unknown() {
        assert_eq!(
            settle_unknown_commit(Err(StoreError::Unavailable)),
            Err(EngineError::Store(StoreError::CommitOutcomeUnknown))
        );
    }
}
