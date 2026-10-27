//! Writing a decision: the status change, the outbox event, the audit record and the ledger
//! entry, through one transaction.
//!
//! [`Cx`] carries what every write of one decision shares: the tenant, the job, the correlation id
//! that every event and log line of the job carries, the id of the command that caused the
//! decision, and the time. A move is planned by `AppliedTransition::plan`, which asks the domain's
//! transition table, so this module cannot write a status that the table does not list (INV-02).
//! The event type and the transition id of an event come from the same table row.

use factory_domain::contracts::domain_event::AggregateKind;
use factory_domain::contracts::{Contract, DomainEvent};
use factory_domain::ids::{CausationId, CorrelationId, JobId, TenantId};
use factory_domain::state::{
    AttemptEvent, AttemptStatus, JobEvent, JobStatus, StageRunEvent, StageRunStatus, Status,
};
use factory_domain::values::{Slug, Timestamp, Traceparent};
use factory_ports::store::{
    AppliedTransition, Attempt, AuditActor, AuditEvent, Job, LeaseEpoch, StageRun, Tx, Version,
    Versioned,
};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::Engine;
use super::error::EngineError;
use crate::audit::AuditAction;

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
        }
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
        event: JobEvent,
        cause: Option<&str>,
        payload: Map<String, Value>,
    ) -> Result<Version, EngineError> {
        let planned = AppliedTransition::plan(job.value.status, event, self.now)?;
        let version = tx
            .transition_job(job.value.id, job.version, planned)
            .await?;
        self.enqueue::<JobStatus>(
            tx,
            AggregateKind::Job,
            job.value.id.as_uuid(),
            version,
            planned.transition_id(),
            cause,
            payload,
        )
        .await?;
        Ok(version)
    }

    /// Moves a stage run and announces it. Returns the version after the move.
    pub(crate) async fn move_stage_run(
        &self,
        tx: &mut dyn Tx,
        run: &Versioned<StageRun>,
        event: StageRunEvent,
        cause: Option<&str>,
        payload: Map<String, Value>,
    ) -> Result<Version, EngineError> {
        let planned = AppliedTransition::plan(run.value.status, event, self.now)?;
        let version = tx
            .transition_stage_run(run.value.id, run.version, planned)
            .await?;
        self.enqueue::<StageRunStatus>(
            tx,
            AggregateKind::StageRun,
            run.value.id.as_uuid(),
            version,
            planned.transition_id(),
            cause,
            payload,
        )
        .await?;
        Ok(version)
    }

    /// Moves an attempt and announces it. `epoch` is the lease epoch the move is written under.
    /// The store refuses a move whose epoch is not current (INV-05).
    pub(crate) async fn move_attempt(
        &self,
        tx: &mut dyn Tx,
        attempt: &Versioned<Attempt>,
        epoch: LeaseEpoch,
        event: AttemptEvent,
        cause: Option<&str>,
        payload: Map<String, Value>,
    ) -> Result<Version, EngineError> {
        let planned = AppliedTransition::plan(attempt.value.status, event, self.now)?;
        let version = tx
            .transition_attempt(attempt.value.id, attempt.version, epoch, planned)
            .await?;
        self.enqueue::<AttemptStatus>(
            tx,
            AggregateKind::Attempt,
            attempt.value.id.as_uuid(),
            version,
            planned.transition_id(),
            cause,
            payload,
        )
        .await?;
        Ok(version)
    }

    /// Writes the outbox event that a transition emits, in the same transaction as the move.
    /// The event type comes from the transition row, so it cannot name a move that did not happen.
    #[allow(clippy::too_many_arguments)]
    async fn enqueue<S: Status>(
        &self,
        tx: &mut dyn Tx,
        kind: AggregateKind,
        aggregate: Uuid,
        version: Version,
        transition_id: &str,
        cause: Option<&str>,
        payload: Map<String, Value>,
    ) -> Result<(), EngineError> {
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
        tx.enqueue_event(event).await?;
        Ok(())
    }

    /// Records an audit event of the engine: the actor, the action, the policy hash in force and
    /// the correlation id.
    pub(crate) async fn audit(
        &self,
        tx: &mut dyn Tx,
        actor: AuditActor,
        action: AuditAction,
    ) -> Result<(), EngineError> {
        tx.record_audit(AuditEvent {
            job_id: self.job,
            actor,
            action: action.slug()?,
            policy_hash: self.engine.config.policy_hash.clone(),
            correlation_id: self.correlation,
            occurred_at: self.now,
        })
        .await?;
        Ok(())
    }

    /// Records an audit event with the engine as the actor.
    pub(crate) async fn audit_engine(
        &self,
        tx: &mut dyn Tx,
        action: AuditAction,
    ) -> Result<(), EngineError> {
        self.audit(tx, AuditActor::Component(Self::component()?), action)
            .await
    }
}
