//! Controlling a whole job: pause, resume and cancel, and the clean-up that cancellation needs.
//!
//! * **Pause** stops new leases and does not touch running attempts (`J05`).
//! * **Cancel** moves the job to `CANCELLING` (`J09`). The engine then asks each live attempt to
//!   stop (`A08`); the worker learns of it from its heartbeat, stops its handler and reports the
//!   sandbox gone (`A09`). An attempt whose worker never answers is forced after the teardown
//!   grace period (`A10`). A stage run with no active attempt is cancelled (`S19`), and when every
//!   attempt has ended the job is cancelled (`J10`).
//!
//! The clean-up runs inside [`Engine::settle`] one move at a time, so it is finished by whichever
//! decision comes next, and by [`Engine::sweep`] when nothing else does.

use factory_domain::ids::JobId;
use factory_domain::machines::guards::{
    AttemptsFacts, CancelFacts, GuardFacts, PrincipalFacts, SandboxGoneFacts, TeardownFacts,
    evaluate,
};
use factory_domain::machines::snapshot::{AttemptSnapshot, SandboxState};
use factory_domain::state::{
    AttemptEvent, AttemptStatus, Guard, JobEvent, StageRunEvent, StageRunStatus, Status,
};
use factory_domain::vocabulary::HumanRole;
use factory_ports::store::{AttemptEnd, AuditActor, Job, StageRunEffects, Tx, Versioned};

use super::Engine;
use super::error::EngineError;
use super::payload;
use super::progress::{Board, clear, guard_error};
use super::record::{Cx, Step};
use super::timeline::Timeline;
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::commands::{Actor, JobCommand};
use crate::scheduler::ClaimedAttempt;

/// Whether a round of cancellation made a move.
pub(crate) enum Cancellation {
    /// A move was made. Read the state again.
    Moved,
    /// Nothing more to do now.
    Idle,
}

impl Engine {
    /// Pauses, resumes or cancels a job.
    ///
    /// # Errors
    /// * [`EngineError::NotAuthorized`] when the principal may not (an operator pauses and
    ///   resumes; the requester or an operator cancels). The refusal is audited.
    /// * [`EngineError::Illegal`] when the job is in a state the command does not apply to.
    /// * [`EngineError::Duplicate`] when this command was already applied.
    pub async fn control(
        &self,
        actor: &Actor,
        job: JobId,
        command: JobCommand,
    ) -> Result<(), EngineError> {
        let roles = self
            .deps
            .authority
            .roles(actor.tenant, actor.principal)
            .await
            .map_err(|_| EngineError::Refused("the protected configuration cannot be read"))?;
        let mut tx = self.tenant_tx(actor.tenant).await?;
        let stored = tx.get_job(job).await?;
        let timeline = Timeline::load(&mut *tx, job).await?;
        if timeline.has_applied(actor.command) {
            return Err(EngineError::Duplicate);
        }
        let cx = Cx::new(self, &stored.value, actor.command);
        let facts = PrincipalFacts {
            roles: &roles,
            is_job_requester: actor.principal == stored.value.requester
                && roles.contains(&HumanRole::Requester),
        };
        let (guard, event) = match command {
            JobCommand::Pause => (Guard::ActorMayPause, JobEvent::Pause),
            JobCommand::Resume => (Guard::ActorMayPause, JobEvent::Resume),
            JobCommand::Cancel => (Guard::ActorMayCancel, JobEvent::RequestCancel),
        };
        let cleared = match evaluate(guard, &GuardFacts::Principal(facts)) {
            Ok(cleared) => cleared,
            Err(error) => {
                drop(tx);
                let mut denied = self.tenant_tx(actor.tenant).await?;
                let again = denied.get_job(job).await?;
                let cx = Cx::new(self, &again.value, actor.command);
                cx.audit(
                    &mut *denied,
                    AuditActor::Human(actor.principal),
                    AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),
                )
                .await?;
                cx.commit(denied).await?;
                return Err(guard_error(error));
            }
        };
        cx.move_job(
            &mut *tx,
            &stored,
            Step::new(event, cleared)
                .cause(cause_of(command))
                .payload(payload_for(actor)),
        )
        .await?;
        cx.audit(
            &mut *tx,
            AuditActor::Human(actor.principal),
            AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Granted),
        )
        .await?;
        self.settle(&mut *tx, &cx).await?;
        cx.commit(tx).await?;
        Ok(())
    }

    /// Finishes what a worker started when it stopped a cancelled attempt: the sandbox is gone
    /// (`A09`), and the rest of the cancellation follows.
    pub(crate) async fn teardown_complete(
        &self,
        claimed: &ClaimedAttempt,
    ) -> Result<(), EngineError> {
        let mut tx = self.tenant_tx(claimed.tenant).await?;
        let attempt = tx.get_attempt(claimed.attempt).await?;
        if attempt.value.status != AttemptStatus::Cancelling {
            return Ok(());
        }
        let job = tx.get_job(claimed.job).await?;
        let cx = Cx::new(self, &job.value, self.new_causation_id());
        // The handler stopped and tore its sandbox down before it returned, so the provider's
        // confirmation is the handler's return.
        let cleared = clear(
            Guard::SandboxGone,
            &GuardFacts::SandboxGone(SandboxGoneFacts {
                provider_confirms_sandbox_gone: true,
            }),
        )?;
        cx.move_attempt(
            &mut *tx,
            &attempt,
            claimed.epoch,
            Step::new(AttemptEvent::TeardownComplete, cleared)
                .cause("teardown-complete")
                .payload(payload::attempt_event(
                    claimed.kind,
                    claimed.stage_run,
                    claimed.attempt_number,
                    None,
                )),
            AttemptEnd::default(),
        )
        .await?;
        self.settle(&mut *tx, &cx).await?;
        cx.commit(tx).await?;
        Ok(())
    }

    /// One move of a cancellation. Called by `settle` while the job is `CANCELLING`.
    pub(crate) async fn cancellation_round(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        job: &Versioned<Job>,
        timeline: &Timeline,
        board: &Board,
    ) -> Result<Cancellation, EngineError> {
        let now = tx.database_time().await?;
        let mut snapshots: Vec<AttemptSnapshot> = Vec::new();
        for record in &timeline.runs {
            let run = board.run(record.id).ok_or(EngineError::NotFound)?;
            let mut active = false;
            let mut of_run: Vec<AttemptSnapshot> = Vec::new();
            for attempt in &record.attempts {
                let row = tx.get_attempt(attempt.id).await?;
                let snapshot = AttemptSnapshot {
                    status: row.value.status,
                    sandbox: if row.value.status.is_terminal() {
                        SandboxState::TornDown
                    } else {
                        SandboxState::Up
                    },
                };
                snapshots.push(snapshot);
                of_run.push(snapshot);
                match row.value.status {
                    AttemptStatus::Starting | AttemptStatus::Running => {
                        // Ask the attempt to stop.
                        let facts = GuardFacts::Cancel(CancelFacts {
                            attempt: row.value.status,
                            job: job.value.status,
                            stage_run_is_being_superseded: false,
                        });
                        let cleared = clear(Guard::CancelAllowed, &facts)?;
                        cx.move_attempt(
                            tx,
                            &row,
                            row.value.epoch,
                            Step::new(AttemptEvent::RequestCancel, cleared)
                                .cause("job-cancelled")
                                .payload(payload::attempt_event(
                                    record.kind,
                                    record.id,
                                    row.value.number,
                                    None,
                                )),
                            AttemptEnd {
                                teardown_grace: Some(self.config.teardown_grace),
                                ..AttemptEnd::default()
                            },
                        )
                        .await?;
                        return Ok(Cancellation::Moved);
                    }
                    AttemptStatus::Cancelling => {
                        active = true;
                        // The store keeps the end of the grace period (`teardown_deadline_at`); the
                        // guard reads the moment the cancel was asked and the length of the period.
                        if let Some(requested) = row
                            .value
                            .teardown_deadline_at
                            .and_then(|deadline| deadline.checked_sub(self.config.teardown_grace))
                        {
                            let facts = TeardownFacts {
                                now,
                                cancel_requested_at: requested,
                                grace_seconds: u32::try_from(self.config.teardown_grace.as_secs())
                                    .unwrap_or(u32::MAX),
                            };
                            if let Ok(cleared) = evaluate(
                                Guard::TeardownDeadlinePassed,
                                &GuardFacts::Teardown(facts),
                            ) {
                                cx.move_attempt(
                                    tx,
                                    &row,
                                    row.value.epoch,
                                    Step::new(AttemptEvent::TeardownDeadline, cleared)
                                        .cause("teardown-deadline")
                                        .payload(payload::attempt_event(
                                            record.kind,
                                            record.id,
                                            row.value.number,
                                            None,
                                        )),
                                    AttemptEnd::default(),
                                )
                                .await?;
                                return Ok(Cancellation::Moved);
                            }
                        }
                    }
                    _ => {}
                }
            }
            let live = !matches!(
                run.value.status,
                StageRunStatus::Passed
                    | StageRunStatus::ReworkRequested
                    | StageRunStatus::Failed
                    | StageRunStatus::Skipped
                    | StageRunStatus::Superseded
                    | StageRunStatus::Cancelled
            );
            if live && !active {
                let attempts = AttemptsFacts { attempts: &of_run };
                let cleared = clear(Guard::NoActiveAttempt, &GuardFacts::Attempts(attempts))?;
                cx.move_stage_run(
                    tx,
                    run,
                    Step::new(StageRunEvent::Cancel, cleared)
                        .cause("job-cancelled")
                        .payload(payload::for_run(record.kind, record.id)),
                    StageRunEffects::default(),
                )
                .await?;
                return Ok(Cancellation::Moved);
            }
        }
        let facts = GuardFacts::Attempts(AttemptsFacts {
            attempts: &snapshots,
        });
        if let Ok(cleared) = evaluate(Guard::AllAttemptsTerminal, &facts) {
            cx.move_job(tx, job, Step::new(JobEvent::CancellationComplete, cleared))
                .await?;
            return Ok(Cancellation::Moved);
        }
        Ok(Cancellation::Idle)
    }
}

fn cause_of(command: JobCommand) -> &'static str {
    match command {
        JobCommand::Pause => "paused",
        JobCommand::Resume => "resumed",
        JobCommand::Cancel => "cancel-requested",
    }
}

fn payload_for(actor: &Actor) -> serde_json::Map<String, serde_json::Value> {
    let mut payload = serde_json::Map::new();
    payload.insert(
        payload::key::PRINCIPAL.to_owned(),
        serde_json::json!(actor.principal.to_string()),
    );
    payload
}
