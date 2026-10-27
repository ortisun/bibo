//! The sweeper: the timer tick of the engine.
//!
//! Timers are columns, never timers in a process (ADR 0001), so the sweeper is a function that
//! asks the store which attempts are due by the database clock and moves them. A caller runs
//! [`Engine::sweep`] on an interval. Two sweepers at once are safe: each move is a
//! compare-and-swap, and the one that loses reads the new state and skips.
//!
//! Three things make an attempt due (`SystemTx::find_due_attempts`):
//!
//! * its lease ran out without a heartbeat (`A07`, `LEASE_LOST`);
//! * its deadline passed while it was starting or running (`A06`, `TIMED_OUT`);
//! * it was asked to cancel and did not tear down within the grace period (`A10`).
//!
//! After `A06` and `A07` the stage run retries, asks a person or fails by the rules of
//! `crate::engine::failure`, in the same transaction. After `A10` the cancellation goes on.

use factory_domain::ids::{AttemptId, JobId, TenantId};
use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::guards::{
    DeadlineFacts, GuardFacts, LeaseExpiryFacts, TeardownFacts, evaluate,
};
use factory_domain::state::{AttemptEvent, AttemptStatus, Guard};
use factory_ports::store::{AttemptEnd, DueReason};

use crate::engine::payload::attempt_event;
use crate::engine::record::{Cx, Step};
use crate::engine::{Engine, EngineError};

/// The most attempts one sweep takes for each reason.
const SWEEP_BATCH: u32 = 64;

/// The reasons an attempt is due, in the order the sweeper looks at them.
const REASONS: [DueReason; 3] = [
    DueReason::LeaseExpired,
    DueReason::DeadlinePassed,
    DueReason::TeardownDeadlinePassed,
];

/// What one sweep did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Swept {
    /// Attempts that were `LEASE_LOST` by this sweep.
    pub lease_lost: Vec<AttemptId>,
    /// Attempts that were `TIMED_OUT` by this sweep because their deadline passed.
    pub timed_out: Vec<AttemptId>,
    /// Cancelled attempts that this sweep forced to `CANCELLED` because their teardown did not
    /// finish in time.
    pub forced: Vec<AttemptId>,
    /// Attempts the sweep found and left alone: the lease was renewed, the attempt had ended, or
    /// another sweeper took the move first.
    pub skipped: Vec<AttemptId>,
}

impl Engine {
    /// Ends every attempt that is due by the database clock, across all tenants: a lapsed lease,
    /// a passed deadline, or a teardown that ran out of time.
    ///
    /// # Errors
    /// The store errors of the lookup. A move that loses a race is reported in
    /// [`Swept::skipped`], not as an error.
    pub async fn sweep(&self) -> Result<Swept, EngineError> {
        let mut swept = Swept::default();
        for reason in REASONS {
            let found = {
                let mut tx = self.system_tx().await?;
                let due = tx.find_due_attempts(reason, SWEEP_BATCH).await;
                // The transaction ends whether or not the lookup worked, so no lock outlives it.
                tx.finish().await?;
                due?
            };
            for due in found {
                let (tenant, job, attempt) = (due.tenant, due.job, due.attempt);
                match self.end_due_attempt(tenant, job, attempt, reason).await {
                    Ok(true) => match reason {
                        DueReason::LeaseExpired => swept.lease_lost.push(attempt),
                        DueReason::DeadlinePassed => swept.timed_out.push(attempt),
                        DueReason::TeardownDeadlinePassed => swept.forced.push(attempt),
                    },
                    Ok(false)
                    | Err(
                        EngineError::Conflict
                        | EngineError::LeaseFenced
                        | EngineError::GuardUnmet(_)
                        | EngineError::Illegal(_),
                    ) => swept.skipped.push(attempt),
                    Err(other) => return Err(other),
                }
            }
        }
        Ok(swept)
    }

    /// Takes `A07`, `A06` or `A10` for one attempt, if it really is due. Returns whether it moved.
    async fn end_due_attempt(
        &self,
        tenant: TenantId,
        job_id: JobId,
        attempt_id: AttemptId,
        reason: DueReason,
    ) -> Result<bool, EngineError> {
        let mut tx = self.tenant_tx(tenant).await?;
        let attempt = tx.get_attempt(attempt_id).await?;
        let run = tx.get_stage_run(attempt.value.stage_run_id).await?;
        let job = tx.get_job(job_id).await?;
        if run.value.lease_epoch != attempt.value.epoch {
            // A later claim holds the stage run. This attempt was already replaced.
            return Ok(false);
        }
        let live = matches!(
            attempt.value.status,
            AttemptStatus::Starting | AttemptStatus::Running
        );
        let now = tx.database_time().await?;
        let (event, cleared, cause, failure) = match reason {
            DueReason::LeaseExpired if live => {
                let facts = GuardFacts::LeaseExpiry(LeaseExpiryFacts {
                    now,
                    lease_expires_at: attempt.value.lease_expires_at,
                    heartbeat_arrived: false,
                });
                let Ok(cleared) = evaluate(Guard::LeaseExpired, &facts) else {
                    return Ok(false);
                };
                (
                    AttemptEvent::LeaseExpired,
                    cleared,
                    "lease-expired",
                    Some(FailureClass::LeaseLost),
                )
            }
            DueReason::DeadlinePassed if live => {
                let facts = GuardFacts::Deadline(DeadlineFacts {
                    now,
                    attempt_deadline: attempt.value.deadline_at,
                });
                let Ok(cleared) = evaluate(Guard::DeadlinePassed, &facts) else {
                    return Ok(false);
                };
                (
                    AttemptEvent::DeadlineExceeded,
                    cleared,
                    "deadline-exceeded",
                    Some(FailureClass::TimedOut),
                )
            }
            DueReason::TeardownDeadlinePassed
                if attempt.value.status == AttemptStatus::Cancelling =>
            {
                let Some(deadline) = attempt.value.teardown_deadline_at else {
                    return Ok(false);
                };
                let grace = self.config.teardown_grace;
                // The store keeps the end of the grace period; the guard reads the moment the
                // cancel was asked and the length of the period.
                let Some(requested) = deadline.checked_sub(grace) else {
                    return Ok(false);
                };
                let facts = GuardFacts::Teardown(TeardownFacts {
                    now,
                    cancel_requested_at: requested,
                    grace_seconds: u32::try_from(grace.as_secs()).unwrap_or(u32::MAX),
                });
                let Ok(cleared) = evaluate(Guard::TeardownDeadlinePassed, &facts) else {
                    return Ok(false);
                };
                (
                    AttemptEvent::TeardownDeadline,
                    cleared,
                    "teardown-deadline",
                    None,
                )
            }
            // The attempt is no longer in the state that made it due.
            _ => return Ok(false),
        };
        let cx = Cx::new(self, &job.value, self.new_causation_id());
        let payload = attempt_event(run.value.kind, run.value.id, attempt.value.number, failure);
        cx.move_attempt(
            &mut *tx,
            &attempt,
            attempt.value.epoch,
            Step::new(event, cleared).cause(cause).payload(payload),
            AttemptEnd::default(),
        )
        .await?;
        match failure {
            // The lease ran out or the deadline passed, so the stage run decides: retry after a
            // back-off, ask a person or fail, by the same rules as for any other failed attempt.
            Some(class) => {
                self.after_attempt_failed(&mut *tx, &cx, run.value.id, attempt_id, class, None)
                    .await?;
            }
            // A forced teardown goes on with the cancellation.
            None => self.settle(&mut *tx, &cx).await?,
        }
        cx.commit(tx).await?;
        Ok(true)
    }
}
