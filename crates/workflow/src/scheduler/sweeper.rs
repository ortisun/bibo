//! The sweeper: the timer tick of the engine.
//!
//! Timers are columns, never timers in a process (ADR 0001), so the sweeper is a function that
//! looks at the database clock and moves what is due. A caller runs [`Engine::sweep`] on an
//! interval. Two sweepers at once are safe: each move is a compare-and-swap, and the one that
//! loses reads the new state and skips.
//!
//! The sweeper ends attempts whose lease ran out without a heartbeat (`A07`). The stage run then
//! retries, asks a person or fails by the rules of `crate::engine::failure`, in the same
//! transaction.

use factory_domain::ids::{AttemptId, JobId, TenantId};
use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::guards::{GuardFacts, LeaseExpiryFacts, evaluate};
use factory_domain::state::{AttemptEvent, Guard};

use factory_ports::store::{AttemptEnd, DueReason};

use crate::engine::payload::attempt_event;
use crate::engine::record::{Cx, Step};
use crate::engine::{Engine, EngineError};

/// The most expired leases one sweep takes.
const SWEEP_BATCH: u32 = 64;

/// What one sweep did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Swept {
    /// Attempts that were `LEASE_LOST` by this sweep.
    pub lease_lost: Vec<AttemptId>,
    /// Attempts the sweep found and left alone: the lease was renewed, the attempt had ended, or
    /// another sweeper took the move first.
    pub skipped: Vec<AttemptId>,
}

impl Engine {
    /// Ends every attempt whose lease expired without a heartbeat, across all tenants.
    ///
    /// # Errors
    /// The store errors of the lookup. A move that loses a race is reported in
    /// [`Swept::skipped`], not as an error.
    pub async fn sweep(&self) -> Result<Swept, EngineError> {
        let found = {
            let mut tx = self.system_tx().await?;
            let due = tx
                .find_due_attempts(DueReason::LeaseExpired, SWEEP_BATCH)
                .await;
            // The transaction ends whether or not the lookup worked, so no lock outlives it.
            tx.finish().await?;
            due?
        };
        let mut swept = Swept::default();
        for due in found {
            let (tenant, job, attempt) = (due.tenant, due.job, due.attempt);
            match self.expire_lease(tenant, job, attempt).await {
                Ok(true) => swept.lease_lost.push(attempt),
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
        Ok(swept)
    }

    /// Takes `A07` for one attempt, if its lease really ended. Returns whether it moved.
    async fn expire_lease(
        &self,
        tenant: TenantId,
        job_id: JobId,
        attempt_id: AttemptId,
    ) -> Result<bool, EngineError> {
        let mut tx = self.tenant_tx(tenant).await?;
        let attempt = tx.get_attempt(attempt_id).await?;
        let run = tx.get_stage_run(attempt.value.stage_run_id).await?;
        let job = tx.get_job(job_id).await?;
        if run.value.lease_epoch != attempt.value.epoch {
            // A later claim holds the stage run. This attempt was already replaced.
            return Ok(false);
        }
        let now = tx.database_time().await?;
        let facts = GuardFacts::LeaseExpiry(LeaseExpiryFacts {
            now,
            lease_expires_at: attempt.value.lease_expires_at,
            heartbeat_arrived: false,
        });
        let Ok(cleared) = evaluate(Guard::LeaseExpired, &facts) else {
            return Ok(false);
        };
        let cx = Cx::new(self, &job.value, self.new_causation_id());
        let payload = attempt_event(
            run.value.kind,
            run.value.id,
            attempt.value.number,
            Some(FailureClass::LeaseLost),
        );
        cx.move_attempt(
            &mut *tx,
            &attempt,
            attempt.value.epoch,
            Step::new(AttemptEvent::LeaseExpired, cleared)
                .cause("lease-expired")
                .payload(payload),
            AttemptEnd::default(),
        )
        .await?;
        // The lease ran out, so the stage run decides: retry after a back-off, ask a person, or
        // fail, by the same rules as for any other failed attempt.
        self.after_attempt_failed(
            &mut *tx,
            &cx,
            run.value.id,
            attempt_id,
            FailureClass::LeaseLost,
        )
        .await?;
        cx.commit(tx).await?;
        Ok(true)
    }
}
