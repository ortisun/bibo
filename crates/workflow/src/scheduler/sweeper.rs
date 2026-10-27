//! The sweeper: the timer tick of the engine.
//!
//! Timers are columns, never timers in a process (ADR 0001), so the sweeper is a function that
//! looks at the database clock and moves what is due. A caller runs [`Engine::sweep`] on an
//! interval. Two sweepers at once are safe: each move is a compare-and-swap, and the one that
//! loses reads the new state and skips.
//!
//! This part of the sweeper ends attempts whose lease ran out without a heartbeat (`A07`). The
//! consequence for the stage run follows from the failure handling in `crate::engine::failure`.

use factory_domain::ids::{AttemptId, JobId, TenantId};
use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::guards::{GuardFacts, LeaseExpiryFacts, evaluate};
use factory_domain::state::{AttemptEvent, Guard};

use crate::engine::payload::attempt_event;
use crate::engine::record::Cx;
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
            let ids = tx.expired_leases(SWEEP_BATCH).await?;
            let mut found = Vec::with_capacity(ids.len());
            for id in ids {
                let attempt = tx.get_attempt(id).await?;
                found.push((attempt.value.tenant_id, attempt.value.job_id, id));
            }
            tx.rollback().await?;
            found
        };
        let mut swept = Swept::default();
        for (tenant, job, attempt) in found {
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
        let Some(lease) = run.value.lease.clone() else {
            return Ok(false);
        };
        if lease.epoch != attempt.value.epoch {
            // A later claim holds the stage run. This attempt was already replaced.
            return Ok(false);
        }
        let now = tx.database_time().await?;
        let facts = GuardFacts::LeaseExpiry(LeaseExpiryFacts {
            now,
            lease_expires_at: lease.expires_at,
            heartbeat_arrived: false,
        });
        if evaluate(Guard::LeaseExpired, &facts).is_err() {
            return Ok(false);
        }
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
            AttemptEvent::LeaseExpired,
            Some("lease-expired"),
            payload,
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }
}
