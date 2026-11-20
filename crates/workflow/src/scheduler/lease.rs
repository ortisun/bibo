//! Keeping a lease alive: the heartbeat.
//!
//! A worker that holds an attempt renews its lease by calling [`Engine::heartbeat`] more often
//! than the lease ends. The store extends the lease from the database clock, so clock skew
//! between workers cannot extend or shorten it (ADR 0007, rule 7). A heartbeat is not a domain
//! event and does not enter the outbox (ADR 0004).
//!
//! The call is also the worker's window on the engine. It learns from the answer that the job was
//! cancelled or that the attempt ran out of time, and it learns that it lost the lease from the
//! error. A worker that loses its lease must stop. It cannot be forced to, so the epoch check on
//! every write is what protects the data (INV-05).

use super::claim::ClaimedAttempt;
use crate::engine::{Engine, EngineError};
use factory_domain::state::AttemptStatus;
use factory_ports::store::{Fence, StoreError};

/// What a heartbeat found out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pulse {
    /// The lease was renewed and the attempt goes on.
    Alive,
    /// The engine asked the attempt to cancel (`A08`). The worker tears the sandbox down and
    /// reports it; the lease was still renewed so the teardown can finish.
    CancelRequested,
    /// The attempt deadline has passed. The worker stops, and the engine ends the attempt as
    /// timed out.
    DeadlinePassed,
}

impl Engine {
    /// Renews the lease of a claimed attempt.
    ///
    /// # Errors
    /// * [`EngineError::LeaseFenced`] when the lease was lost: it expired, another worker took the
    ///   stage run at a higher epoch, or the attempt already ended. The worker stops and writes
    ///   nothing more.
    /// * The store errors.
    pub async fn heartbeat(&self, claimed: &ClaimedAttempt) -> Result<Pulse, EngineError> {
        let fence = Fence {
            attempt: claimed.attempt,
            epoch: claimed.epoch,
            worker: claimed.worker.clone(),
        };
        let mut tx = self.tenant_tx(claimed.tenant).await?;
        let renewal = match tx.heartbeat(fence, self.config.lease_ttl).await {
            Ok(renewal) => renewal,
            // The store reports an attempt that already ended as a conflict. For the worker that
            // is the same as a lost lease: the sweeper or a cancel ended the attempt, so it stops.
            Err(StoreError::Conflict) => return Err(EngineError::LeaseFenced),
            Err(other) => return Err(other.into()),
        };
        let now = tx.database_time().await?;
        tx.commit().await?;
        Ok(if renewal.status == AttemptStatus::Cancelling {
            Pulse::CancelRequested
        } else if now > renewal.deadline_at {
            Pulse::DeadlinePassed
        } else {
            Pulse::Alive
        })
    }
}
