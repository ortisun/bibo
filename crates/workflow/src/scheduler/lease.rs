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
use factory_domain::state::{AttemptStatus, Status};
use factory_ports::store::StoreError;

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
    /// * [`EngineError::LeaseFenced`] when the lease was lost: it expired, or another worker took
    ///   the stage run at a higher epoch. The worker stops and writes nothing more.
    /// * [`EngineError::Conflict`] when the attempt already ended.
    /// * The store errors.
    pub async fn heartbeat(&self, claimed: &ClaimedAttempt) -> Result<Pulse, EngineError> {
        let mut tx = self.tenant_tx(claimed.tenant).await?;
        match tx.heartbeat(claimed.attempt, claimed.epoch).await {
            Ok(()) => {}
            Err(StoreError::Conflict) => {
                // The store reports an attempt that already ended as a conflict. For the worker
                // that is the same as a lost lease: the sweeper or a cancel ended the attempt, so
                // it stops. The check reads in a new transaction, because a failed statement can
                // leave the first one unusable.
                drop(tx);
                let mut read = self.tenant_tx(claimed.tenant).await?;
                let attempt = read.get_attempt(claimed.attempt).await?;
                read.rollback().await?;
                return Err(if attempt.value.status.is_terminal() {
                    EngineError::LeaseFenced
                } else {
                    EngineError::Conflict
                });
            }
            Err(other) => return Err(other.into()),
        }
        let attempt = tx.get_attempt(claimed.attempt).await?;
        let now = tx.database_time().await?;
        tx.commit().await?;
        Ok(if attempt.value.status == AttemptStatus::Cancelling {
            Pulse::CancelRequested
        } else if now > claimed.deadline_at {
            Pulse::DeadlinePassed
        } else {
            Pulse::Alive
        })
    }
}
