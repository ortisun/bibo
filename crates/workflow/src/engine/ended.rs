//! Telling the metrics that a stage run ended.
//!
//! A stage run ends when a decision leaves it in `PASSED`, `FAILED`, `BLOCKED` or
//! `REWORK_REQUESTED`: the gate judged it ([`gate`](super::gate)), or its last attempt failed in a
//! way that retrying cannot fix ([`failure`](super::failure)). Both paths call
//! [`Engine::note_stage_end`] once the moves are written, and it reads the status the row now
//! holds. It does not guess the outcome from the branch that was taken, so every branch that
//! leaves the run in one of those four statuses is counted, whichever branch it is, and a branch
//! that only pauses the run (a retry, a question to a person) is not.
//!
//! The counter and the histogram are recorded when the decision commits, through
//! [`Cx::stage_ended`], so a decision that loses a race counts nothing.

use factory_domain::ids::StageRunId;
use factory_domain::state::StageRunStatus;
use factory_ports::store::Tx;

use super::Engine;
use super::error::EngineError;
use super::record::{Cx, StageEnded};

/// The outcome value of the conventions page for the status of an ended stage run, or `None` when
/// the stage run has not ended: it is waiting for a retry, for a person or for its gate.
pub(super) const fn outcome_of(status: StageRunStatus) -> Option<&'static str> {
    match status {
        StageRunStatus::Passed => Some("passed"),
        StageRunStatus::Failed => Some("failed"),
        StageRunStatus::Blocked => Some("blocked"),
        StageRunStatus::ReworkRequested => Some("rework_requested"),
        _ => None,
    }
}

impl Engine {
    /// Notes that the stage run ended in this decision, if it did.
    ///
    /// The duration runs from the creation of the stage run's first attempt to the database clock
    /// now. It therefore includes the time of failed attempts, of retry back-offs and of waits for
    /// a person, which is the wall-clock time the stage run took. A stage run with no attempt has
    /// no start, and its duration is left out and not made up.
    ///
    /// # Errors
    /// The store errors of the reads. The caller drops the transaction.
    pub(crate) async fn note_stage_end(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        run: StageRunId,
    ) -> Result<(), EngineError> {
        let row = tx.get_stage_run(run).await?;
        let Some(outcome) = outcome_of(row.value.status) else {
            return Ok(());
        };
        let started = tx
            .list_attempts(run)
            .await?
            .iter()
            .map(|attempt| attempt.value.created_at)
            .min();
        let now = tx.database_time().await?;
        let seconds = started
            .and_then(|start| now.duration_since(&start))
            .map(|elapsed| elapsed.as_secs_f64());
        cx.stage_ended(StageEnded {
            stage: row.value.kind,
            outcome,
            seconds,
        });
        Ok(())
    }
}
