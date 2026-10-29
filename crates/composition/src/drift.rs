//! The `EvidenceDrift` seam, for an engine whose futures are not `Send`.
//!
//! The delivery stage calls `EvidenceDrift::binding_changed` when a value that the gate evidence
//! is bound to (the base commit, the gate definition hash, the policy hash, the image digest) is no
//! longer what the evidence recorded. The engine's answer is `Engine::apply_change` with
//! `ArtifactChange::GateEvidenceBinding`: it supersedes the validation, review, documentation
//! review, delivery and approval runs and starts new ones (ADR 0010).
//!
//! A stage handler's future must be `Send`, and the future of `apply_change` is not: it holds the
//! engine's single-threaded context. So the handler cannot call the engine. It sends a request
//! down a channel and waits for the answer, and a [`DriftPump`], which runs on the thread that
//! owns the engine, takes the request and makes the call:
//!
//! ```text
//! stage handler (Send)            worker loop thread (owns the engine)
//!   ChannelDrift::binding_changed ──request──▶ DriftPump::serve_next ──▶ Engine::apply_change
//!                               ◀──answer────
//! ```
//!
//! The call cancels the attempt that asked for it. The handler gets its answer first, sees its own
//! cancellation, and returns `StageError::Cancelled`, as the seam's contract says.
//!
//! A pump that is never polled leaves the handler waiting until its attempt is cancelled or its
//! deadline passes, and the stage fails closed. A [`ChannelDrift`] with no pump at all (the
//! receiver was dropped) answers `Unavailable` at once.

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::machines::invalidation::ArtifactChange;
use factory_domain::vocabulary::Fidelity;
use factory_workflow::engine::Engine;
use factory_workflow::stages::delivery::SeamError;
use factory_workflow::stages::delivery::seams::EvidenceDrift;
use tokio::sync::{Mutex, mpsc, oneshot};

/// One report that a bound value changed, and where to send the answer.
struct Request {
    tenant: TenantId,
    job: JobId,
    reply: oneshot::Sender<Result<(), SeamError>>,
}

/// The handler's end: implements the seam by sending a request to the pump.
#[derive(Clone)]
pub struct ChannelDrift {
    requests: mpsc::UnboundedSender<Request>,
}

/// The engine's end: serves requests with `Engine::apply_change`.
pub struct DriftPump {
    requests: Mutex<mpsc::UnboundedReceiver<Request>>,
}

/// A connected [`ChannelDrift`] and [`DriftPump`].
#[must_use]
pub fn channel() -> (ChannelDrift, DriftPump) {
    let (sender, receiver) = mpsc::unbounded_channel();
    (
        ChannelDrift { requests: sender },
        DriftPump {
            requests: Mutex::new(receiver),
        },
    )
}

#[async_trait]
impl EvidenceDrift for ChannelDrift {
    fn fidelity(&self) -> Fidelity {
        // It hands the report to the task that owns the engine. A pump that is gone reads as
        // unavailable, never as success.
        Fidelity::Real
    }

    async fn binding_changed(&self, tenant: TenantId, job: JobId) -> Result<(), SeamError> {
        let (reply, answer) = oneshot::channel();
        self.requests
            .send(Request { tenant, job, reply })
            .map_err(|_| SeamError::Unavailable)?;
        // A pump that is dropped before it answers drops the sender, which reads as unavailable.
        answer.await.map_err(|_| SeamError::Unavailable)?
    }
}

impl DriftPump {
    /// Waits for the next request and serves it. Returns `false` when every [`ChannelDrift`] is
    /// gone and the queue is empty, so there will be no more.
    ///
    /// Dropping the future while the engine call is under way abandons that request: its reply
    /// sender is dropped, and the handler that waits reads `Unavailable` and fails closed. A
    /// request still in the queue is untouched and served by the next call.
    pub async fn serve_next(&self, engine: &Engine) -> bool {
        let request = self.requests.lock().await.recv().await;
        let Some(request) = request else {
            return false;
        };
        let applied = engine
            .apply_change(
                request.tenant,
                request.job,
                ArtifactChange::GateEvidenceBinding,
            )
            .await;
        let answer = match applied {
            Ok(applied) => {
                tracing::warn!(
                    superseded = applied.superseded.len(),
                    created = applied.created.len(),
                    "the gate evidence binding changed; the dependent stage runs were replaced"
                );
                Ok(())
            }
            Err(error) => {
                tracing::error!(%error, "the engine could not apply the evidence binding change");
                Err(SeamError::Unavailable)
            }
        };
        // The handler may have been cancelled and gone; nobody waits for the answer then.
        let _ = request.reply.send(answer);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::ids::{JobId, TenantId};

    fn ids() -> (TenantId, JobId) {
        (
            TenantId::from_uuid(uuid::Uuid::from_u128(1)),
            JobId::from_uuid(uuid::Uuid::from_u128(2)),
        )
    }

    #[tokio::test]
    async fn a_report_with_no_pump_is_unavailable_at_once() {
        let (drift, pump) = channel();
        drop(pump);
        let (tenant, job) = ids();
        assert_eq!(
            drift.binding_changed(tenant, job).await,
            Err(SeamError::Unavailable)
        );
    }

    #[tokio::test]
    async fn a_pump_dropped_while_a_report_waits_makes_it_unavailable() {
        let (drift, pump) = channel();
        let (tenant, job) = ids();
        let waiting = tokio::spawn(async move { drift.binding_changed(tenant, job).await });
        tokio::task::yield_now().await;
        // Take the request off the queue and drop it without answering.
        let request = pump.requests.lock().await.recv().await;
        drop(request);
        assert_eq!(waiting.await.expect("joins"), Err(SeamError::Unavailable));
    }
}
