//! The cancellation signal that the engine hands to a running stage handler.
//!
//! The engine learns that an attempt must stop from the database: a heartbeat answers that the
//! job is cancelling, that the deadline passed, or that the lease is gone. It then trips this
//! signal, which the handler passes to every long operation (`AgentRuntime::run`,
//! `SandboxSession::exec`). The signal only asks. The handler decides how to stop cleanly, and the
//! engine abandons a handler that does not stop within the teardown grace period.

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::CancelSignal;
use tokio::sync::watch;

/// A signal that the engine trips. It is the real implementation of the port and reports `real`.
#[derive(Debug)]
pub(crate) struct AttemptCancel {
    sender: watch::Sender<bool>,
}

impl AttemptCancel {
    /// A signal that is not tripped.
    pub(crate) fn new() -> Self {
        Self {
            sender: watch::Sender::new(false),
        }
    }

    /// Asks the handler to stop. It cannot be taken back.
    pub(crate) fn trip(&self) {
        self.sender.send_replace(true);
    }
}

#[async_trait]
impl CancelSignal for AttemptCancel {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Real
    }

    fn is_cancelled(&self) -> bool {
        *self.sender.borrow()
    }

    async fn cancelled(&self) {
        let mut receiver = self.sender.subscribe();
        // `wait_for` returns at once when the value already satisfies the test.
        let _ = receiver.wait_for(|cancelled| *cancelled).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_tripped_signal_stays_tripped_and_wakes_a_waiter() {
        let signal = AttemptCancel::new();
        assert!(!signal.is_cancelled());
        signal.trip();
        assert!(signal.is_cancelled());
        signal.cancelled().await;
        signal.trip();
        assert!(signal.is_cancelled());
    }
}
