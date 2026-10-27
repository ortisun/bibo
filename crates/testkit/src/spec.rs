//! A specification provider that plays back queued outcomes.
//!
//! It runs no Spec Kit. A test queues what the next calls return, in order, and reads back the
//! requests the provider received. A call made after the cancel signal is set fails with a
//! cancelled runtime error, and a call with nothing queued reports that the tool is missing.

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::AgentRunError;
use factory_ports::spec::{
    SpecContext, SpecError, SpecOutcome, SpecRequest, SpecificationProvider,
};

/// A specification provider with a queue of outcomes. Reports fidelity `fake`.
#[derive(Default)]
pub struct FakeSpecificationProvider {
    outcomes: Mutex<VecDeque<Result<SpecOutcome, SpecError>>>,
    requests: Mutex<Vec<SpecRequest>>,
}

impl FakeSpecificationProvider {
    /// A provider with nothing queued.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues what a later call returns. Outcomes are played in the order they were queued.
    pub fn queue(&self, outcome: Result<SpecOutcome, SpecError>) {
        self.outcomes
            .lock()
            .expect("the lock is never poisoned")
            .push_back(outcome);
    }

    /// Every request the provider received, oldest first.
    #[must_use]
    pub fn requests(&self) -> Vec<SpecRequest> {
        self.requests
            .lock()
            .expect("the lock is never poisoned")
            .clone()
    }
}

#[async_trait]
impl SpecificationProvider for FakeSpecificationProvider {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn run(
        &self,
        req: SpecRequest,
        ctx: &mut SpecContext<'_>,
    ) -> Result<SpecOutcome, SpecError> {
        self.requests
            .lock()
            .expect("the lock is never poisoned")
            .push(req);
        if ctx.cancel.is_cancelled() {
            return Err(SpecError::Runtime(AgentRunError::Cancelled));
        }
        self.outcomes
            .lock()
            .expect("the lock is never poisoned")
            .pop_front()
            .unwrap_or(Err(SpecError::ToolMissing))
    }
}
