//! An identifier generator that can be told to repeat a value, to make a write fail.
//!
//! The in-memory store refuses a second event or attempt with an id it already holds. A test that
//! arms this generator makes the engine's n-th identifier from now a repeat of the one before, so
//! some write in some transaction fails. The transaction is dropped, and the test checks that
//! nothing of it remains. Repeated at every n, it is a crash at every write boundary.

use std::sync::Mutex;

use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::{IdGenerator, Uuid};
use factory_testkit::clock::SequentialIdGenerator;

struct State {
    calls: u64,
    fault_at: Option<u64>,
    last: Option<Uuid>,
}

/// A generator that counts like `SequentialIdGenerator` and repeats one value on request.
pub struct FaultyIds {
    inner: SequentialIdGenerator,
    state: Mutex<State>,
}

impl FaultyIds {
    pub fn new() -> Self {
        Self {
            inner: SequentialIdGenerator::new(),
            state: Mutex::new(State {
                calls: 0,
                fault_at: None,
                last: None,
            }),
        }
    }

    /// Makes the `n`-th identifier from now (the next one is 1) repeat the one before it.
    pub fn arm(&self, n: u64) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        state.fault_at = Some(state.calls + n);
    }

    /// Stops repeating.
    pub fn disarm(&self) {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .fault_at = None;
    }

    /// True when the armed fault has fired.
    pub fn fired(&self) -> bool {
        let state = self.state.lock().expect("the lock is never poisoned");
        state.fault_at.is_some_and(|at| state.calls >= at)
    }
}

impl IdGenerator for FaultyIds {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    fn new_uuid(&self) -> Uuid {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        state.calls += 1;
        if state.fault_at == Some(state.calls)
            && let Some(previous) = state.last
        {
            return previous;
        }
        let fresh = self.inner.new_uuid();
        state.last = Some(fresh);
        fresh
    }
}
