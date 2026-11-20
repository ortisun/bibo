//! An identifier generator that can be told to repeat a value, or to run a hook, at a chosen
//! call. Both make a write fail at a point the test picks.
//!
//! The in-memory store refuses a second event or attempt with an id it already holds. A test that
//! arms this generator makes the engine's n-th identifier from now a repeat of the one before, so
//! some write in some transaction fails. The transaction is dropped, and the test checks that
//! nothing of it remains. Repeated at every n, it is a failure at every write boundary.
//!
//! The second form, [`FaultyIds::arm_hook`], runs a closure at the n-th identifier instead. A test
//! uses it to make the store's next call hang, so the engine's future is dropped mid-transaction:
//! a crash at that boundary rather than an error returned from it.

use std::sync::{Arc, Mutex};

use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::{IdGenerator, Uuid};
use factory_testkit::clock::SequentialIdGenerator;

type Hook = Arc<dyn Fn() + Send + Sync>;

struct State {
    calls: u64,
    fault_at: Option<u64>,
    hook: Option<Hook>,
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
                hook: None,
                last: None,
            }),
        }
    }

    /// Makes the `n`-th identifier from now (the next one is 1) repeat the one before it.
    pub fn arm(&self, n: u64) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        state.fault_at = Some(state.calls + n);
        state.hook = None;
    }

    /// Runs `hook` when the `n`-th identifier from now is made. That identifier is a fresh one.
    pub fn arm_hook(&self, n: u64, hook: impl Fn() + Send + Sync + 'static) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        state.fault_at = Some(state.calls + n);
        state.hook = Some(Arc::new(hook));
    }

    /// Stops repeating and drops the hook.
    pub fn disarm(&self) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        state.fault_at = None;
        state.hook = None;
    }

    /// How many identifiers were made so far.
    pub fn used(&self) -> u64 {
        self.state.lock().expect("the lock is never poisoned").calls
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
        let hook = {
            let mut state = self.state.lock().expect("the lock is never poisoned");
            state.calls += 1;
            if state.fault_at == Some(state.calls) {
                if let Some(hook) = state.hook.clone() {
                    // One shot: the fault fires once.
                    state.fault_at = None;
                    Some(hook)
                } else if let Some(previous) = state.last {
                    return previous;
                } else {
                    None
                }
            } else {
                None
            }
        };
        // The hook runs outside the lock, because it may make the engine ask for another id.
        if let Some(hook) = hook {
            hook();
        }
        let fresh = self.inner.new_uuid();
        self.state.lock().expect("the lock is never poisoned").last = Some(fresh);
        fresh
    }
}
