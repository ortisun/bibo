//! A ticker that a test moves by hand, so no test waits for real time.
//!
//! A sleeping handler of the engine (the heartbeat, the teardown grace) registers a wait here. The
//! wait ends when the test calls [`ManualTicker::advance`] by at least that long. The ticker's own
//! time is separate from the fake database clock: a test moves the database clock to make a lease
//! lapse, and moves this one to make a heartbeat fire.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_workflow::scheduler::Ticker;
use tokio::sync::Notify;

struct State {
    now: Duration,
    waiters: Vec<(Duration, Arc<Notify>)>,
}

/// Waits that end when a test says so.
pub struct ManualTicker {
    state: Mutex<State>,
}

impl ManualTicker {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                now: Duration::ZERO,
                waiters: Vec::new(),
            }),
        }
    }

    /// Moves the ticker's time forward and ends every wait that is now due.
    pub fn advance(&self, by: Duration) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        state.now += by;
        let now = state.now;
        state.waiters.retain(|(due, signal)| {
            if *due <= now {
                signal.notify_one();
                false
            } else {
                true
            }
        });
    }

    /// How many waits are open.
    pub fn waiting(&self) -> usize {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .waiters
            .len()
    }
}

#[async_trait]
impl Ticker for ManualTicker {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn sleep(&self, duration: Duration) {
        let signal = Arc::new(Notify::new());
        {
            let mut state = self.state.lock().expect("the lock is never poisoned");
            let due = state.now + duration;
            state.waiters.push((due, signal.clone()));
        }
        // `notify_one` keeps a permit when it runs before this line, so an `advance` that comes
        // first is not lost.
        signal.notified().await;
    }
}
