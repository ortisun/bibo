//! A ticker that a test moves by hand, so no test waits for real time.
//!
//! A sleeping handler of the engine (the heartbeat, the teardown grace) registers a wait here. The
//! wait ends when the test calls [`ManualTicker::advance`] by at least that long. The ticker's own
//! time is separate from the fake database clock: a test moves the database clock to make a lease
//! lapse, and moves this one to make a heartbeat fire.
//!
//! # A move that finds no wait is lost
//!
//! A wait is due `duration` after it was first polled, by this ticker's time (the contract of
//! [`Ticker::sleep`]). A move of the ticker's time is therefore not remembered for waits that are
//! registered later: `advance` before the engine has reached its wait ends nothing, and the wait
//! that the engine registers a moment afterwards is due a full interval after the move, with
//! nobody left to move the time again. On the in-memory store the engine reaches its wait before
//! the test body is polled again, so the order never varies. On a real database it varies with
//! the speed of every round trip the engine makes before it waits, and a test that moved the
//! time first hung for ever. A test that means "the engine's next wait ends now" must use
//! [`ManualTicker::advance_when_a_wait_is_due`], which holds the move back until such a wait is
//! open.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_testkit::clock::within;
use factory_workflow::scheduler::Ticker;
use tokio::sync::Notify;

/// How long, in real time, [`ManualTicker::advance_when_a_wait_is_due`] waits for the engine to
/// open a wait before it fails the test. It is far longer than any round trip, even on a loaded
/// machine, and it is a failure and not a hang, so a stuck test names its cause.
const OPEN_WAIT_PATIENCE: Duration = Duration::from_secs(60);

struct Waiter {
    id: u64,
    due: Duration,
    signal: Arc<Notify>,
}

struct State {
    now: Duration,
    waiters: Vec<Waiter>,
}

/// Waits that end when a test says so.
pub struct ManualTicker {
    state: Mutex<State>,
    next_id: AtomicU64,
    /// Told whenever a wait is registered, for a test that is holding a move back.
    opened: Notify,
}

impl ManualTicker {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                now: Duration::ZERO,
                waiters: Vec::new(),
            }),
            next_id: AtomicU64::new(0),
            opened: Notify::new(),
        }
    }

    /// Moves the ticker's time forward and ends every wait that is now due.
    ///
    /// A wait that is not open yet is not ended and will not be: see the module notes.
    pub fn advance(&self, by: Duration) {
        let mut state = self.state.lock().expect("the lock is never poisoned");
        Self::move_time(&mut state, by);
    }

    /// Moves the ticker's time forward by `by` once a wait that the move ends is open, and ends
    /// the waits that are due. This is the move a test makes to say "the engine's next wait is
    /// over", whatever the order in which the test and the engine get to run.
    ///
    /// # Panics
    /// When no wait that `by` would end opens within [`OPEN_WAIT_PATIENCE`] of real time. The
    /// engine is then not waiting on the ticker at all (it finished, or it waits on something
    /// else), and a move would be lost.
    pub async fn advance_when_a_wait_is_due(&self, by: Duration) {
        let ready = async {
            loop {
                // Ask to hear of the next wait before looking, so a wait that opens between the
                // look and the sleep is not missed.
                let opened = self.opened.notified();
                tokio::pin!(opened);
                opened.as_mut().enable();
                {
                    let mut state = self.state.lock().expect("the lock is never poisoned");
                    let reach = state.now + by;
                    if state.waiters.iter().any(|waiter| waiter.due <= reach) {
                        Self::move_time(&mut state, by);
                        return;
                    }
                }
                opened.await;
            }
        };
        within(
            OPEN_WAIT_PATIENCE,
            &format!(
                "no wait of the engine opened that a move of {by:?} would end: the engine is not \
                 waiting on the ticker, so the move would be lost and the test would hang"
            ),
            ready,
        )
        .await;
    }

    /// How many waits are open.
    pub fn waiting(&self) -> usize {
        self.state
            .lock()
            .expect("the lock is never poisoned")
            .waiters
            .len()
    }

    fn move_time(state: &mut State, by: Duration) {
        state.now += by;
        let now = state.now;
        state.waiters.retain(|waiter| {
            if waiter.due <= now {
                waiter.signal.notify_one();
                false
            } else {
                true
            }
        });
    }
}

/// Takes a wait off the ticker when its future ends, whether the wait was over or the future was
/// dropped. Dropping the future ends the wait and leaves nothing behind (the contract of
/// [`Ticker::sleep`]); a wait that stayed would be counted as open and would stand for a heartbeat
/// that no longer exists.
struct OpenWait<'a> {
    ticker: &'a ManualTicker,
    id: u64,
}

impl Drop for OpenWait<'_> {
    fn drop(&mut self) {
        let mut state = self
            .ticker
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.waiters.retain(|waiter| waiter.id != self.id);
    }
}

#[async_trait]
impl Ticker for ManualTicker {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn sleep(&self, duration: Duration) {
        let signal = Arc::new(Notify::new());
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut state = self.state.lock().expect("the lock is never poisoned");
            let due = state.now + duration;
            state.waiters.push(Waiter {
                id,
                due,
                signal: signal.clone(),
            });
        }
        let _open = OpenWait { ticker: self, id };
        self.opened.notify_waiters();
        // `notify_one` keeps a permit when it runs before this line, so an `advance` that comes
        // between the registration and here is not lost.
        signal.notified().await;
    }
}
