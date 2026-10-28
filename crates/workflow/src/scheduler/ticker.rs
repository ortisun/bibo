//! Waiting between heartbeats and during a teardown, without a timer of the engine's own.
//!
//! The engine must not read the clock or sleep (rule DEP-05). Two things in a running attempt need
//! a wait all the same: the heartbeat that renews the lease every few seconds, and the grace
//! period a cancelled attempt has to tear its sandbox down. Both are waits for a *duration*, never
//! a reading of the time of day, so they are asked of a port. The composition root supplies one
//! that sleeps; a test supplies one that it moves by hand, so no test depends on real time.
//!
//! Leases, deadlines, back-offs and teardown deadlines are not waits of this kind. They are values
//! in the store, compared with the database clock, and the sweeper finds them there.

use std::time::Duration;

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;

/// Completes after a duration has passed.
///
/// # Preconditions
/// None.
///
/// # Postconditions
/// `sleep` completes no earlier than `duration` after it was first polled, by the implementation's
/// own measure. It reads no time of day and writes nothing.
///
/// # Errors
/// None. A wait cannot fail.
///
/// # Idempotency
/// Each call is a new wait.
///
/// # Cancellation and timeouts
/// Dropping the future ends the wait and leaves nothing behind.
#[async_trait]
pub trait Ticker: Send + Sync {
    /// Says whether this ticker waits in real time (`real`) or is moved by hand (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Waits for `duration`.
    async fn sleep(&self, duration: Duration);
}
