//! The controllable clock (FX-CLOCK), the deterministic identifier generator and the manual
//! cancellation signal.
//!
//! Tests move time by hand, so leases, token expiry and deadlines are exact and nothing waits.

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::{CancelSignal, Clock, IdGenerator, Uuid, timestamp_after};
use tokio::sync::watch;

/// The instant a new [`FakeClock`] starts at.
pub const DEFAULT_START: &str = "2026-10-27T08:30:00Z";

/// A clock that only moves when a test moves it (FX-CLOCK).
///
/// It never goes backwards: [`advance`](Self::advance) adds time and
/// [`advance_to`](Self::advance_to) refuses an earlier instant, as the `Clock` contract requires.
#[derive(Debug)]
pub struct FakeClock {
    now: Mutex<Timestamp>,
}

impl FakeClock {
    /// A clock that starts at [`DEFAULT_START`].
    #[must_use]
    pub fn new() -> Self {
        Self::starting_at(DEFAULT_START)
    }

    /// A clock that starts at the given UTC time, written `YYYY-MM-DDTHH:MM:SSZ`.
    ///
    /// # Panics
    /// Panics when `text` is not a valid timestamp. This is test code, and a bad literal is a bug
    /// in the test.
    #[must_use]
    pub fn starting_at(text: &str) -> Self {
        let start = Timestamp::parse(text).expect("a valid UTC timestamp");
        Self {
            now: Mutex::new(start),
        }
    }

    /// Moves the clock forward by `by`.
    pub fn advance(&self, by: Duration) {
        let mut now = self.now.lock().expect("the clock lock is never poisoned");
        *now = timestamp_after(&now, by);
    }

    /// Moves the clock forward to `target`.
    ///
    /// # Panics
    /// Panics when `target` is before the current time: a clock must not go backwards.
    pub fn advance_to(&self, target: Timestamp) {
        let mut now = self.now.lock().expect("the clock lock is never poisoned");
        let current = *now;
        if target < current {
            // Release the lock before panicking, so the clock stays usable after a refused move.
            drop(now);
            panic!(
                "a clock must not go backwards: it is {current} and was asked to move to {target}"
            );
        }
        *now = target;
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for FakeClock {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    fn now(&self) -> Timestamp {
        *self.now.lock().expect("the clock lock is never poisoned")
    }
}

/// An identifier generator that counts: 1, 2, 3, and so on, written as UUID version 7 values.
///
/// The counter fills the timestamp field of the UUID, so later values sort after earlier ones, as
/// the `IdGenerator` contract requires. Two generators that start the same make the same values,
/// which keeps test output stable.
#[derive(Debug, Default)]
pub struct SequentialIdGenerator {
    next: Mutex<u64>,
}

impl SequentialIdGenerator {
    /// A generator whose first value has counter 1.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl IdGenerator for SequentialIdGenerator {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    fn new_uuid(&self) -> Uuid {
        let mut next = self
            .next
            .lock()
            .expect("the counter lock is never poisoned");
        *next += 1;
        // Layout of UUID version 7: 48 bits of time, 4 bits of version (7), 12 bits, 2 bits of
        // variant (0b10) and 62 bits. The counter sits in the time field so values sort.
        let counter = u128::from(*next);
        let bits = (counter << 80) | (0x7_u128 << 76) | (0b10_u128 << 62);
        Uuid::from_u128(bits)
    }
}

/// A cancellation signal that a test sets by hand.
#[derive(Debug)]
pub struct FakeCancel {
    sender: watch::Sender<bool>,
}

impl FakeCancel {
    /// A signal that is not cancelled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sender: watch::Sender::new(false),
        }
    }

    /// Requests cancellation. It cannot be taken back.
    pub fn cancel(&self) {
        self.sender.send_replace(true);
    }
}

impl Default for FakeCancel {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CancelSignal for FakeCancel {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
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

/// Runs `work` and fails the test if it takes more than `limit` of real time.
///
/// A scenario that moves time by hand has no timer of its own to end it: when a wait is never
/// ended, nothing wakes the runtime and the test hangs for ever (the engine scenarios on
/// PostgreSQL once did, for hours). This turns that into a failure that names what was waited for.
/// It is a guard for a wait that must end, not a way to wait; a limit is a safety margin that no
/// healthy run comes near.
///
/// # Panics
/// With a message that names `what` when `work` has not finished after `limit`.
pub async fn within<F: std::future::Future>(limit: Duration, what: &str, work: F) -> F::Output {
    match tokio::time::timeout(limit, work).await {
        Ok(output) => output,
        Err(_elapsed) => {
            panic!(
                "{what}: not finished after {limit:?} of real time, so nothing is going to end it"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn within_returns_what_the_work_returns() {
        let value = within(Duration::from_secs(5), "a quick job", async { 7 }).await;
        assert_eq!(value, 7);
    }

    #[tokio::test(start_paused = true)]
    #[should_panic(expected = "a wait nobody ends: not finished after 5s")]
    async fn within_fails_a_wait_that_never_ends_and_says_what_it_was() {
        within(
            Duration::from_secs(5),
            "a wait nobody ends",
            std::future::pending::<()>(),
        )
        .await;
    }

    #[test]
    fn the_clock_stands_still_until_it_is_moved() {
        let clock = FakeClock::new();
        assert_eq!(clock.now(), clock.now());
        assert_eq!(clock.now().as_text(), DEFAULT_START);
        clock.advance(Duration::from_secs(90));
        assert_eq!(clock.now().as_text(), "2026-10-27T08:31:30Z");
    }

    #[test]
    fn the_clock_never_goes_backwards() {
        let clock = FakeClock::new();
        let start = clock.now();
        clock.advance(Duration::ZERO);
        assert_eq!(clock.now(), start);
        let earlier = Timestamp::parse("2026-10-27T08:00:00Z").unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            clock.advance_to(earlier);
        }));
        assert!(outcome.is_err(), "moving back must be refused");
        assert_eq!(clock.now(), start, "a refused move changes nothing");
    }

    #[test]
    fn the_clock_can_jump_forward_to_an_instant() {
        let clock = FakeClock::new();
        let later = Timestamp::parse("2026-10-28T00:00:00Z").unwrap();
        clock.advance_to(later);
        assert_eq!(clock.now(), later);
    }

    #[test]
    fn ids_are_version_7_unique_and_in_order() {
        let ids = SequentialIdGenerator::new();
        let made: Vec<Uuid> = (0..50).map(|_| ids.new_uuid()).collect();
        for id in &made {
            assert_eq!(id.get_version_num(), 7, "{id}");
            assert_eq!((id.as_u128() >> 62) & 0b11, 0b10, "variant bits of {id}");
        }
        for pair in made.windows(2) {
            assert!(
                pair[0] < pair[1],
                "{} should sort before {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn two_fresh_generators_make_the_same_values() {
        let a = SequentialIdGenerator::new();
        let b = SequentialIdGenerator::new();
        for _ in 0..5 {
            assert_eq!(a.new_uuid(), b.new_uuid());
        }
    }

    #[test]
    fn the_first_value_is_not_the_nil_uuid() {
        assert_ne!(SequentialIdGenerator::new().new_uuid(), Uuid::nil());
    }

    #[tokio::test]
    async fn cancellation_is_sticky_and_wakes_a_waiter() {
        let cancel = std::sync::Arc::new(FakeCancel::new());
        assert!(!cancel.is_cancelled());
        let waiter = {
            let cancel = std::sync::Arc::clone(&cancel);
            tokio::spawn(async move { cancel.cancelled().await })
        };
        tokio::task::yield_now().await;
        assert!(
            !waiter.is_finished(),
            "the waiter must wait while not cancelled"
        );
        cancel.cancel();
        waiter.await.expect("the waiter finishes after cancel");
        assert!(cancel.is_cancelled());
        // Sticky: still cancelled, and a late waiter completes at once.
        cancel.cancel();
        assert!(cancel.is_cancelled());
        cancel.cancelled().await;
    }
}
