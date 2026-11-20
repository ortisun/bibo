//! Time, identifiers and cancellation: the three things every other port needs and the domain
//! is not allowed to make itself.
//!
//! Inner code never reads the system clock or makes a random identifier (rule DEP-05). It asks
//! these ports, so a test can control all three.

use std::time::Duration;

use async_trait::async_trait;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::Fidelity;
/// The identifier type [`IdGenerator`] returns, re-exported so an implementation (the testkit's
/// fake, or the real generator in the apps) can name it without a `uuid` dependency of its own.
pub use uuid::Uuid;

/// The source of the current time for everything except lease and deadline checks.
///
/// Lease expiry and deadlines use the database clock (`Tx::database_time`), never this port, so
/// that clock skew between worker hosts cannot extend or shorten a lease (ADR 0007).
///
/// # Preconditions
/// None. The clock is ready as soon as it exists.
///
/// # Postconditions
/// `now` never goes backwards between two calls on the same clock value. It may return the same
/// instant twice.
///
/// # Errors
/// None. `now` cannot fail. An implementation that cannot read the time must not exist.
///
/// # Idempotency
/// Reading the time changes nothing, so a call can be repeated freely.
///
/// # Cancellation and timeouts
/// The call is pure and returns at once. There is nothing to cancel and no timeout.
pub trait Clock: Send + Sync {
    /// Says whether this clock is the system clock (`real`) or a controllable stand-in (`fake`).
    /// A production run refuses a clock that reports `fake`.
    fn fidelity(&self) -> Fidelity;

    /// The current UTC time.
    fn now(&self) -> Timestamp;
}

/// The source of new identifiers.
///
/// # Preconditions
/// None.
///
/// # Postconditions
/// Every value returned is a UUID version 7 (ADR 0007), and no two calls on one generator return
/// the same value. Within one generator, values sort in the order they were made.
///
/// # Errors
/// None. `new_uuid` cannot fail.
///
/// # Idempotency
/// Not idempotent by design: each call returns a new value.
///
/// # Cancellation and timeouts
/// The call returns at once. There is nothing to cancel and no timeout.
pub trait IdGenerator: Send + Sync {
    /// Says whether this generator is the real one (`real`) or a deterministic stand-in (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// A new UUID version 7.
    fn new_uuid(&self) -> Uuid;
}

/// A signal that the work in progress should stop.
///
/// A long operation (`SandboxSession::exec`, `AgentRuntime::run`) takes a `&dyn CancelSignal`
/// and must watch it. The signal only asks; the operation decides how to stop cleanly.
///
/// # Preconditions
/// None.
///
/// # Postconditions
/// Once `is_cancelled` returns `true` it returns `true` for ever after on the same signal: a
/// cancel cannot be taken back. `cancelled` completes when, and only when, that has happened. If
/// the signal is already cancelled, `cancelled` completes at once.
///
/// # Errors
/// None. Neither method can fail.
///
/// # Idempotency
/// Reading the signal changes nothing, so both methods can be called any number of times.
///
/// # Cancellation and timeouts
/// Checking the signal never blocks. The signal only asks; a method that takes it stops within one
/// second of the signal being set.
#[async_trait]
pub trait CancelSignal: Send + Sync {
    /// Says whether this signal is wired to a real cancellation source (`real`) or is a manual
    /// stand-in (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// True once cancellation was requested.
    fn is_cancelled(&self) -> bool;

    /// Waits until cancellation is requested.
    async fn cancelled(&self);
}

/// The instant `after` past `start`. The result saturates at the largest instant `Timestamp`
/// can hold instead of failing, because a lease that never expires is a safe answer for a
/// duration that large.
#[must_use]
pub fn timestamp_after(start: &Timestamp, after: Duration) -> Timestamp {
    let step = time::Duration::try_from(after).unwrap_or(time::Duration::MAX);
    let moment = start
        .to_utc()
        .checked_add(step)
        .unwrap_or(time::OffsetDateTime::new_utc(
            time::Date::MAX,
            time::Time::MAX,
        ));
    Timestamp::from_utc(moment)
}

/// How long it is from `earlier` to `later`, or `None` when `later` is before `earlier`.
#[must_use]
pub fn duration_between(earlier: &Timestamp, later: &Timestamp) -> Option<Duration> {
    let gap = later.to_utc() - earlier.to_utc();
    Duration::try_from(gap).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a valid timestamp")
    }

    #[test]
    fn adding_a_duration_moves_the_instant_forward() {
        let start = at("2026-10-27T08:30:01Z");
        let later = timestamp_after(&start, Duration::from_secs(60));
        assert_eq!(later, at("2026-10-27T08:31:01Z"));
    }

    #[test]
    fn adding_keeps_sub_second_precision() {
        let start = at("2026-10-27T08:30:01Z");
        let later = timestamp_after(&start, Duration::from_millis(1500));
        assert_eq!(later, at("2026-10-27T08:30:02.5Z"));
    }

    #[test]
    fn adding_across_midnight_changes_the_date() {
        let start = at("2026-12-31T23:59:30Z");
        let later = timestamp_after(&start, Duration::from_secs(45));
        assert_eq!(later, at("2027-01-01T00:00:15Z"));
    }

    #[test]
    fn a_huge_duration_saturates_instead_of_panicking() {
        let start = at("2026-10-27T08:30:01Z");
        let later = timestamp_after(&start, Duration::from_secs(u64::MAX));
        assert!(later > start);
    }

    #[test]
    fn the_gap_between_two_instants_is_measured() {
        let a = at("2026-10-27T08:30:00Z");
        let b = at("2026-10-27T08:31:30Z");
        assert_eq!(duration_between(&a, &b), Some(Duration::from_secs(90)));
    }

    #[test]
    fn the_gap_is_none_when_the_second_instant_is_earlier() {
        let a = at("2026-10-27T08:30:00Z");
        let b = at("2026-10-27T08:29:59Z");
        assert_eq!(duration_between(&a, &b), None);
    }

    #[test]
    fn the_gap_between_equal_instants_is_zero() {
        let a = at("2026-10-27T08:30:00Z");
        assert_eq!(duration_between(&a, &a), Some(Duration::ZERO));
    }
}
