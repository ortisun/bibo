//! The delay before a stage run is tried again after a retryable failure.
//!
//! The stage contract names the first delay, the longest delay and the jitter. The delay doubles
//! with each failure since the last human answer (`state-machine.md`, bounds: 5 seconds, factor 2,
//! capped at 5 minutes, full jitter). The engine has no source of randomness of its own, so the
//! jitter is drawn from the bits of the failed attempt's identifier. The `IdGenerator` port makes
//! that identifier, so in production it is random and in a test it is a known value, and the delay
//! is the same function of its inputs every time.

use std::time::Duration;

use factory_domain::contracts::stage_contract::{Backoff, Jitter};

/// The delay to wait after the `failures`-th failure of the window (the first failure is 1).
///
/// * The base delay is `initial * 2^(failures - 1)`, never above `max`.
/// * `Jitter::None` waits the base delay.
/// * `Jitter::Equal` waits half of it and adds a share of the other half.
/// * `Jitter::Full` waits a share of the whole base delay, anywhere from none to all of it.
///
/// `seed` picks the share. The same inputs give the same delay, and the delay never exceeds `max`.
#[must_use]
pub fn retry_delay(backoff: &Backoff, failures: u32, seed: u64) -> Duration {
    let initial = u64::try_from(backoff.initial_ms.get()).unwrap_or(0);
    let longest = u64::try_from(backoff.max_ms.get()).unwrap_or(0);
    let doublings = failures.saturating_sub(1).min(32);
    let base = initial
        .checked_shl(doublings)
        .filter(|shifted| shifted >> doublings == initial)
        .map_or(longest, |shifted| shifted.min(longest))
        .min(longest);
    let millis = match backoff.jitter {
        Jitter::None => base,
        Jitter::Equal => {
            let half = base / 2;
            half + seed % (half + 1)
        }
        Jitter::Full => seed % (base + 1),
    };
    Duration::from_millis(millis)
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::values::NonNegativeInt;

    fn backoff(initial_ms: i64, max_ms: i64, jitter: Jitter) -> Backoff {
        Backoff {
            initial_ms: NonNegativeInt::new(initial_ms).expect("a count"),
            max_ms: NonNegativeInt::new(max_ms).expect("a count"),
            jitter,
        }
    }

    #[test]
    fn the_delay_doubles_with_each_failure_and_stops_at_the_cap() {
        let steps = backoff(5_000, 300_000, Jitter::None);
        let delays: Vec<u64> = (1..=8)
            .map(|n| retry_delay(&steps, n, 0).as_millis() as u64)
            .collect();
        assert_eq!(
            delays,
            vec![
                5_000, 10_000, 20_000, 40_000, 80_000, 160_000, 300_000, 300_000
            ]
        );
    }

    #[test]
    fn full_jitter_stays_between_none_and_the_base_delay() {
        let steps = backoff(5_000, 300_000, Jitter::Full);
        for seed in [0, 1, 4_999, 5_000, 123_456_789, u64::MAX] {
            let delay = retry_delay(&steps, 1, seed);
            assert!(delay <= Duration::from_millis(5_000), "{seed}: {delay:?}");
        }
        assert_eq!(retry_delay(&steps, 1, 0), Duration::ZERO);
    }

    #[test]
    fn equal_jitter_keeps_at_least_half_the_base_delay() {
        let steps = backoff(5_000, 300_000, Jitter::Equal);
        for seed in [0, 7, 2_500, u64::MAX] {
            let delay = retry_delay(&steps, 2, seed);
            assert!(delay >= Duration::from_millis(5_000), "{seed}: {delay:?}");
            assert!(delay <= Duration::from_millis(10_000), "{seed}: {delay:?}");
        }
    }

    #[test]
    fn a_huge_number_of_failures_does_not_overflow() {
        let steps = backoff(5_000, 300_000, Jitter::None);
        assert_eq!(
            retry_delay(&steps, u32::MAX, 0),
            Duration::from_millis(300_000)
        );
    }

    #[test]
    fn a_cap_below_the_first_delay_wins() {
        let steps = backoff(10_000, 2_000, Jitter::None);
        assert_eq!(retry_delay(&steps, 1, 0), Duration::from_millis(2_000));
    }
}
