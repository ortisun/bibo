//! Durations and money as integers with a unit. A duration cannot be added to an amount of money,
//! and a total outside the valid range is an error.

use std::fmt;

use super::MetricError;
use super::rounding::divide_half_even;
use crate::values::LARGEST_EXACT_INTEGER;

/// The largest duration: 2^53 - 1 milliseconds, the largest integer a ledger entry holds exactly
/// (ADR 0011). It is about 285 000 years.
const LARGEST_DURATION: u64 = LARGEST_EXACT_INTEGER as u64;

/// A duration in whole milliseconds, from 0 to 2^53 - 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Milliseconds(u64);

impl Milliseconds {
    /// No time at all.
    pub const ZERO: Self = Self(0);
    /// The largest duration, 2^53 - 1 milliseconds.
    pub const MAX: Self = Self(LARGEST_DURATION);

    /// Wraps a number of milliseconds. A value above 2^53 - 1 is refused.
    pub fn new(milliseconds: u64) -> Result<Self, MetricError> {
        if milliseconds > LARGEST_DURATION {
            return Err(MetricError::OutOfRange {
                what: "a duration in milliseconds",
            });
        }
        Ok(Self(milliseconds))
    }

    /// The number of milliseconds.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The same number as a signed integer, for the comparison of medians. It always fits,
    /// because a duration is at most 2^53 - 1.
    pub const fn signed(self) -> i64 {
        self.0 as i64
    }

    /// The sum of two durations. A sum above the largest duration is refused.
    pub fn checked_add(self, other: Self) -> Result<Self, MetricError> {
        // Both are at most 2^53 - 1, so the `u64` addition itself cannot overflow.
        Self::new(self.0 + other.0)
    }

    /// The time from `start` to `end`, both measured from the same origin. An `end` before its
    /// `start` is refused: a negative duration is a fault in the facts, not a small number.
    pub fn between(start: Self, end: Self) -> Result<Self, MetricError> {
        end.0
            .checked_sub(start.0)
            .map(Self)
            .ok_or(MetricError::OutOfRange {
                what: "a duration whose end is before its start",
            })
    }

    /// The sum of many durations. A sum above the largest duration is refused.
    pub fn sum(durations: impl IntoIterator<Item = Self>) -> Result<Self, MetricError> {
        durations
            .into_iter()
            .try_fold(Self::ZERO, Self::checked_add)
    }
}

impl fmt::Display for Milliseconds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ms", self.0)
    }
}

/// An amount of money in millionths of a United States dollar, from -(2^53 - 1) to 2^53 - 1.
/// One dollar is 1 000 000. A refund or a credit is negative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MicroUsd(i64);

impl MicroUsd {
    /// No money.
    pub const ZERO: Self = Self(0);
    /// The largest amount, 2^53 - 1 millionths of a dollar (about nine billion dollars).
    pub const MAX: Self = Self(LARGEST_EXACT_INTEGER);
    /// The smallest amount, -(2^53 - 1) millionths of a dollar.
    pub const MIN: Self = Self(-LARGEST_EXACT_INTEGER);

    /// Wraps a number of millionths of a dollar. A value outside the valid range is refused.
    pub fn new(micro_usd: i64) -> Result<Self, MetricError> {
        if !(-LARGEST_EXACT_INTEGER..=LARGEST_EXACT_INTEGER).contains(&micro_usd) {
            return Err(MetricError::OutOfRange {
                what: "an amount in millionths of a dollar",
            });
        }
        Ok(Self(micro_usd))
    }

    /// The number of millionths of a dollar.
    pub const fn get(self) -> i64 {
        self.0
    }

    /// The sum of two amounts. A sum outside the valid range is refused.
    pub fn checked_add(self, other: Self) -> Result<Self, MetricError> {
        // Both are within 2^53 - 1 of zero, so the `i64` addition itself cannot overflow.
        Self::new(self.0 + other.0)
    }

    /// The sum of many amounts. A sum outside the valid range is refused.
    pub fn sum(amounts: impl IntoIterator<Item = Self>) -> Result<Self, MetricError> {
        amounts.into_iter().try_fold(Self::ZERO, Self::checked_add)
    }

    /// This amount shared over `count` things, rounded half to even to a whole millionth of a
    /// dollar: the cost per accepted pull request is the spend over the merged pull requests.
    /// A count of zero is refused.
    pub fn per(self, count: u64) -> Result<Self, MetricError> {
        let what = "an amount of money per item";
        let share = divide_half_even(i128::from(self.0), i128::from(count), what)?;
        // The share is never further from zero than the amount, so it fits.
        Ok(Self(
            i64::try_from(share).map_err(|_| MetricError::OutOfRange { what })?,
        ))
    }
}

/// Shows the amount in dollars with two decimal places, rounded half to even: `0.84 USD`.
impl fmt::Display for MicroUsd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cents = divide_half_even(i128::from(self.0), 10_000, "an amount in cents")
            .map_err(|_| fmt::Error)?;
        let sign = if cents < 0 { "-" } else { "" };
        let cents = cents.unsigned_abs();
        write!(f, "{sign}{}.{:02} USD", cents / 100, cents % 100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(value: u64) -> Milliseconds {
        Milliseconds::new(value).expect("valid duration")
    }

    fn usd(value: i64) -> MicroUsd {
        MicroUsd::new(value).expect("valid amount")
    }

    #[test]
    fn a_duration_holds_zero_one_and_the_maximum() {
        assert_eq!(ms(0), Milliseconds::ZERO);
        assert_eq!(ms(1).get(), 1);
        assert_eq!(ms(LARGEST_DURATION), Milliseconds::MAX);
        assert_eq!(Milliseconds::MAX.signed(), LARGEST_EXACT_INTEGER);
        assert!(Milliseconds::new(LARGEST_DURATION + 1).is_err());
        assert!(Milliseconds::new(u64::MAX).is_err());
    }

    #[test]
    fn a_sum_of_durations_is_exact_or_refused() {
        assert_eq!(Milliseconds::sum([]), Ok(Milliseconds::ZERO));
        assert_eq!(Milliseconds::sum([ms(1)]), Ok(ms(1)));
        assert_eq!(Milliseconds::sum([ms(40), ms(2), ms(0)]), Ok(ms(42)));
        assert_eq!(
            Milliseconds::sum([ms(LARGEST_DURATION - 1), ms(1)]),
            Ok(Milliseconds::MAX)
        );
        assert!(Milliseconds::sum([Milliseconds::MAX, ms(1)]).is_err());
        assert!(Milliseconds::MAX.checked_add(Milliseconds::MAX).is_err());
    }

    #[test]
    fn an_end_before_its_start_is_refused() {
        assert_eq!(Milliseconds::between(ms(5), ms(5)), Ok(Milliseconds::ZERO));
        assert_eq!(Milliseconds::between(ms(5), ms(6)), Ok(ms(1)));
        assert_eq!(
            Milliseconds::between(Milliseconds::ZERO, Milliseconds::MAX),
            Ok(Milliseconds::MAX)
        );
        assert!(Milliseconds::between(ms(6), ms(5)).is_err());
    }

    #[test]
    fn an_amount_holds_both_signs_up_to_the_ledger_limit() {
        assert_eq!(usd(0), MicroUsd::ZERO);
        assert_eq!(usd(-1).get(), -1);
        assert_eq!(usd(LARGEST_EXACT_INTEGER), MicroUsd::MAX);
        assert_eq!(usd(-LARGEST_EXACT_INTEGER), MicroUsd::MIN);
        assert!(MicroUsd::new(LARGEST_EXACT_INTEGER + 1).is_err());
        assert!(MicroUsd::new(-LARGEST_EXACT_INTEGER - 1).is_err());
        assert!(MicroUsd::new(i64::MIN).is_err());
    }

    #[test]
    fn a_sum_of_amounts_is_exact_or_refused() {
        assert_eq!(MicroUsd::sum([]), Ok(MicroUsd::ZERO));
        assert_eq!(
            MicroUsd::sum([usd(840_000), usd(-40_000)]),
            Ok(usd(800_000))
        );
        assert_eq!(
            MicroUsd::sum([MicroUsd::MAX, MicroUsd::MIN]),
            Ok(MicroUsd::ZERO)
        );
        assert!(MicroUsd::sum([MicroUsd::MAX, usd(1)]).is_err());
        assert!(MicroUsd::sum([MicroUsd::MIN, usd(-1)]).is_err());
    }

    #[test]
    fn a_cost_per_item_rounds_half_to_even() {
        assert_eq!(usd(0).per(3), Ok(usd(0)));
        assert_eq!(usd(10).per(1), Ok(usd(10)));
        assert_eq!(usd(5).per(2), Ok(usd(2)));
        assert_eq!(usd(7).per(2), Ok(usd(4)));
        assert_eq!(usd(-5).per(2), Ok(usd(-2)));
        assert_eq!(usd(16_000_000).per(19), Ok(usd(842_105)));
        assert_eq!(MicroUsd::MAX.per(1), Ok(MicroUsd::MAX));
        assert_eq!(MicroUsd::MAX.per(u64::MAX), Ok(usd(0)));
        assert_eq!(
            usd(1).per(0),
            Err(MetricError::DenominatorNotPositive {
                what: "an amount of money per item"
            })
        );
    }

    #[test]
    fn the_display_shows_dollars_and_cents() {
        assert_eq!(usd(840_000).to_string(), "0.84 USD");
        assert_eq!(usd(1_020_000).to_string(), "1.02 USD");
        assert_eq!(usd(0).to_string(), "0.00 USD");
        assert_eq!(usd(5_000).to_string(), "0.00 USD"); // half a cent, tie, even
        assert_eq!(usd(15_000).to_string(), "0.02 USD"); // one and a half cents, tie, even
        assert_eq!(usd(-15_000).to_string(), "-0.02 USD");
        assert_eq!(usd(-4_000).to_string(), "0.00 USD");
        assert_eq!(usd(12_345_678_900).to_string(), "12345.68 USD");
        assert_eq!(ms(41).to_string(), "41 ms");
    }
}
