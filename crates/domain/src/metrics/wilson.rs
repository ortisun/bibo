//! The Wilson score interval of a rate and Newcombe's interval of the difference of two rates,
//! in integers.
//!
//! The Wilson interval of `x` successes in `n` trials is the set of rates `p` with
//! `(x/n - p)^2 <= z^2 * p * (1 - p) / n`. With `z = 49/25` (1.96) and `p = k / 1 000 000`, that
//! is the integer inequality
//!
//! ```text
//! 625 * (x * 1 000 000 - n * k)^2  <=  2401 * n * k * (1 000 000 - k)
//! ```
//!
//! The left side minus the right side is a quadratic in `k` that opens upward, and its two roots
//! are the bounds. The lower bound, rounded down to a whole millionth, is the largest `k` at or
//! below the measured rate where the inequality fails or holds with equality. A binary search
//! finds it exactly, with no square root. The upper bound follows from the symmetry of the
//! interval: the upper bound of `x` in `n` is one minus the lower bound of `n - x` in `n`.

use super::MetricError;
use super::comparison::Interval;
use super::proportion::Proportion;
use super::rounding::{divide_half_even, square_root_rounded_up};

/// The scale of a rate and of a difference of rates: one is 1 000 000 millionths.
pub const MILLIONTHS: u64 = 1_000_000;

/// The largest number of trials a rate may have in a comparison: 2^32. Above it the comparison
/// is refused. With this limit every product below fits `u128` (the largest is under 2^114).
pub const MAXIMUM_RATE_SAMPLE: u64 = 1 << 32;

/// The square of the numerator of the normal quantile 49/25 (1.96, the 95 percent value).
const QUANTILE_NUMERATOR_SQUARED: u128 = 49 * 49;
/// The square of the denominator of the normal quantile 49/25.
const QUANTILE_DENOMINATOR_SQUARED: u128 = 25 * 25;

const SCALE: u128 = MILLIONTHS as u128;

/// The 95 percent Wilson score interval of a rate, in millionths. The lower bound is rounded
/// down and the upper bound up, so the interval is never narrower than the exact one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RateInterval {
    lower: u32,
    upper: u32,
}

impl RateInterval {
    /// The lower bound in millionths, from 0 to 1 000 000.
    pub const fn lower(self) -> u32 {
        self.lower
    }

    /// The upper bound in millionths, from 0 to 1 000 000.
    pub const fn upper(self) -> u32 {
        self.upper
    }
}

/// The 95 percent Wilson score interval of a rate. A rate of more than 2^32 trials is refused.
pub fn wilson_interval(rate: Proportion) -> Result<RateInterval, MetricError> {
    let successes = rate.numerator();
    let trials = rate.denominator();
    if trials > MAXIMUM_RATE_SAMPLE {
        return Err(MetricError::OutOfRange {
            what: "the number of trials of a compared rate",
        });
    }
    let lower = lower_bound(successes, trials);
    let upper = MILLIONTHS - lower_bound(trials - successes, trials);
    // Both are at most 1 000 000.
    Ok(RateInterval {
        lower: lower as u32,
        upper: upper as u32,
    })
}

/// The exact lower Wilson bound, rounded down to a whole millionth.
fn lower_bound(successes: u64, trials: u64) -> u64 {
    let successes = u128::from(successes);
    let trials = u128::from(trials);
    // The search stays at or below the measured rate, where `trials * k <= successes * SCALE`.
    // With every trial a success the measured rate is itself the upper root, so it is left out.
    let mut last = if successes == trials {
        SCALE - 1
    } else {
        successes * SCALE / trials
    };
    let mut first = 0u128;
    // Invariant: `k = first` is at or below the lower root (true for 0), and every `k > last`
    // within the range is above it.
    while first < last {
        let middle = first + (last - first).div_ceil(2);
        if at_or_below_lower_root(successes, trials, middle) {
            first = middle;
        } else {
            last = middle - 1;
        }
    }
    first as u64
}

/// Whether `k` millionths is at or below the lower root, for a `k` at or below the measured rate.
fn at_or_below_lower_root(successes: u128, trials: u128, k: u128) -> bool {
    // At most 2^32 * 10^6 < 2^52; squared and times 625, under 2^114.
    let distance = successes * SCALE - trials * k;
    let left = QUANTILE_DENOMINATOR_SQUARED * distance * distance;
    // At most 2401 * 2^32 * (10^6 / 2)^2 < 2^82.
    let right = QUANTILE_NUMERATOR_SQUARED * trials * k * (SCALE - k);
    left >= right
}

/// The measured rate in millionths, rounded down and rounded up.
fn measured(rate: Proportion) -> (i64, i64) {
    let scaled = u128::from(rate.numerator()) * SCALE;
    let trials = u128::from(rate.denominator());
    // Both are at most 1 000 000.
    ((scaled / trials) as i64, scaled.div_ceil(trials) as i64)
}

/// The difference of two rates, after minus before, in millionths, with its 95 percent interval
/// by Newcombe's hybrid score method:
///
/// ```text
/// lower = d - sqrt((after - lower_after)^2 + (upper_before - before)^2)
/// upper = d + sqrt((upper_after - after)^2 + (before - lower_before)^2)
/// ```
///
/// Every rounding goes outward (each rate, each Wilson bound and the square root), so the
/// interval contains the exact one and is at most 7 millionths wider on each side.
pub fn rate_difference(before: Proportion, after: Proportion) -> Result<Interval, MetricError> {
    let what = "the difference of two rates";
    let wilson_before = wilson_interval(before)?;
    let wilson_after = wilson_interval(after)?;
    let (before_down, before_up) = measured(before);
    let (after_down, after_up) = measured(after);

    let radius = |first: i64, second: i64| -> i64 {
        // Each gap is between 0 and 1 000 000, so the sum of squares is at most 2 * 10^12.
        let squares = (first * first + second * second) as u128;
        square_root_rounded_up(squares) as i64
    };
    let lower_radius = radius(
        after_up - i64::from(wilson_after.lower()),
        i64::from(wilson_before.upper()) - before_down,
    );
    let upper_radius = radius(
        i64::from(wilson_after.upper()) - after_down,
        before_up - i64::from(wilson_before.lower()),
    );

    let scale = MILLIONTHS as i64;
    let lower = (after_down - before_up - lower_radius).max(-scale);
    let upper = (after_up - before_down + upper_radius).min(scale);

    // d = (x_after * n_before - x_before * n_after) / (n_after * n_before). Each product is at
    // most 2^64, and times 10^6 under 2^84.
    let cross = i128::from(after.numerator()) * i128::from(before.denominator())
        - i128::from(before.numerator()) * i128::from(after.denominator());
    let trials = i128::from(after.denominator()) * i128::from(before.denominator());
    let point = divide_half_even(cross * i128::from(MILLIONTHS), trials, what)?;
    let point = i64::try_from(point).map_err(|_| MetricError::OutOfRange { what })?;

    Interval::new(lower, point, upper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{Direction, Verdict};
    use proptest::prelude::*;

    fn rate(numerator: u64, denominator: u64) -> Proportion {
        Proportion::new(numerator, denominator).expect("valid rate")
    }

    fn bounds(numerator: u64, denominator: u64) -> (u32, u32) {
        let interval = wilson_interval(rate(numerator, denominator)).expect("within the limit");
        (interval.lower(), interval.upper())
    }

    /// The expected values come from the closed formula of the Wilson interval, evaluated with
    /// 60 decimal digits and z = 1.96 in Python's `decimal` module: a different method from the
    /// integer search of this file. The lower bound is that value rounded down, the upper bound
    /// rounded up.
    #[test]
    fn the_bounds_match_the_closed_formula() {
        assert_eq!(bounds(14, 23), (407_851, 778_427)); // 407851.7960, 778426.2202
        assert_eq!(bounds(11, 21), (323_692, 716_563)); // 323692.1790, 716562.8770
        assert_eq!(bounds(3, 7), (158_216, 749_546)); // 158216.9223, 749545.7696
        assert_eq!(bounds(50, 100), (403_829, 596_171)); // 403829.8286, 596170.1714
        assert_eq!(bounds(1, 1_000_000), (0, 6)); // 0.1765, 5.6651
    }

    #[test]
    fn zero_one_and_the_maximum() {
        assert_eq!(bounds(0, 1), (0, 793_457)); // 0, 793456.7085
        assert_eq!(bounds(1, 1), (206_543, 1_000_000)); // 206543.2915, 1000000
        assert_eq!(bounds(0, 20), (0, 161_131)); // 0, 161130.1255
        assert_eq!(bounds(20, 20), (838_869, 1_000_000)); // 838869.8745, 1000000
        // 2^31 of 2^32: 499985.0464, 500014.9536
        assert_eq!(bounds(1 << 31, MAXIMUM_RATE_SAMPLE), (499_985, 500_015));
        assert_eq!(bounds(0, MAXIMUM_RATE_SAMPLE).0, 0);
        assert_eq!(
            bounds(MAXIMUM_RATE_SAMPLE, MAXIMUM_RATE_SAMPLE).1,
            1_000_000
        );
    }

    #[test]
    fn more_than_the_maximum_sample_is_refused() {
        let too_many = rate(1, MAXIMUM_RATE_SAMPLE + 1);
        assert!(wilson_interval(too_many).is_err());
        assert!(rate_difference(too_many, rate(1, 2)).is_err());
        assert!(rate_difference(rate(1, 2), too_many).is_err());
        assert!(wilson_interval(rate(u64::MAX, u64::MAX)).is_err());
    }

    /// The expected values come from Newcombe's formula evaluated with 60 decimal digits in
    /// Python's `decimal` module: the lower bound rounded down, the point rounded half to even,
    /// the upper bound rounded up. Outward rounding may widen each side by up to 7 millionths.
    #[test]
    fn the_difference_matches_newcombes_formula() {
        fn check(before: (u64, u64), after: (u64, u64), lower: i64, point: i64, upper: i64) {
            let interval =
                rate_difference(rate(before.0, before.1), rate(after.0, after.1)).expect("valid");
            assert_eq!(interval.point(), point, "{before:?} to {after:?}");
            assert!(
                (lower - 7..=lower).contains(&interval.lower()),
                "{before:?} to {after:?}: lower {} against {lower}",
                interval.lower()
            );
            assert!(
                (upper..=upper + 7).contains(&interval.upper()),
                "{before:?} to {after:?}: upper {} against {upper}",
                interval.upper()
            );
        }
        check((11, 21), (14, 23), -193_488, 84_886, 347_290); // -193487.9181, 347289.2865
        check((100, 1000), (300, 1000), 165_830, 200_000, 233_769); // 165830.9032, 233768.7444
        check((300, 1000), (100, 1000), -233_769, -200_000, -165_830); // the same, mirrored
        check((0, 20), (20, 20), 772_127, 1_000_000, 1_000_000); // 772127.5912, 1000000
    }

    #[test]
    fn the_decision_follows_the_interval() {
        let small = rate_difference(rate(11, 21), rate(14, 23)).expect("valid");
        assert_eq!(
            small.verdict(Direction::HigherIsBetter),
            Verdict::NoClearChange
        );

        let better = rate_difference(rate(100, 1000), rate(300, 1000)).expect("valid");
        assert_eq!(
            better.verdict(Direction::HigherIsBetter),
            Verdict::Improvement
        );
        assert_eq!(better.verdict(Direction::LowerIsBetter), Verdict::Worsening);

        let same = rate_difference(rate(5, 10), rate(50, 100)).expect("valid");
        assert_eq!(same.point(), 0);
        assert_eq!(
            same.verdict(Direction::HigherIsBetter),
            Verdict::NoClearChange
        );
    }

    #[test]
    fn the_difference_stays_within_minus_one_and_one() {
        let up = rate_difference(rate(0, 1 << 32), rate(1 << 32, 1 << 32)).expect("valid");
        assert_eq!(up.point(), 1_000_000);
        assert!(up.upper() <= 1_000_000 && up.lower() > 999_990);
        let down = rate_difference(rate(1, 1), rate(0, 1)).expect("valid");
        assert_eq!(down.point(), -1_000_000);
        assert!(down.lower() >= -1_000_000);
    }

    proptest! {
        /// The definition, checked directly: the lower bound is at or below the root and the next
        /// millionth is strictly inside the interval; the same for the upper bound, mirrored.
        #[test]
        fn the_bounds_are_the_roots_rounded_outward(
            trials in 1u64..=MAXIMUM_RATE_SAMPLE,
            share in 0u64..=1_000_000,
        ) {
            let successes = ((u128::from(trials) * u128::from(share)) / 1_000_000) as u64;
            let (lower, upper) = bounds(successes, trials);
            let (x, n) = (i128::from(successes), i128::from(trials));
            // Positive when `k` millionths is strictly outside the interval, zero on a root.
            let outside = |k: i128| 625 * (x * 1_000_000 - n * k).pow(2) - 2401 * n * k * (1_000_000 - k);
            let (lower, upper) = (i128::from(lower), i128::from(upper));

            prop_assert!(lower * n <= x * 1_000_000 && x * 1_000_000 <= upper * n);
            prop_assert!(outside(lower) >= 0);
            prop_assert!(outside(upper) >= 0);
            if (lower + 1) * n <= x * 1_000_000 {
                prop_assert!(outside(lower + 1) < 0);
            }
            if (upper - 1) * n >= x * 1_000_000 {
                prop_assert!(outside(upper - 1) < 0);
            }
        }

        #[test]
        fn the_interval_is_symmetric_in_successes_and_failures(
            trials in 1u64..=1_000_000,
            share in 0u64..=1_000_000,
        ) {
            let successes = trials * share / 1_000_000;
            let (lower, upper) = bounds(successes, trials);
            let (mirror_lower, mirror_upper) = bounds(trials - successes, trials);
            prop_assert_eq!(lower, 1_000_000 - mirror_upper);
            prop_assert_eq!(upper, 1_000_000 - mirror_lower);
        }

        #[test]
        fn swapping_before_and_after_mirrors_the_difference(
            before_trials in 1u64..=100_000, before_share in 0u64..=1000,
            after_trials in 1u64..=100_000, after_share in 0u64..=1000,
        ) {
            let before = rate(before_trials * before_share / 1000, before_trials);
            let after = rate(after_trials * after_share / 1000, after_trials);
            let forward = rate_difference(before, after).expect("valid");
            let backward = rate_difference(after, before).expect("valid");
            prop_assert_eq!(forward.lower(), -backward.upper());
            prop_assert_eq!(forward.upper(), -backward.lower());
            prop_assert_eq!(forward.point(), -backward.point());
        }
    }
}
