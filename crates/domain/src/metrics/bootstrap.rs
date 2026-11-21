//! The difference of two medians with a percentile bootstrap interval from a fixed seed.
//!
//! The procedure, as the design document states it:
//!
//! 1. Draw, with replacement, as many values from the "before" samples as there are, then the
//!    same for "after". Take the median of each by nearest rank and their difference.
//! 2. Repeat for the number of resamples.
//! 3. The interval runs from the 2.5th to the 97.5th percentile of those differences, by nearest
//!    rank. If the measured difference lies outside them, the interval is widened to hold it.
//!
//! The draws come from SplitMix64 (Steele, Lea and Flood, 2014), started from the seed. An index
//! below `n` is drawn without bias by Lemire's multiply-and-reject method (2019). Both are fixed
//! here, so the same samples and seed give the same interval on every machine. This is a
//! deterministic function of its input, not a source of randomness: the crate still makes no
//! random call.

use super::MetricError;
use super::comparison::Interval;
use super::percentile::{Percentile, median, nearest_rank_in_place};

/// The 2.5th percentile, in hundredths of a percent.
const LOWER_PERCENTILE: u16 = 250;
/// The 97.5th percentile, in hundredths of a percent.
const UPPER_PERCENTILE: u16 = 9_750;

/// The seed of the bootstrap's generator. It is part of the input, so a result can be recomputed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Seed(pub u64);

impl Seed {
    /// The seed used when a metric's definition states none: 29.
    pub const DEFAULT: Self = Self(29);
}

/// How many times the bootstrap resamples: from 1000 to 100 000.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Resamples(u32);

impl Resamples {
    /// The number used when a metric's definition states none: 2000.
    pub const DEFAULT: Self = Self(2_000);
    const MINIMUM: u32 = 1_000;
    const MAXIMUM: u32 = 100_000;

    /// A number of resamples. Fewer than 1000 make the 2.5th percentile rest on too few values,
    /// and more than 100 000 cost time for no better decision; both are refused.
    pub fn new(resamples: u32) -> Result<Self, MetricError> {
        if !(Self::MINIMUM..=Self::MAXIMUM).contains(&resamples) {
            return Err(MetricError::SettingOutOfRange {
                what: "the number of bootstrap resamples",
                minimum: u64::from(Self::MINIMUM),
                maximum: u64::from(Self::MAXIMUM),
                offered: u64::from(resamples),
            });
        }
        Ok(Self(resamples))
    }

    /// The number of resamples.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// SplitMix64. Its arithmetic wraps on purpose: that is the definition of the generator, not a
/// sum of measured values.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    /// A number from 0 to `bound - 1`, each equally likely. `bound` is at least 1.
    fn below(&mut self, bound: u64) -> u64 {
        let mut product = u128::from(self.next()) * u128::from(bound);
        if (product as u64) < bound {
            // The values of the low half below this threshold are the ones that would make some
            // results more likely than others; they are drawn again.
            let threshold = bound.wrapping_neg() % bound;
            while (product as u64) < threshold {
                product = u128::from(self.next()) * u128::from(bound);
            }
        }
        (product >> 64) as u64
    }
}

/// The median of one resample of `samples`, drawn with replacement into `scratch`.
fn resampled_median(
    samples: &[i64],
    scratch: &mut Vec<i64>,
    generator: &mut SplitMix64,
) -> Result<i64, MetricError> {
    scratch.clear();
    let count = samples.len() as u64;
    for _ in 0..samples.len() {
        // The index is below the length, so it fits `usize`.
        scratch.push(samples[generator.below(count) as usize]);
    }
    nearest_rank_in_place(scratch, Percentile::MEDIAN)
}

fn difference(after: i64, before: i64) -> Result<i64, MetricError> {
    after.checked_sub(before).ok_or(MetricError::OutOfRange {
        what: "the difference of two medians",
    })
}

/// The median of `after` minus the median of `before`, with its 95 percent percentile bootstrap
/// interval. The unit is the unit of the samples. An empty side is refused, and so is a
/// difference that does not fit `i64`.
///
/// The rule on too few samples is the caller's: see
/// [`MinimumSample::measure`](super::MinimumSample::measure).
pub fn median_difference(
    before: &[i64],
    after: &[i64],
    resamples: Resamples,
    seed: Seed,
) -> Result<Interval, MetricError> {
    if before.is_empty() || after.is_empty() {
        return Err(MetricError::NoSamples {
            what: "a comparison of medians",
        });
    }
    let point = difference(median(after)?, median(before)?)?;

    let mut generator = SplitMix64 { state: seed.0 };
    let mut scratch = Vec::with_capacity(before.len().max(after.len()));
    let mut differences = Vec::with_capacity(resamples.0 as usize);
    for _ in 0..resamples.0 {
        let before_median = resampled_median(before, &mut scratch, &mut generator)?;
        let after_median = resampled_median(after, &mut scratch, &mut generator)?;
        differences.push(difference(after_median, before_median)?);
    }

    let lower = nearest_rank_in_place(
        &mut differences,
        Percentile::from_hundredths(LOWER_PERCENTILE)?,
    )?;
    let upper = nearest_rank_in_place(
        &mut differences,
        Percentile::from_hundredths(UPPER_PERCENTILE)?,
    )?;
    Interval::new(lower.min(point), point, upper.max(point))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{Direction, Verdict};
    use proptest::prelude::*;

    fn compare(before: &[i64], after: &[i64], seed: u64) -> Interval {
        median_difference(before, after, Resamples::DEFAULT, Seed(seed)).expect("valid comparison")
    }

    /// The first outputs of the reference implementation for the seeds 1234567 and 0.
    #[test]
    fn the_generator_is_splitmix64() {
        let mut generator = SplitMix64 { state: 1_234_567 };
        assert_eq!(generator.next(), 6_457_827_717_110_365_317);
        assert_eq!(generator.next(), 3_203_168_211_198_807_973);
        assert_eq!(generator.next(), 9_817_491_932_198_370_423);
        let mut generator = SplitMix64 { state: 0 };
        assert_eq!(generator.next(), 16_294_208_416_658_607_535);
        assert_eq!(generator.next(), 7_960_286_522_194_355_700);
    }

    #[test]
    fn an_index_is_always_below_its_bound() {
        let mut generator = SplitMix64 { state: 29 };
        for bound in [1, 2, 3, 7, 1 << 32, u64::MAX - 1, u64::MAX] {
            for _ in 0..200 {
                assert!(generator.below(bound) < bound);
            }
        }
        assert_eq!(generator.below(1), 0);
    }

    #[test]
    fn every_index_is_drawn_about_equally_often() {
        let mut generator = SplitMix64 { state: 29 };
        let mut counts = [0u32; 6];
        for _ in 0..60_000 {
            counts[generator.below(6) as usize] += 1;
        }
        // Each count is binomial(60 000, 1/6): mean 10 000, standard deviation 91. A window of
        // 500 is more than five standard deviations, and the seed is fixed anyway.
        for count in counts {
            assert!((9_500..=10_500).contains(&count), "{counts:?}");
        }
    }

    #[test]
    fn the_range_of_the_resamples() {
        assert!(Resamples::new(0).is_err());
        assert!(Resamples::new(999).is_err());
        assert_eq!(Resamples::new(1_000).map(Resamples::get), Ok(1_000));
        assert_eq!(Resamples::new(100_000).map(Resamples::get), Ok(100_000));
        assert!(Resamples::new(100_001).is_err());
        assert!(Resamples::new(u32::MAX).is_err());
        assert_eq!(Resamples::DEFAULT.get(), 2_000);
    }

    #[test]
    fn an_empty_side_is_refused() {
        let error = Err(MetricError::NoSamples {
            what: "a comparison of medians",
        });
        assert_eq!(
            median_difference(&[], &[1], Resamples::DEFAULT, Seed::DEFAULT),
            error
        );
        assert_eq!(
            median_difference(&[1], &[], Resamples::DEFAULT, Seed::DEFAULT),
            error
        );
    }

    #[test]
    fn one_sample_on_each_side_gives_the_exact_difference() {
        let interval = compare(&[10], &[7], 29);
        assert_eq!(
            (interval.lower(), interval.point(), interval.upper()),
            (-3, -3, -3)
        );
        let interval = compare(&[0], &[0], 29);
        assert_eq!(
            (interval.lower(), interval.point(), interval.upper()),
            (0, 0, 0)
        );
        let interval = compare(&[i64::MIN], &[-1], 29);
        assert_eq!(interval.point(), i64::MAX);
    }

    #[test]
    fn a_difference_that_does_not_fit_is_refused() {
        let error = Err(MetricError::OutOfRange {
            what: "the difference of two medians",
        });
        assert_eq!(
            median_difference(&[i64::MIN], &[0], Resamples::DEFAULT, Seed::DEFAULT),
            error
        );
        assert_eq!(
            median_difference(&[1], &[i64::MIN], Resamples::DEFAULT, Seed::DEFAULT),
            error
        );
    }

    /// The expected interval comes from `tests/oracle/median_bootstrap_oracle.py`, a separate
    /// implementation of the documented procedure. It pins the generator, the order of the draws
    /// and the ranks.
    #[test]
    fn the_interval_matches_the_independent_script() {
        let before: Vec<i64> = (0..40).map(|i| 1_000 + (i * 37) % 101).collect();
        let after: Vec<i64> = (0..35).map(|i| 980 + (i * 53) % 89).collect();
        let interval = compare(&before, &after, 29);
        assert_eq!(
            (interval.lower(), interval.point(), interval.upper()),
            (ORACLE_LOWER, ORACLE_POINT, ORACLE_UPPER)
        );
        let other_seed = compare(&before, &after, 30);
        assert_eq!(other_seed.point(), ORACLE_POINT);
    }

    const ORACLE_LOWER: i64 = -45;
    const ORACLE_POINT: i64 = -22;
    const ORACLE_UPPER: i64 = -3;

    #[test]
    fn a_clear_shift_is_an_improvement_and_no_shift_is_not() {
        let before: Vec<i64> = (0..40).map(|i| 1_000 + (i * 37) % 101).collect();
        let faster: Vec<i64> = before.iter().map(|value| value - 500).collect();
        let interval = compare(&before, &faster, 29);
        assert_eq!(interval.point(), -500);
        assert_eq!(
            interval.verdict(Direction::LowerIsBetter),
            Verdict::Improvement
        );
        assert_eq!(
            interval.verdict(Direction::HigherIsBetter),
            Verdict::Worsening
        );

        let same = compare(&before, &before, 29);
        assert_eq!(same.point(), 0);
        assert_eq!(
            same.verdict(Direction::LowerIsBetter),
            Verdict::NoClearChange
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 32, .. ProptestConfig::default() })]

        #[test]
        fn the_result_is_reproducible_ordered_and_within_the_samples(
            before in proptest::collection::vec(-1_000_000i64..1_000_000, 1..60),
            after in proptest::collection::vec(-1_000_000i64..1_000_000, 1..60),
            seed in any::<u64>(),
        ) {
            let resamples = Resamples::new(1_000).expect("in range");
            let first = median_difference(&before, &after, resamples, Seed(seed)).expect("valid");
            let second = median_difference(&before, &after, resamples, Seed(seed)).expect("valid");
            prop_assert_eq!(first, second);
            prop_assert!(first.lower() <= first.point() && first.point() <= first.upper());
            // No resampled median can leave the range of its samples.
            let smallest = after.iter().min().unwrap() - before.iter().max().unwrap();
            let largest = after.iter().max().unwrap() - before.iter().min().unwrap();
            prop_assert!(smallest <= first.lower() && first.upper() <= largest);
        }
    }
}
