//! Percentiles by nearest rank over the exact samples.

use super::MetricError;

/// A percentile in hundredths of a percent, from 1 (0.01 percent) to 10 000 (100 percent), so
/// that 2.5 percent is written exactly as 250.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Percentile(u16);

impl Percentile {
    /// The 50th percentile. With an even number of samples it is the lower of the two middle
    /// ones.
    pub const MEDIAN: Self = Self(5_000);
    /// The 90th percentile.
    pub const NINETIETH: Self = Self(9_000);

    /// A percentile from hundredths of a percent. Zero and values above 10 000 are refused: the
    /// nearest rank is not defined for a percentile of zero.
    pub fn from_hundredths(hundredths: u16) -> Result<Self, MetricError> {
        if !(1..=10_000).contains(&hundredths) {
            return Err(MetricError::SettingOutOfRange {
                what: "a percentile in hundredths of a percent",
                minimum: 1,
                maximum: 10_000,
                offered: u64::from(hundredths),
            });
        }
        Ok(Self(hundredths))
    }

    /// The percentile in hundredths of a percent.
    pub const fn hundredths(self) -> u16 {
        self.0
    }

    /// The rank of this percentile among `samples` sorted samples, counting from 1:
    /// `percentile × samples / 100`, rounded up. No samples are refused.
    pub fn rank(self, samples: usize) -> Result<usize, MetricError> {
        if samples == 0 {
            return Err(MetricError::NoSamples {
                what: "a percentile",
            });
        }
        // usize is at most 64 bits and the percentile at most 10 000, so the product fits u128.
        let scaled = (samples as u128) * u128::from(self.0);
        let rank = scaled.div_ceil(10_000);
        // The rank is between 1 and `samples`, so it fits.
        Ok(rank as usize)
    }
}

/// The value at the percentile by nearest rank. The samples may be in any order and are not
/// changed. The result is always one of the samples.
pub fn nearest_rank<T: Ord + Copy>(
    samples: &[T],
    percentile: Percentile,
) -> Result<T, MetricError> {
    let mut scratch = samples.to_vec();
    nearest_rank_in_place(&mut scratch, percentile)
}

/// As [`nearest_rank`], reordering the slice it is given instead of copying it.
pub(super) fn nearest_rank_in_place<T: Ord + Copy>(
    samples: &mut [T],
    percentile: Percentile,
) -> Result<T, MetricError> {
    let rank = percentile.rank(samples.len())?;
    let (_, value, _) = samples.select_nth_unstable(rank - 1);
    Ok(*value)
}

/// The median: the 50th percentile by nearest rank.
pub fn median<T: Ord + Copy>(samples: &[T]) -> Result<T, MetricError> {
    nearest_rank(samples, Percentile::MEDIAN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn percentile(hundredths: u16) -> Percentile {
        Percentile::from_hundredths(hundredths).expect("valid percentile")
    }

    #[test]
    fn the_range_of_a_percentile() {
        assert!(Percentile::from_hundredths(0).is_err());
        assert_eq!(percentile(1).hundredths(), 1);
        assert_eq!(percentile(10_000).hundredths(), 10_000);
        assert!(Percentile::from_hundredths(10_001).is_err());
        assert!(Percentile::from_hundredths(u16::MAX).is_err());
    }

    #[test]
    fn the_rank_rounds_up() {
        assert_eq!(Percentile::MEDIAN.rank(1), Ok(1));
        assert_eq!(Percentile::MEDIAN.rank(2), Ok(1));
        assert_eq!(Percentile::MEDIAN.rank(3), Ok(2));
        assert_eq!(Percentile::MEDIAN.rank(4), Ok(2));
        assert_eq!(Percentile::MEDIAN.rank(5), Ok(3));
        assert_eq!(Percentile::NINETIETH.rank(10), Ok(9));
        assert_eq!(Percentile::NINETIETH.rank(11), Ok(10)); // 9.9 rounds up
        assert_eq!(percentile(250).rank(2000), Ok(50));
        assert_eq!(percentile(9_750).rank(2000), Ok(1950));
        assert_eq!(percentile(1).rank(1), Ok(1));
        assert_eq!(
            percentile(1).rank(usize::MAX),
            Ok(usize::MAX.div_ceil(10_000))
        );
        assert_eq!(percentile(10_000).rank(usize::MAX), Ok(usize::MAX));
    }

    #[test]
    fn no_samples_are_an_error_and_not_zero() {
        assert_eq!(
            median::<u64>(&[]),
            Err(MetricError::NoSamples {
                what: "a percentile"
            })
        );
    }

    #[test]
    fn the_value_is_a_sample_whatever_the_order() {
        // The worked example of the nearest-rank method: 15, 20, 35, 40, 50.
        let samples = [40u64, 15, 50, 20, 35];
        assert_eq!(nearest_rank(&samples, percentile(500)), Ok(15));
        assert_eq!(nearest_rank(&samples, percentile(3_000)), Ok(20));
        assert_eq!(nearest_rank(&samples, percentile(4_000)), Ok(20));
        assert_eq!(nearest_rank(&samples, Percentile::MEDIAN), Ok(35));
        assert_eq!(nearest_rank(&samples, percentile(10_000)), Ok(50));
        assert_eq!(samples, [40, 15, 50, 20, 35]);
        assert_eq!(median(&[7i64]), Ok(7));
        assert_eq!(median(&[2i64, 1]), Ok(1)); // the lower of the two middle ones
        assert_eq!(median(&[-3i64, -1, -2, -4]), Ok(-3));
        assert_eq!(median(&[u64::MAX, 0, u64::MAX]), Ok(u64::MAX));
    }

    proptest! {
        /// The definition: at least `p` percent of the samples are at or below the value, and
        /// fewer than `p` percent are strictly below it.
        #[test]
        fn the_value_meets_the_definition(
            samples in proptest::collection::vec(-1000i64..1000, 1..200),
            hundredths in 1u16..=10_000,
        ) {
            let value = nearest_rank(&samples, percentile(hundredths)).expect("has samples");
            let at_or_below = samples.iter().filter(|s| **s <= value).count() as u128;
            let below = samples.iter().filter(|s| **s < value).count() as u128;
            let needed = samples.len() as u128 * u128::from(hundredths);
            prop_assert!(at_or_below * 10_000 >= needed);
            prop_assert!(below * 10_000 < needed);
        }
    }
}
