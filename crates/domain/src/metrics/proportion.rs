//! A rate kept as two counts and divided only for display.

use std::fmt;

use super::MetricError;
use super::rounding::divide_half_even;

/// A rate: `numerator` things out of `denominator`. The numerator is never above the denominator
/// and the denominator is never zero, so the rate is always between 0 and 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Proportion {
    numerator: u64,
    denominator: u64,
}

impl Proportion {
    /// Builds a rate. A denominator of zero and a numerator above the denominator are refused.
    pub fn new(numerator: u64, denominator: u64) -> Result<Self, MetricError> {
        if denominator == 0 {
            return Err(MetricError::DenominatorNotPositive { what: "a rate" });
        }
        if numerator > denominator {
            return Err(MetricError::PartExceedsWhole {
                numerator,
                denominator,
            });
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }

    /// The part.
    pub const fn numerator(self) -> u64 {
        self.numerator
    }

    /// The whole.
    pub const fn denominator(self) -> u64 {
        self.denominator
    }

    /// The rate in tenths of a percent, from 0 to 1000, rounded half to even. 14 of 23 is 609.
    pub fn percent_tenths(self) -> u16 {
        let tenths = divide_half_even(
            i128::from(self.numerator) * 1000,
            i128::from(self.denominator),
            "a rate in tenths of a percent",
        )
        .expect("the denominator of a rate is positive");
        u16::try_from(tenths).expect("a rate is at most 1000 tenths of a percent")
    }
}

/// Shows the rate as the design does: `60.9 % (14 of 23)`.
impl fmt::Display for Proportion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tenths = self.percent_tenths();
        write!(
            f,
            "{}.{} % ({} of {})",
            tenths / 10,
            tenths % 10,
            self.numerator,
            self.denominator
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn rate(numerator: u64, denominator: u64) -> Proportion {
        Proportion::new(numerator, denominator).expect("valid rate")
    }

    #[test]
    fn the_examples_of_the_design_document() {
        assert_eq!(rate(14, 23).to_string(), "60.9 % (14 of 23)");
        assert_eq!(rate(11, 21).to_string(), "52.4 % (11 of 21)");
        assert_eq!(rate(1, 2000).to_string(), "0.0 % (1 of 2000)"); // 0.05 %, tie, even
        assert_eq!(rate(3, 2000).to_string(), "0.2 % (3 of 2000)"); // 0.15 %, tie, even
    }

    #[test]
    fn zero_one_and_the_maximum() {
        assert_eq!(rate(0, 1).percent_tenths(), 0);
        assert_eq!(rate(1, 1).percent_tenths(), 1000);
        assert_eq!(rate(0, u64::MAX).percent_tenths(), 0);
        assert_eq!(rate(u64::MAX, u64::MAX).percent_tenths(), 1000);
        assert_eq!(rate(u64::MAX - 1, u64::MAX).percent_tenths(), 1000);
        assert_eq!(rate(1, u64::MAX).percent_tenths(), 0);
        assert_eq!(rate(1, 3).percent_tenths(), 333);
        assert_eq!(rate(2, 3).percent_tenths(), 667);
    }

    #[test]
    fn an_impossible_rate_is_refused() {
        assert_eq!(
            Proportion::new(0, 0),
            Err(MetricError::DenominatorNotPositive { what: "a rate" })
        );
        assert_eq!(
            Proportion::new(2, 1),
            Err(MetricError::PartExceedsWhole {
                numerator: 2,
                denominator: 1
            })
        );
    }

    proptest! {
        #[test]
        fn the_display_never_leaves_zero_to_a_hundred_percent(
            denominator in 1u64..=u64::MAX,
            share in 0u64..=1_000_000,
        ) {
            let numerator = ((u128::from(denominator) * u128::from(share)) / 1_000_000) as u64;
            let tenths = rate(numerator, denominator).percent_tenths();
            prop_assert!(tenths <= 1000);
            // Within half a tenth of a percent of the exact rate.
            let exact_error = (i128::from(numerator) * 1000
                - i128::from(tenths) * i128::from(denominator))
            .abs();
            prop_assert!(2 * exact_error <= i128::from(denominator));
        }
    }
}
