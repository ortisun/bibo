//! The interval of a difference and the decision it supports.

use super::MetricError;

/// The difference "after minus before" of a metric, with its 95 percent interval. The unit is
/// the caller's: millionths for a rate, milliseconds for a duration, millionths of a dollar for
/// a cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Interval {
    lower: i64,
    point: i64,
    upper: i64,
}

impl Interval {
    /// Builds an interval. The bounds must be in order: `lower <= point <= upper`.
    pub fn new(lower: i64, point: i64, upper: i64) -> Result<Self, MetricError> {
        if lower > point || point > upper {
            return Err(MetricError::IntervalOutOfOrder {
                lower,
                point,
                upper,
            });
        }
        Ok(Self {
            lower,
            point,
            upper,
        })
    }

    /// The lower bound.
    pub const fn lower(self) -> i64 {
        self.lower
    }

    /// The measured difference.
    pub const fn point(self) -> i64 {
        self.point
    }

    /// The upper bound.
    pub const fn upper(self) -> i64 {
        self.upper
    }

    /// The decision: an improvement only when the whole interval lies on the good side of zero,
    /// a worsening only when it lies on the bad side. An interval that touches zero is no clear
    /// change.
    pub fn verdict(self, direction: Direction) -> Verdict {
        let all_below_zero = self.upper < 0;
        let all_above_zero = self.lower > 0;
        match (direction, all_below_zero, all_above_zero) {
            (Direction::LowerIsBetter, true, _) | (Direction::HigherIsBetter, _, true) => {
                Verdict::Improvement
            }
            (Direction::LowerIsBetter, _, true) | (Direction::HigherIsBetter, true, _) => {
                Verdict::Worsening
            }
            _ => Verdict::NoClearChange,
        }
    }
}

/// Which way a metric gets better.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Durations, costs, defects, rejections.
    LowerIsBetter,
    /// Success rates, precision, coverage.
    HigherIsBetter,
}

/// What a before-and-after comparison shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// The whole interval lies on the good side of zero.
    Improvement,
    /// The whole interval lies on the bad side of zero.
    Worsening,
    /// The interval contains or touches zero.
    NoClearChange,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interval(lower: i64, point: i64, upper: i64) -> Interval {
        Interval::new(lower, point, upper).expect("ordered bounds")
    }

    #[test]
    fn bounds_out_of_order_are_refused() {
        assert!(Interval::new(1, 0, 2).is_err());
        assert!(Interval::new(0, 3, 2).is_err());
        assert!(Interval::new(2, 1, 0).is_err());
        assert_eq!(interval(0, 0, 0).point(), 0);
        let widest = interval(i64::MIN, 0, i64::MAX);
        assert_eq!((widest.lower(), widest.upper()), (i64::MIN, i64::MAX));
    }

    #[test]
    fn only_an_interval_clear_of_zero_decides() {
        use Direction::{HigherIsBetter, LowerIsBetter};
        use Verdict::{Improvement, NoClearChange, Worsening};

        let cases = [
            (interval(-9, -5, -1), Improvement, Worsening),
            (interval(1, 5, 9), Worsening, Improvement),
            (interval(-9, -5, 0), NoClearChange, NoClearChange), // touches zero
            (interval(0, 5, 9), NoClearChange, NoClearChange),   // touches zero
            (interval(-1, 0, 1), NoClearChange, NoClearChange),
            (interval(0, 0, 0), NoClearChange, NoClearChange),
            (interval(i64::MIN, i64::MIN, -1), Improvement, Worsening),
            (interval(1, i64::MAX, i64::MAX), Worsening, Improvement),
        ];
        for (interval, when_lower_is_better, when_higher_is_better) in cases {
            assert_eq!(
                interval.verdict(LowerIsBetter),
                when_lower_is_better,
                "{interval:?}"
            );
            assert_eq!(
                interval.verdict(HigherIsBetter),
                when_higher_is_better,
                "{interval:?}"
            );
        }
    }
}
