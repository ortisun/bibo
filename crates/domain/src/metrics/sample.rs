//! The rule that a metric with too few samples has no value.

use super::MetricError;

/// The smallest number of samples from which a metric is shown as a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MinimumSample(u64);

impl MinimumSample {
    /// The minimum of a metric whose definition states none: 20 samples.
    pub const DEFAULT: Self = Self(20);

    /// A minimum of at least one sample. Zero is refused: a metric of no samples has no value.
    pub fn new(minimum: u64) -> Result<Self, MetricError> {
        if minimum == 0 {
            return Err(MetricError::SettingOutOfRange {
                what: "a minimum number of samples",
                minimum: 1,
                maximum: u64::MAX,
                offered: 0,
            });
        }
        Ok(Self(minimum))
    }

    /// The minimum.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Runs `compute` only when there are enough samples, and says "too few samples" otherwise.
    /// With too few samples the calculation does not run at all, so no number can leak out.
    pub fn measure<T>(
        self,
        samples: u64,
        compute: impl FnOnce() -> Result<T, MetricError>,
    ) -> Result<Measured<T>, MetricError> {
        if samples < self.0 {
            return Ok(Measured::TooFewSamples {
                samples,
                minimum: self.0,
            });
        }
        Ok(Measured::Value {
            value: compute()?,
            samples,
        })
    }
}

impl Default for MinimumSample {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The result of a metric: a value with the number of samples behind it, or "too few samples".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Measured<T> {
    /// There were enough samples.
    Value {
        /// The computed value.
        value: T,
        /// The number of samples it was computed from.
        samples: u64,
    },
    /// There were fewer samples than the metric's minimum. It is never shown as a number.
    TooFewSamples {
        /// The number of samples that were there.
        samples: u64,
        /// The minimum the metric needs.
        minimum: u64,
    },
}

impl<T> Measured<T> {
    /// The value, when there were enough samples.
    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Value { value, .. } => Some(value),
            Self::TooFewSamples { .. } => None,
        }
    }

    /// The number of samples that were there, in both cases.
    pub fn samples(&self) -> u64 {
        match self {
            Self::Value { samples, .. } | Self::TooFewSamples { samples, .. } => *samples,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_minimum_is_twenty() {
        assert_eq!(MinimumSample::default().get(), 20);
        assert!(MinimumSample::new(0).is_err());
        assert_eq!(MinimumSample::new(1).map(MinimumSample::get), Ok(1));
        assert_eq!(
            MinimumSample::new(u64::MAX).map(MinimumSample::get),
            Ok(u64::MAX)
        );
    }

    #[test]
    fn nineteen_samples_are_too_few_and_twenty_are_enough() {
        let minimum = MinimumSample::DEFAULT;
        let too_few = minimum.measure::<u64>(19, || panic!("must not be computed"));
        assert_eq!(
            too_few,
            Ok(Measured::TooFewSamples {
                samples: 19,
                minimum: 20
            })
        );
        assert_eq!(too_few.as_ref().map(Measured::value), Ok(None));
        assert_eq!(too_few.as_ref().map(Measured::samples), Ok(19));

        let enough = minimum.measure(20, || Ok(7u64));
        assert_eq!(
            enough,
            Ok(Measured::Value {
                value: 7,
                samples: 20
            })
        );
        assert_eq!(enough.as_ref().map(Measured::value), Ok(Some(&7)));

        let none = minimum.measure::<u64>(0, || panic!("must not be computed"));
        assert_eq!(
            none,
            Ok(Measured::TooFewSamples {
                samples: 0,
                minimum: 20
            })
        );
    }

    #[test]
    fn an_error_of_the_calculation_is_passed_on() {
        let error = MetricError::NoSamples {
            what: "a percentile",
        };
        let result = MinimumSample::DEFAULT.measure::<u64>(u64::MAX, || Err(error.clone()));
        assert_eq!(result, Err(error));
    }
}
