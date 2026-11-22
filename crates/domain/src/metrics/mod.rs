//! The exact arithmetic of the process metrics (ADR 0029, Decision 2).
//!
//! The contract of this module is the section "How each number is computed" of
//! `docs/architecture/process-metrics-and-improvement.md`. Every rule there is a function here:
//!
//! | Rule of the document | Where |
//! |---|---|
//! | Units and sums | [`Milliseconds`], [`MicroUsd`] |
//! | Division and rounding | [`divide_half_even`] |
//! | Rates | [`Proportion`] |
//! | Percentiles and the median | [`Percentile`], [`nearest_rank`], [`median`] |
//! | Too few samples | [`MinimumSample`], [`Measured`] |
//! | Comparing a rate before and after | [`wilson_interval`], [`rate_difference`] |
//! | Comparing a duration or a cost before and after | [`median_difference`] |
//! | The decision | [`Interval::verdict`], [`Direction`], [`Verdict`] |
//! | The metric catalogue and the `metric` entry | [`Metric`], [`MetricDefinition`] |
//! | The `measurement` entry | [`Measurement`], [`Window`], [`Row`] |
//! | From the facts of a window to a snapshot | [`snapshot`], [`Samples`], [`WindowFacts`] |
//! | The weekly measurement pull request: the week, the decision, the text | [`last_whole_week`], [`decide_weekly`], [`weekly_pull_request_text`] |
//! | Experiments and the `improvement` entry | [`Experiment`], [`Setting`], [`Improvement`] |
//!
//! No function uses floating point. A result that does not fit its type or its valid range is a
//! [`MetricError`], never a wrapped or a saturated number. Nothing here reads the clock, a file or
//! the database: the bootstrap draws from a generator this module defines, started from a seed the
//! caller passes, so the same input always gives the same output.

mod bootstrap;
mod catalogue;
mod comparison;
mod experiment;
mod measurement;
mod percentile;
mod proportion;
mod quantity;
mod rounding;
mod sample;
mod snapshot;
mod weekly;
mod wilson;

pub use bootstrap::{Resamples, Seed, median_difference};
pub use catalogue::{Facts, Group, Metric, MetricDefinition, Statistic, Unit};
pub use comparison::{Direction, Interval, Verdict};
pub use experiment::{
    Change, Comparison, DiscardReason, Experiment, Improvement, Outcome, PromotionDecision,
    RollbackDecision, SafeRange, Setting, SettingKind, Share, Tier, Windows,
};
pub use measurement::{Cell, Measurement, Reading, Row, Window, duration_text};
pub use percentile::{Percentile, median, nearest_rank};
pub use proportion::Proportion;
pub use quantity::{MicroUsd, Milliseconds};
pub use rounding::divide_half_even;
pub use sample::{Measured, MinimumSample};
pub use snapshot::{ComparisonSettings, Samples, WindowFacts, has_any_sample, snapshot};
pub use weekly::{
    LatestMeasurement, NothingBecause as WeeklyNothingBecause, ProposalState, WeeklyDecision,
    decide as decide_weekly, last_whole_week, pull_request_text as weekly_pull_request_text,
};
pub use wilson::{MAXIMUM_RATE_SAMPLE, MILLIONTHS, RateInterval, rate_difference, wilson_interval};

/// Why a metric could not be computed. Each message names the rule that was broken.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetricError {
    /// A sum, a difference or a product left the range of its type or its valid range.
    #[error("{what} is outside its valid range; the calculation is refused instead of wrapping")]
    OutOfRange {
        /// The quantity that left its range.
        what: &'static str,
    },
    /// A division had a denominator of zero or below.
    #[error("{what} cannot be divided by a denominator that is not positive")]
    DenominatorNotPositive {
        /// The quantity that was to be divided.
        what: &'static str,
    },
    /// A rate had a numerator above its denominator.
    #[error(
        "a rate of {numerator} out of {denominator} is not possible: the part exceeds the whole"
    )]
    PartExceedsWhole {
        /// The offered numerator.
        numerator: u64,
        /// The offered denominator.
        denominator: u64,
    },
    /// A statistic was asked of an empty set of samples.
    #[error("{what} needs at least one sample")]
    NoSamples {
        /// The statistic that was asked for.
        what: &'static str,
    },
    /// A setting of a calculation was outside the range the design allows.
    #[error("{what} must be between {minimum} and {maximum}, and {offered} was offered")]
    SettingOutOfRange {
        /// The setting.
        what: &'static str,
        /// The smallest allowed value.
        minimum: u64,
        /// The largest allowed value.
        maximum: u64,
        /// The offered value.
        offered: u64,
    },
    /// An experiment, or the comparisons given to it, broke a rule of the design.
    #[error("the experiment is refused: {reason}")]
    ExperimentRefused {
        /// The rule that was broken.
        reason: &'static str,
    },
    /// A window ended at or before its start.
    #[error("a window needs its end after its start")]
    WindowOutOfOrder,
    /// A row of a snapshot does not fit the catalogue.
    #[error("{statistic} of {metric} cannot be a row of a snapshot: {reason}")]
    RowDoesNotFit {
        /// The name of the metric.
        metric: &'static str,
        /// The statistic of the row.
        statistic: &'static str,
        /// The rule that was broken.
        reason: &'static str,
    },
    /// A text that must be one line of an entry was empty or held a line break.
    #[error("{what} must be one line of text that is not empty")]
    TextIsNotOneLine {
        /// The text.
        what: &'static str,
    },
    /// An interval was built with its bounds out of order.
    #[error(
        "an interval needs lower <= point <= upper, and {lower}, {point}, {upper} were offered"
    )]
    IntervalOutOfOrder {
        /// The offered lower bound.
        lower: i64,
        /// The offered point value.
        point: i64,
        /// The offered upper bound.
        upper: i64,
    },
}
