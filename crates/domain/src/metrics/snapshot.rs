//! From the facts of a window to a snapshot: every row of the catalogue, and the lines of "What
//! stands out".
//!
//! This is the pure half of the snapshot job. The other half, which reads the facts from the
//! database, hands them in as [`WindowFacts`]. A metric whose facts are stored must be present;
//! a metric whose facts are not stored must be absent, and is shown as "not measured yet".

use std::collections::BTreeMap;

use super::MetricError;
use super::bootstrap::{Resamples, Seed, median_difference};
use super::catalogue::{Facts, Metric, Statistic, Unit};
use super::comparison::{Interval, Verdict};
use super::measurement::{Cell, Measurement, Reading, Row, Window};
use super::percentile::{Percentile, nearest_rank};
use super::proportion::Proportion;
use super::quantity::{MicroUsd, Milliseconds};
use super::wilson::rate_difference;
use crate::values::GitSha;

/// The facts of one metric over one window, before any statistic is taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Samples {
    /// One duration for each thing measured (a job, a stage run).
    Durations(Vec<Milliseconds>),
    /// One count for each thing measured (the tokens of each task).
    Counts(Vec<u64>),
    /// A part out of a whole (the tasks that passed at once, out of all tasks).
    Rate {
        /// The part.
        part: u64,
        /// The whole. It is also the number of samples, and may be zero.
        whole: u64,
    },
    /// A number of things over the window (rework rounds), with the number of samples it was
    /// counted over (jobs).
    Total {
        /// The number of things.
        count: u64,
        /// The number of samples.
        samples: u64,
    },
    /// An amount of money and the number of items it is shared over (merged pull requests).
    Amount {
        /// The whole amount.
        total: MicroUsd,
        /// The number of items. It is also the number of samples, and may be zero.
        items: u64,
    },
}

impl Samples {
    /// Whether this shape of facts is what a metric of `unit` shown as `statistic` needs.
    const fn fits(&self, statistic: Statistic, unit: Unit) -> bool {
        matches!(
            (self, statistic, unit),
            (
                Self::Durations(_),
                Statistic::Median | Statistic::NinetiethPercentile,
                Unit::Milliseconds
            ) | (
                Self::Counts(_),
                Statistic::Median | Statistic::NinetiethPercentile,
                Unit::Count
            ) | (Self::Total { .. }, Statistic::Total, Unit::Count)
                | (Self::Rate { .. }, Statistic::Rate, Unit::Ratio)
                | (
                    Self::Amount { .. },
                    Statistic::AmountPerItem,
                    Unit::MicroUsd
                )
        )
    }

    /// The number of samples.
    pub fn count(&self) -> u64 {
        match self {
            Self::Durations(samples) => samples.len() as u64,
            Self::Counts(samples) => samples.len() as u64,
            Self::Rate { whole, .. } => *whole,
            Self::Total { samples, .. } => *samples,
            Self::Amount { items, .. } => *items,
        }
    }

    /// The value of one statistic. It runs only when there are enough samples, so the lists are
    /// not empty and the denominators are not zero.
    fn reading(&self, statistic: Statistic) -> Result<Reading, MetricError> {
        let percentile = match statistic {
            Statistic::NinetiethPercentile => Percentile::NINETIETH,
            _ => Percentile::MEDIAN,
        };
        Ok(match self {
            Self::Durations(samples) => Reading::Duration(nearest_rank(samples, percentile)?),
            Self::Counts(samples) => Reading::Count(nearest_rank(samples, percentile)?),
            Self::Rate { part, whole } => Reading::Rate(Proportion::new(*part, *whole)?),
            Self::Total { count, .. } => Reading::Count(*count),
            Self::Amount { total, items } => Reading::Money(total.per(*items)?),
        })
    }
}

/// The facts of one window: the samples of every metric whose facts are stored.
pub type WindowFacts = BTreeMap<Metric, Samples>;

/// Whether any metric of `facts` has at least one sample. A week of a repository without one says
/// nothing worth recording.
pub fn has_any_sample(facts: &WindowFacts) -> bool {
    facts.values().any(|samples| samples.count() > 0)
}

/// The settings of the comparison between two windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComparisonSettings {
    /// The number of bootstrap resamples.
    pub resamples: Resamples,
    /// The seed of the bootstrap.
    pub seed: Seed,
}

impl Default for ComparisonSettings {
    fn default() -> Self {
        Self {
            resamples: Resamples::DEFAULT,
            seed: Seed::DEFAULT,
        }
    }
}

/// The cell of one statistic of one metric over one window.
fn cell(metric: Metric, statistic: Statistic, facts: &WindowFacts) -> Result<Cell, MetricError> {
    let definition = metric.definition();
    let refuse = |reason| MetricError::RowDoesNotFit {
        metric: definition.name,
        statistic: statistic.as_str(),
        reason,
    };
    match (definition.facts, facts.get(&metric)) {
        (Facts::NotStored(_), None) => Ok(Cell::NotMeasuredYet),
        (Facts::NotStored(_), Some(_)) => Err(refuse(
            "the facts of the metric are not stored, so none can be handed in",
        )),
        (Facts::Stored, None) => Err(refuse(
            "the facts of the metric are stored, so they must be handed in",
        )),
        (Facts::Stored, Some(samples)) => {
            if !samples.fits(statistic, definition.unit) {
                return Err(refuse("the facts have another shape than the metric needs"));
            }
            let measured = definition
                .minimum_sample
                .measure(samples.count(), || samples.reading(statistic))?;
            Ok(Cell::Measured(measured))
        }
    }
}

/// The difference between two windows of one metric, after minus before, when the design has a
/// method for it and both windows have enough samples: Newcombe's interval for a rate, and the
/// bootstrap of the medians for durations and counts. A total and an amount per item have no
/// interval, so they are never said to stand out.
fn difference(
    metric: Metric,
    before: &Samples,
    after: &Samples,
    settings: ComparisonSettings,
) -> Result<Option<Interval>, MetricError> {
    let minimum = metric.definition().minimum_sample.get();
    if before.count() < minimum || after.count() < minimum {
        return Ok(None);
    }
    let medians = |before: Vec<i64>, after: Vec<i64>| {
        median_difference(&before, &after, settings.resamples, settings.seed).map(Some)
    };
    let signed = |counts: &[u64]| -> Result<Vec<i64>, MetricError> {
        counts
            .iter()
            .map(|count| {
                i64::try_from(*count).map_err(|_| MetricError::OutOfRange {
                    what: "a count in a comparison",
                })
            })
            .collect()
    };
    match (before, after) {
        (Samples::Durations(before), Samples::Durations(after)) => medians(
            before.iter().map(|duration| duration.signed()).collect(),
            after.iter().map(|duration| duration.signed()).collect(),
        ),
        (Samples::Counts(before), Samples::Counts(after)) => {
            medians(signed(before)?, signed(after)?)
        }
        (
            Samples::Rate {
                part: before_part,
                whole: before_whole,
            },
            Samples::Rate {
                part: after_part,
                whole: after_whole,
            },
        ) => rate_difference(
            Proportion::new(*before_part, *before_whole)?,
            Proportion::new(*after_part, *after_whole)?,
        )
        .map(Some),
        _ => Ok(None),
    }
}

/// The line of "What stands out" for a metric whose comparison shows a clear change.
fn stands_out_line(metric: Metric, interval: Interval) -> Option<String> {
    let definition = metric.definition();
    let word = match interval.verdict(definition.better) {
        Verdict::Improvement => "improved",
        Verdict::Worsening => "got worse",
        Verdict::NoClearChange => return None,
    };
    let (unit, of_what) = match definition.unit {
        Unit::Milliseconds => (" ms", "the median changed by"),
        Unit::Ratio => (" millionths", "the rate changed by"),
        Unit::Count => ("", "the median changed by"),
        Unit::MicroUsd => (" micro-USD", "the amount changed by"),
    };
    Some(format!(
        "{} {} {word} against the window before: {of_what} {}{unit} (95 percent interval {} to {}{unit}).",
        definition.identifier(),
        definition.name,
        interval.point(),
        interval.lower(),
        interval.upper(),
    ))
}

/// Builds the snapshot of a window: one row for each statistic of each metric of the catalogue,
/// in the order of the catalogue, and one line of "What stands out" for each metric that shows a
/// clear change against the window before. With no window before, the previous cells say so and
/// nothing stands out.
pub fn snapshot(
    window: Window,
    query_version: u32,
    computed_at_commit: GitSha,
    current: &WindowFacts,
    previous: Option<&WindowFacts>,
    settings: ComparisonSettings,
) -> Result<Measurement, MetricError> {
    let mut rows = Vec::new();
    let mut stands_out = Vec::new();
    for metric in Metric::ALL {
        for statistic in metric.definition().shown_as {
            let now = cell(*metric, *statistic, current)?;
            let before = match previous {
                Some(previous) => cell(*metric, *statistic, previous)?,
                None => Cell::NotAvailable,
            };
            rows.push(Row::new(*metric, *statistic, now, before)?);
        }
        let both = previous
            .and_then(|previous| previous.get(metric))
            .zip(current.get(metric));
        if let Some((before, after)) = both
            && let Some(interval) = difference(*metric, before, after, settings)?
            && let Some(line) = stands_out_line(*metric, interval)
        {
            stands_out.push(line);
        }
    }
    Ok(Measurement {
        window,
        query_version,
        computed_at_commit,
        rows,
        stands_out,
    })
}

#[cfg(test)]
mod tests;
