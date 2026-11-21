//! A snapshot of the process numbers over one window, and the `measurement` entry of the
//! knowledge base rendered from it.
//!
//! The rules are those of the section "A measurement entry" of
//! `docs/architecture/process-metrics-and-improvement.md`. This module computes nothing from the
//! database: it receives the numbers, checks that each one fits its metric, and writes the text.

use std::fmt::{self, Write as _};

use super::MetricError;
use super::catalogue::{Facts, Metric, Statistic, Unit};
use super::proportion::Proportion;
use super::quantity::{MicroUsd, Milliseconds};
use super::rounding::divide_half_even;
use super::sample::Measured;
use crate::knowledge::yaml_quoted;
use crate::values::{GitSha, Timestamp};

/// Seven days in seconds.
const WEEK_SECONDS: i64 = 7 * 24 * 60 * 60;

/// The time a snapshot covers: from `from`, up to but not including `to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Window {
    from: Timestamp,
    to: Timestamp,
}

impl Window {
    /// A window. `to` must be after `from`.
    pub fn new(from: Timestamp, to: Timestamp) -> Result<Self, MetricError> {
        if to <= from {
            return Err(MetricError::WindowOutOfOrder);
        }
        Ok(Self { from, to })
    }

    /// The first instant of the window.
    pub const fn from(&self) -> Timestamp {
        self.from
    }

    /// The first instant after the window.
    pub const fn to(&self) -> Timestamp {
        self.to
    }

    /// The ISO 8601 year and week, when the window is exactly seven days from a Monday at
    /// 00:00 UTC. The week belongs to the year that holds its Thursday.
    pub fn iso_week(&self) -> Option<(i32, u8)> {
        let start = self.from.to_utc();
        let starts_at_midnight = self.from == self.from.start_of_utc_day();
        let is_a_week = self.to.unix_seconds() - self.from.unix_seconds() == WEEK_SECONDS
            && self.to.subsecond_nanos() == self.from.subsecond_nanos();
        let (year, week, weekday) = start.date().to_iso_week_date();
        (starts_at_midnight && is_a_week && weekday == time::Weekday::Monday)
            .then_some((year, week))
    }

    /// The identifier of the snapshot: `M-2026-W47` for a week, and
    /// `M-2026-11-16-to-2026-12-16` for any other window.
    pub fn identifier(&self) -> String {
        match self.iso_week() {
            Some((year, week)) => format!("M-{year:04}-W{week:02}"),
            None => format!("M-{}-to-{}", date_text(self.from), date_text(self.to)),
        }
    }

    /// The title of the snapshot.
    pub fn title(&self) -> String {
        match self.iso_week() {
            Some((year, week)) => format!("Process numbers, week {week} of {year}"),
            None => {
                format!(
                    "Process numbers, {} to {}",
                    date_text(self.from),
                    date_text(self.to)
                )
            }
        }
    }
}

/// The UTC date of an instant as `2026-11-16`.
fn date_text(instant: Timestamp) -> String {
    let date = instant.to_utc().date();
    format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    )
}

/// One value of a snapshot, with its unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reading {
    /// A duration.
    Duration(Milliseconds),
    /// A rate.
    Rate(Proportion),
    /// An amount of money.
    Money(MicroUsd),
    /// A number of things.
    Count(u64),
}

impl Reading {
    /// Whether this kind of value is what `statistic` of a metric of `unit` produces.
    const fn fits(&self, statistic: Statistic, unit: Unit) -> bool {
        matches!(
            (self, statistic, unit),
            (
                Self::Duration(_),
                Statistic::Median | Statistic::NinetiethPercentile,
                Unit::Milliseconds
            ) | (
                Self::Count(_),
                Statistic::Median | Statistic::NinetiethPercentile,
                Unit::Count
            ) | (Self::Count(_), Statistic::Total, Unit::Count)
                | (Self::Rate(_), Statistic::Rate, Unit::Ratio)
                | (Self::Money(_), Statistic::AmountPerItem, Unit::MicroUsd)
        )
    }
}

/// Shows the value as the design says: `41 min 12 s`, `60.9 % (14 of 23)`, `0.84 USD`, `7`.
impl fmt::Display for Reading {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duration(duration) => f.write_str(&duration_text(*duration)),
            Self::Rate(rate) => rate.fmt(f),
            Self::Money(amount) => amount.fmt(f),
            Self::Count(count) => count.fmt(f),
        }
    }
}

/// A duration for a person: `850 ms` below one second, `12.345 s` below one minute, and above
/// that hours, minutes and whole seconds, the seconds rounded half to even.
pub fn duration_text(duration: Milliseconds) -> String {
    let milliseconds = duration.get();
    if milliseconds < 1_000 {
        return format!("{milliseconds} ms");
    }
    if milliseconds < 60_000 {
        return format!("{}.{:03} s", milliseconds / 1_000, milliseconds % 1_000);
    }
    let seconds = divide_half_even(i128::from(milliseconds), 1_000, "a duration in seconds")
        .expect("the divisor is positive");
    let (hours, minutes, seconds) = (seconds / 3_600, seconds / 60 % 60, seconds % 60);
    if hours > 0 {
        format!("{hours} h {minutes} min {seconds} s")
    } else {
        format!("{minutes} min {seconds} s")
    }
}

/// What a snapshot shows in one cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cell {
    /// A value, or "too few samples", with the number of samples.
    Measured(Measured<Reading>),
    /// The facts of the metric are not stored yet.
    NotMeasuredYet,
    /// There is no window before this one.
    NotAvailable,
}

impl Cell {
    fn value_text(&self) -> String {
        match self {
            Self::Measured(Measured::Value { value, .. }) => value.to_string(),
            Self::Measured(Measured::TooFewSamples { .. }) => "too few samples".to_owned(),
            Self::NotMeasuredYet => "not measured yet".to_owned(),
            Self::NotAvailable => "n/a".to_owned(),
        }
    }

    fn samples_text(&self) -> String {
        match self {
            Self::Measured(measured) => measured.samples().to_string(),
            Self::NotMeasuredYet | Self::NotAvailable => String::new(),
        }
    }

    fn reading(&self) -> Option<&Reading> {
        match self {
            Self::Measured(measured) => measured.value(),
            Self::NotMeasuredYet | Self::NotAvailable => None,
        }
    }
}

/// One row of a snapshot: one statistic of one metric, now and in the window before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Row {
    metric: Metric,
    statistic: Statistic,
    current: Cell,
    previous: Cell,
}

impl Row {
    /// A row. It is refused when the metric does not show that statistic, when a value has the
    /// wrong unit, when a metric whose facts are not stored carries a value, or when the current
    /// cell says there is no window.
    pub fn new(
        metric: Metric,
        statistic: Statistic,
        current: Cell,
        previous: Cell,
    ) -> Result<Self, MetricError> {
        let definition = metric.definition();
        let refuse = |reason: &'static str| MetricError::RowDoesNotFit {
            metric: definition.name,
            statistic: statistic.as_str(),
            reason,
        };
        if !definition.shown_as.contains(&statistic) {
            return Err(refuse(
                "the catalogue does not show this statistic for the metric",
            ));
        }
        if current == Cell::NotAvailable {
            return Err(refuse("the current window always exists"));
        }
        for cell in [&current, &previous] {
            if let Some(reading) = cell.reading()
                && !reading.fits(statistic, definition.unit)
            {
                return Err(refuse("the value has another unit than the metric"));
            }
            let stored = definition.facts == Facts::Stored;
            match cell {
                Cell::Measured(_) if !stored => {
                    return Err(refuse(
                        "the facts of the metric are not stored, so it has no value",
                    ));
                }
                Cell::NotMeasuredYet if stored => {
                    return Err(refuse(
                        "the facts of the metric are stored, so it is measured",
                    ));
                }
                _ => {}
            }
        }
        Ok(Self {
            metric,
            statistic,
            current,
            previous,
        })
    }

    /// The metric of the row.
    pub const fn metric(&self) -> Metric {
        self.metric
    }

    /// The statistic of the row.
    pub const fn statistic(&self) -> Statistic {
        self.statistic
    }

    /// The cell of this window.
    pub const fn current(&self) -> Cell {
        self.current
    }

    /// The cell of the window before.
    pub const fn previous(&self) -> Cell {
        self.previous
    }

    /// The first cell of the row: the identifier and the name, and the statistic when the metric
    /// shows more than one.
    fn label(&self) -> String {
        let definition = self.metric.definition();
        let mut label = format!("{} {}", definition.identifier(), definition.name);
        if definition.shown_as.len() > 1 {
            let _ = write!(label, ", {}", self.statistic.as_str());
        }
        label
    }
}

/// A snapshot: the numbers of one window, with what is needed to compute them again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement {
    /// The time the numbers cover.
    pub window: Window,
    /// The version of the queries that read the facts. It goes up whenever a query changes.
    pub query_version: u32,
    /// The commit of the factory that computed the numbers.
    pub computed_at_commit: GitSha,
    /// The rows, in the order they are shown.
    pub rows: Vec<Row>,
    /// The lines of "What stands out". The snapshot job writes them from the comparisons. Each
    /// is one line of plain text.
    pub stands_out: Vec<String>,
}

impl Measurement {
    /// The file of the entry in a knowledge base: `measurements/M-2026-W47.md`, under
    /// `docs/knowledge/`.
    pub fn entry_path(&self) -> String {
        format!("measurements/{}.md", self.window.identifier())
    }

    /// The `measurement` entry, as Markdown with a front matter block. A line of "What stands
    /// out" that holds a line break is refused: one line cannot start a new block of the entry.
    pub fn render_entry(&self) -> Result<String, MetricError> {
        if self
            .stands_out
            .iter()
            .any(|line| line.contains(['\n', '\r']) || line.trim().is_empty())
        {
            return Err(MetricError::TextIsNotOneLine {
                what: "a line of \"What stands out\"",
            });
        }
        let mut entry = String::new();
        // Writing to a `String` cannot fail.
        let _ = write!(
            entry,
            "---\n\
             id: {id}\n\
             kind: measurement\n\
             title: {title}\n\
             window: {{ from: {from}, to: {to} }}\n\
             query_version: {query_version}\n\
             computed_at_commit: {commit}\n\
             ---\n\
             \n\
             | Metric | Value | Samples | Previous |\n\
             |---|---|---|---|\n",
            id = self.window.identifier(),
            title = self.window.title(),
            from = yaml_quoted(&self.window.from.as_text()),
            to = yaml_quoted(&self.window.to.as_text()),
            query_version = self.query_version,
            commit = yaml_quoted(self.computed_at_commit.as_str()),
        );
        for row in &self.rows {
            let cells = [
                row.label(),
                row.current.value_text(),
                row.current.samples_text(),
                row.previous.value_text(),
            ];
            for cell in cells {
                // An empty cell is written as `| |`, with one space.
                entry.push_str(if cell.is_empty() { "|" } else { "| " });
                entry.push_str(&cell);
                entry.push(' ');
            }
            entry.push_str("|\n");
        }
        entry.push_str("\n## What stands out\n\n");
        if self.stands_out.is_empty() {
            entry.push_str("Nothing: no comparison of this window shows a clear change.\n");
        }
        for line in &self.stands_out {
            let _ = writeln!(entry, "- {}", line.trim());
        }
        Ok(entry)
    }
}

#[cfg(test)]
mod tests;
