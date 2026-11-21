//! The metric catalogue: one typed definition for each metric of the design document, and the
//! `metric` entry of the knowledge base rendered from it.
//!
//! The table "Identifiers, direction and where the facts come from" of
//! `docs/architecture/process-metrics-and-improvement.md` holds the same rows, and a test of this
//! file compares the two, so the document and the code cannot drift apart.

use std::fmt::Write as _;

use super::comparison::Direction;
use super::sample::MinimumSample;

/// The part of the process a metric describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Group {
    /// How long things take.
    Speed,
    /// How often the work is right.
    Quality,
    /// What the work costs.
    Cost,
    /// How well the knowledge base covers the project and is used.
    Knowledge,
    /// The project's own delivery pipeline, read only.
    Delivery,
}

impl Group {
    /// The name used in a `metric` entry.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Speed => "speed",
            Self::Quality => "quality",
            Self::Cost => "cost",
            Self::Knowledge => "knowledge",
            Self::Delivery => "delivery",
        }
    }
}

/// The unit of a metric's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unit {
    /// Whole milliseconds.
    Milliseconds,
    /// A rate kept as two counts.
    Ratio,
    /// A number of things.
    Count,
    /// Millionths of a United States dollar.
    MicroUsd,
}

impl Unit {
    /// The name used in the design document and in a `metric` entry.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Milliseconds => "ms",
            Self::Ratio => "ratio",
            Self::Count => "count",
            Self::MicroUsd => "micro-USD",
        }
    }

    /// How a value of this unit is computed and rounded, for the `metric` entry.
    const fn computation(self) -> &'static str {
        match self {
            Self::Milliseconds => {
                "Durations are whole milliseconds. A percentile is taken by nearest rank over the \
                 exact samples of the window, so it is always one of the samples."
            }
            Self::Ratio => {
                "The rate is kept as a numerator and a denominator. It is divided only for \
                 display, as a percentage with one decimal place, rounded half to even."
            }
            Self::Count => "The value is a whole number of things counted in the window.",
            Self::MicroUsd => {
                "Money is whole millionths of a United States dollar. A division rounds half to \
                 even to a whole millionth, and the display rounds half to even to a cent."
            }
        }
    }
}

/// One number a snapshot shows for a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Statistic {
    /// The 50th percentile by nearest rank.
    Median,
    /// The 90th percentile by nearest rank.
    NinetiethPercentile,
    /// A part out of a whole.
    Rate,
    /// A count over the window.
    Total,
    /// An amount of money shared over a number of items.
    AmountPerItem,
}

impl Statistic {
    /// The name used in the design document, in a `metric` entry and in a snapshot row.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Median => "median",
            Self::NinetiethPercentile => "90th percentile",
            Self::Rate => "rate",
            Self::Total => "total",
            Self::AmountPerItem => "amount per item",
        }
    }

    /// Whether a metric of `unit` can be shown as this statistic.
    pub const fn fits(self, unit: Unit) -> bool {
        matches!(
            (self, unit),
            (
                Self::Median | Self::NinetiethPercentile,
                Unit::Milliseconds | Unit::Count
            ) | (Self::Rate, Unit::Ratio)
                | (Self::Total, Unit::Count)
                | (Self::AmountPerItem, Unit::MicroUsd)
        )
    }
}

/// Whether the facts a metric needs are stored today.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Facts {
    /// The database or the evidence ledger already holds them.
    Stored,
    /// They are not stored. The text says what is missing. A snapshot shows such a metric as
    /// "not measured yet", never as zero.
    NotStored(&'static str),
}

/// The definition of one metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricDefinition {
    /// The number of the identifier: 1 for `MT-0001`. Never reused.
    pub number: u16,
    /// The short name, in lowercase words joined by hyphens.
    pub name: &'static str,
    /// The title a person reads.
    pub title: &'static str,
    /// The part of the process it describes.
    pub group: Group,
    /// The unit of its value.
    pub unit: Unit,
    /// The direction in which it gets better.
    pub better: Direction,
    /// The statistics a snapshot shows, in order.
    pub shown_as: &'static [Statistic],
    /// What is counted and how, in one sentence.
    pub formula: &'static str,
    /// The dimensions a snapshot may cut it by.
    pub cut_by: &'static [&'static str],
    /// The fewest samples from which it is shown as a number.
    pub minimum_sample: MinimumSample,
    /// Whether its facts are stored today.
    pub facts: Facts,
}

impl MetricDefinition {
    /// The identifier, for example `MT-0001`.
    pub fn identifier(&self) -> String {
        format!("MT-{:04}", self.number)
    }

    /// The file of its entry in a knowledge base: `metrics/MT-0001-lead-time-to-pull-request.md`,
    /// under `docs/knowledge/`.
    pub fn entry_path(&self) -> String {
        format!("metrics/{}-{}.md", self.identifier(), self.name)
    }

    /// The `metric` entry of the knowledge base, as Markdown with a front matter block. Every
    /// text in it comes from this catalogue, which is written by people in this repository.
    pub fn render_entry(&self) -> String {
        let better = match self.better {
            Direction::LowerIsBetter => "lower",
            Direction::HigherIsBetter => "higher",
        };
        let shown_as: Vec<&str> = self
            .shown_as
            .iter()
            .map(|statistic| statistic.as_str())
            .collect();
        let mut entry = String::new();
        // Writing to a `String` cannot fail.
        let _ = write!(
            entry,
            "---\n\
             id: {id}\n\
             kind: metric\n\
             title: {title}\n\
             status: active\n\
             group: {group}\n\
             unit: {unit}\n\
             better: {better}\n\
             shown_as: [{shown_as}]\n\
             minimum_sample: {minimum}\n\
             cut_by: [{cut_by}]\n\
             ---\n\
             \n\
             ## What is counted\n\
             \n\
             {formula}\n\
             \n\
             ## How it is computed\n\
             \n\
             {computation} With fewer than {minimum} samples the value is \"too few samples\", \
             never a number.\n\
             \n\
             ## Where the facts come from\n\
             \n\
             {facts}\n",
            id = self.identifier(),
            title = self.title,
            group = self.group.as_str(),
            unit = self.unit.as_str(),
            shown_as = shown_as.join(", "),
            minimum = self.minimum_sample.get(),
            cut_by = self.cut_by.join(", "),
            formula = self.formula,
            computation = self.unit.computation(),
            facts = match self.facts {
                Facts::Stored => {
                    "The factory's database and evidence ledger. Every snapshot names the query \
                     version and the window, so the number can be computed again."
                        .to_owned()
                }
                Facts::NotStored(missing) => format!("Not measured yet: it {missing}."),
            },
        );
        entry
    }
}

macro_rules! catalogue {
    ($(
        $variant:ident = $number:literal, $name:literal, $title:literal, $group:ident, $unit:ident,
        $better:ident, [$($statistic:ident),+], [$($cut:literal),*], $facts:expr, $formula:literal;
    )+) => {
        /// Every metric of the catalogue. The order is the order of the identifiers.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Metric {
            $(
                #[doc = $title]
                $variant,
            )+
        }

        impl Metric {
            /// Every metric, in the order of the identifiers.
            pub const ALL: &'static [Metric] = &[$(Metric::$variant),+];

            /// The definition of the metric.
            pub const fn definition(self) -> &'static MetricDefinition {
                match self {
                    $(
                        Metric::$variant => &MetricDefinition {
                            number: $number,
                            name: $name,
                            title: $title,
                            group: Group::$group,
                            unit: Unit::$unit,
                            better: Direction::$better,
                            shown_as: &[$(Statistic::$statistic),+],
                            formula: $formula,
                            cut_by: &[$($cut),*],
                            minimum_sample: MinimumSample::DEFAULT,
                            facts: $facts,
                        },
                    )+
                }
            }
        }
    };
}

const NEEDS_TEST_TIMES: Facts = Facts::NotStored("needs test results with times");
const NEEDS_KNOWLEDGE_BASE: Facts = Facts::NotStored("needs the knowledge base (ADR 0028)");
const NEEDS_PULL_REQUEST_FATE: Facts =
    Facts::NotStored("needs the fate of each pull request (merged or closed)");
const NEEDS_PIPELINE: Facts = Facts::NotStored("is read from the project's pipeline");

catalogue! {
    LeadTimeToPullRequest = 1, "lead-time-to-pull-request", "Lead time to pull request", Speed, Milliseconds,
        LowerIsBetter, [Median, NinetiethPercentile], ["project", "pack", "risk tier"], Facts::Stored,
        "The time from the moment a job is accepted to the end of the delivery stage run that opened its pull request, for each job.";
    StageDuration = 2, "stage-duration", "Stage duration", Speed, Milliseconds,
        LowerIsBetter, [Median, NinetiethPercentile], ["stage", "outcome"], Facts::Stored,
        "The time from the start of a stage run to its end.";
    HumanWaitTime = 3, "human-wait-time", "Human wait time", Speed, Milliseconds,
        LowerIsBetter, [Median, NinetiethPercentile], ["project", "reason"], Facts::Stored,
        "The sum of the time a job waited for a person: for an answer, a decision or an approval.";
    TimeToFirstFailingTest = 4, "time-to-first-failing-test", "Time to first failing test", Speed, Milliseconds,
        LowerIsBetter, [Median], ["project"], NEEDS_TEST_TIMES,
        "The time from the start of a verify run to its first failing test result.";
    TestRunTime = 5, "test-run-time", "Test run time", Speed, Milliseconds,
        LowerIsBetter, [Median, NinetiethPercentile], ["project"], NEEDS_TEST_TIMES,
        "The duration of a verify run, and the share of it spent in the slowest 10 tests.";
    FirstPassGateSuccess = 6, "first-pass-gate-success", "First-pass gate success", Quality, Ratio,
        HigherIsBetter, [Rate], ["agent", "pack", "model"], Facts::Stored,
        "The tasks whose first attempt passed every gate, out of all tasks.";
    ReworkRounds = 7, "rework-rounds", "Rework rounds", Quality, Count,
        LowerIsBetter, [Total], ["phase", "agent"], Facts::Stored,
        "The rework rounds of each phase of each job (ADR 0023).";
    ReviewPrecision = 8, "review-precision", "Review precision", Quality, Ratio,
        HigherIsBetter, [Rate], ["reviewer agent", "model"],
        Facts::NotStored("needs the fate of each finding"),
        "The findings a person or a later fix confirmed, out of the findings raised.";
    EscapedDefects = 9, "escaped-defects", "Escaped defects", Quality, Count,
        LowerIsBetter, [Total], ["project", "pack"],
        Facts::NotStored("needs bugs linked to pull requests"),
        "The bugs linked to a merged factory pull request within 30 days of the merge.";
    FlakyTests = 10, "flaky-tests", "Flaky tests", Quality, Count,
        LowerIsBetter, [Total], ["project"],
        Facts::NotStored("needs test results by commit"),
        "The tests whose result changed with no code change, in the window.";
    HumanRejectionRate = 11, "human-rejection-rate", "Human rejection rate", Quality, Ratio,
        LowerIsBetter, [Rate], ["project", "pack"], NEEDS_PULL_REQUEST_FATE,
        "The pull requests closed without a merge, out of the pull requests opened.";
    CostPerAcceptedPullRequest = 12, "cost-per-accepted-pull-request", "Cost per accepted pull request", Cost, MicroUsd,
        LowerIsBetter, [AmountPerItem], ["project", "pack"], NEEDS_PULL_REQUEST_FATE,
        "The spend the broker metered for the jobs, divided by the merged pull requests.";
    TokensPerTask = 13, "tokens-per-task", "Tokens per task", Cost, Count,
        LowerIsBetter, [Median], ["agent", "model"],
        Facts::NotStored("needs the tokens of each task in the database"),
        "The input plus output tokens of all attempts of a task.";
    EscalationsToTheLargerModel = 14, "escalations-to-the-larger-model", "Escalations to the larger model", Cost, Ratio,
        LowerIsBetter, [Rate], ["agent"],
        Facts::NotStored("needs the model tier of each task in the database"),
        "The tasks that needed the larger model, out of all tasks.";
    KnowledgeCoverage = 15, "knowledge-coverage", "Knowledge coverage", Knowledge, Ratio,
        HigherIsBetter, [Rate], ["project"], NEEDS_KNOWLEDGE_BASE,
        "The active business rules with at least one enforcing test, out of the active business rules.";
    KnowledgeDrift = 16, "knowledge-drift", "Knowledge drift", Knowledge, Count,
        LowerIsBetter, [Total], ["project"], NEEDS_KNOWLEDGE_BASE,
        "The active entries whose code changed without confirmation, as the documentation gate finds them.";
    KnowledgeUse = 17, "knowledge-use", "Knowledge use", Knowledge, Ratio,
        HigherIsBetter, [Rate], ["agent"], NEEDS_KNOWLEDGE_BASE,
        "The tasks whose agents read at least one relevant entry, out of all tasks.";
    LeadTimeForChanges = 18, "lead-time-for-changes", "Lead time for changes", Delivery, Milliseconds,
        LowerIsBetter, [Median], ["project"], NEEDS_PIPELINE,
        "The time from a merged change to its deployment, read from the project's own pipeline.";
    DeploymentFrequency = 19, "deployment-frequency", "Deployment frequency", Delivery, Count,
        HigherIsBetter, [Total], ["project"], NEEDS_PIPELINE,
        "The deployments in the window, read from the project's own pipeline.";
    ChangeFailureRate = 20, "change-failure-rate", "Change failure rate", Delivery, Ratio,
        LowerIsBetter, [Rate], ["project"], NEEDS_PIPELINE,
        "The deployments that caused a failure, out of all deployments, read from the project's own pipeline.";
    TimeToRestoreService = 21, "time-to-restore-service", "Time to restore service", Delivery, Milliseconds,
        LowerIsBetter, [Median], ["project"], NEEDS_PIPELINE,
        "The time from a failure in production to its repair, read from the project's own pipeline.";
}

impl Metric {
    /// The metric with this identifier, for example `MT-0006`.
    pub fn from_identifier(identifier: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|metric| metric.definition().identifier() == identifier)
    }
}

#[cfg(test)]
mod tests;
