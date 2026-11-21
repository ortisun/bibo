//! Tier A experiments as pure rules: which settings may be tried, which jobs get the variant,
//! when a variant is promoted, discarded or rolled back, and the `improvement` entry.
//!
//! The rules are those of the section "Experiments" of
//! `docs/architecture/process-metrics-and-improvement.md` and of ADR 0029, Decision 3. Nothing
//! here applies a setting to a job or reads a number: the caller passes the comparisons in.

use std::collections::BTreeSet;
use std::fmt::Write as _;

use sha2::{Digest, Sha256};

use super::MetricError;
use super::catalogue::{Metric, Unit};
use super::comparison::{Interval, Verdict};
use super::sample::Measured;
use crate::ids::JobId;
use crate::knowledge::yaml_quoted;
use crate::values::{Slug, Timestamp};

/// How far the factory may make a change on its own (ADR 0029, Decision 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tier {
    /// A reversible operational setting: promoted automatically, with automatic rollback.
    A,
    /// The behaviour of agents: proposed by a draft pull request, approved by a person.
    B,
    /// Policies, gates, security and approvals: never changed by the factory.
    C,
}

/// The kinds of change the improvement loop can think of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Change {
    /// One of the declared tier A settings.
    Setting(SettingKind),
    /// A prompt of an agent.
    Prompt,
    /// A new or changed skill.
    Skill,
    /// An evaluation case of a pack.
    EvaluationCase,
    /// The default model of a role.
    DefaultModel,
    /// A policy file.
    Policy,
    /// A gate or its thresholds.
    Gate,
    /// A security rule.
    SecurityRule,
    /// An approval rule or an autonomy level.
    Approval,
}

impl Change {
    /// The tier of the change. Only a declared setting is tier A.
    pub const fn tier(self) -> Tier {
        match self {
            Self::Setting(_) => Tier::A,
            Self::Prompt | Self::Skill | Self::EvaluationCase | Self::DefaultModel => Tier::B,
            Self::Policy | Self::Gate | Self::SecurityRule | Self::Approval => Tier::C,
        }
    }
}

/// The tier A settings of the design document's table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SettingKind {
    /// Whether the targeted tests run first. The full suite always runs.
    TestOrder,
    /// How many tasks of a job run at once.
    ParallelTasks,
    /// The model tier that starts a task of a known kind.
    StartingModelTier,
    /// The order of the independent reviewers. All of them still run.
    ReviewerOrder,
}

impl SettingKind {
    /// Every setting, in the order of the table.
    pub const ALL: &'static [Self] = &[
        Self::TestOrder,
        Self::ParallelTasks,
        Self::StartingModelTier,
        Self::ReviewerOrder,
    ];

    /// The name used in an `improvement` entry.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TestOrder => "test-order",
            Self::ParallelTasks => "parallel-tasks",
            Self::StartingModelTier => "starting-model-tier",
            Self::ReviewerOrder => "reviewer-order",
        }
    }

    /// The guard metrics of the setting: none of them may get worse. The rate of human
    /// rejections guards every setting (ADR 0029, Decision 3). The "gate failure rate" of the
    /// table is first-pass gate success read the other way round.
    pub const fn guards(self) -> &'static [Metric] {
        match self {
            Self::TestOrder => &[
                Metric::EscapedDefects,
                Metric::FirstPassGateSuccess,
                Metric::HumanRejectionRate,
            ],
            Self::ParallelTasks => &[
                Metric::FirstPassGateSuccess,
                Metric::CostPerAcceptedPullRequest,
                Metric::HumanRejectionRate,
            ],
            Self::StartingModelTier => &[
                Metric::FirstPassGateSuccess,
                Metric::EscapedDefects,
                Metric::HumanRejectionRate,
            ],
            Self::ReviewerOrder => &[Metric::ReviewPrecision, Metric::HumanRejectionRate],
        }
    }
}

/// One value of a tier A setting.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Setting {
    /// Targeted tests first (`true`) or the suite's own order (`false`).
    TestOrder(bool),
    /// The number of tasks of a job that run at once.
    ParallelTasks(u32),
    /// The model tier that starts a task.
    StartingModelTier(Slug),
    /// The reviewers, in the order they run.
    ReviewerOrder(Vec<Slug>),
}

/// What the safe range of each setting is measured against. The caller reads it from the policy
/// and the evaluation records; this module never widens it.
#[derive(Debug, Clone, Copy)]
pub struct SafeRange<'a> {
    /// The policy's limit of tasks that run at once.
    pub parallel_tasks_limit: u32,
    /// The model tiers that passed the evaluation for the agent.
    pub evaluated_tiers: &'a [Slug],
    /// The independent reviewers that run today.
    pub reviewers: &'a [Slug],
}

impl Setting {
    /// The kind of the setting.
    pub const fn kind(&self) -> SettingKind {
        match self {
            Self::TestOrder(_) => SettingKind::TestOrder,
            Self::ParallelTasks(_) => SettingKind::ParallelTasks,
            Self::StartingModelTier(_) => SettingKind::StartingModelTier,
            Self::ReviewerOrder(_) => SettingKind::ReviewerOrder,
        }
    }

    /// Checks the value against its safe range.
    pub fn check(&self, range: &SafeRange<'_>) -> Result<(), MetricError> {
        let refuse = |reason| Err(MetricError::ExperimentRefused { reason });
        match self {
            Self::TestOrder(_) => Ok(()),
            Self::ParallelTasks(tasks) => {
                if (1..=range.parallel_tasks_limit).contains(tasks) {
                    Ok(())
                } else {
                    refuse("the number of parallel tasks is outside 1 to the policy's limit")
                }
            }
            Self::StartingModelTier(tier) => {
                if range.evaluated_tiers.contains(tier) {
                    Ok(())
                } else {
                    refuse("the model tier did not pass the evaluation for the agent")
                }
            }
            Self::ReviewerOrder(order) => {
                let offered: BTreeSet<&Slug> = order.iter().collect();
                let current: BTreeSet<&Slug> = range.reviewers.iter().collect();
                if offered.len() != order.len() {
                    refuse("a reviewer is named twice in the order")
                } else if offered != current || current.len() != range.reviewers.len() {
                    refuse("the order must hold exactly the reviewers that run today")
                } else {
                    Ok(())
                }
            }
        }
    }

    /// The value as text for an `improvement` entry.
    pub fn value_text(&self) -> String {
        match self {
            Self::TestOrder(true) => "targeted tests first".to_owned(),
            Self::TestOrder(false) => "the suite's own order".to_owned(),
            Self::ParallelTasks(tasks) => tasks.to_string(),
            Self::StartingModelTier(tier) => tier.as_str().to_owned(),
            Self::ReviewerOrder(order) => order
                .iter()
                .map(Slug::as_str)
                .collect::<Vec<_>>()
                .join(", "),
        }
    }
}

/// The share of jobs that get the variant, in hundredths of a percent: from 1 to 5000 (half).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Share(u16);

impl Share {
    /// 10 percent.
    pub const DEFAULT: Self = Self(1_000);
    /// The number of parts the share is counted in.
    const PARTS: u64 = 10_000;

    /// A share. Zero and more than half of the jobs are refused.
    pub fn new(hundredths: u16) -> Result<Self, MetricError> {
        if !(1..=5_000).contains(&hundredths) {
            return Err(MetricError::SettingOutOfRange {
                what: "the share of jobs of an experiment, in hundredths of a percent",
                minimum: 1,
                maximum: 5_000,
                offered: u64::from(hundredths),
            });
        }
        Ok(Self(hundredths))
    }

    /// The share in hundredths of a percent.
    pub const fn hundredths(self) -> u16 {
        self.0
    }
}

/// How many windows an experiment may run: from 1 to 12.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Windows(u8);

impl Windows {
    /// 4 windows.
    pub const DEFAULT: Self = Self(4);

    /// A number of windows from 1 to 12.
    pub fn new(windows: u8) -> Result<Self, MetricError> {
        if !(1..=12).contains(&windows) {
            return Err(MetricError::SettingOutOfRange {
                what: "the number of windows of an experiment",
                minimum: 1,
                maximum: 12,
                offered: u64::from(windows),
            });
        }
        Ok(Self(windows))
    }

    /// The number of windows.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// The remainder that decides whether a job gets the variant of an experiment, from 0 to 9999:
/// the first eight bytes of the SHA-256 of `experiment:<experiment>:job:<job>`, read as an
/// unsigned integer with the most significant byte first, modulo 10 000.
fn draw(experiment: &Slug, job: JobId) -> u64 {
    let text = format!("experiment:{}:job:{}", experiment.as_str(), job);
    let digest = Sha256::digest(text.as_bytes());
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(first) % Share::PARTS
}

/// What the comparison of one metric shows, with the metric it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Comparison {
    /// The metric that was compared.
    pub metric: Metric,
    /// The difference "variant minus baseline" (or "after minus before" for a rollback check)
    /// with its interval, or "too few samples".
    pub difference: Measured<Interval>,
}

impl Comparison {
    /// What the comparison shows, in the direction of its metric. `None` with too few samples.
    pub fn verdict(&self) -> Option<Verdict> {
        self.difference
            .value()
            .map(|interval| interval.verdict(self.metric.definition().better))
    }
}

/// Why a variant was discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscardReason {
    /// A guard metric got worse.
    GuardWorsened(Metric),
    /// The target metric got worse.
    TargetWorsened,
    /// The last window passed without a clear improvement and a full set of guards.
    NoClearImprovementInTime,
}

/// What to do with a running experiment after a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PromotionDecision {
    /// Make the variant the setting of every job.
    Promote,
    /// Stop the experiment and keep the baseline.
    Discard(DiscardReason),
    /// Run another window.
    KeepRunning,
}

/// What to do with a promoted setting after the next window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RollbackDecision {
    /// Keep the promoted value.
    Keep,
    /// Put the earlier value back, because this guard metric got worse.
    RollBack(Metric),
}

/// A declared tier A experiment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Experiment {
    identifier: Slug,
    baseline: Setting,
    variant: Setting,
    target: Metric,
    share: Share,
    windows: Windows,
}

impl Experiment {
    /// Declares an experiment. It is refused when the two values are of different settings, when
    /// they are equal, when either is outside the safe range, or when the target is one of the
    /// setting's own guard metrics (a guard only has to hold; the target has to improve).
    pub fn declare(
        identifier: Slug,
        baseline: Setting,
        variant: Setting,
        target: Metric,
        share: Share,
        windows: Windows,
        range: &SafeRange<'_>,
    ) -> Result<Self, MetricError> {
        let refuse = |reason| Err(MetricError::ExperimentRefused { reason });
        if baseline.kind() != variant.kind() {
            return refuse("the baseline and the variant are values of different settings");
        }
        if baseline == variant {
            return refuse("the variant is the same as the baseline");
        }
        baseline.check(range)?;
        variant.check(range)?;
        if baseline.kind().guards().contains(&target) {
            return refuse("the target metric is one of the setting's guard metrics");
        }
        Ok(Self {
            identifier,
            baseline,
            variant,
            target,
            share,
            windows,
        })
    }

    /// The identifier of the experiment.
    pub const fn identifier(&self) -> &Slug {
        &self.identifier
    }

    /// The setting the experiment changes.
    pub const fn kind(&self) -> SettingKind {
        self.baseline.kind()
    }

    /// The metric the variant is meant to improve.
    pub const fn target(&self) -> Metric {
        self.target
    }

    /// The value a job runs with: the variant for the experiment's share of jobs, chosen by a
    /// hash of the experiment and the job, and the baseline for the others. The same job always
    /// gets the same answer.
    pub fn setting_for(&self, job: JobId) -> &Setting {
        if draw(&self.identifier, job) < u64::from(self.share.0) {
            &self.variant
        } else {
            &self.baseline
        }
    }

    /// Checks that `guards` holds exactly one comparison for each guard metric of the setting.
    fn check_guards(&self, guards: &[Comparison]) -> Result<(), MetricError> {
        let offered: BTreeSet<Metric> = guards.iter().map(|guard| guard.metric).collect();
        let expected: BTreeSet<Metric> = self.kind().guards().iter().copied().collect();
        if offered.len() != guards.len() || offered != expected {
            return Err(MetricError::ExperimentRefused {
                reason: "the comparisons must cover each guard metric of the setting exactly once",
            });
        }
        Ok(())
    }

    /// The decision after `windows_run` finished windows. `target` and `guards` compare the jobs
    /// with the variant against the jobs without it. A comparison of another metric than the
    /// target, or guards that are not exactly the setting's, are refused.
    pub fn decide_promotion(
        &self,
        target: &Comparison,
        guards: &[Comparison],
        windows_run: u8,
    ) -> Result<PromotionDecision, MetricError> {
        if target.metric != self.target {
            return Err(MetricError::ExperimentRefused {
                reason: "the target comparison is of another metric than the experiment's target",
            });
        }
        self.check_guards(guards)?;

        if let Some(worse) = guards
            .iter()
            .find(|guard| guard.verdict() == Some(Verdict::Worsening))
        {
            return Ok(PromotionDecision::Discard(DiscardReason::GuardWorsened(
                worse.metric,
            )));
        }
        if target.verdict() == Some(Verdict::Worsening) {
            return Ok(PromotionDecision::Discard(DiscardReason::TargetWorsened));
        }
        // A guard with too few samples has not shown that the variant is safe.
        let every_guard_measured = guards.iter().all(|guard| guard.verdict().is_some());
        if target.verdict() == Some(Verdict::Improvement) && every_guard_measured {
            return Ok(PromotionDecision::Promote);
        }
        if windows_run >= self.windows.0 {
            return Ok(PromotionDecision::Discard(
                DiscardReason::NoClearImprovementInTime,
            ));
        }
        Ok(PromotionDecision::KeepRunning)
    }

    /// The decision one window after a promotion. `guards` compare that window with the window
    /// before the promotion. One guard that got worse rolls the setting back; too few samples or
    /// no clear change keeps it.
    pub fn decide_rollback(&self, guards: &[Comparison]) -> Result<RollbackDecision, MetricError> {
        self.check_guards(guards)?;
        Ok(guards
            .iter()
            .find(|guard| guard.verdict() == Some(Verdict::Worsening))
            .map_or(RollbackDecision::Keep, |worse| {
                RollbackDecision::RollBack(worse.metric)
            }))
    }
}

/// What happened to an experiment, for its `improvement` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The variant became the setting of every job.
    Promoted,
    /// The baseline was kept.
    Discarded(DiscardReason),
    /// The variant was promoted and later put back.
    RolledBack(Metric),
}

/// The record of one decision about an experiment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Improvement<'a> {
    /// The number of the identifier: 1 for `IM-0001`. Never reused.
    pub number: u16,
    /// The experiment.
    pub experiment: &'a Experiment,
    /// What the variant was expected to change, in one line.
    pub hypothesis: &'a str,
    /// The comparison of the target metric.
    pub target: Comparison,
    /// The comparisons of the guard metrics.
    pub guards: &'a [Comparison],
    /// What was decided.
    pub outcome: Outcome,
    /// When it was decided.
    pub decided_at: Timestamp,
}

impl Improvement<'_> {
    /// The identifier, for example `IM-0001`.
    pub fn identifier(&self) -> String {
        format!("IM-{:04}", self.number)
    }

    /// The file of the entry in a knowledge base, under `docs/knowledge/`.
    pub fn entry_path(&self) -> String {
        format!(
            "improvements/{}-{}.md",
            self.identifier(),
            self.experiment.identifier.as_str()
        )
    }

    /// The `improvement` entry, as Markdown with a front matter block. A hypothesis that is
    /// empty or holds a line break is refused.
    pub fn render_entry(&self) -> Result<String, MetricError> {
        let hypothesis = self.hypothesis.trim();
        if hypothesis.is_empty() || hypothesis.contains(['\n', '\r']) {
            return Err(MetricError::TextIsNotOneLine {
                what: "the hypothesis of an improvement",
            });
        }
        let (decision, explanation) = match self.outcome {
            Outcome::Promoted => (
                "promoted",
                "The target metric improved and no guard metric got worse, so the variant is now \
                 the setting of every job. It is rolled back automatically if a guard metric gets \
                 worse in the next window."
                    .to_owned(),
            ),
            Outcome::Discarded(DiscardReason::GuardWorsened(metric)) => (
                "discarded",
                format!(
                    "The guard metric {} got worse, so the baseline is kept.",
                    metric.definition().name
                ),
            ),
            Outcome::Discarded(DiscardReason::TargetWorsened) => (
                "discarded",
                "The target metric got worse, so the baseline is kept.".to_owned(),
            ),
            Outcome::Discarded(DiscardReason::NoClearImprovementInTime) => (
                "discarded",
                format!(
                    "After {} windows the target metric showed no clear improvement with every \
                     guard metric measured, so the baseline is kept.",
                    self.experiment.windows.0
                ),
            ),
            Outcome::RolledBack(metric) => (
                "rolled back",
                format!(
                    "After the promotion the guard metric {} got worse, so the earlier value is \
                     back.",
                    metric.definition().name
                ),
            ),
        };

        let mut entry = String::new();
        // Writing to a `String` cannot fail.
        let _ = write!(
            entry,
            "---\n\
             id: {id}\n\
             kind: improvement\n\
             title: {title}\n\
             status: active\n\
             tier: A\n\
             experiment: {experiment}\n\
             setting: {setting}\n\
             from: {from}\n\
             to: {to}\n\
             share_of_jobs: {share} hundredths of a percent\n\
             decision: {decision}\n\
             decided_at: {decided_at}\n\
             ---\n\
             \n\
             ## Hypothesis\n\
             \n\
             {hypothesis}\n\
             \n\
             ## What was measured\n\
             \n\
             The difference is the variant minus the baseline, with its 95 percent interval.\n\
             \n\
             | Metric | Role | Difference | Interval | Samples | Shows |\n\
             |---|---|---|---|---|---|\n",
            id = self.identifier(),
            title = yaml_quoted(hypothesis),
            experiment = yaml_quoted(self.experiment.identifier.as_str()),
            setting = self.experiment.kind().as_str(),
            from = yaml_quoted(&self.experiment.baseline.value_text()),
            to = yaml_quoted(&self.experiment.variant.value_text()),
            share = self.experiment.share.0,
            decided_at = yaml_quoted(&self.decided_at.as_text()),
        );
        let rows = std::iter::once(("target", &self.target))
            .chain(self.guards.iter().map(|guard| ("guard", guard)));
        for (role, comparison) in rows {
            let definition = comparison.metric.definition();
            let unit = match definition.unit {
                Unit::Milliseconds => "ms",
                Unit::Ratio => "millionths",
                Unit::Count => "",
                Unit::MicroUsd => "micro-USD",
            };
            let with_unit = |text: String| format!("{text} {unit}").trim_end().to_owned();
            let (difference, interval, shows) = match (comparison.difference, comparison.verdict())
            {
                (Measured::Value { value, .. }, Some(verdict)) => (
                    with_unit(value.point().to_string()),
                    with_unit(format!("{} to {}", value.lower(), value.upper())),
                    match verdict {
                        Verdict::Improvement => "improvement",
                        Verdict::Worsening => "worsening",
                        Verdict::NoClearChange => "no clear change",
                    },
                ),
                _ => (
                    "too few samples".to_owned(),
                    "too few samples".to_owned(),
                    "nothing yet",
                ),
            };
            let _ = writeln!(
                entry,
                "| {} {} | {role} | {difference} | {interval} | {} | {shows} |",
                definition.identifier(),
                definition.name,
                comparison.difference.samples(),
            );
        }
        let _ = write!(entry, "\n## Decision\n\n{explanation}\n");
        Ok(entry)
    }
}

#[cfg(test)]
mod tests;
