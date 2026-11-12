//! Budgets and rework caps (`budgets` of `policies/security.yaml`).
//!
//! The ceilings are hard: a policy can lower them and never raise them, and raising one is the
//! `raise_budget_ceiling` action, which needs an `org_admin`. The checks here take a measured
//! usage and say whether the limit is reached. They are total: a usage that is not a finite,
//! non-negative number counts as over the limit, because a counter that went wrong is not a
//! counter that says there is room.
//!
//! The rework and repair caps use the types of [`crate::machines::limits`], which can only be built
//! by taking the lower of the policy value and the default of two. The engine also refuses to
//! build from a policy whose value is above two, so the file and the code cannot disagree
//! (NT-BUD-04, ADR 0009 item 6, ADR 0010).

use crate::machines::limits::{
    DEFAULT_REPAIR_CAP, DEFAULT_REWORK_CAP, RepairCap, ReworkLedger, ReworkLimits, ReworkTrack,
};

use super::security::SecurityPolicy;
use super::{BuildError, RuleRef};

/// A quantity a budget limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Metric {
    /// Money, in US dollars.
    Usd,
    /// Input tokens.
    InputTokens,
    /// Output tokens.
    OutputTokens,
    /// Model requests.
    Turns,
    /// Tool calls.
    ToolCalls,
    /// Wall-clock seconds.
    WallClockSeconds,
    /// Jobs started.
    JobsStarted,
    /// Depth of delegation between agents.
    DelegationDepth,
}

/// The scope a limit belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Scope {
    /// One task.
    Task,
    /// One job.
    Job,
    /// One repository for one day.
    RepoDay,
    /// One organization for one day.
    OrgDay,
}

impl Scope {
    fn as_str(self) -> &'static str {
        match self {
            Self::Task => "per_task",
            Self::Job => "per_job",
            Self::RepoDay => "per_repo_day",
            Self::OrgDay => "per_org_day",
        }
    }
}

/// One measured quantity.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Reading {
    /// What is measured.
    pub metric: Metric,
    /// Its value now.
    pub used: f64,
}

/// The answer for a set of readings in one scope.
#[derive(Debug, Clone, PartialEq)]
pub enum BudgetVerdict {
    /// Every reading is below the warning fraction.
    Within,
    /// At least one reading passed the warning fraction and none reached the stop fraction.
    Warn {
        /// The readings over the warning fraction.
        metrics: Vec<Metric>,
    },
    /// At least one reading reached the stop fraction. The job stops, the job token is revoked
    /// and a human is asked.
    Exhausted {
        /// The readings that reached it.
        metrics: Vec<Metric>,
        /// The scope's rule.
        rule: RuleRef,
    },
}

impl BudgetVerdict {
    /// True when work may go on.
    #[must_use]
    pub fn may_continue(&self) -> bool {
        !matches!(self, Self::Exhausted { .. })
    }
}

/// Why a request to change the ceilings was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CeilingRefusal {
    /// A requested ceiling is above the one in force. Raising needs `raise_budget_ceiling`.
    #[error("a requested ceiling is higher than the one in force")]
    Raises,
    /// A requested ceiling is not a finite, non-negative number.
    #[error("a requested ceiling is not a valid number")]
    Invalid,
}

/// The limits of one scope, by metric.
#[derive(Debug, Clone, PartialEq)]
struct Limits(Vec<(Metric, f64)>);

impl Limits {
    fn get(&self, metric: Metric) -> Option<f64> {
        self.0.iter().find(|(m, _)| *m == metric).map(|(_, v)| *v)
    }
}

/// The hard ceilings and the thresholds.
#[derive(Debug, Clone, PartialEq)]
pub struct BudgetPolicy {
    task: Limits,
    job: Limits,
    repo_day: Limits,
    org_day: Limits,
    warn_at: f64,
    stop_at: f64,
    rework: ReworkLimits,
    repair: RepairCap,
    max_running_jobs_per_repo: u64,
    max_queued_jobs_per_repo: u64,
}

#[allow(clippy::cast_precision_loss)]
fn count(value: u64) -> f64 {
    value as f64
}

fn clamp_u8(value: u32) -> u8 {
    u8::try_from(value).unwrap_or(u8::MAX)
}

impl BudgetPolicy {
    /// Reads the budgets of `policy`.
    ///
    /// # Errors
    /// A [`BuildError`] when a rework or repair cap is above two, a threshold is not between 0 and
    /// 1, a number is not usable, or `rework.on_cap_reached` is not `human_decides`.
    pub fn from_policy(policy: &SecurityPolicy) -> Result<Self, BuildError> {
        let b = &policy.budgets;
        let c = &b.hard_ceilings;
        let caps = [
            (
                "budgets.hard_ceilings.per_job.max_rework_iterations",
                c.per_job.max_rework_iterations,
            ),
            (
                "budgets.hard_ceilings.per_job.max_documentation_rework_iterations",
                c.per_job.max_documentation_rework_iterations,
            ),
            ("budgets.rework.default_rounds", b.rework.default_rounds),
        ];
        for (key, value) in caps {
            if value > u32::from(DEFAULT_REWORK_CAP) {
                return Err(BuildError::Contradiction(format!(
                    "{key} is {value}, above the cap of {DEFAULT_REWORK_CAP} rounds (ADR 0009 item 6); a human decides after the cap"
                )));
            }
        }
        if b.rework.on_cap_reached != "human_decides" {
            return Err(BuildError::UnknownValue {
                key: "budgets.rework.on_cap_reached",
                found: b.rework.on_cap_reached.clone(),
            });
        }
        if b.rework.project_override != "lower_only" {
            return Err(BuildError::UnknownValue {
                key: "budgets.rework.project_override",
                found: b.rework.project_override.clone(),
            });
        }
        let (warn_at, stop_at) = (b.thresholds.warn_at_fraction, b.thresholds.stop_at_fraction);
        let fraction_ok = |f: f64| f.is_finite() && f > 0.0 && f <= 1.0;
        if !fraction_ok(warn_at) || !fraction_ok(stop_at) || warn_at > stop_at {
            return Err(BuildError::Contradiction(
                "budgets.thresholds must satisfy 0 < warn_at_fraction <= stop_at_fraction <= 1"
                    .to_owned(),
            ));
        }
        let usd_ok = |key: &'static str, v: f64| {
            if v.is_finite() && v >= 0.0 {
                Ok(v)
            } else {
                Err(BuildError::UnknownValue {
                    key,
                    found: v.to_string(),
                })
            }
        };
        let task = Limits(vec![
            (
                Metric::Usd,
                usd_ok("budgets.hard_ceilings.per_task.max_usd", c.per_task.max_usd)?,
            ),
            (Metric::InputTokens, count(c.per_task.max_input_tokens)),
            (Metric::OutputTokens, count(c.per_task.max_output_tokens)),
            (Metric::Turns, count(c.per_task.max_turns)),
            (Metric::ToolCalls, count(c.per_task.max_tool_calls)),
            (Metric::WallClockSeconds, count(c.per_task.max_wall_clock_s)),
        ]);
        let job = Limits(vec![
            (
                Metric::Usd,
                usd_ok("budgets.hard_ceilings.per_job.max_usd", c.per_job.max_usd)?,
            ),
            (Metric::WallClockSeconds, count(c.per_job.max_wall_clock_s)),
            (
                Metric::DelegationDepth,
                f64::from(c.per_job.max_delegation_depth),
            ),
        ]);
        let repo_day = Limits(vec![
            (
                Metric::Usd,
                usd_ok(
                    "budgets.hard_ceilings.per_repo_day.max_usd",
                    c.per_repo_day.max_usd,
                )?,
            ),
            (Metric::JobsStarted, count(c.per_repo_day.max_jobs_started)),
        ]);
        let org_day = Limits(vec![(
            Metric::Usd,
            usd_ok(
                "budgets.hard_ceilings.per_org_day.max_usd",
                c.per_org_day.max_usd,
            )?,
        )]);
        let repair = policy
            .untrusted_content
            .structured_output
            .bounded_repair_attempts;
        if repair > u32::from(DEFAULT_REPAIR_CAP) {
            return Err(BuildError::Contradiction(format!(
                "untrusted_content.structured_output.bounded_repair_attempts is {repair}, above the cap of {DEFAULT_REPAIR_CAP} repairs (ADR 0010)"
            )));
        }
        Ok(Self {
            task,
            job,
            repo_day,
            org_day,
            warn_at,
            stop_at,
            rework: ReworkLimits::from_policy(
                clamp_u8(c.per_job.max_rework_iterations),
                clamp_u8(c.per_job.max_documentation_rework_iterations),
            ),
            repair: RepairCap::from_policy(clamp_u8(repair)),
            max_running_jobs_per_repo: b.concurrency.max_running_jobs_per_repo,
            max_queued_jobs_per_repo: b.concurrency.max_queued_jobs_per_repo,
        })
    }

    /// The rework caps of a job.
    #[must_use]
    pub fn rework_limits(&self) -> ReworkLimits {
        self.rework
    }

    /// The repair cap after an invalid output.
    #[must_use]
    pub fn repair_cap(&self) -> RepairCap {
        self.repair
    }

    /// True when a job may go through one more rework round on `track`, given the rounds used.
    #[must_use]
    pub fn rework_allowed(&self, ledger: ReworkLedger, track: ReworkTrack) -> bool {
        ledger.has_room(track, self.rework)
    }

    /// The most jobs that run at once in one repository.
    #[must_use]
    pub fn max_running_jobs_per_repo(&self) -> u64 {
        self.max_running_jobs_per_repo
    }

    /// The most jobs that wait in one repository.
    #[must_use]
    pub fn max_queued_jobs_per_repo(&self) -> u64 {
        self.max_queued_jobs_per_repo
    }

    /// The ceiling of a metric in a scope, if the scope limits it.
    #[must_use]
    pub fn ceiling(&self, scope: Scope, metric: Metric) -> Option<f64> {
        self.limits(scope).get(metric)
    }

    /// The usage of a metric at which [`check`](Self::check) says a scope is exhausted: the
    /// ceiling at the stop fraction. `None` when the scope does not limit the metric.
    #[must_use]
    pub fn stops_at(&self, scope: Scope, metric: Metric) -> Option<f64> {
        self.ceiling(scope, metric)
            .map(|ceiling| ceiling * self.stop_at)
    }

    fn limits(&self, scope: Scope) -> &Limits {
        match scope {
            Scope::Task => &self.task,
            Scope::Job => &self.job,
            Scope::RepoDay => &self.repo_day,
            Scope::OrgDay => &self.org_day,
        }
    }

    /// Checks readings against the ceilings of a scope. A metric the scope does not limit is
    /// ignored. A reading that is not finite and non-negative counts as reaching the limit.
    #[must_use]
    pub fn check(&self, scope: Scope, readings: &[Reading]) -> BudgetVerdict {
        let limits = self.limits(scope);
        let (mut warn, mut stop) = (Vec::new(), Vec::new());
        for r in readings.iter().take(64) {
            let Some(limit) = limits.get(r.metric) else {
                continue;
            };
            let valid = r.used.is_finite() && r.used >= 0.0;
            if !valid || r.used >= limit * self.stop_at {
                stop.push(r.metric);
            } else if r.used >= limit * self.warn_at {
                warn.push(r.metric);
            }
        }
        if !stop.is_empty() {
            BudgetVerdict::Exhausted {
                metrics: stop,
                rule: RuleRef::new("budgets.hard_ceilings", scope.as_str()),
            }
        } else if !warn.is_empty() {
            BudgetVerdict::Warn { metrics: warn }
        } else {
            BudgetVerdict::Within
        }
    }

    /// The ceilings a project may ask for: each requested value must be at or below the one in
    /// force. Returns the lowered policy.
    ///
    /// # Errors
    /// [`CeilingRefusal`] when a value is above the current one or not a valid number. Nothing
    /// is changed then.
    pub fn lowered(
        &self,
        scope: Scope,
        requested: &[(Metric, f64)],
    ) -> Result<Self, CeilingRefusal> {
        let mut next = self.clone();
        let target = match scope {
            Scope::Task => &mut next.task,
            Scope::Job => &mut next.job,
            Scope::RepoDay => &mut next.repo_day,
            Scope::OrgDay => &mut next.org_day,
        };
        for (metric, value) in requested {
            if !(value.is_finite() && *value >= 0.0) {
                return Err(CeilingRefusal::Invalid);
            }
            let Some(slot) = target.0.iter_mut().find(|(m, _)| m == metric) else {
                return Err(CeilingRefusal::Raises);
            };
            if *value > slot.1 {
                return Err(CeilingRefusal::Raises);
            }
            slot.1 = *value;
        }
        Ok(next)
    }
}
