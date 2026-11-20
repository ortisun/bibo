//! The schedule rules of `policies/troubleshooting.yaml`, as pure functions of the policy, the
//! stored counters and the clock (ADR 0021, Decision 2). Days are UTC calendar days (ADR 0011).
//!
//! * A probe that tripped starts an agent run only when it is past its cool-down.
//! * The sweep is due when the last sweep started at least one sweep period ago; with no sweep on
//!   record, one sweep period after this process started (so a fresh install does not spend a
//!   model run in its first minute; `--sweep-now` starts one at once).
//! * An agent run starts only while the day's runs are under `max_agent_runs_per_day` and the
//!   day's spend is under the role's `per_day` ceiling; its own ceiling is the role's `per_run`,
//!   cut to what is left of the day.
//! * New issues stop at `max_new_per_day`; a "seen again" comment is posted at most
//!   `max_comments_per_issue_per_day` times on one issue in one day.

use std::time::Duration;

use factory_domain::policy::troubleshooting::Schedule;
use factory_domain::values::Timestamp;
use factory_storage::pg::troubleshooting::{DayCounters, IssueEntry, ProbeState, utc_day};

/// Whether a probe that tripped now may start an agent run: its cool-down is over or was never
/// started.
#[must_use]
pub fn past_cooldown(state: Option<&ProbeState>, now: &Timestamp) -> bool {
    state
        .and_then(|state| state.cooldown_until.as_ref())
        .is_none_or(|until| until <= now)
}

/// When the cool-down of a probe investigated now ends.
#[must_use]
pub fn cooldown_until(schedule: &Schedule, now: &Timestamp) -> Timestamp {
    now.checked_add(Duration::from_secs(schedule.probe_cooldown_s))
        .unwrap_or(*now)
}

/// Whether the sweep is due.
#[must_use]
pub fn sweep_due(
    schedule: &Schedule,
    last_sweep: Option<&Timestamp>,
    process_started: &Timestamp,
    now: &Timestamp,
) -> bool {
    let since = last_sweep.unwrap_or(process_started);
    now.duration_since(since)
        .is_some_and(|elapsed| elapsed >= Duration::from_secs(schedule.sweep_period_s))
}

/// Why an agent run may not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The day's runs reached `max_agent_runs_per_day`.
    RunCap,
    /// The day's spend reached the role's `per_day` ceiling.
    SpendCeiling,
}

/// Whether an agent run may start today, and with what spend ceiling (millionths of a dollar).
///
/// # Errors
/// [`Refusal`].
pub fn agent_budget(
    schedule: &Schedule,
    today: &DayCounters,
    per_run_micro_usd: u64,
    per_day_micro_usd: u64,
) -> Result<u64, Refusal> {
    if today.agent_runs >= schedule.max_agent_runs_per_day {
        return Err(Refusal::RunCap);
    }
    let left = per_day_micro_usd.saturating_sub(today.spend_micro_usd);
    if left == 0 {
        return Err(Refusal::SpendCeiling);
    }
    Ok(per_run_micro_usd.min(left))
}

/// Whether one more new issue may be opened today.
#[must_use]
pub fn may_open_issue(max_new_per_day: u32, today: &DayCounters) -> bool {
    today.new_issues < max_new_per_day
}

/// Whether the issue of `entry` may get one more "seen again" comment on the UTC day of `now`.
#[must_use]
pub fn may_comment(max_per_day: u32, entry: Option<&IssueEntry>, now: &Timestamp) -> bool {
    let today = utc_day(now);
    let used = entry
        .filter(|entry| entry.last_comment_day.as_deref() == Some(today.as_str()))
        .map_or(0, |entry| entry.comments_on_last_day);
    used < max_per_day
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::values::Sha256Digest;
    use factory_storage::pg::troubleshooting::ProbeOutcome;

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a time")
    }

    fn schedule() -> Schedule {
        Schedule {
            probe_period_s: 300,
            sweep_period_s: 86_400,
            probe_cooldown_s: 21_600,
            max_concurrent_agent_runs: 1,
            max_agent_runs_per_day: 8,
        }
    }

    fn counters(runs: u32, spend: u64) -> DayCounters {
        DayCounters {
            agent_runs: runs,
            spend_micro_usd: spend,
            ..DayCounters::default()
        }
    }

    #[test]
    fn the_run_cap_allows_one_under_and_refuses_at_and_over() {
        let s = schedule();
        assert_eq!(
            agent_budget(&s, &counters(7, 0), 750_000, 3_000_000),
            Ok(750_000)
        );
        assert_eq!(
            agent_budget(&s, &counters(8, 0), 750_000, 3_000_000),
            Err(Refusal::RunCap)
        );
        assert_eq!(
            agent_budget(&s, &counters(9, 0), 750_000, 3_000_000),
            Err(Refusal::RunCap)
        );
    }

    #[test]
    fn the_spend_ceiling_cuts_the_run_and_stops_at_the_day_ceiling() {
        let s = schedule();
        assert_eq!(
            agent_budget(&s, &counters(1, 2_500_000), 750_000, 3_000_000),
            Ok(500_000),
            "what is left of the day"
        );
        assert_eq!(
            agent_budget(&s, &counters(1, 2_999_999), 750_000, 3_000_000),
            Ok(1)
        );
        assert_eq!(
            agent_budget(&s, &counters(1, 3_000_000), 750_000, 3_000_000),
            Err(Refusal::SpendCeiling)
        );
        assert_eq!(
            agent_budget(&s, &counters(1, 3_000_001), 750_000, 3_000_000),
            Err(Refusal::SpendCeiling)
        );
    }

    #[test]
    fn the_cooldown_ends_exactly_at_its_time() {
        let s = schedule();
        let tripped = at("2026-11-20T09:00:00Z");
        let until = cooldown_until(&s, &tripped);
        assert_eq!(until, at("2026-11-20T15:00:00Z"));
        let state = ProbeState {
            probe_id: "retries".to_owned(),
            last_outcome: ProbeOutcome::Tripped,
            last_value: None,
            last_call_id: None,
            last_checked_at: tripped,
            last_tripped_at: Some(tripped),
            cooldown_until: Some(until),
        };
        assert!(!past_cooldown(Some(&state), &at("2026-11-20T14:59:59Z")));
        assert!(past_cooldown(Some(&state), &at("2026-11-20T15:00:00Z")));
        assert!(past_cooldown(None, &at("2026-11-20T09:00:00Z")));
    }

    #[test]
    fn the_sweep_comes_due_one_period_after_the_last_or_after_the_start() {
        let s = schedule();
        let start = at("2026-11-20T00:00:00Z");
        assert!(!sweep_due(&s, None, &start, &at("2026-11-20T23:59:59Z")));
        assert!(sweep_due(&s, None, &start, &at("2026-11-21T00:00:00Z")));
        let last = at("2026-11-21T06:00:00Z");
        assert!(!sweep_due(
            &s,
            Some(&last),
            &start,
            &at("2026-11-22T05:59:59Z")
        ));
        assert!(sweep_due(
            &s,
            Some(&last),
            &start,
            &at("2026-11-22T06:00:00Z")
        ));
    }

    #[test]
    fn new_issues_stop_at_the_cap() {
        let at_cap = DayCounters {
            new_issues: 3,
            ..DayCounters::default()
        };
        let under = DayCounters {
            new_issues: 2,
            ..DayCounters::default()
        };
        assert!(may_open_issue(3, &under));
        assert!(!may_open_issue(3, &at_cap));
    }

    #[test]
    fn one_comment_a_day_and_a_new_utc_day_counts_again() {
        let entry = IssueEntry {
            fingerprint: Sha256Digest::of(b"f"),
            category: "retries".to_owned(),
            component: "worker".to_owned(),
            title: "t".to_owned(),
            repository: "example-org/fixture".to_owned(),
            issue_number: 1,
            opened_at: at("2026-11-20T00:00:00Z"),
            last_comment_day: Some("2026-11-20".to_owned()),
            comments_on_last_day: 1,
        };
        assert!(!may_comment(1, Some(&entry), &at("2026-11-20T23:59:59Z")));
        assert!(may_comment(1, Some(&entry), &at("2026-11-21T00:00:00Z")));
        assert!(may_comment(2, Some(&entry), &at("2026-11-20T12:00:00Z")));
        assert!(may_comment(1, None, &at("2026-11-20T12:00:00Z")));
    }
}
