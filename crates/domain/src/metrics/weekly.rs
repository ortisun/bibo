//! The rules of the weekly measurement pull request (ADR 0031): which week, whether to propose it,
//! and the text of the pull request.
//!
//! The contract is the section "The weekly measurement pull request" of
//! `docs/architecture/process-metrics-and-improvement.md`. Nothing here calls GitHub: the caller
//! hands in what the newest pull request is, and gets the decision.

use std::time::Duration;

use super::MetricError;
use super::measurement::Window;
use crate::knowledge::{EntryId, EntryKind};
use crate::values::Timestamp;

/// One week, in seconds.
const WEEK: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// The last whole ISO week before `now`: from the Monday 00:00 UTC of the week before the current
/// one, to the Monday 00:00 UTC of the current one.
///
/// # Errors
/// [`MetricError::OutOfRange`] when the week falls outside the dates a timestamp holds.
pub fn last_whole_week(now: Timestamp) -> Result<Window, MetricError> {
    let out_of_range = || MetricError::OutOfRange {
        what: "the last whole week",
    };
    let midnight = now.start_of_utc_day();
    let days_since_monday = u64::from(midnight.to_utc().weekday().number_days_from_monday());
    let this_monday = midnight
        .checked_sub(Duration::from_secs(days_since_monday * 24 * 60 * 60))
        .ok_or_else(out_of_range)?;
    let last_monday = this_monday.checked_sub(WEEK).ok_or_else(out_of_range)?;
    Window::new(last_monday, this_monday)
}

/// The state of a measurement pull request, as the code host reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProposalState {
    /// Waiting for a person.
    Open,
    /// A person merged it.
    Merged,
    /// A person closed it without a merge.
    Closed,
}

/// The newest measurement pull request of the factory, and the week its marker names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestMeasurement {
    /// Its state.
    pub state: ProposalState,
    /// The week of its marker, or `None` when the marker is missing.
    pub week: Option<EntryId>,
}

/// Why nothing is proposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NothingBecause {
    /// The open pull request already holds this week or a later one.
    AlreadyProposed,
    /// A merged pull request holds this week or a later one.
    Recorded,
    /// A person closed the pull request that held this week or a later one.
    Declined,
}

/// What to do with the week.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WeeklyDecision {
    /// Open a new pull request from the tip of the default branch.
    OpenNew,
    /// Add the week on top of the open pull request.
    AddToOpen,
    /// Propose nothing.
    Nothing(NothingBecause),
}

/// The decision of the design's table for `week`, given the newest measurement pull request.
/// Weeks compare by their identifier, which sorts as the weeks do (`M-2025-W52` before
/// `M-2026-W01`).
pub fn decide(latest: Option<&LatestMeasurement>, week: &EntryId) -> WeeklyDecision {
    let Some(latest) = latest else {
        return WeeklyDecision::OpenNew;
    };
    let covered = latest
        .week
        .as_ref()
        .is_some_and(|proposed| proposed.as_str() >= week.as_str());
    match (latest.state, covered) {
        (ProposalState::Open, true) => WeeklyDecision::Nothing(NothingBecause::AlreadyProposed),
        (ProposalState::Open, false) => WeeklyDecision::AddToOpen,
        (ProposalState::Merged, true) => WeeklyDecision::Nothing(NothingBecause::Recorded),
        (ProposalState::Closed, true) => WeeklyDecision::Nothing(NothingBecause::Declined),
        (ProposalState::Merged | ProposalState::Closed, false) => WeeklyDecision::OpenNew,
    }
}

/// The title and the body of the measurement pull request, from a closed template. `held` is every
/// week the pull request holds after this proposal, the newest last. Only identifiers of weeks
/// and fixed text go in, so nothing written by a person or a model reaches the pull request.
///
/// # Errors
/// [`MetricError::RowDoesNotFit`] when `held` is empty or holds an identifier that is not a
/// measurement.
pub fn pull_request_text(
    window: Window,
    held: &[EntryId],
) -> Result<(String, String), MetricError> {
    let refuse = |reason| MetricError::RowDoesNotFit {
        metric: "the weekly measurement",
        statistic: "pull request",
        reason,
    };
    if held.is_empty() {
        return Err(refuse("a measurement pull request holds at least one week"));
    }
    if held.iter().any(|id| id.kind() != EntryKind::Measurement) {
        return Err(refuse("a measurement pull request holds measurements only"));
    }
    let title = format!(
        "Record the process numbers of {}",
        window.title().trim_start_matches("Process numbers, ")
    );
    let weeks: Vec<String> = held
        .iter()
        .map(|id| format!("- `docs/knowledge/measurements/{id}.md`"))
        .collect();
    let count = if held.len() == 1 {
        "one week".to_owned()
    } else {
        format!("{} weeks", held.len())
    };
    let body = format!(
        "The factory measured its own process in this project and records the numbers in the knowledge base \
         (ADR 0029). This pull request holds {count}:\n\n{}\n\n\
         Each entry names the commit of the factory that computed it and the version of its queries, so the \
         numbers can be computed again. A metric with fewer than its minimum of samples shows \"too few samples\" \
         instead of a number.\n\n\
         A person reviews and merges this pull request; the factory never merges. Closing it without a merge \
         declines the weeks it holds, and the factory proposes the next week again.",
        weeks.join("\n")
    );
    Ok((title, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("valid timestamp")
    }

    fn week(text: &str) -> EntryId {
        EntryId::parse(text).expect("valid identifier")
    }

    #[test]
    fn the_last_whole_week_ends_at_this_mondays_midnight() {
        // Saturday 2026-11-21: the last whole week is week 46, 2026-11-09 to 2026-11-16.
        for now in [
            "2026-11-21T13:05:00Z",
            "2026-11-16T00:00:00Z",
            "2026-11-22T23:59:59.999Z",
        ] {
            let window = last_whole_week(at(now)).expect("a week");
            assert_eq!(
                (window.from(), window.to()),
                (at("2026-11-09T00:00:00Z"), at("2026-11-16T00:00:00Z")),
                "{now}"
            );
            assert_eq!(window.identifier(), "M-2026-W46", "{now}");
        }
        // One nanosecond before Monday is still the week before.
        let before = last_whole_week(at("2026-11-15T23:59:59.999999999Z")).expect("a week");
        assert_eq!(before.identifier(), "M-2026-W45");
        // Across the year: Monday 2026-01-05 gives week 1 of 2026, which began on 2025-12-29.
        assert_eq!(
            last_whole_week(at("2026-01-05T08:00:00Z"))
                .expect("a week")
                .identifier(),
            "M-2026-W01"
        );
        assert_eq!(
            last_whole_week(at("2026-01-04T08:00:00Z"))
                .expect("a week")
                .identifier(),
            "M-2025-W52"
        );
        // The first days the calendar holds have no whole week before them.
        assert!(last_whole_week(at("0000-01-03T00:00:00Z")).is_err());
    }

    #[test]
    fn the_decision_is_the_table_of_the_design() {
        let w47 = week("M-2026-W47");
        let latest = |state, proposed: Option<&str>| LatestMeasurement {
            state,
            week: proposed.map(week),
        };
        use NothingBecause::{AlreadyProposed, Declined, Recorded};
        use ProposalState::{Closed, Merged, Open};
        use WeeklyDecision::{AddToOpen, Nothing, OpenNew};
        let cases = [
            (None, OpenNew),
            (Some(latest(Open, Some("M-2026-W46"))), AddToOpen),
            (
                Some(latest(Open, Some("M-2026-W47"))),
                Nothing(AlreadyProposed),
            ),
            (
                Some(latest(Open, Some("M-2026-W48"))),
                Nothing(AlreadyProposed),
            ),
            (Some(latest(Merged, Some("M-2026-W46"))), OpenNew),
            (Some(latest(Merged, Some("M-2026-W47"))), Nothing(Recorded)),
            (Some(latest(Closed, Some("M-2026-W46"))), OpenNew),
            (Some(latest(Closed, Some("M-2026-W47"))), Nothing(Declined)),
            (Some(latest(Open, None)), AddToOpen),
            (Some(latest(Merged, None)), OpenNew),
            (Some(latest(Closed, None)), OpenNew),
        ];
        for (found, expected) in cases {
            assert_eq!(decide(found.as_ref(), &w47), expected, "{found:?}");
        }
        // Weeks compare across years.
        let new_year = week("M-2026-W01");
        assert_eq!(
            decide(Some(&latest(Merged, Some("M-2025-W52"))), &new_year),
            OpenNew
        );
        assert_eq!(
            decide(Some(&latest(Merged, Some("M-2026-W01"))), &new_year),
            Nothing(Recorded)
        );
    }

    #[test]
    fn the_text_names_every_week_it_holds_and_says_who_merges() {
        let window = last_whole_week(at("2026-11-23T10:00:00Z")).expect("a week");
        let (title, body) =
            pull_request_text(window, &[week("M-2026-W46"), week("M-2026-W47")]).expect("text");
        assert_eq!(title, "Record the process numbers of week 47 of 2026");
        assert!(body.contains("This pull request holds 2 weeks:\n\n- `docs/knowledge/measurements/M-2026-W46.md`\n- `docs/knowledge/measurements/M-2026-W47.md`\n"));
        assert!(body.contains("the factory never merges"));
        let (_, one) = pull_request_text(window, &[week("M-2026-W47")]).expect("text");
        assert!(one.contains("holds one week:"));
        assert!(pull_request_text(window, &[]).is_err());
        assert!(pull_request_text(window, &[week("BR-0001")]).is_err());
    }
}
