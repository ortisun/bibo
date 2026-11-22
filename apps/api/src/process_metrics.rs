//! `GET /v1/process-metrics/snapshot`: the process numbers of the caller's tenant over a window,
//! as a `measurement` entry (ADR 0029).
//!
//! The rules are in the section "How a person asks for a snapshot" of
//! `docs/architecture/process-metrics-and-improvement.md`. The handler stores nothing: it runs the
//! snapshot job of `factory_workflow::process_metrics` in a transaction of the caller's tenant and
//! rolls it back.

use std::time::Duration;

use factory_domain::metrics::{ComparisonSettings, Window};
use factory_domain::values::{GitSha, Timestamp};
use factory_workflow::process_metrics::{SnapshotError, process_snapshot};
use serde_json::json;

use crate::answers::{Answer, ApiError, Reply};
use crate::auth::Caller;
use crate::state::ApiState;

/// The longest window a snapshot is computed for: 366 days.
const LONGEST_WINDOW: Duration = Duration::from_secs(366 * 24 * 60 * 60);

/// The commit this build was made from, when the build said so in `FACTORY_BUILD_COMMIT`. A value
/// that is not a full Git object id counts as none. The worker's weekly measurement reads the
/// same value, from the same function.
pub use factory_composition::knowledge_measurements::build_commit;

/// Reads `from` and `to` from the query. Each must be there exactly once, nothing else may be, and
/// the window must be in order and at most 366 days long.
fn window_of(query: Option<&str>) -> Result<Window, ApiError> {
    let (mut from, mut to) = (None, None);
    for pair in query
        .unwrap_or("")
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        let (slot, field, value) = match pair.split_once('=') {
            Some(("from", value)) => (&mut from, "from", value),
            Some(("to", value)) => (&mut to, "to", value),
            _ => return Err(ApiError::BadRequest("query")),
        };
        // A timestamp needs no escaping in a query, so an escaped one is refused, not decoded.
        let instant = (value.len() <= 40)
            .then(|| Timestamp::parse(value).ok())
            .flatten()
            .ok_or(ApiError::BadRequest(field))?;
        if slot.replace(instant).is_some() {
            return Err(ApiError::BadRequest(field));
        }
    }
    let from = from.ok_or(ApiError::BadRequest("from"))?;
    let to = to.ok_or(ApiError::BadRequest("to"))?;
    let window = Window::new(from, to).map_err(|_| ApiError::BadRequest("to"))?;
    match to.duration_since(&from) {
        Some(length) if length <= LONGEST_WINDOW => Ok(window),
        _ => Err(ApiError::BadRequest("to")),
    }
}

/// The window of the same length right before `window`, when the calendar holds it.
fn window_before(window: Window) -> Option<Window> {
    let length = window.to().duration_since(&window.from())?;
    let start = window.from().checked_sub(length)?;
    Window::new(start, window.from()).ok()
}

/// The snapshot of the window `from` to `to` for the caller's tenant, computed by the build whose
/// commit is `commit`.
///
/// # Errors
/// `403` for a caller who is not on the allowlist, `400` naming the field for a window that cannot
/// be read, and `503` when the build does not know its commit, the store cannot be read, or a
/// stored fact cannot be right.
pub async fn snapshot(
    state: &ApiState,
    caller: &Caller,
    query: Option<&str>,
    commit: Option<GitSha>,
) -> Answer {
    caller.require_listed()?;
    let window = window_of(query)?;
    // A snapshot that cannot name the code that computed it cannot be computed again.
    let commit = commit.ok_or(ApiError::Unavailable)?;

    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let built = process_snapshot(
        tx.as_mut(),
        window,
        window_before(window),
        commit,
        ComparisonSettings::default(),
    )
    .await;
    let _ = tx.rollback().await;
    let measurement = built.map_err(|error| match error {
        SnapshotError::Store(store) => ApiError::from(store),
        // A fact that cannot be right, or a number outside its range: the entry is not handed out.
        SnapshotError::Metric(_) | SnapshotError::EndsBeforeItStarts { .. } => {
            tracing::error!(error = %error, "the process snapshot is refused");
            ApiError::Unavailable
        }
    })?;
    let entry = measurement
        .render_entry()
        .map_err(|_| ApiError::Unavailable)?;

    Ok(Reply::ok(json!({
        "id": measurement.window.identifier(),
        "path": measurement.entry_path(),
        "query_version": measurement.query_version,
        "computed_at_commit": measurement.computed_at_commit.as_str(),
        "window": {
            "from": measurement.window.from().as_text(),
            "to": measurement.window.to().as_text(),
        },
        "entry": entry,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("valid timestamp")
    }

    #[test]
    fn the_window_is_read_from_the_two_fields() {
        let window =
            window_of(Some("from=2026-11-16T00:00:00Z&to=2026-11-23T00:00:00Z")).expect("a week");
        assert_eq!(window.identifier(), "M-2026-W47");
        // The order of the fields does not matter.
        assert_eq!(
            window_of(Some("to=2026-11-23T00:00:00Z&from=2026-11-16T00:00:00Z")),
            Ok(window)
        );
    }

    #[test]
    fn a_window_that_cannot_be_read_names_its_field() {
        let cases = [
            (None, "from"),
            (Some(""), "from"),
            (Some("from=2026-11-16T00:00:00Z"), "to"),
            (Some("to=2026-11-23T00:00:00Z"), "from"),
            (Some("from=yesterday&to=2026-11-23T00:00:00Z"), "from"),
            (Some("from=2026-11-16T00:00:00Z&to=2026-11-16"), "to"),
            // An escaped colon is refused, not decoded.
            (
                Some("from=2026-11-16T00%3A00%3A00Z&to=2026-11-23T00:00:00Z"),
                "from",
            ),
            // Not in order, and of no length.
            (
                Some("from=2026-11-23T00:00:00Z&to=2026-11-16T00:00:00Z"),
                "to",
            ),
            (
                Some("from=2026-11-16T00:00:00Z&to=2026-11-16T00:00:00Z"),
                "to",
            ),
            // A field twice, and a field the route does not take.
            (
                Some("from=2026-11-16T00:00:00Z&from=2026-11-17T00:00:00Z&to=2026-11-23T00:00:00Z"),
                "from",
            ),
            (
                Some("from=2026-11-16T00:00:00Z&to=2026-11-23T00:00:00Z&limit=5"),
                "query",
            ),
            (Some("from"), "query"),
        ];
        for (query, field) in cases {
            assert_eq!(
                window_of(query),
                Err(ApiError::BadRequest(field)),
                "{query:?}"
            );
        }
    }

    #[test]
    fn a_window_is_at_most_366_days_long() {
        // 2024 is a leap year: 2024-01-01 to 2025-01-01 is 366 days.
        assert!(window_of(Some("from=2024-01-01T00:00:00Z&to=2025-01-01T00:00:00Z")).is_ok());
        assert_eq!(
            window_of(Some("from=2024-01-01T00:00:00Z&to=2025-01-01T00:00:01Z")),
            Err(ApiError::BadRequest("to"))
        );
        assert!(window_of(Some("from=2026-11-16T00:00:00Z&to=2026-11-16T00:00:01Z")).is_ok());
    }

    #[test]
    fn the_window_before_has_the_same_length_and_ends_where_this_one_starts() {
        let week = Window::new(at("2026-11-16T00:00:00Z"), at("2026-11-23T00:00:00Z")).expect("ok");
        let before = window_before(week).expect("the week before");
        assert_eq!(
            (before.from(), before.to()),
            (at("2026-11-09T00:00:00Z"), at("2026-11-16T00:00:00Z"))
        );
        assert_eq!(before.identifier(), "M-2026-W46");
        let odd =
            Window::new(at("2026-11-16T10:00:00Z"), at("2026-11-16T10:00:01.5Z")).expect("ok");
        let before = window_before(odd).expect("the span before");
        assert_eq!(before.from(), at("2026-11-16T09:59:58.5Z"));
        // At the first date the calendar holds there is no window before.
        let first =
            Window::new(at("0000-01-01T00:00:00Z"), at("0000-01-02T00:00:00Z")).expect("ok");
        assert_eq!(window_before(first), None);
    }

    #[test]
    fn a_build_commit_is_a_full_git_object_id_or_none() {
        // The test build sets no commit unless the person who runs it does.
        match option_env!("FACTORY_BUILD_COMMIT") {
            Some(text) => assert_eq!(build_commit().is_some(), GitSha::parse(text).is_ok()),
            None => assert_eq!(build_commit(), None),
        }
    }
}
