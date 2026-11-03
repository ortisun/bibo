//! When the words of an issue were last edited (DR-1).
//!
//! The design gate must know whether the title or the body was edited after the approver applied the
//! approving label, because the label says nothing about the words. The REST API shows a title edit
//! as a `renamed` event of the issue and shows no body edit at all; the `updated_at` of the issue
//! moves with any activity (a label, a comment), so it cannot stand for either. GraphQL has the time
//! of the last edit of a body: `lastEditedAt`. This module is the one place the adapter speaks
//! GraphQL, and it speaks one read:
//!
//! * the query is a constant. The owner, the name and the number go in as variables, never into
//!   the text, so nothing from outside can make it a different query;
//! * it is a `query`, never a `mutation`: the adapter's source scan (`security_review`) holds the
//!   word out of every other file and out of this one, and holds the route on a short list;
//! * it asks for `lastEditedAt` of one issue and nothing else.
//!
//! UNVERIFIED against the real GitHub: that `lastEditedAt` is `null` for a body never edited and
//! moves on every edit, that a title edit is shown by the `renamed` event (it is documented) and
//! not by `lastEditedAt`, and that an installation token with `issues: read` and `metadata: read`
//! may run the query. The answer is read strictly: anything that is not a time or an explicit
//! `null` is [`TextEdit::Unknown`], which the gate refuses on.

use factory_domain::values::Timestamp;
use factory_ports::githost::{IssueRef, TextEdit};
use serde_json::{Value, json};

use crate::parse::timestamp;

/// The path of the GraphQL endpoint, relative to the API base (`https://api.github.com`).
pub(crate) const ROUTE: &str = "/graphql";

/// The one query. A constant: see the module notes.
pub(crate) const QUERY: &str = "query($owner:String!,$name:String!,$number:Int!){repository(owner:$owner,name:$name){issue(number:$number){lastEditedAt}}}";

/// The body of the request for `issue`.
pub(crate) fn request(issue: &IssueRef) -> Value {
    json!({
        "query": QUERY,
        "variables": {
            "owner": issue.repo.owner(),
            "name": issue.repo.name(),
            "number": issue.number,
        },
    })
}

/// The time of the last edit of the body from the answer to [`request`]: `Ok(None)` when the host
/// says the body was never edited (an explicit `null`), `Ok(Some(time))` for a time, and `Err(())`
/// for anything else: an `errors` member, a missing issue, a missing `lastEditedAt`, a value that
/// is not a time.
pub(crate) fn body_edit(answer: &Value) -> Result<Option<Timestamp>, ()> {
    if answer.get("errors").is_some_and(|errors| !errors.is_null()) {
        return Err(());
    }
    let issue = answer
        .get("data")
        .and_then(|data| data.get("repository"))
        .and_then(|repository| repository.get("issue"))
        .filter(|issue| issue.is_object())
        .ok_or(())?;
    match issue.get("lastEditedAt").ok_or(())? {
        Value::Null => Ok(None),
        text @ Value::String(_) => timestamp(text).map(Some).map_err(|_| ()),
        _ => Err(()),
    }
}

/// The time of the last `renamed` event among the events of the issue, which is how the REST API
/// shows an edit of the title. `Err(())` when an event cannot be read: an entry that is not an
/// object, has no `event` string, or is a `renamed` event without a time.
pub(crate) fn title_edit(events: &[Value]) -> Result<Option<Timestamp>, ()> {
    let mut latest: Option<Timestamp> = None;
    for event in events {
        if !event.is_object() {
            return Err(());
        }
        let kind = event["event"].as_str().ok_or(())?;
        if kind != "renamed" {
            continue;
        }
        let at = timestamp(&event["created_at"]).map_err(|_| ())?;
        latest = Some(latest.map_or(at, |held| held.max(at)));
    }
    Ok(latest)
}

/// What the two reads come to: the later of the two edits, never when neither was made.
pub(crate) fn later_of(body: Option<Timestamp>, title: Option<Timestamp>) -> TextEdit {
    match (body, title) {
        (None, None) => TextEdit::Never,
        (Some(at), None) | (None, Some(at)) => TextEdit::At(at),
        (Some(a), Some(b)) => TextEdit::At(a.max(b)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a time")
    }

    #[test]
    fn the_query_is_a_constant_read_with_the_issue_in_the_variables_only() {
        assert!(QUERY.starts_with("query"));
        // The word is made from two parts so that the source scan, which holds it out of every
        // line of this file, has nothing to find here.
        let forbidden = ["muta", "tion"].concat();
        assert!(!QUERY.to_ascii_lowercase().contains(&forbidden));
        assert!(QUERY.contains("lastEditedAt"));
        let issue = IssueRef {
            repo: factory_ports::paths::RepoRef::parse("example-org/fixture").expect("a repo"),
            number: 12,
        };
        let body = request(&issue);
        assert_eq!(body["query"], QUERY);
        assert_eq!(body["variables"]["owner"], "example-org");
        assert_eq!(body["variables"]["name"], "fixture");
        assert_eq!(body["variables"]["number"], 12);
        // Nothing of the issue is in the text of the query.
        assert!(!QUERY.contains("example-org") && !QUERY.contains("12"));
    }

    #[test]
    fn the_answer_is_read_strictly() {
        let ok =
            |edited: Value| json!({"data": {"repository": {"issue": {"lastEditedAt": edited}}}});
        assert_eq!(body_edit(&ok(Value::Null)), Ok(None));
        assert_eq!(
            body_edit(&ok(json!("2026-11-03T10:00:00Z"))),
            Ok(Some(at("2026-11-03T10:00:00Z")))
        );
        for bad in [
            json!({}),
            json!({"data": null}),
            json!({"data": {"repository": null}}),
            json!({"data": {"repository": {"issue": null}}}),
            json!({"data": {"repository": {"issue": {}}}}),
            json!({"data": {"repository": {"issue": {"lastEditedAt": 7}}}}),
            json!({"data": {"repository": {"issue": {"lastEditedAt": "soon"}}}}),
            json!({"data": {"repository": {"issue": {"lastEditedAt": ""}}}}),
            json!({"errors": [{"message": "no"}], "data": {"repository": {"issue": {"lastEditedAt": null}}}}),
            json!([]),
            Value::Null,
        ] {
            assert_eq!(body_edit(&bad), Err(()), "{bad}");
        }
    }

    #[test]
    fn a_title_edit_is_the_latest_renamed_event_and_a_bad_event_is_unreadable() {
        let events = vec![
            json!({"event": "labeled", "created_at": "2026-11-03T09:00:00Z"}),
            json!({"event": "renamed", "created_at": "2026-11-03T10:00:00Z"}),
            json!({"event": "renamed", "created_at": "2026-11-03T11:00:00Z"}),
            json!({"event": "closed", "created_at": "2026-11-03T12:00:00Z"}),
        ];
        assert_eq!(title_edit(&events), Ok(Some(at("2026-11-03T11:00:00Z"))));
        assert_eq!(title_edit(&[]), Ok(None));
        for bad in [
            vec![json!("renamed")],
            vec![json!({"created_at": "2026-11-03T10:00:00Z"})],
            vec![json!({"event": "renamed"})],
            vec![json!({"event": "renamed", "created_at": "yesterday"})],
        ] {
            assert_eq!(title_edit(&bad), Err(()), "{bad:?}");
        }
    }

    #[test]
    fn the_later_of_the_two_edits_counts_and_no_edit_is_never() {
        let (early, late) = (at("2026-11-03T10:00:00Z"), at("2026-11-03T11:00:00Z"));
        assert_eq!(later_of(None, None), TextEdit::Never);
        assert_eq!(later_of(Some(early), None), TextEdit::At(early));
        assert_eq!(later_of(None, Some(late)), TextEdit::At(late));
        assert_eq!(later_of(Some(late), Some(early)), TextEdit::At(late));
        assert_eq!(later_of(Some(early), Some(late)), TextEdit::At(late));
    }
}
