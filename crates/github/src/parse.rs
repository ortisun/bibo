//! Reading GitHub's JSON into the port types, and the paths of the API.
//!
//! The rules here are the ones that protect authority: a person is identified by the numeric id,
//! never by the login, and a missing or odd field is an error and not a default that could pass a
//! check.

use factory_domain::values::Timestamp;
use factory_ports::githost::{AccountType, ActorLogin, GitHostError, GithubActor};
use factory_ports::paths::RepoRef;
use serde_json::Value;

/// The id GitHub gives the placeholder account for a deleted user.
const GHOST_ID: u64 = 10_137;

/// `/repos/{owner}/{repo}`. The parts are checked by [`RepoRef`], so no encoding is needed.
pub(crate) fn repo_path(repo: &RepoRef) -> String {
    format!("/repos/{}/{}", repo.owner(), repo.name())
}

/// A person or bot from a `user` or `actor` object. `null` is the placeholder account of a
/// deleted user. The login is for display; a bot's `[bot]` suffix is dropped because the port's
/// login type cannot hold it, and a login that is still not valid is shown as `ghost`.
pub(crate) fn actor(value: &Value) -> Result<GithubActor, GitHostError> {
    if value.is_null() {
        return Ok(GithubActor {
            id: GHOST_ID,
            login: ghost(),
        });
    }
    let id = value["id"].as_u64().ok_or(GitHostError::Unavailable)?;
    let raw = value["login"].as_str().unwrap_or_default();
    let login =
        ActorLogin::new(raw.strip_suffix("[bot]").unwrap_or(raw)).unwrap_or_else(|_| ghost());
    Ok(GithubActor { id, login })
}

/// The kind of account of an `actor` object, from its `type` and its login. `null` is the
/// placeholder of a deleted account, which is not a person; so is an object with no `type`.
pub(crate) fn actor_type(value: &Value) -> AccountType {
    if value.is_null() {
        return AccountType::Other;
    }
    AccountType::from_host(
        value["type"].as_str(),
        value["login"].as_str().unwrap_or_default(),
    )
}

fn ghost() -> ActorLogin {
    ActorLogin::new("ghost").expect("the literal ghost is a valid login")
}

/// A timestamp field, which must be present and valid.
pub(crate) fn timestamp(value: &Value) -> Result<Timestamp, GitHostError> {
    value
        .as_str()
        .and_then(|text| Timestamp::parse(text).ok())
        .ok_or(GitHostError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_person_is_read_by_numeric_id_and_a_bot_login_loses_its_suffix() {
        let person = actor(&json!({"id": 77, "login": "maintainer"})).unwrap();
        assert_eq!((person.id, person.login.as_str()), (77, "maintainer"));
        let bot = actor(&json!({"id": 5, "login": "factory-app[bot]"})).unwrap();
        assert_eq!((bot.id, bot.login.as_str()), (5, "factory-app"));
    }

    #[test]
    fn a_deleted_user_is_the_ghost_and_a_missing_id_is_an_error() {
        let ghost = actor(&Value::Null).unwrap();
        assert_eq!((ghost.id, ghost.login.as_str()), (GHOST_ID, "ghost"));
        assert!(actor(&json!({"login": "x"})).is_err());
        assert!(actor(&json!({"id": "7", "login": "x"})).is_err());
    }

    #[test]
    fn an_odd_login_never_decides_who_a_person_is() {
        let odd = actor(&json!({"id": 9, "login": "not a login!"})).unwrap();
        assert_eq!((odd.id, odd.login.as_str()), (9, "ghost"));
    }

    #[test]
    fn timestamps_must_be_valid() {
        assert!(timestamp(&json!("2026-10-28T10:00:00Z")).is_ok());
        assert!(timestamp(&json!("yesterday")).is_err());
        assert!(timestamp(&json!(null)).is_err());
    }
}
