//! Registering a repository, attesting its project map, enabling it and disabling it.
//!
//! The factory takes tickets from a GitHub repository only after a person has installed the
//! workflow into the project, mapped it and read the map (ADR 0016, the onboarding guide). This
//! module is how that path reaches the engine:
//!
//! 1. **Register** (`POST /v1/repositories`). The repository exists, switched off, at autonomy level
//!    `L0`, with no project map. Nothing in the request can change those three facts: the body
//!    refuses unknown fields, and the database login of the API is granted only the six columns a
//!    registration writes.
//! 2. **Attest the project map** (`POST /v1/repositories/{id}/project-map`). A person says that
//!    commit `C` of the default branch holds the project map, and why they are able to say so.
//! 3. **Enable** (`POST /v1/repositories/{id}/enable`). Refused with the code
//!    `project_map_not_attested` until step 2 happened. The table refuses the same change for every
//!    role, so this check is a clear answer and not the only guard.
//! 4. **Disable** (`POST /v1/repositories/{id}/disable`). A webhook and a job submission for a
//!    disabled repository are dropped by the code that already reads `repositories.enabled`.
//!
//! # An attestation is not a verification
//!
//! The API holds **no GitHub credential**. It cannot read the repository, so it cannot check that
//! the commit exists, that it is on the default branch, that the map files are there or that they
//! are any good. What it records is a person's statement: who, when (the database clock), which
//! commit and the reason they gave. Every record, answer and document says so, and no part of this
//! module may be changed to suggest otherwise. If the engine ever gets a way to look, that is a new
//! check with its own name and its own tests.
//!
//! # Who
//!
//! The designation each action needs is read from the `actions` table of `policies/approval.yaml`
//! (`register_repository`, `confirm_project_map`, `enable_repository`, `disable_repository`), by the
//! numeric GitHub id of the principal behind the token, as for a decision. A caller without it is
//! answered 403 with no reason, and the attempt is audited within the bounds of API-8. An allowlist
//! entry narrowed to other repositories is refused as one without the designation (API-1).
//!
//! # Exactly once
//!
//! Every change carries an `Idempotency-Key`. The audit record that goes with it has an id derived
//! from the tenant, the caller, the repository and the key, and the same key with the same request
//! finds that record and changes nothing. The same key with a different request is a conflict. The
//! change and its audit record are written in one transaction, so there is no change without a
//! record and no record without a change.

use axum::http::{HeaderMap, StatusCode};
use factory_domain::ids::{AuditEventId, CorrelationId, RepositoryId};
use factory_domain::values::Sha256Digest;
use factory_ports::store::{
    AuditActor, AuditDecision, ConstraintRule, GithubRepositoryId, IdempotencyKey, InstallationId,
    NewAuditEvent, NewRepository, ProjectMapCommit, Repository, StoreError, Tx, Versioned, Witness,
};
use factory_workflow::gates::supply_chain::approval::{MAX_REASON_CHARS, MIN_REASON_CHARS};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::answers::{Answer, ApiError, Reply};
use crate::auth::{Caller, require_repository};
use crate::decisions::{refuse, roles_of_action};
use crate::jobs::{audit_action, clean_text, commit, decode, idempotency_key, parse_id};
use crate::state::ApiState;
use crate::tokens;

/// The action of the policy table that registering a repository needs.
pub const REGISTER: &str = "register_repository";
/// The action of the policy table that attesting a project map needs.
pub const CONFIRM_MAP: &str = "confirm_project_map";
/// The action of the policy table that enabling a repository needs.
pub const ENABLE: &str = "enable_repository";
/// The action of the policy table that disabling a repository needs.
pub const DISABLE: &str = "disable_repository";

/// The longest a default branch name may be, in bytes (the column's own limit).
const MAX_BRANCH_BYTES: usize = 255;
/// The longest `owner/name` a registration accepts. GitHub allows 39 and 100 characters.
const MAX_FULL_NAME_BYTES: usize = 140;
/// The most bytes of an audit reason (the store's limit is 1000).
const REASON_BYTES: usize = 1000;

/// The body of `POST /v1/repositories`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterBody {
    installation_id: u64,
    github_repository_id: u64,
    full_name: String,
    default_branch: String,
}

/// The body of `POST /v1/repositories/{id}/project-map`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestBody {
    commit: String,
    reason: String,
}

/// The body of `POST /v1/repositories/{id}/enable` and `.../disable`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeBody {
    #[serde(default)]
    reason: Option<String>,
}

/// A UUID derived from the tenant, the caller, what the change is for and the caller's key. The
/// same five always give the same value, and two callers who send one key get two values.
fn derived(tag: &str, caller: &Caller, subject: &str, key: &IdempotencyKey) -> uuid::Uuid {
    let digest = Sha256Digest::of(
        format!(
            "{tag}\n{}\n{}\n{subject}\n{}",
            caller.tenant.as_text(),
            caller.principal.as_text(),
            key.as_str()
        )
        .as_bytes(),
    );
    let hash = tokens::digest_bytes(&digest);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

/// `owner/name` as the table checks it, and no longer than GitHub allows.
fn is_full_name(text: &str) -> bool {
    let word = |part: &str| {
        !part.is_empty()
            && part != "."
            && part != ".."
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    };
    text.len() <= MAX_FULL_NAME_BYTES
        && text
            .split_once('/')
            .is_some_and(|(owner, name)| word(owner) && word(name))
}

/// A branch name as the API accepts it: letters, digits and `. _ / -`, no empty part, no `..`.
fn is_branch(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_BRANCH_BYTES
        && !text.starts_with(['-', '/'])
        && !text.ends_with('/')
        && !text.contains("..")
        && !text.contains("//")
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'/'))
}

/// The reason of a change, trimmed and checked: 10 to 500 characters, text, and no secret.
fn checked_reason(state: &ApiState, text: &str) -> Result<String, ApiError> {
    let reason = text.trim();
    let length = reason.chars().count();
    if !(MIN_REASON_CHARS..=MAX_REASON_CHARS).contains(&length)
        || !clean_text(reason)
        || state
            .redactor
            .contains_secret(reason.as_bytes())
            .unwrap_or(true)
    {
        return Err(ApiError::BadRequest("reason"));
    }
    Ok(reason.to_owned())
}

/// The optional reason of an enable or a disable.
fn optional_reason(state: &ApiState, text: Option<&str>) -> Result<Option<String>, ApiError> {
    text.map(|text| checked_reason(state, text)).transpose()
}

/// `fixed` followed by `reason`, cut at a character boundary so the whole fits the audit column.
fn with_reason(fixed: &str, reason: Option<&str>) -> String {
    let Some(reason) = reason else {
        return fixed.to_owned();
    };
    let mut text = format!("{fixed} Reason given: ");
    let room = REASON_BYTES.saturating_sub(text.len());
    let mut end = reason.len().min(room);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    text.push_str(&reason[..end]);
    text
}

/// The repository as the API shows it. The attestation names what it is: a person's statement,
/// not checked by the engine.
fn repository_json(row: &Versioned<Repository>) -> Value {
    let repository = &row.value;
    let map = repository.project_map.as_ref().map(|map| {
        json!({
            "commit": map.commit.as_str(),
            "attested_by": map.attested_by.as_text(),
            "attested_at": map.attested_at.as_text(),
            "verified_by_engine": false,
        })
    });
    json!({
        "repository_id": repository.id.as_text(),
        "full_name": repository.full_name,
        "default_branch": repository.default_branch,
        "github_installation_id": repository.installation.0,
        "github_repository_id": repository.github_repository_id.0,
        "enabled": repository.enabled,
        "protection_preflight_passed": repository.protection_preflight_passed,
        "autonomy_ceiling": repository.autonomy_ceiling.as_str(),
        "version": row.version.get(),
        "project_map": map,
    })
}

fn changed(row: &Versioned<Repository>, did_change: bool, status: StatusCode) -> Reply {
    Reply::new(
        status,
        json!({"repository": repository_json(row), "changed": did_change}),
    )
}

/// Opens the caller's transaction and settles who may do this.
///
/// The role comes first and does not depend on the repository, so a person without it learns
/// nothing about the tenant's repositories. Then the repository is read (another tenant's looks
/// missing) and the allowlist entry of the caller is checked against its name. A refusal is
/// audited and answered 403 with no reason by [`refuse`].
async fn open(
    state: &ApiState,
    caller: &Caller,
    action: &str,
    repository: Option<RepositoryId>,
    named: Option<&str>,
    refused_as: String,
) -> Result<(Box<dyn Tx>, Option<Versioned<Repository>>), ApiError> {
    let needed = roles_of_action(state, action);
    let mut allowed = caller.require_any(&needed).is_ok();
    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let mut found = None;
    if allowed {
        if let Some(id) = repository {
            let row = tx.get_repository(id).await?;
            if narrowed_away(state, caller, &row.value.full_name)? {
                allowed = false;
            }
            found = Some(row);
        } else if let Some(name) = named
            && narrowed_away(state, caller, name)?
        {
            allowed = false;
        }
    }
    if !allowed {
        let correlation = CorrelationId::from_uuid(state.ports.ids.new_uuid());
        return Err(refuse(state, caller, tx, refused_as, correlation)
            .await
            .err()
            .unwrap_or(ApiError::Forbidden));
    }
    Ok((tx, found))
}

/// True when the caller's allowlist entry is narrowed to other repositories than `full_name`.
fn narrowed_away(state: &ApiState, caller: &Caller, full_name: &str) -> Result<bool, ApiError> {
    match require_repository(state, caller, full_name) {
        Ok(()) => Ok(false),
        Err(ApiError::Forbidden) => Ok(true),
        Err(other) => Err(other),
    }
}

/// Settles whether the request was recorded before. `true` is a replay of the same request, and
/// the same key with a different request is a conflict.
async fn is_replay(tx: &mut dyn Tx, event: &NewAuditEvent) -> Result<bool, ApiError> {
    match tx.find_audit(event.id).await? {
        None => Ok(false),
        Some(record) if record.event == *event => Ok(true),
        Some(_) => Err(ApiError::Conflict),
    }
}

fn event(
    state: &ApiState,
    caller: &Caller,
    key: &IdempotencyKey,
    action: &str,
    repository: RepositoryId,
    subject: String,
    reason: String,
) -> Result<NewAuditEvent, ApiError> {
    let subject_key = repository.as_text();
    Ok(NewAuditEvent {
        id: AuditEventId::from_uuid(derived(action, caller, &subject_key, key)),
        actor: AuditActor::Human(caller.principal),
        action: audit_action(action)?,
        subject,
        decision: AuditDecision::Record,
        reason,
        policy_hash: state.policy_hash(),
        job: None,
        stage_run: None,
        correlation_id: CorrelationId::from_uuid(derived(
            "repository-correlation",
            caller,
            &subject_key,
            key,
        )),
    })
}

/// Records the audit event and commits, with the event as the witness of the commit.
async fn finish(
    state: &ApiState,
    caller: &Caller,
    mut tx: Box<dyn Tx>,
    audit: NewAuditEvent,
) -> Result<(), ApiError> {
    let id = audit.id;
    match tx.record_audit(audit).await {
        Ok(_) => {}
        Err(StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent)) => {
            return Err(ApiError::Conflict);
        }
        Err(other) => return Err(other.into()),
    }
    commit(state, caller.scope(), tx, Witness::Audit(id)).await
}

/// `POST /v1/repositories`.
pub async fn register(
    state: &ApiState,
    caller: &Caller,
    headers: &HeaderMap,
    body: &[u8],
) -> Answer {
    let key = idempotency_key(headers)?;
    let parsed: RegisterBody = decode(body)?;
    if parsed.installation_id == 0 || i64::try_from(parsed.installation_id).is_err() {
        return Err(ApiError::BadRequest("installation_id"));
    }
    if parsed.github_repository_id == 0 || i64::try_from(parsed.github_repository_id).is_err() {
        return Err(ApiError::BadRequest("github_repository_id"));
    }
    if !is_full_name(&parsed.full_name) {
        return Err(ApiError::BadRequest("full_name"));
    }
    if !is_branch(&parsed.default_branch) {
        return Err(ApiError::BadRequest("default_branch"));
    }

    // The id follows the caller and the key only, so that the same key with another request finds
    // the record of the first and is a conflict, as it is for a job and for a decision.
    let id = RepositoryId::from_uuid(derived("repository", caller, "", &key));
    let refused_as = format!("repository.register name={}", parsed.full_name);
    let (mut tx, _) = open(
        state,
        caller,
        REGISTER,
        None,
        Some(&parsed.full_name),
        refused_as,
    )
    .await?;
    let audit = event(
        state,
        caller,
        &key,
        "repository.registered",
        id,
        format!("repository {} {}", id.as_text(), parsed.full_name),
        "A person registered the repository. It starts disabled, at autonomy level L0, with no project map. The engine did not look at the repository: the installation, the GitHub repository id and the name are what the person gave."
            .to_owned(),
    )?;
    if is_replay(&mut *tx, &audit).await? {
        let row = tx.get_repository(id).await?;
        let _ = tx.rollback().await;
        return Ok(changed(&row, false, StatusCode::OK));
    }
    let registered = tx
        .register_repository(NewRepository {
            id,
            installation: InstallationId(parsed.installation_id),
            github_repository_id: GithubRepositoryId(parsed.github_repository_id),
            full_name: parsed.full_name,
            default_branch: parsed.default_branch,
        })
        .await
        .map_err(|error| match error {
            // A GitHub repository that is already registered, here or by another tenant, is
            // reported as "not found" by the store (NT-TEN-05). On this route that would read as
            // an unknown route, so it is a conflict, and it does not say whose.
            StoreError::NotFound
            | StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent) => {
                ApiError::Conflict
            }
            other => other.into(),
        })?;
    let status = if registered.created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    finish(state, caller, tx, audit).await?;
    Ok(changed(&registered.row, registered.created, status))
}

/// `GET /v1/repositories/{repository_id}`.
pub async fn show(state: &ApiState, caller: &Caller, repository_id: &str) -> Answer {
    caller.require_listed()?;
    let id = parse_id(repository_id, RepositoryId::parse).ok_or(ApiError::NotFound)?;
    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let found = tx.get_repository(id).await;
    let _ = tx.rollback().await;
    Ok(Reply::ok(repository_json(&found?)))
}

/// `POST /v1/repositories/{repository_id}/project-map`.
pub async fn attest_map(
    state: &ApiState,
    caller: &Caller,
    repository_id: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Answer {
    let id = parse_id(repository_id, RepositoryId::parse).ok_or(ApiError::NotFound)?;
    let key = idempotency_key(headers)?;
    let parsed: AttestBody = decode(body)?;
    let map_commit =
        ProjectMapCommit::new(&parsed.commit).map_err(|_| ApiError::BadRequest("commit"))?;
    let reason = checked_reason(state, &parsed.reason)?;

    let refused_as = format!("repository.confirm_project_map repository={}", id.as_text());
    let (mut tx, found) = open(state, caller, CONFIRM_MAP, Some(id), None, refused_as).await?;
    let row = found.ok_or(ApiError::NotFound)?;
    let audit = event(
        state,
        caller,
        &key,
        "repository.map_attested",
        id,
        format!(
            "repository {} project map commit {} attested by {}",
            id.as_text(),
            map_commit.as_str(),
            caller.principal.as_text()
        ),
        with_reason(
            &format!(
                "Attestation by a person, not a verification. The person says that commit {} of the default branch holds the project map. The engine holds no GitHub credential and did not read the repository.",
                map_commit.as_str()
            ),
            Some(&reason),
        ),
    )?;
    if is_replay(&mut *tx, &audit).await? {
        let current = tx.get_repository(id).await?;
        let _ = tx.rollback().await;
        return Ok(changed(&current, false, StatusCode::OK));
    }
    tx.attest_project_map(id, row.version, map_commit, caller.principal)
        .await
        .map_err(refusal_of_store)?;
    let current = tx.get_repository(id).await?;
    finish(state, caller, tx, audit).await?;
    Ok(changed(&current, true, StatusCode::OK))
}

/// `POST /v1/repositories/{repository_id}/enable` and `.../disable`.
pub async fn switch(
    state: &ApiState,
    caller: &Caller,
    repository_id: &str,
    headers: &HeaderMap,
    body: &[u8],
    enable: bool,
) -> Answer {
    let id = parse_id(repository_id, RepositoryId::parse).ok_or(ApiError::NotFound)?;
    let key = idempotency_key(headers)?;
    let parsed: ChangeBody = decode(body)?;
    let reason = optional_reason(state, parsed.reason.as_deref())?;

    let (action, name, verb) = if enable {
        (ENABLE, "repository.enabled", "enable")
    } else {
        (DISABLE, "repository.disabled", "disable")
    };
    let refused_as = format!("repository.{verb} repository={}", id.as_text());
    let (mut tx, found) = open(state, caller, action, Some(id), None, refused_as).await?;
    let row = found.ok_or(ApiError::NotFound)?;
    let fixed = if enable {
        match &row.value.project_map {
            Some(map) => format!(
                "A person enabled the repository. It has a project map that a person attested at commit {}. The engine did not verify that map.",
                map.commit.as_str()
            ),
            // The clear answer. The table would refuse this change as well.
            None => return Err(ApiError::ProjectMapNotAttested),
        }
    } else {
        "A person disabled the repository. Its webhooks are dropped and no job can be submitted for it.".to_owned()
    };
    let audit = event(
        state,
        caller,
        &key,
        name,
        id,
        format!("repository {} {}", id.as_text(), verb_past(enable)),
        with_reason(&fixed, reason.as_deref()),
    )?;
    if is_replay(&mut *tx, &audit).await? {
        let current = tx.get_repository(id).await?;
        let _ = tx.rollback().await;
        return Ok(changed(&current, false, StatusCode::OK));
    }
    tx.set_repository_enabled(id, row.version, enable)
        .await
        .map_err(refusal_of_store)?;
    let current = tx.get_repository(id).await?;
    finish(state, caller, tx, audit).await?;
    Ok(changed(&current, true, StatusCode::OK))
}

const fn verb_past(enable: bool) -> &'static str {
    if enable { "enabled" } else { "disabled" }
}

/// What a store refusal of a repository change is to the caller. A rule of the project map is
/// the typed answer. A stale version is a conflict. A mistake of the caller is never a fault.
fn refusal_of_store(error: StoreError) -> ApiError {
    match error {
        StoreError::Constraint(ConstraintRule::ProjectMapRule) => ApiError::ProjectMapNotAttested,
        other => other.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_name_is_owner_slash_name_and_nothing_else() {
        for good in ["octo/hello", "a/b", "my-org/my.repo_1", "O/n"] {
            assert!(is_full_name(good), "{good}");
        }
        for bad in [
            "", "octo", "octo/", "/hello", "a/b/c", "a b/c", "a/b c", "a/b\n", "../x", "a/..",
            "./x", "é/x", "a/b?x", "a/b#1", "a/b%2f",
        ] {
            assert!(!is_full_name(bad), "{bad:?}");
        }
        assert!(!is_full_name(&format!(
            "{}/x",
            "o".repeat(MAX_FULL_NAME_BYTES)
        )));
    }

    #[test]
    fn a_branch_is_a_plain_path_of_safe_characters() {
        for good in ["main", "release/1.2", "feature/a-b_c", "v1.0.0"] {
            assert!(is_branch(good), "{good}");
        }
        for bad in [
            "", "/main", "main/", "a//b", "a..b", "-main", "a b", "a\tb", "a\nb", "é", "a:b",
            "a~b", "a^b", "a?b", "a*b", "a[b", "a\\b",
        ] {
            assert!(!is_branch(bad), "{bad:?}");
        }
        assert!(!is_branch(&"a".repeat(MAX_BRANCH_BYTES + 1)));
        assert!(is_branch(&"a".repeat(MAX_BRANCH_BYTES)));
    }

    #[test]
    fn the_reason_is_cut_at_a_character_boundary_and_fits_the_audit_column() {
        let long = "é".repeat(500);
        let text = with_reason(&"x".repeat(300), Some(&long));
        assert!(text.len() <= REASON_BYTES, "{}", text.len());
        assert!(text.is_char_boundary(text.len()));
        assert_eq!(with_reason("fixed.", None), "fixed.");
    }

    #[test]
    fn the_id_follows_the_tenant_the_caller_the_subject_and_the_key() {
        use factory_domain::ids::{PrincipalId, TenantId};
        use factory_domain::vocabulary::HumanRole;
        let caller = |tenant: &str, principal: &str| Caller {
            tenant: TenantId::parse(tenant).expect("tenant"),
            principal: PrincipalId::parse(principal).expect("principal"),
            github_user_id: Some(1),
            roles: vec![HumanRole::Operator],
        };
        let t1 = "00000000-0000-7000-8000-000000000001";
        let t2 = "00000000-0000-7000-8000-000000000002";
        let p1 = "00000000-0000-7000-8000-0000000000a1";
        let p2 = "00000000-0000-7000-8000-0000000000a2";
        let key = IdempotencyKey::new("k1").expect("key");
        let other = IdempotencyKey::new("k2").expect("key");
        let base = derived("t", &caller(t1, p1), "s", &key);
        assert_eq!(base, derived("t", &caller(t1, p1), "s", &key));
        assert_ne!(base, derived("t", &caller(t1, p1), "s", &other));
        assert_ne!(base, derived("t", &caller(t1, p1), "s2", &key));
        assert_ne!(base, derived("u", &caller(t1, p1), "s", &key));
        assert_ne!(base, derived("t", &caller(t2, p1), "s", &key));
        assert_ne!(base, derived("t", &caller(t1, p2), "s", &key));
    }
}
