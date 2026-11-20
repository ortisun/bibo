//! Registering a repository, attesting its project map, enabling it and disabling it.
//!
//! The factory takes tickets from a GitHub repository only after a person has installed the
//! workflow into the project, mapped it and read the map (ADR 0016, the onboarding guide). This
//! module is how that path reaches the engine:
//!
//! 1. **Register** (`POST /v1/repositories`). The repository exists, switched off, at autonomy level
//!    `L0`, with no project map. Nothing in the request can change those three facts: the body
//!    refuses unknown fields, and the worker registers with the six columns a registration writes.
//! 2. **Attest the project map** (`POST /v1/repositories/{id}/project-map`). A person says that
//!    commit `C` of the default branch holds the project map, and why they are able to say so.
//! 3. **Enable** (`POST /v1/repositories/{id}/enable`). The body names the map commit the approver
//!    means, as an approval elsewhere in this system is bound to the head the person saw. Refused
//!    with the code `project_map_not_attested` until step 2 happened, with `project_map_changed`
//!    when the commit named is not the one attested now, and with `enabler_is_attestor` when the
//!    person attested the map of a repository that was not registered as a single-maintainer one.
//!    The worker, the Store and the table refuse the same changes, so these checks are clear answers
//!    and not the only guard.
//! 4. **Disable** (`POST /v1/repositories/{id}/disable`). A webhook and a job submission for a
//!    disabled repository are dropped by the code that already reads `repositories.enabled`.
//!
//! # Signed requests (finding REG-2)
//!
//! Register, attest and enable WIDEN the factory's reach, so this module does not make them. It
//! checks the designation and the narrowing of the caller, appends one `repository.change_requested`
//! audit record that carries a keyed word (`crates/composition/src/repository_changes.rs`, the key of
//! the decisions), and answers `202`. The worker verifies the word, asks the protected allowlist again
//! by the numeric GitHub id, applies the change through the Store and writes the result as the system.
//! `GET /v1/repository-changes/{id}` says where a request stands. The database login of the API holds
//! no grant that changes a repository except the switch-off, and a trigger refuses anything else.
//!
//! **Disable** only narrows, so it is made here, directly, in the caller's transaction with its
//! audit record, and answers `200`.
//!
//! A repository that is enabled does not stay enabled over another map. Attesting another commit,
//! or the same commit by another person, switches it off in the same change (the table does it, for
//! every writer), and the worker writes a `repository.disabled` audit record in the same
//! transaction, so that the record of who did what shows it.
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
//! entry narrowed to other repositories is refused as one without the designation (API-1), by the
//! GitHub id of the repository when the entry lists it (RR-28).
//!
//! # Exactly once
//!
//! Every change carries an `Idempotency-Key`. The audit record that goes with it has an id derived
//! from the tenant, the caller, the repository and the key, and the same key with the same request
//! finds that record and changes nothing. The same key with a different request is a conflict.
//! A request and its record are one transaction, and the worker writes the result and the change in
//! one transaction too, so there is no change without a record and no record without a change.

use axum::http::{HeaderMap, StatusCode};
use factory_composition::decision_signing::{
    RepositoryChangeSigning, read_repository_change_subject,
};
use factory_composition::repository_changes::{
    Change, NO_REASON, REFUSED, REQUESTED, RepositoryChangeFields, payload_digest,
    registration_detail, single_maintainer_is_possible,
};
use factory_domain::ids::{AuditEventId, CorrelationId, RepositoryId};
use factory_domain::policy::authority::RepositoryIdentity;
use factory_domain::values::{Sha256Digest, is_repository_branch, is_repository_full_name};
use factory_ports::store::{
    AuditActor, AuditDecision, ConstraintRule, IdempotencyKey, NewAuditEvent, ProjectMapCommit,
    Repository, StoreError, Tx, Versioned, Witness,
};
use factory_workflow::gates::supply_chain::approval::{MAX_REASON_CHARS, MIN_REASON_CHARS};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::answers::{Answer, ApiError, Reply};
use crate::auth::{Caller, require_identity};
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
    /// True when one person may both attest the project map and enable the repository (finding
    /// REG-6). False, the default, is the strict rule. It is written here and nowhere else.
    #[serde(default)]
    single_maintainer: bool,
}

/// The body of `POST /v1/repositories/{id}/project-map`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttestBody {
    commit: String,
    reason: String,
}

/// The body of `POST /v1/repositories/{id}/disable`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeBody {
    #[serde(default)]
    reason: Option<String>,
}

/// The body of `POST /v1/repositories/{id}/enable`: the map commit the approver means.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnableBody {
    commit: String,
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
    let enabled_for = repository.enabled_for.as_ref().map(|record| {
        json!({
            "commit": record.commit.as_str(),
            "enabled_by": record.enabled_by.map(|by| by.as_text()),
            "enabled_at": record.enabled_at.as_text(),
        })
    });
    json!({
        "repository_id": repository.id.as_text(),
        "full_name": repository.full_name,
        "default_branch": repository.default_branch,
        "github_installation_id": repository.installation.0,
        "github_repository_id": repository.github_repository_id.0,
        "single_maintainer": repository.single_maintainer,
        "enabled": repository.enabled,
        "enabled_for": enabled_for,
        "protection_preflight_passed": repository.protection_preflight_passed,
        "autonomy_ceiling": repository.autonomy_ceiling.as_str(),
        "version": row.version.get(),
        "project_map": map,
        "standing": {
            "attestor_is_active_human": repository.attestor_is_active,
            "enabler_is_active_human": repository.enabler_is_active,
            "open_for_new_jobs": repository.open_for_new_jobs(),
        },
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
    named: Option<RepositoryIdentity<'_>>,
    refused_as: String,
) -> Result<(Box<dyn Tx>, Option<Versioned<Repository>>), ApiError> {
    let needed = roles_of_action(state, action);
    let mut allowed = caller.require_any(&needed).is_ok();
    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let mut found = None;
    if allowed {
        if let Some(id) = repository {
            let row = tx.get_repository(id).await?;
            if narrowed_away(state, caller, &row.value.identity())? {
                allowed = false;
            }
            found = Some(row);
        } else if let Some(name) = named
            && narrowed_away(state, caller, &name)?
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

/// True when the caller's allowlist entry is narrowed to other repositories than this one. The
/// question carries GitHub's numeric id (finding RR-28).
fn narrowed_away(
    state: &ApiState,
    caller: &Caller,
    identity: &RepositoryIdentity<'_>,
) -> Result<bool, ApiError> {
    match require_identity(state, caller, identity) {
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

/// The answer to a request: it is recorded, and the worker has not necessarily applied it yet.
fn accepted(id: AuditEventId, change: &Change, did_change: bool) -> Reply {
    Reply::new(
        StatusCode::ACCEPTED,
        json!({
            "request_id": id.as_uuid().hyphenated().to_string(),
            "kind": change.kind(),
            "repository_id": change.repository().as_text(),
            "state": "requested",
            "changed": did_change,
        }),
    )
}

/// Appends the signed request for a change that widens the factory's reach, commits, and answers `202`.
/// The API changes nothing in the table: the worker verifies the word, asks the allowlist again and
/// applies the change (finding REG-2).
///
/// A request with this id that was written before is a repeat when it asks for the same change by the
/// same person, and a conflict when it asks for another. `detail` is the `reason` column of the record;
/// the signed subject carries its digest.
async fn request_change(
    state: &ApiState,
    caller: &Caller,
    mut tx: Box<dyn Tx>,
    key: &IdempotencyKey,
    change: Change,
    detail: String,
) -> Answer {
    let repository = change.repository();
    let subject_key = repository.as_text();
    let fields = RepositoryChangeFields {
        payload: payload_digest(&detail),
        change,
    };
    let id = AuditEventId::from_uuid(derived(
        &format!("{REQUESTED}.{}", fields.change.kind()),
        caller,
        &subject_key,
        key,
    ));
    if let Some(record) = tx.find_audit(id).await? {
        let _ = tx.rollback().await;
        let same = record.event.actor == AuditActor::Human(caller.principal)
            && read_repository_change_subject(&record.event.subject)
                .is_some_and(|read| read.fields == fields);
        return if same {
            Ok(accepted(id, &fields.change, false))
        } else {
            Err(ApiError::Conflict)
        };
    }
    let requested_at = state.ports.clock.now().as_text();
    let subject = state
        .decision_keys
        .signed_repository_change_subject(&RepositoryChangeSigning {
            tenant: caller.tenant,
            actor: caller.principal,
            event: id,
            requested_at: &requested_at,
            fields: &fields,
        });
    let audit = NewAuditEvent {
        id,
        actor: AuditActor::Human(caller.principal),
        action: audit_action(REQUESTED)?,
        subject,
        decision: AuditDecision::Record,
        reason: detail,
        policy_hash: state.policy_hash(),
        job: None,
        stage_run: None,
        correlation_id: CorrelationId::from_uuid(derived(
            "repository-correlation",
            caller,
            &subject_key,
            key,
        )),
    };
    finish(state, caller, tx, audit).await?;
    Ok(accepted(id, &fields.change, true))
}

/// `POST /v1/repositories`. The answer is `202`: the worker registers the repository.
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
    if !is_repository_full_name(&parsed.full_name) {
        return Err(ApiError::BadRequest("full_name"));
    }
    if !is_repository_branch(&parsed.default_branch) {
        return Err(ApiError::BadRequest("default_branch"));
    }

    // The id follows the caller and the key only, so that the same key with another request finds
    // the record of the first and is a conflict, as it is for a job and for a decision.
    let id = RepositoryId::from_uuid(derived("repository", caller, "", &key));
    let refused_as = format!("repository.register name={}", parsed.full_name);
    let (tx, _) = open(
        state,
        caller,
        REGISTER,
        None,
        // What the operator typed: the name and the GitHub id of the registration (finding RH-2).
        Some(RepositoryIdentity::typed(
            &parsed.full_name,
            parsed.github_repository_id,
        )),
        refused_as,
    )
    .await?;
    let mut tx = tx;
    if parsed.single_maintainer {
        single_maintainer_allowed(
            state,
            caller,
            &mut *tx,
            &RepositoryIdentity::typed(&parsed.full_name, parsed.github_repository_id),
        )
        .await?;
    }
    let change = Change::Register {
        repository: id,
        installation: parsed.installation_id,
        github_repository: parsed.github_repository_id,
        single_maintainer: parsed.single_maintainer,
    };
    let detail = registration_detail(&parsed.full_name, &parsed.default_branch);
    request_change(state, caller, tx, &key, change, detail).await
}

/// `GET /v1/repositories/{repository_id}`.
pub async fn show(state: &ApiState, caller: &Caller, repository_id: &str) -> Answer {
    caller.require_listed()?;
    let id = parse_id(repository_id, RepositoryId::parse).ok_or(ApiError::NotFound)?;
    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let found = tx.get_repository(id).await;
    let _ = tx.rollback().await;
    let row = found?;
    // An allowlist entry narrowed to other repositories does not see this one, as it does not see
    // its jobs (API-1): the answer is the one for a repository that is not there (REG-4).
    if narrowed_away(state, caller, &row.value.identity())? {
        return Err(ApiError::NotFound);
    }
    Ok(Reply::ok(repository_json(&row)))
}

/// `POST /v1/repositories/{repository_id}/project-map`. The answer is `202`: the worker attests the map.
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
    let (tx, found) = open(state, caller, CONFIRM_MAP, Some(id), None, refused_as).await?;
    // The repository exists for this tenant. The worker reads it again when it applies the request.
    found.ok_or(ApiError::NotFound)?;
    let change = Change::Attest {
        repository: id,
        commit: map_commit.as_str().to_owned(),
    };
    request_change(state, caller, tx, &key, change, reason).await
}

/// `POST /v1/repositories/{repository_id}/enable` and `.../disable`.
///
/// Enabling names the map commit the approver means. It must be the commit attested now: a map
/// that was attested again since the approver looked is refused with `project_map_changed`, and
/// the approver reads the new one and enables it. The answer to an enable is `202`: the worker enables
/// the repository (finding REG-2). Disabling is done here, directly, and answers `200`: narrowing is safe,
/// and the table lets the API login do nothing else.
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
    let (meant, reason) = if enable {
        let parsed: EnableBody = decode(body)?;
        let meant =
            ProjectMapCommit::new(&parsed.commit).map_err(|_| ApiError::BadRequest("commit"))?;
        (
            Some(meant),
            optional_reason(state, parsed.reason.as_deref())?,
        )
    } else {
        let parsed: ChangeBody = decode(body)?;
        (None, optional_reason(state, parsed.reason.as_deref())?)
    };

    let (action, verb) = if enable {
        (ENABLE, "enable")
    } else {
        (DISABLE, "disable")
    };
    let refused_as = format!("repository.{verb} repository={}", id.as_text());
    let (mut tx, found) = open(state, caller, action, Some(id), None, refused_as).await?;
    let row = found.ok_or(ApiError::NotFound)?;
    if let Some(meant) = meant {
        // The clear answers, from the row as it is now. The worker, the store and the table refuse
        // these changes as well, so they are not the only guard.
        match &row.value.project_map {
            Some(map) if map.commit == meant => {
                if !row.value.single_maintainer && map.attested_by == caller.principal {
                    return Err(ApiError::EnablerIsAttestor);
                }
            }
            Some(_) => return Err(ApiError::ProjectMapChanged),
            None => return Err(ApiError::ProjectMapNotAttested),
        }
        // Already enabled (for the commit attested now, which the match above settled): nothing to ask the
        // worker. The table keeps the first enabler, and a second request would only put a second name in the
        // log (finding RH-7).
        if row.value.enabled {
            let _ = tx.rollback().await;
            return Ok(changed(&row, false, StatusCode::OK));
        }
        let change = Change::Enable {
            repository: id,
            commit: meant.as_str().to_owned(),
        };
        let detail = reason.unwrap_or_else(|| NO_REASON.to_owned());
        return request_change(state, caller, tx, &key, change, detail).await;
    }
    let audit = event(
        state,
        caller,
        &key,
        "repository.disabled",
        id,
        format!("repository {} disabled", id.as_text()),
        with_reason(
            "A person disabled the repository. Its webhooks are dropped and no job can be submitted for it. Jobs that exist go on; cancel them one by one to stop them.",
            reason.as_deref(),
        ),
    )?;
    if is_replay(&mut *tx, &audit).await? {
        let current = tx.get_repository(id).await?;
        let _ = tx.rollback().await;
        return Ok(changed(&current, false, StatusCode::OK));
    }
    tx.disable_repository(id, row.version)
        .await
        .map_err(refusal_of_store)?;
    let current = tx.get_repository(id).await?;
    finish(state, caller, tx, audit).await?;
    Ok(changed(&current, true, StatusCode::OK))
}

/// `GET /v1/repository-changes/{request_id}`: where a request to register, attest or enable stands.
/// `requested` until the worker settles it, then `applied`, or `refused` with the fixed code of the
/// refusal. The answer holds no text of the request.
pub async fn change_status(state: &ApiState, caller: &Caller, request_id: &str) -> Answer {
    caller.require_listed()?;
    let id = parse_id(request_id, AuditEventId::parse).ok_or(ApiError::NotFound)?;
    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let request = tx.find_audit(id).await;
    // The result is looked for under every key in force: one written before a rotation has the id of the
    // previous key (finding RH-4).
    let mut result = Ok(None);
    for result_id in state.decision_keys.repository_change_result_ids(id) {
        result = tx.find_audit(result_id).await;
        if !matches!(result, Ok(None)) {
            break;
        }
    }
    let request = match request {
        Ok(Some(record)) if record.event.action.as_str() == REQUESTED => record,
        Ok(_) => {
            let _ = tx.rollback().await;
            return Err(ApiError::NotFound);
        }
        Err(other) => {
            let _ = tx.rollback().await;
            return Err(other.into());
        }
    };
    // A row with this action is not a request until its word is good (finding RH-5): the status route does not
    // believe what the database login could write.
    let read = read_repository_change_subject(&request.event.subject).ok_or(ApiError::NotFound)?;
    let AuditActor::Human(requested_by) = request.event.actor else {
        let _ = tx.rollback().await;
        return Err(ApiError::NotFound);
    };
    if request.event.job.is_some()
        || !state.decision_keys.verify_repository_change(
            &RepositoryChangeSigning {
                tenant: caller.tenant,
                actor: requested_by,
                event: id,
                requested_at: &read.requested_at,
                fields: &read.fields,
            },
            &read.word,
        )
        || payload_digest(&request.event.reason) != read.fields.payload
    {
        let _ = tx.rollback().await;
        return Err(ApiError::NotFound);
    }
    let fields = read.fields;
    // An allowlist entry narrowed to other repositories does not see the request, as it does not see the
    // repository (REG-4). A registration that is not applied yet has no row, and is not narrowed here: the
    // narrowing of the registration was settled when it was asked for.
    if let Ok(row) = tx.get_repository(fields.change.repository()).await
        && narrowed_away(state, caller, &row.value.identity())?
    {
        let _ = tx.rollback().await;
        return Err(ApiError::NotFound);
    }
    let _ = tx.rollback().await;
    let result = result?;
    let (state_word, code) = match &result {
        None => ("requested", Value::Null),
        Some(record) if record.event.action.as_str() == REFUSED => {
            let code = record.event.reason.split(':').next().unwrap_or("refused");
            // An enable of a repository that was enabled already: what was asked is in place (finding RH-7).
            if code == "already_enabled" {
                ("applied", json!(code))
            } else {
                ("refused", json!(code))
            }
        }
        Some(_) => ("applied", Value::Null),
    };
    Ok(Reply::ok(json!({
        "request_id": id.as_uuid().hyphenated().to_string(),
        "kind": fields.change.kind(),
        "repository_id": fields.change.repository().as_text(),
        "state": state_word,
        "code": code,
    })))
}

/// Finding RH-6: the exception to the strict rule is for a tenant in which exactly one active person holds the
/// designations the rule constrains. The worker asks again when it applies the request; this is the clear answer.
async fn single_maintainer_allowed(
    state: &ApiState,
    caller: &Caller,
    tx: &mut dyn Tx,
    identity: &RepositoryIdentity<'_>,
) -> Result<(), ApiError> {
    let mut roles = Vec::new();
    for action in [CONFIRM_MAP, ENABLE] {
        roles.extend(
            roles_of_action(state, action)
                .into_iter()
                .map(|role| role.as_str().to_owned()),
        );
    }
    let holders = state
        .allowlist_file
        .holders_of(caller.tenant, &roles, identity, state.ports.clock.now())
        .map_err(|_| ApiError::Unavailable)?;
    match single_maintainer_is_possible(tx, &holders).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(ApiError::SingleMaintainerNotAllowed),
        Err(other) => Err(other.into()),
    }
}

/// What a store refusal of a repository change is to the caller. A rule of the project map is
/// the typed answer. A stale version is a conflict. A mistake of the caller is never a fault.
fn refusal_of_store(error: StoreError) -> ApiError {
    match error {
        StoreError::Constraint(ConstraintRule::ProjectMapRule) => ApiError::ProjectMapNotAttested,
        StoreError::Constraint(ConstraintRule::ProjectMapChanged) => ApiError::ProjectMapChanged,
        StoreError::Constraint(ConstraintRule::EnablerIsAttestor) => ApiError::EnablerIsAttestor,
        other => other.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
