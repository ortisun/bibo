//! Job submission, status, listing and timeline.
//!
//! * **Submit** stores the request as a `RECEIVED` job. Admission is the engine's own decision: the
//!   API checks who is calling and writes the job, the original request exactly as received and an
//!   audit record in one transaction. A repeat of the same `Idempotency-Key` finds the first job
//!   and writes nothing; the same key with a different request is a conflict.
//! * **Status**, **list** and **timeline** read through the caller's tenant scope. A job of
//!   another tenant is not found, with the same answer as a job that does not exist: row-level
//!   security hides the row and the scope hides it again.

use axum::http::{HeaderMap, StatusCode};
use factory_domain::ids::{AuditEventId, CorrelationId, JobId, RepositoryId};
use factory_domain::scope::TenantScope;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::{HumanRole, StageKind};
use factory_ports::store::{
    AuditAction, AuditActor, AuditDecision, AuditFilter, IdempotencyKey, JobFilter, JobOrigin,
    NewAuditEvent, NewJob, NewOriginalRequest, OutboxSeq, PageCursor, PipelineScope, RequestSource,
    StoreError, Tx, Witness,
};
use factory_workflow::engine::config::SLICE_ONE_SCOPE;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::answers::{Answer, ApiError, Reply};
use crate::auth::{Caller, require_repository};
use crate::state::ApiState;

/// The longest request text the API accepts, in bytes. The store allows 1 MiB; the API's body
/// limit is the tighter bound.
pub const MAX_TEXT_BYTES: usize = 200 * 1024;

/// The longest source reference, in bytes (the store's limit).
pub const MAX_SOURCE_REF_BYTES: usize = 2048;

/// The body of `POST /v1/jobs`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitBody {
    repository_id: String,
    text: String,
    #[serde(default)]
    source_ref: Option<String>,
}

/// Decodes a JSON body into a type that denies unknown fields. Every failure is the same 400 and
/// the library's message is dropped.
pub(crate) fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(bytes).map_err(|_| ApiError::BadRequest("body"))
}

/// Text that may contain line breaks and tabs and no other control character, in particular no NUL
/// (which the database refuses) and no escape (which a terminal would act on).
pub(crate) fn clean_text(text: &str) -> bool {
    !text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}

/// Text on one line with no control character.
pub(crate) fn clean_line(text: &str) -> bool {
    !text.chars().any(char::is_control)
}

/// The caller's idempotency key: exactly one header of 1 to 128 characters from a small alphabet.
pub(crate) fn idempotency_key(headers: &HeaderMap) -> Result<IdempotencyKey, ApiError> {
    let mut values = headers.get_all("idempotency-key").iter();
    let value = values
        .next()
        .ok_or(ApiError::BadRequest("idempotency-key"))?;
    if values.next().is_some() {
        return Err(ApiError::BadRequest("idempotency-key"));
    }
    let text = value
        .to_str()
        .map_err(|_| ApiError::BadRequest("idempotency-key"))?;
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '~' | '-');
    if !text.chars().all(allowed) {
        return Err(ApiError::BadRequest("idempotency-key"));
    }
    IdempotencyKey::new(text).map_err(|_| ApiError::BadRequest("idempotency-key"))
}

/// Parses a UUID path or body value. A value that is not one is "not found" in a path and a bad
/// request in a body; the caller picks.
pub(crate) fn parse_id<T>(
    text: &str,
    parse: impl FnOnce(&str) -> Result<T, factory_domain::error::ValueError>,
) -> Option<T> {
    parse(text).ok()
}

/// Commits, and when the answer to the commit is lost asks whether the witnessed write is there.
pub(crate) async fn commit(
    state: &ApiState,
    scope: TenantScope,
    tx: Box<dyn Tx>,
    witness: Witness,
) -> Result<(), ApiError> {
    match tx.commit().await {
        Ok(()) => Ok(()),
        Err(StoreError::CommitOutcomeUnknown) => {
            match state.ports.store.committed(scope, witness).await {
                Ok(true) => Ok(()),
                _ => Err(ApiError::Unavailable),
            }
        }
        Err(other) => Err(other.into()),
    }
}

/// `POST /v1/jobs`.
pub async fn submit(
    state: &ApiState,
    caller: &Caller,
    headers: &HeaderMap,
    body: &[u8],
    correlation: &str,
) -> Answer {
    caller.require(HumanRole::Requester)?;
    let key = idempotency_key(headers)?;
    let parsed: SubmitBody = decode(body)?;
    let repository = parse_id(&parsed.repository_id, RepositoryId::parse)
        .ok_or(ApiError::BadRequest("repository_id"))?;
    if parsed.text.trim().is_empty()
        || parsed.text.len() > MAX_TEXT_BYTES
        || !clean_text(&parsed.text)
    {
        return Err(ApiError::BadRequest("text"));
    }
    if let Some(source) = &parsed.source_ref
        && (source.is_empty() || source.len() > MAX_SOURCE_REF_BYTES || !clean_line(source))
    {
        return Err(ApiError::BadRequest("source_ref"));
    }
    // A secret in a request is refused, not stored: the original request is kept as received.
    if state
        .redactor
        .contains_secret(parsed.text.as_bytes())
        .unwrap_or(true)
    {
        return Err(ApiError::BadRequest("text"));
    }
    let text_hash = Sha256Digest::of(parsed.text.as_bytes());

    let ids = &state.ports.ids;
    let job_id = JobId::from_uuid(ids.new_uuid());
    let correlation_id = CorrelationId::parse(correlation)
        .unwrap_or_else(|_| CorrelationId::from_uuid(ids.new_uuid()));
    let audit_id = AuditEventId::from_uuid(ids.new_uuid());

    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let registered = tx.get_repository(repository).await?;
    if !registered.value.enabled {
        return Err(ApiError::NotFound);
    }
    // A requester narrowed to some repositories asks for work there and nowhere else (API-1).
    require_repository(state, caller, &registered.value.full_name)?;
    let pipeline_scope =
        PipelineScope::new(SLICE_ONE_SCOPE.to_vec()).map_err(|_| ApiError::Unavailable)?;
    let inserted = tx
        .insert_job(NewJob {
            id: job_id,
            correlation_id,
            repository,
            requester: caller.principal,
            execution_mode: state.profile.execution_mode(),
            autonomy_level: registered.value.autonomy_ceiling,
            pipeline_scope,
            origin: Some(JobOrigin::Request(key)),
        })
        .await?;
    let job = inserted.row.value;
    if !inserted.created {
        // The key was used before. It finds its job if the request is the same one.
        let first = tx.get_original_request(job.id, Some(1)).await?;
        let same = job.repository == repository && first.content_sha256 == text_hash;
        let _ = tx.rollback().await;
        if !same {
            return Err(ApiError::Conflict);
        }
        return Ok(Reply::ok(job_json(&job, false)));
    }
    tx.record_original_request(NewOriginalRequest {
        id: ids.new_uuid(),
        job: job.id,
        revision: 1,
        source: RequestSource::Api,
        source_ref: parsed.source_ref,
        author_github_user_id: caller.github_user_id,
        text: parsed.text,
    })
    .await?;
    tx.record_audit(NewAuditEvent {
        id: audit_id,
        actor: AuditActor::Human(caller.principal),
        action: audit_action("job.submitted")?,
        subject: format!("job {}", job.id.as_text()),
        decision: AuditDecision::Record,
        reason: "The job was accepted through the API.".to_owned(),
        policy_hash: state.policy_hash(),
        job: Some(job.id),
        stage_run: None,
        correlation_id,
    })
    .await?;
    commit(state, caller.scope(), tx, Witness::Audit(audit_id)).await?;
    Ok(Reply::new(StatusCode::CREATED, job_json(&job, true)))
}

pub(crate) fn audit_action(name: &str) -> Result<AuditAction, ApiError> {
    AuditAction::new(name).map_err(|_| ApiError::Unavailable)
}

fn job_json(job: &factory_ports::store::Job, created: bool) -> Value {
    json!({
        "job_id": job.id.as_text(),
        "status": job.status.to_string(),
        "repository_id": job.repository.as_text(),
        "correlation_id": job.correlation_id.as_text(),
        "created": created,
    })
}

/// `GET /v1/jobs/{job_id}`.
pub async fn status(state: &ApiState, caller: &Caller, job_id: &str) -> Answer {
    caller.require_listed()?;
    let job_id = parse_id(job_id, JobId::parse).ok_or(ApiError::NotFound)?;
    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let found = async {
        let job = tx.get_job(job_id).await?;
        let runs = tx.list_stage_runs(job_id).await?;
        Ok::<_, StoreError>((job, runs))
    }
    .await;
    let _ = tx.rollback().await;
    let (job, runs) = found?;
    let job = job.value;
    let stages: Vec<Value> = runs
        .iter()
        .map(|run| {
            let run = &run.value;
            json!({
                "stage_run_id": run.id.as_text(),
                "kind": run.kind.as_str(),
                "status": run.status.to_string(),
                "run_number": run.run_number,
                "created_at": run.created_at.as_text(),
                "finished_at": run.finished_at.as_ref().map(|at| at.as_text()),
            })
        })
        .collect();
    let scope: Vec<&str> = job
        .pipeline_scope
        .kinds()
        .iter()
        .map(|k: &StageKind| k.as_str())
        .collect();
    Ok(Reply::ok(json!({
        "job_id": job.id.as_text(),
        "status": job.status.to_string(),
        "repository_id": job.repository.as_text(),
        "requester_id": job.requester.as_text(),
        "autonomy_level": job.autonomy_level.as_str(),
        "execution_mode": job.execution_mode.as_str(),
        "pipeline_scope": scope,
        "correlation_id": job.correlation_id.as_text(),
        "created_at": job.created_at.as_text(),
        "terminal_at": job.terminal_at.as_ref().map(|at| at.as_text()),
        "stages": stages,
    })))
}

/// The query of `GET /v1/jobs`: `limit` (1 to 100, default 25) and `after` (an opaque cursor).
fn list_query(query: Option<&str>) -> Result<(u32, Option<PageCursor>), ApiError> {
    let mut limit = 25_u32;
    let mut after = None;
    for pair in query
        .unwrap_or("")
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        match pair.split_once('=') {
            Some(("limit", value)) => {
                limit = value
                    .parse::<u32>()
                    .ok()
                    .filter(|n| (1..=100).contains(n))
                    .ok_or(ApiError::BadRequest("limit"))?;
            }
            Some(("after", value))
                if !value.is_empty()
                    && value.len() <= 200
                    && value.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'=' | b'.' | b':')
                    }) =>
            {
                after = Some(PageCursor::new(value.to_owned()));
            }
            Some(("after", _)) => return Err(ApiError::BadRequest("after")),
            _ => return Err(ApiError::BadRequest("query")),
        }
    }
    Ok((limit, after))
}

/// `GET /v1/jobs`.
pub async fn list(state: &ApiState, caller: &Caller, query: Option<&str>) -> Answer {
    caller.require_listed()?;
    let (limit, after) = list_query(query)?;
    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let page = tx.list_jobs(JobFilter::default(), after, limit).await;
    let _ = tx.rollback().await;
    let page = page?;
    let jobs: Vec<Value> = page
        .rows
        .iter()
        .map(|row| {
            json!({
                "job_id": row.value.id.as_text(),
                "status": row.value.status.to_string(),
                "repository_id": row.value.repository.as_text(),
                "created_at": row.value.created_at.as_text(),
            })
        })
        .collect();
    Ok(Reply::ok(json!({
        "jobs": jobs,
        "next": page.next.as_ref().map(|cursor| cursor.as_str().to_owned()),
    })))
}

/// The most rows of each kind one timeline answer carries.
pub const TIMELINE_LIMIT: u32 = 500;

/// `GET /v1/jobs/{job_id}/timeline`: the state transitions with their reasons, from the outbox,
/// and the audit records of the job, in time order.
pub async fn timeline(state: &ApiState, caller: &Caller, job_id: &str) -> Answer {
    caller.require_listed()?;
    let job_id = parse_id(job_id, JobId::parse).ok_or(ApiError::NotFound)?;
    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let found = async {
        tx.get_job(job_id).await?;
        let events = tx
            .read_events(job_id, OutboxSeq::START, TIMELINE_LIMIT)
            .await?;
        let audit = tx
            .read_audit(AuditFilter::Job(job_id), 0, TIMELINE_LIMIT)
            .await?;
        Ok::<_, StoreError>((events, audit))
    }
    .await;
    let _ = tx.rollback().await;
    let (events, audit) = found?;
    let truncated = events.len() as u32 >= TIMELINE_LIMIT || audit.len() as u32 >= TIMELINE_LIMIT;
    let mut entries: Vec<(factory_domain::values::Timestamp, Value)> = Vec::new();
    for row in &events {
        let event = &row.event;
        entries.push((
            event.occurred_at,
            json!({
                "at": event.occurred_at.as_text(),
                "kind": "transition",
                "event": event.event_type.as_str(),
                "transition": event.transition_id.as_str(),
                "reason": event.reason_code.as_ref().map(|code| code.as_str().to_owned()),
            }),
        ));
    }
    for record in &audit {
        entries.push((
            record.created_at,
            json!({
                "at": record.created_at.as_text(),
                "kind": "audit",
                "action": record.event.action.as_str(),
                "decision": match record.event.decision {
                    AuditDecision::Allow => "allow",
                    AuditDecision::Deny => "deny",
                    AuditDecision::Record => "record",
                },
            }),
        ));
    }
    entries.sort_by_key(|entry| entry.0);
    let entries: Vec<Value> = entries.into_iter().map(|(_, entry)| entry).collect();
    Ok(Reply::ok(json!({
        "job_id": job_id.as_text(),
        "entries": entries,
        "truncated": truncated,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn text_may_hold_line_breaks_and_no_other_control_character() {
        assert!(clean_text("a\nb\tc\r\n"));
        for bad in ["a\0b", "a\u{1b}[31m", "a\u{7f}"] {
            assert!(!clean_text(bad), "{bad:?}");
        }
        assert!(clean_line("one line"));
        assert!(!clean_line("two\nlines"));
    }

    #[test]
    fn an_idempotency_key_is_one_header_from_a_small_alphabet() {
        let mut headers = HeaderMap::new();
        assert!(idempotency_key(&headers).is_err(), "a request needs a key");
        headers.insert(
            "idempotency-key",
            HeaderValue::from_static("order-42:retry.1"),
        );
        assert_eq!(
            idempotency_key(&headers).expect("valid").as_str(),
            "order-42:retry.1"
        );
        for bad in ["a b", "a'b", "a;drop", "é"] {
            headers.insert(
                "idempotency-key",
                HeaderValue::from_bytes(bad.as_bytes()).expect("bytes"),
            );
            assert!(idempotency_key(&headers).is_err(), "{bad:?}");
        }
        headers.insert(
            "idempotency-key",
            HeaderValue::from_str(&"k".repeat(129)).expect("header"),
        );
        assert!(idempotency_key(&headers).is_err());
        let mut two = HeaderMap::new();
        two.append("idempotency-key", HeaderValue::from_static("a"));
        two.append("idempotency-key", HeaderValue::from_static("b"));
        assert!(idempotency_key(&two).is_err());
    }

    #[test]
    fn the_list_query_accepts_a_limit_and_a_cursor_and_nothing_else() {
        assert_eq!(list_query(None).expect("default").0, 25);
        assert_eq!(list_query(Some("limit=100")).expect("max").0, 100);
        for bad in [
            "limit=0",
            "limit=101",
            "limit=x",
            "after=",
            "after=a b",
            "sort=asc",
            "limit",
        ] {
            assert!(list_query(Some(bad)).is_err(), "{bad}");
        }
        assert!(list_query(Some("after=abc_-=.:")).is_ok());
    }
}
