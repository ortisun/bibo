//! Decisions of people: approve, reject, request rework, pause, resume, cancel.
//!
//! The API is the front door for a decision, and the engine is the judge. This module does the
//! part that belongs to the front door and nothing the engine decides:
//!
//! 1. **Who.** The caller is the principal behind the token. The roles come from the protected
//!    allowlist by the numeric GitHub id of that principal, and the action table of
//!    `policies/approval.yaml` names the designation each verb needs (`approve_pr` and
//!    `reject_or_request_rework` need an approver; `pause_or_resume_job` and `cancel_job` an
//!    operator). A login string is never read. A caller without the role gets a 403 with no
//!    reason, and the attempt is audited.
//! 2. **What.** The words are read by the same pure grammar every channel uses
//!    (`factory_composition::commands`), so `merge`, `deploy`, `ready` and `undraft` are unknown
//!    verbs here as they are in a pull request comment.
//! 3. **Record.** The request is written to the audit log in the caller's tenant, with an id
//!    derived from the tenant, the job and the `Idempotency-Key`, so a retry writes nothing new
//!    and the same key with a different decision is a conflict. The subject ends with the time of
//!    the request and a keyed word (`at=` and `mac=`, HMAC-SHA256 over the tenant, the person, the
//!    event id, the time and the other words) that only this service can make. The worker's hook
//!    applies a request only if the word is right (AUT-12). A retry of the same request, which has
//!    a later time and so another word, finds the record it wrote and answers as the first did.
//!
//! **What this module does not do: apply the decision.** Moving the stage run needs the engine
//! (`Engine::decide`, `Engine::control`) and, for a pull request approval, the change host and the
//! binding checks of `ApprovalService::judge` (head, tree, base and evidence as they are now). The
//! engine runs in the worker, which holds the sandbox, the runtime and the GitHub App; the API
//! holds none of them and cannot build one without a fake. So the answer is `202` with
//! `"applied": false`: the decision is recorded, authorized by the allowlist and waiting for the
//! worker. `"applied": false` is true of the moment of the answer and says nothing about what
//! comes after. The worker (`factory_composition::decisions::ClaimWork`, a step before each claim)
//! reads the record, checks the allowlist again by numeric id, applies the decision once and
//! writes the audit record `decision.applied` or `decision.rejected` for the same job, which
//! `GET /v1/jobs/{id}/timeline` shows.

use axum::http::{HeaderMap, StatusCode};
use factory_composition::commands::{CommandError, ParsedDecision, parse_form};
use factory_composition::decision_signing::{Signing, SubjectKind, read_subject};
use factory_composition::decisions::DecisionFields;
use factory_domain::ids::{AuditEventId, CorrelationId, JobId, StageRunId};
use factory_domain::vocabulary::HumanRole;
use factory_ports::store::{
    AuditActor, AuditDecision, ConstraintRule, NewAuditEvent, StoreError, Tx, Witness,
};
use factory_workflow::stages::approval::Verb;
use serde::Deserialize;
use serde_json::json;

use crate::answers::{Answer, ApiError, Reply};
use crate::auth::{Caller, require_repository};
use crate::jobs::{
    audit_action, clean_line, clean_text, commit, decode, idempotency_key, parse_id,
};
use crate::limits::Refusal;
use crate::state::ApiState;
use crate::tokens;

/// The body of `POST /v1/jobs/{job_id}/decisions`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionBody {
    verb: String,
    #[serde(default)]
    stage_run_id: Option<String>,
    #[serde(default)]
    head: Option<String>,
    #[serde(default)]
    evidence: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// The longest slice of a reason the audit record keeps, in bytes.
const REASON_KEPT: usize = 900;

fn field_of(error: &CommandError) -> &'static str {
    match error {
        CommandError::UnknownVerb(_) | CommandError::NoVerb => "verb",
        CommandError::BadValue(field) | CommandError::Repeated(field) => field,
        CommandError::Reason => "reason",
        CommandError::Missing(..) => "body",
    }
}

/// The designations the policy's action table names for a verb. Empty when the table has no row
/// for it, which the caller treats as a refusal.
fn required_roles(state: &ApiState, verb: Verb) -> Vec<HumanRole> {
    state
        .policies
        .approval
        .actions
        .iter()
        .find(|row| row.id == verb.action())
        .and_then(|row| row.approver_roles.as_ref())
        .map(|names| {
            names
                .iter()
                .filter_map(|name| HumanRole::parse(name).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// A UUID derived from the tenant, the caller, the job and the caller's key: the same four always
/// give the same id, so a retried request is the same record, and two people who send the same key
/// for the same job write two records, not one record that the second of them is told is theirs
/// (API-2).
fn derived_id(tenant: &str, principal: &str, job: &str, key: &str) -> uuid::Uuid {
    let digest = factory_domain::values::Sha256Digest::of(
        format!("decision\n{tenant}\n{principal}\n{job}\n{key}").as_bytes(),
    );
    let hash = tokens::digest_bytes(&digest);
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

fn kept(reason: &str) -> &str {
    if reason.len() <= REASON_KEPT {
        return reason;
    }
    let mut end = REASON_KEPT;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason[..end]
}

/// `POST /v1/jobs/{job_id}/decisions`.
pub async fn decide(
    state: &ApiState,
    caller: &Caller,
    job_id: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Answer {
    let job_id = parse_id(job_id, JobId::parse).ok_or(ApiError::NotFound)?;
    let key = idempotency_key(headers)?;
    let parsed: DecisionBody = decode(body)?;
    for (field, value) in [
        ("verb", Some(&parsed.verb)),
        ("head", parsed.head.as_ref()),
        ("evidence", parsed.evidence.as_ref()),
        ("target", parsed.target.as_ref()),
        ("stage_run_id", parsed.stage_run_id.as_ref()),
    ] {
        if value.is_some_and(|text| !clean_line(text)) {
            return Err(ApiError::BadRequest(field));
        }
    }
    if parsed.reason.as_ref().is_some_and(|text| !clean_text(text)) {
        return Err(ApiError::BadRequest("reason"));
    }
    let mut fields: Vec<(&str, &str)> = vec![("verb", parsed.verb.as_str())];
    for (name, value) in [
        ("head", &parsed.head),
        ("evidence", &parsed.evidence),
        ("target", &parsed.target),
        ("reason", &parsed.reason),
    ] {
        if let Some(text) = value {
            fields.push((name, text));
        }
    }
    let decision: ParsedDecision =
        parse_form(&fields).map_err(|e| ApiError::BadRequest(field_of(&e)))?;
    let stage_run = parsed
        .stage_run_id
        .as_deref()
        .map(|text| parse_id(text, StageRunId::parse).ok_or(ApiError::BadRequest("stage_run_id")))
        .transpose()?;
    match decision.verb {
        Verb::Approve if decision.head.is_none() => return Err(ApiError::BadRequest("head")),
        Verb::Approve if decision.evidence.is_none() => {
            return Err(ApiError::BadRequest("evidence"));
        }
        Verb::Rework if decision.target.is_none() => return Err(ApiError::BadRequest("target")),
        Verb::Approve | Verb::Reject | Verb::Rework if stage_run.is_none() => {
            return Err(ApiError::BadRequest("stage_run_id"));
        }
        _ => {}
    }
    if state
        .redactor
        .contains_secret(decision.reason.as_bytes())
        .unwrap_or(true)
    {
        return Err(ApiError::BadRequest("reason"));
    }

    let ids = &state.ports.ids;
    let command = derived_id(
        &caller.tenant.as_text(),
        &caller.principal.as_text(),
        &job_id.as_text(),
        key.as_str(),
    );

    // 1. Who. The attempt of someone without the role is audited and refused with no reason, and
    // the answer does not depend on whether the job exists: an unlisted person learns nothing
    // about the tenant's jobs. The record names the job as text and does not reference it.
    let needed = required_roles(state, decision.verb);
    let mut allowed = caller.require_any(&needed).is_ok();

    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let mut found_job = None;
    if allowed {
        let job = tx.get_job(job_id).await?;
        // The designation holds on the repositories the allowlist entry names (API-1). A person
        // narrowed to other repositories is refused as one without the designation: audited, no
        // reason, and the record names no job.
        let repository = tx.get_repository(job.value.repository).await?;
        match require_repository(state, caller, &repository.value.full_name) {
            Ok(()) => {}
            Err(ApiError::Forbidden) => allowed = false,
            Err(other) => return Err(other),
        }
        found_job = Some(job);
    }
    let (job_ref, correlation_id) = if let (true, Some(job)) = (allowed, found_job) {
        if let Some(run) = stage_run {
            let found = tx.get_stage_run(run).await?;
            if found.value.job_id != job.value.id {
                return Err(ApiError::NotFound);
            }
        }
        // The job's own correlation id: the same for every record of the job, and the same on a
        // retry, which is what lets a retried request find the record it wrote.
        (Some(job_id), job.value.correlation_id)
    } else {
        (None, CorrelationId::from_uuid(ids.new_uuid()))
    };
    let audit_id = if allowed {
        AuditEventId::from_uuid(command)
    } else {
        AuditEventId::from_uuid(ids.new_uuid())
    };
    // The one grammar of the subject is shared with the worker, which reads it back to apply the
    // decision.
    let fields = DecisionFields {
        verb: decision.verb,
        job: job_id,
        stage_run,
        head: decision.head.as_ref().map(|h| h.as_str().to_owned()),
        evidence: decision.evidence.as_ref().map(|e| e.as_str().to_owned()),
        target: decision.target.map(|t| t.as_str().to_owned()),
    };
    if !allowed {
        return refuse(state, caller, tx, fields.subject(), correlation_id).await;
    }
    let reason = format!("requested: {}", kept(&decision.reason));
    let accepted = || {
        Reply::new(
            StatusCode::ACCEPTED,
            json!({
                "decision_id": command.hyphenated().to_string(),
                "status": "recorded",
                "applied": false,
            }),
        )
    };
    // A retry of a request that was recorded finds its record. The record carries the time of the
    // first request, so a retry's own subject differs in its last two words and the store would call
    // it another record under the same id.
    if let Some(earlier) = recorded_request(&mut *tx, job_id, audit_id).await? {
        return if earlier.is_the_same_request(caller, &fields, stage_run, &reason) {
            let _ = tx.rollback().await;
            Ok(accepted())
        } else {
            Err(ApiError::Conflict)
        };
    }
    let requested_at = state.ports.clock.now().as_text();
    let subject = state.decision_keys.signed_subject(&Signing {
        tenant: caller.tenant,
        actor: caller.principal,
        event: audit_id,
        requested_at: &requested_at,
        fields: &fields,
    });
    let written = tx
        .record_audit(NewAuditEvent {
            id: audit_id,
            actor: AuditActor::Human(caller.principal),
            action: audit_action("decision.requested")?,
            subject,
            decision: AuditDecision::Record,
            reason,
            policy_hash: state.policy_hash(),
            job: job_ref,
            stage_run,
            correlation_id,
        })
        .await;
    match written {
        Ok(_) => {}
        Err(StoreError::Constraint(ConstraintRule::IdReusedWithDifferentContent)) => {
            return Err(ApiError::Conflict);
        }
        Err(other) => return Err(other.into()),
    }
    commit(state, caller.scope(), tx, Witness::Audit(audit_id)).await?;
    Ok(accepted())
}

/// The most pages of a job's audit log read to find an earlier request.
const REPLAY_PAGES: u32 = 20;

/// A `decision.requested` record this service wrote earlier.
struct Earlier(factory_ports::store::AuditRecord);

impl Earlier {
    /// True when the record is the same request: the same person, the same words, the same reason.
    /// Only the time and the keyed word may differ.
    fn is_the_same_request(
        &self,
        caller: &Caller,
        fields: &DecisionFields,
        stage_run: Option<StageRunId>,
        reason: &str,
    ) -> bool {
        let event = &self.0.event;
        let same_fields = matches!(
            read_subject(&event.subject),
            Some(SubjectKind::Signed { fields: stored, .. }) if &stored == fields
        );
        same_fields
            && event.actor == AuditActor::Human(caller.principal)
            && event.stage_run == stage_run
            && event.reason == reason
    }
}

/// The `decision.requested` record of this id, if the job's audit log holds it.
async fn recorded_request(
    tx: &mut dyn Tx,
    job: JobId,
    id: AuditEventId,
) -> Result<Option<Earlier>, ApiError> {
    let mut after = 0;
    for _ in 0..REPLAY_PAGES {
        let page = tx
            .read_audit(factory_ports::store::AuditFilter::Job(job), after, 500)
            .await?;
        let count = page.len();
        for record in page {
            after = record.sequence;
            if record.event.id == id {
                return Ok(Some(Earlier(record)));
            }
        }
        if count < 500 {
            break;
        }
    }
    Ok(None)
}

/// The refusal of someone who does not hold the designation: audited, within what the audit log
/// takes from one person (API-8), and answered `403` with no reason.
///
/// A refused caller used to leave one row with a new id for every request, so any token holder, listed
/// or not, could grow the tenant's hash-chained audit log by thousands of rows an hour, and the
/// chain serialises its writers. A person now has a few rows a minute, then one row that says the
/// rest are counted, and the count is written when the next minute opens.
async fn refuse(
    state: &ApiState,
    caller: &Caller,
    mut tx: Box<dyn Tx>,
    subject: String,
    correlation_id: CorrelationId,
) -> Answer {
    let rows: Vec<(&str, String, &str)> = match state
        .refusals
        .admit(caller.principal, std::time::Instant::now())
    {
        Refusal::Count => {
            let _ = tx.rollback().await;
            return Err(ApiError::Forbidden);
        }
        Refusal::Record { carried } => {
            let mut rows = vec![(
                "decision.denied",
                subject,
                "The caller does not hold the designation this decision needs.",
            )];
            if carried > 0 {
                rows.push((
                        "decision.denied_summary",
                        format!("decision refusals: {carried} not recorded"),
                        "Refusals of this person in the minute before went past what the audit log records one by one; the count is in the subject.",
                    ));
            }
            rows
        }
        Refusal::Suppress => vec![(
            "decision.denied_suppressed",
            "decision refusals".to_owned(),
            "More refusals of this person follow in this minute; they are counted, not recorded one by one.",
        )],
    };
    let mut last = None;
    for (action, subject, reason) in rows {
        let id = AuditEventId::from_uuid(state.ports.ids.new_uuid());
        tx.record_audit(NewAuditEvent {
            id,
            actor: AuditActor::Human(caller.principal),
            action: audit_action(action)?,
            subject,
            decision: AuditDecision::Deny,
            reason: reason.to_owned(),
            policy_hash: state.policy_hash(),
            job: None,
            stage_run: None,
            correlation_id,
        })
        .await?;
        last = Some(id);
    }
    if let Some(id) = last {
        commit(state, caller.scope(), tx, Witness::Audit(id)).await?;
    }
    Err(ApiError::Forbidden)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_tenant_caller_job_and_key_give_the_same_id_and_a_different_one_does_not() {
        let a = derived_id("t1", "p1", "j1", "k1");
        assert_eq!(a, derived_id("t1", "p1", "j1", "k1"));
        assert_ne!(a, derived_id("t1", "p1", "j1", "k2"));
        assert_ne!(a, derived_id("t1", "p1", "j2", "k1"));
        assert_ne!(a, derived_id("t2", "p1", "j1", "k1"));
        assert_ne!(
            a,
            derived_id("t1", "p2", "j1", "k1"),
            "another caller, the same key"
        );
        assert_eq!(a.get_version_num(), 4);
    }

    #[test]
    fn a_long_reason_is_cut_at_a_character_boundary() {
        let long = "é".repeat(600);
        assert!(kept(&long).len() <= REASON_KEPT);
        assert!(long.starts_with(kept(&long)));
        assert_eq!(kept("short"), "short");
    }

    #[test]
    fn the_words_are_the_grammar_of_every_channel() {
        for word in ["merge", "deploy", "ready", "undraft", "APPROVE", ""] {
            assert!(parse_form(&[("verb", word)]).is_err(), "{word:?}");
        }
        assert!(parse_form(&[("verb", "cancel"), ("reason", "no longer needed")]).is_ok());
        assert!(
            parse_form(&[("verb", "cancel")]).is_err(),
            "cancel says why"
        );
    }
}
