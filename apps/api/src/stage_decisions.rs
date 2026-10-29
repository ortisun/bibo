//! Decisions about a stage run that are not an approval of a pull request: `unblock`.
//!
//! The front door does here what it does for the other decisions (`decisions.rs`) and nothing the
//! engine decides: it reads who the caller is, checks the designation the action row names and the
//! repositories the allowlist entry reaches, reads the words with a strict grammar, and records the
//! request as the audit record `decision.stage_requested` under an id derived from the tenant, the
//! caller, the job and the `Idempotency-Key`. The subject ends with the time and the keyed word
//! that only this service can make. The answer is `202` with `"applied": false`: the worker's
//! step (`factory_composition::stage_decisions`) reads the record, asks the policy engine and the
//! engine, and writes the marker `decision.applied` or `decision.rejected`.
//!
//! | Verb | Designation | Needs | Names |
//! |---|---|---|---|
//! | `unblock` | operator (`unblock_blocked_stage_run`) | `stage_run_id`, `reason` | nothing else |
//!
//! A word that means nothing to the verb is refused and not ignored.

use axum::http::StatusCode;
use factory_composition::decision_signing::{StageSigning, StageSubject, read_stage_subject};
use factory_composition::stage_decisions::{REQUESTED, StageFields, StageVerb};
use factory_domain::ids::{AuditEventId, CorrelationId, JobId, StageRunId};
use factory_ports::store::{
    AuditActor, AuditDecision, ConstraintRule, IdempotencyKey, NewAuditEvent, StoreError, Witness,
};
use factory_workflow::gates::supply_chain::approval::{MAX_REASON_CHARS, MIN_REASON_CHARS};
use serde_json::json;

use crate::answers::{Answer, ApiError, Reply};
use crate::auth::{Caller, require_repository};
use crate::decisions::{DecisionBody, derived_id, kept, recorded_request, refuse, roles_of_action};
use crate::jobs::{audit_action, clean_line, clean_text, commit, parse_id};
use crate::state::ApiState;

/// The fields of the body that mean something to `verb`.
const fn takes(verb: StageVerb) -> &'static [&'static str] {
    match verb {
        StageVerb::Unblock => &["stage_run_id", "reason"],
    }
}

/// The names of the optional fields of the body that are set.
fn given(body: &DecisionBody) -> Vec<&'static str> {
    [
        ("stage_run_id", body.stage_run_id.is_some()),
        ("head", body.head.is_some()),
        ("evidence", body.evidence.is_some()),
        ("target", body.target.is_some()),
        ("reason", body.reason.is_some()),
        ("package", body.package.is_some()),
        ("version", body.version.is_some()),
        ("checksum", body.checksum.is_some()),
        ("path", body.path.is_some()),
        ("digest", body.digest.is_some()),
        ("warning", body.warning.is_some()),
    ]
    .into_iter()
    .filter_map(|(name, set)| set.then_some(name))
    .collect()
}

/// `POST /v1/jobs/{job_id}/decisions` with a verb about a stage run.
#[allow(clippy::too_many_lines)]
pub(crate) async fn decide(
    state: &ApiState,
    caller: &Caller,
    job_id: JobId,
    key: &IdempotencyKey,
    parsed: &DecisionBody,
    verb: StageVerb,
) -> Answer {
    // Words that mean nothing to this verb are refused, not ignored.
    if let Some(field) = given(parsed)
        .into_iter()
        .find(|field| !takes(verb).contains(field))
    {
        return Err(ApiError::BadRequest(field));
    }
    if parsed
        .stage_run_id
        .as_ref()
        .is_some_and(|text| !clean_line(text))
    {
        return Err(ApiError::BadRequest("stage_run_id"));
    }
    let stage_run = parsed
        .stage_run_id
        .as_deref()
        .map(|text| parse_id(text, StageRunId::parse).ok_or(ApiError::BadRequest("stage_run_id")))
        .transpose()?;
    let reason = parsed.reason.as_deref().map_or("", str::trim);
    if reason.chars().count() < MIN_REASON_CHARS
        || reason.chars().count() > MAX_REASON_CHARS
        || !clean_text(reason)
        || state
            .redactor
            .contains_secret(reason.as_bytes())
            .unwrap_or(true)
    {
        return Err(ApiError::BadRequest("reason"));
    }
    let fields = StageFields {
        verb,
        job: job_id,
        stage_run,
        path: None,
        digest: None,
        index: None,
    };
    if !fields.is_well_formed() {
        return Err(ApiError::BadRequest("stage_run_id"));
    }

    let ids = &state.ports.ids;
    let command_id = derived_id(
        &caller.tenant.as_text(),
        &caller.principal.as_text(),
        &job_id.as_text(),
        key.as_str(),
    );

    // Who: the designations the action names. The worker asks the policy engine again, with the
    // allowlist as it is then.
    let needed = roles_of_action(state, verb.action());
    let mut allowed = caller.require_any(&needed).is_ok();
    let mut tx = state.ports.store.begin(caller.scope()).await?;
    let mut found_job = None;
    if allowed {
        let job = tx.get_job(job_id).await?;
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
        (Some(job_id), job.value.correlation_id)
    } else {
        (None, CorrelationId::from_uuid(ids.new_uuid()))
    };
    let audit_id = if allowed {
        AuditEventId::from_uuid(command_id)
    } else {
        AuditEventId::from_uuid(ids.new_uuid())
    };
    if !allowed {
        return refuse(state, caller, tx, fields.subject(), correlation_id).await;
    }
    let stored_reason = format!("requested: {}", kept(reason));
    let accepted = || {
        Reply::new(
            StatusCode::ACCEPTED,
            json!({
                "decision_id": command_id.hyphenated().to_string(),
                "status": "recorded",
                "applied": false,
            }),
        )
    };
    if let Some(earlier) = recorded_request(&mut *tx, job_id, audit_id).await? {
        let event = &earlier.0.event;
        let same = matches!(
            read_stage_subject(&event.subject),
            Some(StageSubject::Signed { fields: stored, .. }) if stored == fields
        ) && event.actor == AuditActor::Human(caller.principal)
            && event.stage_run == stage_run
            && event.reason == stored_reason;
        return if same {
            let _ = tx.rollback().await;
            Ok(accepted())
        } else {
            Err(ApiError::Conflict)
        };
    }
    let requested_at = state.ports.clock.now().as_text();
    let subject = state.decision_keys.signed_stage_subject(&StageSigning {
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
            action: audit_action(REQUESTED)?,
            subject,
            decision: AuditDecision::Record,
            reason: stored_reason,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn body(json: &str) -> DecisionBody {
        serde_json::from_str(json).expect("a body")
    }

    #[test]
    fn a_word_that_means_nothing_to_unblock_is_named() {
        for (extra, field) in [
            (r#""head":"a""#, "head"),
            (r#""evidence":"sha256:b""#, "evidence"),
            (r#""target":"VALIDATION""#, "target"),
            (r#""package":"serde""#, "package"),
            (r#""version":"1.0.0""#, "version"),
            (r#""checksum":"abababababab""#, "checksum"),
            (r#""path":"build.rs""#, "path"),
            (r#""digest":"abababababab""#, "digest"),
            (r#""warning":1"#, "warning"),
        ] {
            let parsed = body(&format!(r#"{{"verb":"unblock",{extra}}}"#));
            let stray = given(&parsed)
                .into_iter()
                .find(|name| !takes(StageVerb::Unblock).contains(name));
            assert_eq!(stray, Some(field));
        }
        let fine = body(r#"{"verb":"unblock","stage_run_id":"x","reason":"The daemon is back."}"#);
        assert!(
            given(&fine)
                .into_iter()
                .all(|name| takes(StageVerb::Unblock).contains(&name))
        );
    }
}
