//! The GitHub webhook endpoint.
//!
//! The order is the point:
//!
//! 1. **Size and time, before the body is read.** The pipeline refuses a declared length above the
//!    limit and reads the body with a hard cap and a deadline (`routes`).
//! 2. **Verify on the raw bytes, with no database.** The `WebhookVerifier` port checks the headers,
//!    the content type and the HMAC of the exact bytes received, in constant time, against every
//!    secret in the rotation window, and only then reads the identifiers it needs. A delivery that
//!    fails any of this gets the same `401` whatever the reason, and the API touches no database
//!    on its account: it puts one event in a bounded queue, which a task writes at a limited rate
//!    (NT-WH-01, NT-WH-10). A repeated signature header is a failure too.
//! 3. **Bind to a tenant.** `Store::resolve_installation` maps the installation and repository to
//!    a tenant. An unknown binding is dropped, audited under the platform tenant and acknowledged
//!    like any other delivery (NT-AUTHZ-08).
//! 4. **Deduplicate in the store.** `record_delivery` is the filter: the same delivery id, body or
//!    event on the same subject revision is a repeat, audited as `webhook.duplicate_delivery`
//!    and acknowledged. Fifty concurrent copies give one new delivery and 49 repeats (NT-WH-04).
//! 5. **Act on a hint, never on a claim.** The payload is a hint. An `issues.labeled` event with the
//!    factory label from a sender who is a registered principal and an allowlisted requester
//!    (looked up by numeric id) makes a `RECEIVED` job in the same transaction. The text of the
//!    issue is **not** in the payload the verifier reads and the API holds no GitHub credential, so
//!    the job has no original request yet: the engine's intake fetches the live issue (README,
//!    "What is not done").
//! 6. **Refuse, say so, and let the worker answer.** The same label from anyone else (a person the
//!    tenant does not know, a person who is not a requester, a requester narrowed to other
//!    repositories) makes no job. FR-002 asks for a plain explanation on the issue and a record of
//!    the rejection, and the API holds no GitHub credential, so it leaves one signed request in the
//!    audit log in the same transaction (`ask_for_a_reply`); the worker's hook posts the reply and
//!    writes the record `intake.rejected` (`factory_composition::intake_rejections`). A repeat of
//!    a delivery leaves none, so the reply is not sent twice. A bot is never answered.
//! 7. **A repository that is switched off is not bound, and the record says what the label did
//!    (SF-19).** The lookup of step 3 answers only for a repository that is registered and
//!    enabled, so a label in a repository that is switched off is dropped there, whoever the
//!    sender is: no delivery row, no job, no request for a reply. The platform record
//!    `webhook.unbound` is all the API can leave, because it has no tenant for the delivery; for
//!    the factory label its reason says that the repository is not registered **or** that the
//!    factory is switched off for it, and that the label starts nothing, instead of the plain
//!    "not registered". A record in the tenant's own stream, naming the repository, would need
//!    the lookup to return the disabled row too (a change of the function and of the port).
//!
//! Every outcome after a valid signature is `202 {"status": "accepted"}`: a sender learns nothing
//! about tenants, repositories or the allowlist from the answer.

use axum::http::{HeaderMap, StatusCode};
use factory_composition::decision_signing::RejectionSigning;
use factory_composition::intake_rejections::RejectionFields;
use factory_domain::ids::{AuditEventId, CorrelationId, JobId, WebhookDeliveryId};
use factory_domain::scope::TenantScope;
use factory_domain::vocabulary::HumanRole;
use factory_ports::githost::{VerifiedDelivery, WebhookHeaders, WebhookHint, WebhookRejection};
use factory_ports::store::{
    AuditActor, AuditDecision, DeliveryOutcome, JobOrigin, NewAuditEvent, NewJob,
    NewWebhookDelivery, PipelineScope, Tx, Witness,
};
use factory_workflow::engine::config::SLICE_ONE_SCOPE;
use serde_json::json;

use crate::answers::{Answer, ApiError, Reply};
use crate::jobs::{audit_action, commit};
use crate::limits::{Key, PlatformEvent};
use crate::state::ApiState;

/// The reason of the record that the factory label leaves when the repository does not resolve
/// (SF-19). The lookup that binds a delivery to a tenant answers only for a repository that is
/// registered **and enabled**, so a repository that is switched off looks to the API like one that
/// was never registered, and the reason says both. It says what the factory did with the label,
/// so that a reader of the log is not left with "not registered" for a repository that is.
const UNBOUND_FACTORY_LABEL: &str = "The factory label was applied in a repository that is not registered or that the factory is switched off for. The label starts nothing and nobody is answered.";

/// The reason of the record of any other delivery that does not resolve.
const UNBOUND: &str = "The installation or repository is not registered.";

/// What a delivery is acknowledged with, whatever became of it.
fn accepted() -> Answer {
    Ok(Reply::new(
        StatusCode::ACCEPTED,
        json!({"status": "accepted"}),
    ))
}

/// A header's value when there is exactly one, `None` for none or for a repeat.
fn single(headers: &HeaderMap, name: &str) -> (Option<String>, bool) {
    let mut values = headers.get_all(name).iter();
    let first = values
        .next()
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let repeated = values.next().is_some();
    (first, repeated)
}

fn read_headers(headers: &HeaderMap) -> (WebhookHeaders, bool) {
    let (event, event_twice) = single(headers, "x-github-event");
    let (delivery, delivery_twice) = single(headers, "x-github-delivery");
    let (signature_256, signature_twice) = single(headers, "x-hub-signature-256");
    let (content_type, type_twice) = single(headers, "content-type");
    (
        WebhookHeaders {
            event,
            delivery,
            signature_256,
            content_type,
            has_legacy_signature: headers.contains_key("x-hub-signature"),
        },
        event_twice || delivery_twice || signature_twice || type_twice,
    )
}

/// The delivery id for a record, when it has the shape the verifier accepts.
fn subject_of(delivery: Option<&str>) -> String {
    match delivery {
        Some(id)
            if (8..=128).contains(&id.len())
                && id.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':')
                }) =>
        {
            format!("delivery {id}")
        }
        _ => "delivery none".to_owned(),
    }
}

/// `POST /v1/webhooks/github`.
pub async fn receive(state: &ApiState, headers: &HeaderMap, body: &[u8]) -> Answer {
    // No verifier, no endpoint: the route answers as an unknown route does.
    let verifier = state.ports.webhooks.as_ref().ok_or(ApiError::NotFound)?;
    let (read, repeated) = read_headers(headers);
    let verified = if repeated {
        Err(WebhookRejection::BadSignature)
    } else {
        verifier.verify(body, &read)
    };
    let delivery = match verified {
        Ok(delivery) => delivery,
        // Valid signature, not something the factory acts on. Acknowledged so GitHub does not retry.
        Err(WebhookRejection::UnsupportedEvent | WebhookRejection::Malformed) => {
            return accepted();
        }
        Err(_) => {
            state.platform_audit.report(PlatformEvent {
                action: "webhook_accepted_or_rejected.denied",
                subject: subject_of(read.delivery.as_deref()),
                reason: "The delivery did not pass its checks.",
            });
            return Err(ApiError::Unauthorized);
        }
    };
    let subject = subject_of(Some(&delivery.delivery_id));
    let Some(repository) = delivery.repository else {
        state.platform_audit.report(PlatformEvent {
            action: "webhook.unbound",
            subject,
            reason: "The delivery names no repository.",
        });
        return accepted();
    };
    if !state.limiter.allow(
        Key::Installation(delivery.installation.0),
        state.limits.webhook_per_installation_per_minute,
        std::time::Instant::now(),
    ) {
        return Err(ApiError::RateLimited);
    }
    let Some(bound) = state
        .ports
        .store
        .resolve_installation(delivery.installation, repository)
        .await?
    else {
        let factory_label = matches!(
            &delivery.hint,
            WebhookHint::IssueLabeled { label, .. } if *label == state.github.factory_label
        );
        state.platform_audit.report(PlatformEvent {
            action: "webhook.unbound",
            subject,
            reason: if factory_label {
                UNBOUND_FACTORY_LABEL
            } else {
                UNBOUND
            },
        });
        return accepted();
    };

    // The requester behind a factory label, found by numeric id before the transaction opens.
    let requester = requester_of(state, &delivery, bound.tenant).await?;

    let ids = &state.ports.ids;
    let scope = TenantScope::new(bound.tenant);
    let mut tx = state.ports.store.begin(scope).await?;
    let outcome = tx
        .record_delivery(NewWebhookDelivery {
            id: WebhookDeliveryId::from_uuid(ids.new_uuid()),
            delivery_id: delivery.delivery_id.clone(),
            event_name: delivery.event.clone(),
            action: delivery.action.clone(),
            installation: delivery.installation,
            repository: delivery.repository,
            sender_github_user_id: delivery.sender_github_user_id,
            body_sha256: delivery.body_sha256.clone(),
            semantic_key: delivery.semantic_key.clone(),
        })
        .await?;
    let (action, reason, recorded) = match outcome {
        DeliveryOutcome::Duplicate(_) => (
            "webhook.duplicate_delivery",
            "The delivery repeats one that was recorded.",
            None,
        ),
        DeliveryOutcome::Recorded(id) => (
            "webhook_accepted_or_rejected.granted",
            "The delivery was verified and recorded.",
            Some(id),
        ),
    };
    let mut witness = audit(state, &mut *tx, &subject, action, reason, None).await?;
    if let Some(delivery_row) = recorded
        && let WebhookHint::IssueLabeled { issue, label } = &delivery.hint
        && *label == state.github.factory_label
    {
        let registered = tx.get_repository(bound.repository).await?;
        // The label of a requester who is narrowed to other repositories makes no job (API-1).
        let in_reach = match delivery.sender_github_user_id {
            Some(sender) => state
                .allowlist_file
                .covers(bound.tenant, sender, &registered.value.identity())
                .map_err(|_| ApiError::Unavailable)?,
            None => false,
        };
        let authorized = requester.filter(|_| in_reach);
        // A repository whose attestor or enabler is no longer an active human takes no label, as a
        // disabled one does not (REG-6).
        let open = registered.value.open_for_new_jobs();
        if open && authorized.is_none() {
            // Someone who may not ask applied the factory label (FR-002, SC-002). No job. The
            // API holds no GitHub credential, so it cannot answer; it leaves one signed request
            // in the same transaction, which the worker answers and records.
            witness = ask_for_a_reply(
                state,
                &mut *tx,
                bound.tenant,
                &RejectionFields {
                    repository: bound.repository,
                    issue: issue.number,
                    sender: delivery.sender_github_user_id,
                    delivery: delivery.delivery_id.clone(),
                    allowlist: state
                        .allowlist_file
                        .entries()
                        .map_err(|_| ApiError::Unavailable)?
                        .0
                        .as_str()
                        .to_owned(),
                },
            )
            .await?;
        }
        if let (true, Some(requester)) = (open, authorized) {
            let job_id = JobId::from_uuid(ids.new_uuid());
            // The record of the job is written under the job's own correlation id, as every record
            // of a job is, so that one search finds all of them.
            let correlation = CorrelationId::from_uuid(ids.new_uuid());
            let pipeline_scope =
                PipelineScope::new(SLICE_ONE_SCOPE.to_vec()).map_err(|_| ApiError::Unavailable)?;
            tx.insert_job(NewJob {
                id: job_id,
                correlation_id: correlation,
                repository: bound.repository,
                requester,
                execution_mode: state.profile.execution_mode(),
                autonomy_level: registered.value.autonomy_ceiling,
                pipeline_scope,
                origin: Some(JobOrigin::Webhook(delivery_row)),
            })
            .await?;
            witness = audit(
                state,
                &mut *tx,
                // The repository is the registered one, found by the installation and repository
                // ids. The `full_name` of the payload is text the sender chose, and stale after a
                // rename (R-15).
                &format!("issue {}#{}", registered.value.full_name, issue.number),
                "job.received_from_webhook",
                "A job was received from a labeled issue.",
                Some((job_id, correlation)),
            )
            .await?;
        }
    }
    commit(state, scope, tx, Witness::Audit(witness)).await?;
    accepted()
}

/// The registered principal of the sender, when the delivery is a factory label from a person the
/// allowlist lists as a requester. Looked up by numeric id; the login in the payload is not read.
async fn requester_of(
    state: &ApiState,
    delivery: &VerifiedDelivery,
    tenant: factory_domain::ids::TenantId,
) -> Result<Option<factory_domain::ids::PrincipalId>, ApiError> {
    let WebhookHint::IssueLabeled { label, .. } = &delivery.hint else {
        return Ok(None);
    };
    let Some(sender) = delivery.sender_github_user_id else {
        return Ok(None);
    };
    if *label != state.github.factory_label {
        return Ok(None);
    }
    let mut tx = state
        .ports
        .store
        .begin(factory_domain::scope::TenantScope::new(tenant))
        .await?;
    let found = tx.find_principal_by_github_user(sender).await;
    let _ = tx.rollback().await;
    let Some(principal) = found?.filter(|p| p.disabled_at.is_none()) else {
        return Ok(None);
    };
    let roles = state
        .ports
        .authority
        .roles(tenant, principal.id)
        .await
        .map_err(|_| ApiError::Unavailable)?;
    Ok(roles
        .contains(&HumanRole::Requester)
        .then_some(principal.id))
}

/// Leaves the request for the reply to a label from someone who may not ask. The action is one the
/// database trigger lets the API write (`webhook_accepted_or_rejected.denied`); the words are the
/// registered repository, the issue number, the numeric id of the sender, the delivery id and the
/// version of the allowlist, and nothing from the payload that the sender chose. The word that
/// signs them is the one only the API can make, so the worker answers only a request that is the
/// API's (the grammar and the worker's side are in `factory_composition::intake_rejections`).
async fn ask_for_a_reply(
    state: &ApiState,
    tx: &mut dyn Tx,
    tenant: factory_domain::ids::TenantId,
    fields: &RejectionFields,
) -> Result<AuditEventId, ApiError> {
    let ids = &state.ports.ids;
    let id = AuditEventId::from_uuid(ids.new_uuid());
    let requested_at = state.ports.clock.now().as_text();
    let subject = state
        .decision_keys
        .signed_rejection_subject(&RejectionSigning {
            tenant,
            event: id,
            requested_at: &requested_at,
            fields,
        });
    tx.record_audit(NewAuditEvent {
        id,
        actor: AuditActor::Anonymous(
            factory_domain::values::Slug::parse("webhook").map_err(|_| ApiError::Unavailable)?,
        ),
        action: audit_action("webhook_accepted_or_rejected.denied")?,
        subject,
        decision: AuditDecision::Deny,
        reason: "A label from a sender who is not an authorized requester was refused.".to_owned(),
        policy_hash: state.policy_hash(),
        job: None,
        stage_run: None,
        correlation_id: CorrelationId::from_uuid(ids.new_uuid()),
    })
    .await?;
    Ok(id)
}

async fn audit(
    state: &ApiState,
    tx: &mut dyn Tx,
    subject: &str,
    action: &str,
    reason: &str,
    job: Option<(JobId, CorrelationId)>,
) -> Result<AuditEventId, ApiError> {
    let ids = &state.ports.ids;
    let id = AuditEventId::from_uuid(ids.new_uuid());
    // A record of a job has the job's correlation id. A record of no job has one of its own.
    let correlation_id = job.map_or_else(|| CorrelationId::from_uuid(ids.new_uuid()), |(_, c)| c);
    tx.record_audit(NewAuditEvent {
        id,
        actor: AuditActor::Anonymous(
            factory_domain::values::Slug::parse("webhook").map_err(|_| ApiError::Unavailable)?,
        ),
        action: audit_action(action)?,
        subject: subject.to_owned(),
        // The accepted delivery is a grant under the required type name; a repeat is only noted.
        decision: if action.ends_with(".granted") {
            AuditDecision::Allow
        } else {
            AuditDecision::Record
        },
        reason: reason.to_owned(),
        policy_hash: state.policy_hash(),
        job: job.map(|(job, _)| job),
        stage_run: None,
        correlation_id,
    })
    .await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn a_repeated_header_is_reported_as_repeated() {
        let mut headers = HeaderMap::new();
        headers.append("x-hub-signature-256", HeaderValue::from_static("sha256=aa"));
        let (_, repeated) = read_headers(&headers);
        assert!(!repeated);
        headers.append("x-hub-signature-256", HeaderValue::from_static("sha256=bb"));
        let (_, repeated) = read_headers(&headers);
        assert!(repeated);
    }

    #[test]
    fn the_legacy_header_is_noted_and_never_a_signature() {
        let mut headers = HeaderMap::new();
        headers.insert("x-hub-signature", HeaderValue::from_static("sha1=aa"));
        let (read, _) = read_headers(&headers);
        assert!(read.has_legacy_signature);
        assert!(read.signature_256.is_none());
    }

    #[test]
    fn only_a_delivery_id_of_the_accepted_shape_reaches_a_record() {
        assert_eq!(subject_of(Some("a1b2c3d4-e5f6")), "delivery a1b2c3d4-e5f6");
        for bad in [
            None,
            Some("short"),
            Some("has space in it"),
            Some("a;drop table x;"),
        ] {
            assert_eq!(subject_of(bad), "delivery none");
        }
    }
}
