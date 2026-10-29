//! The audit stream of the broker: what happened to a token, as typed events.
//!
//! An event carries identifiers, counts and closed reasons. It carries no free text from a
//! request or an answer, no header and no secret, so there is nothing in a line that needs to be
//! scrubbed; the JSON writer scrubs it anyway with the exact values the broker holds.

use std::io::Write;
use std::sync::{Arc, Mutex};

use factory_domain::ids::{JobId, TenantId};
use factory_domain::redaction::Redactor;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::StageKind;
use factory_ports::agent::{CostMicroUsd, JobTokenId, Usage};

use super::caps::{Refusal, RevokeReason};
use super::provider::Provider;

/// One thing that happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// When the broker's clock said it happened.
    pub at: Timestamp,
    /// What happened.
    pub kind: AuditKind,
}

/// What happened. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditKind {
    /// A token was issued.
    TokenIssued {
        /// The token.
        token: JobTokenId,
        /// Its tenant.
        tenant: TenantId,
        /// Its job.
        job: JobId,
        /// Its stage.
        stage: StageKind,
        /// Its ceiling.
        ceiling: CostMicroUsd,
    },
    /// A token was revoked.
    TokenRevoked {
        /// The token.
        token: JobTokenId,
        /// Its job.
        job: JobId,
        /// Why.
        reason: RevokeReason,
    },
    /// The recorded cost crossed a percentage of the ceiling. Written once per percentage: at
    /// `warn_percent` (80) and at 100.
    BudgetThreshold {
        /// The token.
        token: JobTokenId,
        /// Its job.
        job: JobId,
        /// The percentage that was crossed.
        percent: u8,
        /// The cost recorded when it was crossed.
        cost: CostMicroUsd,
        /// The ceiling.
        ceiling: CostMicroUsd,
    },
    /// A request was let through to the provider.
    RequestAdmitted {
        /// The token.
        token: JobTokenId,
        /// Its job.
        job: JobId,
        /// The provider it goes to.
        provider: Provider,
    },
    /// A request was refused before anything was sent to a provider.
    RequestRefused {
        /// The token, when the credential matched one.
        token: Option<JobTokenId>,
        /// Why.
        reason: Refusal,
    },
    /// An admitted request ended and its usage was recorded.
    RequestSettled {
        /// The token.
        token: JobTokenId,
        /// Its job.
        job: JobId,
        /// What the request added to the token's usage.
        added: Usage,
        /// False when the usage could not be read from the answer and the broker charged the
        /// worst case for one request instead.
        usage_read: bool,
    },
}

impl AuditEvent {
    /// The event as one JSON object, with stable field names.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        let mut value = match &self.kind {
            AuditKind::TokenIssued {
                token,
                tenant,
                job,
                stage,
                ceiling,
            } => json!({
                "event": "token_issued", "token": token.to_string(), "tenant": tenant.to_string(),
                "job": job.to_string(), "stage": stage.as_str(), "ceiling_micro_usd": ceiling.0,
            }),
            AuditKind::TokenRevoked { token, job, reason } => json!({
                "event": "token_revoked", "token": token.to_string(), "job": job.to_string(),
                "reason": reason.as_str(),
            }),
            AuditKind::BudgetThreshold {
                token,
                job,
                percent,
                cost,
                ceiling,
            } => json!({
                "event": "budget_threshold", "token": token.to_string(), "job": job.to_string(),
                "percent": percent, "cost_micro_usd": cost.0, "ceiling_micro_usd": ceiling.0,
            }),
            AuditKind::RequestAdmitted {
                token,
                job,
                provider,
            } => json!({
                "event": "request_admitted", "token": token.to_string(), "job": job.to_string(),
                "provider": provider.as_str(),
            }),
            AuditKind::RequestRefused { token, reason } => {
                let mut line = json!({
                    "event": "request_refused", "token": token.map(|t| t.to_string()),
                    "reason": reason.as_str(), "status": reason.http_status(),
                });
                // The class of what the broker would not forward: a closed name, never the key,
                // the value or the position.
                if let (Refusal::RequestShape(violation), Some(object)) =
                    (reason, line.as_object_mut())
                {
                    object.insert("detail".to_owned(), json!(violation.as_str()));
                }
                line
            }
            AuditKind::RequestSettled {
                token,
                job,
                added,
                usage_read,
            } => json!({
                "event": "request_settled", "token": token.to_string(), "job": job.to_string(),
                "input_tokens": added.input_tokens, "output_tokens": added.output_tokens,
                "cost_micro_usd": added.cost.0, "usage_read": usage_read,
            }),
        };
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "at".to_owned(),
                serde_json::Value::String(self.at.as_text()),
            );
        }
        value
    }
}

/// Where audit events go.
pub trait AuditSink: Send + Sync {
    /// Records one event. It must not block for long and must not fail the request: an audit
    /// sink that cannot write drops the line and the broker goes on.
    fn record(&self, event: AuditEvent);
}

/// Drops every event.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullAudit;

impl AuditSink for NullAudit {
    fn record(&self, _event: AuditEvent) {}
}

/// Keeps every event in memory, for tests and for a caller that wants to read them back.
#[derive(Debug, Default)]
pub struct MemoryAudit {
    events: Mutex<Vec<AuditEvent>>,
}

impl MemoryAudit {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A copy of the events so far.
    #[must_use]
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }
}

impl AuditSink for MemoryAudit {
    fn record(&self, event: AuditEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }
}

/// Writes one JSON object per line to a writer, after the redactor has had a look at the line.
pub struct JsonLinesAudit<W: Write + Send> {
    out: Mutex<W>,
    redactor: Arc<Redactor>,
}

impl<W: Write + Send> JsonLinesAudit<W> {
    /// A sink that writes to `out` and scrubs with `redactor`.
    pub fn new(out: W, redactor: Arc<Redactor>) -> Self {
        Self {
            out: Mutex::new(out),
            redactor,
        }
    }
}

impl<W: Write + Send> AuditSink for JsonLinesAudit<W> {
    fn record(&self, event: AuditEvent) {
        let line = event.to_json().to_string();
        // If the redactor fails the line is dropped, as the policy says: raw text is never
        // written because the redactor was unavailable.
        let Ok(clean) = self.redactor.redact_str(&line) else {
            return;
        };
        if let Ok(mut out) = self.out.lock() {
            let _ = writeln!(out, "{}", clean.output);
            let _ = out.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_domain::values::Timestamp;
    use factory_ports::clock::Uuid;

    fn at() -> Timestamp {
        Timestamp::parse("2026-10-28T10:00:00Z").expect("a timestamp")
    }

    #[test]
    fn an_event_becomes_one_json_object_with_stable_names_and_no_free_text() {
        let event = AuditEvent {
            at: at(),
            kind: AuditKind::RequestRefused {
                token: Some(JobTokenId::from_uuid(Uuid::from_u128(7))),
                reason: Refusal::Revoked(RevokeReason::CostCeiling),
            },
        };
        let json = event.to_json();
        assert_eq!(json["event"], "request_refused");
        assert_eq!(json["reason"], "revoked");
        assert_eq!(json["status"], 402);
        assert_eq!(json["at"], "2026-10-28T10:00:00Z");
    }

    #[test]
    fn the_json_writer_writes_one_line_per_event() {
        let redactor = Arc::new(Redactor::builder().build().expect("a redactor"));
        let sink = JsonLinesAudit::new(Vec::<u8>::new(), redactor);
        sink.record(AuditEvent {
            at: at(),
            kind: AuditKind::RequestRefused {
                token: None,
                reason: Refusal::UnknownToken,
            },
        });
        let written = sink.out.lock().expect("the lock").clone();
        let text = String::from_utf8(written).expect("utf-8");
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("\"reason\":\"unknown_token\""));
    }
}
