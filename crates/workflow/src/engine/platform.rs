//! Audit events that belong to no job and no tenant.
//!
//! A webhook with a bad signature, or one from an installation nobody registered, is an event of
//! the platform: there is no tenant to write it under and no job to attach it to (FR-002). The
//! store keeps such events in the platform's own audit chain (`Store::record_platform_audit`).
//!
//! Only the component that receives webhooks may write there, so the caller passes the
//! [`PlatformScope`] in. The engine never makes one: it adds what it knows, which is the record's
//! identifier, the policy in force and a correlation id that belongs to this event alone.

use factory_domain::ids::{AuditEventId, CorrelationId};
use factory_domain::scope::PlatformScope;
use factory_ports::store::{
    AuditAction as PortAuditAction, AuditActor, AuditDecision as PortAuditDecision, AuditRecord,
    NewAuditEvent,
};

use super::Engine;
use super::error::EngineError;
use crate::audit::{AuditAction, AuditDecision};

/// What the caller knows about an event of the platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformEvent {
    /// Who did it, or `Anonymous` when nobody could be identified.
    pub actor: AuditActor,
    /// What was done and what was decided.
    pub action: AuditAction,
    /// What it was done to, 1 to 500 bytes. Never a secret and never issue text.
    pub subject: String,
    /// Why, 1 to 1000 bytes. Never reveals which test of a group failed.
    pub reason: String,
}

impl Engine {
    /// Records an audit event that belongs to no job and no tenant, under the platform's own
    /// chain. The write is idempotent by the record's identifier, which the engine makes.
    ///
    /// # Errors
    /// The store errors, including `Constraint(TextBounds)` for a subject or reason that is empty
    /// or too long.
    pub async fn record_platform_event(
        &self,
        scope: PlatformScope,
        event: PlatformEvent,
    ) -> Result<AuditRecord, EngineError> {
        let slug = event.action.slug()?;
        let record = self
            .deps
            .store
            .record_platform_audit(
                scope,
                NewAuditEvent {
                    id: AuditEventId::from_uuid(self.deps.ids.new_uuid()),
                    actor: event.actor,
                    action: PortAuditAction::new(slug.as_str())?,
                    subject: event.subject,
                    decision: match event.action.decision {
                        AuditDecision::Granted => PortAuditDecision::Allow,
                        AuditDecision::Denied => PortAuditDecision::Deny,
                        AuditDecision::Ended | AuditDecision::Noted => PortAuditDecision::Record,
                    },
                    reason: event.reason,
                    policy_hash: self.config.policy_hash.clone(),
                    job: None,
                    stage_run: None,
                    // An event with no job has no correlation id of a job; it gets its own.
                    correlation_id: CorrelationId::from_uuid(self.deps.ids.new_uuid()),
                },
            )
            .await?;
        Ok(record)
    }
}
