//! A record that must be in the store before the handler acts on the world (DR-3).
//!
//! The engine writes what a handler notes when the attempt ends (`record_handler_notes`), with the
//! result. An attempt that is cancelled, that loses its lease or whose process is killed never gets
//! there, so a note is not a record. The design gate says it writes the record of a refusal before
//! the reply is tried, and the reply is a comment on the issue that nobody can take back: the
//! record must be in the store by then. [`EngineRecords`] is what the handler calls for it
//! (`StageContext::record_now`): it opens a transaction of its own for the tenant, writes one audit
//! row with the same actor, policy hash and correlation id as a noted record, and commits.
//!
//! The row is written whatever the state of the lease. It is a fact about a decision that was
//! taken, it changes no aggregate, and the epoch check guards the writes that do. If the store
//! cannot take it, the error goes back to the handler, which does not act, and the attempt is tried
//! again.

use async_trait::async_trait;
use factory_domain::ids::{AuditEventId, CorrelationId, JobId, TenantId};
use factory_domain::values::Slug;
use factory_domain::vocabulary::StageKind;
use factory_ports::store::{
    AuditAction as PortAuditAction, AuditActor, AuditDecision as PortAuditDecision, NewAuditEvent,
};

use super::Engine;
use crate::audit::{AuditAction, AuditDecision};
use crate::handlers::{DurableRecords, StageError};
use crate::scheduler::ClaimedAttempt;

/// The longest reason the store takes. A longer one is cut at a character boundary, as the record
/// of a noted fact is.
const REASON_MAX_BYTES: usize = 1000;

/// Writes the durable records of one attempt.
pub(crate) struct EngineRecords<'e> {
    engine: &'e Engine,
    tenant: TenantId,
    job: JobId,
    correlation: CorrelationId,
    kind: StageKind,
}

impl<'e> EngineRecords<'e> {
    /// The writer for the attempt `claimed` names.
    pub(crate) fn new(engine: &'e Engine, claimed: &ClaimedAttempt) -> Self {
        Self {
            engine,
            tenant: claimed.tenant,
            job: claimed.job,
            correlation: claimed.correlation,
            kind: claimed.kind,
        }
    }
}

#[async_trait]
impl DurableRecords for EngineRecords<'_> {
    async fn record(&self, action: AuditAction, mut reason: String) -> Result<(), StageError> {
        // The same actor a noted record has: the stage handler of this kind of stage.
        let actor = AuditActor::System(
            Slug::parse(&format!(
                "stage-handler.{}",
                self.kind.as_str().to_ascii_lowercase()
            ))
            .map_err(|_| StageError::Internal)?,
        );
        let slug = action.slug().map_err(|_| StageError::Internal)?;
        if reason.len() > REASON_MAX_BYTES {
            let mut end = REASON_MAX_BYTES;
            while !reason.is_char_boundary(end) {
                end -= 1;
            }
            reason.truncate(end);
        }
        let event = NewAuditEvent {
            id: AuditEventId::from_uuid(self.engine.deps.ids.new_uuid()),
            actor,
            action: PortAuditAction::new(slug.as_str()).map_err(|_| StageError::Internal)?,
            subject: format!("job {}", self.job),
            decision: match action.decision {
                AuditDecision::Granted => PortAuditDecision::Allow,
                AuditDecision::Denied => PortAuditDecision::Deny,
                AuditDecision::Ended | AuditDecision::Noted => PortAuditDecision::Record,
            },
            reason,
            policy_hash: self.engine.config.policy_hash.clone(),
            job: Some(self.job),
            stage_run: None,
            correlation_id: self.correlation,
        };
        let mut tx = self
            .engine
            .tenant_tx(self.tenant)
            .await
            .map_err(|_| StageError::Tool)?;
        if tx.record_audit(event).await.is_err() {
            let _ = tx.rollback().await;
            return Err(StageError::Tool);
        }
        // A commit whose answer is lost may or may not have been applied. The handler then
        // fails the attempt and tries again, which can leave the record twice and never none.
        tx.commit().await.map_err(|_| StageError::Tool)
    }
}
