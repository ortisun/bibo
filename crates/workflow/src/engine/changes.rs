//! A change from outside the pipeline: the source request was edited, the repository map changed,
//! or a value that gate evidence is bound to moved.
//!
//! Nothing in the pipeline produces such a change, so nothing is spared: every live run that the
//! invalidation table lists for it becomes `SUPERSEDED`, the first one included, its live attempts
//! are cancelled, and a new run starts for each (ADR 0010, decision 4). The table is the domain's
//! `plan_for_change`, which the conformance test compares with `state-machine.json`.
//!
//! The caller is a trusted component: the webhook handler that saw the edit, or the delivery
//! stage that compared the evidence binding. A person cannot send this command.

use factory_domain::ids::{JobId, StageRunId, TenantId};
use factory_domain::machines::invalidation::{ArtifactChange, plan_for_change};
use factory_domain::state::{JobStatus, Status};
use factory_domain::vocabulary::StageKind;

use super::Engine;
use super::error::EngineError;
use super::record::Cx;
use super::replace::Why;

/// What a change did to the job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeApplied {
    /// The runs that became stale, in the order of the invalidation table.
    pub superseded: Vec<StageRunId>,
    /// The new runs that replace them.
    pub created: Vec<(StageKind, StageRunId)>,
}

/// The short code the events and audit records give for a change.
const fn code(change: ArtifactChange) -> &'static str {
    match change {
        ArtifactChange::RequestEdited => "request-edited",
        ArtifactChange::RepositoryMapVersion => "repository-map-changed",
        ArtifactChange::GateEvidenceBinding => "gate-evidence-binding-changed",
        _ => "artifact-changed",
    }
}

impl Engine {
    /// Applies a change to a job.
    ///
    /// # Errors
    /// * [`EngineError::Refused`] when the job has ended or is being cancelled.
    /// * The store errors, including [`EngineError::Conflict`] when another writer moved first.
    pub async fn apply_change(
        &self,
        tenant: TenantId,
        job: JobId,
        change: ArtifactChange,
    ) -> Result<ChangeApplied, EngineError> {
        let mut tx = self.tenant_tx(tenant).await?;
        let stored = tx.get_job(job).await?;
        if stored.value.status.is_terminal() || stored.value.status == JobStatus::Cancelling {
            return Err(EngineError::Refused(
                "the job has ended or is being cancelled, so a change cannot be applied",
            ));
        }
        let cx = Cx::new(self, &stored.value, self.new_causation_id());
        let snaps = self.snapshots_of(&mut *tx, &cx).await?;
        let stale = plan_for_change(&snaps, change);
        // One new run for each stale run, in pipeline order.
        let mut kinds: Vec<StageKind> = Vec::new();
        for id in &stale {
            if let Some(snapshot) = snaps.iter().find(|s| s.id == *id)
                && !kinds.contains(&snapshot.kind)
            {
                kinds.push(snapshot.kind);
            }
        }
        kinds.sort_by_key(|kind| super::config::position(*kind));
        let why = if change.producer().is_none() {
            Why::External
        } else {
            Why::ArtifactChanged
        };
        let created = self
            .supersede_and_replace(&mut *tx, &cx, &stale, &kinds, why, code(change))
            .await?;
        self.settle(&mut *tx, &cx).await?;
        cx.commit(tx).await?;
        Ok(ChangeApplied {
            superseded: stale,
            created,
        })
    }
}
