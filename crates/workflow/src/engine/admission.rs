//! Admission: from a stored request to a running job (`J01`), or to a refusal (`J02`).
//!
//! The API checks the caller and stores the request as a `RECEIVED` job. Admission is the
//! engine's own decision: is the requester on the allowlist, is the tenant within its quota, is
//! the repository registered and enabled, and does policy allow this class of request
//! (`G_ADMISSION_OK`). A job that passes gets its stage runs, one for each stage in the scope, and
//! the first stage becomes ready. A job that does not is rejected, the reasons go to the audit
//! log, and nothing in the reply says which test failed (`G_ADMISSION_DENIED`).

use factory_domain::ids::{JobId, PrincipalId, StageRunId, TenantId};
use factory_domain::machines::guards::{GuardFacts, evaluate};
use factory_domain::state::{Guard, JobEvent, JobStatus};
use factory_domain::vocabulary::StageKind;
use factory_ports::store::{AuditActor, NewJob, NewStageRun};
use serde_json::json;

use super::Engine;
use super::error::EngineError;
use super::payload::{self, key};
use super::progress::guard_error;
use super::record::Cx;
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use factory_domain::ids::CorrelationId;

/// What admission decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// The job is `ACTIVE`. These are its stage runs, in pipeline order.
    Admitted {
        /// The stage runs created for the job.
        stage_runs: Vec<(StageKind, StageRunId)>,
    },
    /// The job is `REJECTED`. The reply does not say why: the reasons are in the audit log.
    Rejected,
}

impl Engine {
    /// Stores a request as a job in `RECEIVED`. The API does this after it has authenticated the
    /// caller; it is here so that the engine and its tests have one way to make a job.
    ///
    /// # Errors
    /// The store errors, for instance when the requester is not a principal of the tenant.
    pub async fn receive_job(
        &self,
        tenant: TenantId,
        requester: PrincipalId,
    ) -> Result<JobId, EngineError> {
        let id = JobId::from_uuid(self.deps.ids.new_uuid());
        let correlation = CorrelationId::from_uuid(self.deps.ids.new_uuid());
        let mut tx = self.tenant_tx(tenant).await?;
        tx.insert_job(NewJob {
            id,
            correlation_id: correlation,
            requester,
            created_at: self.deps.clock.now(),
        })
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Decides whether a received job runs.
    ///
    /// # Errors
    /// * [`EngineError::NoHandler`] when a stage in the scope has no handler. The job stays
    ///   `RECEIVED`: a job that could never finish is not admitted.
    /// * [`EngineError::Illegal`] when the job is not `RECEIVED`.
    /// * [`EngineError::Refused`] when the protected configuration cannot be read. The engine
    ///   fails closed and leaves the job `RECEIVED`, so a later call can decide.
    /// * The store errors, including [`EngineError::Conflict`] when another engine decided first.
    pub async fn admit_job(&self, tenant: TenantId, job: JobId) -> Result<Admission, EngineError> {
        for kind in &self.config.scope {
            if self.handlers.get(*kind).is_none() {
                return Err(EngineError::NoHandler(*kind));
            }
        }
        let mut tx = self.tenant_tx(tenant).await?;
        let stored = tx.get_job(job).await?;
        let cx = Cx::new(self, &stored.value, self.new_causation_id());

        let facts = self
            .deps
            .authority
            .admission(tenant, stored.value.requester)
            .await
            .map_err(|_| EngineError::Refused("the protected configuration cannot be read"))?;

        match evaluate(Guard::AdmissionOk, &GuardFacts::Admission(facts)) {
            Ok(()) => {
                let mut created = Vec::with_capacity(self.config.scope.len());
                for kind in &self.config.scope {
                    let id = self.new_stage_run_id();
                    tx.insert_stage_run(NewStageRun {
                        id,
                        job_id: job,
                        kind: *kind,
                        created_at: cx.now,
                    })
                    .await?;
                    created.push((*kind, id));
                }
                let listed: Vec<_> = created
                    .iter()
                    .map(|(kind, id)| payload::run_ref(*id, *kind))
                    .collect();
                let mut event = serde_json::Map::new();
                event.insert(key::STAGE_RUNS.to_owned(), json!(listed));
                event.insert(
                    "autonomy_limited_to_l0".to_owned(),
                    json!(facts.autonomy_limited_to_l0()),
                );
                cx.move_job(&mut *tx, &stored, JobEvent::Admit, None, event)
                    .await?;
                cx.audit_engine(
                    &mut *tx,
                    AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Granted),
                )
                .await?;
                self.settle(&mut *tx, &cx).await?;
                tx.commit().await?;
                Ok(Admission::Admitted {
                    stage_runs: created,
                })
            }
            Err(_) => {
                // The definition of G_ADMISSION_DENIED is the opposite of G_ADMISSION_OK, so it
                // holds here. It is evaluated anyway: a move needs its own guard.
                evaluate(Guard::AdmissionDenied, &GuardFacts::Admission(facts))
                    .map_err(guard_error)?;
                cx.move_job(
                    &mut *tx,
                    &stored,
                    JobEvent::RejectAtAdmission,
                    Some("admission-denied"),
                    serde_json::Map::new(),
                )
                .await?;
                cx.audit(
                    &mut *tx,
                    AuditActor::Component(factory_domain::values::Slug::parse(
                        super::record::COMPONENT,
                    )?),
                    AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),
                )
                .await?;
                tx.commit().await?;
                Ok(Admission::Rejected)
            }
        }
    }

    /// The status of a job.
    ///
    /// # Errors
    /// [`EngineError::NotFound`] when the job does not exist for the tenant.
    pub async fn job_status(&self, tenant: TenantId, job: JobId) -> Result<JobStatus, EngineError> {
        let mut tx = self.tenant_tx(tenant).await?;
        let stored = tx.get_job(job).await?;
        tx.rollback().await?;
        Ok(stored.value.status)
    }
}
