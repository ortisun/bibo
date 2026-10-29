//! Recording an approver's decision about a translation warning.
//!
//! The sibling of [`record_dependency_decision`](super::Engine::record_dependency_decision). The
//! approval stage stores an approval request that counts the open warnings of the documentation
//! reviewer's rule `translation-unfaithful`, and the guard `G_APPROVER_AUTHORIZED` holds an
//! approval back until every one has a decision of the approver. This is the use case that
//! records one decision. It moves nothing: the stage run stays `WAITING_FOR_HUMAN`, and the
//! approval that follows reads the decisions back from the ledger (`stages::approval::warnings`).
//!
//! # What is checked, in this order, before anything is written
//!
//! 1. **The acting principal** is a person of the tenant whose numeric GitHub id is the one on the
//!    proof, is not the requester of the job, and holds *now* the `approver` role.
//! 2. **The proof** is for the action `acknowledge_documentation_warning`.
//! 3. **The stage run** is the job's `APPROVAL` run and waits for a person.
//! 4. **The warning** is one the run's own stored approval request counts: a number from 1 to the
//!    number of open warnings. The request is read from what the run stored, and the manifest the
//!    decision is bound to is the one in it, not one the caller names.
//!
//! # What is written, in one transaction
//!
//! The decision document as an artifact; a link from the stage run to it under a role of its own
//! (`warning-decision-<command>`, which `UnblockRerun` does not read); one ledger entry, an expert
//! judgment that names the person and the role; and an audit record. A command that arrives twice
//! names the same role, so the second is `Duplicate` and writes nothing.

use factory_domain::contracts::evidence_ledger_entry::{
    ArtifactEvidence, Attestor, ClaimKind, Evidence, ExpertJudgmentEvidence,
};
use factory_domain::policy::decision::Designation;
use factory_domain::values::{HumanText, MediaType};
use factory_domain::vocabulary::{ConfidenceLevel, HumanRole, StageKind};
use factory_ports::store::{ArtifactDirection, AuditActor, Tx};

use super::Engine;
use super::error::EngineError;
use super::ledger::ClaimSpec;
use super::links;
use super::record::{Cx, index_entry};
use super::timeline::Timeline;
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::commands::{Actor, RecordWarningDecision, WarningDecisionRecorded};
use crate::gates::supply_chain::approval::{ApprovalError, DecisionScope};
use crate::stages::approval::warnings::ARTIFACT_NOTE;
use crate::stages::approval::warnings::{WarningDecision, warnings_of_request};

impl Engine {
    /// Records an approver's decision about one translation warning. See the module notes.
    ///
    /// # Errors
    /// * [`EngineError::NotAuthorized`] when the proof is not for the acting principal, the
    ///   principal is the requester or no longer holds the role, or the proof is not for the
    ///   action `acknowledge_documentation_warning`. Audited.
    /// * [`EngineError::Refused`] when the stage run is not an approval run that waits for a
    ///   person, the warning is not one its request counts, or the reason is too short. Audited.
    /// * [`EngineError::Duplicate`] when this command was already applied.
    /// * The store and artifact errors.
    pub async fn record_warning_decision(
        &self,
        actor: &Actor,
        request: RecordWarningDecision,
    ) -> Result<WarningDecisionRecorded, EngineError> {
        let roles = self.roles_of(actor).await?;
        let mut tx = self.tenant_tx(actor.tenant).await?;
        let job = tx.get_job(request.stage.job).await?;
        let run = tx.get_stage_run(request.stage.stage_run).await?;
        if run.value.job_id != request.stage.job {
            return Err(EngineError::NotFound);
        }
        let timeline = Timeline::load(&mut *tx, request.stage.job).await?;
        let cx = Cx::new(self, &job.value, actor.command);
        let applied = self
            .apply_warning_decision(
                &mut *tx,
                &cx,
                (actor, &roles),
                (&run, job.value.requester),
                &timeline,
                &request,
            )
            .await;
        match applied {
            Ok(recorded) => {
                cx.audit(
                    &mut *tx,
                    AuditActor::Human(actor.principal),
                    AuditAction::new(AuditKind::ApprovalGrantedOrRejected, AuditDecision::Granted),
                )
                .await?;
                cx.commit(tx).await?;
                Ok(recorded)
            }
            Err(error @ (EngineError::NotAuthorized(_) | EngineError::Refused(_))) => {
                drop(tx);
                self.record_denial(
                    actor,
                    request.stage,
                    AuditAction::new(AuditKind::ApprovalGrantedOrRejected, AuditDecision::Denied),
                )
                .await?;
                Err(error)
            }
            Err(other) => Err(other),
        }
    }

    async fn apply_warning_decision(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        (actor, roles): (&Actor, &[HumanRole]),
        (run, requester): (
            &factory_ports::store::Versioned<factory_ports::store::StageRun>,
            factory_domain::ids::PrincipalId,
        ),
        timeline: &Timeline,
        request: &RecordWarningDecision,
    ) -> Result<WarningDecisionRecorded, EngineError> {
        // 1 and 2. The person, the proof and the role.
        let role = self
            .check_person(
                tx,
                actor,
                roles,
                requester,
                &request.proof,
                (
                    &[Designation::Approver],
                    "the person who asked for the job may not decide on its translation warnings",
                ),
            )
            .await?;

        // 3. The stage run is the job's approval run, and it waits for a person.
        if run.value.kind != StageKind::Approval
            || run.value.status != factory_domain::state::StageRunStatus::WaitingForHuman
        {
            return Err(EngineError::Refused(
                "a decision on a translation warning is recorded for an approval stage run that waits for a person",
            ));
        }

        // 4. The warning is one the stored request counts, and the manifest is the request's own.
        let record = timeline.run(run.value.id).ok_or(EngineError::Corrupt(
            "the stage run is not in the timeline of its job",
        ))?;
        // The request is found by what it says it is, as the evidence is, and not by its name.
        let document = self
            .stored_document(tx, record.outputs.as_slice(), cx, "approval-request")
            .await?;
        let (open, manifest) = warnings_of_request(&document).ok_or(EngineError::Refused(
            "the approval stage run stored no request that counts warnings",
        ))?;
        if request.warning == 0 || request.warning > open {
            return Err(EngineError::Refused(
                "the approval request does not count a warning with that number",
            ));
        }

        // 5. The record, bound to the policy bundle the engine runs under.
        let decision = WarningDecision::record(
            &request.proof,
            (run.value.id, manifest, request.warning),
            self.config.policy_hash.clone(),
            DecisionScope {
                tenant: cx.tenant,
                job: cx.job,
            },
            request.reason.as_str(),
        )
        .map_err(|error| match error {
            ApprovalError::WrongAction => {
                EngineError::NotAuthorized("the proof is for another action")
            }
            ApprovalError::NoReason | ApprovalError::NoChecksum => {
                EngineError::Refused("a decision needs a reason of at least ten characters")
            }
        })?;

        // A repeat of the command names the same role and writes nothing.
        let role_name = links::warning_role(actor.command)?;
        let linked = tx.list_stage_run_artifacts(run.value.id).await?;
        if linked
            .iter()
            .any(|link| link.direction == ArtifactDirection::Input && link.role == role_name)
        {
            return Err(EngineError::Duplicate);
        }

        // What is written.
        let bytes = serde_json::to_vec(&decision.to_json())
            .map_err(|error| EngineError::Invalid(error.to_string()))?;
        let artifact = cx.defer_blob(bytes, MediaType::parse("application/json")?);
        tx.index_artifact(index_entry(&artifact, cx.job, run.value.id)?)
            .await?;
        tx.link_stage_run_artifact(
            run.value.id,
            ArtifactDirection::Input,
            role_name,
            artifact.sha256.clone(),
        )
        .await?;
        let claim = ClaimSpec {
            statement: decision.statement(),
            kind: ClaimKind::ExpertJudgment,
            assurance_level: None,
            confidence: ConfidenceLevel::Medium,
            rationale: "A named person stands behind this decision; it is not a measurement."
                .to_owned(),
        };
        let scope = HumanText::parse(&format!(
            "The person decided on translation warning {} of the approval request, as the {} stage run showed it.",
            decision.warning, run.value.kind
        ))?;
        let evidence = [
            Evidence::ExpertJudgment(ExpertJudgmentEvidence {
                attestor: Attestor {
                    principal_id: actor.principal,
                    role,
                },
                scope,
                recorded_at: cx.now,
            }),
            Evidence::Artifact(ArtifactEvidence {
                sha256: artifact.sha256.clone(),
                media_type: artifact.media_type.clone(),
                description: Some(HumanText::parse(ARTIFACT_NOTE)?),
            }),
        ];
        let ledger_hash = cx
            .record_claim(tx, run.value.id, None, &claim, &evidence)
            .await?;
        Ok(WarningDecisionRecorded {
            artifact,
            ledger_hash,
        })
    }
}
