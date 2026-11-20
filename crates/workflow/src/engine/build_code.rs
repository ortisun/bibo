//! Recording a security approver's decision on the project's own build code.
//!
//! The sibling of [`record_dependency_decision`](super::Engine::record_dependency_decision). The
//! validation stage blocks the gate `build` with `policy_unresolvable` when the change adds build
//! code of the project's own (`gates::scope::build_code`), and stores in its evidence document the
//! files that wait, each with the hash of its content (`gates::scope::own_build_code`). This is
//! the use case that records the decision. It changes no status: the stage run stays `BLOCKED`,
//! and the operator's `UnblockRerun` lets it go once this decision is in.
//!
//! # What is checked, in this order, before anything is written
//!
//! 1. **The acting principal** is a person of the tenant whose numeric GitHub id is the one on the
//!    proof, is not the requester of the job, and holds *now* the `security_approver` role. The
//!    action row `approve_build_code` names no other designation, and the engine does not rely on
//!    the proof for it.
//! 2. **The proof** is for the action `approve_build_code`. Nobody but the policy engine can make
//!    one.
//! 3. **The stage run** is the job's `VALIDATION` run and is `BLOCKED`.
//! 4. **The subject** (path and content hash) is one the run's own stored evidence shows as
//!    awaiting. A decision is never recorded for a file the person was not shown: the content of
//!    the person's words is never the subject.
//! 5. **The record** is made by [`ProjectBuildCodeApproval::record`], with the hash of the policy
//!    bundle the engine runs under, and the tenant and the job.
//!
//! # What is written, in one transaction
//!
//! The decision document as an artifact; a link from the stage run to it with the same role the
//! decisions on dependencies use (`dependency-decision-<k>-<command>`), which is what
//! `UnblockRerun` reads as its third alternative and which only counts for the attempt that
//! blocked the run; one ledger entry, an expert judgment that names the person and the role; and
//! an audit record. A command that arrives twice names the same role, so the second is
//! `Duplicate` and writes nothing. A refusal is audited and writes nothing else.

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
use super::solo::SoloCheck;
use super::timeline::Timeline;
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::commands::{Actor, ProjectBuildCodeRecorded, RecordProjectBuildCodeDecision};
use crate::gates::scope::own_build_code::{
    ARTIFACT_NOTE, BuildScript, EVIDENCE_KEY, ProjectBuildCodeApproval,
};
use crate::gates::supply_chain::approval::{ApprovalError, DecisionScope};
use factory_domain::policy::solo::{SoloTarget, SoloWait};

/// The entries of `awaiting` in a stored evidence document.
fn awaiting_in(document: &serde_json::Value) -> Vec<BuildScript> {
    document
        .get(EVIDENCE_KEY)
        .and_then(|section| section.get("awaiting"))
        .and_then(serde_json::Value::as_array)
        .map(|entries| entries.iter().filter_map(BuildScript::from_json).collect())
        .unwrap_or_default()
}

impl Engine {
    /// Records a security approver's decision on the project's own build code. See the module
    /// notes.
    ///
    /// # Errors
    /// * [`EngineError::NotAuthorized`] when the proof is not for the acting principal, the
    ///   principal is the requester or no longer holds the role, or the proof is not for the
    ///   action `approve_build_code`. Audited.
    /// * [`EngineError::Refused`] when the stage run is not a blocked `VALIDATION` run, the file
    ///   is not one its evidence awaits with that content, or the reason is too short. Audited.
    /// * [`EngineError::Duplicate`] when this command was already applied.
    /// * The store and artifact errors.
    pub async fn record_project_build_code_decision(
        &self,
        actor: &Actor,
        request: RecordProjectBuildCodeDecision,
    ) -> Result<ProjectBuildCodeRecorded, EngineError> {
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
            .apply_build_code_decision(
                &mut *tx,
                &cx,
                (actor, &roles),
                (&run, &job.value),
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
            Err(
                error @ (EngineError::NotAuthorized(_)
                | EngineError::Refused(_)
                | EngineError::SoloRefused(_)),
            ) => {
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

    async fn apply_build_code_decision(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        (actor, roles): (&Actor, &[HumanRole]),
        (run, job): (
            &factory_ports::store::Versioned<factory_ports::store::StageRun>,
            &factory_ports::store::Job,
        ),
        timeline: &Timeline,
        request: &RecordProjectBuildCodeDecision,
    ) -> Result<ProjectBuildCodeRecorded, EngineError> {
        // 1 and 2. The person, the proof and the role.
        let role = self
            .check_person(
                tx,
                actor,
                roles,
                job,
                &request.proof,
                (
                    &[Designation::SecurityApprover],
                    "the person who asked for the job may not decide on its build code",
                ),
                &SoloCheck {
                    request: request.solo.as_ref(),
                    milestone: timeline.run(run.value.id).and_then(|r| r.blocked_at),
                    wait: SoloWait::BuildCode,
                    expected: self
                        .config
                        .solo
                        .expected_word(&SoloTarget::ProjectBuildCode {
                            path: request.script.path.as_str(),
                        }),
                },
            )
            .await?;

        // 3. The stage run is the job's blocked validation run.
        if run.value.kind != StageKind::Validation
            || run.value.status != factory_domain::state::StageRunStatus::Blocked
        {
            return Err(EngineError::Refused(
                "a decision on build code is recorded for a blocked validation stage run",
            ));
        }

        // 4. The file is one the run's evidence awaits, with the content it shows.
        let record = timeline.run(run.value.id).ok_or(EngineError::Corrupt(
            "the stage run is not in the timeline of its job",
        ))?;
        let document = self
            .stored_evidence_document(tx, record.outputs.as_slice(), cx)
            .await?;
        if !awaiting_in(&document).contains(&request.script) {
            return Err(EngineError::Refused(
                "the stage run's evidence does not await a decision on that file with that content",
            ));
        }

        // 5. The record, bound to the policy bundle the engine runs under.
        let approval = ProjectBuildCodeApproval::record(
            &request.proof,
            request.script.clone(),
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
        let attempts = record
            .attempts
            .iter()
            .map(|attempt| attempt.number)
            .max()
            .unwrap_or(0);
        let role_name = links::decision_role(attempts, actor.command)?;
        let linked = tx.list_stage_run_artifacts(run.value.id).await?;
        if linked
            .iter()
            .any(|link| link.direction == ArtifactDirection::Input && link.role == role_name)
        {
            return Err(EngineError::Duplicate);
        }

        // What is written.
        let bytes = serde_json::to_vec(&approval.to_json())
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
            statement: approval.statement(),
            kind: ClaimKind::ExpertJudgment,
            assurance_level: None,
            confidence: ConfidenceLevel::Medium,
            rationale: "A named person stands behind this decision; it is not a measurement."
                .to_owned(),
        };
        let scope = HumanText::parse(&format!(
            "The person decided on the build code in {} with the content {}, as the {} stage run showed it.",
            approval.script.path, approval.script.sha256, run.value.kind
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
        Ok(ProjectBuildCodeRecorded {
            artifact,
            ledger_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_awaiting_list_is_read_from_the_stored_evidence_and_from_nowhere_else() {
        let script = "a".repeat(64);
        let document = json!({
            "kind": "validation-evidence",
            EVIDENCE_KEY: {
                "awaiting": [{"path": "build.rs", "sha256": format!("sha256:{script}")}],
                "decided": [{"path": "other/build.rs", "sha256": format!("sha256:{script}")}]
            }
        });
        let found = awaiting_in(&document);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, "build.rs");
        assert!(awaiting_in(&json!({})).is_empty());
        assert!(awaiting_in(&json!({EVIDENCE_KEY: {"awaiting": "build.rs"}})).is_empty());
    }
}
