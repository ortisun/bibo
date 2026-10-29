//! Recording a person's decision on a dependency (review B-4).
//!
//! The supply chain gates block `dependency-review` with `policy_unresolvable` until a decision
//! covers every new direct dependency (and, for build code, every package that has it). This is the
//! one use case that records such a decision. It changes no status: the stage run stays `BLOCKED`.
//! What it does is write what the next steps read.
//!
//! # What is checked, in this order, before anything is written
//!
//! 1. **The acting principal** is a human of the tenant whose numeric GitHub id is the one on the
//!    proof, is not the requester of the job (separation of duties: a new dependency is a high-tier
//!    change), and the roles that principal holds *now* (the [`Authority`](crate::commands::Authority)
//!    seam reads the allowlist for each call) include the one the designation on the proof names.
//!    A proof made for another person, or for a person removed since, is refused.
//! 2. **The proof** is for one of the two actions of `approval.yaml` (`add_new_direct_dependency`,
//!    `approve_build_code`). Nobody but the policy engine can make a proof, and it has already
//!    applied the allowlist, the level, the action row and separation of duties.
//! 3. **The stage run** is the job's `VALIDATION` run and is `BLOCKED`.
//! 4. **The subject** (name, version, checksum) is one the run's own stored evidence shows as
//!    awaited, of the kind the proof is for, and the designation on the proof is enough for it
//!    (an approver cannot decide what needs a security approver). A decision is never recorded
//!    for a package the person was not shown: a decision given ahead of time would cover a later
//!    candidate of the same job.
//! 5. **The record** is made by `DependencyApproval::record`, with the hash of the policy bundle
//!    the engine runs under (the one the stages read as their policy input; the caller does not
//!    choose it), and the tenant and the job.
//!
//! # What is written, in one transaction
//!
//! * the decision document, as an artifact of the tenant ([`DependencyApproval::to_json`]);
//! * a link from the stage run to it, an input with the role `dependency-decision-<k>-<command>`
//!   (see [`links`](super::links)): this is what `UnblockRerun` reads, as the third alternative of
//!   guard `G_BLOCK_CLEARED_RERUN`, and it only counts for the attempt that blocked the run;
//! * one ledger entry, an expert judgment that names the person and the role and cites the
//!   document by its hash ([`gates::supply_chain::ledger`](crate::gates::supply_chain::ledger)),
//!   which is where the gate reads the decisions back from;
//! * an audit record, `approval_granted_or_rejected`.
//!
//! A command that arrives twice names the same role, so the second is `Duplicate` and writes
//! nothing. A refusal is audited and writes nothing else.

use factory_domain::contracts::evidence_ledger_entry::{
    ArtifactEvidence, Attestor, ClaimKind, Evidence, ExpertJudgmentEvidence,
};
use factory_domain::ids::PrincipalId;
use factory_domain::policy::decision::{AuthorizedApproval, Designation};
use factory_domain::values::{HumanText, MediaType};
use factory_domain::vocabulary::{ConfidenceLevel, HumanRole, StageKind};
use factory_ports::store::{ArtifactDirection, AuditActor, PrincipalKind, StageRun, Tx, Versioned};

use super::Engine;
use super::error::EngineError;
use super::ledger::ClaimSpec;
use super::links;
use super::record::{Cx, index_entry};
use super::timeline::Timeline;
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::commands::{Actor, DependencyDecisionRecorded, RecordDependencyDecision};
use crate::gates::supply_chain::approval::{
    ApprovalKind, DecisionScope, DependencyApproval, Subject as Package,
};
use crate::gates::supply_chain::ledger::{ARTIFACT_NOTE, statement_of};
use crate::gates::supply_chain::review::awaiting_in;
use crate::stages::validation::EVIDENCE;

/// The role a designation must be held as for the engine's own check of the roles.
fn role_of(designation: Designation) -> Option<HumanRole> {
    match designation {
        Designation::Approver => Some(HumanRole::Approver),
        Designation::SecurityApprover => Some(HumanRole::SecurityApprover),
        _ => None,
    }
}

impl Engine {
    /// Checks the person behind a proof of authority, for the decisions that are bound to what a
    /// blocked stage run waits for: the acting principal is a person of the tenant whose numeric
    /// GitHub id is the one on the proof, is not the person who asked for the job (separation of
    /// duties, RR-24: the requester is known here and nowhere else), and holds *now* the role of
    /// the designation the proof names, which must be one of `wanted`. Returns that role.
    pub(super) async fn check_person(
        &self,
        tx: &mut dyn Tx,
        actor: &Actor,
        roles: &[HumanRole],
        requester: PrincipalId,
        proof: &AuthorizedApproval,
        (wanted, requester_refusal): (&[Designation], &'static str),
    ) -> Result<HumanRole, EngineError> {
        let principal = tx.get_principal(actor.principal).await?;
        let PrincipalKind::Human { github_user_id } = principal.kind else {
            return Err(EngineError::NotAuthorized(
                "only a person records a decision on what a blocked stage run waits for",
            ));
        };
        if principal.disabled_at.is_some() || github_user_id != proof.approver().get() {
            return Err(EngineError::NotAuthorized(
                "the proof of authority is for another person",
            ));
        }
        if actor.principal == requester {
            return Err(EngineError::NotAuthorized(requester_refusal));
        }
        let designation = proof.designation();
        let role = wanted
            .contains(&designation)
            .then(|| role_of(designation))
            .flatten()
            .ok_or(EngineError::NotAuthorized(
                "the proof names a designation that does not decide on this",
            ))?;
        if !roles.contains(&role) {
            return Err(EngineError::NotAuthorized(
                "the person no longer holds the role the proof names",
            ));
        }
        Ok(role)
    }

    /// Records a person's decision on a dependency or on its build code. See the module notes.
    ///
    /// # Errors
    /// * [`EngineError::NotAuthorized`] when the proof is not for the acting principal, the
    ///   principal no longer holds the role, or the proof is not for a decision on a dependency.
    ///   Audited.
    /// * [`EngineError::Refused`] when the stage run is not a blocked `VALIDATION` run, the
    ///   subject is not one its evidence awaits, the designation is not enough, or the decision
    ///   cannot be made (a reason that is too short, a checksum that is not one). Audited.
    /// * [`EngineError::Duplicate`] when this command was already applied.
    /// * The store and artifact errors.
    pub async fn record_dependency_decision(
        &self,
        actor: &Actor,
        request: RecordDependencyDecision,
    ) -> Result<DependencyDecisionRecorded, EngineError> {
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
            .apply_dependency_decision(
                &mut *tx,
                &cx,
                actor,
                &roles,
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

    #[allow(clippy::too_many_arguments)]
    async fn apply_dependency_decision(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        actor: &Actor,
        roles: &[HumanRole],
        (run, requester): (&Versioned<StageRun>, PrincipalId),
        timeline: &Timeline,
        request: &RecordDependencyDecision,
    ) -> Result<DependencyDecisionRecorded, EngineError> {
        // 1. The acting principal is the person the proof is for, is not the requester, and holds
        // the role now.
        let role = self
            .check_person(
                tx,
                actor,
                roles,
                requester,
                &request.proof,
                (
                    &[Designation::Approver, Designation::SecurityApprover],
                    "the person who asked for the job may not decide on its dependencies",
                ),
            )
            .await?;

        // 2. The proof is for one of the two actions.
        let kind =
            ApprovalKind::of_action(request.proof.action()).ok_or(EngineError::NotAuthorized(
                "the proof is for an action that is not a dependency decision",
            ))?;

        // 3. The stage run is the job's blocked validation run.
        if run.value.kind != StageKind::Validation
            || run.value.status != factory_domain::state::StageRunStatus::Blocked
        {
            return Err(EngineError::Refused(
                "a decision on a dependency is recorded for a blocked validation stage run",
            ));
        }

        // 4. The subject is one the run's evidence awaits, and the designation is enough.
        let record = timeline.run(run.value.id).ok_or(EngineError::Corrupt(
            "the stage run is not in the timeline of its job",
        ))?;
        let evidence = self
            .stored_evidence(tx, record.outputs.as_slice(), cx)
            .await?;
        let awaited = awaiting_in(&evidence)
            .into_iter()
            .find(|awaited| awaited.kind == kind && awaited.subject.same_as(&request.package))
            .ok_or(EngineError::Refused(
                "the stage run's evidence does not await a decision of this kind on that package",
            ))?;

        // 5. The record. It is bound to the hash of the policy bundle the engine runs under: the
        // same hash the stage reads as its policy input, so a decision taken under another bundle
        // is not one the review counts (B-7). The caller does not choose it.
        let policy_hash = self.config.policy_hash.clone();
        let approval = DependencyApproval::record(
            &request.proof,
            Package {
                name: awaited.subject.name.clone(),
                version: awaited.subject.version.clone(),
                checksum: awaited.subject.checksum.clone(),
            },
            policy_hash,
            DecisionScope {
                tenant: cx.tenant,
                job: cx.job,
            },
            request.reason.as_str(),
        )
        .map_err(|error| match error {
            crate::gates::supply_chain::approval::ApprovalError::WrongAction => {
                EngineError::NotAuthorized("the proof is for another action")
            }
            crate::gates::supply_chain::approval::ApprovalError::NoReason => {
                EngineError::Refused("a decision needs a reason of at least ten characters")
            }
            crate::gates::supply_chain::approval::ApprovalError::NoChecksum => {
                EngineError::Refused("the dependency has no valid checksum to bind the decision to")
            }
        })?;
        if !approval.satisfies(awaited.needs) {
            return Err(EngineError::Refused(
                "the person's designation is not enough for what this package needs",
            ));
        }

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
            statement: statement_of(&approval),
            kind: ClaimKind::ExpertJudgment,
            assurance_level: None,
            confidence: ConfidenceLevel::Medium,
            rationale: "A named person stands behind this decision; it is not a measurement."
                .to_owned(),
        };
        let scope = HumanText::parse(&format!(
            "The person decided on {} {} with the checksum {}, as the {} stage run showed it.",
            approval.subject.name,
            approval.subject.version,
            approval.subject.checksum,
            run.value.kind
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
        Ok(DependencyDecisionRecorded {
            kind,
            artifact,
            ledger_hash,
        })
    }

    /// The dependency review in the evidence document of the blocked stage run, read from the
    /// artifact the run stored. A run that stored none, or none the engine can read, awaits nothing.
    async fn stored_evidence(
        &self,
        tx: &mut dyn Tx,
        outputs: &[crate::handlers::NamedArtifact],
        cx: &Cx<'_>,
    ) -> Result<serde_json::Value, EngineError> {
        Ok(self
            .stored_evidence_document(tx, outputs, cx)
            .await?
            .get("dependency_review")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }

    /// The whole evidence document of the blocked stage run, as the run stored it, or `null`.
    pub(super) async fn stored_evidence_document(
        &self,
        tx: &mut dyn Tx,
        outputs: &[crate::handlers::NamedArtifact],
        cx: &Cx<'_>,
    ) -> Result<serde_json::Value, EngineError> {
        self.stored_document(tx, outputs, cx, EVIDENCE).await
    }

    /// The first of the stage run's `outputs` that is a document of this `kind`, as it was stored,
    /// or `null`. The kind is the document's own `kind` field.
    pub(super) async fn stored_document(
        &self,
        tx: &mut dyn Tx,
        outputs: &[crate::handlers::NamedArtifact],
        cx: &Cx<'_>,
        kind: &str,
    ) -> Result<serde_json::Value, EngineError> {
        let scope = factory_domain::scope::TenantScope::new(cx.tenant);
        for output in outputs {
            let Ok(indexed) = tx.get_artifact_index(&output.artifact.sha256).await else {
                continue;
            };
            let Ok(bytes) = self.deps.artifacts.get(&scope, &indexed.artifact).await else {
                continue;
            };
            let Ok(document) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                continue;
            };
            if document.get("kind").and_then(serde_json::Value::as_str) == Some(kind) {
                return Ok(document);
            }
        }
        Ok(serde_json::Value::Null)
    }
}
