//! Human decisions on a stage run, and who may take them.
//!
//! Every decision follows the same path. The roles of the principal are read from the
//! [`Authority`](crate::commands::Authority) *now*, so a person removed from the allowlist loses
//! the right at once (NT-AUTHZ-04). The engine checks the roles the move needs, builds the facts
//! of the guard from stored state, evaluates the guard, and applies the move with its evidence in
//! one transaction. A refusal is recorded in the audit log with the actor, and leaves the state as
//! it was.
//!
//! Text a person writes is untrusted. It is stored as an artifact, and the event carries only its
//! hash. An approval is bound to the evidence the person saw: the hash of the last ledger entry
//! must still be the head, so a gate result that arrived after the person looked invalidates the
//! approval (NT-MRG-02, NT-MRG-03).

use factory_domain::contracts::ArtifactRef;
use factory_domain::contracts::evidence_ledger_entry::{
    Attestor, ClaimKind, Evidence, ExpertJudgmentEvidence,
};
use factory_domain::ids::{PrincipalId, StageRunId};
use factory_domain::machines::guards::{
    AnswerFacts, ApprovalFacts, GuardFacts, HumanRejectFacts, HumanReworkFacts,
    OverrideFacts as DomainOverride, UnblockFacts,
};
use factory_domain::machines::rework::{
    HumanReworkDecision, HumanReworkRequest, decide_human_rework,
};
use factory_domain::state::{Guard, StageRunEvent, StageRunStatus};
use factory_domain::values::{HumanText, MediaType};
use factory_domain::vocabulary::{ConfidenceLevel, GateOutcome, HumanRole, StageKind};
use factory_ports::store::{
    ArtifactDirection, AuditActor, GateRecord, StageRun, StageRunEffects, Tx, Versioned,
};
use serde_json::json;

use super::Engine;
use super::decision::{DecisionKind, DecisionReport};
use super::error::EngineError;
use super::failure::HumanReason;
use super::gate::ReworkMove;
use super::ledger::ClaimSpec;
use super::links;
use super::payload::{self, key};
use super::progress::clear;
use super::record::{Cx, Step, index_entry};
use super::timeline::{RunRecord, Timeline};
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::commands::{Actor, Decision, Subject};

/// The sentence stored as the input a specification approval adds to its stage run. It is the
/// factory's own text, never a person's.
const APPROVAL_NOTE: &str = "The approver approved the draft that was shown.";

impl Engine {
    /// Applies a human decision to a stage run.
    ///
    /// # Errors
    /// * [`EngineError::NotAuthorized`] when the principal lacks the role the move needs. The
    ///   refusal is audited.
    /// * [`EngineError::GuardUnmet`] when the guard does not hold, for instance an approval whose
    ///   evidence is out of date. The refusal is audited.
    /// * [`EngineError::Illegal`] when the stage run is not in a state the decision applies to.
    /// * [`EngineError::Duplicate`] when this command was already applied.
    /// * The store errors.
    pub async fn decide(
        &self,
        actor: &Actor,
        subject: Subject,
        decision: Decision,
    ) -> Result<(), EngineError> {
        let roles = self.roles_of(actor).await?;
        // Text a person wrote is stored before the transaction opens, and only its hash is used.
        let stored = match &decision {
            Decision::Answer { text, .. } => Some(self.store_text(text.as_bytes()).await?),
            Decision::Reject { reason } => Some(self.store_text(reason.as_str().as_bytes()).await?),
            Decision::Override { justification, .. } => {
                Some(self.store_text(justification.as_str().as_bytes()).await?)
            }
            // Not a person's text: a fixed sentence. Only an approval of a specification keeps it
            // (see `apply_decision`), and every other approval ignores it.
            Decision::Approve { .. } => Some(self.store_text(APPROVAL_NOTE.as_bytes()).await?),
            _ => None,
        };
        let mut tx = self.tenant_tx(actor.tenant).await?;
        let job = tx.get_job(subject.job).await?;
        let run = tx.get_stage_run(subject.stage_run).await?;
        if run.value.job_id != subject.job {
            return Err(EngineError::NotFound);
        }
        let timeline = Timeline::load(&mut *tx, subject.job).await?;
        if timeline.has_applied(actor.command) {
            return Err(EngineError::Duplicate);
        }
        // A review that waits because no model was independent of the author has no verdict. An
        // approval would pass it on nobody's review, so it is refused here, before the state
        // machine's `S14` could apply. The person sends the work back, rejects it or cancels.
        if matches!(decision, Decision::Approve { .. })
            && run.value.status == StageRunStatus::WaitingForHuman
            && timeline
                .run(run.value.id)
                .and_then(|record| record.wait_reason.as_deref())
                == Some(HumanReason::NoIndependentReviewer.code())
        {
            drop(tx);
            self.record_denial(
                actor,
                subject,
                AuditAction::new(AuditKind::ApprovalGrantedOrRejected, AuditDecision::Denied),
            )
            .await?;
            return Err(EngineError::Refused(
                "the review waits because no model independent of the author was available, and \
                 an approval would pass it with no review verdict; send the work back, reject it \
                 or cancel the job",
            ));
        }
        let cx = Cx::new(self, &job.value, actor.command);
        let applied = self
            .apply_decision(
                &mut *tx, &cx, actor, &roles, &job.value, &run, &timeline, &decision, stored,
            )
            .await;
        match applied {
            Ok(action) => {
                cx.audit(&mut *tx, AuditActor::Human(actor.principal), action)
                    .await?;
                self.settle(&mut *tx, &cx).await?;
                cx.commit(tx).await?;
                Ok(())
            }
            Err(error @ (EngineError::NotAuthorized(_) | EngineError::GuardUnmet(_))) => {
                drop(tx);
                let kind = match decision {
                    Decision::Approve { .. } | Decision::Reject { .. } => {
                        AuditKind::ApprovalGrantedOrRejected
                    }
                    Decision::Override { .. } => AuditKind::HumanOverride,
                    _ => AuditKind::AuthorizationDecision,
                };
                self.record_denial(
                    actor,
                    subject,
                    AuditAction::new(kind, AuditDecision::Denied),
                )
                .await?;
                Err(error)
            }
            Err(other) => Err(other),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_decision(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        actor: &Actor,
        roles: &[HumanRole],
        job: &factory_ports::store::Job,
        run: &Versioned<StageRun>,
        timeline: &Timeline,
        decision: &Decision,
        stored: Option<ArtifactRef>,
    ) -> Result<AuditAction, EngineError> {
        let holds = |role: HumanRole| roles.contains(&role);
        let is_requester = actor.principal == job.requester;
        let base = payload::with(
            payload::for_run(run.value.kind, run.value.id),
            key::PRINCIPAL,
            json!(actor.principal.to_string()),
        );
        match decision {
            Decision::Answer {
                raises_budget_ceiling,
                ..
            } => {
                let may = holds(HumanRole::Operator)
                    || holds(HumanRole::Approver)
                    || holds(HumanRole::OrgAdmin)
                    || (holds(HumanRole::Requester) && is_requester);
                if !may {
                    return Err(EngineError::NotAuthorized(
                        "only the requester, an operator, an approver or an org admin may answer",
                    ));
                }
                let facts = AnswerFacts {
                    answer_recorded_with_principal: true,
                    answer_became_a_new_input_hash: stored.is_some(),
                    raises_a_ceiling: *raises_budget_ceiling,
                    principal_is_org_admin: holds(HumanRole::OrgAdmin),
                };
                let cleared = clear(Guard::AnswerRecorded, &GuardFacts::Answer(facts))?;
                let answer = stored.ok_or(EngineError::Corrupt("an answer was not stored"))?;
                self.index_for(tx, cx, run.value.id, &answer).await?;
                self.link_answer(tx, run.value.id, &answer).await?;
                cx.move_stage_run(
                    tx,
                    run,
                    Step::new(StageRunEvent::HumanAnswered, cleared)
                        .cause("answered")
                        .payload(base),
                    StageRunEffects::default(),
                )
                .await?;
                Ok(AuditAction::new(
                    AuditKind::AuthorizationDecision,
                    AuditDecision::Granted,
                ))
            }
            Decision::Approve {
                evidence_seen,
                warnings_decided,
            } => {
                let head = tx.ledger_head(cx.job).await?;
                let facts = ApprovalFacts {
                    decision_is_approve: true,
                    // Nobody approves their own request: a distinct approver is required. For the
                    // approval of a pull request the policy has already said which designation
                    // counts at this tier (a critical change names `security_approver` alone), so
                    // a person who holds either approving role satisfies the engine (AUT-3). The
                    // freezing of a specification stays with the `approver` role.
                    principal_holds_required_role: (holds(HumanRole::Approver)
                        || (run.value.kind == StageKind::Approval
                            && holds(HumanRole::SecurityApprover)))
                        && !is_requester,
                    evidence_digest_seen_equals_current: head
                        .as_ref()
                        .is_some_and(|head| &head.hash == evidence_seen),
                    translation_warnings_decided: *warnings_decided,
                };
                if !facts.principal_holds_required_role {
                    return Err(EngineError::NotAuthorized(
                        "an approval needs an approver other than the requester",
                    ));
                }
                let cleared = clear(Guard::ApproverAuthorized, &GuardFacts::Approval(facts))?;
                self.record_judgment(
                    tx,
                    cx,
                    run,
                    actor.principal,
                    if holds(HumanRole::Approver) {
                        HumanRole::Approver
                    } else {
                        HumanRole::SecurityApprover
                    },
                    "approved",
                )
                .await?;
                if run.value.kind == StageKind::Specification {
                    // The specification stage has stored nothing yet when it asks: it keeps its
                    // draft aside and waits. Its next attempt reads the judgment above from the
                    // ledger (`SpecApprovals`) and freezes exactly that draft. Passing the run
                    // here would pass a stage with no specification in it, so the approval sends
                    // the run back to `READY` the way an answer does (`S13`), and the stage
                    // passes by its own attempt. The state machine's `S14` still holds for every
                    // stage that stores its result before it asks.
                    let note =
                        stored.ok_or(EngineError::Corrupt("the approval note was not stored"))?;
                    let answered = clear(
                        Guard::AnswerRecorded,
                        &GuardFacts::Answer(AnswerFacts {
                            answer_recorded_with_principal: true,
                            answer_became_a_new_input_hash: true,
                            raises_a_ceiling: false,
                            principal_is_org_admin: holds(HumanRole::OrgAdmin),
                        }),
                    )?;
                    self.index_for(tx, cx, run.value.id, &note).await?;
                    self.link_answer(tx, run.value.id, &note).await?;
                    cx.move_stage_run(
                        tx,
                        run,
                        Step::new(StageRunEvent::HumanAnswered, answered)
                            .cause("approved-for-freezing")
                            .payload(base),
                        StageRunEffects::default(),
                    )
                    .await?;
                    return Ok(AuditAction::new(
                        AuditKind::ApprovalGrantedOrRejected,
                        AuditDecision::Granted,
                    ));
                }
                // No gate ran, but the decision still rests on a document: the person, the role
                // and the evidence they had seen. The gate record names it by hash, as the store
                // requires for every outcome but NOT_APPLICABLE.
                let mut details = serde_json::Map::new();
                details.insert("decided_by".to_owned(), json!(actor.principal.to_string()));
                details.insert("role".to_owned(), json!(HumanRole::Approver.as_str()));
                details.insert("evidence_seen".to_owned(), json!(evidence_seen.to_string()));
                details.insert("warnings_decided".to_owned(), json!(warnings_decided));
                let report = cx
                    .record_decision(
                        tx,
                        &DecisionReport {
                            kind: DecisionKind::HumanApproval,
                            outcome: GateOutcome::Passed,
                            stage_run: run.value.id,
                            stage: run.value.kind,
                            cause: "approved",
                            details,
                        },
                    )
                    .await?;
                cx.move_stage_run(
                    tx,
                    run,
                    Step::new(StageRunEvent::HumanApproved, cleared)
                        .cause("approved")
                        .payload(base),
                    StageRunEffects {
                        gate: Some(GateRecord {
                            outcome: GateOutcome::Passed,
                            report_sha256: Some(report),
                            failing_set_sha256: None,
                        }),
                        ..StageRunEffects::default()
                    },
                )
                .await?;
                Ok(AuditAction::new(
                    AuditKind::ApprovalGrantedOrRejected,
                    AuditDecision::Granted,
                ))
            }
            Decision::Reject { .. } => {
                if !holds(HumanRole::Approver) {
                    return Err(EngineError::NotAuthorized("only an approver may reject"));
                }
                let facts = HumanRejectFacts {
                    decider_is_authorized_approver: true,
                    reject_decision_recorded: true,
                    reason_recorded: stored.is_some(),
                };
                let cleared = clear(Guard::HumanRejected, &GuardFacts::HumanReject(facts))?;
                self.record_judgment(
                    tx,
                    cx,
                    run,
                    actor.principal,
                    HumanRole::Approver,
                    "rejected",
                )
                .await?;
                cx.move_stage_run(
                    tx,
                    run,
                    Step::new(StageRunEvent::HumanRejected, cleared)
                        .cause("rejected")
                        .payload(base),
                    StageRunEffects::default(),
                )
                .await?;
                Ok(AuditAction::new(
                    AuditKind::ApprovalGrantedOrRejected,
                    AuditDecision::Ended,
                ))
            }
            Decision::RequestRework { target } => {
                let request = HumanReworkRequest {
                    from: run.value.kind,
                    target: *target,
                    principal_roles: roles,
                    ledger: timeline.rework,
                    limits: self.config.rework_limits,
                };
                match decide_human_rework(&request) {
                    HumanReworkDecision::Rework(plan) => {
                        let cleared = clear(
                            Guard::HumanReworkAllowed,
                            &GuardFacts::HumanRework(HumanReworkFacts {
                                principal_roles: roles,
                                rounds_used: timeline.rework.used(plan.track),
                                cap: self.config.rework_limits.cap(plan.track),
                            }),
                        )?;
                        self.apply_rework(
                            tx,
                            cx,
                            run,
                            &plan,
                            ReworkMove {
                                event: StageRunEvent::HumanRequestedRework,
                                cleared,
                                effects: StageRunEffects::default(),
                            },
                        )
                        .await?;
                        Ok(AuditAction::new(
                            AuditKind::AuthorizationDecision,
                            AuditDecision::Granted,
                        ))
                    }
                    HumanReworkDecision::Refused(failure) => {
                        if !(holds(HumanRole::Approver) || holds(HumanRole::Operator)) {
                            return Err(EngineError::NotAuthorized(
                                "only an approver or an operator may send work back",
                            ));
                        }
                        Err(EngineError::GuardUnmet(failure))
                    }
                    HumanReworkDecision::NoRoute(_) => Err(EngineError::Refused(
                        "the table of human rework routes has no such route from this stage",
                    )),
                }
            }
            Decision::UnblockRerun {
                capability_reprobe_passed,
                dependency_now_available,
            } => {
                if !holds(HumanRole::Operator) {
                    return Err(EngineError::NotAuthorized("only an operator may unblock"));
                }
                let facts = UnblockFacts {
                    capability_reprobe_passed: *capability_reprobe_passed,
                    missing_dependency_now_available: *dependency_now_available,
                    // Read from what the engine stored: a decision recorded through
                    // `record_dependency_decision` after the attempt that blocked this run. The
                    // caller cannot assert it, so a composition root has no bool to pass blindly.
                    dependency_decision_recorded: timeline
                        .run(run.value.id)
                        .is_some_and(RunRecord::dependency_decision_since_last_attempt),
                };
                let cleared = clear(Guard::BlockClearedRerun, &GuardFacts::Unblock(facts))?;
                cx.move_stage_run(
                    tx,
                    run,
                    Step::new(StageRunEvent::UnblockedRerun, cleared)
                        .cause("unblocked")
                        .payload(base),
                    StageRunEffects::default(),
                )
                .await?;
                Ok(AuditAction::new(
                    AuditKind::AuthorizationDecision,
                    AuditDecision::Granted,
                ))
            }
            Decision::Override { facts, .. } => {
                let required = if facts.security_class {
                    HumanRole::SecurityApprover
                } else {
                    HumanRole::Approver
                };
                if !holds(required) {
                    return Err(EngineError::NotAuthorized(
                        "an override needs the role the block requires",
                    ));
                }
                // What blocked the run is read from the event the engine wrote, and the
                // blocks that no override may pass from the engine's own configuration. The
                // caller's `policy_permits` can only narrow this: a caller that writes `true` by
                // hand gets the engine's answer. A run whose stored block names nothing is
                // refused, because nothing says what the override would accept.
                let blocks = timeline
                    .run(run.value.id)
                    .map_or(&[][..], |record| record.blocks.as_slice());
                let engine_permits = !blocks.is_empty()
                    && blocks
                        .iter()
                        .all(|block| !self.config.non_overridable_blocks.contains(block));
                let guard = DomainOverride {
                    policy_permits_override_for_block_code: facts.policy_permits && engine_permits,
                    block_is_security_class: facts.security_class,
                    principal_roles: roles,
                    role_required_by_policy: required,
                    justification_recorded: stored.is_some(),
                    blocked_gate_is_mandatory_of_active_profile: facts.mandatory_of_active_profile,
                };
                let cleared = clear(Guard::OverridePermitted, &GuardFacts::Override(guard))?;
                self.record_judgment(
                    tx,
                    cx,
                    run,
                    actor.principal,
                    required,
                    "accepted the risk of",
                )
                .await?;
                cx.move_stage_run(
                    tx,
                    run,
                    Step::new(StageRunEvent::OverrideAccepted, cleared)
                        .cause("override")
                        .payload(base),
                    StageRunEffects::default(),
                )
                .await?;
                Ok(AuditAction::new(
                    AuditKind::HumanOverride,
                    AuditDecision::Granted,
                ))
            }
        }
    }

    /// The roles of the principal now, or a refusal when the configuration cannot be read.
    pub(super) async fn roles_of(&self, actor: &Actor) -> Result<Vec<HumanRole>, EngineError> {
        self.deps
            .authority
            .roles(actor.tenant, actor.principal)
            .await
            .map_err(|_| EngineError::Refused("the protected configuration cannot be read"))
    }

    /// Stores a person's text as an artifact and returns its reference.
    async fn store_text(&self, bytes: &[u8]) -> Result<ArtifactRef, EngineError> {
        self.deps
            .artifacts
            .put(bytes.to_vec(), MediaType::parse("text/plain")?)
            .await
            .map_err(|error| EngineError::Artifacts(error.to_string()))
    }

    /// Records in the tenant's index that it holds an artifact made for a stage run.
    async fn index_for(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        run: StageRunId,
        artifact: &ArtifactRef,
    ) -> Result<(), EngineError> {
        tx.index_artifact(index_entry(artifact, cx.job, run)?)
            .await?;
        Ok(())
    }

    /// Links the answer to the stage run as an input, in the transaction that records the move
    /// (`S13`). The role says how many attempts the run had, which is where the window of attempts
    /// starts again (see [`links`](super::links)). The database computes the same number into
    /// `stage_runs.attempts_before_last_answer` when the run moves to `READY`.
    async fn link_answer(
        &self,
        tx: &mut dyn Tx,
        run: StageRunId,
        answer: &ArtifactRef,
    ) -> Result<(), EngineError> {
        let attempts_before = tx
            .list_attempts(run)
            .await?
            .iter()
            .map(|attempt| attempt.value.number)
            .max()
            .unwrap_or(0);
        tx.link_stage_run_artifact(
            run,
            ArtifactDirection::Input,
            links::answer_role(attempts_before)?,
            answer.sha256.clone(),
        )
        .await?;
        Ok(())
    }

    /// Writes the ledger entry that names the person who stands behind a decision. It is a
    /// judgment: it supports no assurance level, so an override or an approval never creates one.
    async fn record_judgment(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        run: &Versioned<StageRun>,
        principal: PrincipalId,
        role: HumanRole,
        what: &str,
    ) -> Result<(), EngineError> {
        let scope = HumanText::parse(&format!(
            "The person {what} the {} stage run after reading the recorded evidence.",
            run.value.kind
        ))?;
        let claim = ClaimSpec {
            statement: format!(
                "A person with the role {} {what} the {} stage run.",
                role.as_str(),
                run.value.kind
            ),
            kind: ClaimKind::ExpertJudgment,
            assurance_level: None,
            confidence: ConfidenceLevel::Medium,
            rationale: "A named person stands behind this decision; it is not a measurement."
                .to_owned(),
        };
        let evidence = Evidence::ExpertJudgment(ExpertJudgmentEvidence {
            attestor: Attestor {
                principal_id: principal,
                role,
            },
            scope,
            recorded_at: cx.now,
        });
        cx.record_claim(tx, run.value.id, None, &claim, &[evidence])
            .await?;
        Ok(())
    }

    /// Records a refused decision in the audit log, in a transaction of its own because the
    /// decision's transaction is dropped.
    pub(super) async fn record_denial(
        &self,
        actor: &Actor,
        subject: Subject,
        action: AuditAction,
    ) -> Result<(), EngineError> {
        let mut tx = self.tenant_tx(actor.tenant).await?;
        let job = tx.get_job(subject.job).await?;
        let cx = Cx::new(self, &job.value, actor.command);
        cx.audit(&mut *tx, AuditActor::Human(actor.principal), action)
            .await?;
        cx.commit(tx).await?;
        Ok(())
    }
}
