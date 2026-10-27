//! Applying a gate outcome: the ledger entries that justify it, and the move.
//!
//! The stage run goes from `RUNNING` to `GATING` (`S04`) and then takes the move that the outcome
//! names, in the same transaction as the attempt's success and the evidence (INV-03). The domain
//! guard of each move is evaluated with facts the engine computed from the stored evidence, never
//! from anything the handler said:
//!
//! | Outcome | Move | Guard |
//! |---|---|---|
//! | pass | `S08` | `G_GATE_PASS_EVIDENCED` |
//! | blocked | `S11` | `G_BLOCKING_CONDITION` |
//! | failed, or changes required, rework allowed | `S09` | `G_REWORK_ALLOWED` |
//! | a person decides | `S10` | `G_NEEDS_HUMAN_VERDICT` |
//! | failed with no route | `S12` | `G_GATE_FAILED_NO_REWORK` |
//!
//! A pass whose guard does not hold (a criterion without evidence, say) does not fail the stage
//! and does not pass it: it blocks, because the evidence is missing.

use factory_domain::contracts::evidence_ledger_entry::{
    ArtifactEvidence, ClaimKind, Evidence, TestEvidence, TestResult,
};
use factory_domain::contracts::review_verdict::DefectClass;
use factory_domain::contracts::{ArtifactRef, StageContract};
use factory_domain::machines::guards::{
    BlockingFacts, GatePassFacts, GuardFacts, NeedsHumanFacts, NoReworkFacts, ReworkFacts, evaluate,
};
use factory_domain::machines::rework::{
    GateFinding, GateReworkDecision, GateReworkRequest, NeedsHumanCause, ReworkPlan,
    decide_gate_rework,
};
use factory_domain::machines::snapshot::StageRunSnapshot;
use factory_domain::state::{Guard, StageRunEvent, StageRunStatus};
use factory_domain::values::{HumanText, MediaType, Sha256Digest};
use factory_domain::vocabulary::{ConfidenceLevel, GateOutcome, Verdict};
use factory_ports::store::{StageRun, Tx, Versioned};
use serde_json::{Value, json};

use super::Engine;
use super::error::EngineError;
use super::ledger::ClaimSpec;
use super::payload::{self, key};
use super::progress::guard_error;
use super::record::Cx;
use super::timeline::Timeline;
use crate::audit::{AuditAction, AuditDecision, AuditKind};
use crate::gates::framework::{
    BlockCause, EvidenceProblem, GateDecision, Resolution, resolve, snapshots,
};
use crate::handlers::NamedArtifact;

/// A decision together with where its documents were stored, before the transaction opens.
#[derive(Debug)]
pub(crate) struct Judged {
    /// What the handler handed over.
    pub(crate) decision: GateDecision,
    /// The stored form of each report, in the order of `decision.reports`.
    pub(crate) reports: Vec<ArtifactRef>,
    /// The stored form of the verdict.
    pub(crate) review: Option<ArtifactRef>,
    /// Why the evidence was refused, if it was. Refused evidence is neither stored nor cited.
    pub(crate) problem: Option<EvidenceProblem>,
    /// The gate said it could not run (a tool or capability is missing).
    pub(crate) could_not_run: bool,
}

impl Engine {
    /// Moves the running stage run through `GATING` to the outcome of its gate.
    ///
    /// # Errors
    /// Any error of a guard, a move or a read. The caller drops the transaction.
    pub(crate) async fn gate_stage(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        run: &Versioned<StageRun>,
        contract: &StageContract,
        judged: &Judged,
        outputs: &[NamedArtifact],
    ) -> Result<(), EngineError> {
        let listed: Vec<Value> = outputs
            .iter()
            .map(|named| {
                json!({
                    "name": named.name.as_str(),
                    "sha256": named.artifact.sha256.as_str(),
                    "media_type": named.artifact.media_type.as_str(),
                })
            })
            .collect();
        let gating_payload = payload::with(
            payload::for_run(run.value.kind, run.value.id),
            key::OUTPUTS,
            Value::Array(listed),
        );
        let version = cx
            .move_stage_run(
                tx,
                run,
                StageRunEvent::AttemptSucceeded,
                None,
                gating_payload,
            )
            .await?;
        let gating = Versioned {
            value: StageRun {
                status: StageRunStatus::Gating,
                ..run.value.clone()
            },
            version,
        };

        let resolution = if judged.problem.is_some() {
            Resolution::Blocked(BlockCause::InvalidEvidence)
        } else if judged.could_not_run {
            Resolution::Blocked(BlockCause::MissingEvidence)
        } else {
            resolve(contract, &judged.decision)
        };
        if judged.problem.is_none() {
            self.record_gate_evidence(tx, cx, &gating, judged).await?;
        }
        // What the metrics will say. A pass whose guard does not hold is a block, and says so.
        let mut metric_outcome = match &resolution {
            Resolution::Pass => "passed",
            Resolution::Blocked(_) => "blocked",
            Resolution::Failed { .. } | Resolution::ChangesRequired { .. } => "failed",
            Resolution::ReviewerNeedsHuman | Resolution::HumanGate => "",
        };
        let audit = |decision| AuditAction::new(AuditKind::GateResult, decision);

        match resolution {
            Resolution::Pass => {
                let covered = self
                    .record_criteria(tx, cx, &gating, contract, judged)
                    .await?;
                let snaps = snapshots(&judged.decision.reports);
                let facts = GatePassFacts {
                    decision_is_pass_and_persisted: true,
                    criteria_without_ledger_entry: contract
                        .acceptance_criteria
                        .len()
                        .saturating_sub(covered),
                    mandatory_gate_reports: &snaps,
                };
                if evaluate(Guard::GatePassEvidenced, &GuardFacts::GatePass(facts)).is_ok() {
                    let hashes: Vec<String> = judged
                        .reports
                        .iter()
                        .map(|artifact| artifact.sha256.to_string())
                        .collect();
                    let payload = payload::with(
                        payload::for_run(gating.value.kind, gating.value.id),
                        "gate_report_sha256s",
                        json!(hashes),
                    );
                    cx.move_stage_run(tx, &gating, StageRunEvent::GatePassed, None, payload)
                        .await?;
                    cx.audit_engine(tx, audit(AuditDecision::Granted)).await?;
                } else {
                    metric_outcome = "blocked";
                    self.block(tx, cx, &gating, &BlockCause::MissingEvidence)
                        .await?;
                    cx.audit_engine(tx, audit(AuditDecision::Denied)).await?;
                }
            }
            Resolution::Blocked(cause) => {
                self.block(tx, cx, &gating, &cause).await?;
                cx.audit_engine(tx, audit(AuditDecision::Denied)).await?;
            }
            Resolution::Failed { failing } => {
                self.rework_or_ask(
                    tx,
                    cx,
                    &gating,
                    None,
                    GateFinding::DeterministicGateFailed,
                    &failing,
                )
                .await?;
                cx.audit_engine(tx, audit(AuditDecision::Denied)).await?;
            }
            Resolution::ChangesRequired { defect, failing } => {
                self.rework_or_ask(
                    tx,
                    cx,
                    &gating,
                    defect,
                    GateFinding::VerdictChangesRequired,
                    &failing,
                )
                .await?;
                cx.audit_engine(tx, audit(AuditDecision::Denied)).await?;
            }
            Resolution::ReviewerNeedsHuman => {
                let facts = NeedsHumanFacts {
                    verdict_is_needs_human: true,
                    rework_limit_reached: false,
                    stagnation_detected: false,
                    budget_limit_reached: false,
                    gate_is_a_human_gate: false,
                    defect_needs_a_person: false,
                };
                self.ask_person(tx, cx, &gating, facts, "reviewer-needs-a-person")
                    .await?;
                cx.audit_engine(tx, audit(AuditDecision::Noted)).await?;
            }
            Resolution::HumanGate => {
                let facts = NeedsHumanFacts {
                    verdict_is_needs_human: false,
                    rework_limit_reached: false,
                    stagnation_detected: false,
                    budget_limit_reached: false,
                    gate_is_a_human_gate: true,
                    defect_needs_a_person: false,
                };
                self.ask_person(tx, cx, &gating, facts, "human-gate")
                    .await?;
                cx.audit_engine(tx, audit(AuditDecision::Noted)).await?;
            }
        }
        let gate = gate_label(contract);
        match metric_outcome {
            "passed" => tracing::info!(
                monotonic_counter.factory_stage_runs_total = 1_u64,
                stage = gating.value.kind.as_str(),
                outcome = "passed"
            ),
            "blocked" | "failed" => tracing::info!(
                monotonic_counter.factory_gate_failures_total = 1_u64,
                gate = gate,
                outcome = metric_outcome
            ),
            _ => {}
        }
        self.settle(tx, cx).await
    }

    /// Writes one ledger entry for each report and for the verdict. Each cites the stored
    /// document by its hash.
    async fn record_gate_evidence(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        run: &Versioned<StageRun>,
        judged: &Judged,
    ) -> Result<(), EngineError> {
        for (report, stored) in judged.decision.reports.iter().zip(&judged.reports) {
            let result = match report.outcome {
                GateOutcome::Passed => TestResult::Passed,
                GateOutcome::Failed => TestResult::Failed,
                GateOutcome::Blocked | GateOutcome::NotApplicable => TestResult::NotRun,
            };
            let claim = ClaimSpec {
                statement: format!(
                    "The gate {} reported {} for the {} stage run.",
                    report.metadata.gate_id,
                    report.outcome.as_str(),
                    run.value.kind
                ),
                kind: ClaimKind::MeasuredFact,
                assurance_level: None,
                confidence: ConfidenceLevel::High,
                rationale: "The report is stored by its hash and follows the gate report schema."
                    .to_owned(),
            };
            let evidence = Evidence::Test(TestEvidence {
                gate_report_id: report.metadata.gate_report_id,
                gate_report_sha256: stored.sha256.clone(),
                test_name: None,
                result,
            });
            cx.record_claim(
                tx,
                run.value.id,
                report.metadata.attempt_id,
                &claim,
                &[evidence],
            )
            .await?;
        }
        if let (Some(verdict), Some(stored)) = (&judged.decision.review, &judged.review) {
            let claim = ClaimSpec {
                statement: format!(
                    "The independent reviewer returned the verdict {} for the {} stage run.",
                    verdict.verdict.as_str(),
                    run.value.kind
                ),
                kind: ClaimKind::MeasuredFact,
                assurance_level: None,
                confidence: ConfidenceLevel::Medium,
                rationale: "A reviewer's verdict is evidence of an opinion, never a gate result."
                    .to_owned(),
            };
            let evidence = Evidence::Artifact(ArtifactEvidence {
                sha256: stored.sha256.clone(),
                media_type: stored.media_type.clone(),
                description: Some(HumanText::parse(
                    "The review verdict as the reviewer returned it",
                )?),
            });
            cx.record_claim(tx, run.value.id, None, &claim, &[evidence])
                .await?;
        }
        Ok(())
    }

    /// Writes one ledger entry for each acceptance criterion that has evidence. Returns how many.
    async fn record_criteria(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        run: &Versioned<StageRun>,
        contract: &StageContract,
        judged: &Judged,
    ) -> Result<usize, EngineError> {
        use factory_domain::contracts::stage_contract::VerificationKind;
        let mut covered = 0;
        for criterion in contract.acceptance_criteria.iter() {
            let verification = &criterion.verification;
            let evidence = match verification.kind {
                VerificationKind::Gate | VerificationKind::Test => judged
                    .decision
                    .reports
                    .iter()
                    .zip(&judged.reports)
                    .find(|(report, _)| {
                        report.metadata.gate_id == verification.reference
                            && matches!(
                                report.outcome,
                                GateOutcome::Passed | GateOutcome::NotApplicable
                            )
                    })
                    .map(|(report, stored)| {
                        Evidence::Test(TestEvidence {
                            gate_report_id: report.metadata.gate_report_id,
                            gate_report_sha256: stored.sha256.clone(),
                            test_name: None,
                            result: if report.outcome == GateOutcome::Passed {
                                TestResult::Passed
                            } else {
                                TestResult::NotRun
                            },
                        })
                    }),
                VerificationKind::Review => judged
                    .decision
                    .review
                    .as_ref()
                    .zip(judged.review.as_ref())
                    .filter(|(verdict, _)| verdict.verdict == Verdict::Pass)
                    .map(|(_, stored)| {
                        Evidence::Artifact(ArtifactEvidence {
                            sha256: stored.sha256.clone(),
                            media_type: stored.media_type.clone(),
                            description: None,
                        })
                    }),
                VerificationKind::SchemaValidation => Some(Evidence::Artifact(ArtifactEvidence {
                    sha256: Sha256Digest::of(verification.reference.as_str().as_bytes()),
                    media_type: MediaType::parse("text/plain")?,
                    description: Some(HumanText::parse(
                        "The output was checked against its schema before this gate ran",
                    )?),
                })),
                VerificationKind::HumanDecision => None,
            };
            let Some(evidence) = evidence else {
                continue;
            };
            let claim = ClaimSpec {
                statement: format!(
                    "The acceptance criterion {} is verified by {} {}.",
                    criterion.id,
                    verification_word(verification.kind),
                    verification.reference
                ),
                kind: ClaimKind::MeasuredFact,
                assurance_level: None,
                confidence: ConfidenceLevel::High,
                rationale: "The evidence is stored by its hash and was checked by the engine."
                    .to_owned(),
            };
            cx.record_claim(tx, run.value.id, None, &claim, &[evidence])
                .await?;
            covered += 1;
        }
        Ok(covered)
    }

    /// Blocks the stage run (`S11`).
    async fn block(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        gating: &Versioned<StageRun>,
        cause: &BlockCause,
    ) -> Result<(), EngineError> {
        let facts = BlockingFacts {
            verdict_is_block: matches!(cause, BlockCause::ReviewerBlocked),
            mandatory_gate_could_not_run: !matches!(
                cause,
                BlockCause::PolicyViolation | BlockCause::ReviewerBlocked
            ),
            policy_violation_detected: matches!(cause, BlockCause::PolicyViolation),
        };
        evaluate(Guard::BlockingCondition, &GuardFacts::Blocking(facts)).map_err(guard_error)?;
        let payload = payload::with(
            payload::for_run(gating.value.kind, gating.value.id),
            key::CAUSE,
            json!(cause.code()),
        );
        cx.move_stage_run(
            tx,
            gating,
            StageRunEvent::GateBlocks,
            Some(cause.code()),
            payload,
        )
        .await?;
        Ok(())
    }

    /// Asks a person (`S10`).
    async fn ask_person(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        gating: &Versioned<StageRun>,
        facts: NeedsHumanFacts,
        cause: &'static str,
    ) -> Result<(), EngineError> {
        evaluate(Guard::NeedsHumanVerdict, &GuardFacts::NeedsHuman(facts)).map_err(guard_error)?;
        let payload = payload::with(
            payload::for_run(gating.value.kind, gating.value.id),
            key::CAUSE,
            json!(cause),
        );
        cx.move_stage_run(
            tx,
            gating,
            StageRunEvent::GateNeedsHuman,
            Some(cause),
            payload,
        )
        .await?;
        Ok(())
    }

    /// A failed gate or a verdict asking for changes: rework while the limits allow it, a person
    /// when they do not or when only a person can decide, and a final failure when there is no
    /// route at all.
    async fn rework_or_ask(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        gating: &Versioned<StageRun>,
        defect: Option<DefectClass>,
        finding: GateFinding,
        failing: &Sha256Digest,
    ) -> Result<(), EngineError> {
        let timeline = Timeline::load(tx, cx.job).await?;
        let differs = timeline.last_failing_set(gating.value.kind) != Some(failing);
        let request = GateReworkRequest {
            from: gating.value.kind,
            defect,
            finding,
            ledger: timeline.rework,
            limits: self.config.rework_limits,
            failing_set_differs: differs,
            budget_remains: timeline.spent_micro_usd < self.config.job_budget_micro_usd,
        };
        match decide_gate_rework(&request) {
            GateReworkDecision::Rework(plan) => {
                let facts = ReworkFacts {
                    verdict_is_changes_required: finding == GateFinding::VerdictChangesRequired,
                    deterministic_gate_failed: finding == GateFinding::DeterministicGateFailed,
                    rounds_used: timeline.rework.used(plan.track),
                    cap: self.config.rework_limits.cap(plan.track),
                    failing_set_differs_from_previous_round: differs,
                    budget_remains: request.budget_remains,
                };
                evaluate(Guard::ReworkAllowed, &GuardFacts::Rework(facts)).map_err(guard_error)?;
                self.apply_rework(
                    tx,
                    cx,
                    gating,
                    &plan,
                    Some(failing),
                    StageRunEvent::GateRequiresRework,
                )
                .await?;
            }
            GateReworkDecision::NeedsHuman(cause) => {
                let (facts, code) = needs_human_facts(cause);
                self.ask_person(tx, cx, gating, facts, code).await?;
            }
            GateReworkDecision::NoRoute(_) => {
                let facts = NoReworkFacts {
                    gate_failed: true,
                    a_rework_route_exists: false,
                };
                evaluate(Guard::GateFailedNoRework, &GuardFacts::NoRework(facts))
                    .map_err(guard_error)?;
                let payload = payload::with(
                    payload::for_run(gating.value.kind, gating.value.id),
                    key::CAUSE,
                    json!("no-rework-route"),
                );
                cx.move_stage_run(
                    tx,
                    gating,
                    StageRunEvent::GateFailedFinal,
                    Some("no-rework-route"),
                    payload,
                )
                .await?;
            }
        }
        Ok(())
    }

    /// Sends the work back: the failing run takes `event` (`S09` from a gate, `S15` from a
    /// person), the runs the target's new artifact makes stale are superseded, and a new run
    /// starts for the target and every stage after it.
    pub(crate) async fn apply_rework(
        &self,
        tx: &mut dyn Tx,
        cx: &Cx<'_>,
        failing_run: &Versioned<StageRun>,
        plan: &ReworkPlan,
        failing: Option<&Sha256Digest>,
        event: StageRunEvent,
    ) -> Result<(), EngineError> {
        let snaps: Vec<StageRunSnapshot> = self.snapshots_of(tx, cx).await?;
        let to_supersede = factory_domain::machines::invalidation::plan_for_rework(
            &snaps,
            plan.target,
            failing_run.value.id,
        );
        let created = self
            .supersede_and_replace(
                tx,
                cx,
                &to_supersede,
                &plan.replaced_stages(),
                super::replace::Why::Rework,
                "rework",
            )
            .await?;
        let listed: Vec<Value> = created
            .iter()
            .map(|(kind, id)| payload::run_ref(*id, *kind))
            .collect();
        let mut payload = payload::for_run(failing_run.value.kind, failing_run.value.id);
        payload = payload::with(payload, key::CREATED, Value::Array(listed));
        payload = payload::with(payload, "rework_target", json!(plan.target.as_str()));
        payload = payload::with(payload, key::REWORK_TRACK, json!(plan.track.as_str()));
        payload = payload::with(payload, "rework_round", json!(plan.round));
        if let Some(failing) = failing {
            payload = payload::with(payload, key::FAILING_SET, json!(failing.to_string()));
        }
        cx.move_stage_run(tx, failing_run, event, Some("rework"), payload)
            .await?;
        Ok(())
    }
}

fn needs_human_facts(cause: NeedsHumanCause) -> (NeedsHumanFacts, &'static str) {
    let code = match cause {
        NeedsHumanCause::ReworkLimit => "rework-limit",
        NeedsHumanCause::Stagnation => "stagnation",
        NeedsHumanCause::BudgetLimit => "budget-limit",
        NeedsHumanCause::DefectNeedsDecision(_) => "defect-needs-a-person",
    };
    (cause.facts(), code)
}

fn verification_word(
    kind: factory_domain::contracts::stage_contract::VerificationKind,
) -> &'static str {
    use factory_domain::contracts::stage_contract::VerificationKind;
    match kind {
        VerificationKind::SchemaValidation => "the schema check",
        VerificationKind::Gate => "the gate",
        VerificationKind::Test => "the test",
        VerificationKind::Review => "the review",
        VerificationKind::HumanDecision => "the decision of a person",
    }
}

pub(super) fn gate_label(contract: &StageContract) -> &str {
    contract
        .evaluator
        .gate_ids
        .as_ref()
        .and_then(|ids| ids.iter().next())
        .map_or("none", factory_domain::values::Slug::as_str)
}

pub(super) fn outcome_label(resolution: &Resolution) -> &'static str {
    match resolution {
        Resolution::Pass => "passed",
        Resolution::Blocked(_) => "blocked",
        Resolution::Failed { .. } | Resolution::ChangesRequired { .. } => "rework_requested",
        Resolution::ReviewerNeedsHuman | Resolution::HumanGate => "blocked",
    }
}
