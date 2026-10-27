//! From evidence to a gate outcome.
//!
//! [`resolve`] reads the contract's evaluator and the evidence in a [`GateDecision`] and says what
//! the gate found. It is a pure function, and it is deliberately hard on the stage:
//!
//! * A gate that the contract names and that has no report did not run, and a gate that did not
//!   run **blocks** (INV-06). Missing evidence is never read as a pass.
//! * A reviewer's `PASS` cannot outweigh a gate that failed or was blocked (NT-INJ-06). The
//!   verdict is read only after every gate.
//! * A decision with no report and no verdict has nothing to rest a pass on, so it blocks. There
//!   is no field in a decision that says "passed".
//!
//! Order of precedence, strongest first: a policy violation, a missing or blocked gate, a missing
//! or blocking review, a failed gate, a verdict asking for changes, a request for a person, and
//! only then a pass.

use factory_domain::contracts::review_verdict::DefectClass;
use factory_domain::contracts::stage_contract::{EvaluatorKind, VerificationKind};
use factory_domain::contracts::{GateReport, StageContract};
use factory_domain::machines::rework::routing_defect;
use factory_domain::machines::snapshot::GateReportSnapshot;
use factory_domain::values::{Sha256Digest, Slug};
use factory_domain::vocabulary::{GateOutcome, Verdict};

use super::decision::GateDecision;

/// Why a stage run is blocked at its gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockCause {
    /// A deterministic check detected a violation of policy.
    PolicyViolation,
    /// A gate that the contract names has no report: it did not run.
    MissingGate(Slug),
    /// A gate reported that it could not run.
    GateBlocked(Slug),
    /// The contract needs an independent reviewer and there is no verdict.
    MissingReview,
    /// The reviewer's verdict is `BLOCK`.
    ReviewerBlocked,
    /// Nothing was handed over that a pass could rest on.
    MissingEvidence,
    /// The evidence was refused (see `EvidenceProblem`).
    InvalidEvidence,
}

impl BlockCause {
    /// A short machine code for the event and the audit record.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::PolicyViolation => "policy-violation",
            Self::MissingGate(_) => "gate-did-not-run",
            Self::GateBlocked(_) => "gate-blocked",
            Self::MissingReview => "review-missing",
            Self::ReviewerBlocked => "reviewer-blocked",
            Self::MissingEvidence => "no-evidence",
            Self::InvalidEvidence => "evidence-refused",
        }
    }
}

/// What the gate found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Every gate passed, the reviewer agrees, and each criterion has evidence. The engine still
    /// asks the domain guard before it moves.
    Pass,
    /// The stage run cannot be promoted and a person must dispose of the block (`S11`).
    Blocked(BlockCause),
    /// A deterministic gate failed.
    Failed {
        /// A digest of what failed, so a repeat of the same failure is recognised.
        failing: Sha256Digest,
    },
    /// The reviewer asked for changes.
    ChangesRequired {
        /// The defect class that routes the verdict, from the findings that justify it.
        defect: Option<DefectClass>,
        /// A digest of the findings that justify the verdict.
        failing: Sha256Digest,
    },
    /// The reviewer asked for a person.
    ReviewerNeedsHuman,
    /// The gate itself is a human gate.
    HumanGate,
}

/// Decides what the evidence says. See the module documentation for the order.
#[must_use]
pub fn resolve(contract: &StageContract, decision: &GateDecision) -> Resolution {
    let kind = contract.evaluator.kind;
    let needs_gates = matches!(
        kind,
        EvaluatorKind::DeterministicGate | EvaluatorKind::GateAndReviewer
    );
    let needs_review = matches!(
        kind,
        EvaluatorKind::IndependentReviewer | EvaluatorKind::GateAndReviewer
    );

    if decision.policy_violation {
        return Resolution::Blocked(BlockCause::PolicyViolation);
    }
    if needs_gates && let Some(required) = &contract.evaluator.gate_ids {
        for gate in required.iter() {
            if !decision
                .reports
                .iter()
                .any(|report| &report.metadata.gate_id == gate)
            {
                return Resolution::Blocked(BlockCause::MissingGate(gate.clone()));
            }
        }
    }
    if let Some(report) = decision
        .reports
        .iter()
        .find(|report| report.outcome == GateOutcome::Blocked)
    {
        return Resolution::Blocked(BlockCause::GateBlocked(report.metadata.gate_id.clone()));
    }
    if needs_review && decision.review.is_none() {
        return Resolution::Blocked(BlockCause::MissingReview);
    }
    if decision
        .review
        .as_ref()
        .is_some_and(|verdict| verdict.verdict == Verdict::Block)
    {
        return Resolution::Blocked(BlockCause::ReviewerBlocked);
    }
    if kind == EvaluatorKind::Human
        && !decision.human_gate
        && decision.reports.is_empty()
        && decision.review.is_none()
    {
        return Resolution::Blocked(BlockCause::MissingEvidence);
    }

    if decision
        .reports
        .iter()
        .any(|report| report.outcome == GateOutcome::Failed)
    {
        return Resolution::Failed {
            failing: failing_set(decision),
        };
    }
    if let Some(verdict) = &decision.review {
        match verdict.verdict {
            Verdict::ChangesRequired => {
                return Resolution::ChangesRequired {
                    defect: routing_defect(&verdict.findings),
                    failing: failing_set(decision),
                };
            }
            Verdict::NeedsHuman => return Resolution::ReviewerNeedsHuman,
            Verdict::Pass | Verdict::Block => {}
        }
    }
    if decision.human_gate || kind == EvaluatorKind::Human {
        return Resolution::HumanGate;
    }
    if decision.reports.is_empty() && decision.review.is_none() {
        return Resolution::Blocked(BlockCause::MissingEvidence);
    }
    Resolution::Pass
}

/// A digest of what failed: the failed checks of each failed report and the findings that justify
/// a verdict, sorted so the same failures give the same digest in any order.
#[must_use]
pub fn failing_set(decision: &GateDecision) -> Sha256Digest {
    let mut items: Vec<String> = Vec::new();
    for report in decision
        .reports
        .iter()
        .filter(|r| r.outcome == GateOutcome::Failed)
    {
        for failure in report.failures.iter().flatten() {
            items.push(format!(
                "{}:{}",
                report.metadata.gate_id,
                failure.check_id.as_str()
            ));
        }
    }
    if let Some(verdict) = &decision.review {
        for finding in &verdict.findings {
            use factory_domain::contracts::review_verdict::Severity;
            if matches!(
                finding.severity,
                Severity::Blocker | Severity::High | Severity::Medium
            ) {
                items.push(format!("finding:{}", finding.finding_id.as_str()));
            }
        }
    }
    items.sort();
    items.dedup();
    Sha256Digest::of(items.join("\n").as_bytes())
}

/// The reports as the pass guard reads them.
#[must_use]
pub fn snapshots(reports: &[GateReport]) -> Vec<GateReportSnapshot> {
    reports
        .iter()
        .map(|report| GateReportSnapshot {
            outcome: report.outcome,
            not_applicable_reason_recorded: report.not_applicable_reason.is_some(),
        })
        .collect()
}

/// How many acceptance criteria of the contract have no evidence behind them in this decision.
///
/// * A gate or a test criterion is covered by a report of that gate that passed or does not
///   apply.
/// * A schema criterion is covered because the engine validated the output before this point.
/// * A review criterion is covered by a `PASS` verdict.
/// * A criterion decided by a person is never covered by the automatic path.
#[must_use]
pub fn uncovered_criteria(contract: &StageContract, decision: &GateDecision) -> usize {
    contract
        .acceptance_criteria
        .iter()
        .filter(|criterion| {
            let verification = &criterion.verification;
            let covered = match verification.kind {
                VerificationKind::Gate | VerificationKind::Test => {
                    decision.reports.iter().any(|report| {
                        report.metadata.gate_id == verification.reference
                            && matches!(
                                report.outcome,
                                GateOutcome::Passed | GateOutcome::NotApplicable
                            )
                    })
                }
                VerificationKind::SchemaValidation => true,
                VerificationKind::Review => decision
                    .review
                    .as_ref()
                    .is_some_and(|verdict| verdict.verdict == Verdict::Pass),
                VerificationKind::HumanDecision => false,
            };
            !covered
        })
        .count()
}
