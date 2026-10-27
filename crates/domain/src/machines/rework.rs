//! Where rework goes, and whether the cap allows it.
//!
//! When a gate sends work back, a new run of an earlier stage replaces the failing one. The
//! `rework_routes` of `state-machine.json` say which stage. The cap of ADR 0009 says how many
//! times: two rounds for code and two for documentation, then a human decides.
//!
//! A rework request has three possible answers, and the gate and human paths differ:
//!
//! * **A gate finding** ([`decide_gate_rework`]) becomes rework (`S09`), or a human is asked
//!   (`S10`) when the cap is used up, the same findings came back, or the budget is gone, or the
//!   stage fails for good (`S12`) when no route exists for the finding.
//! * **A human request** ([`decide_human_rework`]) becomes rework (`S15`), or is refused when the
//!   principal lacks the role or the cap is used up. The stagnation detector does not apply to a
//!   human's request. After the cap, a human who still wants another round must choose to go on
//!   and record that decision, which is not a rework request.
//!
//! The routes are applied exactly as the file lists them. Where the file is silent, there is no
//! route, and the answer says so:
//!
//! * A finding at `DOCUMENTATION_REVIEW` with defect class `specification` or `policy`. The file
//!   routes only `documentation` and `code_behavior`.
//! * A human request for rework at any stage but `APPROVAL`.

use crate::contracts::review_verdict::DefectClass;
use crate::machines::guards::stage_run::{human_rework_allowed, rework_allowed};
use crate::machines::guards::{GuardFailure, HumanReworkFacts, NeedsHumanFacts, ReworkFacts};
use crate::machines::invalidation::rework_stages;
use crate::machines::limits::{ReworkLedger, ReworkLimits, ReworkTrack};
use crate::macros::string_enum;
use crate::state::{Guard, StageRunEvent};
use crate::vocabulary::{HumanRole, StageKind};

string_enum! {
    /// What sends work back. The spelling is the `trigger` text of the rework routes in
    /// `state-machine.json`.
    pub enum ReworkTrigger("rework trigger") {
        /// The gate of the stage returned `CHANGES_REQUIRED`.
        GateChangesRequired = "gate CHANGES_REQUIRED",
        /// The task plan validator failed.
        ValidatorFailed = "validator FAILED",
        /// The scope check of the implementation failed.
        ScopeCheckFailed = "scope check FAILED",
        /// A mandatory validation gate failed.
        MandatoryGateFailed = "any mandatory gate FAILED",
        /// The reviewer's verdict is `CHANGES_REQUIRED`.
        VerdictChangesRequired = "verdict CHANGES_REQUIRED",
        /// The documentation review found a documentation defect.
        DocumentationDefect = "CHANGES_REQUIRED with defect_class documentation",
        /// The documentation review found that the code or behavior does not match.
        CodeBehaviorDefect = "CHANGES_REQUIRED with defect_class code_behavior",
        /// A human asked for rework.
        HumanRequestsRework = "human requests rework",
    }
}

impl ReworkTrigger {
    /// The defect class that a route with this trigger is chosen by, if it is chosen by one.
    #[must_use]
    pub const fn defect(self) -> Option<DefectClass> {
        match self {
            ReworkTrigger::DocumentationDefect => Some(DefectClass::Documentation),
            ReworkTrigger::CodeBehaviorDefect => Some(DefectClass::CodeBehavior),
            _ => None,
        }
    }
}

/// One row of the rework routes in `state-machine.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReworkRoute {
    /// The stage whose run needs rework.
    pub from: StageKind,
    /// What sent the work back.
    pub trigger: ReworkTrigger,
    /// The stage that gets a new run.
    pub target: StageKind,
}

/// Every rework route, in the order of the file.
pub static REWORK_ROUTES: &[ReworkRoute] = &[
    ReworkRoute {
        from: StageKind::Specification,
        trigger: ReworkTrigger::GateChangesRequired,
        target: StageKind::Specification,
    },
    ReworkRoute {
        from: StageKind::Architecture,
        trigger: ReworkTrigger::GateChangesRequired,
        target: StageKind::Architecture,
    },
    ReworkRoute {
        from: StageKind::TaskPlanning,
        trigger: ReworkTrigger::ValidatorFailed,
        target: StageKind::TaskPlanning,
    },
    ReworkRoute {
        from: StageKind::Implementation,
        trigger: ReworkTrigger::ScopeCheckFailed,
        target: StageKind::Implementation,
    },
    ReworkRoute {
        from: StageKind::Validation,
        trigger: ReworkTrigger::MandatoryGateFailed,
        target: StageKind::Implementation,
    },
    ReworkRoute {
        from: StageKind::Review,
        trigger: ReworkTrigger::VerdictChangesRequired,
        target: StageKind::Implementation,
    },
    ReworkRoute {
        from: StageKind::DocumentationReview,
        trigger: ReworkTrigger::DocumentationDefect,
        target: StageKind::Documenting,
    },
    ReworkRoute {
        from: StageKind::DocumentationReview,
        trigger: ReworkTrigger::CodeBehaviorDefect,
        target: StageKind::Implementation,
    },
    ReworkRoute {
        from: StageKind::Approval,
        trigger: ReworkTrigger::HumanRequestsRework,
        target: StageKind::Implementation,
    },
];

/// Who is asking for rework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReworkCause {
    /// A gate or a reviewer found something. `defect` is the defect class of the finding, when
    /// the finding has one.
    Gate {
        /// The defect class of the finding.
        defect: Option<DefectClass>,
    },
    /// A human asked.
    Human,
}

/// No route exists for the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NoReworkRoute {
    /// The stage has no route for a gate finding.
    #[error("the {0} stage has no rework route for a gate finding")]
    Stage(StageKind),
    /// The stage routes by defect class and has no route for this one.
    #[error("the {stage} stage has no rework route for a {defect} defect")]
    Defect {
        /// The stage.
        stage: StageKind,
        /// The defect class that has no route.
        defect: DefectClass,
    },
    /// The stage routes by defect class, and the finding names none.
    #[error("the {0} stage routes rework by defect class, and the finding names none")]
    DefectNeeded(StageKind),
    /// The stage has no route for a human's request.
    #[error("a human request for rework has no route from the {0} stage")]
    Human(StageKind),
}

/// The route for a request that comes from `from`.
///
/// A stage whose route does not depend on the defect class ignores it. `DOCUMENTATION_REVIEW`
/// is the one stage in the file that routes by defect class.
///
/// # Errors
/// Returns [`NoReworkRoute`] when the file lists no route for the request.
pub fn route(from: StageKind, cause: ReworkCause) -> Result<&'static ReworkRoute, NoReworkRoute> {
    let gate_routes = || {
        REWORK_ROUTES.iter().filter(move |row| {
            row.from == from && row.trigger != ReworkTrigger::HumanRequestsRework
        })
    };
    match cause {
        ReworkCause::Human => REWORK_ROUTES
            .iter()
            .find(|row| row.from == from && row.trigger == ReworkTrigger::HumanRequestsRework)
            .ok_or(NoReworkRoute::Human(from)),
        ReworkCause::Gate { defect } => {
            if !gate_routes().any(|row| row.trigger.defect().is_some()) {
                return gate_routes().next().ok_or(NoReworkRoute::Stage(from));
            }
            let defect = defect.ok_or(NoReworkRoute::DefectNeeded(from))?;
            gate_routes()
                .find(|row| row.trigger.defect() == Some(defect))
                .ok_or(NoReworkRoute::Defect {
                    stage: from,
                    defect,
                })
        }
    }
}

/// What a gate found, as far as guard `G_REWORK_ALLOWED` cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateFinding {
    /// A reviewer's verdict is `CHANGES_REQUIRED`.
    VerdictChangesRequired,
    /// A deterministic gate failed.
    DeterministicGateFailed,
}

/// Rework that a decision allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReworkPlan {
    /// The stage that gets a new run.
    pub target: StageKind,
    /// The count this round is charged to.
    pub track: ReworkTrack,
    /// The number of this round on that count, starting at 1.
    pub round: u8,
    /// The ledger once the round is recorded.
    pub ledger_after: ReworkLedger,
}

impl ReworkPlan {
    /// The stages whose live runs are superseded when this rework starts: the old run of the
    /// target and every stage after it. See [`rework_stages`].
    #[must_use]
    pub fn replaced_stages(&self) -> Vec<StageKind> {
        rework_stages(self.target)
    }
}

fn plan(target: StageKind, track: ReworkTrack, ledger_after: ReworkLedger) -> ReworkPlan {
    ReworkPlan {
        target,
        track,
        round: ledger_after.used(track),
        ledger_after,
    }
}

/// Why a gate hands a finding to a human instead of sending the work back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedsHumanCause {
    /// The cap is used up. After the last round a human decides.
    ReworkLimit,
    /// The same findings came back, so another round would not help.
    Stagnation,
    /// A budget limit was reached.
    BudgetLimit,
}

impl NeedsHumanCause {
    /// The facts for guard `G_NEEDS_HUMAN_VERDICT` that this cause stands for. The guard holds
    /// for them.
    #[must_use]
    pub const fn facts(self) -> NeedsHumanFacts {
        let none = NeedsHumanFacts {
            verdict_is_needs_human: false,
            rework_limit_reached: false,
            stagnation_detected: false,
            budget_limit_reached: false,
            gate_is_a_human_gate: false,
        };
        match self {
            NeedsHumanCause::ReworkLimit => NeedsHumanFacts {
                rework_limit_reached: true,
                ..none
            },
            NeedsHumanCause::Stagnation => NeedsHumanFacts {
                stagnation_detected: true,
                ..none
            },
            NeedsHumanCause::BudgetLimit => NeedsHumanFacts {
                budget_limit_reached: true,
                ..none
            },
        }
    }
}

/// A gate finding that asks for rework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateReworkRequest {
    /// The stage whose gate found something.
    pub from: StageKind,
    /// The defect class of the finding, when it has one.
    pub defect: Option<DefectClass>,
    /// What the gate found.
    pub finding: GateFinding,
    /// Rounds used so far in the job.
    pub ledger: ReworkLedger,
    /// The caps.
    pub limits: ReworkLimits,
    /// The failing set differs from the previous round. True for the first round.
    pub failing_set_differs: bool,
    /// Budget remains.
    pub budget_remains: bool,
}

/// The answer to a gate finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateReworkDecision {
    /// Send the work back (`S09`).
    Rework(ReworkPlan),
    /// Ask a human (`S10`).
    NeedsHuman(NeedsHumanCause),
    /// No route exists, so the stage fails for good (`S12`).
    NoRoute(NoReworkRoute),
}

impl GateReworkDecision {
    /// The stage run event that applies the decision to a `GATING` stage run.
    #[must_use]
    pub const fn event(&self) -> StageRunEvent {
        match self {
            GateReworkDecision::Rework(_) => StageRunEvent::GateRequiresRework,
            GateReworkDecision::NeedsHuman(_) => StageRunEvent::GateNeedsHuman,
            GateReworkDecision::NoRoute(_) => StageRunEvent::GateFailedFinal,
        }
    }
}

/// Decides what a gate finding does: rework, a human, or a final failure. The decision is
/// backed by guard `G_REWORK_ALLOWED`, so the two cannot disagree.
#[must_use]
pub fn decide_gate_rework(request: &GateReworkRequest) -> GateReworkDecision {
    let found = match route(
        request.from,
        ReworkCause::Gate {
            defect: request.defect,
        },
    ) {
        Ok(found) => found,
        Err(missing) => return GateReworkDecision::NoRoute(missing),
    };
    let track = ReworkTrack::for_target(found.target);
    let facts = ReworkFacts {
        verdict_is_changes_required: request.finding == GateFinding::VerdictChangesRequired,
        deterministic_gate_failed: request.finding == GateFinding::DeterministicGateFailed,
        rounds_used: request.ledger.used(track),
        cap: request.limits.cap(track),
        failing_set_differs_from_previous_round: request.failing_set_differs,
        budget_remains: request.budget_remains,
    };
    match (
        rework_allowed(&facts),
        request.ledger.start_round(track, request.limits),
    ) {
        (Ok(()), Ok(ledger_after)) => {
            GateReworkDecision::Rework(plan(found.target, track, ledger_after))
        }
        (Ok(()), Err(_)) => GateReworkDecision::NeedsHuman(NeedsHumanCause::ReworkLimit),
        (Err(_), _) => {
            let cause = if !request.ledger.has_room(track, request.limits) {
                NeedsHumanCause::ReworkLimit
            } else if !request.failing_set_differs {
                NeedsHumanCause::Stagnation
            } else {
                NeedsHumanCause::BudgetLimit
            };
            GateReworkDecision::NeedsHuman(cause)
        }
    }
}

/// A human's request to send a stage back for rework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanReworkRequest<'a> {
    /// The stage whose run the human wants reworked.
    pub from: StageKind,
    /// The roles the principal holds.
    pub principal_roles: &'a [HumanRole],
    /// Rounds used so far in the job.
    pub ledger: ReworkLedger,
    /// The caps.
    pub limits: ReworkLimits,
}

/// The answer to a human's request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HumanReworkDecision {
    /// Send the work back (`S15`).
    Rework(ReworkPlan),
    /// Guard `G_HUMAN_REWORK_ALLOWED` does not hold: the principal lacks the role, or the cap is
    /// used up.
    Refused(GuardFailure),
    /// No route exists for a human request from this stage.
    NoRoute(NoReworkRoute),
}

impl HumanReworkDecision {
    /// The stage run event that applies the decision, or `None` when the request is not
    /// accepted.
    #[must_use]
    pub const fn event(&self) -> Option<StageRunEvent> {
        match self {
            HumanReworkDecision::Rework(_) => Some(StageRunEvent::HumanRequestedRework),
            HumanReworkDecision::Refused(_) | HumanReworkDecision::NoRoute(_) => None,
        }
    }
}

/// Decides what a human's rework request does. The stagnation detector does not apply.
#[must_use]
pub fn decide_human_rework(request: &HumanReworkRequest<'_>) -> HumanReworkDecision {
    // A human request is routed by the stage alone: the file has one human route and it does
    // not depend on a defect class.
    let found = match route(request.from, ReworkCause::Human) {
        Ok(found) => found,
        Err(missing) => return HumanReworkDecision::NoRoute(missing),
    };
    let track = ReworkTrack::for_target(found.target);
    let facts = HumanReworkFacts {
        principal_roles: request.principal_roles,
        rounds_used: request.ledger.used(track),
        cap: request.limits.cap(track),
    };
    match (
        human_rework_allowed(&facts),
        request.ledger.start_round(track, request.limits),
    ) {
        (Ok(()), Ok(ledger_after)) => {
            HumanReworkDecision::Rework(plan(found.target, track, ledger_after))
        }
        (Err(failure), _) => HumanReworkDecision::Refused(failure),
        (Ok(()), Err(_)) => HumanReworkDecision::Refused(GuardFailure {
            guard: Guard::HumanReworkAllowed,
            unmet: vec!["the rework cap is used up"],
            any_of: false,
        }),
    }
}

#[cfg(test)]
mod tests;
