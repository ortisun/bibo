//! Where rework goes, and whether the cap allows it.
//!
//! When a gate sends work back, a new run of an earlier stage replaces the failing one. Three
//! tables in the `pipeline` section of `state-machine.json` decide where it goes, and the cap of
//! ADR 0009 says how many times: two rounds on each count, then a human decides. ADR 0022 gives
//! the specification, the design (`ARCHITECTURE` and `TASK_PLANNING`), the code and the
//! documentation each their own count, charged by the stage a round targets
//! ([`ReworkTrack::for_target`]).
//!
//! | Table | What it says | In this module |
//! |---|---|---|
//! | `rework_routes` | The stage that gets a new run, for each stage and trigger | [`REWORK_ROUTES`], [`route`] |
//! | `defect_routing` | For the four stages with an independent reviewer, whether a defect class is reworked or asks a person, and which class wins | [`defect_outcome`], [`DEFECT_PRECEDENCE`], [`routing_defect`] |
//! | `human_rework_routes` | The stages a person may send rework to, for each waiting or blocked stage | [`HUMAN_REWORK_ROUTES`], [`human_targets`] |
//!
//! A rework request has three possible answers, and the gate and human paths differ:
//!
//! * **A gate finding** ([`decide_gate_rework`]) first asks `defect_routing`: a `specification`
//!   or `policy` defect asks a person (`S10`) and uses no round, except that `SPECIFICATION`
//!   reworks its own specification. Otherwise the finding becomes rework (`S09`), or a person is
//!   asked (`S10`) when the cap is used up, the same findings came back, or the budget is gone.
//!   The stage fails for good (`S12`) only when it has no route at all, such as an intake record
//!   that is still invalid after repair.
//! * **A human request** ([`decide_human_rework`]) names a target. It becomes rework (`S15`) when
//!   `human_rework_routes` lists the target for the waiting stage, the principal has the role
//!   and the cap of the target's count has room. The stagnation detector does not apply to a
//!   human's request. After the cap, a human who still wants another round must choose to go on
//!   and record that decision, which is not a rework request.
//!
//! The tables are applied exactly as the file lists them. What is left without a route:
//!
//! * A stage that is not in `rework_routes` has no route for a gate finding, and the stage fails.
//! * `INTAKE`, `REPOSITORY_INTELLIGENCE`, `DOMAIN_DISCOVERY` and `MERGE` have no human rework
//!   route. A person answers, approves or rejects there.
//! * `SPECIFICATION` is a human target only from `SPECIFICATION` itself, because revising a frozen
//!   specification needs the method of ADR 0006, which is not proven yet.
//!
//! A deterministic failure at `DOCUMENTATION_REVIEW` has no reviewer class and counts as a
//! documentation defect, so a broken link is reworked and does not fail the job.

use crate::contracts::review_verdict::{DefectClass, Finding, Severity};
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

string_enum! {
    /// What a reviewer's finding does at a stage with an independent reviewer
    /// (`pipeline.defect_routing` in `state-machine.json`).
    pub enum DefectOutcome("defect outcome") {
        /// The route in `rework_routes` applies, within the cap.
        Rework = "rework",
        /// The stage run waits for a person (`S10`).
        Human = "human",
    }
}

/// The order in which the defect classes of the findings decide the routing: when they differ,
/// the first in this list wins, so a decision that needs a person is not hidden behind an easier
/// fix (`pipeline.defect_routing.precedence`).
pub const DEFECT_PRECEDENCE: [DefectClass; 4] = [
    DefectClass::Specification,
    DefectClass::Policy,
    DefectClass::CodeBehavior,
    DefectClass::Documentation,
];

/// The stages that have an independent reviewer, and so route by defect class.
pub const DEFECT_ROUTED_STAGES: [StageKind; 4] = [
    StageKind::Specification,
    StageKind::Architecture,
    StageKind::Review,
    StageKind::DocumentationReview,
];

/// What a finding of class `defect` does at `stage` (`pipeline.defect_routing.stages`), or
/// `None` for a stage without an independent reviewer. Those stages are deterministic and use the
/// single route of [`REWORK_ROUTES`].
///
/// * A `policy` finding asks a person at every one of the four stages.
/// * A `specification` finding asks a person, except at `SPECIFICATION`, which produces the
///   specification and reworks its own artifact.
/// * `code_behavior` and `documentation` are reworked, along the route of the stage.
#[must_use]
pub const fn defect_outcome(stage: StageKind, defect: DefectClass) -> Option<DefectOutcome> {
    match (stage, defect) {
        (StageKind::Specification, DefectClass::Policy)
        | (
            StageKind::Architecture | StageKind::Review | StageKind::DocumentationReview,
            DefectClass::Specification | DefectClass::Policy,
        ) => Some(DefectOutcome::Human),
        (
            StageKind::Specification,
            DefectClass::CodeBehavior | DefectClass::Documentation | DefectClass::Specification,
        )
        | (
            StageKind::Architecture | StageKind::Review | StageKind::DocumentationReview,
            DefectClass::CodeBehavior | DefectClass::Documentation,
        ) => Some(DefectOutcome::Rework),
        _ => None,
    }
}

/// The defect class that routes a `CHANGES_REQUIRED` verdict, taken from the findings that
/// justify it: those of severity blocker, high or medium. When their classes differ, the first in
/// [`DEFECT_PRECEDENCE`] wins. Returns `None` when no finding is that serious, which a valid
/// `CHANGES_REQUIRED` verdict never gives (the contract requires one of medium severity or above).
///
/// The result goes into [`GateReworkRequest::defect`].
#[must_use]
pub fn routing_defect<'a>(findings: impl IntoIterator<Item = &'a Finding>) -> Option<DefectClass> {
    let classes: Vec<DefectClass> = findings
        .into_iter()
        .filter(|finding| {
            matches!(
                finding.severity,
                Severity::Blocker | Severity::High | Severity::Medium
            )
        })
        .map(|finding| finding.defect_class)
        .collect();
    DEFECT_PRECEDENCE
        .into_iter()
        .find(|class| classes.contains(class))
}

/// Where a person may send rework from a stage run that waits or is blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanReworkRoute {
    /// The stage whose run waits for a person or is blocked.
    pub from: StageKind,
    /// The stages a person may name as the target.
    pub targets: &'static [StageKind],
}

/// Every human rework route (`pipeline.human_rework_routes`), in the order of the file.
///
/// A target is an agent-produced stage at or before the waiting stage. `SPECIFICATION` is a target
/// only from `SPECIFICATION` itself.
pub static HUMAN_REWORK_ROUTES: &[HumanReworkRoute] = &[
    HumanReworkRoute {
        from: StageKind::Specification,
        targets: &[StageKind::Specification],
    },
    HumanReworkRoute {
        from: StageKind::Architecture,
        targets: &[StageKind::Architecture],
    },
    HumanReworkRoute {
        from: StageKind::TaskPlanning,
        targets: &[StageKind::Architecture, StageKind::TaskPlanning],
    },
    HumanReworkRoute {
        from: StageKind::Implementation,
        targets: &[
            StageKind::Architecture,
            StageKind::TaskPlanning,
            StageKind::Implementation,
        ],
    },
    HumanReworkRoute {
        from: StageKind::Validation,
        targets: &[
            StageKind::Architecture,
            StageKind::TaskPlanning,
            StageKind::Implementation,
        ],
    },
    HumanReworkRoute {
        from: StageKind::Review,
        targets: &[
            StageKind::Architecture,
            StageKind::TaskPlanning,
            StageKind::Implementation,
        ],
    },
    HumanReworkRoute {
        from: StageKind::Documenting,
        targets: &[
            StageKind::Architecture,
            StageKind::TaskPlanning,
            StageKind::Implementation,
            StageKind::Documenting,
        ],
    },
    HumanReworkRoute {
        from: StageKind::DocumentationReview,
        targets: &[
            StageKind::Architecture,
            StageKind::TaskPlanning,
            StageKind::Implementation,
            StageKind::Documenting,
        ],
    },
    HumanReworkRoute {
        from: StageKind::Delivery,
        targets: &[
            StageKind::Architecture,
            StageKind::TaskPlanning,
            StageKind::Implementation,
            StageKind::Documenting,
        ],
    },
    HumanReworkRoute {
        from: StageKind::Approval,
        targets: &[
            StageKind::Architecture,
            StageKind::TaskPlanning,
            StageKind::Implementation,
            StageKind::Documenting,
        ],
    },
];

/// The stages a person may send rework to from `from`, in pipeline order. Empty when the file
/// lists none for that stage.
#[must_use]
pub fn human_targets(from: StageKind) -> &'static [StageKind] {
    HUMAN_REWORK_ROUTES
        .iter()
        .find(|route| route.from == from)
        .map_or(&[], |route| route.targets)
}

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
    /// The stage has no route for a human's request.
    #[error("a human request for rework has no route from the {0} stage")]
    Human(StageKind),
    /// A person may send rework from this stage, but not to the stage they named.
    #[error("a human request for rework from the {from} stage cannot go to the {target} stage")]
    HumanTarget {
        /// The stage whose run waits for a person or is blocked.
        from: StageKind,
        /// The stage the person named.
        target: StageKind,
    },
}

/// The route for a request that comes from `from`, read from [`REWORK_ROUTES`] alone.
///
/// A stage whose route does not depend on the defect class ignores it. `DOCUMENTATION_REVIEW`
/// is the one stage with a row for each defect class, and a finding there that names no class
/// counts as `documentation`: a deterministic failure has no reviewer class. [`decide_gate_rework`]
/// asks [`defect_outcome`] before it calls this, so a class that only a person can decide never
/// gets a route from it.
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
            let defect = defect.unwrap_or(DefectClass::Documentation);
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
    /// The findings carry a defect class that only a person can decide at this stage.
    DefectNeedsDecision(DefectClass),
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
            defect_needs_a_person: false,
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
            NeedsHumanCause::DefectNeedsDecision(_) => NeedsHumanFacts {
                defect_needs_a_person: true,
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
    /// The defect class that routes the verdict, when it has one: the result of
    /// [`routing_defect`] over the findings of a reviewer. A deterministic gate has none.
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
    // A class that only a person can decide at this stage asks a person first. It is not
    // rework, so it uses no round and the cap does not matter.
    if let Some(defect) = request.defect
        && defect_outcome(request.from, defect) == Some(DefectOutcome::Human)
    {
        return GateReworkDecision::NeedsHuman(NeedsHumanCause::DefectNeedsDecision(defect));
    }
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
    /// The stage whose run waits for a person or is blocked.
    pub from: StageKind,
    /// The stage that gets a new run, named by the person.
    pub target: StageKind,
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
///
/// The target must be one that [`human_targets`] lists for the stage. A stage with no targets at
/// all gives [`NoReworkRoute::Human`], and a stage that has targets but not this one gives
/// [`NoReworkRoute::HumanTarget`]. The route is checked first, then the role and the cap of the
/// count the target is charged to.
#[must_use]
pub fn decide_human_rework(request: &HumanReworkRequest<'_>) -> HumanReworkDecision {
    let targets = human_targets(request.from);
    if targets.is_empty() {
        return HumanReworkDecision::NoRoute(NoReworkRoute::Human(request.from));
    }
    if !targets.contains(&request.target) {
        return HumanReworkDecision::NoRoute(NoReworkRoute::HumanTarget {
            from: request.from,
            target: request.target,
        });
    }
    let target = request.target;
    let track = ReworkTrack::for_target(target);
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
            HumanReworkDecision::Rework(plan(target, track, ledger_after))
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
