use super::*;
use crate::contracts::review_verdict::DefectClass;
use crate::machines::guards::stage_run::needs_human_verdict;
use crate::machines::invalidation::ArtifactChange;
use crate::machines::limits::{ReworkLedger, ReworkLimits, ReworkTrack};
use crate::state::{StageRunEvent, StageRunStatus, Status};
use crate::vocabulary::{HumanRole, StageKind};

fn route_of(from: StageKind, cause: ReworkCause) -> Result<StageKind, NoReworkRoute> {
    route(from, cause).map(|r| r.target)
}

fn gate(defect: Option<DefectClass>) -> ReworkCause {
    ReworkCause::Gate { defect }
}

// ---- the routes ---------------------------------------------------------------------------------------

#[test]
fn the_table_holds_the_nine_routes_of_the_file_in_order() {
    let rows: Vec<(StageKind, ReworkTrigger, StageKind)> = REWORK_ROUTES
        .iter()
        .map(|r| (r.from, r.trigger, r.target))
        .collect();
    assert_eq!(
        rows,
        [
            (
                StageKind::Specification,
                ReworkTrigger::GateChangesRequired,
                StageKind::Specification
            ),
            (
                StageKind::Architecture,
                ReworkTrigger::GateChangesRequired,
                StageKind::Architecture
            ),
            (
                StageKind::TaskPlanning,
                ReworkTrigger::ValidatorFailed,
                StageKind::TaskPlanning
            ),
            (
                StageKind::Implementation,
                ReworkTrigger::ScopeCheckFailed,
                StageKind::Implementation
            ),
            (
                StageKind::Validation,
                ReworkTrigger::MandatoryGateFailed,
                StageKind::Implementation
            ),
            (
                StageKind::Review,
                ReworkTrigger::VerdictChangesRequired,
                StageKind::Implementation
            ),
            (
                StageKind::DocumentationReview,
                ReworkTrigger::DocumentationDefect,
                StageKind::Documenting
            ),
            (
                StageKind::DocumentationReview,
                ReworkTrigger::CodeBehaviorDefect,
                StageKind::Implementation
            ),
            (
                StageKind::Approval,
                ReworkTrigger::HumanRequestsRework,
                StageKind::Implementation
            ),
        ]
    );
}

#[test]
fn a_gate_finding_returns_to_the_stage_the_file_names() {
    assert_eq!(
        route_of(StageKind::Specification, gate(None)),
        Ok(StageKind::Specification)
    );
    assert_eq!(
        route_of(StageKind::Architecture, gate(None)),
        Ok(StageKind::Architecture)
    );
    assert_eq!(
        route_of(StageKind::TaskPlanning, gate(None)),
        Ok(StageKind::TaskPlanning)
    );
    assert_eq!(
        route_of(StageKind::Implementation, gate(None)),
        Ok(StageKind::Implementation)
    );
    assert_eq!(
        route_of(StageKind::Validation, gate(None)),
        Ok(StageKind::Implementation)
    );
    assert_eq!(
        route_of(StageKind::Review, gate(None)),
        Ok(StageKind::Implementation)
    );
}

#[test]
fn a_stage_whose_route_does_not_depend_on_the_defect_ignores_it() {
    // The file gives REVIEW one route, "verdict CHANGES_REQUIRED", with no defect class.
    for defect in [
        None,
        Some(DefectClass::CodeBehavior),
        Some(DefectClass::Documentation),
        Some(DefectClass::Specification),
        Some(DefectClass::Policy),
    ] {
        assert_eq!(
            route_of(StageKind::Review, gate(defect)),
            Ok(StageKind::Implementation),
            "{defect:?}"
        );
    }
}

#[test]
fn the_documentation_review_routes_by_defect_class() {
    assert_eq!(
        route_of(
            StageKind::DocumentationReview,
            gate(Some(DefectClass::Documentation))
        ),
        Ok(StageKind::Documenting)
    );
    assert_eq!(
        route_of(
            StageKind::DocumentationReview,
            gate(Some(DefectClass::CodeBehavior))
        ),
        Ok(StageKind::Implementation)
    );
}

#[test]
fn a_documentation_review_finding_the_file_does_not_route_has_no_route() {
    assert_eq!(
        route_of(StageKind::DocumentationReview, gate(None)),
        Err(NoReworkRoute::DefectNeeded(StageKind::DocumentationReview))
    );
    for defect in [DefectClass::Specification, DefectClass::Policy] {
        assert_eq!(
            route_of(StageKind::DocumentationReview, gate(Some(defect))),
            Err(NoReworkRoute::Defect {
                stage: StageKind::DocumentationReview,
                defect
            })
        );
    }
}

#[test]
fn a_human_rework_request_has_a_route_only_from_the_approval() {
    assert_eq!(
        route_of(StageKind::Approval, ReworkCause::Human),
        Ok(StageKind::Implementation)
    );
    for kind in StageKind::ALL {
        if *kind != StageKind::Approval {
            assert_eq!(
                route_of(*kind, ReworkCause::Human),
                Err(NoReworkRoute::Human(*kind)),
                "{kind}"
            );
        }
    }
}

#[test]
fn a_stage_with_no_gate_route_has_none() {
    for kind in [
        StageKind::Intake,
        StageKind::RepositoryIntelligence,
        StageKind::DomainDiscovery,
        StageKind::Documenting,
        StageKind::Delivery,
        StageKind::Approval,
        StageKind::Merge,
    ] {
        assert_eq!(
            route_of(kind, gate(None)),
            Err(NoReworkRoute::Stage(kind)),
            "{kind}"
        );
    }
}

#[test]
fn a_no_route_error_explains_itself_in_plain_english() {
    assert_eq!(
        NoReworkRoute::Stage(StageKind::Intake).to_string(),
        "the INTAKE stage has no rework route for a gate finding"
    );
    assert_eq!(
        NoReworkRoute::Human(StageKind::Review).to_string(),
        "a human request for rework has no route from the REVIEW stage"
    );
    assert_eq!(
        NoReworkRoute::Defect {
            stage: StageKind::DocumentationReview,
            defect: DefectClass::Policy
        }
        .to_string(),
        "the DOCUMENTATION_REVIEW stage has no rework route for a policy defect"
    );
    assert_eq!(
        NoReworkRoute::DefectNeeded(StageKind::DocumentationReview).to_string(),
        "the DOCUMENTATION_REVIEW stage routes rework by defect class, and the finding names none"
    );
}

#[test]
fn no_route_ever_leads_forward_in_the_pipeline() {
    for r in REWORK_ROUTES {
        assert!(r.target <= r.from, "{} -> {}", r.from, r.target);
    }
}

#[test]
fn every_rework_target_produces_an_artifact_that_makes_later_work_stale() {
    // Rework replaces the target's old run, so the target must be a stage whose output later
    // stages consume by hash. That is what lets the invalidation rules decide the rest.
    for r in REWORK_ROUTES {
        assert!(
            ArtifactChange::produced_by(r.target).is_some(),
            "{} -> {}",
            r.from,
            r.target
        );
    }
}

#[test]
fn the_trigger_text_is_the_text_of_the_file() {
    assert_eq!(
        ReworkTrigger::GateChangesRequired.as_str(),
        "gate CHANGES_REQUIRED"
    );
    assert_eq!(
        ReworkTrigger::CodeBehaviorDefect.as_str(),
        "CHANGES_REQUIRED with defect_class code_behavior"
    );
    assert_eq!(
        ReworkTrigger::HumanRequestsRework.as_str(),
        "human requests rework"
    );
}

// ---- gate rework decisions ----------------------------------------------------------------------------------

fn gate_request(from: StageKind, ledger: ReworkLedger) -> GateReworkRequest {
    GateReworkRequest {
        from,
        defect: None,
        finding: GateFinding::DeterministicGateFailed,
        ledger,
        limits: ReworkLimits::default(),
        failing_set_differs: true,
        budget_remains: true,
    }
}

#[test]
fn the_first_validation_failure_goes_back_to_implementation_as_round_one() {
    let decision = decide_gate_rework(&gate_request(
        StageKind::Validation,
        ReworkLedger::default(),
    ));
    let GateReworkDecision::Rework(plan) = decision else {
        panic!("expected rework, got {decision:?}");
    };
    assert_eq!(plan.target, StageKind::Implementation);
    assert_eq!(plan.track, ReworkTrack::Code);
    assert_eq!(plan.round, 1);
    assert_eq!(plan.ledger_after, ReworkLedger::new(1, 0));
    assert_eq!(decision.event(), StageRunEvent::GateRequiresRework);
    assert_eq!(
        StageRunStatus::Gating.apply(decision.event()),
        Ok(StageRunStatus::ReworkRequested)
    );
}

#[test]
fn the_second_round_is_still_allowed_and_the_third_is_not() {
    let second = decide_gate_rework(&gate_request(StageKind::Review, ReworkLedger::new(1, 0)));
    let GateReworkDecision::Rework(plan) = second else {
        panic!("{second:?}");
    };
    assert_eq!(plan.round, 2);
    assert_eq!(plan.ledger_after, ReworkLedger::new(2, 0));

    let third = decide_gate_rework(&gate_request(StageKind::Review, ReworkLedger::new(2, 0)));
    assert_eq!(
        third,
        GateReworkDecision::NeedsHuman(NeedsHumanCause::ReworkLimit)
    );
    assert_eq!(third.event(), StageRunEvent::GateNeedsHuman);
    assert_eq!(
        StageRunStatus::Gating.apply(third.event()),
        Ok(StageRunStatus::WaitingForHuman)
    );
}

#[test]
fn documentation_rework_has_its_own_count() {
    let mut request = gate_request(StageKind::DocumentationReview, ReworkLedger::new(2, 0));
    request.defect = Some(DefectClass::Documentation);
    let GateReworkDecision::Rework(plan) = decide_gate_rework(&request) else {
        panic!("documentation rework should still have both rounds");
    };
    assert_eq!(plan.target, StageKind::Documenting);
    assert_eq!(plan.track, ReworkTrack::Documentation);
    assert_eq!(plan.ledger_after, ReworkLedger::new(2, 1));

    // Code rework found by the same stage is charged to the full code count.
    request.defect = Some(DefectClass::CodeBehavior);
    assert_eq!(
        decide_gate_rework(&request),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::ReworkLimit)
    );
}

#[test]
fn a_lower_cap_stops_rework_sooner_and_a_higher_policy_value_cannot_buy_a_round() {
    let mut request = gate_request(StageKind::Validation, ReworkLedger::new(1, 0));
    request.limits = ReworkLimits::from_policy(1, 2);
    assert_eq!(
        decide_gate_rework(&request),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::ReworkLimit)
    );

    let mut request = gate_request(StageKind::Validation, ReworkLedger::new(2, 0));
    request.limits = ReworkLimits::from_policy(9, 9);
    assert_eq!(
        decide_gate_rework(&request),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::ReworkLimit)
    );
}

#[test]
fn a_cap_of_zero_sends_every_finding_to_a_human() {
    let mut request = gate_request(StageKind::Validation, ReworkLedger::default());
    request.limits = ReworkLimits::from_policy(0, 0);
    assert_eq!(
        decide_gate_rework(&request),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::ReworkLimit)
    );
}

#[test]
fn the_same_findings_twice_go_to_a_human_even_with_rounds_left() {
    let mut request = gate_request(StageKind::Validation, ReworkLedger::new(1, 0));
    request.failing_set_differs = false;
    assert_eq!(
        decide_gate_rework(&request),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::Stagnation)
    );
}

#[test]
fn no_budget_sends_the_finding_to_a_human() {
    let mut request = gate_request(StageKind::Validation, ReworkLedger::default());
    request.budget_remains = false;
    assert_eq!(
        decide_gate_rework(&request),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::BudgetLimit)
    );
}

#[test]
fn a_stage_with_no_route_fails_for_good_and_a_human_is_not_asked() {
    let decision = decide_gate_rework(&gate_request(StageKind::Intake, ReworkLedger::default()));
    assert_eq!(
        decision,
        GateReworkDecision::NoRoute(NoReworkRoute::Stage(StageKind::Intake))
    );
    assert_eq!(decision.event(), StageRunEvent::GateFailedFinal);
    assert_eq!(
        StageRunStatus::Gating.apply(decision.event()),
        Ok(StageRunStatus::Failed)
    );
}

#[test]
fn the_facts_a_human_cause_stands_for_satisfy_the_needs_human_guard() {
    for cause in [
        NeedsHumanCause::ReworkLimit,
        NeedsHumanCause::Stagnation,
        NeedsHumanCause::BudgetLimit,
    ] {
        assert!(needs_human_verdict(&cause.facts()).is_ok(), "{cause:?}");
    }
}

#[test]
fn a_rework_plan_names_the_stages_whose_old_runs_are_replaced() {
    let GateReworkDecision::Rework(plan) = decide_gate_rework(&gate_request(
        StageKind::Validation,
        ReworkLedger::default(),
    )) else {
        panic!("expected rework");
    };
    let stages = plan.replaced_stages();
    assert_eq!(stages[0], StageKind::Implementation);
    assert_eq!(stages.len(), 7);
    assert!(stages.contains(&StageKind::Approval));
    assert!(!stages.contains(&StageKind::TaskPlanning));
}

#[test]
fn repeated_findings_use_exactly_the_cap_and_then_stop() {
    for configured in 0..=5u8 {
        let limits = ReworkLimits::from_policy(configured, configured);
        let mut ledger = ReworkLedger::default();
        let mut rounds = 0;
        for _ in 0..20 {
            let mut request = gate_request(StageKind::Validation, ledger);
            request.limits = limits;
            match decide_gate_rework(&request) {
                GateReworkDecision::Rework(plan) => {
                    ledger = plan.ledger_after;
                    rounds += 1;
                }
                other => {
                    assert_eq!(
                        other,
                        GateReworkDecision::NeedsHuman(NeedsHumanCause::ReworkLimit)
                    );
                }
            }
        }
        assert_eq!(rounds, configured.min(2), "configured {configured}");
        assert_eq!(ledger.used(ReworkTrack::Code), configured.min(2));
    }
}

// ---- human rework decisions -------------------------------------------------------------------------------------------

fn human_request<'a>(
    from: StageKind,
    roles: &'a [HumanRole],
    ledger: ReworkLedger,
) -> HumanReworkRequest<'a> {
    HumanReworkRequest {
        from,
        principal_roles: roles,
        ledger,
        limits: ReworkLimits::default(),
    }
}

#[test]
fn an_approver_can_send_the_approval_back_to_implementation() {
    let roles = [HumanRole::Approver];
    let decision = decide_human_rework(&human_request(
        StageKind::Approval,
        &roles,
        ReworkLedger::default(),
    ));
    let HumanReworkDecision::Rework(plan) = &decision else {
        panic!("{decision:?}");
    };
    assert_eq!(plan.target, StageKind::Implementation);
    assert_eq!(plan.round, 1);
    assert_eq!(decision.event(), Some(StageRunEvent::HumanRequestedRework));
    assert_eq!(
        StageRunStatus::WaitingForHuman.apply(StageRunEvent::HumanRequestedRework),
        Ok(StageRunStatus::ReworkRequested)
    );
}

#[test]
fn a_human_without_the_role_is_refused() {
    let roles = [HumanRole::Requester];
    let decision = decide_human_rework(&human_request(
        StageKind::Approval,
        &roles,
        ReworkLedger::default(),
    ));
    let HumanReworkDecision::Refused(failure) = &decision else {
        panic!("{decision:?}");
    };
    assert_eq!(failure.guard, crate::state::Guard::HumanReworkAllowed);
    assert_eq!(decision.event(), None);
}

#[test]
fn a_human_request_after_the_cap_is_refused_until_a_human_chooses_to_go_on() {
    let roles = [HumanRole::Operator];
    let decision = decide_human_rework(&human_request(
        StageKind::Approval,
        &roles,
        ReworkLedger::new(2, 0),
    ));
    assert!(
        matches!(decision, HumanReworkDecision::Refused(_)),
        "{decision:?}"
    );
    assert_eq!(decision.event(), None);
}

#[test]
fn a_human_request_from_a_stage_without_a_human_route_has_no_route() {
    let roles = [HumanRole::Approver];
    let decision = decide_human_rework(&human_request(
        StageKind::Review,
        &roles,
        ReworkLedger::default(),
    ));
    assert_eq!(
        decision,
        HumanReworkDecision::NoRoute(NoReworkRoute::Human(StageKind::Review))
    );
    assert_eq!(decision.event(), None);
}
