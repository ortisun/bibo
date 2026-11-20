use super::*;
use crate::contracts::review_verdict::{DefectClass, Finding, Severity};
use crate::machines::guards::stage_run::needs_human_verdict;
use crate::machines::invalidation::ArtifactChange;
use crate::machines::limits::{ReworkLedger, ReworkLimits, ReworkTrack};
use crate::state::{StageRunEvent, StageRunStatus, Status};
use crate::vocabulary::{HumanRole, StageKind};

/// A ledger with `code` rounds used on the code count and `documentation` on the documentation
/// count, and none on the specification and design counts.
fn code_docs(code: u8, documentation: u8) -> ReworkLedger {
    ReworkLedger::default()
        .with_used(ReworkTrack::Code, code)
        .with_used(ReworkTrack::Documentation, documentation)
}

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
fn a_documentation_review_finding_with_no_class_counts_as_documentation() {
    // A deterministic failure at DOCUMENTATION_REVIEW has no reviewer class (ADR 0010).
    assert_eq!(
        route_of(StageKind::DocumentationReview, gate(None)),
        Ok(StageKind::Documenting)
    );
    assert_eq!(
        route_of(
            StageKind::DocumentationReview,
            gate(Some(DefectClass::Documentation))
        ),
        route_of(StageKind::DocumentationReview, gate(None))
    );
}

#[test]
fn the_route_table_alone_has_no_route_for_a_class_only_a_person_decides_there() {
    // `route` reads `rework_routes` and nothing else. The decision consults the defect matrix
    // first, so these two classes never get this far at DOCUMENTATION_REVIEW.
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
        NoReworkRoute::HumanTarget {
            from: StageKind::Review,
            target: StageKind::Specification
        }
        .to_string(),
        "a human request for rework from the REVIEW stage cannot go to the SPECIFICATION stage"
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
    for route in HUMAN_REWORK_ROUTES {
        for target in route.targets {
            assert!(
                ArtifactChange::produced_by(*target).is_some(),
                "{} -> {target}",
                route.from
            );
        }
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
    assert_eq!(plan.ledger_after, code_docs(1, 0));
    assert_eq!(decision.event(), StageRunEvent::GateRequiresRework);
    assert_eq!(
        StageRunStatus::Gating.apply(decision.event()),
        Ok(StageRunStatus::ReworkRequested)
    );
}

#[test]
fn the_second_round_is_still_allowed_and_the_third_is_not() {
    let second = decide_gate_rework(&gate_request(StageKind::Review, code_docs(1, 0)));
    let GateReworkDecision::Rework(plan) = second else {
        panic!("{second:?}");
    };
    assert_eq!(plan.round, 2);
    assert_eq!(plan.ledger_after, code_docs(2, 0));

    let third = decide_gate_rework(&gate_request(StageKind::Review, code_docs(2, 0)));
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
    let mut request = gate_request(StageKind::DocumentationReview, code_docs(2, 0));
    request.defect = Some(DefectClass::Documentation);
    let GateReworkDecision::Rework(plan) = decide_gate_rework(&request) else {
        panic!("documentation rework should still have both rounds");
    };
    assert_eq!(plan.target, StageKind::Documenting);
    assert_eq!(plan.track, ReworkTrack::Documentation);
    assert_eq!(plan.ledger_after, code_docs(2, 1));

    // Code rework found by the same stage is charged to the full code count.
    request.defect = Some(DefectClass::CodeBehavior);
    assert_eq!(
        decide_gate_rework(&request),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::ReworkLimit)
    );
}

#[test]
fn two_specification_rounds_leave_the_architecture_and_the_implementation_their_own() {
    // Run 29 of scenario E1: the specification converged in two rounds, then the first
    // architecture gate failure was refused with rework-limit because both were on the code count.
    let mut ledger = ReworkLedger::default();
    for round in 1..=2 {
        let GateReworkDecision::Rework(plan) =
            decide_gate_rework(&gate_request(StageKind::Specification, ledger))
        else {
            panic!("specification round {round}");
        };
        assert_eq!(plan.track, ReworkTrack::Specification);
        assert_eq!(plan.round, round);
        ledger = plan.ledger_after;
    }
    assert_eq!(
        decide_gate_rework(&gate_request(StageKind::Specification, ledger)),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::ReworkLimit),
        "a third specification round goes to a person"
    );

    // The architecture still has both design rounds; the third goes to a person.
    for round in 1..=2 {
        let GateReworkDecision::Rework(plan) =
            decide_gate_rework(&gate_request(StageKind::Architecture, ledger))
        else {
            panic!("architecture round {round}");
        };
        assert_eq!(plan.target, StageKind::Architecture);
        assert_eq!(plan.track, ReworkTrack::Design);
        assert_eq!(plan.round, round);
        ledger = plan.ledger_after;
    }
    assert_eq!(
        decide_gate_rework(&gate_request(StageKind::Architecture, ledger)),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::ReworkLimit),
        "a third design round goes to a person"
    );
    // The task plan shares the design count with the architecture it is cut from.
    assert_eq!(
        decide_gate_rework(&gate_request(StageKind::TaskPlanning, ledger)),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::ReworkLimit)
    );

    // The implementation still has both of its rounds.
    for round in 1..=2 {
        let GateReworkDecision::Rework(plan) =
            decide_gate_rework(&gate_request(StageKind::Validation, ledger))
        else {
            panic!("code round {round}");
        };
        assert_eq!(plan.track, ReworkTrack::Code);
        assert_eq!(plan.round, round);
        ledger = plan.ledger_after;
    }
    assert_eq!(ledger.used(ReworkTrack::Specification), 2);
    assert_eq!(ledger.used(ReworkTrack::Design), 2);
    assert_eq!(ledger.used(ReworkTrack::Code), 2);
    assert_eq!(ledger.used(ReworkTrack::Documentation), 0);
}

#[test]
fn a_lower_cap_stops_rework_sooner_and_a_higher_policy_value_cannot_buy_a_round() {
    let mut request = gate_request(StageKind::Validation, code_docs(1, 0));
    request.limits = ReworkLimits::default().with_policy(ReworkTrack::Code, 1);
    assert_eq!(
        decide_gate_rework(&request),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::ReworkLimit)
    );

    let mut request = gate_request(StageKind::Validation, code_docs(2, 0));
    request.limits = ReworkLimits::uniform(9);
    assert_eq!(
        decide_gate_rework(&request),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::ReworkLimit)
    );
}

#[test]
fn a_cap_of_zero_sends_every_finding_to_a_human() {
    let mut request = gate_request(StageKind::Validation, ReworkLedger::default());
    request.limits = ReworkLimits::uniform(0);
    assert_eq!(
        decide_gate_rework(&request),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::ReworkLimit)
    );
}

#[test]
fn the_same_findings_twice_go_to_a_human_even_with_rounds_left() {
    let mut request = gate_request(StageKind::Validation, code_docs(1, 0));
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
    let mut causes = vec![
        NeedsHumanCause::ReworkLimit,
        NeedsHumanCause::Stagnation,
        NeedsHumanCause::BudgetLimit,
    ];
    causes.extend(
        DefectClass::ALL
            .iter()
            .map(|class| NeedsHumanCause::DefectNeedsDecision(*class)),
    );
    for cause in causes {
        assert!(needs_human_verdict(&cause.facts()).is_ok(), "{cause:?}");
    }
    // The defect cause names itself and nothing else.
    let facts = NeedsHumanCause::DefectNeedsDecision(DefectClass::Policy).facts();
    assert!(facts.defect_needs_a_person);
    assert!(
        !facts.rework_limit_reached && !facts.stagnation_detected && !facts.budget_limit_reached
    );
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
        let limits = ReworkLimits::uniform(configured);
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

// ---- the defect matrix ----------------------------------------------------------------------------------------------

fn finding(severity: Severity, defect: DefectClass) -> Finding {
    serde_json::from_value(serde_json::json!({
        "finding_id": "finding-1",
        "severity": severity.as_str(),
        "category": "correctness",
        "title": "The totals are wrong",
        "description": "The total does not add the last line, so the output is short.",
        "confidence": 0.9,
        "proposed_next_action": "fix",
        "defect_class": defect.as_str(),
    }))
    .expect("a finding")
}

fn reviewed(from: StageKind, defect: DefectClass) -> GateReworkDecision {
    decide_gate_rework(&GateReworkRequest {
        from,
        defect: Some(defect),
        finding: GateFinding::VerdictChangesRequired,
        ledger: ReworkLedger::default(),
        limits: ReworkLimits::default(),
        failing_set_differs: true,
        budget_remains: true,
    })
}

#[test]
fn the_four_reviewed_stages_are_the_ones_with_a_matrix_and_no_other_stage_has_one() {
    assert_eq!(
        DEFECT_ROUTED_STAGES,
        [
            StageKind::Specification,
            StageKind::Architecture,
            StageKind::Review,
            StageKind::DocumentationReview,
        ]
    );
    for stage in StageKind::ALL {
        for defect in DefectClass::ALL {
            assert_eq!(
                defect_outcome(*stage, *defect).is_some(),
                DEFECT_ROUTED_STAGES.contains(stage),
                "{stage} / {defect}"
            );
        }
    }
}

#[test]
fn a_policy_finding_asks_a_person_at_every_reviewed_stage() {
    for stage in DEFECT_ROUTED_STAGES {
        assert_eq!(
            defect_outcome(stage, DefectClass::Policy),
            Some(DefectOutcome::Human),
            "{stage}"
        );
        let decision = reviewed(stage, DefectClass::Policy);
        assert_eq!(
            decision,
            GateReworkDecision::NeedsHuman(NeedsHumanCause::DefectNeedsDecision(
                DefectClass::Policy
            )),
            "{stage}"
        );
        assert_eq!(decision.event(), StageRunEvent::GateNeedsHuman);
    }
}

#[test]
fn a_specification_finding_asks_a_person_except_where_the_specification_is_made() {
    for stage in [
        StageKind::Architecture,
        StageKind::Review,
        StageKind::DocumentationReview,
    ] {
        assert_eq!(
            reviewed(stage, DefectClass::Specification),
            GateReworkDecision::NeedsHuman(NeedsHumanCause::DefectNeedsDecision(
                DefectClass::Specification
            )),
            "{stage}"
        );
    }
    // At SPECIFICATION the stage reworks its own artifact.
    let GateReworkDecision::Rework(plan) =
        reviewed(StageKind::Specification, DefectClass::Specification)
    else {
        panic!("a specification defect at SPECIFICATION is reworked");
    };
    assert_eq!(plan.target, StageKind::Specification);
    assert_eq!(plan.track, ReworkTrack::Specification);
}

#[test]
fn the_classes_the_builder_can_fix_are_reworked_at_every_reviewed_stage() {
    for stage in DEFECT_ROUTED_STAGES {
        for defect in [DefectClass::CodeBehavior, DefectClass::Documentation] {
            assert!(
                matches!(reviewed(stage, defect), GateReworkDecision::Rework(_)),
                "{stage} / {defect}"
            );
        }
    }
    // The documentation review still picks its row by class.
    let GateReworkDecision::Rework(plan) =
        reviewed(StageKind::DocumentationReview, DefectClass::CodeBehavior)
    else {
        panic!("rework");
    };
    assert_eq!(plan.target, StageKind::Implementation);
    let GateReworkDecision::Rework(plan) =
        reviewed(StageKind::DocumentationReview, DefectClass::Documentation)
    else {
        panic!("rework");
    };
    assert_eq!(plan.target, StageKind::Documenting);
    assert_eq!(plan.track, ReworkTrack::Documentation);
}

#[test]
fn a_class_only_a_person_decides_does_not_use_up_a_round() {
    // Asking a person is not rework: the ledger the caller holds stays as it was, and the cap
    // does not matter.
    let mut request = GateReworkRequest {
        from: StageKind::Review,
        defect: Some(DefectClass::Policy),
        finding: GateFinding::VerdictChangesRequired,
        ledger: code_docs(2, 2),
        limits: ReworkLimits::default(),
        failing_set_differs: false,
        budget_remains: false,
    };
    assert_eq!(
        decide_gate_rework(&request),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::DefectNeedsDecision(DefectClass::Policy))
    );
    request.ledger = ReworkLedger::default();
    request.failing_set_differs = true;
    request.budget_remains = true;
    assert!(matches!(
        decide_gate_rework(&request),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::DefectNeedsDecision(_))
    ));
}

#[test]
fn a_deterministic_failure_at_the_documentation_review_counts_as_documentation() {
    let request = GateReworkRequest {
        from: StageKind::DocumentationReview,
        defect: None,
        finding: GateFinding::DeterministicGateFailed,
        ledger: ReworkLedger::default(),
        limits: ReworkLimits::default(),
        failing_set_differs: true,
        budget_remains: true,
    };
    let GateReworkDecision::Rework(plan) = decide_gate_rework(&request) else {
        panic!("a broken link is reworked, and does not fail the job");
    };
    assert_eq!(plan.target, StageKind::Documenting);
    assert_eq!(plan.track, ReworkTrack::Documentation);
}

#[test]
fn mixed_defect_classes_follow_precedence() {
    use DefectClass::{CodeBehavior, Documentation, Policy, Specification};
    use Severity::{Blocker, High, Medium};
    assert_eq!(
        DEFECT_PRECEDENCE,
        [Specification, Policy, CodeBehavior, Documentation]
    );

    // Whatever order the findings come in, the first class in the precedence wins.
    let all = [
        finding(High, Documentation),
        finding(Medium, CodeBehavior),
        finding(Blocker, Policy),
        finding(High, Specification),
    ];
    for start in 0..all.len() {
        let mut rotated = all.to_vec();
        rotated.rotate_left(start);
        assert_eq!(routing_defect(&rotated), Some(Specification), "{start}");
        rotated.reverse();
        assert_eq!(routing_defect(&rotated), Some(Specification), "{start}");
    }
    let without_specification = &all[..3];
    assert_eq!(routing_defect(without_specification), Some(Policy));
    let without_policy = [finding(High, Documentation), finding(Medium, CodeBehavior)];
    assert_eq!(routing_defect(&without_policy), Some(CodeBehavior));
    assert_eq!(routing_defect(&without_policy[..1]), Some(Documentation));

    // A decision that needs a person is not hidden behind an easy fix: the same findings that
    // include a policy defect ask a person at REVIEW, and without it they are reworked.
    let class = routing_defect(&[finding(High, Documentation), finding(Medium, Policy)]).unwrap();
    assert_eq!(
        reviewed(StageKind::Review, class),
        GateReworkDecision::NeedsHuman(NeedsHumanCause::DefectNeedsDecision(Policy))
    );
    let class =
        routing_defect(&[finding(High, Documentation), finding(Medium, CodeBehavior)]).unwrap();
    assert!(matches!(
        reviewed(StageKind::Review, class),
        GateReworkDecision::Rework(_)
    ));
}

#[test]
fn only_findings_of_medium_severity_or_above_decide_the_class() {
    use DefectClass::{CodeBehavior, Documentation, Policy, Specification};
    use Severity::{Blocker, High, Info, Low, Medium};
    // A low or informational finding never wins, even with a class that outranks the rest.
    assert_eq!(
        routing_defect(&[finding(Low, Specification), finding(Medium, Documentation)]),
        Some(Documentation)
    );
    assert_eq!(
        routing_defect(&[finding(Info, Policy), finding(High, CodeBehavior)]),
        Some(CodeBehavior)
    );
    for severity in [Blocker, High, Medium] {
        assert_eq!(routing_defect(&[finding(severity, Policy)]), Some(Policy));
    }
    for severity in [Low, Info] {
        assert_eq!(routing_defect(&[finding(severity, Policy)]), None);
    }
    assert_eq!(routing_defect(&[]), None);
}

// ---- human rework decisions -------------------------------------------------------------------------------------------

fn human_request<'a>(
    from: StageKind,
    target: StageKind,
    roles: &'a [HumanRole],
    ledger: ReworkLedger,
) -> HumanReworkRequest<'a> {
    HumanReworkRequest {
        from,
        target,
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
        StageKind::Implementation,
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
        StageKind::Implementation,
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
        StageKind::Implementation,
        &roles,
        code_docs(2, 0),
    ));
    assert!(
        matches!(decision, HumanReworkDecision::Refused(_)),
        "{decision:?}"
    );
    assert_eq!(decision.event(), None);
}

#[test]
fn a_human_request_from_a_stage_without_a_human_route_has_no_route() {
    // INTAKE, REPOSITORY_INTELLIGENCE and DOMAIN_DISCOVERY have no human rework route: a person
    // answers, approves or rejects there.
    let roles = [HumanRole::Approver];
    for from in [
        StageKind::Intake,
        StageKind::RepositoryIntelligence,
        StageKind::DomainDiscovery,
        StageKind::Merge,
    ] {
        let decision = decide_human_rework(&human_request(
            from,
            StageKind::Implementation,
            &roles,
            ReworkLedger::default(),
        ));
        assert_eq!(
            decision,
            HumanReworkDecision::NoRoute(NoReworkRoute::Human(from)),
            "{from}"
        );
        assert_eq!(decision.event(), None);
    }
}

// ---- where a person may send rework -------------------------------------------------------------------------------

fn approver_sends(from: StageKind, target: StageKind) -> HumanReworkDecision {
    let roles = [HumanRole::Approver];
    decide_human_rework(&human_request(
        from,
        target,
        &roles,
        ReworkLedger::default(),
    ))
}

#[test]
fn a_person_may_send_rework_to_every_target_the_file_lists_for_the_stage() {
    // One case for each row of the table, and for each target in it.
    assert_eq!(HUMAN_REWORK_ROUTES.len(), 10);
    for route in HUMAN_REWORK_ROUTES {
        assert!(!route.targets.is_empty(), "{}", route.from);
        for target in route.targets {
            let decision = approver_sends(route.from, *target);
            let HumanReworkDecision::Rework(plan) = &decision else {
                panic!("{} -> {target}: {decision:?}", route.from);
            };
            assert_eq!(plan.target, *target);
            assert_eq!(decision.event(), Some(StageRunEvent::HumanRequestedRework));
        }
    }
}

#[test]
fn a_later_stage_is_refused_as_a_target() {
    for route in HUMAN_REWORK_ROUTES {
        for target in StageKind::ALL {
            if route.targets.contains(target) {
                continue;
            }
            assert_eq!(
                approver_sends(route.from, *target),
                HumanReworkDecision::NoRoute(NoReworkRoute::HumanTarget {
                    from: route.from,
                    target: *target
                }),
                "{} -> {target}",
                route.from
            );
        }
        // No target is ever later than the stage that waits.
        assert!(
            route.targets.iter().all(|t| *t <= route.from),
            "{}",
            route.from
        );
    }
    assert_eq!(
        approver_sends(StageKind::Review, StageKind::Documenting),
        HumanReworkDecision::NoRoute(NoReworkRoute::HumanTarget {
            from: StageKind::Review,
            target: StageKind::Documenting
        })
    );
}

#[test]
fn the_specification_is_a_target_only_from_the_specification() {
    // Revising a frozen specification needs the method of ADR 0006, which is not proven yet.
    for route in HUMAN_REWORK_ROUTES {
        assert_eq!(
            route.targets.contains(&StageKind::Specification),
            route.from == StageKind::Specification,
            "{}",
            route.from
        );
    }
    for from in [
        StageKind::Architecture,
        StageKind::Review,
        StageKind::Approval,
    ] {
        assert_eq!(
            approver_sends(from, StageKind::Specification),
            HumanReworkDecision::NoRoute(NoReworkRoute::HumanTarget {
                from,
                target: StageKind::Specification
            })
        );
    }
    assert!(matches!(
        approver_sends(StageKind::Specification, StageKind::Specification),
        HumanReworkDecision::Rework(_)
    ));
}

#[test]
fn only_agent_produced_stages_are_targets() {
    let agent_produced = [
        StageKind::Specification,
        StageKind::Architecture,
        StageKind::TaskPlanning,
        StageKind::Implementation,
        StageKind::Documenting,
    ];
    for route in HUMAN_REWORK_ROUTES {
        for target in route.targets {
            assert!(
                agent_produced.contains(target),
                "{} -> {target}",
                route.from
            );
        }
    }
}

#[test]
fn the_cap_and_the_counts_follow_the_target_a_person_names() {
    // Rework to DOCUMENTING is charged to the documentation count, to ARCHITECTURE or
    // TASK_PLANNING to the design count, and to IMPLEMENTATION to the code count (ADR 0022).
    let to_documenting = approver_sends(StageKind::Approval, StageKind::Documenting);
    let HumanReworkDecision::Rework(plan) = &to_documenting else {
        panic!("{to_documenting:?}");
    };
    assert_eq!(plan.track, ReworkTrack::Documentation);
    assert_eq!(plan.ledger_after, code_docs(0, 1));

    let to_architecture = approver_sends(StageKind::Approval, StageKind::Architecture);
    let HumanReworkDecision::Rework(plan) = &to_architecture else {
        panic!("{to_architecture:?}");
    };
    assert_eq!(plan.track, ReworkTrack::Design);
    assert_eq!(
        plan.ledger_after,
        ReworkLedger::default().with_used(ReworkTrack::Design, 1)
    );

    // A full code count does not stop a documentation round, and the other way round.
    let roles = [HumanRole::Approver];
    let request = |target, ledger| {
        decide_human_rework(&human_request(StageKind::Approval, target, &roles, ledger))
    };
    assert!(matches!(
        request(StageKind::Documenting, code_docs(2, 0)),
        HumanReworkDecision::Rework(_)
    ));
    assert!(matches!(
        request(StageKind::Implementation, code_docs(0, 2)),
        HumanReworkDecision::Rework(_)
    ));
    assert!(matches!(
        request(StageKind::Implementation, code_docs(2, 0)),
        HumanReworkDecision::Refused(_)
    ));
    // A full code count does not stop a person from sending the design back, and a full design
    // count stops the design and not the code.
    let design_full = ReworkLedger::default().with_used(ReworkTrack::Design, 2);
    for target in [StageKind::Architecture, StageKind::TaskPlanning] {
        assert!(
            matches!(
                request(target, code_docs(2, 0)),
                HumanReworkDecision::Rework(_)
            ),
            "{target}"
        );
        assert!(
            matches!(
                request(target, design_full),
                HumanReworkDecision::Refused(_)
            ),
            "{target}"
        );
    }
    assert!(matches!(
        request(StageKind::Implementation, design_full),
        HumanReworkDecision::Rework(_)
    ));
    assert!(matches!(
        request(StageKind::Documenting, code_docs(0, 2)),
        HumanReworkDecision::Refused(_)
    ));
}

#[test]
fn a_refused_target_is_reported_before_the_role_and_the_cap_are_looked_at() {
    // The route comes first: a person with no role who names a stage that is not a target hears
    // about the target, and nothing changes in the ledger.
    let roles: [HumanRole; 0] = [];
    let decision = decide_human_rework(&human_request(
        StageKind::Review,
        StageKind::Documenting,
        &roles,
        code_docs(2, 2),
    ));
    assert!(matches!(
        decision,
        HumanReworkDecision::NoRoute(NoReworkRoute::HumanTarget { .. })
    ));
}
