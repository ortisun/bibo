use super::*;
use crate::ids::StageRunId;
use crate::machines::snapshot::StageRunSnapshot;
use crate::state::{StageRunEvent, StageRunStatus, Status, TaskNodeEvent, TaskNodeStatus};
use crate::vocabulary::StageKind;

fn id(n: u128) -> StageRunId {
    StageRunId::from_uuid(uuid::Uuid::from_u128(n))
}

fn run(n: u128, kind: StageKind, status: StageRunStatus) -> StageRunSnapshot {
    StageRunSnapshot::new(id(n), kind, status)
}

/// Every stage that waits, directly or through other stages, for `source`.
fn downstream(source: StageKind) -> Vec<StageKind> {
    let mut found: Vec<StageKind> = Vec::new();
    loop {
        let before = found.len();
        for kind in StageKind::ALL {
            let waits_for_it = kind
                .requires()
                .iter()
                .any(|r| *r == source || found.contains(r));
            if waits_for_it && !found.contains(kind) {
                found.push(*kind);
            }
        }
        if found.len() == before {
            break;
        }
    }
    found.sort();
    found
}

#[test]
fn a_new_specification_makes_every_stage_after_it_stale() {
    assert_eq!(
        ArtifactChange::SpecificationApproved.stale_stages(),
        [
            StageKind::DomainDiscovery,
            StageKind::Architecture,
            StageKind::TaskPlanning,
            StageKind::Implementation,
            StageKind::Validation,
            StageKind::Review,
            StageKind::Documenting,
            StageKind::DocumentationReview,
            StageKind::Delivery,
            StageKind::Approval,
        ]
    );
}

#[test]
fn a_new_plan_makes_the_implementation_and_everything_after_it_stale() {
    assert_eq!(
        ArtifactChange::PlanVersion.stale_stages(),
        [
            StageKind::Implementation,
            StageKind::Validation,
            StageKind::Review,
            StageKind::Documenting,
            StageKind::DocumentationReview,
            StageKind::Delivery,
            StageKind::Approval,
        ]
    );
}

#[test]
fn a_new_documentation_commit_leaves_the_code_runs_alone() {
    assert_eq!(
        ArtifactChange::DocumentationCommit.stale_stages(),
        [
            StageKind::DocumentationReview,
            StageKind::Delivery,
            StageKind::Approval
        ]
    );
}

#[test]
fn the_table_has_one_rule_for_each_change_in_declaration_order() {
    assert_eq!(INVALIDATION_RULES.len(), ArtifactChange::ALL.len());
    for (rule, change) in INVALIDATION_RULES.iter().zip(ArtifactChange::ALL) {
        assert_eq!(rule.change, *change);
        assert_eq!(rule.supersedes, change.stale_stages());
    }
}

#[test]
fn eight_rules_are_in_the_table_and_the_last_three_are_the_new_ones() {
    assert_eq!(INVALIDATION_RULES.len(), 8);
    let tail: Vec<ArtifactChange> = INVALIDATION_RULES[5..].iter().map(|r| r.change).collect();
    assert_eq!(
        tail,
        [
            ArtifactChange::RequestEdited,
            ArtifactChange::RepositoryMapVersion,
            ArtifactChange::GateEvidenceBinding,
        ]
    );
    assert_eq!(
        ArtifactChange::RequestEdited.as_str(),
        "The source request is edited after the intake snapshot"
    );
    assert_eq!(
        ArtifactChange::RepositoryMapVersion.as_str(),
        "REPOSITORY_INTELLIGENCE produces a new repository map"
    );
    assert_eq!(
        ArtifactChange::GateEvidenceBinding.as_str(),
        "A value bound to gate evidence changes"
    );
}

#[test]
fn a_change_never_makes_its_own_producer_stale() {
    for change in ArtifactChange::ALL {
        if let Some(producer) = change.producer() {
            assert!(!change.stale_stages().contains(&producer), "{change}");
        }
    }
}

#[test]
fn every_change_with_a_producer_has_exactly_one_and_the_lookup_agrees() {
    for change in ArtifactChange::ALL {
        if let Some(producer) = change.producer() {
            assert_eq!(ArtifactChange::produced_by(producer), Some(*change));
        }
    }
    let producers: Vec<Option<StageKind>> =
        ArtifactChange::ALL.iter().map(|c| c.producer()).collect();
    assert_eq!(
        producers,
        [
            Some(StageKind::Specification),
            Some(StageKind::Architecture),
            Some(StageKind::TaskPlanning),
            Some(StageKind::Implementation),
            Some(StageKind::Documenting),
            // The source request is edited by a person, outside the pipeline.
            None,
            Some(StageKind::RepositoryIntelligence),
            // A value bound to gate evidence moves outside the pipeline: the base branch, the
            // policy, the gate definition or the image.
            None,
        ]
    );
    assert_eq!(ArtifactChange::produced_by(StageKind::Review), None);
    // The lookup never answers with a change that no stage produces.
    for stage in StageKind::ALL {
        if let Some(change) = ArtifactChange::produced_by(*stage) {
            assert_eq!(change.producer(), Some(*stage));
        }
    }
}

#[test]
fn a_new_repository_map_makes_the_specification_and_everything_after_it_stale() {
    assert_eq!(
        ArtifactChange::produced_by(StageKind::RepositoryIntelligence),
        Some(ArtifactChange::RepositoryMapVersion)
    );
    assert_eq!(
        ArtifactChange::RepositoryMapVersion.stale_stages(),
        [
            StageKind::Specification,
            StageKind::DomainDiscovery,
            StageKind::Architecture,
            StageKind::TaskPlanning,
            StageKind::Implementation,
            StageKind::Validation,
            StageKind::Review,
            StageKind::Documenting,
            StageKind::DocumentationReview,
            StageKind::Delivery,
            StageKind::Approval,
        ]
    );
}

#[test]
fn an_edited_request_makes_every_stage_stale_including_the_intake() {
    // The text that every later stage read is no longer the text a person authorized, so the
    // intake run goes too (ADR 0010, NT-AUTHZ-05).
    let stale = ArtifactChange::RequestEdited.stale_stages();
    assert_eq!(stale.len(), 13);
    assert_eq!(stale[0], StageKind::Intake);
    assert_eq!(stale[1], StageKind::RepositoryIntelligence);
    assert_eq!(stale[12], StageKind::Approval);
    assert!(!stale.contains(&StageKind::Merge));
}

#[test]
fn a_change_to_a_value_bound_to_gate_evidence_leaves_the_documentation_text_alone() {
    // The base commit, the gate definition hash, the policy hash and the image digest are bound
    // to the evidence. The documentation text did not change, so DOCUMENTING stays.
    assert_eq!(
        ArtifactChange::GateEvidenceBinding.stale_stages(),
        [
            StageKind::Validation,
            StageKind::Review,
            StageKind::DocumentationReview,
            StageKind::Delivery,
            StageKind::Approval,
        ]
    );
    assert!(
        !ArtifactChange::GateEvidenceBinding
            .stale_stages()
            .contains(&StageKind::Documenting)
    );
}

fn one_passed_run_per_stage() -> Vec<StageRunSnapshot> {
    StageKind::ALL
        .iter()
        .enumerate()
        .map(|(index, kind)| run(index as u128 + 1, *kind, StageRunStatus::Passed))
        .collect()
}

#[test]
fn an_external_change_supersedes_its_first_stage_too() {
    // A change with no producing stage has nobody to spare, so every listed run is superseded,
    // the first one included.
    let runs = one_passed_run_per_stage();
    for (change, first) in [
        (ArtifactChange::RequestEdited, StageKind::Intake),
        (ArtifactChange::GateEvidenceBinding, StageKind::Validation),
    ] {
        assert_eq!(change.producer(), None);
        let planned = plan_for_change(&runs, change);
        let first_run = runs.iter().find(|r| r.kind == first).unwrap();
        assert!(planned.contains(&first_run.id), "{change}");
        assert_eq!(planned.len(), change.stale_stages().len(), "{change}");
    }
    // A change that a stage produces spares that stage.
    let planned = plan_for_change(&runs, ArtifactChange::RepositoryMapVersion);
    let producer = runs
        .iter()
        .find(|r| r.kind == StageKind::RepositoryIntelligence)
        .unwrap();
    assert!(!planned.contains(&producer.id));
    let first = runs
        .iter()
        .find(|r| r.kind == StageKind::Specification)
        .unwrap();
    assert!(planned.contains(&first.id));
}

#[test]
fn an_edited_request_supersedes_live_and_skipped_runs_alike() {
    let runs = [
        run(1, StageKind::Intake, StageRunStatus::Passed),
        run(2, StageKind::Specification, StageRunStatus::WaitingForHuman),
        run(3, StageKind::DomainDiscovery, StageRunStatus::Skipped),
        run(4, StageKind::Architecture, StageRunStatus::Failed),
        run(5, StageKind::Approval, StageRunStatus::Pending),
    ];
    assert_eq!(
        plan_for_change(&runs, ArtifactChange::RequestEdited),
        [id(1), id(2), id(3), id(5)]
    );
}

#[test]
fn a_rework_to_repository_intelligence_is_planned_from_the_new_row() {
    let stages = rework_stages(StageKind::RepositoryIntelligence);
    assert_eq!(stages[0], StageKind::RepositoryIntelligence);
    assert_eq!(
        &stages[1..],
        ArtifactChange::RepositoryMapVersion.stale_stages()
    );
    let runs = [
        run(1, StageKind::Intake, StageRunStatus::Passed),
        run(2, StageKind::RepositoryIntelligence, StageRunStatus::Gating),
        run(3, StageKind::Specification, StageRunStatus::Pending),
        run(4, StageKind::Architecture, StageRunStatus::Pending),
    ];
    assert_eq!(
        plan_for_rework(&runs, StageKind::RepositoryIntelligence, id(2)),
        [id(3), id(4)]
    );
}

#[test]
fn the_rules_equal_everything_downstream_of_the_producer_except_merge() {
    // The pipeline's `requires` lists are a second description of the same order. If the two
    // disagree, one of them is wrong. MERGE is left out of the file because it is not
    // implemented and is disabled by default.
    for change in ArtifactChange::ALL {
        // A change that no stage produces has no producer to measure from. The request edit
        // starts from the intake, which is why the intake goes too, and the gate evidence rule is
        // a list of its own.
        let Some(producer) = change.producer() else {
            continue;
        };
        let mut expected = downstream(producer);
        expected.retain(|kind| *kind != StageKind::Merge);
        let mut actual = change.stale_stages().to_vec();
        actual.sort();
        assert_eq!(actual, expected, "{change}");
    }
    // The edited request is everything from the intake on.
    let mut from_the_intake = downstream(StageKind::Intake);
    from_the_intake.push(StageKind::Intake);
    from_the_intake.retain(|kind| *kind != StageKind::Merge);
    from_the_intake.sort();
    let mut actual = ArtifactChange::RequestEdited.stale_stages().to_vec();
    actual.sort();
    assert_eq!(actual, from_the_intake);
}

#[test]
fn only_runs_that_can_still_be_superseded_are_picked() {
    let runs = [
        run(1, StageKind::Implementation, StageRunStatus::Passed),
        run(2, StageKind::Validation, StageRunStatus::Passed),
        run(3, StageKind::Review, StageRunStatus::Running),
        run(4, StageKind::Documenting, StageRunStatus::Skipped),
        run(5, StageKind::DocumentationReview, StageRunStatus::Failed),
        run(6, StageKind::Delivery, StageRunStatus::Superseded),
        run(7, StageKind::Approval, StageRunStatus::Pending),
    ];
    assert_eq!(
        plan_for_change(&runs, ArtifactChange::ImplementationCommit),
        [id(2), id(3), id(4), id(7)]
    );
}

#[test]
fn skipped_stage_is_superseded_by_an_upstream_change() {
    // ADR 0010 decision 2: the skip decision was made on recorded inputs. When an upstream
    // artifact changes, the decision must be made again, so the old skipped run goes stale. If it
    // stayed, it would still satisfy the guard of the stage after it.
    let runs = [
        run(1, StageKind::Documenting, StageRunStatus::Skipped),
        run(2, StageKind::DocumentationReview, StageRunStatus::Skipped),
        run(3, StageKind::Implementation, StageRunStatus::Passed),
    ];
    let planned = plan_for_change(&runs, ArtifactChange::ImplementationCommit);
    assert_eq!(planned, [id(1), id(2)]);

    // Applying the plan really takes the skipped runs to SUPERSEDED, and a second plan is empty.
    let mut applied = runs;
    for run in &mut applied {
        if planned.contains(&run.id) {
            assert_eq!(
                run.status.advance(StageRunEvent::Supersede).map(|t| t.id),
                Ok("S20")
            );
            assert_eq!(run.status, StageRunStatus::Superseded);
        }
    }
    assert!(plan_for_change(&applied, ArtifactChange::ImplementationCommit).is_empty());

    // Rework to an earlier stage replaces a skipped run of a later one for the same reason.
    let by_rework = plan_for_rework(&runs, StageKind::Implementation, id(3));
    assert_eq!(by_rework, [id(1), id(2)]);
}

#[test]
fn the_producer_run_is_not_picked_by_its_own_change() {
    let runs = [run(1, StageKind::Implementation, StageRunStatus::Passed)];
    assert!(plan_for_change(&runs, ArtifactChange::ImplementationCommit).is_empty());
}

#[test]
fn runs_of_stages_outside_the_rule_are_left_alone() {
    let runs = [
        run(1, StageKind::Intake, StageRunStatus::Passed),
        run(2, StageKind::Specification, StageRunStatus::Passed),
        run(3, StageKind::Implementation, StageRunStatus::Passed),
        run(4, StageKind::Validation, StageRunStatus::Passed),
    ];
    assert_eq!(
        plan_for_change(&runs, ArtifactChange::DocumentationCommit),
        Vec::<StageRunId>::new()
    );
}

#[test]
fn every_old_run_of_a_stale_stage_is_picked_not_only_the_latest() {
    let runs = [
        run(1, StageKind::Validation, StageRunStatus::Passed),
        run(2, StageKind::Validation, StageRunStatus::Pending),
    ];
    assert_eq!(
        plan_for_change(&runs, ArtifactChange::ImplementationCommit),
        [id(1), id(2)]
    );
}

#[test]
fn applying_a_plan_makes_the_same_plan_empty() {
    let mut runs = vec![
        run(1, StageKind::Validation, StageRunStatus::Passed),
        run(2, StageKind::Review, StageRunStatus::Gating),
        run(3, StageKind::Approval, StageRunStatus::WaitingForHuman),
    ];
    let first = plan_for_change(&runs, ArtifactChange::ImplementationCommit);
    assert_eq!(first.len(), 3);
    for run in &mut runs {
        if first.contains(&run.id) {
            run.status.advance(StageRunEvent::Supersede).unwrap();
        }
    }
    assert!(plan_for_change(&runs, ArtifactChange::ImplementationCommit).is_empty());
    assert!(runs.iter().all(|r| r.status == StageRunStatus::Superseded));
}

#[test]
fn every_planned_run_accepts_the_supersede_event() {
    for status in StageRunStatus::STATES {
        let runs = [run(1, StageKind::Validation, *status)];
        let planned = plan_for_change(&runs, ArtifactChange::ImplementationCommit);
        assert_eq!(
            !planned.is_empty(),
            status.apply(StageRunEvent::Supersede).is_ok(),
            "{status}"
        );
    }
}

#[test]
fn rework_replaces_the_old_target_run_and_everything_after_it() {
    assert_eq!(
        rework_stages(StageKind::Documenting),
        [
            StageKind::Documenting,
            StageKind::DocumentationReview,
            StageKind::Delivery,
            StageKind::Approval,
        ]
    );
    assert_eq!(
        rework_stages(StageKind::Implementation)[0],
        StageKind::Implementation
    );
    assert_eq!(rework_stages(StageKind::Implementation).len(), 7);
}

#[test]
fn a_stage_that_produces_nothing_is_replaced_alone() {
    assert_eq!(rework_stages(StageKind::Review), [StageKind::Review]);
}

#[test]
fn rework_keeps_the_failing_run_so_it_can_become_rework_requested() {
    // VALIDATION fails and sends the work back to IMPLEMENTATION. The old IMPLEMENTATION run and
    // the runs that wait for it are superseded. The failing VALIDATION run is not: it takes the
    // REWORK_REQUESTED transition instead.
    let runs = [
        run(1, StageKind::Implementation, StageRunStatus::Passed),
        run(2, StageKind::Validation, StageRunStatus::Gating),
        run(3, StageKind::Review, StageRunStatus::Pending),
        run(4, StageKind::Specification, StageRunStatus::Passed),
    ];
    assert_eq!(
        plan_for_rework(&runs, StageKind::Implementation, id(2)),
        [id(1), id(3)]
    );
}

#[test]
fn a_run_that_reworks_itself_is_not_superseded() {
    // SPECIFICATION asks for another SPECIFICATION run. The failing run is the old target run.
    let runs = [
        run(1, StageKind::Specification, StageRunStatus::Gating),
        run(2, StageKind::Architecture, StageRunStatus::Pending),
    ];
    assert_eq!(
        plan_for_rework(&runs, StageKind::Specification, id(1)),
        [id(2)]
    );
}

#[test]
fn task_nodes_of_a_superseded_run_are_cancelled_unless_they_are_finished() {
    for status in [
        TaskNodeStatus::Pending,
        TaskNodeStatus::Ready,
        TaskNodeStatus::Running,
        TaskNodeStatus::Failed,
    ] {
        assert_eq!(
            task_node_event_on_supersession(status),
            Some(TaskNodeEvent::Cancel),
            "{status}"
        );
    }
    for status in [TaskNodeStatus::Succeeded, TaskNodeStatus::Cancelled] {
        assert_eq!(task_node_event_on_supersession(status), None, "{status}");
    }
}
