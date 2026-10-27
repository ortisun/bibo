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
fn a_change_never_makes_its_own_producer_stale() {
    for change in ArtifactChange::ALL {
        assert!(
            !change.stale_stages().contains(&change.producer()),
            "{change}"
        );
    }
}

#[test]
fn every_change_has_exactly_one_producer_and_the_lookup_agrees() {
    for change in ArtifactChange::ALL {
        assert_eq!(
            ArtifactChange::produced_by(change.producer()),
            Some(*change)
        );
    }
    let producers: Vec<StageKind> = ArtifactChange::ALL.iter().map(|c| c.producer()).collect();
    assert_eq!(
        producers,
        [
            StageKind::Specification,
            StageKind::Architecture,
            StageKind::TaskPlanning,
            StageKind::Implementation,
            StageKind::Documenting,
        ]
    );
    assert_eq!(ArtifactChange::produced_by(StageKind::Review), None);
}

#[test]
fn the_rules_equal_everything_downstream_of_the_producer_except_merge() {
    // The pipeline's `requires` lists are a second description of the same order. If the two
    // disagree, one of them is wrong. MERGE is left out of the file because it is not
    // implemented and is disabled by default.
    for change in ArtifactChange::ALL {
        let mut expected = downstream(change.producer());
        expected.retain(|kind| *kind != StageKind::Merge);
        let mut actual = change.stale_stages().to_vec();
        actual.sort();
        assert_eq!(actual, expected, "{change}");
    }
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
