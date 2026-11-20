use super::*;
use crate::vocabulary::StageKind;

#[test]
fn the_default_cap_is_two_as_adr_0009_says() {
    assert_eq!(DEFAULT_REWORK_CAP, 2);
    assert_eq!(ReworkCap::default().get(), 2);
}

#[test]
fn a_policy_value_can_lower_the_cap_but_never_raise_it_above_two() {
    assert_eq!(ReworkCap::from_policy(0).get(), 0);
    assert_eq!(ReworkCap::from_policy(1).get(), 1);
    assert_eq!(ReworkCap::from_policy(2).get(), 2);
    for configured in 3..=u8::MAX {
        assert_eq!(
            ReworkCap::from_policy(configured).get(),
            2,
            "policy value {configured}"
        );
    }
}

#[test]
fn repair_cap_is_at_most_two() {
    // ADR 0010: two repairs after an invalid output, and a policy may only lower that.
    assert_eq!(DEFAULT_REPAIR_CAP, 2);
    assert_eq!(RepairCap::default().get(), 2);
    assert_eq!(RepairCap::DEFAULT, RepairCap::default());
    for configured in 0..=u8::MAX {
        assert_eq!(
            RepairCap::from_policy(configured).get(),
            configured.min(2),
            "policy value {configured}"
        );
    }
}

#[test]
fn each_target_is_charged_to_the_count_of_its_phase() {
    use ReworkTrack::{Code, Design, Documentation, Specification};
    let expected = [
        (StageKind::Intake, Specification),
        (StageKind::RepositoryIntelligence, Specification),
        (StageKind::Specification, Specification),
        (StageKind::DomainDiscovery, Design),
        (StageKind::Architecture, Design),
        (StageKind::TaskPlanning, Design),
        (StageKind::Implementation, Code),
        (StageKind::Validation, Code),
        (StageKind::Review, Code),
        (StageKind::Documenting, Documentation),
        (StageKind::DocumentationReview, Code),
        (StageKind::Delivery, Code),
        (StageKind::Approval, Code),
        (StageKind::Merge, Code),
    ];
    assert_eq!(
        expected.len(),
        StageKind::ALL.len(),
        "every stage kind is listed"
    );
    for (kind, track) in expected {
        assert_eq!(ReworkTrack::for_target(kind), track, "{kind}");
    }
}

#[test]
fn the_tracks_are_spelled_as_the_policy_and_the_audit_events_spell_them() {
    let names: Vec<&str> = ReworkTrack::ALL.iter().map(|t| t.as_str()).collect();
    assert_eq!(names, ["specification", "design", "code", "documentation"]);
}

#[test]
fn a_new_ledger_has_used_no_rounds() {
    let ledger = ReworkLedger::default();
    for track in ReworkTrack::ALL {
        assert_eq!(ledger.used(*track), 0, "{track}");
    }
}

#[test]
fn every_count_is_kept_apart_from_the_others() {
    let limits = ReworkLimits::default();
    for full in ReworkTrack::ALL {
        let ledger = ReworkLedger::default()
            .start_round(*full, limits)
            .unwrap()
            .start_round(*full, limits)
            .unwrap();
        assert_eq!(ledger.used(*full), 2);
        assert!(!ledger.has_room(*full, limits));
        for other in ReworkTrack::ALL.iter().filter(|t| *t != full) {
            assert_eq!(ledger.used(*other), 0, "{full} rounds moved {other}");
            assert!(
                ledger.has_room(*other, limits),
                "{full} rounds filled {other}"
            );
        }
    }
}

#[test]
fn a_design_round_does_not_use_a_code_round() {
    // Run 29 of scenario E1: the specification used its two rounds, then the architecture failed.
    let limits = ReworkLimits::default();
    let ledger = ReworkLedger::default()
        .start_round(ReworkTrack::Specification, limits)
        .unwrap()
        .start_round(ReworkTrack::Specification, limits)
        .unwrap()
        .start_round(ReworkTrack::Design, limits)
        .unwrap();
    assert_eq!(ledger.used(ReworkTrack::Specification), 2);
    assert_eq!(ledger.used(ReworkTrack::Design), 1);
    assert_eq!(ledger.used(ReworkTrack::Code), 0);
    // The implementation still has both of its rounds.
    let ledger = ledger
        .start_round(ReworkTrack::Code, limits)
        .unwrap()
        .start_round(ReworkTrack::Code, limits)
        .unwrap();
    assert_eq!(ledger.used(ReworkTrack::Code), 2);
    // The second design round is still there, and the third is not.
    let ledger = ledger.start_round(ReworkTrack::Design, limits).unwrap();
    assert!(ledger.start_round(ReworkTrack::Design, limits).is_err());
}

#[test]
fn a_cap_of_zero_one_or_two_allows_exactly_that_many_rounds_on_each_count() {
    for configured in [0_u8, 1, 2] {
        for track in ReworkTrack::ALL {
            let limits = ReworkLimits::default().with_policy(*track, configured);
            assert_eq!(limits.cap(*track).get(), configured);
            let mut ledger = ReworkLedger::default();
            let mut taken = 0_u8;
            while let Ok(next) = ledger.start_round(*track, limits) {
                ledger = next;
                taken += 1;
                assert!(taken <= DEFAULT_REWORK_CAP, "{track} went past the default");
            }
            assert_eq!(taken, configured, "{track} at a cap of {configured}");
            assert_eq!(ledger.used(*track), configured);
        }
    }
}

#[test]
fn a_policy_value_above_the_default_is_lowered_to_it_on_every_count() {
    for configured in [3_u8, 9, u8::MAX] {
        let uniform = ReworkLimits::uniform(configured);
        for track in ReworkTrack::ALL {
            assert_eq!(uniform.cap(*track).get(), DEFAULT_REWORK_CAP, "{track}");
            let one = ReworkLimits::default().with_policy(*track, configured);
            assert_eq!(one.cap(*track).get(), DEFAULT_REWORK_CAP, "{track}");
        }
    }
}

#[test]
fn a_third_round_is_refused_with_a_plain_message() {
    let limits = ReworkLimits::default();
    let ledger = ReworkLedger::default().with_used(ReworkTrack::Code, 2);
    let error = ledger.start_round(ReworkTrack::Code, limits).unwrap_err();
    assert_eq!(
        error,
        ReworkCapReached {
            track: ReworkTrack::Code,
            cap: 2
        }
    );
    assert_eq!(
        error.to_string(),
        "the code rework cap of 2 rounds is reached; a human decides whether to go on"
    );
    let design = ReworkLedger::default().with_used(ReworkTrack::Design, 2);
    assert_eq!(
        design
            .start_round(ReworkTrack::Design, limits)
            .unwrap_err()
            .to_string(),
        "the design rework cap of 2 rounds is reached; a human decides whether to go on"
    );
}

#[test]
fn a_refused_round_leaves_the_ledger_as_it_was() {
    let limits = ReworkLimits::default();
    let ledger = ReworkLedger::default()
        .with_used(ReworkTrack::Code, 2)
        .with_used(ReworkTrack::Documentation, 1);
    assert!(ledger.start_round(ReworkTrack::Code, limits).is_err());
    assert_eq!(
        ledger,
        ReworkLedger::default()
            .with_used(ReworkTrack::Code, 2)
            .with_used(ReworkTrack::Documentation, 1)
    );
}

#[test]
fn a_lower_project_cap_applies_to_its_own_track_only() {
    let limits = ReworkLimits::default()
        .with_policy(ReworkTrack::Code, 1)
        .with_policy(ReworkTrack::Documentation, 0);
    assert_eq!(limits.cap(ReworkTrack::Code).get(), 1);
    assert_eq!(limits.cap(ReworkTrack::Documentation).get(), 0);
    assert_eq!(limits.cap(ReworkTrack::Design).get(), 2);
    assert_eq!(limits.cap(ReworkTrack::Specification).get(), 2);
    let ledger = ReworkLedger::default();
    assert!(ledger.has_room(ReworkTrack::Code, limits));
    assert!(!ledger.has_room(ReworkTrack::Documentation, limits));
    assert!(ledger.has_room(ReworkTrack::Design, limits));
}

#[test]
fn a_cap_lowered_after_rounds_were_used_does_not_panic_or_wrap() {
    // Two rounds were used when the cap was 2; the project then lowered the cap to 1.
    let limits = ReworkLimits::uniform(1);
    let mut ledger = ReworkLedger::default();
    for track in ReworkTrack::ALL {
        ledger = ledger.with_used(*track, 2);
    }
    for track in ReworkTrack::ALL {
        assert!(!ledger.has_room(*track, limits));
        assert!(ledger.start_round(*track, limits).is_err());
    }
    // A count read back at the largest value a byte holds is refused too, never wrapped.
    let full = ReworkLedger::default().with_used(ReworkTrack::Design, u8::MAX);
    assert!(
        full.start_round(ReworkTrack::Design, ReworkLimits::default())
            .is_err()
    );
}
