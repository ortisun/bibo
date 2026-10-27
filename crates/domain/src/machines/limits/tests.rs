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
fn only_a_documenting_target_is_counted_as_documentation_rework() {
    for kind in StageKind::ALL {
        let expected = if *kind == StageKind::Documenting {
            ReworkTrack::Documentation
        } else {
            ReworkTrack::Code
        };
        assert_eq!(ReworkTrack::for_target(*kind), expected, "{kind}");
    }
}

#[test]
fn a_new_ledger_has_used_no_rounds() {
    let ledger = ReworkLedger::default();
    assert_eq!(ledger.used(ReworkTrack::Code), 0);
    assert_eq!(ledger.used(ReworkTrack::Documentation), 0);
}

#[test]
fn rounds_are_counted_apart_for_code_and_documentation() {
    let limits = ReworkLimits::default();
    let ledger = ReworkLedger::default()
        .start_round(ReworkTrack::Code, limits)
        .unwrap()
        .start_round(ReworkTrack::Code, limits)
        .unwrap();
    assert_eq!(ledger.used(ReworkTrack::Code), 2);
    assert_eq!(ledger.used(ReworkTrack::Documentation), 0);
    // Documentation still has both of its rounds.
    assert!(ledger.has_room(ReworkTrack::Documentation, limits));
    assert!(!ledger.has_room(ReworkTrack::Code, limits));
}

#[test]
fn a_third_round_is_refused_with_a_plain_message() {
    let limits = ReworkLimits::default();
    let ledger = ReworkLedger::new(2, 0);
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
}

#[test]
fn a_refused_round_leaves_the_ledger_as_it_was() {
    let limits = ReworkLimits::default();
    let ledger = ReworkLedger::new(2, 1);
    assert!(ledger.start_round(ReworkTrack::Code, limits).is_err());
    assert_eq!(ledger, ReworkLedger::new(2, 1));
}

#[test]
fn a_lower_project_cap_applies_to_its_own_track_only() {
    let limits = ReworkLimits::from_policy(1, 0);
    assert_eq!(limits.cap(ReworkTrack::Code).get(), 1);
    assert_eq!(limits.cap(ReworkTrack::Documentation).get(), 0);
    let ledger = ReworkLedger::default();
    assert!(ledger.has_room(ReworkTrack::Code, limits));
    assert!(!ledger.has_room(ReworkTrack::Documentation, limits));
}

#[test]
fn a_cap_lowered_after_rounds_were_used_does_not_panic_or_wrap() {
    // Two rounds were used when the cap was 2; the project then lowered the cap to 1.
    let limits = ReworkLimits::from_policy(1, 1);
    let ledger = ReworkLedger::new(2, 2);
    assert!(!ledger.has_room(ReworkTrack::Code, limits));
    assert!(ledger.start_round(ReworkTrack::Code, limits).is_err());
}
