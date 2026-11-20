//! The fake change host of the test kit records the installation tokens it would have asked for
//! (finding SF-04 of the Slice 1 run). It cannot depend on this crate, so it holds a copy of the
//! permission sets. This test compares the copy with the adapter's sets for every stage, so that
//! a change to one that is not made to the other fails here.

use factory_domain::vocabulary::StageKind;
use factory_github::{Level, PermissionSet};
use factory_testkit::githost::{TokenKind, permissions_asked};

fn as_asked(set: &PermissionSet) -> Vec<(&'static str, &'static str)> {
    let mut entries: Vec<(&'static str, &'static str)> = set
        .entries()
        .into_iter()
        .map(|(name, level)| {
            (
                name,
                match level {
                    Level::Read => "read",
                    Level::Write => "write",
                },
            )
        })
        .collect();
    entries.sort_unstable();
    entries
}

#[test]
fn the_fake_asks_for_what_the_adapter_asks_for() {
    for stage in StageKind::ALL.iter().copied() {
        assert_eq!(
            permissions_asked(stage, TokenKind::Stage),
            as_asked(&PermissionSet::for_stage(stage)),
            "the stage token of {stage:?}"
        );
    }
    for stage in StageKind::ALL.iter().copied() {
        assert_eq!(
            permissions_asked(stage, TokenKind::Fetch),
            as_asked(&PermissionSet::fetch()),
            "the fetch token does not depend on the stage"
        );
    }
    assert_eq!(
        permissions_asked(StageKind::Delivery, TokenKind::Push),
        as_asked(&PermissionSet::push())
    );
}
