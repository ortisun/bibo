use super::Designation::{Approver, Operator, OrgAdmin, Requester, SecurityApprover};
use super::*;
use crate::fx::github::{FakeGithub, User};

fn list() -> Allowlist {
    Allowlist::new(3)
        .with(AllowlistEntry::new(1001, "alice", &[Requester]))
        .with(AllowlistEntry::new(1002, "bob", &[Requester, Approver]))
        .with(AllowlistEntry::new(1004, "dana", &[Operator, SecurityApprover]).expiring_at(5_000))
}

#[test]
fn the_decision_follows_the_numeric_id_and_the_designation() {
    let list = list();
    assert!(list.decide(1001, Requester, 0).is_allowed());
    assert!(list.decide(1002, Approver, 0).is_allowed());
    // On the list, without that designation.
    assert!(matches!(
        list.decide(1001, Approver, 0),
        Decision::Denied {
            reason: DenyReason::DesignationMissing,
            ..
        }
    ));
    // Not on the list.
    assert!(matches!(
        list.decide(9999, Requester, 0),
        Decision::Denied {
            reason: DenyReason::NotOnAllowlist,
            ..
        }
    ));
}

#[test]
fn an_entry_stops_counting_at_its_expiry() {
    let list = list();
    assert!(list.decide(1004, Operator, 4_999).is_allowed());
    assert!(matches!(
        list.decide(1004, Operator, 5_000),
        Decision::Denied {
            reason: DenyReason::EntryExpired,
            ..
        }
    ));
}

#[test]
fn a_github_role_grants_nothing() {
    // The fake GitHub gives a stranger the admin role and the OWNER association. The reference
    // decision has nowhere to take either into account, and the answer is the same as for any
    // stranger. The fake also records every use of its collaborator-permission endpoint, which
    // the decision must never make.
    let github = FakeGithub::new();
    github
        .add_repo("acme/widgets", "main")
        .add_user(User::person("mallory", 7777, "admin", "OWNER"))
        .add_user(User::person("nobody", 8888, "read", "NONE"));
    let list = list();
    for stranger in [7777, 8888] {
        assert!(matches!(
            list.decide(stranger, Requester, 0),
            Decision::Denied {
                reason: DenyReason::NotOnAllowlist,
                ..
            }
        ));
    }
    assert!(github.permission_lookups().is_empty());
}

#[test]
fn a_login_that_matches_a_listed_one_is_not_enough() {
    // Someone renames their account to "alice", or takes the name after she leaves. The login is
    // not a parameter of the decision, so only the numeric id can open the door.
    let list = list();
    let imposter_id = 424_242;
    assert!(!list.decide(imposter_id, Requester, 0).is_allowed());
    assert!(list.decide(1001, Requester, 0).is_allowed());
    assert_eq!(list.entries()[0].login, "alice");
}

#[test]
fn removing_a_person_changes_the_decision_and_the_recorded_hash() {
    let before = list();
    let after = Allowlist::new(4)
        .with(AllowlistEntry::new(1001, "alice", &[Requester]))
        .with(AllowlistEntry::new(1004, "dana", &[Operator, SecurityApprover]).expiring_at(5_000));
    let decision_before = before.decide(1002, Approver, 0);
    let decision_after = after.decide(1002, Approver, 0);
    assert!(decision_before.is_allowed());
    assert!(matches!(
        decision_after,
        Decision::Denied {
            reason: DenyReason::NotOnAllowlist,
            ..
        }
    ));
    // Each decision says which list it was made under.
    assert_eq!(decision_before.list_hash(), before.hash());
    assert_eq!(decision_after.list_hash(), after.hash());
    assert_ne!(before.hash(), after.hash());
}

#[test]
fn the_hash_covers_content_and_version_and_not_the_order() {
    let a = Allowlist::new(1)
        .with(AllowlistEntry::new(1, "a", &[Requester]))
        .with(AllowlistEntry::new(2, "b", &[Approver]));
    let b = Allowlist::new(1)
        .with(AllowlistEntry::new(2, "b", &[Approver]))
        .with(AllowlistEntry::new(1, "a", &[Requester]));
    assert_eq!(a.hash(), b.hash());
    assert!(a.hash().starts_with("sha256:") && a.hash().len() == "sha256:".len() + 64);
    // A new version, a new designation or a new expiry each change it.
    assert_ne!(
        a.hash(),
        Allowlist::new(2)
            .with(a.entries()[0].clone())
            .with(a.entries()[1].clone())
            .hash()
    );
    let wider = Allowlist::new(1)
        .with(AllowlistEntry::new(1, "a", &[Requester, Operator]))
        .with(AllowlistEntry::new(2, "b", &[Approver]));
    assert_ne!(a.hash(), wider.hash());
    let expiring = Allowlist::new(1)
        .with(AllowlistEntry::new(1, "a", &[Requester]).expiring_at(10))
        .with(AllowlistEntry::new(2, "b", &[Approver]));
    assert_ne!(a.hash(), expiring.hash());
}

#[test]
fn a_decision_that_looked_at_the_role_would_be_caught_by_the_stranger_case() {
    // Deliberate break: a decision that trusts an administrator role lets the stranger in. The
    // stranger case above is what notices, so show that it can.
    let list = list();
    let role_based = |user: &User, designation: Designation| -> bool {
        list.decide(user.id, designation, 0).is_allowed() || user.role == "admin"
    };
    let stranger = User::person("mallory", 7777, "admin", "OWNER");
    assert!(
        role_based(&stranger, Requester),
        "the broken decision admits the stranger"
    );
    assert!(
        !list.decide(stranger.id, Requester, 0).is_allowed(),
        "the reference does not"
    );
    assert_eq!(OrgAdmin.name(), "org_admin");
}
