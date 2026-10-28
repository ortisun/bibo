//! Attack: package identity.
//!
//! The gate keys a locked package by its **name** (and, when a name has several versions, by
//! name and version). Cargo keys it by name, version **and source**: a lockfile may hold
//! `evil 0.1.0` from the workspace and `evil 0.1.0` from crates.io side by side, and writes the
//! reference as `evil 0.1.0 (registry+...)`. The reader drops the source from the reference
//! (`cargo.rs::reference`), `Lockfile::resolve` then finds two packages and returns `None`, and
//! `LockDiff::compare_name` matches by version only, so the second package of a name and version
//! is invisible to the diff.
//!
//! The lockfile used here has the shape that real cargo 1.98.0 wrote for this workspace (a
//! scratch workspace with a directory-source replacement, so that it resolved offline): the path
//! package first, the registry package second, and `app` pointing at the registry one with the
//! source in the reference. `cargo fetch --locked` and `cargo metadata --locked` accepted it.

use factory_domain::policy::decision::Designation;
use factory_domain::policy::dependency::DependencyFlag;
use factory_domain::vocabulary::GateOutcome;
use factory_workflow::gates::supply_chain::facts::StaticRegistry;
use factory_workflow::gates::supply_chain::findings::check;
use factory_workflow::gates::supply_chain::integrity::Integrity;
use factory_workflow::gates::supply_chain::licenses::LicensePolicy;
use factory_workflow::gates::supply_chain::names::PopularNames;
use factory_workflow::gates::supply_chain::report::gate;
use factory_workflow::gates::supply_chain::review::{Plan, RegistryTable, Settings};

use crate::files::{Files, files, judge, judge_with, lock, manifest, member, reg};
use crate::people::{engine, now, policy_hash, scope};
use crate::world::{Script, World, metadata};

const WORKSPACE_APP: &str = "[workspace]\nmembers = [\"app\"]\nresolver = \"2\"\n";
const WORKSPACE_APP_AND: &str = "[workspace]\nmembers = [\"app\", \"MEMBER\"]\nresolver = \"2\"\n";

fn workspace_with(member_name: &str) -> String {
    WORKSPACE_APP_AND.replace("MEMBER", member_name)
}

/// The reference cargo writes for the registry copy when the path copy has the same version.
const EVIL_REGISTRY: &str = "evil 0.1.0 (registry+https://github.com/rust-lang/crates.io-index)";
const FOO_REGISTRY: &str = "foo 0.1.0 (registry+https://github.com/rust-lang/crates.io-index)";

/// The base commit: a workspace with one member, `app`, and no dependency.
fn base_without_members() -> Files {
    files(&[
        ("Cargo.toml", WORKSPACE_APP.to_owned()),
        ("app/Cargo.toml", manifest("app", "")),
        ("Cargo.lock", lock(&[member("app", &[])])),
    ])
}

/// The candidate adds a workspace member called `evil` and, in `app`, a registry dependency on
/// the package `evil`. Nothing in the base commit is called `evil`.
fn head_with_twin_member() -> Files {
    files(&[
        ("Cargo.toml", workspace_with("evil")),
        (
            "app/Cargo.toml",
            manifest(
                "app",
                "[dependencies]\nevil_reg = { package = \"evil\", version = \"0.1.0\" }\n",
            ),
        ),
        ("evil/Cargo.toml", manifest("evil", "")),
        (
            "Cargo.lock",
            lock(&[
                member("app", &[EVIL_REGISTRY]),
                member("evil", &[]),
                reg("evil", "0.1.0", 'e'),
            ]),
        ),
    ])
}

/// The base commit has a workspace member `foo` (an internal package) next to `app`.
fn base_with_foo() -> Files {
    files(&[
        ("Cargo.toml", workspace_with("foo")),
        ("app/Cargo.toml", manifest("app", "")),
        ("foo/Cargo.toml", manifest("foo", "")),
        (
            "Cargo.lock",
            lock(&[member("app", &[]), member("foo", &[])]),
        ),
    ])
}

/// The candidate makes `app` depend on the **registry** package `foo` at the same version as the
/// internal member.
fn head_with_registry_foo_same_version() -> Files {
    files(&[
        ("Cargo.toml", workspace_with("foo")),
        (
            "app/Cargo.toml",
            manifest(
                "app",
                "[dependencies]\nfoo_reg = { package = \"foo\", version = \"0.1.0\" }\n",
            ),
        ),
        ("foo/Cargo.toml", manifest("foo", "")),
        (
            "Cargo.lock",
            lock(&[
                member("app", &[FOO_REGISTRY]),
                member("foo", &[]),
                reg("foo", "0.1.0", 'f'),
            ]),
        ),
    ])
}

/// The same, with a version the internal member does not have (the usual confusion attack uses
/// a high version number).
fn head_with_registry_foo_high_version() -> Files {
    files(&[
        ("Cargo.toml", workspace_with("foo")),
        (
            "app/Cargo.toml",
            manifest(
                "app",
                "[dependencies]\nfoo_reg = { package = \"foo\", version = \"9.9.9\" }\n",
            ),
        ),
        ("foo/Cargo.toml", manifest("foo", "")),
        (
            "Cargo.lock",
            lock(&[
                member("app", &["foo 9.9.9"]),
                member("foo", &[]),
                reg("foo", "9.9.9", 'f'),
            ]),
        ),
    ])
}

fn registry_package_named<'a>(
    integrity: &'a factory_workflow::gates::supply_chain::integrity::Integrity,
    name: &str,
) -> Option<&'a factory_workflow::gates::supply_chain::integrity::NewDirect> {
    integrity
        .new_direct
        .iter()
        .find(|entry| entry.package.name == name && entry.package.origin.is_default_registry())
}

// ---------------------------------------------------------------------------------------------
// SC-1: a brand-new registry package escapes the human decision
// ---------------------------------------------------------------------------------------------

/// A name that exists nowhere in the base commit must be a new direct dependency, or the change
/// must be refused. Here the registry package `evil` is neither: the reference
/// `evil 0.1.0 (registry+...)` matches the new workspace member `evil 0.1.0` as well, `resolve`
/// returns `None`, and `new_direct_dependencies` skips it.
#[test]
fn sc1_a_new_registry_package_beside_a_same_named_member_is_still_a_new_direct_dependency() {
    let integrity = judge(&base_without_members(), &head_with_twin_member());
    assert!(
        integrity.has_violation() || registry_package_named(&integrity, "evil").is_some(),
        "the registry package `evil` is in no base lockfile and no person was asked about it: {:?}",
        integrity.new_direct
    );
}

/// The same attack through the whole gate: no decision is recorded, the registry knows nothing
/// about the package (the worst case), and the gate must not fetch.
#[tokio::test]
async fn sc1_the_gate_does_not_fetch_an_unknown_registry_package_without_a_decision() {
    let world = World::new();
    world.tools.set(Script {
        metadata: metadata(&[("evil", "0.1.0", Some("MIT"), false)]),
        ..Script::default()
    });
    let ran = world
        .gate(
            &base_without_members(),
            &head_with_twin_member(),
            &StaticRegistry::new(),
            &[],
            false,
        )
        .await
        .expect("the gate runs");
    assert!(
        world.sandbox.created().is_empty(),
        "a fetch_deps container was made although no person decided on `evil`"
    );
    assert_eq!(
        ran.outcome(gate::REVIEW),
        GateOutcome::Blocked,
        "the review must wait for a person"
    );
}

// ---------------------------------------------------------------------------------------------
// SC-2: a registry package with the name and version of an internal member is invisible
// ---------------------------------------------------------------------------------------------

/// The base commit has the internal member `foo 0.1.0`. The candidate adds the registry package
/// `foo 0.1.0`. The diff pairs the old `foo 0.1.0` with the first `foo 0.1.0` it finds (the path
/// one, which cargo writes first) and drops the registry copy, so the lockfile looks unchanged.
#[test]
fn sc2_a_registry_copy_of_an_internal_member_changes_the_dependency_set() {
    let integrity = judge(&base_with_foo(), &head_with_registry_foo_same_version());
    assert!(
        integrity.lock_changed() || integrity.has_violation(),
        "the lockfile gained the registry package foo 0.1.0 and the diff says nothing changed"
    );
}

/// Even when the operator lists `foo` as an internal name, the registry copy with the same
/// version is not reported as a dependency confusion, because the diff never shows it.
#[test]
fn sc2_the_internal_name_list_catches_the_registry_copy_of_an_internal_member() {
    let internal = vec!["foo".to_owned()];
    let integrity = judge_with(
        &base_with_foo(),
        &head_with_registry_foo_same_version(),
        &internal,
    );
    assert!(integrity.has(check::CONFUSION), "{:?}", integrity.findings);
}

/// Through the whole gate: the lockfile gains a package from the public registry, the diff is
/// empty, so nothing is fetched, nothing is scanned, and two gates say NOT_APPLICABLE.
#[tokio::test]
async fn sc2_the_gate_scans_a_registry_copy_of_an_internal_member() {
    let world = World::new();
    world.tools.set(Script {
        metadata: metadata(&[("foo", "0.1.0", Some("MIT"), false)]),
        ..Script::default()
    });
    let ran = world
        .gate(
            &base_with_foo(),
            &head_with_registry_foo_same_version(),
            &StaticRegistry::new(),
            &[],
            false,
        )
        .await
        .expect("the gate runs");
    assert_ne!(
        ran.outcome(gate::ADVISORIES),
        GateOutcome::NotApplicable,
        "the dependency set did change: a package from crates.io came in"
    );
}

// ---------------------------------------------------------------------------------------------
// SC-3: "new" is decided by name across every source, so an internal name is never new
// ---------------------------------------------------------------------------------------------

/// `policies/security.yaml` says a dependency is new when its name is absent from the base
/// lockfile. The base lockfile holds the internal member `foo`, so a crates.io package called
/// `foo` is "not new", whatever version it has. Only `internal_names` stands in the way, and
/// that list is a configuration value of the composition root: it is not filled from the base
/// lockfile's own path packages.
#[test]
fn sc3_a_registry_package_named_like_an_internal_member_is_a_new_direct_dependency() {
    let integrity = judge(&base_with_foo(), &head_with_registry_foo_high_version());
    assert!(
        integrity.has_violation() || registry_package_named(&integrity, "foo").is_some(),
        "the registry package foo 9.9.9 came in and nobody was asked: {:?}",
        integrity.findings
    );
}

fn plan_with(integrity: Integrity, internal: &[String]) -> Plan {
    let popular = PopularNames::bundled().expect("the bundled list");
    let licenses = LicensePolicy::owner_approved();
    Plan::new(
        integrity,
        &RegistryTable::new(),
        &[],
        &Settings {
            dependency: &engine().dependency,
            licenses: &licenses,
            internal_names: internal,
            popular: &popular,
            now: now(),
            scope: scope(),
            policy_hash: &policy_hash(),
        },
    )
}

/// Control: when the operator lists the internal name, a higher version of it is still caught.
///
/// After the SC-3 fix the registry package `foo 9.9.9` is a *new direct dependency* whether or
/// not the operator listed the name (the base member `foo` is the project's own code, not a known
/// registry package), so it is no longer a `dependency-confusion` violation. It goes to a person,
/// and the policy engine flags the name as internal, which needs a security approver. What must
/// not happen is the old outcome: no finding and nobody asked.
#[test]
fn control_the_listed_internal_name_still_reaches_a_security_approver() {
    let internal = vec!["foo".to_owned()];
    let integrity = judge_with(
        &base_with_foo(),
        &head_with_registry_foo_high_version(),
        &internal,
    );
    assert!(
        integrity.has(check::CONFUSION) || registry_package_named(&integrity, "foo").is_some(),
        "{:?}",
        integrity.findings
    );
    let plan = plan_with(integrity, &internal);
    assert_eq!(plan.needs.len(), 1, "one person must decide");
    assert_eq!(plan.needs[0].designation, Designation::SecurityApprover);
    assert!(
        plan.needs[0]
            .flags
            .contains(&DependencyFlag::InternalNameCollision),
        "{:?}",
        plan.needs[0].flags
    );
}

/// SC-3 with no operator list at all: the name of a base member is internal by itself.
#[test]
fn the_name_of_a_base_member_is_internal_without_an_operator_list() {
    let integrity = judge(&base_with_foo(), &head_with_registry_foo_high_version());
    assert!(
        integrity.internal_names.contains(&"foo".to_owned()),
        "{:?}",
        integrity.internal_names
    );
    let plan = plan_with(integrity, &[]);
    assert_eq!(plan.needs.len(), 1);
    assert!(
        plan.needs[0]
            .flags
            .contains(&DependencyFlag::InternalNameCollision),
        "{:?}",
        plan.needs[0].flags
    );
}

/// A registry package with the name and version of a member is a collision with no person to ask.
#[test]
fn a_registry_twin_of_a_member_is_a_dependency_confusion_violation() {
    let integrity = judge(&base_with_foo(), &head_with_registry_foo_same_version());
    assert!(integrity.has(check::CONFUSION), "{:?}", integrity.findings);
}

/// The twin of a member added in the same change is caught the same way (the SC-1 shape).
#[test]
fn a_registry_twin_of_a_member_added_in_the_same_change_is_a_violation() {
    let integrity = judge(&base_without_members(), &head_with_twin_member());
    assert!(integrity.has(check::CONFUSION), "{:?}", integrity.findings);
}

/// A reference that names two packages is never resolved by guessing.
#[test]
fn a_reference_that_names_two_packages_is_a_finding_and_is_not_skipped() {
    // `app` lists `evil 0.1.0` with no source, and the lockfile holds two such packages.
    let head = files(&[
        ("Cargo.toml", workspace_with("evil")),
        (
            "app/Cargo.toml",
            manifest(
                "app",
                "[dependencies]\nevil_reg = { package = \"evil\", version = \"0.1.0\" }\n",
            ),
        ),
        ("evil/Cargo.toml", manifest("evil", "")),
        (
            "Cargo.lock",
            lock(&[
                member("app", &["evil 0.1.0"]),
                member("evil", &[]),
                reg("evil", "0.1.0", 'e'),
            ]),
        ),
    ]);
    let integrity = judge(&base_without_members(), &head);
    assert!(
        integrity.has(check::REFERENCE_AMBIGUOUS),
        "{:?}",
        integrity.findings
    );
}

/// A reference to a package that is not in the file is a finding too.
#[test]
fn a_reference_that_names_no_package_is_a_finding() {
    let head = files(&[
        ("Cargo.toml", manifest("app", "")),
        ("Cargo.lock", lock(&[member("app", &["ghost"])])),
    ]);
    let integrity = judge(&files(&[]), &head);
    assert!(
        integrity.has(check::REFERENCE_DANGLING),
        "{:?}",
        integrity.findings
    );
}
