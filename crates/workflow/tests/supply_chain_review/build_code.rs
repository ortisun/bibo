//! Attack: build code arrives through something that is not a new direct dependency.
//!
//! `policies/security.yaml` (`gate_integrity.semantic_checks`) says `build_script_added` blocks
//! until a security review. The gate meets that for the closure of a **new direct dependency**
//! (`review::conclude` escalates to a security approver). Any other package that comes in with a
//! build script or a procedural macro (a new transitive crate pulled by a feature flag, or by a
//! changed manifest) only produces the warning `build-code-added`, and the review passes.

use factory_domain::policy::decision::Designation;
use factory_domain::vocabulary::GateOutcome;
use factory_workflow::gates::supply_chain::approval::{DependencyApproval, Subject};
use factory_workflow::gates::supply_chain::facts::StaticRegistry;
use factory_workflow::gates::supply_chain::report::gate;

use crate::files::{Files, base, files, lock, manifest, member, reg, sum};
use crate::people::{APPROVER, SECURITY, approve};
use crate::world::{Script, World, metadata};

/// The candidate turns on a feature of `serde`. The feature pulls a crate that the base lockfile
/// does not hold. `app` does not depend on it, `serde` does, so it is not a direct dependency.
fn head_with_a_new_transitive_crate() -> Files {
    files(&[
        (
            "Cargo.toml",
            manifest(
                "app",
                "[dependencies]\nserde = { version = \"1\", features = [\"extra\"] }\n",
            ),
        ),
        (
            "Cargo.lock",
            lock(&[
                member("app", &["serde"]),
                reg("serde", "1.0.100", 'a').with_deps(&["serde_derive", "helper"]),
                reg("serde_derive", "1.0.100", 'b'),
                reg("helper", "0.1.0", 'c'),
            ]),
        ),
    ])
}

#[tokio::test]
async fn sc10_a_new_transitive_package_with_a_build_script_blocks_until_a_security_review() {
    let world = World::new();
    world.tools.set(Script {
        metadata: metadata(&[("helper", "0.1.0", Some("MIT"), true)]),
        ..Script::default()
    });
    let ran = world
        .gate(
            &base(),
            &head_with_a_new_transitive_crate(),
            &StaticRegistry::new(),
            &[],
            false,
        )
        .await
        .expect("the gate runs");
    assert_eq!(ran.outcome(gate::INTEGRITY), GateOutcome::Passed);
    assert_ne!(
        ran.outcome(gate::REVIEW),
        GateOutcome::Passed,
        "build code came in with no person looking at it; the gate only warned: {:?}",
        ran.warning_checks(gate::REVIEW)
    );
}

fn helper() -> Subject {
    Subject {
        name: "helper".to_owned(),
        version: "0.1.0".to_owned(),
        checksum: sum('c'),
    }
}

async fn review_with(approvals: &[DependencyApproval]) -> crate::world::Ran {
    let world = World::new();
    world.tools.set(Script {
        metadata: metadata(&[("helper", "0.1.0", Some("MIT"), true)]),
        ..Script::default()
    });
    world
        .gate(
            &base(),
            &head_with_a_new_transitive_crate(),
            &StaticRegistry::new(),
            approvals,
            false,
        )
        .await
        .expect("the gate runs")
}

/// What the person sees: the review is blocked, the missing item names the package and says that
/// a security approver must decide, and the evidence carries the subject to decide on.
#[tokio::test]
async fn sc10_the_block_names_the_package_and_the_designation_that_lifts_it() {
    let ran = review_with(&[]).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);
    let missing = ran.missing(gate::REVIEW);
    assert!(
        missing.contains("security approver") && missing.contains("helper 0.1.0"),
        "{missing}"
    );
    let evidence = ran.done.evidence.as_ref().expect("evidence");
    let awaiting = &evidence["build_code_awaiting_a_security_approver"];
    assert_eq!(awaiting[0]["name"], "helper");
    assert_eq!(awaiting[0]["version"], "0.1.0");
    assert_eq!(awaiting[0]["checksum"], sum('c'));
    assert_eq!(awaiting[0]["needs"], "security_approver");
    // The audit did not run, because the review is not clean.
    assert!(!ran.done.scanned);
}

/// A decision of a security approver on exactly that package lifts the block, and a decision of
/// an ordinary approver does not.
#[tokio::test]
async fn sc10_only_a_security_approver_on_the_exact_package_lifts_the_block() {
    let ordinary = approve(APPROVER, "bob", Designation::Approver, &helper()).expect("recorded");
    let ran = review_with(&[ordinary]).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);

    let other_version = Subject {
        version: "0.1.1".to_owned(),
        ..helper()
    };
    let wrong = approve(
        SECURITY,
        "sam",
        Designation::SecurityApprover,
        &other_version,
    )
    .expect("recorded");
    let ran = review_with(&[wrong]).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);

    let right =
        approve(SECURITY, "sam", Designation::SecurityApprover, &helper()).expect("recorded");
    let ran = review_with(&[right]).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Passed);
    assert!(ran.done.scanned, "now the audit runs");
}
