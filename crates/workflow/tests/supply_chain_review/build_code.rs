//! Attack: build code arrives through something that is not a new direct dependency.
//!
//! `policies/security.yaml` (`gate_integrity.semantic_checks`) says `build_script_added` blocks
//! until a security review. The gate meets that for the closure of a **new direct dependency**
//! (`review::conclude` escalates to a security approver). Any other package that comes in with a
//! build script or a procedural macro (a new transitive crate pulled by a feature flag, or by a
//! changed manifest) only produces the warning `build-code-added`, and the review passes.

use factory_domain::vocabulary::GateOutcome;
use factory_workflow::gates::supply_chain::facts::StaticRegistry;
use factory_workflow::gates::supply_chain::report::gate;

use crate::files::{Files, base, files, lock, manifest, member, reg};
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
#[ignore = "confirmed defect SC-10: a new transitive package with a build script passes the review with a warning; the policy says build_script_added blocks until a security review"]
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
