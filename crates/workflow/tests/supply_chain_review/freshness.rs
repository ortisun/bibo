//! Attack: a stale advisory database makes the audit say "clean".
//!
//! The gate runs `cargo audit --json --no-fetch` in a sandbox with no network, so the database
//! must already be in the image. With `--no-fetch`, cargo-audit 0.22.2 does not check how old the
//! database is, and prints `"last-commit":null,"last-updated":null`. Reproduced offline: a scratch
//! database whose only commit is dated 2025-01-01 (twenty-two months before the review date)
//! gave exit code 0 and `"vulnerabilities":{"found":false,...}` for a lockfile with no advisory
//! match, and no warning. `deny.toml` sets `maximum-db-staleness = "P7D"` for the factory's own
//! CI and says a stale copy is BLOCKED; the supply chain gate has no equivalent and the parser
//! (`tools::parse_audit`) does not read the `database` object at all.
//!
//! The scripted audit of the builder's harness prints `"database":{}`, which carries no age
//! either. A pass that has no evidence of the age of its database is a pass on an unknown.

use factory_domain::vocabulary::GateOutcome;
use factory_workflow::gates::supply_chain::facts::StaticRegistry;
use factory_workflow::gates::supply_chain::report::gate;

use crate::files::{Files, base, files, lock, manifest, member, reg};
use crate::world::{Script, World, metadata};

/// The candidate moves `serde` to a later version in the same series. The manifest is the same
/// as the base commit's, so no person is asked about a new dependency.
pub fn head_upgrading_serde() -> Files {
    files(&[
        (
            "Cargo.toml",
            manifest("app", "[dependencies]\nserde = \"1\"\n"),
        ),
        (
            "Cargo.lock",
            lock(&[
                member("app", &["serde"]),
                reg("serde", "1.0.101", 'c').with_deps(&["serde_derive"]),
                reg("serde_derive", "1.0.100", 'b'),
            ]),
        ),
    ])
}

#[tokio::test]
#[ignore = "confirmed defect SC-6: the advisories gate passes on an audit that gives no evidence of the age of the advisory database"]
async fn sc6_an_audit_with_no_evidence_of_the_database_age_is_not_a_pass() {
    let world = World::new();
    world.tools.set(Script {
        metadata: metadata(&[("serde", "1.0.101", Some("MIT OR Apache-2.0"), false)]),
        ..Script::default()
    });
    let ran = world
        .gate(
            &base(),
            &head_upgrading_serde(),
            &StaticRegistry::new(),
            &[],
            false,
        )
        .await
        .expect("the gate runs");

    // What holds today: the change is judged, fetched and scanned.
    assert_eq!(ran.outcome(gate::INTEGRITY), GateOutcome::Passed);
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Passed);
    assert!(ran.done.scanned, "the audit ran");

    // What must hold: a clean audit that cannot say how old its database is is BLOCKED.
    assert_eq!(
        ran.outcome(gate::ADVISORIES),
        GateOutcome::Blocked,
        "PASSED although the audit gave no date for its advisory database"
    );
}
