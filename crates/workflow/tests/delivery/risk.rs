//! AUT-10: the risk tier and the separation-of-duties facts come from the diff and from every
//! raise, and nothing lowers them.
//!
//! The design says what the architect meant to touch. The diff says what was changed. The tier
//! shown to the approver is the highest of the two assessments and of the intake classifier's
//! claim.

use factory_domain::policy::risk::RiskFacts;
use factory_domain::vocabulary::RiskTier;
use factory_ports::paths::RepoPath;
use factory_ports::workspace::{ChangeKind, ChangedPath};
use factory_workflow::stages::delivery::risk::{
    LARGE_CHANGE_FILES, Reported, assess, from_diff, join_reported,
};

use crate::world::{Scenario, World};

fn changed(path: &str, kind: ChangeKind) -> ChangedPath {
    ChangedPath {
        path: RepoPath::new(path).expect("a path"),
        kind,
    }
}

fn ordinary() -> RiskFacts {
    RiskFacts {
        single_module_change_without_sensitive_or_protected_paths: true,
        ..RiskFacts::default()
    }
}

async fn delivered(scenario: Scenario) -> Reported {
    let world = World::with(scenario);
    let ran = world.run().await;
    Reported::from_json(&ran.result["risk"]).expect("the delivery result carries the risk")
}

// ---- the diff, through the whole stage ----------------------------------------------------------

/// The plan owns `src/lib.rs`, the design says an ordinary single-module change, and the diff adds
/// a build script. The design's tier would have been low.
#[tokio::test]
async fn aut_10_a_build_script_the_design_did_not_list_makes_the_change_high_risk() {
    let reported = delivered(Scenario {
        edited_path: "build.rs",
        ..Scenario::default()
    })
    .await;
    assert_eq!(reported.tier, RiskTier::High);
    assert!(reported.sensitive_file_change);
    assert!(!reported.protected_path_change);
}

#[tokio::test]
async fn aut_10_a_dependency_manifest_in_the_diff_is_a_new_dependency() {
    let reported = delivered(Scenario {
        edited_path: "Cargo.toml",
        ..Scenario::default()
    })
    .await;
    assert_eq!(reported.tier, RiskTier::High);
    assert!(reported.new_dependency);
    assert!(reported.sensitive_file_change);
}

#[tokio::test]
async fn aut_10_the_ordinary_diff_of_an_ordinary_design_stays_low() {
    let reported = delivered(Scenario::default()).await;
    assert_eq!(reported.tier, RiskTier::Low);
    assert!(!reported.sensitive_file_change);
    assert!(!reported.protected_path_change);
    assert!(!reported.new_dependency);
}

/// The classifier's claim is an agent's word. It raises the tier and the diff cannot undo it.
#[tokio::test]
async fn aut_10_the_intake_classifiers_raise_reaches_the_delivery() {
    let reported = delivered(Scenario {
        agent_claim: Some(RiskTier::Critical),
        ..Scenario::default()
    })
    .await;
    assert_eq!(reported.tier, RiskTier::Critical);
}

#[tokio::test]
async fn aut_10_a_low_claim_lowers_nothing() {
    let reported = delivered(Scenario {
        agent_claim: Some(RiskTier::Low),
        edited_path: "build.rs",
        ..Scenario::default()
    })
    .await;
    assert_eq!(reported.tier, RiskTier::High);
}

/// The design says a new dependency (high). A diff that touches one ordinary file does not make it
/// ordinary: the maximum is taken and nothing is lowered.
#[tokio::test]
async fn aut_10_an_ordinary_diff_does_not_lower_the_tier_the_design_showed() {
    let reported = delivered(Scenario {
        risk: RiskFacts {
            new_dependency: true,
            ..RiskFacts::default()
        },
        ..Scenario::default()
    })
    .await;
    assert_eq!(reported.tier, RiskTier::High);
    assert!(reported.new_dependency, "the design's flag is kept");
}

// ---- the measurement, on lists of paths ---------------------------------------------------------

#[test]
fn aut_10_a_protected_path_in_the_diff_is_critical_whatever_the_design_said() {
    let world = World::new();
    for path in [
        ".github/workflows/ci.yml",
        "CODEOWNERS",
        "clippy.toml",
        ".cargo/config.toml",
    ] {
        for kind in [ChangeKind::Added, ChangeKind::Modified, ChangeKind::Deleted] {
            let risk = assess(&world.policy, &ordinary(), None, &[changed(path, kind)]);
            assert_eq!(risk.assessment.tier, RiskTier::Critical, "{path} {kind:?}");
            assert!(risk.facts.protected_path_change, "{path} {kind:?}");
        }
    }
}

#[test]
fn aut_10_a_design_for_one_file_and_a_diff_of_another_takes_the_higher_tier() {
    let world = World::new();
    // The design lists only an ordinary file (the facts say low); the diff has that file and a
    // lockfile as well.
    let diff = [
        changed("src/lib.rs", ChangeKind::Modified),
        changed("Cargo.lock", ChangeKind::Modified),
    ];
    let risk = assess(&world.policy, &ordinary(), None, &diff);
    assert_eq!(risk.assessment.tier, RiskTier::High);
    assert!(risk.facts.new_dependency);
    assert!(risk.facts.sensitive_file_change);
    assert!(
        risk.assessment
            .matched
            .iter()
            .any(|criterion| criterion
                == "single_module_change_without_sensitive_or_protected_paths"),
        "what the design showed is kept"
    );
}

#[test]
fn aut_10_the_facts_of_the_diff_say_what_the_paths_are() {
    let world = World::new();
    let infra = from_diff(&world.policy, &[changed("Dockerfile", ChangeKind::Added)]);
    assert!(infra.infra_change && infra.sensitive_file_change);
    let docs = from_diff(
        &world.policy,
        &[changed("docs/guide.md", ChangeKind::Added)],
    );
    assert!(docs.docs_only && !docs.sensitive_file_change);
    let tests = from_diff(&world.policy, &[changed("tests/it.rs", ChangeKind::Added)]);
    assert!(tests.tests_only_new_files);
    let two = from_diff(
        &world.policy,
        &[
            changed("crates/a/src/lib.rs", ChangeKind::Modified),
            changed("crates/b/src/lib.rs", ChangeKind::Modified),
        ],
    );
    assert!(two.multi_module_change);
    assert!(!two.single_module_change_without_sensitive_or_protected_paths);
}

#[test]
fn aut_10_a_large_change_is_not_a_small_one() {
    let world = World::new();
    let many: Vec<ChangedPath> = (0..=LARGE_CHANGE_FILES)
        .map(|n| changed(&format!("src/f{n}.rs"), ChangeKind::Modified))
        .collect();
    let facts = from_diff(&world.policy, &many);
    assert!(facts.multi_module_change);
    assert_eq!(
        assess(&world.policy, &ordinary(), None, &many)
            .assessment
            .tier,
        RiskTier::Medium
    );
    let few = &many[..LARGE_CHANGE_FILES];
    assert!(!from_diff(&world.policy, few).multi_module_change);
}

/// The approval stage joins what the delivery measured with what it knows itself.
#[test]
fn aut_10_the_approval_joins_the_reported_risk_without_lowering_it() {
    let world = World::new();
    let reported = Reported {
        tier: RiskTier::Medium,
        protected_path_change: false,
        sensitive_file_change: true,
        new_dependency: false,
    };
    // The design is ordinary: the reported medium and the sensitive file stand.
    let joined = join_reported(&world.policy, &ordinary(), None, &reported);
    assert_eq!(joined.tier, RiskTier::Medium);
    assert!(joined.sensitive_file_change);
    // The design knows more than the report: its flag and the claim raise the result.
    let known = RiskFacts {
        new_dependency: true,
        ..RiskFacts::default()
    };
    let joined = join_reported(&world.policy, &known, Some(RiskTier::Critical), &reported);
    assert_eq!(joined.tier, RiskTier::Critical);
    assert!(joined.new_dependency && joined.sensitive_file_change);
    // A lower claim lowers nothing.
    let joined = join_reported(&world.policy, &ordinary(), Some(RiskTier::Low), &reported);
    assert_eq!(joined.tier, RiskTier::Medium);
}

#[test]
fn aut_10_a_delivery_result_without_the_risk_is_not_read() {
    assert_eq!(Reported::from_json(&serde_json::json!({})), None);
    assert_eq!(
        Reported::from_json(&serde_json::json!({ "tier": "bogus" })),
        None
    );
}
