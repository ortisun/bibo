//! Attack: build code arrives through something that is not a new direct dependency.
//!
//! `policies/security.yaml` (`gate_integrity.semantic_checks`) says `build_script_added` blocks
//! until a security review. The gate meets that for the closure of a **new direct dependency**
//! (`review::conclude` escalates to a security approver). Any other package that comes in with a
//! build script or a procedural macro (a new transitive crate pulled by a feature flag, or by a
//! changed manifest) only produces the warning `build-code-added`, and the review passes.

use factory_domain::policy::authority::{ActionDenialReason, ActionVerdict};
use factory_domain::policy::decision::Designation;
use factory_domain::vocabulary::GateOutcome;
use factory_workflow::gates::supply_chain::approval::{ApprovalKind, DependencyApproval, Subject};
use factory_workflow::gates::supply_chain::facts::StaticRegistry;
use factory_workflow::gates::supply_chain::report::gate;

use crate::files::{Files, base, files, lock, manifest, member, reg, sum};
use crate::people::{
    APPROVER, REQUESTER, SECURITY, approve, approve_build_code, authorized, decide,
    decide_build_code, human, policy_hash, scope,
};
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
    let awaiting = &evidence["build_code_awaiting_a_decision"];
    assert_eq!(awaiting[0]["name"], "helper");
    assert_eq!(awaiting[0]["version"], "0.1.0");
    assert_eq!(awaiting[0]["checksum"], sum('c'));
    // The action and the designation are what the policy row says; the gate writes neither.
    assert_eq!(awaiting[0]["action"], "approve_build_code");
    assert_eq!(awaiting[0]["needs"], "security_approver");
    // The audit did not run, because the review is not clean.
    assert!(!ran.done.scanned);
}

/// A decision `approve_build_code` of a security approver on exactly that package lifts the
/// block. A decision of another action does not, and the policy engine gives no ordinary approver
/// a proof for this one.
#[tokio::test]
async fn sc10_only_a_build_code_decision_on_the_exact_package_lifts_the_block() {
    // An ordinary approver has no proof for the action: the engine refuses before any record.
    let ordinary = decide_build_code(&human(APPROVER, "bob"), Some(REQUESTER));
    assert!(
        matches!(&ordinary, ActionVerdict::Denied(d) if matches!(d.reason, ActionDenialReason::MissingDesignation { .. })),
        "{ordinary:?}"
    );

    // The decision on the dependency, even by a security approver, is not a decision on its code.
    let as_a_dependency =
        approve(SECURITY, "sam", Designation::SecurityApprover, &helper()).expect("recorded");
    assert_eq!(as_a_dependency.kind, ApprovalKind::NewDependency);
    let ran = review_with(&[as_a_dependency]).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);

    let other_version = Subject {
        version: "0.1.1".to_owned(),
        ..helper()
    };
    let wrong = approve_build_code(SECURITY, "sam", &other_version).expect("recorded");
    let ran = review_with(&[wrong]).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);

    let other_checksum = Subject {
        checksum: sum('f'),
        ..helper()
    };
    let wrong = approve_build_code(SECURITY, "sam", &other_checksum).expect("recorded");
    let ran = review_with(&[wrong]).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Blocked);

    let right = approve_build_code(SECURITY, "sam", &helper()).expect("recorded");
    assert_eq!(right.kind, ApprovalKind::BuildCode);
    let ran = review_with(&[right]).await;
    assert_eq!(ran.outcome(gate::REVIEW), GateOutcome::Passed);
    assert!(ran.done.scanned, "now the audit runs");
}

/// The proof must come from the policy engine and the record must say which action it was. A
/// record that names the build-code action by hand, in the shape of the ledger evidence, is read
/// back as the same kind and nothing else.
#[test]
fn sc10_the_kind_of_a_decision_survives_the_ledger_form_and_an_unknown_action_is_refused() {
    let right = approve_build_code(SECURITY, "sam", &helper()).expect("recorded");
    let json = right.to_json();
    assert_eq!(json["action"], "approve_build_code");
    assert_eq!(DependencyApproval::from_json(&json), Some(right));

    let mut other = json.clone();
    other["action"] = "approve_pr".into();
    assert_eq!(DependencyApproval::from_json(&other), None);
    let mut hand_written = json;
    hand_written["action"] = "add_new_direct_dependency".into();
    let read = DependencyApproval::from_json(&hand_written).expect("a dependency record");
    assert_eq!(read.kind, ApprovalKind::NewDependency);
}

/// A person who may approve the dependency may not approve its build code merely by holding the
/// designation of another row, and the proof of one action is not the proof of the other.
#[test]
fn sc10_a_proof_of_one_action_is_not_a_proof_of_the_other() {
    let dependency_proof = authorized(decide(
        &human(SECURITY, "sam"),
        Designation::SecurityApprover,
        Some(REQUESTER),
    ));
    let recorded = DependencyApproval::record(
        &dependency_proof,
        helper(),
        policy_hash(),
        scope(),
        "Reviewed the package, its maintainers and its license.",
    )
    .expect("recorded");
    assert_eq!(recorded.kind, ApprovalKind::NewDependency);
    let code_proof = authorized(decide_build_code(&human(SECURITY, "sam"), Some(REQUESTER)));
    assert_eq!(code_proof.action(), "approve_build_code");
    let recorded = DependencyApproval::record(
        &code_proof,
        helper(),
        policy_hash(),
        scope(),
        "Read the build script and the macro; they do only what the crate says.",
    )
    .expect("recorded");
    assert_eq!(recorded.kind, ApprovalKind::BuildCode);
    // The requester of the job, even with the designation, is refused for the code too.
    let own = decide_build_code(&human(SECURITY, "sam"), Some(SECURITY));
    assert!(
        matches!(&own, ActionVerdict::Denied(d) if d.reason == ActionDenialReason::SelfApproval),
        "{own:?}"
    );
}
