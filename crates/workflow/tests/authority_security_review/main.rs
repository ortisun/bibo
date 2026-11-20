//! Security review of authority, approval, delivery and the evidence chain (2026-10-28).
//!
//! Tests named `aut_*` show a confirmed defect and are `#[ignore]`d, so the normal run stays
//! green. Tests named `held_*` pin what the review attacked and found sound; they run normally.
//!
//! One defect:  `cargo test -p factory-workflow --test authority_security_review --locked -- --ignored <name> --exact`
//! All defects: `cargo test -p factory-workflow --test authority_security_review --locked -- --ignored aut_`
//! All probes:  `cargo test -p factory-workflow --test authority_security_review --locked held_`

#[path = "../support/mod.rs"]
mod support;

mod approval_rig;
mod gates;

use factory_domain::state::StageRunStatus;
use factory_domain::vocabulary::HumanRole;
use factory_workflow::commands::{Decision, Subject};
use factory_workflow::engine::EngineError;
use support::World;

// ---- AUT-3 ------------------------------------------------------------------------------------

/// FIXED (AUT-3). The policy gives the critical tier to `security_approver` alone
/// (`policies/approval.yaml` `risk_tiers[critical].approver_roles`), but the engine asked for
/// `HumanRole::Approver` when the last of them approved (`engine/decide.rs`, the
/// `principal_holds_required_role` fact), and a person who held exactly the designation the policy
/// names could not complete the tier. The engine now accepts either approving role.
#[tokio::test]
async fn aut_3_a_person_with_only_the_security_approver_role_can_complete_an_approval() {
    let world = World::new().await;
    let (job, run) = world.at_approval().await;
    let security = world
        .person("security-only", &[HumanRole::SecurityApprover])
        .await;
    let seen = world.head(job).await;
    let result = world
        .engine
        .decide(
            &world.actor(security),
            Subject {
                job,
                stage_run: run,
            },
            Decision::Approve {
                evidence_seen: seen,
                warnings_decided: true,
                proof: None,
            },
        )
        .await;
    assert_eq!(
        result,
        Ok(()),
        "the policy's critical tier names this role and no other, so the engine must accept it"
    );
}

/// The same fact the other way round: with the role `Approver` alone, the engine accepts the
/// decision. This is what lets the critical tier pass today, and it is why the tests of the
/// service give the security approvers both roles.
#[tokio::test]
async fn held_aut_3_the_approver_role_is_what_the_engine_asks_for() {
    let world = World::new().await;
    let (job, run) = world.at_approval().await;
    let approver = world.person("approver-only", &[HumanRole::Approver]).await;
    let seen = world.head(job).await;
    world
        .engine
        .decide(
            &world.actor(approver),
            Subject {
                job,
                stage_run: run,
            },
            Decision::Approve {
                evidence_seen: seen,
                warnings_decided: true,
                proof: None,
            },
        )
        .await
        .expect("an approver other than the requester may approve");
    assert_eq!(
        world.stage_run(run).await.status,
        StageRunStatus::Passed,
        "the stage run passed"
    );
}

/// Nobody approves their own request, whatever the tier (the engine is stricter than the policy,
/// which lets a requester approve a low-risk change).
#[tokio::test]
async fn held_the_engine_refuses_the_requester_as_approver() {
    let world = World::new().await;
    let (job, run) = world.at_approval().await;
    let requester = world.requester;
    world.authority.grant(requester, &[HumanRole::Approver]);
    let seen = world.head(job).await;
    let result = world
        .engine
        .decide(
            &world.actor(requester),
            Subject {
                job,
                stage_run: run,
            },
            Decision::Approve {
                evidence_seen: seen,
                warnings_decided: true,
                proof: None,
            },
        )
        .await;
    assert!(
        matches!(result, Err(EngineError::NotAuthorized(_))),
        "{result:?}"
    );
}
