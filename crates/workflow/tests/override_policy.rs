//! An override of a blocked stage run, with the facts computed from the policy, through the real
//! engine over the in-memory store.
//!
//! The engine evaluates guard `G_OVERRIDE_PERMITTED` from the facts it is handed. These tests hand
//! it facts made by `OverrideFacts::from_policy`, so the answer is the policy's: there is no
//! override for the block `dependency-review` with the code `policy_unresolvable`, however senior
//! the person is and however good the reason, and an override of another block that policy allows
//! still works. The same rule through the validation stage's own reports is in
//! `tests/validation/supply.rs`.

mod support;

use factory_domain::policy::{ApprovalPolicy, PolicyEngine, SecurityPolicy};
use factory_domain::state::{JobStatus, StageRunStatus};
use factory_domain::values::HumanText;
use factory_domain::vocabulary::{HumanRole, StageKind};
use factory_workflow::commands::{Decision, OverrideFacts, Subject};
use factory_workflow::engine::EngineError;
use support::{Eval, World};

const SECURITY: &str = include_str!("../../domain/tests/fixtures/policy/security.json");
const APPROVAL: &str = include_str!("../../domain/tests/fixtures/policy/approval.json");

fn policy() -> PolicyEngine {
    let security: SecurityPolicy = serde_json::from_str(SECURITY).expect("the security policy");
    let approval: ApprovalPolicy = serde_json::from_str(APPROVAL).expect("the approval policy");
    PolicyEngine::new(&security, &approval).expect("a policy engine")
}

fn justification() -> HumanText {
    HumanText::parse("The package looks fine to me and I would like the stage to pass.")
        .expect("a text")
}

/// A job whose intake stage run is blocked.
async fn blocked_job(
    world: &World,
) -> (factory_domain::ids::JobId, factory_domain::ids::StageRunId) {
    let job = world.admitted_job().await;
    world.script(StageKind::Intake).queue_evals([Eval::Blocked]);
    world.run_next("worker-1").await;
    let view = world.view(job).await;
    assert_eq!(view.status, JobStatus::Blocked);
    let run = view.newest(StageKind::Intake).expect("run").id;
    (job, run)
}

#[tokio::test]
async fn an_override_of_a_dependency_review_that_waits_for_a_decision_is_refused_for_everyone() {
    let policy = policy();
    let facts = OverrideFacts::from_policy(
        &policy.authority,
        &[("dependency-review", "policy_unresolvable")],
        true,
        false,
    );
    assert!(!facts.policy_permits);

    let world = World::new().await;
    let (job, run) = blocked_job(&world).await;
    // The person who may waive other security blocks, and one who may waive ordinary ones.
    let security = world
        .person("security-1", &[HumanRole::SecurityApprover])
        .await;
    let org_admin = world.person("admin-1", &[HumanRole::OrgAdmin]).await;
    let approver = world.person("approver-1", &[HumanRole::Approver]).await;
    for who in [security, org_admin, approver] {
        let refused = world
            .engine
            .decide(
                &world.actor(who),
                Subject {
                    job,
                    stage_run: run,
                },
                Decision::Override {
                    justification: justification(),
                    facts,
                },
            )
            .await;
        assert!(
            matches!(
                refused,
                Err(EngineError::GuardUnmet(_) | EngineError::NotAuthorized(_))
            ),
            "{refused:?}"
        );
    }
    // Nothing moved: the run is still blocked, waiting for the decision to be recorded.
    let view = world.view(job).await;
    assert_eq!(view.status, JobStatus::Blocked);
    let state = view.newest(StageKind::Intake).expect("run").status;
    assert_eq!(state, StageRunStatus::Blocked);
}

#[tokio::test]
async fn the_guard_itself_says_so_for_the_person_who_holds_the_role() {
    // The security approver holds the role a security-class override needs, so what holds the
    // override back is the policy fact and nothing else.
    let policy = policy();
    let facts = OverrideFacts::from_policy(
        &policy.authority,
        &[("dependency-review", "policy_unresolvable")],
        true,
        false,
    );
    let world = World::new().await;
    let (job, run) = blocked_job(&world).await;
    let security = world
        .person("security-1", &[HumanRole::SecurityApprover])
        .await;
    let refused = world
        .engine
        .decide(
            &world.actor(security),
            Subject {
                job,
                stage_run: run,
            },
            Decision::Override {
                justification: justification(),
                facts,
            },
        )
        .await;
    match refused {
        Err(EngineError::GuardUnmet(failure)) => {
            let text = failure.to_string();
            assert!(
                text.contains("policy does not permit an override"),
                "{text}"
            );
        }
        other => panic!("expected the guard to hold the override back, got {other:?}"),
    }
}

#[tokio::test]
async fn an_override_of_a_block_the_policy_allows_still_passes_the_stage() {
    // The control: the rule is the pair (gate, code), not every block.
    let policy = policy();
    let facts = OverrideFacts::from_policy(
        &policy.authority,
        &[("sbom", "tool_unavailable")],
        true,
        false,
    );
    assert!(facts.policy_permits);

    let world = World::new().await;
    let (job, run) = blocked_job(&world).await;
    let security = world
        .person("security-1", &[HumanRole::SecurityApprover])
        .await;
    world
        .engine
        .decide(
            &world.actor(security),
            Subject {
                job,
                stage_run: run,
            },
            Decision::Override {
                justification: justification(),
                facts,
            },
        )
        .await
        .expect("the override of an allowed block applies");
    let view = world.view(job).await;
    assert_eq!(
        view.newest(StageKind::Intake).expect("run").status,
        StageRunStatus::Passed
    );
}

#[tokio::test]
async fn facts_with_no_known_block_never_permit_an_override() {
    let policy = policy();
    assert!(!OverrideFacts::from_policy(&policy.authority, &[], true, false).policy_permits);
    // One allowed block and one that is held back: the stage run stays blocked.
    assert!(
        !OverrideFacts::from_policy(
            &policy.authority,
            &[
                ("sbom", "tool_unavailable"),
                ("dependency-review", "policy_unresolvable")
            ],
            true,
            false
        )
        .policy_permits
    );
}
