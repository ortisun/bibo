//! The override of a blocked stage run and `gate_integrity.non_overridable_blocks`.
//!
//! The policy lists blocks that no override may pass, and the engine's guard `G_OVERRIDE_PERMITTED`
//! reads one fact, `policy_permits`, from the caller. The fix computes that fact from the policy
//! (`OverrideFacts::from_policy`, `for_reports`) and says "the rule is enforced where the facts are
//! computed". These tests try the caller that does not compute them.

use factory_domain::policy::{ApprovalPolicy, PolicyEngine, SecurityPolicy};
use factory_domain::state::{JobStatus, StageRunStatus};
use factory_domain::values::HumanText;
use factory_domain::vocabulary::{HumanRole, StageKind};
use factory_workflow::commands::{Decision, OverrideFacts, Subject};
use factory_workflow::engine::EngineError;

use crate::support::{Eval, World};

const SECURITY: &str = include_str!("../../../domain/tests/fixtures/policy/security.json");
const APPROVAL: &str = include_str!("../../../domain/tests/fixtures/policy/approval.json");

fn policy() -> PolicyEngine {
    let security: SecurityPolicy = serde_json::from_str(SECURITY).expect("the security policy");
    let approval: ApprovalPolicy = serde_json::from_str(APPROVAL).expect("the approval policy");
    PolicyEngine::new(&security, &approval).expect("a policy engine")
}

fn justification() -> HumanText {
    HumanText::parse("The package looks fine to me and I would like the stage to pass.")
        .expect("a text")
}

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

/// Control: facts computed from the policy for the unresolved dependency review are refused for a
/// security approver, and facts the policy allows are accepted. This is what the fix shows.
#[tokio::test]
async fn held_facts_made_from_the_policy_hold_the_override_back() {
    let policy = policy();
    let held = OverrideFacts::from_policy(
        &policy.authority,
        &[("dependency-review", "policy_unresolvable")],
        true,
        false,
    );
    assert!(!held.policy_permits);
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
                facts: held,
            },
        )
        .await;
    assert!(
        matches!(refused, Err(EngineError::GuardUnmet(_))),
        "{refused:?}"
    );
}

/// RR-18. The engine takes the facts from the caller and does not look at the block it is asked to
/// override. Facts that name another gate and code (here a block the policy does allow to be
/// overridden), or a hand-written `policy_permits: true`, pass a run that is blocked by a pair the
/// policy lists as never overridable. The engine's own block event records the cause `gate-blocked`
/// and not the gate or the code, so it has nothing to compare the facts with.
///
/// Today no channel carries an override (the hook and the API have no such verb), so nobody can reach
/// this from outside; the first override verb to be wired turns it into an approval of what the policy
/// forbids, by whoever computes the facts wrongly. The test uses an intake run because the rig blocks
/// no other stage with a code; the point is that the facts and the block are not compared, and a
/// dependency review is blocked by the same event.
#[tokio::test]
#[ignore = "confirmed defect RR-18: the engine accepts override facts that are not about the block it overrides; cargo test -p factory-workflow --test security_rereview --locked -- --ignored rr_18 --exact"]
async fn rr_18_the_engine_does_not_take_the_word_of_the_caller_about_which_block_is_overridden() {
    let policy = policy();
    let world = World::new().await;
    let (job, run) = blocked_job(&world).await;
    let security = world
        .person("security-1", &[HumanRole::SecurityApprover])
        .await;
    // The facts the policy would give for a block it allows to be overridden, and the same facts
    // written by hand: neither is about the block that stopped this run.
    let about_another_block = OverrideFacts::from_policy(
        &policy.authority,
        &[("sbom", "tool_unavailable")],
        true,
        false,
    );
    let by_hand = OverrideFacts {
        policy_permits: true,
        security_class: true,
        mandatory_of_active_profile: false,
    };
    for (name, facts) in [("another block", about_another_block), ("by hand", by_hand)] {
        let result = world
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
        let view = world.view(job).await;
        let status = view.newest(StageKind::Intake).expect("run").status;
        assert!(
            result.is_err() && status == StageRunStatus::Blocked,
            "facts about {name} passed the run: {result:?}, the run is now {status:?}"
        );
        if status != StageRunStatus::Blocked {
            break;
        }
    }
}
