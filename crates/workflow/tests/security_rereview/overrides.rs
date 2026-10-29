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

/// RR-18 (closed by the engine-held facts of commit 6809ddd, which the first version of this test
/// predates). The engine used to take the facts from the caller and not look at the block it was
/// asked to override: facts that named another gate and code, or a hand-written `policy_permits:
/// true`, passed a run that is blocked by a pair the policy lists as never overridable. The engine
/// now writes the gate and the code of each block into its own block event, reads them back, and
/// compares them with its own list, so the facts of the caller can only narrow the answer.
///
/// The first version of this test blocked the intake run with a plain `Eval::Blocked`, whose pair is
/// not on the list, and so expected a refusal that was never due: the override of a block the policy
/// allows still passes (`overrides::held_an_override_of_a_block_the_policy_allows_still_passes`). The
/// run here is blocked by the pair the engine holds back, and the facts are the ones that name
/// another block and the ones written by hand.
#[tokio::test]
async fn rr_18_the_engine_does_not_take_the_word_of_the_caller_about_which_block_is_overridden() {
    let policy = policy();
    let world = World::new().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .queue_evals([Eval::BlockedAt(&[(
            "dependency-review",
            "policy_unresolvable",
        )])]);
    world.run_next("worker-1").await;
    let view = world.view(job).await;
    assert_eq!(view.status, JobStatus::Blocked);
    let run = view.newest(StageKind::Intake).expect("run").id;
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
            matches!(result, Err(EngineError::GuardUnmet(_))) && status == StageRunStatus::Blocked,
            "facts about {name} passed the run: {result:?}, the run is now {status:?}"
        );
    }
}

/// Control: a run blocked by a pair the policy allows is still overridden, with facts made for it.
#[tokio::test]
async fn held_an_override_of_a_block_the_policy_allows_still_passes() {
    let policy = policy();
    let world = World::new().await;
    let job = world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .queue_evals([Eval::BlockedAt(&[("sbom", "tool_unavailable")])]);
    world.run_next("worker-1").await;
    let view = world.view(job).await;
    let run = view.newest(StageKind::Intake).expect("run").id;
    let security = world
        .person("security-1", &[HumanRole::SecurityApprover])
        .await;
    let facts = OverrideFacts::from_policy(
        &policy.authority,
        &[("sbom", "tool_unavailable")],
        true,
        false,
    );
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
        .expect("the override of a block the policy allows passes");
    let view = world.view(job).await;
    assert_eq!(
        view.newest(StageKind::Intake).expect("run").status,
        StageRunStatus::Passed
    );
}
