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

// ---- the engine enforces the rule itself ----------------------------------------------------
//
// Until now the rule was enforced where the facts were computed, and a caller could write
// `policy_permits: true` by hand. The engine writes the gate and the code of each block into the
// event of the block, reads them back when an override comes in, and holds back a block that its
// configuration lists. The caller's facts can only narrow what the engine allows.

/// Facts as a caller who wants the stage to pass would write them: everything permitted.
fn claimed() -> OverrideFacts {
    OverrideFacts {
        policy_permits: true,
        security_class: true,
        mandatory_of_active_profile: false,
    }
}

/// A job whose intake stage run is blocked by these gates, with these codes.
async fn blocked_by(
    world: &World,
    blocks: &'static [(&'static str, &'static str)],
) -> (factory_domain::ids::JobId, factory_domain::ids::StageRunId) {
    let job = world.admitted_job().await;
    world
        .script(StageKind::Intake)
        .queue_evals([Eval::BlockedAt(blocks)]);
    world.run_next("worker-1").await;
    let view = world.view(job).await;
    assert_eq!(view.status, JobStatus::Blocked);
    let run = view.newest(StageKind::Intake).expect("run").id;
    (job, run)
}

async fn override_as(
    world: &World,
    job: factory_domain::ids::JobId,
    run: factory_domain::ids::StageRunId,
    facts: OverrideFacts,
) -> Result<(), EngineError> {
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
}

#[tokio::test]
async fn an_override_of_an_unresolved_dependency_review_is_refused_even_when_the_caller_claims_it_is_allowed()
 {
    let world = World::new().await;
    let (job, run) = blocked_by(&world, &[("dependency-review", "policy_unresolvable")]).await;
    // The block event holds the gate and the code, written by the engine.
    let blocked = world
        .events(job)
        .await
        .into_iter()
        .find(|event| event.event_type.as_str() == "stage_run.blocked")
        .expect("the engine wrote the block event");
    assert_eq!(
        blocked.payload["blocks"],
        serde_json::json!([{"gate": "dependency-review", "code": "policy_unresolvable"}])
    );
    let refused = override_as(&world, job, run, claimed()).await;
    match refused {
        Err(EngineError::GuardUnmet(failure)) => {
            assert!(
                failure
                    .to_string()
                    .contains("policy does not permit an override"),
                "{failure}"
            );
        }
        other => panic!("the engine accepted facts it was handed by hand: {other:?}"),
    }
    let view = world.view(job).await;
    assert_eq!(
        view.newest(StageKind::Intake).expect("run").status,
        StageRunStatus::Blocked
    );
}

#[tokio::test]
async fn an_ordinary_overridable_block_still_works_with_the_facts_the_policy_gives() {
    let world = World::new().await;
    let (job, run) = blocked_by(&world, &[("sbom", "tool_unavailable")]).await;
    override_as(&world, job, run, claimed())
        .await
        .expect("a block the engine does not hold back is overridden");
    let view = world.view(job).await;
    assert_eq!(
        view.newest(StageKind::Intake).expect("run").status,
        StageRunStatus::Passed
    );
}

#[tokio::test]
async fn one_block_the_engine_holds_back_holds_back_the_override_of_several() {
    let world = World::new().await;
    let (job, run) = blocked_by(
        &world,
        &[
            ("sbom", "tool_unavailable"),
            ("dependency-review", "policy_unresolvable"),
        ],
    )
    .await;
    let refused = override_as(&world, job, run, claimed()).await;
    assert!(
        matches!(refused, Err(EngineError::GuardUnmet(_))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn the_caller_can_only_narrow_what_the_engine_allows() {
    let world = World::new().await;
    let (job, run) = blocked_by(&world, &[("sbom", "tool_unavailable")]).await;
    let narrowed = OverrideFacts {
        policy_permits: false,
        ..claimed()
    };
    let refused = override_as(&world, job, run, narrowed).await;
    assert!(
        matches!(refused, Err(EngineError::GuardUnmet(_))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_block_the_configuration_adds_is_held_back_too_and_the_floor_stays() {
    // The composition root adds the entries of the policy file. The floor cannot be taken away
    // by adding: `with_non_overridable_blocks` only extends.
    let world = World::with_config(|config| {
        *config = config
            .clone()
            .with_non_overridable_blocks([("sbom".to_owned(), "tool_unavailable".to_owned())]);
    })
    .await;
    assert!(world.config.non_overridable_blocks.contains(&(
        "dependency-review".to_owned(),
        "policy_unresolvable".to_owned()
    )));
    let (job, run) = blocked_by(&world, &[("sbom", "tool_unavailable")]).await;
    let refused = override_as(&world, job, run, claimed()).await;
    assert!(
        matches!(refused, Err(EngineError::GuardUnmet(_))),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_block_that_comes_from_something_other_than_a_gate_is_overridden_as_before() {
    // The scripted intake blocks with a plain blocked report; the engine records the gate and the
    // code it carries, and nothing in the configuration holds that pair back.
    let world = World::new().await;
    let job = world.admitted_job().await;
    world.script(StageKind::Intake).queue_evals([Eval::Blocked]);
    world.run_next("worker-1").await;
    let run = world
        .view(job)
        .await
        .newest(StageKind::Intake)
        .expect("run")
        .id;
    override_as(&world, job, run, claimed())
        .await
        .expect("an ordinary block is overridden");
}
