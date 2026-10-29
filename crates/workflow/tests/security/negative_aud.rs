//! NT-AUD-03: audit coverage.
//!
//! One scripted scenario for each audit event type that `policies/security.yaml` requires
//! (`audit.must_record`). Every record the scenario writes must name its actor, the hash of the
//! policy in force and the correlation id of its job, and every type must have an owner in the
//! matrix of `docs/security/p0-coverage.md`.
//!
//! The scenario is the one of `tests/audit.rs`, which proves the engine part, with two additions
//! that the catalog asks for: the actor is checked, and the matrix is bound to the scenario. The
//! scenario has the engine write the types the engine writes: besides the ones it always wrote,
//! the sandbox lifecycle and each command the factory ran (from the sandbox the stage used) and
//! the model requests the broker metered (from the token's usage at the end of the attempt). The
//! types that a stage handler or the API write are noted by a scripted handler or checked in the
//! composed run, because those components are not in this crate. The matrix says, for each type,
//! who writes it in production code, and the tests fail when a type has no correct producer or
//! when the matrix and the scenario disagree about who writes it.

use std::collections::BTreeSet;

use factory_domain::values::HumanText;
use factory_domain::vocabulary::{HumanRole, StageKind};
use factory_ports::store::AuditActor;
use factory_testkit::agent::AdversarialScript;
use factory_workflow::audit::{AuditAction, AuditDecision, AuditKind};
use factory_workflow::commands::{Decision, OverrideFacts, Subject};
use serde_json::json;

use crate::audit_matrix::{self, Production};
use crate::support::{Eval, World};

/// The types that the scenario cannot make the engine write, because another component does: the
/// stage handlers that scan a change, and the API that receives the webhook.
const SCRIPTED: [AuditKind; 3] = [
    AuditKind::SecretRedactedOrBlocked,
    AuditKind::ProtectedPathDecision,
    AuditKind::WebhookAcceptedOrRejected,
];

/// Runs the scenario and returns every audit record of its two jobs with the data to check them.
async fn scenario() -> (World, Vec<factory_ports::store::AuditRecord>) {
    let world = World::new().await;
    let noted = |kind| AuditAction::new(kind, AuditDecision::Noted);

    // Job one: an agent stage runs in a sandbox, runs two commands there, spends 80 percent of its
    // ceiling and has a tool call denied; a handler notes what only a handler sees. The job runs
    // to the approval, which a person grants.
    world.script(StageKind::Intake).agent_spending(2_000_000);
    world.script(StageKind::Intake).runs_an_agent();
    world.runtime.queue(
        AdversarialScript::returning(json!({}))
            .then_exec(&["echo", "first"])
            .then_exec(&["false"]),
    );
    world.script(StageKind::Intake).denials(1);
    world.script(StageKind::Intake).notes(&SCRIPTED.map(noted));
    let (first, run) = world.at_approval().await;
    world.approve(first, run).await;

    // Job two: a block that a person overrides.
    world.script(StageKind::Intake).agent_spending(0);
    world.script(StageKind::Intake).with(|s| {
        s.agent = false;
        s.run_agent = false;
    });
    world.script(StageKind::Intake).notes(&[]);
    world.script(StageKind::Intake).denials(0);
    world.script(StageKind::Intake).queue_evals([Eval::Blocked]);
    let second = world.admitted_job().await;
    world.advance(400);
    world.run_next("worker-1").await;
    let blocked = world
        .view(second)
        .await
        .newest(StageKind::Intake)
        .expect("run")
        .id;
    let approver = world.person("approver-y", &[HumanRole::Approver]).await;
    world
        .engine
        .decide(
            &world.actor(approver),
            Subject {
                job: second,
                stage_run: blocked,
            },
            Decision::Override {
                justification: HumanText::parse(
                    "The scanner is missing here and the risk is accepted.",
                )
                .expect("a text"),
                facts: OverrideFacts {
                    policy_permits: true,
                    security_class: false,
                    mandatory_of_active_profile: false,
                },
            },
        )
        .await
        .expect("the override applies");

    let mut records = Vec::new();
    for job in [first, second] {
        let correlation = world.events(job).await[0].correlation_id;
        for record in world.audit(job).await {
            assert_eq!(
                record.event.correlation_id, correlation,
                "{}",
                record.event.action
            );
            records.push(record);
        }
    }
    (world, records)
}

/// Every type appears, and no record lacks its actor, its policy hash or its correlation id.
#[tokio::test]
async fn negative_nt_aud_03_every_required_event_type_appears_with_actor_policy_hash_and_correlation_id()
 {
    let (world, records) = scenario().await;
    assert!(records.len() >= 20, "{} records", records.len());
    let mut seen: BTreeSet<AuditKind> = BTreeSet::new();
    for record in &records {
        let action = record.event.action.as_str();
        // The actor is one of the four kinds the port knows, and a component names itself.
        match &record.event.actor {
            AuditActor::System(label) => assert!(!label.as_str().is_empty(), "{action}"),
            AuditActor::Human(_) | AuditActor::Service(_) => {}
            AuditActor::Anonymous(_) => panic!("{action} has no identified actor"),
        }
        // The policy that was in force, as a hash.
        assert_eq!(
            record.event.policy_hash, world.config.policy_hash,
            "{action}"
        );
        // The correlation id was checked against the job's while the records were read.
        assert!(
            !record.event.reason.trim().is_empty(),
            "{action} has no reason"
        );
        assert!(
            !record.event.subject.trim().is_empty(),
            "{action} has no subject"
        );
        if let Some(kind) = AuditKind::of_action(action) {
            seen.insert(kind);
        }
    }
    let missing: Vec<&str> = AuditKind::ALL
        .iter()
        .filter(|kind| !seen.contains(kind))
        .map(|kind| kind.as_str())
        .collect();
    assert!(missing.is_empty(), "no record of these types: {missing:?}");
}

/// The matrix lists exactly the types the policy requires, each with an owner that is a work
/// package, and agrees with the code about which types the engine writes.
#[test]
fn negative_nt_aud_03_the_matrix_lists_an_owner_for_every_type_the_policy_requires() {
    const POLICY: &str = include_str!("../../../../policies/security.yaml");
    let section = POLICY
        .split("must_record:")
        .nth(1)
        .expect("the policy has an audit.must_record list");
    let required: Vec<&str> = section
        .lines()
        .skip(1)
        .map_while(|line| line.trim().strip_prefix("- "))
        .collect();
    let rows = audit_matrix::rows();
    let listed: Vec<&str> = rows.iter().map(|row| row.kind.as_str()).collect();
    assert_eq!(listed, required, "the matrix and the policy file differ");
    let in_code: Vec<&str> = AuditKind::ALL.iter().map(|kind| kind.as_str()).collect();
    assert_eq!(listed, in_code, "the matrix and the code differ");
    for row in &rows {
        assert!(
            row.owner.starts_with("s0-") || row.owner.starts_with("s1-"),
            "{} has no owner: {:?}",
            row.kind,
            row.owner
        );
    }
}

/// The matrix and the scenario agree: the types the scenario has to script are exactly the types
/// the matrix does not give to the engine. If a component starts to write a type the scenario
/// scripts, the matrix has to say so and the scenario has to stop scripting it.
#[test]
fn negative_nt_aud_03_the_types_the_scenario_scripts_are_the_types_the_engine_does_not_write() {
    let scripted: BTreeSet<&str> = SCRIPTED.iter().map(|kind| kind.as_str()).collect();
    for row in audit_matrix::rows() {
        let by_engine = row.production == Production::Engine;
        assert_eq!(
            scripted.contains(row.kind.as_str()),
            !by_engine,
            "{}: the matrix says {:?}, the scenario {} it",
            row.kind,
            row.production,
            if scripted.contains(row.kind.as_str()) {
                "scripts"
            } else {
                "lets the engine write"
            }
        );
    }
    // Every type has a correct producer: the engine, a stage handler or the API under the
    // required name. A type that is written under another name, in another stream or by nothing
    // fails here, and so does a matrix that goes back to saying so.
    let open: Vec<String> = audit_matrix::rows()
        .into_iter()
        .filter(|row| {
            matches!(
                row.production,
                Production::DifferentlyNamed | Production::OtherStream | Production::Nothing
            )
        })
        .map(|row| format!("{} ({:?})", row.kind, row.production))
        .collect();
    assert!(open.is_empty(), "no correct producer: {open:?}");
}

/// One audit record of the sandbox, a command or the broker: the action, the reason and who wrote
/// it.
struct Fact {
    action: String,
    reason: String,
    actor: String,
}

/// The records of one attempt that ran an agent in a sandbox, in the order they were written.
async fn facts_of_an_attempt(argument: &str) -> Vec<Fact> {
    let world = World::new().await;
    world.script(StageKind::Intake).agent_spending(2_000_000);
    world.script(StageKind::Intake).runs_an_agent();
    world.runtime.queue(
        AdversarialScript::returning(json!({}))
            .then_exec(&["echo", argument])
            .then_exec(&["false"]),
    );
    let job = world.admitted_job().await;
    world.advance(400);
    world.run_next("worker-1").await;
    world
        .audit(job)
        .await
        .into_iter()
        .filter(|record| {
            matches!(
                AuditKind::of_action(record.event.action.as_str()),
                Some(
                    AuditKind::SandboxCreatedPostureResultDestroyed
                        | AuditKind::CommandExecuted
                        | AuditKind::EgressRequest
                )
            )
        })
        .map(|record| Fact {
            action: record.event.action.as_str().to_owned(),
            reason: record.event.reason.clone(),
            actor: match &record.event.actor {
                AuditActor::System(label) => label.as_str().to_owned(),
                other => format!("{other:?}"),
            },
        })
        .collect()
}

/// The facts the supervisor returns reach the audit log as records of the engine: the sandbox is
/// created with its posture verified, each command that ran is written with its outcome, the
/// sandbox is destroyed, and the model requests the broker metered are summed. A command is
/// recorded by its program and its result; its arguments, which could hold anything, are not.
#[tokio::test]
async fn negative_nt_aud_03_the_engine_writes_the_sandbox_lifecycle_the_commands_and_the_egress_summary()
 {
    let argument = "an-argument-that-the-audit-log-must-never-hold";
    let facts = facts_of_an_attempt(argument).await;
    let actions: Vec<&str> = facts.iter().map(|fact| fact.action.as_str()).collect();
    assert_eq!(
        actions,
        [
            "sandbox_created_posture_result_destroyed.granted",
            "command_executed.noted",
            "command_executed.noted",
            "sandbox_created_posture_result_destroyed.ended",
            "egress_request.noted",
        ],
        "{actions:?}"
    );
    let reason = |index: usize| facts[index].reason.as_str();
    assert!(reason(0).contains("posture"), "{}", reason(0));
    assert!(reason(1).contains("program echo"), "{}", reason(1));
    assert!(reason(1).contains("exit 0"), "{}", reason(1));
    assert!(reason(2).contains("program false"), "{}", reason(2));
    assert!(reason(2).contains("exit 1"), "{}", reason(2));
    assert!(reason(3).contains("completed"), "{}", reason(3));
    assert!(reason(4).contains("1 request"), "{}", reason(4));
    for fact in &facts {
        assert!(
            !fact.reason.contains(argument),
            "{}: {}",
            fact.action,
            fact.reason
        );
        assert!(
            fact.reason.len() <= 400,
            "{} is {} bytes",
            fact.action,
            fact.reason.len()
        );
    }
}

/// A component never signs for another: the sandbox and the commands are the stage handler's
/// records, because its sandbox ran them, and the summary of the broker is the engine's own,
/// because the engine owns the token.
#[tokio::test]
async fn negative_nt_aud_03_the_facts_of_an_attempt_name_who_wrote_them() {
    let facts = facts_of_an_attempt("x").await;
    for fact in &facts {
        let expected = if fact.action.starts_with("egress_request") {
            "workflow.engine"
        } else {
            "stage-handler.intake"
        };
        assert_eq!(fact.actor, expected, "{}", fact.action);
    }
    assert_eq!(facts.len(), 5);
}
