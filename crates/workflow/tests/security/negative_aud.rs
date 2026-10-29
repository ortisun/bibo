//! NT-AUD-03: audit coverage.
//!
//! One scripted scenario for each audit event type that `policies/security.yaml` requires
//! (`audit.must_record`). Every record the scenario writes must name its actor, the hash of the
//! policy in force and the correlation id of its job, and every type must have an owner in the
//! matrix of `docs/security/p0-coverage.md`.
//!
//! The scenario is the one of `tests/audit.rs`, which proves the engine part, with two additions
//! that the catalog asks for: the actor is checked, and the matrix is bound to the scenario. The
//! scenario has the engine write the types the engine writes. The types that a stage handler, the
//! API, the sandbox or the egress proxy write are noted by a scripted handler, because those
//! components are not in this crate. The matrix says, for each type, whether a component writes it
//! in production code. A type that nothing writes today is listed as such, and the test fails when
//! the matrix says that the engine writes a type that the scenario had to script.

use std::collections::BTreeSet;

use factory_domain::values::HumanText;
use factory_domain::vocabulary::{HumanRole, StageKind};
use factory_ports::store::AuditActor;
use factory_workflow::audit::{AuditAction, AuditDecision, AuditKind};
use factory_workflow::commands::{Decision, OverrideFacts, Subject};

use crate::audit_matrix::{self, Production};
use crate::support::{Eval, World};

/// The types that the scenario cannot make the engine write, because another component does.
const SCRIPTED: [AuditKind; 6] = [
    AuditKind::CommandExecuted,
    AuditKind::SandboxCreatedPostureResultDestroyed,
    AuditKind::EgressRequest,
    AuditKind::SecretRedactedOrBlocked,
    AuditKind::ProtectedPathDecision,
    AuditKind::WebhookAcceptedOrRejected,
];

/// Runs the scenario and returns every audit record of its two jobs with the data to check them.
async fn scenario() -> (World, Vec<factory_ports::store::AuditRecord>) {
    let world = World::new().await;
    let noted = |kind| AuditAction::new(kind, AuditDecision::Noted);

    // Job one: an agent stage spends 80 percent of its ceiling and has a tool call denied; a
    // handler notes what only a handler sees. The job runs to the approval, which a person grants.
    world.script(StageKind::Intake).agent_spending(2_000_000);
    world.script(StageKind::Intake).denials(1);
    world.script(StageKind::Intake).notes(&SCRIPTED.map(noted));
    let (first, run) = world.at_approval().await;
    world.approve(first, run).await;

    // Job two: a block that a person overrides.
    world.script(StageKind::Intake).agent_spending(0);
    world.script(StageKind::Intake).with(|s| s.agent = false);
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
    // Four types have no correct producer today: the matrix says which and why, and the p0
    // coverage page lists them as the open part of NT-AUD-03.
    let open: Vec<String> = audit_matrix::rows()
        .into_iter()
        .filter(|row| {
            matches!(
                row.production,
                Production::DifferentlyNamed | Production::OtherStream | Production::Nothing
            )
        })
        .map(|row| row.kind)
        .collect();
    assert_eq!(open.len(), 4, "{open:?}");
}
