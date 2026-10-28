//! The audit stream and the job audit verifier.
//!
//! The verifier reads a job back and must find a broken chain, a fake entry in a production job,
//! and a `PASSED` stage run with no evidence behind it. The coverage test runs one scripted
//! scenario for each kind of event that `policies/security.yaml` requires the audit log to hold,
//! and checks that each record names its actor, the policy hash and the correlation id.

mod support;

use factory_domain::ids::AttemptId;
use factory_domain::scope::TenantScope;
use factory_domain::state::{Guard, StageRunEvent, StageRunStatus};
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_domain::vocabulary::{ExecutionMode, GateOutcome, HumanRole, StageKind};
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::store::{AppliedTransition, GateRecord, StageRunEffects, StartAttempt};
use factory_testkit::fixtures::{Ids, cleared, ledger_entry};
use factory_testkit::store::StoreDefect;
use factory_workflow::audit::{
    AuditAction, AuditDecision, AuditKind, Finding, RunOutcomes, check_job,
};
use factory_workflow::commands::{Decision, OverrideFacts, Subject};
use support::{Eval, World};

#[tokio::test]
async fn the_verifier_finds_nothing_wrong_in_an_honest_job() {
    let world = World::new().await;
    let (job, run) = world.at_approval().await;
    world.approve(job, run).await;
    let report = world
        .engine
        .verify_job(world.tenant, job)
        .await
        .expect("the verifier runs");
    assert!(report.is_clean(), "{:?}", report.findings);
    assert!(report.entries_checked >= 12);
    assert!(report.stage_runs_checked >= 12);
}

#[tokio::test]
async fn the_verifier_detects_a_broken_chain() {
    // A store that accepts an entry with the wrong previous hash lets a broken chain exist. The
    // verifier does not rely on the store to have refused it.
    let world = World::with_store_defect(StoreDefect::AcceptsBrokenChain).await;
    let job = world.admitted_job().await;
    world.run_next("worker-1").await;
    let stage_run = world.view(job).await.stage_runs[0].id;
    let next = world.ledger(job).await.len() as u64 + 1;
    let wrong_previous = Sha256Digest::of(b"not the hash of the entry before");
    let forged = ledger_entry(
        &Ids::new(),
        job,
        stage_run,
        next,
        Some(&wrong_previous),
        &world.clock.now(),
        "A forged entry that does not follow the chain.",
    );
    let mut tx = world
        .store
        .begin(TenantScope::new(world.tenant))
        .await
        .expect("a tx");
    tx.append_ledger_entry(forged)
        .await
        .expect("the faulty store accepts it");
    tx.commit().await.expect("commit");

    let report = world
        .engine
        .verify_job(world.tenant, job)
        .await
        .expect("runs");
    assert!(
        report
            .findings
            .iter()
            .any(|finding| matches!(finding, Finding::ChainBroken(_))),
        "{:?}",
        report.findings
    );
}

#[tokio::test]
async fn the_verifier_detects_a_fake_entry_in_a_production_job() {
    // A test-mode job is full of fake entries, which is right for a test job and wrong for a
    // production one. The verifier, told the job is production, finds every one.
    let world = World::new().await;
    let job = world.admitted_job().await;
    world.run_stages(2).await;
    let view = world.view(job).await;
    let outcomes = RunOutcomes::from_statuses(view.stage_runs.iter().map(|r| (r.id, r.status)));
    let entries = world.ledger(job).await;
    assert!(!entries.is_empty());
    assert!(check_job(&entries, &outcomes, ExecutionMode::Test).is_empty());
    let findings = check_job(&entries, &outcomes, ExecutionMode::Production);
    let fake = findings
        .iter()
        .filter(|finding| matches!(finding, Finding::FakeEntryInProduction { .. }))
        .count();
    assert_eq!(fake, entries.len());
}

/// Moves a stage run to `PASSED` through the store alone, as a faulty engine would: no gate
/// report, no ledger entry.
async fn pass_without_evidence(world: &World, run: factory_domain::ids::StageRunId) {
    let now = world.clock.now();
    let mut system = world.store_system().await;
    let candidates = system.find_claim_candidates(1).await.expect("find");
    system.finish().await.expect("finish");
    assert_eq!(candidates[0].stage_run, run);
    let mut tx = world
        .store
        .begin(TenantScope::new(world.tenant))
        .await
        .expect("a tx");
    let start = AppliedTransition::plan(
        StageRunStatus::Ready,
        StageRunEvent::Start,
        now,
        cleared(Guard::LeaseAcquired),
    )
    .expect("a legal move");
    let started = tx
        .start_attempt(StartAttempt {
            attempt: AttemptId::from_uuid(world.ids.new_uuid()),
            stage_run: run,
            expected: candidates[0].version,
            worker: World::worker("rogue"),
            lease_ttl: std::time::Duration::from_secs(60),
            attempt_timeout: std::time::Duration::from_secs(600),
            transition: start,
        })
        .await
        .expect("the store starts it");
    let mut version = started.stage_run.version;
    // The store takes a pass that names an outcome and a stored report (it refuses a pass with no
    // report), so the faulty engine names both. What it never writes is the ledger entry that
    // should stand behind them, and the verifier finds the pass by that absence.
    let bytes = b"a report that no ledger entry cites";
    let report = factory_domain::values::Sha256Digest::of(bytes);
    tx.index_artifact(factory_ports::store::NewArtifactIndexEntry {
        sha256: report.clone(),
        media_type: factory_domain::values::MediaType::parse("application/json").expect("a type"),
        size_bytes: factory_domain::values::NonNegativeInt::new(
            i64::try_from(bytes.len()).expect("small"),
        )
        .expect("a size"),
        origin: None,
    })
    .await
    .expect("the report is indexed");
    for (from, event, guard, effects) in [
        (
            StageRunStatus::Running,
            StageRunEvent::AttemptSucceeded,
            Guard::OutputSchemaValid,
            StageRunEffects::default(),
        ),
        (
            StageRunStatus::Gating,
            StageRunEvent::GatePassed,
            Guard::GatePassEvidenced,
            StageRunEffects {
                gate: Some(GateRecord {
                    outcome: GateOutcome::Passed,
                    report_sha256: Some(report),
                    failing_set_sha256: None,
                }),
                ..StageRunEffects::default()
            },
        ),
    ] {
        let plan = AppliedTransition::plan(from, event, now, cleared(guard)).expect("a legal move");
        version = tx
            .transition_stage_run(run, version, plan, effects)
            .await
            .expect("the store accepts a legal move");
    }
    tx.commit().await.expect("commit");
}

#[tokio::test]
async fn the_verifier_detects_a_passed_run_without_evidence() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    let intake = world.view(job).await.stage_runs[0].id;
    pass_without_evidence(&world, intake).await;
    assert_eq!(
        world.view(job).await.stage_runs[0].status,
        StageRunStatus::Passed
    );
    let report = world
        .engine
        .verify_job(world.tenant, job)
        .await
        .expect("runs");
    assert_eq!(
        report.findings,
        vec![Finding::PassedWithoutEvidence { stage_run: intake }]
    );
}

#[tokio::test]
async fn the_verifier_detects_a_skipped_run_without_a_rule() {
    let world = World::new().await;
    let job = world.admitted_job().await;
    let pending = world.view(job).await.stage_runs[1].id;
    let at = Timestamp::parse("2026-10-27T08:30:00Z").expect("an instant");
    let mut tx = world
        .store
        .begin(TenantScope::new(world.tenant))
        .await
        .expect("a tx");
    let version = tx.get_stage_run(pending).await.expect("run").version;
    let plan = AppliedTransition::plan(
        StageRunStatus::Pending,
        StageRunEvent::MarkNotApplicable,
        at,
        cleared(Guard::NotApplicableDecided),
    )
    .expect("legal");
    tx.transition_stage_run(
        pending,
        version,
        plan,
        StageRunEffects {
            gate: Some(GateRecord {
                outcome: GateOutcome::NotApplicable,
                report_sha256: None,
                failing_set_sha256: None,
            }),
            ..StageRunEffects::default()
        },
    )
    .await
    .expect("moves");
    tx.commit().await.expect("commit");
    let report = world
        .engine
        .verify_job(world.tenant, job)
        .await
        .expect("runs");
    assert_eq!(
        report.findings,
        vec![Finding::SkippedWithoutRule { stage_run: pending }]
    );
}

#[tokio::test]
async fn every_required_event_type() {
    // NT-AUD-03, the engine part: one scripted scenario for each type that the policy requires.
    let world = World::new().await;
    let noted = |kind| AuditAction::new(kind, AuditDecision::Noted);

    // Job one: an agent stage that spends 80% of its ceiling, has a tool call denied, and notes
    // what only the handler sees. Then the job runs to the approval, which a person grants.
    world.script(StageKind::Intake).agent_spending(2_000_000);
    world.script(StageKind::Intake).denials(1);
    world.script(StageKind::Intake).notes(&[
        noted(AuditKind::CommandExecuted),
        noted(AuditKind::SandboxCreatedPostureResultDestroyed),
        noted(AuditKind::EgressRequest),
        noted(AuditKind::SecretRedactedOrBlocked),
        noted(AuditKind::ProtectedPathDecision),
        noted(AuditKind::WebhookAcceptedOrRejected),
    ]);
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
                justification: factory_domain::values::HumanText::parse(
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

    let mut seen: std::collections::BTreeSet<AuditKind> = std::collections::BTreeSet::new();
    for job in [first, second] {
        let correlation = world.events(job).await[0].correlation_id;
        for record in world.audit(job).await {
            // Every record names who acted, the policy in force and the job's correlation id.
            assert_eq!(
                record.event.policy_hash, world.config.policy_hash,
                "{}",
                record.event.action
            );
            assert_eq!(
                record.event.correlation_id, correlation,
                "{}",
                record.event.action
            );
            if let Some(kind) = AuditKind::of_action(record.event.action.as_str()) {
                seen.insert(kind);
            }
        }
    }
    let missing: Vec<&str> = AuditKind::ALL
        .iter()
        .filter(|kind| !seen.contains(kind))
        .map(|kind| kind.as_str())
        .collect();
    assert!(missing.is_empty(), "no event of these types: {missing:?}");
}

#[test]
fn the_required_types_are_the_ones_in_the_policy_file() {
    // The list in code and the list in `policies/security.yaml` must stay equal.
    const POLICY: &str = include_str!("../../../policies/security.yaml");
    let section = POLICY
        .split("must_record:")
        .nth(1)
        .expect("the policy has an audit.must_record list");
    let listed: Vec<&str> = section
        .lines()
        .skip(1)
        .map_while(|line| line.trim().strip_prefix("- "))
        .collect();
    let ours: Vec<&str> = AuditKind::ALL.iter().map(|kind| kind.as_str()).collect();
    assert_eq!(listed, ours);
}
