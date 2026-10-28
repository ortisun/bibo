//! What the engine does for `DOMAIN_DISCOVERY`, which is in `SLICE_ONE_SCOPE`.
//!
//! # Finding
//!
//! * `state-machine.json` lists the stage in Slice 1: `requires: [SPECIFICATION]`, executor
//!   `deterministic`, gate "profile resolution and tool capability probes; BLOCKED when a
//!   mandatory profile gate cannot run", human gate `never`.
//! * The engine **refuses to admit** a job whose scope names a stage with no handler:
//!   `admit_job` answers `EngineError::NoHandler(DOMAIN_DISCOVERY)` and the job stays `RECEIVED`.
//! * The engine supports a stage that **does not apply**: a handler's `applicability` returns
//!   `NotApplicable(SkipRule)` with the basis `DomainProfile`, the stage run becomes `SKIPPED`
//!   with the rule and its inputs in the ledger, and ADR 0010 makes a skipped run satisfy the
//!   stages that require it and the completion of the job.
//!
//! # What is registered
//!
//! `factory_workflow::stages::domain_discovery::DomainDiscoveryHandler` is that skip: "Slice 1 does
//! not profile the domain". The lead accepted it for Slice 1. The stage's second duty, the tool
//! capability probes, stays with the start-up probes; the architect has not confirmed that, so it
//! is pending (see the README). The tests below run the real handler over the real store.

mod support;

use std::sync::Arc;

use factory_composition::system::RandomIds;
use factory_domain::ids::TenantId;
use factory_domain::state::{JobStatus, StageRunStatus};
use factory_domain::vocabulary::StageKind;
use factory_ports::clock::IdGenerator;
use factory_workflow::engine::{Admission, Engine, EngineError};
use factory_workflow::handlers::HandlerRegistry;
use factory_workflow::stages::domain_discovery::{DomainDiscoveryHandler, SKIP_RULE};
use support::engine::{Eval, PgWorld, ScriptedHandler};
use support::{TestDb, seed_tenant, seeded_repository, server, worker_config};

async fn world() -> (TestDb, PgWorld) {
    let db = server().clone_database().await;
    let ids = RandomIds::new().expect("the random source opens");
    let tenant = TenantId::from_uuid(ids.new_uuid());
    seed_tenant(&db, tenant, 0, "org/repo-0").await;
    let store = factory_storage::pg::PgStore::connect(worker_config(&db).await)
        .await
        .expect("the store becomes ready");
    let world = PgWorld::new(store, tenant, seeded_repository(tenant), |_| {}).await;
    (db, world)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_whose_scope_names_a_stage_with_no_handler_is_refused_at_admission() {
    let (_db, world) = world().await;
    // Every stage of the scope has a handler but DOMAIN_DISCOVERY: the state of the repository.
    let mut handlers = HandlerRegistry::new();
    for kind in &world.config.scope {
        if *kind != StageKind::DomainDiscovery {
            handlers
                .register(Arc::new(ScriptedHandler::new(
                    *kind,
                    world.script(*kind).clone(),
                )))
                .expect("one handler per stage");
        }
    }
    let engine = Engine::new(world.deps.clone(), world.config.clone(), handlers)
        .expect("the engine starts: the gap shows at admission");
    let job = engine
        .receive_job(world.tenant, world.requester, world.repository)
        .await
        .expect("the job is received");
    let refused = engine
        .admit_job(world.tenant, job)
        .await
        .expect_err("a stage with no handler cannot be admitted");
    assert!(
        matches!(refused, EngineError::NoHandler(StageKind::DomainDiscovery)),
        "{refused:?}"
    );
    let view = engine.job_view(world.tenant, job).await.expect("a view");
    assert_eq!(view.status, JobStatus::Received);
    assert!(view.stage_runs.is_empty(), "no stage run was made");
}

/// The registry of the Slice 1 assembly: the scripted handlers of the engine suite for every stage
/// but `DOMAIN_DISCOVERY`, which is the real handler.
fn registry_with_the_real_discovery(world: &PgWorld) -> HandlerRegistry {
    let mut handlers = HandlerRegistry::new();
    for kind in &world.config.scope {
        if *kind == StageKind::DomainDiscovery {
            handlers
                .register(Arc::new(DomainDiscoveryHandler::new()))
                .expect("one handler per stage");
        } else {
            handlers
                .register(Arc::new(ScriptedHandler::new(
                    *kind,
                    world.script(*kind).clone(),
                )))
                .expect("one handler per stage");
        }
    }
    handlers
}

#[tokio::test(flavor = "multi_thread")]
async fn the_real_handler_skips_the_stage_by_a_recorded_rule_and_the_pipeline_goes_on() {
    let (_db, world) = world().await;
    world
        .script(StageKind::Approval)
        .evals_otherwise(Eval::HumanGate);
    let engine = Engine::new(
        world.deps.clone(),
        world.config.clone(),
        registry_with_the_real_discovery(&world),
    )
    .expect("the engine starts");
    let job = engine
        .receive_job(world.tenant, world.requester, world.repository)
        .await
        .expect("received");
    let admission = engine.admit_job(world.tenant, job).await.expect("admitted");
    assert!(
        matches!(admission, Admission::Admitted { .. }),
        "{admission:?}"
    );
    loop {
        let claimed = engine
            .claim_next(&PgWorld::worker("worker-skip"))
            .await
            .expect("claim")
            .started
            .into_iter()
            .next()
            .expect("one attempt");
        engine
            .run_attempt(&claimed)
            .await
            .expect("the attempt runs");
        if claimed.kind == StageKind::Approval {
            break;
        }
    }
    let view = engine.job_view(world.tenant, job).await.expect("a view");
    let discovery = view
        .newest(StageKind::DomainDiscovery)
        .expect("a run of the stage");
    assert_eq!(discovery.status, StageRunStatus::Skipped, "{view:#?}");
    assert!(
        discovery.attempts.is_empty(),
        "a skipped stage runs no attempt"
    );
    // The stages that require it went on, and the job waits at the approval.
    assert_eq!(
        view.newest(StageKind::Architecture).map(|run| run.status),
        Some(StageRunStatus::Passed)
    );
    assert_eq!(view.status, JobStatus::WaitingForHuman);

    // The skip is in the ledger with its rule, its reason and the basis, and it claims no level.
    let ledger = world.ledger(job).await;
    let entry = ledger
        .iter()
        .find(|entry| entry.claim.statement.as_str().contains(SKIP_RULE))
        .expect("the ledger records the skip rule");
    assert!(
        entry.claim.assurance_level.is_none(),
        "a skip is never evidence for an assurance level"
    );
    let recorded = serde_json::to_string(entry).expect("an entry serializes");
    assert!(
        recorded.contains("Slice 1 does not profile the domain"),
        "the reason is in the entry: {recorded}"
    );
}
