//! What the engine does for `DOMAIN_DISCOVERY`, which is in `SLICE_ONE_SCOPE` and has no handler
//! (`crates/workflow/src/stages/domain_discovery/mod.rs` is a placeholder file).
//!
//! # Finding
//!
//! * `state-machine.json` lists the stage in Slice 1: `requires: [SPECIFICATION]`, executor
//!   `deterministic`, gate "profile resolution and tool capability probes; BLOCKED when a
//!   mandatory profile gate cannot run", human gate `never`. It is not optional in the table.
//! * The engine **refuses to admit** a job whose scope names a stage with no handler:
//!   `admit_job` answers `EngineError::NoHandler(DOMAIN_DISCOVERY)` and the job stays `RECEIVED`.
//!   So a full-scope job cannot run until the stage has a handler of some kind.
//! * The engine does support a stage that **does not apply**: a handler's `applicability` may
//!   return `NotApplicable(SkipRule)` with the basis `DomainProfile`, the stage run becomes
//!   `SKIPPED` with the rule and its inputs in the ledger, and ADR 0010 makes a skipped run
//!   satisfy the stages that require it and the completion of the job.
//!
//! # The smallest correct option
//!
//! A handler of about thirty lines in `crates/workflow/src/stages/domain_discovery` whose
//! `applicability` returns `NotApplicable(SkipRule { basis: DomainProfile, rule:
//! "static-general-software-profile", inputs: "Slice 1 resolves one static profile,
//! general-software, so there is no domain to discover." })`. That is faithful to the rules file
//! ("Slice 1 resolves one static profile") and to ADR 0010, and it records the decision in the
//! ledger instead of hiding it. It drops the stage's second duty, the tool capability probes with
//! a BLOCKED outcome, so the owner (`s1-stage-architecture-and-planning`) and the architect must
//! accept that or write the real stage. This crate writes neither: the second test below shows
//! the engine accepting exactly such a skip, with the engine suite's scripted handler standing in
//! for the thirty lines.

mod support;

use std::sync::Arc;

use factory_composition::system::RandomIds;
use factory_domain::ids::TenantId;
use factory_domain::state::{JobStatus, StageRunStatus};
use factory_domain::values::{HumanText, Slug};
use factory_domain::vocabulary::StageKind;
use factory_ports::clock::IdGenerator;
use factory_workflow::engine::{Engine, EngineError};
use factory_workflow::handlers::{HandlerRegistry, SkipBasis, SkipRule};
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

#[tokio::test(flavor = "multi_thread")]
async fn a_stage_that_does_not_apply_is_skipped_by_a_recorded_rule_and_the_pipeline_goes_on() {
    let (_db, world) = world().await;
    world.script(StageKind::DomainDiscovery).with(|script| {
        script.skip = Some(SkipRule {
            basis: SkipBasis::DomainProfile,
            rule: Slug::parse("static-general-software-profile").expect("a slug"),
            inputs: HumanText::parse(
                "Slice 1 resolves one static profile, general-software, so there is no domain to discover.",
            )
            .expect("text"),
        });
    });
    world
        .script(StageKind::Approval)
        .evals_otherwise(Eval::HumanGate);
    let job = world.admitted_job().await;
    loop {
        let claimed = world.claim_one("worker-skip").await;
        world
            .engine
            .run_attempt(&claimed)
            .await
            .expect("the attempt runs");
        if claimed.kind == StageKind::Approval {
            break;
        }
    }
    let view = world.view(job).await;
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
}
