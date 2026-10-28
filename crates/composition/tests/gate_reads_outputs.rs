//! A stage's gate reads the documents that the engine stored from the stage's own output.
//!
//! The stage authors reported a defect and this test first confirmed it on PostgreSQL: the engine
//! stored an output with `ArtifactStore::put`, which makes no index row, and
//! `ArtifactStore::get` answers only for a hash the tenant has indexed, so the probe in the gate
//! (`evaluate`) of a scripted stage got `NotFound` for every output. The fix is in the engine,
//! `Engine::produce`: the outputs and the attempt manifest are indexed for the tenant before the
//! `GateContext` is built. The test reads each output by `ctx.ports.artifacts.get` in the gate and
//! records what it got.
//!
//! It also shows the second half of the rule: another tenant still cannot read what this tenant
//! has indexed (ADR 0008), so the fix indexes for the owner and opens nothing else.

mod support;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use factory_domain::ids::TenantId;
use factory_domain::scope::TenantScope;
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::agent::RoutingNeed;
use factory_ports::artifact::ArtifactError;
use factory_workflow::engine::Engine;
use factory_workflow::gates::framework::GateDecision;
use factory_workflow::handlers::HandlerRegistry;
use factory_workflow::handlers::{
    Applicability, ContractContext, GateContext, StageContext, StageError, StageHandler,
    StageOutput,
};
use support::engine::{PgWorld, ScriptedHandler};
use support::pg_world;

/// Wraps the scripted handler of a stage and reads the outputs in the gate.
struct Probe {
    inner: ScriptedHandler,
    seen: Arc<Mutex<Vec<Result<usize, ArtifactError>>>>,
    /// What a tenant that did not make the output gets for the same hash.
    foreign: Arc<Mutex<Vec<Result<usize, ArtifactError>>>>,
}

#[async_trait]
impl StageHandler for Probe {
    fn fidelity(&self) -> Fidelity {
        self.inner.fidelity()
    }

    fn kind(&self) -> StageKind {
        self.inner.kind()
    }

    fn applicability(&self, ctx: &ContractContext<'_>) -> Applicability {
        self.inner.applicability(ctx)
    }

    fn routing_need(&self, ctx: &ContractContext<'_>) -> Option<RoutingNeed> {
        self.inner.routing_need(ctx)
    }

    fn contract(
        &self,
        ctx: &ContractContext<'_>,
    ) -> Result<factory_domain::contracts::StageContract, StageError> {
        self.inner.contract(ctx)
    }

    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError> {
        self.inner.execute(ctx).await
    }

    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError> {
        for output in ctx.outputs {
            let read = ctx
                .ports
                .artifacts
                .get(&TenantScope::new(ctx.identity.tenant), &output.artifact)
                .await
                .map(|bytes| bytes.len());
            self.seen.lock().expect("the lock").push(read);
            let stranger = TenantId::from_uuid(uuid::Uuid::from_u128(
                ctx.identity.tenant.as_uuid().as_u128() ^ 0xf0f0,
            ));
            let denied = ctx
                .ports
                .artifacts
                .get(&TenantScope::new(stranger), &output.artifact)
                .await
                .map(|bytes| bytes.len());
            self.foreign.lock().expect("the lock").push(denied);
        }
        self.inner.evaluate(ctx).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_gate_reads_the_documents_the_engine_stored_from_the_stage_output() {
    let (_db, world, _) = pg_world().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let foreign = Arc::new(Mutex::new(Vec::new()));
    // A registry in which the probe stands for INTAKE and the scripted handlers for the rest.
    let mut handlers = HandlerRegistry::new();
    for kind in &world.config.scope {
        let scripted = ScriptedHandler::new(*kind, world.script(*kind).clone());
        if *kind == StageKind::Intake {
            handlers
                .register(Arc::new(Probe {
                    inner: scripted,
                    seen: seen.clone(),
                    foreign: foreign.clone(),
                }))
                .expect("one handler per stage");
        } else {
            handlers
                .register(Arc::new(scripted))
                .expect("one handler per stage");
        }
    }
    let engine =
        Engine::new(world.deps.clone(), world.config.clone(), handlers).expect("the engine starts");
    let job = world.admitted_job().await;
    let claimed = engine
        .claim_next(&PgWorld::worker("worker-probe"))
        .await
        .expect("claim")
        .started
        .into_iter()
        .next()
        .expect("one attempt");
    assert_eq!(claimed.job, job);
    engine
        .run_attempt(&claimed)
        .await
        .expect("the attempt runs");
    let seen = seen.lock().expect("the lock").clone();
    assert!(!seen.is_empty(), "the gate ran and saw at least one output");
    assert!(
        seen.iter().all(Result::is_ok),
        "the gate must read every document the engine stored: {seen:?}"
    );
    let foreign = foreign.lock().expect("the lock").clone();
    assert_eq!(foreign.len(), seen.len());
    assert!(
        foreign
            .iter()
            .all(|read| matches!(read, Err(ArtifactError::NotFound))),
        "another tenant must still get nothing for the same hash: {foreign:?}"
    );
}
