//! KNOWN DEFECT, shown as a test that flips when it is fixed: a stage's gate cannot read the
//! documents that the engine stored from the stage's own output.
//!
//! The stage authors reported it, and this test confirms it on PostgreSQL. The engine stores an
//! output with `ArtifactStore::put`, which makes no index row, and `ArtifactStore::get` answers
//! only for a hash the tenant has indexed. The probe in the gate (`evaluate`) of a scripted stage
//! reads each output by `ctx.ports.artifacts.get` and records what it got: `NotFound`.
//!
//! The composition crate cannot repair this. A wrapper around the artifact store would have to
//! serve a blob that the tenant has not indexed, which is the cross-tenant rule (ADR 0008) turned
//! off. The smallest correct fix is in the engine, `engine/attempt.rs`, `Engine::produce`: after
//! the outputs and the attempt manifest are stored and before the `GateContext` is built, call
//! `self.index_declared(claimed, &refs)` for every stored output (the method exists and is what
//! the engine already does for artifacts a handler declared). When that lands, flip the final
//! assertion to `all(Result::is_ok)`.

mod support;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
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
        }
        self.inner.evaluate(ctx).await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn defect_a_gate_cannot_read_the_documents_the_engine_stored_from_the_stage_output() {
    let (_db, world, _) = pg_world().await;
    let seen = Arc::new(Mutex::new(Vec::new()));
    // A registry in which the probe stands for INTAKE and the scripted handlers for the rest.
    let mut handlers = HandlerRegistry::new();
    for kind in &world.config.scope {
        let scripted = ScriptedHandler::new(*kind, world.script(*kind).clone());
        if *kind == StageKind::Intake {
            handlers
                .register(Arc::new(Probe {
                    inner: scripted,
                    seen: seen.clone(),
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
        seen.iter()
            .all(|read| matches!(read, Err(ArtifactError::NotFound))),
        "the defect is gone (flip this assertion): {seen:?}"
    );
}
