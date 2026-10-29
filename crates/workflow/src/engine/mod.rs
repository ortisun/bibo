//! The engine: the one place that decides a move and writes it.
//!
//! # How a decision is made
//!
//! Every use case in this module follows the same steps, so that the rules of the state machine
//! hold whichever path a request took:
//!
//! 1. Open a transaction for the tenant that owns the job (`Store::begin`). The system scope
//!    (`Store::begin_system`) is used only to *find* work (claim, expired leases), never to apply
//!    it (ADR 0012).
//! 2. Read the rows and the job's timeline, and build the facts the guard reads.
//! 3. Ask the domain guard (`factory_domain::machines::guards::evaluate`). A guard that does not
//!    hold ends the decision with a typed error and changes nothing.
//! 4. Plan each move with `AppliedTransition::plan`, which asks the transition table. A move the
//!    table does not list is an error, never a silent change (INV-02).
//! 5. Write the status changes (compare-and-swap on the version), the ledger entries that justify
//!    them, the outbox events that announce them and the audit records, and commit once
//!    (INV-03). If any step fails, none of it exists.
//!
//! A step that loses a race (`StoreError::Conflict`) returns [`EngineError::Conflict`]. The caller
//! reads the state again and decides again: the engine never overwrites a change it has not seen.

mod admission;
mod agent_span;
mod attempt;
mod build_code;
mod cancel;
mod changes;
pub mod config;
mod control;
mod decide;
mod decision;
mod dependency;
mod ended;
mod error;
mod failure;
mod gate;
mod ledger;
pub mod links;
pub(crate) mod payload;
mod platform;
pub(crate) mod progress;
pub(crate) mod record;
mod replace;
pub(crate) mod timeline;
mod view;
mod warning;

use std::sync::Arc;

use factory_domain::ids::{AttemptId, CausationId, EventId, StageRunId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::vocabulary::{Fidelity, RecorderFidelity};
use factory_ports::agent::{AgentRuntime, ModelBroker, ModelRouter};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::{Clock, IdGenerator};
use factory_ports::registry::{AgentRegistry, OutputValidator};
use factory_ports::require_permitted;
use factory_ports::sandbox::SandboxProvider;
use factory_ports::store::{Store, SystemScope, SystemTx, Tx};
use factory_ports::workspace::WorkspaceProvider;

pub(crate) use ledger::read_all_ledger;

pub use admission::Admission;
pub use attempt::AttemptOutcome;
pub use changes::ChangeApplied;
pub use config::EngineConfig;
pub use error::EngineError;
pub use platform::PlatformEvent;
pub use view::{AttemptView, JobView, StageRunView};

use crate::commands::Authority;
use crate::handlers::{HandlerRegistry, StagePorts};
use crate::scheduler::Ticker;

/// The adapters an engine works through. Each is chosen by the composition root. In a production
/// run every one of them must report fidelity `real` (invariant INV-08).
#[derive(Clone)]
pub struct EngineDeps {
    /// Transactional state, the ledger, the outbox and the audit log.
    pub store: Arc<dyn Store>,
    /// The time, for everything except lease and deadline checks.
    pub clock: Arc<dyn Clock>,
    /// New identifiers.
    pub ids: Arc<dyn IdGenerator>,
    /// Immutable blobs by content hash.
    pub artifacts: Arc<dyn ArtifactStore>,
    /// Creates verified sandboxes.
    pub sandbox: Arc<dyn SandboxProvider>,
    /// Creates job workspaces.
    pub workspaces: Arc<dyn WorkspaceProvider>,
    /// Runs an agent tool inside a sandbox.
    pub runtime: Arc<dyn AgentRuntime>,
    /// Chooses a runtime and a model.
    pub router: Arc<dyn ModelRouter>,
    /// Finds agent manifests and prompts.
    pub registry: Arc<dyn AgentRegistry>,
    /// Checks a document against its schema.
    pub validator: Arc<dyn OutputValidator>,
    /// Issues, revokes and meters job tokens.
    pub broker: Arc<dyn ModelBroker>,
    /// Says who may do what.
    pub authority: Arc<dyn Authority>,
    /// Waits between heartbeats and during a teardown. The engine has no timer of its own.
    pub ticker: Arc<dyn Ticker>,
}

impl std::fmt::Debug for EngineDeps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EngineDeps { .. }")
    }
}

/// Every component the engine works through, with the fidelity it reports: the adapters, the
/// authority, and each stage handler.
#[must_use]
pub fn components_of(deps: &EngineDeps, handlers: &HandlerRegistry) -> Vec<(String, Fidelity)> {
    let mut components = vec![
        ("store".to_owned(), deps.store.fidelity()),
        ("clock".to_owned(), deps.clock.fidelity()),
        ("id generator".to_owned(), deps.ids.fidelity()),
        ("artifact store".to_owned(), deps.artifacts.fidelity()),
        ("sandbox provider".to_owned(), deps.sandbox.fidelity()),
        ("workspace provider".to_owned(), deps.workspaces.fidelity()),
        ("agent runtime".to_owned(), deps.runtime.fidelity()),
        ("model router".to_owned(), deps.router.fidelity()),
        ("agent registry".to_owned(), deps.registry.fidelity()),
        ("model broker".to_owned(), deps.broker.fidelity()),
        ("authority".to_owned(), deps.authority.fidelity()),
        ("ticker".to_owned(), deps.ticker.fidelity()),
    ];
    for handler in handlers.all() {
        components.push((
            format!("stage handler {}", handler.kind()),
            handler.fidelity(),
        ));
    }
    components
}

/// Refuses a fake in a production run (invariant INV-08). Returns the lowest fidelity among the
/// components, which is the fidelity of every record the engine makes.
///
/// # Errors
/// [`EngineError::FakeRefused`], naming the first fake component, in production mode. In test mode
/// every fidelity is allowed.
pub fn refuse_fakes(
    mode: factory_domain::vocabulary::ExecutionMode,
    components: &[(String, Fidelity)],
) -> Result<Fidelity, EngineError> {
    let mut lowest = Fidelity::Real;
    for (component, fidelity) in components {
        require_permitted(mode, component, *fidelity)?;
        if *fidelity == Fidelity::Fake {
            lowest = Fidelity::Fake;
        }
    }
    Ok(lowest)
}

/// The workflow engine.
///
/// An engine holds no state of its own about any job. Two engines on the same store, in the same
/// process or in two, work on the same jobs without double work: the store's claim and its
/// compare-and-swap decide who wins each move.
pub struct Engine {
    pub(crate) deps: EngineDeps,
    pub(crate) config: EngineConfig,
    pub(crate) handlers: HandlerRegistry,
    pub(crate) fidelity: RecorderFidelity,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("mode", &self.config.mode)
            .field("handlers", &self.handlers)
            .finish_non_exhaustive()
    }
}

impl Engine {
    /// Builds an engine, after checking its configuration and refusing a fake in a production run.
    ///
    /// # Errors
    /// * [`EngineError::Config`] when the configuration cannot be used.
    /// * [`EngineError::FakeRefused`], naming the component, when the mode is production and any
    ///   adapter or stage handler reports fidelity `fake` (invariant INV-08). The engine does not
    ///   start, and nothing is written.
    pub fn new(
        deps: EngineDeps,
        config: EngineConfig,
        handlers: HandlerRegistry,
    ) -> Result<Self, EngineError> {
        config.validate()?;
        let components = components_of(&deps, &handlers);
        let lowest = refuse_fakes(config.mode, &components)?;
        Ok(Self {
            deps,
            config,
            handlers,
            fidelity: RecorderFidelity::from(lowest),
        })
    }

    /// The configuration the engine runs under.
    #[must_use]
    pub const fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Opens a transaction that sees only the rows of `tenant`.
    pub(crate) async fn tenant_tx(&self, tenant: TenantId) -> Result<Box<dyn Tx>, EngineError> {
        Ok(self.deps.store.begin(TenantScope::new(tenant)).await?)
    }

    /// Opens the read-only transaction that sees every tenant. Used only to find work; it cannot
    /// write.
    pub(crate) async fn system_tx(&self) -> Result<Box<dyn SystemTx>, EngineError> {
        Ok(self.deps.store.begin_system(SystemScope::engine()).await?)
    }

    pub(crate) fn new_event_id(&self) -> EventId {
        EventId::from_uuid(self.deps.ids.new_uuid())
    }

    pub(crate) fn new_attempt_id(&self) -> AttemptId {
        AttemptId::from_uuid(self.deps.ids.new_uuid())
    }

    pub(crate) fn new_stage_run_id(&self) -> StageRunId {
        StageRunId::from_uuid(self.deps.ids.new_uuid())
    }

    pub(crate) fn new_causation_id(&self) -> CausationId {
        CausationId::from_uuid(self.deps.ids.new_uuid())
    }

    /// The ports a handler may use, as references into this engine.
    ///
    /// The agent runtime is not the engine's own: it is `runtime`, which the caller builds with
    /// `ObservedRuntime::new` around the engine's runtime, so that every agent run a handler
    /// starts is a `factory.agent` span (see `agent_span`).
    pub(crate) fn stage_ports<'a>(&'a self, runtime: &'a dyn AgentRuntime) -> StagePorts<'a> {
        StagePorts {
            artifacts: self.deps.artifacts.as_ref(),
            sandbox: self.deps.sandbox.as_ref(),
            workspaces: self.deps.workspaces.as_ref(),
            runtime,
            router: self.deps.router.as_ref(),
            registry: self.deps.registry.as_ref(),
            validator: self.deps.validator.as_ref(),
            broker: self.deps.broker.as_ref(),
            clock: self.deps.clock.as_ref(),
            ids: self.deps.ids.as_ref(),
        }
    }
}
