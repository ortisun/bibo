//! One agent runtime that serves every tenant (mismatch 7 of the worker README).
//!
//! The runtime adapters bind one tenant when they are built: their I/O takes a `TenantScope`, and
//! `AgentRunRequest` carries no tenant. The worker serves many tenants, one attempt at a time.
//! [`TenantRuntimes`] stands in front of them. It is built with a factory that makes the runtime
//! for a tenant, and it finds the tenant of each call in [`ActiveJobs`], which the loop fills when
//! it claims an attempt:
//!
//! * `run` is asked about an attempt, and the tenant of that attempt is exact;
//! * `probe` is asked about a session only, so it uses the tenant of the one attempt that runs.
//!   With none or more than one running it answers `ProbeFailed` and guesses nothing (the
//!   Slice 1 worker runs one attempt at a time).
//!
//! A tenant's runtime is made on first use and kept. An attempt of a tenant the loop does not know
//! is refused the way the other wrappers refuse: it fails closed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use factory_domain::ids::TenantId;
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{
    AgentRunError, AgentRunReport, AgentRunRequest, AgentRuntime, ProbeError, RuntimeCapabilities,
    RuntimeId, Usage,
};
use factory_ports::clock::CancelSignal;
use factory_ports::sandbox::SandboxSession;

use crate::indexing::ActiveJobs;

/// Makes the runtime for one tenant.
pub type RuntimeFactory = dyn Fn(TenantId) -> Option<Arc<dyn AgentRuntime>> + Send + Sync;

/// A runtime that dispatches by tenant.
pub struct TenantRuntimes {
    id: RuntimeId,
    fidelity: Fidelity,
    jobs: Arc<ActiveJobs>,
    factory: Box<RuntimeFactory>,
    made: Mutex<HashMap<TenantId, Arc<dyn AgentRuntime>>>,
}

impl TenantRuntimes {
    /// A dispatcher for the runtime named `id`. `fidelity` is the fidelity of what `factory` makes:
    /// a dispatcher cannot know before it makes one.
    #[must_use]
    pub fn new(
        id: RuntimeId,
        fidelity: Fidelity,
        jobs: Arc<ActiveJobs>,
        factory: Box<RuntimeFactory>,
    ) -> Self {
        Self {
            id,
            fidelity,
            jobs,
            factory,
            made: Mutex::new(HashMap::new()),
        }
    }

    fn runtime_for(&self, tenant: TenantId) -> Option<Arc<dyn AgentRuntime>> {
        let mut made = self.made.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(found) = made.get(&tenant) {
            return Some(Arc::clone(found));
        }
        let runtime = (self.factory)(tenant)?;
        made.insert(tenant, Arc::clone(&runtime));
        Some(runtime)
    }

    /// How many tenants have a runtime now.
    #[must_use]
    pub fn made(&self) -> usize {
        self.made
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[async_trait]
impl AgentRuntime for TenantRuntimes {
    fn id(&self) -> &RuntimeId {
        &self.id
    }

    fn fidelity(&self) -> Fidelity {
        self.fidelity
    }

    async fn probe(
        &self,
        session: &mut dyn SandboxSession,
    ) -> Result<RuntimeCapabilities, ProbeError> {
        let runtime = self
            .jobs
            .sole_tenant()
            .and_then(|tenant| self.runtime_for(tenant))
            .ok_or(ProbeError::ProbeFailed(
                factory_ports::agent::ProbeStep::Version,
            ))?;
        runtime.probe(session).await
    }

    async fn run(
        &self,
        session: &mut dyn SandboxSession,
        req: AgentRunRequest,
        cancel: &dyn CancelSignal,
    ) -> AgentRunReport {
        let runtime = self
            .jobs
            .tenant_of_attempt(req.attempt)
            .and_then(|tenant| self.runtime_for(tenant));
        match runtime {
            Some(runtime) => runtime.run(session, req, cancel).await,
            None => AgentRunReport {
                outcome: Err(AgentRunError::AuthenticationRequired),
                transcript: None,
                usage: Usage::default(),
                runtime_version: None,
                exit: None,
                permission_denials: Vec::new(),
            },
        }
    }
}

// ---------------------------------------------------------------------------------------------
// One runtime for every tool
// ---------------------------------------------------------------------------------------------

/// The runtimes of a deployment behind the one `AgentRuntime` the engine holds.
///
/// The engine has a single runtime port, and the router may choose between two tools (the Claude
/// Code tool and the Codex tool). The set dispatches a run by the runtime the router chose, which
/// the request carries in `model.runtime`.
///
/// A probe does not say which tool it is for: the session is the only argument. The set therefore
/// probes **every** member in that session and reports only what **all** of them support, so a stage
/// that requires a capability finds it whichever tool the router picks. A member that fails its
/// probe fails the probe of the set; the cause is not hidden.
pub struct RuntimeSet {
    id: RuntimeId,
    members: std::collections::BTreeMap<RuntimeId, Arc<dyn AgentRuntime>>,
}

impl RuntimeSet {
    /// A set of the given runtimes, or `None` for none. The set is named after its members.
    #[must_use]
    pub fn new(members: Vec<Arc<dyn AgentRuntime>>) -> Option<Self> {
        if members.is_empty() {
            return None;
        }
        let map: std::collections::BTreeMap<RuntimeId, Arc<dyn AgentRuntime>> = members
            .into_iter()
            .map(|runtime| (runtime.id().clone(), runtime))
            .collect();
        let name = map
            .keys()
            .map(RuntimeId::as_str)
            .collect::<Vec<_>>()
            .join("-and-");
        let id = RuntimeId::new(&name).ok()?;
        Some(Self { id, members: map })
    }

    /// The runtimes in the set.
    #[must_use]
    pub fn ids(&self) -> Vec<RuntimeId> {
        self.members.keys().cloned().collect()
    }
}

fn only_what_both_support(a: RuntimeCapabilities, b: &RuntimeCapabilities) -> RuntimeCapabilities {
    RuntimeCapabilities {
        runtime_version: format!("{}+{}", a.runtime_version, b.runtime_version),
        observations: a
            .observations
            .into_iter()
            .map(|mut observation| {
                observation.supported = observation.supported && b.supports(observation.capability);
                observation
            })
            .collect(),
    }
}

#[async_trait]
impl AgentRuntime for RuntimeSet {
    fn id(&self) -> &RuntimeId {
        &self.id
    }

    fn fidelity(&self) -> Fidelity {
        if self
            .members
            .values()
            .all(|member| member.fidelity() == Fidelity::Real)
        {
            Fidelity::Real
        } else {
            Fidelity::Fake
        }
    }

    async fn probe(
        &self,
        session: &mut dyn SandboxSession,
    ) -> Result<RuntimeCapabilities, ProbeError> {
        let mut merged: Option<RuntimeCapabilities> = None;
        for member in self.members.values() {
            let found = member.probe(session).await?;
            merged = Some(match merged {
                None => found,
                Some(held) => only_what_both_support(held, &found),
            });
        }
        merged.ok_or(ProbeError::ProbeFailed(
            factory_ports::agent::ProbeStep::Version,
        ))
    }

    async fn run(
        &self,
        session: &mut dyn SandboxSession,
        req: AgentRunRequest,
        cancel: &dyn CancelSignal,
    ) -> AgentRunReport {
        match self.members.get(&req.model.runtime) {
            Some(member) => member.run(session, req, cancel).await,
            // The router chose a runtime this deployment does not have: fail closed, as an
            // unknown tenant does.
            None => AgentRunReport {
                outcome: Err(AgentRunError::AuthenticationRequired),
                transcript: None,
                usage: Usage::default(),
                runtime_version: None,
                exit: None,
                permission_denials: Vec::new(),
            },
        }
    }
}
