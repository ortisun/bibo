//! What the engine hands to a stage handler: who the run is, the ports it may use, and what
//! earlier stages and people produced.
//!
//! A handler gets references to ports and never an engine type. It cannot read or write a status,
//! open a transaction or reach another job. Whatever it learns about other stage runs comes in as
//! [`UpstreamRun`] values that the engine built from stored state.

use std::sync::{Arc, Mutex};

use factory_domain::contracts::{ArtifactRef, StageContract};
use factory_domain::ids::{AttemptId, CorrelationId, JobId, StageRunId, TenantId};
use factory_domain::state::StageRunStatus;
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_domain::vocabulary::{ExecutionMode, StageKind};
use factory_ports::agent::{AgentRuntime, JobTokenRef, ModelBroker, ModelRouter};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::{CancelSignal, Clock, IdGenerator};
use factory_ports::registry::{AgentRegistry, OutputValidator};
use factory_ports::sandbox::SandboxProvider;
use factory_ports::store::LeaseEpoch;
use factory_ports::workspace::WorkspaceProvider;

use super::output::NamedArtifact;
use crate::audit::AuditAction;

/// Who a run is: the tenant, the job, the stage run and the stage kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunIdentity {
    /// The tenant that owns the job.
    pub tenant: TenantId,
    /// The job.
    pub job: JobId,
    /// Shared by every event and log line of the job.
    pub correlation: CorrelationId,
    /// The stage run.
    pub stage_run: StageRunId,
    /// Which stage it is a run of.
    pub kind: StageKind,
}

/// A stage run of the same job that this one builds on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamRun {
    /// The run.
    pub id: StageRunId,
    /// Its stage kind.
    pub kind: StageKind,
    /// `PASSED`, or `SKIPPED` by a recorded rule. A skipped run produced no output.
    pub status: StageRunStatus,
    /// What it produced, by deliverable name. Empty for a skipped run.
    pub outputs: Vec<NamedArtifact>,
}

/// The ports a handler may use. Each is a reference, so a handler cannot keep one past its call.
#[derive(Clone, Copy)]
pub struct StagePorts<'a> {
    /// Immutable blobs by content hash.
    pub artifacts: &'a dyn ArtifactStore,
    /// Creates verified sandboxes.
    pub sandbox: &'a dyn SandboxProvider,
    /// Creates job workspaces.
    pub workspaces: &'a dyn WorkspaceProvider,
    /// Runs an agent tool inside a sandbox.
    pub runtime: &'a dyn AgentRuntime,
    /// Chooses a runtime and a model.
    pub router: &'a dyn ModelRouter,
    /// Finds agent manifests and prompts.
    pub registry: &'a dyn AgentRegistry,
    /// Checks a document against its schema.
    pub validator: &'a dyn OutputValidator,
    /// Reads what the broker metered for a token.
    pub broker: &'a dyn ModelBroker,
    /// The time, for everything except lease and deadline checks.
    pub clock: &'a dyn Clock,
    /// New identifiers.
    pub ids: &'a dyn IdGenerator,
}

impl std::fmt::Debug for StagePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StagePorts { .. }")
    }
}

/// What a handler needs to resolve the stage contract (and to say whether the stage applies).
#[derive(Debug, Clone, Copy)]
pub struct ContractContext<'a> {
    /// Who the run is.
    pub identity: RunIdentity,
    /// Test mode allows fakes. Production mode does not.
    pub mode: ExecutionMode,
    /// The hash of the policy bundle in force.
    pub policy_hash: &'a Sha256Digest,
    /// When the engine asked.
    pub now: Timestamp,
    /// The runs this one builds on, in pipeline order.
    pub upstream: &'a [UpstreamRun],
    /// The answers people gave to this stage run, oldest first. Each is an input of the stage:
    /// resolving the contract again with a new answer gives a new input hash.
    pub human_inputs: &'a [ArtifactRef],
}

/// What the handler tells the engine about the sandbox it provisioned. The facts are the ones
/// guard `G_SANDBOX_PROVISIONED` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxReady {
    /// The sandbox started within its limits and passed its posture check.
    pub started_within_limits: bool,
    /// The tool grants that policy approved are in place.
    pub tool_grants_in_place: bool,
    /// The runtime capability probe satisfies what the stage needs.
    pub capability_probe_satisfied: bool,
}

/// What a handler noted while it ran, for the engine to record with the attempt result.
#[derive(Debug, Default)]
pub(crate) struct AttemptNotes {
    pub(crate) audit: Vec<AuditAction>,
    pub(crate) sandbox_ready: Option<SandboxReady>,
}

/// The notes of one attempt, shared between the handler that writes them and the engine that
/// reads them while the handler is still running.
#[derive(Debug, Clone, Default)]
pub(crate) struct Notes(Arc<Mutex<AttemptNotes>>);

impl Notes {
    fn lock(&self) -> std::sync::MutexGuard<'_, AttemptNotes> {
        // A panic in a handler must not hide what it noted before it, so a poisoned lock is read
        // as it is.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// What the handler said about its sandbox, if it said anything yet.
    pub(crate) fn sandbox_ready(&self) -> Option<SandboxReady> {
        self.lock().sandbox_ready
    }

    /// Takes the audit actions the handler noted, leaving none behind.
    pub(crate) fn take_audit(&self) -> Vec<AuditAction> {
        std::mem::take(&mut self.lock().audit)
    }
}

/// Everything `execute` receives.
pub struct StageContext<'a> {
    /// Who the run is.
    pub identity: RunIdentity,
    /// The attempt.
    pub attempt: AttemptId,
    /// Which try this is for the stage run, from 1.
    pub attempt_number: u32,
    /// The fencing epoch of the lease. The engine sends it with every write for the attempt.
    pub epoch: LeaseEpoch,
    /// Test mode allows fakes. Production mode does not.
    pub mode: ExecutionMode,
    /// The resolved contract: inputs, granted tools, deliverables, budget, limits.
    pub contract: &'a StageContract,
    /// The ports.
    pub ports: StagePorts<'a>,
    /// Trips when the engine cancels the attempt: the job is cancelling, the stage run was
    /// superseded, or the lease was lost. Pass it to every long operation.
    pub cancel: &'a dyn CancelSignal,
    /// The job token that the engine issued for this attempt, when the stage runs an agent. The
    /// secret is never in this value.
    pub job_token: Option<JobTokenRef>,
    /// The answers people gave to this stage run, oldest first.
    pub human_inputs: &'a [ArtifactRef],
    /// The runs this one builds on.
    pub upstream: &'a [UpstreamRun],
    pub(crate) notes: Notes,
}

impl std::fmt::Debug for StageContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StageContext")
            .field("identity", &self.identity)
            .field("attempt", &self.attempt)
            .field("attempt_number", &self.attempt_number)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl<'a> StageContext<'a> {
    /// Builds a context. The engine calls this; a test of a handler may too.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity: RunIdentity,
        attempt: AttemptId,
        attempt_number: u32,
        epoch: LeaseEpoch,
        mode: ExecutionMode,
        contract: &'a StageContract,
        ports: StagePorts<'a>,
        cancel: &'a dyn CancelSignal,
        job_token: Option<JobTokenRef>,
        human_inputs: &'a [ArtifactRef],
        upstream: &'a [UpstreamRun],
    ) -> Self {
        Self {
            identity,
            attempt,
            attempt_number,
            epoch,
            mode,
            contract,
            ports,
            cancel,
            job_token,
            human_inputs,
            upstream,
            notes: Notes::default(),
        }
    }

    /// Shares the notes with the engine, which reads them while the handler runs.
    #[must_use]
    pub(crate) fn with_notes(mut self, notes: Notes) -> Self {
        self.notes = notes;
        self
    }

    /// Tells the engine that the sandbox is up and the preconditions of the agent run hold.
    /// The engine then moves the attempt from `STARTING` to `RUNNING` (`A01`). A stage that
    /// needs no sandbox never calls this.
    pub fn report_sandbox_ready(&mut self, ready: SandboxReady) {
        self.notes.lock().sandbox_ready = Some(ready);
    }

    /// Asks the engine to record an audit event of a kind that only the handler sees, such as a
    /// command it ran. The engine writes it with the actor, the policy hash and the correlation
    /// id when it records the attempt result.
    pub fn note_audit(&mut self, action: AuditAction) {
        self.notes.lock().audit.push(action);
    }
}

/// Everything `evaluate` receives.
pub struct GateContext<'a> {
    /// Who the run is.
    pub identity: RunIdentity,
    /// The attempt whose output is being judged.
    pub attempt: AttemptId,
    /// Test mode allows fakes. Production mode does not.
    pub mode: ExecutionMode,
    /// The resolved contract: acceptance criteria, evaluator, gate ids.
    pub contract: &'a StageContract,
    /// The ports.
    pub ports: StagePorts<'a>,
    /// What the attempt produced and the engine stored, by deliverable name.
    pub outputs: &'a [NamedArtifact],
    /// The answers people gave to this stage run, oldest first.
    pub human_inputs: &'a [ArtifactRef],
    /// The runs this one builds on.
    pub upstream: &'a [UpstreamRun],
}

impl std::fmt::Debug for GateContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GateContext")
            .field("identity", &self.identity)
            .field("attempt", &self.attempt)
            .finish_non_exhaustive()
    }
}
