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
use factory_ports::agent::{AgentRunReport, AgentRuntime, JobTokenRef, ModelBroker, ModelRouter};
use factory_ports::artifact::ArtifactStore;
use factory_ports::clock::{CancelSignal, Clock, IdGenerator};
use factory_ports::registry::{AgentRegistry, OutputValidator};
use factory_ports::sandbox::SandboxProvider;
use factory_ports::store::LeaseEpoch;
use factory_ports::workspace::WorkspaceProvider;

use super::output::{NamedArtifact, StageError};
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
    /// The source request was edited after the intake snapshot. The intake stage must ask for
    /// re-authorization before an agent reads the new text (NT-AUTHZ-05). It is true only for an
    /// `INTAKE` run that replaced an earlier one: the engine reads it from the run number, since
    /// an edit is the only thing that replaces an `INTAKE` run.
    pub request_edited: bool,
}

/// What the handler tells the engine about the sandbox it provisioned. The facts are the ones
/// guard `G_SANDBOX_PROVISIONED` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxReady {
    /// The sandbox provider returned a session, which means it read the container's posture
    /// back and found every part equal to the spec and the policy. Set from that and from nothing
    /// else.
    pub posture_verified: bool,
    /// The tool grants that policy approved are recorded in the audit log.
    pub tool_grants_recorded: bool,
    /// The runtime probe of this attempt supports every capability the stage needs.
    pub probe_satisfies_stage: bool,
}

/// What a handler noted while it ran, for the engine to record with the attempt result.
#[derive(Debug, Default)]
pub(crate) struct AttemptNotes {
    pub(crate) audit: Vec<AuditAction>,
    /// Audit events the engine's own wrappers of the ports noted while the handler ran (the sandbox
    /// it used, the commands it ran), each with the reason to store. See `engine::sandbox_audit`.
    pub(crate) facts: Vec<(AuditAction, String)>,
    pub(crate) sandbox_ready: Option<SandboxReady>,
    pub(crate) cost_micro_usd: u64,
    /// The transcripts of runs the handler wants the tenant to be able to read back: those of a
    /// run that failed, and those a stage asks to keep (see `StageContext::note_transcript`).
    pub(crate) transcripts: Vec<ArtifactRef>,
    /// How many tool calls policy denied in a run that failed.
    pub(crate) denials: usize,
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

    /// Records what the attempt spent, as the broker metered it.
    pub(crate) fn set_cost(&self, micro_usd: u64) {
        self.lock().cost_micro_usd = micro_usd;
    }

    /// What the attempt spent, in millionths of a US dollar.
    pub(crate) fn cost(&self) -> u64 {
        self.lock().cost_micro_usd
    }

    /// The transcripts the handler noted so far, left in place.
    pub(crate) fn transcripts(&self) -> Vec<ArtifactRef> {
        self.lock().transcripts.clone()
    }

    /// Takes the transcripts the handler noted, leaving none behind.
    pub(crate) fn take_transcripts(&self) -> Vec<ArtifactRef> {
        std::mem::take(&mut self.lock().transcripts)
    }

    /// Takes the number of denied tool calls of a failed run, leaving none behind.
    pub(crate) fn take_denials(&self) -> usize {
        std::mem::take(&mut self.lock().denials)
    }

    /// Takes the audit actions the handler noted, leaving none behind.
    pub(crate) fn take_audit(&self) -> Vec<AuditAction> {
        std::mem::take(&mut self.lock().audit)
    }

    /// Notes an audit event that the engine's own wrapper of a port saw, with the reason to store.
    pub(crate) fn note_fact(&self, action: AuditAction, reason: String) {
        self.lock().facts.push((action, reason));
    }

    /// Takes the facts the wrappers noted, in the order they happened, leaving none behind.
    pub(crate) fn take_facts(&self) -> Vec<(AuditAction, String)> {
        std::mem::take(&mut self.lock().facts)
    }

    /// The reasons of the facts noted so far, in order, leaving them in place.
    pub(crate) fn fact_reasons(&self) -> Vec<String> {
        self.lock()
            .facts
            .iter()
            .map(|(_, reason)| reason.clone())
            .collect()
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
    /// Where a record is written at once, in a transaction of its own. The engine sets it; a
    /// context built without an engine (a test of a handler) has none.
    pub(crate) durable: Option<&'a dyn DurableRecords>,
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
            durable: None,
        }
    }

    /// Gives the context a way to write a record at once (DR-3). The engine calls this, and so
    /// may a test of a handler that wants to see what is written before the handler acts.
    #[must_use]
    pub fn with_durable(mut self, durable: &'a dyn DurableRecords) -> Self {
        self.durable = Some(durable);
        self
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

    /// Keeps what a run that failed left behind. An agent run always returns a report, with its
    /// usage, its transcript and the tool calls policy denied, even when it has no output
    /// (ports v1.1). A handler that turns a failed report into a `StageError` calls this first, so
    /// the failure does not discard the evidence: the engine records each denial in the audit
    /// log and indexes the transcript for the tenant, with the result of the attempt. What the
    /// run spent is read from the broker, so it is not repeated here.
    pub fn note_failed_run(&mut self, report: &AgentRunReport) {
        let mut notes = self.notes.lock();
        if let Some(transcript) = &report.transcript {
            notes.transcripts.push(transcript.clone());
        }
        notes.denials = notes
            .denials
            .saturating_add(report.permission_denials.len());
    }

    /// Asks the engine to keep the transcript of a run for the tenant, with the result of the
    /// attempt. A stage whose gate reads a transcript back (the specification stage scans the
    /// transcripts of its skills for a skill outside the profile) calls this for each run, because
    /// the runtime stores the blob and nobody has indexed it for the tenant: without the index the
    /// gate cannot read what it must check, and it fails closed.
    pub fn note_transcript(&mut self, transcript: &ArtifactRef) {
        self.notes.lock().transcripts.push(transcript.clone());
    }

    /// Asks the engine to record an audit event of a kind that only the handler sees, such as a
    /// command it ran. The engine writes it with the actor, the policy hash and the correlation
    /// id when it records the attempt result.
    pub fn note_audit(&mut self, action: AuditAction) {
        self.notes.lock().audit.push(action);
    }

    /// Like [`note_audit`](Self::note_audit), with the reason to store on the record: fixed words,
    /// numbers, the names of labels cleaned for display. The engine cuts a reason longer than 1000
    /// bytes. A reason never holds the text of an issue or of a comment.
    pub fn note_audit_because(&mut self, action: AuditAction, reason: String) {
        self.notes.note_fact(action, reason);
    }

    /// Writes an audit record **now**, in a transaction of its own, and returns when it is
    /// committed (DR-3). A handler uses it for the record of a decision that comes before an act
    /// on the world that cannot be taken back, such as a comment on an issue: the record then
    /// does not wait for the attempt to end, and a cancel, a lost lease or a crash after it
    /// cannot drop it. Everything else is noted with [`note_audit_because`](Self::note_audit_because).
    ///
    /// The record is written whatever the state of the lease: it is a fact about a decision that
    /// was taken, an audit row changes no aggregate, and the epoch check (INV-05) guards the
    /// writes that do.
    ///
    /// A context that has no engine behind it (a test of a handler) cannot write: the record is
    /// noted, and the engine of a real run is the only place where it is durable.
    ///
    /// # Errors
    /// [`StageError::Tool`] when the store cannot take the record. The handler must then not act:
    /// the attempt fails and is tried again.
    pub async fn record_now(
        &mut self,
        action: AuditAction,
        reason: String,
    ) -> Result<(), StageError> {
        match self.durable {
            Some(records) => records.record(action, reason).await,
            None => {
                self.note_audit_because(action, reason);
                Ok(())
            }
        }
    }

    /// The reasons of the audit records the handler has noted with
    /// [`note_audit_because`](Self::note_audit_because) so far, in order. The engine takes the
    /// records itself when the attempt ends; this reads them without taking them, so that a test
    /// of a handler can say what the handler put on the record.
    #[must_use]
    pub fn noted_reasons(&self) -> Vec<String> {
        self.notes.fact_reasons()
    }
}

/// Writes one audit record at once, in a transaction of its own, for the attempt that holds the
/// context (DR-3). The engine implements it over the store; a test of a handler may implement it
/// to see the records in the order the handler writes them.
#[async_trait::async_trait]
pub trait DurableRecords: Send + Sync {
    /// Commits one audit record of the stage handler of the attempt.
    async fn record(&self, action: AuditAction, reason: String) -> Result<(), StageError>;
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
    /// Trips when the engine cancels the attempt. Pass it to every long operation, such as a
    /// command in a fresh sandbox.
    pub cancel: &'a dyn CancelSignal,
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
