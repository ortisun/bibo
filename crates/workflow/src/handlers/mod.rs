//! The stage handler: the one trait that a stage package implements.
//!
//! A handler holds no engine type and writes no status. It resolves the stage contract, does the
//! work, and collects the evidence a gate needs. The engine does everything else: it claims the
//! stage run, holds the lease, validates and stores the output, evaluates the guard, applies the
//! transition and records the ledger entries and the outbox event, all in one transaction.
//!
//! The trait contains no engine type on purpose (ADR 0001, "The seam"): a handler could run as an
//! activity of another engine unchanged.

mod context;
mod output;
mod registry;

use async_trait::async_trait;
use factory_domain::contracts::StageContract;
use factory_domain::values::{HumanText, Slug};
use factory_domain::vocabulary::{Fidelity, StageKind};
use factory_ports::agent::RoutingNeed;

pub(crate) use context::Notes;
pub use context::{
    ContractContext, DurableRecords, GateContext, RunIdentity, SandboxReady, StageContext,
    StagePorts, UpstreamRun,
};
pub use output::{
    NamedArtifact, NeedsHumanRequest, OpenedPullRequest, OutputDocument, StageError, StageOutput,
};
pub use registry::{HandlerRegistry, RegistryError};

use crate::gates::framework::GateDecision;

/// Whether a stage has work to do for a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applicability {
    /// The stage runs.
    Applies,
    /// A deterministic rule, a domain profile or a policy says the stage does not apply. The
    /// engine skips the run (`S02`) and records the rule and its inputs in the ledger. An agent's
    /// opinion is never a reason.
    NotApplicable(SkipRule),
}

/// The recorded reason a stage is skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkipRule {
    /// What states that the stage does not apply.
    pub basis: SkipBasis,
    /// The rule, profile or policy clause, such as `docs-only-change`.
    pub rule: Slug,
    /// What the rule saw, in plain English. It goes in the ledger, so it names no secret.
    pub inputs: HumanText,
}

/// What a skip rests on. An agent's opinion is not among them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipBasis {
    /// A deterministic rule.
    DeterministicRule,
    /// A domain profile.
    DomainProfile,
    /// A policy.
    Policy,
}

/// The only thing a stage package implements.
///
/// # Preconditions
/// A handler is registered for exactly one stage kind. It holds no state that outlives a run: the
/// engine may call it again after a restart, from another process.
///
/// # Postconditions
/// `contract` is pure given the same context. `execute` returns the documents the stage
/// produced and never decides that the stage passed. `evaluate` returns typed evidence and never
/// a verdict. The engine validates and stores both before it records anything.
///
/// # Errors
/// [`StageError`], a closed set. A handler never returns free text from an agent.
///
/// # Idempotency
/// `execute` may run more than once for one stage run (a retry, or a second attempt after the
/// lease was lost), and its side effects must be safe to repeat: use the attempt id or the stage
/// run id as the idempotency key for anything outside the sandbox.
#[async_trait]
pub trait StageHandler: Send + Sync {
    /// Says whether this handler drives the real systems (`real`) or is a scripted stand-in
    /// (`fake`). A production run refuses a handler that reports `fake`.
    fn fidelity(&self) -> Fidelity;

    /// The stage this handler runs.
    fn kind(&self) -> StageKind;

    /// Whether the stage has work to do. The default is that it does.
    fn applicability(&self, _ctx: &ContractContext<'_>) -> Applicability {
        Applicability::Applies
    }

    /// What model the stage needs, when it runs an agent. The engine asks the router before it
    /// starts the stage, so a stage whose runtime lacks a required capability does not start
    /// (guard `G_LEASE_ACQUIRED`, the runtime capability check). The default is no agent.
    fn routing_need(&self, _ctx: &ContractContext<'_>) -> Option<RoutingNeed> {
        None
    }

    /// The need of a reviewer that runs inside the same stage run as the writer whose work it
    /// reviews, such as the specification reviewer. The engine routes it against the model it
    /// chose for [`routing_need`](Self::routing_need) (the need's `author`), and the job token of
    /// the attempt holds both models. When no model is independent of the writer, the stage run
    /// waits for a person before any agent runs. The default is no such reviewer.
    fn reviewer_routing_need(&self, _ctx: &ContractContext<'_>) -> Option<RoutingNeed> {
        None
    }

    /// Resolves the contract for this run from the manifest, the profile, the policy and the
    /// inputs.
    ///
    /// # Errors
    /// A [`StageError`] when the contract cannot be resolved.
    fn contract(&self, ctx: &ContractContext<'_>) -> Result<StageContract, StageError>;

    /// Does the work. May use agents, sandboxes and workspaces. Never writes a status.
    ///
    /// # Errors
    /// A [`StageError`] for a failure. The engine classifies it and decides what happens next.
    async fn execute(&self, ctx: &mut StageContext<'_>) -> Result<StageOutput, StageError>;

    /// Collects the gate evidence from stored artifacts. Agent prose is never proof.
    ///
    /// # Errors
    /// A [`StageError`] when the evidence cannot be collected. A gate that could not run is
    /// `StageError::Blocked`, never a pass.
    async fn evaluate(&self, ctx: &GateContext<'_>) -> Result<GateDecision, StageError>;
}
