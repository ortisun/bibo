//! What the architecture and planning stages need from the outside and no port offers. Each is a
//! small trait that the composition root implements and the tests implement with a list. The
//! schema check, the runtime probes, the sandbox spec factory and the closed `SeamError` are the
//! ones the other agent stages use, so the composition root builds each once.

use async_trait::async_trait;
use factory_domain::contracts::{ArtifactRef, GateReport};
use factory_domain::policy::risk::RiskFacts;
use factory_domain::vocabulary::RiskTier;

use crate::handlers::RunIdentity;

pub use crate::stages::implementation::seams::{
    AgentOutputCheck, CapabilityProbes, SeamError, WorkspaceAgentSpecs,
};

/// What is known about the risk of the job before the design exists. The composition root builds it
/// from the intake classification and the domain profile. The design adds the facts it shows, and
/// the policy engine computes the tier from both.
#[derive(Debug, Clone, Copy, Default)]
pub struct JobRisk {
    /// The facts the job already shows, such as a regulated workflow.
    pub facts: RiskFacts,
    /// The tier an earlier agent claimed. It can raise the tier and never lowers it.
    pub agent_claim: Option<RiskTier>,
}

/// Where the stage learns the risk facts of the job.
#[async_trait]
pub trait RiskSource: Send + Sync {
    /// The facts for the job of this run.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`] when they cannot be read. The stage fails closed: it does not
    /// guess a low tier.
    async fn of(&self, run: &RunIdentity) -> Result<JobRisk, SeamError>;
}

/// The round of rework that this stage run replaces: why it was sent back, and what it produced.
#[derive(Debug, Clone)]
pub struct PreviousRound {
    /// Which round this run is, from 1 for the first rework.
    pub round: u8,
    /// The reports of the gates that failed, as the stage that ran them stored them.
    pub failed_reports: Vec<GateReport>,
    /// The version of the plan the replaced run made, for the planning stage. Zero for the
    /// architecture stage.
    pub plan_version: u32,
    /// The plan the replaced run made, for the planning stage, so that the tasks that were sound
    /// can be kept.
    pub previous_plan: Option<ArtifactRef>,
}

/// Where the stage learns that its run replaces another one, and why. The engine hands a handler
/// no feedback, so the composition root implements this over the stage runs and the artifacts the
/// store holds.
#[async_trait]
pub trait RoundSource: Send + Sync {
    /// The earlier round, or `None` for a first run.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`] when the store cannot be read. The stage fails closed: a rework
    /// run that cannot read its feedback must not run as if it were a first run.
    async fn previous(&self, run: &RunIdentity) -> Result<Option<PreviousRound>, SeamError>;
}
