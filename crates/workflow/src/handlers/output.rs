//! What a stage handler hands back: its output documents, and the ways it can fail.
//!
//! A handler reports. It never marks a stage as passed and never writes a status: the engine
//! validates the output, the gate reads recorded evidence, and the engine applies the result.
//! Nothing here carries free text from an agent, so an error or an output summary can be audited
//! and logged as it is.

use factory_domain::contracts::ArtifactRef;
use factory_domain::contracts::gate_report::BlockedCode;
use factory_domain::machines::failure::FailureClass;
use factory_domain::machines::guards::EnvironmentCause;
use factory_domain::values::{MediaType, Slug};
use factory_ports::agent::{AgentRunError, Denial, ProbeError, Usage};
use factory_ports::registry::ContractKind;
use factory_ports::sandbox::SandboxError;

/// An artifact with the name that the stage contract gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedArtifact {
    /// The name of the deliverable, as in `StageContract::deliverables`.
    pub name: Slug,
    /// The stored bytes.
    pub artifact: ArtifactRef,
}

/// One document a stage produced, before the engine has validated and stored it.
#[derive(Debug, Clone, PartialEq)]
pub struct OutputDocument {
    /// The deliverable it fulfils.
    pub name: Slug,
    /// The contract it must follow, when it follows one of the schemas in `schemas/`. The engine
    /// validates it with the `OutputValidator` before it stores anything.
    pub contract: Option<(ContractKind, u32)>,
    /// The media type to store it under.
    pub media_type: MediaType,
    /// The document. Untrusted until validated.
    pub value: serde_json::Value,
}

/// The agent asked for a person, in a structured way. The reason is a code, not text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeedsHumanRequest {
    /// A short machine code such as `ambiguous-requirement`.
    pub reason: Slug,
    /// What the agent said a person must know or decide, in its words: the reason it is blocked or
    /// the question it asks. Untrusted text, stored with the request so that the person reads why
    /// the stage waits. `None` when the stage has nothing to add to the code.
    pub detail: Option<String>,
}

/// Everything a successful `execute` returns.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StageOutput {
    /// Documents that the engine validates and stores.
    pub documents: Vec<OutputDocument>,
    /// Artifacts the handler already stored itself (a diff, a transcript, a log).
    pub artifacts: Vec<NamedArtifact>,
    /// What the model used, from the broker. The engine adds it to the job's spend.
    pub usage: Usage,
    /// Tool calls that policy denied. The engine records each in the audit log.
    pub permission_denials: Vec<Denial>,
    /// A structured request for a person. The engine escalates (`S07`) and does not retry.
    pub needs_human: Option<NeedsHumanRequest>,
}

/// Why `execute`, `contract` or `evaluate` failed. The set is closed and carries no text.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StageError {
    /// A tool the stage used failed.
    #[error("a tool failed")]
    Tool,
    /// The model provider failed or was unavailable.
    #[error("the model provider failed")]
    Provider,
    /// The sandbox could not start or failed while running.
    #[error("the sandbox failed")]
    Sandbox,
    /// A budget limit was hit. A person decides next, and the job's token is revoked.
    #[error("a budget limit was hit")]
    BudgetExhausted,
    /// Policy denied something the stage tried.
    #[error("policy denied an action")]
    PolicyDenied,
    /// The output did not follow its schema. The engine detects this itself as well.
    #[error("the output is not valid")]
    InvalidOutput,
    /// The stage could not run because a tool, service or capability is missing. At a gate this is
    /// `BLOCKED`, never a pass (invariant INV-06). When the stage itself was running, the stage run
    /// is blocked (`S21`) with the environment cause that [`BlockedCode`] maps to.
    #[error("the stage cannot run: something it needs is missing")]
    Blocked(BlockedCode),
    /// The environment is missing or unsafe: the container runtime is out of reach, the image is
    /// absent, the posture differs from the spec, the spec is weaker than the policy, a tool is
    /// absent, or the policy cannot be loaded. The stage run is blocked (`S21`) and nothing is
    /// retried, with these settings or any other.
    #[error("the environment is missing or unsafe")]
    Environment(EnvironmentCause),
    /// The stage stopped because the engine cancelled it.
    #[error("the stage was cancelled")]
    Cancelled,
    /// A fault in the factory itself.
    #[error("an internal fault")]
    Internal,
}

impl StageError {
    /// The failure class the engine records for an attempt that ends this way, or `None` when the
    /// attempt does not fail (a cancellation is an outcome of its own).
    #[must_use]
    pub const fn failure_class(&self) -> Option<FailureClass> {
        match self {
            Self::Tool => Some(FailureClass::ToolError),
            Self::Provider => Some(FailureClass::ProviderError),
            Self::Sandbox => Some(FailureClass::SandboxError),
            Self::BudgetExhausted => Some(FailureClass::BudgetExhausted),
            Self::PolicyDenied | Self::Blocked(_) => Some(FailureClass::PolicyDenied),
            Self::Environment(cause) => Some(match cause {
                EnvironmentCause::PolicyViolation | EnvironmentCause::PolicyUnloadable => {
                    FailureClass::PolicyDenied
                }
                EnvironmentCause::ToolMissing => FailureClass::ToolError,
                EnvironmentCause::DaemonUnavailable
                | EnvironmentCause::ImageUnavailable
                | EnvironmentCause::PostureMismatch => FailureClass::SandboxError,
            }),
            Self::InvalidOutput => Some(FailureClass::InvalidOutput),
            Self::Internal => Some(FailureClass::Internal),
            Self::Cancelled => None,
        }
    }

    /// The environment cause when the stage ended because something it cannot work without is
    /// missing or unsafe, and `None` for every other failure. The engine takes `S21` first when
    /// there is one, before it considers a retry or a person (`G_ENVIRONMENT_BLOCKED`).
    #[must_use]
    pub const fn environment(&self) -> Option<EnvironmentCause> {
        match self {
            Self::Environment(cause) => Some(*cause),
            Self::Blocked(code) => Some(environment_of(*code)),
            _ => None,
        }
    }
}

/// The environment cause a gate's blocked code stands for when it stops a stage from running.
/// A missing dependency, a missing or unprobeable tool and an unsupported environment all mean a
/// tool or capability the stage needs is absent.
const fn environment_of(code: BlockedCode) -> EnvironmentCause {
    match code {
        BlockedCode::ToolUnavailable
        | BlockedCode::ToolProbeFailed
        | BlockedCode::DependencyUnavailable
        | BlockedCode::EnvironmentUnsupported => EnvironmentCause::ToolMissing,
        BlockedCode::PolicyUnresolvable => EnvironmentCause::PolicyUnloadable,
        // A design that is not approved is a finding of the intake gate. The delivery stage also
        // returns it when it checks the design again before it opens the pull request (DG-8): a
        // policy that stops the run. The stage run is blocked, and it names no gate, so no
        // override passes it.
        BlockedCode::DesignNotApproved => EnvironmentCause::PolicyViolation,
    }
}

impl From<SandboxError> for StageError {
    /// The mapping every stage that provisions a sandbox uses. An environment that is missing or
    /// unsafe blocks the stage run. A provisioning failure, a timeout and a resource limit are
    /// worth another try, so they are not environment causes.
    fn from(error: SandboxError) -> Self {
        match error {
            SandboxError::DaemonUnavailable => {
                Self::Environment(EnvironmentCause::DaemonUnavailable)
            }
            SandboxError::ImageUnavailable => Self::Environment(EnvironmentCause::ImageUnavailable),
            SandboxError::PostureMismatch(_) => {
                Self::Environment(EnvironmentCause::PostureMismatch)
            }
            SandboxError::PolicyViolation(_) => {
                Self::Environment(EnvironmentCause::PolicyViolation)
            }
            SandboxError::Cancelled => Self::Cancelled,
            SandboxError::ProvisionFailed(_)
            | SandboxError::Timeout
            | SandboxError::ResourceExceeded(_)
            | SandboxError::TeardownFailed { .. } => Self::Sandbox,
        }
    }
}

impl From<ProbeError> for StageError {
    /// A tool that is not installed, or in a version the factory does not accept, is an absent
    /// capability and blocks the stage run. A probe command that failed is a tool error.
    fn from(error: ProbeError) -> Self {
        match error {
            ProbeError::BinaryMissing | ProbeError::UnsupportedVersion { .. } => {
                Self::Environment(EnvironmentCause::ToolMissing)
            }
            ProbeError::ProbeFailed(_) => Self::Tool,
        }
    }
}

impl From<AgentRunError> for StageError {
    /// The mapping every agent stage uses, so two stages classify one failure the same way.
    ///
    /// A provider outage or a rate limit is worth retrying. A refused credential is a policy
    /// matter and is never retried. A missing capability blocks. Everything the tool itself did
    /// wrong, including a timeout of the run, is a tool error.
    fn from(error: AgentRunError) -> Self {
        match error {
            AgentRunError::ProviderUnavailable | AgentRunError::RateLimited { .. } => {
                Self::Provider
            }
            AgentRunError::AuthenticationRequired => Self::PolicyDenied,
            AgentRunError::Timeout
            | AgentRunError::ProcessFailed(_)
            | AgentRunError::OutputMissing => Self::Tool,
            // An output over the limit is an output that cannot be used, like one that breaks its
            // schema, so it counts against the repair cap.
            AgentRunError::OutputTooLarge => Self::InvalidOutput,
            AgentRunError::Cancelled => Self::Cancelled,
            AgentRunError::CapabilityMissing(_) => Self::Blocked(BlockedCode::ToolUnavailable),
            AgentRunError::BudgetRefused => Self::BudgetExhausted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use factory_ports::agent::{Capability, ExitInfo};

    #[test]
    fn an_agent_failure_is_classified_the_same_way_by_every_stage() {
        let table = [
            (AgentRunError::ProviderUnavailable, StageError::Provider),
            (
                AgentRunError::RateLimited { retry_after: None },
                StageError::Provider,
            ),
            (
                AgentRunError::AuthenticationRequired,
                StageError::PolicyDenied,
            ),
            (AgentRunError::Timeout, StageError::Tool),
            (
                AgentRunError::ProcessFailed(ExitInfo {
                    code: Some(1),
                    signal: None,
                }),
                StageError::Tool,
            ),
            (AgentRunError::OutputMissing, StageError::Tool),
            (AgentRunError::OutputTooLarge, StageError::InvalidOutput),
            (AgentRunError::Cancelled, StageError::Cancelled),
            (
                AgentRunError::CapabilityMissing(Capability::SkillInvocation),
                StageError::Blocked(BlockedCode::ToolUnavailable),
            ),
            (AgentRunError::BudgetRefused, StageError::BudgetExhausted),
        ];
        for (from, expected) in table {
            assert_eq!(StageError::from(from.clone()), expected, "{from:?}");
        }
    }

    #[test]
    fn a_sandbox_error_blocks_only_when_the_environment_is_the_cause() {
        use factory_ports::sandbox::{
            PolicyViolation, PostureDiff, ProvisionStage, Resource, SandboxError,
        };
        let blocks = [
            (
                SandboxError::DaemonUnavailable,
                EnvironmentCause::DaemonUnavailable,
            ),
            (
                SandboxError::ImageUnavailable,
                EnvironmentCause::ImageUnavailable,
            ),
            (
                SandboxError::PostureMismatch(PostureDiff {
                    fields: vec!["image"],
                }),
                EnvironmentCause::PostureMismatch,
            ),
            (
                SandboxError::PolicyViolation(PolicyViolation { rules: Vec::new() }),
                EnvironmentCause::PolicyViolation,
            ),
        ];
        for (error, cause) in blocks {
            let stage = StageError::from(error.clone());
            assert_eq!(stage, StageError::Environment(cause), "{error:?}");
            assert_eq!(stage.environment(), Some(cause));
        }
        // A try that can succeed next time is not an environment cause.
        for error in [
            SandboxError::ProvisionFailed(ProvisionStage::Create),
            SandboxError::Timeout,
            SandboxError::ResourceExceeded(Resource::Memory),
            SandboxError::TeardownFailed { leaked: false },
        ] {
            let stage = StageError::from(error.clone());
            assert_eq!(stage, StageError::Sandbox, "{error:?}");
            assert_eq!(stage.environment(), None);
        }
        assert_eq!(
            StageError::from(SandboxError::Cancelled),
            StageError::Cancelled
        );
    }

    #[test]
    fn a_probe_that_finds_no_tool_blocks_and_one_that_fails_is_a_tool_error() {
        use factory_ports::agent::ProbeStep;
        assert_eq!(
            StageError::from(ProbeError::BinaryMissing),
            StageError::Environment(EnvironmentCause::ToolMissing)
        );
        assert_eq!(
            StageError::from(ProbeError::UnsupportedVersion {
                found: "0.0.1".to_owned()
            }),
            StageError::Environment(EnvironmentCause::ToolMissing)
        );
        assert_eq!(
            StageError::from(ProbeError::ProbeFailed(ProbeStep::Trial)),
            StageError::Tool
        );
    }

    #[test]
    fn a_blocked_code_maps_to_the_cause_a_person_will_read() {
        assert_eq!(
            StageError::Blocked(BlockedCode::PolicyUnresolvable).environment(),
            Some(EnvironmentCause::PolicyUnloadable)
        );
        for code in [
            BlockedCode::ToolUnavailable,
            BlockedCode::ToolProbeFailed,
            BlockedCode::DependencyUnavailable,
            BlockedCode::EnvironmentUnsupported,
        ] {
            assert_eq!(
                StageError::Blocked(code).environment(),
                Some(EnvironmentCause::ToolMissing),
                "{code:?}"
            );
        }
        assert_eq!(StageError::Tool.environment(), None);
    }

    #[test]
    fn a_cancellation_is_not_a_failure_class() {
        assert_eq!(StageError::Cancelled.failure_class(), None);
        assert_eq!(
            StageError::BudgetExhausted.failure_class(),
            Some(FailureClass::BudgetExhausted)
        );
        assert_eq!(
            StageError::Blocked(BlockedCode::ToolUnavailable).failure_class(),
            Some(FailureClass::PolicyDenied)
        );
    }
}
