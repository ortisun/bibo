//! The agent ports: running an agent tool inside a sandbox, choosing which one, and the broker
//! that holds the real model credentials (ADR 0005).
//!
//! An adapter reports what happened. The engine decides whether it counts: `AgentRuntime::run`
//! never marks a stage successful, and the output it returns is unvalidated.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::contracts::agent_manifest::{AllowedTool, RecommendedTier, ResourceLimits};
use factory_domain::contracts::{ArtifactRef, SchemaRef, VersionedRef};
use factory_domain::error::ValueError;
use factory_domain::ids::{AttemptId, JobId, TenantId};
use factory_domain::values::{NonEmptyString, Sha256Digest, Slug, Timestamp, Uri};
use factory_domain::vocabulary::{Fidelity, RiskTier, StageKind};
use uuid::Uuid;

use crate::clock::CancelSignal;
use crate::sandbox::SandboxSession;

/// The identity of an agent runtime adapter, such as `claude-code-cli`, `codex-cli` or `fake`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuntimeId(Slug);

impl RuntimeId {
    /// Checks and wraps a runtime name.
    ///
    /// # Errors
    /// Returns a [`ValueError`] unless the name is a slug.
    pub fn new(name: &str) -> Result<Self, ValueError> {
        Slug::parse(name).map(Self)
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Something a runtime can do, found by probing and never assumed (ADR 0005).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    /// The tool accepts a JSON Schema for its final output.
    JsonSchemaOutput,
    /// The tool writes a stream of structured events.
    StructuredStream,
    /// The tool has a cost-limit flag.
    BudgetFlag,
    /// The tool can invoke skills by name (needed for the specification stage).
    SkillInvocation,
    /// The tool can run several turns without a person.
    HeadlessMultiTurn,
    /// The tool can be pointed at the broker's base URL.
    BaseUrlOverride,
    /// The tool reads its credential from a file or helper.
    CredentialFromFile,
    /// The tool reports which tool calls were denied.
    PermissionDenialReport,
}

impl Capability {
    /// The name used in records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::JsonSchemaOutput => "json-schema-output",
            Self::StructuredStream => "structured-stream",
            Self::BudgetFlag => "budget-flag",
            Self::SkillInvocation => "skill-invocation",
            Self::HeadlessMultiTurn => "headless-multi-turn",
            Self::BaseUrlOverride => "base-url-override",
            Self::CredentialFromFile => "credential-from-file",
            Self::PermissionDenialReport => "permission-denial-report",
        }
    }
}

/// One probe result: a capability, whether it is there, and where the answer came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityObservation {
    /// What was checked.
    pub capability: Capability,
    /// True when the check found it.
    pub supported: bool,
    /// What was read to decide, such as `--help output`.
    pub source: String,
}

/// What a probe found. It is stored and referenced by hash from each attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCapabilities {
    /// The version string the tool reported.
    pub runtime_version: String,
    /// One observation per capability that was checked.
    pub observations: Vec<CapabilityObservation>,
}

impl RuntimeCapabilities {
    /// True only when the probe observed the capability as supported. A capability that was not
    /// checked counts as missing: the adapter never guesses.
    #[must_use]
    pub fn supports(&self, capability: Capability) -> bool {
        self.observations
            .iter()
            .any(|o| o.capability == capability && o.supported)
    }
}

/// The model to use and the runtime to use it with.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModelSelection {
    /// The runtime.
    pub runtime: RuntimeId,
    /// The model name as the provider spells it.
    pub model: NonEmptyString,
}

/// Which set of tool flags a stage runs with (ADR 0005). The set is per stage because skills must
/// stay visible during specification and hidden everywhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlagSet {
    /// Every stage except specification: slash commands and skills are disabled.
    Standard,
    /// The specification stage: the Spec Kit skills must resolve, so skills stay enabled.
    Specification,
}

impl FlagSet {
    /// The flag set a stage runs with.
    #[must_use]
    pub const fn for_stage(stage: StageKind) -> Self {
        match stage {
            StageKind::Specification => Self::Specification,
            _ => Self::Standard,
        }
    }
}

/// What kind of untrusted text a part of the prompt is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataClass {
    /// Text of an issue.
    IssueText,
    /// A file of the repository.
    RepositoryFile,
    /// Output of a command.
    ToolOutput,
    /// An answer from a person.
    HumanAnswer,
    /// Text a model wrote earlier.
    ModelOutput,
}

/// One piece of untrusted text, with where it came from and a hash of the original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPart {
    /// Where the text came from, such as `issue#12` or `README.md`.
    pub source: String,
    /// What kind of text it is.
    pub class: DataClass,
    /// The hash of the original text, before any escaping.
    pub sha256: Sha256Digest,
    /// The text as placed in the envelope.
    pub text: String,
}

/// A prompt with its two parts kept apart. Untrusted text appears only in `data`, never in
/// `instructions` (ADR 0005, policy `untrusted_content.prompt_assembly`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledPrompt {
    /// The factory's own instructions, from the agent's prompt template.
    pub instructions: String,
    /// The data envelope.
    pub data: Vec<DataPart>,
}

/// An agent and the version of it to run.
pub type AgentRef = VersionedRef;

/// The tools policy decided to grant for this run.
pub type GrantedTools = Vec<AllowedTool>;

/// The limits of one agent run: wall time, tokens, cost, tool calls and delegation depth.
pub type AgentLimits = ResourceLimits;

/// Where the per-job relay forwards model traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerEndpoint {
    /// The broker's base URL.
    pub base_url: Uri,
}

/// The identifier of a job token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JobTokenId(Uuid);

impl JobTokenId {
    /// Wraps a UUID that the `IdGenerator` produced.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// The UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for JobTokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.hyphenated(), f)
    }
}

/// A job token's secret. It is shown to the sandbox only, as a file. Its text never appears in
/// `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct JobTokenSecret(String);

impl JobTokenSecret {
    /// Wraps a secret the broker made.
    #[must_use]
    pub fn new(secret: String) -> Self {
        Self(secret)
    }

    /// The secret text. Write it to the token file and nowhere else.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for JobTokenSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JobTokenSecret(<redacted>)")
    }
}

/// A reference to a job token, without its secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobTokenRef {
    /// The token.
    pub id: JobTokenId,
}

/// Money in millionths of a US dollar, so sums are exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct CostMicroUsd(pub u64);

/// What a run or a token has used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    /// Tokens sent to the model.
    pub input_tokens: u64,
    /// Tokens the model wrote.
    pub output_tokens: u64,
    /// Cost so far.
    pub cost: CostMicroUsd,
    /// Number of model requests.
    pub requests: u64,
}

impl Usage {
    /// The sum of two usages. It saturates instead of overflowing.
    #[must_use]
    pub fn saturating_add(self, other: Usage) -> Usage {
        Usage {
            input_tokens: self.input_tokens.saturating_add(other.input_tokens),
            output_tokens: self.output_tokens.saturating_add(other.output_tokens),
            cost: CostMicroUsd(self.cost.0.saturating_add(other.cost.0)),
            requests: self.requests.saturating_add(other.requests),
        }
    }
}

/// How the tool's process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitInfo {
    /// The exit code, when the process exited by itself.
    pub code: Option<i32>,
    /// The signal that ended it, when it was killed.
    pub signal: Option<i32>,
}

/// A tool call the tool reported as denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// The tool that was refused.
    pub tool: String,
    /// Why, in the tool's words.
    pub reason: String,
}

/// Everything one agent run needs.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentRunRequest {
    /// The attempt the run belongs to.
    pub attempt: AttemptId,
    /// The agent and its version.
    pub agent: AgentRef,
    /// The prompt, with untrusted text only inside the data envelope.
    pub prompt: AssembledPrompt,
    /// The schema the output must follow.
    pub output_schema: SchemaRef,
    /// Where the sidecar relays to.
    pub broker: BrokerEndpoint,
    /// The job token the tool authenticates with.
    pub job_token: JobTokenRef,
    /// The tools policy granted. The agent never decides this.
    pub tools: GrantedTools,
    /// The limits of this run.
    pub limits: AgentLimits,
    /// The model and runtime.
    pub model: ModelSelection,
    /// The flag set for the stage.
    pub flag_set: FlagSet,
}

/// What a run produced. The engine validates `output`; this is a report, not a verdict.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentRunOutcome {
    /// The tool's final output, **unvalidated**.
    pub output: serde_json::Value,
    /// The full transcript, stored in the artifact store after redaction.
    pub transcript: ArtifactRef,
    /// What the run used.
    pub usage: Usage,
    /// The version of the tool that ran.
    pub runtime_version: String,
    /// How the process ended.
    pub exit: ExitInfo,
    /// Tool calls the tool reported as denied.
    pub permission_denials: Vec<Denial>,
}

/// Why a run failed. The set is closed: an adapter maps every failure of its tool onto one of
/// these.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AgentRunError {
    /// The model provider cannot be reached.
    #[error("the model provider is unavailable")]
    ProviderUnavailable,
    /// The provider asked the caller to slow down.
    #[error("the model provider is rate limiting this caller")]
    RateLimited {
        /// How long the provider asked to wait, when it said.
        retry_after: Option<Duration>,
    },
    /// The job token or credential was refused.
    #[error("the model provider refused the credential")]
    AuthenticationRequired,
    /// The run took longer than its wall-clock limit.
    #[error("the agent run timed out")]
    Timeout,
    /// The tool's process ended with a failure.
    #[error("the agent process failed")]
    ProcessFailed(ExitInfo),
    /// The tool ended without producing the final output.
    #[error("the agent produced no output")]
    OutputMissing,
    /// The caller cancelled the run and the tool was stopped.
    #[error("the agent run was cancelled")]
    Cancelled,
    /// The run needs a capability the probe did not find.
    #[error("the runtime lacks the capability {}", .0.as_str())]
    CapabilityMissing(Capability),
    /// The broker refused the call because the budget is used up.
    #[error("the budget is used up")]
    BudgetRefused,
}

/// Why a probe failed. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    /// The tool is not installed in the sandbox image.
    #[error("the agent tool is not installed in the sandbox image")]
    BinaryMissing,
    /// The tool's version is outside the accepted range, so the stage is blocked.
    #[error("the agent tool version {found} is not supported")]
    UnsupportedVersion {
        /// The version the tool reported.
        found: String,
    },
    /// The probe command failed. The text never includes secrets.
    #[error("the probe failed: {0}")]
    ProbeFailed(String),
}

/// Runs an agent tool inside a sandbox.
///
/// # Preconditions
/// The session is an `agent`-profile sandbox that passed its posture check. The prompt keeps
/// untrusted text inside its data envelope. The granted tools were decided by policy.
///
/// # Postconditions
/// `probe` returns what the tool can do, read from the tool itself and repeatable: probing twice
/// gives the same answer. It changes nothing in the sandbox. `run` starts the tool inside the
/// session and returns what the tool produced, **unvalidated**, with a stored transcript, usage
/// and any denials the tool reported. It never marks a stage as successful: the engine validates
/// the output and the gate decides. A cancelled run stops the tool before it returns.
///
/// # Errors
/// [`ProbeError`] for `probe`. [`AgentRunError`] for `run`: `ProviderUnavailable`, `RateLimited`,
/// `AuthenticationRequired`, `Timeout`, `ProcessFailed`, `OutputMissing`, `Cancelled`,
/// `CapabilityMissing` (the probe did not find a capability the run needs) and `BudgetRefused`.
///
/// # Idempotency
/// `probe` is a read. `run` is not idempotent: each call runs the tool again and may cost money.
#[async_trait]
pub trait AgentRuntime: Send + Sync {
    /// The runtime's name: `claude-code-cli`, `codex-cli` or `fake`.
    fn id(&self) -> &RuntimeId;

    /// Says whether this adapter drives a real tool (`real`) or is a scripted stand-in (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Reads the tool's version and flags and reports what it can do.
    async fn probe(
        &self,
        session: &mut dyn SandboxSession,
    ) -> Result<RuntimeCapabilities, ProbeError>;

    /// Starts the tool inside `session`. The engine validates the output. This never marks
    /// success.
    async fn run(
        &self,
        session: &mut dyn SandboxSession,
        req: AgentRunRequest,
        cancel: &dyn CancelSignal,
    ) -> Result<AgentRunOutcome, AgentRunError>;
}

/// What a stage needs from a model, as a routing question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingNeed {
    /// The stage.
    pub stage: StageKind,
    /// How capable the model should be.
    pub tier: RecommendedTier,
    /// Capabilities the runtime must have.
    pub required: Vec<Capability>,
    /// The risk of the job, which can force a larger model.
    pub risk: RiskTier,
}

/// The answer to a routing question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingDecision {
    /// The model and runtime to use.
    pub model: ModelSelection,
    /// The flag set for the stage.
    pub flag_set: FlagSet,
}

/// Why no route was found. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RoutingError {
    /// The routing policy has no entry for this stage and tier.
    #[error("the routing policy has no route for this need")]
    NoRoute,
    /// Every candidate lacks a capability the need requires.
    #[error("no candidate runtime has the capability {}", .0.as_str())]
    CapabilityUnavailable(Capability),
}

/// Chooses a runtime and model. A pure function of the routing policy and the question.
///
/// # Preconditions
/// The routing policy (`policies/model_routing.yaml`) was loaded and validated when the router was
/// built.
///
/// # Postconditions
/// The same need always gets the same decision. The decision's flag set is
/// [`FlagSet::for_stage`] of the need's stage. Routing never calls a provider.
///
/// # Errors
/// [`RoutingError::NoRoute`] and [`RoutingError::CapabilityUnavailable`].
///
/// # Idempotency
/// Idempotent and side-effect free.
pub trait ModelRouter: Send + Sync {
    /// Says whether this router reads the real routing policy (`real`) or a fixed table (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Pure. Reads the routing policy.
    fn route(&self, need: &RoutingNeed) -> Result<RoutingDecision, RoutingError>;
}

/// What to issue a job token for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobTokenRequest {
    /// The tenant the token is bound to.
    pub tenant: TenantId,
    /// The job it is bound to.
    pub job: JobId,
    /// The stage it is bound to.
    pub stage: StageKind,
    /// The most the token may spend.
    pub cost_ceiling: CostMicroUsd,
    /// The only provider models the token may use. Must not be empty.
    pub allowed_models: Vec<ModelSelection>,
    /// How long the token lasts.
    pub ttl: Duration,
}

/// A token the broker issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedJobToken {
    /// The token's identifier.
    pub id: JobTokenId,
    /// The secret, for the token file.
    pub secret: JobTokenSecret,
    /// When the token stops working.
    pub expires_at: Timestamp,
}

/// Where a token stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    /// The token works.
    Active,
    /// The token was revoked, by a call or because it reached its ceiling.
    Revoked,
    /// The token passed its expiry time.
    Expired,
}

/// What a token has used and where it stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenUsage {
    /// What it has used so far.
    pub usage: Usage,
    /// The ceiling it was issued with.
    pub ceiling: CostMicroUsd,
    /// Whether it still works.
    pub state: TokenState,
}

/// Why a broker call failed. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BrokerError {
    /// The broker has no such token.
    #[error("the broker has no such token")]
    UnknownToken,
    /// The request was malformed, such as a zero ceiling or an empty model list.
    #[error("the token request is invalid: {0}")]
    InvalidRequest(String),
    /// The broker cannot be reached.
    #[error("the model broker is unavailable")]
    Unavailable,
}

/// Issues, revokes and meters the per-job tokens that stand between the sandbox and the real
/// model keys.
///
/// # Preconditions
/// `issue` needs a non-empty list of allowed models and a ceiling above zero. The broker holds the
/// real provider keys; the caller never sees them.
///
/// # Postconditions
/// An issued token is bound to its tenant, job and stage, starts with zero usage and is `Active`
/// until it is revoked, expires or reaches its ceiling. After `revoke` the token is `Revoked` and
/// no further spending is allowed under it; the usage recorded so far stays readable. A token
/// that reaches its ceiling is revoked by the broker. The secret never appears in `Debug` output.
///
/// # Errors
/// [`BrokerError::InvalidRequest`] (`issue`), [`BrokerError::UnknownToken`] (`usage`),
/// [`BrokerError::Unavailable`].
///
/// # Idempotency
/// `revoke` is idempotent: revoking a revoked token succeeds and changes nothing, and revoking a
/// token the broker never issued succeeds too. `issue` is not idempotent: each call makes a new
/// token. `usage` is a read.
#[async_trait]
pub trait ModelBroker: Send + Sync {
    /// Says whether this is the real broker (`real`) or an in-memory stand-in (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Bound to tenant, job and stage, with a cost ceiling and an allowed provider and model
    /// list.
    async fn issue(&self, req: JobTokenRequest) -> Result<IssuedJobToken, BrokerError>;

    /// Idempotent.
    async fn revoke(&self, token: &JobTokenId) -> Result<(), BrokerError>;

    /// What the token has used and whether it still works.
    async fn usage(&self, token: &JobTokenId) -> Result<TokenUsage, BrokerError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skills_stay_visible_only_during_specification() {
        for stage in StageKind::ALL {
            let expected = if *stage == StageKind::Specification {
                FlagSet::Specification
            } else {
                FlagSet::Standard
            };
            assert_eq!(FlagSet::for_stage(*stage), expected, "{stage}");
        }
    }

    #[test]
    fn a_capability_that_was_not_checked_counts_as_missing() {
        let found = RuntimeCapabilities {
            runtime_version: "1.0.0".to_owned(),
            observations: vec![
                CapabilityObservation {
                    capability: Capability::JsonSchemaOutput,
                    supported: true,
                    source: "--help".to_owned(),
                },
                CapabilityObservation {
                    capability: Capability::BudgetFlag,
                    supported: false,
                    source: "--help".to_owned(),
                },
            ],
        };
        assert!(found.supports(Capability::JsonSchemaOutput));
        assert!(!found.supports(Capability::BudgetFlag));
        assert!(!found.supports(Capability::SkillInvocation));
    }

    #[test]
    fn usage_adds_and_saturates() {
        let a = Usage {
            input_tokens: 10,
            output_tokens: 5,
            cost: CostMicroUsd(100),
            requests: 1,
        };
        let b = Usage {
            input_tokens: u64::MAX,
            output_tokens: 1,
            cost: CostMicroUsd(50),
            requests: 2,
        };
        let sum = a.saturating_add(b);
        assert_eq!(sum.input_tokens, u64::MAX);
        assert_eq!(sum.output_tokens, 6);
        assert_eq!(sum.cost, CostMicroUsd(150));
        assert_eq!(sum.requests, 3);
    }

    #[test]
    fn secrets_do_not_appear_in_debug_output() {
        let secret = JobTokenSecret::new("sfjt_super-secret-value".to_owned());
        assert!(!format!("{secret:?}").contains("super-secret"));
        assert_eq!(secret.expose(), "sfjt_super-secret-value");
    }
}
