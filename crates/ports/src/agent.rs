//! The agent ports: running an agent tool inside a sandbox, choosing which one, and the broker
//! that holds the real model credentials (ADR 0005, ADR 0014 decision 6).
//!
//! An adapter reports what happened. The engine decides whether it counts: `AgentRuntime::run`
//! never marks a stage successful, and the output it returns is raw bytes that nothing has
//! parsed. A run that failed still reports its usage, transcript and denials. Spend reaches a
//! broker through [`MeteringOps`], which the engine never holds.

use std::collections::BTreeMap;
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

/// Everything one agent run needs. One field is new: `max_output_bytes`.
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
    /// The most bytes of final output the adapter reads. One more byte is `OutputTooLarge`. From
    /// `untrusted_content.structured_output.max_bytes` in the policy.
    pub max_output_bytes: u64,
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

/// The final output of a run, **as bytes**. Nothing has parsed it. The engine hands the bytes to
/// `OutputValidator::validate_bytes`, which refuses a document with a repeated key, an
/// oversize body or too deep a nesting before any parser builds a value, and stores the same
/// bytes as an artifact.
#[derive(Clone, PartialEq, Eq)]
pub struct RawOutput(Vec<u8>);

impl RawOutput {
    /// Wraps the bytes the tool wrote.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for RawOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RawOutput({} bytes)", self.0.len())
    }
}

/// What a run left behind, whether it worked or not. The failed attempt is the one that needs its
/// evidence and may have cost money, so every part is returned either way.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentRunReport {
    /// The final output, or why there is none.
    pub outcome: Result<RawOutput, AgentRunError>,
    /// The transcript, stored after redaction. `None` only when the run failed before the tool
    /// produced any.
    pub transcript: Option<ArtifactRef>,
    /// What the run used, as far as the adapter could tell. Zero when nothing was used.
    pub usage: Usage,
    /// The version of the tool that ran, when it started.
    pub runtime_version: Option<String>,
    /// How the process ended, when it started and ended.
    pub exit: Option<ExitInfo>,
    /// Tool calls the tool reported as denied.
    pub permission_denials: Vec<Denial>,
}

/// Why a run failed. The set is closed. `OutputTooLarge` is new.
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
    /// The final output is larger than `max_output_bytes`.
    #[error("the agent output is larger than the limit")]
    OutputTooLarge,
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

/// The step of a probe that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeStep {
    /// Reading the version.
    Version,
    /// Reading the help text.
    Help,
    /// Running a trial command.
    Trial,
}

/// Why a probe failed. The set is closed. `ProbeFailed` names the step instead of carrying text.
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
    /// The probe command failed.
    #[error("the probe failed at {0:?}")]
    ProbeFailed(ProbeStep),
}

/// Runs an agent tool inside a sandbox.
///
/// # Preconditions
/// The session is an `agent`-profile sandbox that passed its posture check. The prompt keeps
/// untrusted text inside its data envelope. The granted tools were decided by policy.
///
/// # Postconditions
/// `probe` returns what the tool can do, read from the tool itself and repeatable. `run` always
/// returns a report. A report with an output carries the tool's final output as bytes,
/// unvalidated. A report with an error still carries the usage, the transcript and the denials
/// of the run. `run` never marks a stage successful, and a cancelled run stops the tool before
/// it returns.
///
/// # Errors
/// [`ProbeError`] for `probe`. For `run`, the error is `report.outcome`.
///
/// # Idempotency
/// `probe` is a read. `run` is not idempotent: each call runs the tool again and may cost money.
///
/// # Cancellation and timeouts
/// `run` takes a cancel signal and `req.limits` holds the wall clock. Dropping the future kills
/// the tool process but loses the report; the usage is still in the broker (`ModelBroker::usage`).
/// `probe` has a fixed timeout of 30 seconds and is safe to drop.
#[async_trait]
pub trait AgentRuntime: Send + Sync {
    /// The runtime's name.
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
    ) -> AgentRunReport;
}

/// What the probes of the available runtimes found. Probing is done by the engine, per runtime,
/// and cached by runtime version and image digest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbedCapabilities(pub BTreeMap<RuntimeId, RuntimeCapabilities>);

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
    /// Runtimes that already failed for this attempt window. The router never returns one.
    pub exclude: Vec<RuntimeId>,
    /// What the probes found. A runtime with no entry is not a candidate.
    pub probed: ProbedCapabilities,
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
    /// Every candidate was excluded.
    #[error("every candidate runtime was excluded")]
    AllExcluded,
    /// Every remaining candidate lacks a capability the need requires, as the probes found.
    #[error("no candidate runtime has the capability {}", .0.as_str())]
    CapabilityUnavailable(Capability),
}

/// Chooses a runtime and model. A pure function of the routing policy and the question.
///
/// # Postconditions
/// The same need, with the same exclusions and the same probe results, always gets the same
/// decision. The decision's runtime is not in `need.exclude`, has an entry in `need.probed`, and
/// that entry supports every capability in `need.required`. The candidates are tried in the
/// order the policy lists them. Excluding the answer of a first call gives a different runtime
/// or an error, never the same one. The flag set is `FlagSet::for_stage`. Routing never calls a
/// provider.
///
/// # Errors
/// [`RoutingError`].
///
/// # Idempotency
/// Idempotent and side-effect free.
///
/// # Preconditions
/// The routing policy is loaded. The need names a stage, a tier, the capabilities the runtime must
/// have, and the runtimes already excluded and probed.
///
/// # Cancellation and timeouts
/// The call is pure and returns at once. It reads no clock and makes no call, so there is nothing to
/// cancel and no timeout.
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

/// Why a token request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidTokenRequest {
    /// The cost ceiling is zero.
    ZeroCeiling,
    /// The list of allowed models is empty.
    NoModels,
    /// The lifetime is zero.
    ZeroTtl,
}

/// Why a broker call failed. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BrokerError {
    /// The broker has no such token.
    #[error("the broker has no such token")]
    UnknownToken,
    /// The request was malformed.
    #[error("the token request is invalid: {0:?}")]
    InvalidRequest(InvalidTokenRequest),
    /// The broker cannot be reached.
    #[error("the model broker is unavailable")]
    Unavailable,
}

/// Issues, revokes and meters the per-job tokens that stand between the sandbox and the real
/// model keys.
///
/// # Postconditions
/// An issued token is bound to its tenant, job and stage, starts with zero usage and is `Active`
/// until it is revoked, expires or reaches its ceiling. After `revoke` the token is `Revoked`
/// and no further spending is allowed under it; the usage recorded so far stays readable.
/// `revoke_for_job` revokes every token of the job, including tokens whose attempt crashed. The
/// secret never appears in `Debug` output.
///
/// # Errors
/// [`BrokerError`].
///
/// # Idempotency
/// `revoke` and `revoke_for_job` are idempotent: revoking a revoked token, or a token the broker
/// never issued, succeeds. `issue` is not idempotent. `usage` is a read.
///
/// # Cancellation and timeouts
/// Every call is safe to drop. `issue` that was dropped may have made a token that nobody holds;
/// `revoke_for_job` at the end of the job removes it.
///
/// # Preconditions
/// issue needs a non-empty list of allowed models, a ceiling above zero and a lifetime above zero.
/// The broker holds the real provider keys; the caller never sees them.
#[async_trait]
pub trait ModelBroker: Send + Sync {
    /// Says whether this is the real broker (`real`) or an in-memory stand-in (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Bound to tenant, job and stage, with a cost ceiling and an allowed provider and model list.
    async fn issue(&self, req: JobTokenRequest) -> Result<IssuedJobToken, BrokerError>;

    /// Idempotent.
    async fn revoke(&self, token: &JobTokenId) -> Result<(), BrokerError>;

    /// Revokes every token of the job. Idempotent.
    async fn revoke_for_job(&self, job: JobId) -> Result<(), BrokerError>;

    /// What the token has used and whether it still works.
    async fn usage(&self, token: &JobTokenId) -> Result<TokenUsage, BrokerError>;
}

/// The seam through which spend reaches a broker. The real broker's relay calls it in the
/// `egress` crate when it forwards a model request; the fake agent runtime calls it on the fake
/// broker to pretend to spend. **The engine never holds a `MeteringOps`**, and the static check
/// ST-14 fails a reference to it in the `workflow` crate: the engine reads what was spent with
/// `ModelBroker::usage` and cannot invent spend.
///
/// # Postconditions
/// The usage is added to the token's total. If the new total reaches the ceiling, the token is
/// revoked in the same step. Spend under a revoked or expired token is refused with
/// [`BrokerError::UnknownToken`] and adds nothing.
///
/// # Idempotency
/// Not idempotent: each call adds.
///
/// # Preconditions
/// The token was issued by this broker. The caller is the relay inside the egress crate, or a fake
/// agent runtime acting on the fake broker. The workflow crate never holds one (ST-14).
///
/// # Errors
/// BrokerError::UnknownToken (the token is unknown, revoked or expired), BrokerError::Unavailable.
///
/// # Cancellation and timeouts
/// The call is safe to drop. A dropped call may have been applied, so the relay records each spend
/// exactly once and does not retry blindly. The adapter sets a timeout and reports it as Unavailable.
#[async_trait]
pub trait MeteringOps: Send + Sync {
    /// Adds `delta` to the token's usage and returns the totals.
    async fn record_usage(
        &self,
        token: &JobTokenId,
        delta: Usage,
    ) -> Result<TokenUsage, BrokerError>;
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

    #[test]
    fn raw_output_shows_its_size_and_never_its_content() {
        let bytes = format!("{{\"answer\":\"{}\"}}", "sensitive text").into_bytes();
        let output = RawOutput::new(bytes.clone());
        let shown = format!("{output:?}");
        assert_eq!(shown, format!("RawOutput({} bytes)", bytes.len()));
        assert!(!shown.contains("sensitive"));
        assert_eq!(output.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn a_failed_run_report_still_holds_usage_and_denials() {
        let report = AgentRunReport {
            outcome: Err(AgentRunError::Timeout),
            transcript: None,
            usage: Usage {
                input_tokens: 10,
                output_tokens: 2,
                cost: CostMicroUsd(40),
                requests: 1,
            },
            runtime_version: Some("1.2.3".to_owned()),
            exit: None,
            permission_denials: Vec::new(),
        };
        assert!(report.outcome.is_err());
        assert_eq!(report.usage.cost, CostMicroUsd(40));
    }

    #[test]
    fn a_routing_need_with_nothing_probed_has_no_candidate_to_offer() {
        let need = RoutingNeed {
            stage: StageKind::Implementation,
            tier: RecommendedTier::Standard,
            required: vec![Capability::JsonSchemaOutput],
            risk: RiskTier::Low,
            exclude: Vec::new(),
            probed: ProbedCapabilities::default(),
        };
        assert!(need.probed.0.is_empty());
        assert!(need.exclude.is_empty());
    }

    #[test]
    fn the_error_sets_carry_no_free_text() {
        assert_eq!(
            BrokerError::InvalidRequest(InvalidTokenRequest::ZeroCeiling).to_string(),
            "the token request is invalid: ZeroCeiling"
        );
        assert_eq!(
            AgentRunError::OutputTooLarge.to_string(),
            "the agent output is larger than the limit"
        );
        assert_eq!(
            ProbeError::ProbeFailed(ProbeStep::Trial).to_string(),
            "the probe failed at Trial"
        );
        assert_eq!(
            RoutingError::AllExcluded.to_string(),
            "every candidate runtime was excluded"
        );
    }
}
