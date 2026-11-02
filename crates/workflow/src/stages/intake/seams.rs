//! What the intake stage needs from the outside and that no port of `factory-ports` offers. Each is
//! a small trait the composition root implements, and the tests implement with a fixed list.
//!
//! The crate `workflow` may not depend on the crate that checks schemas (`factory-contracts`), on
//! the store, or on the policy files, so the stage asks through these traits instead. None of them
//! does anything the stage could do wrongly with the answer: each returns facts, and the stage
//! decides.

use async_trait::async_trait;
use factory_domain::contracts::{SchemaRef, Violation};
use factory_domain::ids::{AttemptId, JobId, TenantId};
use factory_domain::policy::authority::Allowlist;
use factory_domain::policy::issue_workflow::DesignGate;
use factory_domain::values::Sha256Digest;
use factory_domain::vocabulary::Fidelity;
use factory_ports::agent::{JobTokenRef, ProbedCapabilities};
use factory_ports::githost::IssueRef;
use factory_ports::registry::ValidatedOutput;
use factory_ports::sandbox::SandboxSpec;

/// Why a seam could not answer. The set is closed and carries no text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SeamError {
    /// There is nothing stored for the question.
    #[error("nothing is stored for this question")]
    NotFound,
    /// The source cannot be reached. The stage fails closed.
    #[error("the source cannot be reached")]
    Unavailable,
}

/// The hash and revision of the original request, as the API recorded them when it received the
/// job. The contract of the stage names the original request as its input, and `contract` is not
/// asynchronous, so this one answer comes from memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRequest {
    /// 1 for the first text, 2 for the first edit, and so on.
    pub revision: u32,
    /// The SHA-256 of the text, as the store computed it.
    pub sha256: Sha256Digest,
}

/// The original request exactly as stored (FR-003).
#[derive(Clone, PartialEq, Eq)]
pub struct RequestSnapshot {
    /// The revision.
    pub revision: u32,
    /// Title and body as one text, exactly as received. Untrusted.
    pub text: String,
    /// The SHA-256 the store computed from `text`.
    pub sha256: Sha256Digest,
    /// The numeric id of the author, when there is one.
    pub author: Option<u64>,
    /// The issue the text came from.
    pub issue: IssueRef,
}

impl std::fmt::Debug for RequestSnapshot {
    /// Shows the size and the hash, never the text.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestSnapshot")
            .field("revision", &self.revision)
            .field("bytes", &self.text.len())
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}

/// The first text of a request, fetched live from the code host by the stage itself, for a job
/// that a webhook created. The delivery carries no issue text and the API holds no credential for
/// the code host, so the job starts without a request.
#[derive(Clone, PartialEq, Eq)]
pub struct FetchedRequest {
    /// The issue the text came from.
    pub issue: IssueRef,
    /// The numeric id of the issue's author.
    pub author: u64,
    /// Title and body as one text, exactly as the host returned them. Untrusted.
    pub text: String,
}

impl std::fmt::Debug for FetchedRequest {
    /// Shows the size, never the text.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchedRequest")
            .field("issue", &self.issue)
            .field("author", &self.author)
            .field("bytes", &self.text.len())
            .finish()
    }
}

/// Where the stored request is read from (the `RequestOps` of the store, behind the API).
#[async_trait]
pub trait RequestSource: Send + Sync {
    /// Says whether this reads the real store (`real`) or a fixed list (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// The revision and hash recorded for the job, from memory. `None` when the job has no
    /// recorded request. Then the stage has a contract only if [`RequestSource::awaiting`]
    /// answers.
    fn recorded(&self, job: JobId) -> Option<RecordedRequest>;

    /// The issue a job that a webhook created came from, from memory, when the job has no
    /// recorded request yet. `None` for every other job. The stage then resolves its contract
    /// without the text and fetches the text when it runs.
    fn awaiting(&self, job: JobId) -> Option<IssueRef>;

    /// The newest revision, read now.
    async fn latest(&self, tenant: TenantId, job: JobId) -> Result<RequestSnapshot, SeamError>;

    /// Stores `request` as revision 1 of the job, and returns it as stored. The call is
    /// idempotent: when revision 1 exists with the same text the stored one is returned, and
    /// with other text the call fails, because a stored revision never changes.
    async fn record_first(
        &self,
        tenant: TenantId,
        job: JobId,
        request: FetchedRequest,
    ) -> Result<RequestSnapshot, SeamError>;
}

/// The named allowlist of the protected configuration, as it is now. Nothing is cached: removing a
/// person from the list takes effect on the next call (NT-AUTHZ-04).
#[async_trait]
pub trait AllowlistSource: Send + Sync {
    /// Says whether this reads the real protected configuration (`real`) or a fixed list.
    fn fidelity(&self) -> Fidelity;

    /// The allowlist for the tenant.
    async fn current(&self, tenant: TenantId) -> Result<Allowlist, SeamError>;
}

/// The design rule of `policies/issue-workflow.yaml`, as it is now. Nothing is cached: the file is
/// read for every attempt, so a policy that is repaired takes effect on the next attempt and one
/// that is broken stops the next one.
///
/// This is a CONTROL and not observability. When the rule cannot be read, the stage does not guess
/// and does not fall back to a default: it refuses the issue (see the `design` module).
#[async_trait]
pub trait DesignGatePolicy: Send + Sync {
    /// Says whether this reads the real protected configuration (`real`) or a fixed rule.
    fn fidelity(&self) -> Fidelity;

    /// The rule. [`SeamError::Unavailable`] when the file is missing, unsafe, breaks the strict
    /// contract or breaks one of its rules; the reason is the source's to log, the stage needs no
    /// more than that it cannot judge.
    async fn current(&self) -> Result<DesignGate, SeamError>;
}

/// Why a reply was not delivered. The set is closed and carries no text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplyError {
    /// The host could not be reached or asked to wait. Trying again later may work.
    #[error("the reply could not be delivered now")]
    Later,
    /// The host refused, or the issue is gone. Trying again will not help.
    #[error("the reply cannot be delivered")]
    NotSent,
}

/// Answers a person on the issue when the stage refuses it, with a comment.
///
/// The stage holds a token that reads issues and nothing more, so the comment is posted by the
/// composition root, with a token narrowed to the one repository and to `issues: write`, the way
/// the worker answers a label from someone who may not ask (`IntakeRejections`). Nothing travels
/// through the audit log: the stage runs inside the worker, so no untrusted channel stands between
/// the decision and the reply.
#[async_trait]
pub trait RefusalReplies: Send + Sync {
    /// Says whether this posts to the real code host (`real`) or records what it was given.
    fn fidelity(&self) -> Fidelity;

    /// Posts `text` as a comment on `issue`, once for `key`: a second call with the same key
    /// leaves one comment. The text is plain English written by the stage, never text of the
    /// issue.
    async fn post(
        &self,
        tenant: TenantId,
        issue: &IssueRef,
        key: &str,
        text: &str,
    ) -> Result<(), ReplyError>;
}

/// Checks the bytes an agent returned against that agent's own output schema. The composition root
/// implements it with `factory_contracts::agent_schema::AgentSchema::validate_bytes`, so the limits,
/// the strict JSON parse and the messages are those of `factory-contracts`.
pub trait AgentOutputCheck: Send + Sync {
    /// Says whether this is the real schema check (`real`) or a stand-in (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// The document and the hash of its exact bytes, or the violations.
    ///
    /// # Errors
    /// A non-empty list of violations.
    fn check(&self, schema: &SchemaRef, bytes: &[u8]) -> Result<ValidatedOutput, Vec<Violation>>;
}

/// Builds the sandbox spec of the `agent` profile for one attempt: image, limits, mounts, the
/// network attachment behind the egress sidecar and the job token mount. The policy decides every
/// value, so the stage cannot widen a sandbox.
pub trait AgentSandboxSpecs: Send + Sync {
    /// The spec for the attempt.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`] when the policy or the image cannot be resolved.
    fn agent_spec(
        &self,
        job: JobId,
        attempt: AttemptId,
        token: JobTokenRef,
    ) -> Result<SandboxSpec, SeamError>;
}

/// What the runtime probes found, cached by the composition root.
pub trait CapabilityProbes: Send + Sync {
    /// Says whether these are the capabilities the runtimes reported (`real`) or a fixed list
    /// (`fake`). The profile check refuses a `fake` in production (RR-6): a list that claims every
    /// capability sends work to a runtime that cannot do it.
    fn fidelity(&self) -> Fidelity;

    /// The probed capabilities of the available runtimes.
    fn probed(&self) -> ProbedCapabilities;
}
