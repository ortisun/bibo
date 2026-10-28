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

/// Where the stored request is read from (the `RequestOps` of the store, behind the API).
#[async_trait]
pub trait RequestSource: Send + Sync {
    /// Says whether this reads the real store (`real`) or a fixed list (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// The revision and hash recorded for the job, from memory. `None` when the job has no
    /// recorded request, and then the stage has no contract.
    fn recorded(&self, job: JobId) -> Option<RecordedRequest>;

    /// The newest revision, read now.
    async fn latest(&self, tenant: TenantId, job: JobId) -> Result<RequestSnapshot, SeamError>;
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
    /// The probed capabilities of the available runtimes.
    fn probed(&self) -> ProbedCapabilities;
}
