//! What the delivery and approval stages need from the outside and no port offers. Each is a
//! small trait that the composition root implements and the tests implement with fixed values.
//! See `crate::stages::intake::seams` for why they are traits of this crate.

use async_trait::async_trait;
use factory_domain::ids::{JobId, LedgerEntryId, TenantId};
use factory_domain::policy::risk::RiskFacts;
use factory_domain::values::{GitSha, Sha256Digest, Slug, Timestamp};
use factory_domain::vocabulary::{AssuranceLevel, Fidelity, RiskTier};
use factory_ports::githost::IssueRef;
use factory_ports::paths::{BranchName, CommitSha, RepoPath, RepoRef};

use crate::handlers::RunIdentity;

pub use crate::stages::intake::seams::SeamError;

/// A document committed on the job branch that the pull request links to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocLink {
    /// What the document is, in a few plain words such as `Architecture decision`.
    pub label: String,
    /// Where it is in the repository. The pull request links to it at the head commit.
    pub path: RepoPath,
}

/// Where and what the job delivers.
#[derive(Debug, Clone, PartialEq)]
pub struct DeliveryTarget {
    /// The repository the job is bound to.
    pub repo: RepoRef,
    /// The protected branch the change is made against.
    pub base: BranchName,
    /// The factory branch that carries the change. It starts with `factory/`.
    pub head: BranchName,
    /// The issue the job came from, by its native number.
    pub issue: IssueRef,
    /// What the factory measured about the job and the design, for the risk tier. Never an agent's
    /// claim. The delivery stage joins it with what the diff shows (`risk::assess`).
    pub risk: RiskFacts,
    /// The tier the intake classifier claimed. It can raise the tier and never lowers it.
    pub agent_claim: Option<RiskTier>,
    /// Task, decision and documentation files on the branch, linked from the body.
    pub links: Vec<DocLink>,
}

/// The values the evidence is bound to, as they are now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentValues {
    /// The hash of the gate definitions at the base commit.
    pub definition_hash: Sha256Digest,
    /// The digest of the verify image.
    pub image_digest: Sha256Digest,
}

/// The evidence ledger of the job, read and verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerState {
    /// How many entries the job has.
    pub entry_count: u64,
    /// The sequence of the last entry.
    pub head_sequence: u64,
    /// The hash of the last entry.
    pub head_hash: Sha256Digest,
    /// When the whole chain was last verified.
    pub chain_verified_at: Timestamp,
    /// The assurance levels the ledger supports, with the entry that supports each.
    pub attained: Vec<(AssuranceLevel, LedgerEntryId)>,
    /// The gates a person disposed of after they were `BLOCKED`, with the ledger entry that
    /// records the decision.
    pub dispositions: Vec<(Slug, LedgerEntryId)>,
}

/// Facts the delivery and approval stages read from the store and the repository configuration.
///
/// # Contract
/// * `ledger` returns a state whose chain the implementation verified just now. An implementation
///   that cannot verify returns `Unavailable`, and the stage blocks.
/// * `tree_of` returns the git tree id of the commit in the job's object store. No port exposes
///   it, so the composition root reads it from the store it already holds.
/// * Every method is a read.
#[async_trait]
pub trait DeliverySources: Send + Sync {
    /// Says whether this reads the real store (`real`) or fixed values (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// The repository, branches, issue, risk facts and links of the job.
    ///
    /// # Errors
    /// [`SeamError`].
    async fn target(&self, run: &RunIdentity) -> Result<DeliveryTarget, SeamError>;

    /// The gate definition hash and image digest in force now, for the base commit.
    ///
    /// # Errors
    /// [`SeamError`].
    async fn current_values(
        &self,
        run: &RunIdentity,
        base: &CommitSha,
    ) -> Result<CurrentValues, SeamError>;

    /// The ledger of the job, verified.
    ///
    /// # Errors
    /// [`SeamError`].
    async fn ledger(&self, run: &RunIdentity) -> Result<LedgerState, SeamError>;

    /// The git tree id of a commit.
    ///
    /// # Errors
    /// [`SeamError`].
    async fn tree_of(&self, run: &RunIdentity, commit: &CommitSha) -> Result<GitSha, SeamError>;
}

/// Tells the engine that a value the gate evidence is bound to changed, so that it supersedes the
/// validation, review, documentation review, delivery and approval runs (ADR 0010).
///
/// The implementation calls `Engine::apply_change` with `ArtifactChange::GateEvidenceBinding`.
/// That call cancels the live attempt that asked for it, so a stage that calls this stops and
/// returns `StageError::Cancelled`.
///
/// There is no adapter for the engine in this crate: the future of `Engine::apply_change` is not
/// `Send` (it holds the engine's single-threaded `Cx`), and a stage handler's future must be. The
/// composition root implements this trait by handing the call to a task that owns the engine, for
/// example through a channel.
#[async_trait]
pub trait EvidenceDrift: Send + Sync {
    /// Reports that a bound value changed.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`] when the engine could not be told. The stage fails closed.
    async fn binding_changed(&self, tenant: TenantId, job: JobId) -> Result<(), SeamError>;
}
