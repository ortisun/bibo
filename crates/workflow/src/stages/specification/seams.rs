//! What the specification stage needs from the outside and no port offers. Each is a small trait
//! that the composition root implements and the tests implement with a list. See
//! `crate::stages::intake::seams` for why they are traits of this crate.
//!
//! The schema check, the runtime probes, the sandbox spec factory and the rework source are those
//! of the intake and implementation stages, so the composition root builds each once.

use async_trait::async_trait;
use factory_domain::contracts::SpecificationContract;
use factory_domain::contracts::specification_contract::{ApprovalBasis, SpecApproverRole};
use factory_domain::ids::PrincipalId;
use factory_domain::values::{Sha256Digest, Timestamp};
use factory_domain::vocabulary::Fidelity;
use factory_ports::paths::CommitSha;

pub use crate::stages::implementation::seams::{
    ReworkContext, ReworkSource, WorkspaceAccess, WorkspaceAgentSpecs,
};
pub use crate::stages::intake::seams::{AgentOutputCheck, CapabilityProbes, SeamError};

use crate::handlers::RunIdentity;

/// A person's decision to approve a specification, as the engine recorded it.
///
/// Authorization is a structured fact. The stage never reads it from the text of a specification,
/// of an issue or of an answer: the composition root builds this record from the decision that the
/// engine stored with the identity and the role of the person who made it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRecord {
    /// Who decided.
    pub principal: PrincipalId,
    /// In which role.
    pub role: SpecApproverRole,
    /// On what basis.
    pub basis: ApprovalBasis,
    /// When.
    pub at: Timestamp,
}

/// Where approvals come from.
#[async_trait]
pub trait SpecApprovals: Send + Sync {
    /// Says whether this reads the store (`real`) or a list (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// The approval recorded for this stage run **of the draft with this hash**, or `None`. An
    /// approval of another draft is not an approval of this one.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`] when the store cannot be read. The stage fails closed.
    async fn approval(
        &self,
        run: &RunIdentity,
        draft: &Sha256Digest,
    ) -> Result<Option<ApprovalRecord>, SeamError>;
}

/// The draft a stage run left when it stopped to ask a person. A later attempt of the same stage
/// run starts from it, so the person approves the text they saw and not a new one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftRecord {
    /// The commit that holds the specification files.
    pub commit: CommitSha,
    /// The feature directory.
    pub feature_directory: String,
    /// The bytes of the draft contract.
    pub contract: Vec<u8>,
    /// The bytes of the evidence document.
    pub evidence: Vec<u8>,
}

/// Where a stage run keeps its draft between attempts. The composition root implements it over the
/// artifact store and the stage run's links.
#[async_trait]
pub trait SpecDrafts: Send + Sync {
    /// Says whether this is durable (`real`) or a list (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Keeps the draft of the stage run.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`].
    async fn save(&self, run: &RunIdentity, record: DraftRecord) -> Result<(), SeamError>;

    /// The draft the stage run kept, if any.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`].
    async fn load(&self, run: &RunIdentity) -> Result<Option<DraftRecord>, SeamError>;
}

/// An approved specification that a new revision replaces.
#[derive(Debug, Clone, PartialEq)]
pub struct PreviousSpec {
    /// The frozen contract.
    pub contract: SpecificationContract,
    /// The commit that holds its files.
    pub commit: CommitSha,
    /// Why the requirement changed, in plain English.
    pub reason: String,
}

/// Where the stage learns that its run revises a frozen specification.
#[async_trait]
pub trait SpecHistory: Send + Sync {
    /// The specification this run revises, or `None` for the first one of the job.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`]. The stage fails closed: a revision that cannot read its basis
    /// must not run as if it were a first specification.
    async fn previous(&self, run: &RunIdentity) -> Result<Option<PreviousSpec>, SeamError>;
}
