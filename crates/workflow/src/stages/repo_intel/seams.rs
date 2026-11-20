//! What the repository stage needs from the outside and no port offers. See
//! `crate::stages::intake::seams` for why these are traits of this crate.

use async_trait::async_trait;
use factory_domain::contracts::ProjectManifest;
use factory_domain::ids::{AttemptId, JobId, TenantId};
use factory_domain::vocabulary::Fidelity;
use factory_ports::paths::{BranchName, RepoRef};
use factory_ports::sandbox::SandboxSpec;
use factory_ports::workspace::WorkspaceMounts;

pub use crate::stages::intake::seams::SeamError;

/// The repository a job works on and the branch to read, as the registered row holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRepository {
    /// The repository, by the name the row was registered under.
    pub repo: RepoRef,
    /// The branch whose tip is the base of the job: the default branch of the repository.
    pub branch: BranchName,
    /// GitHub's numeric id of the repository, as the registered row holds it. The design gate asks
    /// who may approve a design with this id first, the way the claim hook and the API do (finding
    /// RH-3), so that a repository that was renamed or transferred keeps its approvers and a new
    /// repository under the old name does not.
    pub github_repository_id: u64,
}

/// Finds the repository of a job. The tenant registered it, and the job names it.
#[async_trait]
pub trait JobRepository: Send + Sync {
    /// Says whether this reads the real store (`real`) or a fixed answer (`fake`). The profile
    /// check refuses a `fake` in production (RR-6): a stand-in that names any repository names the
    /// one the job is built against.
    fn fidelity(&self) -> Fidelity;

    /// The repository and branch of the job.
    ///
    /// # Errors
    /// [`SeamError::NotFound`] when the job has none.
    async fn of(&self, tenant: TenantId, job: JobId) -> Result<TargetRepository, SeamError>;
}

/// Builds the sandbox spec of the `verify` profile: no network, a read-only checkout, the image of
/// the project, and the limits of the policy.
pub trait VerifySandboxSpecs: Send + Sync {
    /// The spec for a verify sandbox over this checkout.
    ///
    /// # Errors
    /// [`SeamError::Unavailable`] when the policy or the image cannot be resolved.
    fn verify_spec(
        &self,
        job: JobId,
        attempt: AttemptId,
        mounts: WorkspaceMounts,
    ) -> Result<SandboxSpec, SeamError>;
}

/// Why a project manifest was not accepted. The text is for the audit log and a person, and is
/// shown to nobody as an instruction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the project manifest is not valid: {0}")]
pub struct ManifestProblem(pub String);

/// Reads `.factory/project.yaml`. The composition root implements it with
/// `factory_contracts::loader::DefinitionLoader::project_manifest`, which parses the restricted YAML
/// and checks the manifest against its schema.
pub trait ProjectManifestParser: Send + Sync {
    /// Says whether this is the parser of the contracts crate (`real`) or a stand-in that accepts
    /// what it is given (`fake`). The profile check refuses a `fake` in production (RR-6).
    fn fidelity(&self) -> Fidelity;

    /// Parses the manifest from the bytes read at the protected base commit.
    ///
    /// # Errors
    /// [`ManifestProblem`].
    fn parse(&self, file: &str, bytes: &[u8]) -> Result<ProjectManifest, ManifestProblem>;
}
