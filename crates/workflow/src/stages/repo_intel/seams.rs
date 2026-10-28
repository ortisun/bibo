//! What the repository stage needs from the outside and no port offers. See
//! `crate::stages::intake::seams` for why these are traits of this crate.

use async_trait::async_trait;
use factory_domain::contracts::ProjectManifest;
use factory_domain::ids::{AttemptId, JobId, TenantId};
use factory_ports::paths::{BranchName, RepoRef};
use factory_ports::sandbox::SandboxSpec;
use factory_ports::workspace::WorkspaceMounts;

pub use crate::stages::intake::seams::SeamError;

/// The repository a job works on and the branch to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRepository {
    /// The repository.
    pub repo: RepoRef,
    /// The branch whose tip is the base of the job: the default branch of the repository.
    pub branch: BranchName,
}

/// Finds the repository of a job. The tenant registered it, and the job names it.
#[async_trait]
pub trait JobRepository: Send + Sync {
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
    /// Parses the manifest from the bytes read at the protected base commit.
    ///
    /// # Errors
    /// [`ManifestProblem`].
    fn parse(&self, file: &str, bytes: &[u8]) -> Result<ProjectManifest, ManifestProblem>;
}
