//! What the approval stage and its service need from the outside and no port offers.

use async_trait::async_trait;
use factory_domain::ids::{JobId, StageRunId, TenantId};
use factory_domain::policy::authority::{Allowlist, AutonomyLevel};
use factory_domain::vocabulary::Fidelity;

use super::request::ApprovalRequest;
use crate::handlers::RunIdentity;
use crate::stages::delivery::SeamError;

/// Facts about the people and the policy around a job.
///
/// # Contract
/// * `allowlist` reads the protected configuration as it is now. Nothing is cached, so a person
///   removed from the list loses the right at once (NT-AUTHZ-04).
/// * `request` returns the stored `approval-request` of the stage run, read back by the hash the
///   engine recorded.
/// * Every method is a read.
#[async_trait]
pub trait ApprovalSources: Send + Sync {
    /// Says whether this reads the real configuration (`real`) or fixed values (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// The numeric GitHub id of the person who asked for the job.
    ///
    /// # Errors
    /// [`SeamError`].
    async fn requester(&self, run: &RunIdentity) -> Result<u64, SeamError>;

    /// The allowlist in force now.
    ///
    /// # Errors
    /// [`SeamError`]. The caller refuses: an allowlist that cannot be read allows nobody.
    async fn allowlist(&self, tenant: TenantId) -> Result<Allowlist, SeamError>;

    /// The autonomy level the job runs at.
    ///
    /// # Errors
    /// [`SeamError`].
    async fn level(&self, tenant: TenantId, job: JobId) -> Result<AutonomyLevel, SeamError>;

    /// The request of an approval stage run.
    ///
    /// # Errors
    /// [`SeamError::NotFound`] when the stage run stored none.
    async fn request(
        &self,
        tenant: TenantId,
        stage_run: StageRunId,
    ) -> Result<ApprovalRequest, SeamError>;
}
