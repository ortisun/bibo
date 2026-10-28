//! Who may do what: the seam to the protected configuration.
//!
//! Authority comes from a named allowlist in protected configuration, never from a GitHub role
//! (ADR 0009 item 5, `policies/approval.yaml` `authority.source`). The engine does not read that
//! configuration itself: the composition root passes an implementation of [`Authority`] that does.
//! Every call reads the allowlist as it is now, so removing a person from it takes effect on the
//! next decision (NT-AUTHZ-04).

use async_trait::async_trait;
use factory_domain::ids::{JobId, PrincipalId, RepositoryId, TenantId};
use factory_domain::machines::guards::AdmissionFacts;
use factory_domain::vocabulary::{Fidelity, HumanRole};

/// The protected configuration could not be read. The engine fails closed: it treats this as a
/// denial and never as an allowance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    /// The configuration source cannot be reached or does not parse.
    #[error("the protected configuration cannot be read")]
    Unavailable,
}

/// Answers the questions the guards ask about people, quotas and policy.
///
/// # Preconditions
/// The implementation reads the protected configuration source only, never the target
/// repository, and never a GitHub permission as the authority for an action.
///
/// # Postconditions
/// Each answer reflects the configuration at the time of the call. A principal that is not on the
/// list has no roles. An expired entry counts as absent.
///
/// # Errors
/// [`AuthorityError::Unavailable`] when the configuration cannot be read. The engine then denies.
///
/// # Idempotency
/// Every method is a read.
#[async_trait]
pub trait Authority: Send + Sync {
    /// Says whether this reads the real protected configuration (`real`) or a fixed list (`fake`).
    /// A production run refuses `fake`.
    fn fidelity(&self) -> Fidelity;

    /// The facts guard `G_ADMISSION_OK` reads for a job that `requester` asked for on
    /// `repository`: whether the requester is on the allowlist, the tenant and the repository are
    /// within their quotas, the repository is registered and enabled, policy allows the class of
    /// request, and the repository passed the protection preflight. The repository is part of the
    /// question because three of those facts are about it.
    async fn admission(
        &self,
        tenant: TenantId,
        requester: PrincipalId,
        repository: RepositoryId,
    ) -> Result<AdmissionFacts, AuthorityError>;

    /// The roles the principal holds on the tenant, now.
    async fn roles(
        &self,
        tenant: TenantId,
        principal: PrincipalId,
    ) -> Result<Vec<HumanRole>, AuthorityError>;

    /// Whether the concurrency quota allows another attempt for the job.
    async fn concurrency_allows(
        &self,
        tenant: TenantId,
        job: JobId,
    ) -> Result<bool, AuthorityError>;
}
