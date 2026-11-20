//! The facts of the solo mode about a repository, read from the store and the allowlist (ADR 0021).
//!
//! The policy turns two facts into the solo fact (`AuthorityPolicy::solo_fact`): whether the
//! repository is marked `single_maintainer`, and how many active people may approve on it. This
//! module reads the second, the same way for every caller (the engine's `Authority`, the approval
//! sources of the worker and the API), with the one counter of people
//! ([`count_active_people`](crate::repository_changes::count_active_people)). An `approver` and a
//! different `security_approver` are two people; an entry that has expired, or that is narrowed to
//! other repositories, is not counted; nor is a listed id with no active human principal.

use factory_domain::ids::{RepositoryId, TenantId};
use factory_domain::policy::authority::RepositoryIdentity;
use factory_domain::values::Timestamp;
use factory_ports::store::{StoreError, Tx};
use factory_workflow::stages::approval::SoloInputs;

use crate::repository_changes::count_active_people;
use crate::seams::FileAllowlist;

/// The designations that approve, by the names of the action table.
pub const APPROVING: [&str; 2] = ["approver", "security_approver"];

/// A reading that could not be made. The caller refuses or waits.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SoloReadError {
    /// The store could not answer.
    #[error("the store could not answer: {0}")]
    Store(StoreError),
    /// The allowlist could not be read.
    #[error("the allowlist cannot be read")]
    Allowlist,
}

/// The facts of the solo mode for `repository`, now, read in `tx` (the tenant's transaction).
///
/// # Errors
/// [`SoloReadError`] when the repository, a principal or the allowlist cannot be read.
pub async fn solo_inputs(
    tx: &mut dyn Tx,
    allowlist: &FileAllowlist,
    tenant: TenantId,
    repository: RepositoryId,
    now: Timestamp,
) -> Result<SoloInputs, SoloReadError> {
    let row = tx
        .get_repository(repository)
        .await
        .map_err(SoloReadError::Store)?
        .value;
    let roles: Vec<String> = APPROVING.iter().map(|name| (*name).to_owned()).collect();
    let holders = allowlist
        .holders_of(
            tenant,
            &roles,
            &RepositoryIdentity::registered(&row.full_name, row.github_repository_id.0),
            now,
        )
        .map_err(|_| SoloReadError::Allowlist)?;
    let people = count_active_people(tx, &holders)
        .await
        .map_err(SoloReadError::Store)?;
    Ok(SoloInputs {
        single_maintainer: row.single_maintainer,
        // More people than a `u32` holds is more than one, which is all that matters.
        approver_count: u32::try_from(people).unwrap_or(u32::MAX),
    })
}
