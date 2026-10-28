//! The engine's `Authority` seam over the allowlist file and the principal rows.
//!
//! Authority comes from the named allowlist of the protected configuration and never from a
//! GitHub role (ADR 0009 item 5). Every call reads the file as it is now, so removing a person
//! takes effect on the next decision. A file that cannot be read is `AuthorityError::Unavailable`,
//! which the engine treats as a denial.
//!
//! # Admission
//!
//! `Authority::admission(tenant, requester, repository)` is asked with the repository, so the three
//! facts that depend on it are read from its row and its jobs:
//!
//! * `repository_registered_and_enabled` is true when the row exists and is switched on.
//! * `protection_preflight_passed` is the result recorded for the repository. A repository with no
//!   passed preflight is admitted and limited to level L0 (ADR 0009).
//! * `tenant_within_job_quota` counts the repository's jobs that have not ended against the sum of
//!   the policy's running and queued caps per repository.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::ids::{JobId, PrincipalId, RepositoryId, TenantId};
use factory_domain::machines::guards::AdmissionFacts;
use factory_domain::policy::PolicyEngine;
use factory_domain::policy::decision::Designation;
use factory_domain::scope::TenantScope;
use factory_domain::state::Status;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::{Fidelity, HumanRole};
use factory_ports::clock::Clock;
use factory_ports::store::{JobFilter, PrincipalKind, Store, StoreError};
use factory_workflow::commands::{Authority, AuthorityError};

use crate::seams::FileAllowlist;

/// The authority of the worker and, later, of the API.
pub struct StoreAuthority {
    store: Arc<dyn Store>,
    allowlist: Arc<FileAllowlist>,
    policy: Arc<PolicyEngine>,
    clock: Arc<dyn Clock>,
}

impl StoreAuthority {
    /// An authority over the store, the allowlist file, the policy and the clock.
    #[must_use]
    pub fn new(
        store: Arc<dyn Store>,
        allowlist: Arc<FileAllowlist>,
        policy: Arc<PolicyEngine>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            store,
            allowlist,
            policy,
            clock,
        }
    }

    async fn github_user(
        &self,
        tenant: TenantId,
        principal: PrincipalId,
    ) -> Result<Option<u64>, AuthorityError> {
        let mut tx = self
            .store
            .begin(TenantScope::new(tenant))
            .await
            .map_err(|_| AuthorityError::Unavailable)?;
        let found = tx.get_principal(principal).await;
        let _ = tx.rollback().await;
        match found {
            Ok(principal) => Ok(match (principal.kind, principal.disabled_at) {
                (PrincipalKind::Human { github_user_id }, None) => Some(github_user_id),
                _ => None,
            }),
            Err(StoreError::NotFound) => Ok(None),
            Err(_) => Err(AuthorityError::Unavailable),
        }
    }

    /// The designations a person holds for a tenant now: listed, for that tenant, not expired.
    fn designations(
        &self,
        tenant: TenantId,
        github_user: u64,
    ) -> Result<BTreeSet<Designation>, AuthorityError> {
        let (_, entries) = self
            .allowlist
            .entries()
            .map_err(|_| AuthorityError::Unavailable)?;
        let now: Timestamp = self.clock.now();
        Ok(entries
            .into_iter()
            .filter(|entry| entry.tenant == tenant && entry.github_user_id.get() == github_user)
            .filter(|entry| entry.expires_at.as_ref().is_none_or(|end| *end > now))
            .flat_map(|entry| entry.designations)
            .collect())
    }
}

#[async_trait]
impl Authority for StoreAuthority {
    fn fidelity(&self) -> Fidelity {
        self.store.fidelity()
    }

    async fn admission(
        &self,
        tenant: TenantId,
        requester: PrincipalId,
        repository: RepositoryId,
    ) -> Result<AdmissionFacts, AuthorityError> {
        let requester_on_allowlist = match self.github_user(tenant, requester).await? {
            Some(user) => self
                .designations(tenant, user)?
                .contains(&Designation::Requester),
            None => false,
        };
        let (active, enabled, preflight_passed) = {
            let mut tx = self
                .store
                .begin(TenantScope::new(tenant))
                .await
                .map_err(|_| AuthorityError::Unavailable)?;
            let jobs = tx
                .list_jobs(
                    JobFilter {
                        statuses: Vec::new(),
                        repository: Some(repository),
                    },
                    None,
                    1000,
                )
                .await;
            let row = tx.get_repository(repository).await;
            let _ = tx.rollback().await;
            let active = jobs
                .map_err(|_| AuthorityError::Unavailable)?
                .rows
                .iter()
                .filter(|job| !job.value.status.is_terminal())
                .count() as u64;
            // A repository the tenant does not have is not registered. Only a store that cannot
            // answer is an error.
            match row {
                Ok(found) => (
                    active,
                    found.value.enabled,
                    found.value.protection_preflight_passed,
                ),
                Err(StoreError::NotFound) => (active, false, false),
                Err(_) => return Err(AuthorityError::Unavailable),
            }
        };
        let cap = self.policy.budget.max_running_jobs_per_repo()
            + self.policy.budget.max_queued_jobs_per_repo();
        Ok(AdmissionFacts {
            requester_on_allowlist,
            tenant_within_job_quota: active < cap,
            repository_registered_and_enabled: enabled,
            policy_allows_request_class: true,
            protection_preflight_passed: preflight_passed,
        })
    }

    async fn roles(
        &self,
        tenant: TenantId,
        principal: PrincipalId,
    ) -> Result<Vec<HumanRole>, AuthorityError> {
        let Some(user) = self.github_user(tenant, principal).await? else {
            return Ok(Vec::new());
        };
        Ok(self
            .designations(tenant, user)?
            .into_iter()
            .filter_map(|designation| match designation {
                Designation::Requester => Some(HumanRole::Requester),
                Designation::Operator => Some(HumanRole::Operator),
                Designation::Approver => Some(HumanRole::Approver),
                Designation::SecurityApprover => Some(HumanRole::SecurityApprover),
                Designation::OrgAdmin => Some(HumanRole::OrgAdmin),
                // The engine has no repository-admin role; the designation matters to the policy.
                Designation::RepoAdmin => None,
            })
            .collect())
    }

    async fn concurrency_allows(
        &self,
        _tenant: TenantId,
        _job: JobId,
    ) -> Result<bool, AuthorityError> {
        // One attempt at a time per worker is the Slice 1 concurrency: the claim batch of 1 and
        // the single loop enforce it. The per-repository running cap of the policy needs the
        // repository, which the engine does not pass.
        Ok(true)
    }
}
