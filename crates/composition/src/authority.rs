//! The engine's `Authority` seam over the allowlist file and the principal rows.
//!
//! Authority comes from the named allowlist of the protected configuration and never from a
//! GitHub role (ADR 0009 item 5). Every call reads the file as it is now, so removing a person
//! takes effect on the next decision. A file that cannot be read is `AuthorityError::Unavailable`,
//! which the engine treats as a denial.
//!
//! # What the seam cannot answer
//!
//! `Authority::admission(tenant, requester)` is asked without the repository, so the two facts
//! that depend on it cannot be read here:
//!
//! * `repository_registered_and_enabled` is `true`, because a job cannot be received for a
//!   repository row that does not exist. The `enabled` flag is not checked.
//! * `protection_preflight_passed` is `false`, the safe side: the job is admitted and limited to
//!   level L0 until a preflight is recorded.
//!
//! The per-repository job caps of the policy cannot be applied for the same reason. The quota used
//! is the tenant-wide sum of the two caps. These are listed in the README as a mismatch between
//! the engine and the policy.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use factory_domain::ids::{JobId, PrincipalId, TenantId};
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
    ) -> Result<AdmissionFacts, AuthorityError> {
        let requester_on_allowlist = match self.github_user(tenant, requester).await? {
            Some(user) => self
                .designations(tenant, user)?
                .contains(&Designation::Requester),
            None => false,
        };
        let active = {
            let mut tx = self
                .store
                .begin(TenantScope::new(tenant))
                .await
                .map_err(|_| AuthorityError::Unavailable)?;
            let jobs = tx
                .list_jobs(
                    JobFilter {
                        statuses: Vec::new(),
                        repository: None,
                    },
                    None,
                    1000,
                )
                .await;
            let _ = tx.rollback().await;
            jobs.map_err(|_| AuthorityError::Unavailable)?
                .rows
                .iter()
                .filter(|job| !job.value.status.is_terminal())
                .count() as u64
        };
        let cap = self.policy.budget.max_running_jobs_per_repo()
            + self.policy.budget.max_queued_jobs_per_repo();
        Ok(AdmissionFacts {
            requester_on_allowlist,
            tenant_within_job_quota: active < cap,
            repository_registered_and_enabled: true,
            policy_allows_request_class: true,
            protection_preflight_passed: false,
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
