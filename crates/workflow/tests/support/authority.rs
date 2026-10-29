//! A fixed list standing in for the protected configuration.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use factory_domain::ids::{JobId, PrincipalId, RepositoryId, TenantId};
use factory_domain::machines::guards::AdmissionFacts;
use factory_domain::vocabulary::{Fidelity, HumanRole};
use factory_workflow::commands::{Authority, AuthorityError};

struct State {
    admission: AdmissionFacts,
    roles: HashMap<PrincipalId, Vec<HumanRole>>,
    concurrency: bool,
    unavailable: bool,
}

/// An authority a test sets by hand. It reports fidelity `fake`.
pub struct StaticAuthority {
    state: Mutex<State>,
}

impl StaticAuthority {
    /// An authority that admits every job and gives nobody a role.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State {
                admission: AdmissionFacts {
                    requester_on_allowlist: true,
                    tenant_within_job_quota: true,
                    repository_registered_and_enabled: true,
                    policy_allows_request_class: true,
                    protection_preflight_passed: true,
                },
                roles: HashMap::new(),
                concurrency: true,
                unavailable: false,
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("the lock is never poisoned")
    }

    /// Changes the admission facts.
    pub fn set_admission(&self, change: impl FnOnce(&mut AdmissionFacts)) {
        change(&mut self.state().admission);
    }

    /// Gives a principal these roles, replacing what it had.
    pub fn grant(&self, principal: PrincipalId, roles: &[HumanRole]) {
        self.state().roles.insert(principal, roles.to_vec());
    }

    /// Removes a principal from the list.
    pub fn revoke(&self, principal: PrincipalId) {
        self.state().roles.remove(&principal);
    }

    /// Lets the concurrency quota allow or refuse another attempt.
    pub fn set_concurrency(&self, allows: bool) {
        self.state().concurrency = allows;
    }

    /// Makes the protected configuration unreadable.
    pub fn set_unavailable(&self, unavailable: bool) {
        self.state().unavailable = unavailable;
    }
}

#[async_trait]
impl Authority for StaticAuthority {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn admission(
        &self,
        _tenant: TenantId,
        _requester: PrincipalId,
        _repository: RepositoryId,
    ) -> Result<AdmissionFacts, AuthorityError> {
        let state = self.state();
        if state.unavailable {
            return Err(AuthorityError::Unavailable);
        }
        Ok(state.admission)
    }

    async fn roles(
        &self,
        _tenant: TenantId,
        principal: PrincipalId,
    ) -> Result<Vec<HumanRole>, AuthorityError> {
        let state = self.state();
        if state.unavailable {
            return Err(AuthorityError::Unavailable);
        }
        Ok(state.roles.get(&principal).cloned().unwrap_or_default())
    }

    async fn concurrency_allows(
        &self,
        _tenant: TenantId,
        _job: JobId,
    ) -> Result<bool, AuthorityError> {
        let state = self.state();
        if state.unavailable {
            return Err(AuthorityError::Unavailable);
        }
        Ok(state.concurrency)
    }
}
