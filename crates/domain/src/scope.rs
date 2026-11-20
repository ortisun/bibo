//! Tenant scope.
//!
//! ADR 0007 says every repository method takes a `TenantScope` and that there is no method
//! without one, so a query that forgets the tenant does not compile. This is the value.
//!
//! A scope is made by the code that has authorized the caller. It has no `Deserialize`
//! implementation on purpose: a scope must never be read from a request body or a file.

use crate::ids::{PrincipalId, RepositoryId, TenantId};

/// The tenant a call is allowed to see and change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantScope {
    tenant_id: TenantId,
}

/// A call tried to reach a row that belongs to another tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a call scoped to tenant {scope} asked for data of tenant {requested}")]
pub struct CrossTenantAccess {
    /// The tenant the call was scoped to.
    pub scope: TenantId,
    /// The tenant that owns the data the call asked for.
    pub requested: TenantId,
}

impl TenantScope {
    /// Scopes a call to one tenant. Call this only after the caller has been authorized for it.
    #[must_use]
    pub const fn new(tenant_id: TenantId) -> Self {
        Self { tenant_id }
    }

    /// The tenant of this scope.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// True when `tenant_id` is the tenant of this scope.
    #[must_use]
    pub fn admits(&self, tenant_id: TenantId) -> bool {
        self.tenant_id == tenant_id
    }

    /// Succeeds only for the scope's own tenant.
    ///
    /// # Errors
    /// Returns [`CrossTenantAccess`] for any other tenant.
    pub fn require(&self, tenant_id: TenantId) -> Result<(), CrossTenantAccess> {
        if self.admits(tenant_id) {
            Ok(())
        } else {
            Err(CrossTenantAccess {
                scope: self.tenant_id,
                requested: tenant_id,
            })
        }
    }
}

/// The scope of the webhook receiver for an event that belongs to no tenant, such as a
/// delivery rejected before it could be matched to one.
///
/// It is used only with `Store::record_platform_audit`. It has no way to open a transaction, so
/// no job can be created under it. Rust cannot restrict a constructor to a named crate, so the
/// architecture check ST-13 names the callers: the `api` binary's webhook handler only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformScope(());

impl PlatformScope {
    /// The receiver's scope.
    #[must_use]
    pub const fn receiver() -> Self {
        Self(())
    }
}

/// What a token lookup returns: the tenant a token belongs to and the principal behind it.
///
/// `TenantScope::new` stays public, so the architecture check ST-13 names the crates that may
/// build this value: `storage` and `testkit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedPrincipal {
    /// The tenant the token belongs to.
    pub tenant: TenantId,
    /// The principal the token stands for.
    pub principal: PrincipalId,
}

/// What an installation lookup returns: the tenant and the repository an installation covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedRepository {
    /// The tenant that registered the repository.
    pub tenant: TenantId,
    /// The registered repository.
    pub repository: RepositoryId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_platform_scope_is_a_value_with_one_constructor() {
        assert_eq!(PlatformScope::receiver(), PlatformScope::receiver());
    }

    #[test]
    fn resolved_values_carry_their_ids() {
        let tenant = TenantId::from_uuid(uuid::Uuid::from_u128(1));
        let principal = PrincipalId::from_uuid(uuid::Uuid::from_u128(2));
        let resolved = ResolvedPrincipal { tenant, principal };
        assert_eq!(resolved.tenant, tenant);
        assert_eq!(resolved.principal, principal);
    }
}
