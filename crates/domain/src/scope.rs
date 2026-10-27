//! Tenant scope.
//!
//! ADR 0007 says every repository method takes a `TenantScope` and that there is no method
//! without one, so a query that forgets the tenant does not compile. This is the value.
//!
//! A scope is made by the code that has authorized the caller. It has no `Deserialize`
//! implementation on purpose: a scope must never be read from a request body or a file.

use crate::ids::TenantId;

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
