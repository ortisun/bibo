//! Who is calling, and what the allowlist lets them do.
//!
//! Authentication is one lookup: the SHA-256 of the presented token and the audience of this API
//! go to `Store::resolve_token`, which answers with the tenant and the principal, or with nothing
//! for an unknown, expired, revoked or wrong-audience token and for a disabled owner or tenant
//! alike. The caller learns none of those reasons: every failure is the same 401.
//!
//! Authorization is a second, separate step. The roles come from the protected allowlist, looked
//! up by the **numeric GitHub user id** of the principal behind the token (`Authority::roles`).
//! A token proves which principal is calling. It grants no role: a person removed from the
//! allowlist loses the right on the next request, whatever their token says, and a login string is
//! never read.

use axum::http::HeaderMap;
use factory_domain::ids::{PrincipalId, TenantId};
use factory_domain::scope::TenantScope;
use factory_domain::vocabulary::HumanRole;
use factory_ports::store::PrincipalKind;
use factory_workflow::commands::AuthorityError;

use crate::answers::ApiError;
use crate::state::ApiState;
use crate::tokens;

/// An authenticated caller.
#[derive(Debug, Clone)]
pub struct Caller {
    /// The tenant of the token.
    pub tenant: TenantId,
    /// The principal behind the token.
    pub principal: PrincipalId,
    /// The numeric GitHub user id, for a human principal.
    pub github_user_id: Option<u64>,
    /// The roles the allowlist gives this person now.
    pub roles: Vec<HumanRole>,
}

impl Caller {
    /// The scope of everything this caller does in the store.
    #[must_use]
    pub const fn scope(&self) -> TenantScope {
        TenantScope::new(self.tenant)
    }

    /// Refuses unless the caller holds `role`.
    ///
    /// # Errors
    /// [`ApiError::Forbidden`].
    pub fn require(&self, role: HumanRole) -> Result<(), ApiError> {
        if self.roles.contains(&role) {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }

    /// Refuses unless the caller holds at least one of `roles`.
    ///
    /// # Errors
    /// [`ApiError::Forbidden`].
    pub fn require_any(&self, roles: &[HumanRole]) -> Result<(), ApiError> {
        if roles.iter().any(|role| self.roles.contains(role)) {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }

    /// Refuses unless the caller is on the allowlist for something.
    ///
    /// # Errors
    /// [`ApiError::Forbidden`].
    pub fn require_listed(&self) -> Result<(), ApiError> {
        if self.roles.is_empty() {
            Err(ApiError::Forbidden)
        } else {
            Ok(())
        }
    }
}

/// Authenticates a request.
///
/// # Errors
/// [`ApiError::Unauthorized`] for every credential that does not resolve, whatever the reason;
/// [`ApiError::Unavailable`] when the database or the allowlist cannot answer (the request is
/// refused, never let through).
pub async fn authenticate(state: &ApiState, headers: &HeaderMap) -> Result<Caller, ApiError> {
    let token = tokens::bearer(headers).ok_or(ApiError::Unauthorized)?;
    let hash = tokens::hash_token(token);
    let resolved = state
        .ports
        .store
        .resolve_token(&hash, &state.audience)
        .await?
        .ok_or(ApiError::Unauthorized)?;

    let mut tx = state
        .ports
        .store
        .begin(TenantScope::new(resolved.tenant))
        .await?;
    let found = tx.get_principal(resolved.principal).await;
    // The read is over; nothing was written.
    let _ = tx.rollback().await;
    let principal = found?;
    if principal.disabled_at.is_some() {
        return Err(ApiError::Unauthorized);
    }
    let github_user_id = match principal.kind {
        PrincipalKind::Human { github_user_id } => Some(github_user_id),
        PrincipalKind::Service => None,
    };
    let roles = state
        .ports
        .authority
        .roles(resolved.tenant, resolved.principal)
        .await
        .map_err(|error| match error {
            AuthorityError::Unavailable => ApiError::Unavailable,
        })?;
    Ok(Caller {
        tenant: resolved.tenant,
        principal: resolved.principal,
        github_user_id,
        roles,
    })
}
