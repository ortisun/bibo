//! The two lookups that happen before a tenant is known (ADR 0012, section 4).
//!
//! Authenticating an API token and binding a webhook to a repository cannot name a tenant, because
//! finding it is their job. They call two `SECURITY DEFINER` functions, owned by the `factory_lookup`
//! role, through the API login. They run outside a transaction as plain function calls, with no
//! tenant setting.
//!
//! A miss gives **no reason**. The functions return zero rows for an unknown token, an expired
//! one, a revoked one, a wrong audience, a disabled owner or a disabled tenant; for an unknown
//! installation, a pair that does not belong together, a disabled repository or a disabled tenant.
//! These methods return `Ok(None)` for all of them, so a caller cannot tell one from another.
//!
//! These two methods are not part of the `Store` port. ADR 0012 says the port gains them, and the
//! port has not been changed yet, so they are methods of `PgStore` (see the handover report).

use diesel::sql_query;
use diesel::sql_types::{BigInt, Bytea, Text, Uuid as SqlUuid};
use diesel::{OptionalExtension, QueryableByName};
use diesel_async::RunQueryDsl;
use factory_domain::ids::{PrincipalId, TenantId};
use factory_ports::store::StoreError;
use uuid::Uuid;

use super::conv::{principal_from_column, tenant_from_column};
use super::error::generic;
use super::store::PgStore;

/// Who a token belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedToken {
    /// The tenant of the token.
    pub tenant: TenantId,
    /// The principal that owns it.
    pub principal: PrincipalId,
}

/// The tenant and repository that a webhook belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedRepository {
    /// The tenant that owns the repository.
    pub tenant: TenantId,
    /// The repository.
    pub repository: Uuid,
}

#[derive(QueryableByName)]
struct TokenRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    principal_id: Uuid,
}

#[derive(QueryableByName)]
struct RepositoryRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    repository_id: Uuid,
}

impl PgStore {
    /// Finds the owner of a token from the SHA-256 of the presented token and the audience the API
    /// serves. `None` for every kind of miss.
    ///
    /// # Errors
    /// `ScopeNotAllowed` when this store's login is not the API login, `Unavailable` when the
    /// database cannot be reached.
    pub async fn resolve_token(
        &self,
        token_sha256: &[u8; 32],
        audience: &str,
    ) -> Result<Option<ResolvedToken>, StoreError> {
        if !self.shared.resolver {
            return Err(StoreError::ScopeNotAllowed);
        }
        let mut connection = self.shared.tenant_pool.get().await?;
        let row = sql_query("SELECT tenant_id, principal_id FROM resolve_token($1, $2)")
            .bind::<Bytea, _>(token_sha256.to_vec())
            .bind::<Text, _>(audience)
            .get_result::<TokenRow>(&mut *connection)
            .await
            .optional()
            .map_err(|error| generic("resolve_token", &error))?;
        Ok(row.map(|row| ResolvedToken {
            tenant: tenant_from_column(row.tenant_id),
            principal: principal_from_column(row.principal_id),
        }))
    }

    /// Finds the tenant and repository of a webhook from the GitHub installation id and the GitHub
    /// repository id. `None` for every kind of miss.
    ///
    /// # Errors
    /// `ScopeNotAllowed` when this store's login is not the API login, `Unavailable` when the
    /// database cannot be reached.
    pub async fn resolve_installation(
        &self,
        installation_id: i64,
        github_repository_id: i64,
    ) -> Result<Option<ResolvedRepository>, StoreError> {
        if !self.shared.resolver {
            return Err(StoreError::ScopeNotAllowed);
        }
        let mut connection = self.shared.tenant_pool.get().await?;
        let row = sql_query("SELECT tenant_id, repository_id FROM resolve_installation($1, $2)")
            .bind::<BigInt, _>(installation_id)
            .bind::<BigInt, _>(github_repository_id)
            .get_result::<RepositoryRow>(&mut *connection)
            .await
            .optional()
            .map_err(|error| generic("resolve_installation", &error))?;
        Ok(row.map(|row| ResolvedRepository {
            tenant: tenant_from_column(row.tenant_id),
            repository: row.repository_id,
        }))
    }
}
