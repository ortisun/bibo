//! People and services that act on jobs.
//!
//! A human is named by the immutable numeric GitHub user id, never by the login, which is display
//! text. The table has no version column: a principal is never edited in place, so every row is
//! read back at the first version.

use async_trait::async_trait;
use diesel::sql_types::{BigInt, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel::{OptionalExtension, QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::{PrincipalId, TenantId};
use factory_ports::store::{
    Inserted, NewPrincipal, Principal, PrincipalKind, PrincipalOps, StoreError, Version, Versioned,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::conv::{corrupt, from_column, unsigned_from_column};
use super::error::database;
use super::tx::{PgTx, call};

const COLUMNS: &str = "tenant_id, id, kind, github_user_id, login, created_at, disabled_at";

#[derive(QueryableByName)]
struct PrincipalRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: Uuid,
    #[diesel(sql_type = SqlUuid)]
    id: Uuid,
    #[diesel(sql_type = Text)]
    kind: String,
    #[diesel(sql_type = Nullable<BigInt>)]
    github_user_id: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    login: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: OffsetDateTime,
    #[diesel(sql_type = Nullable<Timestamptz>)]
    disabled_at: Option<OffsetDateTime>,
}

fn principal_from_row(row: PrincipalRow) -> Result<Principal, StoreError> {
    let kind = match (row.kind.as_str(), row.github_user_id) {
        ("human", Some(github)) => PrincipalKind::Human {
            github_user_id: unsigned_from_column(github, "github user id")?,
        },
        ("service", None) => PrincipalKind::Service,
        _ => return Err(corrupt("principal kind")),
    };
    Ok(Principal {
        id: PrincipalId::from_uuid(row.id),
        tenant_id: TenantId::from_uuid(row.tenant_id),
        kind,
        login: row.login,
        created_at: from_column(row.created_at),
        disabled_at: row.disabled_at.map(from_column),
    })
}

fn kind_columns(kind: &PrincipalKind) -> Result<(&'static str, Option<i64>), StoreError> {
    match kind {
        PrincipalKind::Human { github_user_id } => Ok((
            "human",
            Some(i64::try_from(*github_user_id).map_err(|_| {
                StoreError::Constraint(factory_ports::store::ConstraintRule::TextBounds)
            })?),
        )),
        PrincipalKind::Service => Ok(("service", None)),
    }
}

async fn get(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: PrincipalId,
) -> Result<Option<Principal>, StoreError> {
    let row = sql_query(format!(
        "SELECT {COLUMNS} FROM principals WHERE tenant_id = $1 AND id = $2"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(id.as_uuid())
    .get_result::<PrincipalRow>(connection)
    .await
    .optional()
    .map_err(|error| database("get_principal", &error))?;
    row.map(principal_from_row).transpose()
}

async fn insert(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    new: NewPrincipal,
) -> Result<Inserted<Principal>, StoreError> {
    let (kind, github) = kind_columns(&new.kind)?;
    let inserted = sql_query(format!(
        "INSERT INTO principals (tenant_id, id, kind, github_user_id, login) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (tenant_id, id) DO NOTHING RETURNING {COLUMNS}"
    ))
    .bind::<SqlUuid, _>(tenant.as_uuid())
    .bind::<SqlUuid, _>(new.id.as_uuid())
    .bind::<Text, _>(kind)
    .bind::<Nullable<BigInt>, _>(github)
    .bind::<Nullable<Text>, _>(new.login.as_deref())
    .get_result::<PrincipalRow>(connection)
    .await
    .optional()
    .map_err(|error| database("insert_principal", &error))?;
    if let Some(row) = inserted {
        return Ok(Inserted {
            row: Versioned {
                value: principal_from_row(row)?,
                version: Version::FIRST,
            },
            created: true,
        });
    }
    // The id exists. The same content is a replay; other content is a reuse of the id.
    let Some(found) = get(connection, tenant, new.id).await? else {
        return Err(StoreError::NotFound);
    };
    if found.kind == new.kind && found.login == new.login {
        Ok(Inserted {
            row: Versioned {
                value: found,
                version: Version::FIRST,
            },
            created: false,
        })
    } else {
        Err(StoreError::Constraint(
            factory_ports::store::ConstraintRule::IdReusedWithDifferentContent,
        ))
    }
}

#[async_trait]
impl PrincipalOps for PgTx {
    async fn insert_principal(
        &mut self,
        new: NewPrincipal,
    ) -> Result<Inserted<Principal>, StoreError> {
        call!(self, connection, tenant => insert(connection, tenant, new))
    }

    async fn get_principal(&mut self, id: PrincipalId) -> Result<Principal, StoreError> {
        call!(self, connection, tenant => async {
            get(connection, tenant, id).await?.ok_or(StoreError::NotFound)
        })
    }

    async fn find_principal_by_github_user(
        &mut self,
        github_user_id: u64,
    ) -> Result<Option<Principal>, StoreError> {
        call!(self, connection, tenant => async {
            // No row holds a number above the largest signed 64-bit value.
            let Ok(github) = i64::try_from(github_user_id) else {
                return Ok(None);
            };
            let row = sql_query(format!(
                "SELECT {COLUMNS} FROM principals \
                  WHERE tenant_id = $1 AND github_user_id = $2 AND kind = 'human'"
            ))
            .bind::<SqlUuid, _>(tenant.as_uuid())
            .bind::<BigInt, _>(github)
            .get_result::<PrincipalRow>(connection)
            .await
            .optional()
            .map_err(|error| database("find_principal_by_github_user", &error))?;
            row.map(principal_from_row).transpose()
        })
    }
}
