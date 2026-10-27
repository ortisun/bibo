//! People and services that act on jobs.
//!
//! The port names a principal by an `external_ref`, "how the outside world names them, for
//! example a numeric GitHub user id". The table splits that in two. A reference that is a positive
//! whole number is a human with that GitHub user id (`kind = 'human'`). Anything else is a service
//! with that text as its login (`kind = 'service'`). The reference is read back in the same form.

use diesel::sql_query;
use diesel::sql_types::{BigInt, Nullable, Text, Timestamptz, Uuid as SqlUuid};
use diesel::{OptionalExtension, QueryableByName};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use factory_domain::ids::{PrincipalId, TenantId};
use factory_domain::values::NonEmptyString;
use factory_ports::store::{NewPrincipal, Principal, StoreError};
use time::OffsetDateTime;

use super::conv::{
    corrupt, from_column, principal_from_column, principal_to_column, tenant_from_column,
    tenant_to_column, to_column,
};
use super::error::{Failure, constraint, generic};

#[derive(QueryableByName)]
struct PrincipalRow {
    #[diesel(sql_type = SqlUuid)]
    tenant_id: uuid::Uuid,
    #[diesel(sql_type = SqlUuid)]
    id: uuid::Uuid,
    #[diesel(sql_type = Nullable<BigInt>)]
    github_user_id: Option<i64>,
    #[diesel(sql_type = Nullable<Text>)]
    login: Option<String>,
    #[diesel(sql_type = Timestamptz)]
    created_at: OffsetDateTime,
}

fn principal_from_row(row: PrincipalRow) -> Result<Principal, StoreError> {
    let reference = match (row.github_user_id, row.login) {
        (Some(id), _) => id.to_string(),
        (None, Some(login)) => login,
        (None, None) => return Err(corrupt("principal without a reference")),
    };
    Ok(Principal {
        id: principal_from_column(row.id),
        tenant_id: tenant_from_column(row.tenant_id),
        external_ref: NonEmptyString::parse(&reference)
            .map_err(|_| corrupt("principal reference"))?,
        created_at: from_column(row.created_at),
    })
}

pub(super) async fn insert(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    new: NewPrincipal,
) -> Result<Principal, StoreError> {
    let tenant_raw = tenant_to_column(tenant);
    let reference = new.external_ref.as_str();
    let github_user_id = reference.parse::<i64>().ok().filter(|id| *id > 0);
    if github_user_id.is_none() {
        // A service has no unique key in the table, so the reference is checked here.
        let taken = sql_query(
            "SELECT tenant_id, id, github_user_id, login, created_at FROM principals \
              WHERE tenant_id = $1 AND kind = 'service' AND login = $2",
        )
        .bind::<SqlUuid, _>(tenant_raw)
        .bind::<Text, _>(reference)
        .get_result::<PrincipalRow>(connection)
        .await
        .optional()
        .map_err(|error| generic("insert_principal", &error))?;
        if taken.is_some() {
            return Err(constraint(
                "the external reference is already recorded",
                None,
            ));
        }
    }
    sql_query(
        "INSERT INTO principals (tenant_id, id, kind, github_user_id, login, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind::<SqlUuid, _>(tenant_raw)
    .bind::<SqlUuid, _>(principal_to_column(new.id))
    .bind::<Text, _>(if github_user_id.is_some() {
        "human"
    } else {
        "service"
    })
    .bind::<Nullable<BigInt>, _>(github_user_id)
    .bind::<Nullable<Text>, _>(Some(reference.to_owned()))
    .bind::<Timestamptz, _>(to_column(&new.created_at))
    .execute(connection)
    .await
    .map_err(|error| match Failure::of(&error) {
        Failure::Unique(name) => constraint("unique violation", name.as_deref()),
        Failure::Check(name) => constraint("check violation", name.as_deref()),
        _ => generic("insert_principal", &error),
    })?;
    get(connection, tenant, new.id).await
}

pub(super) async fn get(
    connection: &mut AsyncPgConnection,
    tenant: TenantId,
    id: PrincipalId,
) -> Result<Principal, StoreError> {
    let row = sql_query(
        "SELECT tenant_id, id, github_user_id, login, created_at FROM principals \
          WHERE tenant_id = $1 AND id = $2",
    )
    .bind::<SqlUuid, _>(tenant_to_column(tenant))
    .bind::<SqlUuid, _>(principal_to_column(id))
    .get_result::<PrincipalRow>(connection)
    .await
    .optional()
    .map_err(|error| generic("get_principal", &error))?;
    row.map_or(Err(StoreError::NotFound), principal_from_row)
}
