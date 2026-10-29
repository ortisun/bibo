//! The start-up checks (ADR 0007 rule 1, ADR 0012 section 6): is the login of each pool the kind
//! of login the design allows, and is the schema at the version the code expects.
//!
//! The role query is the text of `docs/database/tests/role_readiness.sql`, the one the `rls`
//! database suite ran as three real logins and as a superuser. It is included, not copied, so the
//! store runs the query that was tried.

use diesel::migration::MigrationSource;
use diesel::pg::Pg;
use diesel::sql_types::{Bool, Text};
use diesel::{QueryableByName, sql_query};
use diesel_async::{AsyncPgConnection, RunQueryDsl};
use diesel_migrations::{EmbeddedMigrations, embed_migrations};
use factory_ports::store::SchemaVersion;

use super::error::{RoleProblem, StartupError};

/// The migrations the code was built against. They are embedded only to read their names. The
/// store never runs them: migrations belong to a deploy step (ADR 0007, rule 1).
pub(super) const MIGRATIONS: EmbeddedMigrations = embed_migrations!("../../migrations");

const ROLE_QUERY: &str = include_str!("../../../../docs/database/tests/role_readiness.sql");

/// What a pool's login must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Expected {
    /// `factory_app` only.
    Worker,
    /// `factory_api_app` and `factory_resolver`, and not `factory_app`: the API login holds only the
    /// privileges the API uses (finding API-3 of `docs/reviews/api-security-review.md`).
    Api,
    /// `factory_system` only.
    System,
}

/// The eight answers of the role query, in the order of the query.
#[derive(Debug, Clone, Copy, QueryableByName)]
pub(super) struct RoleFacts {
    #[diesel(sql_type = Bool)]
    pub superuser: bool,
    #[diesel(sql_type = Bool)]
    pub bypassrls: bool,
    #[diesel(sql_type = Bool)]
    pub owns_relations: bool,
    #[diesel(sql_type = Bool)]
    pub tenant_group: bool,
    #[diesel(sql_type = Bool)]
    pub system_group: bool,
    #[diesel(sql_type = Bool)]
    pub resolver_group: bool,
    #[diesel(sql_type = Bool)]
    pub lookup_group: bool,
    #[diesel(sql_type = Bool)]
    pub api_group: bool,
}

/// Judges the facts about a login. Pure, so it can be tested without a database.
pub(super) fn judge(facts: &RoleFacts, expected: Expected) -> Result<(), RoleProblem> {
    // A superuser is a member of every group in PostgreSQL's eyes, so it is read first.
    if facts.superuser {
        return Err(RoleProblem::Superuser);
    }
    if facts.bypassrls {
        return Err(RoleProblem::BypassesRowLevelSecurity);
    }
    if facts.owns_relations {
        return Err(RoleProblem::OwnsRelations);
    }
    let (tenant, system, resolver, api) = match expected {
        Expected::Worker => (true, false, false, false),
        Expected::Api => (false, false, true, true),
        Expected::System => (false, true, false, false),
    };
    // The lookup group has no members at all.
    if facts.lookup_group {
        return Err(RoleProblem::ForbiddenGroup);
    }
    for (needed, actual) in [
        (tenant, facts.tenant_group),
        (system, facts.system_group),
        (resolver, facts.resolver_group),
        (api, facts.api_group),
    ] {
        if needed && !actual {
            return Err(RoleProblem::MissingGroup);
        }
        if !needed && actual {
            return Err(RoleProblem::ForbiddenGroup);
        }
    }
    Ok(())
}

/// Runs the role query as the login of `connection` and judges the answer.
pub(super) async fn check_role(
    connection: &mut AsyncPgConnection,
    pool: &'static str,
    expected: Expected,
) -> Result<(), StartupError> {
    let facts: RoleFacts = sql_query(ROLE_QUERY)
        .get_result(connection)
        .await
        .map_err(|_| StartupError::Unreachable { pool })?;
    judge(&facts, expected).map_err(|problem| StartupError::RoleNotAllowed { pool, problem })
}

#[derive(QueryableByName)]
struct AppliedMigration {
    #[diesel(sql_type = Text)]
    version: String,
}

/// The versions of the migrations the code was built against, oldest first.
pub(super) fn expected_versions() -> Vec<String> {
    let source: &dyn MigrationSource<Pg> = &MIGRATIONS;
    let mut versions: Vec<String> = source
        .migrations()
        .map(|all| {
            all.iter()
                .map(|migration| migration.name().version().to_string())
                .collect()
        })
        .unwrap_or_default();
    versions.sort();
    versions
}

/// Reads the applied migrations and refuses when one the code expects is missing. A database that
/// is ahead of the code is fine: during an expand, migrate, contract change version N and N+1 of
/// the code run on one schema (ADR 0007).
pub(super) async fn check_schema(
    connection: &mut AsyncPgConnection,
) -> Result<SchemaVersion, StartupError> {
    let applied = applied_versions(connection)
        .await
        .map_err(|_| StartupError::Unreachable { pool: "tenant" })?;
    let missing = expected_versions()
        .iter()
        .filter(|version| !applied.contains(version))
        .count();
    if missing > 0 {
        return Err(StartupError::SchemaBehind { missing });
    }
    Ok(version_number(applied.len()))
}

/// Reads the versions in `__diesel_schema_migrations`.
pub(super) async fn applied_versions(
    connection: &mut AsyncPgConnection,
) -> Result<Vec<String>, diesel::result::Error> {
    let rows: Vec<AppliedMigration> =
        sql_query("SELECT version FROM __diesel_schema_migrations ORDER BY version")
            .load(connection)
            .await?;
    Ok(rows.into_iter().map(|row| row.version).collect())
}

/// The schema version of the port: how many migrations are applied. Diesel's own version is a
/// 14-digit timestamp, which does not fit the port's 32-bit number.
pub(super) fn version_number(applied: usize) -> SchemaVersion {
    SchemaVersion::new(u32::try_from(applied).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(worker: bool, system: bool, resolver: bool) -> RoleFacts {
        RoleFacts {
            superuser: false,
            bypassrls: false,
            owns_relations: false,
            tenant_group: worker,
            system_group: system,
            resolver_group: resolver,
            lookup_group: false,
            api_group: false,
        }
    }

    /// The API login: `factory_api_app` and `factory_resolver`.
    fn api_login() -> RoleFacts {
        RoleFacts {
            resolver_group: true,
            api_group: true,
            ..facts(false, false, false)
        }
    }

    #[test]
    fn the_three_logins_of_the_design_are_accepted() {
        assert_eq!(judge(&facts(true, false, false), Expected::Worker), Ok(()));
        assert_eq!(judge(&api_login(), Expected::Api), Ok(()));
        assert_eq!(judge(&facts(false, true, false), Expected::System), Ok(()));
    }

    #[test]
    fn a_superuser_is_refused_whatever_its_groups() {
        let mut view = facts(true, true, true);
        view.superuser = true;
        assert_eq!(judge(&view, Expected::Worker), Err(RoleProblem::Superuser));
    }

    #[test]
    fn bypass_and_ownership_are_refused() {
        let mut view = facts(true, false, false);
        view.bypassrls = true;
        assert_eq!(
            judge(&view, Expected::Worker),
            Err(RoleProblem::BypassesRowLevelSecurity)
        );
        let mut view = facts(true, false, false);
        view.owns_relations = true;
        assert_eq!(
            judge(&view, Expected::Worker),
            Err(RoleProblem::OwnsRelations)
        );
    }

    #[test]
    fn a_login_in_both_the_tenant_and_the_system_group_is_refused() {
        assert_eq!(
            judge(&facts(true, true, false), Expected::Worker),
            Err(RoleProblem::ForbiddenGroup)
        );
        assert_eq!(
            judge(&facts(true, true, false), Expected::System),
            Err(RoleProblem::ForbiddenGroup)
        );
    }

    #[test]
    fn a_login_without_its_group_is_refused() {
        assert_eq!(
            judge(&facts(false, false, false), Expected::Worker),
            Err(RoleProblem::MissingGroup)
        );
        assert_eq!(
            judge(&facts(false, false, false), Expected::Api),
            Err(RoleProblem::MissingGroup)
        );
        // A resolver without the API's own group is not the API login either.
        assert_eq!(
            judge(&facts(false, false, true), Expected::Api),
            Err(RoleProblem::MissingGroup)
        );
    }

    #[test]
    fn the_api_login_must_not_also_be_in_the_worker_group() {
        // The old shape of the API login (factory_app and factory_resolver) holds every privilege of the
        // worker: it is refused, and so is the new shape with the worker group added back.
        assert_eq!(
            judge(&facts(true, false, true), Expected::Api),
            Err(RoleProblem::ForbiddenGroup)
        );
        let mut both = api_login();
        both.tenant_group = true;
        assert_eq!(
            judge(&both, Expected::Api),
            Err(RoleProblem::ForbiddenGroup)
        );
    }

    #[test]
    fn the_api_group_is_forbidden_on_a_worker_or_system_login() {
        let mut worker = facts(true, false, false);
        worker.api_group = true;
        assert_eq!(
            judge(&worker, Expected::Worker),
            Err(RoleProblem::ForbiddenGroup)
        );
        let mut system = facts(false, true, false);
        system.api_group = true;
        assert_eq!(
            judge(&system, Expected::System),
            Err(RoleProblem::ForbiddenGroup)
        );
    }

    #[test]
    fn the_resolver_group_is_forbidden_on_a_plain_worker_login() {
        assert_eq!(
            judge(&facts(true, false, true), Expected::Worker),
            Err(RoleProblem::ForbiddenGroup)
        );
    }

    #[test]
    fn the_code_expects_the_migrations_in_the_repository() {
        let versions = expected_versions();
        assert!(versions.len() >= 18, "{versions:?}");
        assert_eq!(versions[0], "20261027000100");
    }
}
