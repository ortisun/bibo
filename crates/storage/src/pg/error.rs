//! Maps every failure of the database library onto the closed [`StoreError`] and onto
//! [`StartupError`].
//!
//! The rule that matters most is in [`constraint`]: the text of a database message or detail never
//! reaches a caller. A unique violation names the key value in its detail, and for the two keys
//! that are global (`repositories.github_repository_id`, `api_tokens.token_hash`) that value
//! belongs to another tenant. So the only text taken from a database error is the name of the
//! constraint, which names a rule of the schema and holds no row value. What is logged is the
//! class, the constraint, the table and the column, never the free text (the policy redactor
//! `domain::redaction` of the package `s1-redaction` is not merged yet; dropping the text is the
//! safe form of redaction until it is).

use diesel::result::{DatabaseErrorKind, Error as DieselError};
use factory_ports::store::StoreError;

/// What kind of failure the database reported, with the names of the schema objects involved.
///
/// Built from a [`DieselError`] by [`Failure::of`]. It holds no message and no detail text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Failure {
    /// SQLSTATE 23505. The constraint is the unique key or the primary key that was hit.
    Unique(Option<String>),
    /// SQLSTATE 23503.
    ForeignKey(Option<String>),
    /// SQLSTATE 23514. The triggers of the schema set the constraint name on purpose.
    Check(Option<String>),
    /// SQLSTATE 23502. A column that must be filled was left empty.
    NotNull,
    /// SQLSTATE 40001, a serialization failure.
    Serialization,
    /// The connection is gone or the command could not be sent.
    Connection,
    /// Anything else: a missing grant, a policy refusal, a type error. These are bugs in the
    /// storage code or in the deployment, not something a caller caused.
    Other,
    /// The query matched no row where one was required.
    NoRow,
}

impl Failure {
    /// Classifies an error of the library. The message and detail are not read.
    pub(super) fn of(error: &DieselError) -> Self {
        match error {
            DieselError::NotFound => Self::NoRow,
            DieselError::DatabaseError(kind, info) => {
                let constraint = || info.constraint_name().map(str::to_owned);
                match kind {
                    DatabaseErrorKind::UniqueViolation => Self::Unique(constraint()),
                    DatabaseErrorKind::ForeignKeyViolation => Self::ForeignKey(constraint()),
                    DatabaseErrorKind::CheckViolation => Self::Check(constraint()),
                    DatabaseErrorKind::NotNullViolation => Self::NotNull,
                    DatabaseErrorKind::SerializationFailure => Self::Serialization,
                    DatabaseErrorKind::ClosedConnection
                    | DatabaseErrorKind::UnableToSendCommand => Self::Connection,
                    _ => Self::Other,
                }
            }
            DieselError::BrokenTransactionManager | DieselError::AlreadyInTransaction => {
                Self::Connection
            }
            _ => Self::Other,
        }
    }
}

/// Writes one line to the log about a failure, with no database text.
///
/// `operation` is a fixed name of the storage call, such as `insert_job`.
pub(super) fn log_failure(operation: &'static str, error: &DieselError) {
    let failure = Failure::of(error);
    let (table, column) = match error {
        DieselError::DatabaseError(_, info) => (
            info.table_name().map(str::to_owned),
            info.column_name().map(str::to_owned),
        ),
        _ => (None, None),
    };
    tracing::warn!(
        operation,
        failure = ?failure,
        table = table.as_deref().unwrap_or(""),
        column = column.as_deref().unwrap_or(""),
        "a database call failed"
    );
}

/// The closed error for a violated rule, naming only the constraint.
///
/// This is the one place where a name from the database enters an error that a caller sees. It
/// is the name of a constraint of the schema, never a message and never a value.
pub(super) fn constraint(kind: &'static str, name: Option<&str>) -> StoreError {
    match name {
        Some(name) => StoreError::Constraint(format!("{kind} {name}")),
        None => StoreError::Constraint(kind.to_owned()),
    }
}

/// The generic mapping, used when a call site has no rule of its own for a failure.
///
/// A broken connection is `Unavailable`. A bug of the storage code or the deployment (a missing
/// grant, a policy refusal, a bad type) is logged at error level and also `Unavailable`: the
/// caller did nothing wrong and cannot fix it, and the text stays in the log.
pub(super) fn generic(operation: &'static str, error: &DieselError) -> StoreError {
    log_failure(operation, error);
    match Failure::of(error) {
        Failure::Unique(name) => constraint("unique violation", name.as_deref()),
        Failure::ForeignKey(name) => constraint("foreign key violation", name.as_deref()),
        Failure::Check(name) => constraint("check violation", name.as_deref()),
        Failure::NotNull => constraint("missing value", None),
        Failure::Serialization => StoreError::Conflict,
        Failure::NoRow => StoreError::NotFound,
        Failure::Connection => StoreError::Unavailable,
        Failure::Other => {
            tracing::error!(
                operation,
                "the database refused a call for a reason that is not the caller's"
            );
            StoreError::Unavailable
        }
    }
}

/// Why the store could not become ready. Not a [`StoreError`]: it happens once, at start-up, and
/// the operator reads it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartupError {
    /// A pool could not connect, or could not be built.
    #[error("the {pool} pool cannot reach the database")]
    Unreachable {
        /// Which pool: `tenant` or `system`.
        pool: &'static str,
    },
    /// The login of a pool has rights that the design forbids, or lacks the group it needs.
    #[error("the login of the {pool} pool is not allowed to run the store: {problem}")]
    RoleNotAllowed {
        /// Which pool.
        pool: &'static str,
        /// What is wrong, in plain words.
        problem: RoleProblem,
    },
    /// The database is behind the code.
    #[error("the database is behind the code: {missing} migration(s) are not applied")]
    SchemaBehind {
        /// How many migrations the code expects that the database lacks.
        missing: usize,
    },
    /// The configuration is not usable.
    #[error("the store configuration is not usable: {0}")]
    Misconfigured(&'static str),
}

/// What is wrong with the login of a pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RoleProblem {
    /// The login is a superuser, which bypasses every policy.
    #[error("it is a superuser")]
    Superuser,
    /// The login has the `BYPASSRLS` attribute.
    #[error("it can bypass row-level security")]
    BypassesRowLevelSecurity,
    /// The login owns a table, a view or another relation, so the table owner rules apply to it.
    #[error("it owns database objects")]
    OwnsRelations,
    /// The login is not in the group that its pool needs.
    #[error("it is not a member of the group its pool needs")]
    MissingGroup,
    /// The login is in a group that its pool must not be in (for example both the tenant group
    /// and the system group, which would show it every tenant's rows).
    #[error("it is a member of a group its pool must not be in")]
    ForbiddenGroup,
}
