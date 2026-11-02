//! Maps every failure of the database library onto the closed [`StoreError`] and onto
//! [`StartupError`].
//!
//! The rule that matters most is in [`database`]: the text of a database message or detail never
//! reaches a caller. A unique violation names the key value in its detail, and for the two keys
//! that are global (`repositories.github_repository_id`, `api_tokens.token_hash`) that value
//! belongs to another tenant. So the only text taken from a database error is the name of the
//! constraint, which names a rule of the schema and holds no row value, and that name is only
//! compared with a fixed list. It is never put in an error. A few failures carry no constraint
//! name (a missing grant, a policy refusal, a deadlock, a timeout); the message of those is read
//! once, to tell them apart, and then dropped. What is logged is the class, the constraint, the
//! table and the column, never the free text.
//!
//! The table of `docs/database/for-the-storage-crate.md` ("Errors") is the specification of the
//! name to error mapping below.

use diesel::result::{DatabaseErrorKind, Error as DieselError};
use factory_ports::store::{ConstraintRule, FaultCode, StoreError};

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
    /// SQLSTATE 40P01, two transactions waited for each other.
    Deadlock,
    /// SQLSTATE 55P03 or 57014: a lock or statement timeout set by the adapter.
    Timeout,
    /// SQLSTATE 25P02: an earlier statement of the transaction failed, and PostgreSQL refuses the
    /// rest. The only safe step is to roll back.
    Aborted,
    /// SQLSTATE 42501 for a missing grant: the role may not run the statement.
    PermissionDenied,
    /// SQLSTATE 42501 from a policy, or 22P02 on the tenant setting: the setting was missing or
    /// malformed. A bug of the storage code.
    TenantSetting,
    /// SQLSTATE 22003, a number out of range (the lease epoch at its maximum).
    OutOfRange,
    /// The connection is gone or the command could not be sent.
    Connection,
    /// Anything else. A bug in the storage code or in the deployment.
    Other,
    /// The query matched no row where one was required.
    NoRow,
}

impl Failure {
    /// Classifies an error of the library. The message is read only to tell apart the failures
    /// the library reports as `Unknown`; it is not kept.
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
                    _ => classify_message(info.message()),
                }
            }
            DieselError::BrokenTransactionManager | DieselError::AlreadyInTransaction => {
                Self::Connection
            }
            _ => Self::Other,
        }
    }
}

/// Tells apart the failures that arrive with no constraint. The text is compared and dropped.
fn classify_message(message: &str) -> Failure {
    if message.contains("deadlock detected") {
        Failure::Deadlock
    } else if message.contains("canceling statement due to") {
        Failure::Timeout
    } else if message.contains("current transaction is aborted") {
        Failure::Aborted
    } else if message.contains("row-level security policy")
        || message.contains("invalid input syntax for type uuid")
        || message.contains("unrecognized configuration parameter")
    {
        Failure::TenantSetting
    } else if message.contains("permission denied") || message.contains("must be owner") {
        Failure::PermissionDenied
    } else if message.contains("out of range") {
        Failure::OutOfRange
    } else {
        Failure::Other
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

const fn rule(rule: ConstraintRule) -> StoreError {
    StoreError::Constraint(rule)
}

fn unmapped(kind: &'static str, name: Option<&str>) -> StoreError {
    // The name is logged, never returned.
    tracing::error!(
        kind,
        constraint = name,
        "a database constraint refused a write that the adapter does not map"
    );
    StoreError::Internal(FaultCode::Unmapped)
}

/// The unique keys, by constraint name.
fn unique(name: Option<&str>) -> StoreError {
    match name {
        Some("outbox_one_event_per_aggregate_version" | "ledger_entries_pkey") => {
            StoreError::Conflict
        }
        Some("attempts_one_active_per_stage_run") => rule(ConstraintRule::OneLiveAttempt),
        // The two keys that are global to the database name a value that may belong to another
        // tenant. Their violation is reported as a missing object (NT-TEN-05): the caller cannot
        // learn that another tenant holds the repository or the token.
        Some("repositories_github_repository_id_key" | "api_tokens_token_hash_key") => {
            StoreError::NotFound
        }
        Some("principals_tenant_id_github_user_id_key") => {
            rule(ConstraintRule::ExternalReferenceTaken)
        }
        Some(
            "original_requests_tenant_id_job_id_revision_key"
            | "stage_runs_tenant_id_job_id_stage_kind_run_number_key"
            | "approvals_one_decision_per_head",
        ) => rule(ConstraintRule::IdReusedWithDifferentContent),
        Some("task_nodes_tenant_id_stage_run_id_task_key_key") => {
            rule(ConstraintRule::DuplicateTaskKey)
        }
        other => unmapped("unique violation", other),
    }
}

/// The foreign keys, by constraint name. A composite key into another tenant's row, another job's
/// row or nothing is a missing object: the three look the same to the caller.
fn foreign_key(name: Option<&str>) -> StoreError {
    match name {
        Some(name) if name.contains("prev_sequence") || name.contains("prev_entry") => {
            StoreError::ChainBroken
        }
        Some("outbox_aggregate_type_transition_id_event_type_fkey") => {
            rule(ConstraintRule::EventAggregateMismatch)
        }
        _ => StoreError::NotFound,
    }
}

/// The column checks whose failure means a text value is empty, too long or not of the shape.
const TEXT_COLUMNS: [&str; 10] = [
    "_reason_",
    "_subject_",
    "_action_",
    "_actor_id_",
    "_request_text_",
    "_source_ref_",
    "_login_",
    "_delivery_id_",
    "_event_name_",
    "_full_name_",
];

/// The checks and triggers, by constraint name.
fn check(name: Option<&str>) -> StoreError {
    let Some(name) = name else {
        return unmapped("check violation", None);
    };
    if name.ends_with("_legal_transition") || name.ends_with("_initial_state") {
        return rule(ConstraintRule::IllegalStatusMove);
    }
    match name {
        "attempts_within_stage_run_limit" => rule(ConstraintRule::AttemptLimit),
        "attempts_live_attempt_has_current_epoch" => StoreError::LeaseFenced,
        // The run left RUNNING with a live attempt: the engine did not end the attempt in the
        // same transaction. A domain bug.
        "stage_runs_live_attempt_needs_running_run" => rule(ConstraintRule::IllegalStatusMove),
        "stage_runs_terminal_is_immutable" | "attempts_terminal_is_immutable" => {
            rule(ConstraintRule::TerminalRowImmutable)
        }
        "stage_runs_blocked_has_outcome"
        | "stage_runs_passed_has_outcome"
        | "stage_runs_skipped_has_outcome"
        | "stage_runs_failing_set_needs_failed_outcome"
        | "stage_runs_failing_set_hash_check" => rule(ConstraintRule::GateRecordRule),
        "attempts_failed_has_class"
        | "attempts_succeeded_has_output"
        | "attempts_cancelling_has_teardown" => rule(ConstraintRule::AttemptEndRule),
        "attempts_sandbox_leaked_only_rises" | "attempts_sandbox_id_is_fixed" => {
            rule(ConstraintRule::IdReusedWithDifferentContent)
        }
        "task_node_dependencies_acyclic" => rule(ConstraintRule::DependencyCycle),
        // The task node record does not fit the move. `ConstraintRule` has no code of its own
        // for it (an open point in the database notes), so the nearest one is used.
        "task_nodes_running_has_attempt"
        | "task_nodes_idle_has_no_attempt"
        | "task_nodes_commit_iff_succeeded" => rule(ConstraintRule::IllegalStatusMove),
        "jobs_ledger_head_only_moves_forward"
        | "ledger_entries_hash_matches_document"
        | "ledger_entries_document_matches_columns" => StoreError::ChainBroken,
        "outbox_aggregate_exists"
        | "outbox_aggregate_belongs_to_job"
        | "outbox_aggregate_has_reached_version" => rule(ConstraintRule::EventAggregateMismatch),
        "audit_events_stage_run_needs_job" => rule(ConstraintRule::TextBounds),
        // The project map of a repository: enabled without a commit, a commit that is not 40
        // lowercase hexadecimal characters, a half-filled attestation, or an attestor who is not an
        // active human of the tenant. The storage statements check each one first; these are the
        // backstop of the table.
        "repositories_enabled_needs_project_map"
        | "repositories_project_map_commit_check"
        | "repositories_project_map_attestation_complete"
        | "repositories_map_attestor_is_an_active_human"
        | "repositories_enabler_is_an_active_human"
        | "repositories_enabled_record_is_complete" => rule(ConstraintRule::ProjectMapRule),
        // The table's second guard behind the trigger and the statement: an enabled repository
        // whose record names another commit than the one attested now.
        "repositories_enabled_project_map_commit_matches" => {
            rule(ConstraintRule::ProjectMapChanged)
        }
        other if other.ends_with("_check") && TEXT_COLUMNS.iter().any(|c| other.contains(c)) => {
            rule(ConstraintRule::TextBounds)
        }
        other => unmapped("check violation", Some(other)),
    }
}

/// Maps a failure of the database library onto the closed error. The one place where a database
/// failure becomes a [`StoreError`].
pub(super) fn database(operation: &'static str, error: &DieselError) -> StoreError {
    log_failure(operation, error);
    match Failure::of(error) {
        Failure::Unique(name) => unique(name.as_deref()),
        Failure::ForeignKey(name) => foreign_key(name.as_deref()),
        Failure::Check(name) => check(name.as_deref()),
        Failure::NotNull => unmapped("missing value", None),
        Failure::Serialization | Failure::Deadlock => StoreError::Conflict,
        Failure::NoRow => StoreError::NotFound,
        Failure::Timeout | Failure::Aborted | Failure::Connection => StoreError::Unavailable,
        Failure::PermissionDenied => StoreError::Internal(FaultCode::PermissionDenied),
        Failure::TenantSetting => StoreError::Internal(FaultCode::TenantSetting),
        Failure::OutOfRange => rule(ConstraintRule::LeaseEpochExhausted),
        Failure::Other => {
            tracing::error!(
                operation,
                "the database refused a call for a reason that is not the caller's"
            );
            StoreError::Internal(FaultCode::Unmapped)
        }
    }
}

/// Maps a failure that arrives when the transaction commits, because the checks that span rows
/// are deferred. A unique violation here is a lost race: the first committer won.
pub(super) fn at_commit(error: &DieselError) -> StoreError {
    match Failure::of(error) {
        Failure::Unique(_) | Failure::Serialization => {
            log_failure("commit", error);
            StoreError::Conflict
        }
        _ => database("commit", error),
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

#[cfg(test)]
mod tests {
    use super::*;
    use diesel::result::DatabaseErrorInformation;

    /// A database error as PostgreSQL makes it, with a detail that names a value.
    struct Fake {
        constraint: Option<&'static str>,
        message: &'static str,
    }

    impl DatabaseErrorInformation for Fake {
        fn message(&self) -> &str {
            self.message
        }
        fn details(&self) -> Option<&str> {
            Some("Key (github_repository_id)=(424242) already exists.")
        }
        fn hint(&self) -> Option<&str> {
            None
        }
        fn table_name(&self) -> Option<&str> {
            Some("repositories")
        }
        fn column_name(&self) -> Option<&str> {
            None
        }
        fn constraint_name(&self) -> Option<&str> {
            self.constraint
        }
        fn statement_position(&self) -> Option<i32> {
            None
        }
    }

    const KEY_MESSAGE: &str =
        "duplicate key value violates unique constraint \"repositories_github_repository_id_key\"";

    fn violation(kind: DatabaseErrorKind, constraint: Option<&'static str>) -> DieselError {
        DieselError::DatabaseError(
            kind,
            Box::new(Fake {
                constraint,
                message: KEY_MESSAGE,
            }),
        )
    }

    fn unique_violation(constraint: Option<&'static str>) -> DieselError {
        violation(DatabaseErrorKind::UniqueViolation, constraint)
    }

    fn unknown(message: &'static str) -> DieselError {
        DieselError::DatabaseError(
            DatabaseErrorKind::Unknown,
            Box::new(Fake {
                constraint: None,
                message,
            }),
        )
    }

    #[test]
    fn a_violation_of_a_global_key_is_reported_as_a_missing_object() {
        for key in [
            "repositories_github_repository_id_key",
            "api_tokens_token_hash_key",
        ] {
            assert_eq!(
                database("insert", &unique_violation(Some(key))),
                StoreError::NotFound,
                "{key}"
            );
        }
    }

    #[test]
    fn nothing_from_the_database_comes_through_in_any_error() {
        let errors = [
            unique_violation(Some("jobs_pkey")),
            unique_violation(Some("repositories_github_repository_id_key")),
            unique_violation(None),
            violation(
                DatabaseErrorKind::ForeignKeyViolation,
                Some("jobs_repo_fkey"),
            ),
            violation(
                DatabaseErrorKind::CheckViolation,
                Some("jobs_surprise_check"),
            ),
            unknown("permission denied for table jobs, key 424242"),
            unknown("something else, key (424242) already exists"),
        ];
        for error in errors {
            let mapped = database("insert", &error);
            let shown = format!("{mapped} {mapped:?}");
            for text in [
                "jobs_pkey",
                "jobs_repo_fkey",
                "jobs_surprise_check",
                "424242",
                "already exists",
                "duplicate key",
                "Key (",
                "repositories",
                "permission denied",
            ] {
                assert!(!shown.contains(text), "{text}: {shown}");
            }
        }
    }

    #[test]
    fn a_unique_violation_with_no_name_is_an_unmapped_fault() {
        assert_eq!(
            database("insert", &unique_violation(None)),
            StoreError::Internal(FaultCode::Unmapped)
        );
    }

    #[test]
    fn the_named_rules_of_the_schema_map_to_the_rules_of_the_port() {
        let cases: [(DatabaseErrorKind, &'static str, StoreError); 10] = [
            (
                DatabaseErrorKind::UniqueViolation,
                "attempts_one_active_per_stage_run",
                StoreError::Constraint(ConstraintRule::OneLiveAttempt),
            ),
            (
                DatabaseErrorKind::UniqueViolation,
                "ledger_entries_pkey",
                StoreError::Conflict,
            ),
            (
                DatabaseErrorKind::UniqueViolation,
                "task_nodes_tenant_id_stage_run_id_task_key_key",
                StoreError::Constraint(ConstraintRule::DuplicateTaskKey),
            ),
            (
                DatabaseErrorKind::CheckViolation,
                "attempts_within_stage_run_limit",
                StoreError::Constraint(ConstraintRule::AttemptLimit),
            ),
            (
                DatabaseErrorKind::CheckViolation,
                "attempts_live_attempt_has_current_epoch",
                StoreError::LeaseFenced,
            ),
            (
                DatabaseErrorKind::CheckViolation,
                "stage_runs_legal_transition",
                StoreError::Constraint(ConstraintRule::IllegalStatusMove),
            ),
            (
                DatabaseErrorKind::CheckViolation,
                "stage_runs_terminal_is_immutable",
                StoreError::Constraint(ConstraintRule::TerminalRowImmutable),
            ),
            (
                DatabaseErrorKind::CheckViolation,
                "attempts_failed_has_class",
                StoreError::Constraint(ConstraintRule::AttemptEndRule),
            ),
            (
                DatabaseErrorKind::CheckViolation,
                "outbox_aggregate_has_reached_version",
                StoreError::Constraint(ConstraintRule::EventAggregateMismatch),
            ),
            (
                DatabaseErrorKind::CheckViolation,
                "audit_events_reason_check",
                StoreError::Constraint(ConstraintRule::TextBounds),
            ),
        ];
        for (kind, name, expected) in cases {
            assert_eq!(
                database("write", &violation(kind, Some(name))),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn failures_without_a_constraint_are_told_apart_by_class() {
        assert_eq!(
            database("write", &unknown("deadlock detected")),
            StoreError::Conflict
        );
        assert_eq!(
            database("write", &unknown("canceling statement due to lock timeout")),
            StoreError::Unavailable
        );
        assert_eq!(
            database("write", &unknown("permission denied for table jobs")),
            StoreError::Internal(FaultCode::PermissionDenied)
        );
        assert_eq!(
            database(
                "write",
                &unknown("new row violates row-level security policy for table \"jobs\"")
            ),
            StoreError::Internal(FaultCode::TenantSetting)
        );
        assert_eq!(
            database("write", &unknown("bigint out of range")),
            StoreError::Constraint(ConstraintRule::LeaseEpochExhausted)
        );
    }

    #[test]
    fn a_statement_after_a_failed_one_is_unavailable() {
        assert_eq!(
            database(
                "write",
                &unknown(
                    "current transaction is aborted, commands ignored until end of transaction block"
                )
            ),
            StoreError::Unavailable
        );
    }

    #[test]
    fn a_failure_that_is_not_the_callers_is_unmapped_and_says_nothing() {
        let mapped = database("insert", &unknown("something odd, value 424242"));
        assert_eq!(mapped, StoreError::Internal(FaultCode::Unmapped));
        assert!(!format!("{mapped:?}").contains("424242"));
    }

    #[test]
    fn a_unique_violation_at_commit_is_a_lost_race() {
        assert_eq!(
            at_commit(&unique_violation(Some("ledger_entries_pkey"))),
            StoreError::Conflict
        );
        assert_eq!(
            at_commit(&violation(
                DatabaseErrorKind::CheckViolation,
                Some("attempts_live_attempt_has_current_epoch")
            )),
            StoreError::LeaseFenced
        );
    }
}
