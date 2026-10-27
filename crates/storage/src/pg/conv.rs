//! Small conversions between the domain types and the column types of the schema.
//!
//! A value that comes out of the database and does not parse as a domain type means the database
//! holds something the domain refuses. That is not the caller's doing, so it is logged and
//! reported as `Unavailable`.

use std::time::Duration;

use factory_domain::ids::{
    AttemptId, CorrelationId, JobId, PrincipalId, StageRunId, TaskNodeId, TenantId,
};
use factory_domain::state::Status;
use factory_domain::values::{AggregateVersion, Sha256Digest, Timestamp};
use factory_ports::store::{StoreError, Version};
use time::OffsetDateTime;
use uuid::Uuid;

/// A timestamp as the column type.
pub(super) fn to_column(at: &Timestamp) -> OffsetDateTime {
    at.to_utc()
}

/// A column value as a timestamp.
pub(super) fn from_column(at: OffsetDateTime) -> Timestamp {
    Timestamp::from_utc(at)
}

/// A column value as a version.
pub(super) fn version_from_column(raw: i64) -> Result<Version, StoreError> {
    AggregateVersion::new(raw).map_err(|_| corrupt("version"))
}

/// A status name from a column.
pub(super) fn status_from_column<S: Status>(name: &str) -> Result<S, StoreError> {
    S::parse_name(name).ok_or_else(|| corrupt("status"))
}

/// A digest from a column.
pub(super) fn digest_from_column(text: &str) -> Result<Sha256Digest, StoreError> {
    Sha256Digest::parse(text).map_err(|_| corrupt("digest"))
}

/// The whole microseconds of a duration, for `now() + $1 * interval '1 microsecond'`. A value
/// beyond what fits saturates, which a one-hour lease bound in the schema then refuses.
pub(super) fn micros(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap_or(i64::MAX)
}

/// Logs that the database holds a value the domain refuses, and reports it as unavailable.
pub(super) fn corrupt(what: &'static str) -> StoreError {
    tracing::error!(what, "the database holds a value the domain refuses");
    StoreError::Unavailable
}

macro_rules! id_conversions {
    ($($name:ident => $to:ident, $from:ident);+ $(;)?) => {
        $(
            pub(super) fn $to(id: $name) -> Uuid {
                id.as_uuid()
            }
            pub(super) fn $from(raw: Uuid) -> $name {
                $name::from_uuid(raw)
            }
        )+
    };
}

id_conversions! {
    TenantId => tenant_to_column, tenant_from_column;
    JobId => job_to_column, job_from_column;
    StageRunId => stage_run_to_column, stage_run_from_column;
    AttemptId => attempt_to_column, attempt_from_column;
    TaskNodeId => task_node_to_column, task_node_from_column;
    PrincipalId => principal_to_column, principal_from_column;
    CorrelationId => correlation_to_column, correlation_from_column;
}
