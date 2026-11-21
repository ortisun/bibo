//! Small conversions between the domain types and the column types of the schema.
//!
//! A value that comes out of the database and does not parse as a domain type means the database
//! holds something the domain refuses. That is not the caller's doing, so it is logged and
//! reported as `Internal(Unmapped)`: the store cannot make sense of its own row.

use std::time::Duration;

use factory_domain::state::Status;
use factory_domain::values::{AggregateVersion, GitSha, Sha256Digest, Slug, Timestamp};
use factory_ports::store::{FaultCode, LeaseEpoch, MeteredUsage, StoreError, Version};
use time::OffsetDateTime;

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

/// A slug from a column.
pub(super) fn slug_from_column(text: &str) -> Result<Slug, StoreError> {
    Slug::parse(text).map_err(|_| corrupt("slug"))
}

/// A Git object id from a column.
pub(super) fn git_sha_from_column(text: &str) -> Result<GitSha, StoreError> {
    GitSha::parse(text).map_err(|_| corrupt("git sha"))
}

/// The epoch column as a lease epoch.
pub(super) fn epoch_from_column(raw: i64) -> Result<LeaseEpoch, StoreError> {
    u64::try_from(raw)
        .map(LeaseEpoch::new)
        .map_err(|_| corrupt("lease epoch"))
}

/// A lease epoch as the column type. The epoch never exceeds `i64::MAX`, the type cuts it.
pub(super) fn epoch_to_column(epoch: LeaseEpoch) -> i64 {
    i64::try_from(epoch.get()).unwrap_or(i64::MAX)
}

/// A count or a position from a column that is never negative.
pub(super) fn unsigned_from_column(raw: i64, what: &'static str) -> Result<u64, StoreError> {
    u64::try_from(raw).map_err(|_| corrupt(what))
}

/// A number the caller gave as the column type. A value beyond what fits saturates, and the
/// database then refuses it or finds nothing.
pub(super) fn signed_to_column(raw: u64) -> i64 {
    i64::try_from(raw).unwrap_or(i64::MAX)
}

/// The whole microseconds of a duration, for `now() + $1 * interval '1 microsecond'`. A value
/// beyond what fits saturates, which a one-hour lease bound in the schema then refuses.
pub(super) fn micros(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap_or(i64::MAX)
}

/// The four metered columns of a row as a metered use. They are empty together ("not known") or
/// filled together; the schema says so (`attempts_metered_check`, `task_runs_metered_check`), and
/// a row that breaks the rule is a fault of the store.
pub(super) fn metered_from_columns(
    input_tokens: Option<i64>,
    output_tokens: Option<i64>,
    cost_micro_usd: Option<i64>,
    model_requests: Option<i64>,
) -> Result<Option<MeteredUsage>, StoreError> {
    match (input_tokens, output_tokens, cost_micro_usd, model_requests) {
        (None, None, None, None) => Ok(None),
        (Some(input), Some(output), Some(cost), Some(requests)) => {
            let unsigned = |raw: i64| u64::try_from(raw).map_err(|_| corrupt("metered use"));
            MeteredUsage::new(
                unsigned(input)?,
                unsigned(output)?,
                unsigned(cost)?,
                unsigned(requests)?,
            )
            .map(Some)
            .map_err(|_| corrupt("metered use"))
        }
        _ => Err(corrupt("metered use")),
    }
}

/// A metered use as the four columns, in the order input tokens, output tokens, cost, requests.
/// `None` is four empty columns. Every value of a `MeteredUsage` is at most 2^53 - 1, so each
/// fits the column type exactly.
pub(super) fn metered_to_columns(metered: Option<MeteredUsage>) -> [Option<i64>; 4] {
    match metered {
        None => [None; 4],
        Some(metered) => [
            metered.input_tokens(),
            metered.output_tokens(),
            metered.cost_micro_usd(),
            metered.requests(),
        ]
        .map(|value| i64::try_from(value).ok()),
    }
}

/// Logs that the database holds a value the domain refuses, and reports a fault of the store.
pub(super) fn corrupt(what: &'static str) -> StoreError {
    tracing::error!(what, "the database holds a value the domain refuses");
    StoreError::Internal(FaultCode::Unmapped)
}
