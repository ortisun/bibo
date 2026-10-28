//! What the registry says about a package, as far as the factory could learn it.
//!
//! This crate does no network I/O (rule DEP-05), so it cannot ask a registry. The composition
//! root supplies a [`RegistryMetadata`] that does, through the egress path the policy allows for
//! the control plane. What it learns is recorded and shown to the human who decides on a new
//! dependency. It **approves nothing**: `DependencyPolicy::decide` reads these facts only to
//! choose how much scrutiny the person gets, and a fact that is missing is read as the worst
//! answer (an unknown age is young, an unknown existence is a package that may not exist).

use std::collections::BTreeMap;

use async_trait::async_trait;
use factory_domain::values::Timestamp;

use super::model::normalize;

/// One day, in seconds.
const DAY: i64 = 86_400;

/// What is known about one package version. A field the source could not learn is `None`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RegistryRecord {
    /// Whether the name exists in the registry.
    pub exists: Option<bool>,
    /// When the package was first published (the first version, not this one).
    pub first_published: Option<Timestamp>,
    /// The license expression the registry shows for this version.
    pub license: Option<String>,
    /// The repository link of the package.
    pub repository: Option<String>,
    /// The download count the registry reports.
    pub downloads: Option<u64>,
}

impl RegistryRecord {
    /// The whole days between the first publication and `now`. `None` when the publication time
    /// is not known or lies in the future, which cannot be true and is not trusted.
    #[must_use]
    pub fn age_days(&self, now: &Timestamp) -> Option<u64> {
        let seconds = now.unix_seconds() - self.first_published?.unix_seconds();
        u64::try_from(seconds / DAY).ok()
    }
}

/// A source of registry facts.
#[async_trait]
pub trait RegistryMetadata: Send + Sync {
    /// What the registry says about `name` at `version`. A source that cannot reach the registry
    /// returns the default record, which is all unknown.
    async fn lookup(&self, name: &str, version: &str) -> RegistryRecord;
}

/// The advisory database the audit reads.
///
/// The audit runs in a sandbox with no network and with `--no-fetch`, and with that flag the tool
/// does not check how old its database is and prints no date. The age is therefore a fact the
/// composition root supplies, from where the image was built (the date of the database that was
/// copied into the pinned image), and the gate requires it: an audit against a database of
/// unknown age is not a clean audit.
#[async_trait]
pub trait AdvisoryDatabase: Send + Sync {
    /// When the database the audit reads was last updated. `None` when that is not known.
    async fn updated_at(&self) -> Option<Timestamp>;
}

/// A database whose date was read before the run, and a test double.
#[derive(Debug, Clone, Copy, Default)]
pub struct StaticDatabase(pub Option<Timestamp>);

#[async_trait]
impl AdvisoryDatabase for StaticDatabase {
    async fn updated_at(&self) -> Option<Timestamp> {
        self.0
    }
}

/// How old the advisory database is, judged against the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseAge {
    /// Updated within the limit.
    Fresh {
        /// Whole days since the update.
        days: u64,
    },
    /// Updated before the limit.
    Stale {
        /// Whole days since the update.
        days: u64,
        /// The limit it is judged against.
        limit: u64,
    },
    /// The date is not known, or lies in the future, which cannot be true and is not trusted.
    Unknown,
}

impl DatabaseAge {
    /// Judges the date `updated` at `now` against `limit_days`. A database exactly `limit_days`
    /// old is fresh; one second more is stale.
    #[must_use]
    pub fn judge(now: &Timestamp, updated: Option<Timestamp>, limit_days: u64) -> Self {
        let Some(updated) = updated else {
            return Self::Unknown;
        };
        let seconds = now.unix_seconds() - updated.unix_seconds();
        let Ok(elapsed) = u64::try_from(seconds) else {
            return Self::Unknown;
        };
        let days = elapsed / 86_400;
        if elapsed <= limit_days.saturating_mul(86_400) {
            Self::Fresh { days }
        } else {
            Self::Stale {
                days,
                limit: limit_days,
            }
        }
    }
}

/// A fixed table of records, for a source that was filled before the run and for tests.
#[derive(Debug, Clone, Default)]
pub struct StaticRegistry {
    records: BTreeMap<String, RegistryRecord>,
}

impl StaticRegistry {
    /// An empty table: every package is unknown.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the record of a package. The name is compared as cargo compares names.
    #[must_use]
    pub fn with(mut self, name: &str, record: RegistryRecord) -> Self {
        self.records.insert(normalize(name), record);
        self
    }
}

#[async_trait]
impl RegistryMetadata for StaticRegistry {
    async fn lookup(&self, name: &str, _version: &str) -> RegistryRecord {
        self.records
            .get(&normalize(name))
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("a timestamp")
    }

    #[test]
    fn the_database_age_is_fresh_stale_or_unknown_and_never_guessed() {
        let now = at("2026-10-28T12:00:00Z");
        let judge = |updated: Option<&str>| DatabaseAge::judge(&now, updated.map(at), 7);
        assert_eq!(
            judge(Some("2026-10-28T11:00:00Z")),
            DatabaseAge::Fresh { days: 0 }
        );
        assert_eq!(
            judge(Some("2026-10-21T12:00:00Z")),
            DatabaseAge::Fresh { days: 7 }
        );
        assert_eq!(
            judge(Some("2026-10-21T11:59:59Z")),
            DatabaseAge::Stale { days: 7, limit: 7 },
            "one second past the limit is stale"
        );
        assert_eq!(
            judge(Some("2026-10-20T12:00:00Z")),
            DatabaseAge::Stale { days: 8, limit: 7 }
        );
        assert_eq!(judge(None), DatabaseAge::Unknown);
        assert_eq!(judge(Some("2026-10-29T00:00:00Z")), DatabaseAge::Unknown);
    }

    #[test]
    fn the_age_counts_whole_days_and_distrusts_the_future() {
        let record = RegistryRecord {
            first_published: Some(at("2026-10-25T12:00:00Z")),
            ..RegistryRecord::default()
        };
        assert_eq!(record.age_days(&at("2026-10-28T11:59:59Z")), Some(2));
        assert_eq!(record.age_days(&at("2026-10-28T12:00:00Z")), Some(3));
        assert_eq!(record.age_days(&at("2026-10-24T00:00:00Z")), None);
        assert_eq!(
            RegistryRecord::default().age_days(&at("2026-10-28T12:00:00Z")),
            None
        );
    }
}
