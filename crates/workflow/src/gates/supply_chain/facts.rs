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
