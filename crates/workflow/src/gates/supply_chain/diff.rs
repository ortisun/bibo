//! The difference between two lockfiles: which packages came, went and changed.
//!
//! Packages are matched by name (as cargo compares names) and, when a name has several versions,
//! by version. A version that exists on both sides is compared for its source and checksum. A
//! version that exists on one side only is paired with a version of the same compatibility series
//! on the other side, and the pair is an upgrade or a downgrade. A version with no partner is an
//! added or a removed package, which is how a second, incompatible copy of a crate looks.

use std::collections::BTreeSet;

use super::model::{LockedPackage, Lockfile, normalize};
use super::version::Version;

/// How a package that stayed changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// A later version in the same series.
    Upgrade,
    /// An earlier version in the same series.
    Downgrade,
    /// The same version with another checksum.
    ChecksumOnly,
    /// Another source.
    SourceChanged,
    /// A version that this reader cannot order.
    Unordered,
}

/// A package that is on both sides and is not the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The package before.
    pub before: LockedPackage,
    /// The package after.
    pub after: LockedPackage,
    /// How it changed.
    pub kind: ChangeKind,
}

/// The difference between two lockfiles.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LockDiff {
    /// Packages that only the new lockfile has.
    pub added: Vec<LockedPackage>,
    /// Packages that only the old lockfile has.
    pub removed: Vec<LockedPackage>,
    /// Packages that changed.
    pub changed: Vec<Change>,
}

impl LockDiff {
    /// True when the two lockfiles resolve the same packages from the same places.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }

    /// Compares the lockfile of the base commit with the one of the candidate.
    #[must_use]
    pub fn between(base: &Lockfile, head: &Lockfile) -> Self {
        let names: BTreeSet<String> = base
            .packages
            .iter()
            .chain(&head.packages)
            .map(|package| normalize(&package.name))
            .collect();
        let mut diff = Self::default();
        for name in names {
            let of = |lock: &Lockfile| -> Vec<LockedPackage> {
                lock.packages
                    .iter()
                    .filter(|package| normalize(&package.name) == name)
                    .cloned()
                    .collect()
            };
            diff.compare_name(&of(base), &of(head));
        }
        diff
    }

    fn compare_name(&mut self, before: &[LockedPackage], after: &[LockedPackage]) {
        let mut unmatched_before: Vec<&LockedPackage> = Vec::new();
        for old in before {
            match after.iter().find(|new| new.version == old.version) {
                Some(new) => {
                    if new.origin != old.origin {
                        self.change(old, new, ChangeKind::SourceChanged);
                    } else if new.checksum != old.checksum {
                        self.change(old, new, ChangeKind::ChecksumOnly);
                    }
                }
                None => unmatched_before.push(old),
            }
        }
        for new in after
            .iter()
            .filter(|new| !before.iter().any(|old| old.version == new.version))
        {
            let partner = unmatched_before.iter().position(|old| {
                match (Version::parse(&old.version), Version::parse(&new.version)) {
                    (Some(a), Some(b)) => a.series() == b.series(),
                    // A version that is not a version cannot be told apart from another one
                    // of its package, so it is paired and flagged.
                    _ => true,
                }
            });
            match partner {
                Some(index) => {
                    let old = unmatched_before.remove(index);
                    let kind = if new.origin != old.origin {
                        ChangeKind::SourceChanged
                    } else {
                        match (Version::parse(&old.version), Version::parse(&new.version)) {
                            (Some(a), Some(b)) if b > a => ChangeKind::Upgrade,
                            (Some(a), Some(b)) if b < a => ChangeKind::Downgrade,
                            _ => ChangeKind::Unordered,
                        }
                    };
                    self.change(old, new, kind);
                }
                None => self.added.push(new.clone()),
            }
        }
        self.removed.extend(unmatched_before.into_iter().cloned());
    }

    fn change(&mut self, before: &LockedPackage, after: &LockedPackage, kind: ChangeKind) {
        self.changed.push(Change {
            before: before.clone(),
            after: after.clone(),
            kind,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::supply_chain::model::Origin;

    fn package(name: &str, version: &str, checksum: &str) -> LockedPackage {
        LockedPackage {
            name: name.to_owned(),
            version: version.to_owned(),
            origin: Origin::Registry,
            checksum: Some(checksum.to_owned()),
            dependencies: Vec::new(),
        }
    }

    fn lock(packages: Vec<LockedPackage>) -> Lockfile {
        Lockfile { packages }
    }

    #[test]
    fn identical_lockfiles_have_no_difference() {
        let a = lock(vec![package("serde", "1.0.1", "aa")]);
        assert!(LockDiff::between(&a, &a.clone()).is_empty());
    }

    #[test]
    fn added_removed_and_upgraded_packages_are_told_apart() {
        let base = lock(vec![
            package("a", "1.0.0", "aa"),
            package("gone", "1.0.0", "gg"),
        ]);
        let head = lock(vec![
            package("a", "1.1.0", "bb"),
            package("new", "0.1.0", "nn"),
        ]);
        let diff = LockDiff::between(&base, &head);
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].name, "new");
        assert_eq!(diff.removed.len(), 1);
        assert_eq!(diff.removed[0].name, "gone");
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].kind, ChangeKind::Upgrade);
    }

    #[test]
    fn a_downgrade_a_checksum_swap_and_a_source_move_are_named() {
        let base = lock(vec![
            package("a", "1.2.0", "aa"),
            package("b", "1.0.0", "bb"),
            package("c", "1.0.0", "cc"),
        ]);
        let mut moved = package("c", "1.0.0", "cc");
        moved.origin = Origin::Git("example.test".to_owned());
        let head = lock(vec![
            package("a", "1.1.0", "xx"),
            package("b", "1.0.0", "other"),
            moved,
        ]);
        let diff = LockDiff::between(&base, &head);
        let kind = |name: &str| {
            diff.changed
                .iter()
                .find(|c| c.after.name == name)
                .unwrap_or_else(|| panic!("no change for {name}"))
                .kind
        };
        assert_eq!(kind("a"), ChangeKind::Downgrade);
        assert_eq!(kind("b"), ChangeKind::ChecksumOnly);
        assert_eq!(kind("c"), ChangeKind::SourceChanged);
    }

    #[test]
    fn a_second_incompatible_copy_is_an_added_package_and_not_an_upgrade() {
        let base = lock(vec![package("a", "1.0.0", "aa")]);
        let head = lock(vec![
            package("a", "1.0.0", "aa"),
            package("a", "2.0.0", "bb"),
        ]);
        let diff = LockDiff::between(&base, &head);
        assert_eq!(diff.added.len(), 1);
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn a_version_that_is_not_a_version_is_flagged_unordered() {
        let base = lock(vec![package("a", "1.0.0", "aa")]);
        let head = lock(vec![package("a", "latest", "bb")]);
        let diff = LockDiff::between(&base, &head);
        assert_eq!(diff.changed[0].kind, ChangeKind::Unordered);
    }

    #[test]
    fn names_are_matched_as_cargo_matches_them() {
        let base = lock(vec![package("foo-bar", "1.0.0", "aa")]);
        let head = lock(vec![package("foo_bar", "1.0.0", "aa")]);
        assert!(LockDiff::between(&base, &head).is_empty());
    }
}
