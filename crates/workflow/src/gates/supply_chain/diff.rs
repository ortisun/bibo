//! The difference between two lockfiles: which packages came, went and changed.
//!
//! A package is identified by its **name** (as cargo compares names), its **version** and its
//! **source**. Two packages with the same name and version from different sources are two
//! packages: a workspace member and a registry package can sit side by side in one lockfile, and
//! the diff must not take one for the other.
//!
//! The packages of both sides are matched in three steps:
//!
//! 1. A package whose name, version and source exist on both sides is the same package, and its
//!    checksum is compared. Equal identities pair off one to one, in file order.
//! 2. What is left is grouped by name, and a leftover of the new side is paired with the first
//!    leftover of the old side in the same compatibility series: an upgrade, a downgrade, or a
//!    change of source when the versions are equal. A version that cannot be ordered pairs with
//!    any leftover of its name and is flagged.
//! 3. A leftover with no partner is an added or a removed package, which is how a second,
//!    incompatible copy of a crate looks.
//!
//! Every step works on maps built once, so the cost grows with the size of the lockfiles and not
//! with its square.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use super::model::{LockedPackage, Lockfile, Origin, normalize};
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

/// The identity of a package inside its name group: version and source.
type Identity<'a> = (&'a str, &'a Origin);

fn identity(package: &LockedPackage) -> Identity<'_> {
    (package.version.as_str(), &package.origin)
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
        let before = group(base);
        let after = group(head);
        let names: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
        let mut diff = Self::default();
        let none: Vec<&LockedPackage> = Vec::new();
        for name in names {
            diff.compare_name(
                before.get(name).unwrap_or(&none),
                after.get(name).unwrap_or(&none),
            );
        }
        diff
    }

    fn compare_name(&mut self, before: &[&LockedPackage], after: &[&LockedPackage]) {
        // Step 1: the same name, version and source on both sides.
        let mut waiting: HashMap<Identity<'_>, VecDeque<usize>> = HashMap::new();
        for (position, new) in after.iter().enumerate() {
            waiting
                .entry(identity(new))
                .or_default()
                .push_back(position);
        }
        let mut taken = vec![false; after.len()];
        let mut unmatched_before: Vec<&LockedPackage> = Vec::new();
        for old in before {
            let partner = waiting
                .get_mut(&identity(old))
                .and_then(VecDeque::pop_front);
            match partner {
                Some(position) => {
                    taken[position] = true;
                    if after[position].checksum != old.checksum {
                        self.change(old, after[position], ChangeKind::ChecksumOnly);
                    }
                }
                None => unmatched_before.push(old),
            }
        }

        // Steps 2 and 3: what is left, paired by series.
        let mut pool = Pool::new(&unmatched_before);
        for (position, new) in after.iter().enumerate() {
            if taken[position] {
                continue;
            }
            match pool.take_partner(new) {
                Some(old) => self.pair(old, new),
                None => self.added.push((*new).clone()),
            }
        }
        self.removed.extend(pool.rest().into_iter().cloned());
    }

    fn pair(&mut self, old: &LockedPackage, new: &LockedPackage) {
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

    fn change(&mut self, before: &LockedPackage, after: &LockedPackage, kind: ChangeKind) {
        self.changed.push(Change {
            before: before.clone(),
            after: after.clone(),
            kind,
        });
    }
}

/// The packages of a lockfile by normalized name, in file order.
fn group(lock: &Lockfile) -> BTreeMap<String, Vec<&LockedPackage>> {
    let mut groups: BTreeMap<String, Vec<&LockedPackage>> = BTreeMap::new();
    for package in &lock.packages {
        groups
            .entry(normalize(&package.name))
            .or_default()
            .push(package);
    }
    groups
}

/// The packages of the old side that no package of the new side matched, indexed so that the
/// first partner of a new package is found without a scan.
struct Pool<'a> {
    /// By position in the file.
    all: BTreeMap<usize, &'a LockedPackage>,
    /// Positions of orderable versions, by compatibility series.
    by_series: BTreeMap<(u64, u64, u64), BTreeSet<usize>>,
    /// Positions of versions that cannot be ordered.
    unordered: BTreeSet<usize>,
}

impl<'a> Pool<'a> {
    fn new(packages: &[&'a LockedPackage]) -> Self {
        let mut pool = Self {
            all: BTreeMap::new(),
            by_series: BTreeMap::new(),
            unordered: BTreeSet::new(),
        };
        for (position, package) in packages.iter().enumerate() {
            pool.all.insert(position, package);
            match Version::parse(&package.version) {
                Some(version) => {
                    pool.by_series
                        .entry(version.series())
                        .or_default()
                        .insert(position);
                }
                None => {
                    pool.unordered.insert(position);
                }
            }
        }
        pool
    }

    /// The first old package that `new` replaces: one of its series, or any when either version
    /// cannot be ordered.
    fn take_partner(&mut self, new: &LockedPackage) -> Option<&'a LockedPackage> {
        let position = match Version::parse(&new.version) {
            None => self.all.keys().next().copied(),
            Some(version) => {
                let in_series = self
                    .by_series
                    .get(&version.series())
                    .and_then(|set| set.iter().next().copied());
                let unordered = self.unordered.iter().next().copied();
                match (in_series, unordered) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                }
            }
        }?;
        let package = self.all.remove(&position)?;
        self.unordered.remove(&position);
        if let Some(version) = Version::parse(&package.version)
            && let Some(set) = self.by_series.get_mut(&version.series())
        {
            set.remove(&position);
        }
        Some(package)
    }

    /// What no new package replaced, in file order.
    fn rest(self) -> Vec<&'a LockedPackage> {
        self.all.into_values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package(name: &str, version: &str, checksum: &str) -> LockedPackage {
        LockedPackage {
            name: name.to_owned(),
            version: version.to_owned(),
            origin: Origin::Registry,
            checksum: Some(checksum.to_owned()),
            dependencies: Vec::new(),
        }
    }

    fn member(name: &str, version: &str) -> LockedPackage {
        LockedPackage {
            name: name.to_owned(),
            version: version.to_owned(),
            origin: Origin::Path,
            checksum: None,
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

    /// SC-2. The identity of a package is name, version and source. A registry package with the
    /// name and version of a workspace member is a new package, whichever of the two comes first
    /// in the file.
    #[test]
    fn a_registry_package_beside_a_member_of_the_same_name_and_version_is_added() {
        let base = lock(vec![member("foo", "0.1.0")]);
        for order in [0, 1] {
            let mut packages = vec![member("foo", "0.1.0"), package("foo", "0.1.0", "aa")];
            if order == 1 {
                packages.reverse();
            }
            let diff = LockDiff::between(&base, &lock(packages));
            assert_eq!(diff.added.len(), 1, "order {order}");
            assert_eq!(diff.added[0].origin, Origin::Registry, "order {order}");
            assert!(diff.changed.is_empty() && diff.removed.is_empty());
        }
    }

    #[test]
    fn a_member_replaced_by_a_registry_package_of_the_same_version_is_a_source_change() {
        let base = lock(vec![member("foo", "0.1.0")]);
        let head = lock(vec![package("foo", "0.1.0", "aa")]);
        let diff = LockDiff::between(&base, &head);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].kind, ChangeKind::SourceChanged);
    }

    #[test]
    fn a_repeated_package_is_matched_once_for_each_copy() {
        let base = lock(vec![package("a", "1.0.0", "aa")]);
        let head = lock(vec![
            package("a", "1.0.0", "aa"),
            package("a", "1.0.0", "aa"),
        ]);
        let diff = LockDiff::between(&base, &head);
        assert_eq!(diff.added.len(), 1, "the second copy is new");
    }

    #[test]
    fn many_versions_of_one_name_are_paired_by_series_and_in_file_order() {
        let base = lock(vec![
            package("a", "1.0.0", "a1"),
            package("a", "2.0.0", "a2"),
            package("a", "0.3.0", "a3"),
        ]);
        let head = lock(vec![
            package("a", "1.5.0", "b1"),
            package("a", "2.4.0", "b2"),
            package("a", "0.3.2", "b3"),
            package("a", "3.0.0", "b4"),
        ]);
        let diff = LockDiff::between(&base, &head);
        assert_eq!(diff.changed.len(), 3);
        assert!(
            diff.changed
                .iter()
                .all(|change| change.kind == ChangeKind::Upgrade)
        );
        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].version, "3.0.0");
        assert!(diff.removed.is_empty());
    }
}
