//! The integrity checks: what the candidate's dependency files do compared with the base
//! commit's. Pure code, no sandbox, no network.
//!
//! These are the checks that need nothing but the files, so they run first, and a change that
//! breaks one never reaches a sandbox (the same order as the host-side gates of the validation
//! stage). They answer NT-SUP-03 (lockfile and source tampering) and find the new direct
//! dependencies that the policy sends to a person (NT-SUP-01).
//!
//! | Check | Finding |
//! |---|---|
//! | A package from a git repository, a path, another registry, or an unknown source | `registry_or_source_changed` |
//! | A dependency declared by git, path or another registry | `git-dependency`, `path-dependency`, `alternate-registry-dependency` |
//! | `[patch]` or `[replace]` added or changed | `patch-or-replace` |
//! | The build configuration redirects the registry or names a program | `registry-redirect`, `build-config-changed` |
//! | Same version, other checksum; a registry package with no checksum | `checksum-changed`, `checksum-missing` |
//! | An older version than before; a version that cannot be ordered | `version-downgrade`, `unordered-version` |
//! | Packages added or removed in the lockfile with no change to a manifest | `lockfile-only-edit` |
//! | A manifest dependency the lockfile does not hold; no lockfile at all | `lockfile-out-of-date`, `lockfile-missing` |
//! | A transitive package with the name of an internal package | `dependency-confusion` |

use std::collections::{BTreeMap, BTreeSet};

use super::diff::{ChangeKind, LockDiff};
use super::findings::{Finding, check};
use super::model::{
    BuildConfig, ConfigClass, DeclaredSource, DependencyFormat, FileKind, LockedPackage, Lockfile,
    Manifest, Origin, ParseError, Side, normalize, plain,
};
use super::names::PopularNames;

/// Every dependency file of one commit, read.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    /// Lockfiles by path.
    pub locks: BTreeMap<String, Lockfile>,
    /// Manifests by path.
    pub manifests: BTreeMap<String, Manifest>,
    /// Build configurations by path.
    pub configs: BTreeMap<String, BuildConfig>,
}

impl Snapshot {
    /// Reads every file of `side`. The files that could not be read are returned with the
    /// reason, and are absent from the snapshot.
    #[must_use]
    pub fn read(format: &dyn DependencyFormat, side: &Side) -> (Self, Vec<(String, ParseError)>) {
        let mut snapshot = Self::default();
        let mut unreadable = Vec::new();
        for (path, text) in side.files() {
            let outcome = match format.kind_of(path) {
                Some(FileKind::Lockfile) => format
                    .parse_lockfile(text)
                    .map(|lock| drop(snapshot.locks.insert(path.to_owned(), lock))),
                Some(FileKind::Manifest) => format
                    .parse_manifest(text)
                    .map(|manifest| drop(snapshot.manifests.insert(path.to_owned(), manifest))),
                Some(FileKind::BuildConfig) => format
                    .parse_build_config(text)
                    .map(|config| drop(snapshot.configs.insert(path.to_owned(), config))),
                None => Ok(()),
            };
            if let Err(error) = outcome {
                unreadable.push((path.to_owned(), error));
            }
        }
        (snapshot, unreadable)
    }

    /// The normalized name of every package of every lockfile.
    #[must_use]
    pub fn package_names(&self) -> BTreeSet<String> {
        self.locks.values().flat_map(Lockfile::names).collect()
    }

    /// The registry package names that manifests declare, with the workspace table resolved.
    fn declared_registry_names(&self) -> BTreeSet<String> {
        let workspace: BTreeMap<&str, &super::model::Declared> = self
            .manifests
            .values()
            .flat_map(|manifest| &manifest.workspace_declared)
            .map(|declared| (declared.key.as_str(), declared))
            .collect();
        let mut names = BTreeSet::new();
        for manifest in self.manifests.values() {
            for declared in &manifest.declared {
                let resolved = match declared.source {
                    DeclaredSource::Workspace => workspace.get(declared.key.as_str()).copied(),
                    _ => Some(declared),
                };
                if let Some(resolved) = resolved
                    && resolved.source == DeclaredSource::Registry
                {
                    names.insert(normalize(&resolved.name));
                }
            }
        }
        names
    }

    /// Every declaration, as the canonical lines that tell two versions of a manifest apart.
    fn declarations(&self) -> BTreeSet<(String, String)> {
        self.manifests
            .iter()
            .flat_map(|(path, manifest)| {
                manifest
                    .declared
                    .iter()
                    .chain(&manifest.workspace_declared)
                    .map(|declared| declared.canonical.clone())
                    .chain(manifest.patches.iter().cloned())
                    .map(move |line| (path.clone(), line))
            })
            .collect()
    }
}

/// What the checks need besides the files.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// The names of the organization's internal packages.
    pub internal_names: &'a [String],
    /// The popular names to measure the distance to.
    pub popular: &'a PopularNames,
}

/// A direct dependency that the base commit's lockfile does not hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDirect {
    /// The lockfile that holds it.
    pub lockfile: String,
    /// The locked package.
    pub package: LockedPackage,
}

/// The result of the integrity checks.
#[derive(Debug, Clone)]
pub struct Integrity {
    /// Everything the checks found.
    pub findings: Vec<Finding>,
    /// The packages that came, went and changed, over every lockfile.
    pub diff: LockDiff,
    /// The new direct dependencies.
    pub new_direct: Vec<NewDirect>,
    /// The candidate's files.
    pub head: Snapshot,
    /// The names of the packages of the base commit's lockfiles.
    pub base_names: Vec<String>,
}

impl Integrity {
    /// True when a check found a violation.
    #[must_use]
    pub fn has_violation(&self) -> bool {
        self.findings.iter().any(Finding::is_violation)
    }

    /// True when the findings include one of this check.
    #[must_use]
    pub fn has(&self, check: &str) -> bool {
        self.findings.iter().any(|finding| finding.check == check)
    }

    /// True when the change touches the dependency set: a package came, went or changed.
    #[must_use]
    pub fn lock_changed(&self) -> bool {
        !self.diff.is_empty()
    }
}

/// The file of the base commit could not be read. The base is trusted, so this is not a finding
/// about the change: the gate is blocked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a dependency file of the base commit could not be read")]
pub struct BaseUnreadable {
    /// The path of the first file.
    pub path: String,
}

/// Runs the integrity checks.
///
/// # Errors
/// [`BaseUnreadable`] when a dependency file of the base commit cannot be read.
pub fn inspect(
    format: &dyn DependencyFormat,
    base: &Side,
    head: &Side,
    cx: &Context<'_>,
) -> Result<Integrity, BaseUnreadable> {
    let (base_snapshot, base_bad) = Snapshot::read(format, base);
    if let Some((path, _)) = base_bad.into_iter().next() {
        return Err(BaseUnreadable { path });
    }
    let (head_snapshot, head_bad) = Snapshot::read(format, head);
    let mut run = Run {
        format,
        cx,
        base: &base_snapshot,
        head: &head_snapshot,
        findings: Vec::new(),
        diff: LockDiff::default(),
    };
    for (path, error) in head_bad {
        run.findings.push(Finding::violation(
            check::UNREADABLE,
            Some(&path),
            format!(
                "The dependency file {} could not be read ({}), so the change cannot be judged.",
                plain(&path, 200),
                match error {
                    ParseError::Syntax(_) => "it is not valid",
                    ParseError::Unsupported => "its layout is not one this check knows",
                }
            ),
        ));
    }
    let new_direct = run.run();
    let Run { findings, diff, .. } = run;
    Ok(Integrity {
        findings,
        diff,
        new_direct,
        base_names: base_snapshot.package_names().into_iter().collect(),
        head: head_snapshot,
    })
}

struct Run<'a> {
    format: &'a dyn DependencyFormat,
    cx: &'a Context<'a>,
    base: &'a Snapshot,
    head: &'a Snapshot,
    findings: Vec<Finding>,
    diff: LockDiff,
}

impl Run<'_> {
    fn run(&mut self) -> Vec<NewDirect> {
        self.lockfiles();
        let new_direct = self.new_direct_dependencies();
        self.lockfile_only();
        self.manifests();
        self.configs();
        self.consistency();
        self.names(&new_direct);
        new_direct
    }

    fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// The lockfiles: removal, then each pair compared.
    fn lockfiles(&mut self) {
        let empty = Lockfile::default();
        for path in self.base.locks.keys() {
            if !self.head.locks.contains_key(path) {
                self.push(Finding::violation(
                    check::LOCKFILE_REMOVED,
                    Some(path),
                    format!(
                        "The lockfile {} exists at the base commit and is gone from the change.",
                        plain(path, 200)
                    ),
                ));
            }
        }
        for (path, head) in &self.head.locks {
            let base = self.base.locks.get(path).unwrap_or(&empty);
            let diff = LockDiff::between(base, head);
            self.diff.added.extend(diff.added);
            self.diff.removed.extend(diff.removed);
            self.diff.changed.extend(diff.changed);
        }
        let changed: Vec<_> = self.diff.changed.clone();
        for change in &changed {
            let name = plain(&change.after.name, 80);
            let (before, after) = (
                plain(&change.before.version, 40),
                plain(&change.after.version, 40),
            );
            let finding = match change.kind {
                ChangeKind::Upgrade => continue,
                ChangeKind::Downgrade => Finding::violation(
                    check::DOWNGRADE,
                    None,
                    format!("The package {name} moved from {before} to the older version {after}."),
                ),
                ChangeKind::Unordered => Finding::violation(
                    check::UNORDERED,
                    None,
                    format!(
                        "The package {name} changed from {before} to {after}, and the versions cannot be ordered."
                    ),
                ),
                ChangeKind::ChecksumOnly => Finding::violation(
                    check::CHECKSUM_CHANGED,
                    None,
                    format!(
                        "The package {name} {after} has a different checksum than at the base commit, with the same version."
                    ),
                ),
                ChangeKind::SourceChanged => Finding::violation(
                    check::SOURCE,
                    None,
                    format!(
                        "The package {name} {after} now comes from {}, and came from {}.",
                        change.after.origin.describe(),
                        change.before.origin.describe()
                    ),
                ),
            };
            self.push(finding);
        }
        let touched: Vec<LockedPackage> = self
            .diff
            .added
            .iter()
            .cloned()
            .chain(self.diff.changed.iter().map(|change| change.after.clone()))
            .collect();
        for package in &touched {
            self.package(package);
        }
    }

    /// The rules for one package that is new or different.
    fn package(&mut self, package: &LockedPackage) {
        let name = plain(&package.name, 80);
        let version = plain(&package.version, 40);
        match &package.origin {
            Origin::Registry => {
                let sound = package.checksum.as_deref().is_some_and(|sum| {
                    sum.len() == 64 && sum.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
                });
                if !sound {
                    self.push(Finding::violation(
                        check::CHECKSUM_MISSING,
                        None,
                        format!("The package {name} {version} comes from the registry and has no valid checksum."),
                    ));
                }
            }
            Origin::Path => {
                let explained = self.head.manifests.values().any(|manifest| {
                    manifest
                        .name
                        .as_deref()
                        .is_some_and(|own| normalize(own) == normalize(&package.name))
                });
                if !explained {
                    self.push(Finding::violation(
                        check::PATH_UNEXPLAINED,
                        None,
                        format!("The lockfile holds the package {name} {version} with no source, and no manifest of the project describes it."),
                    ));
                }
            }
            other => self.push(Finding::violation(
                check::SOURCE,
                None,
                format!(
                    "The package {name} {version} comes from {}, and the policy allows only {}.",
                    other.describe(),
                    self.format.registry_label()
                ),
            )),
        }
    }

    /// The direct dependencies that the base lockfiles do not hold: the packages that a member
    /// of the project depends on, whose name is in no base lockfile.
    fn new_direct_dependencies(&self) -> Vec<NewDirect> {
        let known = self.base.package_names();
        let mut found: Vec<NewDirect> = Vec::new();
        for (path, lock) in &self.head.locks {
            for member in lock.members() {
                for reference in &member.dependencies {
                    let Some(package) = lock.resolve(reference) else {
                        continue;
                    };
                    if package.origin == Origin::Path || known.contains(&normalize(&package.name)) {
                        continue;
                    }
                    let entry = NewDirect {
                        lockfile: path.clone(),
                        package: package.clone(),
                    };
                    if !found.contains(&entry) {
                        found.push(entry);
                    }
                }
            }
        }
        found
    }

    /// A lockfile that changed in a way no manifest explains.
    fn lockfile_only(&mut self) {
        if self.diff.is_empty() || self.base.declarations() != self.head.declarations() {
            return;
        }
        let membership = !self.diff.added.is_empty() || !self.diff.removed.is_empty();
        let plain_updates = self
            .diff
            .changed
            .iter()
            .any(|change| change.kind == ChangeKind::Upgrade);
        if membership {
            self.push(Finding::violation(
                check::LOCKFILE_ONLY,
                None,
                "The lockfile adds or removes packages and no manifest changed, so nothing asked for them.".to_owned(),
            ));
        } else if plain_updates {
            self.push(Finding::warning(
                check::UPDATE_ONLY,
                None,
                "The lockfile moves packages to later versions and no manifest changed.".to_owned(),
            ));
        }
    }

    /// The manifests: sources, patches and build code that are new.
    fn manifests(&mut self) {
        let before = self.base.declarations();
        for (path, manifest) in &self.head.manifests {
            let old = self.base.manifests.get(path);
            for declared in manifest.declared.iter().chain(&manifest.workspace_declared) {
                if before.contains(&(path.clone(), declared.canonical.clone())) {
                    continue;
                }
                let (id, what) = match declared.source {
                    DeclaredSource::Git => (check::GIT, "a git repository"),
                    DeclaredSource::Path => (check::PATH, "a path"),
                    DeclaredSource::AlternateRegistry => {
                        (check::ALTERNATE_REGISTRY, "another registry")
                    }
                    DeclaredSource::Registry | DeclaredSource::Workspace => continue,
                };
                self.push(Finding::violation(
                    id,
                    Some(path),
                    format!(
                        "The dependency {} in {} is declared from {what}, and the policy allows only {}.",
                        plain(&declared.name, 80),
                        plain(&declared.section, 80),
                        self.format.registry_label()
                    ),
                ));
            }
            for patch in &manifest.patches {
                if !before.contains(&(path.clone(), patch.clone())) {
                    self.push(Finding::violation(
                        check::PATCH,
                        Some(path),
                        "The manifest adds or changes a patch or replace entry, which swaps a package for another source.".to_owned(),
                    ));
                }
            }
            if (manifest.build_script && !old.is_some_and(|m| m.build_script))
                || (manifest.proc_macro && !old.is_some_and(|m| m.proc_macro))
            {
                self.push(Finding::warning(
                    check::BUILD_CODE,
                    Some(path),
                    "The manifest adds a build script or a procedural macro, which runs when the project is built.".to_owned(),
                ));
            }
        }
    }

    /// The build configuration: any key that is not harmless and is new or different.
    fn configs(&mut self) {
        for (path, config) in &self.head.configs {
            let old: BTreeSet<(&str, &str)> = self
                .base
                .configs
                .get(path)
                .map(|c| {
                    c.entries
                        .iter()
                        .map(|e| (e.key.as_str(), e.value.as_str()))
                        .collect()
                })
                .unwrap_or_default();
            for entry in &config.entries {
                if entry.class == ConfigClass::Benign
                    || old.contains(&(entry.key.as_str(), entry.value.as_str()))
                {
                    continue;
                }
                let (id, what) = match entry.class {
                    ConfigClass::Redirect => (
                        check::REGISTRY_REDIRECT,
                        "changes where packages come from or how the registry is reached",
                    ),
                    ConfigClass::Execution => (
                        check::BUILD_CONFIG,
                        "names a program for cargo to run or an environment to set",
                    ),
                    _ => (
                        check::BUILD_CONFIG,
                        "is a key this check does not know to be harmless",
                    ),
                };
                self.push(Finding::violation(
                    id,
                    Some(path),
                    format!(
                        "The build configuration {} sets {}, which {what}.",
                        plain(path, 200),
                        plain(&entry.key, 120)
                    ),
                ));
            }
        }
    }

    /// The manifests and the lockfiles must agree.
    fn consistency(&mut self) {
        let declared = self.head.declared_registry_names();
        if self.head.locks.is_empty() && !declared.is_empty() {
            self.push(Finding::violation(
                check::LOCKFILE_MISSING,
                None,
                "The project declares dependencies and has no lockfile, and the policy requires one.".to_owned(),
            ));
            return;
        }
        let locked = self.head.package_names();
        for name in declared.difference(&locked) {
            self.push(Finding::violation(
                check::LOCKFILE_STALE,
                None,
                format!(
                    "A manifest declares the dependency {} and the lockfile does not hold it.",
                    plain(name, 80)
                ),
            ));
        }
    }

    /// Names that look like another name: a transitive package with an internal name is a
    /// violation; a package one edit from a popular name is a warning.
    fn names(&mut self, new_direct: &[NewDirect]) {
        let direct: BTreeSet<(String, String)> = new_direct
            .iter()
            .map(|d| (normalize(&d.package.name), d.package.version.clone()))
            .collect();
        let touched: Vec<LockedPackage> = self
            .diff
            .added
            .iter()
            .cloned()
            .chain(self.diff.changed.iter().map(|c| c.after.clone()))
            .collect();
        for package in touched {
            if direct.contains(&(normalize(&package.name), package.version.clone())) {
                // The policy engine decides these, with a security approver.
                continue;
            }
            let wanted = normalize(&package.name);
            let name = plain(&package.name, 80);
            if package.origin.is_default_registry()
                && self
                    .cx
                    .internal_names
                    .iter()
                    .any(|internal| normalize(internal) == wanted)
            {
                self.push(Finding::violation(
                    check::CONFUSION,
                    None,
                    format!("The package {name} comes from the public registry and has the name of an internal package."),
                ));
            }
            if let Some(popular) = self
                .cx
                .popular
                .names()
                .iter()
                .find(|popular| near_miss(&normalize(popular), &wanted))
            {
                self.push(Finding::warning(
                    check::SUSPECT_NAME,
                    None,
                    format!(
                        "The package {name} is one edit away from the popular name {}.",
                        plain(popular, 80)
                    ),
                ));
            }
        }
    }
}

/// True when `a` and `b` differ and are one edit apart: one letter changed, added, dropped, or
/// two neighbouring letters swapped. This is the rule of `DependencyPolicy`.
fn near_miss(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    if a.len().abs_diff(b.len()) > 1 {
        return false;
    }
    let common = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let (ra, rb) = (
        a.get(common..).unwrap_or_default(),
        b.get(common..).unwrap_or_default(),
    );
    match ra.len().cmp(&rb.len()) {
        std::cmp::Ordering::Equal => {
            ra.get(1..) == rb.get(1..)
                || (ra.len() >= 2
                    && ra.first() == rb.get(1)
                    && ra.get(1) == rb.first()
                    && ra.get(2..) == rb.get(2..))
        }
        std::cmp::Ordering::Less => ra == rb.get(1..).unwrap_or_default(),
        std::cmp::Ordering::Greater => ra.get(1..).unwrap_or_default() == rb,
    }
}
