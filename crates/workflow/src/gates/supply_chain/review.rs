//! The review of the new direct dependencies: the policy engine decides what each one needs,
//! and nothing is fetched until a recorded human decision covers all of them.
//!
//! [`Plan::new`] takes the result of the integrity checks, the registry facts and the decisions
//! that people have recorded so far, and answers three questions:
//!
//! * **Is the change refused already?** A violation of the integrity checks, an invalid request,
//!   or a license outside the allow list that the registry already shows. Then nothing is
//!   fetched and no person is asked to approve what cannot pass.
//! * **What does each new direct dependency need?** `DependencyPolicy::decide` says: always a
//!   human, an approver for a package that looks ordinary and a security approver for one that
//!   is young, of unknown age, not in the registry, one edit from a popular name or named like
//!   an internal package. No variant of the answer approves.
//! * **Is every one of them decided?** A dependency is decided when a recorded approval covers
//!   exactly its name, version and checksum, and the person held a designation that is enough.
//!
//! After the fetch, [`conclude`] reads `cargo metadata` for every package that came in: the
//! license of each (direct or not), and the build scripts and procedural macros. Build code that
//! arrives under a dependency needs the approval of a security approver, which is how the policy
//! check `build_script_added` (`blocks_until: security_review`) is met for dependencies.

use std::collections::{BTreeMap, BTreeSet};

use factory_domain::policy::authority::AuthorityPolicy;
use factory_domain::policy::decision::Designation;
use factory_domain::policy::dependency::{
    DependencyDecision, DependencyFlag, DependencyPolicy, DependencyRequest, RegistryFacts,
};
use factory_domain::values::{Sha256Digest, Timestamp};
use serde_json::{Value, json};

use super::approval::{
    ApprovalKind, BUILD_CODE_ACTION, DecisionScope, DependencyApproval, Subject,
};
use super::facts::RegistryRecord;
use super::findings::{Finding, check};
use super::integrity::{Integrity, NewDirect};
use super::licenses::{Denial, LicensePolicy};
use super::model::{LockedPackage, Lockfile, Origin, Resolved, normalize, plain};
use super::names::PopularNames;
use super::tools::PackageMeta;

/// The most characters of a text from the registry that the evidence keeps.
const MAX_REGISTRY_TEXT: usize = 200;

/// The registry facts of the new packages, by normalized name.
pub type RegistryTable = BTreeMap<String, RegistryRecord>;

/// The rules and the data a review reads.
#[derive(Debug, Clone, Copy)]
pub struct Settings<'a> {
    /// The dependency rules of the policy engine.
    pub dependency: &'a DependencyPolicy,
    /// The authority rules of the policy engine. The gate asks it who may approve build code
    /// (`approve_build_code`) and names no designation of its own.
    pub authority: &'a AuthorityPolicy,
    /// The license rule.
    pub licenses: &'a LicensePolicy,
    /// The names of the organization's internal packages.
    pub internal_names: &'a [String],
    /// The popular names to measure the distance to.
    pub popular: &'a PopularNames,
    /// The time of the review, from the clock port.
    pub now: Timestamp,
    /// The tenant and the job under review. A recorded decision for another tenant or job does
    /// not count.
    pub scope: DecisionScope,
    /// The hash of the policy bundle in force now. A decision taken under another bundle does not
    /// count: the policy may have tightened since, and a decision is not a standing waiver.
    pub policy_hash: &'a Sha256Digest,
}

/// One new direct dependency and what it needs.
#[derive(Debug, Clone)]
pub struct Need {
    /// The lockfile that holds it.
    pub lockfile: String,
    /// The exact thing a person approves.
    pub subject: Subject,
    /// The reasons for more scrutiny, from the policy engine. Empty for an ordinary package.
    pub flags: Vec<DependencyFlag>,
    /// The designation the policy engine says must decide.
    pub designation: Designation,
    /// What the registry said, kept as evidence for the person.
    pub record: RegistryRecord,
    /// Days since the first publication, when known.
    pub age_days: Option<u64>,
    /// A recorded decision that covers the subject with a designation that is enough.
    pub approval: Option<DependencyApproval>,
}

impl Need {
    /// True when no decision covers this dependency yet.
    #[must_use]
    pub fn awaiting(&self) -> bool {
        self.approval.is_none()
    }
}

/// The plan for a candidate.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The integrity checks.
    pub integrity: Integrity,
    /// Each new direct dependency.
    pub needs: Vec<Need>,
    /// What the review found besides the integrity checks.
    pub findings: Vec<Finding>,
    approvals: Vec<DependencyApproval>,
    /// The names that count as internal: the operator's list and the members of the project.
    internal_names: Vec<String>,
    /// The designations the policy names for the action `approve_build_code`.
    build_code_designations: Vec<Designation>,
}

impl Plan {
    /// Decides what the new direct dependencies of `integrity` need.
    #[must_use]
    pub fn new(
        integrity: Integrity,
        registry: &RegistryTable,
        approvals: &[DependencyApproval],
        settings: &Settings<'_>,
    ) -> Self {
        let internal_names: Vec<String> = settings
            .internal_names
            .iter()
            .cloned()
            .chain(integrity.internal_names.iter().cloned())
            .collect();
        let mut plan = Self {
            needs: Vec::new(),
            findings: Vec::new(),
            approvals: approvals
                .iter()
                .filter(|approval| approval.is_valid_for(&settings.scope, settings.policy_hash))
                .cloned()
                .collect(),
            internal_names,
            build_code_designations: settings
                .authority
                .approver_designations(BUILD_CODE_ACTION)
                .to_vec(),
            integrity,
        };
        // A change the integrity checks refuse asks nobody anything.
        if plan.integrity.has_violation() {
            return plan;
        }
        let direct = plan.integrity.new_direct.clone();
        for entry in &direct {
            plan.consider(entry, registry, settings);
        }
        plan
    }

    fn consider(&mut self, entry: &NewDirect, registry: &RegistryTable, settings: &Settings<'_>) {
        let package = &entry.package;
        let Some(checksum) = package
            .checksum
            .clone()
            .filter(|_| package.origin == Origin::Registry)
        else {
            return;
        };
        let record = registry
            .get(&normalize(&package.name))
            .cloned()
            .unwrap_or_default();
        let age_days = record.age_days(&settings.now);
        let request = DependencyRequest {
            ecosystem: "cargo",
            name: &package.name,
            version_req: &package.version,
        };
        let facts = RegistryFacts {
            exists_in_registry: record.exists,
            first_publish_age_days: age_days,
            popular_names: settings.popular.names(),
            internal_names: &self.internal_names,
        };
        let decision = settings
            .dependency
            .decide(&request, &self.integrity.base_names, &facts);
        let (designation, flags) = match decision {
            DependencyDecision::NotNew => return,
            DependencyDecision::Refused { .. } => {
                self.findings.push(Finding::violation(
                    check::INVALID_REQUEST,
                    Some(&entry.lockfile),
                    format!(
                        "The dependency {} {} is not a valid request for a dependency.",
                        plain(&package.name, 80),
                        plain(&package.version, 40)
                    ),
                ));
                return;
            }
            DependencyDecision::NeedsHuman {
                designation, flags, ..
            } => (designation, flags),
        };
        if let Some(license) = &record.license
            && let Err(denial) = settings.licenses.check(Some(license))
        {
            self.findings.push(license_finding(package, denial));
        }
        let subject = Subject {
            name: package.name.clone(),
            version: package.version.clone(),
            checksum,
        };
        let approval = self
            .approvals
            .iter()
            .find(|approval| {
                approval.is_for(ApprovalKind::NewDependency, &subject)
                    && approval.satisfies(designation)
            })
            .cloned();
        self.needs.push(Need {
            lockfile: entry.lockfile.clone(),
            subject,
            flags,
            designation,
            record,
            age_days,
            approval,
        });
    }

    /// Every violation: the integrity checks first, then the review.
    pub fn violations(&self) -> impl Iterator<Item = &Finding> {
        self.integrity
            .findings
            .iter()
            .chain(&self.findings)
            .filter(|finding| finding.is_violation())
    }

    /// Every warning.
    pub fn warnings(&self) -> impl Iterator<Item = &Finding> {
        self.integrity
            .findings
            .iter()
            .chain(&self.findings)
            .filter(|finding| !finding.is_violation())
    }

    /// True when the change is refused.
    #[must_use]
    pub fn refused(&self) -> bool {
        self.violations().next().is_some()
    }

    /// The new direct dependencies that no recorded decision covers.
    #[must_use]
    pub fn awaiting(&self) -> Vec<&Need> {
        self.needs.iter().filter(|need| need.awaiting()).collect()
    }

    /// True when the dependencies may be fetched: nothing is refused, every new direct
    /// dependency has its decision, and the dependency set changed so that there is something to
    /// fetch and read.
    #[must_use]
    pub fn may_fetch(&self) -> bool {
        !self.refused() && self.awaiting().is_empty() && self.integrity.lock_changed()
    }

    /// The decisions as ledger evidence: what each dependency is, what the policy said, what the
    /// registry said, and the decision that covers it.
    #[must_use]
    pub fn evidence(&self) -> Value {
        self.evidence_with(None)
    }

    /// The same, and the packages whose build code waits for a decision, with the exact subject
    /// (name, version, checksum) the person decides on and the designation the policy names.
    #[must_use]
    pub fn evidence_with(&self, conclusion: Option<&Conclusion>) -> Value {
        let needs: Vec<Value> = self
            .needs
            .iter()
            .map(|need| {
                json!({
                    "name": need.subject.name,
                    "version": need.subject.version,
                    "checksum": need.subject.checksum,
                    "lockfile": need.lockfile,
                    "needs": need.designation.as_str(),
                    "flags": need.flags.iter().map(flag_name).collect::<Vec<_>>(),
                    "registry": {
                        "exists": need.record.exists,
                        "first_publish_age_days": need.age_days,
                        // Text a package author chose: a fixed alphabet and a length bound, like
                        // every other string of the gate that comes from outside.
                        "license": need.record.license.as_deref().map(|t| plain(t, MAX_REGISTRY_TEXT)),
                        "repository": need.record.repository.as_deref().map(|t| plain(t, MAX_REGISTRY_TEXT)),
                        "downloads": need.record.downloads,
                    },
                    "approval": need.approval.as_ref().map(DependencyApproval::to_json),
                })
            })
            .collect();
        let build_code: Vec<Value> = conclusion
            .map(|c| c.escalated.as_slice())
            .unwrap_or_default()
            .iter()
            .map(|subject| {
                json!({
                    "name": subject.name,
                    "version": subject.version,
                    "checksum": subject.checksum,
                    "action": BUILD_CODE_ACTION,
                    "needs": self.build_code_designations.first().map(|d| d.as_str()),
                })
            })
            .collect();
        json!({
            "new_direct_dependencies": needs,
            "build_code_awaiting_a_decision": build_code,
        })
    }
}

/// The name of a flag for the evidence.
fn flag_name(flag: &DependencyFlag) -> String {
    match flag {
        DependencyFlag::NotInRegistry => "not_in_registry".to_owned(),
        DependencyFlag::RegistryUnknown => "registry_unknown".to_owned(),
        DependencyFlag::FirstPublishTooRecent => "first_publish_too_recent".to_owned(),
        DependencyFlag::FirstPublishUnknown => "first_publish_unknown".to_owned(),
        DependencyFlag::NearPopularName(name) => format!("near_popular_name:{}", plain(name, 80)),
        DependencyFlag::InternalNameCollision => "internal_name_collision".to_owned(),
    }
}

/// A phrase for a message.
#[must_use]
pub fn flag_phrase(flag: &DependencyFlag) -> String {
    match flag {
        DependencyFlag::NotInRegistry => "the name is not in the registry".to_owned(),
        DependencyFlag::RegistryUnknown => {
            "whether the name is in the registry is not known".to_owned()
        }
        DependencyFlag::FirstPublishTooRecent => {
            "it was first published less than 30 days ago".to_owned()
        }
        DependencyFlag::FirstPublishUnknown => "its first publication date is not known".to_owned(),
        DependencyFlag::NearPopularName(name) => {
            format!(
                "its name looks like the popular name {} (one edit away, or the same name with a decoration)",
                plain(name, 80)
            )
        }
        DependencyFlag::InternalNameCollision => {
            "its name is the name of an internal package".to_owned()
        }
    }
}

fn license_finding(package: &LockedPackage, denial: Denial) -> Finding {
    Finding::violation(
        check::LICENSE,
        None,
        format!(
            "The package {} {} {}.",
            plain(&package.name, 80),
            plain(&package.version, 40),
            denial.describe()
        ),
    )
}

/// The packages that are new or different in the candidate's lockfiles, other than the
/// project's own.
fn touched(plan: &Plan) -> impl Iterator<Item = &LockedPackage> {
    plan.integrity
        .diff
        .added
        .iter()
        .chain(
            plan.integrity
                .diff
                .changed
                .iter()
                .map(|change| &change.after),
        )
        .filter(|package| package.origin != Origin::Path)
}

/// What the metadata of the fetched packages adds to the review.
#[derive(Debug, Clone, Default)]
pub struct Conclusion {
    /// Licenses outside the list (violations) and build code that came in (a warning).
    pub findings: Vec<Finding>,
    /// Packages whose build code waits for a decision: every package that is new to the build
    /// (a new direct dependency, a package that comes in under one, or any other added package)
    /// and has a build script or is a procedural macro. The decision is the action
    /// `approve_build_code`, recorded as a [`DependencyApproval`] of kind
    /// [`ApprovalKind::BuildCode`] on exactly this subject (name, version and checksum).
    pub escalated: Vec<Subject>,
    /// The designations the policy names for that action. A report says who must decide from
    /// this list and not from a designation written in the gate.
    pub needs: Vec<Designation>,
}

impl Conclusion {
    /// True when a finding fails the gate.
    #[must_use]
    pub fn has_violation(&self) -> bool {
        self.findings.iter().any(Finding::is_violation)
    }
}

/// Reads the metadata of the fetched packages against the plan.
#[must_use]
pub fn conclude(plan: &Plan, metadata: &[PackageMeta], licenses: &LicensePolicy) -> Conclusion {
    let mut conclusion = Conclusion::default();
    let by_package: BTreeMap<(String, &str), &PackageMeta> = metadata
        .iter()
        .map(|meta| ((normalize(&meta.name), meta.version.as_str()), meta))
        .collect();
    let mut with_build_code: BTreeSet<(String, String)> = BTreeSet::new();
    for package in touched(plan) {
        let meta = by_package.get(&(normalize(&package.name), package.version.as_str()));
        let declared = meta.and_then(|meta| meta.license.as_deref());
        if let Err(denial) = licenses.check(declared) {
            conclusion.findings.push(license_finding(package, denial));
        }
        if meta.is_some_and(|meta| meta.runs_at_build()) {
            with_build_code.insert((normalize(&package.name), package.version.clone()));
        }
    }
    if !with_build_code.is_empty() {
        let names: Vec<String> = with_build_code
            .iter()
            .take(10)
            .map(|(name, version)| format!("{} {}", plain(name, 60), plain(version, 30)))
            .collect();
        conclusion.findings.push(Finding::warning(
            check::BUILD_CODE,
            None,
            format!(
                "{} package(s) that came in have a build script or a procedural macro, which runs when the project is built: {}.",
                with_build_code.len(),
                names.join(", ")
            ),
        ));
    }
    // Build code waits for the decision `approve_build_code`, which the policy gives to the
    // designations of that row, and for nothing else: a decision on the dependency itself, by any
    // designation, does not accept the code that runs when the project is built. The decision is
    // given for the package that has the code, bound to its name, version and checksum.
    let decided = |subject: &Subject| {
        plan.approvals.iter().any(|approval| {
            approval.is_for(ApprovalKind::BuildCode, subject)
                && approval.satisfies_any(&plan.build_code_designations)
        })
    };
    // A package is asked about when it is new to the build and has build code, whether it is a
    // new direct dependency, comes in under one or is a transitive crate pulled by a feature flag
    // or a changed manifest: `build_script_added` blocks until a security review, whoever asked
    // for the package. A package that only changed version, outside the closure of a new direct
    // dependency, is not asked again, because the gate has no record of what the base commit's
    // version ran (see the review notes, H-3).
    let mut in_a_closure: BTreeSet<(String, String)> = BTreeSet::new();
    for need in &plan.needs {
        if let Some(lock) = plan.integrity.head.locks.get(&need.lockfile) {
            in_a_closure.extend(closure(lock, &need.subject));
        }
    }
    let added: BTreeSet<(String, String)> = plan
        .integrity
        .diff
        .added
        .iter()
        .filter(|package| package.origin != Origin::Path)
        .map(|package| (normalize(&package.name), package.version.clone()))
        .collect();
    let mut asked: BTreeSet<(String, String)> = BTreeSet::new();
    for package in touched(plan) {
        let key = (normalize(&package.name), package.version.clone());
        if !with_build_code.contains(&key)
            || !(in_a_closure.contains(&key) || added.contains(&key))
            || !asked.insert(key)
        {
            continue;
        }
        let subject = Subject {
            name: package.name.clone(),
            version: package.version.clone(),
            checksum: package.checksum.clone().unwrap_or_default(),
        };
        if !decided(&subject) {
            conclusion.escalated.push(subject);
        }
    }
    conclusion.needs.clone_from(&plan.build_code_designations);
    conclusion
}

/// The (normalized name, version) of the subject and of everything it reaches in `lock`. The
/// subject is the registry package with that checksum, not a member of the project of the same
/// name and version.
fn closure(lock: &Lockfile, subject: &Subject) -> BTreeSet<(String, String)> {
    let index = lock.index();
    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut queue: Vec<&LockedPackage> = lock
        .packages
        .iter()
        .filter(|p| {
            normalize(&p.name) == normalize(&subject.name)
                && p.version == subject.version
                && p.origin != Origin::Path
        })
        .collect();
    while let Some(package) = queue.pop() {
        if !seen.insert((normalize(&package.name), package.version.clone())) {
            continue;
        }
        queue.extend(
            package
                .dependencies
                .iter()
                .filter_map(|r| match index.resolve(r) {
                    Resolved::One(found) => Some(found),
                    Resolved::Ambiguous | Resolved::Dangling => None,
                }),
        );
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_closure_follows_dependencies_and_stops_at_cycles() {
        let package = |name: &str, deps: &[&str]| LockedPackage {
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            origin: Origin::Registry,
            checksum: None,
            dependencies: deps
                .iter()
                .map(|d| super::super::model::LockedRef {
                    name: (*d).to_owned(),
                    version: None,
                    origin: None,
                })
                .collect(),
        };
        let lock = Lockfile {
            packages: vec![
                package("a", &["b"]),
                package("b", &["c", "a"]),
                package("c", &[]),
                package("z", &[]),
            ],
        };
        let subject = Subject {
            name: "a".to_owned(),
            version: "1.0.0".to_owned(),
            checksum: "0".repeat(64),
        };
        let names: Vec<String> = closure(&lock, &subject)
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }
}
