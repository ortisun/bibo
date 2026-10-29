//! The risk of a change, measured from the diff that will be delivered.
//!
//! `policies/approval.yaml` says the tier is `computed_by: policy_engine_from_trusted_diff_and_spec`.
//! The facts that the architecture stage measured come from the design: the files the architect said
//! it would touch. The implementation stage keeps a builder inside the files its plan owns, but the
//! plan check does not demand that the plan owns only what the design lists, so the diff can touch a
//! protected path, a sensitive file or a dependency manifest that the design never named (AUT-10).
//!
//! This module reads the changed paths the host exported from the job's object store, asks the path
//! policy what each of them is, and joins the answer with everything that is already known:
//!
//! * the facts of the job and of the design, with the intake classifier's claim;
//! * the facts of the diff.
//!
//! The tier is the **maximum** of the two assessments, and the separation-of-duties flags hold when
//! they hold in either. Nothing here lowers a tier: a diff that looks ordinary does not make a change
//! that the design called risky ordinary, and a design that looks ordinary does not hide a diff that
//! is not.
//!
//! A change to a dependency manifest or a lockfile counts as a new dependency. The path policy
//! cannot say from a path whether a package is new, so the rule leans to the side of more care; the
//! supply-chain gate reads the content and decides what is allowed.

use factory_domain::policy::paths::{ChangeEvidence, Operation, PathVerdict};
use factory_domain::policy::risk::{RiskAssessment, RiskFacts};
use factory_domain::policy::{PolicyEngine, RepoKind};
use factory_domain::vocabulary::RiskTier;
use factory_ports::workspace::{ChangeKind, ChangedPath};
use serde_json::{Value, json};

use crate::gates::scope::hardening::{self, PatchSignals};
use crate::stages::architecture::risk::{either, is_documentation, module_of};

/// A change that touches more files than this is not a small change, whatever its paths are.
pub const LARGE_CHANGE_FILES: usize = 25;

/// A change that touches more files than this cannot be read by a person in a review. It is counted
/// as one that touches a sensitive file, which makes it high (RR-16): a list that long is also the
/// shape of a list that was cut.
pub const HUGE_CHANGE_FILES: usize = 500;

/// The sensitive group whose checks include the one for a new dependency.
const DEPENDENCY_CHECK: &str = "new_dependency";
/// The sensitive group of container and infrastructure files.
const INFRASTRUCTURE_GROUP: &str = "container_and_infrastructure";

fn operation(kind: ChangeKind) -> Operation {
    match kind {
        ChangeKind::Added => Operation::Add,
        ChangeKind::Modified => Operation::Modify {
            gained_lines_only: false,
        },
        ChangeKind::Deleted => Operation::Delete,
    }
}

fn is_test_file(path: &str) -> bool {
    path.starts_with("tests/") || path.contains("/tests/")
}

/// The facts the diff shows.
#[must_use]
pub fn from_diff(policy: &PolicyEngine, changes: &[ChangedPath]) -> RiskFacts {
    let mut facts = RiskFacts::default();
    let mut hardened = false;
    for change in changes {
        let path = change.path.as_str();
        match policy.paths.check(
            RepoKind::Target,
            path,
            operation(change.kind),
            None,
            &ChangeEvidence::default(),
        ) {
            PathVerdict::Denied(_) => facts.protected_path_change = true,
            PathVerdict::Allowed(allowance) => {
                if !allowance.sensitive.is_empty() {
                    facts.sensitive_file_change = true;
                }
                for hit in &allowance.sensitive {
                    if hit.checks.iter().any(|check| check == DEPENDENCY_CHECK) {
                        facts.new_dependency = true;
                    }
                    if hit.group == INFRASTRUCTURE_GROUP {
                        facts.infra_change = true;
                    }
                }
            }
        }
        // What the policy's globs do not name: vendored code, the dependency files of other places
        // and ecosystems, and the files that run on a reviewer's machine (RR-14, RR-15, RR-16).
        if let Some(kind) = hardening::classify(path) {
            hardened = true;
            facts.sensitive_file_change = true;
            match kind {
                hardening::Kind::Vendored | hardening::Kind::DependencyFile => {
                    facts.new_dependency = true;
                }
                hardening::Kind::Infrastructure => facts.infra_change = true,
                hardening::Kind::RunsOnReviewer => {}
            }
        }
    }
    let paths: Vec<&str> = changes.iter().map(|change| change.path.as_str()).collect();
    if paths.len() > HUGE_CHANGE_FILES {
        facts.sensitive_file_change = true;
        hardened = true;
    }
    let mut modules: Vec<String> = paths.iter().filter_map(|path| module_of(path)).collect();
    modules.sort();
    modules.dedup();
    let large = paths.len() > LARGE_CHANGE_FILES;
    facts.multi_module_change = modules.len() > 1 || large;
    facts.docs_only =
        !paths.is_empty() && !hardened && paths.iter().all(|path| is_documentation(path));
    facts.tests_only_new_files = !changes.is_empty()
        && changes
            .iter()
            .all(|change| change.kind == ChangeKind::Added && is_test_file(change.path.as_str()));
    facts.single_module_change_without_sensitive_or_protected_paths = !paths.is_empty()
        && modules.len() <= 1
        && !large
        && !facts.sensitive_file_change
        && !facts.protected_path_change;
    facts
}

/// What the delivery stage stores about the risk, and the approval stage reads back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reported {
    /// The tier the delivery stage used.
    pub tier: RiskTier,
    /// A protected path changes.
    pub protected_path_change: bool,
    /// A sensitive file changes.
    pub sensitive_file_change: bool,
    /// A dependency manifest or lockfile changes.
    pub new_dependency: bool,
}

impl Reported {
    /// The part of the delivery result document.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "tier": self.tier.as_str(),
            "protected_path_change": self.protected_path_change,
            "sensitive_file_change": self.sensitive_file_change,
            "new_dependency": self.new_dependency,
        })
    }

    /// Reads it back. `None` for anything that is not one.
    #[must_use]
    pub fn from_json(value: &Value) -> Option<Self> {
        let flag = |key: &str| value.get(key).and_then(Value::as_bool);
        Some(Self {
            tier: RiskTier::parse(value.get("tier")?.as_str()?).ok()?,
            protected_path_change: flag("protected_path_change")?,
            sensitive_file_change: flag("sensitive_file_change")?,
            new_dependency: flag("new_dependency")?,
        })
    }
}

/// The risk of a change: the facts that hold and the assessment the policy made.
#[derive(Debug, Clone)]
pub struct ChangeRisk {
    /// The facts of the job and the design, joined with the facts of the diff.
    pub facts: RiskFacts,
    /// The assessment: the highest tier of the two sources and the agent's claim.
    pub assessment: RiskAssessment,
}

impl ChangeRisk {
    /// What the delivery stage stores.
    #[must_use]
    pub fn reported(&self) -> Reported {
        Reported {
            tier: self.assessment.tier,
            protected_path_change: self.facts.protected_path_change,
            sensitive_file_change: self.facts.sensitive_file_change,
            new_dependency: self.facts.new_dependency,
        }
    }
}

/// Assesses a change from what was known before the diff (`known`, with the classifier's `claim`)
/// and from the diff itself. The tier is the highest of the two; the claim can raise it, never
/// lower it.
#[must_use]
pub fn assess(
    policy: &PolicyEngine,
    known: &RiskFacts,
    claim: Option<RiskTier>,
    changes: &[ChangedPath],
) -> ChangeRisk {
    assess_with_patch(policy, known, claim, changes, &PatchSignals::default())
}

/// What the headers of the patch add to the facts of the paths: a submodule bump is a dependency
/// change, and a symbolic link, a change of mode, a binary file and a patch whose headers could not
/// be read are not ordinary changes (RR-16). None of them lowers anything.
fn apply_signals(facts: &mut RiskFacts, signals: &PatchSignals) {
    if signals.is_ordinary() {
        return;
    }
    if signals.submodule {
        facts.new_dependency = true;
    }
    facts.sensitive_file_change = true;
    facts.docs_only = false;
    facts.tests_only_new_files = false;
    facts.single_module_change_without_sensitive_or_protected_paths = false;
}

/// [`assess`], with what the headers of the exported patch show ([`PatchSignals::of`]).
#[must_use]
pub fn assess_with_patch(
    policy: &PolicyEngine,
    known: &RiskFacts,
    claim: Option<RiskTier>,
    changes: &[ChangedPath],
    signals: &PatchSignals,
) -> ChangeRisk {
    let mut diff = from_diff(policy, changes);
    apply_signals(&mut diff, signals);
    let before = policy.risk.assess(known, claim);
    let after = policy.risk.assess(&diff, None);
    let mut assessment = if after.tier > before.tier {
        after.clone()
    } else {
        before.clone()
    };
    for criterion in before.matched.iter().chain(after.matched.iter()) {
        if !assessment.matched.contains(criterion) {
            assessment.matched.push(criterion.clone());
        }
    }
    assessment.agent_claim = claim;
    ChangeRisk {
        facts: either(*known, diff),
        assessment,
    }
}

/// The risk the approval stage puts in front of a person: what it knows itself, joined with what
/// the delivery stage measured from the diff. Nothing is lowered.
#[must_use]
pub fn join_reported(
    policy: &PolicyEngine,
    known: &RiskFacts,
    claim: Option<RiskTier>,
    reported: &Reported,
) -> Reported {
    let own = policy.risk.assess(known, claim);
    Reported {
        tier: own.tier.max(reported.tier),
        protected_path_change: known.protected_path_change || reported.protected_path_change,
        sensitive_file_change: known.sensitive_file_change || reported.sensitive_file_change,
        new_dependency: known.new_dependency || reported.new_dependency,
    }
}
