//! New direct dependencies (`supply_chain.new_direct_dependency` of `policies/security.yaml`,
//! ADR 0009 item 4).
//!
//! A dependency is **new** when its package name is absent from the resolved lockfile at the base
//! commit, direct or transitive. A new dependency always needs a human. There is no allowlist, no
//! age or popularity threshold and no earlier approval that makes it automatic, and
//! [`DependencyDecision`] has no variant that approves one. The registry facts (does the name
//! exist, how old is its first publication, is it near a popular name, does it collide with an
//! internal package) never approve anything. They only decide how much scrutiny the human gets:
//!
//! * an ordinary approver for a name that exists, is old enough and looks ordinary;
//! * a security approver when the first publication is younger than
//!   `min_first_publish_age_days`, or its age is unknown, or the name is not in the registry or its
//!   existence is unknown, or it is one edit away from a popular name, or it equals an internal
//!   package name.
//!
//! A request is refused before any of that when the name is not a name of its ecosystem, or the
//! version requirement could name a source other than the registry (a git URL, a path, a tarball).
//! Names are compared as the ecosystem compares them: Cargo treats `-` and `_` as one letter and
//! ignores case; PyPI folds case and runs of `-`, `_` and `.`; npm and Go names are exact.

use std::collections::BTreeSet;

use super::decision::Designation;
use super::security::SecurityPolicy;
use super::{BuildError, RuleRef};

/// The longest package name accepted, matching `deps.request` (`max_len: 214`).
pub const MAX_NAME_BYTES: usize = 214;
/// The longest version requirement accepted, matching `deps.request` (`max_len: 64`).
pub const MAX_VERSION_REQ_BYTES: usize = 64;

/// The ecosystems of `deps.request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ecosystem {
    /// Rust crates.
    Cargo,
    /// npm packages.
    Npm,
    /// Python packages.
    Pip,
    /// Go modules.
    Go,
}

impl Ecosystem {
    /// Reads the policy spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "cargo" => Some(Self::Cargo),
            "npm" => Some(Self::Npm),
            "pip" => Some(Self::Pip),
            "go" => Some(Self::Go),
            _ => None,
        }
    }

    fn normalize(self, name: &str) -> String {
        match self {
            Self::Cargo => name.to_ascii_lowercase().replace('-', "_"),
            Self::Pip => {
                let mut out = String::with_capacity(name.len());
                let mut separator = false;
                for c in name.chars() {
                    if matches!(c, '-' | '_' | '.') {
                        separator = true;
                    } else {
                        if separator && !out.is_empty() {
                            out.push('-');
                        }
                        separator = false;
                        out.extend(c.to_lowercase());
                    }
                }
                out
            }
            Self::Npm | Self::Go => name.to_owned(),
        }
    }

    fn valid_name(self, name: &str) -> bool {
        if name.is_empty() || name.len() > MAX_NAME_BYTES {
            return false;
        }
        let alnum = |c: char| c.is_ascii_alphanumeric();
        match self {
            Self::Cargo => {
                name.len() <= 64
                    && name.starts_with(|c: char| c.is_ascii_alphabetic())
                    && name.chars().all(|c| alnum(c) || c == '-' || c == '_')
            }
            Self::Pip => {
                name.starts_with(alnum)
                    && name.ends_with(alnum)
                    && name
                        .chars()
                        .all(|c| alnum(c) || matches!(c, '-' | '_' | '.'))
            }
            Self::Npm => {
                let body = match name.strip_prefix('@') {
                    Some(scoped) => match scoped.split_once('/') {
                        Some((scope, rest)) if !scope.is_empty() && !rest.contains('/') => {
                            if !npm_part(scope) {
                                return false;
                            }
                            rest
                        }
                        _ => return false,
                    },
                    None => name,
                };
                npm_part(body)
            }
            Self::Go => {
                let mut parts = name.split('/');
                let first = parts.next().unwrap_or_default();
                first.contains('.')
                    && name.split('/').all(|p| {
                        !p.is_empty()
                            && p != "."
                            && p != ".."
                            && p.chars()
                                .all(|c| alnum(c) || matches!(c, '.' | '_' | '-' | '~'))
                    })
            }
        }
    }
}

fn npm_part(part: &str) -> bool {
    !part.is_empty()
        && !part.starts_with(['.', '_'])
        && part.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.' | '_' | '~')
        })
}

/// A typed dependency request (`deps.request`).
#[derive(Debug, Clone, Copy)]
pub struct DependencyRequest<'a> {
    /// The ecosystem, as the policy spells it.
    pub ecosystem: &'a str,
    /// The package name.
    pub name: &'a str,
    /// The version requirement.
    pub version_req: &'a str,
}

/// What the registry and the repository say about the package. A field the caller could not
/// learn is `None`, and `None` is treated as the worst answer, never the best.
#[derive(Debug, Clone, Copy, Default)]
pub struct RegistryFacts<'a> {
    /// Whether the name exists in the registry.
    pub exists_in_registry: Option<bool>,
    /// Days since the first publication of the package.
    pub first_publish_age_days: Option<u64>,
    /// Popular package names to measure the distance to.
    pub popular_names: &'a [String],
    /// Names of the organization's internal packages.
    pub internal_names: &'a [String],
}

/// Why a request was refused outright. The set is closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DependencyRefusal {
    /// The ecosystem is not one of the four.
    #[error("the ecosystem is not supported")]
    UnknownEcosystem,
    /// The name is not a name of the ecosystem: a URL, a path, a spec, a space.
    #[error("the name is not a valid package name")]
    InvalidName,
    /// The version requirement is too long or could name a source other than the registry.
    #[error("the version requirement is not a plain version requirement")]
    InvalidVersionRequirement,
}

/// A reason the human should look harder.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyFlag {
    /// The registry has no package of that name.
    NotInRegistry,
    /// Whether the registry has the package is not known.
    RegistryUnknown,
    /// The first publication is younger than the policy minimum.
    FirstPublishTooRecent,
    /// The age of the first publication is not known.
    FirstPublishUnknown,
    /// The name is one edit from a popular name.
    NearPopularName(String),
    /// The name equals an internal package name.
    InternalNameCollision,
}

/// What a dependency request needs. No variant approves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencyDecision {
    /// The name is already in the base lockfile, so this rule does not fire. A version change is
    /// still a lockfile change and goes through the lockfile, source and scanner checks.
    NotNew,
    /// A human must decide.
    NeedsHuman {
        /// The designation that must decide.
        designation: Designation,
        /// Why the scrutiny is what it is. Empty for an ordinary approver.
        flags: Vec<DependencyFlag>,
        /// The rule.
        rule: RuleRef,
    },
    /// Refused.
    Refused {
        /// Why.
        reason: DependencyRefusal,
        /// The rule.
        rule: RuleRef,
    },
}

/// The dependency rules of one security policy.
#[derive(Debug, Clone, Copy)]
pub struct DependencyPolicy {
    min_first_publish_age_days: u64,
}

fn within_one_edit(a: &str, b: &str) -> bool {
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
            // One substituted letter, or two neighbouring letters swapped (`reqwset`).
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

impl DependencyPolicy {
    /// Reads the dependency rules of `policy`.
    ///
    /// # Errors
    /// A [`BuildError`] when the policy does not say that a new direct dependency always needs a
    /// human, or defines "new" in a way this engine does not implement.
    pub fn from_policy(policy: &SecurityPolicy) -> Result<Self, BuildError> {
        let rule = &policy.supply_chain.new_direct_dependency;
        if rule.approval != "human_always" {
            return Err(BuildError::ProtectionDisabled {
                key: "supply_chain.new_direct_dependency.approval",
                found: rule.approval.clone(),
            });
        }
        if rule.new_means != "name_absent_from_base_commit_lockfile" {
            return Err(BuildError::UnknownValue {
                key: "supply_chain.new_direct_dependency.new_means",
                found: rule.new_means.clone(),
            });
        }
        Ok(Self {
            min_first_publish_age_days: rule.min_first_publish_age_days,
        })
    }

    /// Decides what a dependency request needs. `base_lockfile_names` are the package names of
    /// the resolved lockfile at the base commit, direct and transitive.
    #[must_use]
    pub fn decide(
        &self,
        request: &DependencyRequest<'_>,
        base_lockfile_names: &[String],
        facts: &RegistryFacts<'_>,
    ) -> DependencyDecision {
        let rule = RuleRef::new("supply_chain", "new_direct_dependency");
        let refuse = |reason| DependencyDecision::Refused {
            reason,
            rule: RuleRef::new("tools.entries", "deps.request"),
        };
        let Some(ecosystem) = Ecosystem::parse(request.ecosystem) else {
            return refuse(DependencyRefusal::UnknownEcosystem);
        };
        if !ecosystem.valid_name(request.name) {
            return refuse(DependencyRefusal::InvalidName);
        }
        let version_ok = request.version_req.len() <= MAX_VERSION_REQ_BYTES
            && request.version_req.chars().all(|c| {
                c.is_ascii_alphanumeric()
                    || matches!(
                        c,
                        '.' | '+' | '*' | '^' | '~' | '<' | '>' | '=' | '!' | '|' | ',' | ' ' | '-'
                    )
            });
        if !version_ok {
            return refuse(DependencyRefusal::InvalidVersionRequirement);
        }

        let wanted = ecosystem.normalize(request.name);
        if base_lockfile_names
            .iter()
            .any(|existing| ecosystem.normalize(existing) == wanted)
        {
            return DependencyDecision::NotNew;
        }

        let mut flags = BTreeSet::new();
        match facts.exists_in_registry {
            Some(true) => {}
            Some(false) => {
                flags.insert(DependencyFlag::NotInRegistry);
            }
            None => {
                flags.insert(DependencyFlag::RegistryUnknown);
            }
        }
        match facts.first_publish_age_days {
            Some(days) if days >= self.min_first_publish_age_days => {}
            Some(_) => {
                flags.insert(DependencyFlag::FirstPublishTooRecent);
            }
            None => {
                flags.insert(DependencyFlag::FirstPublishUnknown);
            }
        }
        for popular in facts.popular_names.iter().take(100_000) {
            let popular_norm = ecosystem.normalize(popular);
            if popular_norm != wanted && within_one_edit(&popular_norm, &wanted) {
                flags.insert(DependencyFlag::NearPopularName(popular.clone()));
            }
        }
        if facts
            .internal_names
            .iter()
            .take(100_000)
            .any(|internal| ecosystem.normalize(internal) == wanted)
        {
            flags.insert(DependencyFlag::InternalNameCollision);
        }
        DependencyDecision::NeedsHuman {
            designation: if flags.is_empty() {
                Designation::Approver
            } else {
                Designation::SecurityApprover
            },
            flags: flags.into_iter().collect(),
            rule,
        }
    }
}
