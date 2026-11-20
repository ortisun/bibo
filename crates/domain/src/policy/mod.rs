//! The typed policy documents, and the pure rules that decide what a path, a command, a tool
//! call, a dependency or an action may do under `policies/security.yaml` and
//! `policies/approval.yaml`.
//!
//! # Why the documents live here
//!
//! The two files are read by `factory-contracts`, a ring 2 adapter that depends on this crate. The
//! evaluators are ring 0 and must name the document types, so the types are here and
//! `factory-contracts` re-exports them. They use `serde`, `regex` and `globset` only, all three on
//! the `domain` allow list. Reading a file, parsing YAML, checking that a name used in one place is
//! defined in another, and the policy hash stay in `factory-contracts`.
//!
//! No policy type implements `Default`: a missing policy is an error, never an empty allow.
//!
//! # The evaluators
//!
//! | Module | Decides | Answer |
//! |---|---|---|
//! | [`paths`] | Whether a path, a diff entry or a symlink target may be read, added, changed, deleted or renamed | [`paths::PathVerdict`] |
//! | [`commands`] | Whether an argument vector may run, and with which forced arguments | [`commands::CommandVerdict`] |
//! | [`tools`] | Which tools a stage may hold, and whether a call, a skill or a grant request is allowed | [`tools::ToolVerdict`] |
//! | [`egress`] | Whether a host, port and method may be reached under a network profile, and which resolved addresses are refused | [`egress::EgressVerdict`] |
//! | [`dependency`] | What a new direct dependency needs | [`dependency::DependencyDecision`] |
//! | [`authority`] | Who holds a designation, who may take an action, the autonomy ladder, overrides | [`authority::ActionVerdict`] |
//! | [`risk`] | The risk tier of a change, computed from facts and never from an agent's claim | [`risk::RiskAssessment`] |
//! | [`budget`] | Budget and rework checks against the ceilings, which a project can only lower | [`budget::BudgetVerdict`] |
//! | [`issue_workflow`] | Which `factory:` label shows which job state, and whether a name may be written as a status label | [`issue_workflow::StatusLabel`] |
//! | [`tighten`] | Whether a project policy only tightens the central one, and the merged policy | [`tighten::TightenReport`] |
//!
//! [`PolicyEngine`] builds all of them from one pair of documents, except [`tighten`], which
//! compares two pairs.
//!
//! # Rules that hold for every evaluator
//!
//! * **Pure.** A decision is a function of the policy and the facts passed in. There is no clock,
//!   file, process, network or random call. Time comes in as a parameter.
//! * **Total and panic-free.** Every input, hostile or not, gets an answer. Sizes are bounded
//!   before any work is done, and the work after that is linear in the input.
//! * **Closed answers.** A verdict is an enum. A denial carries a reason from a closed set and the
//!   [`RuleRef`] of the policy rule that caused it, so an audit event can name both.
//! * **Deny overrides.** When a deny and an allow both apply, the deny wins.
//! * **Fail closed on the policy itself.** A setting the engine cannot honour, such as a boolean
//!   that says a protection is off, is a [`BuildError`]. The engine does not run with it.
//! * **Authority comes from the allowlist.** A role is a designation on the allowlist, found by
//!   the numeric GitHub user id. A login, a GitHub permission and an `author_association` grant
//!   nothing.

pub mod approval;
pub mod authority;
pub mod budget;
pub mod commands;
pub mod common;
pub mod decision;
pub mod dependency;
pub mod egress;
pub mod issue_workflow;
pub mod paths;
pub mod risk;
pub mod routing;
pub mod security;
pub mod solo;
pub mod tighten;
pub mod tools;

mod engine;

pub use approval::ApprovalPolicy;
pub use common::{ConfigSource, GlobText, PolicyStatus, RegexText, ThreatId};
pub use engine::PolicyEngine;
pub use security::SecurityPolicy;

use std::fmt;

/// The policy rule behind a decision: the part of the policy (`area`, such as
/// `protected_paths.groups` or `forbidden_command_classes`) and the identifier inside it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RuleRef {
    area: &'static str,
    id: String,
}

impl RuleRef {
    /// Names a rule.
    #[must_use]
    pub fn new(area: &'static str, id: impl Into<String>) -> Self {
        Self {
            area,
            id: id.into(),
        }
    }

    /// The part of the policy, such as `forbidden_command_classes`.
    #[must_use]
    pub fn area(&self) -> &'static str {
        self.area
    }

    /// The identifier inside that part, such as `shell_interpreters`.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl fmt::Display for RuleRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.area, self.id)
    }
}

/// Which repository a rule is applied to: the target repository the factory works on, or the
/// factory's own repository. A protected group with `applies_to: factory_repo` applies to the
/// second only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RepoKind {
    /// A repository a tenant asked the factory to change.
    Target,
    /// The factory's own repository.
    Factory,
}

/// The sandbox profile a command or tool runs under (`sandbox.profiles`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SandboxProfileKind {
    /// The agent CLI's sandbox: broker only, writable workspace.
    Agent,
    /// The gate runner: read-only workspace, no network, held-out tests.
    Verify,
    /// The dependency fetch: allowlisted registries, scripts disabled.
    FetchDeps,
}

impl SandboxProfileKind {
    /// Every profile.
    pub const ALL: [SandboxProfileKind; 3] = [Self::Agent, Self::Verify, Self::FetchDeps];

    /// The spelling the policy files use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Verify => "verify",
            Self::FetchDeps => "fetch_deps",
        }
    }

    /// Reads the policy spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == text)
    }
}

/// Why an engine could not be built from a pair of documents. No evaluator exists after one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// A glob does not compile in the policy dialect.
    #[error("the glob `{glob}` in {place} does not compile: {message}")]
    Glob {
        /// Where the glob is.
        place: String,
        /// The glob.
        glob: String,
        /// The compiler's message.
        message: String,
    },
    /// A regular expression does not compile.
    #[error("the regular expression in {place} does not compile: {message}")]
    Regex {
        /// Where the expression is.
        place: String,
        /// The compiler's message.
        message: String,
    },
    /// A glob contains a character outside ASCII. The domain crate has no Unicode normalization
    /// tables, so it cannot promise that a composed and a decomposed spelling match. Use `*`.
    #[error(
        "the glob `{glob}` in {place} contains a non-ASCII character; write the part with `*` so that a composed and a decomposed spelling both match"
    )]
    NonAsciiGlob {
        /// Where the glob is.
        place: String,
        /// The glob.
        glob: String,
    },
    /// The document turns off a protection this engine always applies.
    #[error(
        "{key} is {found}, but this engine always applies the rule and will not run with it off"
    )]
    ProtectionDisabled {
        /// The key.
        key: &'static str,
        /// What the document says.
        found: String,
    },
    /// A value the engine does not know how to honour.
    #[error("{key} has the value `{found}`, which this engine does not know")]
    UnknownValue {
        /// The key.
        key: &'static str,
        /// What the document says.
        found: String,
    },
    /// One name is defined twice where it must be unique.
    #[error("{what} `{name}` is defined more than once")]
    Duplicate {
        /// The kind of name.
        what: &'static str,
        /// The name.
        name: String,
    },
    /// The two documents contradict each other.
    #[error("the policy contradicts itself: {0}")]
    Contradiction(String),
}
