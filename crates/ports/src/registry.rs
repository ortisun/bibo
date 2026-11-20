//! The registry ports: finding agent definitions and checking an agent's output against its
//! schema.
//!
//! Both are pure reads of definitions that were loaded and validated at start-up, so neither is
//! async and neither does I/O at call time.

use factory_domain::contracts::{
    AgentManifest, Contract, DomainCapabilityProfile, DomainEvent, EvidenceLedgerEntry,
    EvidenceManifest, GateReport, ProjectManifest, ReviewVerdict, SpecificationContract,
    StageContract, TaskDag, Violation, agent_manifest::PromptTemplate,
};
use factory_domain::values::{SemanticVersion, Sha256Digest, Slug};
use factory_domain::vocabulary::Fidelity;

/// The identifier of an agent, such as `software-engineer`.
pub type AgentId = Slug;

/// A domain tag a capability profile matches on, such as `rust` or `web-app`.
pub type DomainTag = Slug;

/// Which versions of an agent are acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionReq {
    /// Any version. The highest wins.
    Any,
    /// Exactly this version.
    Exact(SemanticVersion),
    /// Any version with this major number. The highest wins.
    SameMajor(u64),
    /// This version or a higher one. The highest wins.
    AtLeast(SemanticVersion),
}

impl VersionReq {
    /// True when `version` is acceptable.
    #[must_use]
    pub fn matches(&self, version: &SemanticVersion) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(wanted) => version == wanted,
            Self::SameMajor(major) => version.version().major == *major,
            Self::AtLeast(least) => version >= least,
        }
    }
}

/// The kinds of contract document an output can be validated as. Each is a schema in `schemas/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ContractKind {
    /// An agent manifest.
    AgentManifest,
    /// A domain capability profile.
    DomainCapabilityProfile,
    /// A domain event.
    DomainEvent,
    /// An evidence ledger entry.
    EvidenceLedgerEntry,
    /// An evidence manifest.
    EvidenceManifest,
    /// A gate report.
    GateReport,
    /// A project manifest.
    ProjectManifest,
    /// A review verdict.
    ReviewVerdict,
    /// A specification contract.
    SpecificationContract,
    /// A stage contract.
    StageContract,
    /// A task graph.
    TaskDag,
}

impl ContractKind {
    /// Every kind.
    pub const ALL: [ContractKind; 11] = [
        Self::AgentManifest,
        Self::DomainCapabilityProfile,
        Self::DomainEvent,
        Self::EvidenceLedgerEntry,
        Self::EvidenceManifest,
        Self::GateReport,
        Self::ProjectManifest,
        Self::ReviewVerdict,
        Self::SpecificationContract,
        Self::StageContract,
        Self::TaskDag,
    ];

    /// The schema's file stem, such as `gate-report`. It equals `Contract::SCHEMA` of the domain
    /// type, and a test checks that for every kind.
    #[must_use]
    pub const fn schema_name(self) -> &'static str {
        match self {
            Self::AgentManifest => AgentManifest::SCHEMA,
            Self::DomainCapabilityProfile => DomainCapabilityProfile::SCHEMA,
            Self::DomainEvent => DomainEvent::SCHEMA,
            Self::EvidenceLedgerEntry => EvidenceLedgerEntry::SCHEMA,
            Self::EvidenceManifest => EvidenceManifest::SCHEMA,
            Self::GateReport => GateReport::SCHEMA,
            Self::ProjectManifest => ProjectManifest::SCHEMA,
            Self::ReviewVerdict => ReviewVerdict::SCHEMA,
            Self::SpecificationContract => SpecificationContract::SCHEMA,
            Self::StageContract => StageContract::SCHEMA,
            Self::TaskDag => TaskDag::SCHEMA,
        }
    }
}

/// A prompt template and the reference it was loaded for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPrompt {
    /// The reference from the manifest: path, version and hash.
    pub template: PromptTemplate,
    /// The template text. Its SHA-256 equals `template.template_sha256`.
    pub text: String,
}

/// Why a registry lookup failed. The set is closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    /// No agent has this id.
    #[error("no agent has this id")]
    UnknownAgent,
    /// The agent exists but no version satisfies the requirement.
    #[error("no version of the agent satisfies the requirement")]
    NoMatchingVersion,
    /// The prompt file the manifest names is not in the registry.
    #[error("the prompt template named by the manifest was not found")]
    PromptNotFound,
    /// The prompt file's hash differs from the hash in the manifest, so it was changed.
    #[error("the prompt template does not match the hash in its manifest")]
    PromptHashMismatch {
        /// The hash the manifest declares.
        expected: Sha256Digest,
        /// The hash of the text that was found.
        actual: Sha256Digest,
    },
}

/// Finds agent manifests, their prompts and the capability profiles for a set of domain tags.
///
/// # Preconditions
/// The registry was loaded and every definition in it validated against its schema.
///
/// # Postconditions
/// `manifest` returns the highest version that satisfies the requirement. `prompt` returns text
/// whose hash equals the manifest's declared hash: it never returns a prompt that was changed
/// after the manifest was written. `profiles_matching` returns profiles in a stable order and
/// returns an empty list, not an error, when no profile matches.
///
/// # Errors
/// [`RegistryError::UnknownAgent`], [`RegistryError::NoMatchingVersion`],
/// [`RegistryError::PromptNotFound`] and [`RegistryError::PromptHashMismatch`].
///
/// # Idempotency
/// Every method is a read and gives the same answer for the same registry.
///
/// # Cancellation and timeouts
/// Synchronous reads of definitions loaded at start-up. They do no I/O at call time, so there is
/// nothing to cancel and no timeout.
pub trait AgentRegistry: Send + Sync {
    /// Says whether this registry reads the real definition files (`real`) or a fixed in-memory
    /// set (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// The highest version of the agent that satisfies `req`.
    fn manifest(&self, id: &AgentId, req: &VersionReq) -> Result<AgentManifest, RegistryError>;

    /// The prompt template of the manifest, with its hash checked.
    fn prompt(&self, manifest: &AgentManifest) -> Result<LoadedPrompt, RegistryError>;

    /// The capability profiles that match any of the tags.
    fn profiles_matching(
        &self,
        tags: &[DomainTag],
    ) -> Result<Vec<DomainCapabilityProfile>, RegistryError>;
}

/// A document that passed the strict path.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedOutput {
    /// The parsed document.
    pub value: serde_json::Value,
    /// The SHA-256 of the exact bytes that were validated. The artifact that stores them has this
    /// hash.
    pub sha256: Sha256Digest,
    /// The size of the bytes.
    pub size_bytes: u64,
}

/// Checks a JSON document against the schema of a contract kind.
///
/// # Preconditions
/// None. The bytes are untrusted agent output.
///
/// # Postconditions
/// `validate_bytes` refuses, before any parser builds a value: a body over the size limit, bytes
/// that are not UTF-8, nesting deeper than the limit, a node count over the budget, and an object
/// that repeats a key. If it returns `Ok`, the document follows the schema of that kind and
/// version and `value` is the parse of exactly those bytes. On failure the list holds every
/// violation found, each with a path and a plain-English message, and never repeats a large part
/// of the input. `validate_value` is for values the factory built itself and applies the same
/// schema; it cannot see a repeated key because the value no longer has one.
///
/// # Errors
/// A non-empty list of [`Violation`]s. An unknown schema version is a violation.
///
/// # Idempotency
/// Pure: the same input gives the same result.
///
/// # Cancellation and timeouts
/// Pure and synchronous. The size, depth and node limits bound the work, so there is nothing to
/// cancel and no timeout.
pub trait OutputValidator: Send + Sync {
    /// The only path for agent output and for anything read from a file or the network.
    fn validate_bytes(
        &self,
        kind: ContractKind,
        version: u32,
        bytes: &[u8],
    ) -> Result<ValidatedOutput, Vec<Violation>>;

    /// For values the factory built itself.
    fn validate_value(
        &self,
        kind: ContractKind,
        version: u32,
        instance: &serde_json::Value,
    ) -> Result<(), Vec<Violation>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> SemanticVersion {
        SemanticVersion::parse(text).unwrap()
    }

    #[test]
    fn version_requirements_select_the_right_versions() {
        assert!(VersionReq::Any.matches(&v("0.1.0")));
        assert!(VersionReq::Exact(v("1.2.3")).matches(&v("1.2.3")));
        assert!(!VersionReq::Exact(v("1.2.3")).matches(&v("1.2.4")));
        assert!(VersionReq::SameMajor(1).matches(&v("1.9.0")));
        assert!(!VersionReq::SameMajor(1).matches(&v("2.0.0")));
        assert!(VersionReq::AtLeast(v("1.2.0")).matches(&v("1.2.0")));
        assert!(VersionReq::AtLeast(v("1.2.0")).matches(&v("3.0.0")));
        assert!(!VersionReq::AtLeast(v("1.2.0")).matches(&v("1.1.9")));
    }

    #[test]
    fn every_contract_kind_names_its_schema_file() {
        let names: Vec<&str> = ContractKind::ALL.iter().map(|k| k.schema_name()).collect();
        assert_eq!(names.len(), 11);
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 11, "two kinds share a schema: {names:?}");
        assert!(names.contains(&"gate-report"));
        assert!(names.contains(&"specification-contract"));
    }
}
