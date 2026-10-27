//! `schemas/evidence-manifest.schema.json`: the summary attached to a draft pull request.
//!
//! It lists, by content hash, the specification, plan, change, gate reports, reviews and
//! documentation checks behind the pull request, the head of the evidence ledger, the assurance
//! levels attained, and the ones that were not. It must always state its limitations. A manifest
//! never hides that something was not verified, and in production mode every adapter that took
//! part must have been real.

use serde::{Deserialize, Serialize};

use super::common::{PassVerdict, SchemaVersion};
use super::{Violations, contract};
use crate::ids::{JobId, LedgerEntryId, ManifestId, PlanId, SpecId, TenantId};
use crate::macros::{patterned_string, string_enum};
use crate::patterns;
use crate::values::{
    Bounded, GitSha, HumanText, HumanTitle, NonEmptyString, NonEmptyVec, NonNegativeInt,
    PositiveInt, Sha256Digest, Slug, Timestamp, UniqueVec,
};
use crate::vocabulary::{AssuranceLevel, ExecutionMode, Fidelity, ReviewerRole, RiskTier};

patterned_string! {
    /// A repository name in `owner/name` form.
    pub struct RepositoryName("repository name") = patterns::REPOSITORY_FULL_NAME,
        "use owner/name with letters, digits, dots, underscores and hyphens"
}

string_enum! {
    /// The outcome of a gate as it appears in a delivered manifest. A `FAILED` gate cannot appear:
    /// delivery happens only after rework cleared it.
    pub enum DeliveredGateOutcome("delivered gate outcome") {
        /// The gate passed.
        Passed = "PASSED",
        /// The gate does not apply.
        NotApplicable = "NOT_APPLICABLE",
        /// The gate could not run, and a person recorded a decision about it.
        Blocked = "BLOCKED",
    }
}

string_enum! {
    /// What kind of adapter took part in the job.
    pub enum AdapterKind("adapter kind") {
        /// An agent runtime.
        AgentRuntime = "agent_runtime",
        /// A sandbox provider.
        Sandbox = "sandbox",
        /// A change host such as GitHub.
        ChangeHost = "change_host",
        /// An artifact store.
        ArtifactStore = "artifact_store",
        /// The transactional store.
        Store = "store",
        /// A specification provider.
        SpecificationProvider = "specification_provider",
    }
}

string_enum! {
    /// A role whose approval the pull request still needs.
    pub enum RequiredApproval("required approval") {
        /// An approver.
        Approver = "approver",
        /// A security approver.
        SecurityApprover = "security_approver",
        /// An organization administrator.
        OrgAdmin = "org_admin",
    }
}

/// The repository and the commits the pull request spans.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryRef {
    /// The repository.
    pub full_name: RepositoryName,
    /// The commit the work started from.
    pub base_commit: GitSha,
    /// The commit the pull request ends at.
    pub head_commit: GitSha,
}

/// Ids and mode.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestMetadata {
    /// This manifest.
    pub manifest_id: ManifestId,
    /// The job.
    pub job_id: JobId,
    /// The tenant.
    pub tenant_id: TenantId,
    /// When it was made.
    pub generated_at: Timestamp,
    /// Production or test.
    pub execution_mode: ExecutionMode,
    /// The repository.
    pub repository: RepositoryRef,
}

/// The head of the evidence ledger and when the chain was last checked.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerHead {
    /// How many entries the job has.
    pub entry_count: PositiveInt,
    /// The sequence of the last entry.
    pub head_sequence: PositiveInt,
    /// The hash of the last entry.
    pub head_hash: Sha256Digest,
    /// When the whole chain was last verified.
    pub chain_verified_at: Timestamp,
}

/// The specification the work is based on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecificationRef {
    /// The specification.
    pub spec_id: SpecId,
    /// Its version.
    pub spec_version: PositiveInt,
    /// Its hash.
    pub sha256: Sha256Digest,
}

/// A document identified by hash alone.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashRef {
    /// The hash.
    pub sha256: Sha256Digest,
}

/// The task plan.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanRef {
    /// The plan.
    pub plan_id: PlanId,
    /// Its version.
    pub plan_version: PositiveInt,
    /// Its hash.
    pub sha256: Sha256Digest,
}

/// The size of the change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummary {
    /// The hash of the diff.
    pub diff_sha256: Sha256Digest,
    /// Files changed.
    pub files_changed: NonNegativeInt,
    /// Lines added.
    pub insertions: NonNegativeInt,
    /// Lines removed.
    pub deletions: NonNegativeInt,
}

/// A gate report in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateEntry {
    /// The gate.
    pub gate_id: Slug,
    /// The outcome.
    pub outcome: DeliveredGateOutcome,
    /// The report's hash.
    pub sha256: Sha256Digest,
    /// For a `BLOCKED` gate, the ledger entry that records the human decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disposition_ledger_entry_id: Option<LedgerEntryId>,
}

/// A review that passed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewEntry {
    /// What the reviewer looked at.
    pub role: ReviewerRole,
    /// Always `PASS`: a review that did not pass blocks delivery.
    pub verdict: PassVerdict,
    /// The verdict document's hash.
    pub sha256: Sha256Digest,
}

/// The documentation checks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationRefs {
    /// The documentation plan.
    pub plan_sha256: Sha256Digest,
    /// The documentation gate report.
    pub gate_report_sha256: Sha256Digest,
    /// The documentation review.
    pub review_sha256: Sha256Digest,
}

/// An assurance level that was reached, and the ledger entry that shows it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attained {
    /// The level.
    pub level: AssuranceLevel,
    /// The ledger entry that supports it.
    pub ledger_entry_id: LedgerEntryId,
}

/// An assurance level that was not reached, and why.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotAttained {
    /// The level.
    pub level: AssuranceLevel,
    /// Why not.
    pub reason: HumanText,
}

/// Which assurance levels were reached and which were not.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assurance {
    /// Reached.
    pub attained: UniqueVec<Attained>,
    /// Not reached.
    pub not_attained: Vec<NotAttained>,
}

/// An adapter that took part in the job.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterUse {
    /// The adapter.
    pub name: Slug,
    /// What kind.
    pub kind: AdapterKind,
    /// Real or fake. Production mode needs real.
    pub fidelity: Fidelity,
    /// Its version.
    pub version: NonEmptyString,
}

/// The risk of the change.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestRisk {
    /// The tier.
    pub tier: RiskTier,
    /// A score from 0 to 100.
    pub score: Bounded<0, 100>,
    /// Why.
    pub rationale: HumanText,
}

contract! {
    "evidence-manifest";
    /// The summary that the delivery stage attaches to a draft pull request.
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
    pub struct EvidenceManifest {
        /// Always 1.
        pub schema_version: SchemaVersion,
        /// Ids and mode.
        pub metadata: ManifestMetadata,
        /// A plain-English title.
        pub title: HumanTitle,
        /// A short summary.
        pub summary: HumanText,
        /// The head of the evidence ledger.
        pub ledger: LedgerHead,
        /// The specification.
        pub specification: SpecificationRef,
        /// The architecture.
        pub architecture: HashRef,
        /// The plan.
        pub plan: PlanRef,
        /// The change.
        pub change: ChangeSummary,
        /// The gate reports.
        pub gate_reports: NonEmptyVec<GateEntry>,
        /// The reviews, all passed.
        pub reviews: NonEmptyVec<ReviewEntry>,
        /// The documentation checks.
        pub documentation: DocumentationRefs,
        /// What was verified and what was not.
        pub assurance: Assurance,
        /// The adapters that took part.
        pub adapters: NonEmptyVec<AdapterUse>,
        /// The risk.
        pub risk: ManifestRisk,
        /// The approvals still needed.
        pub approvals_required: UniqueVec<RequiredApproval, 1>,
        /// What was not verified, mocked, skipped or left to a human. Never empty.
        pub limitations: NonEmptyVec<HumanText>,
    }
}

impl EvidenceManifest {
    fn check(&self, found: &mut Violations) {
        for (index, gate) in self.gate_reports.iter().enumerate() {
            if gate.outcome == DeliveredGateOutcome::Blocked {
                found.require(
                    gate.disposition_ledger_entry_id.is_some(),
                    format!("gate_reports[{index}].disposition_ledger_entry_id"),
                    "a BLOCKED gate must point to the ledger entry that records the human decision about it",
                );
            }
        }

        if self.metadata.execution_mode == ExecutionMode::Production {
            for (index, adapter) in self.adapters.iter().enumerate() {
                found.require(
                    adapter.fidelity == Fidelity::Real,
                    format!("adapters[{index}].fidelity"),
                    "a production job cannot list a fake adapter",
                );
            }
        }

        // The schema description says PRODUCTION_READY must appear in exactly one of the two
        // lists, but its `anyOf` also accepts both. Saying a level is both reached and not
        // reached is nonsense, so this check follows the description.
        let attained = self
            .assurance
            .attained
            .iter()
            .any(|entry| entry.level == AssuranceLevel::ProductionReady);
        let not_attained = self
            .assurance
            .not_attained
            .iter()
            .any(|entry| entry.level == AssuranceLevel::ProductionReady);
        found.require(
            attained != not_attained,
            "assurance",
            "PRODUCTION_READY must appear in exactly one of `attained` and `not_attained`, so the manifest always says whether it was reached",
        );
    }
}
