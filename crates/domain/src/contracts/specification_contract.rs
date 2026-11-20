//! `schemas/specification-contract.schema.json`: the typed form of an approved Spec Kit
//! specification.
//!
//! The original Spec Kit files stay the canonical text. This contract points to them by content
//! hash and adds the structure that later stages need. Once the status is `approved` the contract
//! is frozen: a change makes a new specification version.

use serde::{Deserialize, Serialize};
use serde_json::Number;

use super::common::{NeedsClarification, RequirementId, ScenarioId, SchemaVersion};
use super::{Violations, contract};
use crate::ids::{JobId, PrincipalId, SpecId};
use crate::macros::{patterned_string, string_enum};
use crate::patterns;
use crate::values::{
    GitSha, HumanText, HumanTitle, NonEmptyString, NonEmptyVec, PositiveInt, Sha256Digest, Slug,
    Timestamp, UniqueVec,
};
use crate::vocabulary::{ExecutionMode, Fidelity};

patterned_string! {
    /// A non-functional requirement (`NFR-001`) or a Spec Kit success criterion (`SC-001`).
    pub struct NonFunctionalId("non-functional requirement id") = patterns::NONFUNCTIONAL_ID,
        "use NFR- or SC- followed by at least three digits, for example NFR-001"
}

patterned_string! {
    /// A risk id such as `RISK-001`.
    pub struct RiskId("risk id") = patterns::RISK_ID,
        "use RISK- followed by at least three digits, for example RISK-001"
}

patterned_string! {
    /// An open question id such as `Q-001`.
    pub struct QuestionId("question id") = patterns::QUESTION_ID,
        "use Q- followed by at least three digits, for example Q-001"
}

patterned_string! {
    /// A constraint id such as `C-001`.
    pub struct ConstraintId("constraint id") = patterns::CONSTRAINT_ID,
        "use C- followed by at least three digits, for example C-001"
}

patterned_string! {
    /// A language tag such as `en` or `pt-BR`.
    pub struct LanguageTag("language tag") = patterns::LANGUAGE,
        "use a language code such as en or pt-BR"
}

patterned_string! {
    /// A repository-relative Spec Kit feature directory such as `specs/001-json-flag`. The factory
    /// chooses the name and sets it explicitly. It is never inferred from the git branch.
    pub struct FeatureDirectory("feature directory") = patterns::FEATURE_DIRECTORY,
        "use `specs/` followed by a lowercase name, for example specs/001-json-flag"
}

string_enum! {
    /// Where a specification stands.
    pub enum SpecStatus("specification status") {
        /// Still being written.
        Draft = "draft",
        /// Frozen. Later stages build on it.
        Approved = "approved",
        /// Replaced by a newer version.
        Superseded = "superseded",
    }
}

string_enum! {
    /// Who approved a specification.
    pub enum SpecApproverRole("approver role") {
        /// An approver.
        Approver = "approver",
        /// An operator.
        Operator = "operator",
        /// The policy engine, for low-risk work with a passing gate.
        PolicyEngine = "policy_engine",
    }
}

string_enum! {
    /// Why an approval counts.
    pub enum ApprovalBasis("approval basis") {
        /// A person decided.
        HumanDecision = "human_decision",
        /// Policy allowed it for low-risk work and the gate passed.
        LowRiskPolicyWithPassingGate = "low_risk_policy_with_passing_gate",
    }
}

string_enum! {
    /// The priority Spec Kit gives a user story.
    pub enum Priority("priority") {
        /// Most important.
        P1 = "P1",
        /// Important.
        P2 = "P2",
        /// Useful.
        P3 = "P3",
    }
}

string_enum! {
    /// Likelihood or impact of a risk.
    pub enum Level("level") {
        /// Low.
        Low = "low",
        /// Medium.
        Medium = "medium",
        /// High.
        High = "high",
    }
}

string_enum! {
    /// Where an open question stands.
    pub enum QuestionStatus("question status") {
        /// Not answered.
        Open = "open",
        /// Answered.
        Answered = "answered",
        /// Put off on purpose.
        Deferred = "deferred",
    }
}

string_enum! {
    /// What kind of constraint it is.
    pub enum ConstraintKind("constraint kind") {
        /// A technical limit.
        Technical = "technical",
        /// A legal limit.
        Legal = "legal",
        /// A safety limit.
        Safety = "safety",
        /// A platform limit.
        Platform = "platform",
        /// A business limit.
        Business = "business",
    }
}

string_enum! {
    /// The only Spec Kit skills the factory may invoke.
    pub enum SpecToolSkill("Spec Kit skill") {
        /// Project principles.
        Constitution = "constitution",
        /// The specification.
        Specify = "specify",
        /// Clarifying questions.
        Clarify = "clarify",
        /// Quality checklists.
        Checklist = "checklist",
    }
}

string_enum! {
    /// What a recorded Spec Kit file is.
    pub enum SpecArtifactRole("specification artifact role") {
        /// The specification itself.
        Specification = "specification",
        /// The requirements checklist.
        RequirementsChecklist = "requirements_checklist",
        /// A custom checklist.
        CustomChecklist = "custom_checklist",
        /// The constitution.
        Constitution = "constitution",
        /// The clarification log.
        ClarificationLog = "clarification_log",
    }
}

string_enum! {
    /// How a new specification version was made.
    pub enum RevisionMethod("revision method") {
        /// A new feature directory. The proposed method, pending a spike (ADR 0006).
        NewFeatureDirectory = "new_feature_directory",
        /// The clarify skill, in place.
        ClarifyInPlace = "clarify_in_place",
        /// A person edited the file.
        HumanEdit = "human_edit",
    }
}

/// Who approved the specification and why.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    /// Who.
    pub principal_id: PrincipalId,
    /// In which role.
    pub role: SpecApproverRole,
    /// On what basis.
    pub basis: ApprovalBasis,
}

/// Ids, version, status and approval.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecMetadata {
    /// This specification.
    pub spec_id: SpecId,
    /// Its version, from 1.
    pub spec_version: PositiveInt,
    /// The version it replaces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes_spec_version: Option<PositiveInt>,
    /// Draft, approved or superseded.
    pub status: SpecStatus,
    /// The job.
    pub job_id: JobId,
    /// Production or test.
    pub execution_mode: ExecutionMode,
    /// The repository commit the specification was written against.
    pub commit_sha: GitSha,
    /// When it was made.
    pub created_at: Timestamp,
    /// When it was approved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<Timestamp>,
    /// Who approved it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<Approval>,
}

/// A functional requirement.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    /// The id as Spec Kit wrote it.
    pub id: RequirementId,
    /// What the system must do.
    pub statement: HumanText,
    /// The priority of the user story it belongs to.
    pub priority: Priority,
    /// The user story, as Spec Kit names it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_story_ref: Option<NonEmptyString>,
    /// The scenarios that show it works.
    pub acceptance_scenario_ids: UniqueVec<ScenarioId, 1>,
}

/// A Given-When-Then acceptance scenario.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceScenario {
    /// The id.
    pub id: ScenarioId,
    /// The user story, as Spec Kit names it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_story_ref: Option<NonEmptyString>,
    /// The starting situation.
    pub given: HumanText,
    /// The action.
    pub when: HumanText,
    /// The expected result.
    pub then: HumanText,
    /// The requirements it covers.
    pub requirement_ids: UniqueVec<RequirementId, 1>,
}

/// A measurable target.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metric {
    /// What is measured.
    pub name: NonEmptyString,
    /// The target, kept exactly as written.
    pub target: Number,
    /// The unit.
    pub unit: NonEmptyString,
}

/// A non-functional requirement or a success criterion.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonFunctionalRequirement {
    /// The id.
    pub id: NonFunctionalId,
    /// What is required.
    pub statement: HumanText,
    /// A target that can be measured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metric: Option<Metric>,
}

/// A risk the specification names.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecRisk {
    /// The id.
    pub id: RiskId,
    /// What could go wrong.
    pub description: HumanText,
    /// How likely.
    pub likelihood: Level,
    /// How bad.
    pub impact: Level,
    /// What reduces it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigation: Option<HumanText>,
}

/// A question that the specification leaves open or has answered.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenQuestion {
    /// The id.
    pub id: QuestionId,
    /// The question.
    pub question: HumanText,
    /// Whether the work must wait for the answer.
    pub blocking: bool,
    /// Where it stands.
    pub status: QuestionStatus,
    /// The answer, once there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answer: Option<HumanText>,
    /// Present when the question came from a Spec Kit clarification marker.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_marker: Option<NeedsClarification>,
}

/// A constraint on the solution.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constraint {
    /// The id.
    pub id: ConstraintId,
    /// What kind.
    pub kind: ConstraintKind,
    /// What it says.
    pub description: HumanText,
}

/// Which Spec Kit produced the files.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecToolInfo {
    /// The value of `speckit_version` in `.specify/init-options.json`.
    pub cli_version: NonEmptyString,
    /// The integration used.
    pub integration: NonEmptyString,
    /// Only the four allowed skills may appear.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skills_invoked: Option<Vec<SpecToolSkill>>,
}

/// The runtime that ran Spec Kit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRuntime {
    /// The adapter.
    pub adapter: Slug,
    /// Its version.
    pub adapter_version: NonEmptyString,
    /// Real or fake. Production mode needs real.
    pub fidelity: Fidelity,
}

/// An original Spec Kit file recorded by hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecArtifact {
    /// What the file is.
    pub role: SpecArtifactRole,
    /// The repository-relative path.
    pub path: NonEmptyString,
    /// The content hash.
    pub sha256: Sha256Digest,
}

/// The original request, stored apart because it is untrusted.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRequest {
    /// Its hash.
    pub sha256: Sha256Digest,
    /// Its language.
    pub language: LanguageTag,
}

/// How a new version relates to the one before.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    /// How the new version was made.
    pub method: RevisionMethod,
    /// The version it was made from.
    pub basis_spec_version: PositiveInt,
}

/// Where the specification came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecProvenance {
    /// Spec Kit.
    pub spec_kit: SpecToolInfo,
    /// The runtime.
    pub host_runtime: HostRuntime,
    /// The original files. One of them is the specification.
    pub artifacts: NonEmptyVec<SpecArtifact>,
    /// The request.
    pub source_request: SourceRequest,
    /// The feature directory. Required for a revision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature_directory: Option<FeatureDirectory>,
    /// The link to the version this one replaces. Required for a revision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<Revision>,
}

contract! {
    "specification-contract";
    /// The typed form of an approved feature specification.
    #[derive(Debug, Clone, PartialEq, Serialize)]
    pub struct SpecificationContract {
        /// Always 1.
        pub schema_version: SchemaVersion,
        /// Ids, version, status and approval.
        pub metadata: SpecMetadata,
        /// The feature in a few words.
        pub title: HumanTitle,
        /// A short summary.
        pub summary: HumanText,
        /// What the system must do.
        pub requirements: NonEmptyVec<Requirement>,
        /// How to tell it does.
        pub acceptance_scenarios: NonEmptyVec<AcceptanceScenario>,
        /// Quality targets.
        pub nonfunctional_requirements: Vec<NonFunctionalRequirement>,
        /// What could go wrong.
        pub risks: Vec<SpecRisk>,
        /// Questions still open or answered.
        pub open_questions: Vec<OpenQuestion>,
        /// Limits on the solution.
        pub constraints: Vec<Constraint>,
        /// What this feature does not cover.
        pub out_of_scope: Vec<HumanText>,
        /// Where it came from.
        pub provenance: SpecProvenance,
    }
}

impl SpecificationContract {
    fn check(&self, found: &mut Violations) {
        let metadata = &self.metadata;
        match metadata.status {
            SpecStatus::Approved => {
                found.require(
                    metadata.approved_at.is_some(),
                    "metadata.approved_at",
                    "an approved specification must say when it was approved",
                );
                found.require(
                    metadata.approved_by.is_some(),
                    "metadata.approved_by",
                    "an approved specification must say who approved it",
                );
                for (index, question) in self.open_questions.iter().enumerate() {
                    found.require(
                        !(question.blocking && question.status == QuestionStatus::Open),
                        format!("open_questions[{index}]"),
                        "an approved specification cannot have a blocking question that is still open",
                    );
                }
            }
            SpecStatus::Superseded => found.require(
                metadata.approved_at.is_some(),
                "metadata.approved_at",
                "a superseded specification was approved once, so it must say when",
            ),
            SpecStatus::Draft => {}
        }

        if metadata.execution_mode == ExecutionMode::Production {
            found.require(
                self.provenance.host_runtime.fidelity == Fidelity::Real,
                "provenance.host_runtime.fidelity",
                "a production job cannot use a fake runtime",
            );
        }

        if metadata.supersedes_spec_version.is_some() {
            found.require(
                self.provenance.feature_directory.is_some(),
                "provenance.feature_directory",
                "a revision must record the feature directory it was written in",
            );
            found.require(
                self.provenance.revision.is_some(),
                "provenance.revision",
                "a revision must record how it was made and which version it was made from",
            );
        }

        found.require(
            self.provenance
                .artifacts
                .iter()
                .any(|artifact| artifact.role == SpecArtifactRole::Specification),
            "provenance.artifacts",
            "the original Spec Kit specification file must be among the recorded artifacts",
        );
    }
}
