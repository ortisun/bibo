//! `schemas/review-verdict.schema.json`: the structured result of one independent review.
//!
//! The reviewer works from the frozen specification, the diff and verified gate evidence. It does
//! not receive the builder's own account of the work. The verdict and the findings must agree.

use serde::{Deserialize, Serialize};

use super::common::{ArtifactRef, BuilderSummaryNotSeen, SchemaVersion};
use super::{Violations, contract};
use crate::ids::{GateReportId, JobId, ReviewId, StageRunId};
use crate::macros::string_enum;
use crate::values::{
    HumanText, HumanTitle, NonEmptyString, NonEmptyVec, PositiveInt, SemanticVersion, Sha256Digest,
    Slug, Timestamp, UnitInterval,
};
use crate::vocabulary::{ExecutionMode, Fidelity, ReviewerRole, Verdict};

string_enum! {
    /// How serious a finding is.
    pub enum Severity("severity") {
        /// Must be fixed before the work can go on.
        Blocker = "blocker",
        /// Serious.
        High = "high",
        /// Worth fixing.
        Medium = "medium",
        /// Minor.
        Low = "low",
        /// For information.
        Info = "info",
    }
}

string_enum! {
    /// What a finding is about.
    pub enum Category("finding category") {
        /// The code is wrong.
        Correctness = "correctness",
        /// Threads or ordering.
        Concurrency = "concurrency",
        /// Security.
        Security = "security",
        /// Speed or memory.
        Performance = "performance",
        /// Hard to change.
        Maintainability = "maintainability",
        /// Breaks users of the code.
        Compatibility = "compatibility",
        /// Tests are missing or weak.
        Tests = "tests",
        /// Does not do what was asked.
        IntentAlignment = "intent_alignment",
        /// Documentation.
        Documentation = "documentation",
        /// Accessibility.
        Accessibility = "accessibility",
        /// Anything else.
        Other = "other",
    }
}

string_enum! {
    /// How to reproduce a finding.
    pub enum ReproductionKind("reproduction kind") {
        /// A command.
        Command = "command",
        /// A test.
        Test = "test",
        /// Steps to follow.
        Steps = "steps",
    }
}

string_enum! {
    /// What the reviewer suggests doing about a finding.
    pub enum NextAction("proposed next action") {
        /// Fix it.
        Fix = "fix",
        /// Add a test.
        AddTest = "add_test",
        /// Clarify the specification.
        ClarifySpecification = "clarify_specification",
        /// Ask a person.
        EscalateToHuman = "escalate_to_human",
        /// Accept the risk.
        AcceptRisk = "accept_risk",
    }
}

string_enum! {
    /// Used to route a `CHANGES_REQUIRED` verdict (`pipeline.defect_routing` in
    /// `state-machine.json`, and [`machines::rework`](crate::machines::rework)).
    ///
    /// `code_behavior` goes to a new run of `IMPLEMENTATION` and `documentation` to `DOCUMENTING`,
    /// as the route of the stage says. `specification` and `policy` are decisions for a person, so
    /// the stage run waits for one, except that the stage that produces the specification reworks
    /// its own artifact. When findings differ, `specification` wins over `policy`, `policy` over
    /// `code_behavior` and `code_behavior` over `documentation`.
    pub enum DefectClass("defect class") {
        /// The code behaves wrongly. Goes back to implementation.
        CodeBehavior = "code_behavior",
        /// The documentation is wrong. Goes back to documenting.
        Documentation = "documentation",
        /// The specification is wrong. A person decides.
        Specification = "specification",
        /// A policy is broken. A person decides.
        Policy = "policy",
    }
}

/// The runtime the reviewer ran on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewerRuntime {
    /// The adapter.
    pub adapter: Slug,
    /// Its version.
    pub adapter_version: NonEmptyString,
    /// The model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<NonEmptyString>,
    /// Real or fake. Production mode needs real.
    pub fidelity: Fidelity,
}

/// Who reviewed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reviewer {
    /// The reviewing agent.
    pub agent_id: Slug,
    /// Its version.
    pub agent_version: SemanticVersion,
    /// What it reviews.
    pub role: ReviewerRole,
    /// What it ran on.
    pub runtime: ReviewerRuntime,
}

/// Ids and the reviewer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewMetadata {
    /// This review.
    pub review_id: ReviewId,
    /// The job.
    pub job_id: JobId,
    /// The stage run.
    pub stage_run_id: StageRunId,
    /// Production or test.
    pub execution_mode: ExecutionMode,
    /// When it was made.
    pub created_at: Timestamp,
    /// Who reviewed.
    pub reviewer: Reviewer,
}

/// A gate report the reviewer was given.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateReportRef {
    /// The report.
    pub gate_report_id: GateReportId,
    /// Its hash.
    pub sha256: Sha256Digest,
}

/// What the engine gave the reviewer. The engine builds this list. The reviewer does not choose it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputsReviewed {
    /// The frozen specification.
    pub frozen_spec_sha256: Sha256Digest,
    /// The diff.
    pub diff_sha256: Sha256Digest,
    /// The verified gate reports.
    pub gate_reports: NonEmptyVec<GateReportRef>,
    /// Other artifacts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_artifacts: Option<Vec<ArtifactRef>>,
    /// Always `false`: the reviewer never sees the builder's own account.
    pub saw_builder_self_assessment: BuilderSummaryNotSeen,
}

/// Where in the code a finding is.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingLocation {
    /// The path.
    pub path: NonEmptyString,
    /// First line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_start: Option<PositiveInt>,
    /// Last line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_end: Option<PositiveInt>,
}

/// How to reproduce a finding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reproduction {
    /// How.
    pub kind: ReproductionKind,
    /// The command, test or steps.
    pub detail: HumanText,
}

/// One thing the reviewer found.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    /// The finding. Machine metadata, never the title.
    pub finding_id: Slug,
    /// How serious.
    pub severity: Severity,
    /// What it is about.
    pub category: Category,
    /// A plain-English title.
    pub title: HumanTitle,
    /// What is wrong and why it matters.
    pub description: HumanText,
    /// Where.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<FindingLocation>,
    /// How to see it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reproduction: Option<Reproduction>,
    /// How sure the reviewer is, from 0 to 1.
    pub confidence: UnitInterval,
    /// What to do about it.
    pub proposed_next_action: NextAction,
    /// Where rework goes.
    pub defect_class: DefectClass,
}

contract! {
    "review-verdict";
    /// The structured result of one independent review.
    #[derive(Debug, Clone, PartialEq, Serialize)]
    pub struct ReviewVerdict {
        /// Always 1.
        pub schema_version: SchemaVersion,
        /// Ids and the reviewer.
        pub metadata: ReviewMetadata,
        /// A plain-English title.
        pub title: HumanTitle,
        /// The verdict.
        pub verdict: Verdict,
        /// A short summary.
        pub summary: HumanText,
        /// What the reviewer was given.
        pub inputs_reviewed: InputsReviewed,
        /// What the reviewer found.
        pub findings: Vec<Finding>,
        /// How sure the reviewer is overall, from 0 to 1.
        pub confidence_overall: UnitInterval,
        /// One focused question. Required when the verdict is `NEEDS_HUMAN`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub human_question: Option<HumanText>,
        /// Risks that remain.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub residual_risks: Option<Vec<HumanText>>,
    }
}

impl ReviewVerdict {
    fn check(&self, found: &mut Violations) {
        let severities = || self.findings.iter().map(|finding| finding.severity);
        match self.verdict {
            Verdict::Pass => {
                for (index, finding) in self.findings.iter().enumerate() {
                    found.require(
                        matches!(finding.severity, Severity::Medium | Severity::Low | Severity::Info),
                        format!("findings[{index}].severity"),
                        "a PASS verdict cannot carry a blocker or a high-severity finding",
                    );
                }
            }
            Verdict::ChangesRequired => found.require(
                severities().any(|s| matches!(s, Severity::Blocker | Severity::High | Severity::Medium)),
                "findings",
                "a CHANGES_REQUIRED verdict needs at least one finding of medium severity or above to explain it",
            ),
            Verdict::Block => found.require(
                severities().any(|s| s == Severity::Blocker),
                "findings",
                "a BLOCK verdict needs at least one blocker finding to explain it",
            ),
            Verdict::NeedsHuman => found.require(
                self.human_question.is_some(),
                "human_question",
                "a NEEDS_HUMAN verdict must carry the one question for the person",
            ),
        }

        // FR-023 and SC-008: a finding of a verdict other than PASS cites a file and a line, so
        // the review gate can check that the line is in the patch. A PASS finding cites them
        // only when it concerns one.
        if self.verdict != Verdict::Pass {
            for (index, finding) in self.findings.iter().enumerate() {
                match &finding.location {
                    None => found.push(
                        format!("findings[{index}].location"),
                        "a finding of a verdict other than PASS cites a file and a line",
                    ),
                    Some(location) => found.require(
                        location.line_start.is_some(),
                        format!("findings[{index}].location.line_start"),
                        "a finding of a verdict other than PASS cites a line",
                    ),
                }
            }
        }

        if self.metadata.execution_mode == ExecutionMode::Production {
            found.require(
                self.metadata.reviewer.runtime.fidelity == Fidelity::Real,
                "metadata.reviewer.runtime.fidelity",
                "a production job cannot use a fake reviewer runtime",
            );
        }
    }
}
