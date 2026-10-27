//! `schemas/evidence-ledger-entry.schema.json`: one append-only claim bound to its evidence.
//!
//! Entries form a hash chain per job. The chain hash is computed in [`crate::ledger`].

use serde::{Deserialize, Serialize};

use super::common::{SchemaVersion, required_nullable};
use super::{Violations, contract};
use crate::ids::{
    AttemptId, ExperimentRunId, GateReportId, JobId, LedgerEntryId, PrincipalId, StageRunId,
};
use crate::macros::string_enum;
use crate::values::{
    ExactInteger, ExactPositiveInt, GitSha, HumanText, MediaType, NonEmptyString, NonEmptyVec,
    Sha256Digest, Slug, SpanId, Timestamp, TraceId, UniqueVec, Uri,
};
use crate::vocabulary::{
    AssuranceLevel, ConfidenceLevel, ExecutionMode, HumanRole, RecorderFidelity,
};

string_enum! {
    /// What sort of claim an entry makes.
    pub enum ClaimKind("claim kind") {
        /// Something that was measured.
        MeasuredFact = "measured_fact",
        /// The result of a simulation.
        SimulationResult = "simulation_result",
        /// Something taken as true without proof.
        Assumption = "assumption",
        /// Something believed and not yet tested.
        Hypothesis = "hypothesis",
        /// A named person's judgment.
        ExpertJudgment = "expert_judgment",
    }
}

string_enum! {
    /// The result of a test cited as evidence.
    pub enum TestResult("test result") {
        /// The test passed.
        Passed = "passed",
        /// The test failed.
        Failed = "failed",
        /// The test did not run.
        NotRun = "not_run",
    }
}

string_enum! {
    /// The kinds of evidence, by their `type` tag.
    pub enum EvidenceKind("evidence type") {
        /// A gate report.
        Test = "test",
        /// A trace.
        Trace = "trace",
        /// A stored artifact.
        Artifact = "artifact",
        /// A cited source.
        Source = "source",
        /// A benchmark result.
        Benchmark = "benchmark",
        /// An experiment.
        Experiment = "experiment",
        /// A place in the code.
        CodeLocation = "code_location",
        /// A named expert's judgment.
        ExpertJudgment = "expert_judgment",
    }
}

/// A test result from a gate report.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestEvidence {
    /// The gate report the test belongs to.
    pub gate_report_id: GateReportId,
    /// The hash of that gate report.
    pub gate_report_sha256: Sha256Digest,
    /// The test, when one test is meant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_name: Option<NonEmptyString>,
    /// What happened.
    pub result: TestResult,
}

/// An OpenTelemetry trace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceEvidence {
    /// The trace.
    pub trace_id: TraceId,
    /// The span within it, when one span is meant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<SpanId>,
}

/// A stored artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEvidence {
    /// The content hash.
    pub sha256: Sha256Digest,
    /// What kind of bytes it is.
    pub media_type: MediaType,
    /// What it shows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<HumanText>,
}

/// A cited source such as a document or a web page.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceEvidence {
    /// The citation, in plain English.
    pub citation: HumanText,
    /// Where it was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Uri>,
    /// The version that was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<NonEmptyString>,
    /// When it was read.
    pub retrieved_at: Timestamp,
    /// The hash of what was read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Sha256Digest>,
}

/// A benchmark result.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkEvidence {
    /// The benchmark.
    pub name: NonEmptyString,
    /// The value with its unit, kept as text so no precision is lost.
    pub result: NonEmptyString,
    /// Where and how it ran.
    pub environment: HumanText,
}

/// An experiment and its runs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentEvidence {
    /// The experiment.
    pub experiment_id: Slug,
    /// Its runs.
    pub run_ids: NonEmptyVec<ExperimentRunId>,
    /// The random seeds, so the runs can be repeated. Each is a whole number from -(2^53 - 1) to
    /// 2^53 - 1, because the entry hash is taken over RFC 8785 canonical JSON, which would round
    /// a larger one (ADR 0011). A larger seed belongs in the experiment's own stored artifact.
    pub seeds: NonEmptyVec<ExactInteger>,
}

/// A place in the code at a commit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeLocationEvidence {
    /// The repository-relative path.
    pub path: NonEmptyString,
    /// First line, from 1 to 2^53 - 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_start: Option<ExactPositiveInt>,
    /// Last line, from 1 to 2^53 - 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_end: Option<ExactPositiveInt>,
    /// The commit the path and lines refer to.
    pub commit_sha: GitSha,
}

/// The person who stands behind an expert judgment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestor {
    /// Who.
    pub principal_id: PrincipalId,
    /// In which role.
    pub role: HumanRole,
}

/// A named expert's judgment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpertJudgmentEvidence {
    /// Who stands behind it.
    pub attestor: Attestor,
    /// What the judgment covers.
    pub scope: HumanText,
    /// When it was given.
    pub recorded_at: Timestamp,
}

/// One piece of evidence. The `type` field says which kind.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Evidence {
    /// A test result.
    Test(TestEvidence),
    /// A trace.
    Trace(TraceEvidence),
    /// A stored artifact.
    Artifact(ArtifactEvidence),
    /// A cited source.
    Source(SourceEvidence),
    /// A benchmark.
    Benchmark(BenchmarkEvidence),
    /// An experiment.
    Experiment(ExperimentEvidence),
    /// A place in the code.
    CodeLocation(CodeLocationEvidence),
    /// A named expert's judgment.
    ExpertJudgment(ExpertJudgmentEvidence),
}

impl Evidence {
    /// Which kind of evidence this is.
    #[must_use]
    pub const fn kind(&self) -> EvidenceKind {
        match self {
            Evidence::Test(_) => EvidenceKind::Test,
            Evidence::Trace(_) => EvidenceKind::Trace,
            Evidence::Artifact(_) => EvidenceKind::Artifact,
            Evidence::Source(_) => EvidenceKind::Source,
            Evidence::Benchmark(_) => EvidenceKind::Benchmark,
            Evidence::Experiment(_) => EvidenceKind::Experiment,
            Evidence::CodeLocation(_) => EvidenceKind::CodeLocation,
            Evidence::ExpertJudgment(_) => EvidenceKind::ExpertJudgment,
        }
    }
}

/// Who wrote the entry and how real that component was.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recorder {
    /// The factory component, for example `workflow.gate-evaluator`.
    pub component: Slug,
    /// Real, simulated or fake.
    pub fidelity: RecorderFidelity,
}

/// Where the entry sits in the job and who wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerMetadata {
    /// This entry.
    pub entry_id: LedgerEntryId,
    /// The job the chain belongs to.
    pub job_id: JobId,
    /// The stage run that produced the claim.
    pub stage_run_id: StageRunId,
    /// The attempt, when one is meant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<AttemptId>,
    /// Position in the job's chain, from 1 with no gaps, up to 2^53 - 1.
    pub sequence: ExactPositiveInt,
    /// When it was recorded.
    pub recorded_at: Timestamp,
    /// Production or test.
    pub execution_mode: ExecutionMode,
    /// Who wrote it.
    pub recorded_by: Recorder,
}

/// The claim itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    /// What is claimed, in plain English.
    pub statement: HumanText,
    /// Fact, simulation, assumption, hypothesis or judgment.
    pub kind: ClaimKind,
    /// The assurance level this claim supports, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assurance_level: Option<AssuranceLevel>,
}

/// How sure the writer is, and why.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confidence {
    /// Low, medium or high.
    pub level: ConfidenceLevel,
    /// Why.
    pub rationale: HumanText,
}

contract! {
    "evidence-ledger-entry";
    /// One append-only record that binds a claim to the evidence behind it.
    ///
    /// The entry hash is checked by [`crate::ledger`], not here: the examples in `schemas/examples`
    /// carry made-up hashes, and the hash of an entry says nothing about whether its fields are
    /// valid.
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
    pub struct EvidenceLedgerEntry {
        /// Always 1.
        pub schema_version: SchemaVersion,
        /// Position, time, producer and mode.
        pub metadata: LedgerMetadata,
        /// The claim.
        pub claim: Claim,
        /// What backs it.
        pub evidence: Vec<Evidence>,
        /// How sure the writer is.
        pub confidence: Confidence,
        /// Earlier entries this one withdraws.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub invalidates: Option<UniqueVec<LedgerEntryId>>,
        /// The hash of the previous entry. `null` only for sequence 1.
        #[serde(deserialize_with = "required_nullable")]
        pub prev_entry_hash: Option<Sha256Digest>,
        /// The hash of this entry (see [`crate::ledger`]).
        pub entry_hash: Sha256Digest,
    }
}

impl EvidenceLedgerEntry {
    fn check(&self, found: &mut Violations) {
        let is_first = self.metadata.sequence.get() == 1;
        match (&self.prev_entry_hash, is_first) {
            (Some(_), true) => found.push(
                "prev_entry_hash",
                "the first entry of a job (sequence 1) has no previous entry, so this must be null",
            ),
            (None, false) => found.push(
                "prev_entry_hash",
                "every entry after the first must carry the hash of the entry before it",
            ),
            _ => {}
        }

        let has_assurance_level = self.claim.assurance_level.is_some();
        match self.claim.kind {
            ClaimKind::MeasuredFact => {
                found.require(
                    !self.evidence.is_empty(),
                    "evidence",
                    "a measured fact needs at least one piece of evidence",
                );
                for (index, item) in self.evidence.iter().enumerate() {
                    let supports = !matches!(
                        item.kind(),
                        EvidenceKind::Experiment | EvidenceKind::ExpertJudgment
                    );
                    found.require(
                        supports,
                        format!("evidence[{index}].type"),
                        "a measured fact must rest on a test, trace, artifact, benchmark, code location or source, not on an experiment or an opinion",
                    );
                }
            }
            ClaimKind::SimulationResult => found.require(
                self.evidence.iter().any(|item| {
                    matches!(
                        item.kind(),
                        EvidenceKind::Artifact | EvidenceKind::Experiment | EvidenceKind::Benchmark
                    )
                }),
                "evidence",
                "a simulation result needs an artifact, an experiment or a benchmark as evidence",
            ),
            ClaimKind::ExpertJudgment => found.require(
                self.evidence
                    .iter()
                    .any(|item| item.kind() == EvidenceKind::ExpertJudgment),
                "evidence",
                "an expert judgment needs a named attestor as evidence",
            ),
            ClaimKind::Assumption | ClaimKind::Hypothesis => found.require(
                !has_assurance_level,
                "claim.assurance_level",
                "an assumption or a hypothesis cannot support an assurance level",
            ),
        }

        if has_assurance_level {
            found.require(
                !self.evidence.is_empty(),
                "evidence",
                "a claim that supports an assurance level needs at least one piece of evidence",
            );
            found.require(
                self.metadata.recorded_by.fidelity == RecorderFidelity::Real,
                "metadata.recorded_by.fidelity",
                "only a real component can record a claim that supports an assurance level",
            );
        }

        if self.metadata.recorded_by.fidelity != RecorderFidelity::Real {
            found.require(
                self.metadata.execution_mode == ExecutionMode::Test,
                "metadata.execution_mode",
                "a fake or simulated component may record evidence only when the job runs in test mode",
            );
            found.require(
                !has_assurance_level,
                "claim.assurance_level",
                "evidence from a fake or simulated component never supports an assurance level",
            );
        }
    }
}
