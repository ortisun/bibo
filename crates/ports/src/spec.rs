//! The specification port: the anti-corruption boundary around GitHub Spec Kit (ADR 0006).
//!
//! Spec Kit is used for the specification stage only, through four operations. The rest of the
//! factory sees a typed [`SpecificationContract`] and never Spec Kit's files. The set of
//! operations is closed: no other operation can be written, so a skill outside the boundary
//! cannot be asked for.
//!
//! In ports-v1.1 the provider splits in two: `run` drives the skills in the sandbox and reports
//! which files it expects; the stage handler stops the sandbox, ingests, commits and reads the
//! files back with `JobRepo::read_file_at`; then the pure `assemble` builds the typed outcome
//! from the exact bytes. The adapter reads no file and holds no workspace.

use async_trait::async_trait;
use factory_domain::contracts::specification_contract::{OpenQuestion, QuestionId};
use factory_domain::contracts::{ArtifactRef, SpecificationContract};
use factory_domain::ids::JobId;
use factory_domain::values::{HumanText, Slug};
use factory_domain::vocabulary::Fidelity;

use crate::agent::{AgentRunError, AgentRunRequest, AgentRuntime, Denial, Usage};
use crate::clock::CancelSignal;
use crate::paths::{CommitSha, Finding, NameError, RepoPath};
use crate::sandbox::SandboxSession;

/// The four Spec Kit operations the factory may run. Planning, task generation, implementation
/// and the other installed skills are not here and cannot be requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpecOperation {
    /// Write or update the project's constitution.
    Constitution,
    /// Write the specification for a request.
    Specify,
    /// Ask the questions the specification leaves open.
    Clarify,
    /// Write the quality checklist for the specification.
    Checklist,
}

/// The directory of one feature's Spec Kit files, written `specs/<name>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FeatureDir(String);

impl FeatureDir {
    /// Checks that `text` is `specs/` followed by a lower-case name of letters, digits, `.`, `_`
    /// and `-` that starts with a letter or digit.
    ///
    /// # Errors
    /// Returns [`NameError::BadRepository`] for any other shape, so a feature directory cannot
    /// point outside `specs/`.
    pub fn new(text: &str) -> Result<Self, NameError> {
        let name = text
            .strip_prefix("specs/")
            .ok_or(NameError::BadRepository)?;
        let ok = name
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
        if ok {
            Ok(Self(text.to_owned()))
        } else {
            Err(NameError::BadRepository)
        }
    }

    /// The directory as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A person's answer to one open question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanAnswer {
    /// The question answered.
    pub question: QuestionId,
    /// The answer.
    pub answer: HumanText,
}

/// A request to change a specification that already exists, with the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionRequest {
    /// Why the specification is being revised, in plain English.
    pub reason: HumanText,
}

/// A request to repair a draft that the gate of the stage sent back.
///
/// It differs from a [`RevisionRequest`]: a revision changes a specification that was approved and
/// frozen, and makes a new version of it. A rework repairs a draft that never passed its gate, in
/// the same version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReworkRequest {
    /// The file that holds what must change in the draft: what a person asked for, when a person
    /// sent it back, and what the gates and the independent reviewer found. The skill reads it as
    /// data that says what to change in the specification and nothing else.
    pub feedback_file: RepoPath,
    /// Which rework round this is, from 1.
    pub round: u8,
}

/// One run of one Spec Kit operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecRequest {
    /// The job the specification belongs to.
    pub job: JobId,
    /// Which operation.
    pub op: SpecOperation,
    /// The feature's directory.
    pub feature_directory: FeatureDir,
    /// The file that holds the normalized request text. The original text is stored apart.
    pub request_file: RepoPath,
    /// Answers to earlier open questions.
    pub answers: Vec<HumanAnswer>,
    /// Present when an existing specification is being revised.
    pub revision: Option<RevisionRequest>,
    /// Present when the draft in the feature's directory was sent back and is being repaired.
    pub rework: Option<ReworkRequest>,
    /// Present when the draft in the feature's directory stopped on questions, a person answered
    /// them, and this operation goes on from that draft.
    pub resume: Option<ResumeRequest>,
}

/// The draft an earlier attempt of the same stage run left when it stopped to ask a person. The
/// operation applies the answers to that draft and does not write a new specification, so the
/// answers meet the questions they were given to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeRequest {
    /// How many times people have answered so far, from 1.
    pub round: u8,
}

/// A specification the operation produced.
#[derive(Debug, Clone, PartialEq)]
pub struct SpecificationDraft {
    /// The typed contract, with hashes and provenance.
    pub contract: SpecificationContract,
    /// The Spec Kit files that were produced, stored as artifacts.
    pub files: Vec<ArtifactRef>,
}

/// What an operation produced.
#[derive(Debug, Clone, PartialEq)]
pub enum SpecOutcome {
    /// A specification draft.
    Draft(Box<SpecificationDraft>),
    /// The specification cannot go on until a person answers these questions.
    NeedsHuman(Vec<OpenQuestion>),
}

/// A condition that a Spec Kit run should have left true and did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostCondition {
    /// The condition, such as `feature-file-written`.
    pub name: Slug,
    /// What was found instead, in plain English.
    pub detail: String,
}

/// What a Spec Kit run may use. The adapter owns none of these, and it has no access to the host
/// side of the repository: files come back through [`SpecFileSet`], read by the engine.
pub struct SpecContext<'a> {
    /// The `agent`-profile sandbox the skills run in.
    pub session: &'a mut dyn SandboxSession,
    /// The agent runtime that runs the skills.
    pub runtime: &'a dyn AgentRuntime,
    /// A request to copy for each skill run. The adapter replaces its prompt.
    pub run_template: AgentRunRequest,
    /// Stops the run.
    pub cancel: &'a dyn CancelSignal,
}

/// What one skill run cost. The stage handler adds it to the attempt's usage and keeps the
/// transcripts as evidence.
#[derive(Debug, Clone, PartialEq)]
pub struct SkillRun {
    /// The transcript, stored after redaction.
    pub transcript: Option<ArtifactRef>,
    /// What the run used.
    pub usage: Usage,
    /// Tool calls the tool reported as denied.
    pub permission_denials: Vec<Denial>,
    /// The skill invocation the provider put in the prompt. The stage checks that the transcript
    /// shows exactly this invocation and no other. `None` only for a provider that invokes no
    /// skill, such as a scripted fake; a real provider always says what it sent.
    pub invocation: Option<SkillInvocation>,
}

/// A skill invocation as the provider wrote it: the skill as the host names it, without the
/// sigil, and the text that followed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillInvocation {
    /// The skill, such as `speckit-specify`.
    pub skill: String,
    /// The arguments: the fixed instruction, never text a person or a model wrote.
    pub arguments: String,
}

/// What `run` did. The files are in the sandbox's checkout; the stage handler stops the
/// sandbox, ingests, commits and reads them back (`JobRepo::read_file_at`).
#[derive(Debug, Clone, PartialEq)]
pub struct SpecRunReport {
    /// The operation that ran.
    pub op: SpecOperation,
    /// The feature directory the skills wrote to.
    pub feature_directory: FeatureDir,
    /// The files the run is expected to have left, relative to the repository root. The stage
    /// handler reads exactly these.
    pub expected_files: Vec<RepoPath>,
    /// One entry for each skill run, in order.
    pub skill_runs: Vec<SkillRun>,
}

/// One file read back from a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecFile {
    /// The path.
    pub path: RepoPath,
    /// The exact bytes of the committed file.
    pub bytes: Vec<u8>,
}

/// The committed files of a Spec Kit run, for `assemble`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecFileSet {
    /// The commit the files were read from.
    pub commit: CommitSha,
    /// The files, including the constitution when the operation wrote it.
    pub files: Vec<SpecFile>,
}

/// Why a file could not be read into the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseReason {
    /// The file is not in the set.
    Missing,
    /// The bytes are not UTF-8 text.
    NotText,
    /// A required section is absent.
    SectionMissing,
    /// A requirement or scenario id does not follow the id patterns.
    BadId,
    /// The file is larger than the limit.
    TooLarge,
}

/// Why a Spec Kit run failed. The set is closed. `ForbiddenOperation` is removed: the operation
/// is a closed enum, so the variant could never be produced.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecError {
    /// Spec Kit is not installed in the project.
    #[error("Spec Kit is not installed in the project")]
    ToolMissing,
    /// The installed version is not the pinned one.
    #[error("Spec Kit version {found} is installed but {expected} is pinned")]
    VersionMismatch {
        /// The pinned version.
        expected: String,
        /// The installed version.
        found: String,
    },
    /// An installed Spec Kit file differs from the pinned manifest.
    #[error("{} Spec Kit file(s) differ from the pinned manifest", .0.len())]
    IntegrityNotOk(Vec<Finding>),
    /// A Spec Kit extension is installed. None is allowed.
    #[error("a Spec Kit extension is installed, and none is allowed")]
    ExtensionsPresent,
    /// The run finished but left the project in a state the adapter does not accept.
    #[error("{} post-condition(s) of the Spec Kit run do not hold", .0.len())]
    PostConditionFailed(Vec<PostCondition>),
    /// A Spec Kit file could not be read into the contract.
    #[error("the Spec Kit file {path} could not be read: {reason:?}")]
    ParseError {
        /// The file.
        path: RepoPath,
        /// Why not.
        reason: ParseReason,
    },
    /// The agent runtime failed.
    #[error("the agent runtime failed while running a Spec Kit skill")]
    Runtime(AgentRunError),
}

/// Runs the Spec Kit operations and returns a typed specification.
///
/// # Preconditions
/// `run`: the sandbox's checkout holds the project with Spec Kit installed at the pinned
/// version and the session is a verified `agent`-profile sandbox. `assemble`: the files were
/// read from a commit the factory made, after ingestion passed.
///
/// # Postconditions
/// `run` leaves files only under the feature directory and the constitution, and says which it
/// expects. `assemble` is pure: `Draft` carries a contract that validates against its schema with
/// the SHA-256 of each file's exact bytes; `NeedsHuman` lists every blocking question and
/// writes no contract. A cancelled `run` stops before it returns.
///
/// # Errors
/// [`SpecError`].
///
/// # Idempotency
/// `run` is not idempotent: a second `Specify` for the same feature directory may overwrite the
/// first draft, so the caller runs `Specify` once per feature and revises through
/// `SpecRequest::revision`. `assemble` is idempotent.
///
/// # Cancellation and timeouts
/// `run` takes the cancel signal in its context and stops its skill runs. `assemble` is
/// synchronous and bounded by the size of the files.
#[async_trait]
pub trait SpecificationProvider: Send + Sync {
    /// Says whether this provider drives real Spec Kit (`real`) or is scripted (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Runs one operation inside the sandbox.
    async fn run(
        &self,
        req: &SpecRequest,
        ctx: &mut SpecContext<'_>,
    ) -> Result<SpecRunReport, SpecError>;

    /// Builds the typed outcome from the committed files.
    fn assemble(&self, req: &SpecRequest, files: &SpecFileSet) -> Result<SpecOutcome, SpecError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_feature_directory_is_a_name_under_specs() {
        for good in ["specs/001-word-count", "specs/a", "specs/feature.v2_x-1"] {
            assert!(FeatureDir::new(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "specs",
            "specs/",
            "specs/../etc",
            "specs/A",
            "other/x",
            "/specs/x",
            "specs/-x",
            "specs/a b",
            "specs/a/b",
        ] {
            assert!(FeatureDir::new(bad).is_err(), "{bad:?}");
        }
    }
}
