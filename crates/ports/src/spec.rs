//! The specification port: the anti-corruption boundary around GitHub Spec Kit (ADR 0006).
//!
//! Spec Kit is used for the specification stage only, through four operations. The rest of the
//! factory sees a typed [`SpecificationContract`] and never Spec Kit's files. The set of
//! operations is closed: no other operation can be written, so a skill outside the boundary
//! cannot be asked for.

use async_trait::async_trait;
use factory_domain::contracts::specification_contract::{OpenQuestion, QuestionId};
use factory_domain::contracts::{ArtifactRef, SpecificationContract};
use factory_domain::ids::JobId;
use factory_domain::values::{HumanText, Slug};
use factory_domain::vocabulary::Fidelity;

use crate::agent::{AgentRunError, AgentRunRequest, AgentRuntime};
use crate::clock::CancelSignal;
use crate::paths::{Finding, NameError, RepoPath};
use crate::sandbox::SandboxSession;
use crate::workspace::Workspace;

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

/// What a Spec Kit run may use. The adapter does not own any of these.
pub struct SpecContext<'a> {
    /// The host side of the repository.
    pub workspace: &'a dyn Workspace,
    /// The `agent`-profile sandbox the skills run in.
    pub session: &'a mut dyn SandboxSession,
    /// The agent runtime that runs the skills.
    pub runtime: &'a dyn AgentRuntime,
    /// A request to copy for each skill run. The adapter replaces its prompt.
    pub run_template: AgentRunRequest,
    /// Stops the run.
    pub cancel: &'a dyn CancelSignal,
}

/// Why a Spec Kit run failed. The set is closed.
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
    #[error("the Spec Kit file {path} could not be read: {reason}")]
    ParseError {
        /// The file.
        path: String,
        /// Why not.
        reason: String,
    },
    /// The request needs something outside the four allowed operations.
    #[error("the request needs an operation outside the allowed four")]
    ForbiddenOperation,
    /// The agent runtime failed.
    #[error("the agent runtime failed while running a Spec Kit skill")]
    Runtime(AgentRunError),
}

/// Runs the Spec Kit operations and returns a typed specification.
///
/// # Preconditions
/// The workspace holds the project with Spec Kit installed at the pinned version and the
/// session is a verified `agent`-profile sandbox. The request file holds normalized text.
///
/// # Postconditions
/// `Draft` carries a contract that validates against its schema, with a hash of each Spec Kit
/// file it was read from. `NeedsHuman` lists every blocking question and writes no contract. A
/// run that is cancelled stops before it returns. No file outside the feature directory and the
/// constitution is changed.
///
/// # Errors
/// [`SpecError`]: `ToolMissing`, `VersionMismatch`, `IntegrityNotOk`, `ExtensionsPresent`,
/// `PostConditionFailed`, `ParseError`, `ForbiddenOperation` and `Runtime`.
///
/// # Idempotency
/// Not idempotent. A second `Specify` for the same feature directory may overwrite the first
/// draft, so the caller runs `Specify` once per feature and revises through
/// [`SpecRequest::revision`].
#[async_trait]
pub trait SpecificationProvider: Send + Sync {
    /// Says whether this provider drives real Spec Kit (`real`) or is scripted (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// Runs one operation.
    async fn run(
        &self,
        req: SpecRequest,
        ctx: &mut SpecContext<'_>,
    ) -> Result<SpecOutcome, SpecError>;
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
