//! What the specification stage takes from the stage runs before it, and what it hands on.

pub use crate::stages::implementation::input::{
    REPOSITORY_MAP, input_artifact, map_commit, upstream_output,
};
pub use crate::stages::validation::SPECIFICATION_CONTRACT;

/// The normalized request, written by the intake stage.
pub const NORMALIZED_REQUEST: &str = "normalized-request";
/// The measurements of the run: commits, changed paths, hashes, denials, the review and the
/// failures. The gates read it.
pub const EVIDENCE: &str = "specification-evidence";
/// The file the stage writes the request to, in the sandbox, for the skills to read as data.
pub const REQUEST_FILE: &str = "inputs/request.md";
/// The file the stage writes the answers of people to.
pub const ANSWERS_FILE: &str = "inputs/answers.md";
/// The file the stage writes the feedback of a rework round to: what the gates and the
/// independent reviewer found in the draft that was sent back. It is apart from the answers
/// because it has another origin. An answer is the word of a person; the feedback is the output
/// of tools and of a model, and the skill is told to read it as data.
pub const FEEDBACK_FILE: &str = "inputs/review-feedback.md";
/// The agent that writes the specification.
pub const WRITER: &str = "specification-writer";
/// The agent that reviews it, independent of the writer.
pub const REVIEWER: &str = "specification-reviewer";
