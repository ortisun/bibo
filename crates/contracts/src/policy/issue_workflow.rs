//! `policies/issue-workflow.yaml`: loading it, and the rules that tie it to the engine.
//!
//! The file is read like the other policies: through a [`ProtectedPolicySource`], one document in
//! the restricted YAML subset, `schema_version` checked first, no unknown key at any depth, and a
//! hash of the canonical form. The rules in
//! [`IssueWorkflowPolicy::problems`](factory_domain::policy::issue_workflow::IssueWorkflowPolicy::problems)
//! then run, and a file that breaks one does not load: a policy that leaves a job state without a
//! label, names a state the engine does not have, puts the trigger label in a namespace, or breaks
//! a label length limit is refused with the key and the line.
//!
//! The Python tool `scripts/lib/issue_workflow.py` checks the same file for the installer and the
//! Action. `crates/contracts/tests/issue_workflow.rs` compares what this loader reads with the JSON
//! that tool renders, so the two cannot disagree about a label.

use factory_domain::policy::issue_workflow::{IssueWorkflowPolicy, ProblemKind as DomainKind};

use super::check::{Problem, ProblemKind};
use super::{
    ConfigSource, LoadedPolicy, PolicyError, PolicyLoader, ProtectedPolicySource, load_document,
    read_policy_file,
};

/// The issue workflow policy file, relative to the checkout.
pub const ISSUE_WORKFLOW_FILE: &str = "policies/issue-workflow.yaml";

impl PolicyLoader {
    /// Loads `policies/issue-workflow.yaml`.
    ///
    /// # Errors
    /// A [`PolicyError`]. No policy value exists after an error.
    pub fn load_issue_workflow(
        source: &ProtectedPolicySource,
    ) -> Result<LoadedPolicy<IssueWorkflowPolicy>, PolicyError> {
        let (label, text, file_sha256) = read_policy_file(source, ISSUE_WORKFLOW_FILE)?;
        load_document(
            &label,
            &text,
            file_sha256,
            // The file has no `config_source`: it is read from the protected checkout like the
            // others, and a source cannot be named in it.
            |_: &IssueWorkflowPolicy| ConfigSource::ProtectedDefaultBranch,
            issue_workflow_problems,
        )
    }
}

/// The rules of the file, as the loader reports them.
#[must_use]
pub fn issue_workflow_problems(policy: &IssueWorkflowPolicy) -> Vec<Problem> {
    policy
        .problems()
        .into_iter()
        .map(|found| Problem {
            path: found.path,
            kind: match found.kind {
                DomainKind::Duplicate => ProblemKind::DuplicateId,
                DomainKind::Unknown => ProblemKind::UnknownReference,
                DomainKind::Shape => ProblemKind::InvalidGlob,
                DomainKind::Constraint => ProblemKind::Constraint,
            },
            message: found.message,
        })
        .collect()
}
