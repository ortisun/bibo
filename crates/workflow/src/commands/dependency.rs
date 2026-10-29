//! The command that records a person's decision on a dependency, and what it answers.
//!
//! The command is the engine-side half of the human decision the supply chain gates wait for
//! (`gates::supply_chain`): the gate blocks `dependency-review` with `policy_unresolvable` and
//! names the exact package, version and checksum a person must decide on; this command is how the
//! decision gets into the job. The words a person writes are read by
//! [`gates::supply_chain::command`](crate::gates::supply_chain::command), which finds the subject;
//! this command takes the subject, never the words.

use factory_domain::contracts::ArtifactRef;
use factory_domain::policy::decision::AuthorizedApproval;
use factory_domain::values::{HumanText, Sha256Digest};

use super::Subject;
use crate::gates::scope::own_build_code::BuildScript;
use crate::gates::supply_chain::approval::{ApprovalKind, Subject as Package};

/// A person's decision on a dependency, or on its build code, for a blocked stage run.
///
/// The authority is the **proof** of the policy engine, which only the policy engine can make
/// (`gates::supply_chain::approval::authorize` and `authorize_build_code`): the person's numeric
/// GitHub id was found on the allowlist, the designation the action row names was held, and
/// separation of duties allowed it. The engine checks the proof again against the principal that
/// acts and the roles that principal holds now, and against the evidence the blocked stage run
/// stored; it does not take the proof as the whole truth.
#[derive(Debug, Clone)]
pub struct RecordDependencyDecision {
    /// The job and the blocked `VALIDATION` stage run that waits for the decision.
    pub stage: Subject,
    /// The proof that the policy engine authorized this person for this action.
    pub proof: AuthorizedApproval,
    /// The exact package: name, version and checksum, as the stage run's evidence showed them.
    pub package: Package,
    /// Why, in the person's words. Untrusted text; the caller has run it through the redactor.
    pub reason: HumanText,
}

/// What the engine stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyDecisionRecorded {
    /// The decision on the dependency, or on its build code.
    pub kind: ApprovalKind,
    /// The document of the decision, stored for the tenant.
    pub artifact: ArtifactRef,
    /// The hash of the ledger entry that names it.
    pub ledger_hash: Sha256Digest,
}

/// A security approver's decision on the project's own build code, for a blocked stage run.
///
/// The authority is the **proof** of the policy engine for the action `approve_build_code`
/// (`gates::supply_chain::approval::authorize_build_code`). The engine checks it again against the
/// principal that acts, the roles that principal holds now and the evidence the blocked stage run
/// stored; it does not take the proof as the whole truth.
#[derive(Debug, Clone)]
pub struct RecordProjectBuildCodeDecision {
    /// The job and the blocked `VALIDATION` stage run that waits for the decision.
    pub stage: Subject,
    /// The proof that the policy engine authorized this person for this action.
    pub proof: AuthorizedApproval,
    /// The file and the hash of its content, as the stage run's evidence showed them.
    pub script: BuildScript,
    /// Why, in the person's words. Untrusted text; the caller has run it through the redactor.
    pub reason: HumanText,
}

/// What the engine stored for a decision on the project's own build code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectBuildCodeRecorded {
    /// The document of the decision, stored for the tenant.
    pub artifact: ArtifactRef,
    /// The hash of the ledger entry that names it.
    pub ledger_hash: Sha256Digest,
}

/// An approver's decision about one translation warning of the approval request, for the
/// approval stage run that waits for a person.
///
/// The authority is the **proof** of the policy engine for the action
/// `acknowledge_documentation_warning`. The engine checks it again against the principal that
/// acts and the roles that principal holds now, and reads the warnings and the manifest of the
/// request from what the stage run stored; it does not take them from the caller.
#[derive(Debug, Clone)]
pub struct RecordWarningDecision {
    /// The job and the approval stage run that waits for the decision.
    pub stage: Subject,
    /// The proof that the policy engine authorized this person for this action.
    pub proof: AuthorizedApproval,
    /// The number of the warning, counted from 1.
    pub warning: u32,
    /// Why, in the person's words. Untrusted text; the caller has run it through the redactor.
    pub reason: HumanText,
}

/// What the engine stored for a decision about a translation warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarningDecisionRecorded {
    /// The document of the decision, stored for the tenant.
    pub artifact: ArtifactRef,
    /// The hash of the ledger entry that names it.
    pub ledger_hash: Sha256Digest,
}
