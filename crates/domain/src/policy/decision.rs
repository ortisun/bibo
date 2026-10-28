//! Values shared by the evaluators that deal with people: the numeric GitHub id, the designations
//! on the allowlist, and the proof that a human decision was authorized.

use std::fmt;

use crate::values::Timestamp;

use super::RuleRef;

/// The immutable numeric id of a GitHub account.
///
/// This is the only identity the authority rules compare. A login can be renamed, released and
/// registered again by someone else, so a login is display text and never a key
/// (`authority.identity_key: github_user_numeric_id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GithubUserId(u64);

impl GithubUserId {
    /// Wraps a numeric id. GitHub ids start at 1, so 0 is refused.
    #[must_use]
    pub fn new(id: u64) -> Option<Self> {
        (id != 0).then_some(Self(id))
    }

    /// The number.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for GithubUserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A factory designation, held by being named on the allowlist for it
/// (`approval.yaml` `roles`). A designation does not imply another: an `org_admin` is not an
/// `approver` unless the allowlist also names them as one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Designation {
    /// May submit a request.
    Requester,
    /// May pause, resume, cancel and view jobs.
    Operator,
    /// May approve, reject and request rework.
    Approver,
    /// May approve protected paths, egress, tool grants and sandbox settings.
    SecurityApprover,
    /// May lower autonomy and change a repository's factory settings.
    RepoAdmin,
    /// May raise autonomy, enable auto-merge or deploy, change budgets above ceilings and edit the
    /// allowlist.
    OrgAdmin,
}

impl Designation {
    /// Every designation.
    pub const ALL: [Designation; 6] = [
        Self::Requester,
        Self::Operator,
        Self::Approver,
        Self::SecurityApprover,
        Self::RepoAdmin,
        Self::OrgAdmin,
    ];

    /// The spelling the policy files use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requester => "requester",
            Self::Operator => "operator",
            Self::Approver => "approver",
            Self::SecurityApprover => "security_approver",
            Self::RepoAdmin => "repo_admin",
            Self::OrgAdmin => "org_admin",
        }
    }

    /// Reads the policy spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.as_str() == text)
    }
}

impl fmt::Display for Designation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The record that an authorized human took an action. It can be made only by
/// [`PolicyEngine`](super::PolicyEngine) evaluating a real decision against the allowlist, so a
/// function that asks for one (such as a protected-path exception) cannot be handed a `true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedApproval {
    action: String,
    approver: GithubUserId,
    designation: Designation,
    allowlist_version: String,
    decided_at: Timestamp,
    rule: RuleRef,
}

impl AuthorizedApproval {
    // Only the authority evaluator calls this; it arrives in the next commit of this work package.
    #[allow(dead_code)]
    pub(crate) fn new(
        action: &str,
        approver: GithubUserId,
        designation: Designation,
        allowlist_version: &str,
        decided_at: Timestamp,
        rule: RuleRef,
    ) -> Self {
        Self {
            action: action.to_owned(),
            approver,
            designation,
            allowlist_version: allowlist_version.to_owned(),
            decided_at,
            rule,
        }
    }

    /// The action the human was authorized to take, such as `change_protected_path`.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    /// The numeric id of the human.
    #[must_use]
    pub fn approver(&self) -> GithubUserId {
        self.approver
    }

    /// The designation the allowlist gave the human, which the decision relied on.
    #[must_use]
    pub fn designation(&self) -> Designation {
        self.designation
    }

    /// The version hash of the allowlist the decision was read from.
    #[must_use]
    pub fn allowlist_version(&self) -> &str {
        &self.allowlist_version
    }

    /// When the decision was taken.
    #[must_use]
    pub fn decided_at(&self) -> &Timestamp {
        &self.decided_at
    }

    /// The action row that allowed it.
    #[must_use]
    pub fn rule(&self) -> &RuleRef {
        &self.rule
    }
}
