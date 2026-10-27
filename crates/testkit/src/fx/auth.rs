//! FX-AUTH: the authority allowlist, as a fixture and a reference decision.
//!
//! In the factory, who may do what comes from a named allowlist in protected configuration, keyed
//! by the numeric GitHub user id and carrying designations (`requester`, `operator`, `approver`,
//! `security_approver`, `repo_admin`, `org_admin`). A GitHub role grants nothing: an organisation
//! owner who is not on the list is a stranger (NT-AUTHZ-01, NT-AUTHZ-02, NT-AUTHZ-04).
//!
//! This file has two jobs:
//!
//! * [`Allowlist`] is a versioned list that a test builds, with a hash of its content, so a test
//!   can check that a decision records the version it used.
//! * [`Allowlist::decide`] is a small reference decision to compare against. It looks at the
//!   numeric id and the designation and the entry's expiry, and at nothing else. It has no
//!   parameter for a GitHub role or an `author_association`, which is the point: there is no way
//!   to pass one in. The fake GitHub server can give the same people any role, and the tests
//!   assert that the answer does not change.
//!
//! The decision is a model for tests of the real one. It is not the real one.

use std::collections::BTreeSet;
use std::fmt;

use super::digest::sha256;
use super::encoding::hex_encode;

/// What a person on the list may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Designation {
    /// May label an issue to start a job.
    Requester,
    /// May pause, resume and cancel.
    Operator,
    /// May approve a change.
    Approver,
    /// May approve what needs a security approver.
    SecurityApprover,
    /// May decide for a repository.
    RepoAdmin,
    /// May decide for the organisation.
    OrgAdmin,
}

impl Designation {
    fn name(self) -> &'static str {
        match self {
            Designation::Requester => "requester",
            Designation::Operator => "operator",
            Designation::Approver => "approver",
            Designation::SecurityApprover => "security_approver",
            Designation::RepoAdmin => "repo_admin",
            Designation::OrgAdmin => "org_admin",
        }
    }
}

/// One person on the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistEntry {
    /// The numeric GitHub user id. This is what is compared.
    pub github_user_id: u64,
    /// The login at the time the entry was written. For people to read; never compared.
    pub login: String,
    /// What the person may do.
    pub designations: BTreeSet<Designation>,
    /// Seconds since the epoch when the entry stops counting, if it expires.
    pub expires_at: Option<i64>,
}

impl AllowlistEntry {
    /// An entry that does not expire.
    #[must_use]
    pub fn new(github_user_id: u64, login: &str, designations: &[Designation]) -> Self {
        Self {
            github_user_id,
            login: login.to_owned(),
            designations: designations.iter().copied().collect(),
            expires_at: None,
        }
    }

    /// The same entry with an expiry.
    #[must_use]
    pub fn expiring_at(mut self, seconds: i64) -> Self {
        self.expires_at = Some(seconds);
        self
    }
}

/// Why a person was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The numeric id is not on the list.
    NotOnAllowlist,
    /// The id is on the list and the entry has expired.
    EntryExpired,
    /// The id is on the list and does not hold this designation.
    DesignationMissing,
}

/// The reference decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Allowed, under this version of the list.
    Allowed {
        /// The hash of the list that was used.
        list_hash: String,
    },
    /// Refused, under this version of the list.
    Denied {
        /// Why.
        reason: DenyReason,
        /// The hash of the list that was used.
        list_hash: String,
    },
}

impl Decision {
    /// True for `Allowed`.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allowed { .. })
    }

    /// The hash of the list the decision was made under.
    #[must_use]
    pub fn list_hash(&self) -> &str {
        match self {
            Decision::Allowed { list_hash } | Decision::Denied { list_hash, .. } => list_hash,
        }
    }
}

/// A versioned allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allowlist {
    version: u32,
    entries: Vec<AllowlistEntry>,
}

impl Allowlist {
    /// An empty list with a version number.
    #[must_use]
    pub fn new(version: u32) -> Self {
        Self {
            version,
            entries: Vec::new(),
        }
    }

    /// The list with one more entry.
    #[must_use]
    pub fn with(mut self, entry: AllowlistEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// The version number.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The entries.
    #[must_use]
    pub fn entries(&self) -> &[AllowlistEntry] {
        &self.entries
    }

    /// A hash of the version and the content of the list, the same for any order of entries. A
    /// decision records it, so a test can tell which list a decision used.
    #[must_use]
    pub fn hash(&self) -> String {
        let mut lines: Vec<String> = self
            .entries
            .iter()
            .map(|e| {
                format!(
                    "{}|{}|{}|{}",
                    e.github_user_id,
                    e.login,
                    e.designations
                        .iter()
                        .map(|d| d.name())
                        .collect::<Vec<_>>()
                        .join(","),
                    e.expires_at
                        .map_or_else(|| "never".to_owned(), |t| t.to_string())
                )
            })
            .collect();
        lines.sort();
        let text = format!("version={}\n{}", self.version, lines.join("\n"));
        format!("sha256:{}", hex_encode(&sha256(text.as_bytes()), false))
    }

    /// Decides whether the person with this numeric id may act with this designation at `now`
    /// (seconds since the epoch).
    ///
    /// The function takes no GitHub role and no login. The login is not a parameter because a
    /// login can be changed or reused; the id cannot.
    #[must_use]
    pub fn decide(&self, github_user_id: u64, designation: Designation, now: i64) -> Decision {
        let list_hash = self.hash();
        let Some(entry) = self
            .entries
            .iter()
            .find(|e| e.github_user_id == github_user_id)
        else {
            return Decision::Denied {
                reason: DenyReason::NotOnAllowlist,
                list_hash,
            };
        };
        if entry.expires_at.is_some_and(|expiry| now >= expiry) {
            return Decision::Denied {
                reason: DenyReason::EntryExpired,
                list_hash,
            };
        }
        if !entry.designations.contains(&designation) {
            return Decision::Denied {
                reason: DenyReason::DesignationMissing,
                list_hash,
            };
        }
        Decision::Allowed { list_hash }
    }
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DenyReason::NotOnAllowlist => "not_on_allowlist",
            DenyReason::EntryExpired => "entry_expired",
            DenyReason::DesignationMissing => "designation_missing",
        })
    }
}

#[cfg(test)]
mod tests;
