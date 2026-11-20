//! Opening the pull request that installs the project's rules for agents (ports v1.4, ADR 0026).
//!
//! When a project is onboarded, and when a new release of the factory changes its rules, the
//! factory proposes `AGENTS.md` (and the index files of `docs/` the project lacks) as a **draft**
//! pull request from one fixed branch, [`RULES_BRANCH`]. A person approves and merges it. The
//! factory never merges and never writes to the default branch.
//!
//! # Why this is its own port
//!
//! [`ChangeHost`](crate::githost::ChangeHost) writes through the token of a stage, in a scope that
//! names a job, and its push goes through the fetched workspace of that job. The rules pull request
//! belongs to no job and to no stage. This port has its own credential: `contents: write`,
//! `pull_requests: write` and `metadata: read`, for one repository, minted for this purpose only,
//! so no stage token is widened and the delivery token is not borrowed (the same reasoning as
//! [`IssueStatusWriter`](crate::issue_status::IssueStatusWriter), ADR 0017).
//!
//! # The contract
//!
//! The preconditions, postconditions, errors, idempotency and cancellation are in
//! `docs/architecture/ports-v1.4.md`, section 3. In short: only [`RULES_BRANCH`] is ever written,
//! a pull request is a draft and is never merged or marked ready, only pull requests of the
//! factory's own App count, and the version marker at the end of the body is added by the adapter
//! after its text checks.

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::vocabulary::Fidelity;

use crate::githost::{GitHostError, PullRequestLifecycle, PullRequestRef};
use crate::paths::{BranchName, CommitSha, RepoPath, RepoRef};

/// The branch every rules pull request of the factory comes from.
pub const RULES_BRANCH: &str = "factory/project-rules";

/// The file the rules live in, at the root of the repository.
pub const RULES_FILE: &str = factory_domain::project_rules::RULES_FILE;

/// The most bytes of the rules file the factory reads: 64 KiB.
pub const MAX_RULES_FILE_BYTES: u64 = 65_536;

/// The start of the hidden marker at the end of a rules pull request's body.
pub const PROPOSAL_MARKER_PREFIX: &str = "<!-- factory-project-rules version=";

/// The hidden marker for a proposal of `version`: `<!-- factory-project-rules version=N -->`.
#[must_use]
pub fn proposal_marker(version: u32) -> String {
    format!("{PROPOSAL_MARKER_PREFIX}{version} -->")
}

/// The version in the last marker of a body, or `None` when there is none or when it is not
/// exactly the form [`proposal_marker`] writes.
#[must_use]
pub fn proposed_version(body: &str) -> Option<u32> {
    let start = body.rfind(PROPOSAL_MARKER_PREFIX)?;
    let rest = body.get(start + PROPOSAL_MARKER_PREFIX.len()..)?;
    let digits = rest.get(..rest.find(" -->")?)?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The rules branch as a checked name.
///
/// # Panics
/// Never: the constant is a valid branch name, and a unit test says so.
#[must_use]
#[allow(clippy::expect_used)]
pub fn rules_branch() -> BranchName {
    BranchName::new(RULES_BRANCH).expect("the rules branch is a valid branch name")
}

/// What a rules call may touch. A credential is minted for exactly this.
///
/// Like [`StatusScope`](crate::issue_status::StatusScope) it names no stage: the credential of a
/// rules call does not depend on one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RulesScope {
    /// The tenant.
    pub tenant: TenantId,
    /// The identifier the credential is kept under and ended by
    /// ([`ChangeHost::revoke_job_tokens`](crate::githost::ChangeHost::revoke_job_tokens)). It is
    /// not a job: the caller uses a fresh identifier for each check.
    pub session: JobId,
    /// The one repository the credential works on.
    pub repo: RepoRef,
}

/// The default branch and the commit at its tip, read together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultBranch {
    /// The branch.
    pub name: BranchName,
    /// The commit at its tip.
    pub commit: CommitSha,
}

/// A file read at one commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileAt {
    /// No file at that path (or a directory).
    Missing,
    /// The bytes of the file.
    Found(Vec<u8>),
    /// Larger than the limit the caller gave. Its bytes were not read.
    TooLarge,
}

/// The newest pull request of the factory's own App on [`RULES_BRANCH`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesPullRequest {
    /// The pull request.
    pub pr: PullRequestRef,
    /// Open, closed or merged.
    pub lifecycle: PullRequestLifecycle,
    /// The version of the marker at the end of its body, or `None`.
    pub proposed_version: Option<u32>,
}

/// One file to write on the rules branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedFile {
    /// Where, from the root of the repository.
    pub path: RepoPath,
    /// The whole content.
    pub bytes: Vec<u8>,
}

/// What to propose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesProposal {
    /// The default branch, and the commit a new rules branch starts from.
    pub base: DefaultBranch,
    /// The template version, written in the hidden marker of the body.
    pub version: u32,
    /// The files, at least one.
    pub files: Vec<ProposedFile>,
    /// The title, from a closed template.
    pub title: String,
    /// The body without the marker, from a closed template.
    pub body: String,
}

/// Reads what the rules decision needs and proposes the rules as a draft pull request.
///
/// # Preconditions
/// The scope names the tenant and one repository. The caller decided that a proposal is needed;
/// this port authorizes nothing. The title and the body come from a closed template.
///
/// # Postconditions
/// See `docs/architecture/ports-v1.4.md`, section 3. No call writes to any branch but
/// [`RULES_BRANCH`], no call merges, and no call marks a pull request ready.
///
/// # Errors
/// [`GitHostError`].
///
/// # Idempotency
/// `propose` with the same proposal again writes no file and opens no second pull request. The
/// rest are reads.
///
/// # Cancellation and timeouts
/// Every call is safe to drop, with the effect of a request already sent being possible. The
/// adapter sets a request timeout of 30 seconds and reports `Unavailable` when it is exceeded.
#[async_trait]
pub trait ProjectRulesHost: Send + Sync {
    /// Says whether this host talks to the real code host (`real`) or is scripted (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// The default branch of the repository and its tip.
    async fn default_branch(&self, scope: &RulesScope) -> Result<DefaultBranch, GitHostError>;

    /// The file at `path` at `commit`, read only up to `max_bytes`.
    async fn read_file(
        &self,
        scope: &RulesScope,
        commit: &CommitSha,
        path: &RepoPath,
        max_bytes: u64,
    ) -> Result<FileAt, GitHostError>;

    /// The newest pull request that the factory's own App opened from [`RULES_BRANCH`], in any
    /// state, or `None`.
    async fn latest_rules_pull_request(
        &self,
        scope: &RulesScope,
    ) -> Result<Option<RulesPullRequest>, GitHostError>;

    /// Writes the files on [`RULES_BRANCH`] and opens a draft pull request into the default
    /// branch, or updates the open one.
    async fn propose(
        &self,
        scope: &RulesScope,
        proposal: &RulesProposal,
    ) -> Result<PullRequestRef, GitHostError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rules_branch_is_a_factory_branch() {
        assert!(
            rules_branch()
                .as_str()
                .starts_with(crate::paths::FACTORY_BRANCH_PREFIX)
        );
        assert_eq!(RULES_FILE, "AGENTS.md");
        assert_eq!(
            usize::try_from(MAX_RULES_FILE_BYTES).ok(),
            Some(factory_domain::project_rules::MAX_RULES_BYTES)
        );
    }

    #[test]
    fn a_marker_reads_back_as_its_version_and_nothing_else_does() {
        for version in [1, 2, 10, u32::MAX] {
            let body = format!("Text.\n\n{}", proposal_marker(version));
            assert_eq!(proposed_version(&body), Some(version));
        }
        let last = format!("{}\n{}", proposal_marker(1), proposal_marker(2));
        assert_eq!(proposed_version(&last), Some(2));
        for bad in [
            "no marker".to_owned(),
            "<!-- factory-project-rules version=0 -->".to_owned(),
            "<!-- factory-project-rules version=01 -->".to_owned(),
            "<!-- factory-project-rules version=-1 -->".to_owned(),
            "<!-- factory-project-rules version=1x -->".to_owned(),
            "<!-- factory-project-rules version= -->".to_owned(),
            "<!-- factory-project-rules version=4294967296 -->".to_owned(),
            "<!-- factory-project-rules version=1".to_owned(),
        ] {
            assert_eq!(proposed_version(&bad), None, "{bad}");
        }
    }
}
