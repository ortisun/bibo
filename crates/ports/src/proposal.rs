//! Proposing the factory's own documents in a project as draft pull requests (ports v1.6,
//! ADR 0031; first built for the rules of ADR 0026 as ports v1.4).
//!
//! The factory proposes two documents of its own in a project: the rules for agents in `AGENTS.md`
//! (ADR 0026) and the weekly measurement of its process in the knowledge base (ADR 0029). Each
//! comes from one fixed branch of the closed set [`ProposalBranch`], as a **draft** pull request. A
//! person approves and merges it. The factory never merges and never writes to the default branch.
//!
//! # Why this is its own port
//!
//! [`ChangeHost`](crate::githost::ChangeHost) writes through the token of a stage, in a scope that
//! names a job, and its push goes through the fetched workspace of that job. A proposal belongs to
//! no job and to no stage. This port has its own credential: `contents: write`,
//! `pull_requests: write` and `metadata: read`, for one repository, minted for this purpose only,
//! so no stage token is widened and the delivery token is not borrowed (the same reasoning as
//! [`IssueStatusWriter`](crate::issue_status::IssueStatusWriter), ADR 0017).
//!
//! # The contract
//!
//! The preconditions, postconditions, errors, idempotency and cancellation are in
//! `docs/architecture/ports-v1.4.md`, section 3, and `ports-v1.6.md`. In short: only the branches
//! of [`ProposalBranch`] are ever written, a pull request is a draft and is never merged or marked
//! ready, only pull requests of the factory's own App count, and the marker at the end of the body
//! is added by the adapter after its text checks.

use async_trait::async_trait;
use factory_domain::ids::{JobId, TenantId};
use factory_domain::knowledge::{EntryId, EntryKind};
use factory_domain::vocabulary::Fidelity;

use crate::githost::{GitHostError, PullRequestLifecycle, PullRequestRef};
use crate::paths::{BranchName, CommitSha, RepoPath, RepoRef};

/// The branch every rules pull request of the factory comes from.
pub const RULES_BRANCH: &str = "factory/project-rules";

/// The branch every measurement pull request of the factory comes from.
pub const MEASUREMENTS_BRANCH: &str = "factory/knowledge-measurements";

/// The file the rules live in, at the root of the repository.
pub const RULES_FILE: &str = factory_domain::project_rules::RULES_FILE;

/// The most bytes of the rules file the factory reads: 64 KiB.
pub const MAX_RULES_FILE_BYTES: u64 = 65_536;

const RULES_MARKER_PREFIX: &str = "<!-- factory-project-rules version=";
const MEASUREMENT_MARKER_PREFIX: &str = "<!-- factory-knowledge-measurement id=";
const MARKER_END: &str = " -->";

/// A branch the factory may write, with the document it proposes from it. The set is closed: the
/// adapter writes to no branch this enum does not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProposalBranch {
    /// The rules for agents, `factory/project-rules` (ADR 0026).
    ProjectRules,
    /// The weekly measurement of the process, `factory/knowledge-measurements` (ADR 0029, 0031).
    KnowledgeMeasurements,
}

impl ProposalBranch {
    /// Every branch, in a fixed order.
    pub const ALL: [Self; 2] = [Self::ProjectRules, Self::KnowledgeMeasurements];

    /// The name of the branch.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ProjectRules => RULES_BRANCH,
            Self::KnowledgeMeasurements => MEASUREMENTS_BRANCH,
        }
    }

    /// The branch as a checked name.
    ///
    /// # Panics
    /// Never: both constants are valid branch names, and a unit test says so.
    #[must_use]
    #[allow(clippy::expect_used)]
    pub fn branch_name(self) -> BranchName {
        BranchName::new(self.name()).expect("a proposal branch is a valid branch name")
    }

    /// Whether `marker` is of this branch's kind.
    #[must_use]
    pub const fn accepts(self, marker: &ProposalMarker) -> bool {
        matches!(
            (self, marker),
            (Self::ProjectRules, ProposalMarker::RulesVersion(_))
                | (Self::KnowledgeMeasurements, ProposalMarker::Measurement(_))
        )
    }

    /// The marker of this branch's form in the last marker of `body`, or `None` when there is
    /// none or when it is not exactly the form [`ProposalMarker::text`] writes.
    #[must_use]
    pub fn marker_of(self, body: &str) -> Option<ProposalMarker> {
        match self {
            Self::ProjectRules => proposed_version(body).map(ProposalMarker::RulesVersion),
            Self::KnowledgeMeasurements => {
                let start = body.rfind(MEASUREMENT_MARKER_PREFIX)?;
                let rest = body.get(start + MEASUREMENT_MARKER_PREFIX.len()..)?;
                let id = EntryId::parse(rest.get(..rest.find(MARKER_END)?)?).ok()?;
                (id.kind() == EntryKind::Measurement).then_some(ProposalMarker::Measurement(id))
            }
        }
    }
}

/// What the hidden marker at the end of a proposal's body says.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProposalMarker {
    /// The template version of the rules.
    RulesVersion(u32),
    /// The newest measurement the pull request holds.
    Measurement(EntryId),
}

impl ProposalMarker {
    /// The marker as it is written at the end of the body.
    #[must_use]
    pub fn text(&self) -> String {
        match self {
            Self::RulesVersion(version) => format!("{RULES_MARKER_PREFIX}{version}{MARKER_END}"),
            Self::Measurement(id) => format!("{MEASUREMENT_MARKER_PREFIX}{id}{MARKER_END}"),
        }
    }

    /// The commit message of one file of the proposal.
    #[must_use]
    pub fn commit_message(&self, path: &RepoPath) -> String {
        match self {
            Self::RulesVersion(version) => format!(
                "Install the factory's rules for agents, version {version}: {}",
                path.as_str()
            ),
            Self::Measurement(id) => {
                format!("Record the process numbers of {id}: {}", path.as_str())
            }
        }
    }
}

/// The hidden marker for a rules proposal of `version`:
/// `<!-- factory-project-rules version=N -->`.
#[must_use]
pub fn proposal_marker(version: u32) -> String {
    ProposalMarker::RulesVersion(version).text()
}

/// The version in the last rules marker of a body, or `None` when there is none or when it is not
/// exactly the form [`proposal_marker`] writes.
#[must_use]
pub fn proposed_version(body: &str) -> Option<u32> {
    let start = body.rfind(RULES_MARKER_PREFIX)?;
    let rest = body.get(start + RULES_MARKER_PREFIX.len()..)?;
    let digits = rest.get(..rest.find(MARKER_END)?)?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The rules branch as a checked name.
#[must_use]
pub fn rules_branch() -> BranchName {
    ProposalBranch::ProjectRules.branch_name()
}

/// What a proposal call may touch. A credential is minted for exactly this.
///
/// Like [`StatusScope`](crate::issue_status::StatusScope) it names no stage: the credential of a
/// proposal does not depend on one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProposalScope {
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

/// The newest pull request of the factory's own App on one proposal branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalPullRequest {
    /// The pull request.
    pub pr: PullRequestRef,
    /// Open, closed or merged.
    pub lifecycle: PullRequestLifecycle,
    /// The commit at the tip of the pull request's branch.
    pub head: CommitSha,
    /// The marker at the end of its body, read by the branch's own form, or `None`.
    pub marker: Option<ProposalMarker>,
}

/// One file to write on a proposal branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedFile {
    /// Where, from the root of the repository.
    pub path: RepoPath,
    /// The whole content.
    pub bytes: Vec<u8>,
}

/// What to propose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequestProposal {
    /// The branch the proposal comes from.
    pub branch: ProposalBranch,
    /// The default branch, and the commit a new proposal branch starts from.
    pub base: DefaultBranch,
    /// The marker written at the end of the body. Of the branch's kind.
    pub marker: ProposalMarker,
    /// The files, at least one.
    pub files: Vec<ProposedFile>,
    /// The title, from a closed template.
    pub title: String,
    /// The body without the marker, from a closed template.
    pub body: String,
}

/// Reads what a proposal decision needs and proposes a document as a draft pull request.
///
/// # Preconditions
/// The scope names the tenant and one repository. The caller decided that a proposal is needed;
/// this port authorizes nothing. The title and the body come from a closed template.
///
/// # Postconditions
/// See `docs/architecture/ports-v1.4.md`, section 3, and `ports-v1.6.md`. No call writes to any
/// branch but those of [`ProposalBranch`], no call merges, and no call marks a pull request ready.
///
/// # Errors
/// [`GitHostError`]. A proposal whose marker is not of its branch's kind is
/// `Rejected(Other)` before any request.
///
/// # Idempotency
/// `propose` with the same proposal again writes no file and opens no second pull request. The
/// rest are reads.
///
/// # Cancellation and timeouts
/// Every call is safe to drop, with the effect of a request already sent being possible. The
/// adapter sets a request timeout of 30 seconds and reports `Unavailable` when it is exceeded.
#[async_trait]
pub trait ProposalHost: Send + Sync {
    /// Says whether this host talks to the real code host (`real`) or is scripted (`fake`).
    fn fidelity(&self) -> Fidelity;

    /// The default branch of the repository and its tip.
    async fn default_branch(&self, scope: &ProposalScope) -> Result<DefaultBranch, GitHostError>;

    /// The file at `path` at `commit`, read only up to `max_bytes`.
    async fn read_file(
        &self,
        scope: &ProposalScope,
        commit: &CommitSha,
        path: &RepoPath,
        max_bytes: u64,
    ) -> Result<FileAt, GitHostError>;

    /// The newest pull request that the factory's own App opened from `branch`, in any state, or
    /// `None`.
    async fn latest_pull_request(
        &self,
        scope: &ProposalScope,
        branch: ProposalBranch,
    ) -> Result<Option<ProposalPullRequest>, GitHostError>;

    /// Writes the files on the proposal's branch and opens a draft pull request into the default
    /// branch, or updates the open one.
    async fn propose(
        &self,
        scope: &ProposalScope,
        proposal: &PullRequestProposal,
    ) -> Result<PullRequestRef, GitHostError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_proposal_branch_is_a_factory_branch_of_its_own() {
        for branch in ProposalBranch::ALL {
            assert!(
                branch
                    .branch_name()
                    .as_str()
                    .starts_with(crate::paths::FACTORY_BRANCH_PREFIX)
            );
        }
        assert_ne!(
            ProposalBranch::ProjectRules.name(),
            ProposalBranch::KnowledgeMeasurements.name()
        );
        assert_eq!(rules_branch().as_str(), RULES_BRANCH);
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

    #[test]
    fn each_branch_reads_only_its_own_marker() {
        let week = EntryId::parse("M-2026-W47").expect("valid");
        let measurement = ProposalMarker::Measurement(week.clone());
        assert_eq!(
            measurement.text(),
            "<!-- factory-knowledge-measurement id=M-2026-W47 -->"
        );
        let body = format!("Numbers.\n\n{}", measurement.text());
        assert_eq!(
            ProposalBranch::KnowledgeMeasurements.marker_of(&body),
            Some(measurement.clone())
        );
        assert_eq!(ProposalBranch::ProjectRules.marker_of(&body), None);
        let rules = format!("Rules.\n\n{}", proposal_marker(2));
        assert_eq!(
            ProposalBranch::ProjectRules.marker_of(&rules),
            Some(ProposalMarker::RulesVersion(2))
        );
        assert_eq!(
            ProposalBranch::KnowledgeMeasurements.marker_of(&rules),
            None
        );
        // The last marker wins; a marker that names no measurement is none.
        let two = format!(
            "{}\n{}",
            ProposalMarker::Measurement(EntryId::parse("M-2026-W46").expect("valid")).text(),
            measurement.text()
        );
        assert_eq!(
            ProposalBranch::KnowledgeMeasurements.marker_of(&two),
            Some(measurement.clone())
        );
        for bad in [
            "<!-- factory-knowledge-measurement id=BR-0001 -->",
            "<!-- factory-knowledge-measurement id=M-2026-W99 -->",
            "<!-- factory-knowledge-measurement id= -->",
            "<!-- factory-knowledge-measurement id=M-2026-W47",
        ] {
            assert_eq!(
                ProposalBranch::KnowledgeMeasurements.marker_of(bad),
                None,
                "{bad}"
            );
        }
        assert!(ProposalBranch::KnowledgeMeasurements.accepts(&measurement));
        assert!(!ProposalBranch::ProjectRules.accepts(&measurement));
        assert!(ProposalBranch::ProjectRules.accepts(&ProposalMarker::RulesVersion(1)));
        let path = RepoPath::new("docs/knowledge/measurements/M-2026-W47.md").expect("valid");
        assert_eq!(
            measurement.commit_message(&path),
            "Record the process numbers of M-2026-W47: docs/knowledge/measurements/M-2026-W47.md"
        );
        assert_eq!(
            ProposalMarker::RulesVersion(2)
                .commit_message(&RepoPath::new("AGENTS.md").expect("valid")),
            "Install the factory's rules for agents, version 2: AGENTS.md"
        );
    }
}
