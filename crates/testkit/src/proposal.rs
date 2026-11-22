//! An in-memory fake of `ProposalHost` (ports v1.4 and v1.6, ADR 0026 and 0031), with deliberate
//! defects that the contract suite must catch.
//!
//! The fake keeps one repository per name: a default branch `main`, branches with their files at
//! their tip, and pull requests. A write makes a new commit id, so a branch that moved can be told
//! from one that did not. Pull requests the factory opens are authored by the factory; a test can
//! add one by a person, as a person can on GitHub.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use async_trait::async_trait;
use factory_domain::vocabulary::Fidelity;
use factory_ports::githost::{GitHostError, PullRequestLifecycle, PullRequestRef, Rejection};
use factory_ports::paths::{BranchName, CommitSha, RepoPath, RepoRef};
use factory_ports::proposal::{
    DefaultBranch, FileAt, ProposalBranch, ProposalHost, ProposalPullRequest, ProposalScope,
    PullRequestProposal,
};

use crate::contracts::githost::repo as suite_repo;
use crate::contracts::proposal::{ProposalSubject, SeenPull};
use crate::githost::looks_like_a_secret;

/// The default branch of every repository of the fake.
pub const DEFAULT_BRANCH: &str = "main";

/// A deliberate defect. Each one breaks one rule of the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalDefect {
    /// Writes the files on the default branch instead of the rules branch.
    WritesTheDefaultBranch,
    /// Opens a new pull request even when one is open.
    OpensASecondPullRequest,
    /// Opens a pull request that is not a draft.
    OpensReadyPullRequests,
    /// Leaves the version marker out of the body.
    ForgetsTheMarker,
    /// Counts a pull request a person opened from the rules branch as the factory's.
    TrustsAnyAuthor,
    /// Moves the branch back to the default branch even when a pull request is open.
    ResetsAnOpenBranch,
    /// Sends a body that looks like it holds a secret.
    SkipsSecretCheck,
    /// Asks for a credential wider than `contents` and `pull_requests` write.
    AsksForAWiderToken,
    /// Answers for another repository than the scope's.
    IgnoresTheScope,
    /// Returns the bytes of a file over the limit.
    IgnoresTheSizeLimit,
    /// Reports the first commit of the default branch, not its tip.
    ReportsAStaleTip,
    /// Commits on top of a branch left from a closed proposal instead of starting again.
    KeepsAClosedBranch,
    /// Accepts an empty title or a proposal with no file.
    AcceptsEmptyText,
    /// Writes and reads the rules branch whatever branch the proposal names.
    IgnoresTheBranch,
}

/// Each defect, and the checks of the suite that must fail with it.
pub const PROPOSAL_DEFECTS: &[(ProposalDefect, &[&str])] = &[
    (
        ProposalDefect::WritesTheDefaultBranch,
        &["a_proposal_is_one_draft_pull_request_and_the_default_branch_is_untouched"],
    ),
    (
        ProposalDefect::OpensASecondPullRequest,
        &["proposing_again_opens_no_second_pull_request"],
    ),
    (
        ProposalDefect::OpensReadyPullRequests,
        &["a_proposal_is_one_draft_pull_request_and_the_default_branch_is_untouched"],
    ),
    (
        ProposalDefect::ForgetsTheMarker,
        &["the_latest_pull_request_carries_its_state_and_version"],
    ),
    (
        ProposalDefect::TrustsAnyAuthor,
        &["a_pull_request_a_person_opened_from_the_rules_branch_is_not_the_factorys"],
    ),
    (
        ProposalDefect::ResetsAnOpenBranch,
        &["an_open_proposal_is_updated_on_top_and_a_persons_commit_is_kept"],
    ),
    (
        ProposalDefect::SkipsSecretCheck,
        &["a_body_with_a_secret_is_not_sent"],
    ),
    (
        ProposalDefect::AsksForAWiderToken,
        &["the_credential_is_contents_and_pull_requests_write_and_nothing_else"],
    ),
    (
        ProposalDefect::IgnoresTheScope,
        &["a_scope_for_another_repository_reaches_nothing"],
    ),
    (
        ProposalDefect::IgnoresTheSizeLimit,
        &["a_file_is_missing_found_or_too_large"],
    ),
    (
        ProposalDefect::ReportsAStaleTip,
        &["the_default_branch_is_read_with_its_tip"],
    ),
    (
        ProposalDefect::KeepsAClosedBranch,
        &["a_new_proposal_after_a_closed_one_starts_from_the_default_branch"],
    ),
    (
        ProposalDefect::AcceptsEmptyText,
        &["an_empty_title_or_no_file_is_refused"],
    ),
    (
        ProposalDefect::IgnoresTheBranch,
        &["each_branch_has_its_own_pull_request_and_marker"],
    ),
];

#[derive(Debug, Clone)]
struct Pull {
    number: u64,
    head: String,
    base: String,
    title: String,
    body: String,
    draft: bool,
    lifecycle: PullRequestLifecycle,
    by_factory: bool,
}

#[derive(Debug, Clone, Default)]
struct Branch {
    commit: String,
    files: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Default)]
struct Repo {
    branches: BTreeMap<String, Branch>,
    /// Every commit ever made, with its files, so a file can be read at an old commit.
    commits: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
    pulls: Vec<Pull>,
}

#[derive(Debug, Default)]
struct State {
    repos: BTreeMap<String, Repo>,
    next_commit: u64,
    permissions: Vec<Vec<(String, String)>>,
}

impl State {
    fn new_commit(&mut self) -> String {
        self.next_commit += 1;
        format!("{:040x}", self.next_commit)
    }

    fn repo(&mut self, repo: &RepoRef) -> &mut Repo {
        let key = repo.to_string().to_ascii_lowercase();
        if !self.repos.contains_key(&key) {
            self.next_commit += 1;
            let commit = format!("{:040x}", self.next_commit);
            let mut created = Repo::default();
            created.commits.insert(commit.clone(), BTreeMap::new());
            created.branches.insert(
                DEFAULT_BRANCH.to_owned(),
                Branch {
                    commit,
                    files: BTreeMap::new(),
                },
            );
            self.repos.insert(key.clone(), created);
        }
        self.repos.get_mut(&key).unwrap_or_else(|| unreachable!())
    }

    /// Sets `files` on `branch` as one new commit. `None` removes the file.
    fn commit(&mut self, repo: &RepoRef, branch: &str, changes: &[(&str, Option<Vec<u8>>)]) {
        let commit = self.new_commit();
        let target = self.repo(repo);
        let mut files = target
            .branches
            .get(branch)
            .map(|b| b.files.clone())
            .unwrap_or_default();
        for (path, bytes) in changes {
            match bytes {
                Some(bytes) => {
                    files.insert((*path).to_owned(), bytes.clone());
                }
                None => {
                    files.remove(*path);
                }
            }
        }
        target.commits.insert(commit.clone(), files.clone());
        target
            .branches
            .insert(branch.to_owned(), Branch { commit, files });
    }
}

/// A pull request as the fake holds it, for a test to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullView {
    /// Its number.
    pub number: u64,
    /// The head branch.
    pub head: String,
    /// The base branch.
    pub base: String,
    /// The title.
    pub title: String,
    /// The body as sent, with the marker.
    pub body: String,
    /// True while it is a draft.
    pub draft: bool,
    /// Open, closed or merged.
    pub lifecycle: PullRequestLifecycle,
    /// True when the factory opened it.
    pub by_factory: bool,
}

/// The fake project rules host.
#[derive(Debug, Default)]
pub struct FakeProposalHost {
    state: Mutex<State>,
    defect: Option<ProposalDefect>,
}

impl FakeProposalHost {
    /// A fake with no repository yet. A repository is made, empty, the first time it is named.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A fake with one deliberate defect.
    #[must_use]
    pub fn with_defect(defect: ProposalDefect) -> Self {
        Self {
            state: Mutex::new(State::default()),
            defect: Some(defect),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn is(&self, defect: ProposalDefect) -> bool {
        self.defect == Some(defect)
    }

    /// A person's commit on a branch: sets or removes files. A branch that does not exist is made
    /// from the default branch first.
    pub fn person_commit(&self, repo: &RepoRef, branch: &str, changes: &[(&str, Option<&str>)]) {
        let mut state = self.lock();
        let exists = state.repo(repo).branches.contains_key(branch);
        if !exists {
            let from = state.repo(repo).branches.get(DEFAULT_BRANCH).cloned();
            if let Some(from) = from {
                state.repo(repo).branches.insert(branch.to_owned(), from);
            }
        }
        let owned: Vec<(&str, Option<Vec<u8>>)> = changes
            .iter()
            .map(|(path, text)| (*path, text.map(|t| t.as_bytes().to_vec())))
            .collect();
        state.commit(repo, branch, &owned);
    }

    /// The files at the tip of a branch.
    #[must_use]
    pub fn files_on(&self, repo: &RepoRef, branch: &str) -> BTreeMap<String, Vec<u8>> {
        self.lock()
            .repo(repo)
            .branches
            .get(branch)
            .map(|b| b.files.clone())
            .unwrap_or_default()
    }

    /// The commit at the tip of a branch, if the branch exists.
    #[must_use]
    pub fn tip(&self, repo: &RepoRef, branch: &str) -> Option<String> {
        self.lock()
            .repo(repo)
            .branches
            .get(branch)
            .map(|b| b.commit.clone())
    }

    /// Every pull request of the repository, lowest number first.
    #[must_use]
    pub fn pulls(&self, repo: &RepoRef) -> Vec<PullView> {
        self.lock()
            .repo(repo)
            .pulls
            .iter()
            .map(|p| PullView {
                number: p.number,
                head: p.head.clone(),
                base: p.base.clone(),
                title: p.title.clone(),
                body: p.body.clone(),
                draft: p.draft,
                lifecycle: p.lifecycle,
                by_factory: p.by_factory,
            })
            .collect()
    }

    /// A person closes a pull request without merging it.
    pub fn close(&self, repo: &RepoRef, number: u64) {
        if let Some(pull) = self
            .lock()
            .repo(repo)
            .pulls
            .iter_mut()
            .find(|p| p.number == number)
        {
            pull.lifecycle = PullRequestLifecycle::Closed;
        }
    }

    /// A person merges a pull request: the default branch gets the files of its head.
    pub fn merge(&self, repo: &RepoRef, number: u64) {
        let mut state = self.lock();
        let Some(head) = state
            .repo(repo)
            .pulls
            .iter()
            .find(|p| p.number == number)
            .map(|p| p.head.clone())
        else {
            return;
        };
        let files = state
            .repo(repo)
            .branches
            .get(&head)
            .map(|b| b.files.clone())
            .unwrap_or_default();
        let changes: Vec<(&str, Option<Vec<u8>>)> = files
            .iter()
            .map(|(path, bytes)| (path.as_str(), Some(bytes.clone())))
            .collect();
        state.commit(repo, DEFAULT_BRANCH, &changes);
        if let Some(pull) = state
            .repo(repo)
            .pulls
            .iter_mut()
            .find(|p| p.number == number)
        {
            pull.lifecycle = PullRequestLifecycle::Merged;
        }
    }

    /// A person opens a pull request from a branch, with a body of their own.
    pub fn person_pull_request(&self, repo: &RepoRef, head: &str, body: &str) -> u64 {
        let mut state = self.lock();
        let target = state.repo(repo);
        let number = u64::try_from(target.pulls.len()).unwrap_or(u64::MAX) + 1;
        target.pulls.push(Pull {
            number,
            head: head.to_owned(),
            base: DEFAULT_BRANCH.to_owned(),
            title: "A person's change".to_owned(),
            body: body.to_owned(),
            draft: false,
            lifecycle: PullRequestLifecycle::Open,
            by_factory: false,
        });
        number
    }

    /// The permission sets asked for, one entry for each credential, each sorted.
    #[must_use]
    pub fn permissions_asked(&self) -> Vec<Vec<(String, String)>> {
        self.lock().permissions.clone()
    }

    fn note_credential(&self, state: &mut State) {
        let mut asked = vec![
            ("metadata".to_owned(), "read".to_owned()),
            ("contents".to_owned(), "write".to_owned()),
            ("pull_requests".to_owned(), "write".to_owned()),
        ];
        if self.is(ProposalDefect::AsksForAWiderToken) {
            asked.push(("issues".to_owned(), "write".to_owned()));
        }
        asked.sort();
        state.permissions.push(asked);
    }

    fn known(&self, state: &State, repo: &RepoRef) -> Result<(), GitHostError> {
        if state
            .repos
            .contains_key(&repo.to_string().to_ascii_lowercase())
        {
            Ok(())
        } else {
            Err(GitHostError::NotFound)
        }
    }

    /// The branch a call really uses: the one named, or, with the defect, the rules branch.
    fn branch(&self, named: ProposalBranch) -> &'static str {
        if self.is(ProposalDefect::IgnoresTheBranch) {
            ProposalBranch::ProjectRules.name()
        } else {
            named.name()
        }
    }

    fn latest(&self, repo: &mut Repo, branch: &str) -> Option<Pull> {
        let trust_anyone = self.is(ProposalDefect::TrustsAnyAuthor);
        repo.pulls
            .iter()
            .filter(|p| p.head == branch && (p.by_factory || trust_anyone))
            .max_by_key(|p| p.number)
            .cloned()
    }
}

/// The repository a call reaches: the scope's, or, with the defect, another one the fake knows.
fn reach(fake: &FakeProposalHost, state: &State, scope: &ProposalScope) -> RepoRef {
    if fake.is(ProposalDefect::IgnoresTheScope)
        && !state
            .repos
            .contains_key(&scope.repo.to_string().to_ascii_lowercase())
        && let Some(other) = state.repos.keys().next()
        && let Ok(other) = RepoRef::parse(other)
    {
        return other;
    }
    scope.repo.clone()
}

#[async_trait]
impl ProposalHost for FakeProposalHost {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn default_branch(&self, scope: &ProposalScope) -> Result<DefaultBranch, GitHostError> {
        let mut state = self.lock();
        let repo = reach(self, &state, scope);
        self.known(&state, &repo)?;
        self.note_credential(&mut state);
        let stale = self.is(ProposalDefect::ReportsAStaleTip);
        let target = state.repo(&repo);
        let tip = if stale {
            target.commits.keys().next().cloned()
        } else {
            target
                .branches
                .get(DEFAULT_BRANCH)
                .map(|b| b.commit.clone())
        }
        .ok_or(GitHostError::NotFound)?;
        Ok(DefaultBranch {
            name: BranchName::new(DEFAULT_BRANCH).map_err(|_| GitHostError::Unavailable)?,
            commit: CommitSha::parse(&tip).map_err(|_| GitHostError::Unavailable)?,
        })
    }

    async fn read_file(
        &self,
        scope: &ProposalScope,
        commit: &CommitSha,
        path: &RepoPath,
        max_bytes: u64,
    ) -> Result<FileAt, GitHostError> {
        let mut state = self.lock();
        let repo = reach(self, &state, scope);
        self.known(&state, &repo)?;
        self.note_credential(&mut state);
        let files = state
            .repo(&repo)
            .commits
            .get(commit.as_str())
            .cloned()
            .ok_or(GitHostError::NotFound)?;
        Ok(match files.get(path.as_str()) {
            None => FileAt::Missing,
            Some(bytes)
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes
                    && !self.is(ProposalDefect::IgnoresTheSizeLimit) =>
            {
                FileAt::TooLarge
            }
            Some(bytes) => FileAt::Found(bytes.clone()),
        })
    }

    async fn latest_pull_request(
        &self,
        scope: &ProposalScope,
        branch: ProposalBranch,
    ) -> Result<Option<ProposalPullRequest>, GitHostError> {
        let mut state = self.lock();
        let repo = reach(self, &state, scope);
        self.known(&state, &repo)?;
        self.note_credential(&mut state);
        let name = self.branch(branch);
        let Some(pull) = self.latest(state.repo(&repo), name) else {
            return Ok(None);
        };
        let head = state
            .repo(&repo)
            .branches
            .get(name)
            .map(|b| b.commit.clone())
            .ok_or(GitHostError::Unavailable)?;
        Ok(Some(ProposalPullRequest {
            pr: PullRequestRef {
                repo: repo.clone(),
                number: pull.number,
            },
            lifecycle: pull.lifecycle,
            head: CommitSha::parse(&head).map_err(|_| GitHostError::Unavailable)?,
            marker: branch.marker_of(&pull.body),
        }))
    }

    async fn propose(
        &self,
        scope: &ProposalScope,
        proposal: &PullRequestProposal,
    ) -> Result<PullRequestRef, GitHostError> {
        if (proposal.title.trim().is_empty()
            || proposal.body.trim().is_empty()
            || proposal.files.is_empty())
            && !self.is(ProposalDefect::AcceptsEmptyText)
        {
            return Err(GitHostError::Rejected(Rejection::TextBounds));
        }
        if !proposal.branch.accepts(&proposal.marker) && !self.is(ProposalDefect::IgnoresTheBranch)
        {
            return Err(GitHostError::Rejected(Rejection::Other));
        }
        if ProposalBranch::ALL
            .iter()
            .any(|b| b.name() == proposal.base.name.as_str())
        {
            return Err(GitHostError::BranchNotAllowed);
        }
        let branch = self.branch(proposal.branch);
        if !self.is(ProposalDefect::SkipsSecretCheck)
            && (looks_like_a_secret(&proposal.body) || looks_like_a_secret(&proposal.title))
        {
            return Err(GitHostError::UnsafeText);
        }
        let mut state = self.lock();
        let repo = reach(self, &state, scope);
        self.known(&state, &repo)?;
        self.note_credential(&mut state);
        let open = self
            .latest(state.repo(&repo), branch)
            .filter(|p| p.lifecycle == PullRequestLifecycle::Open && p.by_factory)
            .filter(|_| !self.is(ProposalDefect::OpensASecondPullRequest));
        let target = if self.is(ProposalDefect::WritesTheDefaultBranch) {
            DEFAULT_BRANCH
        } else {
            branch
        };
        // No open pull request: the branch starts again from the commit given.
        let kept = self.is(ProposalDefect::KeepsAClosedBranch)
            && state.repo(&repo).branches.contains_key(branch);
        if (open.is_none() || self.is(ProposalDefect::ResetsAnOpenBranch))
            && target == branch
            && !kept
        {
            let files = state
                .repo(&repo)
                .commits
                .get(proposal.base.commit.as_str())
                .cloned()
                .ok_or(GitHostError::Conflict)?;
            state.repo(&repo).branches.insert(
                branch.to_owned(),
                Branch {
                    commit: proposal.base.commit.as_str().to_owned(),
                    files,
                },
            );
        }
        let current = state
            .repo(&repo)
            .branches
            .get(target)
            .map(|b| b.files.clone())
            .unwrap_or_default();
        for file in &proposal.files {
            if current.get(file.path.as_str()) != Some(&file.bytes) {
                state.commit(
                    &repo,
                    target,
                    &[(file.path.as_str(), Some(file.bytes.clone()))],
                );
            }
        }
        let body = if self.is(ProposalDefect::ForgetsTheMarker) {
            proposal.body.clone()
        } else {
            format!("{}\n\n{}", proposal.body, proposal.marker.text())
        };
        let draft = !self.is(ProposalDefect::OpensReadyPullRequests);
        let pulls = &mut state.repo(&repo).pulls;
        if let Some(open) = open
            && let Some(pull) = pulls.iter_mut().find(|p| p.number == open.number)
        {
            pull.title.clone_from(&proposal.title);
            pull.body = body;
            return Ok(PullRequestRef {
                repo,
                number: pull.number,
            });
        }
        let number = u64::try_from(pulls.len()).unwrap_or(u64::MAX) + 1;
        pulls.push(Pull {
            number,
            head: branch.to_owned(),
            base: proposal.base.name.as_str().to_owned(),
            title: proposal.title.clone(),
            body,
            draft,
            lifecycle: PullRequestLifecycle::Open,
            by_factory: true,
        });
        Ok(PullRequestRef { repo, number })
    }
}

#[async_trait]
impl ProposalSubject for FakeProposalHost {
    fn host(&self) -> &dyn ProposalHost {
        self
    }

    async fn person_commit(&self, branch: &str, changes: &[(&str, Option<&str>)]) {
        FakeProposalHost::person_commit(self, &suite_repo(), branch, changes);
    }

    async fn files_on(&self, branch: &str) -> BTreeMap<String, String> {
        FakeProposalHost::files_on(self, &suite_repo(), branch)
            .into_iter()
            .map(|(path, bytes)| (path, String::from_utf8_lossy(&bytes).into_owned()))
            .collect()
    }

    async fn pulls(&self) -> Vec<SeenPull> {
        FakeProposalHost::pulls(self, &suite_repo())
            .into_iter()
            .map(|p| SeenPull {
                number: p.number,
                head: p.head,
                base: p.base,
                body: p.body,
                draft: p.draft,
                lifecycle: p.lifecycle,
            })
            .collect()
    }

    async fn close(&self, number: u64, merged: bool) {
        if merged {
            self.merge(&suite_repo(), number);
        } else {
            FakeProposalHost::close(self, &suite_repo(), number);
        }
    }

    async fn person_pull_request(&self, head: &str, body: &str) {
        FakeProposalHost::person_pull_request(self, &suite_repo(), head, body);
    }

    async fn permissions_asked(&self) -> Vec<Vec<(String, String)>> {
        FakeProposalHost::permissions_asked(self)
    }
}

impl FakeProposalHost {
    /// A fake that already holds the repository of the contract suites, with an empty default
    /// branch.
    #[must_use]
    pub fn with_suite_repository() -> Self {
        let fake = Self::new();
        fake.person_commit(&suite_repo(), DEFAULT_BRANCH, &[]);
        fake
    }

    /// The same, with one deliberate defect.
    #[must_use]
    pub fn with_suite_repository_and_defect(defect: ProposalDefect) -> Self {
        let fake = Self::with_defect(defect);
        fake.person_commit(&suite_repo(), DEFAULT_BRANCH, &[]);
        fake
    }
}
