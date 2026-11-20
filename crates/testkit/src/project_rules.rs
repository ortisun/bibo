//! An in-memory fake of `ProjectRulesHost` (ports v1.4, ADR 0026), with deliberate defects that
//! the contract suite must catch.
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
use factory_ports::project_rules::{
    DefaultBranch, FileAt, ProjectRulesHost, RULES_BRANCH, RulesProposal, RulesPullRequest,
    RulesScope, proposal_marker, proposed_version,
};

use crate::contracts::githost::repo as suite_repo;
use crate::contracts::project_rules::{ProjectRulesSubject, SeenPull};
use crate::githost::looks_like_a_secret;

/// The default branch of every repository of the fake.
pub const DEFAULT_BRANCH: &str = "main";

/// A deliberate defect. Each one breaks one rule of the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectRulesDefect {
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
}

/// Each defect, and the checks of the suite that must fail with it.
pub const PROJECT_RULES_DEFECTS: &[(ProjectRulesDefect, &[&str])] = &[
    (
        ProjectRulesDefect::WritesTheDefaultBranch,
        &["a_proposal_is_one_draft_pull_request_and_the_default_branch_is_untouched"],
    ),
    (
        ProjectRulesDefect::OpensASecondPullRequest,
        &["proposing_again_opens_no_second_pull_request"],
    ),
    (
        ProjectRulesDefect::OpensReadyPullRequests,
        &["a_proposal_is_one_draft_pull_request_and_the_default_branch_is_untouched"],
    ),
    (
        ProjectRulesDefect::ForgetsTheMarker,
        &["the_latest_pull_request_carries_its_state_and_version"],
    ),
    (
        ProjectRulesDefect::TrustsAnyAuthor,
        &["a_pull_request_a_person_opened_from_the_rules_branch_is_not_the_factorys"],
    ),
    (
        ProjectRulesDefect::ResetsAnOpenBranch,
        &["an_open_proposal_is_updated_on_top_and_a_persons_commit_is_kept"],
    ),
    (
        ProjectRulesDefect::SkipsSecretCheck,
        &["a_body_with_a_secret_is_not_sent"],
    ),
    (
        ProjectRulesDefect::AsksForAWiderToken,
        &["the_credential_is_contents_and_pull_requests_write_and_nothing_else"],
    ),
    (
        ProjectRulesDefect::IgnoresTheScope,
        &["a_scope_for_another_repository_reaches_nothing"],
    ),
    (
        ProjectRulesDefect::IgnoresTheSizeLimit,
        &["a_file_is_missing_found_or_too_large"],
    ),
    (
        ProjectRulesDefect::ReportsAStaleTip,
        &["the_default_branch_is_read_with_its_tip"],
    ),
    (
        ProjectRulesDefect::KeepsAClosedBranch,
        &["a_new_proposal_after_a_closed_one_starts_from_the_default_branch"],
    ),
    (
        ProjectRulesDefect::AcceptsEmptyText,
        &["an_empty_title_or_no_file_is_refused"],
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
pub struct FakeProjectRulesHost {
    state: Mutex<State>,
    defect: Option<ProjectRulesDefect>,
}

impl FakeProjectRulesHost {
    /// A fake with no repository yet. A repository is made, empty, the first time it is named.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A fake with one deliberate defect.
    #[must_use]
    pub fn with_defect(defect: ProjectRulesDefect) -> Self {
        Self {
            state: Mutex::new(State::default()),
            defect: Some(defect),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn is(&self, defect: ProjectRulesDefect) -> bool {
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
        if self.is(ProjectRulesDefect::AsksForAWiderToken) {
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

    fn latest(&self, repo: &mut Repo) -> Option<Pull> {
        let trust_anyone = self.is(ProjectRulesDefect::TrustsAnyAuthor);
        repo.pulls
            .iter()
            .filter(|p| p.head == RULES_BRANCH && (p.by_factory || trust_anyone))
            .max_by_key(|p| p.number)
            .cloned()
    }
}

/// The repository a call reaches: the scope's, or, with the defect, another one the fake knows.
fn reach(fake: &FakeProjectRulesHost, state: &State, scope: &RulesScope) -> RepoRef {
    if fake.is(ProjectRulesDefect::IgnoresTheScope)
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
impl ProjectRulesHost for FakeProjectRulesHost {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn default_branch(&self, scope: &RulesScope) -> Result<DefaultBranch, GitHostError> {
        let mut state = self.lock();
        let repo = reach(self, &state, scope);
        self.known(&state, &repo)?;
        self.note_credential(&mut state);
        let stale = self.is(ProjectRulesDefect::ReportsAStaleTip);
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
        scope: &RulesScope,
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
                    && !self.is(ProjectRulesDefect::IgnoresTheSizeLimit) =>
            {
                FileAt::TooLarge
            }
            Some(bytes) => FileAt::Found(bytes.clone()),
        })
    }

    async fn latest_rules_pull_request(
        &self,
        scope: &RulesScope,
    ) -> Result<Option<RulesPullRequest>, GitHostError> {
        let mut state = self.lock();
        let repo = reach(self, &state, scope);
        self.known(&state, &repo)?;
        self.note_credential(&mut state);
        let latest = self.latest(state.repo(&repo));
        Ok(latest.map(|pull| RulesPullRequest {
            pr: PullRequestRef {
                repo: repo.clone(),
                number: pull.number,
            },
            lifecycle: pull.lifecycle,
            proposed_version: proposed_version(&pull.body),
        }))
    }

    async fn propose(
        &self,
        scope: &RulesScope,
        proposal: &RulesProposal,
    ) -> Result<PullRequestRef, GitHostError> {
        if (proposal.title.trim().is_empty()
            || proposal.body.trim().is_empty()
            || proposal.files.is_empty())
            && !self.is(ProjectRulesDefect::AcceptsEmptyText)
        {
            return Err(GitHostError::Rejected(Rejection::TextBounds));
        }
        if proposal.base.name.as_str() == RULES_BRANCH {
            return Err(GitHostError::BranchNotAllowed);
        }
        if !self.is(ProjectRulesDefect::SkipsSecretCheck)
            && (looks_like_a_secret(&proposal.body) || looks_like_a_secret(&proposal.title))
        {
            return Err(GitHostError::UnsafeText);
        }
        let mut state = self.lock();
        let repo = reach(self, &state, scope);
        self.known(&state, &repo)?;
        self.note_credential(&mut state);
        let open = self
            .latest(state.repo(&repo))
            .filter(|p| p.lifecycle == PullRequestLifecycle::Open && p.by_factory)
            .filter(|_| !self.is(ProjectRulesDefect::OpensASecondPullRequest));
        let target = if self.is(ProjectRulesDefect::WritesTheDefaultBranch) {
            DEFAULT_BRANCH
        } else {
            RULES_BRANCH
        };
        // No open pull request: the branch starts again from the commit given.
        let kept = self.is(ProjectRulesDefect::KeepsAClosedBranch)
            && state.repo(&repo).branches.contains_key(RULES_BRANCH);
        if (open.is_none() || self.is(ProjectRulesDefect::ResetsAnOpenBranch))
            && target == RULES_BRANCH
            && !kept
        {
            let files = state
                .repo(&repo)
                .commits
                .get(proposal.base.commit.as_str())
                .cloned()
                .ok_or(GitHostError::Conflict)?;
            state.repo(&repo).branches.insert(
                RULES_BRANCH.to_owned(),
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
        let body = if self.is(ProjectRulesDefect::ForgetsTheMarker) {
            proposal.body.clone()
        } else {
            format!("{}\n\n{}", proposal.body, proposal_marker(proposal.version))
        };
        let draft = !self.is(ProjectRulesDefect::OpensReadyPullRequests);
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
            head: RULES_BRANCH.to_owned(),
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
impl ProjectRulesSubject for FakeProjectRulesHost {
    fn host(&self) -> &dyn ProjectRulesHost {
        self
    }

    async fn person_commit(&self, branch: &str, changes: &[(&str, Option<&str>)]) {
        FakeProjectRulesHost::person_commit(self, &suite_repo(), branch, changes);
    }

    async fn files_on(&self, branch: &str) -> BTreeMap<String, String> {
        FakeProjectRulesHost::files_on(self, &suite_repo(), branch)
            .into_iter()
            .map(|(path, bytes)| (path, String::from_utf8_lossy(&bytes).into_owned()))
            .collect()
    }

    async fn pulls(&self) -> Vec<SeenPull> {
        FakeProjectRulesHost::pulls(self, &suite_repo())
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
            FakeProjectRulesHost::close(self, &suite_repo(), number);
        }
    }

    async fn person_pull_request(&self, head: &str, body: &str) {
        FakeProjectRulesHost::person_pull_request(self, &suite_repo(), head, body);
    }

    async fn permissions_asked(&self) -> Vec<Vec<(String, String)>> {
        FakeProjectRulesHost::permissions_asked(self)
    }
}

impl FakeProjectRulesHost {
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
    pub fn with_suite_repository_and_defect(defect: ProjectRulesDefect) -> Self {
        let fake = Self::with_defect(defect);
        fake.person_commit(&suite_repo(), DEFAULT_BRANCH, &[]);
        fake
    }
}
