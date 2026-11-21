//! `FakePullRequestFates`: the pull requests of one repository and what a person did with each,
//! behind the port [`PullRequestFateSource`] (ports v1.5).
//!
//! The fake keeps a list and reads its clock; it calls nothing. A deliberate defect breaks one
//! documented rule, so the contract suite (`contracts::pull_request_fate`) can be shown to fail
//! when the rule is broken.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::values::Timestamp;
use factory_domain::vocabulary::Fidelity;
use factory_ports::clock::Clock;
use factory_ports::githost::{GitHostError, PullRequestRef};
use factory_ports::paths::RepoRef;
use factory_ports::pull_request_fate::{FateScope, ObservedPullRequest, PullRequestFateSource};

use crate::clock::FakeClock;
use crate::contracts::pull_request_fate::PullRequestFateSubject;

/// A deliberate defect of the fake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PullRequestFateDefect {
    /// A pull request nobody decided about is reported as closed.
    ReportsOpenAsClosed,
    /// A merged pull request is reported as closed without a merge.
    ReportsAMergeAsAClose,
    /// A pull request closed without a merge is reported as merged.
    ReportsACloseAsAMerge,
    /// The time of the look is reported in place of the time of the decision.
    ReportsTheTimeOfTheLook,
    /// A pull request of another repository than the scope's, or one that does not exist, is
    /// answered as an open one.
    IgnoresTheScope,
    /// The credential asked for can write pull requests.
    AsksForAWriteToken,
}

/// Each defect and the checks of `contracts::pull_request_fate` that must fail when the fake has
/// it.
pub const PULL_REQUEST_FATE_DEFECTS: &[(PullRequestFateDefect, &[&str])] = &[
    (
        PullRequestFateDefect::ReportsOpenAsClosed,
        &["an_open_pull_request_is_open_and_has_no_time"],
    ),
    (
        PullRequestFateDefect::ReportsAMergeAsAClose,
        &["a_merge_is_reported_with_the_time_of_the_merge"],
    ),
    (
        PullRequestFateDefect::ReportsACloseAsAMerge,
        &["a_close_without_a_merge_is_reported_with_the_time_of_the_close"],
    ),
    (
        PullRequestFateDefect::ReportsTheTimeOfTheLook,
        &[
            "a_merge_is_reported_with_the_time_of_the_merge",
            "a_close_without_a_merge_is_reported_with_the_time_of_the_close",
        ],
    ),
    (
        PullRequestFateDefect::IgnoresTheScope,
        &["a_pull_request_the_scope_does_not_cover_is_not_found"],
    ),
    (
        PullRequestFateDefect::AsksForAWriteToken,
        &["the_credential_reads_pull_requests_and_nothing_else"],
    ),
];

/// How a pull request was closed, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Decision {
    merged: bool,
    at: Timestamp,
}

#[derive(Debug, Default)]
struct State {
    /// The pull requests by number: `None` while open.
    pulls: BTreeMap<u64, Option<Decision>>,
    /// The permission sets asked for, one for each look.
    asked: Vec<Vec<(String, String)>>,
    /// The next look fails with this error, once.
    fail_next: Option<GitHostError>,
}

/// The in-memory fate source.
#[derive(Debug)]
pub struct FakePullRequestFates {
    repo: RepoRef,
    clock: Arc<FakeClock>,
    defect: Option<PullRequestFateDefect>,
    state: Mutex<State>,
}

impl FakePullRequestFates {
    /// A fake for `repo` with no pull request, on a clock of its own.
    #[must_use]
    pub fn new(repo: RepoRef) -> Self {
        Self::on_clock(repo, Arc::new(FakeClock::new()))
    }

    /// A fake for `repo` that reads this clock. Share it with the code under test so that both
    /// see the same time.
    #[must_use]
    pub fn on_clock(repo: RepoRef, clock: Arc<FakeClock>) -> Self {
        Self {
            repo,
            clock,
            defect: None,
            state: Mutex::new(State::default()),
        }
    }

    /// A fake for the repository of the contract suite.
    #[must_use]
    pub fn with_suite_repository() -> Self {
        Self::new(crate::contracts::githost::repo())
    }

    /// The same, with one deliberate defect.
    #[must_use]
    pub fn with_suite_repository_and_defect(defect: PullRequestFateDefect) -> Self {
        Self {
            defect: Some(defect),
            ..Self::with_suite_repository()
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn is(&self, defect: PullRequestFateDefect) -> bool {
        self.defect == Some(defect)
    }

    /// A person opens pull request `number`. Opening one that exists makes it open again.
    pub fn open(&self, number: u64) {
        self.lock().pulls.insert(number, None);
    }

    /// A person closes pull request `number` now, merged or not.
    ///
    /// # Panics
    /// Panics when the pull request is not known: a test that closes one it never opened is wrong.
    pub fn close_pull(&self, number: u64, merged: bool) {
        let at = self.clock.now();
        let mut state = self.lock();
        let pull = state.pulls.get_mut(&number).expect("a known pull request");
        *pull = Some(Decision { merged, at });
    }

    /// The next look fails with `error`, and the one after it works again.
    pub fn fail_next_look(&self, error: GitHostError) {
        self.lock().fail_next = Some(error);
    }

    /// How many looks were made.
    #[must_use]
    pub fn looks(&self) -> usize {
        self.lock().asked.len()
    }
}

#[async_trait]
impl PullRequestFateSource for FakePullRequestFates {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn observe(
        &self,
        scope: &FateScope,
        pr: &PullRequestRef,
    ) -> Result<ObservedPullRequest, GitHostError> {
        let pulls = if self.is(PullRequestFateDefect::AsksForAWriteToken) {
            "write"
        } else {
            "read"
        };
        let mut state = self.lock();
        state.asked.push(vec![
            ("metadata".to_owned(), "read".to_owned()),
            ("pull_requests".to_owned(), pulls.to_owned()),
        ]);
        if let Some(error) = state.fail_next.take() {
            return Err(error);
        }
        let in_scope = scope.repo == self.repo && pr.repo == self.repo;
        let found = state.pulls.get(&pr.number).copied().filter(|_| in_scope);
        let decision = match found {
            Some(decision) => decision,
            None if self.is(PullRequestFateDefect::IgnoresTheScope) => None,
            None => return Err(GitHostError::NotFound),
        };
        let now = self.clock.now();
        Ok(match decision {
            None if self.is(PullRequestFateDefect::ReportsOpenAsClosed) => {
                ObservedPullRequest::closed(now)
            }
            None => ObservedPullRequest::OPEN,
            Some(Decision { merged, at }) => {
                let at = if self.is(PullRequestFateDefect::ReportsTheTimeOfTheLook) {
                    now
                } else {
                    at
                };
                let merged = match self.defect {
                    Some(PullRequestFateDefect::ReportsAMergeAsAClose) => false,
                    Some(PullRequestFateDefect::ReportsACloseAsAMerge) => true,
                    _ => merged,
                };
                if merged {
                    ObservedPullRequest::merged(at)
                } else {
                    ObservedPullRequest::closed(at)
                }
            }
        })
    }
}

#[async_trait]
impl PullRequestFateSubject for FakePullRequestFates {
    fn source(&self) -> &dyn PullRequestFateSource {
        self
    }

    async fn open_pull_request(&self) -> u64 {
        let mut state = self.lock();
        let number = state.pulls.keys().next_back().map_or(1, |last| last + 1);
        state.pulls.insert(number, None);
        number
    }

    async fn close(&self, number: u64, merged: bool) {
        self.close_pull(number, merged);
    }

    async fn host_time(&self) -> Timestamp {
        self.clock.now()
    }

    async fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    async fn permissions_asked(&self) -> Vec<Vec<(String, String)>> {
        self.lock().asked.clone()
    }
}
