//! `FakeTriageIssues`: the troubleshooter's triage issue writer of ports v1.3 kept in memory (ADR
//! 0021, Decision 7).
//!
//! **This is a fake.** It reports fidelity `fake`, and a production run refuses it. It keeps the
//! issues and comments of one configured repository, applies the rules of the port (the
//! fingerprint is read from the body of the factory's own open issues that carry the label
//! `troubleshooter`, and only from a line that is exactly the marker; look before writing; only
//! the configured repository; secrets refused; an ended run gets nothing) and records the
//! permissions the real adapter would have asked for. It sends nothing anywhere.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use async_trait::async_trait;
use factory_domain::policy::troubleshooting::Issues;
use factory_domain::troubleshooting::issue::{SeenAgainComment, TriageIssue};
use factory_domain::troubleshooting::{
    FindingFingerprint, TRIAGE_LABEL, TriageLabels, TroubleshootingRunId, check_triage_label_name,
};
use factory_domain::vocabulary::Fidelity;
use factory_ports::githost::{CommentRef, CommentTarget, GitHostError, IssueRef, Rejection};
use factory_ports::paths::RepoRef;
use factory_ports::triage_issue::{OpenedIssue, RunScope, SeenAgainPost, TriageIssueWriter};

use crate::contracts::triage_issue::TriageIssueSubject;
use crate::githost::looks_like_a_secret;

/// The labels of `issues.labels` in `policies/troubleshooting.yaml`, made through the same check
/// as the real policy. The domain's tests compare the list with the file.
///
/// # Panics
/// Never: the labels are sound.
#[must_use]
pub fn triage_labels() -> TriageLabels {
    TriageLabels::from_policy(&Issues {
        max_new_per_day: 3,
        max_comments_per_issue_per_day: 1,
        labels: vec![TRIAGE_LABEL.to_owned(), "troubleshooter: triage".to_owned()],
    })
    .expect("the policy's labels are triage labels")
}

/// A deliberate fault, for proving that the contract suite can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriageIssueDefect {
    /// The body is cleaned like other Markdown, which drops HTML comments and so the marker.
    StripsTheMarker,
    /// The marker is also read from comments.
    ReadsMarkersInComments,
    /// An issue a person opened counts.
    TrustsAnyAuthor,
    /// A marker anywhere in the body counts, not only on a line of its own.
    ReadsMarkersInsideText,
    /// Opening does not look first.
    OpensDuplicates,
    /// Closed issues are found.
    FindsClosedIssues,
    /// "Seen again" is posted every time.
    CommentsTwice,
    /// Text is not checked for secrets.
    SkipsSecretCheck,
    /// Any repository is accepted.
    IgnoresTheRepository,
    /// The credential asks for more than `issues: write`.
    AsksForMoreThanIssuesWrite,
    /// A run's credential survives the end of the run.
    KeepsTokensAfterTheRun,
}

/// The defects, and the checks of the contract that must fail with each.
pub const TRIAGE_ISSUE_DEFECTS: &[(TriageIssueDefect, &[&str])] = &[
    (
        TriageIssueDefect::StripsTheMarker,
        &["an_issue_opens_with_the_template_text_and_the_policy_labels"],
    ),
    (
        TriageIssueDefect::ReadsMarkersInComments,
        &["the_marker_counts_only_in_the_body_of_the_factorys_own_open_issue"],
    ),
    (
        TriageIssueDefect::TrustsAnyAuthor,
        &["the_marker_counts_only_in_the_body_of_the_factorys_own_open_issue"],
    ),
    (
        TriageIssueDefect::ReadsMarkersInsideText,
        &["the_marker_counts_only_in_the_body_of_the_factorys_own_open_issue"],
    ),
    (
        TriageIssueDefect::OpensDuplicates,
        &["opening_twice_keeps_one_issue"],
    ),
    (
        TriageIssueDefect::FindsClosedIssues,
        &["a_closed_issue_is_not_found"],
    ),
    (
        TriageIssueDefect::CommentsTwice,
        &["saying_seen_again_twice_in_a_run_posts_one_comment"],
    ),
    (
        TriageIssueDefect::SkipsSecretCheck,
        &["text_with_a_secret_is_not_written"],
    ),
    (
        TriageIssueDefect::IgnoresTheRepository,
        &["a_scope_for_another_repository_is_refused"],
    ),
    (
        TriageIssueDefect::AsksForMoreThanIssuesWrite,
        &["the_credential_is_issues_write_and_metadata_read"],
    ),
    (
        TriageIssueDefect::KeepsTokensAfterTheRun,
        &["an_ended_run_gets_no_credential"],
    ),
];

#[derive(Debug, Clone)]
struct FakeIssue {
    body: String,
    labels: Vec<String>,
    by_app: bool,
    open: bool,
    /// `(id, by_app, body)`.
    comments: Vec<(u64, bool, String)>,
}

#[derive(Debug, Default)]
struct State {
    issues: BTreeMap<u64, FakeIssue>,
    next_id: u64,
    asked: Vec<Vec<(String, String)>>,
    runs_with_token: BTreeSet<String>,
    ended: BTreeSet<String>,
}

/// The triage issue writer kept in memory, for one configured repository.
#[derive(Debug)]
pub struct FakeTriageIssues {
    repository: RepoRef,
    other: RepoRef,
    defect: Option<TriageIssueDefect>,
    state: Mutex<State>,
}

impl Default for FakeTriageIssues {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeTriageIssues {
    /// A writer for `example-org/fixture` with no defect.
    ///
    /// # Panics
    /// Never: the names are valid.
    #[must_use]
    pub fn new() -> Self {
        Self {
            repository: RepoRef::parse("example-org/fixture").expect("a repository"),
            other: RepoRef::parse("example-org/other").expect("a repository"),
            defect: None,
            state: Mutex::new(State {
                next_id: 1,
                ..State::default()
            }),
        }
    }

    /// A writer with a deliberate defect.
    #[must_use]
    pub fn with_defect(defect: TriageIssueDefect) -> Self {
        Self {
            defect: Some(defect),
            ..Self::new()
        }
    }

    fn has(&self, defect: TriageIssueDefect) -> bool {
        self.defect == Some(defect)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The scope check and the credential, as the adapter does them.
    fn credential(&self, scope: &RunScope) -> Result<(), GitHostError> {
        if !self.has(TriageIssueDefect::IgnoresTheRepository)
            && !scope.repo.same_repository(&self.repository)
        {
            return Err(GitHostError::Forbidden);
        }
        let mut state = self.state();
        let run = scope.run.as_str().to_owned();
        if state.ended.contains(&run) && !self.has(TriageIssueDefect::KeepsTokensAfterTheRun) {
            return Err(GitHostError::Unauthorized);
        }
        if state.runs_with_token.insert(run) {
            let mut set = vec![
                ("issues".to_owned(), "write".to_owned()),
                ("metadata".to_owned(), "read".to_owned()),
            ];
            if self.has(TriageIssueDefect::AsksForMoreThanIssuesWrite) {
                set.insert(0, ("contents".to_owned(), "write".to_owned()));
            }
            state.asked.push(set);
        }
        Ok(())
    }

    fn reads_marker(&self, issue: &FakeIssue, fingerprint: &FindingFingerprint) -> bool {
        let marker = fingerprint.marker();
        let in_body = if self.has(TriageIssueDefect::ReadsMarkersInsideText) {
            issue.body.contains(&marker)
        } else {
            FindingFingerprint::from_body(&issue.body).as_ref() == Some(fingerprint)
        };
        let in_comment = self.has(TriageIssueDefect::ReadsMarkersInComments)
            && issue.comments.iter().any(|(_, _, c)| c.contains(&marker));
        in_body || in_comment
    }

    fn find(&self, fingerprint: &FindingFingerprint) -> Option<u64> {
        let state = self.state();
        state
            .issues
            .iter()
            .filter(|(_, i)| i.open || self.has(TriageIssueDefect::FindsClosedIssues))
            .filter(|(_, i)| i.by_app || self.has(TriageIssueDefect::TrustsAnyAuthor))
            .filter(|(_, i)| {
                i.labels
                    .iter()
                    .any(|l| l.eq_ignore_ascii_case(TRIAGE_LABEL))
            })
            .filter(|(_, i)| self.reads_marker(i, fingerprint))
            .map(|(n, _)| *n)
            .min()
    }

    fn insert(&self, body: &str, labels: &[&str], by_app: bool) -> u64 {
        let mut state = self.state();
        let number = state.next_id;
        state.next_id += 1;
        state.issues.insert(
            number,
            FakeIssue {
                body: body.to_owned(),
                labels: labels.iter().map(|l| (*l).to_owned()).collect(),
                by_app,
                open: true,
                comments: Vec::new(),
            },
        );
        number
    }

    fn secret_check(&self, texts: &[&str]) -> Result<(), GitHostError> {
        if !self.has(TriageIssueDefect::SkipsSecretCheck)
            && texts.iter().any(|t| looks_like_a_secret(t))
        {
            return Err(GitHostError::UnsafeText);
        }
        Ok(())
    }
}

#[async_trait]
impl TriageIssueWriter for FakeTriageIssues {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn find_open_issue(
        &self,
        scope: &RunScope,
        fingerprint: &FindingFingerprint,
    ) -> Result<Option<IssueRef>, GitHostError> {
        self.credential(scope)?;
        Ok(self.find(fingerprint).map(|number| IssueRef {
            repo: scope.repo.clone(),
            number,
        }))
    }

    async fn open_issue(
        &self,
        scope: &RunScope,
        issue: &TriageIssue,
    ) -> Result<OpenedIssue, GitHostError> {
        let labels = issue.labels().names();
        for name in &labels {
            check_triage_label_name(name)
                .map_err(|_| GitHostError::Rejected(Rejection::LabelNotAllowed))?;
        }
        if !self.has(TriageIssueDefect::IgnoresTheRepository)
            && !scope.repo.same_repository(&self.repository)
        {
            return Err(GitHostError::Forbidden);
        }
        self.secret_check(&[issue.title(), issue.body(), issue.agent_text()])?;
        self.credential(scope)?;
        if !self.has(TriageIssueDefect::OpensDuplicates)
            && let Some(number) = self.find(issue.fingerprint())
        {
            return Ok(OpenedIssue::AlreadyOpen(IssueRef {
                repo: scope.repo.clone(),
                number,
            }));
        }
        let body = if self.has(TriageIssueDefect::StripsTheMarker) {
            issue.body_before_marker()
        } else {
            issue.body()
        };
        let number = self.insert(body, &labels, true);
        Ok(OpenedIssue::Opened(IssueRef {
            repo: scope.repo.clone(),
            number,
        }))
    }

    async fn post_seen_again(
        &self,
        scope: &RunScope,
        issue: &IssueRef,
        comment: &SeenAgainComment,
    ) -> Result<SeenAgainPost, GitHostError> {
        self.credential(scope)?;
        if !scope.repo.same_repository(&issue.repo) {
            return Err(GitHostError::NotFound);
        }
        self.secret_check(&[comment.body(), comment.agent_text()])?;
        let reference = |id: u64| CommentRef {
            target: CommentTarget::Issue(issue.clone()),
            id,
        };
        let mut state = self.state();
        let id = state.next_id;
        state.next_id += 1;
        let found = state
            .issues
            .get_mut(&issue.number)
            .ok_or(GitHostError::NotFound)?;
        if !self.has(TriageIssueDefect::CommentsTwice)
            && let Some((id, _, _)) = found
                .comments
                .iter()
                .find(|(_, by_app, body)| *by_app && body.contains(comment.key()))
        {
            return Ok(SeenAgainPost::AlreadyThere(reference(*id)));
        }
        found.comments.push((id, true, comment.body().to_owned()));
        Ok(SeenAgainPost::Posted(reference(id)))
    }

    async fn revoke_run_tokens(&self, run: &TroubleshootingRunId) -> Result<(), GitHostError> {
        let mut state = self.state();
        state.runs_with_token.remove(run.as_str());
        state.ended.insert(run.as_str().to_owned());
        Ok(())
    }
}

#[async_trait]
impl TriageIssueSubject for FakeTriageIssues {
    fn writer(&self) -> &dyn TriageIssueWriter {
        self
    }

    fn repository(&self) -> RepoRef {
        self.repository.clone()
    }

    fn other_repository(&self) -> RepoRef {
        self.other.clone()
    }

    async fn seed_app_issue(&self, body: &str, labels: &[&str]) -> u64 {
        self.insert(body, labels, true)
    }

    async fn seed_person_issue(&self, body: &str, labels: &[&str]) -> u64 {
        self.insert(body, labels, false)
    }

    async fn seed_person_comment(&self, number: u64, body: &str) {
        let mut state = self.state();
        let id = state.next_id;
        state.next_id += 1;
        if let Some(issue) = state.issues.get_mut(&number) {
            issue.comments.push((id, false, body.to_owned()));
        }
    }

    async fn close(&self, number: u64) {
        if let Some(issue) = self.state().issues.get_mut(&number) {
            issue.open = false;
        }
    }

    async fn open_issues(&self) -> Vec<u64> {
        self.state()
            .issues
            .iter()
            .filter(|(_, i)| i.open)
            .map(|(n, _)| *n)
            .collect()
    }

    async fn issue(&self, number: u64) -> Option<(String, Vec<String>)> {
        self.state()
            .issues
            .get(&number)
            .map(|i| (i.body.clone(), i.labels.clone()))
    }

    async fn app_comments(&self, number: u64) -> Vec<String> {
        self.state()
            .issues
            .get(&number)
            .map(|i| {
                i.comments
                    .iter()
                    .filter(|(_, by_app, _)| *by_app)
                    .map(|(_, _, b)| b.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn permissions_asked(&self) -> Vec<Vec<(String, String)>> {
        self.state().asked.clone()
    }
}
