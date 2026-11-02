//! `FakeIssueStatusWriter`: the status writer of ports v1.2 kept in memory (ADR 0017).
//!
//! **This is a fake.** It reports fidelity `fake`, and a production run refuses it. It does what
//! the contract in `factory_ports::issue_status` says and nothing else: it keeps the labels and
//! comments of the issues it is told about, applies the rules of the port (only the `factory: `
//! namespace, one comment found by its marker among the comments of the factory's own account,
//! newest stamp wins), and records the permissions the real adapter would have asked for. It
//! sends nothing anywhere. It cannot show how the real GitHub answers.
//!
//! The labels a test needs come from [`status_labels`], which builds them from the rendered policy
//! `onboarding/github/issue-workflow.json` through the same validation as the real policy, so no
//! label name is written twice in this crate.

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use factory_domain::policy::issue_workflow::{
    IssueWorkflowPolicy, STATUS_PREFIX, StatusLabel, StatusLabels, check_status_label_name,
};
use factory_domain::vocabulary::Fidelity;
use factory_ports::githost::{CommentRef, CommentTarget, GitHostError, IssueRef, Rejection};
use factory_ports::issue_status::{
    CommentWrite, IssueStatusWriter, LabelOutcome, StatusComment, StatusScope, StatusStamp,
};
use factory_ports::paths::RepoRef;
use serde_json::{Value, json};

use crate::contracts::issue_status::IssueStatusSubject;
use crate::githost::looks_like_a_secret;

const RENDERED_POLICY: &str = include_str!("../../../onboarding/github/issue-workflow.json");

/// The status labels of the policy, built from the rendered policy file with the same validation
/// as the real one. Every call returns an equal value.
///
/// # Panics
/// When `onboarding/github/issue-workflow.json` is not a sound rendering. A test that reaches it
/// is testing against a broken repository.
#[must_use]
pub fn status_labels() -> StatusLabels {
    let rendered: Value = serde_json::from_str(RENDERED_POLICY).expect("the rendered policy");
    let factory: Vec<Value> = rendered["factory"]["job_states"]
        .as_object()
        .expect("job states")
        .iter()
        .map(|(state, label)| {
            let name = label
                .as_str()
                .and_then(|l| l.strip_prefix(STATUS_PREFIX))
                .expect("a factory label");
            json!({"job_state": state, "name": name, "color": "ededed", "description": "A state."})
        })
        .collect();
    let policy: IssueWorkflowPolicy = serde_json::from_value(json!({
        "schema_version": 1,
        "policy": {"id": "issue-workflow", "status": "designed"},
        "trigger": {"label": "factory", "color": "1d76db", "description": "The trigger."},
        "namespaces": {
            "design": {"prefix": "design: ", "written_by": "people"},
            "factory": {"prefix": "factory: ", "written_by": "factory"},
        },
        "design_track": {
            "start_states": ["proposed"],
            "states": [{"name": "proposed", "color": "c5def5", "description": "Proposed."}],
            "transitions": [],
            "approval_requires": {"design_document": {
                "issue_body_field": "Design document",
                "path_glob": "docs/designs/*.md",
            }},
        },
        "factory_track": {"states": factory},
        "intake_requirements": {"design_track_requires": "proposed"},
    }))
    .expect("a policy of the right shape");
    policy
        .status_labels()
        .expect("the rendered policy has a label for every job state")
}

/// A deliberate fault, for proving that the contract suite can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueStatusDefect {
    /// A label outside the `factory: ` namespace is accepted and written.
    AcceptsAnyLabel,
    /// The other `factory: ` labels stay on the issue.
    KeepsOldStatusLabels,
    /// Every other label is taken off, in every namespace.
    RemovesEveryOtherLabel,
    /// Taking off a label that is not there is an error.
    MissingRemovalIsAnError,
    /// Every status update makes a new comment.
    DuplicateComments,
    /// An update overwrites a comment that shows a newer stamp.
    IgnoresTheStamp,
    /// A comment a person wrote that carries the marker is taken for the status comment.
    TrustsAnyAuthor,
    /// Text is not checked for secrets.
    SkipsSecretCheck,
    /// The repository of the scope is not compared with the repository of the issue.
    IgnoresTheScope,
    /// The credential asks for more than `issues: write`.
    AsksForMoreThanIssuesWrite,
    /// A comment that already says the same is written again.
    RewritesTheSameText,
}

/// The defects, and the checks of the contract that must fail with each.
pub const ISSUE_STATUS_DEFECTS: &[(IssueStatusDefect, &[&str])] = &[
    (
        IssueStatusDefect::AcceptsAnyLabel,
        &["only_labels_of_the_factory_namespace_are_ever_written"],
    ),
    (
        IssueStatusDefect::KeepsOldStatusLabels,
        &[
            "a_status_label_replaces_every_other_factory_label",
            "setting_the_same_label_twice_changes_nothing",
        ],
    ),
    (
        IssueStatusDefect::RemovesEveryOtherLabel,
        &["a_status_label_replaces_every_other_factory_label"],
    ),
    (
        IssueStatusDefect::MissingRemovalIsAnError,
        &["a_label_that_is_not_there_is_not_an_error"],
    ),
    (
        IssueStatusDefect::DuplicateComments,
        &[
            "the_status_comment_is_made_once_and_edited_in_place",
            "repeating_the_same_comment_changes_nothing",
        ],
    ),
    (
        IssueStatusDefect::IgnoresTheStamp,
        &[
            "an_older_stamp_never_overwrites_a_newer_comment",
            "a_later_job_replaces_the_comment_of_an_earlier_one_and_not_the_other_way",
        ],
    ),
    (
        IssueStatusDefect::TrustsAnyAuthor,
        &["a_marker_pasted_by_a_person_is_not_the_status_comment"],
    ),
    (
        IssueStatusDefect::SkipsSecretCheck,
        &["text_with_a_secret_is_not_written"],
    ),
    (
        IssueStatusDefect::IgnoresTheScope,
        &["a_scope_for_another_repository_cannot_reach_the_issue"],
    ),
    (
        IssueStatusDefect::AsksForMoreThanIssuesWrite,
        &["the_credential_is_issues_write_and_nothing_else"],
    ),
    (
        IssueStatusDefect::RewritesTheSameText,
        &["repeating_the_same_comment_changes_nothing"],
    ),
];

#[derive(Debug, Clone)]
struct FakeComment {
    id: u64,
    by_the_app: bool,
    body: String,
}

#[derive(Debug, Default, Clone)]
struct FakeIssue {
    labels: Vec<String>,
    comments: Vec<FakeComment>,
}

#[derive(Default)]
struct State {
    issues: BTreeMap<(RepoRef, u64), FakeIssue>,
    next_comment: u64,
    permissions: Vec<Vec<(String, String)>>,
}

/// The status writer in memory. Reports fidelity `fake`.
pub struct FakeIssueStatusWriter {
    state: Mutex<State>,
    defect: Option<IssueStatusDefect>,
}

impl FakeIssueStatusWriter {
    /// A faithful fake.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
            defect: None,
        }
    }

    /// A fake that breaks one rule of the contract on purpose.
    #[must_use]
    pub fn with_defect(defect: IssueStatusDefect) -> Self {
        Self {
            state: Mutex::new(State::default()),
            defect: Some(defect),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("the lock is never poisoned")
    }

    fn is(&self, defect: IssueStatusDefect) -> bool {
        self.defect == Some(defect)
    }

    /// Puts labels on an issue, as people or other tools would have.
    pub fn seed_labels(&self, issue: &IssueRef, labels: &[&str]) {
        let mut state = self.lock();
        let entry = state
            .issues
            .entry((issue.repo.clone(), issue.number))
            .or_default();
        for label in labels {
            if !entry.labels.iter().any(|l| l == label) {
                entry.labels.push((*label).to_owned());
            }
        }
    }

    /// The labels on an issue, in the order they were added.
    #[must_use]
    pub fn labels_of(&self, issue: &IssueRef) -> Vec<String> {
        self.lock()
            .issues
            .get(&(issue.repo.clone(), issue.number))
            .map(|i| i.labels.clone())
            .unwrap_or_default()
    }

    /// A comment a person wrote.
    pub fn seed_person_comment(&self, issue: &IssueRef, body: &str) {
        let mut state = self.lock();
        state.next_comment += 1;
        let id = state.next_comment;
        state
            .issues
            .entry((issue.repo.clone(), issue.number))
            .or_default()
            .comments
            .push(FakeComment {
                id,
                by_the_app: false,
                body: body.to_owned(),
            });
    }

    /// Lands an older update on the issue **as a second worker's late write would**: GitHub has no
    /// conditional edit, so a write that listed the comments before a newer one was made can edit
    /// after it. This bypasses the rule that a newer stamp is never overwritten, on purpose, and
    /// only for a test of the step's second look at an end state (finding STS-3). It replaces the
    /// App's comment (or makes one) and puts `label` in place of every status label.
    pub fn land_a_late_write(&self, issue: &IssueRef, comment: &StatusComment, label: &str) {
        let full = format!("{}\n\n{}", comment.body(), comment.stamp().marker());
        let mut state = self.lock();
        state.next_comment += 1;
        let fresh = state.next_comment;
        let entry = state
            .issues
            .entry((issue.repo.clone(), issue.number))
            .or_default();
        match entry
            .comments
            .iter_mut()
            .filter(|c| c.by_the_app)
            .min_by_key(|c| c.id)
        {
            Some(found) => found.body = full,
            None => entry.comments.push(FakeComment {
                id: fresh,
                by_the_app: true,
                body: full,
            }),
        }
        entry.labels.retain(|l| !is_status_label(l));
        entry.labels.push(label.to_owned());
    }

    /// The text of the comments the factory's own account wrote on the issue.
    #[must_use]
    pub fn app_comments(&self, issue: &IssueRef) -> Vec<String> {
        self.comments(issue, true)
    }

    /// The text of the comments people wrote on the issue.
    #[must_use]
    pub fn person_comments(&self, issue: &IssueRef) -> Vec<String> {
        self.comments(issue, false)
    }

    fn comments(&self, issue: &IssueRef, by_the_app: bool) -> Vec<String> {
        self.lock()
            .issues
            .get(&(issue.repo.clone(), issue.number))
            .map(|i| {
                i.comments
                    .iter()
                    .filter(|c| c.by_the_app == by_the_app)
                    .map(|c| c.body.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The permission sets the writer asked a token for, one entry per call, sorted.
    #[must_use]
    pub fn permissions_asked(&self) -> Vec<Vec<(String, String)>> {
        self.lock().permissions.clone()
    }

    fn note_credential(&self, state: &mut State) {
        let mut asked = vec![
            ("issues".to_owned(), "write".to_owned()),
            ("metadata".to_owned(), "read".to_owned()),
        ];
        if self.is(IssueStatusDefect::AsksForMoreThanIssuesWrite) {
            asked.push(("contents".to_owned(), "write".to_owned()));
        }
        asked.sort();
        state.permissions.push(asked);
    }

    fn check_scope(&self, scope: &StatusScope, issue: &IssueRef) -> Result<(), GitHostError> {
        if scope.repo.same_repository(&issue.repo) || self.is(IssueStatusDefect::IgnoresTheScope) {
            Ok(())
        } else {
            Err(GitHostError::NotFound)
        }
    }
}

impl Default for FakeIssueStatusWriter {
    fn default() -> Self {
        Self::new()
    }
}

fn is_status_label(name: &str) -> bool {
    name.get(..STATUS_PREFIX.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(STATUS_PREFIX))
}

#[async_trait]
impl IssueStatusWriter for FakeIssueStatusWriter {
    fn fidelity(&self) -> Fidelity {
        Fidelity::Fake
    }

    async fn set_status_label(
        &self,
        scope: &StatusScope,
        issue: &IssueRef,
        label: &StatusLabel,
    ) -> Result<LabelOutcome, GitHostError> {
        if !self.is(IssueStatusDefect::AcceptsAnyLabel)
            && check_status_label_name(label.as_str()).is_err()
        {
            return Err(GitHostError::Rejected(Rejection::LabelNotAllowed));
        }
        self.check_scope(scope, issue)?;
        let mut state = self.lock();
        self.note_credential(&mut state);
        let entry = state
            .issues
            .entry((issue.repo.clone(), issue.number))
            .or_default();
        let wanted = label.as_str();
        let added = !entry.labels.iter().any(|l| l.eq_ignore_ascii_case(wanted));
        if added {
            entry.labels.push(wanted.to_owned());
        }
        let mut removed = 0;
        if !self.is(IssueStatusDefect::KeepsOldStatusLabels) {
            let every = self.is(IssueStatusDefect::RemovesEveryOtherLabel);
            let before = entry.labels.len();
            entry
                .labels
                .retain(|l| l.eq_ignore_ascii_case(wanted) || !(every || is_status_label(l)));
            removed = u32::try_from(before - entry.labels.len()).unwrap_or(u32::MAX);
        }
        if self.is(IssueStatusDefect::MissingRemovalIsAnError) && removed == 0 && !added {
            return Err(GitHostError::NotFound);
        }
        Ok(LabelOutcome { added, removed })
    }

    async fn upsert_status_comment(
        &self,
        scope: &StatusScope,
        issue: &IssueRef,
        comment: &StatusComment,
    ) -> Result<CommentWrite, GitHostError> {
        self.check_scope(scope, issue)?;
        if !self.is(IssueStatusDefect::SkipsSecretCheck) && looks_like_a_secret(comment.body()) {
            return Err(GitHostError::UnsafeText);
        }
        let mut state = self.lock();
        self.note_credential(&mut state);
        let full = format!("{}\n\n{}", comment.body(), comment.stamp().marker());
        let reference = |id: u64| CommentRef {
            target: CommentTarget::Issue(issue.clone()),
            id,
        };
        let trust_anyone = self.is(IssueStatusDefect::TrustsAnyAuthor);
        let found = state
            .issues
            .get(&(issue.repo.clone(), issue.number))
            .and_then(|i| {
                i.comments
                    .iter()
                    .filter(|c| {
                        (c.by_the_app || trust_anyone) && StatusStamp::mentions_marker(&c.body)
                    })
                    .min_by_key(|c| c.id)
                    .cloned()
            });
        let make = |state: &mut State| {
            state.next_comment += 1;
            let id = state.next_comment;
            state
                .issues
                .entry((issue.repo.clone(), issue.number))
                .or_default()
                .comments
                .push(FakeComment {
                    id,
                    by_the_app: true,
                    body: full.clone(),
                });
            id
        };
        if self.is(IssueStatusDefect::DuplicateComments) {
            return Ok(CommentWrite::Created(reference(make(&mut state))));
        }
        let Some(found) = found else {
            return Ok(CommentWrite::Created(reference(make(&mut state))));
        };
        let shown = StatusStamp::from_text(&found.body);
        if !self.is(IssueStatusDefect::IgnoresTheStamp)
            && let Some(shown) = shown
            && shown > *comment.stamp()
        {
            return Ok(CommentWrite::Superseded(reference(found.id)));
        }
        if !self.is(IssueStatusDefect::RewritesTheSameText)
            && shown == Some(*comment.stamp())
            && found.body == full
        {
            return Ok(CommentWrite::Unchanged(reference(found.id)));
        }
        if let Some(entry) = state
            .issues
            .get_mut(&(issue.repo.clone(), issue.number))
            .and_then(|i| i.comments.iter_mut().find(|c| c.id == found.id))
        {
            entry.body = full;
        }
        Ok(CommentWrite::Updated(reference(found.id)))
    }
}

#[async_trait]
impl IssueStatusSubject for FakeIssueStatusWriter {
    fn writer(&self) -> &dyn IssueStatusWriter {
        self
    }

    async fn seed_labels(&self, issue: &IssueRef, labels: &[&str]) {
        FakeIssueStatusWriter::seed_labels(self, issue, labels);
    }

    async fn labels_of(&self, issue: &IssueRef) -> Vec<String> {
        FakeIssueStatusWriter::labels_of(self, issue)
    }

    async fn seed_person_comment(&self, issue: &IssueRef, body: &str) {
        FakeIssueStatusWriter::seed_person_comment(self, issue, body);
    }

    async fn app_comments(&self, issue: &IssueRef) -> Vec<String> {
        FakeIssueStatusWriter::app_comments(self, issue)
    }

    async fn person_comments(&self, issue: &IssueRef) -> Vec<String> {
        FakeIssueStatusWriter::person_comments(self, issue)
    }

    async fn permissions_asked(&self) -> Vec<Vec<(String, String)>> {
        FakeIssueStatusWriter::permissions_asked(self)
    }
}
