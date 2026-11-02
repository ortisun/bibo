//! The contract suite for `IssueStatusWriter` (ports v1.2, ADR 0017): only the `factory: `
//! namespace is ever written, a status label replaces the others, the status comment is made once
//! and edited in place, the newest stamp wins, a marker pasted by a person is not the status
//! comment, secrets are not written, the scope is kept, and the credential is `issues: write` and
//! nothing else.
//!
//! The same checks run against the in-memory fake (`FakeIssueStatusWriter`) and against the GitHub
//! adapter over the loopback fake server (`crates/github/tests/issue_status_contract.rs`). Neither
//! is the real GitHub: what the real service does is not verified by this suite.

use std::future::Future;

use async_trait::async_trait;
use factory_domain::ids::JobId;
use factory_domain::policy::issue_workflow::StatusLabel;
use factory_domain::state::JobStatus;
use factory_domain::values::{AggregateVersion, Timestamp};
use factory_ports::clock::Uuid;
use factory_ports::githost::{GitHostError, IssueRef, Rejection};
use factory_ports::issue_status::{
    CommentWrite, IssueStatusWriter, StatusComment, StatusScope, StatusStamp,
};
use factory_ports::paths::RepoRef;

use super::githost::{TOKEN_CANARY, repo, scope};
use super::{
    Check, Context, Report, Waiver, check_list, ensure, ensure_eq, ensure_err, run_checks,
};
use crate::issue_status::status_labels;

/// What the suite needs beyond the `IssueStatusWriter` port itself.
#[async_trait]
pub trait IssueStatusSubject: Send + Sync {
    /// The writer under test.
    fn writer(&self) -> &dyn IssueStatusWriter;

    /// Puts labels on an issue, as people or other tools would have.
    async fn seed_labels(&self, issue: &IssueRef, labels: &[&str]);

    /// The labels on an issue now, in the order the host lists them.
    async fn labels_of(&self, issue: &IssueRef) -> Vec<String>;

    /// A comment a person wrote on the issue.
    async fn seed_person_comment(&self, issue: &IssueRef, body: &str);

    /// The text of the comments the factory's own account wrote on the issue.
    async fn app_comments(&self, issue: &IssueRef) -> Vec<String>;

    /// The text of the comments people wrote on the issue.
    async fn person_comments(&self, issue: &IssueRef) -> Vec<String>;

    /// The permission sets the writer asked a token for, by GitHub's names and levels, one entry
    /// for each token it asked for, each sorted.
    async fn permissions_asked(&self) -> Vec<Vec<(String, String)>>;
}

/// A check of the status writer contract.
pub type IssueStatusCheck = Check<dyn IssueStatusSubject>;

/// Runs the whole suite. `make` builds a fresh subject for every check.
pub async fn run_issue_status<S, F, Fut>(make: F) -> Report
where
    S: IssueStatusSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&issue_status_checks(), || async {
        Box::new(make().await) as Box<dyn IssueStatusSubject>
    })
    .await
}

/// Every check of the status writer contract.
#[must_use]
pub fn issue_status_checks() -> Vec<IssueStatusCheck> {
    check_list![dyn IssueStatusSubject;
        a_status_label_replaces_every_other_factory_label,
        setting_the_same_label_twice_changes_nothing,
        a_label_that_is_not_there_is_not_an_error,
        only_labels_of_the_factory_namespace_are_ever_written,
        the_status_comment_is_made_once_and_edited_in_place,
        repeating_the_same_comment_changes_nothing,
        an_older_stamp_never_overwrites_a_newer_comment,
        a_later_job_replaces_the_comment_of_an_earlier_one_and_not_the_other_way,
        a_marker_pasted_by_a_person_is_not_the_status_comment,
        text_with_a_secret_is_not_written,
        a_scope_for_another_repository_cannot_reach_the_issue,
        the_credential_is_issues_write_and_nothing_else,
    ]
}

/// No waivers: every check has a defect.
pub const WAIVERS: &[Waiver] = &[];

fn status_scope() -> StatusScope {
    let base = scope(1, 1);
    StatusScope {
        tenant: base.tenant,
        session: base.job,
        repo: base.repo,
    }
}

fn issue(number: u64) -> IssueRef {
    IssueRef {
        repo: repo(),
        number,
    }
}

fn label(state: JobStatus) -> StatusLabel {
    status_labels().label_for(state).clone()
}

fn stamp(started: &str, version: i64, job: u128) -> Result<StatusStamp, String> {
    Ok(StatusStamp {
        started: Timestamp::parse(started).ctx("time")?,
        version: AggregateVersion::new(version).ctx("version")?,
        job: JobId::from_uuid(Uuid::from_u128(job)),
    })
}

fn comment(stamp: StatusStamp, words: &str) -> Result<StatusComment, String> {
    StatusComment::new(stamp, words.to_owned()).ctx("a status comment")
}

const EARLY: &str = "2026-11-02T09:00:00Z";
const LATE: &str = "2026-11-02T10:00:00Z";

// ---------------------------------------------------------------------------------------------
// Labels

async fn a_status_label_replaces_every_other_factory_label(
    subject: &dyn IssueStatusSubject,
) -> Result<(), String> {
    let issue = issue(12);
    subject
        .seed_labels(
            &issue,
            &[
                "bug",
                "factory",
                "design: approved",
                "factory: queued",
                "factory: working",
            ],
        )
        .await;
    let outcome = subject
        .writer()
        .set_status_label(&status_scope(), &issue, &label(JobStatus::Completed))
        .await
        .ctx("set the label")?;
    ensure!(
        outcome.added,
        "the label was not on the issue, so it is added"
    );
    ensure_eq!(
        outcome.removed,
        2,
        "the two older status labels are taken off"
    );
    let mut labels = subject.labels_of(&issue).await;
    labels.sort();
    ensure_eq!(
        labels,
        vec![
            "bug".to_owned(),
            "design: approved".to_owned(),
            "factory".to_owned(),
            "factory: done".to_owned(),
        ],
        "the labels after the call: the trigger, the design label and the unrelated label stay"
    );
    Ok(())
}

async fn setting_the_same_label_twice_changes_nothing(
    subject: &dyn IssueStatusSubject,
) -> Result<(), String> {
    let issue = issue(12);
    subject
        .seed_labels(&issue, &["bug", "factory: queued"])
        .await;
    let first = subject
        .writer()
        .set_status_label(&status_scope(), &issue, &label(JobStatus::Active))
        .await
        .ctx("first call")?;
    ensure!(first.added && first.removed == 1, "first call: {first:?}");
    let after_first = subject.labels_of(&issue).await;
    ensure_eq!(
        after_first.clone(),
        vec!["bug".to_owned(), "factory: working".to_owned()],
        "the labels after the first call"
    );
    let second = subject
        .writer()
        .set_status_label(&status_scope(), &issue, &label(JobStatus::Active))
        .await
        .ctx("second call")?;
    ensure!(
        !second.added && second.removed == 0,
        "the second call adds and removes nothing: {second:?}"
    );
    ensure_eq!(
        subject.labels_of(&issue).await,
        after_first,
        "the labels after the second call"
    );
    Ok(())
}

async fn a_label_that_is_not_there_is_not_an_error(
    subject: &dyn IssueStatusSubject,
) -> Result<(), String> {
    // An issue with no status label at all, and one call after another on it: there is nothing to
    // take off, and that is not a failure.
    let issue = issue(30);
    subject.seed_labels(&issue, &["bug"]).await;
    for state in [JobStatus::Received, JobStatus::Received] {
        subject
            .writer()
            .set_status_label(&status_scope(), &issue, &label(state))
            .await
            .ctx("a call with nothing to take off")?;
    }
    Ok(())
}

async fn only_labels_of_the_factory_namespace_are_ever_written(
    subject: &dyn IssueStatusSubject,
) -> Result<(), String> {
    let issue = issue(12);
    subject
        .seed_labels(&issue, &["factory", "design: approved", "bug"])
        .await;
    let before = subject.labels_of(&issue).await;
    for wrong in [
        "factory",
        "design: approved",
        "design: in review",
        "bug",
        "Factory: working",
        "factory:working",
        "factory: ",
        "",
    ] {
        ensure_err!(
            subject
                .writer()
                .set_status_label(
                    &status_scope(),
                    &issue,
                    &StatusLabel::forged_for_negative_tests(wrong),
                )
                .await,
            GitHostError::Rejected(Rejection::LabelNotAllowed),
            "the label {wrong:?}"
        );
    }
    ensure_eq!(
        subject.labels_of(&issue).await,
        before,
        "a refused label changes nothing on the issue"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The comment

async fn the_status_comment_is_made_once_and_edited_in_place(
    subject: &dyn IssueStatusSubject,
) -> Result<(), String> {
    let issue = issue(12);
    let first = subject
        .writer()
        .upsert_status_comment(
            &status_scope(),
            &issue,
            &comment(stamp(EARLY, 1, 1)?, "The work is queued.")?,
        )
        .await
        .ctx("first")?;
    ensure!(
        matches!(first, CommentWrite::Created(_)),
        "first: {first:?}"
    );
    let second = subject
        .writer()
        .upsert_status_comment(
            &status_scope(),
            &issue,
            &comment(stamp(EARLY, 2, 1)?, "The work is under way.")?,
        )
        .await
        .ctx("second")?;
    ensure!(
        matches!(second, CommentWrite::Updated(_)),
        "second: {second:?}"
    );
    let third = subject
        .writer()
        .upsert_status_comment(
            &status_scope(),
            &issue,
            &comment(stamp(EARLY, 3, 1)?, "The work is done.")?,
        )
        .await
        .ctx("third")?;
    ensure!(
        matches!(third, CommentWrite::Updated(_)),
        "third: {third:?}"
    );
    let comments = subject.app_comments(&issue).await;
    ensure_eq!(
        comments.len(),
        1,
        "one status comment, however many updates"
    );
    ensure!(
        comments[0].contains("The work is done.") && !comments[0].contains("under way"),
        "the comment shows the last text: {:?}",
        comments[0]
    );
    ensure!(
        comments[0].contains(&stamp(EARLY, 3, 1)?.marker()),
        "the comment carries the marker of the last stamp"
    );
    Ok(())
}

async fn repeating_the_same_comment_changes_nothing(
    subject: &dyn IssueStatusSubject,
) -> Result<(), String> {
    let issue = issue(12);
    let same = comment(stamp(EARLY, 4, 1)?, "The work needs a person.")?;
    subject
        .writer()
        .upsert_status_comment(&status_scope(), &issue, &same)
        .await
        .ctx("first")?;
    let before = subject.app_comments(&issue).await;
    let again = subject
        .writer()
        .upsert_status_comment(&status_scope(), &issue, &same)
        .await
        .ctx("again")?;
    ensure!(
        matches!(again, CommentWrite::Unchanged(_)),
        "the same call again: {again:?}"
    );
    ensure_eq!(
        subject.app_comments(&issue).await,
        before,
        "the comments after a repeat"
    );
    Ok(())
}

async fn an_older_stamp_never_overwrites_a_newer_comment(
    subject: &dyn IssueStatusSubject,
) -> Result<(), String> {
    let issue = issue(12);
    subject
        .writer()
        .upsert_status_comment(
            &status_scope(),
            &issue,
            &comment(stamp(EARLY, 5, 1)?, "Newer text.")?,
        )
        .await
        .ctx("newer")?;
    let result = subject
        .writer()
        .upsert_status_comment(
            &status_scope(),
            &issue,
            &comment(stamp(EARLY, 4, 1)?, "Older text.")?,
        )
        .await
        .ctx("older")?;
    ensure!(
        matches!(result, CommentWrite::Superseded(_)),
        "the older update: {result:?}"
    );
    let comments = subject.app_comments(&issue).await;
    ensure_eq!(comments.len(), 1, "still one comment");
    ensure!(
        comments[0].contains("Newer text.") && !comments[0].contains("Older text."),
        "the newer text stays: {:?}",
        comments[0]
    );
    Ok(())
}

async fn a_later_job_replaces_the_comment_of_an_earlier_one_and_not_the_other_way(
    subject: &dyn IssueStatusSubject,
) -> Result<(), String> {
    let issue = issue(12);
    // Job 1 started early and reached version 9. Job 2 started later and is at version 1.
    subject
        .writer()
        .upsert_status_comment(
            &status_scope(),
            &issue,
            &comment(stamp(EARLY, 9, 1)?, "The first job finished.")?,
        )
        .await
        .ctx("first job")?;
    let second = subject
        .writer()
        .upsert_status_comment(
            &status_scope(),
            &issue,
            &comment(stamp(LATE, 1, 2)?, "A new job is queued.")?,
        )
        .await
        .ctx("second job")?;
    ensure!(
        matches!(second, CommentWrite::Updated(_)),
        "the later job takes the comment over: {second:?}"
    );
    let stale = subject
        .writer()
        .upsert_status_comment(
            &status_scope(),
            &issue,
            &comment(stamp(EARLY, 10, 1)?, "The first job, late news.")?,
        )
        .await
        .ctx("late news of the first job")?;
    ensure!(
        matches!(stale, CommentWrite::Superseded(_)),
        "late news of the earlier job does not take it back: {stale:?}"
    );
    let comments = subject.app_comments(&issue).await;
    ensure_eq!(comments.len(), 1, "one comment");
    ensure!(
        comments[0].contains("A new job is queued."),
        "the later job's text stays: {:?}",
        comments[0]
    );
    Ok(())
}

async fn a_marker_pasted_by_a_person_is_not_the_status_comment(
    subject: &dyn IssueStatusSubject,
) -> Result<(), String> {
    let issue = issue(12);
    // A person pastes a marker with a stamp from the far future, to stop the factory reporting
    // or to have its comment edited.
    let pasted = format!(
        "Look at this.\n\n{}",
        stamp("2099-01-01T00:00:00Z", 99, 1)?.marker()
    );
    subject.seed_person_comment(&issue, &pasted).await;
    let result = subject
        .writer()
        .upsert_status_comment(
            &status_scope(),
            &issue,
            &comment(stamp(EARLY, 1, 1)?, "The work is queued.")?,
        )
        .await
        .ctx("upsert")?;
    ensure!(
        matches!(result, CommentWrite::Created(_)),
        "the factory makes its own comment: {result:?}"
    );
    ensure_eq!(
        subject.person_comments(&issue).await,
        vec![pasted],
        "the person's comment is not edited"
    );
    ensure_eq!(
        subject.app_comments(&issue).await.len(),
        1,
        "one comment of the factory"
    );
    Ok(())
}

async fn text_with_a_secret_is_not_written(subject: &dyn IssueStatusSubject) -> Result<(), String> {
    let issue = issue(12);
    ensure_err!(
        subject
            .writer()
            .upsert_status_comment(
                &status_scope(),
                &issue,
                &comment(
                    stamp(EARLY, 1, 1)?,
                    &format!("The token is {TOKEN_CANARY} for now.")
                )?,
            )
            .await,
        GitHostError::UnsafeText,
        "text with a token in it"
    );
    ensure!(
        subject.app_comments(&issue).await.is_empty(),
        "nothing was written"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Scope and credential

async fn a_scope_for_another_repository_cannot_reach_the_issue(
    subject: &dyn IssueStatusSubject,
) -> Result<(), String> {
    let elsewhere = IssueRef {
        repo: RepoRef::parse("example-org/other").ctx("repo")?,
        number: 12,
    };
    ensure_err!(
        subject
            .writer()
            .set_status_label(&status_scope(), &elsewhere, &label(JobStatus::Active))
            .await,
        GitHostError::NotFound,
        "a label on an issue of another repository"
    );
    ensure_err!(
        subject
            .writer()
            .upsert_status_comment(
                &status_scope(),
                &elsewhere,
                &comment(stamp(EARLY, 1, 1)?, "The work is queued.")?,
            )
            .await,
        GitHostError::NotFound,
        "a comment on an issue of another repository"
    );
    ensure!(
        subject.labels_of(&elsewhere).await.is_empty()
            && subject.app_comments(&elsewhere).await.is_empty(),
        "nothing was written on the other repository"
    );
    Ok(())
}

async fn the_credential_is_issues_write_and_nothing_else(
    subject: &dyn IssueStatusSubject,
) -> Result<(), String> {
    let issue = issue(12);
    subject
        .writer()
        .set_status_label(&status_scope(), &issue, &label(JobStatus::Active))
        .await
        .ctx("label")?;
    subject
        .writer()
        .upsert_status_comment(
            &status_scope(),
            &issue,
            &comment(stamp(EARLY, 1, 1)?, "The work is under way.")?,
        )
        .await
        .ctx("comment")?;
    let asked = subject.permissions_asked().await;
    ensure!(!asked.is_empty(), "the writer asked for a token");
    let expected = vec![
        ("issues".to_owned(), "write".to_owned()),
        ("metadata".to_owned(), "read".to_owned()),
    ];
    for set in &asked {
        ensure_eq!(
            set.clone(),
            expected.clone(),
            "a token the writer asked for: issues write and the read of metadata every token carries, nothing else"
        );
    }
    Ok(())
}
