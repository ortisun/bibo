//! The contract suite for `PullRequestFateSource` (ports v1.5, ADR 0029): an open pull request is
//! open and has no time; a merge and a close without a merge are told apart, each with the time
//! the code host gives for it and not the time of the look; a pull request the scope does not
//! cover is not found; and the credential reads pull requests and nothing else.
//!
//! The same checks run against the in-memory fake (`FakePullRequestFates`) and against the GitHub
//! adapter over the loopback fake server (`crates/github/tests/pull_request_fate.rs`). Neither is
//! the real GitHub.

use std::future::Future;
use std::time::Duration;

use async_trait::async_trait;
use factory_domain::values::Timestamp;
use factory_ports::githost::{GitHostError, PullRequestLifecycle, PullRequestRef};
use factory_ports::paths::RepoRef;
use factory_ports::pull_request_fate::{FateScope, PullRequestFateSource};

use super::githost::{repo, scope};
use super::{
    Check, Context, Report, Waiver, check_list, ensure, ensure_eq, ensure_err, run_checks,
};

/// What the suite needs beyond the port itself. The repository is [`repo`], and it exists before
/// the first check runs.
#[async_trait]
pub trait PullRequestFateSubject: Send + Sync {
    /// The source under test.
    fn source(&self) -> &dyn PullRequestFateSource;

    /// A pull request is opened in the repository. Returns its number. A check opens at most
    /// three.
    async fn open_pull_request(&self) -> u64;

    /// A person closes a pull request now, merged or not.
    async fn close(&self, number: u64, merged: bool);

    /// The time of the code host now. The code host keeps whole seconds.
    async fn host_time(&self) -> Timestamp;

    /// Moves the clock of the code host forward.
    async fn advance(&self, by: Duration);

    /// The permission sets the source asked a credential for, each sorted. One that asks for
    /// none (a fake) reports the set it would ask for, once for each look.
    async fn permissions_asked(&self) -> Vec<Vec<(String, String)>>;
}

/// A check of the fate source contract.
pub type PullRequestFateCheck = Check<dyn PullRequestFateSubject>;

/// Runs the whole suite. `make` builds a fresh subject for every check.
pub async fn run_pull_request_fate<S, F, Fut>(make: F) -> Report
where
    S: PullRequestFateSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&pull_request_fate_checks(), || async {
        Box::new(make().await) as Box<dyn PullRequestFateSubject>
    })
    .await
}

/// Every check of the contract.
#[must_use]
pub fn pull_request_fate_checks() -> Vec<PullRequestFateCheck> {
    check_list![dyn PullRequestFateSubject;
        an_open_pull_request_is_open_and_has_no_time,
        a_merge_is_reported_with_the_time_of_the_merge,
        a_close_without_a_merge_is_reported_with_the_time_of_the_close,
        a_pull_request_the_scope_does_not_cover_is_not_found,
        the_credential_reads_pull_requests_and_nothing_else,
    ]
}

/// No waivers: every check has a defect.
pub const WAIVERS: &[Waiver] = &[];

/// The scope of a look at the suite's repository.
#[must_use]
pub fn fate_scope() -> FateScope {
    let base = scope(1, 1);
    FateScope {
        tenant: base.tenant,
        session: base.job,
        repo: base.repo,
    }
}

fn pull(number: u64) -> PullRequestRef {
    PullRequestRef {
        repo: repo(),
        number,
    }
}

/// How long the suite lets pass between two events, so that the time of a decision and the time
/// of a look can be told apart on a clock of whole seconds.
const STEP: Duration = Duration::from_secs(90);

async fn an_open_pull_request_is_open_and_has_no_time(
    subject: &dyn PullRequestFateSubject,
) -> Result<(), String> {
    let number = subject.open_pull_request().await;
    subject.advance(STEP).await;
    let seen = subject
        .source()
        .observe(&fate_scope(), &pull(number))
        .await
        .ctx("look at the open pull request")?;
    ensure_eq!(seen.lifecycle(), PullRequestLifecycle::Open, "the state");
    ensure_eq!(
        seen.decided_at(),
        None,
        "nobody decided, so there is no time"
    );
    // Looking changes nothing: a second look says the same.
    let again = subject
        .source()
        .observe(&fate_scope(), &pull(number))
        .await
        .ctx("look again")?;
    ensure_eq!(again, seen, "the second look");
    Ok(())
}

/// Opens a pull request, lets a person close it, lets time pass, and looks.
async fn decided(
    subject: &dyn PullRequestFateSubject,
    merged: bool,
) -> Result<
    (
        Timestamp,
        factory_ports::pull_request_fate::ObservedPullRequest,
    ),
    String,
> {
    let number = subject.open_pull_request().await;
    subject.advance(STEP).await;
    let at = subject.host_time().await;
    subject.close(number, merged).await;
    subject.advance(STEP).await;
    let seen = subject
        .source()
        .observe(&fate_scope(), &pull(number))
        .await
        .ctx("look at the decided pull request")?;
    Ok((at, seen))
}

async fn a_merge_is_reported_with_the_time_of_the_merge(
    subject: &dyn PullRequestFateSubject,
) -> Result<(), String> {
    let (at, seen) = decided(subject, true).await?;
    ensure_eq!(seen.lifecycle(), PullRequestLifecycle::Merged, "the state");
    ensure_eq!(
        seen.decided_at(),
        Some(at),
        "the time of the merge, not the time of the look"
    );
    Ok(())
}

async fn a_close_without_a_merge_is_reported_with_the_time_of_the_close(
    subject: &dyn PullRequestFateSubject,
) -> Result<(), String> {
    let (at, seen) = decided(subject, false).await?;
    ensure_eq!(seen.lifecycle(), PullRequestLifecycle::Closed, "the state");
    ensure_eq!(
        seen.decided_at(),
        Some(at),
        "the time of the close, not the time of the look"
    );
    Ok(())
}

async fn a_pull_request_the_scope_does_not_cover_is_not_found(
    subject: &dyn PullRequestFateSubject,
) -> Result<(), String> {
    let number = subject.open_pull_request().await;
    ensure_err!(
        subject
            .source()
            .observe(&fate_scope(), &pull(number + 1_000))
            .await,
        GitHostError::NotFound,
        "a number nobody opened"
    );
    let elsewhere = PullRequestRef {
        repo: RepoRef::parse("example-org/other").ctx("a repository")?,
        number,
    };
    ensure_err!(
        subject.source().observe(&fate_scope(), &elsewhere).await,
        GitHostError::NotFound,
        "the same number in a repository the scope does not name"
    );
    ensure!(
        subject
            .source()
            .observe(&fate_scope(), &pull(number))
            .await
            .is_ok(),
        "the pull request of the scope is still found"
    );
    Ok(())
}

async fn the_credential_reads_pull_requests_and_nothing_else(
    subject: &dyn PullRequestFateSubject,
) -> Result<(), String> {
    let number = subject.open_pull_request().await;
    subject
        .source()
        .observe(&fate_scope(), &pull(number))
        .await
        .ctx("look")?;
    let asked = subject.permissions_asked().await;
    ensure!(!asked.is_empty(), "a credential was asked for");
    let wanted = vec![
        ("metadata".to_owned(), "read".to_owned()),
        ("pull_requests".to_owned(), "read".to_owned()),
    ];
    for set in asked {
        ensure_eq!(set, wanted.clone(), "the permissions of the credential");
    }
    Ok(())
}
