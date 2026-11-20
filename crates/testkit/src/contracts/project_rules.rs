//! The contract suite for `ProjectRulesHost` (ports v1.3, ADR 0026): a proposal is one draft pull
//! request from `factory/project-rules` and the default branch is never written; proposing again
//! opens no second one; an open proposal is updated on top and a person's commit on it is kept; a
//! new proposal after a closed one starts from the default branch; only the factory's own pull
//! requests count, with the state and the version of their marker; a file is missing, found or too
//! large; secrets are not sent; the scope is kept; and the credential is `contents` and
//! `pull_requests` write and nothing else.
//!
//! The same checks run against the in-memory fake (`FakeProjectRulesHost`) and against the GitHub
//! adapter over the loopback fake server (`crates/github/tests/project_rules.rs`). Neither is the
//! real GitHub.

use std::collections::BTreeMap;
use std::future::Future;

use async_trait::async_trait;
use factory_ports::githost::{GitHostError, PullRequestLifecycle, Rejection};
use factory_ports::paths::{RepoPath, RepoRef};
use factory_ports::project_rules::{
    FileAt, ProjectRulesHost, ProposedFile, RULES_BRANCH, RulesProposal, RulesScope,
    proposal_marker,
};

use super::githost::{TOKEN_CANARY, repo, scope};
use super::{
    Check, Context, Report, Waiver, check_list, ensure, ensure_eq, ensure_err, run_checks,
};

/// A pull request as the subject sees it on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeenPull {
    /// Its number.
    pub number: u64,
    /// The head branch.
    pub head: String,
    /// The base branch.
    pub base: String,
    /// The body as it is on the host.
    pub body: String,
    /// True while it is a draft.
    pub draft: bool,
    /// Open, closed or merged.
    pub lifecycle: PullRequestLifecycle,
}

/// What the suite needs beyond the port itself. The repository is [`repo`]; its default branch
/// is `main`, and it exists before the first check runs.
#[async_trait]
pub trait ProjectRulesSubject: Send + Sync {
    /// The host under test.
    fn host(&self) -> &dyn ProjectRulesHost;

    /// A person's commit on `branch`: sets (`Some`) or removes (`None`) files. A branch that does
    /// not exist starts from the default branch.
    async fn person_commit(&self, branch: &str, changes: &[(&str, Option<&str>)]);

    /// The files at the tip of a branch, with their text.
    async fn files_on(&self, branch: &str) -> BTreeMap<String, String>;

    /// Every pull request of the repository, lowest number first.
    async fn pulls(&self) -> Vec<SeenPull>;

    /// A person closes a pull request, merged or not.
    async fn close(&self, number: u64, merged: bool);

    /// A person opens a pull request from `head` into the default branch.
    async fn person_pull_request(&self, head: &str, body: &str);

    /// The permission sets the host asked a credential for, each sorted.
    async fn permissions_asked(&self) -> Vec<Vec<(String, String)>>;
}

/// A check of the project rules host contract.
pub type ProjectRulesCheck = Check<dyn ProjectRulesSubject>;

/// Runs the whole suite. `make` builds a fresh subject for every check.
pub async fn run_project_rules<S, F, Fut>(make: F) -> Report
where
    S: ProjectRulesSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&project_rules_checks(), || async {
        Box::new(make().await) as Box<dyn ProjectRulesSubject>
    })
    .await
}

/// Every check of the contract.
#[must_use]
pub fn project_rules_checks() -> Vec<ProjectRulesCheck> {
    check_list![dyn ProjectRulesSubject;
        the_default_branch_is_read_with_its_tip,
        a_file_is_missing_found_or_too_large,
        a_proposal_is_one_draft_pull_request_and_the_default_branch_is_untouched,
        proposing_again_opens_no_second_pull_request,
        an_open_proposal_is_updated_on_top_and_a_persons_commit_is_kept,
        a_new_proposal_after_a_closed_one_starts_from_the_default_branch,
        the_latest_pull_request_carries_its_state_and_version,
        a_pull_request_a_person_opened_from_the_rules_branch_is_not_the_factorys,
        a_body_with_a_secret_is_not_sent,
        an_empty_title_or_no_file_is_refused,
        a_scope_for_another_repository_reaches_nothing,
        the_credential_is_contents_and_pull_requests_write_and_nothing_else,
    ]
}

/// No waivers: every check has a defect.
pub const WAIVERS: &[Waiver] = &[];

fn rules_scope() -> RulesScope {
    let base = scope(1, 1);
    RulesScope {
        tenant: base.tenant,
        session: base.job,
        repo: base.repo,
    }
}

fn file(path: &str, text: &str) -> Result<ProposedFile, String> {
    Ok(ProposedFile {
        path: RepoPath::new(path).ctx("a path")?,
        bytes: text.as_bytes().to_vec(),
    })
}

async fn proposal(
    subject: &dyn ProjectRulesSubject,
    version: u32,
    files: &[(&str, &str)],
) -> Result<RulesProposal, String> {
    let base = subject
        .host()
        .default_branch(&rules_scope())
        .await
        .ctx("the default branch")?;
    Ok(RulesProposal {
        base,
        version,
        files: files
            .iter()
            .map(|(path, text)| file(path, text))
            .collect::<Result<_, _>>()?,
        title: format!("Install the rules for agents (version {version})"),
        body: "The factory's rules for agents.".to_owned(),
    })
}

fn path(text: &str) -> Result<RepoPath, String> {
    RepoPath::new(text).ctx("a path")
}

// ---------------------------------------------------------------------------------------------

async fn the_default_branch_is_read_with_its_tip(
    subject: &dyn ProjectRulesSubject,
) -> Result<(), String> {
    let host = subject.host();
    let first = host.default_branch(&rules_scope()).await.ctx("read")?;
    ensure_eq!(first.name.as_str(), "main", "the default branch");
    subject
        .person_commit("main", &[("README.md", Some("Hello.\n"))])
        .await;
    let second = host
        .default_branch(&rules_scope())
        .await
        .ctx("read again")?;
    ensure!(
        second.commit != first.commit,
        "the tip did not move after a commit"
    );
    Ok(())
}

async fn a_file_is_missing_found_or_too_large(
    subject: &dyn ProjectRulesSubject,
) -> Result<(), String> {
    subject
        .person_commit("main", &[("AGENTS.md", Some("Our rules.\n"))])
        .await;
    let host = subject.host();
    let tip = host.default_branch(&rules_scope()).await.ctx("read")?;
    let found = host
        .read_file(&rules_scope(), &tip.commit, &path("AGENTS.md")?, 1024)
        .await
        .ctx("read the file")?;
    ensure_eq!(found, FileAt::Found(b"Our rules.\n".to_vec()), "the file");
    let small = host
        .read_file(&rules_scope(), &tip.commit, &path("AGENTS.md")?, 4)
        .await
        .ctx("read with a small limit")?;
    ensure_eq!(small, FileAt::TooLarge, "a file over the limit");
    let missing = host
        .read_file(&rules_scope(), &tip.commit, &path("docs/README.md")?, 1024)
        .await
        .ctx("read a missing file")?;
    ensure_eq!(missing, FileAt::Missing, "a missing file");
    Ok(())
}

async fn a_proposal_is_one_draft_pull_request_and_the_default_branch_is_untouched(
    subject: &dyn ProjectRulesSubject,
) -> Result<(), String> {
    subject
        .person_commit("main", &[("README.md", Some("Hello.\n"))])
        .await;
    let before = subject.files_on("main").await;
    let made = proposal(
        subject,
        2,
        &[("AGENTS.md", "rules v2\n"), ("docs/README.md", "# Docs\n")],
    )
    .await?;
    let pr = subject
        .host()
        .propose(&rules_scope(), &made)
        .await
        .ctx("propose")?;
    ensure_eq!(
        subject.files_on("main").await,
        before,
        "the default branch changed"
    );
    let on_branch = subject.files_on(RULES_BRANCH).await;
    ensure_eq!(
        on_branch.get("AGENTS.md").map(String::as_str),
        Some("rules v2\n"),
        "the rules file on the branch"
    );
    ensure_eq!(
        on_branch.get("README.md").map(String::as_str),
        Some("Hello.\n"),
        "the branch starts from the default branch"
    );
    let pulls = subject.pulls().await;
    ensure_eq!(pulls.len(), 1, "pull requests");
    let pull = pulls.first().ok_or("no pull request")?;
    ensure_eq!(pull.number, pr.number, "the number returned");
    ensure!(pull.draft, "the pull request is not a draft");
    ensure_eq!(pull.head.as_str(), RULES_BRANCH, "the head");
    ensure_eq!(pull.base.as_str(), "main", "the base");
    ensure!(
        pull.body.ends_with(&proposal_marker(2)),
        "the body does not end with the marker: {}",
        pull.body
    );
    Ok(())
}

async fn proposing_again_opens_no_second_pull_request(
    subject: &dyn ProjectRulesSubject,
) -> Result<(), String> {
    let made = proposal(subject, 1, &[("AGENTS.md", "rules\n")]).await?;
    let first = subject
        .host()
        .propose(&rules_scope(), &made)
        .await
        .ctx("propose")?;
    let tip = subject.files_on(RULES_BRANCH).await;
    let second = subject
        .host()
        .propose(&rules_scope(), &made)
        .await
        .ctx("propose again")?;
    ensure_eq!(first, second, "the same pull request");
    ensure_eq!(subject.pulls().await.len(), 1, "pull requests");
    ensure_eq!(subject.files_on(RULES_BRANCH).await, tip, "the files");
    Ok(())
}

async fn an_open_proposal_is_updated_on_top_and_a_persons_commit_is_kept(
    subject: &dyn ProjectRulesSubject,
) -> Result<(), String> {
    let first = proposal(subject, 1, &[("AGENTS.md", "rules v1\n")]).await?;
    subject
        .host()
        .propose(&rules_scope(), &first)
        .await
        .ctx("propose")?;
    subject
        .person_commit(RULES_BRANCH, &[("NOTES.md", Some("A person's note.\n"))])
        .await;
    let second = proposal(subject, 2, &[("AGENTS.md", "rules v2\n")]).await?;
    subject
        .host()
        .propose(&rules_scope(), &second)
        .await
        .ctx("propose the next version")?;
    let files = subject.files_on(RULES_BRANCH).await;
    ensure_eq!(
        files.get("AGENTS.md").map(String::as_str),
        Some("rules v2\n"),
        "the new rules"
    );
    ensure!(
        files.contains_key("NOTES.md"),
        "the person's commit on the open branch was thrown away"
    );
    let pulls = subject.pulls().await;
    ensure_eq!(pulls.len(), 1, "pull requests");
    ensure!(
        pulls.iter().all(|p| p.body.ends_with(&proposal_marker(2))),
        "the body was not updated to the new version"
    );
    Ok(())
}

async fn a_new_proposal_after_a_closed_one_starts_from_the_default_branch(
    subject: &dyn ProjectRulesSubject,
) -> Result<(), String> {
    let first = proposal(subject, 1, &[("AGENTS.md", "rules v1\n")]).await?;
    let pr = subject
        .host()
        .propose(&rules_scope(), &first)
        .await
        .ctx("propose")?;
    subject
        .person_commit(RULES_BRANCH, &[("STALE.md", Some("left over\n"))])
        .await;
    subject.close(pr.number, false).await;
    subject
        .person_commit("main", &[("README.md", Some("New.\n"))])
        .await;
    let second = proposal(subject, 2, &[("AGENTS.md", "rules v2\n")]).await?;
    let again = subject
        .host()
        .propose(&rules_scope(), &second)
        .await
        .ctx("propose again")?;
    ensure!(
        again.number != pr.number,
        "the closed pull request was reused"
    );
    let files = subject.files_on(RULES_BRANCH).await;
    ensure!(
        !files.contains_key("STALE.md"),
        "the branch kept a closed proposal's commit"
    );
    ensure_eq!(
        files.get("README.md").map(String::as_str),
        Some("New.\n"),
        "the branch starts from the default branch's tip"
    );
    ensure_eq!(subject.pulls().await.len(), 2, "pull requests");
    Ok(())
}

async fn the_latest_pull_request_carries_its_state_and_version(
    subject: &dyn ProjectRulesSubject,
) -> Result<(), String> {
    let host = subject.host();
    ensure_eq!(
        host.latest_rules_pull_request(&rules_scope())
            .await
            .ctx("look")?,
        None,
        "before any proposal"
    );
    let made = proposal(subject, 7, &[("AGENTS.md", "rules\n")]).await?;
    let pr = host.propose(&rules_scope(), &made).await.ctx("propose")?;
    let open = host
        .latest_rules_pull_request(&rules_scope())
        .await
        .ctx("look")?
        .ok_or("no pull request found")?;
    ensure_eq!(open.pr.number, pr.number, "the number");
    ensure_eq!(open.lifecycle, PullRequestLifecycle::Open, "the state");
    ensure_eq!(open.proposed_version, Some(7), "the version");
    subject.close(pr.number, true).await;
    let merged = host
        .latest_rules_pull_request(&rules_scope())
        .await
        .ctx("look after the merge")?
        .ok_or("no pull request found")?;
    ensure_eq!(
        merged.lifecycle,
        PullRequestLifecycle::Merged,
        "after a merge"
    );
    let on_main = subject.files_on("main").await;
    ensure_eq!(
        on_main.get("AGENTS.md").map(String::as_str),
        Some("rules\n"),
        "the merge put the file on the default branch"
    );
    let next = proposal(subject, 8, &[("AGENTS.md", "rules 8\n")]).await?;
    let pr8 = host.propose(&rules_scope(), &next).await.ctx("propose 8")?;
    subject.close(pr8.number, false).await;
    let closed = host
        .latest_rules_pull_request(&rules_scope())
        .await
        .ctx("look after the close")?
        .ok_or("no pull request found")?;
    ensure_eq!(
        (closed.pr.number, closed.lifecycle, closed.proposed_version),
        (pr8.number, PullRequestLifecycle::Closed, Some(8)),
        "the newest, closed"
    );
    Ok(())
}

async fn a_pull_request_a_person_opened_from_the_rules_branch_is_not_the_factorys(
    subject: &dyn ProjectRulesSubject,
) -> Result<(), String> {
    subject
        .person_commit(RULES_BRANCH, &[("AGENTS.md", Some("a person's rules\n"))])
        .await;
    subject
        .person_pull_request(RULES_BRANCH, &format!("Mine.\n\n{}", proposal_marker(99)))
        .await;
    ensure_eq!(
        subject
            .host()
            .latest_rules_pull_request(&rules_scope())
            .await
            .ctx("look")?,
        None,
        "a person's pull request was taken for the factory's"
    );
    Ok(())
}

async fn a_body_with_a_secret_is_not_sent(subject: &dyn ProjectRulesSubject) -> Result<(), String> {
    let mut made = proposal(subject, 1, &[("AGENTS.md", "rules\n")]).await?;
    made.body = format!("Use the token {TOKEN_CANARY} to push.");
    ensure_err!(
        subject.host().propose(&rules_scope(), &made).await,
        GitHostError::UnsafeText,
        "a body with a secret"
    );
    ensure!(
        subject.pulls().await.is_empty(),
        "a pull request was opened"
    );
    ensure!(
        !subject
            .files_on(RULES_BRANCH)
            .await
            .contains_key("AGENTS.md"),
        "a file was written before the text check"
    );
    Ok(())
}

async fn an_empty_title_or_no_file_is_refused(
    subject: &dyn ProjectRulesSubject,
) -> Result<(), String> {
    let mut made = proposal(subject, 1, &[("AGENTS.md", "rules\n")]).await?;
    made.title = "  ".to_owned();
    ensure_err!(
        subject.host().propose(&rules_scope(), &made).await,
        GitHostError::Rejected(Rejection::TextBounds),
        "an empty title"
    );
    let empty = proposal(subject, 1, &[]).await?;
    ensure_err!(
        subject.host().propose(&rules_scope(), &empty).await,
        GitHostError::Rejected(Rejection::TextBounds),
        "no file"
    );
    ensure!(
        subject.pulls().await.is_empty(),
        "a pull request was opened"
    );
    Ok(())
}

async fn a_scope_for_another_repository_reaches_nothing(
    subject: &dyn ProjectRulesSubject,
) -> Result<(), String> {
    let elsewhere = RulesScope {
        repo: RepoRef::parse("example-org/not-installed").ctx("a name")?,
        ..rules_scope()
    };
    ensure_err!(
        subject.host().default_branch(&elsewhere).await,
        GitHostError::NotFound,
        "the default branch of a repository outside the scope"
    );
    ensure_err!(
        subject.host().latest_rules_pull_request(&elsewhere).await,
        GitHostError::NotFound,
        "the pull requests of a repository outside the scope"
    );
    let _ = repo();
    Ok(())
}

async fn the_credential_is_contents_and_pull_requests_write_and_nothing_else(
    subject: &dyn ProjectRulesSubject,
) -> Result<(), String> {
    let made = proposal(subject, 1, &[("AGENTS.md", "rules\n")]).await?;
    subject
        .host()
        .propose(&rules_scope(), &made)
        .await
        .ctx("propose")?;
    let expected = vec![
        ("contents".to_owned(), "write".to_owned()),
        ("metadata".to_owned(), "read".to_owned()),
        ("pull_requests".to_owned(), "write".to_owned()),
    ];
    let asked = subject.permissions_asked().await;
    ensure!(!asked.is_empty(), "no credential was asked for");
    for set in asked {
        ensure_eq!(set, expected, "a credential");
    }
    Ok(())
}
