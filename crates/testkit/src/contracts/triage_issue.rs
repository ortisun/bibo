//! The contract suite for `TriageIssueWriter` (ports v1.3, ADR 0021 Decision 7): an issue is opened
//! with the template's text and the policy's labels, opening twice keeps one issue, the fingerprint
//! is read from the body of the factory's own open issues only, a closed issue is not found, "seen
//! again" is said once per run, secrets are not written, the scope is kept to the configured
//! repository, the credential is `issues: write` and `metadata: read`, and an ended run gets no
//! credential.
//!
//! The same checks run against the in-memory fake (`FakeTriageIssues`) and against the GitHub
//! adapter over the loopback fake server (`crates/github/tests/triage_issue.rs`). Neither is the
//! real GitHub.

use std::future::Future;

use async_trait::async_trait;
use factory_domain::troubleshooting::issue::{
    Investigation, SeenAgainComment, TriageIssue, render_issue, render_seen_again,
};
use factory_domain::troubleshooting::{
    Finding, FindingCategory, FindingComponent, FindingSeverity, GatewayCallId, GatewayToolName,
    Observation, TriageLabels, TroubleshootingRunId,
};
use factory_domain::values::{Slug, Timestamp};
use factory_ports::githost::GitHostError;
use factory_ports::paths::RepoRef;
use factory_ports::triage_issue::{OpenedIssue, RunScope, SeenAgainPost, TriageIssueWriter};

use super::githost::{TOKEN_CANARY, scope};
use super::{
    Check, Context, Report, Waiver, check_list, ensure, ensure_eq, ensure_err, run_checks,
};
use crate::triage_issue::triage_labels;

/// What the suite needs beyond the `TriageIssueWriter` port itself.
#[async_trait]
pub trait TriageIssueSubject: Send + Sync {
    /// The writer under test.
    fn writer(&self) -> &dyn TriageIssueWriter;

    /// The issue repository the writer was configured with.
    fn repository(&self) -> RepoRef;

    /// Another repository the installation covers, which the writer must refuse.
    fn other_repository(&self) -> RepoRef;

    /// An open issue the factory's own account opened, with this body and these labels.
    async fn seed_app_issue(&self, body: &str, labels: &[&str]) -> u64;

    /// An open issue a person opened.
    async fn seed_person_issue(&self, body: &str, labels: &[&str]) -> u64;

    /// A comment a person wrote on an issue.
    async fn seed_person_comment(&self, number: u64, body: &str);

    /// Closes an issue.
    async fn close(&self, number: u64);

    /// The numbers of the open issues of the configured repository.
    async fn open_issues(&self) -> Vec<u64>;

    /// The body and labels of an issue.
    async fn issue(&self, number: u64) -> Option<(String, Vec<String>)>;

    /// The text of the comments the factory's own account wrote on an issue.
    async fn app_comments(&self, number: u64) -> Vec<String>;

    /// The permission sets the writer asked a token for, each sorted, one entry per token.
    async fn permissions_asked(&self) -> Vec<Vec<(String, String)>>;
}

/// A check of the triage issue writer contract.
pub type TriageIssueCheck = Check<dyn TriageIssueSubject>;

/// Runs the whole suite. `make` builds a fresh subject for every check.
pub async fn run_triage_issue<S, F, Fut>(make: F) -> Report
where
    S: TriageIssueSubject + 'static,
    F: Fn() -> Fut,
    Fut: Future<Output = S>,
{
    run_checks(&triage_issue_checks(), || async {
        Box::new(make().await) as Box<dyn TriageIssueSubject>
    })
    .await
}

/// Every check of the triage issue writer contract.
#[must_use]
pub fn triage_issue_checks() -> Vec<TriageIssueCheck> {
    check_list![dyn TriageIssueSubject;
        an_issue_opens_with_the_template_text_and_the_policy_labels,
        opening_twice_keeps_one_issue,
        the_marker_counts_only_in_the_body_of_the_factorys_own_open_issue,
        a_closed_issue_is_not_found,
        saying_seen_again_twice_in_a_run_posts_one_comment,
        text_with_a_secret_is_not_written,
        a_scope_for_another_repository_is_refused,
        the_credential_is_issues_write_and_metadata_read,
        an_ended_run_gets_no_credential,
    ]
}

/// No waivers: every check has a defect.
pub const WAIVERS: &[Waiver] = &[];

/// The run of the suite.
///
/// # Panics
/// Never: the text is a valid run id.
#[must_use]
pub fn run_id() -> TroubleshootingRunId {
    TroubleshootingRunId::parse("contract-run-1").expect("a run id")
}

fn run_scope(repo: RepoRef) -> RunScope {
    RunScope {
        tenant: scope(1, 1).tenant,
        run: run_id(),
        repo,
    }
}

/// A finding of the suite: a probe-explained stage failure in the worker, with `title` as the
/// agent's words.
///
/// # Panics
/// Never: every identifier is valid.
#[must_use]
pub fn finding(probe: &str, title: &str) -> Finding {
    Finding {
        category: FindingCategory::StageFailures,
        severity: FindingSeverity::High,
        component: FindingComponent::Worker,
        title: title.to_owned(),
        probe_ids: vec![Slug::parse(probe).expect("a probe id")],
        observations: vec![Observation {
            call_id: GatewayCallId::parse("call-1").expect("a call id"),
            tool: GatewayToolName::parse("vm_query").expect("a tool"),
            observed: "Twelve stage failures in the last hour.".to_owned(),
        }],
        hypothesis: "The sandbox image is missing a tool the stage needs.".to_owned(),
        confidence: 0.6,
        next_checks: vec!["Read the last failed stage's log.".to_owned()],
    }
}

fn investigation(run: &TroubleshootingRunId) -> Result<Investigation<'_>, String> {
    Ok(Investigation {
        run,
        window_from: Timestamp::parse("2026-11-20T09:00:00Z").ctx("time")?,
        window_to: Timestamp::parse("2026-11-20T10:00:00Z").ctx("time")?,
        earlier_closed_issue: None,
        held_back: &[],
    })
}

fn rendered(f: &Finding, labels: &TriageLabels) -> Result<TriageIssue, String> {
    let run = run_id();
    render_issue(f, &investigation(&run)?, labels).ctx("render the issue")
}

fn seen_again(f: &Finding) -> Result<SeenAgainComment, String> {
    let run = run_id();
    render_seen_again(f, &investigation(&run)?).ctx("render the comment")
}

async fn an_issue_opens_with_the_template_text_and_the_policy_labels(
    subject: &dyn TriageIssueSubject,
) -> Result<(), String> {
    let scope = run_scope(subject.repository());
    let issue = rendered(
        &finding("stage-failure-rate", "Stage failures rose"),
        &triage_labels(),
    )?;
    let writer = subject.writer();
    ensure_eq!(
        writer
            .find_open_issue(&scope, issue.fingerprint())
            .await
            .ctx("find")?,
        None,
        "check 1"
    );
    let OpenedIssue::Opened(opened) = writer.open_issue(&scope, &issue).await.ctx("open")? else {
        return Err("a first open made no issue".to_owned());
    };
    let (body, labels) = subject
        .issue(opened.number)
        .await
        .ok_or_else(|| "the opened issue is not there".to_owned())?;
    ensure!(
        body.lines().any(|l| l == issue.fingerprint().marker()),
        "the body carries the marker on a line of its own: {body}"
    );
    ensure!(
        body.contains("Nothing will be built from this issue until a person approves it"),
        "the body keeps the preface"
    );
    ensure_eq!(
        labels,
        vec!["troubleshooter", "troubleshooter: triage"],
        "check 2"
    );
    ensure!(
        !labels
            .iter()
            .any(|l| l.starts_with("factory") || l.starts_with("design:")),
        "never a factory or design label"
    );
    ensure_eq!(
        writer
            .find_open_issue(&scope, issue.fingerprint())
            .await
            .ctx("find again")?,
        Some(opened),
        "check 3"
    );
    Ok(())
}

async fn opening_twice_keeps_one_issue(subject: &dyn TriageIssueSubject) -> Result<(), String> {
    let scope = run_scope(subject.repository());
    let before = subject.open_issues().await.len();
    let issue = rendered(&finding("queue-depth", "Work waits"), &triage_labels())?;
    let first = subject
        .writer()
        .open_issue(&scope, &issue)
        .await
        .ctx("open")?;
    let second = subject
        .writer()
        .open_issue(&scope, &issue)
        .await
        .ctx("open again")?;
    let OpenedIssue::Opened(made) = first else {
        return Err(format!("the first open was {first:?}"));
    };
    ensure_eq!(second, OpenedIssue::AlreadyOpen(made), "check 4");
    ensure_eq!(subject.open_issues().await.len(), before + 1, "check 5");
    Ok(())
}

async fn the_marker_counts_only_in_the_body_of_the_factorys_own_open_issue(
    subject: &dyn TriageIssueSubject,
) -> Result<(), String> {
    let scope = run_scope(subject.repository());
    let issue = rendered(
        &finding("db-latency", "The database is slow"),
        &triage_labels(),
    )?;
    let marker = issue.fingerprint().marker();
    let labels = ["troubleshooter", "troubleshooter: triage"];
    // A person's issue with the exact marker in its body.
    subject
        .seed_person_issue(&format!("Copied.\n\n{marker}\n"), &labels)
        .await;
    // The factory's issue of another problem, with the marker pasted into a comment.
    let other = rendered(&finding("queue-depth", "Another problem"), &triage_labels())?;
    let decoy = subject.seed_app_issue(other.body(), &labels).await;
    subject
        .seed_person_comment(decoy, &format!("Same thing?\n{marker}\n"))
        .await;
    // The factory's issues with the marker inside other text, or quoted.
    subject
        .seed_app_issue(&format!("Text {marker}\n"), &labels)
        .await;
    subject
        .seed_app_issue(&format!("> {marker}\n"), &labels)
        .await;
    // The factory's issue with the marker but without the label that finds it.
    subject
        .seed_app_issue(&format!("Body.\n\n{marker}\n"), &["bug"])
        .await;
    ensure_eq!(
        subject
            .writer()
            .find_open_issue(&scope, issue.fingerprint())
            .await
            .ctx("find among decoys")?,
        None,
        "check 6"
    );
    let real = subject
        .seed_app_issue(&format!("Body.\n\n{marker}\n"), &labels)
        .await;
    ensure_eq!(
        subject
            .writer()
            .find_open_issue(&scope, issue.fingerprint())
            .await
            .ctx("find")?
            .map(|i| i.number),
        Some(real),
        "check 7"
    );
    Ok(())
}

async fn a_closed_issue_is_not_found(subject: &dyn TriageIssueSubject) -> Result<(), String> {
    let scope = run_scope(subject.repository());
    let issue = rendered(&finding("spend-rate", "Spend rose"), &triage_labels())?;
    let number = subject
        .seed_app_issue(issue.body(), &["troubleshooter", "troubleshooter: triage"])
        .await;
    subject.close(number).await;
    ensure_eq!(
        subject
            .writer()
            .find_open_issue(&scope, issue.fingerprint())
            .await
            .ctx("find")?,
        None,
        "check 8"
    );
    let opened = subject
        .writer()
        .open_issue(&scope, &issue)
        .await
        .ctx("open")?;
    ensure!(
        matches!(&opened, OpenedIssue::Opened(made) if made.number != number),
        "a closed issue is not reused: {opened:?}"
    );
    Ok(())
}

async fn saying_seen_again_twice_in_a_run_posts_one_comment(
    subject: &dyn TriageIssueSubject,
) -> Result<(), String> {
    let scope = run_scope(subject.repository());
    let f = finding("stage-failure-rate", "Stage failures rose");
    let issue = rendered(&f, &triage_labels())?;
    let OpenedIssue::Opened(opened) = subject
        .writer()
        .open_issue(&scope, &issue)
        .await
        .ctx("open")?
    else {
        return Err("no issue".to_owned());
    };
    let comment = seen_again(&f)?;
    let first = subject
        .writer()
        .post_seen_again(&scope, &opened, &comment)
        .await
        .ctx("post")?;
    let second = subject
        .writer()
        .post_seen_again(&scope, &opened, &comment)
        .await
        .ctx("post again")?;
    let SeenAgainPost::Posted(made) = first else {
        return Err(format!("the first post was {first:?}"));
    };
    ensure_eq!(second, SeenAgainPost::AlreadyThere(made), "check 9");
    let comments = subject.app_comments(opened.number).await;
    ensure_eq!(comments.len(), 1, "check 10");
    ensure!(
        comments.iter().all(|c| c.contains(comment.key())),
        "the comment carries its key"
    );
    Ok(())
}

async fn text_with_a_secret_is_not_written(subject: &dyn TriageIssueSubject) -> Result<(), String> {
    let scope = run_scope(subject.repository());
    let before = subject.open_issues().await.len();
    let mut f = finding("api-errors", "Errors in the API");
    f.observations[0].observed = format!("The log line held {TOKEN_CANARY} in a header.");
    let issue = rendered(&f, &triage_labels())?;
    ensure_err!(
        subject.writer().open_issue(&scope, &issue).await,
        GitHostError::UnsafeText,
        "check 11"
    );
    ensure_eq!(subject.open_issues().await.len(), before, "check 12");
    Ok(())
}

async fn a_scope_for_another_repository_is_refused(
    subject: &dyn TriageIssueSubject,
) -> Result<(), String> {
    let scope = run_scope(subject.other_repository());
    let issue = rendered(
        &finding("api-errors", "Errors in the API"),
        &triage_labels(),
    )?;
    let writer = subject.writer();
    ensure_err!(
        writer.find_open_issue(&scope, issue.fingerprint()).await,
        GitHostError::Forbidden,
        "check 13"
    );
    ensure_err!(
        writer.open_issue(&scope, &issue).await,
        GitHostError::Forbidden,
        "check 14"
    );
    let target = factory_ports::githost::IssueRef {
        repo: subject.other_repository(),
        number: 1,
    };
    ensure_err!(
        writer
            .post_seen_again(
                &scope,
                &target,
                &seen_again(&finding("api-errors", "x y z"))?
            )
            .await,
        GitHostError::Forbidden,
        "check 15"
    );
    ensure!(
        subject.permissions_asked().await.is_empty(),
        "no credential was asked for"
    );
    Ok(())
}

async fn the_credential_is_issues_write_and_metadata_read(
    subject: &dyn TriageIssueSubject,
) -> Result<(), String> {
    let scope = run_scope(subject.repository());
    let f = finding("worker-heartbeat", "The worker is quiet");
    let issue = rendered(&f, &triage_labels())?;
    let OpenedIssue::Opened(opened) = subject
        .writer()
        .open_issue(&scope, &issue)
        .await
        .ctx("open")?
    else {
        return Err("no issue".to_owned());
    };
    subject
        .writer()
        .post_seen_again(&scope, &opened, &seen_again(&f)?)
        .await
        .ctx("post")?;
    let asked = subject.permissions_asked().await;
    ensure!(!asked.is_empty(), "a credential was asked for");
    let expected = vec![
        ("issues".to_owned(), "write".to_owned()),
        ("metadata".to_owned(), "read".to_owned()),
    ];
    for set in asked {
        ensure_eq!(set, expected, "check 16");
    }
    Ok(())
}

async fn an_ended_run_gets_no_credential(subject: &dyn TriageIssueSubject) -> Result<(), String> {
    let scope = run_scope(subject.repository());
    let issue = rendered(&finding("db-latency", "Slow"), &triage_labels())?;
    subject
        .writer()
        .find_open_issue(&scope, issue.fingerprint())
        .await
        .ctx("find")?;
    subject
        .writer()
        .revoke_run_tokens(&scope.run)
        .await
        .ctx("revoke")?;
    subject
        .writer()
        .revoke_run_tokens(&scope.run)
        .await
        .ctx("revoke twice")?;
    let before = subject.open_issues().await.len();
    ensure_err!(
        subject.writer().open_issue(&scope, &issue).await,
        GitHostError::Unauthorized,
        "check 17"
    );
    ensure_eq!(subject.open_issues().await.len(), before, "check 18");
    Ok(())
}
