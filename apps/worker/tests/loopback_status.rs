//! The status write-back through the real adapters, judged from what the fake GitHub received.
//!
//! The worker writes the state of each job on its issue: one `factory: <state>` label and one
//! status comment that it edits (ADR 0017, `github.write_issue_status`, on by default). It does so
//! only after the job's intake stage has passed, and intake needs the Docker sandbox for its
//! classifier, so a run through the real worker binary cannot get there on a host without the
//! images (`loopback_e2e.rs` shows the worker stopping at that point).
//!
//! So this file takes the other half of the worker's own start-up: it reads the same configuration
//! file and calls the functions the binary calls (`boot`, `external_ports`, `issue_status`,
//! `token_sweep`), which build the real GitHub adapter, the real status step over the real store
//! and the real token sweep, and runs them in the worker's own loop (`WorkerLoop`) beside an engine
//! whose stage handlers are the engine suite's scripted ones. The scripted handlers are the only
//! stand-in, and they stand in for the stages that need a sandbox. They make the job go through the
//! states a real one goes through, from `ACTIVE` to a wait for a person to `COMPLETED`.
//!
//! The judgments read what the fake GitHub received. Nothing here touched real GitHub.

mod support;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use factory_composition::config::FactoryConfig;
use factory_composition::system::{RandomIds, Shutdown, TokioTicker};
use factory_domain::ids::JobId;
use factory_domain::scope::TenantScope;
use factory_domain::state::{JobStatus, Status as _};
use factory_domain::vocabulary::StageKind;
use factory_ports::clock::IdGenerator;
use factory_ports::store::{NewOriginalRequest, RequestSource};
use factory_testkit::fx::github::{AppConfig, MintRecord, TokenView};
use factory_worker::boot::boot;
use factory_worker::pipeline::{external_ports, issue_status, token_sweep};
use factory_worker::run::WorkerLoop;
use serde_json::Value;
use support::engine::{Eval, PgWorld};
use support::loopback::*;
use support::worker_config;

/// The labels `policies/issue-workflow.yaml` maps the job states of this run to. The test fails
/// loudly when the policy is renamed, as the other tests of the policy do.
const WORKING: &str = "factory: working";
const WAITING: &str = "factory: waiting for a person";
const DONE: &str = "factory: done";

/// Every route a status update may use, and no other.
const STATUS_ROUTES: [&str; 9] = [
    "GET /app",
    "POST /app/installations/{id}/access_tokens",
    "DELETE /installation/token",
    "GET /repos/{owner}/{repo}/issues/{number}/comments",
    "POST /repos/{owner}/{repo}/issues/{number}/comments",
    "PATCH /repos/{owner}/{repo}/issues/comments/{id}",
    "GET /repos/{owner}/{repo}/issues/{number}/labels",
    "POST /repos/{owner}/{repo}/issues/{number}/labels",
    "DELETE /repos/{owner}/{repo}/issues/{number}/labels/{name}",
];

struct Observed {
    job_status: JobStatus,
    routes: BTreeMap<String, usize>,
    comments: Vec<String>,
    labels: Vec<String>,
    /// The labels the worker added, in order, and the ones it removed.
    added: Vec<String>,
    removed: Vec<String>,
    mints: Vec<MintRecord>,
    tokens: Vec<TokenView>,
    merges: usize,
    pulls: usize,
    pushes: usize,
    written: usize,
    failed: usize,
    leaks: Vec<String>,
}

fn level(text: &str) -> u8 {
    match text {
        "read" => 1,
        "write" => 2,
        _ => 3,
    }
}

fn judge(o: &Observed) -> Vec<String> {
    let mut problems = Vec::new();
    if o.job_status != JobStatus::Completed {
        problems.push(format!("the job is {:?}, not COMPLETED", o.job_status));
    }
    // Only the routes of a status update, and no merge, pull request or push.
    for route in o.routes.keys() {
        if !STATUS_ROUTES.contains(&route.as_str()) {
            problems.push(format!(
                "GitHub received a request on a route a status never uses: {route}"
            ));
        }
    }
    if o.merges + o.pulls + o.pushes != 0 {
        problems.push("a merge, a pull request or a push exists".to_owned());
    }
    // One comment, made once and edited after.
    let posts = o
        .routes
        .get("POST /repos/{owner}/{repo}/issues/{number}/comments")
        .copied()
        .unwrap_or(0);
    let edits = o
        .routes
        .get("PATCH /repos/{owner}/{repo}/issues/comments/{id}")
        .copied()
        .unwrap_or(0);
    if posts != 1 {
        problems.push(format!(
            "the status comment was created {posts} time(s), not once"
        ));
    }
    if edits < 2 {
        problems.push(format!(
            "the status comment was edited {edits} time(s); three states need at least two edits"
        ));
    }
    if o.comments.len() != 1 {
        problems.push(format!(
            "the issue has {} comment(s), not one",
            o.comments.len()
        ));
    }
    if !o
        .comments
        .iter()
        .all(|c| c.contains("<!-- factory-status job="))
    {
        problems.push("a comment on the issue is not the status comment".to_owned());
    }
    // Exactly one status label at the end, the right one, and the trigger label untouched.
    let status_labels: Vec<&String> = o
        .labels
        .iter()
        .filter(|l| l.starts_with("factory: "))
        .collect();
    if status_labels != [&DONE.to_owned()] {
        problems.push(format!(
            "the issue ends with the status labels {status_labels:?}, not [{DONE:?}]"
        ));
    }
    if !o.labels.iter().any(|l| l == "factory") {
        problems.push("the trigger label was taken off".to_owned());
    }
    for label in &o.added {
        if ![WORKING, WAITING, DONE].contains(&label.as_str()) {
            problems.push(format!(
                "the worker added a label outside the status labels: {label}"
            ));
        }
    }
    for label in &o.removed {
        if !label.starts_with("factory: ") {
            problems.push(format!(
                "the worker removed a label outside the status namespace: {label}"
            ));
        }
    }
    for expected in [WORKING, WAITING, DONE] {
        if !o.added.iter().any(|l| l == expected) {
            problems.push(format!("the label {expected:?} was never written"));
        }
    }
    // Tokens: each narrowed to the one repository, and nothing but issues: write and metadata: read.
    if o.mints.is_empty() {
        problems.push("no installation token was requested".to_owned());
    }
    for mint in &o.mints {
        if mint.requested_repositories.as_deref() != Some(&["word-count".to_owned()][..]) {
            problems.push(format!(
                "token {} was not narrowed to the one repository",
                mint.token_id
            ));
        }
        let wanted: BTreeMap<&str, &str> = [("issues", "write"), ("metadata", "read")].into();
        let asked: BTreeMap<&str, &str> = mint
            .requested_permissions
            .iter()
            .flatten()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        if asked != wanted {
            problems.push(format!(
                "token {} asked for {asked:?}, not the narrowest {wanted:?}",
                mint.token_id
            ));
        }
        if mint.granted_permissions.iter().any(|(_, l)| level(l) > 2) {
            problems.push(format!("token {} holds more than write", mint.token_id));
        }
    }
    for token in &o.tokens {
        if token.revoked_at.is_none() {
            problems.push(format!(
                "token {} is still live after the updates",
                token.id
            ));
        }
        if token.uses_after_revoke != 0 {
            problems.push(format!("token {} was used after it was revoked", token.id));
        }
    }
    // The audit log records each write, and no failure.
    if o.written == 0 {
        problems.push("no issue_status.written record exists".to_owned());
    }
    if o.failed != 0 {
        problems.push(format!("{} issue_status.failed record(s) exist", o.failed));
    }
    for leak in &o.leaks {
        problems.push(format!("a credential was found: {leak}"));
    }
    problems
}

async fn observe(lab: &Lab, issue: u64, status: JobStatus) -> Observed {
    let mut routes = BTreeMap::new();
    for request in lab.fake.requests() {
        *routes.entry(request.route).or_insert(0) += 1;
    }
    let mut added = Vec::new();
    let mut removed = Vec::new();
    for request in lab.fake.requests() {
        match request.route.as_str() {
            "POST /repos/{owner}/{repo}/issues/{number}/labels" => {
                if let Some(Value::Array(list)) = request.body_json().map(|b| b["labels"].clone()) {
                    added.extend(list.iter().filter_map(|l| l.as_str().map(str::to_owned)));
                }
            }
            "DELETE /repos/{owner}/{repo}/issues/{number}/labels/{name}" => {
                let name = request.path.rsplit('/').next().unwrap_or_default();
                removed.push(factory_testkit::fx::http::percent_decode(name));
            }
            _ => {}
        }
    }
    let count = |action: &str| {
        let sql = format!("SELECT count(*) FROM audit_events WHERE action = '{action}'");
        let db = &lab.deployment.db;
        async move { db.number(&sql).await }
    };
    Observed {
        job_status: status,
        routes,
        comments: lab.fake.comments(REPO, issue),
        labels: lab.fake.labels_of(REPO, issue),
        added,
        removed,
        mints: lab.fake.mints(),
        tokens: lab.fake.tokens(),
        merges: lab.fake.merge_attempts().len(),
        pulls: lab.fake.pull_numbers(REPO).len(),
        pushes: lab.fake.pushes().len(),
        written: usize::try_from(count("issue_status.written").await).unwrap_or(0),
        failed: usize::try_from(count("issue_status.failed").await).unwrap_or(0),
        leaks: lab.credential_leaks(issue).await,
    }
}

/// Runs one job to `COMPLETED` through the worker's own start-up functions, the worker's loop and
/// the scripted stages, with the person's decision in between, and returns what the issue holds.
/// `expect_status` says whether the run waits for the status to appear at each state.
async fn run_job(
    options: Options,
    expect_status: bool,
    change: impl FnOnce(&Lab),
) -> (Lab, u64, JobStatus) {
    let lab = Lab::start(Options {
        without_people: true,
        ..options
    })
    .await;
    change(&lab);
    let issue = lab.fake.add_issue(
        REPO,
        "Add a --json flag",
        "Please add a --json flag to the word count tool so other programs can read the counts.",
        REQUESTER.login,
        &["factory"],
    );
    let config =
        Arc::new(FactoryConfig::from_file(&lab.deployment.config_path).expect("the configuration"));
    let booted = boot(&config).await.expect("the worker boots");
    let world = external_ports(&booted, &config)
        .await
        .unwrap_or_else(|lines| panic!("BLOCKED: {lines:?}"));
    let step = issue_status(&booted, &config, &world).expect("the status step builds");
    let degraded = step
        .as_ref()
        .is_some_and(factory_composition::issue_status::StatusStep::is_off);
    let sweep = token_sweep(&booted, &config, &world).expect("the token sweep builds");

    let store = factory_storage::pg::PgStore::connect(worker_config(&lab.deployment.db).await)
        .await
        .expect("the store");
    let rig = PgWorld::new(store, lab.tenant, lab.repository, |_| {}).await;
    rig.script(StageKind::Approval)
        .evals_otherwise(Eval::HumanGate);
    let job: JobId = rig.admitted_job().await;
    {
        use factory_ports::store::Store as _;
        let mut tx = rig
            .store
            .begin(TenantScope::new(lab.tenant))
            .await
            .expect("a transaction");
        tx.record_original_request(NewOriginalRequest {
            id: RandomIds::new().expect("ids").new_uuid(),
            job,
            revision: 1,
            source: RequestSource::GithubIssue,
            source_ref: Some(format!("{REPO}#{issue}")),
            author_github_user_id: Some(REQUESTER.id),
            text: "Add a --json flag. Please add a --json flag.".to_owned(),
        })
        .await
        .expect("the original request");
        tx.commit().await.expect("commit");
    }

    let shutdown = Shutdown::new();
    let mut hooks: Vec<Arc<dyn factory_composition::hooks::BeforeClaim>> = vec![sweep];
    if let Some(step) = step {
        hooks.push(step.hook());
    }
    let mut worker_loop = WorkerLoop::shared(
        Arc::new(rig.restarted_engine()),
        Arc::new(TokioTicker),
        PgWorld::worker("worker-status"),
        PgWorld::loop_settings(),
        shutdown.clone(),
    )
    .with_active_jobs(Arc::clone(&booted.jobs));
    for hook in hooks {
        worker_loop = worker_loop.with_before_claim(hook);
    }

    let watcher = rig.restarted_engine();
    let labels_are = |lab: &Lab, wanted: &str| {
        let labels = lab.fake.labels_of(REPO, issue);
        labels
            .iter()
            .filter(|l| l.starts_with("factory: "))
            .collect::<Vec<_>>()
            == [&wanted.to_owned()]
    };
    let driver = async {
        let until = |seconds| tokio::time::Instant::now() + Duration::from_secs(seconds);
        // 1. The job reaches the wait for a person.
        let deadline = until(60);
        let waiting = loop {
            let view = watcher.job_view(lab.tenant, job).await.expect("a view");
            if view.status == JobStatus::WaitingForHuman {
                break view;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the job never waited: {view:#?}"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        // 2. The issue shows it: one label, the one comment.
        if expect_status {
            let deadline = until(60);
            while !(labels_are(&lab, WAITING) && lab.fake.comments(REPO, issue).len() == 1) {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the issue never showed the wait: {:?}",
                    lab.fake.labels_of(REPO, issue)
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        } else {
            tokio::time::sleep(Duration::from_secs(6)).await;
        }
        // 3. A person decides, and the job completes.
        let run = waiting
            .newest(StageKind::Approval)
            .expect("an approval run")
            .id;
        rig.approve(&watcher, job, run).await;
        let deadline = until(60);
        let done = loop {
            let view = watcher.job_view(lab.tenant, job).await.expect("a view");
            if view.status.is_terminal() {
                break view.status;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the job never ended: {view:#?}"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        // 4. The issue shows the end.
        if expect_status {
            let deadline = until(60);
            while !labels_are(&lab, DONE) {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the issue never showed the end: {:?}",
                    lab.fake.labels_of(REPO, issue)
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        } else {
            tokio::time::sleep(Duration::from_secs(6)).await;
        }
        done
    };
    let done = tokio::select! {
        done = driver => done,
        summary = worker_loop.run() => panic!("the loop ended by itself: {summary:?}"),
    };
    assert!(
        !degraded || !expect_status,
        "the status step was built in its off state"
    );
    shutdown.raise();
    booted.broker.shutdown();
    (lab, issue, done)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_job_is_written_on_its_issue_through_the_real_adapter_one_label_and_one_comment_edited() {
    let (lab, issue, status) = run_job(Options::default(), true, |_| {}).await;
    let observed = observe(&lab, issue, status).await;
    let problems = judge(&observed);
    assert!(
        problems.is_empty(),
        "{problems:#?}\nlabels {:?}\ncomments {:?}",
        observed.labels,
        observed.comments
    );
    // The evidence, for a person reading the run with --no-capture.
    println!("STATUS-RUN routes {:#?}", observed.routes);
    println!(
        "STATUS-RUN labels added {:?}, removed {:?}, at the end {:?}",
        observed.added, observed.removed, observed.labels
    );
    println!("STATUS-RUN the one comment: {:?}", observed.comments);
    println!(
        "STATUS-RUN tokens: {} minted, all revoked; audit written {}, failed {}",
        observed.mints.len(),
        observed.written,
        observed.failed
    );
}

// ---- deliberate breaks ------------------------------------------------------------------------

/// Break 1: the switch is off. Nothing is written, and the judgment says the issue shows nothing.
#[tokio::test(flavor = "multi_thread")]
async fn break_the_status_write_back_switched_off_is_caught() {
    let (lab, issue, status) = run_job(
        Options {
            config: Some(Box::new(|text| {
                text.replace(
                    "  api_base_url:",
                    "  write_issue_status: false\n  api_base_url:",
                )
            })),
            ..Options::default()
        },
        false,
        |_| {},
    )
    .await;
    let observed = observe(&lab, issue, status).await;
    let problems = judge(&observed);
    assert!(
        problems.iter().any(|p| p.contains("never written")),
        "{problems:#?}"
    );
    assert!(
        problems.iter().any(|p| p.contains("not once")),
        "{problems:#?}"
    );
    assert!(
        observed.labels == ["factory".to_owned()],
        "{:?}",
        observed.labels
    );
}

/// Break 2: the approval policy no longer lets the worker write a status without a person. The
/// step is built in its off state, the worker goes on and writes nothing: the job is not affected
/// and the judgment says so.
#[tokio::test(flavor = "multi_thread")]
async fn break_a_policy_row_that_asks_for_a_person_turns_the_write_back_off_and_is_caught() {
    let (lab, issue, status) = run_job(
        Options {
            checkout: Some(Box::new(|protected| {
                let path = protected.join("policies/approval.yaml");
                let text = std::fs::read_to_string(&path).expect("the approval policy");
                let from = "{ id: write_status_label,             min_level: L0, requires: none,";
                assert!(text.contains(from), "the approval policy no longer has the row; update this test");
                let to = "{ id: write_status_label,             min_level: L0, requires: human, approver_roles: [operator],";
                std::fs::write(&path, text.replace(from, to)).expect("the changed policy");
            })),
            ..Options::default()
        },
        false,
        |_| {},
    )
    .await;
    let observed = observe(&lab, issue, status).await;
    assert_eq!(
        observed.job_status,
        JobStatus::Completed,
        "the job was not affected"
    );
    let problems = judge(&observed);
    assert!(
        problems.iter().any(|p| p.contains("never written")),
        "{problems:#?}"
    );
}

/// Break 3: the App lacks the permission to write issues. The updates fail, are recorded as
/// failed, and the job still completes: the judgment names the missing status.
#[tokio::test(flavor = "multi_thread")]
async fn break_an_app_without_the_issues_permission_fails_each_write_and_is_caught() {
    // The fake's App is changed before the worker reads anything from it.
    let (lab, issue, status) = run_job(Options::default(), false, |lab| {
        lab.fake
            .set_app(AppConfig::factory_default().without_permission("issues"));
    })
    .await;
    let observed = observe(&lab, issue, status).await;
    assert_eq!(
        observed.job_status,
        JobStatus::Completed,
        "a failing GitHub never fails a job"
    );
    let problems = judge(&observed);
    assert!(
        problems.iter().any(|p| p.contains("never written")),
        "{problems:#?}"
    );
    assert!(
        problems.iter().any(|p| p.contains("issue_status.failed")),
        "{problems:#?}"
    );
}
