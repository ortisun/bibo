//! The loopback end-to-end run: the REAL worker, started from a configuration file in which every
//! external endpoint is a loopback fake, over a real PostgreSQL, judged from the outside.
//!
//! `scripts/e2e.sh` scenarios E3 to E9 run the pipeline with test doubles, and `apps/api/tests/
//! live_run.rs` proves the real adapters in a rig that copies the worker's assembly. This file
//! starts the binary itself (`factory-worker`, `FACTORY_CONFIG`), so the path from the file to the
//! adapters to the stage runs to the events to GitHub is the one a deployment takes. Only the other
//! side of each adapter is a fake: FX-GH for GitHub, a refusing server for the model providers and
//! another for the registry. Nothing here touched real GitHub, real providers or real keys. See
//! `docs/reports/real-adapter-loopback-e2e.md`.
//!
//! What the judgments read is what the fake GitHub received, and what the run left in PostgreSQL
//! (jobs, stage runs, audit, outbox, ledger), the artifact store and the worker's logs. They never
//! read the worker's memory.
//!
//! The checks are pure functions of an [`Observed`] value, so each deliberate break below runs the
//! same checks against a wiring that was damaged on purpose, and against evidence that was
//! doctored, and requires a complaint that names the broken fact.
//!
//! What needs a sandbox is not here: the classifier of the intake stage runs in a Docker container
//! of the pinned `agent` image. The scenarios that reach that point stop at it with a named cause.
//! `the_worker_probes_both_agent_tools_in_a_real_container_when_it_starts` is the one test here that
//! needs the images; it is ignored in the default suite and panics with `BLOCKED:` where they are
//! missing, which is never a pass. The whole job, to a draft pull request, is
//! `apps/api/tests/live_run.rs`, and it is `BLOCKED` in the same way.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use factory_domain::ids::JobId;
use factory_testkit::fx::canary::{Canary, CanarySet, Sweeper};
use factory_testkit::fx::github::{AppConfig, MintRecord, TokenView};
use factory_testkit::fx::sinks::{SinkCollector, SinkKind};
use serde_json::Value;
use support::loopback::*;

/// The name of the repository as an installation token is narrowed to it.
const REPO_NAME: &str = "word-count";

// ---- what a run is judged on ---------------------------------------------------------------

/// Everything the judgments read, collected after a run.
struct Observed {
    job: String,
    job_status: String,
    job_correlation: String,
    /// Stage kind and its status.
    stages: BTreeMap<String, String>,
    /// `METHOD /route/template` of each request the fake GitHub received, and how many.
    routes: BTreeMap<String, usize>,
    /// The same, for the requests it answered with a success.
    done: BTreeMap<String, usize>,
    comments: Vec<String>,
    labels: Vec<String>,
    mints: Vec<MintRecord>,
    tokens: Vec<TokenView>,
    merges: usize,
    pulls: usize,
    pushes: usize,
    permission_lookups: usize,
    provider_hits: Vec<String>,
    registry_hits: Vec<String>,
    audit: Vec<Value>,
    outbox: Vec<Value>,
    ledger_entries: usize,
    ledger_problem: Option<String>,
    /// Where a credential was found, with no value.
    leaks: Vec<String>,
    /// What the security policy says about the App's permissions.
    required: BTreeMap<String, String>,
    forbidden: Vec<String>,
}

fn level(text: &str) -> u8 {
    match text {
        "read" => 1,
        "write" => 2,
        "admin" => 3,
        _ => 0,
    }
}

/// The routes an intake that ends at a refusal or at the sandbox may use, and nothing else.
const INTAKE_ROUTES: [&str; 8] = [
    "GET /app",
    "POST /app/installations/{id}/access_tokens",
    "DELETE /installation/token",
    "GET /repos/{owner}/{repo}",
    "GET /repos/{owner}/{repo}/issues/{number}",
    "GET /repos/{owner}/{repo}/issues/{number}/events",
    "GET /repos/{owner}/{repo}/issues/{number}/comments",
    "POST /repos/{owner}/{repo}/issues/{number}/comments",
];

async fn observe(lab: &Lab, job: JobId, issue: u64) -> Observed {
    let mut routes = BTreeMap::new();
    let mut done = BTreeMap::new();
    for request in lab.fake.requests() {
        if request.status < 300 {
            *done.entry(request.route.clone()).or_insert(0) += 1;
        }
        *routes.entry(request.route).or_insert(0) += 1;
    }
    let stages = lab
        .stage_runs(job)
        .await
        .iter()
        .map(|run| {
            (
                run["stage_kind"].as_str().unwrap_or_default().to_owned(),
                run["status"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let correlation = lab
        .deployment
        .db
        .text(&format!(
            "SELECT correlation_id::text FROM jobs WHERE id = '{}'",
            job.as_uuid()
        ))
        .await
        .unwrap_or_default();
    let policies = factory_composition::startup::load_policy(&lab.protected, &[]).expect("policy");
    let app = &policies.security.credentials.github_app;
    let (ledger_entries, ledger_problem) = lab.ledger_check(job).await;
    Observed {
        job: job.as_uuid().to_string(),
        job_status: lab.job_status(job).await,
        job_correlation: correlation,
        stages,
        routes,
        done,
        comments: lab.fake.comments(REPO, issue),
        labels: lab.fake.labels_of(REPO, issue),
        mints: lab.fake.mints(),
        tokens: lab.fake.tokens(),
        merges: lab.fake.merge_attempts().len(),
        pulls: lab.fake.pull_numbers(REPO).len(),
        pushes: lab.fake.pushes().len(),
        permission_lookups: lab.fake.permission_lookups().len(),
        provider_hits: lab.provider_seen.all(),
        registry_hits: lab.registry_seen.all(),
        audit: lab.audit(job).await,
        outbox: lab.outbox(job).await,
        ledger_entries,
        ledger_problem,
        leaks: lab.credential_leaks(issue).await,
        required: app.permissions_required.clone(),
        forbidden: app.permissions_forbidden.clone(),
    }
}

// ---- the judgments --------------------------------------------------------------------------

/// What every run on the intake path must satisfy whatever the issue was.
fn judge_common(o: &Observed, ledger_expected: bool) -> Vec<String> {
    let mut problems = Vec::new();
    // Nothing that publishes, merges or pushes. These are separate facts, so each is reported.
    if o.merges != 0 {
        problems.push(format!("a merge was attempted {} time(s)", o.merges));
    }
    if o.pulls != 0 {
        problems.push(format!("{} pull request(s) exist", o.pulls));
    }
    if o.pushes != 0 {
        problems.push(format!("{} branch change(s) were pushed", o.pushes));
    }
    if o.permission_lookups != 0 {
        problems.push(
            "the collaborator-permission endpoint was used; the allowlist decides, not GitHub roles"
                .to_owned(),
        );
    }
    // Exactly the routes of the path, and no other.
    let allowed: BTreeSet<&str> = INTAKE_ROUTES.into_iter().collect();
    for route in o.routes.keys() {
        if !allowed.contains(route.as_str()) {
            problems.push(format!(
                "GitHub received a request on a route the path never uses: {route}"
            ));
        }
    }
    // Tokens: each narrowed to the one repository, with permissions the policy lists and none it
    // forbids, and none above what the policy requires.
    if o.mints.is_empty() {
        problems.push(
            "no installation token was requested, so nothing could have read the issue".to_owned(),
        );
    }
    for mint in &o.mints {
        match &mint.requested_repositories {
            Some(repositories) if repositories.len() == 1 && repositories[0] == REPO_NAME => {}
            other => problems.push(format!(
                "token {} was not narrowed to the one repository: asked for {other:?}",
                mint.token_id
            )),
        }
        if mint.granted_repositories != [REPO.to_owned()] {
            problems.push(format!(
                "token {} covers {:?}, not the one repository",
                mint.token_id, mint.granted_repositories
            ));
        }
        match &mint.requested_permissions {
            None => problems.push(format!(
                "token {} asked for no permission list, which means all of the App's",
                mint.token_id
            )),
            Some(permissions) => {
                for (name, wanted) in permissions {
                    if o.forbidden.iter().any(|f| f == name) {
                        problems.push(format!(
                            "token {} holds the forbidden permission {name}",
                            mint.token_id
                        ));
                    }
                    match o.required.get(name) {
                        Some(ceiling) if level(wanted) <= level(ceiling) => {}
                        _ => problems.push(format!(
                            "token {} asked for {name}: {wanted}, above what the policy grants the App",
                            mint.token_id
                        )),
                    }
                }
                // A token that writes carries nothing else of value: issues, and metadata to read.
                if permissions.values().any(|l| level(l) >= 2)
                    && permissions.iter().any(|(name, l)| {
                        !(name == "metadata" && l == "read") && !(name == "issues" && l == "write")
                    })
                {
                    problems.push(format!(
                        "token {} can write and carries more than issues: write and metadata: read: {permissions:?}",
                        mint.token_id
                    ));
                }
            }
        }
    }
    for token in &o.tokens {
        if token.uses_after_revoke != 0 {
            problems.push(format!(
                "token {} was used {} time(s) after it was revoked",
                token.id, token.uses_after_revoke
            ));
        }
    }
    // The model providers and the registry were never asked: no sandbox ran, so no agent did.
    if !o.provider_hits.is_empty() {
        problems.push(format!(
            "the model-provider fake received {:?}",
            o.provider_hits
        ));
    }
    if !o.registry_hits.is_empty() {
        problems.push(format!("the registry fake received {:?}", o.registry_hits));
    }
    // Later stages never started.
    for (kind, status) in &o.stages {
        if kind != "INTAKE" && status != "PENDING" {
            problems.push(format!(
                "the stage {kind} is {status}, but intake did not pass"
            ));
        }
    }
    if o.stages.len() != 13 {
        problems.push(format!("the job has {} stage runs, not 13", o.stages.len()));
    }
    // Events and evidence carry the job's correlation id, and the ledger chain verifies.
    for (name, rows) in [("audit", &o.audit), ("outbox", &o.outbox)] {
        if rows.is_empty() {
            problems.push(format!("the {name} of the job is empty"));
        }
        for row in rows {
            if row["correlation_id"] != Value::String(o.job_correlation.clone()) {
                problems.push(format!(
                    "a {name} row does not carry the job's correlation id: {row}"
                ));
            }
        }
    }
    let events: Vec<&str> = o
        .outbox
        .iter()
        .filter_map(|r| r["event_type"].as_str())
        .collect();
    if events.first() != Some(&"job.admitted") {
        problems.push(format!(
            "the job's events do not start with job.admitted: {events:?}"
        ));
    }
    // A gate that ran leaves ledger entries. A stage that stopped before any gate (a sandbox that
    // could not be made) leaves its cause in the audit log and nothing in the ledger.
    if ledger_expected && o.ledger_entries == 0 {
        problems.push("the evidence ledger of the job is empty".to_owned());
    }
    if let Some(problem) = &o.ledger_problem {
        problems.push(format!("the ledger chain does not verify: {problem}"));
    }
    // No credential anywhere.
    for leak in &o.leaks {
        problems.push(format!("a credential was found: {leak}"));
    }
    problems
}

/// An issue that intake refused: one answer on the issue, a blocked job, and no status written.
fn judge_refusal(o: &Observed, reason: &str) -> Vec<String> {
    let mut problems = judge_common(o, true);
    if o.job_status != "BLOCKED" {
        problems.push(format!("the job is {}, not BLOCKED", o.job_status));
    }
    if o.stages.get("INTAKE").map(String::as_str) != Some("BLOCKED") {
        problems.push(format!(
            "the INTAKE stage run is {:?}, not BLOCKED",
            o.stages.get("INTAKE")
        ));
    }
    if o.comments.len() != 1 {
        problems.push(format!(
            "the person got {} comment(s) on the issue, not exactly one",
            o.comments.len()
        ));
    }
    if !o
        .comments
        .iter()
        .any(|c| c.contains("design is not approved") || c.contains("`design: approved`"))
    {
        problems.push("the comment does not tell the person the design is not approved".to_owned());
    }
    if o.comments.iter().any(|c| c.contains("factory: ")) {
        problems.push("a status comment was written for an issue intake refused".to_owned());
    }
    if o.labels.iter().any(|l| l.starts_with("factory: ")) {
        problems.push(format!(
            "a status label was written for an issue intake refused: {:?}",
            o.labels
        ));
    }
    let reasons: Vec<String> = o
        .audit
        .iter()
        .filter(|r| r["action"] == "authorization_decision.denied")
        .map(|r| r["reason"].as_str().unwrap_or_default().to_owned())
        .collect();
    if !reasons
        .iter()
        .any(|r| r.contains("DESIGN_NOT_APPROVED") && r.contains(reason))
    {
        problems.push(format!(
            "no audit record denies the design with the reason {reason}: {reasons:?}"
        ));
    }
    // The only writes to GitHub are the one comment, and the only calls made are the intake's.
    if o.done
        .get("POST /repos/{owner}/{repo}/issues/{number}/comments")
        .copied()
        != Some(1)
    {
        problems.push("the answer was not posted exactly once".to_owned());
    }
    let events: Vec<&str> = o
        .outbox
        .iter()
        .filter_map(|r| r["event_type"].as_str())
        .collect();
    if events.last() != Some(&"job.blocked") || !events.contains(&"stage_run.blocked") {
        problems.push(format!(
            "the job's events do not end in a block: {events:?}"
        ));
    }
    problems
}

/// An approved design that stops at the sandbox: the gate passed and the image was not there.
fn judge_gate_passed_then_sandbox(o: &Observed) -> Vec<String> {
    judge_reached_the_sandbox(o, true)
}

/// An issue that reached the sandbox. `on_the_track` says whether it was on the design track, so
/// that the gate judged it, or was a small change that the gate does not touch.
fn judge_reached_the_sandbox(o: &Observed, on_the_track: bool) -> Vec<String> {
    let mut problems = judge_common(o, false);
    if o.job_status != "BLOCKED" {
        problems.push(format!(
            "the job is {}, not BLOCKED at the sandbox",
            o.job_status
        ));
    }
    let actions: Vec<(String, String)> = o
        .audit
        .iter()
        .map(|r| {
            (
                r["action"].as_str().unwrap_or_default().to_owned(),
                r["reason"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let gate_passed = actions.iter().any(|(a, r)| {
        a == "authorization_decision.granted"
            && r.starts_with("design gate passed")
            && r.contains("approver designation")
    });
    if on_the_track && !gate_passed {
        problems.push(format!(
            "no audit record says the design gate passed for an approver: {actions:?}"
        ));
    }
    if !on_the_track && actions.iter().any(|(_, r)| r.contains("design gate")) {
        problems.push(format!(
            "the design gate judged an issue that is not on the design track: {actions:?}"
        ));
    }
    if !actions.iter().any(|(a, r)| {
        a.starts_with("sandbox_created_posture_result_destroyed")
            && r.contains("the image is not on this host")
    }) {
        problems.push(format!(
            "the stop at the sandbox is not recorded with its cause: {actions:?}"
        ));
    }
    if !o.comments.is_empty() {
        problems.push(format!(
            "the issue got {} comment(s) although nothing was refused",
            o.comments.len()
        ));
    }
    if o.labels.iter().any(|l| l.starts_with("factory: ")) {
        problems.push(format!(
            "a status label was written before intake passed: {:?}",
            o.labels
        ));
    }
    if o.routes
        .contains_key("POST /repos/{owner}/{repo}/issues/{number}/comments")
    {
        problems.push("something was posted on the issue".to_owned());
    }
    problems
}

// ---- the worlds -------------------------------------------------------------------------

fn design_issue(lab: &Lab, label: &str, applied_by: Person) -> u64 {
    let number = lab.fake.add_issue(
        REPO,
        "Add a --json flag",
        "Please add a --json flag to the word count tool so other programs can read the counts.",
        REQUESTER.login,
        &["factory"],
    );
    lab.fake.label_issue(REPO, number, label, applied_by.login);
    number
}

/// Waits until the intake stage run is no longer waiting or running, then a little longer, so that
/// a write that should not happen has time to show.
async fn settle(lab: &mut Lab, job: JobId, what: &str) {
    lab.wait_for(what, 60, async |lab: &Lab| {
        let runs = lab.stage_runs(job).await;
        let intake = runs.iter().find(|r| r["stage_kind"] == "INTAKE")?;
        let status = intake["status"].as_str()?;
        (!matches!(status, "PENDING" | "READY" | "RUNNING")
            && lab.job_status(job).await == "BLOCKED")
            .then_some(())
    })
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
}

/// A catalog in which the agent image is a digest that no host has. The sandbox then stops the
/// stage on a host that has the real images as well as on one that has not.
fn catalog_without_the_agent_image(dir: &Path) -> PathBuf {
    let root = support::deployment::repository_root();
    let text = std::fs::read_to_string(root.join("infra/sandbox-images/images.json"))
        .expect("the catalog");
    let mut catalog: Value = serde_json::from_str(&text).expect("a JSON catalog");
    let absent = format!("sha256:{}", random_hex(32));
    let agent = &mut catalog["platforms"]["linux/arm64"]["images"]["agent"];
    agent["digest"] = Value::String(absent.clone());
    agent["image_id"] = Value::String(absent.clone());
    agent["reference"] = Value::String(format!("factory-sandbox/agent@{absent}"));
    let path = dir.join("images-without-the-agent.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&catalog).expect("json"))
        .expect("a catalog file");
    path
}

fn without_the_agent_image(text: String) -> String {
    // The deployment directory is the parent of the artifact root the configuration names.
    let marker = "artifacts: { root: ";
    let start = text.find(marker).expect("the artifacts root") + marker.len();
    let end = start
        + text[start..]
            .find("/artifacts }")
            .expect("the end of the root");
    let dir = PathBuf::from(&text[start..end]);
    let catalog = catalog_without_the_agent_image(&dir);
    let root = support::deployment::repository_root();
    text.replace(
        &format!("{}/infra/sandbox-images/images.json", root.display()),
        &catalog.display().to_string(),
    )
}

async fn run_refused(
    label: &str,
    by: Person,
    options: Options,
    env: &[(&str, &str)],
) -> (Lab, JobId, u64) {
    let mut lab = Lab::start(options).await;
    let issue = design_issue(&lab, label, by);
    let job = lab.receive_webhook_job(issue, REQUESTER).await;
    lab.spawn_worker(env);
    settle(&mut lab, job, "intake to refuse the issue").await;
    (lab, job, issue)
}

// ---- the scenarios ----------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_design_issue_without_approval_is_refused_through_the_real_adapters() {
    let (mut lab, job, issue) =
        run_refused("design: in review", REQUESTER, Options::default(), &[]).await;
    let observed = observe(&lab, job, issue).await;
    let problems = judge_refusal(&observed, "not_approved");
    assert!(problems.is_empty(), "{problems:#?}");
    // The worker was started from the file and stops when it is asked to.
    assert_eq!(lab.stop_worker(), Some(0), "{}", lab.logs().1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_design_approved_by_a_person_who_is_not_an_approver_is_refused() {
    // The requester applies `design: approved`. The allowlist lists them as a requester only.
    let (lab, job, issue) =
        run_refused("design: approved", REQUESTER, Options::default(), &[]).await;
    let observed = observe(&lab, job, issue).await;
    let problems = judge_refusal(&observed, "not_applied_by_an_approver");
    assert!(problems.is_empty(), "{problems:#?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_design_approved_by_an_approver_passes_the_gate_and_stops_at_the_sandbox_with_a_named_cause()
 {
    let mut lab = Lab::start(Options {
        config: Some(Box::new(without_the_agent_image)),
        ..Options::default()
    })
    .await;
    let issue = design_issue(&lab, "design: approved", APPROVER);
    let job = lab.receive_webhook_job(issue, REQUESTER).await;
    lab.spawn_worker(&[]);
    settle(&mut lab, job, "intake to reach the sandbox").await;
    let observed = observe(&lab, job, issue).await;
    let problems = judge_gate_passed_then_sandbox(&observed);
    assert!(problems.is_empty(), "{problems:#?}");
    assert_eq!(lab.stop_worker(), Some(0), "{}", lab.logs().1);
}

/// A small change: no design label was ever applied. The gate does not touch it, the person is not
/// answered, and the stage goes on to the sandbox.
#[tokio::test(flavor = "multi_thread")]
async fn an_issue_off_the_design_track_is_not_touched_by_the_gate_and_stops_at_the_sandbox() {
    let mut lab = Lab::start(Options {
        config: Some(Box::new(without_the_agent_image)),
        ..Options::default()
    })
    .await;
    let issue = lab.fake.add_issue(
        REPO,
        "Add a --json flag",
        "Please add a --json flag to the word count tool so other programs can read the counts.",
        REQUESTER.login,
        &["factory"],
    );
    let job = lab.receive_webhook_job(issue, REQUESTER).await;
    lab.spawn_worker(&[]);
    settle(&mut lab, job, "intake to reach the sandbox").await;
    let observed = observe(&lab, job, issue).await;
    let problems = judge_reached_the_sandbox(&observed, false);
    assert!(problems.is_empty(), "{problems:#?}");
    // The same evidence judged as an issue on the track is rejected: the two judgments differ.
    assert!(!judge_reached_the_sandbox(&observed, true).is_empty());
}

// ---- deliberate breaks ----------------------------------------------------------------------

/// Break 1: the GitHub adapter is pointed at the wrong base URL (the registry fake's). The worker
/// cannot read the issue, so nobody is answered. The judgment of a refusal must complain.
#[tokio::test(flavor = "multi_thread")]
async fn break_the_github_adapter_at_the_wrong_base_url_is_caught() {
    let mut lab = Lab::start(Options {
        config: Some(Box::new(|text| {
            // The registry fake is a different server on another port.
            let github = text
                .lines()
                .find_map(|l| {
                    l.trim()
                        .strip_prefix("api_base_url: '")
                        .map(|r| r.trim_end_matches('\'').to_owned())
                })
                .expect("the GitHub base URL");
            let registry = text
                .split("registry: { base_url: '")
                .nth(1)
                .and_then(|r| r.split('\'').next())
                .expect("the registry URL")
                .to_owned();
            text.replace(&github, &registry)
        })),
        ..Options::default()
    })
    .await;
    let issue = design_issue(&lab, "design: in review", REQUESTER);
    let job = lab.receive_webhook_job(issue, REQUESTER).await;
    lab.spawn_worker(&[]);
    // The intake cannot finish; give it time to try, then look.
    tokio::time::sleep(Duration::from_secs(12)).await;
    let observed = observe(&lab, job, issue).await;
    let problems = judge_refusal(&observed, "not_approved");
    assert!(
        problems.iter().any(|p| p.contains("not exactly one")),
        "{problems:#?}"
    );
    assert!(
        problems.iter().any(|p| p.contains("the job is")),
        "{problems:#?}"
    );
    assert!(
        !observed.registry_hits.is_empty()
            && problems
                .iter()
                .any(|p| p.contains("the registry fake received")),
        "the adapter's requests went to the wrong server and the judgment says so: {problems:#?}"
    );
    assert_eq!(lab.fake.requests().len(), 0, "GitHub received nothing");
}

/// Break 2: the App lacks the permission to write issues. The answer cannot be posted. The
/// judgment must complain that the person got no comment.
#[tokio::test(flavor = "multi_thread")]
async fn break_an_app_without_the_issues_write_permission_is_caught() {
    let mut lab = Lab::start(Options::default()).await;
    lab.fake
        .set_app(AppConfig::factory_default().without_permission("issues"));
    let issue = design_issue(&lab, "design: in review", REQUESTER);
    let job = lab.receive_webhook_job(issue, REQUESTER).await;
    lab.spawn_worker(&[]);
    tokio::time::sleep(Duration::from_secs(10)).await;
    let observed = observe(&lab, job, issue).await;
    let problems = judge_refusal(&observed, "not_approved");
    // The worker did ask for a token and GitHub did refuse it: the empty issue is not a worker that
    // never ran.
    assert!(
        lab.fake
            .requests()
            .iter()
            .any(|r| r.status >= 400 && r.route == "POST /app/installations/{id}/access_tokens"),
        "no token request was refused: {:?}",
        lab.fake
            .requests()
            .iter()
            .map(|r| (&r.route, r.status))
            .collect::<Vec<_>>()
    );
    assert!(
        problems.iter().any(|p| p.contains("got 0 comment(s)")),
        "the missing scope is caught as a missing answer: {problems:#?}"
    );
    let _ = lab.stop_worker();
}

/// Break 3: the design gate's policy file is gone from the protected checkout. The gate fails
/// closed: even an issue approved by an approver is not let through, and the person is told so.
#[tokio::test(flavor = "multi_thread")]
async fn break_a_missing_design_policy_stops_even_an_approved_issue_and_is_caught() {
    let mut lab = Lab::start(Options {
        checkout: Some(Box::new(|protected| {
            std::fs::remove_file(protected.join("policies/issue-workflow.yaml"))
                .expect("a policy file");
        })),
        ..Options::default()
    })
    .await;
    let issue = design_issue(&lab, "design: approved", APPROVER);
    let job = lab.receive_webhook_job(issue, REQUESTER).await;
    lab.spawn_worker(&[]);
    tokio::time::sleep(Duration::from_secs(10)).await;
    let observed = observe(&lab, job, issue).await;
    let problems = judge_gate_passed_then_sandbox(&observed);
    assert!(
        problems
            .iter()
            .any(|p| p.contains("no audit record says the design gate passed")),
        "{problems:#?}"
    );
    let (_, stderr) = lab.logs();
    assert!(
        stderr.contains("NOT READY"),
        "the worker says the gate cannot judge: {stderr}"
    );
    let _ = lab.stop_worker();
}

/// Break 4: the allowlist does not list the approver. The gate bites: the same issue that passed
/// is refused.
#[tokio::test(flavor = "multi_thread")]
async fn break_an_approver_missing_from_the_allowlist_is_refused_and_caught() {
    let mut lab = Lab::start(Options {
        checkout: Some(Box::new(|protected| {
            let path = protected.join("allowlist/allowlist.yaml");
            let text = std::fs::read_to_string(&path).expect("the allowlist");
            // Two header lines and the requester's entry of four lines; the approver's follows.
            let mut kept: String = text.lines().take(6).collect::<Vec<_>>().join("\n");
            kept.push('\n');
            std::fs::write(path, kept).expect("the allowlist");
        })),
        ..Options::default()
    })
    .await;
    let issue = design_issue(&lab, "design: approved", APPROVER);
    let job = lab.receive_webhook_job(issue, REQUESTER).await;
    lab.spawn_worker(&[]);
    settle(&mut lab, job, "intake to refuse").await;
    let observed = observe(&lab, job, issue).await;
    let problems = judge_gate_passed_then_sandbox(&observed);
    assert!(
        problems
            .iter()
            .any(|p| p.contains("no audit record says the design gate passed")),
        "{problems:#?}"
    );
    let refusal = judge_refusal(&observed, "not_applied_by_an_approver");
    assert!(
        refusal.is_empty(),
        "the same run is a clean refusal: {refusal:#?}"
    );
}

// ---- the judgments are shown to bite ------------------------------------------------------------

async fn clean_refusal() -> (Lab, Observed) {
    let (lab, job, issue) =
        run_refused("design: in review", REQUESTER, Options::default(), &[]).await;
    let observed = observe(&lab, job, issue).await;
    assert_eq!(
        judge_refusal(&observed, "not_approved"),
        Vec::<String>::new()
    );
    (lab, observed)
}

#[tokio::test(flavor = "multi_thread")]
async fn break_doctored_evidence_is_caught_by_each_judgment() {
    let (_lab, honest) = clean_refusal().await;
    let find = |problems: Vec<String>, needle: &str| {
        assert!(
            problems.iter().any(|p| p.contains(needle)),
            "expected a complaint containing {needle:?}, got {problems:#?}"
        );
    };
    // A merge call.
    let mut o = honest.clone_view();
    o.merges = 1;
    find(judge_refusal(&o, "not_approved"), "merge was attempted");
    // A pull request, a push, a collaborator-permission lookup.
    let mut o = honest.clone_view();
    o.pulls = 1;
    o.pushes = 1;
    o.permission_lookups = 1;
    let problems = judge_refusal(&o, "not_approved");
    find(problems.clone(), "pull request(s) exist");
    find(problems.clone(), "pushed");
    find(problems, "collaborator-permission");
    // A route the path never uses.
    let mut o = honest.clone_view();
    o.routes.insert(
        "PUT /repos/{owner}/{repo}/pulls/{number}/merge".to_owned(),
        1,
    );
    find(
        judge_refusal(&o, "not_approved"),
        "route the path never uses",
    );
    // A token that is not narrowed, and one that holds a forbidden permission or asks for more
    // than the policy grants.
    let mut o = honest.clone_view();
    o.mints[0].requested_repositories = None;
    find(
        judge_refusal(&o, "not_approved"),
        "not narrowed to the one repository",
    );
    let mut o = honest.clone_view();
    o.mints[0].requested_repositories = Some(vec![REPO_NAME.to_owned(), "other".to_owned()]);
    find(
        judge_refusal(&o, "not_approved"),
        "not narrowed to the one repository",
    );
    let mut o = honest.clone_view();
    o.mints[0]
        .requested_permissions
        .as_mut()
        .expect("permissions")
        .insert("administration".to_owned(), "write".to_owned());
    find(
        judge_refusal(&o, "not_approved"),
        "forbidden permission administration",
    );
    let mut o = honest.clone_view();
    o.mints[1]
        .requested_permissions
        .as_mut()
        .expect("permissions")
        .insert("contents".to_owned(), "write".to_owned());
    find(
        judge_refusal(&o, "not_approved"),
        "can write and carries more",
    );
    // A second comment (a duplicate answer), a status label and a status comment on a refused issue.
    let mut o = honest.clone_view();
    o.comments.push("another".to_owned());
    find(judge_refusal(&o, "not_approved"), "not exactly one");
    let mut o = honest.clone_view();
    o.labels.push("factory: working".to_owned());
    find(
        judge_refusal(&o, "not_approved"),
        "status label was written",
    );
    // A later stage that started anyway.
    let mut o = honest.clone_view();
    o.stages
        .insert("SPECIFICATION".to_owned(), "RUNNING".to_owned());
    find(judge_refusal(&o, "not_approved"), "intake did not pass");
    // A request that reached a model provider.
    let mut o = honest.clone_view();
    o.provider_hits.push("POST /v1/messages".to_owned());
    find(
        judge_refusal(&o, "not_approved"),
        "model-provider fake received",
    );
    // A row without the job's correlation id, a broken ledger and a leak.
    let mut o = honest.clone_view();
    o.outbox[0]["correlation_id"] =
        Value::String("00000000-0000-0000-0000-000000000000".to_owned());
    find(judge_refusal(&o, "not_approved"), "correlation id");
    let mut o = honest.clone_view();
    o.ledger_problem = Some("a link is broken".to_owned());
    find(
        judge_refusal(&o, "not_approved"),
        "ledger chain does not verify",
    );
    let mut o = honest.clone_view();
    o.leaks.push("token in stderr".to_owned());
    find(judge_refusal(&o, "not_approved"), "a credential was found");
}

/// The credential sweep is not a formality: a token planted in each kind of sink is found.
#[tokio::test(flavor = "multi_thread")]
async fn break_the_credential_sweep_finds_a_token_planted_in_a_log_an_audit_row_and_an_artifact() {
    let (lab, job, issue) =
        run_refused("design: in review", REQUESTER, Options::default(), &[]).await;
    let token = lab
        .fake
        .minted_secrets()
        .first()
        .expect("a minted token")
        .value()
        .to_owned();
    let mut sweeper = Sweeper::new(&CanarySet::generate());
    sweeper.add(&Canary::custom("planted-token", &token));
    let sinks = SinkCollector::new();
    sinks.record(
        SinkKind::Stderr,
        "worker",
        format!("{{\"message\":\"retrying with {token}\"}}"),
    );
    sinks.record(
        SinkKind::AuditRow,
        "audit_events",
        format!("{{\"reason\":\"used {token}\"}}"),
    );
    sinks.record(SinkKind::Artifact, "artifact", token.as_bytes());
    let report = sinks.sweep(&sweeper);
    assert_eq!(report.hits.len(), 3, "{:?}", report.hits);
    // And the same sweep of the real run, with the same canary, is clean.
    let observed = observe(&lab, job, issue).await;
    assert!(observed.leaks.is_empty(), "{:?}", observed.leaks);
}

/// The same refusal with the worker's log filter at `trace`. A credential that only a verbose log
/// would carry (a header of a request, a token in a retry message) would be found here. The worker
/// and the libraries it links write almost nothing more at `trace` (six lines in all in the run this
/// was written from), so this shows that the filter is no way to a credential and nothing more.
#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_leaves_no_credential_with_the_log_filter_at_trace() {
    let (mut lab, job, issue) = run_refused(
        "design: in review",
        REQUESTER,
        Options::default(),
        &[("FACTORY_LOG", "trace")],
    )
    .await;
    let observed = observe(&lab, job, issue).await;
    let problems = judge_refusal(&observed, "not_approved");
    assert!(problems.is_empty(), "{problems:#?}");
    let (_, stderr) = lab.logs();
    println!("TRACE-LOG lines {}", stderr.lines().count());
    assert!(stderr.contains("worker loop started"), "{stderr}");
    let _ = lab.stop_worker();
}

/// GitHub fails the way it does: a token request answered 502, the issue read answered 429 with a
/// `Retry-After`, and the one comment post answered 502. The test doubles never fail like this. The
/// adapter retries the first two inside the call; the failed post fails the attempt, and the engine
/// runs it again. The person is answered exactly once.
#[tokio::test(flavor = "multi_thread")]
async fn transient_github_failures_are_retried_and_the_person_is_answered_exactly_once() {
    let mut lab = Lab::start(Options::default()).await;
    let issue = design_issue(&lab, "design: in review", REQUESTER);
    lab.fake.fail_next(
        "POST /app/installations/{id}/access_tokens",
        502,
        "Bad Gateway",
    );
    lab.fake
        .rate_limit_next("GET /repos/{owner}/{repo}/issues/{number}", 1);
    lab.fake.fail_next(
        "POST /repos/{owner}/{repo}/issues/{number}/comments",
        502,
        "Bad Gateway",
    );
    let job = lab.receive_webhook_job(issue, REQUESTER).await;
    lab.spawn_worker(&[]);
    settle(
        &mut lab,
        job,
        "intake to refuse the issue after the failures",
    )
    .await;
    let observed = observe(&lab, job, issue).await;
    let problems = judge_refusal(&observed, "not_approved");
    assert!(problems.is_empty(), "{problems:#?}");
    let statuses: Vec<u16> = lab.fake.requests().iter().map(|r| r.status).collect();
    for failed in [502, 429] {
        assert!(
            statuses.contains(&failed),
            "the fault {failed} never happened: {statuses:?}"
        );
    }
    let events: Vec<&str> = observed
        .outbox
        .iter()
        .filter_map(|r| r["event_type"].as_str())
        .collect();
    assert!(
        events.contains(&"attempt.failed"),
        "the failed attempt is in the events: {events:?}"
    );
    assert_eq!(observed.comments.len(), 1);
}

// ---- the real start-up probe ----------------------------------------------------------------

/// The scenarios above declare the capabilities of the agent tools (`declare_capabilities`), as the
/// local profile allows, because the real probe runs both tools in a container of the agent image.
/// Without the image the probe cannot run, and the worker must say so and not start. This is the
/// one place where the real-adapter path differs most from the declared one.
#[tokio::test(flavor = "multi_thread")]
async fn a_worker_that_must_probe_its_tools_is_blocked_and_says_why_when_the_agent_image_is_missing()
 {
    let mut lab = Lab::start(Options {
        config: Some(Box::new(|text| {
            without_the_agent_image(text.replace("runtimes: { declare_capabilities: true }\n", ""))
        })),
        ..Options::default()
    })
    .await;
    assert!(
        !std::fs::read_to_string(&lab.deployment.config_path)
            .expect("config")
            .contains("declare_capabilities"),
        "the configuration still declares the capabilities"
    );
    lab.spawn_worker(&[]);
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = lab.worker_ended() {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the worker neither started nor stopped"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let (_, stderr) = lab.logs();
    assert_eq!(status.code(), Some(3), "{stderr}");
    let blocked: Vec<&str> = stderr
        .lines()
        .filter(|l| l.starts_with("BLOCKED: "))
        .collect();
    assert!(
        blocked
            .iter()
            .any(|l| l.starts_with("BLOCKED: CapabilityProbes: runtimes: ")),
        "the BLOCKED line names the port and the key: {blocked:?}"
    );
    println!("BLOCKED-LINES {blocked:#?}");
    assert!(stderr.contains("BLOCKED is not a pass"), "{stderr}");
    // It claimed no work and spoke to nobody.
    assert_eq!(
        lab.fake.requests().len(),
        0,
        "GitHub was not asked anything"
    );
    assert!(lab.provider_seen.all().is_empty() && lab.registry_seen.all().is_empty());
}

// ---- what needs the Docker daemon and the pinned images -------------------------------------------

/// The cross-process lock of the real-Docker tests that make a network, shared with the sandbox,
/// runtime and live-run tests, so that they wait for each other.
#[allow(dead_code)]
#[path = "../../../crates/sandbox/tests/support/docker_lock.rs"]
mod docker_lock;

/// The reference of an image of the catalog, or a `BLOCKED:` panic when the catalog does not name
/// it, says it is not ready, or this host does not have it. Images are never pulled.
fn require_image(kind: &str) -> String {
    let root = support::deployment::repository_root();
    let text = std::fs::read_to_string(root.join("infra/sandbox-images/images.json"))
        .expect("the catalog");
    let catalog: Value = serde_json::from_str(&text).expect("a JSON catalog");
    let entry = &catalog["platforms"]["linux/arm64"]["images"][kind];
    let reference = entry["reference"]
        .as_str()
        .unwrap_or_else(|| panic!("BLOCKED: the catalog names no {kind} image"));
    assert!(
        entry["status"] == "ready",
        "BLOCKED: the {kind} image is not ready in the catalog"
    );
    let found = std::process::Command::new("docker")
        .args(["image", "inspect", "--format", "{{.Id}}", reference])
        .output()
        .is_ok_and(|out| out.status.success());
    assert!(
        found,
        "BLOCKED: the image {reference} is not on this host (images are never pulled), so the {kind} sandbox cannot be made"
    );
    reference.to_owned()
}

/// The worker started from the file, with the capabilities of its agent tools probed in a real
/// container of the real `agent` image, behind the real egress sidecar, as a deployment does.
/// The probe asks no model anything, so the provider fake must see no request.
///
/// **Not run on a host without the images, and not run by this work at all:** this host has none,
/// so the test ends at the first line below with `BLOCKED:`, which is never a pass. The part after
/// the check was written from `apps/api/tests/live/mod.rs` (which has run the same probe against the
/// images) and has not been run.
///
/// ```text
/// cargo nextest run -p factory-worker --run-ignored only --test loopback_e2e
/// ```
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Docker daemon, the pinned images and the shared network lock; see the head of the test"]
async fn the_worker_probes_both_agent_tools_in_a_real_container_when_it_starts() {
    use factory_testkit::fx::docker::DockerGuard;
    let docker = DockerGuard::from_environment();
    let scope = docker.require_or_block();
    let verify = require_image("verify");
    let _agent = require_image("agent");
    let _sidecar = require_image("egress-sidecar");
    // Waits for the machine's lock for five minutes at most, so that nextest's limit of ten minutes
    // for a test is never what ends the wait.
    let _lock = docker_lock::DockerLock::acquire_at(
        &docker_lock::default_lock_path(),
        Duration::from_secs(300),
    )
    .unwrap_or_else(|waited| panic!("{waited}"));
    // Where the host is, as a container on the default bridge sees it. The sidecar is the one
    // container with a way out, and the worker's broker is the only place it relays to.
    let [label_key, label_value] = scope.label_args();
    let resolved = scope
        .cli()
        .run(&[
            "run",
            "--rm",
            "--pull=never",
            &label_key,
            &label_value,
            &verify,
            "getent",
            "hosts",
            "host.docker.internal",
        ])
        .unwrap_or_else(|error| panic!("BLOCKED: the docker client could not run: {error}"));
    assert!(
        resolved.success(),
        "BLOCKED: host.docker.internal does not resolve in the verify image"
    );
    let host_ip = resolved
        .stdout
        .split_whitespace()
        .next()
        .expect("an address")
        .to_owned();
    let run = scope.label().value().to_owned();

    let mut lab = Lab::start(Options {
        config: Some(Box::new(move |text| {
            let port = text
                .split("listen: '127.0.0.1:")
                .nth(1)
                .and_then(|rest| rest.split('\'').next())
                .expect("the broker port")
                .to_owned();
            text.replace("runtimes: { declare_capabilities: true }\n", "")
                .replace(&format!("listen: '127.0.0.1:{port}'"), &format!("listen: '0.0.0.0:{port}'"))
                .replace(
                    "/remote } }",
                    &format!(
                        "/remote }}, labels: {{ factory.test: 'true', factory.test.owner: loopback-e2e, factory.test.run: '{run}' }}, sidecar_command: [--mode, broker, --listen, '0.0.0.0:8443', --upstream, '{host_ip}:{port}', --job, loopback-e2e] }}"
                    ),
                )
        })),
        ..Options::default()
    })
    .await;
    lab.spawn_worker(&[]);
    lab.wait_for(
        "the worker to start its loop after the probe",
        180,
        async |lab: &Lab| lab.logs().1.contains("worker loop started").then_some(()),
    )
    .await;
    let (_, stderr) = lab.logs();
    assert!(!stderr.contains("BLOCKED"), "{stderr}");
    assert!(
        lab.provider_seen.all().is_empty(),
        "a version probe asks no model: {:?}",
        lab.provider_seen.all()
    );
    assert_eq!(lab.stop_worker(), Some(0), "{}", lab.logs().1);
}

impl Observed {
    fn clone_view(&self) -> Self {
        Self {
            job: self.job.clone(),
            job_status: self.job_status.clone(),
            job_correlation: self.job_correlation.clone(),
            stages: self.stages.clone(),
            routes: self.routes.clone(),
            done: self.done.clone(),
            comments: self.comments.clone(),
            labels: self.labels.clone(),
            mints: self.mints.clone(),
            tokens: self.tokens.clone(),
            merges: self.merges,
            pulls: self.pulls,
            pushes: self.pushes,
            permission_lookups: self.permission_lookups,
            provider_hits: self.provider_hits.clone(),
            registry_hits: self.registry_hits.clone(),
            audit: self.audit.clone(),
            outbox: self.outbox.clone(),
            ledger_entries: self.ledger_entries,
            ledger_problem: self.ledger_problem.clone(),
            leaks: self.leaks.clone(),
            required: self.required.clone(),
            forbidden: self.forbidden.clone(),
        }
    }
}
