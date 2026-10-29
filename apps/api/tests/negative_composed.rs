//! The cross-cutting negative tests that need the whole composed pipeline: the real API server on
//! loopback, the real engine and all thirteen stage handlers on a real PostgreSQL, over the labelled
//! fakes of the rig of `full/mod.rs` (the scripted agents, the fake sandbox, the fake code host).
//! They belong to the work package `s1-security-review-and-tests`. The workflow target of
//! `crates/workflow/tests/security` cannot link the API (rule DEP-01), so these live here.
//!
//! * NT-SEC-01, composed. A canary of every class of secret is planted where a job meets it: in
//!   the text of the issue, in the files of the repository, in the output of the builder and of the
//!   reviewer, and in requests that are refused. The job runs from the signed webhook to its
//!   completion through the API. Then every sink the API can serve or the store holds is swept: the
//!   answers of the API (status, timeline, gate reports, every stored artifact), the error bodies of
//!   rejected requests, the pull request body and the comments of the code host, the audit log, the
//!   outbox, the ledger, a dump of every table, the artifact store, the prompts, the log lines and
//!   the recording the end-to-end recorder writes.
//! * NT-INJ-04, composed. A job token of a running job is presented to every operation of
//!   `apps/api/openapi.json`, enumerated from the document, in every place a credential can sit.
//!   Each answer is the answer of a request with no credential, and the authority tables of the
//!   store are as they were.
//! * NT-AUD-03, the API part. A webhook the API accepts is audited as
//!   `webhook_accepted_or_rejected.granted` and one it rejects as
//!   `webhook_accepted_or_rejected.denied`, and under no other name.
//!
//! The fake sandbox stores the output of a command without redacting it, as its contract says the
//! real adapter does (`crates/sandbox`, NT-SEC-02), so this run plants no canary in the standard
//! output of a command: a hit there would be the fake's and not the factory's.

#[allow(dead_code, unused_imports)]
#[path = "../../../crates/workflow/tests/validation/cargo.rs"]
mod cargo;
#[allow(dead_code, unused_imports)]
#[path = "../../../crates/workflow/tests/security/classes.rs"]
mod classes;
mod e2e;
mod full;
#[allow(dead_code)]
mod playbook;
mod support;

use std::collections::BTreeMap;
use std::time::Duration;

use e2e::journey::{Filed, Journey, begin, get};
use e2e::{Extras, Tokens, Transitions};
use factory_domain::scope::TenantScope;
use factory_domain::state::StageRunStatus;
use factory_domain::vocabulary::StageKind;
use factory_ports::store::{AuditFilter, OutboxSeq};
use factory_testkit::fx::canary::{CanarySet, Sweeper};
use factory_testkit::fx::sinks::{SinkCollector, SinkKind};
use full::Options;
use serde_json::{Value, json};
use support::{Env, Reply, Req, eventually};

// ---- what is planted --------------------------------------------------------------------------

/// The values of the canaries that sit on one line, `label=value`, one to a line.
fn env_file(canaries: &CanarySet) -> String {
    let mut text = canaries
        .iter()
        .filter(|c| !c.value().contains('\n'))
        .map(|c| format!("{}={}", c.label(), c.value()))
        .collect::<Vec<_>>()
        .join("\n");
    text.push('\n');
    text
}

/// The values a deployment registers with the redactor at start-up (`FactorySecrets`): the webhook
/// secret, database credentials and the key that signs decisions. A pattern cannot find them,
/// because they have no shape; the registry can, in every encoding the policy names.
fn registered_by_the_deployment(canaries: &CanarySet) -> Vec<(&'static str, String)> {
    [
        ("webhook_secret", "webhook_secret"),
        ("database_password", "database_credentials"),
        ("decision_signing_key", "decision_signing_key"),
    ]
    .into_iter()
    .filter_map(|(canary, label)| {
        canaries
            .by_label(canary)
            .map(|c| (label, c.value().to_owned()))
    })
    .collect()
}

/// The files of the repository that a careless owner left secrets in.
fn planted_files(canaries: &CanarySet) -> Vec<(String, String)> {
    let one_line = |label: &str| {
        canaries
            .by_label(label)
            .map(|c| c.value().to_owned())
            .unwrap_or_default()
    };
    vec![
        (".env".to_owned(), env_file(canaries)),
        ("tests/holdout/secret.txt".to_owned(), env_file(canaries)),
        (
            "docs/request-notes.md".to_owned(),
            format!(
                "Notes of the requester. My token for the build is {}.\n",
                one_line("github_token_classic")
            ),
        ),
    ]
}

/// The environment a careless requester pastes into an issue: what the requester could hold. The
/// holdout string (test data held back from the builder) and a second tenant's string are nothing a
/// requester has, so they are not in the issue; the sweep looks for them in every sink all the same.
fn requesters_environment(canaries: &CanarySet) -> String {
    let mut text = canaries
        .iter()
        .filter(|c| !c.value().contains('\n'))
        .filter(|c| !matches!(c.label(), "holdout_string" | "second_tenant_string"))
        .map(|c| format!("{}={}", c.label(), c.value()))
        .collect::<Vec<_>>()
        .join("\n");
    text.push('\n');
    text
}

/// The issue as a careless requester wrote it: a canary in the title and every one-line canary the
/// requester could hold in the text.
fn planted_issue(canaries: &CanarySet) -> Filed {
    let title_secret = canaries
        .by_label("api_token")
        .map(|c| c.value().to_owned())
        .unwrap_or_default();
    Filed {
        title: format!("Add a --json flag (my key is {title_secret})"),
        body: format!(
            "Please add a --json flag to the word count tool so other programs can read the counts.\n\nFor reference, my environment:\n{}",
            requesters_environment(canaries)
        ),
    }
}

/// Appends a canary to the free-text fields of the answer of an agent: what the builder says it
/// did and what the reviewer says it found.
fn leak_into(reply: &mut playbook::Reply, text: &str) {
    fn walk(value: &mut Value, text: &str) {
        match value {
            Value::Object(map) => {
                for (key, inner) in map.iter_mut() {
                    match inner {
                        Value::String(held)
                            if matches!(key.as_str(), "summary" | "message" | "rationale") =>
                        {
                            held.push(' ');
                            held.push_str(text);
                        }
                        other => walk(other, text),
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(|item| walk(item, text)),
            _ => {}
        }
    }
    walk(&mut reply.output, text);
}

// ---- the sinks ---------------------------------------------------------------------------------

/// Requests the API refuses, each carrying a canary where the caller put it, and the answers.
async fn refused_requests(journey: &Journey, canaries: &CanarySet) -> Vec<(String, Reply)> {
    let value = |label: &str| {
        canaries
            .by_label(label)
            .map(|c| c.value().to_owned())
            .unwrap_or_default()
    };
    let job = journey.job;
    let model_key = value("model_api_key");
    let token = value("github_installation_token");
    let job_token = value("job_token");
    let password = value("database_password");
    let requests: Vec<(&str, Req)> = vec![
        (
            "a job id that is a key",
            Req::get(&format!("/v1/jobs/{model_key}")).bearer(&journey.requester),
        ),
        (
            "an artifact hash that is a key",
            Req::get(&format!("/v1/jobs/{job}/artifacts/{model_key}")).bearer(&journey.requester),
        ),
        (
            "a query that carries a token",
            Req::get(&format!("/v1/jobs?access_token={token}")).bearer(&journey.requester),
        ),
        (
            "a job request that carries a token",
            Req::post("/v1/jobs")
                .bearer(&journey.requester)
                .json(&json!({ "title": token, "body": format!("password {password}") })),
        ),
        (
            "a decision that carries secrets in every field",
            Req::post(&format!("/v1/jobs/{job}/decisions"))
                .bearer(&journey.approver)
                .header("Idempotency-Key", &format!("refused-{job}"))
                .json(&json!({
                    "verb": "approve",
                    "stage_run_id": token,
                    "head": password,
                    "evidence": model_key,
                    "reason": format!("because {token}"),
                })),
        ),
        (
            "a bearer that is a job token",
            Req::get("/v1/jobs").header("Authorization", &format!("Bearer {job_token}")),
        ),
        (
            "a delivery that is not signed and carries a token",
            Req::post("/v1/webhooks/github")
                .header("X-GitHub-Event", "issues")
                .header("X-GitHub-Delivery", "0190a3b2-7c4d-4e5f-8a6b-000000000099")
                .header("X-Hub-Signature-256", &format!("sha256={token}"))
                .header("Content-Type", "application/json")
                .body(format!("{{\"leak\": \"{token}\"}}").into_bytes()),
        ),
    ];
    let mut sent = Vec::new();
    for (label, request) in requests {
        sent.push((label.to_owned(), journey.rig.env.send(request).await));
    }
    sent
}

/// Every table the store holds, as one JSON text for each.
async fn dump_of_every_table(env: &Env) -> Vec<(String, String)> {
    let tables = env
        .db
        .text(
            "SELECT string_agg(table_name, ',' ORDER BY table_name) FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_type = 'BASE TABLE'",
        )
        .await
        .unwrap_or_default();
    let mut dumps = Vec::new();
    for table in tables.split(',').filter(|t| !t.is_empty()) {
        let rows = env
            .db
            .text(&format!(
                "SELECT string_agg(row_to_json(t)::text, E'\\n') FROM {table} t"
            ))
            .await
            .unwrap_or_default();
        dumps.push((table.to_owned(), rows));
    }
    dumps
}

/// Reads every sink of the run into a collector. The collector is returned with the number of
/// each kind of sink, so that a sweep of nothing cannot pass.
async fn collect_sinks(journey: &Journey, refused: &[(String, Reply)]) -> SinkCollector {
    let rig = &journey.rig;
    let sinks = SinkCollector::new();
    let scope = TenantScope::new(rig.tenant);

    // What the API serves to the two people, and what it answered to the requests it refused.
    let job = journey.job;
    for (who, token) in [
        ("requester", &journey.requester),
        ("approver", &journey.approver),
    ] {
        for path in [
            "/v1/jobs".to_owned(),
            format!("/v1/jobs/{job}"),
            format!("/v1/jobs/{job}/timeline"),
            format!("/v1/jobs/{job}/specification-draft"),
            format!("/v1/jobs/{job}/gate-reports"),
        ] {
            let reply = get(rig, token, &path).await;
            sinks.record(
                SinkKind::ApiResponse,
                &format!("{who} {path}"),
                format!("{}\n{:?}\n{}", reply.status, reply.headers, reply.text()),
            );
        }
    }
    for (label, reply) in refused {
        sinks.record(
            SinkKind::ApiResponse,
            &format!("refused: {label}"),
            format!("{}\n{:?}\n{}", reply.status, reply.headers, reply.text()),
        );
    }

    // The store: audit, outbox, ledger, and the stage runs with their artifacts.
    let mut tx = rig.store.begin(scope).await.expect("a transaction");
    for record in tx
        .read_audit(AuditFilter::Tenant, 0, 5000)
        .await
        .expect("audit")
    {
        sinks.record(
            SinkKind::AuditRow,
            &format!("audit#{}", record.sequence),
            format!("{record:?}"),
        );
    }
    for event in tx
        .read_events(job, OutboxSeq::START, 5000)
        .await
        .expect("events")
    {
        sinks.record(SinkKind::OutboxRow, "outbox", format!("{event:?}"));
    }
    let ledger = factory_composition::reading::Reader::job_ledger(&mut *tx, job)
        .await
        .expect("the ledger");
    for entry in &ledger {
        sinks.record_json(
            SinkKind::DatabaseDump,
            "ledger",
            &serde_json::to_value(entry).expect("an entry serializes"),
        );
    }
    let runs = tx.list_stage_runs(job).await.expect("runs");
    let mut hashes = Vec::new();
    // What each stored document is called, so that a hit names the stage and the role.
    let mut roles: BTreeMap<String, String> = BTreeMap::new();
    for run in &runs {
        for link in tx
            .list_stage_run_artifacts(run.value.id)
            .await
            .expect("links")
        {
            let hash = link.sha256.as_str().to_owned();
            roles.insert(
                hash.trim_start_matches("sha256:").to_owned(),
                format!("{} {}", run.value.kind.as_str(), link.role.as_str()),
            );
            hashes.push(hash);
        }
    }
    let _ = tx.rollback().await;
    hashes.sort();
    hashes.dedup();
    // Every stored artifact, read the way the API serves it.
    for hash in &hashes {
        let reply = get(
            rig,
            &journey.requester,
            &format!("/v1/jobs/{job}/artifacts/{hash}"),
        )
        .await;
        sinks.record(
            SinkKind::ApiResponse,
            &format!("artifact {hash}"),
            reply.body.clone(),
        );
    }
    // And every file of the artifact root, which also holds what no record links (transcripts).
    let mut stack = vec![rig.artifact_root()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let role = roles
                    .get(&name)
                    .map_or("not linked to a stage run", String::as_str);
                sinks.record(
                    SinkKind::Artifact,
                    &format!("artifact {role} {name}"),
                    bytes,
                );
            }
        }
    }
    for (table, rows) in dump_of_every_table(&rig.env).await {
        sinks.record(SinkKind::DatabaseDump, &format!("table {table}"), rows);
    }

    // The code host: the description of each pull request and every comment.
    for (pr, body) in rig.host.pull_request_bodies() {
        sinks.record(
            SinkKind::PullRequestText,
            &format!("pull request #{} description", pr.number),
            body,
        );
        for (index, comment) in rig
            .host
            .comments_on(&factory_ports::githost::CommentTarget::PullRequest(
                pr.clone(),
            ))
            .into_iter()
            .enumerate()
        {
            sinks.record(
                SinkKind::PullRequestText,
                &format!("pull request #{} comment {index}", pr.number),
                comment,
            );
        }
    }
    for (index, comment) in rig
        .host
        .comments_on(&factory_ports::githost::CommentTarget::Issue(
            factory_ports::githost::IssueRef {
                repo: rig.repo.clone(),
                number: full::ISSUE,
            },
        ))
        .into_iter()
        .enumerate()
    {
        sinks.record(
            SinkKind::PullRequestText,
            &format!("issue comment {index}"),
            comment,
        );
    }
    for request in rig.host.recorded_requests() {
        sinks.record(
            SinkKind::GithubRequest,
            "request",
            format!("{} {}", request.method, request.path),
        );
    }

    // The prompts and the log lines of the whole process.
    for prompt in rig.runtime_prompts() {
        sinks.record(SinkKind::CapturedPrompt, "prompt", prompt);
    }
    for line in support::captured().lock().expect("lock").iter() {
        sinks.record(SinkKind::LogLine, "log line", line.clone());
    }

    // The recording the end-to-end recorder writes for this run, file by file.
    let collected = e2e::collect(
        rig,
        Some(job),
        "negative-composed",
        &Tokens {
            requester: journey.requester.clone(),
        },
        Extras {
            issue_number: full::ISSUE,
            ..Extras::default()
        },
        &Transitions::load(&full::root()),
    )
    .await;
    let dir = rig.scratch.join("recordings").join("negative-composed");
    e2e::write(&dir, &collected);
    let mut stack = vec![dir];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                sinks.record(
                    SinkKind::Artifact,
                    &format!("recording {}", path.display()),
                    bytes,
                );
            }
        }
    }
    sinks
}

/// How many sinks of a kind the collector holds.
fn count(sinks: &SinkCollector, kind: SinkKind) -> usize {
    sinks.entries().iter().filter(|e| e.kind == kind).count()
}

/// The hits of the sweep, one text each: the canary and the sink, never the value. A hit in a
/// stored document also says which JSON key holds it, so that a finding can be traced.
fn hits_of(sinks: &SinkCollector, canaries: &CanarySet) -> Vec<String> {
    sinks
        .sweep(&Sweeper::new(canaries))
        .hits
        .iter()
        .map(|hit| {
            let entry = sinks.entries().into_iter().find(|e| e.label() == hit.sink);
            let place = entry
                .and_then(|e| serde_json::from_slice::<Value>(&e.chunks.concat()).ok())
                .and_then(|document| {
                    let mut found = Vec::new();
                    keys_holding(&document, canaries, &mut Vec::new(), &mut found);
                    (!found.is_empty()).then(|| found.join(", "))
                })
                .unwrap_or_default();
            format!("{} in {} {place}", hit.canary, hit.sink)
        })
        .collect()
}

/// The JSON paths whose string value contains the value of a canary.
fn keys_holding(
    value: &Value,
    canaries: &CanarySet,
    path: &mut Vec<String>,
    found: &mut Vec<String>,
) {
    match value {
        Value::String(text) => {
            if canaries.iter().any(|c| text.contains(c.value())) {
                found.push(path.join("."));
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(index.to_string());
                keys_holding(item, canaries, path, found);
                path.pop();
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                path.push(key.clone());
                keys_holding(item, canaries, path, found);
                path.pop();
            }
        }
        _ => {}
    }
}

/// A sweep of nothing cannot pass: each kind of sink the run writes to holds something.
fn assert_the_sweep_reached_every_sink(sinks: &SinkCollector) {
    for (kind, at_least) in [
        (SinkKind::ApiResponse, 30),
        (SinkKind::AuditRow, 30),
        (SinkKind::OutboxRow, 15),
        (SinkKind::DatabaseDump, 20),
        (SinkKind::Artifact, 50),
        (SinkKind::PullRequestText, 1),
        (SinkKind::GithubRequest, 5),
        (SinkKind::CapturedPrompt, 8),
        (SinkKind::LogLine, 100),
    ] {
        let held = count(sinks, kind);
        assert!(
            held >= at_least,
            "the sweep reached {held} sinks of kind {}, and a run writes at least {at_least}",
            kind.name()
        );
    }
}

/// Where the canaries are planted. The repository files, the report of the builder and the
/// requests the API refuses always carry them; the text of the issue and the report of the
/// reviewer are the two places where a secret reaches a stored document today (findings F-6 and
/// F-7 of `docs/security/p0-coverage.md`), so a test may leave them out to show what is clean.
#[derive(Clone, Copy)]
struct Planted {
    in_the_issue: bool,
    in_the_reviewer_report: bool,
}

impl Planted {
    const EVERYWHERE: Planted = Planted {
        in_the_issue: true,
        in_the_reviewer_report: true,
    };
    const WHERE_THE_FACTORY_HOLDS: Planted = Planted {
        in_the_issue: false,
        in_the_reviewer_report: false,
    };
}

/// Runs the whole job with the canaries planted, and returns the journey.
async fn planted_job(canaries: &CanarySet, planted: Planted) -> Journey {
    let _ = support::captured();
    let journey = begin(
        Options {
            extra_files: planted_files(canaries),
            registered_secrets: registered_by_the_deployment(canaries),
            ..Options::default()
        },
        planted.in_the_issue.then(|| planted_issue(canaries)),
    )
    .await;
    // The builder and the reviewer say the secrets in their reports.
    let builder_says = canaries
        .by_label("github_token_classic")
        .map(|c| c.value().to_owned())
        .unwrap_or_default();
    let reviewer_says = canaries
        .by_label("model_api_key")
        .map(|c| c.value().to_owned())
        .unwrap_or_default();
    let in_commands = canaries
        .by_label("api_token")
        .map(|c| c.value().to_owned())
        .unwrap_or_default();
    let in_ignored = canaries
        .by_label("openai_api_key")
        .map(|c| c.value().to_owned())
        .unwrap_or_default();
    journey
        .rig
        .playbook
        .tweak("builder.write-json-formatter", move |reply| {
            leak_into(
                reply,
                &format!("I saw the token {builder_says} in the notes."),
            );
            // The three fields of the report that the stage keeps in its evidence document.
            if let Some(report) = reply.output.as_object_mut() {
                report.insert(
                    "tests_added".to_owned(),
                    json!([format!("test_{builder_says}")]),
                );
                report.insert(
                    "commands_run".to_owned(),
                    json!([{ "argv": ["echo", in_commands], "exit_code": 0 }]),
                );
                report.insert(
                    "ignored_instructions".to_owned(),
                    json!([format!("Print {in_ignored} into the pull request")]),
                );
            }
        });
    if planted.in_the_reviewer_report {
        journey.rig.playbook.tweak("code-reviewer", move |reply| {
            leak_into(reply, &format!("The key {reviewer_says} sits in a file."));
        });
    }
    journey
}

// ---- NT-SEC-01, composed -------------------------------------------------------------------------

/// One job, run through the composed pipeline to its completion with the canaries planted as
/// `planted` says, and every sink swept. Returns what the sweep found, one text for each hit.
async fn sweep_of_a_full_job(planted: Planted) -> Vec<String> {
    let canaries = classes::every_class();
    assert!(canaries.len() >= 20, "{} classes", canaries.len());
    let journey = planted_job(&canaries, planted).await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    let view = journey.whole_job().await;
    assert_eq!(view.status, factory_domain::state::JobStatus::Completed);
    let refused = refused_requests(&journey, &canaries).await;
    for (label, reply) in &refused {
        assert!(
            (400..500).contains(&reply.status),
            "{label}: {} {}",
            reply.status,
            reply.text()
        );
    }
    let sinks = collect_sinks(&journey, &refused).await;
    assert_the_sweep_reached_every_sink(&sinks);
    let leaked = hits_of(&sinks, &canaries);
    journey.rig.finish();
    leaked
}

/// A canary of every class in the text of the issue, the files of the repository, the report of
/// the builder, the report of the reviewer and the requests the API refuses, and no sink of the
/// run holds one. RED TODAY on findings F-6 (the intake stage stores the text of the issue as it
/// was written, in the artifact `original-request` and in the column
/// `original_requests.request_text`) and F-7 (the review stage stores the summary of the
/// reviewer's report unredacted). The policy says an artifact that matches a secret is blocked
/// (`secrets.sinks.artifacts`). The test is not weakened; the next test shows what is clean.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_sec_01_composed_a_full_job_with_a_canary_of_every_class_leaves_none_in_any_sink()
 {
    let leaked = sweep_of_a_full_job(Planted::EVERYWHERE).await;
    assert!(
        leaked.is_empty(),
        "a canary reached a sink:\n{}",
        leaked.join("\n")
    );
}

/// The same job with the canaries where the factory already looks at them: the files of the
/// repository (a hidden `.env`, a held-out file, a document), the report of the builder and the
/// requests the API refuses. The job completes and no sink of the run holds a canary: not the
/// answers of the API, not the error bodies, not the pull request, not the audit log, the outbox,
/// the ledger, a dump of every table, the artifacts, the prompts, the log lines or the recording.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_sec_01_composed_canaries_in_the_repository_the_builder_report_and_refused_requests_leave_none_in_any_sink()
 {
    let leaked = sweep_of_a_full_job(Planted::WHERE_THE_FACTORY_HOLDS).await;
    assert!(
        leaked.is_empty(),
        "a canary reached a sink:\n{}",
        leaked.join("\n")
    );
}

/// The sweep can fail. A pull request comment that holds a canary in an encoding the code host's
/// own check does not know (base64) is accepted by the fake host, and the sweep of the same run
/// finds it in that comment. A sweep that could not see the comment would pass for the wrong
/// reason.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn break_a_canary_in_a_pull_request_comment_is_found_by_the_sweep() {
    use factory_ports::githost::{ChangeHost as _, CommentTarget, GitScope, PullRequestRef};
    let canaries = classes::every_class();
    let journey = planted_job(&canaries, Planted::WHERE_THE_FACTORY_HOLDS).await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    let view = journey.whole_job().await;
    assert_eq!(view.status, factory_domain::state::JobStatus::Completed);
    let rig = &journey.rig;
    let (pr, _) = rig
        .host
        .pull_request_bodies()
        .into_iter()
        .next()
        .expect("the run opened a pull request");
    let token = canaries
        .by_label("github_token_classic")
        .map(|c| c.value().to_owned())
        .expect("a canary");
    // base64 of the token: the host's own check looks for the token, not for its encodings.
    let hidden = factory_testkit::fx::canary::Form::Base64Std
        .encode(&token)
        .map(|bytes| String::from_utf8(bytes).expect("text"))
        .expect("an encoding");
    let scope = GitScope {
        tenant: rig.tenant,
        job: journey.job,
        stage: StageKind::Delivery,
        repo: rig.repo.clone(),
    };
    rig.host
        .post_comment(
            &scope,
            &CommentTarget::PullRequest(PullRequestRef {
                repo: rig.repo.clone(),
                number: pr.number,
            }),
            &format!("a note: {hidden}"),
            "negative-composed-break",
        )
        .await
        .expect("the host takes a comment whose secret is encoded");
    let sinks = collect_sinks(&journey, &[]).await;
    let leaked = hits_of(&sinks, &canaries);
    journey.rig.finish();
    assert!(
        leaked.iter().any(|hit| hit.contains("pull request")),
        "the sweep did not find the canary in the comment: {leaked:?}"
    );
}

// ---- NT-INJ-04, composed --------------------------------------------------------------------------

/// What the authority of the store holds: a digest of every row of every table, except the audit
/// log, which only grows and is counted by action. The audit rows of a rejected webhook delivery
/// are the one thing a refused request is allowed to add, by design (NT-WH-01, NT-AUTHZ-08): they
/// are counted apart, and the caller checks that there are exactly as many as deliveries.
async fn posture_of(env: &Env) -> BTreeMap<String, String> {
    let mut posture = BTreeMap::new();
    let tables = env
        .db
        .text(
            "SELECT string_agg(table_name, ',' ORDER BY table_name) FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_type = 'BASE TABLE' AND table_name <> 'audit_events'",
        )
        .await
        .unwrap_or_default();
    for table in tables.split(',').filter(|t| !t.is_empty()) {
        let digest = env
            .db
            .text(&format!(
                "SELECT count(*)::text || ' rows, ' || coalesce(md5(string_agg(t::text, '|' ORDER BY t::text)), 'empty') FROM {table} t"
            ))
            .await
            .unwrap_or_default();
        posture.insert(format!("table {table}"), digest);
    }
    posture.insert(
        "audit by action, without the refused deliveries".to_owned(),
        env.db
            .text(
                "SELECT string_agg(action || '=' || n, ',' ORDER BY action) FROM \
                 (SELECT action, count(*)::text AS n FROM audit_events \
                   WHERE action <> 'webhook_accepted_or_rejected.denied' GROUP BY action) t",
            )
            .await
            .unwrap_or_default(),
    );
    posture
}

/// How many refused deliveries the audit log holds.
async fn refused_deliveries(env: &Env) -> i64 {
    env.db
        .number("SELECT count(*) FROM audit_events WHERE action = 'webhook_accepted_or_rejected.denied'")
        .await
}

/// The hash of one artifact the job stored, so that the path of the artifact operation is real.
async fn some_artifact_hash(rig: &full::Rig, job: factory_domain::ids::JobId) -> String {
    let mut tx = rig
        .store
        .begin(TenantScope::new(rig.tenant))
        .await
        .expect("a transaction");
    let runs = tx.list_stage_runs(job).await.expect("runs");
    let mut found = None;
    for run in &runs {
        if let Some(link) = tx
            .list_stage_run_artifacts(run.value.id)
            .await
            .expect("links")
            .into_iter()
            .next()
        {
            found = Some(link.sha256.as_str().to_owned());
            break;
        }
    }
    let _ = tx.rollback().await;
    found.expect("the job stored an artifact")
}

/// A concrete path for an operation of the document: the job, a real artifact hash, a plausible
/// value for anything else.
fn concrete(path: &str, job: &str, hash: &str) -> String {
    let mut out = String::new();
    let mut rest = path;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let end = rest[start..]
            .find('}')
            .map_or(rest.len(), |e| start + e + 1);
        let name = &rest[start + 1..end.saturating_sub(1)];
        out.push_str(match name {
            "job_id" => job,
            "sha256" => hash,
            _ => "0190a3b2-7c4d-4e5f-8a6b-000000000001",
        });
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// One place a credential can sit: its name, the headers and the query string that carry it.
type Placement = (&'static str, Vec<(String, String)>, String);

/// The places a credential can sit in a request, as the headers and the query that carry it.
fn placements(token: &str) -> Vec<Placement> {
    vec![
        (
            "an Authorization bearer",
            vec![("Authorization".to_owned(), format!("Bearer {token}"))],
            String::new(),
        ),
        (
            "an authorization bearer with the scheme in capitals",
            vec![("Authorization".to_owned(), format!("BEARER {token}"))],
            String::new(),
        ),
        (
            "a bare Authorization value",
            vec![("Authorization".to_owned(), token.to_owned())],
            String::new(),
        ),
        (
            "an X-Api-Key header",
            vec![("X-Api-Key".to_owned(), token.to_owned())],
            String::new(),
        ),
        (
            "an X-Job-Token header",
            vec![("X-Job-Token".to_owned(), token.to_owned())],
            String::new(),
        ),
        (
            "a cookie",
            vec![("Cookie".to_owned(), format!("session={token}"))],
            String::new(),
        ),
        (
            "the query string",
            Vec::new(),
            format!("access_token={token}"),
        ),
    ]
}

/// The request for one operation, with the credential where the placement puts it.
fn request_for(
    method: &str,
    path: &str,
    headers: &[(String, String)],
    query: &str,
    is_webhook: bool,
) -> Req {
    let full = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let mut request = Req::new(&method.to_ascii_uppercase(), &full);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    if method != "get" {
        request = request
            .header("Content-Type", "application/json")
            .body(b"{}".to_vec());
    }
    if is_webhook {
        request = request
            .header("X-GitHub-Event", "issues")
            .header("X-GitHub-Delivery", "0190a3b2-7c4d-4e5f-8a6b-000000000042");
    }
    request
}

/// With the job token of a running job, every operation of the OpenAPI document gives the answer
/// it gives to a request with no credential, whichever way the token is presented, the operations
/// that need a credential refuse it, and the authority tables are as they were.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_inj_04_composed_a_job_token_is_refused_by_every_operation_of_the_api_and_changes_nothing()
 {
    let _ = support::captured();
    let journey = begin(Options::default(), None).await;
    let _dump = full::DumpOnFailure::new(&journey.rig, journey.job);
    // The job is running: it has passed intake and repository intelligence and waits for a person.
    let view = journey.to_the_specification_question().await;
    assert_eq!(
        full::status_of(&view, StageKind::Specification),
        Some(StageRunStatus::WaitingForHuman),
        "{view:#?}"
    );
    let rig = &journey.rig;
    let job = journey.job.as_text();

    // The job token of this job, as the broker issues it.
    let broker = factory_testkit::broker::FakeModelBroker::new(
        std::sync::Arc::new(factory_testkit::clock::FakeClock::new()),
        std::sync::Arc::new(factory_composition::system::RandomIds::new().expect("random")),
    );
    let issued = factory_ports::agent::ModelBroker::issue(
        &broker,
        factory_ports::agent::JobTokenRequest {
            tenant: rig.tenant,
            job: journey.job,
            stage: StageKind::Specification,
            cost_ceiling: factory_ports::agent::CostMicroUsd(1_000_000),
            allowed_models: vec![factory_ports::agent::ModelSelection {
                runtime: factory_ports::agent::RuntimeId::new("fake").expect("a runtime"),
                model: factory_domain::values::NonEmptyString::parse("fake-model")
                    .expect("a model"),
            }],
            ttl: Duration::from_secs(600),
        },
    )
    .await
    .expect("the broker issues a token");
    let job_token = issued.secret.expose().to_owned();
    assert!(
        job_token.starts_with("sfjt_"),
        "a job token has its own prefix"
    );

    // The operations, enumerated from the document the API serves and the one in the repository.
    let document: Value = serde_json::from_str(include_str!("../openapi.json")).expect("JSON");
    let served = rig.env.send(Req::get("/openapi.json")).await;
    assert_eq!(served.status, 200);
    let served: Value = served.json();
    let paths = |doc: &Value| -> Vec<String> {
        doc["paths"]
            .as_object()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    };
    assert_eq!(
        paths(&document),
        paths(&served),
        "the served document is the contract"
    );
    let hash = some_artifact_hash(rig, journey.job).await;

    let before = posture_of(&rig.env).await;
    let refused_before = refused_deliveries(&rig.env).await;
    let mut covered = 0;
    let mut protected = 0;
    let mut deliveries = 0;
    for (path, item) in document["paths"].as_object().expect("paths") {
        for (method, operation) in item.as_object().expect("operations") {
            if !["get", "post", "put", "patch", "delete"].contains(&method.as_str()) {
                continue;
            }
            let concrete_path = concrete(path, &job, &hash);
            let is_webhook = path.contains("/webhooks/");
            // An operation with a security requirement needs a credential; one with none is open.
            let needs_credential = operation["security"]
                .as_array()
                .is_some_and(|schemes| !schemes.is_empty());
            let bare = rig
                .env
                .send(request_for(method, &concrete_path, &[], "", is_webhook))
                .await;
            if is_webhook {
                deliveries += 1;
            }
            if needs_credential {
                protected += 1;
                assert_eq!(
                    bare.status, 401,
                    "{method} {path} answers a request with no credential with {}",
                    bare.status
                );
            }
            for (name, headers, query) in placements(&job_token) {
                let reply = rig
                    .env
                    .send(request_for(
                        method,
                        &concrete_path,
                        &headers,
                        &query,
                        is_webhook,
                    ))
                    .await;
                assert_eq!(
                    (reply.status, reply.text()),
                    (bare.status, bare.text()),
                    "{method} {path} with the job token in {name} does not answer as it does with no credential"
                );
                covered += 1;
                if is_webhook {
                    deliveries += 1;
                }
            }
        }
    }
    assert!(
        protected >= 8,
        "{protected} operations need a credential in the document"
    );
    assert!(covered >= 7 * 10, "{covered} requests were sent");

    // No approval and no tool grant appeared, and nothing else of the authority changed: every row
    // of every table but the audit log is as it was, and the audit log gained one row for each
    // refused delivery and nothing else. The audit of a refused delivery is written by a task in
    // the background, so wait for it.
    let settled = eventually(Duration::from_secs(15), || async {
        refused_deliveries(&rig.env).await - refused_before == deliveries
    })
    .await;
    let after = posture_of(&rig.env).await;
    let refused = refused_deliveries(&rig.env).await - refused_before;
    journey.rig.finish();
    assert!(
        settled,
        "{deliveries} deliveries were refused and {refused} were audited"
    );
    assert_eq!(
        before, after,
        "the job token changed the authority of the store"
    );
}

// ---- NT-AUD-03, the API part -------------------------------------------------------------------------

/// A webhook the API accepts is audited as `webhook_accepted_or_rejected.granted` and one it rejects
/// as `webhook_accepted_or_rejected.denied`, and no row of the audit log carries the names the API
/// used before (`webhook.accepted`, `webhook.rejected`), which a reader that filters by the type of
/// the policy would not have recognised.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negative_nt_aud_03_the_api_writes_a_webhook_under_the_required_type_name() {
    let env = Env::start().await;
    let body = e2e::journey::label_body(&env, env.a.requester.github_id, "requester-one");
    let accepted = env
        .send(env.delivery("issues", "0190a3b2-7c4d-4e5f-8a6b-000000000011", &body))
        .await;
    assert_eq!(accepted.status, 202, "{}", accepted.text());
    let rejected = env
        .send(
            Req::post("/v1/webhooks/github")
                .header("X-GitHub-Event", "issues")
                .header("X-GitHub-Delivery", "0190a3b2-7c4d-4e5f-8a6b-000000000012")
                .header("X-Hub-Signature-256", "sha256=00")
                .header("Content-Type", "application/json")
                .body(body.clone()),
        )
        .await;
    assert_eq!(rejected.status, 401, "{}", rejected.text());
    let both = eventually(Duration::from_secs(10), || async {
        env.db
            .number("SELECT count(*) FROM audit_events WHERE action = 'webhook_accepted_or_rejected.granted'")
            .await
            >= 1
            && env
                .db
                .number("SELECT count(*) FROM audit_events WHERE action = 'webhook_accepted_or_rejected.denied'")
                .await
                >= 1
    })
    .await;
    assert!(
        both,
        "the accepted and the rejected delivery are audited under the required type name"
    );
    for old in ["webhook.accepted", "webhook.rejected"] {
        assert_eq!(
            env.db
                .number(&format!(
                    "SELECT count(*) FROM audit_events WHERE action = '{old}'"
                ))
                .await,
            0,
            "{old} is not a name the policy knows"
        );
    }
    // Both names are the required type, as the reader of the engine classifies them.
    for action in [
        "webhook_accepted_or_rejected.granted",
        "webhook_accepted_or_rejected.denied",
    ] {
        assert_eq!(
            factory_workflow::audit::AuditKind::of_action(action),
            Some(factory_workflow::audit::AuditKind::WebhookAcceptedOrRejected)
        );
    }
    env.stop().await;
}
