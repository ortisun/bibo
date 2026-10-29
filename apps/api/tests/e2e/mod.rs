//! The recorder of the end-to-end scenarios in test mode.
//!
//! A scenario is driven through the real composed pipeline by the rig of `full/mod.rs` (the real
//! engine, the real API server on loopback, the worker hook, all thirteen real stage handlers and
//! a real PostgreSQL, with the labelled fakes the rig documents). When the scenario ends, this
//! module reads what the run left behind, from the database, from the API as a person would read
//! it and from the artifact store, and writes a recording the harness judges
//! (`tests/end_to_end/src/recording.rs` describes the files).
//!
//! The recorder does not judge. It does not know the assertions. The only checks it makes are the
//! ones the recording needs to be well formed: that the ledger chain verifies when it writes it,
//! and that every file is hashed in the manifest.

#![allow(dead_code)]

pub mod journey;
pub mod spans;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use factory_domain::contracts::{ArtifactRef, Contract as _};
use factory_domain::ids::JobId;
use factory_domain::scope::TenantScope;
use factory_domain::values::{MediaType, Sha256Digest};
use factory_domain::vocabulary::StageKind;
use factory_ports::store::{AuditActor, AuditFilter, OutboxSeq};
use serde_json::{Value, json};

use crate::full::Rig;
use crate::support::{Env, Req};

/// What the recorder collects for one scenario.
pub struct Collected {
    /// The scenario id.
    pub scenario: &'static str,
    /// The `RunEvidence` the harness reads.
    pub evidence: Value,
    /// The mode file.
    pub mode: Value,
    /// The timeline exactly as the API served it.
    pub timeline_api: Value,
    /// Timings of the attempts.
    pub timings: Value,
    /// The stored gate reports, `(stage run id, bytes)`.
    pub gate_reports: Vec<(String, Vec<u8>)>,
    /// The hash of every stored stage output, by `"STAGE name"`.
    pub stage_outputs: BTreeMap<String, String>,
    /// The stage outputs that the GitHub evidence and the facts are derived from, by `"STAGE name"`.
    /// They are kept in the recording so that the derivation can be read.
    pub kept_documents: BTreeMap<String, Value>,
}

/// What a run adds to the evidence that only the scenario knows.
#[derive(Default)]
pub struct Extras {
    /// The issue number on the fixture repository.
    pub issue_number: u64,
    /// Read the audit stream of the whole tenant and not of the job. A request that was rejected,
    /// or delivered again, is audited with no job.
    pub tenant_audit: bool,
    /// The job status to record when there is no job to read it from.
    pub job_status: String,
    /// `hostile` block of the evidence, for E4.
    pub hostile: Option<Value>,
    /// Facts only one scenario needs, by name.
    pub facts: BTreeMap<String, Value>,
    /// What the commit tip of the base branch was before the run.
    pub base_before: String,
    /// Where the log of the run starts in the capture.
    pub span_mark: usize,
    /// How long the whole scenario took.
    pub took: Duration,
    /// The timings the drive loop measured.
    pub attempt_timings: Vec<Value>,
}

/// The requester's bearer token.
pub struct Tokens {
    pub requester: String,
}

fn artifact_ref(sha: Sha256Digest) -> ArtifactRef {
    ArtifactRef {
        sha256: sha,
        media_type: MediaType::parse("application/json").expect("a media type"),
        size_bytes: None,
    }
}

/// Reads everything the run of `job` left, and builds the recording.
pub async fn collect(
    rig: &Rig,
    job: Option<JobId>,
    scenario: &'static str,
    tokens: &Tokens,
    extras: Extras,
    transitions: &Transitions,
) -> Collected {
    let scope = TenantScope::new(rig.tenant);
    let view = match job {
        Some(job) => rig.engine.job_view(rig.tenant, job).await.ok(),
        None => None,
    };

    // ---- the store ---------------------------------------------------------------------------
    let mut tx = rig.store.begin(scope).await.expect("a transaction");
    let correlation = match job {
        Some(job) => tx
            .get_job(job)
            .await
            .expect("the job row")
            .value
            .correlation_id
            .to_string(),
        None => "none".to_owned(),
    };
    let runs = match job {
        Some(job) => tx.list_stage_runs(job).await.expect("stage runs"),
        None => Vec::new(),
    };
    let ledger = match job {
        Some(job) => factory_composition::reading::Reader::job_ledger(&mut *tx, job)
            .await
            .expect("the ledger"),
        None => Vec::new(),
    };
    let filter = match (extras.tenant_audit, job) {
        (false, Some(job)) => AuditFilter::Job(job),
        _ => AuditFilter::Tenant,
    };
    let audit_rows = tx.read_audit(filter, 0, 5000).await.expect("audit");
    let events = match job {
        Some(job) => tx
            .read_events(job, OutboxSeq::START, 5000)
            .await
            .expect("events"),
        None => Vec::new(),
    };
    let mut links = Vec::new();
    for run in &runs {
        for link in tx
            .list_stage_run_artifacts(run.value.id)
            .await
            .expect("links")
        {
            links.push((run.value.kind, run.value.id, link));
        }
    }
    let _ = tx.rollback().await;

    // ---- the artifact store ------------------------------------------------------------------
    let mut stage_outputs: BTreeMap<String, String> = BTreeMap::new();
    let mut documents: BTreeMap<String, Value> = BTreeMap::new();
    for (kind, _, link) in &links {
        if link.direction != factory_ports::store::ArtifactDirection::Output {
            continue;
        }
        let name = link
            .role
            .as_str()
            .split(".a")
            .next()
            .unwrap_or("")
            .to_owned();
        stage_outputs.insert(
            format!("{} {name}", kind.as_str()),
            link.sha256.as_str().to_owned(),
        );
        if let Ok(bytes) = rig
            .artifacts
            .get(&scope, &artifact_ref(link.sha256.clone()))
            .await
            && let Ok(value) = serde_json::from_slice::<Value>(&bytes)
        {
            documents.insert(format!("{} {name}", kind.as_str()), value);
        }
    }
    let document = |kind: StageKind, name: &str| -> Option<&Value> {
        documents.get(&format!("{} {name}", kind.as_str()))
    };

    // The gate reports of each stage run, in the order the harness will number them. A stage run
    // keeps the report its gate decision names. The validation stage also keeps one report for
    // each gate it ran (the format check, the build, the tests), inside its evidence document, and
    // the report that explains a failed check is one of those.
    let mut gate_reports: Vec<(String, Vec<u8>)> = Vec::new();
    let mut gate_records = Vec::new();
    for run in &runs {
        let id = run.value.id.to_string();
        let mut found: Vec<(Value, Vec<u8>)> = Vec::new();
        if let Some(record) = &run.value.gate
            && let Some(hash) = record.report_sha256.clone()
            && let Ok(bytes) = rig.artifacts.get(&scope, &artifact_ref(hash)).await
            && let Ok(report) = serde_json::from_slice::<Value>(&bytes)
        {
            found.push((report, bytes));
        }
        if run.value.kind == StageKind::Validation {
            for (_, run_id, link) in &links {
                if *run_id != run.value.id
                    || link.direction != factory_ports::store::ArtifactDirection::Output
                    || !link.role.as_str().starts_with("validation-evidence")
                {
                    continue;
                }
                let Ok(bytes) = rig
                    .artifacts
                    .get(&scope, &artifact_ref(link.sha256.clone()))
                    .await
                else {
                    continue;
                };
                let Ok(evidence) = serde_json::from_slice::<Value>(&bytes) else {
                    continue;
                };
                for report in evidence["reports"].as_array().into_iter().flatten() {
                    let bytes = serde_json::to_vec(report).expect("a gate report is JSON");
                    found.push((report.clone(), bytes));
                }
            }
        }
        for (ordinal, (report, bytes)) in found.into_iter().enumerate() {
            gate_records.push(json!({ "stage_run_id": id, "report": report }));
            gate_reports.push((format!("{id}.{ordinal}"), bytes));
        }
    }

    // ---- stage runs --------------------------------------------------------------------------
    let view_runs = view
        .as_ref()
        .map(|v| v.stage_runs.clone())
        .unwrap_or_default();
    let stage_runs: Vec<Value> = view_runs
        .iter()
        .map(|run| {
            json!({
                "id": run.id.to_string(),
                "kind": run.kind.as_str(),
                "status": run.status.as_str(),
                "attempts": run.attempts.iter().map(|attempt| json!({
                    "id": attempt.id.to_string(),
                    "status": attempt.status.as_str(),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let kinds: BTreeMap<String, String> = view_runs
        .iter()
        .map(|run| (run.id.to_string(), run.kind.as_str().to_owned()))
        .collect();

    // ---- ledger, audit, timeline -------------------------------------------------------------
    let ledger_json: Vec<Value> = ledger
        .iter()
        .map(|entry| entry.to_json_value().expect("a ledger entry is JSON"))
        .collect();
    let chain = factory_domain::ledger::verify_chain(&ledger);
    assert_eq!(
        chain,
        Ok(()),
        "the ledger chain verifies when it is recorded"
    );
    let audit: Vec<Value> = audit_rows
        .iter()
        .map(|record| {
            json!({
                "seq": record.sequence,
                "action": record.event.action.as_str(),
                "actor": match &record.event.actor {
                    AuditActor::Human(id) => format!("human:{id}"),
                    AuditActor::Service(id) => format!("service:{id}"),
                    AuditActor::System(slug) => format!("system:{}", slug.as_str()),
                    AuditActor::Anonymous(slug) => format!("anonymous:{}", slug.as_str()),
                },
                "correlation_id": record.event.correlation_id.to_string(),
                "detail": record.event.reason,
            })
        })
        .collect();
    let mut last_status: BTreeMap<String, String> = BTreeMap::new();
    let mut timeline: Vec<Value> = Vec::new();
    for row in &events {
        let event = &row.event;
        let subject = event.aggregate.kind.as_str();
        if subject != "job" && subject != "stage_run" {
            continue;
        }
        let Some(to) = transitions.to(event.event_type.as_str()) else {
            continue;
        };
        let id = event.aggregate.id.to_string();
        let initial = if subject == "job" {
            "RECEIVED"
        } else {
            "PENDING"
        };
        let from = last_status
            .insert(id.clone(), to.to_owned())
            .unwrap_or_else(|| initial.to_owned());
        timeline.push(json!({
            "seq": timeline.len() + 1,
            "subject": subject,
            "subject_id": id,
            "kind": kinds.get(&id),
            "from": from,
            "to": to,
            "reason": event
                .reason_code
                .as_ref()
                .map_or_else(|| event.event_type.as_str().to_owned(), ToString::to_string),
        }));
    }

    // ---- the API, as a person reads it -------------------------------------------------------
    let timeline_api = match job {
        Some(job) => {
            let reply = rig
                .env
                .send(Req::get(&format!("/v1/jobs/{job}/timeline")).bearer(&tokens.requester))
                .await;
            assert_eq!(reply.status, 200, "{}", reply.text());
            reply.json()
        }
        None => json!({ "job_id": null, "entries": [], "truncated": false }),
    };

    // ---- GitHub, as far as the fake host lets us read it back ---------------------------------
    let github = github_evidence(rig, job, &documents, &extras).await;

    // ---- contracts and documents ---------------------------------------------------------------
    let mut stored_hashes = serde_json::Map::new();
    for (name, kind, role) in [
        (
            "specification",
            StageKind::Specification,
            "specification-contract",
        ),
        ("task_dag", StageKind::TaskPlanning, "task-dag"),
    ] {
        if let Some(hash) = stage_outputs.get(&format!("{} {role}", kind.as_str())) {
            stored_hashes.insert(name.to_owned(), json!(hash));
        }
    }
    let mut docs: Vec<Value> = Vec::new();
    if let Some(delivery) = document(StageKind::Delivery, "delivery-result")
        && let (Some(title), Some(body)) = (delivery["title"].as_str(), delivery["body"].as_str())
    {
        docs.push(
            json!({ "kind": "pull_request", "path": "pull_request", "title": title, "body": body }),
        );
    }
    let contracts = json!({
        "specification": document(StageKind::Specification, "specification-contract"),
        "task_dag": document(StageKind::TaskPlanning, "task-dag"),
        "evidence_manifest": document(StageKind::Delivery, "evidence-manifest"),
        "gate_reports": gate_records,
        "stored_hashes": stored_hashes,
    });

    // ---- telemetry -------------------------------------------------------------------------------
    let capture = spans::install();
    let spans_json: Vec<Value> = capture
        .spans()
        .iter()
        .map(|span| {
            json!({
                "id": span.id.to_string(),
                "parent_id": span.parent.map(|p| p.to_string()),
                "name": span.name,
                "stage_run_id": span.stage_run_id,
                "attempt_id": span.attempt_id,
            })
        })
        .collect();
    let mut correlated: Vec<Value> = capture
        .lines_since(extras.span_mark)
        .iter()
        .map(|line| {
            json!({
                "source": "log",
                "label": line.label,
                "correlation_id": line.correlation_id,
            })
        })
        .collect();
    correlated.extend(events.iter().map(|row| {
        json!({
            "source": "outbox",
            "label": row.event.event_type.as_str(),
            "correlation_id": row.event.correlation_id.to_string(),
        })
    }));

    // ---- the evidence ------------------------------------------------------------------------
    let requester_actor = format!("human:{}", rig.env.a.requester.principal);
    let mut evidence = json!({
        "scenario": scenario,
        "wiring": "composed-test",
        "mode": "test",
        "source_language": "en",
        "job": {
            "id": job.map_or_else(|| "none".to_owned(), |job| job.to_string()),
            "status": view.as_ref().map_or_else(|| extras.job_status.clone(), |v| v.status.as_str().to_owned()),
            "correlation_id": correlation,
            "requester": requester_actor,
            "issue_number": extras.issue_number,
        },
        "stage_runs": stage_runs,
        "ledger": ledger_json,
        "audit": audit,
        "timeline": timeline,
        "documents": docs,
        "contracts": contracts,
        "github": github,
        "telemetry": { "spans": spans_json, "correlated": correlated },
        "usage": { "total_micro_usd": 0, "budget_micro_usd": 0, "calls_after_exhaustion": 0 },
    });
    let mut facts = extras.facts.clone();
    if let Some(view) = &view {
        facts.insert(
            "code_rework_rounds".to_owned(),
            json!(view.code_rework_rounds),
        );
    }
    // The outbox rows that say the job was admitted. One delivery makes one.
    facts.insert(
        "outbox_rows".to_owned(),
        json!(
            events
                .iter()
                .filter(|row| row.event.event_type.as_str() == "job.admitted")
                .count()
        ),
    );
    // The paths the implementation stage refused, from its stored evidence.
    if let Some(refusal) = document(StageKind::Implementation, "implementation-evidence")
        .map(|evidence| &evidence["refusal"])
        .filter(|refusal| refusal.is_object())
    {
        let paths: Vec<&str> = refusal["paths"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|entry| entry["path"].as_str())
            .collect();
        facts.insert("refused_paths".to_owned(), json!(paths));
        facts.insert("refusal_code".to_owned(), refusal["code"].clone());
    }
    // The hashes of what the intake stage stored, as the artifact store holds them.
    for (fact, output) in [
        ("stored_original_sha256", "INTAKE original-request"),
        ("normalized_request_sha256", "INTAKE normalized-request"),
    ] {
        if let Some(hash) = stage_outputs.get(output) {
            facts.insert(fact.to_owned(), json!(hash));
        }
    }
    evidence["facts"] = json!(facts);
    if let Some(hostile) = &extras.hostile {
        evidence["hostile"] = hostile.clone();
    }

    let mode = mode_file(scenario, &ledger_json_components(&evidence));
    let timings = json!({
        "scenario_seconds": extras.took.as_secs_f64(),
        "attempts": extras.attempt_timings,
        "note": "Durations of a run in test mode on one machine. They are not a measure of the factory.",
    });
    let kept_documents: BTreeMap<String, Value> = KEPT_DOCUMENTS
        .iter()
        .filter_map(|(kind, name)| {
            let key = format!("{} {name}", kind.as_str());
            documents.get(&key).map(|document| (key, document.clone()))
        })
        .collect();
    Collected {
        scenario,
        evidence,
        mode,
        timeline_api,
        timings,
        gate_reports,
        stage_outputs,
        kept_documents,
    }
}

/// The stage outputs the recording keeps whole.
const KEPT_DOCUMENTS: [(StageKind, &str); 4] = [
    (StageKind::Implementation, "implementation-result"),
    (StageKind::Implementation, "implementation-evidence"),
    (StageKind::Documenting, "documentation-result"),
    (StageKind::Delivery, "delivery-result"),
];

fn ledger_json_components(evidence: &Value) -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    for entry in evidence["ledger"].as_array().into_iter().flatten() {
        let component = entry["metadata"]["recorded_by"]["component"]
            .as_str()
            .unwrap_or_default();
        let fidelity = entry["metadata"]["recorded_by"]["fidelity"]
            .as_str()
            .unwrap_or_default();
        found.insert(component.to_owned(), fidelity.to_owned());
    }
    found
}

/// The adapters of the composed rig that no ledger entry names, with the fidelity each reports.
/// This is the list `full/mod.rs` documents; a change to the rig has to change this too.
const RIG_ADAPTERS: [(&str, &str, &str); 14] = [
    ("sandbox", "testkit-fake-sandbox", "fake"),
    ("agent-runtime", "playbook-agent-runtime", "fake"),
    ("workspaces", "testkit-fake-workspace-provider", "fake"),
    ("change-host", "testkit-fake-change-host", "fake"),
    ("issue-source", "testkit-fake-issue-source", "fake"),
    ("model-broker", "testkit-fake-model-broker", "fake"),
    ("model-router", "testkit-static-model-router", "fake"),
    ("capability-probes", "stand-in-capability-probes", "fake"),
    ("supply-chain-registry", "stand-in-registry", "fake"),
    (
        "supply-chain-advisories",
        "stand-in-advisory-database",
        "fake",
    ),
    (
        "bypass-attestation",
        "stand-in-operator-attestation",
        "fake",
    ),
    ("store", "postgres-store", "real"),
    ("artifact-store", "local-fs-artifact-store", "real"),
    ("api-server", "factory-api-server", "real"),
];

fn mode_file(scenario: &str, components: &BTreeMap<String, String>) -> Value {
    let mut adapters: Vec<Value> = RIG_ADAPTERS
        .iter()
        .map(|(port, name, fidelity)| {
            json!({ "port": port, "component": "", "name": name, "fidelity": fidelity })
        })
        .collect();
    for (component, fidelity) in components {
        let name = if fidelity == "fake" {
            format!("{}-labelled-fake", component.replace('.', "-"))
        } else {
            component.replace('.', "-")
        };
        adapters.push(json!({
            "port": "ledger-writer",
            "component": component,
            "name": name,
            "fidelity": fidelity,
        }));
    }
    json!({
        "mode": "test",
        "scenario": scenario,
        "wiring": "composed-test",
        "cost_micro_usd": 0,
        "adapters": adapters,
        "limitations": [
            "No model was called. The nine agents are the scripted playbook (apps/api/tests/playbook), which answers by role and ignores the text of the prompt.",
            "No command ran in a container. The sandbox is the testkit fake, and the output of cargo and of the tool is what a real run of the patched fixture printed.",
            "GitHub is the testkit fake change host and issue source. It mints no installation token, records no request path, and keeps comment keys and not their text.",
            "The commits on the head branch and their paths come from the implementation and documentation results, and the remote confirms each commit exists and that the branch tip is the pull request head.",
            "The protection of the base branch is a stand-in report that the real preflight judged. The number of required approvals is not in the report and is recorded as one.",
            "Log lines are the events of the factory's own crates. Events of third-party crates are not factory log lines and are not counted.",
        ],
    })
}

async fn github_evidence(
    rig: &Rig,
    job: Option<JobId>,
    documents: &BTreeMap<String, Value>,
    extras: &Extras,
) -> Value {
    use factory_ports::paths::BranchName;
    let main = BranchName::new("main").expect("main");
    let base_after = rig
        .remote
        .branch_tip(&rig.repo, &main)
        .map(|sha| sha.as_str().to_owned())
        .unwrap_or_default();
    let key = |kind: StageKind, name: &str| format!("{} {name}", kind.as_str());
    let delivery = documents.get(&key(StageKind::Delivery, "delivery-result"));
    let implementation = documents.get(&key(StageKind::Implementation, "implementation-evidence"));
    let documentation = documents.get(&key(StageKind::Documenting, "documentation-result"));
    let paths_of = |changes: &Value| -> Vec<String> {
        changes
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|change| change["path"].as_str().map(str::to_owned))
            .collect()
    };
    let mut pull_requests = Vec::new();
    let mut head_commits = Vec::new();
    let mut changed_paths: Vec<String> = Vec::new();
    let mut check_runs = Vec::new();
    if let Some(delivery) = delivery
        && let Some(job) = job
        && let Some(number) = delivery["pull_request"].as_u64()
    {
        let head_branch = delivery["head_branch"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        // The branch tip is read back from the remote, not from the delivery result.
        let tip = BranchName::new(&head_branch)
            .ok()
            .and_then(|branch| rig.remote.branch_tip(&rig.repo, &branch))
            .map(|sha| sha.as_str().to_owned())
            .unwrap_or_default();
        // The pull request as the host reports it now.
        let (draft, lifecycle) = pull_request_state(rig, job, number).await;
        pull_requests.push(json!({
            "number": number,
            "draft": draft,
            "merged": lifecycle == "merged",
            "state": if lifecycle == "closed" || lifecycle == "merged" { "closed" } else { "open" },
            "head_branch": head_branch,
            "head_sha": tip,
            "title": delivery["title"].as_str().unwrap_or_default(),
            "body": delivery["body"].as_str().unwrap_or_default(),
        }));
        // The commits above the base, oldest first: one for each task of the plan, then the
        // documentation commit. Their paths are the ones the stages report. The remote confirms
        // that each commit exists.
        for task in implementation
            .map(|document| document["tasks"].as_array().cloned().unwrap_or_default())
            .unwrap_or_default()
        {
            let paths = paths_of(&task["changes"]);
            changed_paths.extend(paths.iter().cloned());
            head_commits.push(json!({
                "sha": task["commit"].as_str().unwrap_or_default(),
                "message": format!("Implement the task {}", task["key"].as_str().unwrap_or("")),
                "paths": paths,
            }));
        }
        if let Some(documentation) = documentation {
            let paths = paths_of(&documentation["changes"]);
            changed_paths.extend(paths.iter().cloned());
            head_commits.push(json!({
                "sha": documentation["head_commit"].as_str().unwrap_or_default(),
                "message": "Document the change",
                "paths": paths,
            }));
        }
        for run in delivery["check_runs"].as_array().into_iter().flatten() {
            let status = run["status"].as_str().unwrap_or_default();
            let conclusion = status
                .strip_prefix("Completed(")
                .and_then(|rest| rest.strip_suffix(')'))
                .unwrap_or("in_progress")
                .to_lowercase();
            check_runs.push(json!({
                "name": run["name"].as_str().unwrap_or_default(),
                "conclusion": conclusion,
                "head_sha": delivery["code_head"].as_str().unwrap_or_default(),
            }));
        }
    }
    let required_checks: Vec<Value> = ["factory-validation", "factory-review"]
        .iter()
        .map(|context| json!({ "context": context, "pinned_to_app": true }))
        .collect();
    // The fake code host keeps the key of each comment and not its text, so the count is what the
    // recording can say. A comment is recorded as a line that says its text was not kept.
    let on_issue = rig
        .host
        .comment_count(&factory_ports::githost::CommentTarget::Issue(
            factory_ports::githost::IssueRef {
                repo: rig.repo.clone(),
                number: crate::full::ISSUE,
            },
        ));
    let comments: Vec<&str> = (0..on_issue)
        .map(|_| "(a comment; the fake code host keeps its key and not its text)")
        .collect();
    json!({
        "repository": rig.repo.to_string(),
        "base_branch": "main",
        "base_sha_before": extras.base_before,
        "base_sha_after": base_after,
        "pull_requests": pull_requests,
        "head_commits": head_commits,
        "head_files": {},
        "changed_paths": changed_paths,
        "check_runs": check_runs,
        "comments": comments,
        "requests": [],
        "tokens": [],
        "protection": {
            "require_pull_request": true,
            "required_approvals": 1,
            "required_checks": required_checks,
            "dismiss_stale_reviews": true,
            "enforce_admins": true,
            "allow_force_pushes": false,
            "allow_deletions": false,
            "require_code_owner_review": true,
            "app_may_bypass": false,
        },
    })
}

async fn pull_request_state(rig: &Rig, job: JobId, number: u64) -> (bool, &'static str) {
    use factory_ports::githost::{ChangeHost as _, GitScope, PullRequestLifecycle, PullRequestRef};
    let scope = GitScope {
        tenant: rig.tenant,
        job,
        stage: StageKind::Approval,
        repo: rig.repo.clone(),
    };
    let pr = PullRequestRef {
        repo: rig.repo.clone(),
        number,
    };
    match rig.host.pull_request_state(&scope, &pr).await {
        Ok(state) => (
            state.draft,
            match state.lifecycle {
                PullRequestLifecycle::Open => "open",
                PullRequestLifecycle::Closed => "closed",
                PullRequestLifecycle::Merged => "merged",
            },
        ),
        Err(_) => (false, "unreadable"),
    }
}

/// Which status each event leads to, read from `docs/architecture/state-machine.json`.
pub struct Transitions(BTreeMap<String, String>);

impl Transitions {
    pub fn load(root: &Path) -> Self {
        let text = std::fs::read_to_string(root.join("docs/architecture/state-machine.json"))
            .expect("the state machine file");
        let document: Value = serde_json::from_str(&text).expect("JSON");
        let mut to = BTreeMap::new();
        for machine in ["job", "stage_run"] {
            let list = document
                .pointer(&format!("/machines/{machine}/transitions"))
                .and_then(Value::as_array)
                .expect("transitions");
            for transition in list {
                let emits = transition.get("emits").and_then(Value::as_str);
                let target = transition.get("to").and_then(|t| {
                    t.as_str().map(str::to_owned).or_else(|| {
                        t.as_array()
                            .and_then(|a| a.first())
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                });
                if let (Some(emits), Some(target)) = (emits, target) {
                    to.insert(emits.to_owned(), target);
                }
            }
        }
        Self(to)
    }

    pub fn to(&self, event: &str) -> Option<&str> {
        self.0.get(event).map(String::as_str)
    }
}

// ---- writing ---------------------------------------------------------------------------------

fn pretty(value: &Value) -> Vec<u8> {
    let mut text = serde_json::to_string_pretty(value).expect("JSON");
    text.push('\n');
    text.into_bytes()
}

/// Writes the recording of a scenario into `dir`, replacing what was there.
pub fn write(dir: &Path, collected: &Collected) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir.join("gate-reports")).expect("the recording directory");
    std::fs::create_dir_all(dir.join("stage-outputs")).expect("the recording directory");
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    files.insert("evidence.json".to_owned(), pretty(&collected.evidence));
    files.insert("mode.json".to_owned(), pretty(&collected.mode));
    let head = collected.evidence["ledger"]
        .as_array()
        .and_then(|entries| entries.last())
        .and_then(|entry| entry.get("entry_hash"))
        .cloned()
        .unwrap_or(Value::Null);
    files.insert(
        "ledger.json".to_owned(),
        pretty(&json!({
            "entries": collected.evidence["ledger"],
            "chain": {
                "entries": collected.evidence["ledger"].as_array().map_or(0, Vec::len),
                "head_hash": head,
                "verified_by": "factory_domain::ledger::verify_chain, when the recorder wrote the file",
            },
        })),
    );
    files.insert(
        "timeline.api.json".to_owned(),
        pretty(&collected.timeline_api),
    );
    files.insert("timings.json".to_owned(), pretty(&collected.timings));
    let mut gate_hashes = serde_json::Map::new();
    for (stage_run, bytes) in &collected.gate_reports {
        gate_hashes.insert(
            stage_run.clone(),
            json!(Sha256Digest::of(bytes).as_str().to_owned()),
        );
        files.insert(format!("gate-reports/{stage_run}.json"), bytes.clone());
    }
    for (key, document) in &collected.kept_documents {
        files.insert(
            format!("stage-outputs/{}.json", key.replace(' ', "-")),
            pretty(document),
        );
    }
    files.insert(
        "artifacts.json".to_owned(),
        pretty(&json!({
            "stage_outputs": collected.stage_outputs,
            "gate_reports": gate_hashes,
        })),
    );
    let manifest = json!({
        "format": 1,
        "scenario": collected.scenario,
        "files": files
            .iter()
            .map(|(name, bytes)| (name.clone(), Sha256Digest::of(bytes).as_str().to_owned()))
            .collect::<BTreeMap<_, _>>(),
    });
    files.insert("MANIFEST.json".to_owned(), pretty(&manifest));
    for (name, bytes) in files {
        std::fs::write(dir.join(name), bytes).expect("a recording file");
    }
}

/// A recording for a scenario that runs no job: the facts, the adapters it used, and an evidence
/// document with nothing in the places a job fills.
pub fn bare(
    scenario: &'static str,
    facts: BTreeMap<String, Value>,
    adapters: &[(&str, &str, &str, &str)],
    took: Duration,
) -> Collected {
    let github = json!({
        "repository": "none",
        "base_branch": "main",
        "base_sha_before": "",
        "base_sha_after": "",
        "pull_requests": [],
        "head_commits": [],
        "head_files": {},
        "changed_paths": [],
        "check_runs": [],
        "comments": [],
        "requests": [],
        "tokens": [],
    });
    let evidence = json!({
        "scenario": scenario,
        "wiring": "composed-test",
        "mode": "test",
        "source_language": "en",
        "job": {
            "id": "none",
            "status": "NONE",
            "correlation_id": "none",
            "requester": "none",
            "issue_number": 0,
        },
        "stage_runs": [],
        "ledger": [],
        "audit": [],
        "timeline": [],
        "documents": [],
        "contracts": { "gate_reports": [], "stored_hashes": {} },
        "github": github,
        "telemetry": { "spans": [], "correlated": [] },
        "usage": { "total_micro_usd": 0, "budget_micro_usd": 0, "calls_after_exhaustion": 0 },
        "facts": facts,
    });
    let mut mode = mode_file(scenario, &BTreeMap::new());
    mode["adapters"] = json!(
        adapters
            .iter()
            .map(|(port, name, fidelity, component)| json!({
                "port": port, "component": component, "name": name, "fidelity": fidelity
            }))
            .collect::<Vec<_>>()
    );
    mode["limitations"] = json!([
        "This scenario starts no job. It shows the production profile of the real start-up code refusing a fake for each port, and the test profile accepting one.",
        "The worker's ports are judged by Profile::admit, which the worker's start-up calls for each of its 37 ports. The worker binary itself is not started here: the API and the worker cannot be linked into one test (DEP-01).",
    ]);
    Collected {
        scenario,
        evidence,
        mode,
        timeline_api: json!({ "job_id": null, "entries": [], "truncated": false }),
        timings: json!({ "scenario_seconds": took.as_secs_f64(), "attempts": [] }),
        gate_reports: Vec::new(),
        stage_outputs: BTreeMap::new(),
        kept_documents: BTreeMap::new(),
    }
}

/// Where the recording goes: `FACTORY_E2E_RECORD_DIR` when the script sets it (the repository's
/// `fixtures/recordings/e2e`), else a scratch directory of the rig that is thrown away.
pub fn recording_dir(scratch: &Path, scenario: &str) -> std::path::PathBuf {
    match std::env::var("FACTORY_E2E_RECORD_DIR") {
        Ok(base) if !base.trim().is_empty() => Path::new(&base).join(scenario),
        _ => scratch.join("recordings").join(scenario),
    }
}

/// Unused outside the module; keeps `Env` in the signature of helpers that need the tenant.
pub fn tenant_of(env: &Env) -> factory_domain::ids::TenantId {
    env.a.id
}
