//! A canned, honest evidence set for the happy path (scenarios E1 and E2).
//!
//! It is what a correct run would leave behind, built from the valid examples in
//! `schemas/examples/` with the identifiers, hashes and links made consistent. Every assertion
//! passes on it. The mutation tests in `tests/mutations.rs` corrupt one fact at a time and show
//! that the matching assertion fails, which is the proof that the assertions can detect a defect.
//!
//! The scripted wiring uses the same document builders, so the documents it stores look like these.
//! Nothing here is a result of the factory: a canned set proves the assertions, not the factory.

use std::collections::BTreeMap;

use factory_domain::contracts::{Contract, EvidenceLedgerEntry};
use factory_domain::values::Sha256Digest;
use serde_json::{Value, json};

use crate::check::Env;
use crate::evidence::{
    AttemptRecord, AuditRecord, CheckRun, Commit, Contracts, Correlated, Document,
    GateReportRecord, GithubEvidence, GithubRequest, JobRecord, Mode, ProtectionFacts, PullRequest,
    RequiredCheckFacts, RunEvidence, Span, StageRunRecord, Telemetry, TimelineEntry, TokenRecord,
    Usage,
};

const SPEC_EXAMPLE: &str = include_str!(
    "../../../schemas/examples/specification-contract/valid/approved-json-output-flag.json"
);
const DAG_EXAMPLE: &str =
    include_str!("../../../schemas/examples/task-dag/valid/json-output-flag-plan.json");
const MANIFEST_EXAMPLE: &str = include_str!(
    "../../../schemas/examples/evidence-manifest/valid/json-output-flag-draft-pr.json"
);
const GATE_EXAMPLE: &str =
    include_str!("../../../schemas/examples/gate-report/valid/build-and-test-passed.json");

/// The repository the canned run is about.
pub const REPOSITORY: &str = "example-org/word-count";
/// The issue number.
pub const ISSUE: u64 = 12;
/// The correlation id of the canned job.
pub const CORRELATION: &str = "cor-0000000000000001";

/// What to build.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// The scenario id to put on the evidence.
    pub scenario: &'static str,
    /// Production (real adapters) or test mode (labelled fakes).
    pub mode: Mode,
    /// The language of the request: `en` or `pt-BR`.
    pub source_language: &'static str,
}

impl Options {
    /// E1 as it should look with real adapters.
    #[must_use]
    pub fn e1_production() -> Self {
        Self {
            scenario: "E1",
            mode: Mode::Production,
            source_language: "en",
        }
    }

    /// E2 as it should look with real adapters.
    #[must_use]
    pub fn e2_production() -> Self {
        Self {
            scenario: "E2",
            mode: Mode::Production,
            source_language: "pt-BR",
        }
    }

    /// E1 as it should look in test mode with labelled fakes.
    #[must_use]
    pub fn e1_test_mode() -> Self {
        Self {
            scenario: "E1",
            mode: Mode::Test,
            source_language: "en",
        }
    }
}

/// A UUID-shaped identifier that is the same every time: `kind` separates the families.
#[must_use]
pub fn uid(kind: u16, n: u32) -> String {
    format!("018f3a7e-{kind:04x}-7000-8000-{n:012x}")
}

/// `sha256:` and the hash of `bytes`.
#[must_use]
pub fn sha(bytes: &[u8]) -> String {
    Sha256Digest::of(bytes).as_str().to_owned()
}

fn patch(value: &mut Value, pointer: &str, with: Value) {
    if let Some(slot) = value.pointer_mut(pointer) {
        *slot = with;
    } else {
        panic!("the template has no {pointer}");
    }
}

fn parse(text: &str) -> Value {
    serde_json::from_str(text).expect("a schema example is JSON")
}

// ---------------------------------------------------------------------------------------------
// The documents

/// The specification contract for the job, patched from the valid example.
#[must_use]
pub fn specification(job: &str, o: &Options, files: &BTreeMap<String, String>) -> Value {
    let mut spec = parse(SPEC_EXAMPLE);
    patch(&mut spec, "/metadata/job_id", json!(job));
    patch(
        &mut spec,
        "/metadata/execution_mode",
        json!(o.mode.as_str()),
    );
    patch(
        &mut spec,
        "/provenance/source_request/language",
        json!(o.source_language),
    );
    if o.mode == Mode::Test {
        patch(
            &mut spec,
            "/provenance/host_runtime/fidelity",
            json!("fake"),
        );
    }
    if let Some(artifacts) = spec
        .pointer_mut("/provenance/artifacts")
        .and_then(Value::as_array_mut)
    {
        for artifact in artifacts {
            let path = artifact["path"].as_str().unwrap_or_default().to_owned();
            if let Some(hash) = files.get(&path) {
                artifact["sha256"] = json!(hash);
            }
        }
    }
    spec
}

/// The task graph for the job, patched from the valid example. The documentation task owns the
/// changelog too, because the documenting stage updates it.
#[must_use]
pub fn task_dag(job: &str, o: &Options, spec_hash: &str) -> Value {
    let mut dag = parse(DAG_EXAMPLE);
    patch(&mut dag, "/metadata/job_id", json!(job));
    patch(&mut dag, "/metadata/execution_mode", json!(o.mode.as_str()));
    patch(&mut dag, "/metadata/spec_ref/sha256", json!(spec_hash));
    if let Some(tasks) = dag.pointer_mut("/tasks").and_then(Value::as_array_mut) {
        for task in tasks {
            if task["task_id"] == "document-json-flag" {
                task["owned_files"] = json!(["README.md", "CHANGELOG.md"]);
                task["expected_changes"] = json!([
                    { "path_glob": "README.md", "change": "modify" },
                    { "path_glob": "CHANGELOG.md", "change": "modify" }
                ]);
            }
            if let Some(inputs) = task
                .get_mut("input_artifacts")
                .and_then(Value::as_array_mut)
            {
                for input in inputs {
                    input["sha256"] = json!(spec_hash);
                }
            }
        }
    }
    dag
}

/// A gate report patched from the valid example.
#[must_use]
pub fn gate_report(
    job: &str,
    stage_run: &str,
    attempt: &str,
    gate_id: &str,
    argvs: &[&[&str]],
    o: &Options,
    n: u32,
) -> Value {
    let mut report = parse(GATE_EXAMPLE);
    patch(&mut report, "/metadata/gate_report_id", json!(uid(7, n)));
    patch(&mut report, "/metadata/gate_id", json!(gate_id));
    patch(&mut report, "/metadata/job_id", json!(job));
    patch(&mut report, "/metadata/stage_run_id", json!(stage_run));
    patch(&mut report, "/metadata/attempt_id", json!(attempt));
    patch(
        &mut report,
        "/metadata/execution_mode",
        json!(o.mode.as_str()),
    );
    if o.mode == Mode::Test {
        patch(&mut report, "/environment/fidelity", json!("fake"));
    }
    let template = report["commands"][0].clone();
    let commands: Vec<Value> = argvs
        .iter()
        .map(|argv| {
            let mut command = template.clone();
            command["argv"] = json!(argv);
            command
        })
        .collect();
    patch(&mut report, "/commands", Value::Array(commands));
    report
}

/// The task documents, one for each task of the graph, in the four-section template.
#[must_use]
pub fn task_documents(dag: &Value) -> Vec<Document> {
    let tasks = dag["tasks"].as_array().cloned().unwrap_or_default();
    tasks
        .iter()
        .map(|task| {
            let bullets = |key: &str| -> String {
                task[key]
                    .as_array()
                    .map(|list| {
                        list.iter()
                            .filter_map(Value::as_str)
                            .map(|line| format!("- {line}"))
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default()
            };
            Document {
                kind: "task".to_owned(),
                path: format!("tasks/{}", task["task_id"].as_str().unwrap_or("task")),
                title: task["title"].as_str().unwrap_or_default().to_owned(),
                body: format!(
                    "## Why this matters\n{}\n\n## What needs to change\n{}\n\n## Acceptance criteria\n{}\n\n## Verification\n{}",
                    task["why_this_matters"].as_str().unwrap_or_default(),
                    task["what_needs_to_change"].as_str().unwrap_or_default(),
                    bullets("acceptance_criteria"),
                    bullets("verification"),
                ),
                doc_type: None,
            }
        })
        .collect()
}

/// The specification as a human-facing text.
#[must_use]
pub fn specification_document() -> Document {
    Document {
        kind: "specification".to_owned(),
        path: "specs/001-json-output/spec.md".to_owned(),
        title: "Add a JSON output option to the word count tool".to_owned(),
        body: concat!(
            "Users of the word count command line tool want to read its results from scripts. ",
            "The tool should print the line, word and character counts as a JSON object when asked, ",
            "and keep its current output otherwise.\n\n",
            "## Requirements\n",
            "- When the --json flag is given, the tool prints the line, word and character counts as one JSON object on standard output.\n",
            "- When the --json flag is not given, the tool keeps its plain-text output unchanged.\n",
            "- When the input file cannot be read, the tool writes an error message to standard error and exits with a non-zero status, with or without the --json flag.\n\n",
            "## Acceptance scenarios\n",
            "- A text file with 3 lines, 7 words and 31 characters gives a JSON object with lines set to 3, words set to 7 and characters set to 31.\n",
            "- An empty file gives a JSON object with all three counts set to 0.\n",
            "- Without the --json flag the output is byte for byte the same as in the previous release.\n",
            "- A path that does not exist gives an empty standard output, an explanation on standard error and a non-zero exit status.\n\n",
            "## Constraints\n",
            "- The change adds no third-party dependency, so the tool still builds without a network."
        )
        .to_owned(),
        doc_type: None,
    }
}

/// The pull request as a human-facing text. `head_hash` is the ledger head the body must carry.
#[must_use]
pub fn pull_request_document(head_hash: &str) -> Document {
    Document {
        kind: "pull_request".to_owned(),
        path: "pull_request".to_owned(),
        title: "Add a JSON output option to the word count tool".to_owned(),
        body: format!(
            concat!(
                "This change adds the --json option, so scripts can read the counts as a JSON object. ",
                "The plain-text output does not change. It closes issue #{issue}.\n\n",
                "## Evidence\n",
                "- Specification: [specs/001-json-output/spec.md](specs/001-json-output/spec.md)\n",
                "- Plan: [specs/001-json-output/plan.md](specs/001-json-output/plan.md)\n",
                "- Evidence manifest: [evidence/manifest.json](evidence/manifest.json)\n",
                "- Ledger head: {head}\n\n",
                "## Test matrix\n",
                "- Build and unit tests passed in a fresh sandbox.\n",
                "- The independent reviewer returned PASS.\n",
                "- The documentation gate passed.\n\n",
                "A person still has to approve this pull request. Nothing is merged or deployed by the factory."
            ),
            issue = ISSUE,
            head = head_hash
        ),
        doc_type: None,
    }
}

/// The README and the changelog entry that the documenting stage writes.
#[must_use]
pub fn documentation_documents() -> Vec<Document> {
    vec![
        Document {
            kind: "documentation".to_owned(),
            path: "README.md".to_owned(),
            title: "Count lines, words and characters with the word count tool".to_owned(),
            body: concat!(
                "The word count tool prints the number of lines, words and characters of a text file.\n\n",
                "## Options\n",
                "| Option | Effect |\n",
                "|---|---|\n",
                "| `--json` | Print the counts as one JSON object with the keys `lines`, `words` and `characters`, in that order. |\n\n",
                "Without `--json` the tool prints three columns of numbers, as before. ",
                "If the file cannot be read, the tool writes an error to standard error and exits with a non-zero status."
            )
            .to_owned(),
            doc_type: Some("reference".to_owned()),
        },
        Document {
            kind: "documentation".to_owned(),
            path: "CHANGELOG.md".to_owned(),
            title: "Changelog of the word count tool".to_owned(),
            body: "## Unreleased\n\n### Added\n\n- The `--json` option prints the line, word and character counts as one JSON object.".to_owned(),
            doc_type: Some("changelog".to_owned()),
        },
    ]
}

// ---------------------------------------------------------------------------------------------
// The ledger

/// The identifiers and the claim of one ledger entry.
#[derive(Clone, Copy)]
struct EntrySpec<'a> {
    job: &'a str,
    stage_run: &'a str,
    attempt: &'a str,
    sequence: u32,
    mode: Mode,
    claim: &'a Value,
    evidence: &'a Value,
}

fn ledger_entry(
    spec: &EntrySpec<'_>,
    previous: Option<&EvidenceLedgerEntry>,
) -> EvidenceLedgerEntry {
    let EntrySpec {
        job,
        stage_run,
        attempt,
        sequence,
        mode,
        claim,
        evidence,
    } = *spec;
    let (component, fidelity) = match mode {
        Mode::Production => ("workflow.gate-evaluator", "real"),
        Mode::Test => ("testkit.fake-agent-runtime", "fake"),
    };
    let draft = json!({
        "schema_version": 1,
        "metadata": {
            "entry_id": uid(5, sequence),
            "job_id": job,
            "stage_run_id": stage_run,
            "attempt_id": attempt,
            "sequence": sequence,
            "recorded_at": "2026-10-27T09:16:35Z",
            "execution_mode": mode.as_str(),
            "recorded_by": { "component": component, "fidelity": fidelity }
        },
        "claim": claim,
        "evidence": evidence,
        "confidence": { "level": if mode == Mode::Production { "high" } else { "low" }, "rationale": "The stage gate recorded this claim from stored evidence." },
        "prev_entry_hash": if previous.is_some() { json!(sha(b"placeholder")) } else { Value::Null },
        "entry_hash": sha(b"placeholder")
    });
    let mut entry = EvidenceLedgerEntry::from_json_value(draft).expect("the ledger draft is valid");
    entry.prev_entry_hash = previous.map(|p| p.entry_hash.clone());
    entry.sealed().expect("the entry can be sealed")
}

// ---------------------------------------------------------------------------------------------
// The whole run

/// The honest evidence of the happy path for the stages of `env`.
///
/// # Panics
/// When a template or a derived document is malformed, which a test of this module catches.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn honest(env: &Env, o: Options) -> RunEvidence {
    let job = uid(1, 1);
    let mut seq: u64 = 0;
    let mut next = || {
        seq += 1;
        seq
    };
    let mut timeline = Vec::new();
    let mut stage_runs = Vec::new();
    let mut spans = Vec::new();
    let mut audit = Vec::new();
    let mut correlated = Vec::new();
    let mut gate_reports = Vec::new();

    let push_audit = |audit: &mut Vec<AuditRecord>,
                      correlated: &mut Vec<Correlated>,
                      action: &str,
                      actor: &str,
                      detail: &str| {
        let n = audit.len() as u64 + 1;
        audit.push(AuditRecord {
            seq: n,
            action: action.to_owned(),
            actor: actor.to_owned(),
            correlation_id: Some(CORRELATION.to_owned()),
            detail: detail.to_owned(),
        });
        correlated.push(Correlated {
            source: "audit".to_owned(),
            label: format!("{action} #{n}"),
            correlation_id: Some(CORRELATION.to_owned()),
        });
    };

    timeline.push(TimelineEntry {
        seq: next(),
        subject: "job".to_owned(),
        subject_id: job.clone(),
        kind: None,
        from: "RECEIVED".to_owned(),
        to: "ACTIVE".to_owned(),
        reason:
            "The requester is on the allowlist and the repository passed the protection preflight."
                .to_owned(),
    });
    push_audit(
        &mut audit,
        &mut correlated,
        "job.admitted",
        "factory",
        "admitted",
    );
    spans.push(Span {
        id: uid(8, 0),
        parent_id: None,
        name: "factory.job".to_owned(),
        stage_run_id: None,
        attempt_id: None,
    });

    // The documents come first so the ledger head can go into the pull request body.
    let mut files: BTreeMap<String, String> = BTreeMap::new();
    for (path, text) in [
        ("specs/001-json-output/spec.md", "spec text"),
        (
            "specs/001-json-output/checklists/requirements.md",
            "checklist text",
        ),
        (".specify/memory/constitution.md", "constitution text"),
    ] {
        files.insert(path.to_owned(), sha(text.as_bytes()));
    }
    let spec = specification(&job, &o, &files);
    let spec_hash = sha(spec.to_string().as_bytes());
    let dag = task_dag(&job, &o, &spec_hash);
    let dag_hash = sha(dag.to_string().as_bytes());

    // Stage runs, timeline, spans and the ledger.
    let mut ledger_typed: Vec<EvidenceLedgerEntry> = Vec::new();
    let mut run_ids: BTreeMap<String, (String, String)> = BTreeMap::new();
    for (index, stage) in env.stages.iter().enumerate() {
        let n = u32::try_from(index).unwrap_or(0) + 1;
        let run_id = uid(2, n);
        let attempt_id = uid(3, n);
        run_ids.insert(stage.kind.clone(), (run_id.clone(), attempt_id.clone()));
        let steps: &[(&str, &str)] = if stage.kind == "APPROVAL" {
            &[
                ("PENDING", "READY"),
                ("READY", "RUNNING"),
                ("RUNNING", "GATING"),
                ("GATING", "WAITING_FOR_HUMAN"),
            ]
        } else {
            &[
                ("PENDING", "READY"),
                ("READY", "RUNNING"),
                ("RUNNING", "GATING"),
                ("GATING", "PASSED"),
            ]
        };
        for (from, to) in steps {
            timeline.push(TimelineEntry {
                seq: next(),
                subject: "stage_run".to_owned(),
                subject_id: run_id.clone(),
                kind: Some(stage.kind.clone()),
                from: (*from).to_owned(),
                to: (*to).to_owned(),
                reason: format!("The {} stage moved from {from} to {to}.", stage.kind),
            });
        }
        if stage.kind == "APPROVAL" {
            timeline.push(TimelineEntry {
                seq: next(),
                subject: "job".to_owned(),
                subject_id: job.clone(),
                kind: None,
                from: "ACTIVE".to_owned(),
                to: "WAITING_FOR_HUMAN".to_owned(),
                reason: "The draft pull request waits for a person to approve.".to_owned(),
            });
            push_audit(
                &mut audit,
                &mut correlated,
                "job.waiting_for_human",
                "factory",
                "approval",
            );
            timeline.push(TimelineEntry {
                seq: next(),
                subject: "stage_run".to_owned(),
                subject_id: run_id.clone(),
                kind: Some(stage.kind.clone()),
                from: "WAITING_FOR_HUMAN".to_owned(),
                to: "PASSED".to_owned(),
                reason: "An approver accepted the evidence.".to_owned(),
            });
            push_audit(
                &mut audit,
                &mut correlated,
                "approval.recorded",
                "reviewer-ana",
                "role=approver; evidence_seen=ledger head",
            );
            timeline.push(TimelineEntry {
                seq: next(),
                subject: "job".to_owned(),
                subject_id: job.clone(),
                kind: None,
                from: "WAITING_FOR_HUMAN".to_owned(),
                to: "COMPLETED".to_owned(),
                reason: "The approval was recorded. The pull request stays unmerged.".to_owned(),
            });
            push_audit(
                &mut audit,
                &mut correlated,
                "job.completed",
                "factory",
                "completed",
            );
        } else {
            push_audit(
                &mut audit,
                &mut correlated,
                "stage_run.passed",
                "factory",
                &stage.kind,
            );
        }
        spans.push(Span {
            id: uid(8, n),
            parent_id: Some(uid(8, 0)),
            name: "factory.stage_run".to_owned(),
            stage_run_id: Some(run_id.clone()),
            attempt_id: None,
        });
        spans.push(Span {
            id: uid(9, n),
            parent_id: Some(uid(8, n)),
            name: "factory.attempt".to_owned(),
            stage_run_id: Some(run_id.clone()),
            attempt_id: Some(attempt_id.clone()),
        });
        correlated.push(Correlated {
            source: "log".to_owned(),
            label: format!("{} attempt log", stage.kind),
            correlation_id: Some(CORRELATION.to_owned()),
        });
        stage_runs.push(StageRunRecord {
            id: run_id.clone(),
            kind: stage.kind.clone(),
            status: "PASSED".to_owned(),
            attempts: vec![AttemptRecord {
                id: attempt_id.clone(),
                status: "SUCCEEDED".to_owned(),
            }],
            rework_round: 0,
        });

        // The ledger entry of the stage.
        let claim_for = |level: Option<&str>| -> (Value, Value) {
            match o.mode {
                Mode::Production => {
                    let mut claim = json!({
                        "statement": format!("The {} stage passed its gate on stored evidence.", stage.kind),
                        "kind": "measured_fact"
                    });
                    if let Some(level) = level {
                        claim["assurance_level"] = json!(level);
                    }
                    (
                        claim,
                        json!([{ "type": "trace", "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "span_id": "00f067aa0ba902b7" }]),
                    )
                }
                Mode::Test => (
                    json!({
                        "statement": format!("A fake component produced the {} output, which only shows that the engine accepts its shape.", stage.kind),
                        "kind": "assumption"
                    }),
                    json!([]),
                ),
            }
        };
        let level = match stage.kind.as_str() {
            "SPECIFICATION" => Some("SPECIFIED"),
            "IMPLEMENTATION" => Some("IMPLEMENTED"),
            "VALIDATION" => Some("VERIFIED_IN_SANDBOX"),
            _ => None,
        };
        let (claim, evidence) = claim_for(level);
        let entry = ledger_entry(
            &EntrySpec {
                job: &job,
                stage_run: &run_id,
                attempt: &attempt_id,
                sequence: n,
                mode: o.mode,
                claim: &claim,
                evidence: &evidence,
            },
            ledger_typed.last(),
        );
        ledger_typed.push(entry);
    }

    // The head the pull request body and the manifest cite is the DELIVERY entry.
    let delivery_index = env
        .stages
        .iter()
        .position(|s| s.kind == "DELIVERY")
        .expect("the pipeline has a DELIVERY stage");
    let head_entry = &ledger_typed[delivery_index];
    let head_hash = head_entry.entry_hash.as_str().to_owned();
    let head_sequence = head_entry.sequence();

    // The manifest.
    let mut manifest = parse(MANIFEST_EXAMPLE);
    patch(&mut manifest, "/metadata/job_id", json!(job));
    patch(
        &mut manifest,
        "/metadata/execution_mode",
        json!(o.mode.as_str()),
    );
    patch(
        &mut manifest,
        "/metadata/repository/full_name",
        json!(REPOSITORY),
    );
    patch(
        &mut manifest,
        "/ledger",
        json!({
            "entry_count": head_sequence,
            "head_sequence": head_sequence,
            "head_hash": head_hash,
            "chain_verified_at": "2026-10-27T10:19:58Z"
        }),
    );
    patch(&mut manifest, "/specification/sha256", json!(spec_hash));
    patch(&mut manifest, "/plan/sha256", json!(dag_hash));
    patch(
        &mut manifest,
        "/metadata/repository/head_commit",
        json!(sha_hex40("head")),
    );
    patch(
        &mut manifest,
        "/metadata/repository/base_commit",
        json!(sha_hex40("base")),
    );
    if o.mode == Mode::Test {
        let fake_names = [
            ("fake-agent-runtime", "agent_runtime"),
            ("fake-sandbox", "sandbox"),
            ("fake-github", "change_host"),
            ("in-memory-artifacts", "artifact_store"),
            ("in-memory-store", "store"),
        ];
        let adapters: Vec<Value> = fake_names
            .iter()
            .map(|(name, kind)| json!({ "name": name, "kind": kind, "fidelity": "fake", "version": "testkit" }))
            .collect();
        patch(&mut manifest, "/adapters", Value::Array(adapters));
        patch(
            &mut manifest,
            "/assurance",
            json!({
                "attained": [],
                "not_attained": [
                    { "level": "SPECIFIED", "reason": "A fake component recorded the evidence, and a fake never supports an assurance level." },
                    { "level": "IMPLEMENTED", "reason": "A fake component recorded the evidence, and a fake never supports an assurance level." },
                    { "level": "VERIFIED_IN_SANDBOX", "reason": "A fake component recorded the evidence, and a fake never supports an assurance level." },
                    { "level": "PRODUCTION_READY", "reason": "The run used fakes in test mode and no human release sign-off exists." }
                ]
            }),
        );
        patch(
            &mut manifest,
            "/limitations",
            json!([
                "Every adapter in this run is a labelled fake, so the run shows the engine and the contracts and nothing about a real agent, sandbox or GitHub.",
                "No assurance level is attained."
            ]),
        );
    } else {
        // The three levels cite the entries that claim them.
        let cite = |kind: &str| -> String {
            let index = env.stages.iter().position(|s| s.kind == kind).unwrap_or(0);
            ledger_typed[index].metadata.entry_id.to_string()
        };
        patch(
            &mut manifest,
            "/assurance/attained",
            json!([
                { "level": "SPECIFIED", "ledger_entry_id": cite("SPECIFICATION") },
                { "level": "IMPLEMENTED", "ledger_entry_id": cite("IMPLEMENTATION") },
                { "level": "VERIFIED_IN_SANDBOX", "ledger_entry_id": cite("VALIDATION") }
            ]),
        );
    }

    // The approval entry, after the manifest, extends the chain.
    let approval_index = env
        .stages
        .iter()
        .position(|s| s.kind == "APPROVAL")
        .unwrap_or(0);
    let _ = approval_index; // the APPROVAL entry is already in the chain at its own position

    // Gate reports.
    let (validation_run, validation_attempt) = run_ids["VALIDATION"].clone();
    let (docs_run, docs_attempt) = run_ids["DOCUMENTATION_REVIEW"].clone();
    gate_reports.push(GateReportRecord {
        stage_run_id: validation_run.clone(),
        report: gate_report(
            &job,
            &validation_run,
            &validation_attempt,
            "build-and-unit-tests",
            &[
                &["cargo", "build", "--locked"],
                &["cargo", "test", "--locked"],
            ],
            &o,
            1,
        ),
    });
    gate_reports.push(GateReportRecord {
        stage_run_id: docs_run.clone(),
        report: gate_report(
            &job,
            &docs_run,
            &docs_attempt,
            "documentation-gate",
            &[
                &["docs-link-check", "--root", "."],
                &["docs-snippet-run", "README.md"],
            ],
            &o,
            2,
        ),
    });

    // Documents.
    let mut documents = vec![specification_document()];
    documents.extend(task_documents(&dag));
    documents.push(pull_request_document(&head_hash));
    documents.extend(documentation_documents());

    // GitHub.
    let commits = vec![
        Commit {
            sha: sha_hex40("c1"),
            message: "Add the JSON output option".to_owned(),
            paths: vec![
                "src/main.rs".to_owned(),
                "src/output.rs".to_owned(),
                "tests/json_output.rs".to_owned(),
            ],
        },
        Commit {
            sha: sha_hex40("c2"),
            message: "Test the unreadable file error".to_owned(),
            paths: vec!["tests/errors.rs".to_owned()],
        },
        Commit {
            sha: sha_hex40("c3"),
            message: "Document the JSON option".to_owned(),
            paths: vec!["README.md".to_owned(), "CHANGELOG.md".to_owned()],
        },
    ];
    let head_sha = commits[commits.len() - 1].sha.clone();
    let changed_paths: Vec<String> = commits.iter().flat_map(|c| c.paths.clone()).collect();
    let required_permissions: BTreeMap<String, String> = [
        ("metadata", "read"),
        ("contents", "write"),
        ("pull_requests", "write"),
        ("issues", "write"),
        ("checks", "write"),
        ("statuses", "write"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    let github = GithubEvidence {
        repository: REPOSITORY.to_owned(),
        base_branch: "main".to_owned(),
        base_sha_before: sha_hex40("base"),
        base_sha_after: sha_hex40("base"),
        pull_requests: vec![PullRequest {
            number: 7,
            draft: true,
            merged: false,
            state: "open".to_owned(),
            head_branch: "factory/json-output".to_owned(),
            head_sha: head_sha.clone(),
            title: "Add a JSON output option to the word count tool".to_owned(),
            body: pull_request_document(&head_hash).body,
        }],
        head_commits: commits,
        head_files: files,
        changed_paths,
        check_runs: vec![CheckRun {
            name: "ci".to_owned(),
            conclusion: "success".to_owned(),
            head_sha,
        }],
        comments: vec![
            "The factory accepted this request and opened a draft pull request.".to_owned(),
        ],
        requests: [
            ("GET", "/repos/example-org/word-count/issues/12"),
            ("POST", "/repos/example-org/word-count/git/refs"),
            ("PUT", "/repos/example-org/word-count/contents/src/main.rs"),
            ("POST", "/repos/example-org/word-count/pulls"),
            ("POST", "/repos/example-org/word-count/check-runs"),
            ("POST", "/repos/example-org/word-count/issues/12/comments"),
        ]
        .iter()
        .map(|(method, path)| GithubRequest {
            method: (*method).to_owned(),
            path: (*path).to_owned(),
        })
        .collect(),
        tokens: vec![TokenRecord {
            id: "token-1".to_owned(),
            permissions: required_permissions,
            repositories: vec![REPOSITORY.to_owned()],
        }],
        protection: Some(ProtectionFacts {
            require_pull_request: true,
            required_approvals: 1,
            required_checks: vec![RequiredCheckFacts {
                context: "ci".to_owned(),
                pinned_to_app: true,
            }],
            dismiss_stale_reviews: true,
            enforce_admins: true,
            allow_force_pushes: false,
            allow_deletions: false,
            require_code_owner_review: true,
            app_may_bypass: false,
        }),
    };

    let ledger: Vec<Value> = ledger_typed
        .iter()
        .map(|entry| entry.to_json_value().expect("an entry is JSON"))
        .collect();

    let mut stored_hashes = BTreeMap::new();
    stored_hashes.insert("specification".to_owned(), spec_hash);
    stored_hashes.insert("task_dag".to_owned(), dag_hash);

    RunEvidence {
        scenario: o.scenario.to_owned(),
        wiring: "canned".to_owned(),
        mode: o.mode,
        source_language: o.source_language.to_owned(),
        job: JobRecord {
            id: job,
            status: "COMPLETED".to_owned(),
            correlation_id: CORRELATION.to_owned(),
            requester: "requester-bruno".to_owned(),
            issue_number: ISSUE,
        },
        stage_runs,
        ledger,
        audit,
        timeline,
        documents,
        contracts: Contracts {
            specification: Some(spec),
            task_dag: Some(dag),
            evidence_manifest: Some(manifest),
            gate_reports,
            stored_hashes,
        },
        github,
        telemetry: Telemetry { spans, correlated },
        usage: Usage {
            total_micro_usd: 1_500_000,
            budget_micro_usd: 5_000_000,
            calls_after_exhaustion: 0,
        },
        hostile: None,
        facts: BTreeMap::new(),
    }
}

/// A 40-character commit id made from a label, the same every time.
#[must_use]
pub fn sha_hex40(label: &str) -> String {
    sha(label.as_bytes())
        .trim_start_matches("sha256:")
        .chars()
        .take(40)
        .collect()
}
