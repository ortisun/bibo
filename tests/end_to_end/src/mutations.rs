//! Deliberate corruptions of the honest evidence, one fact at a time.
//!
//! An assertion that cannot fail proves nothing. Each mutation here starts from an honest evidence
//! set (see [`crate::canned`]), breaks one fact that an assertion exists to protect, and says which
//! assertion must then fail and what its reason must mention. `self_test` runs all of them, and
//! `tests/mutations.rs` does the same under `cargo test`.
//!
//! Mutations that change the ledger re-seal the chain afterwards, so the evidence stays consistent
//! everywhere except at the broken fact. That keeps the blast radius small, and the self-test
//! reports which assertions failed besides the target.

use factory_domain::contracts::{Contract, EvidenceLedgerEntry};
use serde_json::{Value, json};

use crate::assertions;
use crate::canned::{self, Options};
use crate::check::Env;
use crate::evidence::{Correlated, Mode, RunEvidence, StageRunRecord};

/// Which honest evidence a mutation starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    /// E1 with real adapters.
    Production,
    /// E2 with real adapters (a Portuguese request).
    ProductionPortuguese,
    /// E1 in test mode with labelled fakes.
    TestMode,
}

impl Base {
    fn options(self) -> Options {
        match self {
            Self::Production => Options::e1_production(),
            Self::ProductionPortuguese => Options::e2_production(),
            Self::TestMode => Options::e1_test_mode(),
        }
    }
}

/// One deliberate corruption.
#[derive(Clone, Copy)]
pub struct Mutation {
    /// A short name, unique.
    pub name: &'static str,
    /// The assertion that must fail.
    pub assertion: &'static str,
    /// What is broken, in a sentence.
    pub what: &'static str,
    /// Text that the failing reason must contain.
    pub expect: &'static str,
    /// The honest evidence to start from.
    pub base: Base,
    /// The corruption.
    pub apply: fn(&mut RunEvidence),
}

// ---------------------------------------------------------------------------------------------
// Helpers

fn run_id(ev: &RunEvidence, kind: &str) -> String {
    ev.stage_runs
        .iter()
        .find(|run| run.kind == kind)
        .map(|run| run.id.clone())
        .unwrap_or_else(|| panic!("the evidence has no {kind} run"))
}

fn run_mut<'a>(ev: &'a mut RunEvidence, kind: &str) -> &'a mut StageRunRecord {
    ev.stage_runs
        .iter_mut()
        .find(|run| run.kind == kind)
        .unwrap_or_else(|| panic!("the evidence has no {kind} run"))
}

fn ledger_index(ev: &RunEvidence, kind: &str) -> usize {
    let id = run_id(ev, kind);
    ev.ledger
        .iter()
        .position(|entry| {
            entry
                .pointer("/metadata/stage_run_id")
                .and_then(Value::as_str)
                == Some(id.as_str())
        })
        .unwrap_or_else(|| panic!("the ledger has no entry for {kind}"))
}

/// Recomputes the hash chain after a change to a ledger entry, and moves the head hash in the
/// manifest and in the pull request body with it, so the chain stays valid and consistent.
pub fn reseal(ev: &mut RunEvidence) {
    let old_head = ev.contracts.evidence_manifest.as_ref().and_then(|m| {
        m.pointer("/ledger/head_hash")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let head_sequence = ev
        .contracts
        .evidence_manifest
        .as_ref()
        .and_then(|m| m.pointer("/ledger/head_sequence").and_then(Value::as_u64))
        .unwrap_or(0);
    let mut previous: Option<EvidenceLedgerEntry> = None;
    let mut resealed: Vec<Value> = Vec::new();
    for value in &ev.ledger {
        let mut entry = EvidenceLedgerEntry::from_json_value(value.clone())
            .expect("a ledger entry stays valid when only its hashes are stale");
        entry.prev_entry_hash = previous.as_ref().map(|p| p.entry_hash.clone());
        let entry = entry.sealed().expect("an entry can be sealed");
        resealed.push(entry.to_json_value().expect("an entry is JSON"));
        previous = Some(entry);
    }
    ev.ledger = resealed;
    let new_head = usize::try_from(head_sequence)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|i| ev.ledger.get(i))
        .and_then(|e| {
            e.pointer("/entry_hash")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    if let (Some(old), Some(new)) = (old_head, new_head) {
        if let Some(slot) = ev
            .contracts
            .evidence_manifest
            .as_mut()
            .and_then(|m| m.pointer_mut("/ledger/head_hash"))
        {
            *slot = json!(new);
        }
        for pr in &mut ev.github.pull_requests {
            pr.body = pr.body.replace(&old, &new);
        }
        for doc in ev.documents.iter_mut().filter(|d| d.kind == "pull_request") {
            doc.body = doc.body.replace(&old, &new);
        }
    }
}

/// Recomputes the stored hash of the task graph and writes it into the manifest.
fn rehash_dag(ev: &mut RunEvidence) {
    let Some(dag) = &ev.contracts.task_dag else {
        return;
    };
    let hash = canned::sha(dag.to_string().as_bytes());
    ev.contracts
        .stored_hashes
        .insert("task_dag".to_owned(), hash.clone());
    if let Some(slot) = ev
        .contracts
        .evidence_manifest
        .as_mut()
        .and_then(|m| m.pointer_mut("/plan/sha256"))
    {
        *slot = json!(hash);
    }
}

fn set(value: &mut Option<Value>, pointer: &str, with: Value) {
    let slot = value
        .as_mut()
        .and_then(|v| v.pointer_mut(pointer))
        .unwrap_or_else(|| panic!("no {pointer} to change"));
    *slot = with;
}

fn gate_mut<'a>(ev: &'a mut RunEvidence, gate_id: &str) -> &'a mut Value {
    &mut ev
        .contracts
        .gate_reports
        .iter_mut()
        .find(|record| {
            record
                .report
                .pointer("/metadata/gate_id")
                .and_then(Value::as_str)
                == Some(gate_id)
        })
        .unwrap_or_else(|| panic!("no gate report {gate_id}"))
        .report
}

fn doc_mut<'a>(ev: &'a mut RunEvidence, kind: &str) -> &'a mut crate::evidence::Document {
    ev.documents
        .iter_mut()
        .find(|d| d.kind == kind)
        .unwrap_or_else(|| panic!("no {kind} document"))
}

fn swap_entry_runs(ev: &mut RunEvidence, a: &str, b: &str) {
    let (ia, ib) = (ledger_index(ev, a), ledger_index(ev, b));
    let (ra, rb) = (run_id(ev, a), run_id(ev, b));
    ev.ledger[ia]["metadata"]["stage_run_id"] = json!(rb);
    ev.ledger[ib]["metadata"]["stage_run_id"] = json!(ra);
    reseal(ev);
}

fn requests_push(ev: &mut RunEvidence, method: &str, path: &str) {
    ev.github.requests.push(crate::evidence::GithubRequest {
        method: method.to_owned(),
        path: path.to_owned(),
    });
}

const PORTUGUESE: &str = "A ferramenta de contagem de palavras deve imprimir as contagens de linhas, palavras e caracteres como um objeto JSON quando o usuário pedir. Quando a opção não for usada, a saída continua exatamente como era antes. Se o arquivo não puder ser lido, a ferramenta escreve uma mensagem de erro na saída de erro e termina com um código diferente de zero.";

// ---------------------------------------------------------------------------------------------
// The mutations

/// Every mutation, in the order of the assertions.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn all() -> Vec<Mutation> {
    use Base::{Production, ProductionPortuguese, TestMode};
    vec![
        // ---- A1 ------------------------------------------------------------------------------
        Mutation {
            name: "job-still-active",
            assertion: "A1",
            what: "The job is ACTIVE instead of COMPLETED.",
            expect: "not COMPLETED",
            base: Production,
            apply: |ev| ev.job.status = "ACTIVE".to_owned(),
        },
        Mutation {
            name: "two-passed-runs-of-one-stage",
            assertion: "A1",
            what: "INTAKE has two PASSED runs.",
            expect: "has 2 PASSED runs",
            base: Production,
            apply: |ev| {
                let mut twin = ev.stage_runs[0].clone();
                twin.id = canned::uid(2, 900);
                ev.stage_runs.push(twin);
            },
        },
        Mutation {
            name: "a-stage-has-no-passed-run",
            assertion: "A1",
            what: "DOMAIN_DISCOVERY never ran.",
            expect: "has 0 PASSED runs",
            base: Production,
            apply: |ev| ev.stage_runs.retain(|run| run.kind != "DOMAIN_DISCOVERY"),
        },
        Mutation {
            name: "a-stage-is-skipped-and-no-rule-is-recorded",
            assertion: "A1",
            what: "DOMAIN_DISCOVERY is SKIPPED and the ledger holds no entry about the skip.",
            expect: "SKIPPED runs",
            base: Production,
            apply: |ev| {
                let skipped = run_id(ev, "DOMAIN_DISCOVERY");
                for run in &mut ev.stage_runs {
                    if run.id == skipped {
                        run.status = "SKIPPED".to_owned();
                    }
                }
                ev.ledger
                    .retain(|entry| entry["metadata"]["stage_run_id"].as_str() != Some(&skipped));
                reseal(ev);
            },
        },
        Mutation {
            name: "a-stage-passed-before-the-one-it-requires",
            assertion: "A1",
            what: "SPECIFICATION is shown passing before INTAKE.",
            expect: "before INTAKE passed",
            base: Production,
            apply: |ev| {
                let spec = run_id(ev, "SPECIFICATION");
                for entry in &mut ev.timeline {
                    if entry.subject_id == spec && entry.to == "PASSED" {
                        entry.seq = 0;
                    }
                }
            },
        },
        Mutation {
            name: "a-run-is-left-running",
            assertion: "A1",
            what: "A completed job still has a RUNNING run.",
            expect: "is RUNNING",
            base: Production,
            apply: |ev| {
                let mut extra = ev.stage_runs[1].clone();
                extra.id = canned::uid(2, 901);
                extra.status = "RUNNING".to_owned();
                ev.stage_runs.push(extra);
            },
        },
        // ---- A2 ------------------------------------------------------------------------------
        Mutation {
            name: "documentation-before-review",
            assertion: "A2",
            what: "The ledger shows DOCUMENTING finished before REVIEW.",
            expect: "REVIEW is not finished",
            base: Production,
            apply: |ev| swap_entry_runs(ev, "REVIEW", "DOCUMENTING"),
        },
        Mutation {
            name: "documentation-review-before-documenting",
            assertion: "A2",
            what: "The ledger shows DOCUMENTATION_REVIEW before DOCUMENTING.",
            expect: "DOCUMENTING is not finished",
            base: Production,
            apply: |ev| swap_entry_runs(ev, "DOCUMENTING", "DOCUMENTATION_REVIEW"),
        },
        Mutation {
            name: "delivery-before-documentation-review",
            assertion: "A2",
            what: "The ledger shows DELIVERY before DOCUMENTATION_REVIEW.",
            expect: "DOCUMENTATION_REVIEW is not finished",
            base: Production,
            apply: |ev| swap_entry_runs(ev, "DOCUMENTATION_REVIEW", "DELIVERY"),
        },
        Mutation {
            name: "passed-run-with-no-ledger-entry",
            assertion: "A2",
            what: "The DELIVERY run is PASSED and has no ledger entry.",
            expect: "PASSED with no ledger entry",
            base: Production,
            apply: |ev| {
                let index = ledger_index(ev, "DELIVERY");
                ev.ledger[index]["metadata"]["stage_run_id"] = json!(canned::uid(2, 999));
                reseal(ev);
            },
        },
        // ---- A3 ------------------------------------------------------------------------------
        Mutation {
            name: "pull-request-is-not-a-draft",
            assertion: "A3",
            what: "The pull request is ready for review, not a draft.",
            expect: "is not a draft",
            base: Production,
            apply: |ev| ev.github.pull_requests[0].draft = false,
        },
        Mutation {
            name: "no-pull-request",
            assertion: "A3",
            what: "GitHub holds no pull request from the job.",
            expect: "holds 0 pull requests",
            base: Production,
            apply: |ev| ev.github.pull_requests.clear(),
        },
        Mutation {
            name: "two-pull-requests",
            assertion: "A3",
            what: "The job opened two pull requests.",
            expect: "holds 2 pull requests",
            base: Production,
            apply: |ev| {
                let mut second = ev.github.pull_requests[0].clone();
                second.number = 8;
                ev.github.pull_requests.push(second);
            },
        },
        Mutation {
            name: "pull-request-body-does-not-link-the-issue",
            assertion: "A3",
            what: "The pull request body has no reference to the issue.",
            expect: "does not link issue #12",
            base: Production,
            apply: |ev| {
                ev.github.pull_requests[0].body =
                    ev.github.pull_requests[0].body.replace("#12", "the issue")
            },
        },
        Mutation {
            name: "pull-request-links-another-issue",
            assertion: "A3",
            what: "The body links #123, which is not issue 12.",
            expect: "does not link issue #12",
            base: Production,
            apply: |ev| {
                ev.github.pull_requests[0].body =
                    ev.github.pull_requests[0].body.replace("#12", "#123")
            },
        },
        Mutation {
            name: "no-documentation-commit",
            assertion: "A3",
            what: "The head branch has code commits and no documentation commit.",
            expect: "no commit that changes only documentation",
            base: Production,
            apply: |ev| {
                ev.github.head_commits.pop();
                ev.github.pull_requests[0].head_sha = ev
                    .github
                    .head_commits
                    .last()
                    .map(|c| c.sha.clone())
                    .unwrap_or_default();
            },
        },
        Mutation {
            name: "no-code-commit",
            assertion: "A3",
            what: "The head branch has only a documentation commit.",
            expect: "changes code",
            base: Production,
            apply: |ev| {
                ev.github
                    .head_commits
                    .retain(|c| c.message.starts_with("Document"))
            },
        },
        Mutation {
            name: "branch-tip-is-not-the-pull-request-head",
            assertion: "A3",
            what: "The branch tip is not the head commit of the pull request.",
            expect: "is not the head",
            base: Production,
            apply: |ev| ev.github.pull_requests[0].head_sha = canned::sha_hex40("elsewhere"),
        },
        Mutation {
            name: "pull-request-is-closed",
            assertion: "A3",
            what: "The pull request is closed.",
            expect: "not open",
            base: Production,
            apply: |ev| ev.github.pull_requests[0].state = "closed".to_owned(),
        },
        // ---- A4 ------------------------------------------------------------------------------
        Mutation {
            name: "no-evidence-manifest",
            assertion: "A4",
            what: "The run left no evidence manifest.",
            expect: "no evidence manifest",
            base: Production,
            apply: |ev| ev.contracts.evidence_manifest = None,
        },
        Mutation {
            name: "manifest-without-limitations",
            assertion: "A4",
            what: "The manifest lists no limitation.",
            expect: "at least 1 item",
            base: Production,
            apply: |ev| {
                set(
                    &mut ev.contracts.evidence_manifest,
                    "/limitations",
                    json!([]),
                )
            },
        },
        Mutation {
            name: "manifest-lists-a-fake-adapter-in-production",
            assertion: "A4",
            what: "An adapter in the manifest is a fake in a production job.",
            expect: "does not validate",
            base: Production,
            apply: |ev| {
                set(
                    &mut ev.contracts.evidence_manifest,
                    "/adapters/0/fidelity",
                    json!("fake"),
                )
            },
        },
        Mutation {
            name: "a-ledger-entry-was-changed-after-it-was-written",
            assertion: "A4",
            what: "The text of a ledger entry was edited, so its hash no longer matches.",
            expect: "does not verify",
            base: Production,
            apply: |ev| {
                ev.ledger[2]["claim"]["statement"] = json!("A different claim, written afterwards.")
            },
        },
        Mutation {
            name: "a-ledger-entry-was-removed",
            assertion: "A4",
            what: "An entry is missing from the middle of the chain.",
            expect: "does not verify",
            base: Production,
            apply: |ev| {
                ev.ledger.remove(4);
            },
        },
        Mutation {
            name: "manifest-cites-another-head",
            assertion: "A4",
            what: "The head hash in the manifest is not the stored one.",
            expect: "the manifest cites the head",
            base: Production,
            apply: |ev| {
                set(
                    &mut ev.contracts.evidence_manifest,
                    "/ledger/head_hash",
                    json!(canned::sha(b"another head")),
                )
            },
        },
        Mutation {
            name: "pull-request-body-carries-another-head",
            assertion: "A4",
            what: "The head hash in the pull request body is not the stored one.",
            expect: "does not carry the stored head",
            base: Production,
            apply: |ev| {
                let head = ev
                    .contracts
                    .evidence_manifest
                    .as_ref()
                    .and_then(|m| {
                        m.pointer("/ledger/head_hash")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .expect("a head");
                ev.github.pull_requests[0].body = ev.github.pull_requests[0]
                    .body
                    .replace(&head, &canned::sha(b"other"));
            },
        },
        Mutation {
            name: "a-passed-run-has-no-ledger-entry",
            assertion: "A4",
            what: "The INTAKE run is PASSED and no ledger entry cites it.",
            expect: "has no ledger entry",
            base: Production,
            apply: |ev| {
                let index = ledger_index(ev, "INTAKE");
                ev.ledger[index]["metadata"]["stage_run_id"] = json!(canned::uid(2, 998));
                reseal(ev);
            },
        },
        Mutation {
            name: "manifest-cites-another-specification",
            assertion: "A4",
            what: "The manifest cites a specification hash that differs from the stored bytes.",
            expect: "the stored bytes hash to",
            base: Production,
            apply: |ev| {
                set(
                    &mut ev.contracts.evidence_manifest,
                    "/specification/sha256",
                    json!(canned::sha(b"other spec")),
                )
            },
        },
        Mutation {
            name: "test-mode-manifest-says-production",
            assertion: "A4",
            what: "A test-mode job has a manifest that does not say test mode.",
            expect: "does not validate",
            base: TestMode,
            apply: |ev| {
                set(
                    &mut ev.contracts.evidence_manifest,
                    "/metadata/execution_mode",
                    json!("production"),
                )
            },
        },
        // ---- A5 ------------------------------------------------------------------------------
        Mutation {
            name: "no-specification",
            assertion: "A5",
            what: "The run left no specification contract.",
            expect: "no specification contract",
            base: Production,
            apply: |ev| ev.contracts.specification = None,
        },
        Mutation {
            name: "specification-artifact-hash-differs-from-the-branch",
            assertion: "A5",
            what: "A file on the branch no longer matches the hash in the specification.",
            expect: "hashes to",
            base: Production,
            apply: |ev| {
                ev.github.head_files.insert(
                    "specs/001-json-output/spec.md".to_owned(),
                    canned::sha(b"edited"),
                );
            },
        },
        Mutation {
            name: "specification-artifact-is-not-on-the-branch",
            assertion: "A5",
            what: "A file the specification cites is not on the branch.",
            expect: "not on the head branch",
            base: Production,
            apply: |ev| {
                ev.github.head_files.remove("specs/001-json-output/spec.md");
            },
        },
        Mutation {
            name: "specification-records-a-fifth-skill",
            assertion: "A5",
            what: "The specification records a Spec Kit skill outside the four allowed.",
            expect: "does not validate",
            base: Production,
            apply: |ev| {
                set(
                    &mut ev.contracts.specification,
                    "/provenance/spec_kit/skills_invoked/0",
                    json!("analyze"),
                )
            },
        },
        Mutation {
            name: "specification-is-superseded",
            assertion: "A5",
            what: "The specification is superseded, not approved.",
            expect: "not approved",
            base: Production,
            apply: |ev| {
                set(
                    &mut ev.contracts.specification,
                    "/metadata/status",
                    json!("superseded"),
                )
            },
        },
        // ---- A6 ------------------------------------------------------------------------------
        Mutation {
            name: "no-task-graph",
            assertion: "A6",
            what: "The run left no task graph.",
            expect: "no task graph",
            base: Production,
            apply: |ev| ev.contracts.task_dag = None,
        },
        Mutation {
            name: "an-acceptance-scenario-has-no-task",
            assertion: "A6",
            what: "The task that covers AS-004 is gone.",
            expect: "covered by no task",
            base: Production,
            apply: |ev| {
                if let Some(dag) = ev.contracts.task_dag.as_mut() {
                    if let Some(tasks) = dag["tasks"].as_array_mut() {
                        tasks.retain(|t| t["task_id"] != "cover-unreadable-file-error");
                    }
                    dag["critical_path"] =
                        json!(["add-json-output-formatter", "document-json-flag"]);
                }
                rehash_dag(ev);
            },
        },
        Mutation {
            name: "the-branch-changes-a-path-no-task-owns",
            assertion: "A6",
            what: "The branch changes Cargo.toml, which no task owns.",
            expect: "no task owns",
            base: Production,
            apply: |ev| ev.github.changed_paths.push("Cargo.toml".to_owned()),
        },
        Mutation {
            name: "the-task-graph-has-a-cycle",
            assertion: "A6",
            what: "The first task depends on the last one, which depends on the first.",
            expect: "form a cycle",
            base: Production,
            apply: |ev| {
                if let Some(dag) = ev.contracts.task_dag.as_mut() {
                    dag["tasks"][0]["depends_on"] = json!(["document-json-flag"]);
                }
                rehash_dag(ev);
            },
        },
        Mutation {
            name: "the-plan-cites-another-specification",
            assertion: "A6",
            what: "The plan cites a specification hash that differs from the stored specification.",
            expect: "the plan cites the specification",
            base: Production,
            apply: |ev| {
                set(
                    &mut ev.contracts.task_dag,
                    "/metadata/spec_ref/sha256",
                    json!(canned::sha(b"another spec")),
                );
                rehash_dag(ev);
            },
        },
        Mutation {
            name: "a-task-depends-on-a-task-that-does-not-exist",
            assertion: "A6",
            what: "A task depends on an id that is not in the plan.",
            expect: "which is not a task of the plan",
            base: Production,
            apply: |ev| {
                if let Some(dag) = ev.contracts.task_dag.as_mut() {
                    dag["tasks"][1]["depends_on"] = json!(["ghost-task"]);
                }
                rehash_dag(ev);
            },
        },
        Mutation {
            name: "two-tasks-own-the-same-file",
            assertion: "A6",
            what: "Two tasks both own README.md.",
            expect: "is owned by both",
            base: Production,
            apply: |ev| {
                if let Some(dag) = ev.contracts.task_dag.as_mut() {
                    dag["tasks"][1]["owned_files"] = json!(["tests/errors.rs", "README.md"]);
                }
                rehash_dag(ev);
            },
        },
        // ---- A7 ------------------------------------------------------------------------------
        Mutation {
            name: "no-gate-reports",
            assertion: "A7",
            what: "The run left no gate report.",
            expect: "no gate report",
            base: Production,
            apply: |ev| ev.contracts.gate_reports.clear(),
        },
        Mutation {
            name: "a-passed-report-with-a-failing-command",
            assertion: "A7",
            what: "A PASSED report has a command that exited with code 1.",
            expect: "does not validate",
            base: Production,
            apply: |ev| gate_mut(ev, "build-and-unit-tests")["commands"][1]["exit_code"] = json!(1),
        },
        Mutation {
            name: "a-gate-report-from-a-fake-in-production",
            assertion: "A7",
            what: "A production gate report says its environment was a fake.",
            expect: "does not validate",
            base: Production,
            apply: |ev| {
                gate_mut(ev, "build-and-unit-tests")["environment"]["fidelity"] = json!("fake")
            },
        },
        Mutation {
            name: "the-image-is-not-pinned-by-digest",
            assertion: "A7",
            what: "The sandbox image of a report is a tag, not a digest.",
            expect: "does not validate",
            base: Production,
            apply: |ev| {
                gate_mut(ev, "build-and-unit-tests")["environment"]["sandbox"]["image_digest"] =
                    json!("rust:latest")
            },
        },
        Mutation {
            name: "a-decision-document-that-names-no-cause",
            assertion: "A7",
            what: "The engine's document for a gate that could not run says no cause.",
            expect: "names no cause",
            base: Production,
            apply: |ev| {
                let stage_run_id = ev.contracts.gate_reports[0].stage_run_id.clone();
                ev.contracts
                    .gate_reports
                    .push(crate::evidence::GateReportRecord {
                        report: json!({
                            "schema_version": 1,
                            "kind": "gate-decision",
                            "outcome": "BLOCKED",
                            "job_id": "00000000-0000-4000-8000-000000000001",
                            "stage_run_id": stage_run_id,
                            "stage": "SPECIFICATION",
                            "cause": "",
                            "recorded_at": "2026-11-15T00:00:00Z",
                            "details": {"gate_could_not_run": true}
                        }),
                        stage_run_id,
                    });
            },
        },
        // ---- A8 ------------------------------------------------------------------------------
        Mutation {
            name: "specification-left-in-portuguese",
            assertion: "A8",
            what: "The specification of a Portuguese request is still Portuguese.",
            expect: "text-not-english",
            base: ProductionPortuguese,
            apply: |ev| doc_mut(ev, "specification").body = PORTUGUESE.to_owned(),
        },
        Mutation {
            name: "pull-request-left-in-portuguese",
            assertion: "A8",
            what: "The pull request of a Portuguese request is still Portuguese.",
            expect: "text-not-english",
            base: ProductionPortuguese,
            apply: |ev| doc_mut(ev, "pull_request").body = PORTUGUESE.to_owned(),
        },
        Mutation {
            name: "documentation-left-in-portuguese",
            assertion: "A8",
            what: "The README of a Portuguese request is still Portuguese.",
            expect: "text-not-english",
            base: ProductionPortuguese,
            apply: |ev| {
                if let Some(doc) = ev.documents.iter_mut().find(|d| d.kind == "documentation") {
                    doc.body = PORTUGUESE.to_owned();
                }
            },
        },
        Mutation {
            name: "title-with-a-machine-prefix",
            assertion: "A8",
            what: "The pull request title starts with an identifier chain.",
            expect: "title-",
            base: Production,
            apply: |ev| {
                doc_mut(ev, "pull_request").title =
                    "SF-FEAT-031 | Add a JSON output option".to_owned()
            },
        },
        Mutation {
            name: "a-task-lacks-its-verification-section",
            assertion: "A8",
            what: "A task has no Verification section.",
            expect: "task-missing-section",
            base: Production,
            apply: |ev| {
                if let Some(task) = ev.documents.iter_mut().find(|d| d.kind == "task")
                    && let Some(at) = task.body.find("## Verification")
                {
                    task.body.truncate(at);
                }
            },
        },
        Mutation {
            name: "no-pull-request-text-to-check",
            assertion: "A8",
            what: "The pull request text is missing from the evidence.",
            expect: "no pull_request",
            base: Production,
            apply: |ev| ev.documents.retain(|d| d.kind != "pull_request"),
        },
        // ---- A9 ------------------------------------------------------------------------------
        Mutation {
            name: "the-pull-request-was-merged",
            assertion: "A9",
            what: "The pull request is merged.",
            expect: "was merged",
            base: Production,
            apply: |ev| ev.github.pull_requests[0].merged = true,
        },
        Mutation {
            name: "the-base-branch-moved",
            assertion: "A9",
            what: "The tip of the base branch changed during the job.",
            expect: "the base branch moved",
            base: Production,
            apply: |ev| ev.github.base_sha_after = canned::sha_hex40("moved"),
        },
        Mutation {
            name: "the-requester-approved-their-own-request",
            assertion: "A9",
            // With the solo mode on (ADR 0022) the requester may approve their own request, but
            // then the engine records their judgment in the ledger too. An audit record that names
            // the requester over a ledger judgment of someone else is a forged approval either way.
            what: "The approval is recorded for the requester, over a ledger that holds another person's judgment.",
            expect: "does not hold the approver's judgment",
            base: Production,
            apply: |ev| {
                let requester = ev.job.requester.clone();
                for record in ev
                    .audit
                    .iter_mut()
                    .filter(|r| r.action == "approval_granted_or_rejected.granted")
                {
                    record.actor.clone_from(&requester);
                }
            },
        },
        Mutation {
            name: "the-requester-approved-their-own-request-of-medium-risk",
            assertion: "A9",
            // With the solo mode on (ADR 0022) the requester may approve their own request, but
            // then the engine records their judgment in the ledger too. An audit record that names
            // the requester over a ledger judgment of someone else is a forged approval either way.
            what: "The approval is recorded for the requester, and the job's risk is medium, over a ledger that holds another person's judgment.",
            expect: "does not hold the approver's judgment",
            base: Production,
            apply: |ev| {
                let requester = ev.job.requester.clone();
                ev.facts.insert("risk_tier".to_owned(), json!("medium"));
                for record in ev
                    .audit
                    .iter_mut()
                    .filter(|r| r.action == "approval_granted_or_rejected.granted")
                {
                    record.actor.clone_from(&requester);
                }
            },
        },
        Mutation {
            name: "a-service-account-approved",
            assertion: "A9",
            what: "The approval is recorded for a service account, not a person.",
            expect: "not a person",
            base: Production,
            apply: |ev| {
                for record in ev
                    .audit
                    .iter_mut()
                    .filter(|r| r.action == "approval_granted_or_rejected.granted")
                {
                    record.actor = format!("service:{}", canned::uid(6, 9));
                }
            },
        },
        Mutation {
            name: "the-approver-did-not-hold-the-approver-role",
            assertion: "A9",
            what: "The ledger records the approval judgment under the requester role.",
            expect: "with the approver role",
            base: Production,
            apply: |ev| {
                let index = ledger_index(ev, "APPROVAL");
                ev.ledger[index]["evidence"][0]["attestor"]["role"] = json!("requester");
                reseal(ev);
            },
        },
        Mutation {
            name: "the-approval-judgment-is-by-someone-else",
            assertion: "A9",
            what: "The ledger judgment is by a different person than the audit record names.",
            expect: "with the approver role",
            base: Production,
            apply: |ev| {
                let index = ledger_index(ev, "APPROVAL");
                ev.ledger[index]["evidence"][0]["attestor"]["principal_id"] =
                    json!(canned::uid(6, 77));
                reseal(ev);
            },
        },
        Mutation {
            name: "no-approval-record",
            assertion: "A9",
            what: "No approval is recorded in the audit stream.",
            expect: "holds 0 approval records",
            base: Production,
            apply: |ev| {
                ev.audit
                    .retain(|r| r.action != "approval_granted_or_rejected.granted")
            },
        },
        Mutation {
            name: "the-job-never-waited-for-a-person",
            assertion: "A9",
            what: "The approval stage never waited.",
            expect: "never waited",
            base: Production,
            apply: |ev| {
                let approval = run_id(ev, "APPROVAL");
                ev.timeline
                    .retain(|e| !(e.subject_id == approval && e.to == "WAITING_FOR_HUMAN"));
            },
        },
        Mutation {
            name: "the-job-completed-before-the-approval",
            assertion: "A9",
            what: "The job is shown completing before the approval passed.",
            expect: "not after the approval",
            base: Production,
            apply: |ev| {
                let approval = run_id(ev, "APPROVAL");
                let approved = ev
                    .timeline
                    .iter()
                    .find(|e| e.subject_id == approval && e.to == "PASSED")
                    .map(|e| e.seq)
                    .expect("approval passed");
                for entry in ev
                    .timeline
                    .iter_mut()
                    .filter(|e| e.subject == "job" && e.to == "COMPLETED")
                {
                    entry.seq = approved - 1;
                }
            },
        },
        // ---- A10 -----------------------------------------------------------------------------
        Mutation {
            name: "the-factory-called-merge",
            assertion: "A10",
            what: "The factory sent a merge request to GitHub.",
            expect: "which merges",
            base: Production,
            apply: |ev| requests_push(ev, "PUT", "/repos/example-org/word-count/pulls/7/merge"),
        },
        Mutation {
            name: "the-factory-enabled-auto-merge",
            assertion: "A10",
            what: "The factory enabled auto-merge.",
            expect: "which merges",
            base: Production,
            apply: |ev| {
                requests_push(
                    ev,
                    "PUT",
                    "/repos/example-org/word-count/pulls/7/auto_merge",
                )
            },
        },
        Mutation {
            name: "the-factory-created-a-deployment",
            assertion: "A10",
            what: "The factory created a deployment.",
            expect: "deploys or releases",
            base: Production,
            apply: |ev| requests_push(ev, "POST", "/repos/example-org/word-count/deployments"),
        },
        Mutation {
            name: "the-factory-wrote-to-the-base-branch",
            assertion: "A10",
            what: "The factory moved the base branch.",
            expect: "wrote to the base branch",
            base: Production,
            apply: |ev| {
                requests_push(
                    ev,
                    "PATCH",
                    "/repos/example-org/word-count/git/refs/heads/main",
                )
            },
        },
        Mutation {
            name: "a-token-holds-a-forbidden-permission",
            assertion: "A10",
            what: "A token holds the workflows permission.",
            expect: "forbidden permission workflows",
            base: Production,
            apply: |ev| {
                ev.github.tokens[0]
                    .permissions
                    .insert("workflows".to_owned(), "read".to_owned());
            },
        },
        Mutation {
            name: "a-token-holds-administration-write",
            assertion: "A10",
            what: "A token holds administration above the read the owner allowed on 2026-11-12.",
            expect: "administration: write, above the read the policy allows",
            base: Production,
            apply: |ev| {
                ev.github.tokens[0]
                    .permissions
                    .insert("administration".to_owned(), "write".to_owned());
            },
        },
        Mutation {
            name: "a-token-reaches-two-repositories",
            assertion: "A10",
            what: "A token is not narrowed to one repository.",
            expect: "must be exactly one",
            base: Production,
            apply: |ev| {
                ev.github.tokens[0]
                    .repositories
                    .push("example-org/other".to_owned())
            },
        },
        Mutation {
            name: "the-head-branch-is-the-base-branch-name",
            assertion: "A10",
            what: "The pull request head branch is not under factory/.",
            expect: "not under factory/",
            base: Production,
            apply: |ev| ev.github.pull_requests[0].head_branch = "main".to_owned(),
        },
        Mutation {
            name: "the-base-branch-needs-no-review",
            assertion: "A10",
            what: "The protection of the base branch needs no approving review.",
            expect: "a review",
            base: Production,
            apply: |ev| {
                if let Some(p) = ev.github.protection.as_mut() {
                    p.required_approvals = 0;
                }
            },
        },
        Mutation {
            name: "the-app-may-bypass-the-protection",
            assertion: "A10",
            what: "The factory's App is on the bypass list.",
            expect: "bypass",
            base: Production,
            apply: |ev| {
                if let Some(p) = ev.github.protection.as_mut() {
                    p.app_may_bypass = true;
                }
            },
        },
        Mutation {
            name: "the-protection-was-not-read",
            assertion: "A10",
            what: "The protection of the base branch is unknown.",
            expect: "was not read",
            base: Production,
            apply: |ev| ev.github.protection = None,
        },
        Mutation {
            name: "no-token-is-recorded",
            assertion: "A10",
            what: "No installation token is recorded.",
            expect: "no installation token",
            base: Production,
            apply: |ev| ev.github.tokens.clear(),
        },
        // ---- A11 -----------------------------------------------------------------------------
        Mutation {
            name: "an-attempt-has-no-span",
            assertion: "A11",
            what: "The span of one attempt is missing.",
            expect: "has 0 spans",
            base: Production,
            apply: |ev| {
                if let Some(at) = ev
                    .telemetry
                    .spans
                    .iter()
                    .position(|s| s.name == "factory.attempt")
                {
                    ev.telemetry.spans.remove(at);
                }
            },
        },
        Mutation {
            name: "an-attempt-span-hangs-under-the-wrong-parent",
            assertion: "A11",
            what: "An attempt span has no parent.",
            expect: "which is not a stage run span of the",
            base: Production,
            apply: |ev| {
                if let Some(span) = ev
                    .telemetry
                    .spans
                    .iter_mut()
                    .find(|s| s.name == "factory.attempt")
                {
                    span.parent_id = None;
                }
            },
        },
        Mutation {
            name: "a-log-line-has-another-correlation-id",
            assertion: "A11",
            what: "A log line carries another job's correlation id.",
            expect: "carries the correlation id",
            base: Production,
            apply: |ev| {
                if let Some(line) = ev
                    .telemetry
                    .correlated
                    .iter_mut()
                    .find(|c| c.source == "log")
                {
                    line.correlation_id = Some("cor-ffffffffffffffff".to_owned());
                }
            },
        },
        Mutation {
            name: "an-audit-event-has-no-correlation-id",
            assertion: "A11",
            what: "An audit event carries no correlation id.",
            expect: "audit event",
            base: Production,
            apply: |ev| ev.audit[0].correlation_id = None,
        },
        Mutation {
            name: "no-log-line-was-captured",
            assertion: "A11",
            what: "The harness captured no log line.",
            expect: "no log line",
            base: Production,
            apply: |ev| {
                ev.telemetry
                    .correlated
                    .retain(|c: &Correlated| c.source != "log")
            },
        },
        // ---- A12 -----------------------------------------------------------------------------
        Mutation {
            name: "no-documentation-gate-report",
            assertion: "A12",
            what: "The run left no documentation gate report.",
            expect: "no documentation gate report",
            base: Production,
            apply: |ev| {
                ev.contracts.gate_reports.retain(|r| {
                    r.report
                        .pointer("/metadata/gate_id")
                        .and_then(Value::as_str)
                        != Some("documentation-gate")
                })
            },
        },
        Mutation {
            name: "the-link-check-did-not-run",
            assertion: "A12",
            what: "The documentation gate is PASSED but ran no link check.",
            expect: "link check did not run",
            base: Production,
            apply: |ev| {
                gate_mut(ev, "documentation-gate")["commands"]
                    .as_array_mut()
                    .expect("commands")
                    .remove(0);
            },
        },
        Mutation {
            name: "no-snippet-was-executed",
            assertion: "A12",
            what: "The documentation gate is PASSED but executed no snippet.",
            expect: "no snippet was executed",
            base: Production,
            apply: |ev| {
                gate_mut(ev, "documentation-gate")["commands"]
                    .as_array_mut()
                    .expect("commands")
                    .remove(1);
            },
        },
        Mutation {
            name: "the-snippet-command-was-not-executed",
            assertion: "A12",
            what: "The snippet command is recorded with executed set to false.",
            expect: "no snippet was executed",
            base: Production,
            apply: |ev| {
                gate_mut(ev, "documentation-gate")["commands"][1]["executed"] = json!(false)
            },
        },
        Mutation {
            name: "not-applicable-with-no-recorded-rule",
            assertion: "A12",
            what: "The documentation gate is NOT_APPLICABLE and records no rule.",
            expect: "no recorded rule",
            base: Production,
            apply: |ev| {
                let report = gate_mut(ev, "documentation-gate");
                report["outcome"] = json!("NOT_APPLICABLE");
                report["not_applicable_reason"] = json!("");
            },
        },
        Mutation {
            name: "the-documentation-gate-failed",
            assertion: "A12",
            what: "The documentation gate outcome is FAILED.",
            expect: "not PASSED",
            base: Production,
            apply: |ev| gate_mut(ev, "documentation-gate")["outcome"] = json!("FAILED"),
        },
        // ---- A13 -----------------------------------------------------------------------------
        Mutation {
            name: "delivery-started-after-a-failing-check",
            assertion: "A13",
            what: "The build gate FAILED and DELIVERY started anyway.",
            expect: "DELIVERY started although",
            base: Production,
            apply: |ev| gate_mut(ev, "build-and-unit-tests")["outcome"] = json!("FAILED"),
        },
        Mutation {
            name: "a-pull-request-exists-after-a-failing-check",
            assertion: "A13",
            what: "The build gate FAILED, DELIVERY did not start, and a pull request exists.",
            expect: "a pull request exists although",
            base: Production,
            apply: |ev| {
                gate_mut(ev, "build-and-unit-tests")["outcome"] = json!("FAILED");
                let delivery = run_mut(ev, "DELIVERY");
                delivery.status = "PENDING".to_owned();
                delivery.attempts.clear();
            },
        },
        Mutation {
            name: "delivery-started-with-a-stage-waiting-for-a-person",
            assertion: "A13",
            what: "REVIEW waits for a person and DELIVERY started.",
            expect: "the newest REVIEW run is WAITING_FOR_HUMAN",
            base: Production,
            apply: |ev| run_mut(ev, "REVIEW").status = "WAITING_FOR_HUMAN".to_owned(),
        },
        // ---- A14 -----------------------------------------------------------------------------
        Mutation {
            name: "a-fake-recorded-a-ledger-entry-in-production",
            assertion: "A14",
            what: "A ledger entry was recorded by a fake in a production job.",
            expect: "recorded by the fake",
            base: Production,
            apply: |ev| {
                // The domain contract refuses this entry in a production job, so the chain is not
                // re-sealed: A4 fails for the same fact, and A14 must fail on its own account.
                ev.ledger[0]["metadata"]["recorded_by"]["fidelity"] = json!("fake");
            },
        },
        Mutation {
            name: "the-manifest-lists-a-fake-adapter-in-production",
            assertion: "A14",
            what: "The manifest lists a fake adapter in a production job.",
            expect: "lists the fake adapter",
            base: Production,
            apply: |ev| {
                set(
                    &mut ev.contracts.evidence_manifest,
                    "/adapters/1/fidelity",
                    json!("fake"),
                )
            },
        },
        Mutation {
            name: "a-fake-claims-an-assurance-level-in-test-mode",
            assertion: "A14",
            what: "In test mode a fake entry claims an assurance level.",
            expect: "still claims an assurance level",
            base: TestMode,
            apply: |ev| ev.ledger[0]["claim"]["assurance_level"] = json!("IMPLEMENTED"),
        },
        Mutation {
            name: "the-manifest-attains-a-level-on-a-fake-entry",
            assertion: "A14",
            what: "In test mode the manifest attains a level on an entry a fake recorded.",
            expect: "attains",
            base: TestMode,
            apply: |ev| {
                let entry = ev.ledger[0]["metadata"]["entry_id"].clone();
                set(
                    &mut ev.contracts.evidence_manifest,
                    "/assurance/attained",
                    json!([{ "level": "SPECIFIED", "ledger_entry_id": entry }]),
                );
            },
        },
    ]
}

/// What one mutation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationResult {
    /// The mutation name.
    pub name: &'static str,
    /// The target assertion.
    pub assertion: &'static str,
    /// Whether the target assertion failed with a reason that mentions what was expected.
    pub detected: bool,
    /// The reason the target gave.
    pub reason: String,
    /// The other assertions that failed on the same evidence.
    pub also_failed: Vec<String>,
}

/// Applies one mutation to a fresh honest evidence set and judges it.
#[must_use]
pub fn run_one(mutation: &Mutation, env: &Env) -> MutationResult {
    let honest = canned::honest(env, mutation.base.options());
    let mut mutated = honest.clone();
    (mutation.apply)(&mut mutated);
    let verdicts = assertions::run_all(&mutated, env);
    let target = verdicts.iter().find(|v| v.id == mutation.assertion);
    let (detected, reason) = match target {
        Some(v) if !v.pass => (v.reason.contains(mutation.expect), v.reason.clone()),
        Some(v) => (false, format!("the assertion still passed: {}", v.reason)),
        None => (false, "there is no such assertion".to_owned()),
    };
    let unchanged = mutated == honest;
    MutationResult {
        name: mutation.name,
        assertion: mutation.assertion,
        detected: detected && !unchanged,
        reason: if unchanged {
            "the mutation changed nothing".to_owned()
        } else {
            reason
        },
        also_failed: verdicts
            .iter()
            .filter(|v| !v.pass && v.id != mutation.assertion)
            .map(|v| v.id.clone())
            .collect(),
    }
}

/// The whole self-test: the honest sets pass, and every mutation is detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTest {
    /// Problems with the honest sets, one line each. Empty when all three pass all assertions.
    pub honest_problems: Vec<String>,
    /// The result of every mutation.
    pub results: Vec<MutationResult>,
    /// Assertions that no mutation targets. Must be empty.
    pub uncovered: Vec<String>,
}

impl SelfTest {
    /// True when nothing is wrong.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.honest_problems.is_empty()
            && self.uncovered.is_empty()
            && self.results.iter().all(|r| r.detected)
    }
}

/// Runs the self-test.
#[must_use]
pub fn self_test(env: &Env) -> SelfTest {
    let mut honest_problems = Vec::new();
    for options in [
        Options::e1_production(),
        Options::e2_production(),
        Options::e1_test_mode(),
    ] {
        let evidence = canned::honest(env, options);
        for verdict in assertions::run_all(&evidence, env) {
            if !verdict.pass {
                honest_problems.push(format!(
                    "{} {} ({}): {}",
                    options.scenario,
                    options.mode.as_str(),
                    verdict.id,
                    verdict.reason
                ));
            }
        }
        if evidence.mode == Mode::Production && evidence.wiring == "composed" {
            honest_problems.push("a canned set claims to be composed".to_owned());
        }
    }
    let mutations = all();
    let results: Vec<MutationResult> = mutations.iter().map(|m| run_one(m, env)).collect();
    let uncovered = assertions::all()
        .iter()
        .filter(|check| !mutations.iter().any(|m| m.assertion == check.id))
        .map(|check| check.id.to_owned())
        .collect();
    SelfTest {
        honest_problems,
        results,
        uncovered,
    }
}
