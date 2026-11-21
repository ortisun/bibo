//! Assertions about the contract documents and the ledger: A4, A5, A6, A7, A12 and A14.
//!
//! Each document is read back through the typed contract of `factory-domain`, so a document is
//! judged by the same rules that judged it when the factory stored it.

use std::collections::BTreeSet;

use factory_domain::contracts::{
    Contract, EvidenceLedgerEntry, EvidenceManifest, GateReport, SpecificationContract, TaskDag,
};
use factory_domain::ledger::{head_of, verify_chain};
use serde_json::Value;

use crate::check::{Env, Verdict};
use crate::evidence::{Mode, RunEvidence};

use super::support::{PASSED, glob_matches, runs_of, text_at};

/// The ledger of the evidence, read back through the typed contract.
///
/// # Errors
/// A sentence naming the entry that does not validate.
pub fn typed_ledger(ev: &RunEvidence) -> Result<Vec<EvidenceLedgerEntry>, String> {
    ev.ledger
        .iter()
        .enumerate()
        .map(|(position, value)| {
            EvidenceLedgerEntry::from_json_value(value.clone()).map_err(|error| {
                format!("ledger entry {} does not validate: {error}", position + 1)
            })
        })
        .collect()
}

fn array_len(value: &Value, pointer: &str) -> usize {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
}

/// A4: the evidence manifest validates, `limitations` is not empty, every adapter is real, the
/// ledger chain verifies, and the head hash in the pull request body equals the stored head.
///
/// In test mode "every adapter is real" becomes "the manifest says test mode, and no adapter that
/// the ledger records as a fake is called real". A fake is allowed there only because it is
/// labelled.
#[must_use]
pub fn a4(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "A4";
    let Some(manifest) = &ev.contracts.evidence_manifest else {
        return Verdict::fail(ID, "the run left no evidence manifest");
    };
    if let Err(error) = EvidenceManifest::from_json_value(manifest.clone()) {
        return Verdict::fail(
            ID,
            format!("the evidence manifest does not validate: {error}"),
        );
    }
    if array_len(manifest, "/limitations") == 0 {
        return Verdict::fail(
            ID,
            "the evidence manifest lists no limitation, and an honest run always has some",
        );
    }
    let adapters = manifest
        .pointer("/adapters")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if adapters.is_empty() {
        return Verdict::fail(ID, "the evidence manifest lists no adapter");
    }
    match ev.mode {
        Mode::Production => {
            if let Some(fake) = adapters
                .iter()
                .find(|adapter| text_at(adapter, "/fidelity") != Some("real"))
            {
                return Verdict::fail(
                    ID,
                    format!(
                        "adapter {} is not real in a production job",
                        text_at(fake, "/name").unwrap_or("(unnamed)")
                    ),
                );
            }
        }
        Mode::Test => {
            if text_at(manifest, "/metadata/execution_mode") != Some("test") {
                return Verdict::fail(
                    ID,
                    "a test-mode job has a manifest that does not say test mode",
                );
            }
        }
    }
    let entries = match typed_ledger(ev) {
        Ok(entries) => entries,
        Err(reason) => return Verdict::fail(ID, reason),
    };
    if entries.is_empty() {
        return Verdict::fail(ID, "the ledger is empty");
    }
    if let Err(error) = verify_chain(&entries) {
        return Verdict::fail(ID, format!("the ledger chain does not verify: {error}"));
    }
    if head_of(&entries).is_none() {
        return Verdict::fail(ID, "the ledger has no head");
    }
    // The manifest is written when the pull request opens, so its head is the entry at the
    // sequence it names. Entries after that one (the approval) may follow.
    let Some(head_sequence) = manifest
        .pointer("/ledger/head_sequence")
        .and_then(Value::as_u64)
    else {
        return Verdict::fail(ID, "the manifest names no head sequence");
    };
    let Some(stored) = usize::try_from(head_sequence)
        .ok()
        .and_then(|n| n.checked_sub(1))
        .and_then(|index| entries.get(index))
    else {
        return Verdict::fail(
            ID,
            format!(
                "the manifest names head sequence {head_sequence}, which the stored ledger does not reach"
            ),
        );
    };
    let stored_head = stored.entry_hash.as_str();
    if text_at(manifest, "/ledger/head_hash") != Some(stored_head) {
        return Verdict::fail(
            ID,
            format!(
                "the manifest cites the head {}, but the stored entry {head_sequence} hashes to {stored_head}",
                text_at(manifest, "/ledger/head_hash").unwrap_or("(none)")
            ),
        );
    }
    if manifest
        .pointer("/ledger/entry_count")
        .and_then(Value::as_u64)
        != Some(head_sequence)
    {
        return Verdict::fail(
            ID,
            "the manifest's entry count differs from its head sequence",
        );
    }
    let [pr] = ev.github.pull_requests.as_slice() else {
        return Verdict::fail(
            ID,
            "there is no single pull request whose body could carry the head hash",
        );
    };
    // The body writes a hash as its hexadecimal digits, without the `sha256:` prefix the ledger
    // stores (`crates/workflow/src/stages/delivery/pr.rs`). The digits are the digest, so they
    // are what is compared; the prefixed form is accepted too.
    let head_digits = stored_head.strip_prefix("sha256:").unwrap_or(stored_head);
    if head_digits.len() != 64 || !pr.body.contains(head_digits) {
        return Verdict::fail(
            ID,
            format!(
                "the body of pull request #{} does not carry the stored head {stored_head}",
                pr.number
            ),
        );
    }
    for run in ev.stage_runs.iter().filter(|run| run.status == PASSED) {
        let has_entry = ev
            .ledger
            .iter()
            .any(|entry| text_at(entry, "/metadata/stage_run_id") == Some(run.id.as_str()));
        if !has_entry {
            return Verdict::fail(
                ID,
                format!(
                    "the {} run {} is PASSED but has no ledger entry",
                    run.kind, run.id
                ),
            );
        }
    }
    for (document, key, pointer) in [
        ("specification", "specification", "/specification/sha256"),
        ("plan", "task_dag", "/plan/sha256"),
    ] {
        if let (Some(stored), Some(cited)) = (
            ev.contracts.stored_hashes.get(key),
            text_at(manifest, pointer),
        ) && stored != cited
        {
            return Verdict::fail(
                ID,
                format!(
                    "the manifest cites {cited} for the {document}, but the stored bytes hash to {stored}"
                ),
            );
        }
    }
    Verdict::pass(
        ID,
        format!(
            "the manifest validates with {} limitation(s), the chain of {} entries verifies, and head {} is in the manifest and in pull request #{}",
            array_len(manifest, "/limitations"),
            entries.len(),
            stored_head,
            pr.number
        ),
    )
}

/// The Spec Kit skills a specification may record (`specification-contract.schema.json`).
pub const ALLOWED_SKILLS: [&str; 4] = ["constitution", "specify", "clarify", "checklist"];

/// A5: the specification contract validates, its artifact hashes match the files at the commit it
/// was frozen at (read from the job's store), a cited file that is also on the head branch matches
/// there too, and `skills_invoked` is a subset of the four allowed.
#[must_use]
pub fn a5(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "A5";
    let Some(spec) = &ev.contracts.specification else {
        return Verdict::fail(ID, "the run left no specification contract");
    };
    if let Err(error) = SpecificationContract::from_json_value(spec.clone()) {
        return Verdict::fail(
            ID,
            format!("the specification contract does not validate: {error}"),
        );
    }
    if text_at(spec, "/metadata/status") != Some("approved") {
        return Verdict::fail(
            ID,
            format!(
                "the specification is {}, not approved",
                text_at(spec, "/metadata/status").unwrap_or("(unknown)")
            ),
        );
    }
    let skills: Vec<&str> = spec
        .pointer("/provenance/spec_kit/skills_invoked")
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if let Some(extra) = skills.iter().find(|skill| !ALLOWED_SKILLS.contains(skill)) {
        return Verdict::fail(
            ID,
            format!(
                "the specification records the skill {extra}, which is not one of the four allowed"
            ),
        );
    }
    let artifacts = spec
        .pointer("/provenance/artifacts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if artifacts.is_empty() {
        return Verdict::fail(
            ID,
            "the specification cites no artifact, so nothing ties it to the branch",
        );
    }
    let commit = text_at(spec, "/metadata/commit_sha").unwrap_or("(none)");
    let mut on_head_branch = 0_usize;
    for artifact in &artifacts {
        let (Some(path), Some(hash)) = (text_at(artifact, "/path"), text_at(artifact, "/sha256"))
        else {
            return Verdict::fail(ID, "an artifact of the specification has no path or hash");
        };
        // The specification is bound to the commit it was frozen at, which the job's store holds.
        match ev.contracts.specification_files.get(path) {
            None => {
                return Verdict::fail(
                    ID,
                    format!(
                        "the specification cites {path}, which the job's store does not hold at its commit {commit}"
                    ),
                );
            }
            Some(stored) if stored != hash => {
                return Verdict::fail(
                    ID,
                    format!(
                        "the specification cites {hash} for {path}, but the file at its commit {commit} hashes to {stored}"
                    ),
                );
            }
            Some(_) => {}
        }
        // The head branch need not carry the specification (the code starts from the repository
        // map's commit, ADR 0025). When it does carry a cited file, the file must be the same.
        if let Some(on_branch) = ev.github.head_files.get(path) {
            if on_branch != hash {
                return Verdict::fail(
                    ID,
                    format!(
                        "the specification cites {hash} for {path}, but the file on the head branch hashes to {on_branch}"
                    ),
                );
            }
            on_head_branch += 1;
        }
    }
    Verdict::pass(
        ID,
        format!(
            "the specification validates, is approved, records {} allowed skill(s), and its {} artifact hash(es) match the files at its commit {commit} ({on_head_branch} of them also on the head branch)",
            skills.len(),
            artifacts.len()
        ),
    )
}

fn id_list(value: &Value, pointer: &str, key: &str) -> BTreeSet<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|item| text_at(item, key).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The structural checks of a task graph that a schema cannot make: unique task ids, no dependency
/// on a task that does not exist, no cycle, a critical path made of real tasks, and no file owned
/// by two tasks. Returns one sentence for each problem found.
///
/// The planner validator of `s1-stage-architecture-and-planning` is not merged yet, and the typed
/// task graph checks only the size and that each task owns something. When the planner validator
/// exists, it can replace this function.
#[must_use]
pub fn planner_problems(dag: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    let tasks = dag
        .pointer("/tasks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let ids: Vec<&str> = tasks
        .iter()
        .filter_map(|t| text_at(t, "/task_id"))
        .collect();
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    if unique.len() != ids.len() {
        problems.push("two tasks share one task id".to_owned());
    }
    // Dependencies and cycles, by repeatedly removing the tasks whose dependencies are all gone.
    let mut remaining: Vec<(&str, Vec<&str>)> = Vec::new();
    for task in &tasks {
        let id = text_at(task, "/task_id").unwrap_or_default();
        let deps: Vec<&str> = task
            .pointer("/depends_on")
            .and_then(Value::as_array)
            .map(|list| list.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        for dep in &deps {
            if !unique.contains(dep) {
                problems.push(format!(
                    "task {id} depends on {dep}, which is not a task of the plan"
                ));
            }
        }
        remaining.push((id, deps));
    }
    loop {
        let done: BTreeSet<&str> = unique
            .iter()
            .copied()
            .filter(|id| !remaining.iter().any(|(r, _)| r == id))
            .collect();
        let before = remaining.len();
        remaining.retain(|(_, deps)| !deps.iter().all(|d| done.contains(d) || !unique.contains(d)));
        if remaining.len() == before {
            break;
        }
    }
    if !remaining.is_empty() {
        let names: Vec<&str> = remaining.iter().map(|(id, _)| *id).collect();
        problems.push(format!(
            "the dependencies form a cycle through {}",
            names.join(", ")
        ));
    }
    if let Some(path) = dag.pointer("/critical_path").and_then(Value::as_array) {
        for id in path.iter().filter_map(Value::as_str) {
            if !unique.contains(id) {
                problems.push(format!(
                    "the critical path names {id}, which is not a task of the plan"
                ));
            }
        }
    }
    let mut owner: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for task in &tasks {
        let id = text_at(task, "/task_id").unwrap_or_default();
        if let Some(files) = task.pointer("/owned_files").and_then(Value::as_array) {
            for file in files.iter().filter_map(Value::as_str) {
                if let Some(first) = owner.insert(file, id)
                    && first != id
                {
                    problems.push(format!("{file} is owned by both {first} and {id}"));
                }
            }
        }
    }
    problems
}

/// A6: the task graph validates and passes the planner checks, every acceptance scenario is
/// covered, and the changed paths are inside the union of owned files. A page the documentation
/// stage wrote (`facts.documentation_paths`) is judged by that stage's scope gate instead.
#[must_use]
pub fn a6(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "A6";
    let (Some(dag), Some(spec)) = (&ev.contracts.task_dag, &ev.contracts.specification) else {
        return Verdict::fail(
            ID,
            "the run left no task graph or no specification to cover",
        );
    };
    if let Err(error) = TaskDag::from_json_value(dag.clone()) {
        return Verdict::fail(ID, format!("the task graph does not validate: {error}"));
    }
    if let Some(problem) = planner_problems(dag).first() {
        return Verdict::fail(
            ID,
            format!("the task graph fails the planner checks: {problem}"),
        );
    }
    if let (Some(stored), Some(cited)) = (
        ev.contracts.stored_hashes.get("specification"),
        text_at(dag, "/metadata/spec_ref/sha256"),
    ) && stored != cited
    {
        return Verdict::fail(
            ID,
            format!(
                "the plan cites the specification as {cited}, but the stored specification hashes to {stored}"
            ),
        );
    }
    let scenarios = id_list(spec, "/acceptance_scenarios", "/id");
    let mut covered: BTreeSet<String> = BTreeSet::new();
    let tasks = dag
        .pointer("/tasks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for task in &tasks {
        if let Some(ids) = task
            .pointer("/acceptance_mapping/acceptance_scenario_ids")
            .and_then(Value::as_array)
        {
            covered.extend(ids.iter().filter_map(Value::as_str).map(str::to_owned));
        }
    }
    if let Some(missing) = scenarios.difference(&covered).next() {
        return Verdict::fail(
            ID,
            format!("acceptance scenario {missing} is covered by no task"),
        );
    }
    if let Some(unknown) = covered.difference(&scenarios).next() {
        return Verdict::fail(
            ID,
            format!(
                "a task cites acceptance scenario {unknown}, which the specification does not have"
            ),
        );
    }
    let requirements = id_list(spec, "/requirements", "/id");
    let mut required_covered: BTreeSet<String> = BTreeSet::new();
    for task in &tasks {
        if let Some(ids) = task
            .pointer("/acceptance_mapping/requirement_ids")
            .and_then(Value::as_array)
        {
            required_covered.extend(ids.iter().filter_map(Value::as_str).map(str::to_owned));
        }
    }
    if let Some(missing) = requirements.difference(&required_covered).next() {
        return Verdict::fail(ID, format!("requirement {missing} is covered by no task"));
    }
    let mut owned: Vec<String> = Vec::new();
    for task in &tasks {
        if let Some(files) = task.pointer("/owned_files").and_then(Value::as_array) {
            owned.extend(files.iter().filter_map(Value::as_str).map(str::to_owned));
        }
    }
    if ev.github.changed_paths.is_empty() {
        return Verdict::fail(
            ID,
            "the branch changes no path, so ownership cannot be judged",
        );
    }
    // The pages the documentation stage wrote are judged by that stage's own scope gate against
    // the documentation plan (`documenting-scope`), not by the ownership of a task.
    let documented: BTreeSet<&str> = ev
        .facts
        .get("documentation_paths")
        .and_then(Value::as_array)
        .map(|paths| paths.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if let Some(stray) = ev.github.changed_paths.iter().find(|path| {
        !owned.iter().any(|pattern| glob_matches(pattern, path))
            && !documented.contains(path.as_str())
    }) {
        return Verdict::fail(
            ID,
            format!(
                "the branch changes {stray}, which no task owns and the documentation stage did not write"
            ),
        );
    }
    Verdict::pass(
        ID,
        format!(
            "the task graph validates, its {} task(s) cover all {} acceptance scenario(s) and {} requirement(s), and the {} changed path(s) are inside the owned files or among the {} page(s) the documentation stage wrote",
            tasks.len(),
            scenarios.len(),
            requirements.len(),
            ev.github.changed_paths.len(),
            documented.len()
        ),
    )
}

/// What is wrong with an engine decision document, or `None` when `report` is a valid one or is
/// not a decision document at all (it has no `kind`). The shape is `crates/workflow/src/engine/
/// decision.rs`: version 1, a known kind, an outcome, the stage run it is about, a non-empty cause
/// code and an object of details.
fn decision_document_problem(report: &Value, stage_run_id: &str) -> Option<String> {
    let kind = report.get("kind")?;
    let kind = kind.as_str().unwrap_or("");
    if !["gate-decision", "environment-block", "human-approval"].contains(&kind) {
        return Some(format!(
            "the decision document has an unknown kind `{kind}`"
        ));
    }
    let wrong = |what: &str| {
        Some(format!(
            "the {kind} decision document does not validate: {what}"
        ))
    };
    if report.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return wrong("its schema_version is not 1");
    }
    if !matches!(
        text_at(report, "/outcome"),
        Some("PASSED" | "FAILED" | "BLOCKED" | "NOT_APPLICABLE")
    ) {
        return wrong("its outcome is not a gate outcome");
    }
    if text_at(report, "/stage_run_id") != Some(stage_run_id) {
        return wrong("it names another stage run");
    }
    if text_at(report, "/cause").is_none_or(str::is_empty) {
        return wrong("it names no cause");
    }
    if !report.get("details").is_some_and(Value::is_object) {
        return wrong("its details are not an object");
    }
    None
}

/// A7: every gate report validates, every `PASSED` report has exit code 0 for all commands,
/// images are pinned by digest, and fidelity is real.
#[must_use]
pub fn a7(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "A7";
    if ev.contracts.gate_reports.is_empty() {
        return Verdict::fail(ID, "the run left no gate report");
    }
    for record in &ev.contracts.gate_reports {
        let report = &record.report;
        // The engine's own decision document stands where no gate produced a report (ADR 0014,
        // amendment 1): a gate that could not run, refused evidence, a person's approval. It has
        // its own shape, checked here, and none of the commands a gate report runs.
        if let Some(problem) = decision_document_problem(report, &record.stage_run_id) {
            return Verdict::fail(ID, problem);
        }
        if report.get("kind").is_some() {
            continue;
        }
        let name = text_at(report, "/metadata/gate_id").unwrap_or("(unnamed gate)");
        if let Err(error) = GateReport::from_json_value(report.clone()) {
            return Verdict::fail(
                ID,
                format!("the gate report {name} does not validate: {error}"),
            );
        }
        if text_at(report, "/outcome") == Some("PASSED") {
            let commands = report
                .pointer("/commands")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if commands.iter().any(|command| {
                command.pointer("/executed").and_then(Value::as_bool) != Some(true)
                    || command.pointer("/exit_code").and_then(Value::as_i64) != Some(0)
            }) {
                return Verdict::fail(
                    ID,
                    format!(
                        "the gate report {name} is PASSED, but a command did not run and exit with 0"
                    ),
                );
            }
        }
        if text_at(report, "/environment/executor_kind") == Some("sandbox_command") {
            let digest = text_at(report, "/environment/sandbox/image_digest").unwrap_or_default();
            let pinned = digest
                .strip_prefix("sha256:")
                .is_some_and(|hex| hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()));
            if !pinned {
                return Verdict::fail(
                    ID,
                    format!("the gate report {name} does not pin its image by digest"),
                );
            }
        }
        if ev.mode == Mode::Production && text_at(report, "/environment/fidelity") != Some("real") {
            return Verdict::fail(
                ID,
                format!("the gate report {name} was made by a fake in a production job"),
            );
        }
    }
    Verdict::pass(
        ID,
        format!(
            "all {} gate report(s) validate; every PASSED one ran all commands with exit code 0 in an image pinned by digest",
            ev.contracts.gate_reports.len()
        ),
    )
}

/// The gate id of the link check of the Documentation Quality Gate. The gate writes one report
/// for each check (`crates/workflow/src/gates/docs/check.rs`).
pub const LINK_CHECK: &str = factory_workflow::gates::docs::check::LINKS;
/// The gate id of the example (snippet) execution of the Documentation Quality Gate.
pub const SNIPPET_CHECK: &str = factory_workflow::gates::docs::check::EXAMPLES;
/// The stage whose run holds the reports of the Documentation Quality Gate.
pub const DOCS_STAGE: &str = "DOCUMENTATION_REVIEW";

/// The recorded rule of a `NOT_APPLICABLE` report: the justification of `not_applicable_reason`
/// (an object in `gate-report.schema.json`), or the text when an older report wrote a string.
fn recorded_rule(report: &Value) -> &str {
    let reason = report.get("not_applicable_reason");
    reason
        .and_then(|reason| reason.get("justification"))
        .and_then(Value::as_str)
        .or_else(|| reason.and_then(Value::as_str))
        .unwrap_or_default()
        .trim()
}

/// Whether a report ran at least one command, and every command it records ran and exited with 0.
fn every_command_ran(report: &Value) -> bool {
    report
        .pointer("/commands")
        .and_then(Value::as_array)
        .is_some_and(|commands| {
            !commands.is_empty()
                && commands.iter().all(|command| {
                    command.pointer("/executed").and_then(Value::as_bool) == Some(true)
                        && command.pointer("/exit_code").and_then(Value::as_i64) == Some(0)
                })
        })
}

/// What one check of the documentation gate says: a sentence for the pass, or the failure.
fn docs_check(
    report: Option<&Value>,
    gate: &str,
    what: &str,
    needs_commands: bool,
) -> Result<String, String> {
    let Some(report) = report else {
        return Err(format!(
            "the passed {DOCS_STAGE} run left no {gate} report, so the {what} cannot be judged"
        ));
    };
    match text_at(report, "/outcome") {
        Some("PASSED") if needs_commands && !every_command_ran(report) => Err(format!(
            "the {gate} report is PASSED, but no {what} ran with exit code 0"
        )),
        Some("PASSED") => Ok(format!("the {what} is PASSED")),
        Some("NOT_APPLICABLE") => {
            let rule = recorded_rule(report);
            if rule.is_empty() {
                Err(format!(
                    "the {gate} report is NOT_APPLICABLE with no recorded rule"
                ))
            } else {
                Ok(format!(
                    "the {what} is NOT_APPLICABLE by a recorded rule: {rule}"
                ))
            }
        }
        other => Err(format!(
            "the {gate} report is {}, not PASSED",
            other.unwrap_or("(none)")
        )),
    }
}

/// A12: the documentation gate report is `PASSED` with the link check and snippet execution
/// actually run. `NOT_APPLICABLE` only with a recorded rule.
///
/// The gate writes one report for each of its checks, so this reads the `docs-links` and
/// `docs-examples` reports of the passed `DOCUMENTATION_REVIEW` run (of its newest attempt). The
/// link check runs in the factory's process and records no command, so its `PASSED` is the run.
/// The example check runs each example as a command, so its `PASSED` needs at least one command,
/// each executed with exit code 0. Either may instead be `NOT_APPLICABLE` with a recorded rule
/// (documentation policy 9.8: the documents contain no links, no executable example).
#[must_use]
pub fn a12(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "A12";
    let Some(run) = ev
        .stage_runs
        .iter()
        .rev()
        .find(|run| run.kind == DOCS_STAGE && run.status == PASSED)
    else {
        return Verdict::fail(
            ID,
            format!("no {DOCS_STAGE} run passed, so there is no documentation gate report"),
        );
    };
    let reports: Vec<&Value> = ev
        .contracts
        .gate_reports
        .iter()
        .filter(|record| record.stage_run_id == run.id)
        .map(|record| &record.report)
        .collect();
    if !reports.iter().any(|report| {
        text_at(report, "/metadata/gate_id").is_some_and(|id| id.starts_with("docs-"))
    }) {
        return Verdict::fail(
            ID,
            format!("the passed {DOCS_STAGE} run left no documentation gate report"),
        );
    }
    // The report of the newest attempt: an attempt that ran again wrote its reports again.
    let attempt = run.attempts.last().map(|attempt| attempt.id.as_str());
    let newest = |gate: &str| -> Option<&Value> {
        let of_gate: Vec<&Value> = reports
            .iter()
            .copied()
            .filter(|report| text_at(report, "/metadata/gate_id") == Some(gate))
            .collect();
        of_gate
            .iter()
            .copied()
            .rfind(|report| attempt.is_some() && text_at(report, "/metadata/attempt_id") == attempt)
            .or_else(|| of_gate.last().copied())
    };
    let links = match docs_check(newest(LINK_CHECK), LINK_CHECK, "link check", false) {
        Ok(sentence) => sentence,
        Err(reason) => return Verdict::fail(ID, reason),
    };
    let snippets = match docs_check(
        newest(SNIPPET_CHECK),
        SNIPPET_CHECK,
        "snippet execution",
        true,
    ) {
        Ok(sentence) => sentence,
        Err(reason) => return Verdict::fail(ID, reason),
    };
    Verdict::pass(
        ID,
        format!("in the passed {DOCS_STAGE} run, {links}, and {snippets}"),
    )
}

/// A14: the ledger holds no entry with fidelity `fake` in a production-mode job, and no `fake`
/// adapter appears in the manifest.
///
/// In test mode the rule that matters is the one for labelled fakes: a fake entry may exist, but it
/// may not claim an assurance level, and the manifest may not attain a level on a fake entry.
#[must_use]
pub fn a14(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "A14";
    let fake_entries: Vec<&Value> = ev
        .ledger
        .iter()
        .filter(|entry| text_at(entry, "/metadata/recorded_by/fidelity") == Some("fake"))
        .collect();
    let manifest_fakes: Vec<String> = ev
        .contracts
        .evidence_manifest
        .as_ref()
        .and_then(|manifest| {
            manifest
                .pointer("/adapters")
                .and_then(Value::as_array)
                .cloned()
        })
        .unwrap_or_default()
        .iter()
        .filter(|adapter| text_at(adapter, "/fidelity") == Some("fake"))
        .map(|adapter| text_at(adapter, "/name").unwrap_or("(unnamed)").to_owned())
        .collect();
    match ev.mode {
        Mode::Production => {
            if let Some(entry) = fake_entries.first() {
                return Verdict::fail(
                    ID,
                    format!(
                        "ledger entry {} was recorded by the fake {} in a production job",
                        entry
                            .pointer("/metadata/sequence")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                        text_at(entry, "/metadata/recorded_by/component").unwrap_or("(unnamed)")
                    ),
                );
            }
            if let Some(name) = manifest_fakes.first() {
                return Verdict::fail(
                    ID,
                    format!("the manifest lists the fake adapter {name} in a production job"),
                );
            }
            Verdict::pass(
                ID,
                format!(
                    "none of the {} ledger entries and no manifest adapter is a fake",
                    ev.ledger.len()
                ),
            )
        }
        Mode::Test => {
            let fake_ids: BTreeSet<&str> = fake_entries
                .iter()
                .filter_map(|entry| text_at(entry, "/metadata/entry_id"))
                .collect();
            for entry in &fake_entries {
                if entry.pointer("/claim/assurance_level").is_some() {
                    return Verdict::fail(
                        ID,
                        format!(
                            "ledger entry {} was recorded by a fake and still claims an assurance level",
                            entry
                                .pointer("/metadata/sequence")
                                .and_then(Value::as_u64)
                                .unwrap_or(0)
                        ),
                    );
                }
            }
            let attained = ev
                .contracts
                .evidence_manifest
                .as_ref()
                .and_then(|manifest| {
                    manifest
                        .pointer("/assurance/attained")
                        .and_then(Value::as_array)
                        .cloned()
                })
                .unwrap_or_default();
            if let Some(level) = attained.iter().find(|level| {
                text_at(level, "/ledger_entry_id").is_some_and(|id| fake_ids.contains(id))
            }) {
                return Verdict::fail(
                    ID,
                    format!(
                        "the manifest attains {} on a ledger entry that a fake recorded",
                        text_at(level, "/level").unwrap_or("(a level)")
                    ),
                );
            }
            Verdict::pass(
                ID,
                format!(
                    "test mode: {} fake entries are labelled, none claims an assurance level, and the manifest attains no level on one",
                    fake_entries.len()
                ),
            )
        }
    }
}

/// The stage runs of a kind that are not superseded (used by scenario checks).
#[must_use]
pub fn live_runs<'a>(ev: &'a RunEvidence, kind: &str) -> Vec<&'a crate::evidence::StageRunRecord> {
    runs_of(ev, kind)
        .into_iter()
        .filter(|run| run.status != "SUPERSEDED")
        .collect()
}
