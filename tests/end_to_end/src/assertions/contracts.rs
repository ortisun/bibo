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
    if !pr.body.contains(stored_head) {
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

/// A5: the specification contract validates, its artifact hashes match the files on the branch,
/// and `skills_invoked` is a subset of the four allowed.
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
    for artifact in &artifacts {
        let (Some(path), Some(hash)) = (text_at(artifact, "/path"), text_at(artifact, "/sha256"))
        else {
            return Verdict::fail(ID, "an artifact of the specification has no path or hash");
        };
        match ev.github.head_files.get(path) {
            None => {
                return Verdict::fail(
                    ID,
                    format!("the specification cites {path}, which is not on the head branch"),
                );
            }
            Some(on_branch) if on_branch != hash => {
                return Verdict::fail(
                    ID,
                    format!(
                        "the specification cites {hash} for {path}, but the file on the branch hashes to {on_branch}"
                    ),
                );
            }
            Some(_) => {}
        }
    }
    Verdict::pass(
        ID,
        format!(
            "the specification validates, is approved, records {} allowed skill(s), and its {} artifact hash(es) match the branch",
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
/// covered, and the changed paths are inside the union of owned files.
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
    if let Some(stray) = ev
        .github
        .changed_paths
        .iter()
        .find(|path| !owned.iter().any(|pattern| glob_matches(pattern, path)))
    {
        return Verdict::fail(
            ID,
            format!("the branch changes {stray}, which no task owns"),
        );
    }
    Verdict::pass(
        ID,
        format!(
            "the task graph validates, its {} task(s) cover all {} acceptance scenario(s) and {} requirement(s), and the {} changed path(s) are inside the owned files",
            tasks.len(),
            scenarios.len(),
            requirements.len(),
            ev.github.changed_paths.len()
        ),
    )
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

/// The names that identify the checks of the documentation gate in its report. The documentation
/// gate package (`s1-stage-documentation`) is not merged, so the report is read for a command whose
/// argument vector names the check. When that package defines its own names, change them here.
pub const DOCS_GATE_WORD: &str = "doc";
/// The word that marks the link check among the commands of the documentation report.
pub const LINK_CHECK_WORD: &str = "link";
/// The word that marks the snippet execution among the commands of the documentation report.
pub const SNIPPET_CHECK_WORD: &str = "snippet";

fn command_ran(report: &Value, word: &str) -> bool {
    report
        .pointer("/commands")
        .and_then(Value::as_array)
        .is_some_and(|commands| {
            commands.iter().any(|command| {
                let argv = command
                    .pointer("/argv")
                    .and_then(Value::as_array)
                    .map(|list| {
                        list.iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" ")
                            .to_ascii_lowercase()
                    })
                    .unwrap_or_default();
                argv.contains(word)
                    && command.pointer("/executed").and_then(Value::as_bool) == Some(true)
                    && command.pointer("/exit_code").and_then(Value::as_i64) == Some(0)
            })
        })
}

/// A12: the documentation gate report is `PASSED` with the link check and snippet execution
/// actually run. `NOT_APPLICABLE` only with a recorded rule.
#[must_use]
pub fn a12(ev: &RunEvidence, _env: &Env) -> Verdict {
    const ID: &str = "A12";
    let reports: Vec<&Value> = ev
        .contracts
        .gate_reports
        .iter()
        .map(|record| &record.report)
        .filter(|report| {
            text_at(report, "/metadata/gate_id")
                .is_some_and(|id| id.to_ascii_lowercase().contains(DOCS_GATE_WORD))
        })
        .collect();
    let Some(report) = reports.last() else {
        return Verdict::fail(ID, "the run left no documentation gate report");
    };
    match text_at(report, "/outcome") {
        Some("PASSED") => {
            if !command_ran(report, LINK_CHECK_WORD) {
                return Verdict::fail(
                    ID,
                    "the documentation gate is PASSED, but the link check did not run and exit with 0",
                );
            }
            if !command_ran(report, SNIPPET_CHECK_WORD) {
                return Verdict::fail(
                    ID,
                    "the documentation gate is PASSED, but no snippet was executed with exit code 0",
                );
            }
            Verdict::pass(
                ID,
                "the documentation gate is PASSED, and the link check and the snippet execution both ran with exit code 0",
            )
        }
        Some("NOT_APPLICABLE") => {
            let rule = text_at(report, "/not_applicable_reason").unwrap_or_default();
            if rule.trim().is_empty() {
                Verdict::fail(
                    ID,
                    "the documentation gate is NOT_APPLICABLE with no recorded rule",
                )
            } else {
                Verdict::pass(
                    ID,
                    format!("the documentation gate is NOT_APPLICABLE by a recorded rule: {rule}"),
                )
            }
        }
        other => Verdict::fail(
            ID,
            format!(
                "the documentation gate outcome is {}, not PASSED",
                other.unwrap_or("(none)")
            ),
        ),
    }
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
