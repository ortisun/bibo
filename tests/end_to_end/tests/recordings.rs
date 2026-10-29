//! The recordings of the composed pipeline, and the deliberate breaks the runner must catch.
//!
//! A recording is judged by the harness and not by the process that made it. Each test here makes
//! an honest recording (the canned honest test-mode run, written in the format of the recorder),
//! shows that the runner passes it, and then breaks it in one way and shows the runner failing it
//! for the right reason.

use std::path::{Path, PathBuf};

use factory_e2e::canned::{Options, honest};
use factory_e2e::check::Env;
use factory_e2e::recorded::Recorded;
use factory_e2e::recording::{self, AdapterUse, ModeFile, Parts, Transitions, WIRING};
use factory_e2e::report_check;
use factory_e2e::runner::{RunOptions, ScenarioReport, Status, render, run_scenario};
use factory_e2e::scenarios;
use serde_json::{Value, json};

fn repository_root() -> PathBuf {
    factory_e2e::repository_root()
}

fn env() -> Env {
    Env::load(&repository_root()).expect("the state machine file loads")
}

/// A root directory with the state machine file, where a recording can be written.
fn temp_root(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("e2e-recordings-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let docs = root.join("docs/architecture");
    std::fs::create_dir_all(&docs).expect("a directory");
    std::fs::copy(
        repository_root().join("docs/architecture/state-machine.json"),
        docs.join("state-machine.json"),
    )
    .expect("the state machine file is copied");
    root
}

fn transitions() -> Transitions {
    let text =
        std::fs::read_to_string(repository_root().join("docs/architecture/state-machine.json"))
            .expect("the state machine file");
    Transitions::from_state_machine(&text).expect("transitions")
}

/// The honest test-mode run of the harness, as a recording of the composed pipeline would be.
fn parts() -> Parts {
    let env = env();
    let mut evidence = honest(&env, Options::e1_test_mode());
    evidence.wiring = WIRING.to_owned();
    evidence.usage.total_micro_usd = 0;
    let transitions = transitions();
    let entries: Vec<Value> = evidence
        .timeline
        .iter()
        .map(|entry| {
            json!({
                "at": "2026-10-29T10:00:00Z",
                "kind": "transition",
                "event": transitions.event_for(&entry.to).expect("an event for the status"),
                "reason": entry.reason,
            })
        })
        .collect();
    let mut adapters: Vec<AdapterUse> = Vec::new();
    for entry in &evidence.ledger {
        let component = entry["metadata"]["recorded_by"]["component"]
            .as_str()
            .expect("a component")
            .to_owned();
        let fidelity = entry["metadata"]["recorded_by"]["fidelity"]
            .as_str()
            .expect("a fidelity")
            .to_owned();
        if adapters.iter().all(|known| known.component != component) {
            let name = if fidelity == "fake" {
                format!("{}-playbook", component.replace('.', "-"))
            } else {
                component.replace('.', "-")
            };
            adapters.push(AdapterUse {
                port: "recorded-by".to_owned(),
                component,
                name,
                fidelity,
            });
        }
    }
    Parts {
        mode: ModeFile {
            mode: "test".to_owned(),
            scenario: evidence.scenario.clone(),
            wiring: WIRING.to_owned(),
            cost_micro_usd: 0,
            adapters,
            limitations: vec!["A synthetic recording for the harness's own tests.".to_owned()],
        },
        timeline_api: json!({ "job_id": evidence.job.id, "entries": entries, "truncated": false }),
        timings: json!({ "attempts": [] }),
        evidence,
    }
}

/// Writes the recording under `root` and runs the runner over it, as the command line does.
fn run(root: &Path) -> ScenarioReport {
    let mut wiring = Recorded::new(root, "E1").expect("the wiring loads");
    let scenario = scenarios::by_id("E1").expect("E1");
    let options = RunOptions {
        test_mode_for_real_scenarios: true,
    };
    run_scenario(&mut wiring, scenario, &env(), options, &|_| None)
}

fn write(root: &Path, parts: &Parts) -> PathBuf {
    let dir = recording::directory(root, "E1");
    recording::write(&dir, parts).expect("the recording is written");
    dir
}

fn failed_for(report: &ScenarioReport, id: &str, needle: &str) {
    assert_eq!(report.status, Status::Failed, "{}", render(report));
    let verdict = report
        .verdicts
        .iter()
        .find(|v| v.id == id && !v.pass)
        .unwrap_or_else(|| panic!("{id} did not fail:\n{}", render(report)));
    assert!(
        verdict.reason.contains(needle),
        "{id} failed for another reason: {}",
        verdict.reason
    );
}

// ---- the control -----------------------------------------------------------------------------

#[test]
fn an_intact_recording_passes_every_integrity_check_and_every_assertion() {
    let root = temp_root("control");
    write(&root, &parts());
    let report = run(&root);
    assert_eq!(report.status, Status::Passed, "{}", render(&report));
    let ids: Vec<&str> = report.verdicts.iter().map(|v| v.id.as_str()).collect();
    for needed in [
        "R.manifest",
        "R.mode",
        "R.adapters",
        "R.ledger",
        "R.sources",
        "A14",
    ] {
        assert!(ids.contains(&needed), "{needed} was not judged: {ids:?}");
    }
    assert!(report.label.contains("TEST MODE"), "{}", report.label);
}

#[test]
fn a_scenario_with_no_recording_is_blocked_and_says_how_to_make_one() {
    let root = temp_root("missing");
    let report = run(&root);
    assert_eq!(report.status, Status::Blocked);
    assert!(
        report.verdicts.is_empty(),
        "nothing is judged without a recording"
    );
    assert!(
        report.blocked[0].contains("scripts/e2e.sh --scenario E1"),
        "{:?}",
        report.blocked
    );
}

// ---- deliberate break 1: a broken ledger chain ------------------------------------------------

#[test]
fn break_a_ledger_chain_that_does_not_verify_fails_the_runner() {
    let root = temp_root("chain");
    let mut broken = parts();
    // The time one entry was recorded at is changed, and the recording is written again, so every
    // hash in the manifest is right. Only the hash chain of the ledger can tell.
    let entry = &mut broken.evidence.ledger[3];
    entry["metadata"]["recorded_at"] = json!("2026-10-27T09:59:59Z");
    write(&root, &broken);
    let report = run(&root);
    failed_for(&report, "R.ledger", "hash chain does not verify");
    // No assertion read the evidence of a ledger that does not verify.
    assert!(
        report.verdicts.iter().all(|v| v.id.starts_with("R.")),
        "{}",
        render(&report)
    );
}

// ---- deliberate break 2: a recording edited after the run -------------------------------------

#[test]
fn break_an_assertion_made_to_pass_by_editing_the_recording_after_the_run_fails_the_runner() {
    let root = temp_root("edited");
    let mut failing = parts();
    // A run in which A13 would fail: DELIVERY started with a failed gate report.
    failing.evidence.contracts.gate_reports[0].report["outcome"] = json!("FAILED");
    let dir = write(&root, &failing);
    // First, the honest verdict of this recording: it fails.
    let honest_run = run(&root);
    assert_eq!(honest_run.status, Status::Failed, "{}", render(&honest_run));

    // Then someone edits the evidence so that the assertion passes, and leaves the manifest alone.
    let path = dir.join("evidence.json");
    let text = std::fs::read_to_string(&path).expect("the evidence");
    std::fs::write(
        &path,
        text.replace("\"outcome\": \"FAILED\"", "\"outcome\": \"PASSED\""),
    )
    .expect("an edit");
    let report = run(&root);
    failed_for(&report, "R.manifest", "was changed after the run");
}

#[test]
fn break_an_edit_that_also_rewrites_the_manifest_is_caught_by_the_digest_in_the_report() {
    let root = temp_root("resealed");
    // The recording of E3 here is the harness's honest sample; only its files matter to the report.
    let dir = recording::directory(&root, "E3");
    recording::write(&dir, &parts()).expect("the recording is written");
    let digest = recording::manifest_digest(&dir).expect("a digest");
    let report_text = format!(
        "| E3 | PASSED, test mode with fakes | [recording](../../fixtures/recordings/e2e/E3/evidence.json) | manifest {digest} |"
    );
    assert_eq!(
        report_check::problems(&report_text, &root),
        Vec::<String>::new()
    );

    // The evidence is edited and the manifest is rewritten so that the recording is consistent.
    let path = dir.join("evidence.json");
    let text = std::fs::read_to_string(&path).expect("the evidence");
    std::fs::write(&path, text.replace("\"E1\"", "\"E1\" ")).expect("an edit");
    recording::reseal(&dir).expect("reseal");
    assert!(
        recording::verify_files(&dir).is_ok(),
        "the recording is consistent with its own manifest again"
    );
    let problems = report_check::problems(&report_text, &root).join("\n");
    assert!(
        problems.contains("changed after the report was written"),
        "{problems}"
    );
}

// ---- deliberate break 3: a report that claims PASSED without a recording ----------------------

#[test]
fn break_a_report_that_claims_passed_with_a_missing_recording_fails_the_check() {
    let root = temp_root("report");
    let report = "\
| Scenario | Result | Recording |
|---|---|---|
| E3 | PASSED, test mode with fakes | [recording](../../fixtures/recordings/e2e/E3/evidence.json) |
| E4 | PASSED, test mode with fakes | none |
| E1 | PASSED, real adapters | [recording](../../fixtures/recordings/e2e/E1/evidence.json) |
";
    let problems = report_check::problems(report, &root);
    assert!(
        problems
            .iter()
            .any(|p| p.contains("E3") && p.contains("does not exist")),
        "{problems:?}"
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("E4") && p.contains("cites no recording")),
        "{problems:?}"
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("E1") && p.contains("does not exist")),
        "{problems:?}"
    );
}

#[test]
fn a_blocked_line_that_names_nothing_fails_the_check() {
    let problems = report_check::problems("| E2 | BLOCKED |", Path::new("/nowhere"));
    assert_eq!(problems.len(), 1, "{problems:?}");
}

// ---- deliberate break 4: a real adapter's name on a fake --------------------------------------

#[test]
fn break_a_fake_that_carries_the_name_of_a_real_adapter_fails_the_runner() {
    let root = temp_root("realname");
    let mut broken = parts();
    let fake = broken
        .mode
        .adapters
        .iter_mut()
        .find(|adapter| adapter.fidelity == "fake")
        .expect("a fake");
    fake.name = "docker-sandbox".to_owned();
    write(&root, &broken);
    let report = run(&root);
    failed_for(&report, "R.adapters", "real adapter docker-sandbox");
}

#[test]
fn break_a_fake_that_is_listed_as_real_fails_the_runner() {
    let root = temp_root("fidelity");
    let mut broken = parts();
    let fake = broken
        .mode
        .adapters
        .iter_mut()
        .find(|adapter| adapter.fidelity == "fake")
        .expect("a fake");
    fake.fidelity = "real".to_owned();
    write(&root, &broken);
    let report = run(&root);
    failed_for(&report, "R.adapters", "recorded a ledger entry as fake");
}

#[test]
fn break_a_fake_with_a_name_that_does_not_say_so_fails_the_runner() {
    let root = temp_root("plainname");
    let mut broken = parts();
    let fake = broken
        .mode
        .adapters
        .iter_mut()
        .find(|adapter| adapter.fidelity == "fake")
        .expect("a fake");
    fake.name = "agent-runtime".to_owned();
    write(&root, &broken);
    let report = run(&root);
    failed_for(&report, "R.adapters", "does not say it is a fake");
}

#[test]
fn break_a_component_that_wrote_the_ledger_and_is_not_listed_fails_the_runner() {
    let root = temp_root("unlisted");
    let mut broken = parts();
    broken
        .mode
        .adapters
        .retain(|adapter| adapter.fidelity != "fake");
    write(&root, &broken);
    let report = run(&root);
    failed_for(&report, "R.adapters", "does not list that component");
}

// ---- the other integrity checks ---------------------------------------------------------------

#[test]
fn a_recording_that_says_production_or_a_cost_fails_the_runner() {
    let root = temp_root("mode");
    let mut broken = parts();
    broken.mode.cost_micro_usd = 12;
    write(&root, &broken);
    failed_for(&run(&root), "R.mode", "must cost nothing");

    let mut broken = parts();
    broken.mode.mode = "production".to_owned();
    write(&root, &broken);
    failed_for(&run(&root), "R.mode", "not 'test'");

    let mut broken = parts();
    broken.mode.adapters.clear();
    write(&root, &broken);
    failed_for(&run(&root), "R.mode", "lists no adapter");
}

#[test]
fn a_timeline_that_is_not_the_one_the_api_served_fails_the_runner() {
    let root = temp_root("timeline");
    let mut broken = parts();
    broken.timeline_api["entries"]
        .as_array_mut()
        .expect("entries")
        .remove(2);
    write(&root, &broken);
    failed_for(&run(&root), "R.sources", "not the one the API served");
}

#[test]
fn a_gate_report_that_is_not_the_stored_file_fails_the_runner() {
    let root = temp_root("gate");
    let dir = write(&root, &parts());
    let id = parts().evidence.contracts.gate_reports[0]
        .stage_run_id
        .clone();
    let path = dir.join(format!("gate-reports/{id}.json"));
    std::fs::write(&path, "{\"outcome\": \"PASSED\", \"edited\": true}\n").expect("an edit");
    recording::reseal(&dir).expect("reseal");
    failed_for(&run(&root), "R.sources", "hashes to");
}

#[test]
fn a_file_added_to_the_recording_without_the_manifest_fails_the_runner() {
    let root = temp_root("extra");
    let dir = write(&root, &parts());
    std::fs::write(dir.join("notes.txt"), "added later").expect("a file");
    failed_for(&run(&root), "R.manifest", "not in the manifest");
}

#[test]
fn a_recording_for_another_scenario_fails_the_runner() {
    let root = temp_root("other");
    let mut broken = parts();
    broken.mode.scenario = "E4".to_owned();
    write(&root, &broken);
    failed_for(&run(&root), "R.mode", "the directory is E1");
}
