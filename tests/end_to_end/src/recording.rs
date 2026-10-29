//! Recordings of composed test-mode runs, and the checks that keep them honest.
//!
//! A recording is a directory under `fixtures/recordings/e2e/<scenario>/` that the test
//! `apps/api/tests/e2e_scenarios.rs` writes after it drove a scenario through the real composed
//! pipeline (the real engine, the real API on loopback, the worker hook and a real PostgreSQL, with
//! the labelled fakes the file `mode.json` lists). The harness judges the recording, not the
//! process that made it: the assertions A1 to A14 and the scenario checks read `evidence.json`,
//! and nothing else in the run is trusted.
//!
//! # Files
//!
//! | File | What it holds |
//! |---|---|
//! | `evidence.json` | The [`RunEvidence`] the assertions read. |
//! | `mode.json` | The `mode: test` marker, the wiring name, and every adapter the run used with its fidelity. |
//! | `ledger.json` | The ledger entries as stored, and the chain head the recorder computed. |
//! | `timeline.api.json` | The timeline exactly as `GET /v1/jobs/{id}/timeline` served it. |
//! | `artifacts.json` | The hash of every stored stage output and gate report. |
//! | `gate-reports/RUN.N.json` | The N-th gate report of a stage run, byte for byte as the recorder kept it. |
//! | `timings.json` | How long each attempt took. |
//! | `MANIFEST.json` | The SHA-256 of every file above. |
//!
//! # What the harness checks before it trusts the evidence
//!
//! * **R.manifest**: every file matches its hash and no file is unlisted. A recording edited after
//!   the run does not match.
//! * **R.mode**: the mode is `test`, the scenario and wiring agree in every file, and the run cost
//!   nothing.
//! * **R.adapters**: every component that wrote a ledger entry is listed with the fidelity it
//!   reported, no adapter that needs a credential is listed (a composed test run has none), and a
//!   fake carries a name that says so.
//! * **R.ledger**: the ledger in `ledger.json` is the ledger in the evidence, its chain verifies
//!   (checked here again, not taken from the recorder), and the head hash is the last entry's hash.
//! * **R.sources**: the gate reports in the evidence are the stored files, whose hashes are in
//!   `artifacts.json`, and the status changes in the evidence are the ones the API timeline served.
//!
//! The acceptance report cites the digest of `MANIFEST.json` for each recording, so editing a file
//! and the manifest together is caught by [`crate::report_check`].

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use factory_domain::contracts::{Contract as _, EvidenceLedgerEntry};
use factory_domain::ledger::verify_chain;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::check::Verdict;
use crate::evidence::{Mode, RunEvidence};

/// Where the recordings are, below the repository root.
pub const RECORDING_ROOT: &str = "fixtures/recordings/e2e";
/// The name the evidence gives the wiring that made a recording.
pub const WIRING: &str = "composed-test";
/// The manifest file.
pub const MANIFEST: &str = "MANIFEST.json";
/// The format number of the manifest.
pub const FORMAT: u64 = 1;

/// Names of adapters that need a credential or a live service. A composed test run has none, so
/// none of these may appear in the adapters of a recording.
pub const CREDENTIALED_ADAPTERS: [&str; 6] = [
    "claude-code",
    "codex",
    "github-app",
    "docker-sandbox",
    "anthropic-api",
    "openai-api",
];

/// What marks a name as a labelled fake.
const FAKE_MARKS: [&str; 5] = ["fake", "stand-in", "scripted", "playbook", "testkit"];

/// The directory of the recording of a scenario.
#[must_use]
pub fn directory(root: &Path, scenario: &str) -> PathBuf {
    root.join(RECORDING_ROOT).join(scenario)
}

/// The SHA-256 of the manifest of a recording, as `sha256:...`, or `None` when it has none. The
/// acceptance report cites this digest.
#[must_use]
pub fn manifest_digest(dir: &Path) -> Option<String> {
    std::fs::read(dir.join(MANIFEST))
        .ok()
        .map(|bytes| crate::canned::sha(&bytes))
}

/// The `mode.json` file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModeFile {
    /// Always `test`.
    pub mode: String,
    /// The scenario.
    pub scenario: String,
    /// Always [`WIRING`].
    pub wiring: String,
    /// What the run cost, in millionths of a US dollar. Test mode costs nothing.
    pub cost_micro_usd: u64,
    /// Every adapter and stand-in the run used.
    pub adapters: Vec<AdapterUse>,
    /// What the recording does not show, in plain English.
    #[serde(default)]
    pub limitations: Vec<String>,
}

/// One adapter or stand-in a run used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterUse {
    /// The port it stands behind, such as `sandbox` or `change-host`.
    pub port: String,
    /// The component name as the ledger records it in `recorded_by.component`, when one does.
    pub component: String,
    /// The name of the adapter or stand-in.
    pub name: String,
    /// `real` or `fake`.
    pub fidelity: String,
}

/// The manifest file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// The format number.
    pub format: u64,
    /// The scenario.
    pub scenario: String,
    /// Relative path to digest, for every other file.
    pub files: BTreeMap<String, String>,
}

/// The result of loading a recording.
#[derive(Debug)]
pub struct Loaded {
    /// The evidence, when the recording could be read far enough to have it.
    pub evidence: Option<RunEvidence>,
    /// The integrity verdicts. A failing one means the evidence must not be trusted.
    pub verdicts: Vec<Verdict>,
    /// The digest of the manifest.
    pub manifest_digest: Option<String>,
    /// The adapters the run used, for the report.
    pub adapters: Vec<AdapterUse>,
}

/// The recording of a scenario is not there at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missing(pub String);

/// Which status each event of the state machine leads to.
pub struct Transitions(BTreeMap<String, String>);

impl Transitions {
    /// Reads the `emits` and `to` of every job and stage run transition.
    ///
    /// # Errors
    /// A sentence saying what is wrong with the file.
    pub fn from_state_machine(text: &str) -> Result<Self, String> {
        let document: Value =
            serde_json::from_str(text).map_err(|error| format!("not JSON: {error}"))?;
        let mut to = BTreeMap::new();
        for machine in ["job", "stage_run"] {
            let list = document
                .pointer(&format!("/machines/{machine}/transitions"))
                .and_then(Value::as_array)
                .ok_or_else(|| format!("no transitions for {machine}"))?;
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
        Ok(Self(to))
    }

    /// The status the event leads to, when it is a job or stage run transition.
    #[must_use]
    pub fn to(&self, event: &str) -> Option<&str> {
        self.0.get(event).map(String::as_str)
    }

    /// An event that leads to this status. A test builds the timeline the API would serve from
    /// the status changes of a run with it.
    #[must_use]
    pub fn event_for(&self, status: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(_, to)| to.as_str() == status)
            .map(|(event, _)| event.as_str())
    }
}

fn read_json<T: serde::de::DeserializeOwned>(
    files: &BTreeMap<String, Vec<u8>>,
    name: &str,
) -> Result<T, String> {
    let bytes = files
        .get(name)
        .ok_or_else(|| format!("the recording has no {name}"))?;
    serde_json::from_slice(bytes).map_err(|error| format!("{name} is not valid: {error}"))
}

fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            walk(base, &path, out);
        } else if let Ok(relative) = path.strip_prefix(base) {
            out.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// Loads the recording of a scenario and checks it.
///
/// # Errors
/// [`Missing`] when there is no recording directory for the scenario. A recording that exists and
/// is damaged is not an error here: it comes back with failing verdicts.
pub fn load(root: &Path, scenario: &str, transitions: &Transitions) -> Result<Loaded, Missing> {
    let dir = directory(root, scenario);
    if !dir.is_dir() {
        return Err(Missing(format!(
            "there is no recording for {scenario} at {}; run scripts/e2e.sh --scenario {scenario}, which drives the composed pipeline and writes it",
            dir.strip_prefix(root).unwrap_or(&dir).display()
        )));
    }
    let mut verdicts = Vec::new();
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut listed = Vec::new();
    walk(&dir, &dir, &mut listed);
    for name in &listed {
        if let Ok(bytes) = std::fs::read(dir.join(name)) {
            files.insert(name.clone(), bytes);
        }
    }
    let digest = manifest_digest(&dir);

    // R.manifest
    let manifest: Result<Manifest, String> = read_json(&files, MANIFEST);
    let manifest_verdict = match &manifest {
        Err(reason) => Verdict::fail("R.manifest", reason.clone()),
        Ok(manifest) => manifest_verdict(manifest, scenario, &files),
    };
    verdicts.push(manifest_verdict);

    let evidence: Result<RunEvidence, String> = read_json(&files, "evidence.json");
    let mode: Result<ModeFile, String> = read_json(&files, "mode.json");
    let ledger: Result<Value, String> = read_json(&files, "ledger.json");
    let timeline: Result<Value, String> = read_json(&files, "timeline.api.json");
    let artifacts: Result<Value, String> = read_json(&files, "artifacts.json");

    let mut adapters = Vec::new();
    match (&evidence, &mode) {
        (Ok(evidence), Ok(mode)) => {
            adapters.clone_from(&mode.adapters);
            verdicts.push(mode_verdict(evidence, mode, scenario));
            verdicts.push(adapters_verdict(evidence, mode));
        }
        (Err(reason), _) | (_, Err(reason)) => {
            verdicts.push(Verdict::fail("R.mode", reason.clone()));
        }
    }
    match (&evidence, &ledger) {
        (Ok(evidence), Ok(ledger)) => verdicts.push(ledger_verdict(evidence, ledger)),
        (Err(reason), _) | (_, Err(reason)) => {
            verdicts.push(Verdict::fail("R.ledger", reason.clone()));
        }
    }
    match (&evidence, &timeline, &artifacts) {
        (Ok(evidence), Ok(timeline), Ok(artifacts)) => {
            verdicts.push(sources_verdict(
                evidence,
                timeline,
                artifacts,
                &files,
                transitions,
            ));
        }
        (Err(reason), _, _) | (_, Err(reason), _) | (_, _, Err(reason)) => {
            verdicts.push(Verdict::fail("R.sources", reason.clone()));
        }
    }
    Ok(Loaded {
        evidence: evidence.ok(),
        verdicts,
        manifest_digest: digest,
        adapters,
    })
}

fn manifest_verdict(
    manifest: &Manifest,
    scenario: &str,
    files: &BTreeMap<String, Vec<u8>>,
) -> Verdict {
    const ID: &str = "R.manifest";
    if manifest.scenario != scenario {
        return Verdict::fail(
            ID,
            format!(
                "the manifest is about {}, and the directory is {scenario}",
                manifest.scenario
            ),
        );
    }
    match check_files(manifest, files) {
        Ok(count) => Verdict::pass(
            ID,
            format!("all {count} files match the hashes the run recorded"),
        ),
        Err(reason) => Verdict::fail(ID, reason),
    }
}

/// Every file of the manifest is there with the hash the manifest lists, and no other file is.
fn check_files(manifest: &Manifest, files: &BTreeMap<String, Vec<u8>>) -> Result<usize, String> {
    if manifest.format != FORMAT {
        return Err(format!(
            "the manifest has format {}, not {FORMAT}",
            manifest.format
        ));
    }
    for (name, expected) in &manifest.files {
        let Some(bytes) = files.get(name) else {
            return Err(format!("{name} is listed in the manifest and is not there"));
        };
        let found = crate::canned::sha(bytes);
        if &found != expected {
            return Err(format!(
                "{name} was changed after the run: the manifest has {expected} and the file hashes to {found}"
            ));
        }
    }
    if let Some(name) = files
        .keys()
        .find(|name| name.as_str() != MANIFEST && !manifest.files.contains_key(*name))
    {
        return Err(format!(
            "{name} is in the recording and not in the manifest"
        ));
    }
    Ok(manifest.files.len())
}

/// Reads a recording directory and checks that its files are the ones its manifest lists.
///
/// # Errors
/// A sentence saying which file is missing, changed or unlisted.
pub fn verify_files(dir: &Path) -> Result<usize, String> {
    let mut listed = Vec::new();
    walk(dir, dir, &mut listed);
    let mut files = BTreeMap::new();
    for name in listed {
        let bytes = std::fs::read(dir.join(&name)).map_err(|error| format!("{name}: {error}"))?;
        files.insert(name, bytes);
    }
    let manifest: Manifest = read_json(&files, MANIFEST)?;
    check_files(&manifest, &files)
}

fn mode_verdict(evidence: &RunEvidence, mode: &ModeFile, scenario: &str) -> Verdict {
    const ID: &str = "R.mode";
    if mode.mode != "test" {
        return Verdict::fail(
            ID,
            format!("mode.json says mode '{}', not 'test'", mode.mode),
        );
    }
    if evidence.mode != Mode::Test {
        return Verdict::fail(
            ID,
            "evidence.json claims production mode in a test-mode recording",
        );
    }
    if mode.scenario != scenario || evidence.scenario != scenario {
        return Verdict::fail(
            ID,
            format!(
                "the files are about {} and {}, and the directory is {scenario}",
                mode.scenario, evidence.scenario
            ),
        );
    }
    if mode.wiring != WIRING || evidence.wiring != WIRING {
        return Verdict::fail(
            ID,
            format!(
                "the wiring is '{}' and '{}', and a recording of the composed pipeline says '{WIRING}'",
                mode.wiring, evidence.wiring
            ),
        );
    }
    if mode.cost_micro_usd != 0 || evidence.usage.total_micro_usd != 0 {
        return Verdict::fail(
            ID,
            "a test-mode run calls no model and must cost nothing, and the recording reports a cost",
        );
    }
    if mode.adapters.is_empty() {
        return Verdict::fail(
            ID,
            "mode.json lists no adapter, so nothing says what was fake",
        );
    }
    Verdict::pass(
        ID,
        format!(
            "mode test, wiring {WIRING}, cost 0, {} adapters listed",
            mode.adapters.len()
        ),
    )
}

fn adapters_verdict(evidence: &RunEvidence, mode: &ModeFile) -> Verdict {
    const ID: &str = "R.adapters";
    for adapter in &mode.adapters {
        if !matches!(adapter.fidelity.as_str(), "real" | "fake") {
            return Verdict::fail(
                ID,
                format!(
                    "{} has the fidelity '{}', and it must be real or fake",
                    adapter.name, adapter.fidelity
                ),
            );
        }
        let lower = adapter.name.to_lowercase();
        if let Some(credentialed) = CREDENTIALED_ADAPTERS
            .iter()
            .find(|name| lower == **name || lower.starts_with(&format!("{name}-")))
        {
            return Verdict::fail(
                ID,
                format!(
                    "the adapter '{}' has the name of the real adapter {credentialed}, which needs a credential, and a composed test run has none",
                    adapter.name
                ),
            );
        }
        if adapter.fidelity == "fake" && !FAKE_MARKS.iter().any(|mark| lower.contains(mark)) {
            return Verdict::fail(
                ID,
                format!(
                    "the fake '{}' has a name that does not say it is a fake",
                    adapter.name
                ),
            );
        }
    }
    let listed: BTreeMap<&str, &str> = mode
        .adapters
        .iter()
        .filter(|adapter| !adapter.component.is_empty())
        .map(|adapter| (adapter.component.as_str(), adapter.fidelity.as_str()))
        .collect();
    let mut seen = BTreeSet::new();
    for entry in &evidence.ledger {
        let component = entry
            .pointer("/metadata/recorded_by/component")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let fidelity = entry
            .pointer("/metadata/recorded_by/fidelity")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match listed.get(component) {
            None => {
                return Verdict::fail(
                    ID,
                    format!(
                        "the ledger holds an entry recorded by '{component}' ({fidelity}), and mode.json does not list that component"
                    ),
                );
            }
            Some(label) if *label != fidelity => {
                return Verdict::fail(
                    ID,
                    format!(
                        "'{component}' recorded a ledger entry as {fidelity}, and mode.json lists it as {label}"
                    ),
                );
            }
            Some(_) => {
                seen.insert(component);
            }
        }
    }
    let fakes = mode
        .adapters
        .iter()
        .filter(|adapter| adapter.fidelity == "fake")
        .count();
    Verdict::pass(
        ID,
        format!(
            "{} adapters listed, {fakes} of them labelled fakes; the {} components that wrote ledger entries are all listed with the fidelity they reported",
            mode.adapters.len(),
            seen.len()
        ),
    )
}

fn ledger_verdict(evidence: &RunEvidence, ledger: &Value) -> Verdict {
    const ID: &str = "R.ledger";
    let Some(entries) = ledger.pointer("/entries").and_then(Value::as_array) else {
        return Verdict::fail(ID, "ledger.json has no entries list");
    };
    if entries != &evidence.ledger {
        return Verdict::fail(
            ID,
            format!(
                "the ledger in evidence.json ({} entries) is not the ledger in ledger.json ({} entries)",
                evidence.ledger.len(),
                entries.len()
            ),
        );
    }
    let mut typed = Vec::new();
    for (position, entry) in entries.iter().enumerate() {
        match EvidenceLedgerEntry::from_json_value(entry.clone()) {
            Ok(entry) => typed.push(entry),
            Err(error) => {
                return Verdict::fail(
                    ID,
                    format!(
                        "ledger entry {} is not a valid entry: {error}",
                        position + 1
                    ),
                );
            }
        }
    }
    if let Err(error) = verify_chain(&typed) {
        return Verdict::fail(ID, format!("the hash chain does not verify: {error}"));
    }
    let recorded_head = ledger
        .pointer("/chain/head_hash")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let actual_head = typed
        .last()
        .map(|entry| entry.entry_hash.as_str().to_owned());
    if recorded_head != actual_head {
        return Verdict::fail(
            ID,
            format!(
                "the head hash in ledger.json is {recorded_head:?}, and the last entry hashes to {actual_head:?}"
            ),
        );
    }
    Verdict::pass(
        ID,
        format!(
            "{} entries, the chain verifies again here, and the head is {}",
            typed.len(),
            actual_head.unwrap_or_else(|| "(empty ledger)".to_owned())
        ),
    )
}

/// The name of the n-th gate report of a stage run, from 0, in the order the evidence lists them.
/// A stage run can have several: the validation stage keeps one for each gate it ran.
#[must_use]
pub fn report_key(stage_run_id: &str, ordinal: usize) -> String {
    format!("{stage_run_id}.{ordinal}")
}

fn sources_verdict(
    evidence: &RunEvidence,
    timeline: &Value,
    artifacts: &Value,
    files: &BTreeMap<String, Vec<u8>>,
    transitions: &Transitions,
) -> Verdict {
    const ID: &str = "R.sources";
    // The gate reports in the evidence are the stored files.
    let hashes = artifacts
        .pointer("/gate_reports")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if hashes.len() != evidence.contracts.gate_reports.len() {
        return Verdict::fail(
            ID,
            format!(
                "artifacts.json lists {} gate reports and the evidence holds {}",
                hashes.len(),
                evidence.contracts.gate_reports.len()
            ),
        );
    }
    let mut ordinals: BTreeMap<&str, usize> = BTreeMap::new();
    for record in &evidence.contracts.gate_reports {
        let ordinal = ordinals.entry(record.stage_run_id.as_str()).or_insert(0);
        let key = report_key(&record.stage_run_id, *ordinal);
        *ordinal += 1;
        let name = format!("gate-reports/{key}.json");
        let Some(bytes) = files.get(&name) else {
            return Verdict::fail(ID, format!("{name} is not in the recording"));
        };
        let found = crate::canned::sha(bytes);
        let expected = hashes.get(&key).and_then(Value::as_str).unwrap_or_default();
        if found != expected {
            return Verdict::fail(
                ID,
                format!("{name} hashes to {found}, and artifacts.json says {expected}"),
            );
        }
        match serde_json::from_slice::<Value>(bytes) {
            Ok(stored) if stored == record.report => {}
            _ => {
                return Verdict::fail(
                    ID,
                    format!("the gate report in the evidence is not the stored file {name}"),
                );
            }
        }
    }
    // The status changes in the evidence are the ones the API served.
    let served: Vec<(String, String)> = timeline
        .pointer("/entries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| entry.get("kind").and_then(Value::as_str) == Some("transition"))
        .filter_map(|entry| {
            let event = entry.get("event").and_then(Value::as_str)?;
            let to = transitions.to(event)?;
            let reason = entry.get("reason").and_then(Value::as_str).unwrap_or(event);
            Some((to.to_owned(), reason.to_owned()))
        })
        .collect();
    let claimed: Vec<(String, String)> = evidence
        .timeline
        .iter()
        .map(|entry| (entry.to.clone(), entry.reason.clone()))
        .collect();
    if served != claimed {
        let at = served
            .iter()
            .zip(&claimed)
            .position(|(a, b)| a != b)
            .unwrap_or_else(|| served.len().min(claimed.len()));
        return Verdict::fail(
            ID,
            format!(
                "the timeline in the evidence ({} changes) is not the one the API served ({} changes); they part at position {}",
                claimed.len(),
                served.len(),
                at + 1
            ),
        );
    }
    Verdict::pass(
        ID,
        format!(
            "{} gate reports are the stored files, and the {} status changes are the ones the API timeline served",
            evidence.contracts.gate_reports.len(),
            claimed.len()
        ),
    )
}

/// What a test needs to write a recording: the same files the recorder in `apps/api` writes.
#[derive(Debug, Clone)]
pub struct Parts {
    /// The evidence.
    pub evidence: RunEvidence,
    /// The mode file.
    pub mode: ModeFile,
    /// The raw timeline as the API served it.
    pub timeline_api: Value,
    /// Timings.
    pub timings: Value,
}

/// Writes a recording the way the recorder does, for the harness's own tests and for the
/// deliberate breaks. It computes the ledger file, the artifact hashes and the manifest.
///
/// # Errors
/// The text of the I/O error.
pub fn write(dir: &Path, parts: &Parts) -> Result<(), String> {
    let io = |error: std::io::Error| error.to_string();
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir.join("gate-reports")).map_err(io)?;
    let pretty = |value: &Value| -> Vec<u8> {
        let mut text = serde_json::to_string_pretty(value).expect("JSON");
        text.push('\n');
        text.into_bytes()
    };
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    files.insert(
        "evidence.json".to_owned(),
        pretty(&serde_json::to_value(&parts.evidence).expect("evidence is JSON")),
    );
    files.insert(
        "mode.json".to_owned(),
        pretty(&serde_json::to_value(&parts.mode).expect("mode is JSON")),
    );
    let head = parts
        .evidence
        .ledger
        .last()
        .and_then(|entry| entry.pointer("/entry_hash"))
        .cloned()
        .unwrap_or(Value::Null);
    files.insert(
        "ledger.json".to_owned(),
        pretty(&serde_json::json!({
            "entries": parts.evidence.ledger,
            "chain": { "entries": parts.evidence.ledger.len(), "head_hash": head },
        })),
    );
    files.insert("timeline.api.json".to_owned(), pretty(&parts.timeline_api));
    files.insert("timings.json".to_owned(), pretty(&parts.timings));
    let mut gate_hashes = serde_json::Map::new();
    let mut ordinals: BTreeMap<&str, usize> = BTreeMap::new();
    for record in &parts.evidence.contracts.gate_reports {
        let ordinal = ordinals.entry(record.stage_run_id.as_str()).or_insert(0);
        let key = report_key(&record.stage_run_id, *ordinal);
        *ordinal += 1;
        let bytes = pretty(&record.report);
        gate_hashes.insert(key.clone(), Value::String(crate::canned::sha(&bytes)));
        files.insert(format!("gate-reports/{key}.json"), bytes);
    }
    files.insert(
        "artifacts.json".to_owned(),
        pretty(&serde_json::json!({ "gate_reports": gate_hashes })),
    );
    let manifest = Manifest {
        format: FORMAT,
        scenario: parts.evidence.scenario.clone(),
        files: files
            .iter()
            .map(|(name, bytes)| (name.clone(), crate::canned::sha(bytes)))
            .collect(),
    };
    files.insert(
        MANIFEST.to_owned(),
        pretty(&serde_json::to_value(&manifest).expect("manifest is JSON")),
    );
    for (name, bytes) in files {
        std::fs::write(dir.join(name), bytes).map_err(io)?;
    }
    Ok(())
}

/// Rewrites the manifest of a recording so that it matches the files as they are now. A test uses
/// it to show that editing a file together with the manifest is caught by the digest in the
/// report, and not by the manifest.
///
/// # Errors
/// The text of the I/O error.
pub fn reseal(dir: &Path) -> Result<(), String> {
    let mut listed = Vec::new();
    walk(dir, dir, &mut listed);
    let mut files = BTreeMap::new();
    let mut scenario = dir
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    for name in listed {
        if name == MANIFEST {
            if let Ok(old) = std::fs::read(dir.join(&name))
                && let Ok(old) = serde_json::from_slice::<Manifest>(&old)
            {
                scenario = old.scenario;
            }
            continue;
        }
        let bytes = std::fs::read(dir.join(&name)).map_err(|error| error.to_string())?;
        files.insert(name, crate::canned::sha(&bytes));
    }
    let manifest = Manifest {
        format: FORMAT,
        scenario,
        files,
    };
    let mut text = serde_json::to_string_pretty(&manifest).map_err(|error| error.to_string())?;
    text.push('\n');
    std::fs::write(dir.join(MANIFEST), text).map_err(|error| error.to_string())
}
