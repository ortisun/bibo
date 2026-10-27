//! The harness checked against itself: a control-off proof for each control it provides.
//!
//! Principle 2 of the catalog says a test is accepted only if it fails when the control it checks
//! is switched off. The tests in each module do this one case at a time. This module collects the
//! controls of the harness itself in one [`ControlLedger`] built from the real fixtures, so that
//!
//! * a reviewer sees the list in one place, as JSON, and
//! * the security review package has a worked example of the pattern it must apply to every P0
//!   test of the catalog: write the test as a scenario that asks `controls.is_on(..)` at the one
//!   place the control acts, then let [`ControlLedger::check`] run it both ways.
//!
//! This file holds tests only.

use crate::fx::canary::{CanaryKind, CanarySet, Form, Sweeper};
use crate::fx::control::{ControlLedger, Controls};
use crate::fx::github::{FakeGithub, ReferenceVerifier, User, verdict_matches};
use crate::fx::rng::FxRng;
use crate::fx::sinks::SinkCollector;
use crate::fx::spawn::{Behavior, SpawnPolicy, SpawnRecorder};
use std::process::Command;

fn canaries() -> CanarySet {
    CanarySet::generate_with(&mut FxRng::from_seed(21))
}

/// The sweeper finds a canary that was written in hexadecimal.
fn encoded_form_scenario(controls: &Controls) -> Result<(), String> {
    let set = canaries();
    let token = set.get(CanaryKind::GithubInstallationToken);
    let sweeper = if controls.is_on("sweeper_hex_form") {
        Sweeper::new(&set)
    } else {
        Sweeper::new(&set).without_forms(&[Form::HexLower, Form::HexUpper])
    };
    let leak = Form::HexLower.encode(token.value()).expect("hex is a form");
    if sweeper
        .scan("log", &leak)
        .iter()
        .any(|h| h.canary == token.label())
    {
        Ok(())
    } else {
        Err("the hexadecimal leak was not found".to_owned())
    }
}

/// The sweeper finds a canary that a chunk boundary cut in two.
fn chunk_boundary_scenario(controls: &Controls) -> Result<(), String> {
    let set = canaries();
    let token = set.get(CanaryKind::JobToken);
    let sweeper = Sweeper::new(&set).with_marker_scan(false);
    let (left, right) = token.value().as_bytes().split_at(17);
    let hits = if controls.is_on("sweeper_stream_state") {
        sweeper.scan_chunks("stdout", [left, right])
    } else {
        // Each chunk on its own, as a scanner without memory between chunks would do.
        let mut hits = sweeper.scan("stdout", left);
        hits.extend(sweeper.scan("stdout", right));
        hits
    };
    if hits.is_empty() {
        Err("the split canary was not found".to_owned())
    } else {
        Ok(())
    }
}

/// The spawn recorder sees a shell that the code under test started.
fn shell_trap_scenario(controls: &Controls) -> Result<(), String> {
    let mut recorder =
        SpawnRecorder::new(SpawnPolicy::docker_and_git()).map_err(|e| e.to_string())?;
    recorder
        .install("docker", &Behavior::Record)
        .map_err(|e| e.to_string())?;
    if controls.is_on("spawn_shell_trap") {
        recorder.install_shell_traps().map_err(|e| e.to_string())?;
    }
    // The code under test starts a shell by name. Whether that start is seen depends on the trap.
    let _ = Command::new("sh")
        .args(["-c", "true"])
        .env_clear()
        .env("PATH", recorder.path_env())
        .output();
    let seen = recorder.violations();
    recorder.disarm();
    if seen.is_empty() {
        Err("the shell start was not seen".to_owned())
    } else {
        Ok(())
    }
}

/// Every forged webhook is refused by the verifier under test.
fn signature_scenario(controls: &Controls) -> Result<(), String> {
    let github = FakeGithub::new();
    github
        .add_repo("acme/widgets", "main")
        .add_user(User::person("alice", 1, "write", "MEMBER"));
    let number = github.add_issue("acme/widgets", "A", "B", "alice", &[]);
    let delivery = github.issues_labeled("acme/widgets", number, "factory:go", "alice");
    let secret = github.webhook_secret();
    let strict = ReferenceVerifier::new(vec![secret.clone()]);
    let wrong: Vec<String> = delivery
        .attack_variants(&secret)
        .iter()
        .filter_map(|attack| {
            let verdict = if controls.is_on("webhook_signature_check") {
                strict.verify(&attack.delivery.headers, &attack.delivery.body)
            } else {
                // A receiver that checks only that a signature header is present.
                crate::fx::github::Verdict::Valid { secret_index: 0 }
            };
            (!verdict_matches(verdict, attack.expect)).then_some(attack.name.to_owned())
        })
        .collect();
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(format!("wrongly accepted: {}", wrong.join(", ")))
    }
}

/// A secret passed on a command line is found by the sweep.
fn process_argument_scenario(controls: &Controls) -> Result<(), String> {
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    let mut recorder =
        SpawnRecorder::new(SpawnPolicy::docker_and_git()).map_err(|e| e.to_string())?;
    recorder
        .install("docker", &Behavior::Record)
        .map_err(|e| e.to_string())?;
    let token = set.get(CanaryKind::ModelApiKey).value();
    Command::new("docker")
        .args(["run", "--env", &format!("KEY={token}")])
        .env_clear()
        .env("PATH", recorder.path_env())
        .status()
        .map_err(|e| e.to_string())?;
    let collector = SinkCollector::new();
    if controls.is_on("sink_ingest_spawns") {
        collector.ingest_spawns(&recorder);
    }
    if collector.sweep(&sweeper).is_clean() {
        Err("the secret in the process arguments was not found".to_owned())
    } else {
        Ok(())
    }
}

#[test]
fn each_control_of_the_harness_has_a_control_off_proof() {
    let mut ledger = ControlLedger::new();
    ledger
        .check(
            "FX-CANARY encoded forms",
            "sweeper_hex_form",
            encoded_form_scenario,
        )
        .check(
            "FX-CANARY chunk boundaries",
            "sweeper_stream_state",
            chunk_boundary_scenario,
        )
        .check(
            "FX-SPAWN shell start",
            "spawn_shell_trap",
            shell_trap_scenario,
        )
        .check(
            "FX-GH forged webhooks",
            "webhook_signature_check",
            signature_scenario,
        )
        .check(
            "FX-SINKS process arguments",
            "sink_ingest_spawns",
            process_argument_scenario,
        );
    ledger.assert_all_proven();
    assert_eq!(ledger.proofs().len(), 5);

    let json = ledger.to_json();
    assert_eq!(json["fidelity"], "fake");
    assert_eq!(json["proven"].as_array().unwrap().len(), 5);
    assert!(json["rejected"].as_array().unwrap().is_empty());
    // Each proof records what went wrong when the control was off.
    for proof in ledger.proofs() {
        assert!(!proof.failure_with_control_off.is_empty(), "{}", proof.test);
    }
}

#[test]
fn every_fake_server_labels_the_data_it_records() {
    use crate::fx::dns::{DnsAnswer, FlippingDns, ScriptedHttp};
    use crate::fx::http::send_request;
    use crate::fx::registry::{FakeRegistry, PackageSpec};

    // Each server answers with the label on the wire, and the JSON of what it recorded carries
    // the label on the document and on every record.
    let wire = |server_addr, path: &str| {
        let response = send_request(server_addr, "GET", path, &[], b"").unwrap();
        assert_eq!(
            response.header("X-Factory-Fidelity"),
            Some("fake"),
            "{path}"
        );
        assert!(
            response
                .header("Server")
                .unwrap()
                .contains("factory-testkit-fake"),
            "{path}"
        );
    };

    let github = FakeGithub::new();
    let github_server = github.serve().unwrap();
    wire(github_server.addr(), "/app");
    let json = github.to_json();
    assert_eq!(json["fidelity"], "fake");
    assert!(!json["requests"].as_array().unwrap().is_empty());
    for record in json["requests"].as_array().unwrap() {
        assert_eq!(record["fidelity"], "fake");
    }

    let registry = FakeRegistry::new();
    registry.publish(PackageSpec::npm_named("pkg", 0));
    let registry_server = registry.serve().unwrap();
    wire(registry_server.addr(), "/pkg");
    let json = registry.to_json();
    assert_eq!(json["fidelity"], "fake");
    for record in json["requests"].as_array().unwrap() {
        assert_eq!(record["fidelity"], "fake");
    }

    let web = ScriptedHttp::start("upstream").unwrap();
    wire(web.addr(), "/anything");

    let dns = FlippingDns::start().unwrap();
    dns.always("a.test", DnsAnswer::NxDomain);
    let socket = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .unwrap();
    let mut query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 4];
    query.extend_from_slice(b"test");
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    socket.send_to(&query, dns.addr()).unwrap();
    let mut buffer = [0u8; 512];
    socket.recv_from(&mut buffer).unwrap();
    let json = dns.to_json();
    assert_eq!(json["fidelity"], "fake");
    assert_eq!(json["queries"][0]["fidelity"], "fake");

    // The recorders that are not servers say the same of what they hold.
    let mut recorder = SpawnRecorder::new(SpawnPolicy::docker_and_git()).unwrap();
    recorder.install("docker", &Behavior::Record).unwrap();
    Command::new("docker")
        .env_clear()
        .env("PATH", recorder.path_env())
        .status()
        .unwrap();
    let json = recorder.to_json();
    assert_eq!(json["fidelity"], "fake");
    assert_eq!(json["records"][0]["fidelity"], "fake");
    let collector = SinkCollector::new();
    collector.ingest_spawns(&recorder);
    let json = collector.to_json();
    assert_eq!(json["fidelity"], "fake");
    assert_eq!(json["entries"][0]["fidelity"], "fake");
}

#[test]
fn a_scenario_that_ignores_its_control_is_rejected_by_the_same_ledger() {
    // Deliberate break: the check that counts the sweeper's forms is only worth something if the
    // ledger can refuse a scenario that never asks about its control.
    let mut ledger = ControlLedger::new();
    ledger.check("FX-CANARY careless", "sweeper_hex_form", |_controls| {
        let set = canaries();
        let sweeper = Sweeper::new(&set);
        let token = set.get(CanaryKind::GithubInstallationToken);
        // The raw form is found with or without the hexadecimal form, so this proves nothing
        // about it.
        if sweeper.scan("log", token.value().as_bytes()).is_empty() {
            Err("not found".to_owned())
        } else {
            Ok(())
        }
    });
    assert_eq!(ledger.proofs().len(), 0);
    assert_eq!(ledger.rejected().len(), 1);
    assert!(
        ledger.rejected()[0]
            .to_string()
            .contains("does not test that control")
    );
}
