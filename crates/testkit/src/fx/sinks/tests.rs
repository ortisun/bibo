use super::*;
use crate::fx::canary::{Canary, CanaryKind, CanarySet, Form, Sweeper};
use crate::fx::control::prove_control_matters;
use crate::fx::encoding::{Base64Alphabet, base64_encode};
use crate::fx::rng::FxRng;

fn canaries() -> CanarySet {
    CanarySet::generate_with(&mut FxRng::from_seed(7))
}

/// Puts ordinary text in every kind of sink, so a planted canary has to be found among noise.
fn fill_with_noise(collector: &SinkCollector) {
    for kind in SinkKind::ALL {
        collector.record(
            kind,
            "noise",
            format!("an ordinary {} record, nothing secret", kind.name()),
        );
    }
}

/// Plants `secret` in one sink of the given kind, using the recording method a real test would.
fn plant(collector: &SinkCollector, kind: SinkKind, secret: &str) {
    match kind {
        SinkKind::Stdout | SinkKind::Stderr => {
            // A stream, cut through the middle of the secret.
            let cut = secret.len() / 2;
            collector.record_chunk(kind, "worker", &secret.as_bytes()[..cut]);
            collector.record_chunk(kind, "worker", &secret.as_bytes()[cut..]);
        }
        SinkKind::TelemetryAttribute => {
            collector.record_attribute(kind, "job.note", secret);
        }
        SinkKind::Environment => {
            collector.record_environment("agent", [("HOME", "/home/agent"), ("API", secret)]);
        }
        SinkKind::ProcessArgument => {
            collector.record_arguments("docker", ["run", "--env", secret]);
        }
        SinkKind::OutboxRow | SinkKind::AuditRow | SinkKind::NatsMessage => {
            collector.record_json(
                kind,
                "events",
                &serde_json::json!({"payload": {"note": secret}}),
            );
        }
        _ => collector.record(kind, "planted", format!("before {secret} after")),
    }
}

#[test]
fn the_sweeper_finds_a_canary_planted_in_every_kind_of_sink() {
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    let kinds = [
        CanaryKind::GithubInstallationToken,
        CanaryKind::WebhookSecret,
        CanaryKind::ModelApiKey,
        CanaryKind::JobToken,
        CanaryKind::HoldoutString,
        CanaryKind::SecondTenantString,
        CanaryKind::DatabasePassword,
        CanaryKind::AppPrivateKey,
    ];
    for (i, sink_kind) in SinkKind::ALL.into_iter().enumerate() {
        // Rotate through the canary kinds so each sink is tried with a different secret.
        let canary = set.get(kinds[i % kinds.len()]);
        let collector = SinkCollector::new();
        fill_with_noise(&collector);
        plant(&collector, sink_kind, canary.value());

        let report = collector.sweep(&sweeper);
        let planted: Vec<_> = report
            .hits
            .iter()
            .filter(|h| h.canary == canary.label())
            .collect();
        assert_eq!(
            planted.len(),
            1,
            "a {} planted in {} was not found exactly once: {:?}",
            canary.label(),
            sink_kind.name(),
            report.hits
        );
        assert!(
            planted[0].sink.starts_with(sink_kind.name()),
            "the hit named {} instead of {}",
            planted[0].sink,
            sink_kind.name()
        );
        // The noise in the other fifteen sinks produced nothing else.
        assert_eq!(report.hits.len(), 1, "{:?}", report.hits);
    }
}

#[test]
fn every_kind_of_sink_is_covered_by_the_self_proof() {
    // If a kind is added to `SinkKind::ALL` it is planted in by the test above automatically.
    // This one makes sure `ALL` really lists every variant, by name, and that the names differ.
    let names: std::collections::BTreeSet<_> = SinkKind::ALL.iter().map(|k| k.name()).collect();
    assert_eq!(names.len(), SinkKind::ALL.len());
    for needed in [
        "stdout",
        "stderr",
        "log_line",
        "telemetry_attribute",
        "audit_row",
        "outbox_row",
        "nats_message",
        "database_dump",
        "artifact",
        "github_request",
        "pull_request_text",
        "captured_prompt",
        "api_response",
        "environment",
        "process_argument",
    ] {
        assert!(names.contains(needed), "no sink kind named {needed}");
    }
}

#[test]
fn a_clean_run_reports_clean_across_all_sinks() {
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    let collector = SinkCollector::new();
    fill_with_noise(&collector);
    collector.record_chunk(SinkKind::Stdout, "worker", "log line one\n");
    collector.record_chunk(SinkKind::Stdout, "worker", "log line two\n");
    let report = collector.sweep(&sweeper);
    report.assert_clean();
    assert_eq!(report.sinks_scanned, collector.len());
    assert!(report.bytes_scanned > 0);
    // An empty collector is clean too.
    SinkCollector::new().sweep(&sweeper).assert_clean();
}

#[test]
fn a_secret_in_a_different_encoding_is_found_in_a_sink() {
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    let token = set.get(CanaryKind::GithubInstallationToken).value();
    let collector = SinkCollector::new();
    fill_with_noise(&collector);
    // The token base64-encoded into an artifact, as a report generator might.
    collector.record(
        SinkKind::Artifact,
        "report.json",
        base64_encode(token.as_bytes(), Base64Alphabet::Standard, true),
    );
    let report = collector.sweep(&sweeper);
    assert!(
        report
            .hits
            .iter()
            .any(|h| h.canary == "github_installation_token" && h.form == Form::Base64Std)
    );
}

#[test]
fn a_secret_cut_by_a_chunk_boundary_is_found_only_within_one_stream() {
    let set = canaries();
    let sweeper = Sweeper::new(&set).with_marker_scan(false);
    let token = set.get(CanaryKind::JobToken).value().as_bytes();
    let (left, right) = token.split_at(17);

    // Both halves in the same stream: a leak.
    let one_stream = SinkCollector::new();
    one_stream.record_chunk(SinkKind::Stdout, "worker", left);
    one_stream.record_chunk(SinkKind::Stdout, "worker", right);
    assert_eq!(one_stream.sweep(&sweeper).hits.len(), 1);

    // Control: the halves in two different streams are not one secret anywhere.
    let two_streams = SinkCollector::new();
    two_streams.record_chunk(SinkKind::Stdout, "worker", left);
    two_streams.record_chunk(SinkKind::Stderr, "worker", right);
    two_streams.sweep(&sweeper).assert_clean();
}

#[test]
fn a_canary_from_another_run_is_not_this_runs_leak_but_its_marker_is_still_flagged() {
    let mine = canaries();
    let theirs = CanarySet::generate_with(&mut FxRng::from_seed(99));
    let collector = SinkCollector::new();
    collector.record(
        SinkKind::LogLine,
        "worker",
        theirs.get(CanaryKind::JobToken).value(),
    );
    // With the marker check off the sweeper only knows its own secrets.
    let marker_off = Sweeper::new(&mine).with_marker_scan(false);
    let their_token = theirs.get(CanaryKind::JobToken).value();
    assert!(
        marker_off.scan("x", their_token.as_bytes()).is_empty(),
        "another run's canary is not one of mine"
    );
    // With it on, the marker says a fake secret got out, whoever made it.
    let report = collector.sweep(&Sweeper::new(&mine));
    assert_eq!(report.hits.len(), 1);
    assert_eq!(report.hits[0].form, Form::Fragment);
}

#[test]
fn a_registered_value_such_as_a_minted_token_is_swept_for() {
    let set = canaries().with(Canary::custom(
        "minted-token",
        "ghs_minted_during_the_test_0001",
    ));
    let collector = SinkCollector::new();
    collector.record(
        SinkKind::PullRequestText,
        "pr-body",
        "see ghs_minted_during_the_test_0001 for details",
    );
    let report = collector.sweep(&Sweeper::new(&set));
    assert!(report.hits.iter().any(|h| h.canary == "minted-token"));
}

#[test]
fn a_cloned_collector_shares_one_store() {
    let a = SinkCollector::new();
    let b = a.clone();
    b.record(SinkKind::LogLine, "x", "hello");
    assert_eq!(a.len(), 1);
    assert!(!a.is_empty());
}

#[test]
fn the_json_description_is_labelled_fake_and_holds_no_content() {
    let set = canaries();
    let collector = SinkCollector::new();
    collector.record(
        SinkKind::Artifact,
        "report",
        set.get(CanaryKind::JobToken).value(),
    );
    let json = collector.to_json();
    assert_eq!(json["fidelity"], "fake");
    assert_eq!(json["entries"][0]["fidelity"], "fake");
    assert_eq!(json["entries"][0]["kind"], "artifact");
    assert!(
        !json
            .to_string()
            .contains(set.get(CanaryKind::JobToken).value())
    );
}

#[cfg(unix)]
#[test]
fn a_secret_in_a_process_argument_or_environment_is_found_through_the_spawn_recorder() {
    use crate::fx::spawn::{Behavior, SpawnPolicy, SpawnRecorder};
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    let mut recorder = SpawnRecorder::new(SpawnPolicy::docker_and_git()).unwrap();
    recorder.install("docker", &Behavior::Record).unwrap();
    recorder.install("git", &Behavior::Record).unwrap();

    // Clean starts first: nothing is reported.
    let run = |program: &str, args: &[&str], envs: &[(&str, &str)]| {
        let mut command = std::process::Command::new(program);
        command
            .args(args)
            .env_clear()
            .env("PATH", recorder.path_env());
        for (name, value) in envs {
            command.env(name, value);
        }
        assert!(command.status().unwrap().success());
    };
    run("docker", &["ps"], &[("HOME", "/home/agent")]);
    let clean = SinkCollector::new();
    clean.ingest_spawns(&recorder);
    clean.sweep(&sweeper).assert_clean();

    // Then a token on a command line, and another in an environment variable.
    let token = set.get(CanaryKind::GithubInstallationToken).value();
    let key = set.get(CanaryKind::ModelApiKey).value();
    let scheme = "https";
    run(
        "git",
        // The scheme is a variable so the source does not hold a URL with a password in it.
        &["push", &format!("{scheme}://x:{token}@github.com/o/r.git")],
        &[],
    );
    run("docker", &["run", "alpine"], &[("ANTHROPIC_API_KEY", key)]);
    let dirty = SinkCollector::new();
    dirty.ingest_spawns(&recorder);
    let report = dirty.sweep(&sweeper);
    let argument_hit = report
        .hits
        .iter()
        .find(|h| h.canary == "github_installation_token")
        .expect("the token on the command line is found");
    assert!(argument_hit.sink.starts_with("process_argument:git#"));
    let environment_hit = report
        .hits
        .iter()
        .find(|h| h.canary == "model_api_key")
        .expect("the key in the environment is found");
    assert!(environment_hit.sink.starts_with("environment:docker#"));
}

#[test]
fn the_whole_pipeline_fails_when_the_redactor_is_off() {
    // Deliberate break, end to end: a logger that redacts keeps the sinks clean, and the same
    // logger with redaction switched off leaks. The check passes with the control on and fails
    // with it off, which is what a security test must do.
    let set = canaries();
    let sweeper = Sweeper::new(&set);
    let secret = set.get(CanaryKind::ModelApiKey).value().to_owned();
    let outcome = prove_control_matters("FX-SINKS self-proof", "redactor", |controls| {
        let collector = SinkCollector::new();
        let line = format!("calling the model with {secret}");
        let written = if controls.is_on("redactor") {
            line.replace(&secret, "[REDACTED:anthropic_api_key]")
        } else {
            line
        };
        collector.record(SinkKind::LogLine, "worker", written);
        let report = collector.sweep(&sweeper);
        if report.is_clean() {
            Ok(())
        } else {
            Err(report.hits[0].to_string())
        }
    })
    .expect("the scenario depends on the redactor");
    assert!(outcome.failure_with_control_off.contains("model_api_key"));
}
