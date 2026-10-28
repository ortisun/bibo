//! The runbook for the first run names only things that exist (package
//! `s1-observability-instrumentation`).
//!
//! `docs/observability/runbook-first-run-signals.md` tells an operator which span, metric and log
//! line to look for. These tests keep it honest, without running a collector:
//!
//! * every `factory.` and `factory_` name in backticks is a span, an attribute key or a metric of
//!   the conventions page;
//! * every log message the runbook quotes is written by some production source file;
//! * every gap number the runbook cites (OBS-n) has an ignored test that carries the number.
//!
//! They do not prove that a query returns what the page says. That needs a running stack, and the
//! page says so.

mod telemetry_scan;

use std::collections::BTreeSet;

use telemetry_scan::{production_sources, repository_root, table};

const RUNBOOK: &str = include_str!("../../../docs/observability/runbook-first-run-signals.md");

/// The log messages the runbook quotes, as production code writes them.
const LOG_MESSAGES: &[&str] = &[
    "the sweep recovered attempts",
    "the sweep failed and will be tried again",
    "worker loop started",
    "worker loop stopped",
    "the final output was dropped because the redactor could not finish",
    "is not on the allowlist or has an unknown type; it was dropped",
];

/// The text between each pair of backticks.
fn backticked(text: &str) -> Vec<String> {
    text.split('`')
        .enumerate()
        .filter(|(index, _)| index % 2 == 1)
        .map(|(_, piece)| piece.to_owned())
        .collect()
}

fn known_names() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for row in table("spans") {
        names.insert(row[0].clone());
    }
    for row in table("attributes") {
        names.insert(row[0].clone());
    }
    for row in table("metrics") {
        names.insert(row[0].clone());
    }
    names
}

#[test]
fn every_factory_name_in_the_runbook_is_on_the_conventions_page() {
    let known = known_names();
    let mut seen = 0;
    for token in backticked(RUNBOOK) {
        // `factory_gate_failures_total{gate,outcome}` and `factory.outcome` = `lease_lost` style.
        let name = token.split(['{', '=', ' ']).next().unwrap_or_default();
        if name.starts_with("factory.") || name.starts_with("factory_") {
            seen += 1;
            assert!(
                known.contains(name),
                "the runbook names `{name}`, which is not a span, attribute or metric of the \
                 conventions page"
            );
        }
    }
    assert!(
        seen >= 15,
        "the reader found only {seen} names; it is broken"
    );
}

#[test]
fn every_log_message_the_runbook_quotes_is_written_by_production_code() {
    let sources = production_sources();
    for message in LOG_MESSAGES {
        assert!(
            RUNBOOK.contains(message),
            "the runbook no longer quotes \"{message}\": remove it from LOG_MESSAGES"
        );
        assert!(
            sources.iter().any(|(_, text)| text.contains(message)),
            "no production code writes \"{message}\", but the runbook quotes it"
        );
    }
}

/// The log lines of the redactor and the log writer in the observability crate are quoted too.
#[test]
fn the_failure_lines_of_the_redactor_are_written_by_the_observability_crate() {
    let sources = production_sources();
    for message in [
        "log line dropped: redactor unavailable",
        "[REDACTED:scrubber_unavailable]",
    ] {
        assert!(RUNBOOK.contains(message), "{message}");
        assert!(
            sources
                .iter()
                .any(|(path, text)| path.starts_with("crates/observability/")
                    && text.contains(message)),
            "the observability crate does not write \"{message}\""
        );
    }
}

/// Every file under `crates` and `apps` that can hold a test, read as text.
fn test_sources() -> Vec<String> {
    fn walk(dir: &std::path::Path, into: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk(&path, into);
            } else if path.extension().is_some_and(|e| e == "rs")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                into.push(text);
            }
        }
    }
    let mut found = Vec::new();
    for group in ["crates", "apps"] {
        walk(&repository_root().join(group), &mut found);
    }
    found
}

#[test]
fn every_gap_the_runbook_cites_has_an_ignored_test_with_its_number() {
    let sources = test_sources();
    let mut cited = BTreeSet::new();
    for word in RUNBOOK.split(|c: char| !(c.is_alphanumeric() || c == '-')) {
        if let Some(number) = word.strip_prefix("OBS-")
            && number.chars().all(|c| c.is_ascii_digit())
            && !number.is_empty()
        {
            cited.insert(word.to_owned());
        }
    }
    assert!(cited.len() >= 6, "the reader found only {cited:?}");
    for gap in &cited {
        let marker = format!("#[ignore = \"confirmed gap {gap}:");
        assert!(
            sources.iter().any(|text| text.contains(&marker)),
            "the runbook cites {gap} but no ignored test carries it"
        );
    }
}
