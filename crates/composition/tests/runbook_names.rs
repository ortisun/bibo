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

use telemetry_scan::{CONVENTIONS, production_sources, repository_root, table};

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

/// The names the runbook gives in backticks, cut at a brace or an equals sign.
fn runbook_names() -> BTreeSet<String> {
    backticked(RUNBOOK)
        .into_iter()
        .filter_map(|token| {
            let name = token.split(['{', '=', ' ']).next().unwrap_or_default();
            (name.starts_with("factory.") || name.starts_with("factory_")).then(|| name.to_owned())
        })
        .collect()
}

/// Names that production code writes only through a helper of the observability crate, which the
/// composition root calls: the job span and its tenant attribute. The test below checks the call.
const WRITTEN_BY_THE_JOB_HELPER: &[&str] = &["factory.job", "factory.tenant_id"];

#[test]
fn every_name_the_runbook_gives_is_written_by_production_code() {
    // The runbook lists what exists. A name there that no code writes would be a signal that an
    // operator looks for and never finds, which is the defect the gap tests exist to prevent. A
    // span or an attribute must be written as a literal outside the observability crate (the
    // other crates cannot import its constants); a metric is written as an instrument field,
    // `monotonic_counter.<name>`, `histogram.<name>` or `gauge.<name>`, in any crate.
    let sources = production_sources();
    let names = runbook_names();
    assert!(names.len() >= 20, "the reader found only {names:?}");
    for name in &names {
        if WRITTEN_BY_THE_JOB_HELPER.contains(&name.as_str()) {
            assert!(
                sources.iter().any(|(path, text)| {
                    !path.starts_with("crates/observability/") && text.contains("job_stretch_span")
                }),
                "{name} is written by the job helper, and no crate outside observability calls it"
            );
        } else if name.starts_with("factory_") {
            let written = ["monotonic_counter.", "histogram.", "gauge."]
                .iter()
                .any(|prefix| {
                    let field = format!("{prefix}{name}");
                    sources.iter().any(|(_, text)| text.contains(&field))
                });
            assert!(
                written,
                "the runbook names the metric `{name}`, which no code records"
            );
        } else {
            assert!(
                sources.iter().any(|(path, text)| {
                    !path.starts_with("crates/observability/") && text.contains(name.as_str())
                }),
                "the runbook names `{name}`, which no crate outside observability writes"
            );
        }
    }
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

/// The gap numbers (`OBS-n`) that `text` names.
fn gap_numbers(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !(c.is_alphanumeric() || c == '-'))
        .filter(|word| {
            word.strip_prefix("OBS-").is_some_and(|number| {
                !number.is_empty() && number.chars().all(|c| c.is_ascii_digit())
            })
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_gap_reader_finds_the_numbers_in_a_sentence() {
    // The runbook no longer needs to cite six gaps, since they are being closed, so this proves
    // the reader on a fixed text and not on how many gaps are left.
    let found = gap_numbers("see (OBS-3), `OBS-10`; not OBS-, OBS-x or XOBS-4.");
    assert_eq!(
        found.into_iter().collect::<Vec<_>>(),
        ["OBS-10", "OBS-3"],
        "the reader is broken"
    );
}

#[test]
fn every_gap_the_runbook_cites_has_an_ignored_test_with_its_number() {
    // A gap that is closed has no ignored test and no "Not yet emitted" line in the runbook.
    let sources = test_sources();
    for gap in gap_numbers(RUNBOOK) {
        let marker = format!("#[ignore = \"confirmed gap {gap}:");
        assert!(
            sources.iter().any(|text| text.contains(&marker)),
            "the runbook cites {gap} but no ignored test carries it: if the gap is closed, \
             move the signal into the \"What exists\" list and drop the number"
        );
    }
}

#[test]
fn the_conventions_page_marks_a_gap_fixed_exactly_when_its_test_is_no_longer_ignored() {
    // The gap list of the conventions page says "(fixed)" for each closed gap. A gap marked fixed
    // must have no ignored test left, and a gap not marked fixed must still have one, so the page
    // and the tests cannot disagree about what remains.
    let sources = test_sources();
    let mut seen = 0;
    for line in CONVENTIONS.lines() {
        let line = line.trim_start();
        let Some(item) = line.strip_prefix("- OBS-") else {
            continue;
        };
        let gap = format!(
            "OBS-{}",
            item.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
        );
        let fixed = line.starts_with(&format!("- {gap} (fixed)"));
        let marker = format!("#[ignore = \"confirmed gap {gap}:");
        let still_ignored = sources.iter().any(|text| text.contains(&marker));
        seen += 1;
        assert_eq!(
            fixed,
            !still_ignored,
            "{gap} is {} on the conventions page and {} in the tests",
            if fixed { "fixed" } else { "open" },
            if still_ignored {
                "still ignored"
            } else {
                "not ignored"
            }
        );
    }
    assert!(seen >= 10, "the reader found only {seen} gaps");
}
