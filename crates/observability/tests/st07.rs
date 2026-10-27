//! Check ST-07 from the negative test catalog: every metric, log and trace field name used in code
//! is on the attribute allowlist.
//!
//! This file checks the names this crate defines and uses. The names that other crates use in
//! their own `tracing` calls are checked by the repository-wide scan and by the trace tests of
//! work package `s1-observability-instrumentation`; neither exists yet.

mod common;

use common::{CONVENTIONS, table};
use factory_observability::metrics::{LABELS, METRICS};
use factory_observability::names::{self, ATTRIBUTES, SPANS};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

fn source_files() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    for entry in fs::read_dir(&root).expect("read src") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            let text = fs::read_to_string(&path).expect("read source file");
            files.push((path.display().to_string(), text));
        }
    }
    assert!(files.len() >= 8, "found only {} source files", files.len());
    files
}

/// Every string literal in `text` that starts with `factory.` or `factory_`.
fn factory_literals(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find('"') {
        rest = &rest[at + 1..];
        let end = rest.find('"').unwrap_or(rest.len());
        let literal = &rest[..end];
        if (literal.starts_with("factory.") || literal.starts_with("factory_"))
            && literal
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.')
        {
            found.push(literal.to_string());
        }
        rest = &rest[(end + 1).min(rest.len())..];
    }
    found
}

#[test]
fn st_07_field_names_are_allowlisted() {
    // 1. Every name the crate declares is on the list that the exporter and the metric view use.
    for span in SPANS {
        assert!(span.name.starts_with("factory."), "{}", span.name);
    }
    for attribute in ATTRIBUTES {
        assert!(
            names::is_allowed_attribute(attribute.key),
            "{}",
            attribute.key
        );
        assert!(
            names::is_allowed_log_field(attribute.key),
            "{}",
            attribute.key
        );
    }
    assert!(names::is_allowed_log_field("message"));
    assert!(names::is_allowed_log_field(names::CORRELATION_LOG_FIELD));
    for rogue in [
        "prompt",
        "issue_body",
        "authorization",
        "password",
        "job_id",
    ] {
        assert!(!names::is_allowed_attribute(rogue), "{rogue}");
        assert!(!names::is_allowed_log_field(rogue), "{rogue}");
        assert!(!names::is_allowed_event_attribute(rogue), "{rogue}");
    }
    for key in names::EVENT_ATTRIBUTES {
        assert!(names::is_allowed_event_attribute(key), "{key}");
        assert!(
            !names::is_allowed_attribute(key),
            "{key} is allowed on events only"
        );
    }
    let label_names: BTreeSet<&str> = LABELS.iter().map(|l| l.name).collect();
    for metric in METRICS {
        for label in metric.labels {
            assert!(
                label_names.contains(label),
                "{} uses unknown label {label}",
                metric.name
            );
        }
    }

    // 2. Every `factory.` or `factory_` literal in the source is a declared name. A typo or a new
    // name added without a table entry shows up here.
    let mut declared: BTreeSet<String> = BTreeSet::new();
    declared.extend(SPANS.iter().map(|s| s.name.to_string()));
    declared.extend(ATTRIBUTES.iter().map(|a| a.key.to_string()));
    declared.extend(METRICS.iter().map(|m| m.name.to_string()));
    for (path, text) in source_files() {
        for literal in factory_literals(&text) {
            assert!(
                declared.contains(&literal),
                "{path} uses the name {literal:?}, which is not in the span, attribute or metric tables"
            );
        }
    }
}

#[test]
fn the_factory_literal_scanner_finds_what_it_should() {
    let sample = r#"let a = "factory.job"; let b = "factory_retries_total"; let c = "factory-observability"; let d = "other"; let e = "factory.Bad";"#;
    assert_eq!(
        factory_literals(sample),
        ["factory.job", "factory_retries_total"]
    );
}

#[test]
fn conventions_page_event_attribute_table_equals_the_constants() {
    let from_page: Vec<String> = table(CONVENTIONS, "event-attributes")
        .iter()
        .map(|row| row[0].clone())
        .collect();
    let from_code: Vec<String> = names::EVENT_ATTRIBUTES
        .iter()
        .map(|k| k.to_string())
        .collect();
    assert_eq!(from_page, from_code);
}

#[test]
fn conventions_page_outcome_values_equal_the_constants() {
    let from_page: Vec<String> = table(CONVENTIONS, "outcomes")
        .iter()
        .map(|row| row[0].clone())
        .collect();
    let from_code: Vec<String> = names::OUTCOMES.iter().map(|k| k.to_string()).collect();
    assert_eq!(from_page, from_code);
}
