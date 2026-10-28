//! The embedded rule catalog is the file in `fixtures/readability/`, and it agrees with the code.

use factory_workflow::gates::readability::{Catalog, RULES_JSON, RuleId, Severity};

/// The file, read here with its own `include_str!`. The gate embeds the same path; if it pointed
/// at a copy or at an older file, this would differ.
const FILE: &str = include_str!("../../../../fixtures/readability/rules.json");

#[test]
fn the_embedded_catalog_is_the_file_in_fixtures() {
    assert_eq!(RULES_JSON, FILE);
}

#[test]
fn every_deterministic_rule_in_the_file_has_a_function_and_the_other_way_round() {
    let doc: serde_json::Value = serde_json::from_str(FILE).expect("rules.json is JSON");
    let in_file: std::collections::BTreeSet<&str> = doc["rules"]
        .as_array()
        .expect("rules")
        .iter()
        .filter(|rule| rule["mode"] == "deterministic")
        .filter_map(|rule| rule["id"].as_str())
        .collect();
    let in_code: std::collections::BTreeSet<&str> =
        RuleId::ALL.iter().map(|rule| rule.as_str()).collect();
    assert_eq!(in_file, in_code);
    assert_eq!(in_code.len(), 19);
}

#[test]
fn severity_comes_from_the_file_and_a_reviewer_rule_never_blocks() {
    let catalog = Catalog::embedded().expect("the catalog loads");
    let doc: serde_json::Value = serde_json::from_str(FILE).expect("rules.json is JSON");
    for rule in doc["rules"].as_array().expect("rules") {
        let id = rule["id"].as_str().expect("id");
        let severity = rule["severity"].as_str().expect("severity");
        if rule["mode"] == "deterministic" {
            let known = RuleId::parse(id).expect("a known rule");
            assert_eq!(catalog.severity(known).as_str(), severity, "{id}");
        } else {
            assert_eq!(severity, Severity::Warn.as_str(), "reviewer rule {id}");
        }
    }
}
