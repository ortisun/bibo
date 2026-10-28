//! The corpus run: every case, labels against findings.

use factory_workflow::gates::readability::{Catalog, Options, RuleId};

use crate::corpus::{FILES, run, run_with, samples};

fn rank(verdict: &str) -> u8 {
    match verdict {
        "pass" => 0,
        "warn" => 1,
        _ => 2,
    }
}

/// The rules implemented so far.
fn implemented(rule: RuleId) -> bool {
    matches!(
        rule,
        RuleId::TitleSchemaShape
            | RuleId::TitleOpaquePrefix
            | RuleId::TitleMachineLabel
            | RuleId::TitleVague
            | RuleId::TitleTypeTag
            | RuleId::TitleNotSentenceCase
            | RuleId::TitleTooLong
            | RuleId::TitleTrailingPunctuation
    )
}

#[test]
fn the_corpus_has_every_file_and_a_plausible_number_of_cases() {
    assert_eq!(FILES.len(), 9);
    assert!(
        samples().len() >= 137,
        "the corpus shrank: {} samples",
        samples().len()
    );
}

#[test]
fn every_case_matches_its_labels_for_the_rules_implemented_so_far() {
    let outcome = run(implemented);
    assert!(outcome.disagreements.is_empty(), "{}", outcome.describe());
    println!(
        "{} cases, {} matched exactly",
        outcome.cases, outcome.matched
    );
}

#[test]
fn a_case_never_labels_a_milder_verdict_than_its_deterministic_findings_give() {
    let catalog = Catalog::embedded().expect("the embedded catalog loads");
    for sample in samples() {
        let derived = crate::corpus::verdict_of(
            sample
                .breaks
                .iter()
                .filter_map(|id| RuleId::parse(id))
                .map(|rule| catalog.severity(rule)),
        );
        assert!(
            rank(derived) <= rank(&sample.verdict),
            "{}: labelled {} but its deterministic rules give {derived}",
            sample.id,
            sample.verdict
        );
    }
}

#[test]
fn the_corpus_notices_when_any_implemented_rule_stops_working() {
    let catalog = Catalog::embedded().expect("the embedded catalog loads");
    for rule in RuleId::ALL.iter().copied().filter(|r| implemented(*r)) {
        let outcome = run_with(&catalog, &Options::new(), implemented, |hidden| {
            hidden == rule
        });
        assert!(
            !outcome.disagreements.is_empty(),
            "no case fails when {} reports nothing, so the corpus does not test it",
            rule.as_str()
        );
        assert!(
            outcome
                .disagreements
                .iter()
                .all(|d| d.expected.contains(rule.as_str())),
            "hiding {} should only disturb the cases that break it",
            rule.as_str()
        );
    }
}
