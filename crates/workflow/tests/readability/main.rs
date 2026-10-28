//! The readability gate against its rubric.
//!
//! The rubric is `docs/reference/documentation-policy.md`, the rule catalog
//! `fixtures/readability/rules.json` and the labelled corpus `fixtures/readability/cases/`. These
//! tests run the gate over every case and compare the set of rule ids and the verdict with the
//! labels. Where the gate and a label disagree the code is fixed, not the corpus.
//!
//! Every module is named `readability_...`, so each test name contains the word and the filter
//! `cargo nextest run -p factory-workflow readability` runs these tests next to the unit tests.

#[path = "catalog.rs"]
mod readability_catalog;
#[path = "corpus.rs"]
mod readability_corpus;
#[path = "corpus_tests.rs"]
mod readability_corpus_tests;
#[path = "gate_tests.rs"]
mod readability_gate_tests;
#[path = "properties.rs"]
mod readability_properties;
#[path = "schema_check.rs"]
mod readability_schema_check;
