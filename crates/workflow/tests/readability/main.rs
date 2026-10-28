//! The readability gate against its rubric.
//!
//! The rubric is `docs/reference/documentation-policy.md`, the rule catalog
//! `fixtures/readability/rules.json` and the labelled corpus `fixtures/readability/cases/`. These
//! tests run the gate over every case and compare the set of rule ids and the verdict with the
//! labels. Where the gate and a label disagree the code is fixed, not the corpus.

mod catalog;
mod corpus;
mod corpus_tests;
