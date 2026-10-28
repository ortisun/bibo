//! The Documentation Quality Gate: the deterministic part of the documentation checks.
//!
//! Work package `s1-stage-documentation`. `docs/reference/documentation-policy.md` (sections 8 and
//! 9.8) says which documents a change needs and which checks decide whether they are good enough.
//! This module is the code side, and it is pure: it reads text and observations and returns
//! outcomes. The stages run the program in the verify sandbox and hand in what they saw.
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | [`plan`] | The documentation impact policy and the typed documentation plan, with its schema |
//! | [`markdown`] | A small reader for headings, links, fenced blocks and code spans |
//! | [`links`] | Internal links and anchors. External links are counted and never called valid |
//! | [`claims`] | The commands, flags and variables a page names, and the examples it shows |
//! | [`check`] | The nine checks and their four outcomes |
//!
//! The readability of the text is checked by [`crate::gates::readability`], not here.

pub mod check;
pub mod claims;
pub mod links;
pub mod markdown;
pub mod plan;

pub use check::{
    CheckResult, DiagramBlock, DiagramRun, Finding, Inputs, Needs, Observations, Observed, Ran,
    Verdict, needs, run,
};
pub use plan::{
    Audience, Binding, ChangedFile, DocPlan, Facts, Form, Interface, Item, ItemKind, Kind,
    NotApplicable, PlanError, derive, parse_patch, validate,
};
