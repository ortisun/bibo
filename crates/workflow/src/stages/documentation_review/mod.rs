//! The `DOCUMENTATION_REVIEW` stage: the Documentation Quality Gate, then an independent reviewer.
//!
//! Work package `s1-stage-documentation`. The stage judges the documents the `DOCUMENTING` stage
//! committed. Code decides what code can decide, in a fresh `verify` sandbox with no network:
//! internal links and anchors, examples run against the built program with their output compared,
//! the commands, flags and variables the pages name compared with the program's own `--help` and
//! with the source, planned pages, the changelog entry, undocumented changes, diagrams, secrets and
//! staleness. The readability gate reads the text. An independent reviewer judges what code cannot.
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | `verify` | Running the build, `--help`, the examples and the diagram parser in a fresh sandbox |
//! | `handler` | `DocumentationReviewHandler`, its configuration and its stage contract |
//! | `run` | `execute` |
//! | `gates` | `evaluate` |
//!
//! # Rules this stage keeps
//!
//! * **A check that did not run is not a pass.** A tool that is absent, a program that does not
//!   build and a sandbox that fails give `BLOCKED`. A check with nothing to look at gives
//!   `NOT_APPLICABLE` with the rule. Only a check that ran gives `PASSED` or `FAILED`.
//! * **External links are not fetched.** The sandbox has no network. They are counted in the report
//!   and none of them is called valid.
//! * **The reviewer is independent by type.** Its prompt is assembled from `IndependentInput`
//!   values, which cannot be made from an agent's account of its own work. The writer's result,
//!   which holds its claims, is withheld by hash. The reviewer receives the frozen specification,
//!   the plan, both patches and the gate reports.
//! * **A reviewer never overrides a gate.** The engine reads the verdict only after every report: a
//!   blocked gate blocks, a failed gate fails, and a `PASS` changes neither (NT-INJ-06).
//! * **A reviewer changes nothing.** It is granted only tools that read, and its checkout is a copy
//!   that is never ingested.
//! * **The documents are checked again when the code changes.** The binding check compares the code
//!   head the plan and the documentation commit were made over with the code head now, and the
//!   engine supersedes this stage whenever the implementation stage commits (ADR 0010).
//!
//! # Where defects go
//!
//! The route belongs to the engine. A finding carries a `defect_class`: `documentation` goes back
//! to `DOCUMENTING`, `code_behavior` to `IMPLEMENTATION`, and `specification` or `policy` to a
//! person. A failed deterministic check has no class and counts as a documentation defect. Two
//! rounds at most, then a person.

pub mod document;
mod gates;
pub mod handler;
pub(crate) mod run;
pub mod verify;

pub use document::{GateBinding, gate_document};
pub use handler::{
    DocumentationReviewConfig, DocumentationReviewDeps, DocumentationReviewHandler, GRANTED_TOOLS,
    gate_ids,
};
pub use run::{document_type, title_of};
pub use verify::DocsToolchain;
