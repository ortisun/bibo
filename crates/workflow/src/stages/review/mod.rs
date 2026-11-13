//! The `REVIEW` stage: an independent reviewer judges the change from evidence.
//!
//! Work package `s1-stage-implementation-and-review`. The stage gives the `code-reviewer` agent the
//! frozen specification, the patch the host exported between the two commits, and the gate reports
//! of the validation stage, in a read-only sandbox. It never gives it the builder's account of the
//! work. It checks the reviewer's answer against the schema of the agent, wraps it into the stored
//! `review-verdict` with the factory's own fields, deduplicates the findings, and hands the engine
//! two deterministic gates next to the verdict.
//!
//! # Map
//!
//! | Module | What it holds |
//! |---|---|
//! | `findings` | The reviewer's answer wrapped into the verdict, deduplicated, with identifiers the factory derives |
//! | `locate` | Which lines of a patch a finding may cite |
//! | `evidence` | The validation evidence read, and compared with the change under review |
//! | `handler` | `ReviewHandler`, its configuration and its stage contract |
//! | `run` | `execute` |
//! | `gates` | `evaluate` |
//! | `independence` | How far the reviewer's model was from the author's, as the record keeps it |
//!
//! # Rules this stage keeps
//!
//! * **The reviewer is independent by type.** Its prompt is assembled from `IndependentInput`
//!   values, which cannot be made from an agent's account of its own work. The builder's summary
//!   is not even read by this crate (`report::BuilderReport` has no field that holds it).
//! * **A reviewer never overrides a gate.** The validation reports are carried into this stage's
//!   own gate (`review-evidence-verified`). A failed or blocked report there decides first, in the
//!   engine's order, whatever the verdict says (NT-INJ-06).
//! * **A reviewer changes nothing.** It is granted only tools that read (the stage refuses a
//!   manifest that grants a tool that writes or runs a command), its checkout is its own copy that
//!   is never ingested, and the stage holds no push credential. The checkout is writable at the
//!   mount, because the sandbox port allows the `agent` profile nothing else; see
//!   `implementation::seams::WorkspaceAccess`.
//! * **A reviewer's output is never repaired.** An answer that fails the schema, the contract of
//!   the verdict or the citation check is invalid output.
//! * **The same problem is one finding.** Findings are merged by file, category and title, and
//!   identified by those three facts, so the engine's stagnation check sees the same set when the
//!   same problems come back.
//!
//! # Decisions that the specification leaves open
//!
//! * A reviewer still runs when a gate report failed. Its findings are extra feedback for the
//!   builder, and its verdict changes nothing.
//! * A verdict that the gate cannot trust (it names another patch, another specification or other
//!   gate reports, or cites lines the patch does not show) makes the gate `BLOCKED`, not `FAILED`:
//!   the work is not at fault, so it is not sent back.
//! * The rework route and the cap of two rounds belong to the engine. This stage supplies the
//!   `defect_class` of each finding and the stable identifiers.

pub mod evidence;
pub mod findings;
pub mod gates;
pub mod handler;
pub mod independence;
pub mod locate;
mod run;

pub use gates::{EVIDENCE_GATE, GROUNDED_GATE};
pub use handler::{GRANTED_TOOLS, RECORD, ReviewConfig, ReviewDeps, ReviewHandler, VERDICT};
