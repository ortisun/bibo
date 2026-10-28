//! The prompt assembler (`s1-prompt-assembly`).
//!
//! This is where text that other people or programs wrote enters a model prompt, so it is the main
//! defence against prompt injection. The tests here run the real assembler over the nine real
//! agent definitions (`agents/*/manifest.json` and `prompt.md`, read at compile time) and the real
//! policy (`policies/security.yaml` as kept in `crates/domain/tests/fixtures/policy`).
//!
//! Every module is named `prompts_...`, so each test name contains the word and the filter
//! `cargo nextest run -p factory-workflow prompts` runs these tests next to the unit tests of
//! `src/prompts`.
//!
//! The four done-criteria of the work package have a test each, found by these names:
//! `negative_nt_inj_02`, `negative_nt_sec_11`, `spec_kit_input_is_a_fixed_instruction` and
//! `envelope_collision_check`.

#[path = "check.rs"]
mod prompts_check;
#[path = "envelope.rs"]
mod prompts_envelope;
#[path = "exclusion.rs"]
mod prompts_exclusion;
#[path = "limits.rs"]
mod prompts_limits;
#[path = "redaction.rs"]
mod prompts_redaction;
#[path = "support.rs"]
mod prompts_support;
#[path = "template.rs"]
mod prompts_template;
