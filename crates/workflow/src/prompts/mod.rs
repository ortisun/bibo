//! The prompt assembler: where text that other people or programs wrote enters a model prompt.
//!
//! Issue bodies, repository files, command output, web pages and anything a model wrote are all
//! untrusted. They reach a model only through this module, so this module is the main defence
//! against prompt injection (`policies/security.yaml`, `untrusted_content.prompt_assembly`;
//! ADR 0005; negative tests NT-INJ-02 and NT-SEC-11). It is pure: no clock, no file, no
//! randomness, no network. The same inputs always give the same bytes and the same hashes.
//!
//! # What it takes and what it gives
//!
//! An [`Assembler`] holds the job's redactor, the path policy and the [`Limits`]. A request names
//! the agent (its manifest and its prompt text, whose hash must equal the manifest's), a
//! [`Scope`] (the tenant, the kind of repository, texts to withhold) and the [`Input`]s. The
//! result is an [`Assembled`] prompt and a [`ContextManifest`] that the audit ledger can bind a
//! run to. A request that cannot be met gives an [`AssemblyError`] and no prompt.
//!
//! # What happens to an input
//!
//! In this order, for each input of the template:
//!
//! 1. It is matched to the template's table by name and class. An input the template does not
//!    declare, a duplicate, a class that differs and a required input that is missing are
//!    errors.
//! 2. It must belong to the job's tenant, and its hash must not be one the caller withholds.
//! 3. The repository paths it is made of are asked of the path policy for a read. A file that
//!    the policy hides (holdouts, secret-bearing files) or a path that cannot be checked leaves
//!    the input out, whole, and the manifest records the path and the rule. If the input is
//!    required, the assembly fails.
//! 4. Bytes that are not UTF-8 are **refused** (`InvalidUtf8`), not repaired. A lossy repair
//!    would change the data silently, and a binary file is not something to quote into a prompt.
//!    A stage that wants binary files skipped does so before it builds the input.
//! 5. The text is **redacted**, **cleaned** and **redacted again**. Cleaning turns every kind of
//!    line break into `\n` and removes hidden and direction-control characters
//!    (the `sanitize` module documents the set). The first pass sees the text as it was written,
//!    including a secret split by invisible characters. The second sees it as the model will.
//! 6. The text is **cut** if it is over its block limit or the prompt is over its budget. Redaction
//!    comes first, so a cut can never leave half of a secret. The cut is stated in the opening
//!    line of the block (`truncated=yes omitted=<bytes>`), raised as a signal and recorded in
//!    the manifest. See [`Limits`].
//! 7. The block is written, the whole prompt is read back and checked against the template and
//!    against what was meant, and the whole prompt is scanned for secrets once more. If the
//!    structure check fails, or a secret is found, or the redactor cannot check, no prompt is
//!    released (fail closed).
//!
//! # The delimiter, and why text cannot forge it
//!
//! ```text
//! <<<DATA name=request class=issue_text bytes=120 sha256=sha256:... stripped=0 redacted=0 truncated=no omitted=0>>>
//! > first line of the text
//! > second line of the text
//! <<<END name=request>>>
//! ```
//!
//! The delimiter is **not** a string chosen to be unlikely, and it is not secret. The text is
//! encoded instead: after cleaning, `\n` is the only line break, and every line of the text,
//! empty ones included, gets the prefix `> `. A line of data therefore always starts with `> `,
//! and the opening and closing line of a block always start with `<<<`. No line of data can
//! start with `<<<`, so no data can pass for a delimiter, a heading or a placeholder, whatever it
//! contains. Nothing in the opening line comes from the text: the name and class come from the
//! template, the rest are numbers and a hash the assembler computed. A template line that starts
//! with `<<<` is refused, so only blocks have such lines.
//!
//! `verify` re-reads every finished prompt line by line and refuses it unless the text outside
//! the blocks is the template (with trusted values in its slots), every block opens and closes
//! with exactly the lines meant, every line between them is quoted, and removing the prefixes
//! gives back exactly the text that was meant. The tests check the same properties with a
//! separate checker (`tests/prompts/check.rs`) that shares no code with the assembler.
//!
//! Placeholders in data are inert: the template is read once, and the replacement is a single
//! pass over the template's own lines.
//!
//! # Trust
//!
//! Every input is [`Trust::Untrusted`] unless it was made with [`Input::trusted_identifier`],
//! which accepts only a plain identifier. Both kinds fill a `{{input.<name>}}` line as a block.
//! Only a trusted value may fill a `{{trusted.<name>}}` slot in the instructions, and it is
//! checked against the grammar, never escaped. None of the nine agent templates has such a slot.
//!
//! # Reviewers
//!
//! A reviewer or critic judges the change, not the author's account of it. A prompt for such an
//! agent can only be built by [`Assembler::assemble_independent`], which takes
//! [`IndependentInput`]s. The only way to make one is [`Input::into_independent`], which refuses
//! a [`Source::SelfAssessment`]. The plain [`Assembler::assemble`] refuses reviewer roles. A
//! caller that gives a summary another label is caught only if it withholds the summary's hash
//! in the [`Scope`]; the label is the caller's claim.
//!
//! # Spec Kit
//!
//! [`speckit`] builds the input of a skill: a fixed instruction chosen by the operation alone,
//! with the request in a file or a delimited block. No byte of an issue is in the arguments.
//!
//! # What this does not defend against
//!
//! Delimiting text does not solve prompt injection. It makes sure that untrusted text cannot
//! change the structure of the prompt, and that the prompt says so to the model. Whether a model
//! then obeys an instruction that sits inside a block is up to the model.
//!
//! * A model can still follow an instruction in a quoted block. The fixed instruction asks it
//!   not to, and the controls around it (no secrets, tools granted by policy, the sandbox,
//!   host-computed diffs and independent gates) are what limit the harm. `Signal`s are
//!   telemetry for the injection detector of the policy, never a control.
//! * The `> ` prefix is a convention the model must understand. A model that treats a quoted
//!   line as an instruction is not stopped by the quoting.
//! * Look-alike letters (a Cyrillic "a"), text in another language, encoded text (base64 of an
//!   instruction) and instructions spread over many inputs pass untouched. Secrets in forms the
//!   redactor does not decode (double encoding, split over lines) are not found.
//! * A label the caller gives is trusted: the source of an input, its tenant, and whether it is
//!   a self-assessment are decided by the stage that builds the input.
//! * The token figure is an estimate with a fixed ratio, not the tokenizer of the model.
//! * Files the CLI reads on its own (for example `CLAUDE.md` in the checkout) are outside the
//!   envelope; the adapter's flags and the sandbox contain those.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod assemble;
mod block;
mod class;
mod error;
mod input;
mod limits;
mod manifest;
mod sanitize;
pub mod speckit;
mod template;
mod verify;

pub use assemble::{
    Assembled, Assembler, AssemblyRequest, IndependentRequest, Part, Scope, requires_independence,
};
pub use class::ContentClass;
pub use error::{AssemblyError, TemplateError};
pub use input::{IndependentInput, Input, LineRange, Source, Trust};
pub use limits::Limits;
pub use manifest::{
    ContextManifest, Exclusion, ExclusionReason, InputRecord, Signal, TemplateRecord,
};
pub use template::{InputSpec, MAX_INPUTS, Template};
