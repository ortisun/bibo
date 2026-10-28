//! The context manifest: what the model was shown, and where each part came from.
//!
//! The manifest is the record the audit ledger binds a run to. It holds, for the prompt as a
//! whole, the hash of the finished text and the version and hash of the template it was made
//! from. For each input it holds the source, the trust tag, the class, the original and included
//! sizes, the hash of the original, how many hidden characters were removed, how many secrets
//! were replaced, and whether and how much was cut. It never holds a secret or any part of one,
//! and it holds no text of the inputs.

use factory_domain::values::{Sha256Digest, Timestamp};

use super::class::ContentClass;
use super::input::{Source, Trust};

/// The prompt template an assembly used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateRecord {
    /// Where the template is stored, from the manifest of the agent.
    pub path: String,
    /// The version of the template.
    pub version: String,
    /// The hash of the template text.
    pub sha256: Sha256Digest,
}

/// One input as it went into the prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRecord {
    /// The name of the input.
    pub name: String,
    /// The class the template declares.
    pub class: ContentClass,
    /// Whether the factory made the value.
    pub trust: Trust,
    /// Where it came from, or `None` for an input that was not given.
    pub source: Option<Source>,
    /// Whether the input was given. An input that is not given, or that the path policy left
    /// out, has an empty block.
    pub provided: bool,
    /// The repository paths the text is made of.
    pub paths: Vec<String>,
    /// When the text was fetched, as the caller recorded it.
    pub fetched_at: Option<Timestamp>,
    /// The size of the text as it was given, in bytes.
    pub original_bytes: usize,
    /// The hash of the text as it was given.
    pub original_sha256: Sha256Digest,
    /// The size of the cleaned text that is in the block, in bytes.
    pub included_bytes: usize,
    /// The size of the block in the prompt, in bytes, opening and closing line included.
    pub block_bytes: usize,
    /// Hidden characters removed.
    pub stripped: usize,
    /// Secrets replaced by a marker. A count; never the secret.
    pub redacted: u64,
    /// Whether part of the cleaned text was left out.
    pub truncated: bool,
    /// How many bytes of the cleaned text were left out.
    pub omitted_bytes: usize,
}

/// Why an input was left out of the prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExclusionReason {
    /// The path policy hides a file the text is made of, or the path could not be checked.
    HiddenPath {
        /// The rule that decided, such as `protected_paths.groups:evaluation_holdouts`.
        rule: String,
        /// The path.
        path: String,
    },
}

/// An input that was not put into the prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exclusion {
    /// The name of the input.
    pub name: String,
    /// Where it came from.
    pub source: Source,
    /// Why.
    pub reason: ExclusionReason,
}

/// Something the assembler noticed. A signal informs the audit record and the injection signal
/// detector of the policy; it never decides anything by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signal {
    /// Hidden or direction-control characters were found and removed.
    HiddenTextDetected {
        /// The input.
        input: String,
        /// How many characters.
        count: usize,
    },
    /// The text holds lines that look like the opening or closing line of a block.
    DelimiterLookalike {
        /// The input.
        input: String,
        /// How many lines.
        count: usize,
    },
    /// The text holds placeholder syntax.
    PlaceholderSyntax {
        /// The input.
        input: String,
        /// How many places.
        count: usize,
    },
    /// Secrets were found and replaced.
    SecretRedacted {
        /// The input.
        input: String,
        /// How many replacements.
        count: u64,
    },
    /// Part of the text was left out.
    Truncated {
        /// The input.
        input: String,
        /// How many bytes.
        omitted_bytes: usize,
    },
}

impl Signal {
    /// The name used in the audit record.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::HiddenTextDetected { .. } => "hidden_text_detected",
            Self::DelimiterLookalike { .. } => "delimiter_lookalike",
            Self::PlaceholderSyntax { .. } => "placeholder_syntax",
            Self::SecretRedacted { .. } => "secret_redacted",
            Self::Truncated { .. } => "truncated",
        }
    }
}

/// The record of one assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextManifest {
    /// The agent.
    pub agent_id: String,
    /// The version of the agent.
    pub agent_version: String,
    /// The template.
    pub template: TemplateRecord,
    /// The hash of the finished prompt text.
    pub prompt_sha256: Sha256Digest,
    /// The size of the finished prompt in bytes.
    pub prompt_bytes: usize,
    /// The estimated tokens of the prompt.
    pub estimated_tokens: u64,
    /// The byte budget the prompt had to fit.
    pub budget_bytes: usize,
    /// One record for each input of the template, in the order of the blocks.
    pub inputs: Vec<InputRecord>,
    /// The inputs left out.
    pub exclusions: Vec<Exclusion>,
    /// What the assembler noticed, in the order of the inputs.
    pub signals: Vec<Signal>,
}

impl ContextManifest {
    /// The record of the input with this name.
    #[must_use]
    pub fn input(&self, name: &str) -> Option<&InputRecord> {
        self.inputs.iter().find(|i| i.name == name)
    }

    /// Whether a signal with this name was raised.
    #[must_use]
    pub fn has_signal(&self, name: &str) -> bool {
        self.signals.iter().any(|s| s.name() == name)
    }
}
