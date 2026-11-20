//! The context manifest: what the model was shown, and where each part came from.
//!
//! The manifest is the record the audit ledger binds a run to. It holds, for the prompt as a
//! whole, the hash of the finished text and the version and hash of the template it was made
//! from. For each input it holds the source, the trust tag, the class, the original and included
//! sizes, the hash of the original, how many hidden characters were removed, how many secrets
//! were replaced, and whether and how much was cut. It never holds a secret or any part of one,
//! and it holds no text of the inputs.

use factory_domain::values::{Sha256Digest, Timestamp};
use serde_json::{Value, json};

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
    /// The hash of the text as it was given. When `hash_is_of_redacted_text` is true it is the
    /// hash of the text after the replacement of the secrets and the cleaning, because a hash of
    /// text that held a secret would let a reader check a guess at the secret.
    pub original_sha256: Sha256Digest,
    /// Whether `original_sha256` is of the text after secrets were replaced.
    pub hash_is_of_redacted_text: bool,
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

impl Signal {
    fn to_json(&self) -> Value {
        match self {
            Self::HiddenTextDetected { input, count }
            | Self::DelimiterLookalike { input, count }
            | Self::PlaceholderSyntax { input, count } => {
                json!({"name": self.name(), "input": input, "count": count})
            }
            Self::SecretRedacted { input, count } => {
                json!({"name": self.name(), "input": input, "count": count})
            }
            Self::Truncated {
                input,
                omitted_bytes,
            } => json!({"name": self.name(), "input": input, "count": omitted_bytes}),
        }
    }
}

impl InputRecord {
    fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "class": self.class.as_str(),
            "trust": self.trust.as_str(),
            "source": self.source.as_ref().map(Source::to_json),
            "provided": self.provided,
            "paths": self.paths,
            "fetched_at": self.fetched_at.map(|t| t.as_text()),
            "original_bytes": self.original_bytes,
            "original_sha256": self.original_sha256.as_str(),
            "hash_is_of_redacted_text": self.hash_is_of_redacted_text,
            "included_bytes": self.included_bytes,
            "block_bytes": self.block_bytes,
            "stripped": self.stripped,
            "redacted": self.redacted,
            "truncated": self.truncated,
            "omitted_bytes": self.omitted_bytes,
        })
    }
}

impl Exclusion {
    fn to_json(&self) -> Value {
        let reason = match &self.reason {
            ExclusionReason::HiddenPath { rule, path } => {
                json!({"kind": "hidden_path", "rule": rule, "path": path})
            }
        };
        json!({"name": self.name, "source": self.source.to_json(), "reason": reason})
    }
}

impl ContextManifest {
    /// The record as a JSON value, for the audit ledger. Keys are in alphabetical order, so the
    /// same record always gives the same text. It holds no text of any input.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "agent": {"id": self.agent_id, "version": self.agent_version},
            "template": {
                "path": self.template.path,
                "version": self.template.version,
                "sha256": self.template.sha256.as_str(),
            },
            "prompt": {
                "sha256": self.prompt_sha256.as_str(),
                "bytes": self.prompt_bytes,
                "estimated_tokens": self.estimated_tokens,
                "budget_bytes": self.budget_bytes,
            },
            "inputs": self.inputs.iter().map(InputRecord::to_json).collect::<Vec<_>>(),
            "exclusions": self.exclusions.iter().map(Exclusion::to_json).collect::<Vec<_>>(),
            "signals": self.signals.iter().map(Signal::to_json).collect::<Vec<_>>(),
        })
    }

    /// The hash of the record. The ledger stores it to bind a run to what the model saw: the
    /// prompt hash is in it, and so are the template version and hash and the source of every
    /// input.
    #[must_use]
    pub fn sha256(&self) -> Sha256Digest {
        Sha256Digest::of(self.to_json().to_string().as_bytes())
    }

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
