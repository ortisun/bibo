//! What a redactor is built from.
//!
//! These types carry the settings of `secrets` in `policies/security.yaml`. They hold plain
//! data and read nothing: the code that loads the policy turns it into these values, and the
//! redactor never opens a file. The redactor keeps no pattern of its own. A redactor built from an
//! empty list finds nothing but the exact values that are registered with it.

/// What a match of a pattern does, as the policy says (`action`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternAction {
    /// A secret. Where the sink blocks, the content is refused. Where it redacts, the match is
    /// replaced.
    Block,
    /// A signal only. The match is reported and, unless the redactor is set to redact flagged
    /// matches, the text keeps it. The policy uses this for heuristics that would stop real work
    /// if they blocked.
    Flag,
}

/// One secret pattern from the policy: an identifier, a regular expression in the dialect of the
/// Rust `regex` crate, and what a match does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternSpec {
    /// The identifier. It appears in the marker `[REDACTED:<id>]`, so it is limited to 1 to 64
    /// letters, digits, `_`, `-` and `.`.
    pub id: String,
    /// The regular expression, exactly as the policy writes it.
    pub regex: String,
    /// What a match does.
    pub action: PatternAction,
}

impl PatternSpec {
    /// A pattern with the given identifier, expression and action.
    #[must_use]
    pub fn new(id: impl Into<String>, regex: impl Into<String>, action: PatternAction) -> Self {
        Self {
            id: id.into(),
            regex: regex.into(),
            action,
        }
    }
}

/// The entropy heuristic of the policy (`secrets.entropy_heuristic`): a long run of letters,
/// digits and the base64 and URL-safe punctuation whose Shannon entropy is high looks like a key.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntropySpec {
    /// The shortest run that is looked at, in bytes.
    pub min_length: usize,
    /// The least Shannon entropy, in bits per byte, that makes a run suspicious.
    pub min_bits_per_char: f64,
    /// What a hit does. The policy says `flag`.
    pub action: PatternAction,
}

/// What the redactor does with a match whose action is [`PatternAction::Flag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlagHandling {
    /// Report it and leave the text alone. This is what the policy says: a flag must not stop
    /// real work or change what a person reads.
    #[default]
    ReportOnly,
    /// Report it and replace it, as a secret is replaced. For a sink that prefers to lose text
    /// over keeping a doubtful value.
    Redact,
}

/// The size limits that keep the redactor's memory bounded.
///
/// A stream that would need more than a limit allows fails with an error and the caller drops
/// the content, as the policy says (`redactor_failure`). The redactor never writes text it was
/// unable to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes a stream holds back while it waits to learn whether they are part of a
    /// secret. Ordinary text holds back about 8 KiB (measured: at most 8191 bytes). A long
    /// unfinished token, a private key block with no end line, or a flood of escape sequences
    /// holds back more. The redactor raises a value below 24 KiB to 24 KiB, because a stream
    /// needs that much to do its work.
    pub max_pending_bytes: usize,
    /// The largest input the one-shot functions accept. Larger input goes through a stream.
    pub max_input_bytes: usize,
    /// The most secrets that can be registered at once.
    pub max_registry_values: usize,
    /// The longest secret that can be registered, in bytes.
    pub max_value_len: usize,
    /// The most bytes of search strings (every secret in every encoding) the registry may hold.
    pub max_registry_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_pending_bytes: 1 << 20,
            max_input_bytes: 256 << 20,
            max_registry_values: 1024,
            max_value_len: 4096,
            max_registry_bytes: 32 << 20,
        }
    }
}
