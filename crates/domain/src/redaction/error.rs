//! The errors of the redactor. None of them carries text from the input or a secret value.

use thiserror::Error;

/// A redactor could not be built from its settings.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BuildError {
    /// An identifier cannot be written inside the marker `[REDACTED:<id>]`.
    #[error(
        "{id:?} is not a usable identifier: use 1 to 64 letters, digits, underscores, hyphens or dots"
    )]
    InvalidId {
        /// The identifier that was offered.
        id: String,
    },
    /// Two patterns have the same identifier.
    #[error("two patterns have the identifier {id:?}")]
    DuplicateId {
        /// The repeated identifier.
        id: String,
    },
    /// A regular expression does not compile in the dialect of the Rust `regex` crate.
    #[error("the pattern {id} does not compile: {reason}")]
    InvalidPattern {
        /// The pattern identifier.
        id: String,
        /// The compiler's message.
        reason: String,
    },
    /// A regular expression matches the empty text, so it would match at every position.
    #[error("the pattern {id} matches the empty text, so it would match everywhere")]
    EmptyMatch {
        /// The pattern identifier.
        id: String,
    },
    /// The entropy settings cannot be used.
    #[error("the entropy settings are not usable: {reason}")]
    InvalidEntropy {
        /// What is wrong.
        reason: String,
    },
}

/// A secret value could not be registered.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RegistryError {
    /// The label cannot be written inside the marker `[REDACTED:<label>]`.
    #[error(
        "{label:?} is not a usable label: use 1 to 64 letters, digits, underscores, hyphens or dots"
    )]
    InvalidLabel {
        /// The label that was offered.
        label: String,
    },
    /// The value is longer than the limit.
    #[error("the value is longer than the limit of {max} bytes")]
    ValueTooLong {
        /// The limit.
        max: usize,
    },
    /// The registry already holds the most values it may.
    #[error("the registry already holds {max} values; forget the ones that are no longer needed")]
    TooManyValues {
        /// The limit.
        max: usize,
    },
    /// The registry would hold more search strings than the limit allows.
    #[error("the registry would hold more than {max} bytes of search strings")]
    TooLarge {
        /// The limit.
        max: usize,
    },
}

/// The redactor could not finish its work. The caller must drop the content: the policy says
/// that raw text is never written because the redactor failed (`redactor_failure`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RedactionError {
    /// The input is larger than the one-shot limit. Use a stream.
    #[error("the input is larger than the limit of {max} bytes; use a stream")]
    InputTooLarge {
        /// The limit.
        max: usize,
    },
    /// The stream would have to hold back more bytes than the limit allows, because of a very
    /// long unfinished token or block, or a long run of invisible characters and escape sequences.
    #[error("the stream would hold back more than {max} bytes; the content must be dropped")]
    PendingTooLarge {
        /// The limit.
        max: usize,
    },
    /// The stream failed earlier. It accepts nothing more.
    #[error("the stream failed earlier and accepts no more input")]
    StreamFailed,
    /// An internal check failed. The content must be dropped. This is a defect in the redactor.
    #[error("the redactor's internal bookkeeping failed; the content must be dropped")]
    Internal,
}
