//! Removal of secrets from text that is about to leave the process as telemetry.
//!
//! The security documents call for one `Redactor` with one implementation, `domain::redaction`,
//! used by every sink: the logging layer, the trace exporter, the outbox writer, the artifact
//! writer, the GitHub client, the prompt builder and the API serializer. This module is the seam
//! between that redactor and the telemetry pipeline (ADR 0013, decision 2).
//!
//! * [`Scrub`] is the trait the pipeline depends on. The attribute guard, the log writer and the
//!   configuration take an `Arc<dyn Scrub>`, so the pipeline never names a particular redactor.
//! * [`RedactorScrubber`] implements it over `domain::redaction::Redactor`. The composition root
//!   builds the redactor from the loaded policy and the registry of the factory's own secret
//!   values and hands it to [`crate::telemetry::TelemetryConfig::new`], which has no default and
//!   no way to leave the scrubber out.
//!
//! This crate holds no pattern of its own. An earlier baseline carried a hand-written scrubber that
//! mirrored `policies/security.yaml` and a test that kept the two equal. Both are gone: two copies
//! of the patterns drift, and the old one knew nothing of the factory's own secret values.
//!
//! The redactor is shared, not copied. A secret registered after the pipeline was built, such as
//! a job token the broker issues, is found by the next call, because the seam holds the same
//! redactor and the redactor reads its registry on every call.
//!
//! # What a failure means
//!
//! A redactor can refuse an input (it is larger than the redactor's limit, or its internal checks
//! failed). The seam reports that as [`ScrubError::Unavailable`], and every caller in this crate
//! then drops the value: the attribute guard replaces it, and the log writer replaces the line.
//! The original text is never passed on because the redactor failed.

use factory_domain::redaction::Redactor;
use std::borrow::Cow;
use std::sync::Arc;

/// The text that replaces a match is `[REDACTED:<pattern id or label>]`. This is the marker the
/// redactor writes, named here so a test can recognise it.
pub const PLACEHOLDER_PREFIX: &str = "[REDACTED:";

/// Why a scrubber could not do its job.
///
/// A caller must treat this as "drop the value". It must never pass the original text on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScrubError {
    /// The redactor behind the scrubber is not available.
    Unavailable,
}

impl std::fmt::Display for ScrubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScrubError::Unavailable => f.write_str("the redactor is not available"),
        }
    }
}

impl std::error::Error for ScrubError {}

/// Something that removes secrets from text.
///
/// The telemetry pipeline depends on this trait and not on a particular redactor.
pub trait Scrub: Send + Sync + std::fmt::Debug {
    /// The text with every secret replaced. Returns the input itself, without a copy, when it
    /// holds nothing to remove.
    fn scrub<'a>(&self, text: &'a str) -> Result<Cow<'a, str>, ScrubError>;
}

/// The [`Scrub`] seam over the factory's redactor.
///
/// Cloning is cheap and shares the redactor and its registry.
#[derive(Clone)]
pub struct RedactorScrubber {
    redactor: Arc<Redactor>,
}

impl RedactorScrubber {
    /// Wraps the redactor that every sink of this process shares.
    #[must_use]
    pub fn new(redactor: Arc<Redactor>) -> Self {
        Self { redactor }
    }

    /// The redactor behind the seam.
    #[must_use]
    pub fn redactor(&self) -> &Arc<Redactor> {
        &self.redactor
    }
}

/// The debug form names the type only. The redactor's own debug form counts its patterns and
/// registered secrets, and a count is more than a log line needs to say.
impl std::fmt::Debug for RedactorScrubber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RedactorScrubber")
    }
}

impl Scrub for RedactorScrubber {
    fn scrub<'a>(&self, text: &'a str) -> Result<Cow<'a, str>, ScrubError> {
        // The report is dropped on purpose: it names what was found, and this seam returns text.
        self.redactor
            .redact_str(text)
            .map(|redacted| redacted.output)
            .map_err(|_| ScrubError::Unavailable)
    }
}
