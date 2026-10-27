//! Secret redaction: the one component that keeps the factory's secrets out of everything it
//! stores or sends.
//!
//! `docs/security/secrets-and-credentials.md` section 7 requires one [`Redactor`] with one
//! implementation, used by every sink: the logging layer, the trace exporter, the outbox writer,
//! the artifact writer, the GitHub client, the prompt builder and the API serializer. A sink that
//! bypasses it is a defect. This module is that implementation. It is pure: it reads no file,
//! clock, environment or network, and it makes no random choice. It is built from data, and the
//! same input always gives the same output.
//!
//! # What it finds
//!
//! * **Exact values.** The secrets the factory loads or issues (job tokens, the webhook secret,
//!   the App key, database and broker credentials, installation tokens as they are minted) are
//!   registered with [`Redactor::register`]. Each one is looked for in the encodings the policy
//!   lists (`secrets.exact_values.encodings`): as written, in base64 (standard and URL-safe,
//!   with and without padding, and inside a longer base64 message at each of the three byte
//!   alignments), in hexadecimal, percent-encoded and escaped for JSON. An exact value needs no
//!   word boundary and no particular format. Values shorter than the policy minimum (8) are not
//!   registered.
//! * **Patterns.** The vendor formats in `secrets.patterns` are given to the builder as
//!   [`PatternSpec`] values and compiled as written. This crate holds no pattern of its own. A
//!   pattern with the action `block` marks a secret. A pattern with the action `flag`, and the
//!   entropy heuristic, only raise a flag: the text is left alone and the report says so.
//!   (`FlagHandling::Redact` is there for a sink that prefers to lose text.)
//!
//! # What it does about it
//!
//! * [`Redactor::redact`] and [`Redactor::redact_str`] replace each secret with the marker
//!   `[REDACTED:<id>]`, where `<id>` is the pattern identifier or the label given at
//!   registration. The marker never holds a fingerprint or any other part of the secret: the
//!   policy does not allow one, and a fingerprint of a weak secret lets a reader confirm a guess.
//! * [`Redactor::contains_secret`] answers whether text holds a secret, for the sinks that refuse
//!   to publish (pull request text, artifacts, domain events). [`Redactor::scan`] gives the
//!   [`Report`] without the text.
//! * [`Redactor::stream`] and [`Redactor::scan_stream`] do the same for input that arrives in
//!   chunks or is too large to hold. The result is the same whatever the chunk sizes, and memory
//!   stays bounded.
//!
//! # How it handles hard input
//!
//! * **Two views.** Every stream is read twice: as it is, and with terminal escape sequences and
//!   invisible characters taken out. A token with a colour code or a zero-width space between
//!   its characters is found in the second view, and the replaced span covers the noise inside
//!   it. See `terminal` for the exact model, which is the one the canary sweeper of the test kit
//!   reads with.
//! * **Chunk boundaries.** A match cut by a boundary is found, for the registry because the
//!   matcher keeps its state between bytes, and for patterns because the search runs over a
//!   window of the stream in blocks defined by position and never by chunk.
//! * **Overlap.** Matches that overlap are merged into one span and one marker, named by the
//!   match that starts first, then the longest, then the policy order. Matches that only touch
//!   stay separate.
//! * **Long matches.** A match that may go on past what the search could read stays open and
//!   takes the following bytes up to white space. A private key block stays open until its end
//!   line, or the end of the stream. A secret is therefore never left half covered.
//! * **Invalid UTF-8.** Patterns are compiled for bytes, and the registry works on bytes. Input
//!   that is not text is neither rejected nor changed except where a secret is.
//! * **Limits.** Memory is bounded by [`Limits`]. A stream that would have to hold back more
//!   than the limit (a token that never ends, a flood of invisible characters) fails with a
//!   [`RedactionError`], and so does a one-shot input over the size limit. The caller drops the
//!   content, as the policy says: raw text is never written because the redactor failed. The
//!   code never panics: indexing, unwrapping and `panic!` are denied for this module, and the
//!   tests feed it every byte value in random order.
//!
//! # What it does not do
//!
//! * A pattern written with a word boundary does not match a token glued to a word. Registered
//!   values do not have this limit, which is why the factory's own secrets are registered.
//! * It does not decode text that is encoded twice (base64 of hex of a secret), text that was
//!   wrapped over several lines, or text where letters are replaced by look-alike characters.
//! * It does not see a secret the registry has not been given, unless a pattern matches it.
//! * The registry's memory is overwritten when a value is forgotten, as far as the language
//!   lets a safe program do so. Crash dumps and swap are the host's business.
//! * A stream sees the secrets registered before it started.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod automaton;
mod config;
mod core;
mod encodings;
mod error;
mod patterns;
mod redactor;
mod registry;
mod report;
mod scan;
mod sink;
mod terminal;

pub use config::{EntropySpec, FlagHandling, Limits, PatternAction, PatternSpec};
pub use encodings::Encoding;
pub use error::{BuildError, RedactionError, RegistryError};
pub use redactor::{RedactStream, Redacted, RedactedStr, Redactor, RedactorBuilder, ScanStream};
pub use registry::{Registered, SecretHandle};
pub use report::{Finding, FindingSource, MAX_LISTED_FINDINGS, Report, Severity};
