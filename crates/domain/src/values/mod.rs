//! Value types: identifiers' building blocks, hashes, timestamps, text, versions, numbers and
//! counted collections.
//!
//! Every type here is checked when it is created or read, so holding one is proof that it is
//! valid. None of them reads the clock or makes a random value.

mod collections;
mod numbers;
mod text;
mod timestamp;

use std::sync::LazyLock;

use regex::Regex;

use crate::error::ValueError;
use crate::patterns;

pub use collections::{NonEmptyVec, UniqueVec};
pub use numbers::{
    Bounded, Integer, NonNegativeInt, NonNegativeNumber, PositiveFraction, PositiveInt,
    PositiveNumber, UnitInterval,
};
pub use text::{
    BoundedString, EventType, GitSha, HumanText, HumanTitle, MediaType, NonEmptyString,
    SemanticVersion, Sha256Digest, Slug, SpanId, TraceId, Traceparent, TransitionId, Uri,
};
pub use timestamp::Timestamp;

static UUID_SHAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(patterns::UUID).expect("a schema pattern is a valid regex"));

/// Reads the one UUID spelling the schemas allow: 36 characters, lowercase, hyphenated.
///
/// The `uuid` crate would also accept upper case, braces, a `urn:uuid:` prefix and the form
/// without hyphens. Two spellings of one identifier would break equality of stored documents, so
/// they are refused here.
///
/// # Errors
/// Returns a [`ValueError`] that names `what` for any other spelling.
pub fn parse_uuid(what: &'static str, text: &str) -> Result<uuid::Uuid, ValueError> {
    let rule = "use 36 lowercase hex characters with hyphens, such as 018f3a7e-5c1b-7d2e-9a4f-3b6c8d1e2f40";
    if !UUID_SHAPE.is_match(text) {
        return Err(ValueError::new(what, text, rule));
    }
    uuid::Uuid::parse_str(text).map_err(|_| ValueError::new(what, text, rule))
}
