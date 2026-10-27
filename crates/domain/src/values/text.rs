//! Strings with a shape: identifiers, hashes, titles, prose and versions.

use std::sync::LazyLock;

use regex::Regex;

use crate::error::ValueError;
use crate::macros::{patterned_string, string_traits};
use crate::patterns;

patterned_string! {
    /// A machine-safe identifier: lowercase letters, digits, dot, underscore and hyphen, 1 to 64
    /// characters. For metadata fields. Never a human-facing title.
    pub struct Slug("slug") = patterns::SLUG,
        "use 1 to 64 lowercase letters, digits, dots, underscores or hyphens, starting and ending with a letter or digit"
}

patterned_string! {
    /// A full Git object id: 40 or 64 lowercase hex characters.
    pub struct GitSha("Git object id") = patterns::GIT_SHA,
        "use exactly 40 or 64 lowercase hex characters"
}

patterned_string! {
    /// A media type such as `application/json`. Parameters such as a charset are not allowed.
    pub struct MediaType("media type") = patterns::MEDIA_TYPE,
        "use lowercase `type/subtype` with no parameters"
}

patterned_string! {
    /// An OpenTelemetry trace id: 32 lowercase hex characters.
    pub struct TraceId("trace id") = patterns::TRACE_ID,
        "use exactly 32 lowercase hex characters"
}

patterned_string! {
    /// An OpenTelemetry span id: 16 lowercase hex characters.
    pub struct SpanId("span id") = patterns::SPAN_ID,
        "use exactly 16 lowercase hex characters"
}

patterned_string! {
    /// A W3C Trace Context `traceparent` value, so a consumer can continue the trace.
    pub struct Traceparent("traceparent") = patterns::TRACEPARENT,
        "use the W3C form `00-<32 hex>-<16 hex>-<2 hex>` in lowercase"
}

patterned_string! {
    /// The id of a transition in `state-machine.json`: one of `J`, `S`, `A`, `T` and two digits.
    pub struct TransitionId("transition id") = patterns::TRANSITION_ID,
        "use J, S, A or T followed by two digits, for example S08"
}

static EVENT_TYPE_SHAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(patterns::EVENT_TYPE).expect("a schema pattern is a valid regex"));

/// The one event name that looks like a domain event and is not one.
const HEARTBEAT_EVENT: &str = "attempt.heartbeat";

/// A domain event type in the form `aggregate.past_tense_verb`, for example `stage_run.passed`.
///
/// Heartbeats are not domain events, so `attempt.heartbeat` is refused.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventType(String);

impl EventType {
    /// Reads an event type.
    ///
    /// # Errors
    /// Returns a [`ValueError`] when the text is not `aggregate.verb` or is the heartbeat.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        const WHAT: &str = "event type";
        if text == HEARTBEAT_EVENT {
            return Err(ValueError::new(WHAT, text, "heartbeats are not domain events"));
        }
        if !EVENT_TYPE_SHAPE.is_match(text) {
            return Err(ValueError::new(
                WHAT,
                text,
                "use `aggregate.past_tense_verb` in lowercase, for example stage_run.passed",
            ));
        }
        Ok(Self(text.to_owned()))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

string_traits!(EventType);

patterned_string! {
    /// The content hash of bytes, written `sha256:` and 64 lowercase hex characters.
    pub struct Sha256Digest("SHA-256 digest") = patterns::SHA256,
        "use `sha256:` followed by exactly 64 lowercase hex characters"
}

impl Sha256Digest {
    /// Hashes `bytes`. This is the one place in the crate that computes a SHA-256.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        use sha2::Digest as _;
        let hash = sha2::Sha256::digest(bytes);
        Self(format!("sha256:{}", hex::encode(hash)))
    }

    /// The 64 hex characters without the `sha256:` prefix.
    #[must_use]
    pub fn hex(&self) -> &str {
        self.0.strip_prefix("sha256:").unwrap_or(&self.0)
    }
}

/// Compiled forms of the patterns a title must not match.
struct TitleRules {
    trimmed: Regex,
    forbidden: [(Regex, &'static str); 4],
}

static TITLE_RULES: LazyLock<TitleRules> = LazyLock::new(|| {
    let compile = |pattern: &str| Regex::new(pattern).expect("a schema pattern is a valid regex");
    TitleRules {
        trimmed: compile(patterns::TITLE_TRIMMED),
        forbidden: [
            (
                compile(patterns::TITLE_PIPE),
                "a title must not contain a pipe character; put tags in separate fields",
            ),
            (
                compile(patterns::TITLE_MACHINE_PREFIX),
                "a title must not start with a machine identifier such as `TASK-13:`; put the identifier in its own field",
            ),
            (
                compile(patterns::TITLE_BRACKET_PREFIX),
                "a title must not start with a bracketed tag; put the tag in its own field",
            ),
            (
                compile(patterns::TITLE_ROLE_STAMP),
                "a title must not carry a role stamp such as `[AGENT:BACKEND]`; put the role in its own field",
            ),
        ],
    }
});

static TEXT_TRIMMED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(patterns::TEXT_TRIMMED).expect("a schema pattern is a valid regex")
});

/// A short plain-English title in sentence case, 3 to 100 characters.
///
/// Machine identifiers, role stamps and pipeline tags belong in separate fields and are refused
/// here, so a title can never be a code (`TASK-13: ...`, `[AGENT:BACKEND] ...`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HumanTitle(String);

impl HumanTitle {
    /// Fewest characters in a title.
    pub const MIN_CHARS: usize = 3;
    /// Most characters in a title.
    pub const MAX_CHARS: usize = 100;

    /// Checks the length, the trimming and the forbidden shapes.
    ///
    /// # Errors
    /// Returns a [`ValueError`] that says which rule the text broke.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        const WHAT: &str = "title";
        let length = text.chars().count();
        if !(Self::MIN_CHARS..=Self::MAX_CHARS).contains(&length) {
            return Err(ValueError::new(
                WHAT,
                text,
                format!(
                    "a title has {} to {} characters, this one has {length}",
                    Self::MIN_CHARS,
                    Self::MAX_CHARS
                ),
            ));
        }
        if !TITLE_RULES.trimmed.is_match(text) {
            return Err(ValueError::new(
                WHAT,
                text,
                "a title has no leading or trailing whitespace and stays on one line",
            ));
        }
        for (pattern, rule) in &TITLE_RULES.forbidden {
            if pattern.is_match(text) {
                return Err(ValueError::new(WHAT, text, *rule));
            }
        }
        Ok(Self(text.to_owned()))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

string_traits!(HumanTitle);

/// Complete plain-English sentences for a human reader, 10 to 4000 characters, trimmed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HumanText(String);

impl HumanText {
    /// Fewest characters in a text.
    pub const MIN_CHARS: usize = 10;
    /// Most characters in a text.
    pub const MAX_CHARS: usize = 4000;

    /// Checks the length and the trimming.
    ///
    /// # Errors
    /// Returns a [`ValueError`] that says which rule the text broke.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        const WHAT: &str = "text";
        let length = text.chars().count();
        if !(Self::MIN_CHARS..=Self::MAX_CHARS).contains(&length) {
            return Err(ValueError::new(
                WHAT,
                text,
                format!(
                    "a text has {} to {} characters, this one has {length}",
                    Self::MIN_CHARS,
                    Self::MAX_CHARS
                ),
            ));
        }
        if !TEXT_TRIMMED.is_match(text) {
            return Err(ValueError::new(
                WHAT,
                text,
                "a text has no leading or trailing whitespace",
            ));
        }
        Ok(Self(text.to_owned()))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

string_traits!(HumanText);

static SEMVER_SHAPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(patterns::SEMVER).expect("a schema pattern is a valid regex"));

/// A semantic version such as `1.2.0` or `1.0.0-rc.1`, without build metadata.
///
/// The schema pattern is the first gate. The `semver` crate is the second, so identifiers that the
/// pattern lets through but the Semantic Versioning rules forbid (an empty identifier, a leading
/// zero in a numeric pre-release) are refused too.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SemanticVersion {
    version: semver::Version,
    text: String,
}

impl SemanticVersion {
    /// Reads a version.
    ///
    /// # Errors
    /// Returns a [`ValueError`] when the text is not a semantic version in the schema's form.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        const WHAT: &str = "semantic version";
        const RULE: &str = "use `major.minor.patch` with an optional `-pre-release` and no build metadata";
        if !SEMVER_SHAPE.is_match(text) {
            return Err(ValueError::new(WHAT, text, RULE));
        }
        let version =
            semver::Version::parse(text).map_err(|_| ValueError::new(WHAT, text, RULE))?;
        Ok(Self {
            version,
            text: text.to_owned(),
        })
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The parsed version, for comparison.
    #[must_use]
    pub const fn version(&self) -> &semver::Version {
        &self.version
    }
}

string_traits!(SemanticVersion);
