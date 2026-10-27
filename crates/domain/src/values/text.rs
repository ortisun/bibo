//! Strings with a shape: identifiers, hashes, titles, prose and versions.

use std::sync::LazyLock;

use regex::Regex;

use crate::error::ValueError;
use crate::ids::JobId;
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
            return Err(ValueError::new(
                WHAT,
                text,
                "heartbeats are not domain events",
            ));
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

/// The text that the root span id of a job is derived from, placed in front of the job id.
const JOB_SPAN_SEED: &str = "factory.job";

impl Traceparent {
    /// The trace context of a job (ADR 0013). A job is one trace, and any process can find it
    /// from the job id alone, so nothing is stored and a restart needs no restoration.
    ///
    /// * The **trace id** is the 32 lowercase hex characters of the job's UUID.
    /// * The **root span id** is the first 16 hex characters of the SHA-256 of the text
    ///   `factory.job` followed directly by the job id in its usual form (36 characters,
    ///   lowercase, hyphenated), with nothing in between.
    /// * The **flags** are `01`, sampled.
    ///
    /// The result is the parent of the `factory.job` span that each process opens for its stretch
    /// of work. The root span itself is never exported. The function is pure: the same job always
    /// gives the same value. A job id of all zeros would give a trace id that the W3C
    /// specification calls invalid. The `IdGenerator` port never makes one, so the function has
    /// no failure case.
    #[must_use]
    pub fn for_job(job: JobId) -> Self {
        let trace_id = job.as_uuid().simple().to_string();
        let seed = format!("{JOB_SPAN_SEED}{job}");
        let digest = Sha256Digest::of(seed.as_bytes());
        let span_id: String = digest.hex().chars().take(16).collect();
        Self(format!("00-{trace_id}-{span_id}-01"))
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
        const RULE: &str =
            "use `major.minor.patch` with an optional `-pre-release` and no build metadata";
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

/// Text of `MIN` to `MAX` characters, counted as Unicode scalar values the way JSON Schema counts
/// `minLength` and `maxLength`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BoundedString<const MIN: usize, const MAX: usize>(String);

/// Text of at least one character, for example a name or a path.
pub type NonEmptyString = BoundedString<1, { usize::MAX }>;

impl<const MIN: usize, const MAX: usize> BoundedString<MIN, MAX> {
    /// Checks the length.
    ///
    /// # Errors
    /// Returns a [`ValueError`] that states the allowed length.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        let length = text.chars().count();
        if (MIN..=MAX).contains(&length) {
            return Ok(Self(text.to_owned()));
        }
        let rule = if MAX == usize::MAX {
            format!("use at least {MIN} character(s), this one has {length}")
        } else {
            format!("use {MIN} to {MAX} characters, this one has {length}")
        };
        Err(ValueError::new("text", text, rule))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<const MIN: usize, const MAX: usize> std::fmt::Display for BoundedString<MIN, MAX> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<const MIN: usize, const MAX: usize> std::str::FromStr for BoundedString<MIN, MAX> {
    type Err = ValueError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

impl<const MIN: usize, const MAX: usize> serde::Serialize for BoundedString<MIN, MAX> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, const MIN: usize, const MAX: usize> serde::Deserialize<'de> for BoundedString<MIN, MAX> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <String as serde::Deserialize>::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// An absolute URI such as `https://example.org/page`: a scheme, a colon, something after it and
/// no whitespace or control characters.
///
/// The schemas mark these fields `format: uri`, which validators are not required to assert, so
/// this is the check this crate makes for them. It does not fetch or resolve anything.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uri(String);

impl Uri {
    /// Checks the shape of the URI.
    ///
    /// # Errors
    /// Returns a [`ValueError`] when the text is not an absolute URI.
    pub fn parse(text: &str) -> Result<Self, ValueError> {
        let well_formed = text.split_once(':').is_some_and(|(scheme, rest)| {
            let mut chars = scheme.chars();
            chars
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic())
                && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
                && !rest.is_empty()
        }) && !text.chars().any(|c| c.is_whitespace() || c.is_control());
        if well_formed {
            Ok(Self(text.to_owned()))
        } else {
            Err(ValueError::new(
                "URI",
                text,
                "use an absolute URI such as https://example.org/page, with no spaces",
            ))
        }
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

string_traits!(Uri);
