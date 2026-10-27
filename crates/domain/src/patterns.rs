//! Every `pattern` that the contract schemas declare, copied character for character.
//!
//! The types in this crate compile these very strings, so the Rust checks and the schemas use one
//! definition. A test reads every schema file and fails if a pattern appears in a schema and not
//! here, or here and not in a schema, so a change to either side cannot go unnoticed.

/// Lowercase UUID, hyphenated.
pub const UUID: &str = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
/// `sha256:` followed by 64 lowercase hex characters.
pub const SHA256: &str = r"^sha256:[0-9a-f]{64}$";
/// A full Git object id.
pub const GIT_SHA: &str = r"^([0-9a-f]{40}|[0-9a-f]{64})$";
/// UTC instant in RFC 3339 form with a `Z` suffix.
pub const TIMESTAMP: &str = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$";
/// Machine-safe identifier.
pub const SLUG: &str = r"^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$";
/// Semantic version without build metadata.
pub const SEMVER: &str = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$";
/// A title has no leading or trailing whitespace.
pub const TITLE_TRIMMED: &str = r"^\S(.*\S)?$";
/// A title has no pipe character.
pub const TITLE_PIPE: &str = r"\|";
/// A title does not start with a machine tag such as `TASK-13:`.
pub const TITLE_MACHINE_PREFIX: &str = r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+\s*[:|]";
/// A title does not start with a bracketed tag.
pub const TITLE_BRACKET_PREFIX: &str = r"^\[[^\]]+\]";
/// A title does not carry a role stamp such as `[AGENT:BACKEND]`.
pub const TITLE_ROLE_STAMP: &str = r"\[[A-Z_]+:[^\]]*\]";
/// Prose has no leading or trailing whitespace. It may span lines.
pub const TEXT_TRIMMED: &str = r"^\S([\s\S]*\S)?$";
/// A media type such as `application/json`.
pub const MEDIA_TYPE: &str = r"^[a-z]+/[a-z0-9.+-]+$";
/// A Spec Kit requirement id.
pub const REQUIREMENT_ID: &str = r"^FR-[0-9]{3,}$";
/// A Spec Kit acceptance scenario id.
pub const SCENARIO_ID: &str = r"^AS-[0-9]{3,}$";
/// A non-functional requirement or success criterion id.
pub const NONFUNCTIONAL_ID: &str = r"^(NFR|SC)-[0-9]{3,}$";
/// A specification risk id.
pub const RISK_ID: &str = r"^RISK-[0-9]{3,}$";
/// An open question id.
pub const QUESTION_ID: &str = r"^Q-[0-9]{3,}$";
/// A constraint id.
pub const CONSTRAINT_ID: &str = r"^C-[0-9]{3,}$";
/// A language tag such as `en` or `pt-BR`.
pub const LANGUAGE: &str = r"^[a-z]{2,3}(-[A-Za-z0-9]+)*$";
/// A repository-relative Spec Kit feature directory.
pub const FEATURE_DIRECTORY: &str = r"^specs/[a-z0-9][a-z0-9._-]*$";
/// An OpenTelemetry trace id.
pub const TRACE_ID: &str = r"^[0-9a-f]{32}$";
/// An OpenTelemetry span id.
pub const SPAN_ID: &str = r"^[0-9a-f]{16}$";
/// A W3C Trace Context `traceparent` value.
pub const TRACEPARENT: &str = r"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$";
/// A domain event type, `aggregate.past_tense_verb`.
pub const EVENT_TYPE: &str = r"^[a-z][a-z_]*\.[a-z][a-z_]*$";
/// The id of a transition in `state-machine.json`, such as `S08`.
pub const TRANSITION_ID: &str = r"^[JSAT][0-9]{2}$";
/// A repository name in `owner/name` form.
pub const REPOSITORY_FULL_NAME: &str = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$";
/// An absolute working directory inside the sandbox.
pub const WORKDIR: &str = r"^/[A-Za-z0-9._/-]*$";
/// A relative working directory for a gate command. May be empty.
pub const GATE_CWD: &str = r"^[A-Za-z0-9._/-]*$";

/// Every pattern above. The schema drift test compares this list with the schema files.
pub const ALL: &[&str] = &[
    UUID,
    SHA256,
    GIT_SHA,
    TIMESTAMP,
    SLUG,
    SEMVER,
    TITLE_TRIMMED,
    TITLE_PIPE,
    TITLE_MACHINE_PREFIX,
    TITLE_BRACKET_PREFIX,
    TITLE_ROLE_STAMP,
    TEXT_TRIMMED,
    MEDIA_TYPE,
    REQUIREMENT_ID,
    SCENARIO_ID,
    NONFUNCTIONAL_ID,
    RISK_ID,
    QUESTION_ID,
    CONSTRAINT_ID,
    LANGUAGE,
    FEATURE_DIRECTORY,
    TRACE_ID,
    SPAN_ID,
    TRACEPARENT,
    EVENT_TYPE,
    TRANSITION_ID,
    REPOSITORY_FULL_NAME,
    WORKDIR,
    GATE_CWD,
];
