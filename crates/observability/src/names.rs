//! The names of spans, span attributes and log fields, and the rules for using them.
//!
//! These names are a contract between the code that records telemetry and the people and tools
//! that read it. [`docs/observability/conventions.md`] carries the same tables, and a test fails
//! when the page and this file disagree.
//!
//! Crates in the application and adapter ring cannot depend on this crate (the dependency rules
//! forbid peer edges), so they repeat these strings in their `tracing` calls. The tables here are
//! the reference those call sites are checked against. [`check_span_shape`] is the check.
//!
//! [`docs/observability/conventions.md`]: ../../../docs/observability/conventions.md

/// Span names. Each one stands for one part of a job.
pub mod span {
    /// One request, from admission to a terminal state.
    pub const JOB: &str = "factory.job";
    /// One execution of one stage kind. Rework creates a new stage run.
    pub const STAGE_RUN: &str = "factory.stage_run";
    /// One try at a stage run, owned by one worker through one lease.
    pub const ATTEMPT: &str = "factory.attempt";
    /// One agent invocation inside an attempt.
    pub const AGENT: &str = "factory.agent";
    /// One tool call made by an agent, or by the engine on its behalf.
    pub const TOOL_CALL: &str = "factory.tool_call";
    /// One gate evaluation inside a stage run.
    pub const GATE: &str = "factory.gate";
}

/// Span attribute keys.
pub mod attr {
    /// Shared by every span, log line and domain event of one job.
    pub const CORRELATION_ID: &str = "factory.correlation_id";
    pub const TENANT_ID: &str = "factory.tenant_id";
    pub const JOB_ID: &str = "factory.job_id";
    pub const STAGE_RUN_ID: &str = "factory.stage_run_id";
    pub const ATTEMPT_ID: &str = "factory.attempt_id";
    pub const STAGE_KIND: &str = "factory.stage_kind";
    pub const ATTEMPT_NUMBER: &str = "factory.attempt_number";
    pub const AGENT_ID: &str = "factory.agent_id";
    pub const MODEL: &str = "factory.model";
    pub const TOOL_NAME: &str = "factory.tool_name";
    pub const GATE_ID: &str = "factory.gate_id";
    pub const OUTCOME: &str = "factory.outcome";
    pub const ERROR_CLASS: &str = "factory.error_class";
    /// A digest of the prompt. The prompt text is never recorded.
    pub const PROMPT_SHA256: &str = "factory.prompt_sha256";
    /// A digest of the tool arguments. The arguments are never recorded.
    pub const TOOL_ARGS_SHA256: &str = "factory.tool_args_sha256";
    pub const TOKENS_INPUT: &str = "factory.tokens_input";
    pub const TOKENS_OUTPUT: &str = "factory.tokens_output";
    pub const COST_USD: &str = "factory.cost_usd";
    /// The OpenTelemetry semantic-convention key for the kind of error.
    pub const ERROR_TYPE: &str = "error.type";
}

/// The name of the log field that carries the job correlation id.
///
/// It is the same word the domain event schema uses, so one search finds the id in logs and
/// events. On spans the same value travels as [`attr::CORRELATION_ID`].
pub const CORRELATION_LOG_FIELD: &str = "correlation_id";

/// Keys from the OpenTelemetry semantic conventions that are allowed without a `factory.` prefix.
pub const STANDARD_ATTRIBUTES: &[&str] = &[attr::ERROR_TYPE];

/// The longest string value, in bytes, that an exported attribute may keep. A longer value is cut.
/// Digests and identifiers fit. A prompt or an issue body does not, and that is deliberate.
pub const MAX_ATTRIBUTE_VALUE_BYTES: usize = 256;

/// The values `factory.outcome` and the metric label `outcome` may take. Each is the lower case
/// form of a state name in `docs/architecture/state-machine.json` or of a gate outcome in the
/// gate report schema, plus `denied` for a tool call that policy refused.
pub const OUTCOMES: &[&str] = &[
    "passed",
    "failed",
    "blocked",
    "not_applicable",
    "succeeded",
    "timed_out",
    "lease_lost",
    "cancelled",
    "denied",
    "rework_requested",
];

/// How many distinct values an attribute can take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cardinality {
    /// A small closed set. Safe as a metric label if the metric lists it.
    Bounded,
    /// Identifiers, digests and measurements. Allowed on spans and logs, never a metric label.
    Unbounded,
}

impl Cardinality {
    pub fn as_str(self) -> &'static str {
        match self {
            Cardinality::Bounded => "bounded",
            Cardinality::Unbounded => "unbounded",
        }
    }
}

/// The type of an attribute value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    String,
    Int,
    Double,
}

impl ValueType {
    pub fn as_str(self) -> &'static str {
        match self {
            ValueType::String => "string",
            ValueType::Int => "int",
            ValueType::Double => "double",
        }
    }
}

/// What one kind of span must carry.
#[derive(Debug, Clone, Copy)]
pub struct SpanSpec {
    pub name: &'static str,
    /// Attributes that must be present when the span ends.
    pub required: &'static [&'static str],
    pub meaning: &'static str,
}

/// One attribute and where it may appear.
#[derive(Debug, Clone, Copy)]
pub struct AttributeSpec {
    pub key: &'static str,
    pub value_type: ValueType,
    pub cardinality: Cardinality,
    /// The spans this attribute may appear on, whether required or optional.
    pub spans: &'static [&'static str],
    pub meaning: &'static str,
}

const ALL_SPANS: &[&str] = &[
    span::JOB,
    span::STAGE_RUN,
    span::ATTEMPT,
    span::AGENT,
    span::TOOL_CALL,
    span::GATE,
];

/// The six kinds of span, in the order they nest.
pub const SPANS: &[SpanSpec] = &[
    SpanSpec {
        name: span::JOB,
        required: &[attr::CORRELATION_ID, attr::JOB_ID, attr::TENANT_ID],
        meaning: "One request from admission to a terminal state.",
    },
    SpanSpec {
        name: span::STAGE_RUN,
        required: &[
            attr::CORRELATION_ID,
            attr::JOB_ID,
            attr::STAGE_RUN_ID,
            attr::STAGE_KIND,
        ],
        meaning: "One execution of one stage kind.",
    },
    SpanSpec {
        name: span::ATTEMPT,
        required: &[
            attr::CORRELATION_ID,
            attr::JOB_ID,
            attr::STAGE_RUN_ID,
            attr::ATTEMPT_ID,
            attr::ATTEMPT_NUMBER,
            attr::OUTCOME,
        ],
        meaning: "One try at a stage run, owned by one worker.",
    },
    SpanSpec {
        name: span::AGENT,
        required: &[
            attr::CORRELATION_ID,
            attr::JOB_ID,
            attr::ATTEMPT_ID,
            attr::AGENT_ID,
            attr::OUTCOME,
        ],
        meaning: "One agent invocation inside an attempt.",
    },
    SpanSpec {
        name: span::TOOL_CALL,
        required: &[
            attr::CORRELATION_ID,
            attr::JOB_ID,
            attr::ATTEMPT_ID,
            attr::TOOL_NAME,
            attr::OUTCOME,
        ],
        meaning: "One tool call made by an agent.",
    },
    SpanSpec {
        name: span::GATE,
        required: &[
            attr::CORRELATION_ID,
            attr::JOB_ID,
            attr::STAGE_RUN_ID,
            attr::GATE_ID,
            attr::OUTCOME,
        ],
        meaning: "One gate evaluation inside a stage run.",
    },
];

/// Every span attribute the exporter lets through. Anything else is dropped before export.
pub const ATTRIBUTES: &[AttributeSpec] = &[
    AttributeSpec {
        key: attr::CORRELATION_ID,
        value_type: ValueType::String,
        cardinality: Cardinality::Unbounded,
        spans: ALL_SPANS,
        meaning: "Shared by every span, log line and domain event of one job.",
    },
    AttributeSpec {
        key: attr::TENANT_ID,
        value_type: ValueType::String,
        cardinality: Cardinality::Unbounded,
        spans: &[span::JOB],
        meaning: "The tenant that owns the job.",
    },
    AttributeSpec {
        key: attr::JOB_ID,
        value_type: ValueType::String,
        cardinality: Cardinality::Unbounded,
        spans: ALL_SPANS,
        meaning: "The job.",
    },
    AttributeSpec {
        key: attr::STAGE_RUN_ID,
        value_type: ValueType::String,
        cardinality: Cardinality::Unbounded,
        spans: &[span::STAGE_RUN, span::ATTEMPT, span::GATE],
        meaning: "The stage run.",
    },
    AttributeSpec {
        key: attr::ATTEMPT_ID,
        value_type: ValueType::String,
        cardinality: Cardinality::Unbounded,
        spans: &[span::ATTEMPT, span::AGENT, span::TOOL_CALL],
        meaning: "The attempt.",
    },
    AttributeSpec {
        key: attr::STAGE_KIND,
        value_type: ValueType::String,
        cardinality: Cardinality::Bounded,
        spans: &[span::STAGE_RUN, span::ATTEMPT, span::GATE],
        meaning: "The stage kind, such as INTAKE, in the spelling of the state machine file.",
    },
    AttributeSpec {
        key: attr::ATTEMPT_NUMBER,
        value_type: ValueType::Int,
        cardinality: Cardinality::Bounded,
        spans: &[span::ATTEMPT],
        meaning: "Which try this is within the stage run, starting at 1. The engine caps it.",
    },
    AttributeSpec {
        key: attr::AGENT_ID,
        value_type: ValueType::String,
        cardinality: Cardinality::Bounded,
        spans: &[span::AGENT],
        meaning: "The agent identifier from the agent registry.",
    },
    AttributeSpec {
        key: attr::MODEL,
        value_type: ValueType::String,
        cardinality: Cardinality::Bounded,
        spans: &[span::AGENT],
        meaning: "The model name the broker reports.",
    },
    AttributeSpec {
        key: attr::TOOL_NAME,
        value_type: ValueType::String,
        cardinality: Cardinality::Bounded,
        spans: &[span::TOOL_CALL],
        meaning: "The tool, taken from the stage tool profile.",
    },
    AttributeSpec {
        key: attr::GATE_ID,
        value_type: ValueType::String,
        cardinality: Cardinality::Bounded,
        spans: &[span::GATE],
        meaning: "The gate identifier from the gate catalog.",
    },
    AttributeSpec {
        key: attr::OUTCOME,
        value_type: ValueType::String,
        cardinality: Cardinality::Bounded,
        spans: ALL_SPANS,
        meaning: "How the work ended. One of the outcome values.",
    },
    AttributeSpec {
        key: attr::ERROR_CLASS,
        value_type: ValueType::String,
        cardinality: Cardinality::Bounded,
        spans: ALL_SPANS,
        meaning: "The failure class the engine recorded, when the work failed.",
    },
    AttributeSpec {
        key: attr::PROMPT_SHA256,
        value_type: ValueType::String,
        cardinality: Cardinality::Unbounded,
        spans: &[span::AGENT],
        meaning: "Hex digest of the prompt. The prompt itself is stored as an artifact.",
    },
    AttributeSpec {
        key: attr::TOOL_ARGS_SHA256,
        value_type: ValueType::String,
        cardinality: Cardinality::Unbounded,
        spans: &[span::TOOL_CALL],
        meaning: "Hex digest of the tool arguments.",
    },
    AttributeSpec {
        key: attr::TOKENS_INPUT,
        value_type: ValueType::Int,
        cardinality: Cardinality::Unbounded,
        spans: &[span::AGENT],
        meaning: "Input tokens the broker metered for this invocation.",
    },
    AttributeSpec {
        key: attr::TOKENS_OUTPUT,
        value_type: ValueType::Int,
        cardinality: Cardinality::Unbounded,
        spans: &[span::AGENT],
        meaning: "Output tokens the broker metered for this invocation.",
    },
    AttributeSpec {
        key: attr::COST_USD,
        value_type: ValueType::Double,
        cardinality: Cardinality::Unbounded,
        spans: &[span::AGENT],
        meaning: "Cost in US dollars the broker metered for this invocation.",
    },
    AttributeSpec {
        key: attr::ERROR_TYPE,
        value_type: ValueType::String,
        cardinality: Cardinality::Bounded,
        spans: ALL_SPANS,
        meaning: "The standard error.type key. A short error kind, never a message.",
    },
];

/// Attributes that the tracing layer adds to every span event, and that are allowed on events
/// only: the severity of the event and the module path of the code that logged it. Neither holds
/// user content.
pub const EVENT_ATTRIBUTES: &[&str] = &["level", "target"];

/// Whether an attribute key may appear on a span event.
pub fn is_allowed_event_attribute(key: &str) -> bool {
    is_allowed_attribute(key) || EVENT_ATTRIBUTES.contains(&key)
}

/// Fields a log line may carry besides the span attributes: the message, and the correlation id
/// that the log layer adds.
pub const LOG_FIELDS: &[&str] = &["message", CORRELATION_LOG_FIELD];

/// Whether a log field name is on the allowlist (check ST-07).
pub fn is_allowed_log_field(key: &str) -> bool {
    LOG_FIELDS.contains(&key) || is_allowed_attribute(key)
}

/// The declaration of a span kind, or `None` for a name this crate does not know.
pub fn span_spec(name: &str) -> Option<&'static SpanSpec> {
    SPANS.iter().find(|s| s.name == name)
}

/// Whether a span attribute key is on the allowlist (check ST-07).
pub fn is_allowed_attribute(key: &str) -> bool {
    ATTRIBUTES.iter().any(|a| a.key == key)
}

/// Why a span does not have the shape its kind requires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShapeError {
    /// The name is not one of the six span kinds.
    UnknownSpan(String),
    /// Attributes outside the allowlist, sorted.
    ForbiddenAttributes(Vec<String>),
    /// Required attributes that are absent, in the order the table lists them.
    MissingAttributes(Vec<&'static str>),
}

impl std::fmt::Display for ShapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShapeError::UnknownSpan(name) => write!(f, "{name} is not a factory span"),
            ShapeError::ForbiddenAttributes(keys) => {
                write!(f, "attributes not on the allowlist: {}", keys.join(", "))
            }
            ShapeError::MissingAttributes(keys) => {
                write!(f, "required attributes are missing: {}", keys.join(", "))
            }
        }
    }
}

impl std::error::Error for ShapeError {}

/// Check the attributes found on an ended span against the table.
///
/// Other packages call this from their trace tests with the attribute keys they read from the
/// exported span.
pub fn check_span_shape<I>(span_name: &str, present: I) -> Result<(), ShapeError>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    let spec =
        span_spec(span_name).ok_or_else(|| ShapeError::UnknownSpan(span_name.to_string()))?;
    let present: Vec<String> = present
        .into_iter()
        .map(|k| k.as_ref().to_string())
        .collect();

    let mut forbidden: Vec<String> = present
        .iter()
        .filter(|key| !is_allowed_attribute(key))
        .cloned()
        .collect();
    if !forbidden.is_empty() {
        forbidden.sort();
        forbidden.dedup();
        return Err(ShapeError::ForbiddenAttributes(forbidden));
    }

    let missing: Vec<&'static str> = spec
        .required
        .iter()
        .copied()
        .filter(|key| !present.iter().any(|p| p == key))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(ShapeError::MissingAttributes(missing))
    }
}
