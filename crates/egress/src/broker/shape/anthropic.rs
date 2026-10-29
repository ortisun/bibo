//! The allow schema of the Anthropic Messages API (`POST /v1/messages`, and the token count at
//! `/v1/messages/count_tokens`). What each field is for, and why it is here, is in the table of
//! the module documentation of [`super`].

use super::Violation;
use super::rules::{Fields, Rule, TEXT, Tagged};

// `ttl` is `5m` or absent. Anthropic bills a one-hour cache write at about twice the five-minute
// rate, and the price list has one cache-write rate per model and the usage report names one count
// (`cache_creation_input_tokens`), so a `1h` write would be booked at the lower rate (finding RR-2).
// The factory does not need the longer cache (nothing recorded from the real tools sends it), so the
// schema refuses it instead of pricing it. Pricing it would take a second rate and the per-TTL
// counts of `usage.cache_creation`, and is left until a stage needs it.
static CACHE_CONTROL: Fields = Fields {
    fields: &[
        ("type", Rule::Const("ephemeral")),
        ("ttl", Rule::Enum(&["5m"])),
    ],
    required: &[],
};

static OUTPUT_CONFIG: Fields = Fields {
    fields: &[("effort", Rule::Name)],
    required: &[],
};

static TEXT_BLOCK: Fields = Fields {
    fields: &[
        ("text", Rule::Str(TEXT)),
        ("cache_control", Rule::Object(&CACHE_CONTROL)),
    ],
    required: &["text"],
};

/// An image or a document is data in the body. A source that names an address or an uploaded file
/// would make the provider fetch it, so only inline data is a listed source.
static IMAGE_BASE64: Fields = Fields {
    fields: &[
        (
            "media_type",
            Rule::Enum(&["image/png", "image/jpeg", "image/gif", "image/webp"]),
        ),
        ("data", Rule::Str(TEXT)),
    ],
    required: &["media_type", "data"],
};
static IMAGE_SOURCE: Tagged = Tagged {
    tag: "type",
    variants: &[("base64", &IMAGE_BASE64)],
    default: None,
    unknown: Violation::RemoteContent,
};

static DOCUMENT_BASE64: Fields = Fields {
    fields: &[
        ("media_type", Rule::Const("application/pdf")),
        ("data", Rule::Str(TEXT)),
    ],
    required: &["media_type", "data"],
};
static DOCUMENT_PLAIN: Fields = Fields {
    fields: &[
        ("media_type", Rule::Const("text/plain")),
        ("data", Rule::Str(TEXT)),
    ],
    required: &["media_type", "data"],
};
static DOCUMENT_SOURCE: Tagged = Tagged {
    tag: "type",
    variants: &[("base64", &DOCUMENT_BASE64), ("text", &DOCUMENT_PLAIN)],
    default: None,
    unknown: Violation::RemoteContent,
};

static IMAGE_BLOCK: Fields = Fields {
    fields: &[
        ("source", Rule::Tagged(&IMAGE_SOURCE)),
        ("cache_control", Rule::Object(&CACHE_CONTROL)),
    ],
    required: &["source"],
};
static DOCUMENT_BLOCK: Fields = Fields {
    fields: &[
        ("source", Rule::Tagged(&DOCUMENT_SOURCE)),
        ("cache_control", Rule::Object(&CACHE_CONTROL)),
    ],
    required: &["source"],
};

/// What a tool result may hold besides a plain string: text, and an image the tool read.
static RESULT_BLOCK: Tagged = Tagged {
    tag: "type",
    variants: &[("text", &TEXT_BLOCK), ("image", &IMAGE_BLOCK)],
    default: None,
    unknown: Violation::UnknownBlock,
};
static RESULT_BLOCK_RULE: Rule = Rule::Tagged(&RESULT_BLOCK);

/// The model's call of one of the tools the client defined. `input` is the model's own
/// arguments, free-form by nature.
static TOOL_USE: Fields = Fields {
    fields: &[
        ("id", Rule::Name),
        ("name", Rule::Name),
        ("input", Rule::Free),
        ("cache_control", Rule::Object(&CACHE_CONTROL)),
    ],
    required: &["id", "name", "input"],
};
static TOOL_RESULT: Fields = Fields {
    fields: &[
        ("tool_use_id", Rule::Name),
        (
            "content",
            Rule::StrOr(TEXT, &Rule::Array(&RESULT_BLOCK_RULE, 10_000)),
        ),
        ("is_error", Rule::Bool),
        ("cache_control", Rule::Object(&CACHE_CONTROL)),
    ],
    required: &["tool_use_id"],
};
/// Earlier reasoning of the model, sent back with its signature.
static THINKING_BLOCK: Fields = Fields {
    fields: &[
        ("thinking", Rule::Str(TEXT)),
        ("signature", Rule::Str(TEXT)),
    ],
    required: &["thinking"],
};
static REDACTED_THINKING: Fields = Fields {
    fields: &[("data", Rule::Str(TEXT))],
    required: &["data"],
};

static BLOCK: Tagged = Tagged {
    tag: "type",
    variants: &[
        ("text", &TEXT_BLOCK),
        ("image", &IMAGE_BLOCK),
        ("document", &DOCUMENT_BLOCK),
        ("tool_use", &TOOL_USE),
        ("tool_result", &TOOL_RESULT),
        ("thinking", &THINKING_BLOCK),
        ("redacted_thinking", &REDACTED_THINKING),
    ],
    default: None,
    unknown: Violation::UnknownBlock,
};
static BLOCK_RULE: Rule = Rule::Tagged(&BLOCK);

static TEXT_ONLY: Tagged = Tagged {
    tag: "type",
    variants: &[("text", &TEXT_BLOCK)],
    default: None,
    unknown: Violation::UnknownBlock,
};
static TEXT_ONLY_RULE: Rule = Rule::Tagged(&TEXT_ONLY);

static MESSAGE: Fields = Fields {
    fields: &[
        ("role", Rule::Enum(&["user", "assistant", "system"])),
        (
            "content",
            Rule::StrOr(TEXT, &Rule::Array(&BLOCK_RULE, 100_000)),
        ),
        // Per-turn control (beta `per-turn-control-2026-07-01`), seen in the recorded sessions.
        ("output_config", Rule::Object(&OUTPUT_CONFIG)),
    ],
    required: &["role", "content"],
};
static MESSAGE_RULE: Rule = Rule::Object(&MESSAGE);

/// A tool the client defines and runs itself. A tool of any other `type` (`web_search_*`,
/// `web_fetch_*`, `code_execution_*`, `computer_*`, `bash_*`, `text_editor_*`, `memory_*`,
/// `mcp_toolset`, a tool search tool) is run by the provider, and is refused.
static CUSTOM_TOOL: Fields = Fields {
    fields: &[
        ("name", Rule::Name),
        ("description", Rule::Str(TEXT)),
        ("input_schema", Rule::Schema),
        ("cache_control", Rule::Object(&CACHE_CONTROL)),
        ("defer_loading", Rule::Bool),
    ],
    required: &["name", "input_schema"],
};
static TOOL: Tagged = Tagged {
    tag: "type",
    variants: &[("custom", &CUSTOM_TOOL)],
    default: Some("custom"),
    unknown: Violation::ServerTool,
};
static TOOL_RULE: Rule = Rule::Tagged(&TOOL);

static TOOL_CHOICE: Fields = Fields {
    fields: &[
        ("type", Rule::Enum(&["auto", "any", "none", "tool"])),
        ("name", Rule::Name),
        ("disable_parallel_tool_use", Rule::Bool),
    ],
    required: &["type"],
};

static THINKING: Fields = Fields {
    fields: &[
        ("type", Rule::Enum(&["enabled", "disabled", "adaptive"])),
        ("budget_tokens", Rule::Int(0, 10_000_000)),
        ("display", Rule::Name),
    ],
    required: &["type"],
};

/// Editing of the conversation the provider keeps in its prompt cache. Only the two edits that
/// clear earlier thinking and tool results, which the recorded sessions of Claude Code show.
static KEEP: Fields = Fields {
    fields: &[("type", Rule::Name), ("value", Rule::Int(0, 1_000_000))],
    required: &[],
};
static CONTEXT_EDIT: Fields = Fields {
    fields: &[
        (
            "type",
            Rule::Enum(&["clear_thinking_20251015", "clear_tool_uses_20250919"]),
        ),
        ("keep", Rule::StrOr(64, &Rule::Object(&KEEP))),
    ],
    required: &["type"],
};
static CONTEXT_EDIT_RULE: Rule = Rule::Object(&CONTEXT_EDIT);
static CONTEXT_MANAGEMENT: Fields = Fields {
    fields: &[("edits", Rule::Array(&CONTEXT_EDIT_RULE, 8))],
    required: &[],
};

static METADATA: Fields = Fields {
    fields: &[("user_id", Rule::Str(1024))],
    required: &[],
};

/// The body of `POST /v1/messages`.
pub(super) static MESSAGES: Fields = Fields {
    fields: &[
        ("model", Rule::Str(200)),
        ("max_tokens", Rule::Number),
        ("messages", Rule::Array(&MESSAGE_RULE, 100_000)),
        (
            "system",
            Rule::StrOr(TEXT, &Rule::Array(&TEXT_ONLY_RULE, 1000)),
        ),
        ("stream", Rule::Bool),
        ("tools", Rule::Array(&TOOL_RULE, 512)),
        ("tool_choice", Rule::Object(&TOOL_CHOICE)),
        ("thinking", Rule::Object(&THINKING)),
        ("output_config", Rule::Object(&OUTPUT_CONFIG)),
        ("context_management", Rule::Object(&CONTEXT_MANAGEMENT)),
        ("metadata", Rule::Object(&METADATA)),
        ("temperature", Rule::Float(0.0, 1.0)),
        ("top_p", Rule::Float(0.0, 1.0)),
        ("top_k", Rule::Int(0, 1000)),
        ("stop_sequences", Rule::Array(&Rule::Str(256), 16)),
    ],
    required: &["model"],
};

/// The body of `POST /v1/messages/count_tokens`: what is counted, and nothing that generates.
pub(super) static COUNT_TOKENS: Fields = Fields {
    fields: &[
        ("model", Rule::Str(200)),
        ("messages", Rule::Array(&MESSAGE_RULE, 100_000)),
        (
            "system",
            Rule::StrOr(TEXT, &Rule::Array(&TEXT_ONLY_RULE, 1000)),
        ),
        ("tools", Rule::Array(&TOOL_RULE, 512)),
        ("tool_choice", Rule::Object(&TOOL_CHOICE)),
        ("thinking", Rule::Object(&THINKING)),
    ],
    required: &["model"],
};
