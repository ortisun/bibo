//! The allow schemas of the OpenAI Responses API (`POST /v1/responses`, which Codex uses) and the
//! Chat Completions API (`POST /v1/chat/completions`, which no factory runtime uses and which is
//! kept small for that reason). What each field is for, and why it is here, is in the table of the
//! module documentation of [`super`].

use super::Violation;
use super::rules::{Fields, Rule, TEXT, Tagged};

static INPUT_TEXT: Fields = Fields {
    fields: &[("text", Rule::Str(TEXT))],
    required: &["text"],
};

static OUTPUT_TEXT: Fields = Fields {
    fields: &[
        ("text", Rule::Str(TEXT)),
        // Empty in what a client sends back; a non-empty list is the provider's own bookkeeping.
        ("annotations", Rule::Array(&Rule::Free, 0)),
        ("logprobs", Rule::Array(&Rule::Free, 0)),
    ],
    required: &["text"],
};

static REFUSAL: Fields = Fields {
    fields: &[("refusal", Rule::Str(TEXT))],
    required: &["refusal"],
};

/// An image is accepted as a `data:` URL only. An `http(s)` address or a file id would make the
/// provider fetch it.
static INPUT_IMAGE: Fields = Fields {
    fields: &[("image_url", Rule::DataUrl(TEXT)), ("detail", Rule::Name)],
    required: &["image_url"],
};

static PART: Tagged = Tagged {
    tag: "type",
    variants: &[
        ("input_text", &INPUT_TEXT),
        ("output_text", &OUTPUT_TEXT),
        ("refusal", &REFUSAL),
        ("input_image", &INPUT_IMAGE),
    ],
    default: None,
    unknown: Violation::UnknownBlock,
};
static PART_RULE: Rule = Rule::Tagged(&PART);

static MESSAGE: Fields = Fields {
    fields: &[
        ("id", Rule::Name),
        (
            "role",
            Rule::Enum(&["user", "assistant", "system", "developer"]),
        ),
        (
            "content",
            Rule::StrOr(TEXT, &Rule::Array(&PART_RULE, 100_000)),
        ),
        ("status", Rule::Name),
        ("phase", Rule::Name),
        ("end_turn", Rule::Bool),
    ],
    required: &["role", "content"],
};

static SUMMARY: Fields = Fields {
    fields: &[
        ("type", Rule::Const("summary_text")),
        ("text", Rule::Str(TEXT)),
    ],
    required: &["text"],
};
static SUMMARY_RULE: Rule = Rule::Object(&SUMMARY);
static REASONING_TEXT: Fields = Fields {
    fields: &[
        ("type", Rule::Const("reasoning_text")),
        ("text", Rule::Str(TEXT)),
    ],
    required: &["text"],
};
static REASONING_TEXT_RULE: Rule = Rule::Object(&REASONING_TEXT);

/// A client tool whose input is free text, optionally held to a grammar the client wrote.
static CUSTOM_FORMAT: Fields = Fields {
    fields: &[
        ("type", Rule::Enum(&["text", "grammar"])),
        ("syntax", Rule::Name),
        ("definition", Rule::Str(TEXT)),
    ],
    required: &["type"],
};

static FUNCTION_TOOL: Fields = Fields {
    fields: &[
        ("name", Rule::Name),
        ("description", Rule::Str(TEXT)),
        ("parameters", Rule::Schema),
        ("strict", Rule::Bool),
    ],
    required: &["name"],
};
static CUSTOM_TOOL: Fields = Fields {
    fields: &[
        ("name", Rule::Name),
        ("description", Rule::Str(TEXT)),
        ("format", Rule::Object(&CUSTOM_FORMAT)),
    ],
    required: &["name"],
};

/// The function and custom tools that a namespace groups.
static CHILD_TOOL: Tagged = Tagged {
    tag: "type",
    variants: &[("function", &FUNCTION_TOOL), ("custom", &CUSTOM_TOOL)],
    default: None,
    unknown: Violation::ServerTool,
};
static CHILD_TOOL_RULE: Rule = Rule::Tagged(&CHILD_TOOL);

static NAMESPACE_TOOL: Fields = Fields {
    fields: &[
        ("name", Rule::Name),
        ("description", Rule::Str(TEXT)),
        ("tools", Rule::Array(&CHILD_TOOL_RULE, 256)),
    ],
    required: &["name"],
};

/// A tool the client defines and runs itself: `function`, `custom`, and a `namespace` that groups
/// them. Every other `type` (`web_search`, `web_search_preview`, `mcp`, `code_interpreter`,
/// `file_search`, `image_generation`, `computer_use_preview`, `local_shell`, `shell`,
/// `apply_patch`, `tool_search`) is executed by the provider or names a remote server, and is
/// refused.
static TOOL: Tagged = Tagged {
    tag: "type",
    variants: &[
        ("function", &FUNCTION_TOOL),
        ("custom", &CUSTOM_TOOL),
        ("namespace", &NAMESPACE_TOOL),
    ],
    default: None,
    unknown: Violation::ServerTool,
};
static TOOL_RULE: Rule = Rule::Tagged(&TOOL);

static FUNCTION_CALL: Fields = Fields {
    fields: &[
        ("id", Rule::Name),
        ("call_id", Rule::Name),
        ("name", Rule::Name),
        ("namespace", Rule::Name),
        ("arguments", Rule::Str(TEXT)),
        ("status", Rule::Name),
    ],
    required: &["call_id", "name", "arguments"],
};
static FUNCTION_CALL_OUTPUT: Fields = Fields {
    fields: &[
        ("id", Rule::Name),
        ("call_id", Rule::Name),
        (
            "output",
            Rule::StrOr(TEXT, &Rule::Array(&PART_RULE, 10_000)),
        ),
        ("status", Rule::Name),
    ],
    required: &["call_id", "output"],
};
static CUSTOM_TOOL_CALL: Fields = Fields {
    fields: &[
        ("id", Rule::Name),
        ("call_id", Rule::Name),
        ("name", Rule::Name),
        ("input", Rule::Str(TEXT)),
        ("status", Rule::Name),
    ],
    required: &["call_id", "name", "input"],
};
static CUSTOM_TOOL_CALL_OUTPUT: Fields = Fields {
    fields: &[
        ("id", Rule::Name),
        ("call_id", Rule::Name),
        (
            "output",
            Rule::StrOr(TEXT, &Rule::Array(&PART_RULE, 10_000)),
        ),
    ],
    required: &["call_id", "output"],
};
static REASONING_ITEM: Fields = Fields {
    fields: &[
        ("id", Rule::Name),
        ("summary", Rule::Array(&SUMMARY_RULE, 1000)),
        ("content", Rule::Array(&REASONING_TEXT_RULE, 1000)),
        ("encrypted_content", Rule::Str(TEXT)),
        ("status", Rule::Name),
    ],
    required: &[],
};
/// The tool list some Codex requests carry inside `input` instead of at the top level (recorded
/// in `fixtures/recordings/agent-cli`).
static ADDITIONAL_TOOLS: Fields = Fields {
    fields: &[
        ("id", Rule::Name),
        ("role", Rule::Name),
        ("tools", Rule::Array(&TOOL_RULE, 512)),
    ],
    required: &["tools"],
};

static ITEM: Tagged = Tagged {
    tag: "type",
    variants: &[
        ("message", &MESSAGE),
        ("function_call", &FUNCTION_CALL),
        ("function_call_output", &FUNCTION_CALL_OUTPUT),
        ("custom_tool_call", &CUSTOM_TOOL_CALL),
        ("custom_tool_call_output", &CUSTOM_TOOL_CALL_OUTPUT),
        ("reasoning", &REASONING_ITEM),
        ("additional_tools", &ADDITIONAL_TOOLS),
    ],
    // A message may be written without `type`: `{"role": "user", "content": "..."}`.
    default: Some("message"),
    unknown: Violation::UnknownBlock,
};
static ITEM_RULE: Rule = Rule::Tagged(&ITEM);

static TOOL_CHOICE_OBJECT: Fields = Fields {
    fields: &[
        ("type", Rule::Enum(&["function", "custom"])),
        ("name", Rule::Name),
    ],
    required: &["type", "name"],
};

static REASONING: Fields = Fields {
    fields: &[
        ("effort", Rule::Name),
        ("summary", Rule::Name),
        ("context", Rule::Name),
    ],
    required: &[],
};

static TEXT_FORMAT: Fields = Fields {
    fields: &[
        ("type", Rule::Enum(&["text", "json_object", "json_schema"])),
        ("name", Rule::Name),
        ("description", Rule::Str(4096)),
        ("schema", Rule::Schema),
        ("strict", Rule::Bool),
    ],
    required: &["type"],
};

static TEXT_CONFIG: Fields = Fields {
    fields: &[
        ("verbosity", Rule::Name),
        ("format", Rule::Object(&TEXT_FORMAT)),
    ],
    required: &[],
};

/// The body of `POST /v1/responses`.
pub(super) static RESPONSES: Fields = Fields {
    fields: &[
        ("model", Rule::Str(200)),
        (
            "input",
            Rule::StrOr(TEXT, &Rule::Array(&ITEM_RULE, 100_000)),
        ),
        ("instructions", Rule::Str(TEXT)),
        ("tools", Rule::Array(&TOOL_RULE, 512)),
        (
            "tool_choice",
            Rule::StrOr(16, &Rule::Object(&TOOL_CHOICE_OBJECT)),
        ),
        ("parallel_tool_calls", Rule::Bool),
        ("reasoning", Rule::Object(&REASONING)),
        ("store", Rule::Bool),
        (
            "include",
            Rule::Array(&Rule::Const("reasoning.encrypted_content"), 4),
        ),
        ("prompt_cache_key", Rule::Str(256)),
        (
            "client_metadata",
            Rule::StrMap {
                entries: 32,
                value: 4096,
            },
        ),
        ("text", Rule::Object(&TEXT_CONFIG)),
        ("max_output_tokens", Rule::Number),
        ("temperature", Rule::Float(0.0, 2.0)),
        ("top_p", Rule::Float(0.0, 1.0)),
        ("stream", Rule::Bool),
    ],
    required: &["model"],
};

static CHAT_FUNCTION: Fields = Fields {
    fields: &[
        ("name", Rule::Name),
        ("description", Rule::Str(TEXT)),
        ("parameters", Rule::Schema),
        ("strict", Rule::Bool),
    ],
    required: &["name"],
};
static CHAT_TOOL: Fields = Fields {
    fields: &[
        ("type", Rule::Const("function")),
        ("function", Rule::Object(&CHAT_FUNCTION)),
    ],
    required: &["type", "function"],
};
static CHAT_TOOL_RULE: Rule = Rule::Object(&CHAT_TOOL);

static CHAT_TEXT_PART: Fields = Fields {
    fields: &[("type", Rule::Const("text")), ("text", Rule::Str(TEXT))],
    required: &["type", "text"],
};
static CHAT_TEXT_PART_RULE: Rule = Rule::Object(&CHAT_TEXT_PART);

static CHAT_CALLED: Fields = Fields {
    fields: &[("name", Rule::Name), ("arguments", Rule::Str(TEXT))],
    required: &["name", "arguments"],
};
static CHAT_CALL: Fields = Fields {
    fields: &[
        ("id", Rule::Name),
        ("type", Rule::Const("function")),
        ("function", Rule::Object(&CHAT_CALLED)),
    ],
    required: &["id", "type", "function"],
};
static CHAT_CALL_RULE: Rule = Rule::Object(&CHAT_CALL);

static CHAT_MESSAGE: Fields = Fields {
    fields: &[
        (
            "role",
            Rule::Enum(&["system", "developer", "user", "assistant", "tool"]),
        ),
        (
            "content",
            Rule::StrOr(TEXT, &Rule::Array(&CHAT_TEXT_PART_RULE, 100_000)),
        ),
        ("name", Rule::Name),
        ("tool_calls", Rule::Array(&CHAT_CALL_RULE, 512)),
        ("tool_call_id", Rule::Name),
    ],
    required: &["role"],
};
static CHAT_MESSAGE_RULE: Rule = Rule::Object(&CHAT_MESSAGE);

static STREAM_OPTIONS: Fields = Fields {
    fields: &[("include_usage", Rule::Bool)],
    required: &[],
};

/// The body of `POST /v1/chat/completions`.
pub(super) static CHAT: Fields = Fields {
    fields: &[
        ("model", Rule::Str(200)),
        ("messages", Rule::Array(&CHAT_MESSAGE_RULE, 100_000)),
        ("tools", Rule::Array(&CHAT_TOOL_RULE, 512)),
        (
            "tool_choice",
            Rule::StrOr(16, &Rule::Object(&TOOL_CHOICE_OBJECT)),
        ),
        ("parallel_tool_calls", Rule::Bool),
        ("max_tokens", Rule::Number),
        ("max_completion_tokens", Rule::Number),
        ("temperature", Rule::Float(0.0, 2.0)),
        ("top_p", Rule::Float(0.0, 1.0)),
        ("stream", Rule::Bool),
        ("stream_options", Rule::Object(&STREAM_OPTIONS)),
        ("reasoning_effort", Rule::Name),
        ("seed", Rule::Int(i64::MIN, i64::MAX)),
        ("stop", Rule::StrOr(256, &Rule::Array(&Rule::Str(256), 4))),
    ],
    required: &["model"],
};
