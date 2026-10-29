//! What the broker lets into a request to a model provider: a default-deny check of the body, the
//! beta headers and the query, per provider API.
//!
//! # Why this exists (finding EGR-1 of `docs/reviews/isolation-core-security-review.md`)
//!
//! The sandbox may only talk to the broker, and the broker has the provider's key. A body that the
//! broker forwards as it came lets the sandbox use the *provider's* network instead of its own:
//! a server-side tool (`web_fetch`, `web_search`, `code_execution`, computer use), a remote MCP
//! server, an image or document given by URL, a file id, or a container are all executed or
//! fetched by the provider's machines, outside the egress sidecar's allowlist. The model is not
//! trusted to refrain (T-17), and a job with a shell can send the request itself, so the check is
//! made here, on the bytes, before anything is sent.
//!
//! The check is a closed schema per API. A body is accepted only when every field it holds is one
//! the factory's two runtimes (Claude Code 2.1.311 through the Messages API and Codex 0.163.0
//! through the Responses API) really send, has the type and size the schema gives it, and nothing
//! else is in it. There is no list of forbidden fields to forget to extend. The fields were taken
//! from the sessions recorded in `fixtures/recordings/agent-cli`, from requests the real tools
//! made in the end-to-end lab (`crates/egress/tests/e2e_docker.rs`), and from the published shape
//! of the API for the history a long session sends back (thinking blocks, reasoning items). The
//! history shapes could not be seen against a real provider (no real model is called anywhere in
//! this repository), so they are UNVERIFIED against live traffic; the fixed error and the audit
//! event name the class of what was refused, and widening the schema is one reviewed line in
//! `anthropic.rs` or `openai.rs`.
//!
//! # What is parsed, and how
//!
//! [`check_body`] reads the body with [`json::parse`]: one document, no byte order mark, no text
//! around it, no repeated key (compared after escapes are decoded), nesting at most
//! [`json::MAX_DEPTH`]. A parser that took the last of two equal keys while the provider took the
//! first would let a harmless-looking field hide a dangerous one. The bytes that were checked are
//! the bytes that are forwarded (the output token limit is clamped afterwards, from the same
//! parsed value).
//!
//! # The fields that are allowed, and why
//!
//! Anything not in these tables is refused, at any depth.
//!
//! **Anthropic Messages** (`POST /v1/messages`)
//!
//! | Field | Allowed content | Why |
//! |---|---|---|
//! | `model` | a string; the broker checks it against the token's list | routing and price |
//! | `max_tokens` | a number; clamped to the per-request cap | Claude Code sends 128000 |
//! | `messages` | roles `user`, `assistant`, `system`; content as text or blocks; a per-message `output_config.effort` | recorded: Claude Code sends mid-conversation `system` messages |
//! | blocks | `text`; `image` and `document` with an inline `base64` source (or plain text document); `tool_use` (`id`, `name`, `input`); `tool_result` (`tool_use_id`, `content` text or image blocks, `is_error`); `thinking` (with `signature`); `redacted_thinking`; each may carry `cache_control: ephemeral` | the Read tool returns images and PDFs inline; the history carries the model's earlier reasoning |
//! | `system` | text, or text blocks | recorded |
//! | `stream` | a boolean | streaming answers |
//! | `tools` | client tools only: `name`, `description`, `input_schema`, `cache_control`, `defer_loading`, and `type: custom` | recorded; a tool with any other `type` is run by the provider |
//! | `tool_choice` | `auto`, `any`, `none`, `tool` with a name | tool use |
//! | `thinking` | `enabled`, `disabled`, `adaptive`, a budget, a display label | recorded |
//! | `output_config` | `effort` | recorded |
//! | `context_management` | `edits` of `clear_thinking_20251015` or `clear_tool_uses_20250919` | recorded |
//! | `metadata` | `user_id` only | recorded: a device and session label |
//! | `temperature`, `top_p`, `top_k`, `stop_sequences` | in the API's own bounds | sampling |
//!
//! Refused with a class of their own: `mcp_servers` (a remote MCP server the provider connects
//! to), `container`, `files`, `betas`, `service_tier`, a content block of any other type, an
//! `image` or `document` whose source is a URL or a file id, a tool schema with a `$ref` that
//! points outside the schema, and every key not in the table.
//!
//! **OpenAI Responses** (`POST /v1/responses`)
//!
//! | Field | Allowed content | Why |
//! |---|---|---|
//! | `model` | as above | routing and price |
//! | `input` | text, or items: `message` (`input_text`, `output_text`, `refusal`, `input_image` as a `data:` URL), `function_call`, `function_call_output`, `custom_tool_call`, `custom_tool_call_output`, `reasoning`, and `additional_tools` | recorded: Codex sends exactly these |
//! | `instructions`, `prompt_cache_key`, `client_metadata`, `include`, `reasoning`, `text`, `store`, `parallel_tool_calls`, `tool_choice`, `stream` | small, typed values; `include` only `reasoning.encrypted_content`; `text.format` may be `text`, `json_object` or `json_schema` | recorded |
//! | `max_output_tokens`, `temperature`, `top_p` | as above | sampling and cost |
//! | `tools` | `function`, `custom` (a free-text tool, optionally with a grammar) and `namespace` (a group of those) | recorded |
//!
//! Refused: `web_search`, `web_search_preview`, `mcp` (with `server_url` or `connector_id`),
//! `code_interpreter`, `file_search`, `image_generation`, `computer_use_preview`, `local_shell`,
//! `apply_patch` and any other tool `type`; `previous_response_id`, `conversation`, `background`,
//! `prompt`, `metadata`; an `input_file`, or an `input_image` that is not inline data.
//!
//! **OpenAI Chat Completions** (`POST /v1/chat/completions`). No factory runtime uses it. It is
//! kept to messages of text, function tools and the sampling fields; `web_search_options`,
//! `audio`, `modalities`, `prediction`, `response_format` and the rest are refused.
//!
//! **Anthropic token count** (`POST /v1/messages/count_tokens`): the Messages fields that are
//! counted (`model`, `messages`, `system`, `tools`, `tool_choice`, `thinking`).
//!
//! # Headers, query and the answer
//!
//! * `anthropic-beta`: the values Claude Code sends (list in [`headers`]) pass; a value that
//!   switches on a provider-side tool, a remote server or a file store (`mcp-*`, `web-fetch-*`,
//!   `web-search-*`, `code-execution-*`, `computer-use-*`, `files-api-*`, `skills-*`,
//!   `tool-search-*`) refuses the request; any other value is dropped. `openai-beta` is dropped.
//! * The query: `beta=true` on the Anthropic routes, nothing else.
//! * The answer: of the provider's headers only the media type (three known types, else opaque
//!   bytes) and a retry delay in whole seconds reach the sandbox. The provider's request
//!   identifiers, organization, region, rate-limit counters and any other header do not; they
//!   identify the broker's account, and nothing in the sandbox needs them.
//!
//! # What a refusal looks like
//!
//! The sandbox gets HTTP 400 with a fixed sentence. The audit stream gets a `request_refused`
//! event with `reason: "request_shape"` and `detail`, the [`Violation`] class. Neither carries the
//! key, the value or the position that was wrong: those are text the sandbox chose. The request is
//! not counted against the token's request cap, and nothing reaches the provider.
//!
//! # Where the data belongs
//!
//! The schemas are code, not policy data, on purpose: a field added to an allow list is a change
//! to what the provider may do for a sandbox, and should be reviewed with a test next to it. The
//! architect may move them to `policies/` as data later; the walker in `rules.rs` already treats
//! them as data.

pub mod headers;
pub mod json;

mod anthropic;
mod openai;
mod rules;

use serde_json::{Map, Value};

use crate::broker::Provider;
use rules::Fields;

/// Why a request was refused. The set is closed, and a variant carries nothing the sandbox wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Violation {
    /// The body is not exactly one well-formed JSON object.
    Malformed,
    /// The body nests deeper than [`json::MAX_DEPTH`].
    TooDeep,
    /// An object names the same key twice.
    DuplicateKey,
    /// A key the schema does not list.
    UnknownField,
    /// A tool of a type the provider runs itself, or an unlisted tool type.
    ServerTool,
    /// A remote MCP server, connector or `server_url`.
    RemoteMcp,
    /// A provider-side feature: container, file store, stored prompt, background run.
    ServerFeature,
    /// A content block or input item of an unlisted type.
    UnknownBlock,
    /// An image, document or file the provider would have to fetch from an address or a store.
    RemoteContent,
    /// A schema reference that points outside its document.
    RemoteReference,
    /// A listed field with a value of the wrong type, size or range.
    BadValue,
    /// A beta header that switches on a provider-side tool, or is malformed.
    BetaHeader,
}

impl Violation {
    /// The name used in audit lines.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::TooDeep => "too_deep",
            Self::DuplicateKey => "duplicate_key",
            Self::UnknownField => "unknown_field",
            Self::ServerTool => "server_tool",
            Self::RemoteMcp => "remote_mcp",
            Self::ServerFeature => "server_feature",
            Self::UnknownBlock => "unknown_block",
            Self::RemoteContent => "remote_content",
            Self::RemoteReference => "remote_reference",
            Self::BadValue => "bad_value",
            Self::BetaHeader => "beta_header",
        }
    }
}

/// The API a request body is written for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// `POST /v1/messages`.
    AnthropicMessages,
    /// `POST /v1/messages/count_tokens`.
    AnthropicCountTokens,
    /// `POST /v1/responses`.
    OpenAiResponses,
    /// `POST /v1/chat/completions`.
    OpenAiChat,
}

impl Wire {
    /// The API behind a request path, or `None` for a path the broker does not forward.
    #[must_use]
    pub fn for_path(path: &str) -> Option<Self> {
        match path {
            "/v1/messages" => Some(Self::AnthropicMessages),
            "/v1/messages/count_tokens" => Some(Self::AnthropicCountTokens),
            "/v1/responses" => Some(Self::OpenAiResponses),
            "/v1/chat/completions" => Some(Self::OpenAiChat),
            _ => None,
        }
    }

    /// The provider that serves the API.
    #[must_use]
    pub const fn provider(self) -> Provider {
        match self {
            Self::AnthropicMessages | Self::AnthropicCountTokens => Provider::Anthropic,
            Self::OpenAiResponses | Self::OpenAiChat => Provider::OpenAi,
        }
    }

    fn fields(self) -> &'static Fields {
        match self {
            Self::AnthropicMessages => &anthropic::MESSAGES,
            Self::AnthropicCountTokens => &anthropic::COUNT_TOKENS,
            Self::OpenAiResponses => &openai::RESPONSES,
            Self::OpenAiChat => &openai::CHAT,
        }
    }
}

/// The top-level keys a body for this API may hold. For documentation and tests.
#[must_use]
pub fn allowed_top_level_fields(wire: Wire) -> Vec<&'static str> {
    wire.fields().fields.iter().map(|(name, _)| *name).collect()
}

/// The largest body this module reads. The listener refuses a larger one before it reads it; the
/// check is repeated here so that the function is safe on its own.
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Reads `body` as the request of `wire` and checks it against the allow schema.
///
/// # Errors
/// The [`Violation`] class of the first thing found wrong. Nothing about the body is in it.
pub fn check_body(wire: Wire, body: &[u8]) -> Result<Map<String, Value>, Violation> {
    if body.len() > MAX_BODY_BYTES {
        return Err(Violation::Malformed);
    }
    let Value::Object(object) = json::parse(body)? else {
        return Err(Violation::Malformed);
    };
    let fields = wire.fields();
    for (key, value) in rules::in_key_order(&object) {
        match fields.fields.iter().find(|(name, _)| name == key) {
            Some((_, rule)) => rules::check(value, rule)?,
            None => return Err(rules::classify_key(key)),
        }
    }
    for required in fields.required {
        if !object.contains_key(*required) {
            return Err(Violation::BadValue);
        }
    }
    Ok(object)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn check(wire: Wire, body: &Value) -> Result<(), Violation> {
        check_body(wire, body.to_string().as_bytes()).map(|_| ())
    }

    #[test]
    fn a_plain_text_request_of_each_api_passes() {
        assert_eq!(
            check(
                Wire::AnthropicMessages,
                &json!({"model": "m", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]})
            ),
            Ok(())
        );
        assert_eq!(
            check(
                Wire::OpenAiResponses,
                &json!({"model": "m", "store": false, "input": [{"role": "user", "content": "hi"}]})
            ),
            Ok(())
        );
        assert_eq!(
            check(
                Wire::OpenAiChat,
                &json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]})
            ),
            Ok(())
        );
    }

    #[test]
    fn provider_side_tools_and_remote_servers_are_refused_with_their_class() {
        let messages = |extra: Value| {
            let mut body = json!({"model": "m", "messages": []});
            body.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            body
        };
        assert_eq!(
            check(
                Wire::AnthropicMessages,
                &messages(json!({"tools": [{"type": "web_fetch_20250910", "name": "web_fetch"}]}))
            ),
            Err(Violation::ServerTool)
        );
        assert_eq!(
            check(
                Wire::AnthropicMessages,
                &messages(
                    json!({"mcp_servers": [{"type": "url", "url": "https://attacker.test"}]})
                )
            ),
            Err(Violation::RemoteMcp)
        );
        assert_eq!(
            check(
                Wire::AnthropicMessages,
                &messages(json!({"container": "container_011"}))
            ),
            Err(Violation::ServerFeature)
        );
        assert_eq!(
            check(
                Wire::OpenAiResponses,
                &json!({"model": "m", "tools": [{"type": "mcp", "server_url": "https://attacker.test"}]})
            ),
            Err(Violation::RemoteMcp)
        );
        assert_eq!(
            check(
                Wire::OpenAiResponses,
                &json!({"model": "m", "tools": [{"type": "web_search"}]})
            ),
            Err(Violation::ServerTool)
        );
    }

    #[test]
    fn content_the_provider_would_fetch_is_refused() {
        let with_block = |block: Value| json!({"model": "m", "messages": [{"role": "user", "content": [block]}]});
        for source in [
            json!({"type": "url", "url": "https://attacker.test/x.png"}),
            json!({"type": "file", "file_id": "file_011"}),
        ] {
            assert_eq!(
                check(
                    Wire::AnthropicMessages,
                    &with_block(json!({"type": "image", "source": source}))
                ),
                Err(Violation::RemoteContent)
            );
        }
        assert_eq!(
            check(
                Wire::AnthropicMessages,
                &with_block(json!({"type": "mcp_tool_use", "id": "x", "name": "n", "input": {}}))
            ),
            Err(Violation::RemoteMcp)
        );
        assert_eq!(
            check(
                Wire::AnthropicMessages,
                &with_block(
                    json!({"type": "server_tool_use", "id": "x", "name": "n", "input": {}})
                )
            ),
            Err(Violation::UnknownBlock)
        );
        assert_eq!(
            check(
                Wire::OpenAiResponses,
                &json!({"model": "m", "input": [{"role": "user", "content": [
                    {"type": "input_image", "image_url": "https://attacker.test/x.png"}]}]})
            ),
            Err(Violation::RemoteContent)
        );
        assert_eq!(
            check(
                Wire::OpenAiResponses,
                &json!({"model": "m", "input": [{"role": "user", "content": [
                    {"type": "input_file", "file_id": "file-1"}]}]})
            ),
            Err(Violation::RemoteContent)
        );
    }

    #[test]
    fn the_routes_and_their_providers_agree() {
        for (path, provider) in [
            ("/v1/messages", Provider::Anthropic),
            ("/v1/messages/count_tokens", Provider::Anthropic),
            ("/v1/responses", Provider::OpenAi),
            ("/v1/chat/completions", Provider::OpenAi),
        ] {
            assert_eq!(
                Wire::for_path(path).map(Wire::provider),
                Some(provider),
                "{path}"
            );
        }
        assert_eq!(Wire::for_path("/v1/files"), None);
        assert_eq!(Wire::for_path("/v1/messages/batches"), None);
    }

    #[test]
    fn the_top_level_field_lists_are_the_documented_ones() {
        let names = allowed_top_level_fields(Wire::AnthropicMessages);
        for expected in [
            "model",
            "max_tokens",
            "messages",
            "system",
            "tools",
            "stream",
        ] {
            assert!(names.contains(&expected), "{expected}");
        }
        for never in ["mcp_servers", "container", "files", "betas", "service_tier"] {
            assert!(!names.contains(&never), "{never}");
        }
        let names = allowed_top_level_fields(Wire::OpenAiResponses);
        for never in [
            "previous_response_id",
            "background",
            "prompt",
            "metadata",
            "conversation",
        ] {
            assert!(!names.contains(&never), "{never}");
        }
    }
}
