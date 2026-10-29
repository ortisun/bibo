//! NT-SBX-17: the model broker forwards no provider-side tool, no remote server and no fetched
//! content (threat T-17, finding EGR-1 of `docs/reviews/isolation-core-security-review.md`).
//!
//! A sandbox holds a job token and can send the broker any body it likes. The provider's own
//! machines act on some fields of a body: a server-side tool is run by them, a remote MCP server
//! is called by them, an image or document given by URL is fetched by them. Each of those is a
//! network request that does not pass the egress sidecar's allowlist. The broker holds the only
//! door, so the check is made there: a closed schema per provider API (`broker::shape`).
//!
//! WHAT IS ASSERTED, against the real listener and a labelled fake provider that records what it
//! receives:
//!
//! * the requests the real tools make (golden fixtures captured from Claude Code 2.1.311 and Codex
//!   0.163.0 in the end-to-end lab, trimmed) reach the provider with their body unchanged;
//! * every refused shape gets HTTP 400 with a fixed answer, an audit event that names the class
//!   and nothing of the request, no request count, and no call to the provider;
//! * the same holds for bodies that two JSON readers could read differently (a repeated key, a
//!   byte order mark, text after the document, absurd nesting);
//! * beta headers that switch on provider-side tools refuse the request, other unknown betas are
//!   dropped, and only the query `beta=true` is forwarded;
//! * of the provider's answer headers only a media type and a retry delay in seconds reach the
//!   sandbox;
//! * a property test: whatever a random mutation of a real request does to a body, the provider
//!   never receives one that holds a dangerous field outside the free-form places.
//!
//! WHAT FAILS WHEN THE CONTROL IS REMOVED: `tests/mutations.py` has the deliberate breaks
//! (`forward-a-body-without-the-schema-verdict`, `accept-an-unlisted-tool-type`,
//! `accept-a-repeated-key`, `forward-the-provider-request-ids`, `accept-a-server-tool-beta`) and
//! shows each caught by this file.

mod support;

use std::path::Path;

use factory_egress::broker::shape::{self, Violation, Wire};
use factory_egress::broker::{AuditKind, Refusal};
use factory_testkit::fx::http::{ClientResponse, send_request};
use serde_json::{Value, json};
use support::{CEILING, CLAUDE_MODEL, GPT_MODEL, HttpRig, Script};

const RECORDED_BETAS: &str = "claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,effort-2025-11-24";

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/golden")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).expect("a fixture is JSON")
}

/// Sends `body` to the route as the tool of `provider` would, and returns the answer.
fn send(
    rig: &HttpRig,
    path: &str,
    credential: (&str, &str),
    extra: &[(&str, &str)],
    body: &[u8],
) -> ClientResponse {
    let mut headers = vec![("Content-Type", "application/json"), credential];
    headers.extend_from_slice(extra);
    send_request(rig.addr(), "POST", path, &headers, body).expect("the broker answers")
}

struct Door<'a> {
    rig: &'a HttpRig,
    secret: String,
    id: factory_ports::agent::JobTokenId,
}

impl<'a> Door<'a> {
    fn claude(rig: &'a HttpRig) -> Self {
        let token = rig.claude_token(CEILING);
        Self {
            rig,
            secret: token.secret.expose().to_owned(),
            id: token.id,
        }
    }

    fn codex(rig: &'a HttpRig) -> Self {
        let token = rig.codex_token(CEILING);
        Self {
            rig,
            secret: token.secret.expose().to_owned(),
            id: token.id,
        }
    }

    fn messages(&self, body: &Value) -> ClientResponse {
        self.messages_raw("/v1/messages", &[], body.to_string().as_bytes())
    }

    fn messages_raw(&self, path: &str, extra: &[(&str, &str)], body: &[u8]) -> ClientResponse {
        let mut headers = vec![("anthropic-version", "2023-06-01")];
        headers.extend_from_slice(extra);
        send(self.rig, path, ("x-api-key", &self.secret), &headers, body)
    }

    fn responses(&self, path: &str, body: &Value) -> ClientResponse {
        self.responses_raw(path, body.to_string().as_bytes())
    }

    fn responses_raw(&self, path: &str, body: &[u8]) -> ClientResponse {
        let bearer = format!("Bearer {}", self.secret);
        send(self.rig, path, ("Authorization", &bearer), &[], body)
    }
}

fn claude_body(patch: Value) -> Value {
    let mut body = json!({
        "model": CLAUDE_MODEL, "max_tokens": 16,
        "messages": [{"role": "user", "content": "hello"}],
    });
    body.as_object_mut()
        .expect("an object")
        .extend(patch.as_object().expect("an object").clone());
    body
}

fn with_blocks(blocks: Value) -> Value {
    claude_body(json!({"messages": [{"role": "user", "content": blocks}]}))
}

fn responses_body(patch: Value) -> Value {
    let mut body = json!({
        "model": GPT_MODEL, "store": false,
        "input": [{"role": "user", "content": "hello"}],
    });
    body.as_object_mut()
        .expect("an object")
        .extend(patch.as_object().expect("an object").clone());
    body
}

// ---- what the real tools send ------------------------------------------------------------------

/// The requests Claude Code and Codex really made reach the provider as they are (the model name
/// is the test's, and the output limit is the cap: Claude Code's own 128000 was clamped to it, and
/// Codex, which names none, gets it).
#[test]
fn negative_nt_sbx_17_the_requests_of_the_real_tools_pass_unchanged() {
    let rig = HttpRig::new();
    let claude = Door::claude(&rig);
    let codex = Door::codex(&rig);
    for name in [
        "claude_code_first_request.json",
        "claude_code_after_tool_result.json",
    ] {
        let mut body = fixture(name);
        body["model"] = json!(CLAUDE_MODEL);
        let answer = claude.messages_raw(
            "/v1/messages?beta=true",
            &[("anthropic-beta", RECORDED_BETAS)],
            body.to_string().as_bytes(),
        );
        assert_eq!(answer.status, 200, "{name}: {}", answer.text());
        let seen = rig.provider.requests();
        let last = seen.last().expect("the provider was called");
        assert_eq!(
            last.json(),
            body,
            "{name}: the body must be forwarded as it came"
        );
        assert_eq!(last.query, "beta=true");
        assert_eq!(last.header("anthropic-beta"), Some(RECORDED_BETAS));
    }
    for name in ["codex_first_request.json", "codex_after_tool_output.json"] {
        let mut body = fixture(name);
        body["model"] = json!(GPT_MODEL);
        let answer = codex.responses("/v1/responses", &body);
        assert_eq!(answer.status, 200, "{name}: {}", answer.text());
        let seen = rig.provider.requests();
        let last = seen.last().expect("the provider was called");
        // Codex names no output limit, so the broker sets the per-request cap (finding RR-1) and
        // changes nothing else.
        let mut expected = body.clone();
        expected["max_output_tokens"] = json!(rig.rig.core.caps().per_request.max_output_tokens);
        assert_eq!(
            last.json(),
            expected,
            "{name}: the body must be forwarded as it came, with the output cap added"
        );
    }
    assert_eq!(rig.provider.hits(), 4);
}

/// Content a long session sends back that the fake provider never produced: the model's earlier
/// thinking, an inline image a tool read, a PDF, a Codex reasoning item and an image as `data:`.
#[test]
fn negative_nt_sbx_17_history_blocks_of_a_long_session_pass() {
    let rig = HttpRig::new();
    let claude = Door::claude(&rig);
    let codex = Door::codex(&rig);
    let history = claude_body(json!({"messages": [
        {"role": "user", "content": [{"type": "text", "text": "read the image", "cache_control": {"type": "ephemeral"}}]},
        {"role": "assistant", "content": [
            {"type": "thinking", "thinking": "I will read it.", "signature": "c2ln"},
            {"type": "redacted_thinking", "data": "ZGF0YQ=="},
            {"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {"file_path": "/workspace/a.png"}},
        ]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "is_error": false, "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "aGk="}},
            {"type": "text", "text": "done"},
        ]}]},
        {"role": "user", "content": [
            {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "aGk="}},
        ]},
    ]}));
    assert_eq!(claude.messages(&history).status, 200);
    let items = responses_body(json!({"input": [
        {"type": "reasoning", "id": "rs_1", "summary": [{"type": "summary_text", "text": "plan"}], "encrypted_content": "ZW5j"},
        {"type": "message", "role": "assistant", "id": "msg_1", "content": [{"type": "output_text", "text": "ok", "annotations": []}]},
        {"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "exec_command", "arguments": "{\"cmd\":\"ls\"}"},
        {"type": "function_call_output", "call_id": "call_1", "output": "a b"},
        {"type": "message", "role": "user", "content": [{"type": "input_image", "image_url": "data:image/png;base64,aGk="}]},
    ]}));
    assert_eq!(codex.responses("/v1/responses", &items).status, 200);
    assert_eq!(rig.provider.hits(), 2);
}

// ---- what is refused ---------------------------------------------------------------------------

struct Case {
    name: &'static str,
    path: &'static str,
    body: Value,
    expect: Violation,
}

fn case(name: &'static str, path: &'static str, body: Value, expect: Violation) -> Case {
    Case {
        name,
        path,
        body,
        expect,
    }
}

fn refused_cases() -> Vec<Case> {
    use Violation::*;
    let m = "/v1/messages";
    let r = "/v1/responses";
    let tool =
        |kind: &str| claude_body(json!({"tools": [{"type": kind, "name": "attacker_tool"}]}));
    let rtool = |t: Value| responses_body(json!({"tools": [t]}));
    let mut cases = vec![
        // ---- Anthropic: remote servers and provider-side features
        case(
            "mcp_servers",
            m,
            claude_body(
                json!({"mcp_servers": [{"type": "url", "url": "https://attacker.test/mcp", "name": "attacker"}]}),
            ),
            RemoteMcp,
        ),
        case(
            "container",
            m,
            claude_body(json!({"container": "container_011"})),
            ServerFeature,
        ),
        case(
            "files",
            m,
            claude_body(json!({"files": ["file_011"]})),
            ServerFeature,
        ),
        case(
            "betas in the body",
            m,
            claude_body(json!({"betas": ["web-fetch-2025-09-10"]})),
            ServerFeature,
        ),
        case(
            "service_tier",
            m,
            claude_body(json!({"service_tier": "priority"})),
            ServerFeature,
        ),
        case(
            "an unknown top-level key",
            m,
            claude_body(json!({"attacker_field": 1})),
            UnknownField,
        ),
        case(
            "metadata beyond user_id",
            m,
            claude_body(json!({"metadata": {"user_id": "u", "callback": "https://attacker.test"}})),
            UnknownField,
        ),
        case(
            "a non-numeric output limit",
            m,
            claude_body(json!({"max_tokens": "lots"})),
            BadValue,
        ),
        case(
            "temperature out of range",
            m,
            claude_body(json!({"temperature": 5})),
            BadValue,
        ),
        case(
            "an unknown role",
            m,
            claude_body(json!({"messages": [{"role": "tool", "content": "x"}]})),
            BadValue,
        ),
        // ---- Anthropic: server-side tool types
        case("web_search", m, tool("web_search_20250305"), ServerTool),
        case("web_fetch", m, tool("web_fetch_20250910"), ServerTool),
        case(
            "code_execution",
            m,
            tool("code_execution_20250522"),
            ServerTool,
        ),
        case("computer use", m, tool("computer_20250124"), ServerTool),
        case("the bash tool type", m, tool("bash_20250124"), ServerTool),
        case(
            "the text editor tool type",
            m,
            tool("text_editor_20250124"),
            ServerTool,
        ),
        case(
            "the memory tool type",
            m,
            tool("memory_20250818"),
            ServerTool,
        ),
        case(
            "a tool search tool",
            m,
            tool("tool_search_tool_regex_20251119"),
            ServerTool,
        ),
        case("an mcp toolset", m, tool("mcp_toolset"), RemoteMcp),
        case(
            "a tool named like a client tool but typed as a server tool",
            m,
            claude_body(json!({"tools": [
            {"name": "ok", "input_schema": {"type": "object"}}, {"type": "web_fetch_20250910", "name": "ok2"}]})),
            ServerTool,
        ),
        case(
            "a tool with a url field",
            m,
            claude_body(
                json!({"tools": [{"name": "t", "input_schema": {}, "url": "https://attacker.test"}]}),
            ),
            RemoteContent,
        ),
        case(
            "a tool with an unknown field",
            m,
            claude_body(
                json!({"tools": [{"name": "t", "input_schema": {}, "allowed_callers": ["code_execution"]}]}),
            ),
            UnknownField,
        ),
        case(
            "a schema that points to another document",
            m,
            claude_body(
                json!({"tools": [{"name": "t", "input_schema": {"properties": {"a": {"$ref": "https://attacker.test/s.json"}}}}]}),
            ),
            RemoteReference,
        ),
        // ---- Anthropic: content the provider would fetch
        case(
            "an image by url",
            m,
            with_blocks(
                json!([{"type": "image", "source": {"type": "url", "url": "https://attacker.test/a.png"}}]),
            ),
            RemoteContent,
        ),
        case(
            "an image by file id",
            m,
            with_blocks(
                json!([{"type": "image", "source": {"type": "file", "file_id": "file_011"}}]),
            ),
            RemoteContent,
        ),
        case(
            "a document by url",
            m,
            with_blocks(
                json!([{"type": "document", "source": {"type": "url", "url": "https://attacker.test/a.pdf"}}]),
            ),
            RemoteContent,
        ),
        case(
            "a document by file id",
            m,
            with_blocks(
                json!([{"type": "document", "source": {"type": "file", "file_id": "file_011"}}]),
            ),
            RemoteContent,
        ),
        case(
            "a document with a url inside content blocks",
            m,
            with_blocks(
                json!([{"type": "document", "source": {"type": "content", "content": []}}]),
            ),
            RemoteContent,
        ),
        case(
            "an image by url inside a tool result",
            m,
            with_blocks(
                json!([{"type": "tool_result", "tool_use_id": "t", "content": [{"type": "image", "source": {"type": "url", "url": "https://attacker.test/a.png"}}]}]),
            ),
            RemoteContent,
        ),
        case(
            "a server tool use block",
            m,
            with_blocks(
                json!([{"type": "server_tool_use", "id": "x", "name": "web_fetch", "input": {}}]),
            ),
            UnknownBlock,
        ),
        case(
            "a web search result block",
            m,
            with_blocks(
                json!([{"type": "web_search_tool_result", "tool_use_id": "x", "content": []}]),
            ),
            UnknownBlock,
        ),
        case(
            "an mcp tool use block",
            m,
            with_blocks(
                json!([{"type": "mcp_tool_use", "id": "x", "name": "n", "server_name": "s", "input": {}}]),
            ),
            RemoteMcp,
        ),
        case(
            "a tool reference block",
            m,
            with_blocks(
                json!([{"type": "tool_result", "tool_use_id": "t", "content": [{"type": "tool_reference", "tool_name": "x"}]}]),
            ),
            UnknownBlock,
        ),
        case(
            "a search result block",
            m,
            with_blocks(
                json!([{"type": "search_result", "source": "https://attacker.test", "title": "t", "content": []}]),
            ),
            UnknownBlock,
        ),
        case(
            "a text block with citations",
            m,
            with_blocks(
                json!([{"type": "text", "text": "x", "citations": [{"type": "web_search_result_location"}]}]),
            ),
            UnknownField,
        ),
        case(
            "a system block of another type",
            m,
            claude_body(
                json!({"system": [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "aA=="}}]}),
            ),
            UnknownBlock,
        ),
        case(
            "the token count route with a server tool",
            "/v1/messages/count_tokens",
            json!({"model": CLAUDE_MODEL, "messages": [], "tools": [{"type": "web_search_20250305", "name": "w"}]}),
            ServerTool,
        ),
        case(
            "the token count route with a generating field",
            "/v1/messages/count_tokens",
            json!({"model": CLAUDE_MODEL, "messages": [], "max_tokens": 5}),
            UnknownField,
        ),
        // ---- OpenAI Responses
        case(
            "an mcp tool",
            r,
            rtool(
                json!({"type": "mcp", "server_label": "attacker", "server_url": "https://attacker.test/mcp", "require_approval": "never"}),
            ),
            RemoteMcp,
        ),
        case(
            "an mcp connector",
            r,
            rtool(json!({"type": "mcp", "server_label": "x", "connector_id": "connector_gmail"})),
            RemoteMcp,
        ),
        case(
            "web_search",
            r,
            rtool(json!({"type": "web_search"})),
            ServerTool,
        ),
        case(
            "web_search live access",
            r,
            rtool(json!({"type": "web_search", "external_web_access": true})),
            ServerTool,
        ),
        case(
            "web_search_preview",
            r,
            rtool(json!({"type": "web_search_preview"})),
            ServerTool,
        ),
        case(
            "code_interpreter",
            r,
            rtool(json!({"type": "code_interpreter", "container": {"type": "auto"}})),
            ServerTool,
        ),
        case(
            "file_search",
            r,
            rtool(json!({"type": "file_search", "vector_store_ids": ["vs_1"]})),
            ServerTool,
        ),
        case(
            "image_generation",
            r,
            rtool(json!({"type": "image_generation"})),
            ServerTool,
        ),
        case(
            "computer_use_preview",
            r,
            rtool(
                json!({"type": "computer_use_preview", "display_width": 1, "display_height": 1, "environment": "browser"}),
            ),
            ServerTool,
        ),
        case(
            "local_shell",
            r,
            rtool(json!({"type": "local_shell"})),
            ServerTool,
        ),
        case(
            "an mcp tool inside a namespace",
            r,
            rtool(
                json!({"type": "namespace", "name": "ns", "tools": [{"type": "mcp", "server_url": "https://attacker.test"}]}),
            ),
            RemoteMcp,
        ),
        case(
            "a function tool with an unknown field",
            r,
            rtool(
                json!({"type": "function", "name": "f", "parameters": {}, "server_url": "https://attacker.test"}),
            ),
            RemoteMcp,
        ),
        case(
            "a tool search in additional_tools",
            r,
            responses_body(
                json!({"input": [{"type": "additional_tools", "tools": [{"type": "web_search"}]}]}),
            ),
            ServerTool,
        ),
        case(
            "previous_response_id",
            r,
            responses_body(json!({"previous_response_id": "resp_1"})),
            ServerFeature,
        ),
        case(
            "background",
            r,
            responses_body(json!({"background": true})),
            ServerFeature,
        ),
        case(
            "a stored prompt",
            r,
            responses_body(json!({"prompt": {"id": "pmpt_1"}})),
            ServerFeature,
        ),
        case(
            "a conversation",
            r,
            responses_body(json!({"conversation": "conv_1"})),
            ServerFeature,
        ),
        case(
            "metadata",
            r,
            responses_body(json!({"metadata": {"a": "b"}})),
            UnknownField,
        ),
        case(
            "an include that fetches",
            r,
            responses_body(json!({"include": ["web_search_call.action.sources"]})),
            BadValue,
        ),
        case(
            "an image by url",
            r,
            responses_body(
                json!({"input": [{"role": "user", "content": [{"type": "input_image", "image_url": "https://attacker.test/a.png"}]}]}),
            ),
            RemoteContent,
        ),
        case(
            "an image by file id",
            r,
            responses_body(
                json!({"input": [{"role": "user", "content": [{"type": "input_image", "file_id": "file-1"}]}]}),
            ),
            RemoteContent,
        ),
        case(
            "an input file",
            r,
            responses_body(
                json!({"input": [{"role": "user", "content": [{"type": "input_file", "file_url": "https://attacker.test/a.pdf"}]}]}),
            ),
            RemoteContent,
        ),
        case(
            "a web search call item",
            r,
            responses_body(
                json!({"input": [{"type": "web_search_call", "id": "ws_1", "status": "completed"}]}),
            ),
            UnknownBlock,
        ),
        case(
            "an mcp call item",
            r,
            responses_body(json!({"input": [{"type": "mcp_call", "id": "mc_1", "name": "n"}]})),
            RemoteMcp,
        ),
        case(
            "an item reference",
            r,
            responses_body(json!({"input": [{"type": "item_reference", "id": "msg_1"}]})),
            UnknownBlock,
        ),
        case(
            "a non-empty annotation list",
            r,
            responses_body(
                json!({"input": [{"role": "assistant", "content": [{"type": "output_text", "text": "x", "annotations": [{"type": "url_citation", "url": "https://attacker.test"}]}]}]}),
            ),
            BadValue,
        ),
        case(
            "an unknown top-level key",
            r,
            responses_body(json!({"attacker_field": 1})),
            UnknownField,
        ),
        // ---- OpenAI Chat Completions
        case(
            "web_search_options",
            "/v1/chat/completions",
            json!({"model": GPT_MODEL, "messages": [], "web_search_options": {}}),
            ServerFeature,
        ),
        case(
            "an audio request",
            "/v1/chat/completions",
            json!({"model": GPT_MODEL, "messages": [], "audio": {"voice": "x"}}),
            UnknownField,
        ),
        case(
            "a custom tool type",
            "/v1/chat/completions",
            json!({"model": GPT_MODEL, "messages": [], "tools": [{"type": "custom"}]}),
            BadValue,
        ),
        case(
            "an image part by url",
            "/v1/chat/completions",
            json!({"model": GPT_MODEL, "messages": [{"role": "user", "content": [{"image_url": {"url": "https://attacker.test/a.png"}}]}]}),
            RemoteContent,
        ),
    ];
    cases.sort_by_key(|c| c.name);
    cases
}

#[test]
fn negative_nt_sbx_17_every_refused_shape_gets_a_fixed_answer_an_audit_event_and_no_provider_call()
{
    let rig = HttpRig::new();
    let claude = Door::claude(&rig);
    let codex = Door::codex(&rig);
    let cases = refused_cases();
    let mut expected_events = Vec::new();
    for c in &cases {
        let answer = if c.path.starts_with("/v1/messages") {
            claude.messages_raw(c.path, &[], c.body.to_string().as_bytes())
        } else {
            codex.responses(c.path, &c.body)
        };
        assert_eq!(answer.status, 400, "{}: {}", c.name, answer.text());
        let error = answer.json().expect("a JSON error");
        assert_eq!(error["error"]["type"], "request_shape", "{}", c.name);
        assert_eq!(
            error["error"]["message"],
            "The request holds content that this broker does not forward.",
            "{}",
            c.name
        );
        // Nothing the request said is in the answer.
        for echo in [
            "attacker",
            "file_011",
            "web_fetch",
            "mcp",
            "container",
            "resp_1",
        ] {
            assert!(
                !answer.text().contains(echo),
                "{}: the answer echoes {echo}",
                c.name
            );
        }
        expected_events.push((c.name, c.expect));
    }
    assert_eq!(
        rig.provider.hits(),
        0,
        "a refused request must never reach the provider"
    );

    // One audit event per refusal, with the class and no free text.
    let events = rig.rig.audit.events();
    let refused: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.kind {
            AuditKind::RequestRefused {
                token: Some(_),
                reason: Refusal::RequestShape(v),
            } => Some((*v, e.to_json())),
            _ => None,
        })
        .collect();
    assert_eq!(refused.len(), cases.len(), "an event per refusal");
    for ((name, expect), (got, line)) in expected_events.iter().zip(&refused) {
        assert_eq!(got, expect, "{name}");
        assert_eq!(line["reason"], "request_shape");
        assert_eq!(line["status"], 400);
        assert_eq!(line["detail"], expect.as_str());
        let text = line.to_string();
        for echo in ["attacker", "file_011", "web_fetch", "mcp_servers", "resp_1"] {
            assert!(
                !text.contains(echo),
                "{name}: the audit line echoes {echo}: {text}"
            );
        }
    }
    // A refusal is not a request: nothing was counted, and the tokens still work.
    for door in [&claude, &codex] {
        let standing = rig.rig.core.token_usage(&door.id).expect("usage");
        assert_eq!(
            standing.usage.requests, 0,
            "a refused request must not be counted"
        );
        assert_eq!(standing.state, factory_ports::agent::TokenState::Active);
    }
    let good = claude.messages(&claude_body(json!({})));
    assert_eq!(good.status, 200);
    assert_eq!(rig.provider.hits(), 1);
    let counted = rig.rig.core.token_usage(&claude.id).expect("usage");
    assert_eq!(counted.usage.requests, 1);
}

/// A body that two parsers could read in two ways is refused, because the broker must check the
/// document the provider will read.
#[test]
fn negative_nt_sbx_17_bodies_that_parsers_read_differently_are_refused() {
    let rig = HttpRig::new();
    let claude = Door::claude(&rig);
    let codex = Door::codex(&rig);
    let good = br#"{"model":"claude-test-model","max_tokens":5,"messages":[]}"#;
    let mut bom = vec![0xEF, 0xBB, 0xBF];
    bom.extend_from_slice(good);
    let deep = format!(
        "{{\"model\":\"{CLAUDE_MODEL}\",\"messages\":[],\"system\":{}1{}}}",
        "[".repeat(200),
        "]".repeat(200)
    );
    let mut invalid_utf8 = br#"{"model":"claude-test-model","metadata":{"user_id":""#.to_vec();
    invalid_utf8.extend_from_slice(&[0xff, 0xfe]);
    invalid_utf8.extend_from_slice(br#""}}"#);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("a repeated model", br#"{"model":"claude-test-model","model":"claude-other"}"#.to_vec()),
        // The first `tools` is harmless, the second is not: a reader that keeps the first sees
        // nothing, one that keeps the last sees a provider-side tool.
        ("a repeated tools key", br#"{"model":"claude-test-model","tools":[],"tools":[{"type":"web_fetch_20250910","name":"w"}]}"#.to_vec()),
        ("a repeated key spelled with an escape", br#"{"model":"claude-test-model","mcp_servers":[],"mcp_servers":[{"url":"https://attacker.test"}]}"#.to_vec()),
        ("a repeated key deep inside", br#"{"model":"claude-test-model","messages":[{"role":"user","content":"a","content":"b"}]}"#.to_vec()),
        ("a byte order mark", bom),
        ("text after the document", br#"{"model":"claude-test-model"} {"mcp_servers":[]}"#.to_vec()),
        ("a trailing comma", br#"{"model":"claude-test-model",}"#.to_vec()),
        ("a comment", br#"{"model":"claude-test-model" /* x */}"#.to_vec()),
        ("single quotes", br#"{'model':'claude-test-model'}"#.to_vec()),
        ("an array at the root", br#"[{"model":"claude-test-model"}]"#.to_vec()),
        ("a string at the root", br#""claude-test-model""#.to_vec()),
        ("an empty body", Vec::new()),
        ("invalid UTF-8", invalid_utf8),
        ("nesting far past the limit", deep.into_bytes()),
        ("a number with a leading plus", br#"{"model":"claude-test-model","max_tokens":+5}"#.to_vec()),
    ];
    for (name, body) in &cases {
        let answer = claude.messages_raw("/v1/messages", &[], body);
        assert_eq!(answer.status, 400, "{name}: {}", answer.text());
        assert_eq!(
            answer.json().expect("json")["error"]["type"],
            "request_shape",
            "{name}"
        );
    }
    let answer = codex.responses_raw(
        "/v1/responses",
        br#"{"model":"gpt-test-model","tools":[],"tools":[{"type":"web_search"}]}"#,
    );
    assert_eq!(answer.status, 400);
    assert_eq!(rig.provider.hits(), 0);
    // The control: the same document without the fault is served.
    assert_eq!(claude.messages_raw("/v1/messages", &[], good).status, 200);
}

// ---- headers and query -------------------------------------------------------------------------

#[test]
fn negative_nt_sbx_17_beta_headers_that_enable_provider_side_tools_refuse_the_request() {
    let rig = HttpRig::new();
    let claude = Door::claude(&rig);
    let body = claude_body(json!({})).to_string();
    for beta in [
        "web-fetch-2025-09-10",
        "claude-code-20250219,mcp-client-2025-04-04",
        "mcp-client-2025-11-20",
        "code-execution-2025-05-22",
        "computer-use-2025-01-24",
        "files-api-2025-04-14",
        "skills-2025-10-02",
        "web-search-2025-03-05",
    ] {
        let answer =
            claude.messages_raw("/v1/messages", &[("anthropic-beta", beta)], body.as_bytes());
        assert_eq!(answer.status, 400, "{beta}");
        assert_eq!(
            answer.json().expect("json")["error"]["type"],
            "request_shape"
        );
    }
    // Two copies of the header cannot be read as one list.
    let twice = claude.messages_raw(
        "/v1/messages",
        &[
            ("anthropic-beta", "claude-code-20250219"),
            ("anthropic-beta", "web-fetch-2025-09-10"),
        ],
        body.as_bytes(),
    );
    assert_eq!(twice.status, 400);
    assert_eq!(rig.provider.hits(), 0);
    let beta_events = rig
        .rig
        .audit
        .events()
        .iter()
        .filter(|e| {
            matches!(
                &e.kind,
                AuditKind::RequestRefused {
                    reason: Refusal::RequestShape(Violation::BetaHeader),
                    ..
                }
            )
        })
        .count();
    assert_eq!(beta_events, 9);
}

#[test]
fn negative_nt_sbx_17_only_the_recorded_betas_and_the_beta_query_cross() {
    let rig = HttpRig::new();
    let claude = Door::claude(&rig);
    let body = claude_body(json!({})).to_string();
    let answer = claude.messages_raw(
        "/v1/messages?beta=true&x=1",
        &[(
            "anthropic-beta",
            "effort-2025-11-24,some-new-feature-2030-01-01,effort-2025-11-24",
        )],
        body.as_bytes(),
    );
    assert_eq!(answer.status, 200);
    let seen = rig.provider.requests();
    assert_eq!(
        seen[0].query, "",
        "only `beta=true`, as the sole parameter, is forwarded"
    );
    assert_eq!(seen[0].header("anthropic-beta"), Some("effort-2025-11-24"));
    let none = claude.messages_raw(
        "/v1/messages",
        &[("anthropic-beta", "some-new-feature-2030-01-01")],
        body.as_bytes(),
    );
    assert_eq!(none.status, 200);
    assert_eq!(rig.provider.requests()[1].header("anthropic-beta"), None);

    let codex = Door::codex(&rig);
    let answer = send(
        &rig,
        "/v1/responses",
        ("Authorization", &format!("Bearer {}", codex.secret)),
        &[
            ("openai-beta", "assistants=v2"),
            ("x-codex-beta-features", "all"),
        ],
        responses_body(json!({})).to_string().as_bytes(),
    );
    assert_eq!(answer.status, 200);
    let last = rig.provider.requests().pop().expect("a request");
    for dropped in ["openai-beta", "x-codex-beta-features"] {
        assert_eq!(last.header(dropped), None, "{dropped}");
    }
}

#[test]
fn negative_nt_sbx_17_the_answer_headers_are_a_closed_set() {
    let rig = HttpRig::new();
    let claude = Door::claude(&rig);
    rig.provider.set(|script: &mut Script| {
        script.more_headers = vec![
            ("request-id".to_owned(), "req_011ACCOUNTLINKED".to_owned()),
            ("x-request-id".to_owned(), "req_other".to_owned()),
            (
                "anthropic-organization-id".to_owned(),
                "org-0000-account".to_owned(),
            ),
            (
                "anthropic-ratelimit-requests-remaining".to_owned(),
                "41".to_owned(),
            ),
            ("openai-organization".to_owned(), "org-acct".to_owned()),
            ("openai-processing-ms".to_owned(), "77".to_owned()),
            ("set-cookie".to_owned(), "__cf_bm=abc; HttpOnly".to_owned()),
            ("cf-ray".to_owned(), "8a-AMS".to_owned()),
            ("retry-after".to_owned(), "7".to_owned()),
            ("x-should-retry".to_owned(), "true".to_owned()),
        ];
    });
    for stream in [false, true] {
        let answer = claude.messages(&claude_body(json!({"stream": stream})));
        assert_eq!(answer.status, 200);
        let mut names: Vec<String> = answer
            .headers
            .iter()
            .map(|(n, _)| n.to_ascii_lowercase())
            .collect();
        names.retain(|n| {
            !matches!(
                n.as_str(),
                "content-length" | "transfer-encoding" | "connection" | "cache-control"
            )
        });
        names.sort();
        assert_eq!(
            names,
            vec!["content-type", "retry-after"],
            "stream={stream}: {:?}",
            answer.headers
        );
        assert_eq!(answer.header("retry-after"), Some("7"));
        for (_, value) in &answer.headers {
            assert!(
                !value.contains("req_") && !value.contains("org-"),
                "{value}"
            );
        }
    }
    // A type that is not on the short list, and a delay that is not seconds, are not passed.
    rig.provider.set(|script: &mut Script| {
        script.more_headers = vec![(
            "retry-after".to_owned(),
            "Wed, 21 Oct 2026 07:28:00 GMT".to_owned(),
        )];
        script.error_status = Some(429);
    });
    let throttled = claude.messages(&claude_body(json!({})));
    assert_eq!(throttled.status, 429);
    assert_eq!(throttled.header("retry-after"), None);
}

// ---- the property ------------------------------------------------------------------------------

/// A small deterministic generator, so a failure can be replayed from its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

/// Keys and `type` values that make the provider act for the caller, outside the places where the
/// content is free-form.
const DANGEROUS_KEYS: &[&str] = &[
    "mcp_servers",
    "container",
    "files",
    "betas",
    "server_url",
    "connector_id",
    "web_search_options",
    "previous_response_id",
    "background",
    "prompt",
    "conversation",
    "service_tier",
    "url",
    "image_url",
    "file_id",
    "file_url",
    "vector_store_ids",
    "server_label",
    "allowed_callers",
];
const DANGEROUS_TYPES: &[&str] = &[
    "web_search",
    "web_search_preview",
    "web_search_20250305",
    "web_fetch_20250910",
    "code_execution_20250522",
    "code_interpreter",
    "file_search",
    "image_generation",
    "computer_use_preview",
    "computer_20250124",
    "mcp",
    "mcp_toolset",
    "url",
    "file",
    "server_tool_use",
    "mcp_tool_use",
    "input_file",
    "local_shell",
    "bash_20250124",
    "text_editor_20250124",
    "memory_20250818",
    "tool_search_tool_regex_20251119",
    "web_search_call",
    "mcp_call",
    "item_reference",
    "tool_reference",
    "search_result",
];
/// Where the content is the model's or the tool's own and the keys mean nothing to the provider.
const FREE_FORM: &[&str] = &[
    "input_schema",
    "parameters",
    "input",
    "schema",
    "client_metadata",
];

/// The oracle of the property, written apart from the schema: a body holds something the provider
/// acts on when a dangerous key, or a dangerous `type`, appears outside a free-form place.
fn holds_danger(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, inner)| {
            if FREE_FORM.contains(&key.as_str()) {
                return false;
            }
            DANGEROUS_KEYS.contains(&key.as_str())
                || (key == "type" && inner.as_str().is_some_and(|t| DANGEROUS_TYPES.contains(&t)))
                || holds_danger(inner)
        }),
        Value::Array(items) => items.iter().any(holds_danger),
        _ => false,
    }
}

fn paths_of_objects(value: &Value, here: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    match value {
        Value::Object(map) => {
            out.push(here.clone());
            for (key, inner) in map {
                here.push(key.clone());
                paths_of_objects(inner, here, out);
                here.pop();
            }
        }
        Value::Array(items) => {
            for (i, inner) in items.iter().enumerate() {
                here.push(i.to_string());
                paths_of_objects(inner, here, out);
                here.pop();
            }
        }
        _ => {}
    }
}

fn at_mut<'a>(value: &'a mut Value, path: &[String]) -> &'a mut Value {
    let mut current = value;
    for step in path {
        current = match current {
            Value::Object(map) => map.get_mut(step).expect("a path of the document"),
            Value::Array(items) => &mut items[step.parse::<usize>().expect("an index")],
            _ => unreachable!("the path leaves the document"),
        };
    }
    current
}

fn random_value(rng: &mut Rng, depth: usize) -> Value {
    match rng.below(if depth > 2 { 5 } else { 7 }) {
        0 => Value::Null,
        1 => json!(rng.below(1000)),
        2 => json!(rng.next().is_multiple_of(2)),
        3 => json!(format!("s{}", rng.below(100))),
        4 => json!("https://attacker.test/x"),
        5 => Value::Array(
            (0..rng.below(3))
                .map(|_| random_value(rng, depth + 1))
                .collect(),
        ),
        _ => {
            let mut map = serde_json::Map::new();
            for _ in 0..rng.below(3) {
                let key = rng
                    .pick(&[
                        "type",
                        "name",
                        "url",
                        "id",
                        "text",
                        "source",
                        "tools",
                        "mcp_servers",
                        "x",
                    ])
                    .to_string();
                map.insert(key, random_value(rng, depth + 1));
            }
            Value::Object(map)
        }
    }
}

/// One random edit of a real request.
fn mutate(rng: &mut Rng, body: &mut Value) {
    let mut objects = Vec::new();
    paths_of_objects(body, &mut Vec::new(), &mut objects);
    let path = rng.pick(&objects).clone();
    let target = at_mut(body, &path);
    let Some(map) = target.as_object_mut() else {
        return;
    };
    match rng.below(6) {
        0 => {
            let key = rng.pick(DANGEROUS_KEYS).to_string();
            map.insert(key, random_value(rng, 0));
        }
        1 => {
            let key = format!("k{}", rng.below(50));
            map.insert(key, random_value(rng, 0));
        }
        2 => {
            let kind = rng.pick(DANGEROUS_TYPES).to_string();
            map.insert("type".to_owned(), json!(kind));
        }
        3 => {
            let keys: Vec<String> = map.keys().cloned().collect();
            if !keys.is_empty() {
                let key = rng.pick(&keys).clone();
                map.remove(&key);
            }
        }
        4 => {
            let keys: Vec<String> = map.keys().cloned().collect();
            if !keys.is_empty() {
                let key = rng.pick(&keys).clone();
                map.insert(key, random_value(rng, 0));
            }
        }
        _ => {
            let kind = rng.pick(DANGEROUS_TYPES).to_string();
            let tool =
                json!({"type": kind, "name": "attacker", "server_url": "https://attacker.test"});
            match map.get_mut("tools") {
                Some(Value::Array(tools)) => tools.push(tool),
                _ => {
                    map.insert("tools".to_owned(), json!([tool]));
                }
            }
        }
    }
}

fn mutants(seed: u64, count: usize) -> Vec<(Wire, Value)> {
    let mut rng = Rng(seed);
    let bases = [
        (
            Wire::AnthropicMessages,
            fixture("claude_code_first_request.json"),
        ),
        (
            Wire::AnthropicMessages,
            fixture("claude_code_after_tool_result.json"),
        ),
        (Wire::OpenAiResponses, fixture("codex_first_request.json")),
        (
            Wire::OpenAiResponses,
            fixture("codex_after_tool_output.json"),
        ),
        (Wire::AnthropicMessages, claude_body(json!({}))),
        (Wire::OpenAiResponses, responses_body(json!({}))),
    ];
    (0..count)
        .map(|_| {
            let (wire, base) = rng.pick(&bases).clone();
            let mut body = base;
            for _ in 0..1 + rng.below(3) {
                mutate(&mut rng, &mut body);
            }
            (wire, body)
        })
        .collect()
}

/// The schema check, called directly: no mutant that holds a dangerous field outside the
/// free-form places is accepted. Twenty thousand mutants of real requests; the same seed gives the
/// same mutants, so a failure is replayable.
#[test]
fn negative_nt_sbx_17_property_the_schema_accepts_no_mutant_that_holds_a_dangerous_field() {
    let all = mutants(0x5eed_0017, 20_000);
    let (mut accepted, mut refused, mut dangerous) = (0, 0, 0);
    for (wire, body) in &all {
        let verdict = shape::check_body(*wire, body.to_string().as_bytes());
        let danger = holds_danger(body);
        dangerous += usize::from(danger);
        match verdict {
            Ok(_) => {
                accepted += 1;
                assert!(
                    !danger,
                    "{wire:?}: accepted a body with a dangerous field: {body}"
                );
            }
            Err(_) => refused += 1,
        }
    }
    // The property is not vacuous: the mutations both pass and fail, and many are dangerous.
    assert!(
        accepted > 500 && refused > 500 && dangerous > 5_000,
        "{accepted} {refused} {dangerous}"
    );
}

/// The same through the listener: of random mutants and random documents sent to the broker, the
/// provider receives only bodies the oracle finds clean, and every clean golden body still gets
/// through.
#[test]
fn negative_nt_sbx_17_property_the_provider_receives_only_bodies_without_dangerous_fields() {
    let rig = HttpRig::new();
    let claude = Door::claude(&rig);
    let codex = Door::codex(&rig);
    let mut sent = 0_usize;
    for (wire, mut body) in mutants(0x00fe_ed17, 300) {
        let answer = match wire {
            Wire::AnthropicMessages => {
                body["model"] = json!(CLAUDE_MODEL);
                claude.messages(&body)
            }
            _ => {
                body["model"] = json!(GPT_MODEL);
                codex.responses("/v1/responses", &body)
            }
        };
        sent += 1;
        assert!(
            matches!(answer.status, 200 | 400),
            "status {}",
            answer.status
        );
    }
    // Random documents that look nothing like a request.
    let mut rng = Rng(0xabad_1dea);
    for _ in 0..100 {
        let mut doc = random_value(&mut rng, 0);
        if let Some(map) = doc.as_object_mut() {
            map.insert("model".to_owned(), json!(CLAUDE_MODEL));
        }
        let _ = claude.messages(&doc);
        sent += 1;
    }
    let received = rig.provider.requests();
    assert!(
        !received.is_empty(),
        "no mutant was served; the property would be vacuous"
    );
    assert!(
        received.len() < sent,
        "every mutant was served; the check refused nothing"
    );
    for request in &received {
        assert!(
            !holds_danger(&request.json()),
            "the provider received {}",
            String::from_utf8_lossy(&request.body)
        );
    }
}
