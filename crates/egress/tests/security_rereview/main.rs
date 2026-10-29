//! Security re-review of the model broker's allow schema and of the relay's range policy
//! (docs/reviews/isolation-core-security-rereview.md). Written by a reviewer who did not write the
//! schema and did not write the first review.
//!
//! Tests marked `#[ignore = "confirmed defect RR-n: ..."]` fail today and show a defect; they pass
//! when the defect is fixed. Tests without `#[ignore]` pin an attack the re-review tried and that
//! the code withstood. Run the defect tests with:
//!
//! ```text
//! CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 \
//!   cargo test -p factory-egress --test security_rereview -- --ignored
//! ```
//!
//! No real key, no real provider, no external network: the provider is the labelled fake of the
//! egress test support, on the loopback address. Every secret-shaped value is built at run time.

#[path = "../support/mod.rs"]
mod support;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use factory_egress::broker::shape::{self, Violation, Wire};
use factory_egress::relay::policy::{default_deny_ranges, is_denied};
use factory_testkit::fx::http::{ClientResponse, send_request};
use serde_json::{Map, Value, json};
use support::{CEILING, CLAUDE_MODEL, GPT_MODEL, HttpRig};

// ---- helpers ------------------------------------------------------------------------------------

fn check(wire: Wire, body: &Value) -> Result<(), Violation> {
    shape::check_body(wire, body.to_string().as_bytes()).map(|_| ())
}

fn check_raw(wire: Wire, body: &[u8]) -> Result<(), Violation> {
    shape::check_body(wire, body).map(|_| ())
}

fn messages_with(extra: Value) -> Value {
    let mut body = json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]});
    body.as_object_mut()
        .expect("an object")
        .extend(extra.as_object().expect("an object").clone());
    body
}

fn responses_with(extra: Value) -> Value {
    let mut body = json!({"model": "m", "input": [{"role": "user", "content": "hi"}]});
    body.as_object_mut()
        .expect("an object")
        .extend(extra.as_object().expect("an object").clone());
    body
}

/// Sends raw bytes to the listener and returns the status line's code and the whole answer.
fn raw(addr: SocketAddr, bytes: &[u8]) -> (Option<u16>, String) {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("timeout");
    let _ = stream.write_all(bytes);
    let _ = stream.flush();
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    let text = String::from_utf8_lossy(&answer).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok());
    (status, text)
}

fn post(rig: &HttpRig, path: &str, headers: &[(&str, &str)], body: &Value) -> ClientResponse {
    send_request(
        rig.addr(),
        "POST",
        path,
        headers,
        body.to_string().as_bytes(),
    )
    .expect("the broker answers")
}

// ---- a different generator from the author's ------------------------------------------------------
//
// The author's property test takes a recorded request and mutates it, and judges the result with a
// list of dangerous keys and types in which the keys `input`, `schema` and `client_metadata` are
// "free-form" wherever they appear, so the whole of the Responses `input` array is outside what it
// looks at. This generator builds requests from a grammar of valid constructs and, at every choice,
// sometimes takes a value from a pool of hostile ones. The oracle is written the other way round: it
// does not list what is dangerous, it lists the only keys and tags that may appear outside the three
// free-form places (decided by position, not by name) and follows URL-looking strings: such a
// string may sit only in a key that holds text for the model.

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).expect("small")
    }
    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }
}

const HOSTILE_KEYS: &[&str] = &[
    "url",
    "image_url",
    "file_id",
    "file_url",
    "server_url",
    "uri",
    "mcp_servers",
    "container",
    "files",
    "betas",
    "service_tier",
    "previous_response_id",
    "conversation",
    "background",
    "prompt",
    "web_search_options",
    "connector_id",
    "authorization",
    "headers",
    "allowed_tools",
    "require_approval",
    "server_label",
    "citations",
    "title",
    "context",
    "input_examples",
    "allowed_callers",
    "strict_tools",
    "__proto__",
    "constructor",
    "Type",
    "TYPE",
    "tools ",
    "\u{0}",
    "",
];

const HOSTILE_TAGS: &[&str] = &[
    "mcp",
    "mcp_toolset",
    "mcp_tool_use",
    "mcp_tool_result",
    "mcp_call",
    "mcp_list_tools",
    "web_search",
    "web_search_preview",
    "web_search_call",
    "web_search_tool_result",
    "web_fetch_20250910",
    "code_execution_20250522",
    "code_interpreter",
    "file_search",
    "image_generation",
    "computer_use_preview",
    "computer_20250124",
    "bash_20250124",
    "text_editor_20250124",
    "memory_20250818",
    "tool_search_tool_regex_20251119",
    "local_shell",
    "shell",
    "apply_patch",
    "server_tool_use",
    "container_upload",
    "search_result",
    "tool_reference",
    "item_reference",
    "input_file",
    "url",
    "file",
    "compaction",
    "Custom",
    "FUNCTION",
];

const HOSTILE_STRINGS: &[&str] = &[
    "https://attacker.test/x",
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "//attacker.test/x",
    "ftp://attacker.test/",
    "ws://attacker.test/",
    "s3://bucket/key",
    "gs://bucket/key",
    "data:text/html,<script>1</script>",
    "javascript:alert(1)",
    "\\\\attacker.test\\share",
    "#/definitions/ok",
    "#",
];

fn hostile_or(rng: &mut Rng, plain: Value) -> Value {
    if rng.chance(40) {
        Value::String(rng.pick(HOSTILE_STRINGS).to_string())
    } else if rng.chance(60) {
        json!({ *rng.pick(HOSTILE_KEYS): rng.pick(HOSTILE_STRINGS) })
    } else {
        plain
    }
}

fn text_value(rng: &mut Rng) -> Value {
    let n = rng.below(1000);
    hostile_or(rng, Value::String(format!("t{n}")))
}

fn with_noise(rng: &mut Rng, mut object: Map<String, Value>) -> Value {
    if rng.chance(8) {
        object.insert(
            rng.pick(HOSTILE_KEYS).to_string(),
            hostile_or(rng, json!(1)),
        );
    }
    if rng.chance(30) {
        object.insert("type".to_owned(), json!(rng.pick(HOSTILE_TAGS)));
    }
    Value::Object(object)
}

fn schema(rng: &mut Rng, depth: usize) -> Value {
    let mut map = Map::new();
    map.insert("type".to_owned(), json!("object"));
    if depth < 3 && rng.chance(2) {
        let mut props = Map::new();
        props.insert("a".to_owned(), schema(rng, depth + 1));
        if rng.chance(5) {
            props.insert("$ref".to_owned(), json!({"type": "string"}));
        }
        map.insert("properties".to_owned(), Value::Object(props));
    }
    if rng.chance(4) {
        let target = match rng.below(4) {
            0 => "#/definitions/a".to_owned(),
            1 => "#".to_owned(),
            _ => rng.pick(HOSTILE_STRINGS).to_string(),
        };
        let key = *rng.pick(&["$ref", "$dynamicRef", "$recursiveRef"]);
        map.insert(key.to_owned(), Value::String(target));
    }
    Value::Object(map)
}

fn anthropic_block(rng: &mut Rng) -> Value {
    let mut m = Map::new();
    match rng.below(7) {
        0 => {
            m.insert("type".into(), json!("text"));
            m.insert("text".into(), text_value(rng));
            if rng.chance(4) {
                m.insert(
                    "cache_control".into(),
                    json!({"type": "ephemeral", "ttl": rng.pick(&["5m", "1h", "1d"])}),
                );
            }
        }
        1 => {
            m.insert("type".into(), json!("image"));
            let source = match rng.below(3) {
                0 => json!({"type": "base64", "media_type": "image/png", "data": text_value(rng)}),
                1 => json!({"type": "url", "url": text_value(rng)}),
                _ => json!({"type": *rng.pick(HOSTILE_TAGS), "data": text_value(rng)}),
            };
            m.insert("source".into(), source);
        }
        2 => {
            m.insert("type".into(), json!("document"));
            m.insert(
                "source".into(),
                json!({"type": rng.pick(&["base64", "text", "url", "file", "content"]),
                       "media_type": rng.pick(&["application/pdf", "text/plain"]),
                       "data": text_value(rng)}),
            );
        }
        3 => {
            m.insert("type".into(), json!("tool_use"));
            m.insert("id".into(), json!("toolu_1"));
            m.insert("name".into(), json!("Read"));
            m.insert("input".into(), json!({"path": text_value(rng)}));
        }
        4 => {
            m.insert("type".into(), json!("tool_result"));
            m.insert("tool_use_id".into(), json!("toolu_1"));
            let content = if rng.chance(2) {
                text_value(rng)
            } else {
                json!([anthropic_block(rng)])
            };
            m.insert("content".into(), content);
        }
        5 => {
            m.insert("type".into(), json!("thinking"));
            m.insert("thinking".into(), text_value(rng));
            m.insert("signature".into(), json!("sig"));
        }
        _ => {
            m.insert("type".into(), json!("redacted_thinking"));
            m.insert("data".into(), text_value(rng));
        }
    }
    with_noise(rng, m)
}

fn anthropic_tool(rng: &mut Rng) -> Value {
    let mut m = Map::new();
    if rng.chance(2) {
        m.insert("type".into(), json!(rng.pick(&["custom", "custom"])));
    }
    m.insert("name".into(), json!(format!("tool_{}", rng.below(5))));
    m.insert("description".into(), text_value(rng));
    m.insert("input_schema".into(), schema(rng, 0));
    with_noise(rng, m)
}

fn anthropic_body(rng: &mut Rng) -> Value {
    let mut top = Map::new();
    top.insert("model".into(), json!("claude-test-model"));
    if rng.chance(2) {
        top.insert("max_tokens".into(), json!(rng.below(5000)));
    }
    let count = rng.below(4);
    let messages: Vec<Value> = (0..count)
        .map(|_| {
            let content = if rng.chance(3) {
                text_value(rng)
            } else {
                Value::Array((0..=rng.below(3)).map(|_| anthropic_block(rng)).collect())
            };
            let message = json!({"role": rng.pick(&["user", "assistant", "system", "tool"]), "content": content});
            with_noise(rng, message.as_object().expect("an object").clone())
        })
        .collect();
    top.insert("messages".into(), Value::Array(messages));
    if rng.chance(3) {
        let system = if rng.chance(2) {
            text_value(rng)
        } else {
            json!([anthropic_block(rng)])
        };
        top.insert("system".into(), system);
    }
    if rng.chance(2) {
        let tools: Vec<Value> = (0..=rng.below(3)).map(|_| anthropic_tool(rng)).collect();
        top.insert("tools".into(), Value::Array(tools));
    }
    if rng.chance(5) {
        top.insert(
            "tool_choice".into(),
            json!({"type": rng.pick(&["auto", "any", "none", "tool", "web_search"]), "name": "Read"}),
        );
    }
    if rng.chance(5) {
        top.insert(
            "thinking".into(),
            json!({"type": "enabled", "budget_tokens": rng.below(100_000)}),
        );
    }
    if rng.chance(6) {
        top.insert("metadata".into(), json!({"user_id": text_value(rng)}));
    }
    with_noise(rng, top)
}

fn openai_part(rng: &mut Rng) -> Value {
    let mut m = Map::new();
    match rng.below(4) {
        0 => {
            m.insert("type".into(), json!("input_text"));
            m.insert("text".into(), text_value(rng));
        }
        1 => {
            m.insert("type".into(), json!("output_text"));
            m.insert("text".into(), text_value(rng));
        }
        2 => {
            m.insert("type".into(), json!("input_image"));
            let url = match rng.below(3) {
                0 => json!("data:image/png;base64,AAAA"),
                _ => text_value(rng),
            };
            m.insert("image_url".into(), url);
        }
        _ => {
            m.insert("type".into(), json!("refusal"));
            m.insert("refusal".into(), text_value(rng));
        }
    }
    with_noise(rng, m)
}

fn openai_tool(rng: &mut Rng, depth: usize) -> Value {
    let mut m = Map::new();
    match rng.below(4) {
        0 => {
            m.insert("type".into(), json!("function"));
            m.insert("name".into(), json!("shell"));
            m.insert("description".into(), text_value(rng));
            m.insert("parameters".into(), schema(rng, 0));
        }
        1 => {
            m.insert("type".into(), json!("custom"));
            m.insert("name".into(), json!("apply"));
            m.insert(
                "format".into(),
                json!({"type": "grammar", "syntax": "lark", "definition": text_value(rng)}),
            );
        }
        2 if depth < 2 => {
            m.insert("type".into(), json!("namespace"));
            m.insert("name".into(), json!("ns"));
            let children: Vec<Value> = (0..=rng.below(2))
                .map(|_| openai_tool(rng, depth + 1))
                .collect();
            m.insert("tools".into(), Value::Array(children));
        }
        _ => {
            m.insert("type".into(), json!(rng.pick(HOSTILE_TAGS)));
            m.insert("name".into(), json!("x"));
        }
    }
    with_noise(rng, m)
}

fn openai_item(rng: &mut Rng) -> Value {
    let mut m = Map::new();
    match rng.below(6) {
        0 | 1 => {
            if rng.chance(2) {
                m.insert("type".into(), json!("message"));
            }
            m.insert(
                "role".into(),
                json!(rng.pick(&["user", "assistant", "developer", "tool"])),
            );
            let content = if rng.chance(3) {
                text_value(rng)
            } else {
                Value::Array((0..=rng.below(2)).map(|_| openai_part(rng)).collect())
            };
            m.insert("content".into(), content);
        }
        2 => {
            m.insert("type".into(), json!("function_call"));
            m.insert("call_id".into(), json!("call_1"));
            m.insert("name".into(), json!("shell"));
            m.insert("arguments".into(), text_value(rng));
        }
        3 => {
            m.insert("type".into(), json!("function_call_output"));
            m.insert("call_id".into(), json!("call_1"));
            let output = if rng.chance(2) {
                text_value(rng)
            } else {
                json!([openai_part(rng)])
            };
            m.insert("output".into(), output);
        }
        4 => {
            m.insert("type".into(), json!("additional_tools"));
            let tools: Vec<Value> = (0..=rng.below(2)).map(|_| openai_tool(rng, 0)).collect();
            m.insert("tools".into(), Value::Array(tools));
        }
        _ => {
            m.insert("type".into(), json!("reasoning"));
            m.insert(
                "summary".into(),
                json!([{"type": "summary_text", "text": text_value(rng)}]),
            );
            m.insert("encrypted_content".into(), text_value(rng));
        }
    }
    with_noise(rng, m)
}

fn openai_body(rng: &mut Rng) -> Value {
    let mut top = Map::new();
    top.insert("model".into(), json!("gpt-test-model"));
    let items: Vec<Value> = (0..rng.below(4)).map(|_| openai_item(rng)).collect();
    top.insert("input".into(), Value::Array(items));
    if rng.chance(2) {
        let tools: Vec<Value> = (0..=rng.below(3)).map(|_| openai_tool(rng, 0)).collect();
        top.insert("tools".into(), Value::Array(tools));
    }
    if rng.chance(4) {
        top.insert("instructions".into(), text_value(rng));
    }
    if rng.chance(5) {
        top.insert(
            "text".into(),
            json!({"format": {"type": "json_schema", "name": "n", "schema": schema(rng, 0)}}),
        );
    }
    if rng.chance(6) {
        top.insert("client_metadata".into(), json!({"k": text_value(rng)}));
    }
    if rng.chance(6) {
        top.insert(
            "include".into(),
            json!([rng.pick(&[
                "reasoning.encrypted_content",
                "web_search_call.action.sources",
                "file_search_call.results"
            ])]),
        );
    }
    if rng.chance(8) {
        top.insert("store".into(), json!(rng.chance(2)));
    }
    with_noise(rng, top)
}

// ---- the oracle: an allow list of keys and tags, positions decided by structure --------------------

const SAFE_KEYS: &[&str] = &[
    // Messages and Responses, every level.
    "model",
    "max_tokens",
    "messages",
    "system",
    "stream",
    "tools",
    "tool_choice",
    "thinking",
    "output_config",
    "context_management",
    "metadata",
    "temperature",
    "top_p",
    "top_k",
    "stop_sequences",
    "role",
    "content",
    "type",
    "text",
    "cache_control",
    "ttl",
    "source",
    "media_type",
    "data",
    "id",
    "name",
    "input",
    "tool_use_id",
    "is_error",
    "signature",
    "description",
    "input_schema",
    "defer_loading",
    "disable_parallel_tool_use",
    "budget_tokens",
    "display",
    "effort",
    "edits",
    "keep",
    "value",
    "user_id",
    "instructions",
    "parallel_tool_calls",
    "reasoning",
    "store",
    "include",
    "prompt_cache_key",
    "client_metadata",
    "max_output_tokens",
    "image_url",
    "detail",
    "status",
    "phase",
    "end_turn",
    "annotations",
    "logprobs",
    "refusal",
    "summary",
    "encrypted_content",
    "call_id",
    "namespace",
    "arguments",
    "output",
    "format",
    "syntax",
    "definition",
    "parameters",
    "strict",
    "context",
    "verbosity",
    "schema",
];

const SAFE_TAGS: &[&str] = &[
    "text",
    "image",
    "document",
    "tool_use",
    "tool_result",
    "thinking",
    "redacted_thinking",
    "base64",
    "custom",
    "ephemeral",
    "auto",
    "any",
    "none",
    "tool",
    "enabled",
    "disabled",
    "adaptive",
    "clear_thinking_20251015",
    "clear_tool_uses_20250919",
    "message",
    "function_call",
    "function_call_output",
    "custom_tool_call",
    "custom_tool_call_output",
    "reasoning",
    "additional_tools",
    "input_text",
    "output_text",
    "refusal",
    "input_image",
    "function",
    "namespace",
    "summary_text",
    "reasoning_text",
    "json_object",
    "json_schema",
    "grammar",
];

/// Keys whose string value is text the model reads. A URL-looking string may sit only here.
const TEXT_KEYS: &[&str] = &[
    "text",
    "thinking",
    "description",
    "content",
    "instructions",
    "arguments",
    "input",
    "output",
    "refusal",
    "definition",
    "signature",
    "data",
    "encrypted_content",
    "user_id",
    "prompt_cache_key",
    "stop_sequences",
    "system",
];

fn looks_like_an_address(text: &str) -> bool {
    text.contains("://")
        || text.starts_with("//")
        || text.starts_with("file:")
        || text.starts_with("\\\\")
        || text.starts_with("javascript:")
}

/// The first thing in an accepted body that the oracle does not allow, or `None`.
fn unacceptable(value: &Value, key: Option<&str>, zone: Zone, found: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            let is_tool_use = map.get("type").and_then(Value::as_str) == Some("tool_use");
            for (k, inner) in map {
                let inner_zone = match (zone, k.as_str()) {
                    (Zone::Schema, _) => Zone::Schema,
                    (Zone::Strings, _) => Zone::Strings,
                    (Zone::Plain, "input_schema" | "parameters" | "schema") => Zone::Schema,
                    (Zone::Plain, "input") if is_tool_use => Zone::Free,
                    (Zone::Plain, "client_metadata") => Zone::Strings,
                    _ => zone,
                };
                if zone == Zone::Plain && !SAFE_KEYS.contains(&k.as_str()) {
                    found.push(format!("key {k:?}"));
                }
                if zone == Zone::Plain
                    && k == "type"
                    && let Some(tag) = inner.as_str()
                    && !SAFE_TAGS.contains(&tag)
                {
                    found.push(format!("tag {tag:?}"));
                }
                unacceptable(inner, Some(k), inner_zone, found);
            }
        }
        Value::Array(items) => {
            for item in items {
                unacceptable(item, key, zone, found);
            }
        }
        Value::String(text) => match zone {
            Zone::Plain => {
                let in_text_key = key.is_some_and(|k| TEXT_KEYS.contains(&k));
                if looks_like_an_address(text) && !in_text_key {
                    found.push(format!("an address in {key:?}: {text}"));
                }
                if key == Some("image_url") && !text.starts_with("data:image/") {
                    found.push(format!("image_url {text}"));
                }
            }
            Zone::Schema => {
                if matches!(key, Some("$ref" | "$dynamicRef" | "$recursiveRef"))
                    && !text.starts_with('#')
                {
                    found.push(format!("a schema reference to {text}"));
                }
            }
            Zone::Free | Zone::Strings => {}
        },
        _ => {}
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Zone {
    Plain,
    Schema,
    Free,
    Strings,
}

/// A second encoding of the same document: keys and strings with every character as `\uXXXX`
/// escapes where legal, pretty printed. A reader that agrees with the broker gives the same verdict.
fn escaped_copy(value: &Value) -> String {
    fn escape(text: &str) -> String {
        let mut out = String::from("\"");
        for unit in text.encode_utf16() {
            out.push_str(&format!("\\u{unit:04x}"));
        }
        out.push('"');
        out
    }
    fn go(value: &Value, out: &mut String) {
        match value {
            Value::String(text) => out.push_str(&escape(text)),
            Value::Array(items) => {
                out.push_str("[ ");
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push_str(" ,\n");
                    }
                    go(item, out);
                }
                out.push_str(" ]");
            }
            Value::Object(map) => {
                out.push_str("{\t");
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push_str(" ,\r\n");
                    }
                    out.push_str(&escape(k));
                    out.push_str(" : ");
                    go(v, out);
                }
                out.push_str("\t}");
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut out = String::new();
    go(value, &mut out);
    out
}

fn run_property(
    wire: Wire,
    make: fn(&mut Rng) -> Value,
    seed: u64,
    rounds: usize,
) -> (usize, usize) {
    let mut rng = Rng(seed);
    let (mut accepted, mut refused) = (0, 0);
    for round in 0..rounds {
        let body = make(&mut rng);
        let bytes = body.to_string();
        match shape::check_body(wire, bytes.as_bytes()) {
            Ok(object) => {
                accepted += 1;
                // The broker's reading is the standard reading.
                let standard: Value = serde_json::from_slice(bytes.as_bytes()).expect("json");
                assert_eq!(
                    Value::Object(object.clone()),
                    standard,
                    "round {round}: the strict reader and the standard reader differ"
                );
                let mut found = Vec::new();
                unacceptable(&Value::Object(object), None, Zone::Plain, &mut found);
                assert!(
                    found.is_empty(),
                    "round {round}: accepted a body with {found:?}:\n{bytes}"
                );
                // The same document, written with every character escaped and odd white space, gets
                // the same verdict.
                assert!(
                    check_raw(wire, escaped_copy(&body).as_bytes()).is_ok(),
                    "round {round}: an escaped copy of an accepted body is refused:\n{bytes}"
                );
            }
            Err(_) => {
                refused += 1;
                assert!(
                    check_raw(wire, escaped_copy(&body).as_bytes()).is_err(),
                    "round {round}: an escaped copy of a refused body is accepted:\n{bytes}"
                );
            }
        }
    }
    (accepted, refused)
}

/// The acceptance claim, tried with a grammar-driven generator and a positional allow-list oracle.
#[test]
fn held_property_no_accepted_body_holds_a_key_a_tag_or_an_address_the_oracle_does_not_allow() {
    for (label, wire, make, seed) in [
        (
            "anthropic",
            Wire::AnthropicMessages,
            anthropic_body as fn(&mut Rng) -> Value,
            0x9e37_79b9_7f4a_7c15,
        ),
        (
            "openai",
            Wire::OpenAiResponses,
            openai_body as fn(&mut Rng) -> Value,
            0xd1b5_4a32_d192_ed03,
        ),
    ] {
        let (accepted, refused) = run_property(wire, make, seed, 40_000);
        eprintln!("{label}: accepted {accepted}, refused {refused}");
        // The property must not be vacuous.
        assert!(
            accepted >= 800,
            "{label}: only {accepted} bodies were accepted"
        );
        assert!(
            refused >= 5_000,
            "{label}: only {refused} bodies were refused"
        );
    }
}

/// The oracle must be able to say no. Bodies built by hand with one hostile thing each.
#[test]
fn held_the_oracle_flags_what_it_is_there_to_flag() {
    let flagged = |body: Value| {
        let mut found = Vec::new();
        unacceptable(&body, None, Zone::Plain, &mut found);
        !found.is_empty()
    };
    for hostile in [
        json!({"tools": [{"type": "web_fetch_20250910", "name": "w"}]}),
        json!({"mcp_servers": []}),
        json!({"messages": [{"role": "user", "content": [{"type": "image", "source": {"type": "base64", "url": "x"}}]}]}),
        json!({"input": [{"role": "user", "content": [{"type": "input_image", "image_url": "https://attacker.test/x.png"}]}]}),
        json!({"tools": [{"name": "t", "input_schema": {"properties": {"a": {"$ref": "https://attacker.test/s"}}}}]}),
        json!({"messages": [{"role": "user", "content": [{"type": "text", "text": "x", "source": "https://attacker.test"}]}]}),
        json!({"metadata": {"label": "ftp://attacker.test/"}}),
    ] {
        assert!(flagged(hostile.clone()), "{hostile}");
    }
    for fine in [
        json!({"messages": [{"role": "user", "content": "see https://example.test/doc"}]}),
        json!({"tools": [{"name": "t", "input_schema": {"properties": {"a": {"$ref": "#/definitions/a"}}}}]}),
        json!({"messages": [{"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "n", "input": {"url": "https://example.test", "mcp_servers": 1}}]}]}),
    ] {
        assert!(!flagged(fine.clone()), "{fine}");
    }
}

// ---- parser differentials, as bytes ---------------------------------------------------------------

#[test]
fn held_documents_that_two_readers_could_read_differently_are_refused() {
    let base = |extra: &str| format!(r#"{{"model":"m","messages":[]{extra}}}"#);
    let must_refuse: Vec<(&str, Vec<u8>)> = vec![
        ("a repeated key in a nested object", br#"{"model":"m","messages":[{"role":"user","content":"x","content":"y"}]}"#.to_vec()),
        ("a repeated key, the second escaped", br#"{"model":"m","messages":[{"role":"user","ro\u006ce":"assistant","content":"x"}]}"#.to_vec()),
        ("a repeated key at depth inside a tool schema", br##"{"model":"m","tools":[{"name":"n","input_schema":{"a":{"$ref":"#"},"a":{"$ref":"http://x/"}}}]}"##.to_vec()),
        ("a key with a trailing space", base(r#","tools ":[]"#).into_bytes()),
        ("an upper case key", base(r#","Tools":[]"#).into_bytes()),
        ("a key with a NUL after it", base(r#","tools\u0000":[]"#).into_bytes()),
        ("a Cyrillic o in a key", base(r#","t\u043eols":[]"#).into_bytes()),
        ("__proto__ at the top", base(r#","__proto__":{"tools":[]}"#).into_bytes()),
        ("__proto__ in metadata", br#"{"model":"m","metadata":{"__proto__":{"x":1}}}"#.to_vec()),
        ("a comment after the document", b"{\"model\":\"m\"} // x".to_vec()),
        ("a comment before the document", b"/*x*/{\"model\":\"m\"}".to_vec()),
        ("a comment inside", b"{\"model\":/*x*/\"m\"}".to_vec()),
        ("a trailing comma", b"{\"model\":\"m\",}".to_vec()),
        ("single quotes", b"{'model':'m'}".to_vec()),
        ("an unquoted key", b"{model:\"m\"}".to_vec()),
        ("a byte order mark", b"\xef\xbb\xbf{\"model\":\"m\"}".to_vec()),
        ("a vertical tab before the document", b"\x0b{\"model\":\"m\"}".to_vec()),
        ("a form feed before the document", b"\x0c{\"model\":\"m\"}".to_vec()),
        ("a no-break space before the document", b"\xc2\xa0{\"model\":\"m\"}".to_vec()),
        ("a line separator before the document", b"\xe2\x80\xa8{\"model\":\"m\"}".to_vec()),
        ("a NUL after the document", b"{\"model\":\"m\"}\0".to_vec()),
        ("two documents", b"{\"model\":\"m\"}{\"model\":\"n\"}".to_vec()),
        ("a document inside an array", b"[{\"model\":\"m\"}]".to_vec()),
        ("NaN", b"{\"model\":\"m\",\"max_tokens\":NaN}".to_vec()),
        ("Infinity", b"{\"model\":\"m\",\"max_tokens\":Infinity}".to_vec()),
        ("a hexadecimal number", b"{\"model\":\"m\",\"max_tokens\":0x10}".to_vec()),
        ("a number with a digit separator", b"{\"model\":\"m\",\"max_tokens\":1_000}".to_vec()),
        ("a leading plus", b"{\"model\":\"m\",\"max_tokens\":+5}".to_vec()),
        ("a leading zero", b"{\"model\":\"m\",\"max_tokens\":05}".to_vec()),
        ("an exponent past the double range", b"{\"model\":\"m\",\"max_tokens\":1e999}".to_vec()),
        ("a raw control character in a string", b"{\"model\":\"m\",\"system\":\"a\x01b\"}".to_vec()),
        ("a raw newline in a string", b"{\"model\":\"m\",\"system\":\"a\nb\"}".to_vec()),
        ("a lone surrogate escape", b"{\"model\":\"m\",\"system\":\"\\ud800\"}".to_vec()),
        ("an overlong UTF-8 slash in a value", b"{\"model\":\"m\",\"system\":\"\xc0\xaf\"}".to_vec()),
        ("an encoded surrogate in a value", b"{\"model\":\"m\",\"system\":\"\xed\xa0\x80\"}".to_vec()),
        ("invalid UTF-8 in a key", b"{\"mod\xffel\":\"m\"}".to_vec()),
        ("an unknown escape", b"{\"model\":\"m\",\"system\":\"\\x41\"}".to_vec()),
        ("nesting of 65 arrays", {
            let mut v = br#"{"model":"m","metadata":{"user_id":"x"},"stop_sequences":"#.to_vec();
            v.extend(b"[".repeat(65));
            v.extend(b"]".repeat(65));
            v.push(b'}');
            v
        }),
    ];
    for (label, bytes) in &must_refuse {
        assert!(
            check_raw(Wire::AnthropicMessages, bytes).is_err(),
            "accepted: {label}"
        );
    }
}

#[test]
fn held_an_escaped_key_is_checked_as_the_key_it_spells() {
    // `\u0074ools` is `tools`. The provider reads it as `tools`; so must the check.
    let body = br#"{"model":"m","\u0074ools":[{"type":"web_fetch_20250910","name":"w"}]}"#;
    assert_eq!(
        check_raw(Wire::AnthropicMessages, body),
        Err(Violation::ServerTool)
    );
    let body = br#"{"model":"m","messages":[],"\u006dcp_servers":[]}"#;
    assert_eq!(
        check_raw(Wire::AnthropicMessages, body),
        Err(Violation::RemoteMcp)
    );
    let body = br#"{"model":"m","input":[{"\u0074ype":"additional_tools","tools":[{"\u0074ype":"mcp"}]}]}"#;
    // The class is a label for the audit line (`mcp` names a remote server); the point is the refusal.
    assert!(check_raw(Wire::OpenAiResponses, body).is_err());
}

#[test]
fn held_the_numbers_the_broker_accepts_are_the_numbers_the_provider_reads() {
    // The output limit is a number; whatever it is, the clamp replaces what is not a small whole
    // number. The schema itself must refuse a string, a boolean and an array there.
    for bad in [
        json!("5"),
        json!(true),
        json!([5]),
        json!({"a": 5}),
        json!(null),
    ] {
        let body = json!({"model": "m", "max_tokens": bad});
        assert_eq!(
            check(Wire::AnthropicMessages, &body),
            Err(Violation::BadValue)
        );
    }
    for ok in [
        "5",
        "5.0",
        "5e0",
        "5E0",
        "-5",
        "-0",
        "0",
        "18446744073709551615",
        "18446744073709551616",
        "1e308",
        "-1e308",
        "1e-400",
    ] {
        let body = format!(r#"{{"model":"m","max_tokens":{ok}}}"#);
        assert!(
            check_raw(Wire::AnthropicMessages, body.as_bytes()).is_ok(),
            "{ok}"
        );
    }
    // Integers where the API wants integers.
    for bad in ["1.0", "1e2", "-1", "10000001"] {
        let body =
            format!(r#"{{"model":"m","thinking":{{"type":"enabled","budget_tokens":{bad}}}}}"#);
        assert_eq!(
            check_raw(Wire::AnthropicMessages, body.as_bytes()),
            Err(Violation::BadValue),
            "{bad}"
        );
    }
}

#[test]
fn held_nesting_at_the_limit_passes_and_one_more_does_not_inside_a_free_form_place() {
    let deep = |levels: usize| {
        let inner = format!("{}1{}", "[".repeat(levels), "]".repeat(levels));
        format!(
            r#"{{"model":"m","messages":[{{"role":"assistant","content":[{{"type":"tool_use","id":"t","name":"n","input":{inner}}}]}}]}}"#
        )
    };
    // The body adds 4 levels of its own (root, messages, message, content, block = root object 1,
    // messages array 2, message object 3, content array 4, block object 5).
    assert!(check_raw(Wire::AnthropicMessages, deep(59).as_bytes()).is_ok());
    assert_eq!(
        check_raw(Wire::AnthropicMessages, deep(60).as_bytes()),
        Err(Violation::TooDeep)
    );
}

// ---- what the schema lets through, field by field ---------------------------------------------------

#[test]
fn held_server_side_features_stay_out_whatever_the_spelling() {
    let cases: Vec<(&str, Wire, Value)> = vec![
        (
            "an Anthropic tool of a server type inside a deferred list",
            Wire::AnthropicMessages,
            messages_with(
                json!({"tools": [{"type": "custom", "name": "a", "input_schema": {}}, {"type": "tool_search_tool_regex_20251119", "name": "s"}]}),
            ),
        ),
        (
            "a custom tool with allowed_callers",
            Wire::AnthropicMessages,
            messages_with(
                json!({"tools": [{"name": "a", "input_schema": {}, "allowed_callers": ["code_execution_20250825"]}]}),
            ),
        ),
        (
            "a custom tool with input_examples",
            Wire::AnthropicMessages,
            messages_with(
                json!({"tools": [{"name": "a", "input_schema": {}, "input_examples": [{}]}]}),
            ),
        ),
        (
            "a document with a title and citations",
            Wire::AnthropicMessages,
            messages_with(
                json!({"messages": [{"role": "user", "content": [{"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "x"}, "citations": {"enabled": true}}]}]}),
            ),
        ),
        (
            "a document by content blocks",
            Wire::AnthropicMessages,
            messages_with(
                json!({"messages": [{"role": "user", "content": [{"type": "document", "source": {"type": "content", "content": "x"}}]}]}),
            ),
        ),
        (
            "a tool result holding a document",
            Wire::AnthropicMessages,
            messages_with(
                json!({"messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t", "content": [{"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "x"}}]}]}]}),
            ),
        ),
        (
            "the Responses namespace carrying an mcp tool",
            Wire::OpenAiResponses,
            responses_with(
                json!({"tools": [{"type": "namespace", "name": "n", "tools": [{"type": "mcp", "server_url": "https://attacker.test"}]}]}),
            ),
        ),
        (
            "a namespace inside a namespace",
            Wire::OpenAiResponses,
            responses_with(
                json!({"tools": [{"type": "namespace", "name": "n", "tools": [{"type": "namespace", "name": "m", "tools": []}]}]}),
            ),
        ),
        (
            "additional_tools carrying web search",
            Wire::OpenAiResponses,
            responses_with(
                json!({"input": [{"type": "additional_tools", "tools": [{"type": "web_search"}]}]}),
            ),
        ),
        (
            "additional_tools carrying a connector",
            Wire::OpenAiResponses,
            responses_with(
                json!({"input": [{"type": "additional_tools", "tools": [{"type": "mcp", "connector_id": "connector_gmail"}]}]}),
            ),
        ),
        (
            "an include of a search result",
            Wire::OpenAiResponses,
            responses_with(json!({"include": ["web_search_call.action.sources"]})),
        ),
        (
            "a stored prompt",
            Wire::OpenAiResponses,
            responses_with(json!({"prompt": {"id": "pmpt_1"}})),
        ),
        (
            "a previous response id",
            Wire::OpenAiResponses,
            responses_with(json!({"previous_response_id": "resp_1"})),
        ),
        (
            "a conversation",
            Wire::OpenAiResponses,
            responses_with(json!({"conversation": "conv_1"})),
        ),
        (
            "a background run",
            Wire::OpenAiResponses,
            responses_with(json!({"background": true})),
        ),
        (
            "a service tier",
            Wire::OpenAiResponses,
            responses_with(json!({"service_tier": "flex"})),
        ),
        (
            "a user field",
            Wire::OpenAiResponses,
            responses_with(json!({"user": "someone"})),
        ),
        (
            "metadata on Responses",
            Wire::OpenAiResponses,
            responses_with(json!({"metadata": {"a": "b"}})),
        ),
        (
            "a remote schema reference in text.format",
            Wire::OpenAiResponses,
            responses_with(
                json!({"text": {"format": {"type": "json_schema", "name": "n", "schema": {"properties": {"a": {"$ref": "https://attacker.test/s.json"}}}}}}),
            ),
        ),
        (
            "a protocol-relative schema reference",
            Wire::OpenAiResponses,
            responses_with(
                json!({"tools": [{"type": "function", "name": "f", "parameters": {"$ref": "//attacker.test/s"}}]}),
            ),
        ),
        (
            "a schema reference with a leading space",
            Wire::OpenAiResponses,
            responses_with(
                json!({"tools": [{"type": "function", "name": "f", "parameters": {"$ref": " #/x"}}]}),
            ),
        ),
        (
            "an image by https in a Responses message",
            Wire::OpenAiResponses,
            responses_with(
                json!({"input": [{"role": "user", "content": [{"type": "input_image", "image_url": "HTTPS://attacker.test/x.png"}]}]}),
            ),
        ),
        (
            "an image whose data URL is spelled in capitals",
            Wire::OpenAiResponses,
            responses_with(
                json!({"input": [{"role": "user", "content": [{"type": "input_image", "image_url": "DATA:image/png;base64,AAAA"}]}]}),
            ),
        ),
        (
            "an image file id",
            Wire::OpenAiResponses,
            responses_with(
                json!({"input": [{"role": "user", "content": [{"type": "input_image", "file_id": "file-1"}]}]}),
            ),
        ),
        (
            "Chat web search options",
            Wire::OpenAiChat,
            json!({"model": "m", "messages": [], "web_search_options": {}}),
        ),
        (
            "Chat audio",
            Wire::OpenAiChat,
            json!({"model": "m", "messages": [], "audio": {}}),
        ),
    ];
    for (label, wire, body) in &cases {
        assert!(check(*wire, body).is_err(), "accepted: {label}");
    }
}

// ---- the request as the provider sees it ----------------------------------------------------------

#[test]
fn held_the_provider_gets_a_closed_set_of_headers_and_the_fixed_query() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    let secret = token.secret.expose().to_owned();
    let body = json!({"model": CLAUDE_MODEL, "max_tokens": 16, "messages": [{"role": "user", "content": "hi"}]});
    let raw_head = format!(
        "POST /v1/messages?beta=true HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
         Content-Type: application/json; charset=utf-8\r\nx-api-key: {secret}\r\n\
         anthropic-version: 2023-06-01\r\nanthropic-beta: claude-code-20250219\r\n\
         openai-organization: org-attacker\r\nopenai-project: proj-attacker\r\n\
         X-HTTP-Method-Override: DELETE\r\nX-Forwarded-For: 10.0.0.1\r\nForwarded: for=10.0.0.1\r\n\
         Content-Encoding: gzip\r\nProxy-Authorization: Basic eDp5\r\nCookie: a=b\r\n\
         anthropic-dangerous-direct-browser-access: true\r\nx-stainless-os: Linux\r\n\
         Content-Length: {}\r\n\r\n{}",
        body.to_string().len(),
        body
    );
    let (status, answer) = raw(rig.addr(), raw_head.as_bytes());
    assert_eq!(status, Some(200), "{answer}");
    let seen = rig.provider.requests();
    assert_eq!(seen.len(), 1);
    let names: Vec<&str> = seen[0].headers.iter().map(|(n, _)| n.as_str()).collect();
    for never in [
        "openai-organization",
        "openai-project",
        "x-http-method-override",
        "x-forwarded-for",
        "forwarded",
        "content-encoding",
        "proxy-authorization",
        "cookie",
        "anthropic-dangerous-direct-browser-access",
        "x-stainless-os",
    ] {
        assert!(!names.contains(&never), "{never} crossed: {names:?}");
    }
    assert_eq!(
        seen[0].header("x-api-key"),
        Some(rig.anthropic_key.as_str())
    );
    assert_ne!(seen[0].header("x-api-key"), Some(secret.as_str()));
    assert_eq!(seen[0].query, "beta=true");
    assert_eq!(seen[0].method, "POST");
    assert_eq!(seen[0].path, "/v1/messages");
}

#[test]
fn held_paths_queries_and_methods_that_try_to_reach_another_endpoint_never_reach_the_provider() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    let secret = token.secret.expose().to_owned();
    let body = json!({"model": CLAUDE_MODEL, "max_tokens": 16, "messages": [{"role": "user", "content": "hi"}]}).to_string();
    let request = |line: &str, extra: &str| {
        format!(
            "{line}\r\nHost: x\r\nConnection: close\r\nContent-Type: application/json\r\n\
             x-api-key: {secret}\r\nanthropic-version: 2023-06-01\r\n{extra}\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        )
    };
    for line in [
        "POST /v1/messages/../files HTTP/1.1",
        "POST /v1/messages/.. HTTP/1.1",
        "POST //v1/messages HTTP/1.1",
        "POST /v1//messages HTTP/1.1",
        "POST /v1/messages/ HTTP/1.1",
        "POST /v1/messages%2F..%2Ffiles HTTP/1.1",
        "POST /v1/messages%00 HTTP/1.1",
        "POST /v1/messages;x=1 HTTP/1.1",
        "POST /V1/MESSAGES HTTP/1.1",
        "POST /v1/messages/batches HTTP/1.1",
        "POST /v1/files HTTP/1.1",
        "POST /v1/organizations/me HTTP/1.1",
        "POST http://169.254.169.254/v1/messages HTTP/1.1",
        "POST https://api.anthropic.com/v1/messages HTTP/1.1",
        "POST * HTTP/1.1",
        "GET /v1/messages HTTP/1.1",
        "PUT /v1/messages HTTP/1.1",
        "DELETE /v1/messages HTTP/1.1",
        "POST /v1/messages#x HTTP/1.1",
        "POST /v1/messages\\..\\files HTTP/1.1",
        "POST /v1/messages HTTP/1.0",
        "POST /v1/messages HTTP/2.0",
    ] {
        let (status, answer) = raw(rig.addr(), request(line, "").as_bytes());
        assert!(
            status.is_some_and(|s| s >= 400),
            "{line}: {status:?} {answer}"
        );
    }
    assert_eq!(rig.provider.hits(), 0, "{:?}", rig.provider.requests());
    // A query other than the fixed one does not stop the request, and does not cross.
    for (query, expected) in [
        ("?beta=true&x=1", ""),
        ("?x=1&beta=true", ""),
        ("?beta=TRUE", ""),
        ("?beta=true,x", ""),
        ("?beta=true%26x%3D1", ""),
        ("?beta=true&beta=false", ""),
        ("?api_key=abc", ""),
        ("?beta=true", "beta=true"),
    ] {
        let before = rig.provider.hits();
        let (status, answer) = raw(
            rig.addr(),
            request(&format!("POST /v1/messages{query} HTTP/1.1"), "").as_bytes(),
        );
        assert_eq!(status, Some(200), "{query}: {answer}");
        let seen = rig.provider.requests();
        assert_eq!(seen.len(), before + 1);
        assert_eq!(seen[before].query, expected, "{query}");
        assert_eq!(seen[before].path, "/v1/messages");
    }
    // Method override headers change nothing.
    let before = rig.provider.hits();
    let extra =
        "X-HTTP-Method-Override: GET\r\nX-Method-Override: DELETE\r\nX-HTTP-Method: PUT\r\n";
    let (status, _) = raw(
        rig.addr(),
        request("POST /v1/messages HTTP/1.1", extra).as_bytes(),
    );
    assert_eq!(status, Some(200));
    assert_eq!(rig.provider.requests()[before].method, "POST");
}

#[test]
fn held_framing_and_credential_tricks_are_refused_before_the_provider() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    let other = rig.claude_token(CEILING);
    let secret = token.secret.expose().to_owned();
    let other_secret = other.secret.expose().to_owned();
    let body = json!({"model": CLAUDE_MODEL, "max_tokens": 16, "messages": []}).to_string();
    let len = body.len();
    let base = |headers: &str| {
        format!(
            "POST /v1/messages HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/json\r\n{headers}\r\n{body}"
        )
    };
    let cases: Vec<(&str, String)> = vec![
        (
            "two lengths that differ",
            base(&format!(
                "x-api-key: {secret}\r\nContent-Length: {len}\r\nContent-Length: {}\r\n",
                len + 1
            )),
        ),
        (
            "a signed length",
            base(&format!(
                "x-api-key: {secret}\r\nContent-Length: +{len}\r\n"
            )),
        ),
        (
            "a hexadecimal length",
            base(&format!(
                "x-api-key: {secret}\r\nContent-Length: 0x{len:x}\r\n"
            )),
        ),
        (
            "chunked with a length",
            base(&format!(
                "x-api-key: {secret}\r\nContent-Length: {len}\r\nTransfer-Encoding: chunked\r\n"
            )),
        ),
        (
            "chunked with a space before the colon",
            base(&format!(
                "x-api-key: {secret}\r\nContent-Length: {len}\r\nTransfer-Encoding : chunked\r\n"
            )),
        ),
        (
            "an obsolete folded header",
            base(&format!(
                "x-api-key: {secret}\r\nContent-Length: {len}\r\nX-A: b\r\n c\r\n"
            )),
        ),
        (
            "two keys",
            base(&format!(
                "x-api-key: {secret}\r\nx-api-key: {other_secret}\r\nContent-Length: {len}\r\n"
            )),
        ),
        (
            "a key and a bearer that differ",
            base(&format!(
                "x-api-key: {secret}\r\nAuthorization: Bearer {other_secret}\r\nContent-Length: {len}\r\n"
            )),
        ),
        (
            "two authorization lines",
            base(&format!(
                "Authorization: Bearer {secret}\r\nAuthorization: Bearer {other_secret}\r\nContent-Length: {len}\r\n"
            )),
        ),
        (
            "a token with a trailing space and an attacker key",
            base(&format!(
                "x-api-key: {secret} sk-attacker-own-key\r\nContent-Length: {len}\r\n"
            )),
        ),
        (
            "a bearer of the wrong scheme",
            base(&format!(
                "Authorization: Basic {secret}\r\nContent-Length: {len}\r\n"
            )),
        ),
        (
            "the attacker's own provider key",
            base(&format!(
                "x-api-key: {}\r\nContent-Length: {len}\r\n",
                "sk-ant-api03-".to_owned() + &"a".repeat(80)
            )),
        ),
        (
            "a NUL in a header value",
            base(&format!(
                "x-api-key: {secret}\r\nX-A: b\0c\r\nContent-Length: {len}\r\n"
            )),
        ),
    ];
    for (label, request) in &cases {
        let (status, answer) = raw(rig.addr(), request.as_bytes());
        assert!(
            status.is_some_and(|s| s >= 400) || status.is_none(),
            "{label}: {status:?} {answer}"
        );
    }
    assert_eq!(rig.provider.hits(), 0, "{:?}", rig.provider.requests());
}

#[test]
fn held_beta_header_variants_never_enable_a_provider_side_feature() {
    let rig = HttpRig::new();
    let token = rig.claude_token(CEILING);
    let secret = token.secret.expose().to_owned();
    let body = json!({"model": CLAUDE_MODEL, "max_tokens": 16, "messages": []}).to_string();
    let send = |beta_lines: &[&str]| {
        let lines: String = beta_lines
            .iter()
            .map(|v| format!("anthropic-beta: {v}\r\n"))
            .collect();
        let request = format!(
            "POST /v1/messages HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/json\r\n\
             x-api-key: {secret}\r\n{lines}Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        raw(rig.addr(), request.as_bytes()).0
    };
    for refused in [
        vec!["mcp-client-2025-11-20"],
        vec!["claude-code-20250219", "mcp-client-2025-04-04"],
        vec!["web-fetch-2025-09-10"],
        vec!["Web-Fetch-2025-09-10"],
        vec!["claude-code-20250219 , web-search-2025-03-05"],
        vec!["claude-code-20250219,\tcode-execution-2025-08-25"],
        vec!["files-api-2025-04-14"],
        vec!["skills-2025-10-02"],
        vec!["agent-2026-01-01"],
        vec!["claude-code-20250219,"],
        vec![",claude-code-20250219"],
        vec![""],
    ] {
        assert!(
            send(&refused).is_some_and(|s| s == 400),
            "not refused: {refused:?}"
        );
    }
    assert_eq!(rig.provider.hits(), 0);
    // Unknown but well-formed betas are dropped, not forwarded.
    assert_eq!(
        send(&["structured-outputs-2025-11-13,fine-grained-tool-streaming-2025-05-14"]),
        Some(200)
    );
    assert_eq!(
        send(&["claude-code-20250219,interleaved-thinking-2025-05-14"]),
        Some(200)
    );
    let seen = rig.provider.requests();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].header("anthropic-beta"), None);
    assert_eq!(
        seen[1].header("anthropic-beta"),
        Some("claude-code-20250219,interleaved-thinking-2025-05-14")
    );
}

#[test]
fn held_the_answer_headers_are_a_closed_set_even_for_a_hostile_provider() {
    let rig = HttpRig::new();
    rig.provider.set(|s| {
        s.more_headers = vec![
            ("Set-Cookie".into(), "a=b; Domain=attacker.test".into()),
            ("Location".into(), "https://attacker.test/".into()),
            (
                "Link".into(),
                "<https://attacker.test/>; rel=preload".into(),
            ),
            ("Content-Security-Policy".into(), "default-src *".into()),
            ("Refresh".into(), "0; url=https://attacker.test/".into()),
            ("X-Request-Id".into(), "req_1".into()),
            ("Request-Id".into(), "req_2".into()),
            ("Openai-Organization".into(), "org-broker".into()),
            ("Anthropic-Organization-Id".into(), "org-broker".into()),
            ("Retry-After".into(), "7".into()),
        ];
    });
    let token = rig.claude_token(CEILING);
    let response = rig.claude(&token, false);
    assert_eq!(response.status, 200);
    let names: Vec<String> = response
        .headers
        .iter()
        .map(|(n, _)| n.to_ascii_lowercase())
        .collect();
    for never in [
        "set-cookie",
        "location",
        "link",
        "content-security-policy",
        "refresh",
        "x-request-id",
        "request-id",
        "openai-organization",
        "anthropic-organization-id",
    ] {
        assert!(!names.iter().any(|n| n == never), "{never}: {names:?}");
    }
}

// ---- defects ----------------------------------------------------------------------------------------

/// RR-1. The output limit is set for Anthropic when the request names none, and for OpenAI it is
/// never set: a Responses request without `max_output_tokens` is forwarded with none, so the model
/// may produce (and reason) up to its own maximum for one request, past `per_request.max_output_tokens`.
/// The cost cap is checked only after the answer is paid for.
#[test]
fn rr_1_an_openai_request_without_an_output_limit_gets_the_per_request_cap() {
    let rig = HttpRig::new();
    let token = rig.codex_token(CEILING);
    let bearer = format!("Bearer {}", token.secret.expose());
    let cap = rig.rig.core.caps().per_request.max_output_tokens;
    let responses = json!({"model": GPT_MODEL, "store": false, "reasoning": {"effort": "high"},
                           "input": [{"role": "user", "content": "think for a very long time"}]});
    let chat =
        json!({"model": GPT_MODEL, "messages": [{"role": "user", "content": "go on forever"}]});
    let mut unbounded = Vec::new();
    for (path, body, field) in [
        ("/v1/responses", &responses, "max_output_tokens"),
        ("/v1/chat/completions", &chat, "max_completion_tokens"),
    ] {
        let response = post(
            &rig,
            path,
            &[
                ("Content-Type", "application/json"),
                ("Authorization", bearer.as_str()),
            ],
            body,
        );
        assert_eq!(response.status, 200, "{path}");
        let seen = rig.provider.requests();
        let forwarded = seen.last().expect("a request").json();
        let limit = forwarded
            .get(field)
            .or_else(|| forwarded.get("max_tokens"))
            .and_then(Value::as_u64);
        if limit.is_none_or(|n| n > cap) {
            unbounded.push(format!("{path}: limit {limit:?}, cap {cap}"));
        }
    }
    assert!(
        unbounded.is_empty(),
        "forwarded without the per-request output cap: {unbounded:?}"
    );
}

/// RR-2. `cache_control.ttl: "1h"` is accepted, nothing recorded from the real tools uses it, and a
/// one-hour cache write is billed by Anthropic at twice the input price while the broker's price
/// list has one cache-write price per model and reads one count (`cache_creation_input_tokens`).
/// The broker therefore books the spend of such a write at the five-minute rate.
#[test]
fn rr_2_a_one_hour_cache_ttl_is_not_forwarded_while_it_is_booked_at_the_five_minute_price() {
    let body = json!({"model": "m", "max_tokens": 5,
        "system": [{"type": "text", "text": "x", "cache_control": {"type": "ephemeral", "ttl": "1h"}}],
        "messages": [{"role": "user", "content": "hi"}]});
    assert!(
        check(Wire::AnthropicMessages, &body).is_err(),
        "the schema accepted a one-hour cache write"
    );
}

/// RR-3 (hypothesis about the provider, certain about the broker). A `data:image/` prefix is the
/// only check on an inline image of the Responses API. `data:image/svg+xml,...` and a data URL
/// that is not base64 are accepted; an SVG may name external resources that a renderer fetches.
#[test]
#[ignore = "RR-3 hypothesis: an inline image of any image subtype and any encoding is accepted. Run: cargo test -p factory-egress --test security_rereview -- --ignored rr_3"]
fn rr_3_an_inline_image_is_a_base64_raster_of_a_listed_type() {
    let mut accepted = Vec::new();
    for url in [
        "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg'><image href='http://attacker.test/x'/></svg>",
        "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=",
        "data:image/png,http://attacker.test/x.png",
        "data:image/x-icon;base64,AAAA",
    ] {
        let body = responses_with(json!({"input": [{"role": "user", "content": [
            {"type": "input_image", "image_url": url}]}]}));
        if check(Wire::OpenAiResponses, &body).is_ok() {
            accepted.push(url);
        }
    }
    assert!(accepted.is_empty(), "accepted: {accepted:?}");
}

/// RR-4. A schema keeps its base address in `$id` and names its dialect in `$schema`; a resolver
/// that follows them can be pointed at a remote document without a `$ref` that leaves the document.
/// The check refuses only `$ref`, `$dynamicRef` and `$recursiveRef`.
#[test]
#[ignore = "RR-4 hypothesis: $id, $schema, $anchor and $vocabulary with a remote address are accepted in a tool schema. Run: cargo test -p factory-egress --test security_rereview -- --ignored rr_4"]
fn rr_4_a_tool_schema_names_no_remote_base_or_dialect() {
    let mut accepted = Vec::new();
    for schema in [
        json!({"$id": "http://attacker.test/s.json", "$ref": "#/definitions/a", "definitions": {"a": {}}}),
        json!({"$schema": "http://attacker.test/meta.json", "type": "object"}),
        json!({"$vocabulary": {"http://attacker.test/vocab": true}, "type": "object"}),
        json!({"properties": {"a": {"$id": "https://attacker.test/a", "type": "string"}}}),
    ] {
        let body = messages_with(json!({"tools": [{"name": "t", "input_schema": schema.clone()}]}));
        if check(Wire::AnthropicMessages, &body).is_ok() {
            accepted.push(schema.to_string());
        }
    }
    assert!(accepted.is_empty(), "accepted: {accepted:?}");
}

/// RR-5. The deny ranges of the relay leave out addresses that a cloud or a lab host reaches
/// without a route: Azure's platform address `168.63.129.16`, the IETF protocol block
/// `192.0.0.0/24` (DS-Lite and PCP addresses among them) and the site-local `fec0::/10`.
#[test]
fn rr_5_special_purpose_addresses_are_refused_after_resolution() {
    let ranges = default_deny_ranges();
    let mut allowed = Vec::new();
    for text in [
        "168.63.129.16",
        "192.0.0.8",
        "192.0.0.9",
        "192.0.0.170",
        "192.0.0.171",
        "fec0::1",
        "fec0:0:0:ffff::1",
    ] {
        let ip: std::net::IpAddr = text.parse().expect("an address");
        if !is_denied(&ranges, ip) {
            allowed.push(text);
        }
    }
    assert!(allowed.is_empty(), "not refused: {allowed:?}");
}

#[test]
fn held_every_spelling_of_a_private_address_the_relay_policy_names_is_refused() {
    let ranges = default_deny_ranges();
    let mut escaped = Vec::new();
    // Every private, loopback, link-local, metadata or shared IPv4 address, in every IPv6 form that
    // can carry one: mapped, compatible, translated, NAT64 (well known and local), 6to4.
    for v4 in [
        [127, 0, 0, 1],
        [127, 255, 255, 254],
        [10, 0, 0, 1],
        [10, 255, 255, 255],
        [172, 16, 0, 1],
        [172, 31, 255, 255],
        [192, 168, 0, 1],
        [192, 168, 255, 255],
        [169, 254, 169, 254],
        [169, 254, 0, 1],
        [100, 64, 0, 1],
        [100, 127, 255, 254],
        [198, 18, 0, 1],
        [198, 19, 255, 254],
        [0, 0, 0, 0],
        [0, 1, 2, 3],
        [224, 0, 0, 1],
        [239, 255, 255, 250],
        [255, 255, 255, 255],
        [240, 0, 0, 1],
    ] {
        let a = std::net::Ipv4Addr::from(v4);
        let o = a.octets();
        let hi = u16::from(o[0]) << 8 | u16::from(o[1]);
        let lo = u16::from(o[2]) << 8 | u16::from(o[3]);
        let forms: Vec<std::net::Ipv6Addr> = vec![
            std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, hi, lo),
            std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, hi, lo),
            std::net::Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, hi, lo),
            std::net::Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, hi, lo),
            std::net::Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, hi, lo),
            std::net::Ipv6Addr::new(0x64, 0xff9b, 1, 0xabcd, 0, 0, hi, lo),
            std::net::Ipv6Addr::new(0x2002, hi, lo, 0, 0, 0, 0, 1),
            std::net::Ipv6Addr::new(0x2002, hi, lo, 1, 2, 3, 4, 5),
            std::net::Ipv6Addr::new(0x2001, 0, 0x4136, 0xe378, 0x8000, 0x63bf, !hi, !lo),
        ];
        if !is_denied(&ranges, std::net::IpAddr::V4(a)) {
            escaped.push(a.to_string());
        }
        for form in forms {
            if !is_denied(&ranges, std::net::IpAddr::V6(form)) {
                escaped.push(form.to_string());
            }
        }
    }
    for text in [
        "::1",
        "::",
        "fe80::1",
        "febf::1",
        "fc00::1",
        "fd12:3456::1",
        "ff02::1",
        "fd00:ec2::254",
    ] {
        let ip: std::net::IpAddr = text.parse().expect("an address");
        if !is_denied(&ranges, ip) {
            escaped.push(text.to_owned());
        }
    }
    assert!(escaped.is_empty(), "not refused: {escaped:?}");
}

/// RR-6. The strict reader builds the whole document in memory before the schema looks at it, and
/// it has a limit on depth but none on the number of values. A body of the largest size the
/// listener accepts (8 MiB) made of `0,0,0,...` holds four million values and took 218 MB of
/// resident memory to read (13 to 26 times its size; measured with `/usr/bin/time -l`, see the
/// review). The listener takes 64 connections, and the body is read after the credential is
/// checked and before the request is counted, so a holder of one job token can ask for 64 of them
/// at once.
#[test]
fn rr_6_a_body_of_millions_of_values_is_refused_before_it_is_built() {
    let mut body = String::from("[");
    for _ in 0..3_000_000 {
        body.push_str("0,");
    }
    body.push_str("0]");
    assert!(
        body.len() < 8 * 1024 * 1024,
        "the body must fit the listener's limit"
    );
    assert!(
        shape::json::parse(body.as_bytes()).is_err(),
        "three million values were read into memory"
    );
}
