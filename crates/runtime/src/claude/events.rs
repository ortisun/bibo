//! Reads the `stream-json` event stream of Claude Code 2.1.311 (spike section 4.7).
//!
//! The stream has one JSON document per line: `system/init`, `system/api_retry`, `assistant`,
//! `user` and `result`. The reader keeps only what the adapter needs and never trusts what the
//! tool says about success:
//!
//! * `subtype` is **not** read for success. A provider failure arrives with `subtype: "success"`,
//!   so success means `is_error == false` and `terminal_reason == "completed"`.
//! * The exit code is not read here. SIGINT ends the tool with exit code 0 and an error result.
//! * Cost comes from `total_cost_usd`, which the tool computes from its own price list. It is a
//!   second line behind the broker's meter and means nothing for a model the list does not know.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

/// What `system/init` said.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Init {
    /// The model the tool will ask for.
    pub model: String,
    /// The tools it has.
    pub tools: Vec<String>,
    /// The skills it can see. The bundled ones are in this list too.
    pub skills: Vec<String>,
    /// The slash commands it can see.
    pub slash_commands: Vec<String>,
    /// The tool's version.
    pub version: String,
    /// How the credential was found, such as `apiKeyHelper`.
    pub api_key_source: String,
}

/// A tool call the tool refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDenial {
    /// The tool that was refused.
    pub tool_name: String,
    /// The id of the call.
    pub tool_use_id: String,
}

/// The `result` event.
#[derive(Debug, Clone, PartialEq)]
pub struct ResultEvent {
    /// True when the run failed. Read this, not `subtype`.
    pub is_error: bool,
    /// The tool's subtype. It says `success` for provider failures, so it is for the transcript.
    pub subtype: String,
    /// Why the run ended: `completed`, `api_error`, `max_turns`, `aborted_streaming` ...
    pub terminal_reason: Option<String>,
    /// The HTTP status of a provider failure.
    pub api_error_status: Option<u64>,
    /// The final text.
    pub text: String,
    /// Tokens sent, with cache reads and writes.
    pub input_tokens: u64,
    /// Tokens written.
    pub output_tokens: u64,
    /// `total_cost_usd` in millionths of a dollar.
    pub cost_micro: u64,
    /// Calls the tool refused.
    pub denials: Vec<RawDenial>,
}

/// What one run's stream held.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Stream {
    /// The init event.
    pub init: Option<Init>,
    /// The last well-formed result event.
    pub result: Option<ResultEvent>,
    /// How many `api_retry` events there were. Each is a request the provider answered with a
    /// failure.
    pub retries: u64,
    /// The status of the last `api_retry`.
    pub last_retry_status: Option<u64>,
    /// The ids of the model responses seen. A provider-made response has an id that starts `msg_`.
    pub message_ids: BTreeSet<String>,
    /// Tokens of the responses seen, for a run that was cut before its result.
    pub partial_input_tokens: u64,
    /// Output tokens of the responses seen.
    pub partial_output_tokens: u64,
    /// The text of each `tool_result`, by the call it answers.
    pub tool_results: BTreeMap<String, String>,
    /// Lines that were not JSON, or were JSON of the wrong shape.
    pub malformed_lines: usize,
}

fn u64_of(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn text_of(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Dollars to millionths, rounded. A negative or non-finite figure is zero.
fn micro_of(dollars: f64) -> u64 {
    let micro = (dollars * 1_000_000.0).round();
    if micro.is_finite() && micro > 0.0 {
        micro as u64
    } else {
        0
    }
}

fn read_result(event: &Value) -> Option<ResultEvent> {
    let is_error = event.get("is_error")?.as_bool()?;
    let usage = event.get("usage").unwrap_or(&Value::Null);
    let input = u64_of(usage, "input_tokens")
        .saturating_add(u64_of(usage, "cache_creation_input_tokens"))
        .saturating_add(u64_of(usage, "cache_read_input_tokens"));
    let denials = event
        .get("permission_denials")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|d| RawDenial {
                    tool_name: d
                        .get("tool_name")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_owned(),
                    tool_use_id: d
                        .get("tool_use_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                })
                .collect()
        })
        .unwrap_or_default();
    Some(ResultEvent {
        is_error,
        subtype: event
            .get("subtype")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        terminal_reason: event
            .get("terminal_reason")
            .and_then(Value::as_str)
            .map(str::to_owned),
        api_error_status: event.get("api_error_status").and_then(Value::as_u64),
        text: event
            .get("result")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        input_tokens: input,
        output_tokens: u64_of(usage, "output_tokens"),
        cost_micro: event
            .get("total_cost_usd")
            .and_then(Value::as_f64)
            .map_or(0, micro_of),
        denials,
    })
}

fn read_init(event: &Value) -> Init {
    Init {
        model: event
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        tools: strings(event.get("tools")),
        skills: strings(event.get("skills")),
        slash_commands: strings(event.get("slash_commands")),
        version: event
            .get("claude_code_version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        api_key_source: event
            .get("apiKeySource")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    }
}

fn read_assistant(event: &Value, stream: &mut Stream) {
    let Some(message) = event.get("message") else {
        return;
    };
    let id = message.get("id").and_then(Value::as_str).unwrap_or_default();
    if id.starts_with("msg_") && stream.message_ids.insert(id.to_owned()) {
        let usage = message.get("usage").unwrap_or(&Value::Null);
        stream.partial_input_tokens = stream
            .partial_input_tokens
            .saturating_add(u64_of(usage, "input_tokens"))
            .saturating_add(u64_of(usage, "cache_creation_input_tokens"))
            .saturating_add(u64_of(usage, "cache_read_input_tokens"));
        stream.partial_output_tokens = stream
            .partial_output_tokens
            .saturating_add(u64_of(usage, "output_tokens"));
    }
}

fn read_user(event: &Value, stream: &mut Stream) {
    let Some(parts) = event
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(Value::as_array)
    else {
        return;
    };
    for part in parts {
        if part.get("type").and_then(Value::as_str) == Some("tool_result")
            && let Some(id) = part.get("tool_use_id").and_then(Value::as_str)
        {
            let text = part.get("content").map(text_of).unwrap_or_default();
            stream.tool_results.insert(id.to_owned(), text);
        }
    }
}

/// Reads the whole stream. A line that is not a JSON object is counted and skipped.
#[must_use]
pub fn parse(stdout: &[u8]) -> Stream {
    let mut stream = Stream::default();
    for line in stdout.split(|b| *b == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let Ok(event) = serde_json::from_slice::<Value>(line) else {
            stream.malformed_lines += 1;
            continue;
        };
        if !event.is_object() {
            stream.malformed_lines += 1;
            continue;
        }
        match event.get("type").and_then(Value::as_str) {
            Some("system") => match event.get("subtype").and_then(Value::as_str) {
                Some("init") => stream.init = Some(read_init(&event)),
                Some("api_retry") => {
                    stream.retries += 1;
                    stream.last_retry_status = event.get("error_status").and_then(Value::as_u64);
                }
                _ => {}
            },
            Some("assistant") => read_assistant(&event, &mut stream),
            Some("user") => read_user(&event, &mut stream),
            Some("result") => match read_result(&event) {
                Some(result) => stream.result = Some(result),
                None => stream.malformed_lines += 1,
            },
            _ => {}
        }
    }
    stream
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_provider_failure_with_the_success_subtype_is_an_error_result() {
        let line = r#"{"type":"result","subtype":"success","is_error":true,"terminal_reason":"api_error","api_error_status":500,"result":"API Error: 500","usage":{"input_tokens":0,"output_tokens":0},"total_cost_usd":0}"#;
        let stream = parse(line.as_bytes());
        let result = stream.result.expect("a result");
        assert!(result.is_error);
        assert_eq!(result.subtype, "success");
        assert_eq!(result.api_error_status, Some(500));
        assert_eq!(result.terminal_reason.as_deref(), Some("api_error"));
    }

    #[test]
    fn a_result_without_the_error_flag_is_malformed_not_a_success() {
        let stream = parse(br#"{"type":"result","subtype":"success","result":"ok"}"#);
        assert!(stream.result.is_none());
        assert_eq!(stream.malformed_lines, 1);
    }

    #[test]
    fn usage_adds_the_cache_fields_and_the_cost_is_in_millionths() {
        let line = r#"{"type":"result","is_error":false,"terminal_reason":"completed","result":"x","usage":{"input_tokens":1234,"cache_creation_input_tokens":7,"cache_read_input_tokens":89,"output_tokens":56},"total_cost_usd":0.0061088}"#;
        let result = parse(line.as_bytes()).result.expect("a result");
        assert_eq!(result.input_tokens, 1330);
        assert_eq!(result.output_tokens, 56);
        assert_eq!(result.cost_micro, 6109);
    }

    #[test]
    fn garbage_lines_are_counted_and_skipped() {
        let stream = parse(b"not json\n\n{\"type\":\"system\",\"subtype\":\"api_retry\",\"error_status\":401}\n[1,2]\n");
        assert_eq!(stream.malformed_lines, 2);
        assert_eq!(stream.retries, 1);
        assert_eq!(stream.last_retry_status, Some(401));
    }

    #[test]
    fn only_provider_made_responses_count_as_requests() {
        let lines = concat!(
            r#"{"type":"assistant","message":{"id":"msg_a","usage":{"input_tokens":10,"output_tokens":1}}}"#,
            "\n",
            r#"{"type":"assistant","message":{"id":"msg_a","usage":{"input_tokens":10,"output_tokens":5}}}"#,
            "\n",
            r#"{"type":"assistant","message":{"id":"6e0c-synthetic","usage":{"input_tokens":0,"output_tokens":0}}}"#,
            "\n"
        );
        let stream = parse(lines.as_bytes());
        assert_eq!(stream.message_ids.len(), 1);
        assert_eq!(stream.partial_input_tokens, 10);
    }

    #[test]
    fn the_refusal_text_of_a_denied_call_is_kept_by_call_id() {
        let line = r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_1","is_error":true,"content":"Permission for this tool use was denied."}]}}"#;
        let stream = parse(line.as_bytes());
        assert_eq!(
            stream.tool_results.get("toolu_1").map(String::as_str),
            Some("Permission for this tool use was denied.")
        );
    }
}
