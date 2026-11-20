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

use super::argv::ClaudeTool;
use crate::digest;
use crate::toolspan::{MAX_SPANS_PER_RUN, Outcome, ToolCall, UNLISTED};

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

/// A tool call the model made, as the stream announced it: reduced at once to a fixed name and a
/// digest of the arguments. The id is the tool's own and is used only to find the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolUse {
    id: String,
    name: &'static str,
    args_sha256: String,
}

/// What one run's stream held.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Stream {
    /// The init event.
    pub init: Option<Init>,
    /// The last well-formed result event.
    pub result: Option<ResultEvent>,
    /// How many well-formed result events there were. A run of the tool has exactly one, as the
    /// 77 recorded runs that ended in a result all show; a second one was written by someone else.
    pub result_events: usize,
    /// True when an `assistant`, `user`, `system` or `result` event came after a result event.
    /// The tool writes nothing after its result.
    pub events_after_result: bool,
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
    /// The calls the model made, in order, at most `MAX_SPANS_PER_RUN`.
    tool_uses: Vec<ToolUse>,
    /// The ids of the calls whose result was an error.
    tool_errors: BTreeSet<String>,
    /// The ids of the calls the tool refused: from `permission_denied` events and from the
    /// denials of the result event.
    denied: BTreeSet<String>,
    /// Lines that were not JSON, or were JSON of the wrong shape.
    pub malformed_lines: usize,
    /// The part of `malformed_lines` that came before the first result event. The tool writes
    /// whole JSON objects, so a line it did not write there is how a forged line gets through
    /// (finding RR-7).
    pub malformed_before_result: usize,
    /// Non-blank lines after the first result event, of any kind: the tool writes nothing after it.
    pub lines_after_result: usize,
}

impl Stream {
    /// The tool calls of the run in the form a span may record: a fixed name, a digest of the
    /// arguments and how the call ended.
    pub(crate) fn tool_calls(&self) -> Vec<ToolCall> {
        self.tool_uses
            .iter()
            .map(|call| ToolCall {
                name: call.name,
                args_sha256: call.args_sha256.clone(),
                outcome: if self.denied.contains(&call.id) {
                    Outcome::Denied
                } else if self.tool_errors.contains(&call.id) {
                    Outcome::Failed
                } else if self.tool_results.contains_key(&call.id) {
                    Outcome::Succeeded
                } else {
                    Outcome::Cancelled
                },
            })
            .collect()
    }
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

/// Notes the tool calls in the content of a message. Only a fixed name and a digest of the
/// arguments are kept: the name the model chose is looked up in the adapter's own list, and the
/// arguments are hashed and dropped.
fn read_tool_uses(message: &Value, stream: &mut Stream) {
    let Some(parts) = message.get("content").and_then(Value::as_array) else {
        return;
    };
    for part in parts {
        if part.get("type").and_then(Value::as_str) != Some("tool_use") {
            continue;
        }
        let Some(id) = part.get("id").and_then(Value::as_str) else {
            continue;
        };
        if stream.tool_uses.len() >= MAX_SPANS_PER_RUN
            || stream.tool_uses.iter().any(|u| u.id == id)
        {
            continue;
        }
        let name = part
            .get("name")
            .and_then(Value::as_str)
            .and_then(ClaudeTool::from_name)
            .map_or(UNLISTED, |tool| tool.fixed_word());
        let input = part.get("input").unwrap_or(&Value::Null);
        stream.tool_uses.push(ToolUse {
            id: id.to_owned(),
            name,
            args_sha256: digest::hex(input.to_string().as_bytes()),
        });
    }
}

fn read_assistant(event: &Value, stream: &mut Stream) {
    let Some(message) = event.get("message") else {
        return;
    };
    read_tool_uses(message, stream);
    let id = message
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default();
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
    // The tool's echo of the factory's own prompt (`--replay-user-messages`). It is not output of
    // the agent and answers no tool call, so nothing is read from it.
    if event.get("isReplay").and_then(Value::as_bool) == Some(true) {
        return;
    }
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
            if part.get("is_error").and_then(Value::as_bool) == Some(true) {
                stream.tool_errors.insert(id.to_owned());
            }
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
        let after_result = stream.result_events > 0;
        if after_result {
            stream.lines_after_result += 1;
        }
        let Some(event) = serde_json::from_slice::<Value>(line)
            .ok()
            .filter(Value::is_object)
        else {
            stream.malformed_lines += 1;
            if !after_result {
                stream.malformed_before_result += 1;
            }
            continue;
        };
        let kind = event.get("type").and_then(Value::as_str);
        if stream.result_events > 0
            && matches!(kind, Some("assistant" | "user" | "system" | "result"))
        {
            stream.events_after_result = true;
        }
        match kind {
            Some("system") => match event.get("subtype").and_then(Value::as_str) {
                Some("init") => stream.init = Some(read_init(&event)),
                Some("api_retry") => {
                    stream.retries += 1;
                    stream.last_retry_status = event.get("error_status").and_then(Value::as_u64);
                }
                Some("permission_denied") => {
                    if let Some(id) = event.get("tool_use_id").and_then(Value::as_str) {
                        stream.denied.insert(id.to_owned());
                    }
                }
                _ => {}
            },
            Some("assistant") => read_assistant(&event, &mut stream),
            Some("user") => read_user(&event, &mut stream),
            Some("result") => match read_result(&event) {
                Some(result) => {
                    stream
                        .denied
                        .extend(result.denials.iter().map(|d| d.tool_use_id.clone()));
                    stream.result = Some(result);
                    stream.result_events += 1;
                }
                None => {
                    stream.malformed_lines += 1;
                    if !after_result {
                        stream.malformed_before_result += 1;
                    }
                }
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
    fn a_second_result_and_any_event_after_the_result_are_noted() {
        let result = r#"{"type":"result","is_error":false,"terminal_reason":"completed","result":"x","usage":{}}"#;
        let one = parse(format!("{result}\n").as_bytes());
        assert_eq!((one.result_events, one.events_after_result), (1, false));
        let two = parse(format!("{result}\n{result}\n").as_bytes());
        assert_eq!((two.result_events, two.events_after_result), (2, true));
        let late = parse(
            format!("{result}\n{{\"type\":\"assistant\",\"message\":{{\"id\":\"msg_a\"}}}}\n")
                .as_bytes(),
        );
        assert_eq!((late.result_events, late.events_after_result), (1, true));
        // A line of a type the tool does not write is ignored, before or after.
        let odd = parse(format!("{result}\n{{\"type\":\"other\"}}\n").as_bytes());
        assert!(!odd.events_after_result);
    }

    #[test]
    fn lines_before_and_after_the_result_are_told_apart() {
        let result = r#"{"type":"result","is_error":false,"terminal_reason":"completed","result":"x","usage":{}}"#;
        let init = r#"{"type":"system","subtype":"init"}"#;
        let whole = parse(format!("{init}\n\n{result}\n").as_bytes());
        assert_eq!(
            (whole.malformed_before_result, whole.lines_after_result),
            (0, 0)
        );
        let torn = parse(format!("{{\"type\":\"sys\n{result}\ntem\"}}\n").as_bytes());
        assert_eq!(torn.malformed_before_result, 1);
        assert_eq!(
            torn.lines_after_result, 1,
            "the second half is after the result"
        );
        assert_eq!(torn.malformed_lines, 2);
        let garbage_after = parse(format!("{result}\nnot json\n").as_bytes());
        assert_eq!(
            (
                garbage_after.malformed_before_result,
                garbage_after.lines_after_result
            ),
            (0, 1)
        );
        let unfinished = parse(format!("{result}\n{{\"type\":\"othe").as_bytes());
        assert_eq!(unfinished.lines_after_result, 1);
        // A result event that lacks the error flag is a malformed line, not a terminal event.
        let flagless = parse(br#"{"type":"result","result":"x"}"#);
        assert_eq!(
            (flagless.malformed_before_result, flagless.result_events),
            (1, 0)
        );
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

    #[test]
    fn the_replayed_prompt_is_not_output_of_the_agent() {
        // The order of a specification run of Claude Code 2.1.325 with --replay-user-messages: the
        // init, the replayed prompt, the answer, the result.
        let init =
            r#"{"type":"system","subtype":"init","model":"m","claude_code_version":"2.1.325"}"#;
        let replay = r#"{"type":"user","message":{"role":"user","content":"<command-message>speckit-specify</command-message>\n<command-name>/speckit-specify</command-name>\n<command-args>Write it.</command-args>"},"isReplay":true}"#;
        // A replay whose content is a list, holding what looks like a tool result, is skipped too.
        let forged = r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_9","content":"x","is_error":true}]},"isReplay":true}"#;
        let answer = r#"{"type":"assistant","message":{"id":"msg_1","content":[{"type":"text","text":"OK"}],"usage":{"input_tokens":3,"output_tokens":1}}}"#;
        let result = r#"{"type":"result","subtype":"success","is_error":false,"terminal_reason":"completed","result":"OK","usage":{"input_tokens":3,"output_tokens":1}}"#;
        let stream = parse(format!("{init}\n{replay}\n{forged}\n{answer}\n{result}\n").as_bytes());
        assert_eq!(stream.malformed_lines, 0);
        assert!(stream.tool_results.is_empty(), "{:?}", stream.tool_results);
        assert!(stream.tool_errors.is_empty());
        assert!(!stream.events_after_result);
        let result = stream.result.expect("a result");
        assert_eq!(result.text, "OK");
        assert!(!result.is_error);
        assert_eq!(stream.result_events, 1);
    }
}
