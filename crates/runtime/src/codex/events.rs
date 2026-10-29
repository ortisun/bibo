//! Reads the `--json` event stream of Codex 0.163.0 (spike section 4.7).
//!
//! One JSON document per line: `thread.started`, `turn.started`, `item.started`, `item.completed`,
//! `turn.completed`, `turn.failed` and `error`. Success is a `turn.completed` event and no
//! `turn.failed`; the final text is the last `agent_message` item. Codex reports no cost and has no
//! turn cap, so the broker's meter is the source of truth for both.
//!
//! A line of type `item.completed` whose item is of type `error` is a warning (for example "Model
//! metadata not found"), not a failure.

use serde_json::Value;

use crate::digest;
use crate::toolspan::{MAX_SPANS_PER_RUN, Outcome, ToolCall};

/// The name of Codex's one shell tool in a `factory.tool_call` span. A fixed word: the command is
/// not a tool name, and is recorded only as a digest.
const SHELL: &str = "shell";

/// The name of any tool of an MCP server. A fixed word: the server and the tool are named by the
/// repository's configuration, so they are not recorded.
const MCP: &str = "mcp";

/// A tool call that Codex could not run because it needed approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDenial {
    /// The tool, as `mcp:<server>.<tool>`.
    pub tool: String,
    /// The tool's words.
    pub reason: String,
}

/// What one run's stream held.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Stream {
    /// True after `turn.started`.
    pub turn_started: bool,
    /// True after `turn.completed`.
    pub completed: bool,
    /// How many `turn.completed` events there were. A run has exactly one.
    pub completed_events: usize,
    /// True when a `turn.started`, `item.completed`, `turn.completed` or `turn.failed` event came
    /// after a `turn.completed`. The tool writes nothing after it.
    pub events_after_completed: bool,
    /// The message of `turn.failed`.
    pub failed: Option<String>,
    /// The message of the last `error` event.
    pub last_error: Option<String>,
    /// How many `Reconnecting...` errors there were. Each is a request that was repeated.
    pub reconnects: u64,
    /// The last `agent_message`.
    pub final_message: Option<String>,
    /// Command and tool-call items that completed.
    pub tool_items: u64,
    /// Tokens sent, with cached tokens.
    pub input_tokens: u64,
    /// Tokens written.
    pub output_tokens: u64,
    /// Calls the tool could not run because they needed approval.
    pub denials: Vec<RawDenial>,
    /// The completed tool calls, in order, in the form a span may record: a fixed name, a digest of
    /// the arguments and the outcome. At most `MAX_SPANS_PER_RUN`. A call that never completed
    /// (the run was cut) is not here.
    pub(crate) tool_calls: Vec<ToolCall>,
    /// Lines that were not JSON objects.
    pub malformed_lines: usize,
}

/// How a completed item ended, from its `status`: `completed`, `failed` or `declined`. Any other
/// word, or none, means the call has no result to report.
fn outcome_of(item: &Value) -> Outcome {
    match item.get("status").and_then(Value::as_str) {
        Some("completed") => Outcome::Succeeded,
        Some("failed") => Outcome::Failed,
        Some("declined") => Outcome::Denied,
        _ => Outcome::Cancelled,
    }
}

fn keep(stream: &mut Stream, call: ToolCall) {
    if stream.tool_calls.len() < MAX_SPANS_PER_RUN {
        stream.tool_calls.push(call);
    }
}

fn u64_of(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn message_of(event: &Value) -> Option<String> {
    event
        .get("message")
        .or_else(|| event.get("error").and_then(|e| e.get("message")))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn read_item(item: &Value, stream: &mut Stream) {
    match item.get("type").and_then(Value::as_str) {
        Some("agent_message") => {
            stream.final_message = item.get("text").and_then(Value::as_str).map(str::to_owned);
        }
        Some("command_execution") => {
            stream.tool_items += 1;
            let command = item
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or_default();
            keep(
                stream,
                ToolCall {
                    name: SHELL,
                    args_sha256: digest::hex(command.as_bytes()),
                    outcome: outcome_of(item),
                },
            );
        }
        Some("mcp_tool_call") => {
            stream.tool_items += 1;
            let error = item
                .get("error")
                .and_then(|e| e.get("message").or(Some(e)))
                .and_then(Value::as_str);
            let denied = error.filter(|r| r.contains("requires approval"));
            if let Some(reason) = denied {
                let server = item.get("server").and_then(Value::as_str).unwrap_or("?");
                let tool = item.get("tool").and_then(Value::as_str).unwrap_or("?");
                stream.denials.push(RawDenial {
                    tool: format!("mcp:{server}.{tool}"),
                    reason: reason.to_owned(),
                });
            }
            let arguments = item.get("arguments").unwrap_or(&Value::Null);
            keep(
                stream,
                ToolCall {
                    name: MCP,
                    args_sha256: digest::hex(arguments.to_string().as_bytes()),
                    outcome: if denied.is_some() {
                        Outcome::Denied
                    } else if error.is_some() {
                        Outcome::Failed
                    } else {
                        outcome_of(item)
                    },
                },
            );
        }
        _ => {}
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
        let kind = event.get("type").and_then(Value::as_str);
        if stream.completed_events > 0
            && matches!(
                kind,
                Some("turn.started" | "item.completed" | "turn.completed" | "turn.failed")
            )
        {
            stream.events_after_completed = true;
        }
        match kind {
            Some("turn.started") => stream.turn_started = true,
            Some("item.completed") => {
                if let Some(item) = event.get("item") {
                    read_item(item, &mut stream);
                }
            }
            Some("turn.completed") => {
                stream.completed = true;
                stream.completed_events += 1;
                if let Some(usage) = event.get("usage") {
                    stream.input_tokens = u64_of(usage, "input_tokens");
                    stream.output_tokens = u64_of(usage, "output_tokens");
                }
            }
            Some("turn.failed") => {
                stream.failed =
                    Some(message_of(&event).unwrap_or_else(|| "turn failed".to_owned()));
            }
            Some("error") => {
                if let Some(message) = message_of(&event) {
                    if message.starts_with("Reconnecting...") {
                        stream.reconnects += 1;
                    }
                    stream.last_error = Some(message);
                }
            }
            _ => {}
        }
    }
    stream
}

/// The skills a `codex debug prompt-input` listing names, from its "Available skills" section.
#[must_use]
pub fn visible_skills(prompt_input: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_list = false;
    // The listing is JSON; the text lives in an `input_text` string with escaped newlines.
    let text = prompt_input.replace("\\n", "\n");
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("### Available skills") {
            in_list = true;
            continue;
        }
        if in_list {
            if line.starts_with("</skills_instructions>") || line.starts_with("###") {
                break;
            }
            if let Some(rest) = line.strip_prefix("- ")
                && let Some((name, _)) = rest.split_once(':')
            {
                names.push(name.trim().to_owned());
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_completed_turn_gives_the_last_message_and_the_usage() {
        let lines = concat!(
            r#"{"type":"thread.started","thread_id":"t"}"#,
            "\n",
            r#"{"type":"turn.started"}"#,
            "\n",
            r#"{"type":"item.completed","item":{"id":"i0","type":"error","message":"Model metadata for x not found"}}"#,
            "\n",
            r#"{"type":"item.completed","item":{"id":"i1","type":"command_execution","status":"failed"}}"#,
            "\n",
            r#"{"type":"item.completed","item":{"id":"i2","type":"agent_message","text":"done"}}"#,
            "\n",
            r#"{"type":"turn.completed","usage":{"input_tokens":1234,"cached_input_tokens":89,"output_tokens":56}}"#,
            "\n"
        );
        let stream = parse(lines.as_bytes());
        assert!(stream.completed && stream.failed.is_none());
        assert_eq!(stream.final_message.as_deref(), Some("done"));
        assert_eq!((stream.input_tokens, stream.output_tokens), (1234, 56));
        assert_eq!(stream.tool_items, 1);
    }

    #[test]
    fn a_second_completion_and_any_turn_event_after_it_are_noted() {
        let done = r#"{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}"#;
        let one = parse(format!("{done}\n").as_bytes());
        assert_eq!(
            (one.completed_events, one.events_after_completed),
            (1, false)
        );
        let two = parse(format!("{done}\n{done}\n").as_bytes());
        assert_eq!(
            (two.completed_events, two.events_after_completed),
            (2, true)
        );
        let late = parse(
            format!("{done}\n{{\"type\":\"item.completed\",\"item\":{{\"type\":\"agent_message\",\"text\":\"x\"}}}}\n")
                .as_bytes(),
        );
        assert!(late.events_after_completed);
    }

    #[test]
    fn a_failed_turn_keeps_its_message_and_counts_the_reconnects() {
        let lines = concat!(
            r#"{"type":"turn.started"}"#,
            "\n",
            r#"{"type":"error","message":"Reconnecting... 1/5 (unexpected status 401 Unauthorized)"}"#,
            "\n",
            r#"{"type":"error","message":"unexpected status 401 Unauthorized"}"#,
            "\n",
            r#"{"type":"turn.failed","error":{"message":"unexpected status 401 Unauthorized"}}"#,
            "\n"
        );
        let stream = parse(lines.as_bytes());
        assert!(!stream.completed);
        assert_eq!(stream.reconnects, 1);
        assert_eq!(
            stream.failed.as_deref(),
            Some("unexpected status 401 Unauthorized")
        );
    }

    #[test]
    fn an_mcp_call_that_needs_approval_is_a_denial() {
        let line = r#"{"type":"item.completed","item":{"type":"mcp_tool_call","server":"s","tool":"t","error":{"message":"MCP tool call requires approval, but approval policy is never"}}}"#;
        let stream = parse(line.as_bytes());
        assert_eq!(stream.denials.len(), 1);
        assert_eq!(stream.denials[0].tool, "mcp:s.t");
    }

    #[test]
    fn the_skill_listing_is_read_from_the_available_skills_section() {
        let text = "{\"text\":\"<skills_instructions>\\n## Skills\\n### Skill roots\\n- `r0` = `/workspace/.agents/skills`\\n### Available skills\\n- alpha-one: first (file: r0/alpha-one/SKILL.md)\\n- beta-two: second (file: r0/beta-two/SKILL.md)\\n</skills_instructions>\"}";
        assert_eq!(visible_skills(text), vec!["alpha-one", "beta-two"]);
        assert!(visible_skills("{\"text\":\"no skills here\"}").is_empty());
    }
}
