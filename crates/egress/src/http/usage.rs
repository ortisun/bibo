//! Reading token usage from what a provider sends back.
//!
//! The broker meters from the provider's own report, never from the tool's (the spike found that
//! the tools' cost figures come from a built-in price list and mean nothing behind a broker).
//! Two shapes carry usage:
//!
//! * a JSON document (`usage` at the top level, or `input_tokens` alone for a token count), and
//! * a server-sent event stream: the Anthropic Messages API reports input tokens in
//!   `message_start` and the final output tokens in `message_delta`; the OpenAI Responses API
//!   reports everything in `response.completed`, and Chat Completions in a last chunk with `usage`.
//!
//! The reader answers `None` when it did not see the whole report, and the broker then charges the
//! worst case for the request instead of guessing a smaller number. Streamed usage was UNVERIFIED
//! against a real provider (docs/spikes/agent-runtime.md); the shapes here follow the recorded fake
//! provider and the providers' published formats.

use factory_ports::agent::AnswerEnd;
use serde_json::Value;

use crate::broker::{Provider, TokenCounts};

/// The longest single line of an event stream the reader will hold. A longer line makes the whole
/// report unreadable.
const MAX_LINE: usize = 2 * 1024 * 1024;

fn number(object: &Value, key: &str) -> Option<u64> {
    object.get(key).and_then(Value::as_u64)
}

/// The counts in an Anthropic `usage` object.
fn anthropic(usage: &Value) -> TokenCounts {
    TokenCounts {
        input: number(usage, "input_tokens").unwrap_or(0),
        cache_write: number(usage, "cache_creation_input_tokens").unwrap_or(0),
        cache_read: number(usage, "cache_read_input_tokens").unwrap_or(0),
        output: number(usage, "output_tokens").unwrap_or(0),
    }
}

/// The counts in an OpenAI `usage` object, either API. OpenAI counts cached tokens inside the
/// input total, so they are taken out of the plain input here.
fn openai(usage: &Value) -> TokenCounts {
    let total_input = number(usage, "input_tokens")
        .or_else(|| number(usage, "prompt_tokens"))
        .unwrap_or(0);
    let cached = usage
        .get("input_tokens_details")
        .or_else(|| usage.get("prompt_tokens_details"))
        .and_then(|d| number(d, "cached_tokens"))
        .unwrap_or(0)
        .min(total_input);
    TokenCounts {
        input: total_input - cached,
        cache_write: 0,
        cache_read: cached,
        output: number(usage, "output_tokens")
            .or_else(|| number(usage, "completion_tokens"))
            .unwrap_or(0),
    }
}

/// How an Anthropic `stop_reason` ends the turn.
fn anthropic_end(reason: &str) -> AnswerEnd {
    match reason {
        "end_turn" | "stop_sequence" => AnswerEnd::EndTurn,
        "tool_use" => AnswerEnd::ToolUse,
        // `max_tokens`, `pause_turn`, `refusal`, `model_context_window_exceeded` and any reason this
        // reader does not know: the turn did not end normally.
        _ => AnswerEnd::Cut,
    }
}

/// How a Chat Completions `finish_reason` ends the turn.
fn chat_end(reason: &str) -> AnswerEnd {
    match reason {
        "stop" => AnswerEnd::EndTurn,
        "tool_calls" | "function_call" => AnswerEnd::ToolUse,
        _ => AnswerEnd::Cut,
    }
}

/// How an OpenAI Responses object ends the turn. `completed` with a call in the output is a request
/// for a tool result; `completed` without one ends the turn; `incomplete` is cut; the rest failed.
fn responses_end(response: &Value) -> AnswerEnd {
    match response.get("status").and_then(Value::as_str) {
        Some("completed") => {
            let calls = response
                .get("output")
                .and_then(Value::as_array)
                .is_some_and(|items| {
                    items.iter().any(|item| {
                        item.get("type")
                            .and_then(Value::as_str)
                            .is_some_and(|kind| kind.ends_with("_call"))
                    })
                });
            if calls {
                AnswerEnd::ToolUse
            } else {
                AnswerEnd::EndTurn
            }
        }
        Some("incomplete") => AnswerEnd::Cut,
        _ => AnswerEnd::Failed,
    }
}

/// How the answer in a complete JSON body ended. A body that does not say is `Failed`: the broker
/// attests only an ending it read.
#[must_use]
pub fn answer_end_from_json(provider: Provider, body: &[u8]) -> AnswerEnd {
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return AnswerEnd::Failed;
    };
    match provider {
        Provider::Anthropic => value
            .get("stop_reason")
            .and_then(Value::as_str)
            .map_or(AnswerEnd::Failed, anthropic_end),
        Provider::OpenAi => {
            if value.get("status").is_some() {
                return responses_end(&value);
            }
            value
                .pointer("/choices/0/finish_reason")
                .and_then(Value::as_str)
                .map_or(AnswerEnd::Failed, chat_end)
        }
    }
}

/// The usage in a complete JSON answer, or `None` when it holds none.
#[must_use]
pub fn counts_from_json(provider: Provider, body: &[u8]) -> Option<TokenCounts> {
    let value: Value = serde_json::from_slice(body).ok()?;
    if let Some(usage) = value.get("usage").filter(|u| u.is_object()) {
        return Some(match provider {
            Provider::Anthropic => anthropic(usage),
            Provider::OpenAi => openai(usage),
        });
    }
    // The Anthropic token-counting route answers `{"input_tokens": N}`.
    number(&value, "input_tokens").map(|input| TokenCounts {
        input,
        ..TokenCounts::default()
    })
}

/// Reads usage out of a server-sent event stream, chunk by chunk.
#[derive(Debug)]
pub struct StreamUsage {
    provider: Provider,
    line: Vec<u8>,
    discarding: bool,
    counts: TokenCounts,
    saw_start: bool,
    saw_final: bool,
    end: AnswerEnd,
    /// A Responses stream announced a call item (`function_call` and its kin) before it completed.
    saw_call: bool,
}

impl StreamUsage {
    /// A reader for a stream from `provider`.
    #[must_use]
    pub fn new(provider: Provider) -> Self {
        Self {
            provider,
            line: Vec::new(),
            discarding: false,
            counts: TokenCounts::default(),
            saw_start: false,
            saw_final: false,
            end: AnswerEnd::Failed,
            saw_call: false,
        }
    }

    /// Feeds the next bytes of the stream.
    pub fn feed(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if byte == b'\n' {
                if !self.discarding {
                    let line = std::mem::take(&mut self.line);
                    self.line_done(&line);
                }
                self.line.clear();
                self.discarding = false;
            } else if !self.discarding {
                if self.line.len() >= MAX_LINE {
                    self.discarding = true;
                    self.line.clear();
                } else {
                    self.line.push(byte);
                }
            }
        }
    }

    /// True when the whole report has been seen.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        match self.provider {
            Provider::Anthropic => self.saw_start && self.saw_final,
            Provider::OpenAi => self.saw_final,
        }
    }

    /// The counts, when the whole report was seen.
    #[must_use]
    pub fn finish(self) -> Option<TokenCounts> {
        self.finish_with_end().0
    }

    /// The counts, when the whole report was seen, and how the answer ended. A stream that was cut
    /// before its report is complete ends `Failed`, whatever stop reason it carried so far.
    #[must_use]
    pub fn finish_with_end(mut self) -> (Option<TokenCounts>, AnswerEnd) {
        if !self.line.is_empty() && !self.discarding {
            let line = std::mem::take(&mut self.line);
            self.line_done(&line);
        }
        if self.is_complete() {
            (Some(self.counts), self.end)
        } else {
            (None, AnswerEnd::Failed)
        }
    }

    fn line_done(&mut self, raw: &[u8]) {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        let Some(payload) = line.strip_prefix(b"data:") else {
            return;
        };
        let payload = payload.strip_prefix(b" ").unwrap_or(payload);
        if payload == b"[DONE]" {
            return;
        }
        let Ok(event) = serde_json::from_slice::<Value>(payload) else {
            return;
        };
        let kind = event.get("type").and_then(Value::as_str).unwrap_or("");
        match self.provider {
            Provider::Anthropic => self.anthropic_event(kind, &event),
            Provider::OpenAi => self.openai_event(kind, &event),
        }
    }

    fn anthropic_event(&mut self, kind: &str, event: &Value) {
        match kind {
            "message_start" => {
                if let Some(usage) = event.pointer("/message/usage") {
                    self.counts = anthropic(usage);
                    self.saw_start = true;
                }
            }
            "message_delta" => {
                if let Some(reason) = event.pointer("/delta/stop_reason").and_then(Value::as_str) {
                    self.end = anthropic_end(reason);
                }
                if let Some(usage) = event.get("usage") {
                    // The usage of a delta is cumulative. Fields it does not carry keep the value
                    // from `message_start`.
                    for (key, slot) in [
                        ("input_tokens", &mut self.counts.input),
                        ("cache_creation_input_tokens", &mut self.counts.cache_write),
                        ("cache_read_input_tokens", &mut self.counts.cache_read),
                        ("output_tokens", &mut self.counts.output),
                    ] {
                        if let Some(value) = number(usage, key) {
                            *slot = value;
                        }
                    }
                    self.saw_final = true;
                }
            }
            "message_stop" => self.saw_final = self.saw_final || self.saw_start,
            _ => {}
        }
    }

    fn openai_event(&mut self, kind: &str, event: &Value) {
        let usage = match kind {
            "response.completed" | "response.incomplete" | "response.failed" => {
                if let Some(response) = event.get("response") {
                    // The event type decides the status: a `response.completed` event whose object
                    // carries no status is still a completion.
                    self.end = match kind {
                        "response.completed" => match responses_end(response) {
                            AnswerEnd::Failed => AnswerEnd::EndTurn,
                            other => other,
                        },
                        "response.incomplete" => AnswerEnd::Cut,
                        _ => AnswerEnd::Failed,
                    };
                    if self.end == AnswerEnd::EndTurn && self.saw_call {
                        self.end = AnswerEnd::ToolUse;
                    }
                }
                event.pointer("/response/usage")
            }
            "response.output_item.added" | "response.output_item.done" => {
                if event
                    .pointer("/item/type")
                    .and_then(Value::as_str)
                    .is_some_and(|item| item.ends_with("_call"))
                {
                    self.saw_call = true;
                }
                None
            }
            // A Chat Completions chunk has no `type`; the last one carries `usage`, and the one
            // before it names the reason the choice ended.
            "" => {
                if let Some(reason) = event
                    .pointer("/choices/0/finish_reason")
                    .and_then(Value::as_str)
                {
                    self.end = chat_end(reason);
                }
                event.get("usage")
            }
            _ => None,
        };
        if let Some(usage) = usage.filter(|u| u.is_object()) {
            self.counts = openai(usage);
            self.saw_final = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sse(events: &[(&str, &str)]) -> Vec<u8> {
        let mut out = String::new();
        for (name, data) in events {
            out.push_str(&format!("event: {name}\ndata: {data}\n\n"));
        }
        out.into_bytes()
    }

    fn anthropic_stream() -> Vec<u8> {
        sse(&[
            (
                "message_start",
                r#"{"type":"message_start","message":{"id":"m","usage":{"input_tokens":1234,"cache_creation_input_tokens":7,"cache_read_input_tokens":89,"output_tokens":1}}}"#,
            ),
            (
                "content_block_delta",
                r#"{"type":"content_block_delta","delta":{"text":"hi"}}"#,
            ),
            (
                "message_delta",
                r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":56}}"#,
            ),
            ("message_stop", r#"{"type":"message_stop"}"#),
        ])
    }

    #[test]
    fn an_anthropic_stream_gives_the_input_of_the_start_and_the_output_of_the_last_delta() {
        let mut reader = StreamUsage::new(Provider::Anthropic);
        reader.feed(&anthropic_stream());
        assert!(reader.is_complete());
        assert_eq!(
            reader.finish(),
            Some(TokenCounts {
                input: 1234,
                cache_write: 7,
                cache_read: 89,
                output: 56
            })
        );
    }

    #[test]
    fn the_result_does_not_depend_on_where_the_chunks_are_cut() {
        let stream = anthropic_stream();
        for cut in 1..stream.len() {
            let mut reader = StreamUsage::new(Provider::Anthropic);
            reader.feed(&stream[..cut]);
            reader.feed(&stream[cut..]);
            assert_eq!(reader.finish().map(|c| c.output), Some(56), "cut at {cut}");
        }
        // One byte at a time.
        let mut reader = StreamUsage::new(Provider::Anthropic);
        for byte in &stream {
            reader.feed(std::slice::from_ref(byte));
        }
        assert!(reader.is_complete());
    }

    #[test]
    fn a_stream_that_ends_before_the_report_is_complete_gives_nothing() {
        let stream = anthropic_stream();
        let text = String::from_utf8(stream).expect("text");
        let cut = text.find("event: message_delta").expect("an event");
        let mut reader = StreamUsage::new(Provider::Anthropic);
        reader.feed(&text.as_bytes()[..cut]);
        assert!(!reader.is_complete());
        assert_eq!(reader.finish(), None);
        assert_eq!(StreamUsage::new(Provider::Anthropic).finish(), None);
    }

    #[test]
    fn an_openai_responses_stream_gives_usage_with_cached_tokens_taken_out_of_the_input() {
        let stream = sse(&[
            (
                "response.created",
                r#"{"type":"response.created","response":{}}"#,
            ),
            (
                "response.completed",
                r#"{"type":"response.completed","response":{"usage":{"input_tokens":1234,"input_tokens_details":{"cached_tokens":89},"output_tokens":56,"total_tokens":1290}}}"#,
            ),
        ]);
        let mut reader = StreamUsage::new(Provider::OpenAi);
        reader.feed(&stream);
        assert_eq!(
            reader.finish(),
            Some(TokenCounts {
                input: 1145,
                cache_write: 0,
                cache_read: 89,
                output: 56
            })
        );
    }

    #[test]
    fn a_chat_completions_stream_reports_usage_in_its_last_chunk() {
        let mut reader = StreamUsage::new(Provider::OpenAi);
        reader.feed(b"data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n");
        assert!(!reader.is_complete());
        reader.feed(
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":4}}\n\ndata: [DONE]\n\n",
        );
        assert_eq!(
            reader.finish(),
            Some(TokenCounts {
                input: 10,
                output: 4,
                ..TokenCounts::default()
            })
        );
    }

    #[test]
    fn an_endless_line_makes_the_report_unreadable_instead_of_filling_memory() {
        let mut reader = StreamUsage::new(Provider::Anthropic);
        reader.feed(b"data: ");
        let filler = vec![b'x'; 1024 * 1024];
        for _ in 0..4 {
            reader.feed(&filler);
        }
        assert!(reader.line.len() <= MAX_LINE);
        reader.feed(b"\n");
        reader.feed(&anthropic_stream());
        assert!(reader.is_complete(), "the next lines are read again");
    }

    #[test]
    fn json_answers_are_read_for_both_providers_and_for_the_token_count_route() {
        let anthropic_body =
            br#"{"usage":{"input_tokens":10,"cache_read_input_tokens":5,"output_tokens":3}}"#;
        assert_eq!(
            counts_from_json(Provider::Anthropic, anthropic_body),
            Some(TokenCounts {
                input: 10,
                cache_write: 0,
                cache_read: 5,
                output: 3
            })
        );
        let openai_body = br#"{"usage":{"input_tokens":10,"input_tokens_details":{"cached_tokens":4},"output_tokens":3}}"#;
        assert_eq!(
            counts_from_json(Provider::OpenAi, openai_body),
            Some(TokenCounts {
                input: 6,
                cache_write: 0,
                cache_read: 4,
                output: 3
            })
        );
        assert_eq!(
            counts_from_json(Provider::Anthropic, br#"{"input_tokens":77}"#),
            Some(TokenCounts {
                input: 77,
                ..TokenCounts::default()
            })
        );
        assert_eq!(counts_from_json(Provider::OpenAi, b"{}"), None);
        assert_eq!(counts_from_json(Provider::OpenAi, b"not json"), None);
    }
}
