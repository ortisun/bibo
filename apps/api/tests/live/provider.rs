//! A labelled FAKE model provider that plays the playbook over the wire.
//!
//! **Fidelity: fake.** It is the only stand-in for the model in the live-adapters run. It listens on
//! the loopback interface, answers the two request shapes the real tools send (the Anthropic
//! Messages API to Claude Code, the OpenAI Responses API to Codex) with the streaming answers those
//! tools read, and decides what to answer from the playbook (`playbook/`, data in
//! `fixtures/recordings/playbook/word-count/`): the agent is read from the prompt (`Agent: <id>` in
//! the template, or the Spec Kit skill the request expands), and the playbook gives the answer for
//! that agent exactly as it does in the other rigs.
//!
//! What it makes the real tool do is what a model would: an agent that writes files asks for the
//! tool `Read` on each path (Claude Code refuses to overwrite a file it has not read), then for the
//! tool `Write` with the content of the playbook, and then answers with the JSON of its report. The
//! files are therefore written by the real Claude Code in the real container, not by this server.
//!
//! It checks the key the broker sends (the key of the upstream in the broker's configuration, not
//! the job token) and answers 401 to any other. It keeps a record of every request (path, model,
//! agent, round) and never keeps a prompt.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use factory_testkit::fx::http::{HttpRequest, HttpResponse, HttpServer};
use serde_json::{Value, json};

use crate::playbook::{Playbook, Reply};

/// One request the provider answered.
#[derive(Debug, Clone)]
pub struct Seen {
    /// The route.
    pub path: String,
    /// The model the request names.
    pub model: String,
    /// The agent the playbook was asked for, or what the request could not be matched to.
    pub agent: String,
    /// Which answer of the conversation this was: 0 asks to read, 1 asks to write, the last is the
    /// report.
    pub round: usize,
    /// True for a streamed answer.
    pub stream: bool,
}

struct State {
    seen: Vec<Seen>,
    /// The playbook's answer for a conversation, kept by the hash of its first prompt, because the
    /// playbook has one answer per entry.
    replies: HashMap<String, (String, Reply)>,
}

/// The running provider.
pub struct FakeProvider {
    server: HttpServer,
    state: Arc<Mutex<State>>,
}

impl FakeProvider {
    /// Starts the provider on the loopback interface. `key` is the one credential it accepts.
    pub fn start(key: String, playbook: Arc<Playbook>) -> Self {
        let state = Arc::new(Mutex::new(State {
            seen: Vec::new(),
            replies: HashMap::new(),
        }));
        let shared = Arc::clone(&state);
        let server = HttpServer::start("live-fake-provider", move |request| {
            answer(&shared, &key, &playbook, request)
        })
        .expect("the fake provider starts");
        Self { server, state }
    }

    /// `http://127.0.0.1:<port>`.
    pub fn base_url(&self) -> String {
        self.server.base_url()
    }

    /// Every request answered so far, oldest first.
    pub fn seen(&self) -> Vec<Seen> {
        self.state
            .lock()
            .expect("the provider lock is not poisoned")
            .seen
            .clone()
    }
}

fn credential(request: &HttpRequest) -> Option<String> {
    request.header("x-api-key").map(str::to_owned).or_else(|| {
        request
            .header("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::to_owned)
    })
}

fn error(status: u16, message: &str) -> HttpResponse {
    HttpResponse::json(
        status,
        &json!({"type": "error", "error": {"type": "api_error", "message": message}}),
    )
}

fn answer(
    state: &Mutex<State>,
    key: &str,
    playbook: &Playbook,
    request: &HttpRequest,
) -> HttpResponse {
    let path = request.path().to_owned();
    if request.method == "GET" && path.starts_with("/v1/models") {
        return HttpResponse::json(
            200,
            &json!({"data": [], "object": "list", "has_more": false}),
        );
    }
    if request.method != "POST" {
        return error(404, "FAKE-PROVIDER: no such route");
    }
    if credential(request).as_deref() != Some(key) {
        return HttpResponse::json(
            401,
            &json!({"type": "error", "error": {"type": "authentication_error", "message": "FAKE-PROVIDER: the credential is not the one of the upstream"}}),
        );
    }
    let body = request.json().unwrap_or(Value::Null);
    if path.ends_with("/count_tokens") {
        return HttpResponse::json(200, &json!({"input_tokens": 1200}));
    }
    let anthropic = path.starts_with("/v1/messages");
    let model = body["model"].as_str().unwrap_or("unknown").to_owned();
    let stream = body["stream"].as_bool().unwrap_or(false);
    let prompt = first_user_text(&body);
    let Some((agent, instructions)) = identify(&prompt) else {
        let mut guard = state.lock().expect("lock");
        guard.seen.push(Seen {
            path,
            model,
            agent: "(not an agent request)".to_owned(),
            round: 0,
            stream,
        });
        return error(
            400,
            "FAKE-PROVIDER: the request is from no agent of the playbook",
        );
    };

    // One playbook answer for the whole conversation.
    let fingerprint = format!(
        "{agent}:{}",
        factory_domain::values::Sha256Digest::of(prompt.as_bytes())
    );
    let reply = {
        let mut guard = state.lock().expect("lock");
        if let Some((_, reply)) = guard.replies.get(&fingerprint) {
            reply.clone()
        } else {
            // The playbook panics when it has no entry for a call, by design; here that is an
            // error answer, and the miss stays in `Playbook::misses`.
            let asked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                playbook.answer(&agent, &instructions)
            }));
            match asked {
                Ok(reply) => {
                    guard
                        .replies
                        .insert(fingerprint.clone(), (agent.clone(), reply.clone()));
                    reply
                }
                Err(_) => {
                    guard.seen.push(Seen {
                        path,
                        model,
                        agent: format!("{agent} (the playbook has no entry)"),
                        round: 0,
                        stream,
                    });
                    return error(
                        500,
                        "FAKE-PROVIDER: the playbook has no entry for this call",
                    );
                }
            }
        }
    };

    let writes: Vec<&(String, Vec<u8>)> = reply.writes.iter().collect();
    let (blocks, round, ends) = if anthropic {
        let asked = tools_asked(&body);
        if writes.is_empty() {
            (final_text(&reply), 0, true)
        } else if asked.is_empty() {
            let reads = writes
                .iter()
                .map(|(path, _)| ("Read", json!({"file_path": format!("/workspace/{path}")})))
                .collect::<Vec<_>>();
            (tool_calls(&reads, &fingerprint, 0), 0, false)
        } else if !asked.iter().any(|name| name == "Write") {
            let writes_calls = writes
                .iter()
                .map(|(path, bytes)| {
                    (
                        "Write",
                        json!({
                            "file_path": format!("/workspace/{path}"),
                            "content": String::from_utf8_lossy(bytes),
                        }),
                    )
                })
                .collect::<Vec<_>>();
            (tool_calls(&writes_calls, &fingerprint, 1), 1, false)
        } else {
            (final_text(&reply), 2, true)
        }
    } else {
        // Codex agents of the playbook write no files; they report.
        (final_text(&reply), 0, true)
    };

    {
        let mut guard = state.lock().expect("lock");
        guard.seen.push(Seen {
            path,
            model: model.clone(),
            agent: agent.clone(),
            round,
            stream,
        });
    }
    if anthropic {
        anthropic_answer(&model, &blocks, ends, stream)
    } else {
        openai_answer(&model, &blocks, stream)
    }
}

// ---- reading the request -----------------------------------------------------------------------

fn text_of(content: &Value) -> Vec<String> {
    match content {
        Value::String(text) => vec![text.clone()],
        Value::Array(blocks) => blocks
            .iter()
            .filter_map(|block| {
                block["text"]
                    .as_str()
                    .filter(|_| matches!(block["type"].as_str(), Some("text" | "input_text")))
                    .map(str::to_owned)
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Every text of the user messages of the request, oldest first, joined.
fn first_user_text(body: &Value) -> String {
    let mut texts = Vec::new();
    for key in ["messages", "input"] {
        if let Some(items) = body[key].as_array() {
            for item in items {
                if item["role"] == "user" {
                    texts.extend(text_of(&item["content"]));
                }
            }
        }
    }
    texts.join("\n")
}

/// The names of the tools the assistant already asked for in this conversation.
fn tools_asked(body: &Value) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(messages) = body["messages"].as_array() {
        for message in messages {
            if message["role"] == "assistant"
                && let Some(blocks) = message["content"].as_array()
            {
                for block in blocks {
                    if block["type"] == "tool_use"
                        && let Some(name) = block["name"].as_str()
                    {
                        names.push(name.to_owned());
                    }
                }
            }
        }
    }
    names
}

/// The agent a prompt is for, and the instructions the playbook reads.
fn identify(prompt: &str) -> Option<(String, String)> {
    // An agent of the factory: its template names it. This comes first, because the prompt of a
    // reviewer quotes the instruction its writer was given.
    if let Some(agent) = prompt
        .lines()
        .find_map(|line| line.strip_prefix("Agent: "))
        .map(|rest| rest.trim().to_owned())
    {
        return Some((agent, prompt.to_owned()));
    }
    // A Spec Kit skill: the host expanded `/speckit-<skill> <arguments>`; the arguments are the
    // fixed instruction of the adapter, which names the skill by its first words.
    for (skill, start) in [
        (
            "specify",
            "Write the feature specification in the directory ",
        ),
        ("clarify", "Clarify the specification in the directory "),
        (
            "checklist",
            "Write the requirements-quality checklist for the specification in the directory ",
        ),
    ] {
        if let Some(at) = prompt.find(start) {
            let tail = &prompt[at..];
            let end = tail
                .find("call the report tool once with the report the schema asks for.")
                .map_or(tail.len(), |found| {
                    found + "call the report tool once with the report the schema asks for.".len()
                });
            return Some((
                "specification-writer".to_owned(),
                format!("/speckit-{skill} {}", &tail[..end]),
            ));
        }
    }
    None
}

// ---- building the answer -----------------------------------------------------------------------

/// A block of an answer.
#[derive(Debug, Clone)]
enum Block {
    Text(String),
    Tool {
        id: String,
        name: &'static str,
        input: Value,
    },
}

fn final_text(reply: &Reply) -> Vec<Block> {
    vec![Block::Text(
        serde_json::to_string(&reply.output).expect("the playbook output is JSON"),
    )]
}

fn tool_calls(calls: &[(&'static str, Value)], fingerprint: &str, round: usize) -> Vec<Block> {
    let tag: String = fingerprint
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .rev()
        .take(12)
        .collect();
    calls
        .iter()
        .enumerate()
        .map(|(index, (name, input))| Block::Tool {
            id: format!("toolu_fake_{tag}_{round}_{index}"),
            name,
            input: input.clone(),
        })
        .collect()
}

fn sse(events: &[(&str, Value)]) -> Vec<u8> {
    let mut out = String::new();
    for (name, payload) in events {
        out.push_str(&format!("event: {name}\ndata: {payload}\n\n"));
    }
    out.into_bytes()
}

fn anthropic_answer(model: &str, blocks: &[Block], ends: bool, stream: bool) -> HttpResponse {
    let usage = json!({"input_tokens": 1200, "output_tokens": 300,
        "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0});
    let stop = if ends { "end_turn" } else { "tool_use" };
    let content: Vec<Value> = blocks
        .iter()
        .map(|block| match block {
            Block::Text(text) => json!({"type": "text", "text": text}),
            Block::Tool { id, name, input } => {
                json!({"type": "tool_use", "id": id, "name": name, "input": input})
            }
        })
        .collect();
    if !stream {
        return HttpResponse::json(
            200,
            &json!({"id": "msg_fake", "type": "message", "role": "assistant", "model": model,
                "content": content, "stop_reason": stop, "stop_sequence": null, "usage": usage}),
        );
    }
    let mut events: Vec<(&str, Value)> = vec![(
        "message_start",
        json!({"type": "message_start", "message": {"id": "msg_fake", "type": "message",
            "role": "assistant", "model": model, "content": [], "stop_reason": null,
            "stop_sequence": null,
            "usage": {"input_tokens": 1200, "output_tokens": 1,
                "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0}}}),
    )];
    for (index, block) in blocks.iter().enumerate() {
        match block {
            Block::Text(text) => {
                events.push((
                    "content_block_start",
                    json!({"type": "content_block_start", "index": index,
                        "content_block": {"type": "text", "text": ""}}),
                ));
                events.push((
                    "content_block_delta",
                    json!({"type": "content_block_delta", "index": index,
                        "delta": {"type": "text_delta", "text": text}}),
                ));
            }
            Block::Tool { id, name, input } => {
                events.push((
                    "content_block_start",
                    json!({"type": "content_block_start", "index": index,
                        "content_block": {"type": "tool_use", "id": id, "name": name, "input": {}}}),
                ));
                events.push((
                    "content_block_delta",
                    json!({"type": "content_block_delta", "index": index,
                        "delta": {"type": "input_json_delta", "partial_json": input.to_string()}}),
                ));
            }
        }
        events.push((
            "content_block_stop",
            json!({"type": "content_block_stop", "index": index}),
        ));
    }
    events.push((
        "message_delta",
        json!({"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": null},
            "usage": {"output_tokens": 300}}),
    ));
    events.push(("message_stop", json!({"type": "message_stop"})));
    HttpResponse::empty(200)
        .with_header("Content-Type", "text/event-stream")
        .with_header("Cache-Control", "no-cache")
        .with_body(sse(&events))
}

fn openai_answer(model: &str, blocks: &[Block], stream: bool) -> HttpResponse {
    let text = blocks
        .iter()
        .find_map(|block| match block {
            Block::Text(text) => Some(text.clone()),
            Block::Tool { .. } => None,
        })
        .unwrap_or_default();
    let usage = json!({"input_tokens": 1200, "input_tokens_details": {"cached_tokens": 0},
        "output_tokens": 300, "output_tokens_details": {"reasoning_tokens": 0}, "total_tokens": 1500});
    let item = json!({"id": "msg_fake", "type": "message", "status": "completed", "role": "assistant",
        "content": [{"type": "output_text", "text": text, "annotations": []}]});
    let base = json!({"id": "resp_fake", "object": "response", "created_at": 1_700_000_000,
        "model": model, "status": "in_progress", "output": []});
    let mut done = base.clone();
    done["status"] = json!("completed");
    done["output"] = json!([item.clone()]);
    done["usage"] = usage;
    if !stream {
        return HttpResponse::json(200, &done);
    }
    let mut number = 0_u64;
    let mut events: Vec<(&str, Value)> = Vec::new();
    let mut emit = |name: &'static str, mut payload: Value| {
        payload["type"] = json!(name);
        payload["sequence_number"] = json!(number);
        number += 1;
        events.push((name, payload));
    };
    emit("response.created", json!({"response": base}));
    emit("response.in_progress", json!({"response": base}));
    emit(
        "response.output_item.added",
        json!({"output_index": 0, "item": {"id": "msg_fake", "type": "message",
            "status": "in_progress", "role": "assistant", "content": []}}),
    );
    emit(
        "response.content_part.added",
        json!({"item_id": "msg_fake", "output_index": 0, "content_index": 0,
            "part": {"type": "output_text", "text": "", "annotations": []}}),
    );
    emit(
        "response.output_text.delta",
        json!({"item_id": "msg_fake", "output_index": 0, "content_index": 0, "delta": text}),
    );
    emit(
        "response.output_text.done",
        json!({"item_id": "msg_fake", "output_index": 0, "content_index": 0, "text": text}),
    );
    emit(
        "response.content_part.done",
        json!({"item_id": "msg_fake", "output_index": 0, "content_index": 0,
            "part": item["content"][0]}),
    );
    emit(
        "response.output_item.done",
        json!({"output_index": 0, "item": item}),
    );
    emit("response.completed", json!({"response": done}));
    HttpResponse::empty(200)
        .with_header("Content-Type", "text/event-stream")
        .with_header("Cache-Control", "no-cache")
        .with_body(sse(&events))
}
