#!/usr/bin/env python3
"""A labelled FAKE model provider for the agent runtime spike (work package s0-agent-runtime-spike).

Fidelity: fake. It is not the Anthropic or the OpenAI service. It speaks just enough of

  * the Anthropic Messages streaming API (what Claude Code sends to ANTHROPIC_BASE_URL), and
  * the OpenAI Responses streaming API (what Codex sends to a configured model provider)

to finish a turn with a canned reply or one scripted tool call. It makes no network call of its own,
holds no real credential and never reads one. The expected API key is a fake that the test harness
generates at run time and hands over in a file (--key-file); no key is stored in this repository.

Behaviour is driven by the prompt, so it does not depend on how many helper requests a CLI sends.
A directive is a line in the last user message:

  FAKE:TOOL <tool name> <json input>   answer with one tool call (once; after the tool result comes
                                       back the provider answers with a text summary of the result)
  FAKE:HTTP <status>                   answer with that HTTP status and a provider-shaped error body
  FAKE:SLEEP <seconds>                 start the stream, wait, then finish (to test cancellation)
  FAKE:STRUCT                          answer with the JSON file given by --struct-reply, as a
                                       structured output (Claude: a tool call; Codex: output text)
  FAKE:STRUCT_BAD                      the same, but with a document that breaks the schema
  (none)                               answer with a canned text

Every request is appended to the JSONL file given by --log, with credentials removed. Large strings
are cut to a short prefix plus their length and SHA-256, so the log stays small and holds no
repository content beyond what the spike's own fixtures contain.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

LABEL = "FAKE-PROVIDER (fidelity: fake, not a real model)"
CANNED_TEXT = "FAKE-PROVIDER-REPLY: canned answer, no model was called."

# Distinct numbers so a test can see which usage fields a CLI reads and how it adds them up.
USAGE_INPUT = 1234
USAGE_OUTPUT = 56
USAGE_CACHE_CREATE = 7
USAGE_CACHE_READ = 89

LOOP = re.compile(r"FAKE:LOOP[ \t]+(\d+)[ \t]+(\S+)[ \t]*([^\n]*)")
DIRECTIVE = re.compile(r"FAKE:(TOOL|HTTP|SLEEP|STRUCT_BAD|STRUCT)(?:[ \t]+([^\n]*))?")
SECRET_SHAPES = [
    (re.compile(r"sk-[A-Za-z0-9_\-]{16,}"), "<token-shaped>"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{12,}"), "Bearer <token-shaped>"),
    (re.compile(r"\b[0-9a-fA-F]{40,}\b"), "<long-hex>"),
]
CUT = 240
# Strings the spike plants or looks for. The log counts how often each appears in a request body, so a
# test can show that a hostile repository file or a skill body did (or did not) reach the model.
MARKERS = [
    "HOSTILE-INSTRUCTION-MARKER",
    "CLAUDE-MD-WAS-LOADED",
    "AGENTS-MD-WAS-LOADED",
    "PLANTED_CANARY",
    "Check for extension hooks",
    "speckit-specify",
    "speckit-plan",
    "<skills_instructions>",
    "FAKE:",
    "exec_command(args",
    "write_stdin(args",
    "apply_patch(input",
    "mcp__bridge__factory_exec",
]
CUSTOM_TOOLS = {"exec", "apply_patch"}  # Codex freeform tools: their input is raw text, not a JSON object


class Config:
    """Process-wide settings, filled in by main()."""

    log_path: Path = Path("requests.jsonl")
    dump_dir: Path | None = None  # scratch only: full request bodies, never committed
    expected_key: str = ""
    struct_reply: dict[str, Any] = {}
    struct_bad: dict[str, Any] = {"unexpected": True}
    started: float = time.monotonic()
    seq: int = 0
    lock: threading.Lock = threading.Lock()


def scrub_text(text: str) -> str:
    """Remove the expected key and anything shaped like a token from a string."""
    if Config.expected_key:
        text = text.replace(Config.expected_key, "<fake-key>")
    for pattern, replacement in SECRET_SHAPES:
        text = pattern.sub(replacement, text)
    return text


def cut(text: str) -> str:
    text = scrub_text(text)
    if len(text) <= CUT:
        return text
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
    return f"{text[:CUT]}...[len={len(text)} sha256={digest}]"


def summarize(value: Any, key: str = "") -> Any:
    """Copy a JSON value, cutting long strings and hiding the per-install identifiers."""
    if isinstance(value, str):
        if key in {"user_id", "device_id", "account_uuid", "organization_id"}:
            return "<scrubbed>"
        return cut(value)
    if isinstance(value, list):
        items = [summarize(item) for item in value]
        return items
    if isinstance(value, dict):
        return {str(k): summarize(v, str(k)) for k, v in value.items()}
    return value


def tool_schema_summary(tools: Any) -> list[Any]:
    """Name, type and top-level property names of each tool, not the long descriptions."""
    out: list[Any] = []
    if not isinstance(tools, list):
        return out
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        schema = tool.get("input_schema") or tool.get("parameters") or {}
        props = sorted((schema.get("properties") or {}).keys()) if isinstance(schema, dict) else []
        out.append({"name": tool.get("name"), "type": tool.get("type"), "properties": props})
    return out


def last_user_texts(body: dict[str, Any]) -> tuple[list[str], list[dict[str, Any]]]:
    """Texts and tool results of the last user turn, for the Anthropic and the OpenAI shapes."""
    texts: list[str] = []
    results: list[dict[str, Any]] = []
    messages = body.get("messages")
    if isinstance(messages, list):  # Anthropic Messages
        for message in reversed(messages):
            if not isinstance(message, dict) or message.get("role") != "user":
                continue
            content = message.get("content")
            if isinstance(content, str):
                texts.append(content)
            elif isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "text" and isinstance(block.get("text"), str):
                        texts.append(block["text"])
                    elif block.get("type") == "tool_result":
                        results.append(block)
            break
        return texts, results
    items = body.get("input")
    if isinstance(items, list):  # OpenAI Responses
        trailing: list[dict[str, Any]] = []
        for item in reversed(items):
            if isinstance(item, dict) and item.get("type") in {"function_call_output", "custom_tool_call_output"}:
                trailing.append(item)
                continue
            break
        if trailing:
            return texts, trailing
        for item in reversed(items):
            if isinstance(item, dict) and item.get("role") == "user":
                content = item.get("content")
                if isinstance(content, str):
                    texts.append(content)
                elif isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict) and isinstance(part.get("text"), str):
                            texts.append(part["text"])
                break
    return texts, results


def find_directive(texts: list[str]) -> tuple[str, str] | None:
    for text in texts:
        match = DIRECTIVE.search(text)
        if match:
            return match.group(1), (match.group(2) or "").strip()
    return None


def conversation_user_texts(body: dict[str, Any]) -> list[str]:
    """Every text block of every user message, oldest first."""
    texts: list[str] = []
    messages = body.get("messages")
    items = body.get("input")
    sequence: list[Any] = messages if isinstance(messages, list) else (items if isinstance(items, list) else [])
    for message in sequence:
        if not isinstance(message, dict) or message.get("role") != "user":
            continue
        content = message.get("content")
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            texts.extend(str(p["text"]) for p in content if isinstance(p, dict) and isinstance(p.get("text"), str))
    return texts


def count_tool_results(body: dict[str, Any]) -> int:
    """How many tool results the whole conversation holds so far."""
    total = 0
    for message in body.get("messages") or []:
        if isinstance(message, dict) and isinstance(message.get("content"), list):
            total += sum(1 for b in message["content"] if isinstance(b, dict) and b.get("type") == "tool_result")
    for item in body.get("input") or []:
        if isinstance(item, dict) and str(item.get("type", "")).endswith("_output"):
            total += 1
    return total


def find_loop(texts: list[str]) -> tuple[int, str, str] | None:
    """FAKE:LOOP <n> <tool> <input>: keep calling the tool until n results are in, then act as a broker that revoked the token."""
    for text in texts:
        match = LOOP.search(text)
        if match:
            return int(match.group(1)), match.group(2), (match.group(3) or "").strip()
    return None


def features_of(schema: Any) -> list[str]:
    """Which JSON Schema keywords of interest a schema uses anywhere."""
    wanted = {"if", "then", "else", "oneOf", "anyOf", "allOf", "not", "$ref", "$defs", "const", "enum", "pattern", "additionalProperties", "required"}
    found: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in wanted:
                    found.add(key)
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(schema)
    return sorted(found)


def structured_request(body: dict[str, Any]) -> dict[str, Any] | None:
    """What the request says about a structured (schema constrained) answer, for both providers."""
    for tool in body.get("tools") or []:
        if isinstance(tool, dict) and "structured" in str(tool.get("name", "")).lower():
            schema = tool.get("input_schema")
            return {"via": "tool", "tool": tool.get("name"), "schema_features": features_of(schema), "schema_sha256": hashlib.sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest()}
    text = body.get("text")
    if isinstance(text, dict) and isinstance(text.get("format"), dict):
        fmt = text["format"]
        schema = fmt.get("schema")
        return {"via": "text.format", "type": fmt.get("type"), "name": fmt.get("name"), "strict": fmt.get("strict"), "schema_features": features_of(schema), "schema_sha256": hashlib.sha256(json.dumps(schema, sort_keys=True).encode()).hexdigest()}
    return None


def flatten_codex_tools(body: dict[str, Any]) -> list[str]:
    """Codex 0.163 lists its tools inside an input item of type additional_tools, grouped in namespaces."""
    names: list[str] = []
    for item in body.get("input") or []:
        if isinstance(item, dict) and isinstance(item.get("tools"), list):
            for group in item["tools"]:
                if isinstance(group, dict) and isinstance(group.get("tools"), list):
                    names.extend(f"{group.get('name')}.{tool.get('name')}" for tool in group["tools"] if isinstance(tool, dict))
                elif isinstance(group, dict):
                    names.append(str(group.get("name")))
    return names


def result_text(result: dict[str, Any]) -> str:
    content = result.get("content", result.get("output"))
    if isinstance(content, list):
        parts = [str(p.get("text", "")) for p in content if isinstance(p, dict)]
        return " ".join(parts)
    return str(content)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "FakeProvider/1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - signature fixed by the base class
        return

    # ----- plumbing -----
    def read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            return self.rfile.read(length)
        if (self.headers.get("Transfer-Encoding") or "").lower() == "chunked":
            data = b""
            while True:
                size_line = self.rfile.readline().strip()
                size = int(size_line.split(b";")[0] or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                data += self.rfile.read(size)
                self.rfile.readline()
            return data
        return b""

    def auth(self) -> tuple[str, bool]:
        """Which credential header the client used, and whether it holds the expected fake key."""
        key_header = self.headers.get("x-api-key")
        bearer = self.headers.get("Authorization")
        if key_header is not None:
            return "x-api-key", (not Config.expected_key) or key_header == Config.expected_key
        if bearer is not None:
            token = bearer.split(" ", 1)[1] if " " in bearer else bearer
            return "authorization", (not Config.expected_key) or token == Config.expected_key
        return "none", not Config.expected_key

    def record(self, body: bytes, extra: dict[str, Any]) -> None:
        with Config.lock:
            Config.seq += 1
            seq = Config.seq
        headers: dict[str, str] = {}
        for name, value in self.headers.items():
            lowered = name.lower()
            if lowered in {"x-api-key", "authorization", "cookie", "proxy-authorization"}:
                headers[lowered] = "<credential-removed>"
            else:
                headers[lowered] = cut(value)
        parsed: Any = None
        if body:
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = None
        scheme, matches = self.auth()
        entry: dict[str, Any] = {
            "seq": seq,
            "t_ms": int((time.monotonic() - Config.started) * 1000),
            "method": self.command,
            "path": self.path,
            "http_version": self.request_version,
            "client_credential": {"carried_in": scheme, "matches_expected_fake_key": matches},
            "headers": headers,
            "body_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
        if body:
            text_of_body = body.decode("utf-8", "replace")
            counts = {marker: text_of_body.count(marker) for marker in MARKERS if marker in text_of_body}
            if counts:
                entry["marker_counts"] = counts
        if isinstance(parsed, dict):
            entry["body_top_level_keys"] = sorted(parsed.keys())
            entry["body_summary"] = summarize({k: v for k, v in parsed.items() if k not in {"tools"}})
            if "tools" in parsed:
                entry["tools"] = tool_schema_summary(parsed.get("tools"))
            codex_tools = flatten_codex_tools(parsed)
            if codex_tools:
                entry["tools"] = codex_tools
            structured = structured_request(parsed)
            if structured:
                entry["structured_output_request"] = structured
        elif body:
            entry["body_text"] = cut(body.decode("utf-8", "replace"))
        entry.update(extra)
        if Config.dump_dir is not None and body:
            Config.dump_dir.mkdir(parents=True, exist_ok=True)
            (Config.dump_dir / f"{seq:04d}.json").write_bytes(body)
        with Config.lock, Config.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")

    def send_json(self, status: int, payload: dict[str, Any], extra_headers: dict[str, str] | None = None) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def start_sse(self, extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()

    def chunk(self, data: str) -> None:
        raw = data.encode()
        self.wfile.write(f"{len(raw):x}\r\n".encode() + raw + b"\r\n")
        self.wfile.flush()

    def end_chunks(self) -> None:
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def event(self, name: str, payload: dict[str, Any]) -> None:
        self.chunk(f"event: {name}\ndata: {json.dumps(payload)}\n\n")

    # ----- routing -----
    def do_GET(self) -> None:
        self.record(b"", {"handler": "get"})
        if self.path.startswith("/healthz"):
            self.send_json(200, {"status": "ok", "label": LABEL})
        elif self.path.startswith("/v1/models") and "client_version=" in self.path:
            self.send_json(200, {"models": []})  # the shape Codex asks for; an empty catalogue
        elif self.path.startswith("/v1/models"):
            self.send_json(
                200,
                {
                    "data": [{"type": "model", "id": "claude-sonnet-5-5", "display_name": "Fake", "created_at": "2026-01-01T00:00:00Z"}],
                    "object": "list",
                    "has_more": False,
                    "first_id": "claude-sonnet-5-5",
                    "last_id": "claude-sonnet-5-5",
                },
            )
        else:
            self.send_json(404, {"error": {"type": "not_found", "message": f"{LABEL}: no route for GET {self.path}"}})

    def do_POST(self) -> None:
        body = self.read_body()
        path = self.path.split("?", 1)[0]
        parsed: dict[str, Any] = {}
        try:
            loaded = json.loads(body) if body else {}
            parsed = loaded if isinstance(loaded, dict) else {}
        except ValueError:
            parsed = {}
        texts, results = last_user_texts(parsed)
        directive = find_directive(texts)
        meta: dict[str, Any] = {
            "handler": "post",
            "directive": list(directive) if directive else None,
            "tool_results_in_request": len(results),
        }
        _scheme, authorized = self.auth()
        loop = find_loop(conversation_user_texts(parsed))
        revoked = False
        if loop and authorized:
            done = count_tool_results(parsed)
            meta["loop"] = {"limit": loop[0], "tool_results_so_far": done}
            if done >= loop[0]:
                revoked = True  # act like a broker that has cut the job token
            else:
                directive = ("TOOL", f"{loop[1]} {loop[2]}")
                results = []
                meta["directive"] = list(directive)
        if revoked:
            meta["response"] = {"status": 401, "why": "fake broker: job token revoked after the loop limit"}
            self.record(body, meta)
            if path.startswith("/v1/messages"):
                self.send_json(401, {"type": "error", "error": {"type": "authentication_error", "message": "FAKE broker: job token revoked"}})
            else:
                self.send_json(401, {"error": {"message": "FAKE broker: job token revoked", "type": "invalid_request_error", "code": "invalid_api_key"}})
            return
        if not authorized:
            meta["response"] = {"status": 401, "why": "credential does not match the fake key"}
            self.record(body, meta)
            if path.startswith("/v1/messages"):
                self.send_json(401, {"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}})
            else:
                self.send_json(401, {"error": {"message": "Incorrect API key provided", "type": "invalid_request_error", "code": "invalid_api_key"}})
            return
        if directive and directive[0] == "HTTP":
            status = int(directive[1] or "500")
            meta["response"] = {"status": status}
            self.record(body, meta)
            headers = {"retry-after": "1", "x-should-retry": "true"} if status in {429, 500, 502, 503, 529} else {}
            if path.startswith("/v1/messages"):
                kind = {429: "rate_limit_error", 529: "overloaded_error", 500: "api_error"}.get(status, "api_error")
                self.send_json(status, {"type": "error", "error": {"type": kind, "message": f"{LABEL}: injected {status}"}}, headers)
            else:
                self.send_json(status, {"error": {"message": f"{LABEL}: injected {status}", "type": "server_error", "code": None}}, headers)
            return
        if path == "/v1/messages":
            self.anthropic_messages(parsed, body, meta, directive, results)
        elif path == "/v1/messages/count_tokens":
            meta["response"] = {"status": 200}
            self.record(body, meta)
            self.send_json(200, {"input_tokens": USAGE_INPUT})
        elif path.endswith("/responses"):
            self.openai_responses(parsed, body, meta, directive, results)
        else:
            meta["response"] = {"status": 404}
            self.record(body, meta)
            self.send_json(404, {"error": {"type": "not_found", "message": f"{LABEL}: no route for POST {path}"}})

    # ----- Anthropic Messages -----
    def anthropic_messages(
        self,
        body: dict[str, Any],
        raw: bytes,
        meta: dict[str, Any],
        directive: tuple[str, str] | None,
        results: list[dict[str, Any]],
    ) -> None:
        model = str(body.get("model") or "claude-sonnet-5-5")
        streaming = bool(body.get("stream"))
        tool_name: str | None = None
        tool_input: dict[str, Any] = {}
        text = CANNED_TEXT
        if results:
            first = results[0]
            text = f"FAKE-PROVIDER: tool_result received is_error={bool(first.get('is_error'))} content={result_text(first)[:300]!r}"
        elif directive and directive[0] == "TOOL":
            name, _, rest = directive[1].partition(" ")
            tool_name = name
            try:
                loaded = json.loads(rest) if rest.strip() else {}
                tool_input = loaded if isinstance(loaded, dict) else {}
            except ValueError:
                tool_input = {}
        elif directive and directive[0] in {"STRUCT", "STRUCT_BAD"}:
            names = [str(t.get("name")) for t in (body.get("tools") or []) if isinstance(t, dict)]
            structured = [n for n in names if "structured" in n.lower()]
            payload = Config.struct_reply if directive[0] == "STRUCT" else Config.struct_bad
            if structured:
                tool_name, tool_input = structured[0], payload
            else:
                text = json.dumps(payload)
        meta["response"] = {"status": 200, "stream": streaming, "tool_use": tool_name, "text": None if tool_name else cut(text)}
        self.record(raw, meta)
        message_id = f"msg_fake_{Config.seq:04d}"
        usage = {
            "input_tokens": USAGE_INPUT,
            "output_tokens": USAGE_OUTPUT,
            "cache_creation_input_tokens": USAGE_CACHE_CREATE,
            "cache_read_input_tokens": USAGE_CACHE_READ,
        }
        content: list[dict[str, Any]]
        if tool_name:
            content = [{"type": "tool_use", "id": f"toolu_fake_{Config.seq:04d}", "name": tool_name, "input": tool_input}]
        else:
            content = [{"type": "text", "text": text}]
        stop_reason = "tool_use" if tool_name else "end_turn"
        if not streaming:
            self.send_json(
                200,
                {"id": message_id, "type": "message", "role": "assistant", "model": model, "content": content, "stop_reason": stop_reason, "stop_sequence": None, "usage": usage},
                {"request-id": f"req_fake_{Config.seq:04d}"},
            )
            return
        self.start_sse({"request-id": f"req_fake_{Config.seq:04d}"})
        start_usage = dict(usage)
        start_usage["output_tokens"] = 1
        self.event(
            "message_start",
            {"type": "message_start", "message": {"id": message_id, "type": "message", "role": "assistant", "model": model, "content": [], "stop_reason": None, "stop_sequence": None, "usage": start_usage}},
        )
        if directive and directive[0] == "SLEEP":
            time.sleep(float(directive[1] or "30"))
        block = content[0]
        if block["type"] == "tool_use":
            self.event("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}})
            raw_json = json.dumps(block["input"])
            half = max(1, len(raw_json) // 2)
            for part in (raw_json[:half], raw_json[half:]):
                if part:
                    self.event("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": part}})
        else:
            self.event("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
            self.event("ping", {"type": "ping"})
            self.event("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": block["text"]}})
        self.event("content_block_stop", {"type": "content_block_stop", "index": 0})
        self.event("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop_reason, "stop_sequence": None}, "usage": {"output_tokens": USAGE_OUTPUT}})
        self.event("message_stop", {"type": "message_stop"})
        self.end_chunks()

    # ----- OpenAI Responses -----
    def openai_responses(
        self,
        body: dict[str, Any],
        raw: bytes,
        meta: dict[str, Any],
        directive: tuple[str, str] | None,
        results: list[dict[str, Any]],
    ) -> None:
        model = str(body.get("model") or "fake-model")
        tool_name: str | None = None
        tool_args = "{}"
        text = CANNED_TEXT
        if results:
            text = f"FAKE-PROVIDER: tool output received content={result_text(results[0])[:300]!r}"
        elif directive and directive[0] == "TOOL":
            name, _, rest = directive[1].partition(" ")
            tool_name = name
            tool_args = rest.strip() or "{}"
        elif directive and directive[0] in {"STRUCT", "STRUCT_BAD"}:
            text = json.dumps(Config.struct_reply if directive[0] == "STRUCT" else Config.struct_bad)
        meta["response"] = {"status": 200, "stream": bool(body.get("stream")), "tool_use": tool_name, "text": None if tool_name else cut(text)}
        self.record(raw, meta)
        rid = f"resp_fake_{Config.seq:04d}"
        usage = {
            "input_tokens": USAGE_INPUT,
            "input_tokens_details": {"cached_tokens": USAGE_CACHE_READ},
            "output_tokens": USAGE_OUTPUT,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": USAGE_INPUT + USAGE_OUTPUT,
        }
        if tool_name and tool_name in CUSTOM_TOOLS:
            # Codex 0.163 offers its shell through a "custom" (freeform) tool named exec that takes JavaScript.
            item: dict[str, Any] = {"id": f"ctc_fake_{Config.seq:04d}", "type": "custom_tool_call", "status": "completed", "call_id": f"call_fake_{Config.seq:04d}", "name": tool_name, "input": tool_args if tool_args != "{}" else ""}
        elif tool_name:
            item = {"id": f"fc_fake_{Config.seq:04d}", "type": "function_call", "status": "completed", "call_id": f"call_fake_{Config.seq:04d}", "name": tool_name, "arguments": tool_args}
        else:
            item = {"id": f"msg_fake_{Config.seq:04d}", "type": "message", "status": "completed", "role": "assistant", "content": [{"type": "output_text", "text": text, "annotations": []}]}
        base = {"id": rid, "object": "response", "created_at": int(time.time()), "model": model, "status": "in_progress", "output": []}
        if not body.get("stream"):
            done = dict(base)
            done.update({"status": "completed", "output": [item], "usage": usage})
            self.send_json(200, done)
            return
        self.start_sse({"x-request-id": f"req_fake_{Config.seq:04d}"})
        n = 0

        def emit(name: str, payload: dict[str, Any]) -> None:
            nonlocal n
            payload = dict(payload)
            payload["type"] = name
            payload["sequence_number"] = n
            n += 1
            self.event(name, payload)

        emit("response.created", {"response": base})
        emit("response.in_progress", {"response": base})
        if directive and directive[0] == "SLEEP":
            time.sleep(float(directive[1] or "30"))
        if item["type"] == "custom_tool_call":
            started = dict(item)
            started.update({"status": "in_progress", "input": ""})
            emit("response.output_item.added", {"output_index": 0, "item": started})
            emit("response.custom_tool_call_input.delta", {"output_index": 0, "item_id": item["id"], "delta": item["input"]})
            emit("response.custom_tool_call_input.done", {"output_index": 0, "item_id": item["id"], "input": item["input"]})
            emit("response.output_item.done", {"output_index": 0, "item": item})
        elif item["type"] == "function_call":
            started = dict(item)
            started.update({"status": "in_progress", "arguments": ""})
            emit("response.output_item.added", {"output_index": 0, "item": started})
            emit("response.function_call_arguments.delta", {"output_index": 0, "item_id": item["id"], "delta": tool_args})
            emit("response.function_call_arguments.done", {"output_index": 0, "item_id": item["id"], "arguments": tool_args})
            emit("response.output_item.done", {"output_index": 0, "item": item})
        else:
            started = {"id": item["id"], "type": "message", "status": "in_progress", "role": "assistant", "content": []}
            emit("response.output_item.added", {"output_index": 0, "item": started})
            emit("response.content_part.added", {"item_id": item["id"], "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}})
            emit("response.output_text.delta", {"item_id": item["id"], "output_index": 0, "content_index": 0, "delta": text})
            emit("response.output_text.done", {"item_id": item["id"], "output_index": 0, "content_index": 0, "text": text})
            emit("response.content_part.done", {"item_id": item["id"], "output_index": 0, "content_index": 0, "part": item["content"][0]})
            emit("response.output_item.done", {"output_index": 0, "item": item})
        final = dict(base)
        final.update({"status": "completed", "output": [item], "usage": usage})
        emit("response.completed", {"response": final})
        self.end_chunks()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="0.0.0.0")  # noqa: S104 - inside the isolated spike network only
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--log", default="/out/requests.jsonl")
    parser.add_argument("--key-file", default="", help="file that holds the run-time generated fake key")
    parser.add_argument("--struct-reply", default="", help="JSON file used for FAKE:STRUCT")
    parser.add_argument("--dump-dir", default="", help="scratch directory for full request bodies (never commit it)")
    args = parser.parse_args(argv)
    if args.dump_dir:
        Config.dump_dir = Path(args.dump_dir)
    Config.log_path = Path(args.log)
    Config.log_path.parent.mkdir(parents=True, exist_ok=True)
    if args.key_file:
        Config.expected_key = Path(args.key_file).read_text(encoding="utf-8").strip()
    if args.struct_reply:
        Config.struct_reply = json.loads(Path(args.struct_reply).read_text(encoding="utf-8"))
    Config.started = time.monotonic()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.daemon_threads = True
    print(f"{LABEL} listening on {args.host}:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
