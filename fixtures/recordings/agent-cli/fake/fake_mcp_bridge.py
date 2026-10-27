#!/usr/bin/env python3
"""A labelled FAKE stand-in for the factory tool bridge (Model B in sandbox-policy.md section 2.2).

Fidelity: fake. It is a minimal Model Context Protocol server that speaks the streamable HTTP transport (one
JSON-RPC message per POST, answered with plain JSON). It offers one tool, factory_exec, and does nothing with a
call except log it to the file given by --log and return a fixed text. It never runs a command. The spike uses
it to prove that a command line tool can be left with ONLY factory-provided tools: the model's request lists
factory_exec and none of the tool's own shell or edit tools.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

TOOL = {
    "name": "factory_exec",
    "description": "FAKE factory tool: pretend to run one typed command in the sandbox.",
    "inputSchema": {
        "type": "object",
        "properties": {"argv": {"type": "array", "items": {"type": "string"}}},
        "required": ["argv"],
        "additionalProperties": False,
    },
}
LOG_PATH = Path("/out/bridge.jsonl")


def handle_message(message: dict[str, Any]) -> dict[str, Any] | None:
    """Return the JSON-RPC response for one request, or None for a notification."""
    method = message.get("method")
    message_id = message.get("id")
    if message_id is None:
        return None
    if method == "initialize":
        version = (message.get("params") or {}).get("protocolVersion", "2025-06-18")
        result: dict[str, Any] = {"protocolVersion": version, "capabilities": {"tools": {}}, "serverInfo": {"name": "fake-factory-bridge", "version": "0"}}
    elif method == "tools/list":
        result = {"tools": [TOOL]}
    elif method == "tools/call":
        params = message.get("params") or {}
        result = {"content": [{"type": "text", "text": f"FAKE-BRIDGE: received {json.dumps(params.get('arguments'))}; nothing was run"}], "isError": False}
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": message_id, "error": {"code": -32601, "message": "method not found"}}
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - signature fixed by the base class
        del format, args  # silent: the request log is written by record()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            message = json.loads(raw)
        except ValueError:
            message = {}
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"path": self.path, "method": message.get("method"), "params": message.get("params")}, sort_keys=True) + "\n")
        response = handle_message(message) if isinstance(message, dict) else None
        if response is None:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        data = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()


def main(argv: list[str]) -> int:
    global LOG_PATH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", default="/out/bridge.jsonl")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args(argv)
    LOG_PATH = Path(args.log)
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)  # noqa: S104 - isolated spike network
    server.daemon_threads = True
    print(f"fake factory bridge (fidelity: fake) on port {args.port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
