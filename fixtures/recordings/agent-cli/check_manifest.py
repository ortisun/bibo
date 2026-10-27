#!/usr/bin/env python3
"""Check the manifest of the agent runtime spike recordings (work package s0-agent-runtime-spike).

Usage: python3 -I fixtures/recordings/agent-cli/check_manifest.py

What it checks, with the standard library only:

  1. manifest.json exists, is JSON and has the required top-level keys.
  2. Both tools are present with the pinned versions, and every recording names its tool and version.
  3. Every recording has the required keys: id, tool, tool_version, questions, title, argv, exit_code,
     duration_ms, network, fidelity and files. Exit code and duration are integers.
  4. No recording claims real fidelity. Every recording here came from a labelled fake provider or
     from no provider at all, so the only allowed values are "fake_provider" and "offline".
  5. Every file listed exists under this directory and has the recorded SHA-256.
  6. No recorded file holds a token-shaped string or the marker prefix of the run-time fake key.

Exit codes: 0 all checks passed, 1 a check failed, 3 the manifest is missing (nothing to check).
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "manifest.json"
PINNED = {"claude": "2.1.311", "codex": "0.163.0"}
ALLOWED_FIDELITY = {"fake_provider", "offline"}
TOP_LEVEL_KEYS = ["manifest_format", "work_package", "recorded_on", "engine", "tools", "recordings"]
RECORDING_KEYS = ["id", "tool", "tool_version", "questions", "title", "argv", "exit_code", "duration_ms", "network", "fidelity", "files"]
SECRET_SHAPES = [
    ("fake key marker", re.compile(r"sfjt_FAKE")),
    ("Anthropic key shape", re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}")),
    ("OpenAI key shape", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("bearer token shape", re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("GitHub token shape", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("AWS access key shape", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
]


def load() -> dict[str, Any] | None:
    if not MANIFEST.exists():
        print(f"BLOCKED: {MANIFEST} does not exist, so there is nothing to check.")
        return None
    loaded = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("manifest.json must hold a JSON object")
    return loaded


def check(manifest: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for key in TOP_LEVEL_KEYS:
        if key not in manifest:
            problems.append(f"manifest is missing the top-level key '{key}'")
    tools = manifest.get("tools", {})
    for tool, version in PINNED.items():
        recorded = tools.get(tool, {}).get("version") if isinstance(tools, dict) else None
        if recorded != version:
            problems.append(f"tools.{tool}.version is {recorded!r}, expected {version!r}")
    recordings = manifest.get("recordings", [])
    if not isinstance(recordings, list) or not recordings:
        problems.append("recordings must be a non-empty list")
        return problems
    seen_ids: set[str] = set()
    tools_seen: set[str] = set()
    for rec in recordings:
        if not isinstance(rec, dict):
            problems.append("a recording is not an object")
            continue
        rid = str(rec.get("id", "?"))
        for key in RECORDING_KEYS:
            if key not in rec:
                problems.append(f"recording {rid} is missing '{key}'")
        if rid in seen_ids:
            problems.append(f"recording id {rid} is used twice")
        seen_ids.add(rid)
        tool = rec.get("tool")
        if tool not in PINNED:
            problems.append(f"recording {rid} names an unknown tool {tool!r}")
        else:
            tools_seen.add(str(tool))
            if rec.get("tool_version") != PINNED[str(tool)]:
                problems.append(f"recording {rid} has tool_version {rec.get('tool_version')!r}, expected {PINNED[str(tool)]!r}")
        if not isinstance(rec.get("exit_code"), int) or isinstance(rec.get("exit_code"), bool):
            problems.append(f"recording {rid} has a non-integer exit_code")
        if not isinstance(rec.get("duration_ms"), int) or isinstance(rec.get("duration_ms"), bool):
            problems.append(f"recording {rid} has a non-integer duration_ms")
        if rec.get("fidelity") not in ALLOWED_FIDELITY:
            problems.append(f"recording {rid} has fidelity {rec.get('fidelity')!r}; allowed: {sorted(ALLOWED_FIDELITY)}")
        argv = rec.get("argv")
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv) or not argv:
            problems.append(f"recording {rid} needs argv as a non-empty list of strings")
        files = rec.get("files", {})
        if not isinstance(files, dict):
            problems.append(f"recording {rid} files must be an object")
            continue
        for rel, digest in files.items():
            path = ROOT / rel
            if not path.is_file():
                problems.append(f"recording {rid} lists {rel}, which does not exist")
                continue
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                problems.append(f"recording {rid}: SHA-256 of {rel} differs from the manifest")
            text = data.decode("utf-8", "replace")
            for label, pattern in SECRET_SHAPES:
                if pattern.search(text):
                    problems.append(f"recording {rid}: {rel} holds a {label}")
    for tool in PINNED:
        if tool not in tools_seen:
            problems.append(f"no recording exists for {tool}")
    return problems


def main() -> int:
    manifest = load()
    if manifest is None:
        return 3
    problems = check(manifest)
    if problems:
        print(f"FAILED: {len(problems)} problem(s) in {MANIFEST.name}")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    count = len(manifest["recordings"])
    print(f"PASSED: {count} recordings, both tools present at the pinned versions, hashes match, no secret-shaped text.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
