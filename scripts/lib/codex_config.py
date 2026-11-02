#!/usr/bin/env python3
"""Put GitHub's MCP server entry into a project's `.codex/config.toml` without breaking the rest of the file (ADR 0019).

Codex reads `.codex/config.toml` from a project only when the person trusts the project, and it accepts
`[mcp_servers.NAME]` there (checked on Codex 0.166.0). This script adds or corrects the one table
`[mcp_servers.github]`. The table names the environment variable that holds the token and never holds a token.

There is no TOML writer in the Python standard library, so this script edits text, and it is careful:
  * It touches only the table `[mcp_servers.github]`. Other tables, comments and blank lines stay as they are.
  * It refuses to edit a form it does not understand: a quoted name, a sub-table, a dotted key or an inline entry
    under `[mcp_servers]`. It reports "unsafe", and a person edits the file.
  * It reports "credential" for a table that holds a token, a static Authorization header or a value shaped like
    a GitHub token, and it never prints the value.
  * It reports "unsafe" for a table that runs a command or reads other variables (`command`, `args`, `env`,
    `http_headers_helper`, `env_http_headers`). A project file that runs a command is code, and it must be read.
  * When `tomllib` exists (Python 3.11 and later) the result is parsed again and compared before anything is written.
    A result that does not parse, or that does not say what it should, is never written.

Usage:
  codex_config.py inspect PATH VARIABLE            prints absent, same, different, credential or unsafe
  codex_config.py write   PATH VARIABLE [--replace]  adds the table, or with --replace corrects a plain one

Exit codes: 0 done, 1 refused (unsafe, or the result would be wrong), 2 wrong arguments.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile

URL = "https://api.githubcopilot.com/mcp/"
HEADERS = {"X-MCP-Lockdown": "true", "X-MCP-Toolsets": "repos,issues,pull_requests,labels"}
EXPECTED_KEYS = {"url", "bearer_token_env_var", "http_headers"}
EXECUTING_KEYS = {"command", "args", "env", "env_vars", "cwd", "http_headers_helper", "env_http_headers"}
TOKEN_SHAPE = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}")
HEADER_LINE = re.compile(r"^\s*(\[\[?)\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$")
KEY_LINE = re.compile(r"^\s*([A-Za-z0-9_.\"'-]+)\s*=\s*(.*?)\s*$")
PAIR = re.compile(r'"([^"]+)"\s*=\s*"([^"]*)"')
VARIABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def expected_block(variable):
    pairs = ", ".join('"%s" = "%s"' % item for item in sorted(HEADERS.items()))
    return ('[mcp_servers.github]\nurl = "%s"\nbearer_token_env_var = "%s"\nhttp_headers = { %s }\n' % (URL, variable, pairs))


def _tables(lines):
    """Yield (name, start, end) for each table header: end is the line of the next header, or the end of the file."""
    headers = [(i, HEADER_LINE.match(line)) for i, line in enumerate(lines)]
    headers = [(i, m.group(2).replace(" ", "")) for i, m in headers if m]
    for position, (start, name) in enumerate(headers):
        end = headers[position + 1][0] if position + 1 < len(headers) else len(lines)
        yield name, start, end


def _locate(text):
    """Return (state, start, end). `state` is None when the table is plain, or "unsafe" when it cannot be edited."""
    lines = text.split("\n")
    plain = []
    unsafe = False
    current = None
    for name, start, end in _tables(lines):
        if name == "mcp_servers.github":
            plain.append((start, end))
        elif name.startswith(("mcp_servers.github.", 'mcp_servers."github"', "mcp_servers.'github'")):
            unsafe = True
        if name == "mcp_servers":
            for line in lines[start + 1:end]:
                if re.match(r"""^\s*["']?github["']?\s*(=|\.)""", line):
                    unsafe = True
    for line in lines:
        header = HEADER_LINE.match(line)
        if header:
            current = header.group(2)
            continue
        if re.match(r"""^\s*mcp_servers\s*\.\s*["']?github\b""", line) or (
                current is None and re.match(r"""^\s*mcp_servers\s*=""", line)):
            unsafe = True
    if unsafe or len(plain) > 1:
        return "unsafe", None, None
    if not plain:
        return None, None, None
    return None, plain[0][0], plain[0][1]


def inspect_text(text, variable):
    """absent, same, different, credential or unsafe."""
    state, start, end = _locate(text)
    if state == "unsafe":
        return "unsafe"
    if start is None:
        return "absent"
    lines = text.split("\n")[start + 1:end]
    found = {}
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = KEY_LINE.match(line)
        if not match:
            return "different"
        found[match.group(1).strip("\"'")] = re.sub(r"\s+#.*$", "", match.group(2))
    everything = "\n".join(lines)
    credential = (TOKEN_SHAPE.search(everything) is not None
                  or any("token" in key.lower() and key != "bearer_token_env_var" for key in found)
                  or any(name.lower() == "authorization" for name, _ in PAIR.findall(found.get("http_headers", ""))))
    if credential:
        return "credential"
    if set(found) & EXECUTING_KEYS:
        return "unsafe"
    if set(found) != EXPECTED_KEYS:
        return "different"
    if found["url"] != '"%s"' % URL or found["bearer_token_env_var"] != '"%s"' % variable:
        return "different"
    if dict(PAIR.findall(found["http_headers"])) != HEADERS or found["http_headers"].count("=") != len(HEADERS):
        return "different"
    return "same"


def _check_with_tomllib(new_text, variable):
    try:
        import tomllib  # noqa: PLC0415  (Python 3.11 and later; the check is skipped where it does not exist)
    except ImportError:
        return
    try:
        table = tomllib.loads(new_text)["mcp_servers"]["github"]
    except (tomllib.TOMLDecodeError, KeyError) as error:
        raise ValueError("the result would not be valid TOML or would not hold the entry (%s)" % type(error).__name__)
    if table != {"url": URL, "bearer_token_env_var": variable, "http_headers": HEADERS}:
        raise ValueError("the entry would not say what it should")


def write_text(text, variable, replace=False):
    """The new text of the file. Raises ValueError when it cannot be done safely."""
    if not VARIABLE.match(variable):
        raise ValueError("the variable name must look like FACTORY_GITHUB_MCP_TOKEN")
    state = inspect_text(text, variable)
    if state == "same":
        return text
    block = expected_block(variable)
    if state == "absent":
        body = text if text.endswith("\n") or not text else text + "\n"
        new_text = body + ("\n" if body.strip() else "") + block
    elif state in ("different", "credential") and replace:
        _, start, end = _locate(text)
        if start is None or end is None:
            raise ValueError("the github table could not be found")
        lines = text.split("\n")
        tail = lines[end:]
        keep_blank = bool(tail) and (end - 1 > start and not lines[end - 1].strip())
        new_text = "\n".join(lines[:start] + block.rstrip("\n").split("\n") + ([""] if keep_blank else []) + tail)
    else:
        raise ValueError("the file has a github entry that is %s, and it was not replaced" % state)
    _check_with_tomllib(new_text, variable)
    return new_text


def _read(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError:
        return ""


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 3 or args[0] not in ("inspect", "write") or (args[0] == "inspect" and len(args) != 3):
        print(__doc__, file=sys.stderr)
        return 2
    command, path, variable = args[0], args[1], args[2]
    replace = "--replace" in args[3:]
    if set(args[3:]) - {"--replace"} or not VARIABLE.match(variable):
        return 2
    text = _read(path)
    if command == "inspect":
        print(inspect_text(text, variable))
        return 0
    try:
        new_text = write_text(text, variable, replace)
    except ValueError as error:
        print("FAIL %s" % error, file=sys.stderr)
        return 1
    if new_text != text:
        folder = os.path.dirname(os.path.abspath(path))
        os.makedirs(folder, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(dir=folder, prefix=".config.toml.")
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(new_text)
        os.replace(temporary, path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
