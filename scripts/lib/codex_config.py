#!/usr/bin/env python3
"""Put GitHub's MCP server entry into a project's `.codex/config.toml` without breaking the rest of the file (ADR 0019).

Codex reads `.codex/config.toml` from a project only when the person trusts the project, and it accepts
`[mcp_servers.NAME]` there (checked on Codex 0.166.0). This script adds or corrects the one table
`[mcp_servers.github]`. The table names the environment variable that holds the token and never holds a token.

There is no TOML writer in the Python standard library, so this script edits text, and it is careful:
  * It touches only the table `[mcp_servers.github]`. Every other line stays as it is, comments included, and so does
    the mode of the file. A line that starts with `[` always ends the table, whether or not it is understood.
  * It refuses to edit a form it does not understand: a quoted or escaped name that could be `github`, a sub-table, a
    dotted key or an inline entry under `[mcp_servers]`. It reports "unsafe", and a person edits the file.
  * It reports "unsafe" for a table that runs a command or reads other variables (`command`, `args`, `env`,
    `http_headers_helper`, `env_http_headers`), even when the same table also holds a token: that file is code, and a
    person must read it.
  * It reports "redirected" for a table that names the token variable but points to an address that is not GitHub's,
    because Codex would send the token there.
  * It reports "credential" for a table that holds a token, a static Authorization header or a value shaped like a
    GitHub token, and it never prints the value.
  * Every line is read in linear time, and a line longer than 4096 characters makes the file "unsafe" before any
    pattern is tried. A hostile file cannot hold the installer for minutes.
  * The result is checked before anything is written: by structure on every Python (exactly one plain
    `[mcp_servers.github]` header, and the table says what it should), and also by parsing it again with `tomllib`
    where that exists (Python 3.11 and later).
  * It will not write through a symbolic link, and it never leaves a half-written file or a temporary file behind.

Usage:
  codex_config.py inspect PATH VARIABLE            prints absent, same, different, redirected, credential or unsafe
  codex_config.py write   PATH VARIABLE [--replace]  adds the table, or with --replace corrects a plain one

Exit codes: 0 done, 1 refused (unsafe, a link, or the result would be wrong), 2 wrong arguments.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile

URL = "https://api.githubcopilot.com/mcp/"
HEADERS = {"X-MCP-Lockdown": "true", "X-MCP-Toolsets": "repos,issues,pull_requests,labels"}
EXPECTED_KEYS = {"url", "bearer_token_env_var", "http_headers"}
EXECUTING_KEYS = {"command", "args", "env", "env_vars", "cwd", "http_headers_helper", "env_http_headers"}
TOKEN_SHAPE = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}")
PAIR = re.compile(r'"([^"\n]{1,200})"\s*=\s*"([^"\n]{0,200})"')
KEY = re.compile(r"[A-Za-z0-9_.\"'-]{1,64}")
VARIABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
MAX_LINE = 4096


def expected_block(variable):
    pairs = ", ".join('"%s" = "%s"' % item for item in sorted(HEADERS.items()))
    return ('[mcp_servers.github]\nurl = "%s"\nbearer_token_env_var = "%s"\nhttp_headers = { %s }\n' % (URL, variable, pairs))


def _header_name(line):
    """The name of a table header such as `[a.b]`, spaces removed, or None. One pass, no pattern, quotes respected."""
    text = line.strip()
    if not text.startswith("["):
        return None
    depth = 2 if text.startswith("[[") else 1
    quote, index = None, depth
    while index < len(text):
        char = text[index]
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "]":
            rest = text[index + depth:].strip()
            if rest and not rest.startswith("#"):
                return None
            return text[depth:index].replace(" ", "")
        index += 1
    return None


def _strip_comment(value):
    """The value without a trailing `# comment`. One pass, quotes respected."""
    quote = None
    for index, char in enumerate(value):
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
        elif char == "#":
            return value[:index].rstrip()
    return value.rstrip()


def _aliases_github(name):
    """True for a table name under mcp_servers that is, or could be, `github` or one of its sub-tables."""
    if name == "mcp_servers.github" or name.startswith("mcp_servers.github."):
        return True
    if not name.startswith("mcp_servers."):
        return False
    rest = name[len("mcp_servers."):]
    if rest[:1] in ("\"", "'"):
        if "\\" in rest:
            return True  # an escape can spell github in a way no pattern here would see
        return rest.strip("\"'").split("\"")[0].split("'")[0] == "github" or rest.startswith(("\"github\"", "'github'"))
    return False


def _locate(text):
    """Return (state, start, end). `state` is "unsafe" when the table cannot be edited; start and end bound a plain table."""
    lines = text.split("\n")
    if any(len(line) > MAX_LINE for line in lines):
        return "unsafe", None, None
    boundaries = [i for i, line in enumerate(lines) if line.lstrip().startswith("[")]
    plain, unsafe, current = [], False, None
    for position, start in enumerate(boundaries):
        end = boundaries[position + 1] if position + 1 < len(boundaries) else len(lines)
        name = _header_name(lines[start])
        if name == "mcp_servers.github" and not lines[start].lstrip().startswith("[["):
            plain.append((start, end))
        elif name is not None and _aliases_github(name):
            unsafe = True
        if name == "mcp_servers":
            for line in lines[start + 1:end]:
                if re.match(r"""^\s*["']?github["']?\s*(=|\.)""", line):
                    unsafe = True
    for line in lines:
        if line.lstrip().startswith("["):
            current = _header_name(line)
            continue
        stripped = line.lstrip()
        if stripped.startswith("mcp_servers") and re.match(r"""mcp_servers\s*\.\s*["']?github\b""", stripped):
            unsafe = True
        if current is None and re.match(r"mcp_servers\s*=", stripped):
            unsafe = True
    if unsafe or len(plain) > 1:
        return "unsafe", None, None
    if not plain:
        return None, None, None
    start, end = plain[0]
    # Comments and blank lines just before the next table belong to that table, not to this one.
    while end - 1 > start and (not lines[end - 1].strip() or lines[end - 1].lstrip().startswith("#")):
        end -= 1
    return None, start, end


def inspect_text(text, variable):
    """absent, same, different, redirected, credential or unsafe.

    "redirected": the table names the token variable, so Codex would send the token, but to an address that is not GitHub's.
    """
    state, start, end = _locate(text)
    if state == "unsafe":
        return "unsafe"
    if start is None or end is None:
        return "absent"
    lines = text.split("\n")[start + 1:end]
    found = {}
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        if not separator or not KEY.fullmatch(key):
            return "different"
        found[key.strip("\"'")] = _strip_comment(value.strip())
    if set(found) & EXECUTING_KEYS:
        return "unsafe"
    everything = "\n".join(lines)
    credential = (TOKEN_SHAPE.search(everything) is not None
                  or any("token" in key.lower() and key != "bearer_token_env_var" for key in found)
                  or any(name.lower() == "authorization" for name, _ in PAIR.findall(found.get("http_headers", ""))))
    if credential:
        return "credential"
    if found.get("bearer_token_env_var") == '"%s"' % variable and found.get("url") != '"%s"' % URL:
        return "redirected"
    if set(found) != EXPECTED_KEYS:
        return "different"
    if found["url"] != '"%s"' % URL or found["bearer_token_env_var"] != '"%s"' % variable:
        return "different"
    if dict(PAIR.findall(found["http_headers"])) != HEADERS or found["http_headers"].count("=") != len(HEADERS):
        return "different"
    return "same"


def _check_result(new_text, variable):
    """The result must hold exactly one plain github table that says what it should. Raises ValueError otherwise."""
    headers = [line for line in new_text.split("\n") if _header_name(line) == "mcp_servers.github"]
    if len(headers) != 1 or inspect_text(new_text, variable) != "same":
        raise ValueError("the result would not hold exactly one github entry that says what it should")
    try:
        import tomllib  # noqa: PLC0415  (Python 3.11 and later; the structural check above stands in where it does not exist)
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
    elif state in ("different", "redirected", "credential") and replace:
        _, start, end = _locate(text)
        if start is None or end is None:
            raise ValueError("the github table could not be found")
        lines = text.split("\n")
        new_text = "\n".join(lines[:start] + block.rstrip("\n").split("\n") + lines[end:])
    else:
        raise ValueError("the file has a github entry that is %s, and it was not replaced" % state)
    _check_result(new_text, variable)
    return new_text


def _read(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError:
        return ""


def _through_a_link(path):
    folder = os.path.dirname(os.path.abspath(path))
    return os.path.islink(path) or os.path.islink(folder)


def _write_atomically(path, text):
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(dir=folder, prefix=".config.toml.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        if os.path.exists(path):
            shutil.copymode(path, temporary)
        else:
            os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 3 or args[0] not in ("inspect", "write") or (args[0] == "inspect" and len(args) != 3):
        print(__doc__, file=sys.stderr)
        return 2
    command, path, variable = args[0], args[1], args[2]
    replace = "--replace" in args[3:]
    if set(args[3:]) - {"--replace"} or not VARIABLE.match(variable):
        return 2
    if command == "write" and _through_a_link(path):
        print("FAIL refusing to write through a symbolic link: %s" % path, file=sys.stderr)
        return 1
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
        _write_atomically(path, new_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
