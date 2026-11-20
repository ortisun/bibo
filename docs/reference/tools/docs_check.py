#!/usr/bin/env python3
"""The checks behind scripts/docs-check.sh.

The factory applies a documentation gate to the documents it writes for others: links, runnable
examples, command names, readability. This file applies the same kind of gate to the documents of
this repository that the documentation work package owns. Run it through scripts/docs-check.sh.

Every check ends in one of four outcomes, with the meaning scripts/ci.sh gives them:

    PASSED          the check ran and found nothing
    FAILED          the check ran and found a problem
    BLOCKED         the check could not run, so there is no evidence either way
    NOT_APPLICABLE  nothing to check, and the reason is printed

A check that cannot run is never a pass. Exit codes: 0 all passed, 1 something failed, 2 wrong
use, 3 nothing failed but something is BLOCKED.

Document conventions this file relies on are described in docs/reference/documentation-checks.md.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

PASSED = "PASSED"
FAILED = "FAILED"
BLOCKED = "BLOCKED"
NOT_APPLICABLE = "NOT_APPLICABLE"

ROOT = Path(os.environ.get("DOCS_CHECK_ROOT") or Path(__file__).resolve().parents[3])

SHELL_LANGUAGES = {"bash", "sh", "shell", "console", "zsh"}
RECORDINGS = "fixtures/recordings/e2e"


@dataclass
class Outcome:
    """The result of one check: a status and the lines that explain it."""

    check: str
    status: str
    lines: list[str] = field(default_factory=list)


def done(check: str, problems: list[str], ok: str) -> Outcome:
    """PASSED with the sentence `ok`, or FAILED with the problems."""
    if problems:
        return Outcome(check, FAILED, problems)
    return Outcome(check, PASSED, [ok])


def blocked(check: str, reason: str) -> Outcome:
    return Outcome(check, BLOCKED, [reason])


# ---------------------------------------------------------------------------------------------
# Which documents this package owns
# ---------------------------------------------------------------------------------------------


def owned_documents(root: Path) -> list[Path]:
    """README.md and every Markdown file under the four owned directories."""
    found: list[Path] = []
    if (root / "README.md").is_file():
        found.append(root / "README.md")
    for directory in ("docs/guides", "docs/runbooks", "docs/reference", "docs/walkthroughs"):
        base = root / directory
        if base.is_dir():
            found.extend(sorted(base.rglob("*.md")))
    return found


def relative(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------------------------
# Reading Markdown: fenced blocks and inline code
# ---------------------------------------------------------------------------------------------


@dataclass
class Fence:
    """One fenced block. `flags` and `attrs` come from the words after the language."""

    path: Path
    line: int
    lang: str
    flags: set[str]
    attrs: dict[str, list[str]]
    body: str


def parse_info(info: str) -> tuple[str, set[str], dict[str, list[str]]]:
    try:
        words = shlex.split(info)
    except ValueError:
        words = info.split()
    lang = words[0] if words else ""
    flags: set[str] = set()
    attrs: dict[str, list[str]] = {}
    for word in words[1:]:
        if "=" in word:
            key, value = word.split("=", 1)
            attrs.setdefault(key, []).append(value)
        else:
            flags.add(word)
    return lang, flags, attrs


def fences(path: Path, text: str) -> list[Fence]:
    found: list[Fence] = []
    marker = ""
    start = 0
    info = ""
    body: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not marker:
            opened = re.match(r"^(`{3,}|~{3,})(.*)$", stripped)
            if opened:
                marker, info, start, body = opened.group(1), opened.group(2).strip(), number, []
            continue
        if stripped.startswith(marker) and set(stripped) <= {marker[0]}:
            lang, flags, attrs = parse_info(info)
            found.append(Fence(path, start, lang, flags, attrs, "\n".join(body) + "\n"))
            marker = ""
        else:
            body.append(raw)
    return found


def prose_lines(text: str) -> list[tuple[int, str]]:
    """The lines outside fenced blocks and HTML comments, with their line numbers."""
    kept: list[tuple[int, str]] = []
    marker = ""
    in_comment = False
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if marker:
            if stripped.startswith(marker) and set(stripped) <= {marker[0]}:
                marker = ""
            continue
        opened = re.match(r"^(`{3,}|~{3,})", stripped)
        if opened:
            marker = opened.group(1)
            continue
        if in_comment:
            in_comment = "-->" not in raw
            continue
        if "<!--" in raw and "-->" not in raw:
            in_comment = True
            continue
        kept.append((number, raw))
    return kept


def inline_code(text: str) -> list[tuple[int, str]]:
    spans: list[tuple[int, str]] = []
    for number, raw in prose_lines(text):
        for match in re.finditer(r"(?<!`)`([^`\n]+)`(?!`)", raw):
            spans.append((number, match.group(1)))
    return spans


# ---------------------------------------------------------------------------------------------
# Running programs
# ---------------------------------------------------------------------------------------------


@dataclass
class Ran:
    code: int
    output: str
    seconds: float


def run(
    command: list[str],
    cwd: Path,
    env: dict[str, str] | None = None,
    timeout: float = 600,
) -> Ran | None:
    """Runs a program. None when it does not exist or does not finish in time."""
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    return Ran(result.returncode, result.stdout + result.stderr, time.monotonic() - started)


def target_dir(root: Path) -> Path:
    return Path(os.environ.get("CARGO_TARGET_DIR") or root / "target")


def tool_env(root: Path) -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = str(target_dir(root) / "debug") + os.pathsep + env.get("PATH", "")
    return env


def docker_answers() -> bool:
    ran = run(["docker", "info"], ROOT, timeout=20)
    return ran is not None and ran.code == 0


def docker_cli_works() -> bool:
    ran = run(["docker", "compose", "version"], ROOT, timeout=30)
    return ran is not None and ran.code == 0


def postgres_available() -> bool:
    if os.environ.get("FACTORY_DB_ADMIN_URL"):
        return True
    names = ("initdb", "pg_ctl", "postgres")
    places = [os.environ.get("FACTORY_PG_BIN", ""), *os.environ.get("PATH", "").split(os.pathsep)]
    places += ["/opt/homebrew/opt/postgresql@18/bin", "/usr/lib/postgresql/18/bin"]
    return any(all((Path(p) / n).exists() for n in names) for p in places if p)


_BUILT: dict[str, str | None] = {}


def build_cli(root: Path) -> str | None:
    """Builds the operator CLI. None when it is built, otherwise the reason it is not."""
    key = str(root)
    if key in _BUILT:
        return _BUILT[key]
    if shutil.which("cargo") is None:
        reason: str | None = "cargo is not installed, so factory-cli cannot be built to read its help"
    else:
        ran = run(["cargo", "build", "--locked", "--quiet", "-p", "factory-cli"], root, timeout=1500)
        if ran is None or ran.code != 0:
            tail = "" if ran is None else (ran.output.strip().splitlines() or [""])[-1]
            reason = f"factory-cli did not build: {tail}"
        elif not (target_dir(root) / "debug" / "factory-cli").is_file():
            reason = "factory-cli built but is not in the target directory"
        else:
            reason = None
    _BUILT[key] = reason
    return reason


# ---------------------------------------------------------------------------------------------
# Help texts: the facts that command names are checked against
# ---------------------------------------------------------------------------------------------

FLAG = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*")


@dataclass
class Helps:
    cli_verbs: dict[str, set[str]]
    cli_text: str
    xtask_commands: set[str]
    xtask_flags: set[str]
    binaries: set[str]
    sidecar_flags: set[str]
    script_flags: dict[str, set[str]]
    cargo_subcommands: set[str]


def parse_cli_help(text: str) -> dict[str, set[str]]:
    verbs: dict[str, set[str]] = {}
    for line in text.splitlines():
        found = re.match(r"^  ([a-z][a-z-]*(?: \| [a-z][a-z-]*)*)\s+(.*)$", line)
        if not found:
            continue
        for verb in found.group(1).split(" | "):
            # A verb with subcommands has one help line for each, and its options are all of them.
            verbs.setdefault(verb, set()).update(FLAG.findall(found.group(2)))
    for word in ("help", "--help", "-h"):
        verbs[word] = set()
    return verbs


def binary_names(root: Path) -> set[str]:
    names: set[str] = set()
    for manifest in sorted((root / "apps").glob("*/Cargo.toml")):
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        for entry in data.get("bin", []):
            names.add(str(entry.get("name")))
    return names


def script_help(root: Path, name: str) -> set[str] | None:
    ran = run(["bash", str(root / "scripts" / name), "--help"], root, timeout=30)
    if ran is None or ran.code != 0:
        return None
    return set(FLAG.findall(ran.output))


def gather_helps(root: Path) -> Helps | str:
    """The real help of every program the documents may name, or the reason it is missing."""
    reason = build_cli(root)
    if reason:
        return reason
    cli = run([str(target_dir(root) / "debug" / "factory-cli"), "--help"], root, timeout=30)
    if cli is None or cli.code != 0:
        return "factory-cli --help did not answer"
    xtask = run(["cargo", "xtask", "--help"], root, timeout=900)
    if xtask is None or xtask.code != 0:
        return "cargo xtask --help did not answer"
    listing = run(["cargo", "--list"], root, timeout=60)
    if listing is None or listing.code != 0:
        return "cargo --list did not answer"
    sidecar_source = root / "apps/egress-sidecar/src/main.rs"
    sidecar_flags = set(re.findall(r'"(--[a-z][a-z0-9-]*)"', sidecar_source.read_text("utf-8")))
    scripts: dict[str, set[str]] = {}
    for script in sorted((root / "scripts").glob("*.sh")):
        flags = script_help(root, script.name)
        if flags is not None:
            scripts[script.name] = flags
    return Helps(
        cli_verbs=parse_cli_help(cli.output),
        cli_text=cli.output,
        xtask_commands=set(re.findall(r"cargo xtask ([a-z][a-z-]*)", xtask.output)),
        xtask_flags=set(FLAG.findall(xtask.output)),
        binaries=binary_names(root),
        sidecar_flags=sidecar_flags,
        script_flags=scripts,
        cargo_subcommands={m.group(1) for m in re.finditer(r"^\s+([a-z][\w-]*)", listing.output, re.M)},
    )


# ---------------------------------------------------------------------------------------------
# Check: shell snippets are runnable, or say why not
# ---------------------------------------------------------------------------------------------


def check_snippet_marks(root: Path, documents: list[Path]) -> Outcome:
    problems: list[str] = []
    count = 0
    for path in documents:
        for block in fences(path, path.read_text(encoding="utf-8")):
            if block.lang not in SHELL_LANGUAGES:
                continue
            count += 1
            where = f"{relative(root, path)}:{block.line}"
            marked = {"run", "quickstart", "no-run"} & block.flags
            if not marked:
                problems.append(f"{where}: a {block.lang} block is neither run, quickstart nor no-run")
            elif "no-run" in block.flags and not any(block.attrs.get("reason", [])):
                problems.append(f'{where}: a no-run block needs reason="why it is not run"')
            elif len(marked) > 1:
                problems.append(f"{where}: a block is marked {sorted(marked)}; use one")
    return done("snippet-marks", problems, f"all {count} shell blocks say whether they run")


def run_snippets(root: Path, documents: list[Path], cwd: Path | None = None) -> Outcome:
    problems: list[str] = []
    ran_count = 0
    stopped: list[str] = []
    if shutil.which("cargo") and any(
        "run" in b.flags for p in documents for b in fences(p, p.read_text("utf-8"))
    ):
        reason = build_cli(root)
        if reason:
            return blocked("snippets-run", reason)
    env = tool_env(root)
    for path in documents:
        for block in fences(path, path.read_text(encoding="utf-8")):
            if block.lang not in SHELL_LANGUAGES or "run" not in block.flags:
                continue
            where = f"{relative(root, path)}:{block.line}"
            if "docker" in block.attrs.get("needs", []) and not docker_answers():
                stopped.append(f"{where}: needs Docker and the daemon does not answer")
                continue
            ran_count += 1
            with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as handle:
                handle.write(block.body)
            seconds = float(block.attrs.get("timeout", ["120"])[0])
            ran = run(["bash", "-euo", "pipefail", handle.name], cwd or root, env, seconds)
            os.unlink(handle.name)
            if ran is None:
                problems.append(f"{where}: the snippet did not finish in {seconds:.0f} seconds")
                continue
            want = int(block.attrs.get("exit", ["0"])[0])
            if ran.code != want:
                problems.append(f"{where}: exit code {ran.code}, expected {want}")
            for text in block.attrs.get("expect", []):
                if text not in ran.output:
                    problems.append(f"{where}: the output does not contain {text!r}")
    if problems:
        return Outcome("snippets-run", FAILED, problems)
    if stopped:
        return Outcome("snippets-run", BLOCKED, stopped)
    if not ran_count:
        return Outcome("snippets-run", NOT_APPLICABLE, ["no block is marked run"])
    return Outcome("snippets-run", PASSED, [f"{ran_count} runnable blocks ran and printed what the page says"])


# ---------------------------------------------------------------------------------------------
# Check: every command the documents name exists in the real help
# ---------------------------------------------------------------------------------------------

COMMAND_PREFIXES = (
    "factory-cli",
    "factory-worker",
    "factory-api",
    "factory-egress-sidecar",
    "scripts/",
    "./scripts/",
    "cargo ",
    "bash scripts/",
    "python3 -I ",
)
PATH_TOKEN = re.compile(
    r"^(?:\./)?(?:docs|scripts|crates|apps|fixtures|tests|infra|policies|schemas|migrations|profiles|"
    r"agents|specs|\.specify)/[A-Za-z0-9_./-]+$"
)


def command_lines(path: Path, text: str) -> list[tuple[int, str]]:
    """Command lines in shell blocks, and inline code spans that start like a command."""
    found: list[tuple[int, str]] = []
    for block in fences(path, text):
        if block.lang not in SHELL_LANGUAGES:
            continue
        pending = ""
        for offset, raw in enumerate(block.body.splitlines()):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            line = re.sub(r"\s+#\s.*$", "", line)
            line = re.sub(r"^[$>]\s+", "", line)
            if pending:
                line = pending + " " + line
                pending = ""
            if line.endswith("\\"):
                pending = line[:-1].strip()
                continue
            found.append((block.line + 1 + offset, line))
    for number, span in inline_code(text):
        if span.startswith(COMMAND_PREFIXES):
            found.append((number, span))
    return found


def judge_command(root: Path, line: str, helps: Helps) -> list[str]:
    """What is wrong with one command line. Empty when it is fine or not ours to judge."""
    try:
        words = shlex.split(line, comments=False)
    except ValueError:
        return []
    while words and re.match(r"^[A-Z_][A-Z0-9_]*=", words[0]):
        words = words[1:]
    while words and words[0] in {"time", "timeout", "sudo"}:
        words = words[1:]
        if words and words[0].isdigit():
            words = words[1:]
    if not words:
        return []
    problems: list[str] = []
    first = words[0]
    if re.fullmatch(r"(?:\./)?target/(?:debug|release)/factory-[a-z-]+", first):
        first = first.rsplit("/", 1)[1]
    if first == "bash" and len(words) > 1 and words[1].startswith(("scripts/", "./scripts/")):
        words = words[1:]
        first = words[0]
    rest = words[1:]
    before_dash = rest[: rest.index("--")] if "--" in rest else rest
    flags = [
        w.split("=", 1)[0]
        for w in before_dash
        if FLAG.fullmatch(w.split("=", 1)[0]) and w not in {"--help", "--version"}
    ]

    if first == "factory-cli":
        verb = next((w for w in rest if not w.startswith("-")), None)
        if verb is None:
            return problems
        if verb not in helps.cli_verbs:
            return [f"factory-cli has no command {verb!r}"]
        problems += [f"factory-cli {verb} has no option {f}" for f in flags if f not in helps.cli_verbs[verb]]
    elif first in {"factory-worker", "factory-api"}:
        if first not in helps.binaries:
            problems.append(f"there is no binary {first}")
        problems += [f"{first} takes no option, and {f} was given" for f in flags]
    elif first == "factory-egress-sidecar":
        problems += [f"factory-egress-sidecar has no option {f}" for f in flags if f not in helps.sidecar_flags]
    elif first.startswith(("scripts/", "./scripts/")) and re.fullmatch(r"(?:\./)?scripts/[a-z0-9._-]+\.sh", first):
        name = first.removeprefix("./").removeprefix("scripts/")
        if not (root / "scripts" / name).is_file():
            problems.append(f"there is no script {first}")
        elif name in helps.script_flags:
            problems += [f"{first} has no option {f}" for f in flags if f not in helps.script_flags[name]]
        else:
            problems.append(f"{first} --help did not answer, so its options cannot be checked")
    elif first == "cargo" and rest[:1] == ["xtask"]:
        sub = next((w for w in rest[1:] if not w.startswith("-")), None)
        if sub is not None and sub not in helps.xtask_commands and sub != "help":
            problems.append(f"cargo xtask has no command {sub!r}")
        problems += [f"cargo xtask has no option {f}" for f in flags if f not in helps.xtask_flags]
    elif first == "cargo":
        sub = next((w for w in rest if not w.startswith(("-", "+"))), None)
        if sub is not None and sub not in helps.cargo_subcommands:
            problems.append(f"cargo has no command {sub!r}")
    for token in words[1:]:
        if PATH_TOKEN.match(token) and not any(c in token for c in "*<>{}$") and not (root / token).exists():
            problems.append(f"the path {token} does not exist")
    return problems


def table_rows(text: str, first_header: str) -> list[tuple[int, list[str]]]:
    """Rows of every table whose header's first cell is `first_header`, as lists of cells."""
    rows: list[tuple[int, list[str]]] = []
    active = False
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line.startswith("|"):
            active = False
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if cells and cells[0].lower() == first_header.lower():
            active = True
            continue
        if active and not set(line) <= {"|", "-", " ", ":"}:
            rows.append((number, cells))
    return rows


def backticked(cell: str) -> list[str]:
    return re.findall(r"`([^`]+)`", cell)


def check_reference_tables(root: Path, helps: Helps) -> list[str]:
    """The two-way checks of docs/reference/commands.md: CLI commands, API endpoints, exit codes."""
    path = root / "docs/reference/commands.md"
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8")
    problems: list[str] = []
    documented: dict[str, set[str]] = {}
    for number, cells in table_rows(text, "Command"):
        names = backticked(cells[0])
        if not names or not names[0].startswith("factory-cli "):
            continue
        verb = names[0].split(" ", 1)[1]
        documented[verb] = set(FLAG.findall(" ".join(backticked(cells[1])))) if len(cells) > 1 else set()
    in_help = {v for v in helps.cli_verbs if not v.startswith("-") and v != "help"}
    for verb in sorted(in_help - set(documented)):
        problems.append(f"commands.md: the command factory-cli {verb} is in the help and not documented")
    for verb in sorted(set(documented) - in_help):
        problems.append(f"commands.md: factory-cli {verb} is documented and not in the help")
    for verb in sorted(in_help & set(documented)):
        for flag in sorted(helps.cli_verbs[verb] - documented[verb]):
            problems.append(f"commands.md: factory-cli {verb} has {flag} in the help and not in the page")
        for flag in sorted(documented[verb] - helps.cli_verbs[verb]):
            problems.append(f"commands.md: factory-cli {verb} documents {flag}, which is not in the help")
    spec = json.loads((root / "apps/api/openapi.json").read_text(encoding="utf-8"))
    real = {f"{m.upper()} {p}" for p, ops in spec["paths"].items() for m in ops}
    listed = {backticked(c[0])[0] for _, c in table_rows(text, "Endpoint") if backticked(c[0])}
    for item in sorted(real - listed):
        problems.append(f"commands.md: the endpoint {item} is in openapi.json and not documented")
    for item in sorted(listed - real):
        problems.append(f"commands.md: the endpoint {item} is documented and not in openapi.json")
    verbs = set(spec["components"]["schemas"]["Decision"]["properties"]["verb"]["enum"])
    shown = {backticked(c[0])[0] for _, c in table_rows(text, "Verb") if backticked(c[0])}
    for item in sorted(verbs - shown):
        problems.append(f"commands.md: the decision verb {item} is in openapi.json and not documented")
    for item in sorted(shown - verbs):
        problems.append(f"commands.md: the decision verb {item} is documented and not in openapi.json")
    problems += check_worker_lines(root, text)
    codes_in_help = set(re.findall(r"(\d) [a-z ]+(?:,|\.)", helps.cli_text.split("Exit codes:")[-1]))
    codes_shown = {c[0].strip("` ") for _, c in table_rows(text, "Exit code")}
    if codes_in_help and codes_in_help != codes_shown:
        problems.append(f"commands.md: the exit codes of factory-cli are {sorted(codes_in_help)} and the page has {sorted(codes_shown)}")
    return problems


def check_worker_lines(root: Path, text: str) -> list[str]:
    """The BLOCKED lines of the worker, from the two lists in assemble.rs, against the page."""
    assemble = (root / "crates/composition/src/assemble.rs").read_text(encoding="utf-8")
    profile = (root / "crates/composition/src/profile.rs").read_text(encoding="utf-8")
    labels = dict(re.findall(r'^\s*(\w+) => "([^"]+)",$', profile, re.M))
    adapters = assemble.split("pub fn blocked_adapters")[1].split("pub struct BlockedSeam")[0]
    inputs = assemble.split("pub fn blocked_pipeline_inputs")[1].split("pub async fn prepare")[0]
    real = {"BLOCKED: " + labels[v] for v in re.findall(r"port: PortName::(\w+)", adapters) if v in labels}
    real |= {"BLOCKED: " + name for name in re.findall(r'seam: "([^"]+)"', inputs)}
    shown = {backticked(c[0])[0] for _, c in table_rows(text, "Worker line") if backticked(c[0])}
    problems = [f"commands.md: the worker prints `{line}` and the page does not list it" for line in sorted(real - shown)]
    problems += [f"commands.md: the page lists `{line}` and the worker does not print it" for line in sorted(shown - real)]
    return problems


def check_commands(root: Path, documents: list[Path]) -> Outcome:
    helps = gather_helps(root)
    if isinstance(helps, str):
        return blocked("commands", helps)
    problems: list[str] = []
    count = 0
    for path in documents:
        for number, line in command_lines(path, path.read_text(encoding="utf-8")):
            count += 1
            for problem in judge_command(root, line, helps):
                problems.append(f"{relative(root, path)}:{number}: {problem}: {line}")
    problems += check_reference_tables(root, helps)
    return done("commands", problems, f"{count} command lines name only commands, options and paths that exist")


# ---------------------------------------------------------------------------------------------
# Check: configuration keys, both ways, from the serde structure of the Rust code
# ---------------------------------------------------------------------------------------------


@dataclass
class FieldInfo:
    name: str
    type: str
    has_default: bool
    default: str | None


@dataclass
class KeyFact:
    path: str
    kind: str
    required: bool
    default: str | None


CONFIG_SOURCES = ("crates/composition/src/config.rs", "apps/api/src/config.rs")
ENV_SOURCES = (
    "crates/composition/src/config.rs",
    "apps/api/src/config.rs",
    "apps/cli/src/commands.rs",
    "apps/cli/src/lib.rs",
    "apps/worker/src/main.rs",
    "apps/api/src/main.rs",
)
UNKNOWN = "?"  # a default computed by a function that is not a plain number or word
SCALARS = {
    "String": "text",
    "PathBuf": "path",
    "SecretFile": "secret file",
    "bool": "true or false",
    "f64": "number",
    "SocketAddr": "address",
    "Profile": "profile",
}
WHOLE = {"u8", "u16", "u32", "u64", "usize", "i32", "i64"}
PLURAL = {"text": "text", "path": "paths", "secret file": "secret files", "table": "tables", "whole number": "whole numbers"}


DEFAULT_FN = re.compile(r"(?:const )?fn (\w+)\(\) -> [\w<>:, ]+ \{\s*([^{}]+?)\s*\}", re.S)


def parse_structs(source: str) -> dict[str, list[FieldInfo]]:
    """Every `pub struct` that derives Deserialize, with its fields and literal defaults."""
    defaults = dict(DEFAULT_FN.findall(source))
    structs: dict[str, list[FieldInfo]] = {}
    pending: list[str] = []
    current: str | None = None
    serde: list[str] = []
    for raw in source.splitlines():
        line = raw.strip()
        if current is None:
            if line.startswith("#["):
                pending.append(line)
                continue
            opened = re.match(r"^pub struct (\w+)\s*\{$", line)
            name = opened.group(1) if opened else None
            if name is not None and any("Deserialize" in p for p in pending):
                current = name
                structs[name] = []
                serde = []
            if not line.startswith("///"):
                pending = []
            continue
        if line == "}":
            current = None
            pending = []
            continue
        if line.startswith("#[serde"):
            serde.append(line)
            continue
        field_line = re.match(r"^pub (\w+): (.+),$", line)
        if field_line:
            attrs = " ".join(serde)
            renamed = re.search(r'rename = "([^"]+)"', attrs)
            name = renamed.group(1) if renamed else field_line.group(1)
            fn = re.search(r'default = "(\w+)"', attrs)
            value = (literal_default(defaults.get(fn.group(1), "")) or UNKNOWN) if fn else None
            structs[current].append(FieldInfo(name, field_line.group(2).strip(), "default" in attrs, value))
            serde = []
    return structs


def literal_default(expression: str) -> str | None:
    """The value of a default function when it is a plain number or a string."""
    text = expression.strip()
    text = re.sub(r"(?<=\d)_(?=\d)", "", text)
    if re.fullmatch(r"[\d\s*.]+(?:u\d+|usize|f64)?", text):
        number = re.sub(r"(u\d+|usize|f64)$", "", text).strip()
        product: float = 1
        for part in number.split("*"):
            word = part.strip()
            product *= float(word) if "." in word else int(word)
        return str(product)
    quoted = re.fullmatch(r'"([^"]*)"\.to_owned\(\)', text)
    return quoted.group(1) if quoted else None


def kind_of(ty: str, structs: dict[str, list[FieldInfo]]) -> tuple[str, str | None]:
    """The documented kind of a Rust type, and the struct it holds, if any."""
    ty = ty.replace("std::collections::", "").replace(" ", "")
    inner = re.fullmatch(r"Option<(.+)>", ty)
    if inner:
        return kind_of(inner.group(1), structs)
    listed = re.fullmatch(r"Vec<(.+)>", ty)
    if listed:
        kind, struct = kind_of(listed.group(1), structs)
        return "list of " + PLURAL.get(kind, kind), struct
    if ty.startswith("BTreeMap<"):
        return "map of text to text", None
    if ty in SCALARS:
        return SCALARS[ty], None
    if ty in WHOLE:
        return "whole number", None
    if ty in structs:
        return "table", ty
    return "text", None


def walk(
    prefix: str,
    struct: str,
    structs: dict[str, list[FieldInfo]],
    out: dict[str, KeyFact],
) -> None:
    for item in structs[struct]:
        kind, inner = kind_of(item.type, structs)
        optional = item.type.startswith("Option<")
        path = f"{prefix}{item.name}"
        value: str | None = item.default
        if value == UNKNOWN:
            value = None
        elif value is not None:
            pass
        elif optional:
            value = "none"
        elif item.has_default and item.default is None and kind.startswith(("list", "map")):
            value = "empty"
        out[path] = KeyFact(path, kind, not (item.has_default or optional), value)
        if inner:
            walk(path + ("[]." if kind.startswith("list") else "."), inner, structs, out)


def code_keys(root: Path) -> tuple[dict[str, dict[str, KeyFact]], set[str]]:
    """The keys of the worker file and the API file, and the environment variables."""
    structs: dict[str, list[FieldInfo]] = {}
    for name in CONFIG_SOURCES:
        structs.update(parse_structs((root / name).read_text(encoding="utf-8")))
    keys: dict[str, dict[str, KeyFact]] = {"worker": {}, "api": {}}
    walk("", "FactoryConfig", structs, keys["worker"])
    walk("", "ApiConfig", structs, keys["api"])
    variables: set[str] = set()
    for name in ENV_SOURCES:
        source = (root / name).read_text(encoding="utf-8").split("#[cfg(test)]")[0]
        variables.update(re.findall(r'"(FACTORY_[A-Z0-9_]+)"', source))
    return keys, variables


def documented_keys(text: str) -> tuple[dict[str, dict[str, tuple[int, list[str]]]], set[str]]:
    """The rows of the configuration page by section ("worker" or "api"), and the variables."""
    sections: dict[str, dict[str, tuple[int, list[str]]]] = {"worker": {}, "api": {}}
    variables: set[str] = set()
    section = ""
    table: list[str] | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        if raw.startswith("## "):
            title = raw[3:].lower()
            section = "worker" if title.startswith("worker") else "api" if title.startswith("api") else ""
            if title.startswith("environment"):
                section = "env"
            table = None
            continue
        line = raw.strip()
        if not line.startswith("|"):
            table = None
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if cells[0].lower() in {"key", "variable"}:
            table = [c.lower() for c in cells]
            continue
        if table is None or set(line) <= {"|", "-", " ", ":"}:
            continue
        names = backticked(cells[0])
        if not names:
            continue
        if section == "env":
            variables.add(names[0])
        elif section in sections:
            sections[section][names[0]] = (number, cells + ["\0".join(table)])
    return sections, variables


def check_config_keys(root: Path) -> Outcome:
    page = root / "docs/reference/configuration.md"
    if not page.is_file():
        return Outcome("config-keys", FAILED, ["docs/reference/configuration.md does not exist"])
    for name in CONFIG_SOURCES:
        if not (root / name).is_file():
            return blocked("config-keys", f"{name} is missing, so the keys in code cannot be read")
    keys, variables = code_keys(root)
    shown, shown_variables = documented_keys(page.read_text(encoding="utf-8"))
    problems: list[str] = []
    for section, facts in keys.items():
        rows = shown[section]
        for path in sorted(set(facts) - set(rows)):
            problems.append(f"configuration.md: the {section} key {path} is in the code and not documented")
        for path in sorted(set(rows) - set(facts)):
            problems.append(f"configuration.md:{rows[path][0]}: the {section} key {path} is documented and not in the code")
        for path in sorted(set(facts) & set(rows)):
            number, cells = rows[path]
            header = cells[-1].split("\0")
            cells = cells[:-1]
            fact = facts[path]

            def cell(name: str, cells: list[str] = cells, header: list[str] = header) -> str:
                return cells[header.index(name)].strip("` ") if name in header else ""

            where = f"configuration.md:{number}: {section} key {path}"
            if cell("type") != fact.kind:
                problems.append(f"{where}: the type is {cell('type')!r} and the code says {fact.kind!r}")
            say = cell("required")
            if fact.required and say != "yes":
                problems.append(f"{where}: the code requires it and the page says {say!r}")
            if not fact.required and say not in {"no", "production"}:
                problems.append(f"{where}: the code does not require it and the page says {say!r}")
            if fact.default is not None and cell("default") != fact.default:
                problems.append(f"{where}: the default is {cell('default')!r} and the code says {fact.default!r}")
    for name in sorted(variables - shown_variables):
        problems.append(f"configuration.md: the environment variable {name} is read by code and not documented")
    for name in sorted(shown_variables - variables):
        problems.append(f"configuration.md: the environment variable {name} is documented and no code reads it")
    total = sum(len(f) for f in keys.values())
    return done("config-keys", problems, f"{total} keys and {len(variables)} environment variables match the code in both directions")


# ---------------------------------------------------------------------------------------------
# Check: the walkthrough cites only what the recordings hold
# ---------------------------------------------------------------------------------------------

LEDGER_CITE = re.compile(r"^ledger (E\d+) #(\d+) id=([0-9a-f]{8,}) hash=([0-9a-f]{12,})(?: has=(.+))?$")
TIMELINE_CITE = re.compile(r"^timeline (E\d+) #(\d+) ([\w.]+)$")
JSON_CITE = re.compile(r"^json (E\d+/[\w./-]+) ([\w.\[\]-]+)=(.+)$")


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def lookup(document: Any, dotted: str) -> Any:
    value = document
    for part in dotted.split("."):
        if isinstance(value, list):
            value = value[int(part)]
        else:
            value = value[part]
    return value


def judge_citation(root: Path, span: str) -> str | None:
    """None when the citation holds. Otherwise what is wrong with it."""
    base = root / RECORDINGS
    ledger = LEDGER_CITE.match(span)
    if ledger:
        scenario, sequence, entry_id, entry_hash, has = ledger.groups()
        path = base / scenario / "ledger.json"
        if not path.is_file():
            return f"{relative(root, path)} does not exist"
        for entry in load(path)["entries"]:
            if entry["metadata"]["sequence"] == int(sequence):
                if not entry["metadata"]["entry_id"].startswith(entry_id):
                    return f"entry {sequence} of {scenario} does not have the id {entry_id}"
                if not entry["entry_hash"].removeprefix("sha256:").startswith(entry_hash):
                    return f"entry {sequence} of {scenario} does not have the hash {entry_hash}"
                if has and has.strip('"') not in entry["claim"]["statement"]:
                    return f"entry {sequence} of {scenario} does not say {has}"
                return None
        return f"{scenario} has no ledger entry with sequence {sequence}"
    timeline = TIMELINE_CITE.match(span)
    if timeline:
        scenario, index, name = timeline.groups()
        path = base / scenario / "timeline.api.json"
        if not path.is_file():
            return f"{relative(root, path)} does not exist"
        entries = load(path)["entries"]
        if int(index) >= len(entries):
            return f"the timeline of {scenario} has {len(entries)} entries and none is #{index}"
        entry = entries[int(index)]
        if name not in (entry.get("event"), entry.get("action")):
            return f"timeline entry #{index} of {scenario} is {entry.get('event') or entry.get('action')}, not {name}"
        return None
    pointer = JSON_CITE.match(span)
    if pointer:
        name, dotted, expected = pointer.groups()
        path = base / name
        if not path.is_file():
            return f"{relative(root, path)} does not exist"
        try:
            value = lookup(load(path), dotted)
        except (KeyError, IndexError, ValueError, TypeError):
            return f"{name} has no value at {dotted}"
        shown = json.dumps(value) if not isinstance(value, str) else value
        if shown != expected.strip('"'):
            return f"{name} has {shown} at {dotted}, not {expected}"
        return None
    return "this citation is not in a form the checker knows"


def check_walkthrough_text(root: Path, name: str, text: str) -> list[str]:
    problems: list[str] = []
    if "TEST MODE" not in "\n".join(text.splitlines()[:12]):
        problems.append(f"{name}: the label TEST MODE must be in the first 12 lines")
    for match in re.finditer(r"fixtures/recordings/[A-Za-z0-9_./-]*[A-Za-z0-9_]", text):
        if not (root / match.group(0)).exists():
            problems.append(f"{name}: the cited path {match.group(0)} does not exist")
    sections: list[tuple[int, str, list[str]]] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if raw.startswith("### "):
            sections.append((number, raw[4:], []))
        elif sections:
            sections[-1][2].append(raw)
    if not sections:
        problems.append(f"{name}: there is no step (a ### heading), so nothing is cited")
    for number, title, body in sections:
        spans = [s for _, s in inline_code("\n".join(body)) if s.split(" ", 1)[0] in {"ledger", "timeline", "json"}]
        paths = re.findall(r"fixtures/recordings/", "\n".join(body))
        if not spans and not paths:
            problems.append(f"{name}:{number}: the step {title!r} cites no recorded file and no ledger entry")
        for span in spans:
            problem = judge_citation(root, span)
            if problem:
                problems.append(f"{name}: `{span}`: {problem}")
    return problems


def check_walkthrough(root: Path, documents: list[Path] | None = None) -> Outcome:
    pages = documents if documents is not None else sorted((root / "docs/walkthroughs").glob("*.md"))
    if not pages:
        return Outcome("walkthrough", FAILED, ["docs/walkthroughs has no page"])
    problems: list[str] = []
    for page in pages:
        problems += check_walkthrough_text(root, relative(root, page), page.read_text(encoding="utf-8"))
    return done("walkthrough", problems, f"every step of {len(pages)} walkthrough page(s) cites a recording that holds what it says")


def refresh_walkthrough(root: Path) -> Outcome:
    """Rewrites the id and hash of each ledger citation from the recording, by sequence number."""
    changed = 0
    for page in sorted((root / "docs/walkthroughs").glob("*.md")):
        text = page.read_text(encoding="utf-8")

        def fix(match: re.Match[str]) -> str:
            scenario, sequence = match.group(1), int(match.group(2))
            for entry in load(root / RECORDINGS / scenario / "ledger.json")["entries"]:
                if entry["metadata"]["sequence"] == sequence:
                    tail = f" has={match.group(5)}" if match.group(5) else ""
                    return (
                        f"`ledger {scenario} #{sequence} id={entry['metadata']['entry_id'][:8]} "
                        f"hash={entry['entry_hash'].removeprefix('sha256:')[:12]}{tail}`"
                    )
            return match.group(0)

        new = re.sub(r"`ledger (E\d+) #(\d+) id=([0-9a-f]+) hash=([0-9a-f]+)(?: has=([^`]+))?`", fix, text)
        if new != text:
            page.write_text(new, encoding="utf-8")
            changed += 1
    return Outcome("walkthrough-refresh", PASSED, [f"{changed} page(s) rewritten; read the diff before you commit it"])


# ---------------------------------------------------------------------------------------------
# Check: the readability gate and the links, through the factory's own tools
# ---------------------------------------------------------------------------------------------


def check_readability(root: Path, documents: list[Path]) -> Outcome:
    if shutil.which("cargo") is None:
        return blocked("readability", "cargo is not installed, so the readability gate cannot be built")
    command = ["bash", str(root / "scripts/e2e.sh"), "--check-readability", *[str(p) for p in documents]]
    ran = run(command, root, timeout=1500)
    if ran is None:
        return blocked("readability", "scripts/e2e.sh --check-readability did not finish")
    if ran.code not in (0, 1):
        return blocked("readability", "the readability gate could not run: " + (ran.output.strip().splitlines() or [""])[-1])
    findings = [ln for ln in ran.output.splitlines() if ln.startswith(("BLOCK ", "warn "))]
    return done("readability", findings, f"{len(documents)} documents pass the readability gate with no blocking finding and no warning")


def check_links(root: Path, scratch: Path | None = None) -> Outcome:
    if shutil.which("cargo") is None:
        return blocked("links", "cargo is not installed, so cargo xtask check-links cannot run")
    command = ["cargo", "xtask", "check-links"]
    if scratch is not None:
        command += ["--root", str(scratch)]
    ran = run(command, root, timeout=900)
    if ran is None or ran.code == 2:
        return blocked("links", "cargo xtask check-links could not run")
    if ran.code != 0:
        return Outcome("links", FAILED, [ln for ln in ran.output.splitlines() if ln.startswith("error[")] or [ran.output.strip()])
    return Outcome("links", PASSED, [ran.output.strip().splitlines()[-1] if ran.output.strip() else "no dead link"])


# ---------------------------------------------------------------------------------------------
# The quickstart: a clean clone, the commands of the guide, Docker parts BLOCKED
# ---------------------------------------------------------------------------------------------


def check_quickstart(root: Path) -> Outcome:
    guide = root / "docs/guides/quickstart.md"
    if not guide.is_file():
        return Outcome("quickstart", FAILED, ["docs/guides/quickstart.md does not exist"])
    if shutil.which("git") is None:
        return blocked("quickstart", "git is not installed, so the repository cannot be cloned")
    head = run(["git", "rev-parse", "HEAD"], root, timeout=30)
    if head is None or head.code != 0:
        return blocked("quickstart", "git cannot name the commit to clone")
    steps = [b for b in fences(guide, guide.read_text("utf-8")) if "quickstart" in b.flags]
    if not steps:
        return Outcome("quickstart", FAILED, ["the guide has no block marked quickstart"])
    work = Path(tempfile.mkdtemp(prefix="docs-check-quickstart."))
    clone = work / "clone"
    lines: list[str] = []
    failed = False
    stopped = False
    try:
        cloned = run(["git", "clone", "--quiet", "--no-hardlinks", "--no-checkout", str(root), str(clone)], work, timeout=600)
        picked = run(["git", "checkout", "--quiet", "--detach", head.output.strip()], clone, timeout=600) if cloned and cloned.code == 0 else None
        if picked is None or picked.code != 0:
            return Outcome("quickstart", FAILED, ["git clone of the repository failed"])
        lines.append(f"cloned {head.output.strip()[:10]} into a scratch directory; uncommitted changes are not in the clone")
        env = dict(os.environ)
        env.pop("CARGO_TARGET_DIR", None)
        shared = os.environ.get("DOCS_CHECK_TARGET_DIR")
        if shared:
            os.symlink(shared, clone / "target")
            lines.append(f"the build directory of the clone is {shared}")
        for block in steps:
            title = (block.attrs.get("step") or [f"line {block.line}"])[0]
            needs = block.attrs.get("needs", [])
            if "docker" in needs and not docker_answers():
                lines.append(f"BLOCKED  {title}: needs Docker and the daemon does not answer")
                stopped = True
                continue
            if "docker-cli" in needs and not docker_cli_works():
                lines.append(f"BLOCKED  {title}: needs the docker command and its Compose plugin")
                stopped = True
                continue
            if "postgres" in needs and not postgres_available():
                lines.append(f"BLOCKED  {title}: needs the PostgreSQL 18 binaries (or FACTORY_DB_ADMIN_URL)")
                stopped = True
                continue
            seconds = float(block.attrs.get("timeout", ["1200"])[0])
            script = work / "step.sh"
            script.write_text(block.body, encoding="utf-8")
            ran = run(["bash", "-euo", "pipefail", str(script)], clone, env, seconds)
            if ran is None:
                lines.append(f"FAILED   {title}: no end within {seconds:.0f} seconds")
                failed = True
                continue
            missing = [t for t in block.attrs.get("expect", []) if t not in ran.output]
            want = int(block.attrs.get("exit", ["0"])[0])
            if ran.code == 3 and want != 3:
                tail = " | ".join(ran.output.strip().splitlines()[-2:])
                lines.append(f"BLOCKED  {title}: the step ended with exit code 3, which means BLOCKED: {tail}")
                stopped = True
            elif ran.code != want or missing:
                reason = f"exit code {ran.code}, expected {want}" if ran.code != want else f"the output lacks {missing[0]!r}"
                tail = " | ".join(ran.output.strip().splitlines()[-3:])
                lines.append(f"FAILED   {title}: {reason}: {tail}")
                failed = True
            else:
                lines.append(f"PASSED   {title} ({ran.seconds:.0f}s)")
    finally:
        if not os.environ.get("DOCS_CHECK_KEEP"):
            shutil.rmtree(work, ignore_errors=True)
    if failed:
        return Outcome("quickstart", FAILED, lines)
    if stopped:
        return Outcome("quickstart", BLOCKED, lines)
    return Outcome("quickstart", PASSED, lines)


# ---------------------------------------------------------------------------------------------
# Self-test: every check must FAIL on an input that is broken on purpose
# ---------------------------------------------------------------------------------------------


@dataclass
class Case:
    name: str
    outcome: Outcome
    expect: str


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


GOOD_WALKTHROUGH = """# A walkthrough

TEST MODE. Everything here was recorded with fakes.

### Step 1: the first gate

The gate passed. Evidence: `ledger E9 #2 id=22222222 hash=bbbbbbbbbbbb has="gate lint"` in
fixtures/recordings/e2e/E9/ledger.json and `timeline E9 #1 stage_run.started`.
"""


def synthetic_recording(root: Path) -> None:
    base = root / RECORDINGS / "E9"
    entries = [
        {
            "claim": {"statement": f"The {name} was recorded."},
            "entry_hash": "sha256:" + char * 64,
            "metadata": {"sequence": number, "entry_id": f"{str(number) * 8}-0000-4000-8000-000000000000"},
        }
        for number, name, char in ((1, "gate format", "a"), (2, "gate lint", "b"))
    ]
    write(base / "ledger.json", json.dumps({"chain": {}, "entries": entries}))
    write(
        base / "timeline.api.json",
        json.dumps(
            {
                "job_id": "x",
                "entries": [
                    {"kind": "audit", "action": "job.received_from_webhook"},
                    {"kind": "transition", "event": "stage_run.started"},
                ],
            }
        ),
    )
    write(base / "mode.json", json.dumps({"mode": "test", "cost_micro_usd": 0}))


def as_case(name: str, problems: list[str], expect: str) -> Case:
    return Case(name, Outcome(name, FAILED if problems else PASSED, problems), expect)


def self_test(root: Path) -> Outcome:
    """Runs each check on good input, then on input broken on purpose, and demands the result."""
    cases: list[Case] = []
    work = Path(tempfile.mkdtemp(prefix="docs-check-selftest."))
    try:
        # Links: a dead link.
        write(work / "links-good/a.md", "# A\n\nSee [b](./b.md).\n")
        write(work / "links-good/b.md", "# B\n")
        cases.append(Case("a working link", check_links(root, work / "links-good"), PASSED))
        write(work / "links-bad/a.md", "# A\n\nSee [gone](./gone.md).\n")
        cases.append(Case("a dead link", check_links(root, work / "links-bad"), FAILED))

        # Snippets: unmarked, unexplained and failing blocks.
        marked = write(work / "snip/ok.md", '# T\n\n```bash no-run reason="needs Docker"\ndocker ps\n```\n')
        cases.append(Case("a no-run block with a reason", check_snippet_marks(work, [marked]), PASSED))
        bare = write(work / "snip/bare.md", "# T\n\n```bash\nls\n```\n")
        cases.append(Case("a shell block with no mark", check_snippet_marks(work, [bare]), FAILED))
        silent = write(work / "snip/silent.md", "# T\n\n```bash no-run\nls\n```\n")
        cases.append(Case("a no-run block with no reason", check_snippet_marks(work, [silent]), FAILED))
        fine = write(work / "snip/fine.md", '# T\n\n```bash run expect="hello"\necho hello\n```\n')
        cases.append(Case("a runnable block that prints what the page says", run_snippets(root, [fine], work), PASSED))
        broken = write(work / "snip/broken.md", "# T\n\n```bash run\nfalse\n```\n")
        cases.append(Case("a runnable block that fails", run_snippets(root, [broken], work), FAILED))
        lying = write(work / "snip/lying.md", '# T\n\n```bash run expect="goodbye"\necho hello\n```\n')
        cases.append(Case("a runnable block that does not print what the page says", run_snippets(root, [lying], work), FAILED))

        # Commands: a flag, a verb and a path that do not exist.
        helps = gather_helps(root)
        if isinstance(helps, str):
            cases.append(Case("the real help texts", blocked("commands", helps), PASSED))
        else:
            for label, line, want in (
                ("a real CLI command", "factory-cli status --api URL --token-file FILE JOB", PASSED),
                ("a CLI flag that does not exist", "factory-cli submit --api URL --nope X", FAILED),
                ("a CLI command that does not exist", "factory-cli frobnicate --api URL", FAILED),
                ("a script flag that does not exist", "scripts/e2e.sh --no-such-flag", FAILED),
                ("a script that does not exist", "scripts/no-such-script.sh", FAILED),
                ("a path that does not exist", "python3 -I docs/reference/gone.py", FAILED),
                ("an xtask command that does not exist", "cargo xtask check-nothing", FAILED),
            ):
                cases.append(as_case(label, judge_command(root, line, helps), want))
            edits: list[tuple[str, Callable[[str], str]]] = [
                ("a CLI option dropped from the command table", lambda t: t.replace("`--token-file`, ", "", 1)),
                ("an endpoint dropped from the endpoint table", lambda t: re.sub(r"^\| `GET /healthz`.*\n", "", t, flags=re.M)),
                ("a decision verb that does not exist", lambda t: re.sub(r"^(\| `cancel` \|.*\n)", r"\1| `merge` | x |\n", t, flags=re.M)),
                ("a worker BLOCKED line that was dropped", lambda t: re.sub(r"^\| `BLOCKED: model router`.*\n", "", t, flags=re.M)),
                ("a worker BLOCKED line that no code prints", lambda t: t.replace("| `BLOCKED: change host` |", "| `BLOCKED: crystal ball` | x |\n| `BLOCKED: change host` |", 1)),
            ]
            for label, edit in edits:
                scratch = work / "commands"
                shutil.rmtree(scratch, ignore_errors=True)
                for name in ("apps/api/openapi.json", "crates/composition/src/assemble.rs", "crates/composition/src/profile.rs"):
                    write(scratch / name, (root / name).read_text("utf-8"))
                text = (root / "docs/reference/commands.md").read_text("utf-8")
                write(scratch / "docs/reference/commands.md", edit(text))
                cases.append(as_case(label, check_reference_tables(scratch, helps), FAILED))

        # Configuration keys: an undocumented key, an invented key, a wrong default, a wrong type.
        config_edits: list[tuple[str, Callable[[str], str], str]] = [
            ("the page as it is", lambda t: t, PASSED),
            ("a key in code that the page leaves out", lambda t: re.sub(r"^\| `worker\.drain_s`.*\n", "", t, flags=re.M), FAILED),
            (
                "a key on the page that is not in code",
                lambda t: t.replace("| `worker.drain_s` |", "| `worker.no_such_key` | whole number | no | 1 | x |\n| `worker.drain_s` |", 1),
                FAILED,
            ),
            (
                "a default that differs from the code",
                lambda t: re.sub(r"(\| `worker\.drain_s` \|[^|]*\|[^|]*\| )`?120`?", r"\g<1>`121`", t),
                FAILED,
            ),
            (
                "a type that differs from the code",
                lambda t: re.sub(r"(\| `worker\.poll_interval_ms` \| )whole number", r"\1text", t),
                FAILED,
            ),
            (
                "an environment variable that no code reads",
                lambda t: t.replace("| `FACTORY_LOG` |", "| `FACTORY_NO_SUCH` | x |\n| `FACTORY_LOG` |", 1),
                FAILED,
            ),
        ]
        for label, edit, want in config_edits:
            scratch = work / "config"
            shutil.rmtree(scratch, ignore_errors=True)
            for name in sorted(set(CONFIG_SOURCES) | set(ENV_SOURCES)):
                write(scratch / name, (root / name).read_text("utf-8"))
            write(scratch / "docs/reference/configuration.md", edit((root / "docs/reference/configuration.md").read_text("utf-8")))
            cases.append(Case(label, check_config_keys(scratch), want))

        # The walkthrough: a missing file, a wrong hash, a wrong entry, an uncited step, no label.
        walk_edits: list[tuple[str, Callable[[str], str], str]] = [
            ("a walkthrough whose citations hold", lambda t: t, PASSED),
            ("a citation of a file that does not exist", lambda t: t + "\nSee fixtures/recordings/e2e/E9/missing.json.\n", FAILED),
            ("a ledger citation with the wrong hash", lambda t: t.replace("hash=bbbbbbbbbbbb", "hash=cccccccccccc"), FAILED),
            ("a ledger citation with the wrong id", lambda t: t.replace("id=22222222", "id=99999999"), FAILED),
            ("a ledger citation of an entry that does not exist", lambda t: t.replace("#2 id", "#7 id"), FAILED),
            ("a ledger citation whose text is not in the entry", lambda t: t.replace('has="gate lint"', 'has="gate build"'), FAILED),
            ("a timeline citation of the wrong event", lambda t: t.replace("stage_run.started", "job.completed"), FAILED),
            ("a step that cites nothing", lambda t: t + "\n### Step 2: nothing\n\nSomething happened.\n", FAILED),
            ("a page without the TEST MODE label", lambda t: t.replace("TEST MODE", "A RUN"), FAILED),
        ]
        for label, edit, want in walk_edits:
            scratch = work / "walk"
            shutil.rmtree(scratch, ignore_errors=True)
            synthetic_recording(scratch)
            page = write(scratch / "docs/walkthroughs/w.md", edit(GOOD_WALKTHROUGH))
            cases.append(Case(label, check_walkthrough(scratch, [page]), want))

        # The quickstart: steps that pass, fail, differ from the page, or end BLOCKED.
        quick_cases: list[tuple[str, str, str]] = [
            ("a quickstart whose steps pass", '```bash quickstart step=a expect="ok"\necho ok\n```\n', PASSED),
            ("a quickstart step that fails", "```bash quickstart step=a\nfalse\n```\n", FAILED),
            ("a quickstart step that prints something else than the page says", '```bash quickstart step=a expect="nope"\necho ok\n```\n', FAILED),
            ("a quickstart step that ends with exit code 3", "```bash quickstart step=a\nexit 3\n```\n", BLOCKED),
        ]
        for label, body, want in quick_cases:
            repo = work / "quick"
            shutil.rmtree(repo, ignore_errors=True)
            write(repo / "docs/guides/quickstart.md", "# Quickstart\n\n" + body)
            for command in (
                ["git", "init", "-q"],
                ["git", "add", "."],
                ["git", "-c", "user.name=t", "-c", "user.email=t@example.test", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "x"],
            ):
                run(command, repo, timeout=60)
            cases.append(Case(label, check_quickstart(repo), want))

        # Readability: a clean page and a page with filler and a very long sentence.
        clean = write(work / "read/clean.md", "# Clean page\n\nThis page is short. It says one thing.\n")
        cases.append(Case("a readable page", check_readability(root, [clean]), PASSED))
        long_sentence = " ".join(["word"] * 60)
        dirty = write(work / "read/dirty.md", f"# Dirty page\n\nGreat news, feel free to read this. {long_sentence}.\n")
        cases.append(Case("a page with filler and a 60-word sentence", check_readability(root, [dirty]), FAILED))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    lines: list[str] = []
    wrong = False
    cannot = False
    for case in cases:
        got = case.outcome.status
        if got == case.expect:
            shown = "passed as it should" if got == PASSED else "reported BLOCKED and not PASSED" if got == BLOCKED else "caught"
            lines.append(f"ok       {case.name}: {shown}")
        elif got == BLOCKED:
            cannot = True
            lines.append(f"BLOCKED  {case.name}: {case.outcome.lines[0] if case.outcome.lines else ''}")
        else:
            wrong = True
            lines.append(f"WRONG    {case.name}: expected {case.expect}, got {got}: {' '.join(case.outcome.lines)[:200]}")
    if wrong:
        return Outcome("self-test", FAILED, lines)
    if cannot:
        return Outcome("self-test", BLOCKED, lines)
    return Outcome("self-test", PASSED, lines)


# ---------------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------------

USAGE = """usage: scripts/docs-check.sh [MODE ...]

With no mode, every check except --quickstart runs.

  --links            relative links resolve (cargo xtask check-links)
  --snippets         every shell block is run, quickstart or no-run with a reason, and each
                     run block executes and prints what the page says
  --commands         every command, option, endpoint, verb and path the documents name exists
  --config-keys      every configuration key and environment variable is documented, and every
                     documented one exists in the code, with the same type, requirement and default
  --walkthrough      every step of the walkthrough cites a recorded file or ledger entry that holds it
  --readability      the factory's readability gate reports nothing on the owned documents
  --self-test        each check fails on an input that is broken on purpose
  --quickstart       clone the repository into a scratch directory and run the guide's commands
  --refresh-walkthrough   rewrite the ids and hashes of ledger citations after the recordings change
  --print-config-skeleton   print the key rows of the configuration page from the code

Exit codes: 0 all passed, 1 something failed, 2 wrong use, 3 nothing failed and something is BLOCKED.
BLOCKED means a check could not run. It is never a pass."""


def skeleton(root: Path) -> None:
    keys, _ = code_keys(root)
    for section, facts in keys.items():
        print(f"\n## {section}\n")
        print("| Key | Type | Required | Default | Notes |")
        print("|---|---|---|---|---|")
        for path, fact in facts.items():
            default = fact.default if fact.default is not None else "no default" if fact.required else "see notes"
            print(f"| `{path}` | {fact.kind} | {'yes' if fact.required else 'no'} | {default} | |")


def main(argv: list[str]) -> int:
    modes = {a for a in argv if a.startswith("--")}
    known = {
        "--links", "--snippets", "--commands", "--config-keys", "--walkthrough", "--readability",
        "--self-test", "--quickstart", "--refresh-walkthrough", "--print-config-skeleton", "--help",
    }
    if modes - known or len(argv) != len(modes):
        print(USAGE, file=sys.stderr)
        return 2
    if "--help" in modes:
        print(USAGE)
        return 0
    if "--print-config-skeleton" in modes:
        skeleton(ROOT)
        return 0
    documents = owned_documents(ROOT)
    steps: dict[str, Callable[[], list[Outcome]]] = {
        "--links": lambda: [check_links(ROOT)],
        "--snippets": lambda: [check_snippet_marks(ROOT, documents), run_snippets(ROOT, documents)],
        "--commands": lambda: [check_commands(ROOT, documents)],
        "--config-keys": lambda: [check_config_keys(ROOT)],
        "--walkthrough": lambda: [check_walkthrough(ROOT)],
        "--readability": lambda: [check_readability(ROOT, documents)],
        "--self-test": lambda: [self_test(ROOT)],
        "--quickstart": lambda: [check_quickstart(ROOT)],
        "--refresh-walkthrough": lambda: [refresh_walkthrough(ROOT)],
    }
    order = ["--links", "--snippets", "--commands", "--config-keys", "--walkthrough", "--readability", "--self-test"]
    chosen = [m for m in order + ["--quickstart", "--refresh-walkthrough"] if m in modes] if modes else order
    outcomes: list[Outcome] = []
    for mode in chosen:
        for outcome in steps[mode]():
            outcomes.append(outcome)
            print(f"\n==> {outcome.check}: {outcome.status}")
            for line in outcome.lines:
                print(f"    {line}")
    counts = {s: sum(1 for o in outcomes if o.status == s) for s in (PASSED, FAILED, BLOCKED, NOT_APPLICABLE)}
    print("\n" + "  ".join(f"{s} {n}" for s, n in counts.items()))
    if not modes:
        print("NOT RUN: --quickstart (it clones the repository and builds it; run it on its own)")
    print(json.dumps({"schema": "factory-docs-check/1", "counts": counts, "checks": {o.check: o.status for o in outcomes}}))
    if counts[FAILED]:
        return 1
    return 3 if counts[BLOCKED] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
