"""Audit a container image from the outside, without running anything from it.

Two modes. Both read the secret patterns from policies/security.yaml, so the test and the policy
cannot drift apart.

    docker export CONTAINER | fsaudit.py fs --out-dir DIR --forbidden F --shells F --policy P
    fsaudit.py config --inspect INSPECT.json --history HISTORY.txt --policy P --allowed-env NAME ...

`fs` reads the file system as a tar stream. It works for an image that has no shell and no tools
at all (the egress sidecar). It writes one small text file per finding class into --out-dir. An
empty file means no finding. test.sh decides what a finding means for each image.

    setid.txt             regular files with the setuid or setgid bit
    world-writable.txt    files and directories that any user may write, other than the sticky
                          directories (/tmp and its kin) and symbolic links
    forbidden.txt         executables or symlinks whose name is in forbidden-binaries.txt
    shells.txt            executables or symlinks whose name is in shells.txt
    agent-tools.txt       executables or symlinks named claude or codex, with the SHA-256 of files
    tool-modes.txt        the file mode of each agent tool and of /usr/bin/timeout (test.sh wants 0711:
                          a process started from a file that nobody can read is not dumpable, so a
                          process of the sandbox user cannot open its /proc/<pid>/fd or write its memory)
    sidecar-binary.txt    the factory-egress-sidecar file and its SHA-256, if the image holds one
    credential-names.txt  files whose name is a typical credential file
    special.txt           device nodes and fifos outside /dev
    secrets.txt           content that matches a blocking pattern of policies/security.yaml
    skipped.txt           vendor binaries whose content matches were ignored, and why
    documentation.txt     how many distro documentation files had their content left unread (below)
    summary.txt           counts

Distro documentation is not read for secret CONTENT, and nothing else is exempt
---------------------------------------------------------------------------

The URL pattern of policies/security.yaml was widened (IMG-4) to catch a URL with a password in it,
and about thirty Debian documentation files hold the anonymous CVS address of their upstream
(`cvs://:pserver:anoncvs@host:/path`, a public login with no password). The rule
NO-SECRET-CONTENT was red on the stock images for that reason. A pattern narrow enough to leave
those files alone would also leave a real credential alone, so the pattern stays and the scan
changes: it does not read the content of a regular file under

    /usr/share/doc/    /usr/share/common-licenses/    /usr/share/man/

and only of a file that the sandbox user cannot have written: owned by root (uid 0), with no write
bit for the group or for others, a regular file (not a link, not a device), in a path that is
already normalized (no `..`, no `.`, no doubled slash), and not named like an agent tool or the
sidecar (their hashes are still taken). These three trees come from packages and hold text written
for people. The exemption is NOT a tree the sandbox can write into: a file under them that the
sandbox user owns, or that anyone can write, or whose path is not exactly under one of the three
prefixes, is scanned like any other file.

What is still checked for such a file, everywhere, and never skipped: its name against the
credential names (`credential-names.txt`: an `id_rsa`, a `.env`, a `*.key` under /usr/share/doc is
still a finding), its mode (`setid.txt`, `world-writable.txt`, `tool-modes.txt`), and that it is
not a device or a fifo (`special.txt`). Only the read of its bytes for the secret patterns is
left out, and `documentation.txt` says how many files and bytes that was, so a change in the size
of the exemption is visible. `selftest-fsaudit.py` shows each of these cases.

`config` reads `docker image inspect` and `docker history --no-trunc` output and prints one
finding per line: an environment name that is not allowed or looks like a secret, a value that
matches a blocking pattern, a declared volume, a health check.

Standard library only.
"""

from __future__ import annotations

import argparse
import fnmatch
import codecs
import hashlib
import json
import posixpath
import re
import sys
import tarfile
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Pattern, Tuple

CHUNK = 8 * 1024 * 1024
OVERLAP = 4096
SMALL_TEXT_LIMIT = 4 * 1024 * 1024
AGENT_TOOL_NAMES = ("claude", "codex", "codex-code-mode-host")
# Files besides the tools that hold the standard output pipe of an exec: the adapters run
# `env -i ... timeout ... <tool>`, and `timeout` keeps the pipe while the tool runs.
EXEC_ONLY_EXTRA = ("/usr/bin/timeout",)
SIDECAR_NAME = "factory-egress-sidecar"

# The trees whose files are text written for people by the distribution's packages. The content of a
# file in them is not read for secret patterns, under the conditions of `is_distro_documentation`.
# Exactly these three, each with its trailing slash, so that `/usr/share/docs/x` and
# `/usr/share/doc-base/x` are not under them.
DOCUMENTATION_PREFIXES = (
    "/usr/share/doc/",
    "/usr/share/common-licenses/",
    "/usr/share/man/",
)

# Names of files that exist only to hold a credential. A CA bundle (*.pem, *.crt) is public and is
# not on this list.
CREDENTIAL_NAMES = (
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".gitconfig",
    ".env",
    ".envrc",
    "credentials",
    "credentials.json",
    ".credentials.json",
    "auth.json",
    ".claude.json",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.kdbx",
    "authorized_keys",
    "known_hosts",
)
CREDENTIAL_DIRS = (".ssh", ".aws", ".claude", ".codex", ".docker", ".kube", ".gnupg", ".config/gh")

# Patterns whose first characters are a distinct vendor prefix. Only these are used on binaries
# and large files, where generic patterns (a URL with a password, a "password=" assignment, a
# bearer header) match example text inside compilers and libraries. Each id maps to a literal
# that must appear in a chunk before the regular expression is run on it.
HIGH_SIGNAL_LITERALS: Dict[str, Tuple[bytes, ...]] = {
    "github_token_classic": (b"ghp_",),
    "github_token_prefixed": (b"gho_", b"ghu_", b"ghs_", b"ghr_"),
    "github_fine_grained": (b"github_pat_",),
    "private_key_block": (b"PRIVATE KEY",),
    "anthropic_api_key": (b"sk-ant-",),
    "openai_api_key": (b"sk-",),
    "aws_access_key_id": (b"AKIA", b"ASIA", b"AGPA", b"AIDA", b"AROA", b"ANPA", b"ANVA"),
    "gcp_api_key": (b"AIza",),
    "slack_token": (b"xox",),
    "stripe_live_key": (b"_live_",),
    "npm_token": (b"npm_",),
    "pypi_token": (b"pypi-AgE",),
    "factory_job_token": (b"sfjt_",),
    "api_token": (b"sfat_",),
}

# A private key header alone is an ordinary string in TLS libraries. A real key has base64 lines
# right after the header, so that is what counts.
PRIVATE_KEY_BODY = re.compile(rb"PRIVATE KEY(?: BLOCK)?-----\r?\n[A-Za-z0-9+/=]{40,}")

ELF_MAGIC = b"\x7fELF"
# Compiled code and data files (a static library, a time zone table, an object file) hold bytes that
# look like a URL with a password by chance: the generic patterns accept almost any non-ASCII byte in
# a user name or a host, so random bytes match them. Such a file gets the same treatment as an ELF
# file: only the patterns with a distinct vendor prefix apply. A file is text, and gets every
# pattern, when its bytes are valid UTF-8 and hold no control byte other than tab, line feed, carriage
# return and form feed. Anything else is binary. The ELF magic is kept as a fast path.
_CONTROL = frozenset(range(0x00, 0x20)) - {0x09, 0x0A, 0x0C, 0x0D}


def looks_compiled(block: bytes) -> bool:
    """True when the block is not text: an ELF file, a control byte, or bytes that are not UTF-8."""
    if block.startswith(ELF_MAGIC):
        return True
    if any(byte in _CONTROL for byte in block):
        return True
    try:
        # `final=False` accepts a multi-byte sequence cut at the end of the block.
        codecs.getincrementaldecoder("utf-8")().decode(block, final=False)
    except UnicodeDecodeError:
        return True
    return False


def read_names(path: Path) -> List[str]:
    names: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return names


def load_patterns(policy: Path) -> List[Tuple[str, Pattern[bytes]]]:
    """Read the blocking patterns from the `secrets:` section of policies/security.yaml."""
    entry = re.compile(
        r"^\s*-\s*\{\s*id:\s*(?P<id>[a-z0-9_]+),\s*regex:\s*'(?P<regex>(?:[^']|'')*)',\s*action:\s*(?P<action>[a-z]+)"
    )
    patterns: List[Tuple[str, Pattern[bytes]]] = []
    in_secrets = False
    for line in policy.read_text(encoding="utf-8").splitlines():
        if re.match(r"^[A-Za-z_]+:", line):
            in_secrets = line.startswith("secrets:")
            continue
        if not in_secrets:
            continue
        match = entry.match(line)
        if match and match.group("action") == "block":
            source = match.group("regex").replace("''", "'")
            patterns.append((match.group("id"), re.compile(source.encode("utf-8"))))
    if len(patterns) < 15:
        raise SystemExit(f"{policy}: found only {len(patterns)} blocking secret patterns, expected at least 15")
    return patterns


def is_executable_or_link(member: tarfile.TarInfo) -> bool:
    if member.issym() or member.islnk():
        return True
    return member.isfile() and (member.mode & 0o111) != 0


def is_distro_documentation(path: str, member: tarfile.TarInfo) -> bool:
    """True for a file whose content the secret scan does not read (see the module notes).

    Everything must hold: a regular file; its path is already normalized and is exactly under one
    of the three prefixes; it belongs to root; nobody but root can write it (no group or other
    write bit); it carries no set-id bit. A file that the sandbox user could have written fails the
    owner or the mode test, so planting a file under these trees never hides its content.
    """
    if not member.isfile():
        return False
    if posixpath.normpath(path) != path or not path.startswith(DOCUMENTATION_PREFIXES):
        return False
    return member.uid == 0 and not member.mode & 0o6022


def matches_any(base: str, patterns: List[str]) -> Optional[str]:
    for pattern in patterns:
        if fnmatch.fnmatchcase(base, pattern):
            return pattern
    return None


def scan_bytes(
    data: bytes,
    patterns: List[Tuple[str, Pattern[bytes]]],
    high_signal_only: bool,
    path: str,
    findings: List[str],
    runtime_minted: FrozenSet[str] = frozenset(),
) -> None:
    for pattern_id, regex in patterns:
        if high_signal_only:
            # A credential that the factory mints at run time cannot be inside a compiled file. Its
            # prefix is, as a constant, and the compiler lays constants side by side with no
            # separator, so the pattern would read the neighbours as part of a token.
            if pattern_id in runtime_minted:
                continue
            literals = HIGH_SIGNAL_LITERALS.get(pattern_id)
            if literals is None or not any(literal in data for literal in literals):
                continue
        for found in regex.finditer(data):
            if pattern_id == "private_key_block":
                window = data[found.start() : found.end() + 200]
                if not PRIVATE_KEY_BODY.search(window):
                    continue
            findings.append(f"{path}: matches {pattern_id} at byte {found.start()}")
            break


def command_fs(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    forbidden = read_names(Path(args.forbidden))
    shells = read_names(Path(args.shells))
    patterns = load_patterns(Path(args.policy))
    known = {value.lower() for value in args.known_sha256}
    runtime_minted = frozenset(args.runtime_minted)

    setid: List[str] = []
    world_writable: List[str] = []
    forbidden_hits: List[str] = []
    shell_hits: List[str] = []
    tool_hits: List[str] = []
    mode_hits: List[str] = []
    sidecar_hits: List[str] = []
    credential_hits: List[str] = []
    special_hits: List[str] = []
    secret_hits: List[str] = []
    skipped: List[str] = []
    files = 0
    scanned_bytes = 0
    documentation_files = 0
    documentation_bytes = 0

    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as archive:
        for member in archive:
            name = member.name[2:] if member.name.startswith("./") else member.name
            path = "/" + name.lstrip("/")
            base = path.rstrip("/").rsplit("/", 1)[-1]

            if member.isfile() or member.islnk():
                files += 1
                if member.mode & 0o6000:
                    setid.append(f"{path} mode {member.mode & 0o7777:04o}")
                if member.isfile() and (base in AGENT_TOOL_NAMES or path in EXEC_ONLY_EXTRA):
                    mode_hits.append(f"{path} mode {member.mode & 0o7777:04o}")

            if (member.isfile() or member.isdir()) and member.mode & 0o002 and not member.mode & 0o1000:
                world_writable.append(f"{path} mode {member.mode & 0o7777:04o}")

            if member.isdev() or member.isfifo():
                if not path.startswith("/dev/"):
                    special_hits.append(f"{path} (special file)")

            if is_executable_or_link(member):
                hit = matches_any(base, forbidden)
                if hit:
                    target = f" -> {member.linkname}" if member.issym() else ""
                    forbidden_hits.append(f"{path}{target} (matches {hit})")
                if base in shells:
                    target = f" -> {member.linkname}" if member.issym() else ""
                    shell_hits.append(f"{path}{target}")
                if base in AGENT_TOOL_NAMES:
                    target = f" -> {member.linkname}" if member.issym() else ""
                    tool_hits.append(f"{path}{target}")

            if (member.isfile() or member.issym()) and matches_any(base, list(CREDENTIAL_NAMES)):
                credential_hits.append(path)
            for directory in CREDENTIAL_DIRS:
                if member.isdir() and path.rstrip("/").endswith("/" + directory):
                    credential_hits.append(path + "/")

            if not member.isfile() or member.size == 0:
                continue
            if (
                base not in AGENT_TOOL_NAMES
                and base != SIDECAR_NAME
                and is_distro_documentation(path, member)
            ):
                # Names, modes and kinds were judged above. Only the read of the bytes is left out.
                documentation_files += 1
                documentation_bytes += member.size
                continue
            handle = archive.extractfile(member)
            if handle is None:
                continue
            is_tool = base in AGENT_TOOL_NAMES
            is_sidecar = base == SIDECAR_NAME
            digest = hashlib.sha256() if (is_tool or is_sidecar) else None
            block = handle.read(CHUNK)
            if digest is not None:
                digest.update(block)
            file_findings: List[str] = []
            if member.size <= SMALL_TEXT_LIMIT and not looks_compiled(block):
                # The whole file is in this one block. Every blocking pattern applies.
                scan_bytes(block, patterns, False, path, file_findings)
                scanned_bytes += len(block)
            else:
                carry = b""
                while block:
                    window = carry + block
                    scan_bytes(window, patterns, True, path, file_findings, runtime_minted)
                    scanned_bytes += len(block)
                    carry = window[-OVERLAP:]
                    block = handle.read(CHUNK)
                    if digest is not None:
                        digest.update(block)
            if digest is not None and is_sidecar:
                sidecar_hits.append(f"{path} sha256 {digest.hexdigest()}")
            elif digest is not None:
                value = digest.hexdigest()
                tool_hits.append(f"{path} sha256 {value}")
                if value in known:
                    skipped.append(f"{path}: pinned vendor binary, sha256 {value}; matches in it are ignored")
                    file_findings = []
                else:
                    skipped.append(f"{path}: sha256 {value} is not a pinned value, so its matches are kept")
            secret_hits.extend(sorted(set(file_findings)))

    outputs = {
        "setid.txt": setid,
        "world-writable.txt": world_writable,
        "forbidden.txt": forbidden_hits,
        "shells.txt": shell_hits,
        "agent-tools.txt": tool_hits,
        "tool-modes.txt": mode_hits,
        "sidecar-binary.txt": sidecar_hits,
        "credential-names.txt": credential_hits,
        "special.txt": special_hits,
        "secrets.txt": secret_hits,
        "skipped.txt": skipped,
    }
    for name, lines in outputs.items():
        (out_dir / name).write_text("".join(f"{line}\n" for line in sorted(set(lines))), encoding="utf-8")
    (out_dir / "documentation.txt").write_text(
        f"{documentation_files} distro documentation file(s), {documentation_bytes} byte(s), "
        f"under {', '.join(DOCUMENTATION_PREFIXES)}: owned by root, not writable by group or others; "
        "content not scanned, names and modes still audited\n",
        encoding="utf-8",
    )
    (out_dir / "summary.txt").write_text(
        f"files {files}\nscanned_bytes {scanned_bytes}\npatterns {len(patterns)}\n"
        f"documentation_files_not_read {documentation_files}\n",
        encoding="utf-8",
    )
    return 0


SECRET_NAME = re.compile(r"(?i)(token|secret|passw|api_?key|credential|private_?key|auth)")


def forbidden_env_names(policy: Path) -> List[str]:
    """The `forbidden_names` list of sandbox.required.environment in policies/security.yaml."""
    for line in policy.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^\s*forbidden_names:\s*\[(?P<names>[^\]]*)\]", line)
        if match:
            return [name.strip() for name in match.group("names").split(",") if name.strip()]
    raise SystemExit(f"{policy}: no forbidden_names list found")


def command_config(args: argparse.Namespace) -> int:
    patterns = load_patterns(Path(args.policy))
    forbidden = forbidden_env_names(Path(args.policy))
    allowed = set(args.allowed_env)
    inspected = json.loads(Path(args.inspect).read_text(encoding="utf-8"))[0]
    config = inspected.get("Config") or {}
    findings: List[str] = []

    def scan_text(label: str, value: str) -> None:
        for pattern_id, regex in patterns:
            if regex.search(value.encode("utf-8")):
                findings.append(f"{label} matches secret pattern {pattern_id}")

    for item in config.get("Env") or []:
        name, _, value = item.partition("=")
        if name in forbidden:
            findings.append(f"environment name {name} is forbidden by the sandbox policy")
        if name not in allowed:
            findings.append(f"environment name {name} is not on the allowed list for this image")
        if SECRET_NAME.search(name):
            findings.append(f"environment name {name} looks like a secret")
        scan_text(f"environment value of {name}", value)
    for key, value in (config.get("Labels") or {}).items():
        scan_text(f"label {key}", str(value))
    for field in ("Cmd", "Entrypoint"):
        for part in config.get(field) or []:
            scan_text(f"{field} word", str(part))
    if config.get("Volumes"):
        findings.append("the image declares VOLUME entries: " + ", ".join(sorted(config["Volumes"])))
    if config.get("Healthcheck"):
        findings.append("the image declares a health check")
    if config.get("OnBuild"):
        findings.append("the image declares ONBUILD instructions")
    for number, line in enumerate(Path(args.history).read_text(encoding="utf-8").splitlines(), start=1):
        scan_text(f"history line {number}", line)

    for finding in findings:
        print(finding)
    return 0


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    fs = sub.add_parser("fs", help="audit the file system from a tar stream on standard input")
    fs.add_argument("--out-dir", required=True)
    fs.add_argument("--forbidden", required=True)
    fs.add_argument("--shells", required=True)
    fs.add_argument("--policy", required=True)
    fs.add_argument(
        "--known-sha256",
        action="append",
        default=[],
        help="SHA-256 of a vendor binary that was pinned and checked at build time; matches inside it are ignored",
    )
    fs.add_argument(
        "--runtime-minted",
        action="append",
        default=[],
        metavar="PATTERN_ID",
        help=(
            "id of a pattern for a credential that the factory mints at run time (for example "
            "factory_job_token). It is applied to text files and not to compiled or large files, "
            "where only the constant prefix of such a credential can appear"
        ),
    )
    fs.set_defaults(handler=command_fs)

    config = sub.add_parser("config", help="audit image configuration and history")
    config.add_argument("--inspect", required=True)
    config.add_argument("--history", required=True)
    config.add_argument("--policy", required=True)
    config.add_argument("--allowed-env", action="append", default=[])
    config.set_defaults(handler=command_config)

    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
