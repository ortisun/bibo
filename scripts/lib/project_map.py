#!/usr/bin/env python3
"""Check that a project has been mapped by `egm-bootstrap`: every directory that holds code has a contract file.

The factory accepts tickets from a repository only after a person ran EGM's bootstrap over it, read the result and
merged it (ADR 0016). This script is the check that backs that step. It does not run the bootstrap and it cannot
judge whether the contracts are good. It answers one question: which directories that hold code have no contract?

It follows the pruning rules of the bootstrap skill (skills/egm-bootstrap/SKILL.md, step 2), so a directory the
skill would skip is not asked for a contract:
  * only files tracked by git or not ignored by it count (.gitignore), and .egmignore patterns are honored;
  * hidden directories (any name that starts with a dot, such as .git and .github) and system directories
    (node_modules, venv, dist, build, third_party, target) are skipped. The installer's own helper lives in
    .github/scripts, and it must not make a project look unmapped;
  * a directory counts when it directly holds a source file, or a directory below it counts;
  * a directory named tests, testing or testdata, and everything below it, is test-only and is skipped;
  * the root always needs a contract.

A contract is a file named README.md or EGM.md (the skill writes EGM.md when human READMEs must not change).

Usage:  project_map.py check PATH [--contract NAME ...]
Exit codes: 0 every directory has a contract, 1 some do not (they are listed), 2 wrong arguments or no such directory.
"""
from __future__ import annotations

import argparse
import fnmatch
import os
import re
import subprocess
import sys

SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".rs", ".go", ".zig", ".lean",
    ".java", ".kt", ".scala", ".cs", ".fs",
    ".py", ".rb", ".php", ".lua", ".sh", ".bash",
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".swift", ".m", ".dart",
    ".sql", ".proto", ".graphql", ".gql", ".thrift", ".prisma",
    ".tf", ".hcl", ".cue",
}
SKIPPED_DIRECTORIES = {".git", ".antigravity", "node_modules", "venv", ".venv", "dist", "build", "third_party", "target"}
TEST_DIRECTORIES = {"tests", "testing", "testdata"}
DEFAULT_CONTRACTS = ("README.md", "EGM.md")


MAX_FILES = 500_000
MAX_EGMIGNORE_BYTES = 64 * 1024
MAX_PATTERNS = 500
MAX_PATTERN_CHARS = 200


def _git_files(root):
    """The files git would track or could add (so .gitignore applies), or None when `root` is not a git work tree.

    The checkout is not trusted: its .git/config can name a `core.fsmonitor` command that git would run, so the options
    that run commands are switched off for this call.
    """
    environment = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
    try:
        done = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", root,
                               "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                              capture_output=True, check=False, env=environment)
    except OSError:
        return None
    if done.returncode != 0:
        return None
    return [p for p in done.stdout.decode("utf-8", "replace").split("\0") if p]


def _walk_files(root):
    found = []
    for base, directories, files in os.walk(root):
        directories[:] = [d for d in directories
                          if d not in SKIPPED_DIRECTORIES and not d.startswith(".") and not os.path.islink(os.path.join(base, d))]
        for name in files:
            found.append(os.path.relpath(os.path.join(base, name), root))
        if len(found) > MAX_FILES:
            raise ValueError("more than %d files: this is not a project to map by hand" % MAX_FILES)
    return found


def _egmignore(root):
    """The patterns of .egmignore. A link is not followed, and the file, the number of patterns and their length are capped."""
    path = os.path.join(root, ".egmignore")
    if os.path.islink(path) or not os.path.isfile(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read(MAX_EGMIGNORE_BYTES)
    except OSError:
        return []
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    return [line for line in lines if len(line) <= MAX_PATTERN_CHARS][:MAX_PATTERNS]


def _compile(patterns):
    return [re.compile(fnmatch.translate(pattern.strip("/"))) for pattern in patterns]


def _ignored(relative, compiled):
    parts = relative.split("/")
    prefixes = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
    return any(rx.match(relative) or any(rx.match(part) for part in parts) or any(rx.match(prefix) for prefix in prefixes)
               for rx in compiled)


def directories_needing_a_contract(root):
    """The directories (relative to `root`, "" for the root) that hold code, directly or below."""
    files = _git_files(root)
    if files is None:
        files = _walk_files(root)
    patterns = _compile(_egmignore(root))
    needed = {""}
    for relative in files:
        relative = relative.replace(os.sep, "/")
        parts = relative.split("/")
        directories = parts[:-1]
        if any(d in SKIPPED_DIRECTORIES or d in TEST_DIRECTORIES or d.startswith(".") for d in directories):
            continue
        if _ignored(relative, patterns):
            continue
        if os.path.splitext(parts[-1])[1].lower() not in SOURCE_EXTENSIONS:
            continue
        if not os.path.isfile(os.path.join(root, relative)):
            continue  # listed by git but deleted from the work tree
        for depth in range(len(directories) + 1):
            needed.add("/".join(directories[:depth]))
    return sorted(needed)


def missing_contracts(root, contracts=DEFAULT_CONTRACTS, needed=None):
    needed = directories_needing_a_contract(root) if needed is None else needed
    return [d for d in needed if not any(os.path.isfile(os.path.join(root, d, name)) for name in contracts)]


def main(argv=None):
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check")
    check.add_argument("path")
    check.add_argument("--contract", action="append", help="a contract file name; default README.md and EGM.md")
    args = parser.parse_args(argv)
    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print("no such directory: %s" % args.path, file=sys.stderr)
        return 2
    contracts = tuple(args.contract) if args.contract else DEFAULT_CONTRACTS
    try:
        needed = directories_needing_a_contract(root)
    except ValueError as error:
        print("FAIL %s" % error, file=sys.stderr)
        return 2
    missing = missing_contracts(root, contracts, needed)
    for directory in missing:
        print("MISSING %s" % (directory or "."))
    print("%s: %d of %d directories that hold code have a contract (%s)"
          % ("MAPPED" if not missing else "NOT MAPPED", len(needed) - len(missing), len(needed), " or ".join(contracts)))
    return 0 if not missing else 1


if __name__ == "__main__":
    sys.exit(main())
