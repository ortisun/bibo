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


def _git_files(root):
    """The files git would track or could add (so .gitignore applies), or None when `root` is not a git work tree."""
    try:
        done = subprocess.run(["git", "-C", root, "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                              capture_output=True, check=False)
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
    return found


def _egmignore(root):
    path = os.path.join(root, ".egmignore")
    try:
        with open(path, encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip() and not line.startswith("#")]
    except OSError:
        return []


def _ignored(relative, patterns):
    parts = relative.split("/")
    for pattern in patterns:
        pattern = pattern.strip("/")
        if fnmatch.fnmatch(relative, pattern) or any(fnmatch.fnmatch(part, pattern) for part in parts) \
                or any(fnmatch.fnmatch("/".join(parts[:i]), pattern) for i in range(1, len(parts) + 1)):
            return True
    return False


def directories_needing_a_contract(root):
    """The directories (relative to `root`, "" for the root) that hold code, directly or below."""
    files = _git_files(root)
    if files is None:
        files = _walk_files(root)
    patterns = _egmignore(root)
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


def missing_contracts(root, contracts=DEFAULT_CONTRACTS):
    return [d for d in directories_needing_a_contract(root)
            if not any(os.path.isfile(os.path.join(root, d, name)) for name in contracts)]


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
    needed = directories_needing_a_contract(root)
    missing = missing_contracts(root, contracts)
    for directory in missing:
        print("MISSING %s" % (directory or "."))
    print("%s: %d of %d directories that hold code have a contract (%s)"
          % ("MAPPED" if not missing else "NOT MAPPED", len(needed) - len(missing), len(needed), " or ".join(contracts)))
    return 0 if not missing else 1


if __name__ == "__main__":
    sys.exit(main())
