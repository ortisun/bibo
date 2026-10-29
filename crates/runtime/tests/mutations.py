#!/usr/bin/env python3
"""Deliberate breaks of the success rule of the agent adapters (findings RTM-1 and SBX-4 of the
isolation core review), to show that the tests catch each one.

Run from the repository root:  python3 -I crates/runtime/tests/mutations.py [name ...]

For each break the script rewrites one place in the sources (it refuses a replacement that does not
match exactly once), runs the unit tests and the review tests of the runtime package (they need no
Docker daemon), prints the tests that failed, and puts the sources back. A break that no test
catches is reported as MISSED and the script exits with 1. The script stops if the tree has
changes in crates/runtime when it starts, so a restore can never lose work.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
CLAUDE = "crates/runtime/src/claude/mod.rs"
CODEX = "crates/runtime/src/codex/mod.rs"

# name -> (what is broken, [(file, old, new), ...])
MUTATIONS = {
    "claude-success-without-the-exit-check": (
        "a result that says completed is a success whatever became of the process",
        [(CLAUDE, "        let clean_exit = exit.code == Some(0) && result.signal.is_none();",
          "        let clean_exit = true;")],
    ),
    "claude-success-with-a-second-result": (
        "a second result event, or an event after the result, does not stop a success",
        [(CLAUDE, "        let one_result_last = stream.result_events == 1 && !stream.events_after_result;",
          "        let one_result_last = true;")],
    ),
    "codex-success-with-a-second-completion": (
        "a second turn.completed, or an item after it, does not stop a success",
        [(CODEX, "        && stream.completed_events == 1\n        && !stream.events_after_completed\n", "\n")],
    ),
}


def run_tests() -> tuple[bool, list[str]]:
    """Returns (compiled, failed test names)."""
    proc = subprocess.run(
        ["cargo", "nextest", "run", "-p", "factory-runtime", "--no-fail-fast", "-E",
         "kind(lib) | binary(security_review)"],
        cwd=ROOT, capture_output=True, text=True,
    )
    text = proc.stdout + proc.stderr
    if "could not compile" in text or "error[E" in text:
        return False, []
    failed = sorted(set(re.findall(r"^\s+FAIL \[[^\]]*\] \(\s*\d+/\d+\) (.+)$", text, re.M)))
    return True, failed


def main() -> int:
    wanted = sys.argv[1:] or list(MUTATIONS)
    dirty = subprocess.run(
        ["git", "status", "--porcelain", "crates/runtime"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout.strip()
    if dirty:
        print("refusing to run: there are uncommitted changes in the package:\n" + dirty)
        return 2
    missed = []
    for name in wanted:
        what, edits = MUTATIONS[name]
        originals: dict[str, str] = {}
        try:
            for path, old, new in edits:
                file = ROOT / path
                current = file.read_text()
                originals.setdefault(path, current)
                if current.count(old) != 1:
                    print(f"{name}: the text to replace occurs {current.count(old)} times in {path}")
                    return 2
                file.write_text(current.replace(old, new))
            compiled, failed = run_tests()
        finally:
            for path, text in originals.items():
                (ROOT / path).write_text(text)
        if not compiled:
            print(f"BROKEN BUILD  {name}: {what}")
            missed.append(name)
        elif failed:
            print(f"CAUGHT  {name}: {what}")
            for test in failed[:6]:
                print(f"          {test}")
            if len(failed) > 6:
                print(f"          ... and {len(failed) - 6} more")
        else:
            print(f"MISSED  {name}: {what}")
            missed.append(name)
        sys.stdout.flush()
    clean = subprocess.run(
        ["git", "status", "--porcelain", "crates/runtime"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout.strip()
    if clean:
        print("the sources were not restored:\n" + clean)
        return 2
    print("all sources restored")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
