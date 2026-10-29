#!/usr/bin/env python3
"""Deliberate breaks of the success rule of the agent adapters (findings RTM-1, RR-7, RR-8, RR-9
and RR-14 of the security reviews of the isolation core), to show that the tests catch each one.

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
TRUST = "crates/runtime/src/trust.rs"
ATTEST = "crates/runtime/src/attest.rs"

# name -> (what is broken, [(file, old, new), ...])
MUTATIONS = {
    "claude-success-without-the-exit-check": (
        "a result that says completed is a success whatever became of the process",
        [(CLAUDE, "        let clean_exit = exit.code == Some(0) && result.signal.is_none();",
          "        let clean_exit = true;")],
    ),
    "codex-success-ignores-the-signal": (
        "a turn.completed with exit code 0 is a success although a signal ended the process (RR-9)",
        [(CODEX, "    if stream.completed && exit.code == Some(0) && result.signal.is_none() {",
          "    if stream.completed && exit.code == Some(0) {")],
    ),
    "stream-rule-off": (
        "the shape of the stream is not looked at at all (RR-7, RR-8, RTM-1)",
        [(TRUST, "pub fn check_shape(shape: &Shape) -> Result<(), Distrust> {\n    if shape.truncated {",
          "pub fn check_shape(shape: &Shape) -> Result<(), Distrust> {\n    if true {\n        return Ok(());\n    }\n    if shape.truncated {")],
    ),
    "stream-torn-line-ignored": (
        "a line before the terminal event that is not a JSON object does not stop a success (RR-7)",
        [(TRUST, "    } else if shape.malformed_before > 0 {\n        Err(Distrust::MalformedLine)\n    } else if",
          "    } else if")],
    ),
    "stream-cut-capture-ignored": (
        "a capture cut at the output limit does not stop a success (RR-8)",
        [(TRUST, "    if shape.truncated {\n        Err(Distrust::StreamTruncated)\n    } else if",
          "    if false {\n        Err(Distrust::StreamTruncated)\n    } else if")],
    ),
    "stream-second-terminal-ignored": (
        "a second terminal event does not stop a success",
        [(TRUST, "    } else if shape.terminal_events > 1 {\n        Err(Distrust::SecondTerminalEvent)\n    } else if",
          "    } else if")],
    ),
    "stream-output-after-terminal-ignored": (
        "a line after the terminal event does not stop a success",
        [(TRUST, "    } else if shape.lines_after > 0 {\n        Err(Distrust::OutputAfterTerminalEvent)\n    } else {",
          "    } else {")],
    ),
    "attestation-skipped": (
        "a stream that says completed is a success whatever the broker saw (RR-14)",
        [(ATTEST, "        if end.outcome.is_err() {\n            return end;\n        }",
          "        if true {\n            return end;\n        }")],
    ),
    "attestation-ignores-the-last-answer": (
        "a run whose last answer asked for a tool, was cut or failed is attested (RR-14)",
        [(ATTEST, "        || after.last_answer != Some(AnswerEnd::EndTurn)\n", "\n")],
    ),
    "attestation-ignores-the-baseline": (
        "an earlier run of the same token attests this one (RR-14)",
        [(ATTEST, "    let answers = after.answers.saturating_sub(before.answers);\n    let requests = after.usage.requests.saturating_sub(before.usage.requests);",
          "    let answers = after.answers;\n    let requests = after.usage.requests;")],
    ),
    "attestation-ignores-the-claim": (
        "a stream that claims more turns or tokens than the broker metered is attested (RR-14)",
        [(ATTEST, "    if claim.turns > answers.saturating_add(REQUEST_SLACK)", "    if false && claim.turns > answers.saturating_add(REQUEST_SLACK)")],
    ),
}


def run_tests() -> tuple[bool, list[str]]:
    """Returns (compiled, failed test names)."""
    proc = subprocess.run(
        ["cargo", "nextest", "run", "-p", "factory-runtime", "--no-fail-fast", "-E",
         "kind(lib) | binary(security_review) | binary(security_rereview) | binary(stream_rule)"],
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
