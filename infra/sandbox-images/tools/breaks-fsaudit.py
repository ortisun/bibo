"""Deliberate breaks of the `--runtime-minted` option of fsaudit.py (finding DR-5), each of which
`selftest-fsaudit.py` must catch.

    python3 -I infra/sandbox-images/tools/breaks-fsaudit.py [WORD ...]

For each break the script changes one place in `fsaudit.py` (the old text must occur exactly once),
runs `selftest-fsaudit.py`, and puts the file back. A break is CAUGHT when the self-test fails and
MISSED when it passes. The script exits with 1 if any break is MISSED. It leaves the file as it found
it, also when it is interrupted, but run it on a clean tree. Words after the script name select the
breaks whose name contains one of them. Standard library only.
"""

import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
TARGET = HERE / "fsaudit.py"
SELFTEST = HERE / "selftest-fsaudit.py"

GIVEN_UP = "given_up = runtime_minted if compiled else frozenset()"
BREAKS = [
    (
        "DR-5: a text file over the limit gives the patterns up too (the old behaviour)",
        GIVEN_UP,
        "given_up = runtime_minted if (compiled or member.size > SMALL_TEXT_LIMIT) else frozenset()",
    ),
    (
        "DR-5: the patterns are given up for every file that reaches the windowed scan",
        GIVEN_UP,
        "given_up = runtime_minted",
    ),
    (
        "DR-5: the patterns are never given up, so the glued constants of a program are findings",
        GIVEN_UP,
        "given_up = frozenset()",
    ),
    (
        "DR-5: a non-ELF binary is not treated as compiled (only the ELF magic counts)",
        "    if any(byte in _CONTROL for byte in block):\n        return True\n",
        "    if False:\n        return True\n",
    ),
    (
        "DR-5: a file is taken for compiled whatever its bytes are",
        "compiled = looks_compiled(block)",
        "compiled = True",
    ),
]


def main() -> None:
    original = TARGET.read_text()
    only = sys.argv[1:]
    outcomes = []
    try:
        for name, old, new in BREAKS:
            if only and not any(word in name for word in only):
                continue
            if original.count(old) != 1:
                raise SystemExit(f"{name}: the text to change occurs {original.count(old)} times")
            TARGET.write_text(original.replace(old, new))
            done = subprocess.run(
                [sys.executable, "-I", str(SELFTEST)], capture_output=True, text=True, check=False
            )
            TARGET.write_text(original)
            if done.returncode == 0:
                verdict = "MISSED"
            else:
                failed = [line[6:].strip() for line in done.stdout.splitlines() if line.startswith("FAIL")]
                shown = "; ".join(failed[:2]) + (f"; and {len(failed) - 2} more" if len(failed) > 2 else "")
                verdict = "CAUGHT by " + (shown or "an error of the self-test")
            outcomes.append((name, verdict))
            print(f"{name}: {verdict}", flush=True)
    finally:
        TARGET.write_text(original)
    missed = [o for o in outcomes if not o[1].startswith("CAUGHT")]
    print(f"{len(outcomes) - len(missed)} of {len(outcomes)} breaks caught")
    sys.exit(1 if missed else 0)


main()
