#!/usr/bin/env python3
"""Deliberate breaks of the sandbox controls fixed after the isolation core review, to show that the
tests catch each one.

Run from the repository root:  python3 -I crates/sandbox/tests/mutations.py [name ...]

For each break the script rewrites one place in the sources (it refuses a replacement that does not
match exactly once), runs the tests that need no Docker daemon (the unit tests, the scripted
provider tests and the review tests SBX-1, SBX-2 and SBX-3), prints the tests that failed, and puts
the sources back. A break that no test catches is reported as MISSED and the script exits with 1.
The script stops if the tree has changes in crates/sandbox when it starts, so a restore can never
lose work.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
POSTURE_ARGS = "crates/sandbox/src/container/posture_args.rs"
AUDIT = "crates/sandbox/src/workspace/audit.rs"
WATCHDOG = "crates/sandbox/src/supervisor/watchdog.rs"

# name -> (what is broken, [(file, old, new), ...])
MUTATIONS = {
    "a-deny-list-spelling": (
        "`--cgroupns host` is no longer read as a namespace of the host",
        [(POSTURE_ARGS, '    "--userns",\n    "--cgroupns",\n];', '    "--userns",\n];')],
    ),
    "a-seccomp-colon-option": (
        "a security option is read only up to `=`, so `seccomp:unconfined` is a key this list does not know and is allowed",
        [(POSTURE_ARGS, "    let allowed = key == \"no-new-privileges\" && matches!(setting, \"\" | \"true\");",
          "    let allowed = key.starts_with(\"no-new-privileges\") || key.starts_with(\"seccomp\");")],
    ),
    "a-mount-of-the-host-root": (
        "a bind mount of `/`, `/etc` or `/proc` is allowed",
        [(POSTURE_ARGS, "        if host_root || system {", "        if false && (host_root || system) {")],
    ),
    "a-limit-of-zero": (
        "a process limit of -1 or 0 is allowed",
        [(POSTURE_ARGS, "        .and_then(|v| v.parse::<i64>().ok())\n        .is_some_and(|n| n > 0)",
          "        .and_then(|v| v.parse::<i64>().ok())\n        .is_some_and(|n| n > -2)")],
    ),
    "a-bidi-file-name": (
        "the bidirectional controls, the separators and the byte order mark are accepted in a name",
        [(AUDIT, "            | '\\u{2028}'..='\\u{202E}'\n", ""),
         (AUDIT, "            | '\\u{FEFF}'\n", "")],
    ),
    "a-tag-character-name": (
        "tag characters are accepted in a name",
        [(AUDIT, "            | '\\u{E0000}'..='\\u{E0FFF}'\n", "")],
    ),
    "a-failed-disk-measurement-as-zero": (
        "a disk measurement that failed is read as zero bytes",
        [(WATCHDOG, "let measured = disk_usage_kib(&shared.docker, &container).await;",
          "let measured = disk_usage_kib(&shared.docker, &container).await.or(Some(0));")],
    ),
    "a-container-that-is-never-stopped-for-an-unmeasured-disk": (
        "the count of failed polls never reaches the limit",
        [(WATCHDOG, "            if *unmeasured >= MAX_UNMEASURED_POLLS {\n                Poll::Kill(Stop::DiskUnmeasured)",
          "            if *unmeasured >= u32::MAX {\n                Poll::Kill(Stop::DiskUnmeasured)")],
    ),
}


def run_tests() -> tuple[bool, list[str]]:
    """Returns (compiled, failed test names)."""
    proc = subprocess.run(
        ["cargo", "nextest", "run", "-p", "factory-sandbox", "--no-fail-fast", "-E",
         "kind(lib) | binary(scripted) | (binary(security_review) & (test(sbx_1) | test(sbx_2)))"],
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
        ["git", "status", "--porcelain", "crates/sandbox"],
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
                text = file.read_text()
                originals.setdefault(path, text)
                current = file.read_text()
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
        ["git", "status", "--porcelain", "crates/sandbox"],
        cwd=ROOT, capture_output=True, text=True,
    ).stdout.strip()
    if clean:
        print("the sources were not restored:\n" + clean)
        return 2
    print("all sources restored")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
