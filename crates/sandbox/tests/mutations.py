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
    "a-mount-of-a-sensitive-tree": (
        "a bind mount of `/`, `/etc` or `/proc` is allowed even when the pair is on the list",
        [(POSTURE_ARGS, "    if sensitive {", "    if false && sensitive {")],
    ),
    "a-source-outside-the-allowlist": (
        "a bind mount of a source the factory does not provision is allowed (RR-11)",
        [(POSTURE_ARGS, "    if !binds.contains(source, destination) {",
          "    if false && !binds.contains(source, destination) {")],
    ),
    "a-mount-key-in-another-case": (
        "a mount key is read as written, so `SRC=/etc` after `src=/tmp/ok` is not seen (RR-10)",
        [(POSTURE_ARGS, "        match go_lower(raw_key).as_str() {", "        match raw_key {")],
    ),
    "the-first-mount-source-wins": (
        "the first `src` is the effective one, where Docker takes the last (RR-10)",
        [(POSTURE_ARGS, '            "src" | "source" => source = Some(setting),',
          '            "src" | "source" => source = source.or(Some(setting)),')],
    ),
    "a-tmpfs-with-exec": (
        "a scratch tmpfs may be executable, setuid and device-bearing (RR-12)",
        [(POSTURE_ARGS, '        if matches!(option.as_str(), "exec" | "suid" | "dev") {', "        if false {")],
    ),
    "a-negative-ulimit": (
        "`--ulimit core=-1` and the other unlimited values are allowed (RR-12)",
        [(POSTURE_ARGS, "    (!plain || limits.split(':').count() > 2)",
          "    (false && (!plain || limits.split(':').count() > 2))")],
    ),
    "init-switched-off": (
        "`--init=false` is allowed (RR-12)",
        [(POSTURE_ARGS, '        "--init" => switched_off(given).then(|| "no init process".to_owned()),',
          '        "--init" => None,')],
    ),
    "a-name-that-ends-in-a-blank": (
        "a name that ends in a no-break space is accepted (RR-13)",
        [(AUDIT, "        || chars.last().copied().is_some_and(prints_blank)", "        || false")],
    ),
    "a-variation-selector-with-no-base": (
        "a variation selector after an ASCII letter is accepted (RR-13)",
        [(AUDIT, "            if !keycap && !takes_one {", "            if false && !keycap && !takes_one {")],
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
         "kind(lib) | binary(scripted) | binary(security_rereview) | (binary(security_review) & (test(sbx_1) | test(sbx_2)))"],
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
