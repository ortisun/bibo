"""Deliberate breaks of the pin of the git image of the hostile-repository test, each of which a test must catch.

    python3 -I crates/testkit/tests/mutations/git_image_breaks.py [WORD ...]

For each break the script changes one place in `crates/testkit/src/fx/repos/tests.rs` (the old text must occur
exactly once), runs the two tests named below, and puts the file back. A break is CAUGHT when a test fails (the
hostile-repository test fails with BLOCKED when the Docker daemon does not hold the image it names), MISSED when they
pass, and INVALID when the changed source does not compile. The script exits with 1 if any break is MISSED or INVALID.
It leaves the working tree as it found it, also when it is interrupted, but run it on a clean tree. It needs the Docker
daemon and the image of the digest, as the hostile-repository test does.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
TESTS = "crates/testkit/src/fx/repos/tests.rs"
DIGEST = "sha256:ac6c828f15d82775d204d3d75112e1d34af8945da80ccf922713c9891ba68e7a"

COMMAND = ["cargo", "test", "-p", "factory-testkit", "--offline", "--lib", "--",
           "fx::repos::tests::hostile_git_configuration", "fx::repos::tests::the_default_git_image"]

# (name, [(file, old, new)])
BREAKS = [
    (
        "the default is the moving tag again",
        [(TESTS, f'    "alpine/git@{DIGEST}";', '    "alpine/git:latest";')],
    ),
    (
        "the digest loses its last character",
        [(TESTS, f'    "alpine/git@{DIGEST}";', f'    "alpine/git@{DIGEST[:-1]}";')],
    ),
    (
        "the digest is in capital letters",
        [(TESTS, f'    "alpine/git@{DIGEST}";', f'    "alpine/git@sha256:{DIGEST[7:].upper()}";')],
    ),
    (
        "the digest names an image that the machine does not hold",
        [(TESTS, f'    "alpine/git@{DIGEST}";', f'    "alpine/git@sha256:{"0" * 64}";')],
    ),
    (
        "the digest is that of another repository's image",
        [(TESTS, f'    "alpine/git@{DIGEST}";', f'    "library/alpine@{DIGEST}";')],
    ),
]


def run():
    done = subprocess.run(COMMAND, cwd=ROOT, capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def main():
    originals = {}
    outcomes = []
    only = sys.argv[1:]
    try:
        for name, edits in BREAKS:
            if only and not any(word in name for word in only):
                continue
            texts = {}
            for file, old, new in edits:
                path = ROOT / file
                originals.setdefault(file, path.read_text())
                text = texts.get(file, originals[file])
                if text.count(old) != 1:
                    raise SystemExit(f"{name}: the text to change occurs {text.count(old)} times in {file}")
                texts[file] = text.replace(old, new)
            for file, text in texts.items():
                (ROOT / file).write_text(text)
            code, output = run()
            for file in texts:
                (ROOT / file).write_text(originals[file])
            if "could not compile" in output or "error[E" in output:
                verdict = "INVALID (does not compile)"
            elif code == 0:
                verdict = "MISSED"
            else:
                failed = sorted({line.split()[1] for line in output.splitlines() if line.startswith("test ") and line.endswith("FAILED")})
                verdict = "CAUGHT by " + "; ".join(failed)
            outcomes.append((name, verdict))
            print(f"{name}: {verdict}", flush=True)
    finally:
        for file, text in originals.items():
            (ROOT / file).write_text(text)
    bad = [o for o in outcomes if not o[1].startswith("CAUGHT")]
    print(f"{len(outcomes) - len(bad)} of {len(outcomes)} breaks caught")
    sys.exit(1 if bad else 0)


main()
