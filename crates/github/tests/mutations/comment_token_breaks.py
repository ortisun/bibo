"""Deliberate breaks of the token a comment is posted with (SF-14), each of which a test must catch.

    python3 -I crates/github/tests/mutations/comment_token_breaks.py [WORD]

With a word, only the breaks whose name contains it are run.

A comment needs `issues: write` and `metadata: read` and nothing else. For each break the script
changes one place in the source of `factory-github` (the old text must occur exactly once), runs the
tests named for it with `cargo nextest`, and puts the file back. A break is CAUGHT when the tests
fail, MISSED when they pass, and INVALID when the changed source does not compile. The script exits
with 1 if any break is MISSED or INVALID. It leaves the working tree as it found it, also when it is
interrupted, but run it on a clean tree.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
PERMISSIONS = "crates/github/src/permissions.rs"
TOKEN = "crates/github/src/token.rs"
CHANGES = "crates/github/src/changes.rs"

SUITE = ["-p", "factory-github", "--lib", "--test", "negative_tokens", "--test", "fake_host_permissions", "--test", "issue_status"]

# (name, [(file, old, new)])
BREAKS = [
    (
        "SF-14: a comment is posted with the token of its stage again",
        [(TOKEN, '                Ok(if own.holds("issues", Level::Write) {\n                    PermissionSet::comment()\n                } else {\n                    own\n                })', "                Ok(own)")],
    ),
    (
        "SF-14: a stage that may not write issues is given the comment token, so a read-only stage can comment",
        [(TOKEN, '                Ok(if own.holds("issues", Level::Write) {\n                    PermissionSet::comment()', "                Ok(if own.holds(\"issues\", Level::Write) || true {\n                    PermissionSet::comment()")],
    ),
    (
        "SF-14: the comment class also asks for the contents of the repository",
        [(PERMISSIONS, 'Self::of(&[("metadata", Level::Read), ("issues", Level::Write)])\n    }\n\n    /// The credential of the status writer', 'Self::of(&[\n            ("metadata", Level::Read),\n            ("issues", Level::Write),\n            ("contents", Level::Read),\n        ])\n    }\n\n    /// The credential of the status writer')],
    ),
    (
        "SF-14: the search for the marker of a comment uses the token of the stage",
        [(CHANGES, "            .get_pages_as(scope, TokenClass::Comment, &path)\n            .await?;\n        // Only the App's own comment counts", "            .get_pages_as(scope, TokenClass::Stage, &path)\n            .await?;\n        // Only the App's own comment counts")],
    ),
    (
        "SF-14: the post of the comment uses the token of the stage",
        [(CHANGES, "                TokenClass::Comment,\n                Method::Post,\n                &path,", "                TokenClass::Stage,\n                Method::Post,\n                &path,")],
    ),
]


def run():
    command = ["cargo", "nextest", "run", "--offline", "--no-fail-fast", *SUITE]
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def failed_tests(output):
    found = set()
    for line in output.splitlines():
        words = line.split()
        if len(words) >= 4 and words[0] == "FAIL":
            found.add(words[-1])
    return sorted(found)


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
                failed = failed_tests(output)
                shown = "; ".join(failed[:3]) + (f"; and {len(failed) - 3} more" if len(failed) > 3 else "")
                verdict = "CAUGHT by " + shown
            outcomes.append((name, verdict))
            print(f"{name}: {verdict}", flush=True)
    finally:
        for file, text in originals.items():
            (ROOT / file).write_text(text)
    bad = [o for o in outcomes if not o[1].startswith("CAUGHT")]
    print(f"{len(outcomes) - len(bad)} of {len(outcomes)} breaks caught")
    sys.exit(1 if bad else 0)


main()
