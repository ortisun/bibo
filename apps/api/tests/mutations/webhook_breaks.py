"""Deliberate breaks of the record a label of the factory leaves when its repository does not resolve,
which is what a repository that is switched off looks like to the API (SF-19), each of which a test
must catch.

    python3 -I apps/api/tests/mutations/webhook_breaks.py [WORD]

With a word, only the breaks whose name contains it are run.

For each break the script changes one place in the source (the old text must occur exactly once),
runs the tests named for it with `cargo nextest`, and puts the file back. A break is CAUGHT when the
tests fail, MISSED when they pass, and INVALID when the changed source does not compile. The script
exits with 1 if any break is MISSED or INVALID. It leaves the working tree as it found it, also when
it is interrupted, but run it on a clean tree.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
WEBHOOK = "apps/api/src/webhook.rs"

# What the breaks are tested with: (package arguments, nextest filter).
TESTS = (["-p", "factory-api"], "binary(webhook) and test(switched_off)")

# (name, tests, [(file, old, new)])
BREAKS = [
    (
        "SF-19: the factory label in a repository that does not resolve gets the plain reason again",
        TESTS,
        [(WEBHOOK, "            reason: if factory_label {\n                UNBOUND_FACTORY_LABEL", "            reason: if false && factory_label {\n                UNBOUND_FACTORY_LABEL")],
    ),
    (
        "SF-19: every delivery that does not resolve says it was a factory label",
        TESTS,
        [(WEBHOOK, "            reason: if factory_label {\n                UNBOUND_FACTORY_LABEL", "            reason: if true || factory_label {\n                UNBOUND_FACTORY_LABEL")],
    ),
    (
        "SF-19: any label is taken for the factory label",
        TESTS,
        [(WEBHOOK, "            WebhookHint::IssueLabeled { label, .. } if *label == state.github.factory_label\n        );", "            WebhookHint::IssueLabeled { label, .. } if !label.is_empty()\n        );")],
    ),
    (
        "SF-19: the reason does not name the switched-off state",
        TESTS,
        [(WEBHOOK, "not registered or that the factory is switched off for. The label starts nothing", "not registered. The label starts nothing")],
    ),
    (
        "SF-19: the reason does not say what became of the label",
        TESTS,
        [(WEBHOOK, " The label starts nothing and nobody is answered.\";\n\n/// The reason of the record of any other", "\";\n\n/// The reason of the record of any other")],
    ),
    (
        "SF-19: the plain reason is lost for the other deliveries",
        TESTS,
        [(WEBHOOK, 'const UNBOUND: &str = "The installation or repository is not registered.";', 'const UNBOUND: &str = "The delivery was dropped.";')],
    ),
]


def command(tests):
    packages, expression = tests
    return ["cargo", "nextest", "run", "--offline", "--no-fail-fast", *packages, "-E", expression]


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
        for name, tests, edits in BREAKS:
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
            done = subprocess.run(command(tests), cwd=ROOT, capture_output=True, text=True)
            output = done.stdout + done.stderr
            for file in texts:
                (ROOT / file).write_text(originals[file])
            if "could not compile" in output or "error[E" in output:
                verdict = "INVALID (does not compile)"
            elif done.returncode == 0:
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
