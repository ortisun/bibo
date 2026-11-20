"""Deliberate breaks of the bounds on the reply to a label from someone who may not ask (SF-16), each
of which a test must catch.

    python3 -I crates/composition/tests/mutations/intake_reply_breaks.py [WORD]

With a word, only the breaks whose name contains it are run.

The two bounds are the spacing (one reply in ten minutes) and the cap (three replies in 24 hours), and
every reply that is held back must leave a record that says which bound did it. For each break the
script changes one place in the source (the old text must occur exactly once), runs the tests named
for it with `cargo nextest`, and puts the file back. A break is CAUGHT when the tests fail, MISSED when
they pass, and INVALID when the changed source does not compile. The script exits with 1 if any break
is MISSED or INVALID. It leaves the working tree as it found it, also when it is interrupted, but run
it on a clean tree.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
REJECTIONS = "crates/composition/src/intake_rejections.rs"

# What the breaks are tested with: (package arguments, nextest filter).
TESTS = (["-p", "factory-composition"], "binary(intake_rejections) or test(intake_rejections::tests)")

# (name, tests, [(file, old, new)])
BREAKS = [
    (
        "SF-16 spacing: the spacing is ignored, so every toggle of the label is answered",
        TESTS,
        [(REJECTIONS, "    if inside(limits.spacing) > 0 {", "    if false && inside(limits.spacing) > 0 {")],
    ),
    (
        "SF-16 cap: the cap is ignored, so a sender is answered as often as the spacing lets",
        TESTS,
        [(REJECTIONS, "    } else if inside(limits.period) >= limits.cap {", "    } else if false && inside(limits.period) >= limits.cap {")],
    ),
    (
        "SF-16 cap: the cap is one reply too many",
        TESTS,
        [(REJECTIONS, "    } else if inside(limits.period) >= limits.cap {", "    } else if inside(limits.period) > limits.cap {")],
    ),
    (
        "SF-16 cap: the period is not counted, so a reply of last year uses up the cap",
        TESTS,
        [(REJECTIONS, "            .filter(|at| at.checked_add(length).is_some_and(|end| request_at < end))", "            .filter(|at| at.checked_add(length).is_some())")],
    ),
    (
        "SF-16 record: a reply that was held back does not say which bound held it",
        TESTS,
        [(REJECTIONS, '                Reply::Suppressed(bound) => format!(" withheld={}", bound.word()),', "                Reply::Suppressed(_) => String::new(),")],
    ),
    (
        "SF-16 record: a reply that was held back is recorded as posted, so it opens a window of its own",
        TESTS,
        [(REJECTIONS, '                Reply::Suppressed(_) => "suppressed",', '                Reply::Suppressed(_) => "posted",')],
    ),
    (
        "SF-16 log: the replies posted before a restart are forgotten, so a worker that starts later answers again",
        TESTS,
        [(REJECTIONS, "                                scan.note_reply(sender, at);", "                                let _ = (sender, at);")],
    ),
    (
        "SF-16 sender: all senders share one count, so a second sender is held back by the first",
        TESTS,
        [(REJECTIONS, "                .and_then(|scan| scan.replied.get(&sender))", "                .and_then(|scan| scan.replied.values().next())")],
    ),
    (
        "SF-16 log: a record that the worker did not write opens a window, so a forged row silences a sender",
        TESTS,
        [(REJECTIONS, "fn posted_reply(record: &AuditRecord) -> Option<(Option<u64>, Timestamp)> {\n    if !matches!(record.event.actor, AuditActor::System(_)) {", "fn posted_reply(record: &AuditRecord) -> Option<(Option<u64>, Timestamp)> {\n    if false && !matches!(record.event.actor, AuditActor::System(_)) {")],
    ),
    (
        "SF-16 memory: the replies kept for one sender have no bound",
        TESTS,
        [(REJECTIONS, "        if times.len() > REMEMBERED_REPLIES {", "        if false && times.len() > REMEMBERED_REPLIES {")],
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
