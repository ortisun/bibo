"""Deliberate breaks of the observer and the judgments of the loopback end-to-end test (finding DR-8
of the review of the design gate round two), each of which a negative control must catch.

    python3 -I apps/worker/tests/mutations/loopback_judgment_breaks.py [WORD ...]

The checks of `judge_common` for no merge, no pull request, no push, no model-provider request, no
registry request and no later stage hold in every scenario whether or not the gate works, because
no scenario goes far enough to do the thing. A check wired to nothing would stay green. These breaks
cut the wire (the observer reads a constant instead of the fake) or the check itself, and
`break_what_the_judgments_hold_true_by_construction_is_seen_when_it_really_happens` and
`break_doctored_evidence_is_caught_by_each_judgment` must fail.

For each break the script changes one place in `loopback_e2e.rs` (the old text must occur exactly
once), runs the two controls with `cargo nextest`, and puts the file back. A break is CAUGHT when
they fail, MISSED when they pass and INVALID when the changed source does not compile. The script
exits with 1 if any break is MISSED or INVALID. It leaves the file as it found it, also when it is
interrupted, but run it on a clean tree. Words after the script name select the breaks whose name
contains one of them.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
FILE = "apps/worker/tests/loopback_e2e.rs"
COMMAND = [
    "cargo", "nextest", "run", "--offline", "--no-fail-fast", "-p", "factory-worker", "--test", "loopback_e2e",
    "-E", "test(break_what_the_judgments) or test(break_doctored_evidence)",
]

BREAKS = [
    ("the observer does not read the pushes of the fake host", "        pushes: lab.fake.pushes().len(),", "        pushes: 0,"),
    ("the observer does not read the merge attempts of the fake host", "        merges: lab.fake.merge_attempts().len(),", "        merges: 0,"),
    ("the observer does not read the requests to the model-provider fake", "        provider_hits: lab.provider_seen.all(),", "        provider_hits: Vec::new(),"),
    ("the observer does not read the requests to the registry fake", "        registry_hits: lab.registry_seen.all(),", "        registry_hits: Vec::new(),"),
    ("the observer does not read the routes the fake host received", "        routes,\n        done,", "        routes: BTreeMap::new(),\n        done,"),
    (
        "the judgment does not complain about a stage that started after a refusal",
        "        if kind != \"INTAKE\" && status != \"PENDING\" {",
        "        if false && kind != \"INTAKE\" && status != \"PENDING\" {",
    ),
    (
        "the judgment does not require the exact shape of the intake token (LB-03)",
        "                if shape != [(\"issues\", \"read\"), (\"metadata\", \"read\")]\n                    && shape != [(\"issues\", \"write\"), (\"metadata\", \"read\")]\n                {",
        "                if false {",
    ),
    (
        "the judgment does not complain about a merge",
        "    if o.merges != 0 {",
        "    if false && o.merges != 0 {",
    ),
]


def main():
    path = ROOT / FILE
    original = path.read_text()
    only = sys.argv[1:]
    outcomes = []
    try:
        for name, old, new in BREAKS:
            if only and not any(word in name for word in only):
                continue
            if original.count(old) != 1:
                raise SystemExit(f"{name}: the text to change occurs {original.count(old)} times")
            path.write_text(original.replace(old, new))
            done = subprocess.run(COMMAND, cwd=ROOT, capture_output=True, text=True, check=False)
            path.write_text(original)
            output = done.stdout + done.stderr
            if "could not compile" in output or "error[E" in output:
                verdict = "INVALID (does not compile)"
            elif done.returncode == 0:
                verdict = "MISSED"
            else:
                failed = sorted({line.split()[-1] for line in output.splitlines() if line.split()[:1] == ["FAIL"] and len(line.split()) >= 4})
                verdict = "CAUGHT by " + "; ".join(failed[:3])
            outcomes.append((name, verdict))
            print(f"{name}: {verdict}", flush=True)
    finally:
        path.write_text(original)
    missed = [o for o in outcomes if not o[1].startswith("CAUGHT")]
    print(f"{len(outcomes) - len(missed)} of {len(outcomes)} breaks caught")
    sys.exit(1 if missed else 0)


main()
