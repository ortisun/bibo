"""Deliberate breaks of the release of the token of a job that stays blocked (LB-04), each of which a
test must catch.

    python3 -I crates/composition/tests/mutations/blocked_token_breaks.py [WORD]

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
SWEEP = "crates/composition/src/token_sweep.rs"
MINTER = "crates/github/src/token.rs"
CHECK = "crates/contracts/src/policy/check.rs"

# What each group of breaks is tested with: (package arguments, nextest filter).
SWEEP_TESTS = (["-p", "factory-composition"], "binary(token_sweep) or test(token_sweep::tests)")
MINTER_TESTS = (["-p", "factory-github"], "binary(negative_tokens) and test(lb_04)")
POLICY_TESTS = (["-p", "factory-contracts"], "binary(policy_strictness) and test(lb_04)")

# (name, tests, [(file, old, new)])
BREAKS = [
    (
        "LB-04: a job that waits for a person is treated as blocked too (every open job counts)",
        SWEEP_TESTS,
        [(SWEEP, "                        .filter(|job| job.value.status == JobStatus::Blocked)\n", "")],
    ),
    (
        "LB-04: the bound is ignored, so a blocked job loses its token at the first pass",
        SWEEP_TESTS,
        [(SWEEP, "            .filter(|(_, since)| since.checked_add(self.after).is_some_and(|due| due <= now))\n", "            .filter(|(_, since)| since.checked_add(self.after).is_some())\n")],
    ),
    (
        "LB-04: a job that left BLOCKED is not forgotten, so a second block counts from the first",
        SWEEP_TESTS,
        [(SWEEP, "        self.first_seen.retain(|job, _| blocked.contains(job));\n", "")],
    ),
    (
        "LB-04: the release ends the job, so a job that is unblocked can mint no more",
        MINTER_TESTS,
        [(MINTER, "    async fn release_job(&self, job: JobId) -> usize {\n        let (tokens, retries) = {\n            let mut state = self.state();\n", "    async fn release_job(&self, job: JobId) -> usize {\n        let (tokens, retries) = {\n            let mut state = self.state();\n            state.ended.insert(job);\n")],
    ),
    (
        "LB-04: the release does not ask what is running after it has listed the tokens",
        MINTER_TESTS,
        [(MINTER, "        let running = running_now();\n        let mut released = 0;\n", "        let running: HashSet<JobId> = HashSet::new();\n        let _ = running_now;\n        let mut released = 0;\n")],
    ),
    (
        "LB-04: the release also takes the tokens of jobs that were not named as idle",
        MINTER_TESTS,
        [(MINTER, "                .filter(|job| idle.contains(job))\n", "")],
    ),
    (
        "LB-04: a revocation that fails for an idle job is dropped and not tried again",
        MINTER_TESTS,
        [(MINTER, "        if !failed.is_empty() {\n            self.state().leftovers.extend(failed);\n        }\n        released", "        released")],
    ),
    (
        "LB-04: the policy accepts a bound of zero",
        POLICY_TESTS,
        [(CHECK, "    if !(MIN_BLOCKED_REVOKE_S..=MAX_BLOCKED_REVOKE_S).contains(&blocked_after) {", "    if blocked_after > MAX_BLOCKED_REVOKE_S {")],
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
