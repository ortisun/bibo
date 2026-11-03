"""Deliberate breaks of the count of required approving reviews (SF-07), each of which a test must
catch.

    python3 -I crates/composition/tests/mutations/approving_reviews_breaks.py [--check] [WORD ...]

The count runs from the ruleset to the preflight: the GitHub adapter reads `required_approving_review_count`
of the pull request rules (`crates/github/src/protection.rs`), the port judges it against the number the
policy says every pull request needs (`ProtectionReport::evaluate`, `AuthorityPolicy::
approvals_every_pull_request_needs`), and the composition root hands the policy's number to the preflight
(`pipeline.rs`, `preflight.rs`). A count that is unknown, or lower than the policy needs, must cap the
repository at level L0 with a named reason.

For each break the script changes one place in the sources (the old text must occur exactly once in its
file), runs the tests named for it with `cargo nextest`, and puts every file back. A break is CAUGHT when
the tests fail, MISSED when they pass, and INVALID when the changed source does not compile. The script
exits with 1 if any break is MISSED or INVALID. It leaves the working tree as it found it, also when it is
interrupted, but run it on a clean tree.

`--check` runs nothing and changes nothing: it reports every break whose old text does not occur exactly
once in its file, and exits with 1 if there is one. Words after the script name select the breaks whose
name contains one of them.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
PORT = "crates/ports/src/githost.rs"
ADAPTER = "crates/github/src/protection.rs"
POLICY = "crates/domain/src/policy/authority.rs"
PREFLIGHT = "crates/composition/src/preflight.rs"
PIPELINE = "crates/composition/src/pipeline.rs"

# What each break is tested with: package arguments and a nextest filter.
PORT_AND_ADAPTER = (
    ["-p", "factory-ports", "-p", "factory-github"],
    "test(approving) or test(count) or test(negative_nt_mrg_07) or binary(protection)",
)
POLICY_TESTS = (["-p", "factory-domain"], "test(sf_07)")
COMPOSITION = (
    ["-p", "factory-composition"],
    "binary(preflight) or test(the_test_profile_assembles)",
)

# (name, tests, [(file, old, new)])
BREAKS = [
    (
        "SF-07 port: an unknown count is taken for enough",
        PORT_AND_ADAPTER,
        [(PORT, "                None => failures.push(PreflightFailure::ApprovingReviewsUnknown),", "                None => {}")],
    ),
    (
        "SF-07 port: a count of zero is taken for enough",
        PORT_AND_ADAPTER,
        [(PORT, "                Some(found) if found < required_approvals => {", "                Some(found) if found < required_approvals && found > 0 => {")],
    ),
    (
        "SF-07 port: the count the policy needs is ignored and one is assumed",
        PORT_AND_ADAPTER,
        [(PORT, "                Some(found) if found < required_approvals => {", "                Some(found) if found < 1 => {")],
    ),
    (
        "SF-07 adapter: the smallest count of several pull request rules is kept instead of the largest",
        PORT_AND_ADAPTER,
        [(ADAPTER, "                            .map_or(count, |held| held.max(count)),", "                            .map_or(count, |held| held.min(count)),")],
    ),
    (
        "SF-07 adapter: the count is read from a parameter that does not exist, so it is never known",
        PORT_AND_ADAPTER,
        [(ADAPTER, "                if let Some(count) = parameters[\"required_approving_review_count\"]", "                if let Some(count) = parameters[\"required_approving_review_total\"]")],
    ),
    (
        "SF-07 adapter: a count that cannot be read is taken for zero and not for unknown",
        PORT_AND_ADAPTER,
        [(ADAPTER, "        required_approving_reviews: None,\n        required_checks: Vec::new(),\n    };", "        required_approving_reviews: Some(0),\n        required_checks: Vec::new(),\n    };")],
    ),
    (
        "SF-07 policy: the largest number of the tiers is asked of every repository instead of the smallest",
        POLICY_TESTS,
        [(POLICY, "            .map(|tier| tier.approvals)\n            .min()\n            .unwrap_or(u32::MAX)", "            .map(|tier| tier.approvals)\n            .max()\n            .unwrap_or(u32::MAX)")],
    ),
    (
        "SF-07 composition: the preflight is given no number and asks for none",
        COMPOSITION,
        [(PIPELINE, "        required_approvals: policies\n            .engine\n            .authority\n            .approvals_every_pull_request_needs(),", "        required_approvals: 0,")],
    ),
    (
        "SF-07 composition: the preflight does not pass its number on to the judgement",
        COMPOSITION,
        [(PREFLIGHT, "                    attestation.as_ref(),\n                    self.deps.required_approvals,\n                ) {", "                    attestation.as_ref(),\n                    0,\n                ) {")],
    ),
]


def check():
    """Reports every break whose old text does not occur exactly once in its file. Runs nothing."""
    bad = 0
    for name, _tests, edits in BREAKS:
        for file, old, _new in edits:
            count = (ROOT / file).read_text().count(old)
            if count != 1:
                print(f"CANNOT APPLY ({count} matches in {file}): {name}")
                bad += 1
    print(f"{len(BREAKS) - bad} of {len(BREAKS)} breaks apply")
    sys.exit(1 if bad else 0)


def run(tests):
    packages, filterset = tests
    command = ["cargo", "nextest", "run", "--offline", "--no-fail-fast", *packages, "-E", filterset]
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def main():
    args = sys.argv[1:]
    if "--check" in args:
        check()
    originals = {}
    outcomes = []
    try:
        for name, tests, edits in BREAKS:
            if args and not any(word in name for word in args):
                continue
            texts = {}
            for file, old, new in edits:
                originals.setdefault(file, (ROOT / file).read_text())
                text = texts.get(file, originals[file])
                if text.count(old) != 1:
                    raise SystemExit(f"{name}: the text to change occurs {text.count(old)} times in {file}")
                texts[file] = text.replace(old, new)
            for file, text in texts.items():
                (ROOT / file).write_text(text)
            code, output = run(tests)
            for file in texts:
                (ROOT / file).write_text(originals[file])
            if "could not compile" in output or "error[E" in output:
                verdict = "INVALID (does not compile)"
            elif code == 0:
                verdict = "MISSED"
            else:
                failed = sorted({line.split()[-1] for line in output.splitlines() if line.strip().startswith("FAIL [")})
                shown = "; ".join(failed[:4]) + (f"; and {len(failed) - 4} more" if len(failed) > 4 else "")
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
