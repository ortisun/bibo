"""Deliberate breaks of finding RH-3, each of which a test must catch: the person who approved a
design is judged by the registered repository's GitHub id first, the way the claim hook and the API
judge a person (RR-28), and by the name only for an allowlist entry that lists no id.

    python3 -I crates/workflow/tests/mutations/registered_identity_breaks.py [--check] [WORD ...]

For each break the script changes one or two places in the sources (the old text must occur exactly
once in its file), runs the tests that must notice (`cargo test -p factory-workflow --offline
--no-fail-fast` over the test binaries `intake_repo` and `delivery`), and puts every file back. A
break is CAUGHT when the tests fail, MISSED when they pass, and INVALID when the changed source does
not compile. The script exits with 1 if any break is MISSED or INVALID. It leaves the working tree as
it found it, also when it is interrupted, but run it on a clean tree.

`--check` runs nothing and changes nothing: it reports every break whose old text does not occur
exactly once in its file, which is a break that proves nothing. It exits with 1 if there is one.

Words after the script name select the breaks whose name contains one of them.

The tests that catch these are `intake_repo/registered_identity.rs` (the intake stage) and
`delivery/design_recheck.rs` (the re-check before the pull request is opened, DG-8). Each of them has
a sibling that passes on the unbroken code.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
JUDGE = "crates/workflow/src/stages/intake/judge.rs"
DESIGN = "crates/workflow/src/stages/intake/design.rs"
AUTHORIZE = "crates/workflow/src/stages/intake/authorize.rs"
AUTHORITY = "crates/domain/src/policy/authority.rs"

TARGETS = ["--test", "intake_repo", "--test", "delivery"]

# (name, [(file, old, new)])
BREAKS = [
    (
        "RH-3: the judge asks with the name of the registered row and drops its id, as the stage did before",
        [(JUDGE, "                    .map(|(name, id)| RepositoryIdentity::registered(name, *id)),", "                    .map(|(name, _)| RepositoryIdentity::by_name_only(name)),")],
    ),
    (
        "RH-3: the judge asks as for a registration, so an entry with an id must also match the name",
        [(JUDGE, "                    .map(|(name, id)| RepositoryIdentity::registered(name, *id)),", "                    .map(|(name, id)| RepositoryIdentity::typed(name, *id)),")],
    ),
    (
        "RH-3: the stage hands the identity to the policy but the policy is asked by the name alone",
        [(AUTHORIZE, "    match policy.designations_for(allowlist, &tenant, repository, &actor, now) {", "    match policy.designations(allowlist, &tenant, repository.name, &actor, now) {")],
    ),
    (
        "RH-3: the policy takes the identity and judges an entry's id by the name recorded next to it",
        [(AUTHORITY, "        if !entry.covers_repository(repository) {", "        if !entry.covers_repository(&RepositoryIdentity::by_name_only(repository.name)) {")],
    ),
    (
        "RH-3: a registered row that cannot be read is taken for a refusal instead of an error of the attempt",
        [(JUDGE, "            let target = self\n                .repositories\n                .of(scope.tenant, scope.job)\n                .await\n                .map_err(|_| DesignStop::Stage(StageError::Tool))?;\n            Some((\n                format!(\"{}/{}\", target.repo.owner(), target.repo.name()),\n                target.github_repository_id,\n            ))", "            match self.repositories.of(scope.tenant, scope.job).await {\n                Ok(target) => Some((\n                    format!(\"{}/{}\", target.repo.owner(), target.repo.name()),\n                    target.github_repository_id,\n                )),\n                Err(_) => None,\n            }")],
    ),
    (
        "RH-3: the registered row is read for every issue, so an ordinary issue needs the store",
        [(JUDGE, "        let registered = if labels == DesignLabels::ApprovalLabelOnly {", "        let registered = if true {")],
    ),
    (
        "RH-3: an approval asked about with no registered identity is judged by the name of the live issue",
        [(DESIGN, "            let Some(repository) = &judging.repository else {\n                return refused(\n                    RefusalReason::NotAnApprover(DenialReason::RepositoryNotListed),\n                    seen,\n                    applied_by.map(|who| who.id),\n                );\n            };", "            let by_name = RepositoryIdentity::by_name_only(\"example-org/fixture\");\n            let repository = judging.repository.as_ref().unwrap_or(&by_name);")],
    ),
]


def check():
    """Reports every break whose old text does not occur exactly once in its file."""
    bad = 0
    for name, edits in BREAKS:
        texts = {}
        for file, old, new in edits:
            text = texts.get(file) or (ROOT / file).read_text()
            count = text.count(old)
            if count != 1:
                print(f"CANNOT APPLY ({count} matches in {file}): {name}")
                bad += 1
            else:
                texts[file] = text.replace(old, new)
    print(f"{len(BREAKS) - bad} of {len(BREAKS)} breaks apply")
    sys.exit(1 if bad else 0)


def run():
    command = ["cargo", "test", "-p", "factory-workflow", "--offline", "--no-fail-fast", *TARGETS]
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def main():
    args = sys.argv[1:]
    if "--check" in args:
        check()
    originals = {}
    outcomes = []
    try:
        for name, edits in BREAKS:
            if args and not any(word in name for word in args):
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
