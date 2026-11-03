"""Deliberate breaks of the second round of the registration hardening (findings RH-1 to RH-12 of
docs/reviews/registration-hardening-security-review.md).

    FACTORY_DB_PROVISION=local python3 -I apps/api/tests/mutations/registration_hardening_breaks.py [WORDS...]

For each break the script changes one or more places (each old text must occur exactly once in its file),
runs the test targets that cover the path, and puts every file back. A break is CAUGHT when at least one
target fails, MISSED when all pass, and INVALID when the changed source does not compile. The script exits
with 1 if any break is MISSED or INVALID. It leaves the working tree as it found it, also when it is
interrupted by Ctrl-C, but run it on a clean tree. With words after the script name it runs only the breaks
whose name holds one of them.

The rules the database holds (the audit trigger of the API login, the guard that refuses an enabled strict
repository with no enabler) are broken by the controls of `docs/database/tests/repository_map.sql`, sections 13
and 14, which drop each guard and show the statement it refused then goes through. The breaks of the existing
script `repository_change_breaks.py` (the word, the digest, the allowlist, the person, the name, the result,
the repeat) are run by it.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]

STEP = "crates/composition/src/repository_changes.rs"
API = "apps/api/src/repositories.rs"
AUTHORITY = "crates/domain/src/policy/authority.rs"
STORE = "crates/storage/src/pg/jobs.rs"

COMMANDS = [
    ["cargo", "test", "-p", "factory-composition", "--offline", "--lib", "--", "repository_changes"],
    ["cargo", "test", "-p", "factory-composition", "--offline", "--test", "repository_changes"],
    ["cargo", "test", "-p", "factory-api", "--offline", "--test", "repositories"],
    ["cargo", "test", "-p", "factory-domain", "--offline", "--test", "policy", "--", "authority"],
]

# (name, [(file, old, new)])
BREAKS = [
    (
        "RH-1: the worker does not test the age of a request",
        [(STEP, "Some(age) if age > self.deps.max_age => return Some(\"expired\"),", "Some(age) if age > std::time::Duration::MAX => return Some(\"expired\"),")],
    ),
    (
        "RH-1: the worker lets a request dated far ahead of its clock wait",
        [(STEP, ".is_none_or(|gap| gap > MAX_CLOCK_SKEW)", ".is_none_or(|gap| gap > std::time::Duration::MAX)")],
    ),
    (
        "RH-1: a disable does not cancel the requests made before it",
        [(STEP, "        request.disabled_since.then_some(\"disabled_since_request\")\n", "        None\n")],
    ),
    (
        "RH-1: the worker does not read the tail of the log for a disable that came after its pass",
        [(STEP, "            Ok(Tail::Disabled) => return Outcome::Refused(\"disabled_since_request\"),\n", "            Ok(Tail::Disabled) => {}\n")],
    ),
    (
        "RH-1: a record of a disable that the system wrote cancels a request",
        [(STEP, "    if !matches!(record.event.actor, AuditActor::Human(_)) {\n        return None;\n    }\n    let id = record", "    let id = record")],
    ),
    (
        "RH-4: the worker applies before it has read the log to its end",
        [(STEP, "if self.read_new_records(tenant).await != Reading::Complete {", "if self.read_new_records(tenant).await == Reading::Failed {")],
    ),
    (
        "RH-4: the status route looks for the result under the current key only",
        [(API, "for result_id in state.decision_keys.repository_change_result_ids(id) {", "for result_id in [state.decision_keys.repository_change_result_id(id)] {")],
    ),
    (
        "RH-5: the status route reports a request whose word nobody checked",
        [(API, "        || !state.decision_keys.verify_repository_change(\n", "        || false && !state.decision_keys.verify_repository_change(\n")],
    ),
    (
        "RH-5: the worker writes its record of an effect under the API's action",
        [(STEP, "            DISABLED_BY_ATTESTATION,\n            format!(", "            DISABLED,\n            format!(")],
    ),
    (
        "RH-6: the worker does not count the holders of the designations",
        [(STEP, "                Ok(false) => return Outcome::Refused(\"single_maintainer_not_allowed\"),\n", "                Ok(false) => {}\n")],
    ),
    (
        "RH-6: a holder who is switched off is counted",
        [(STEP, "            && principal.disabled_at.is_none()\n", "")],
    ),
    (
        "RH-6: the API does not refuse the exception at the door",
        [(API, "    if parsed.single_maintainer {\n        single_maintainer_allowed(", "    if parsed.single_maintainer && false {\n        single_maintainer_allowed(")],
    ),
    (
        "RH-7: the worker enables a repository that is enabled already",
        [(STEP, "            return Outcome::Refused(\"already_enabled\");\n", "            return Outcome::Refused(\"malformed\");\n")],
    ),
    (
        "RH-7: the API takes a second enable of an enabled repository for a new request",
        [(API, "        if row.value.enabled {\n            let _ = tx.rollback().await;\n", "        if row.value.enabled && false {\n            let _ = tx.rollback().await;\n")],
    ),
    (
        "RH-2: an entry with an id does not require the recorded name for a registration",
        [(AUTHORITY, "listed == known && (!asked.typed || self.name.eq_ignore_ascii_case(asked.name))", "listed == known")],
    ),
    (
        "RH-2: the worker asks about a registration as if the pair were a registered row",
        [(STEP, ") => RepositoryIdentity::typed(name, *github_repository),", ") => RepositoryIdentity::registered(name, *github_repository),")],
    ),
    (
        "RH-2: the API asks about a registration as if the pair were a registered row",
        [(API, "        Some(RepositoryIdentity::typed(\n            &parsed.full_name,", "        Some(RepositoryIdentity::registered(\n            &parsed.full_name,")],
    ),
    (
        "RH-12: the worker does not check the shape of the name and the branch",
        [(STEP, "        && is_repository_full_name(name)\n        && is_repository_branch(branch))", "        && !name.contains(' ')\n        && !branch.contains(' '))")],
    ),
    (
        "RH-7: the Postgres statement enables a repository that is enabled already",
        [(STORE, "            AND NOT enabled \\\n            AND (single_maintainer OR", "            AND (single_maintainer OR")],
    ),
]

# The breaks of the store are caught by the contracts that the PostgreSQL store runs.
STORE_COMMANDS = [
    ["cargo", "test", "-p", "factory-storage", "--offline", "--test", "store_contract"],
]


def commands_for(edits):
    if any(file == STORE for file, _, _ in edits):
        return STORE_COMMANDS
    return COMMANDS


def run(commands):
    output = ""
    for command in commands:
        done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        output += done.stdout + done.stderr
        if "could not compile" in output or "error[E" in output:
            return "invalid", output
        if done.returncode != 0:
            return "failed", output
    return "passed", output


def main():
    originals = {}
    outcomes = []
    try:
        for name, edits in BREAKS:
            if sys.argv[1:] and not any(word in name for word in sys.argv[1:]):
                continue
            changed = {}
            for relative, old, new in edits:
                path = ROOT / relative
                text = changed.get(path)
                if text is None:
                    originals.setdefault(path, path.read_text())
                    text = originals[path]
                if text.count(old) != 1:
                    raise SystemExit(f"{name}: the text to change occurs {text.count(old)} times in {relative}")
                changed[path] = text.replace(old, new)
            for path, text in changed.items():
                path.write_text(text)
            try:
                state, output = run(commands_for(edits))
            finally:
                for path in changed:
                    path.write_text(originals[path])
            if state == "invalid":
                verdict = "INVALID (does not compile)"
            elif state == "passed":
                verdict = "MISSED"
            else:
                failed = sorted({line.split()[1] for line in output.splitlines() if line.startswith("test ") and line.endswith("FAILED")})
                verdict = "CAUGHT by " + "; ".join(failed)
            outcomes.append((name, verdict))
            print(f"{name}: {verdict}", flush=True)
    finally:
        for path, text in originals.items():
            path.write_text(text)
    bad = [o for o in outcomes if not o[1].startswith("CAUGHT")]
    print(f"{len(outcomes) - len(bad)} of {len(outcomes)} breaks caught")
    sys.exit(1 if bad else 0)


main()
