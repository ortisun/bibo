"""Deliberate breaks of the signed requests to register, attest and enable a repository (REG-2).

    FACTORY_DB_PROVISION=local python3 -I apps/api/tests/mutations/repository_change_breaks.py [WORDS...]

For each break the script changes one or more places (each old text must occur exactly once in its
file), runs the two test targets that cover the path, and puts every file back. A break is CAUGHT when
at least one target fails, MISSED when all pass, and INVALID when the changed source does not compile.
The script exits with 1 if any break is MISSED or INVALID. It leaves the working tree as it found it,
also when it is interrupted by Ctrl-C, but run it on a clean tree. With words after the script name it
runs only the breaks whose name holds one of them.

The rules the database holds (the trigger that lets the API login do nothing but switch a repository
off, the grants, the audit actions) are broken by the controls of `docs/database/tests/repository_map.sql`,
section 12, which drop each guard and show the statement it refused then goes through.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]

STEP = "crates/composition/src/repository_changes.rs"
API = "apps/api/src/repositories.rs"

COMMANDS = [
    ["cargo", "test", "-p", "factory-composition", "--offline", "--test", "repository_changes"],
    ["cargo", "test", "-p", "factory-api", "--offline", "--test", "repositories"],
]

# (name, [(file, old, new)])
BREAKS = [
    (
        "REG-2: the worker applies a request without verifying the word",
        [(STEP, "        if !self\n            .deps\n            .keys\n            .verify_repository_change(&signing, &subject.word)\n        {\n            return None;\n        }\n", "")],
    ),
    (
        "REG-2: the worker does not check the detail text against the digest the word covers",
        [(STEP, "        if payload_digest(&record.event.reason) != subject.fields.payload {\n            return None;\n        }\n", "")],
    ),
    (
        "REG-2: the worker does not ask the allowlist again when it applies a request",
        [(STEP, "            Ok(false) => return Outcome::Refused(\"not_permitted\"),\n", "            Ok(false) => {}\n")],
    ),
    (
        "REG-2: the worker applies a request of a person who was switched off since",
        [(STEP, "                (PrincipalKind::Human { github_user_id }, None) => github_user_id,\n", "                (PrincipalKind::Human { github_user_id }, _) => github_user_id,\n")],
    ),
    (
        "REG-2 and RR-28: the worker asks the allowlist with the name alone for a repository that exists",
        [(STEP, "                (_, Some(row), _) => row.value.identity(),\n", "                (_, Some(row), _) => RepositoryIdentity::by_name_only(&row.value.full_name),\n")],
    ),
    (
        "REG-2: the worker writes no result, so the request stays open and is applied again",
        [(STEP, "        let mut events = vec![self.result_event(request, result_id)];\n", "        let mut events = Vec::new();\n        let _ = result_id;\n")],
    ),
    (
        "REG-2: the API takes a request with the same key and another change for a repeat",
        [(API, "            && read_repository_change_subject(&record.event.subject)\n                .is_some_and(|read| read.fields == fields);\n", "            && read_repository_change_subject(&record.event.subject).is_some();\n")],
    ),
]


def run():
    output = ""
    for command in COMMANDS:
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
                state, output = run()
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
