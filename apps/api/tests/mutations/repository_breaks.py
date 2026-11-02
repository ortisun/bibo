"""Deliberate breaks of the repository routes (REG-1, REG-4, REG-5), each of which a test must catch.

    FACTORY_DB_PROVISION=local python3 -I apps/api/tests/mutations/repository_breaks.py

For each break the script changes one place in `apps/api/src/repositories.rs` (the old text must
occur exactly once), runs `cargo test -p factory-api --test repositories`, and puts the file back.
A break is CAUGHT when the tests fail, MISSED when they pass, and INVALID when the changed source
does not compile. The script exits with 1 if any break is MISSED or INVALID. It leaves the working
tree as it found it, also when it is interrupted, but run it on a clean tree.

The rule that an enabled repository does not stay enabled over another map is in the table, not in
this file. Its controls are in `docs/database/tests/repository_map.sql` (section 10) and in the test
`control_without_the_table_rule_an_enabled_repository_stays_enabled_over_another_map`, which drops
the trigger and the check and shows the old behaviour.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
FILE = ROOT / "apps" / "api" / "src" / "repositories.rs"

# (name, [(old, new)])
BREAKS = [
    (
        "REG-5: a replay compares the name only, not the whole registration",
        [("        if !same_request(&row.value, &parsed) {", "        if false {")],
    ),
    (
        "REG-4: reading a repository ignores the narrowing of the allowlist",
        [("    if narrowed_away(state, caller, &row.value.full_name)? {\n        return Err(ApiError::NotFound);", "    if false {\n        return Err(ApiError::NotFound);")],
    ),
    (
        "REG-1: an enable is not bound to the commit the approver named",
        [
            ("            Some(_) => return Err(ApiError::ProjectMapChanged),", "            Some(_) => String::new(),"),
            (
                "            tx.enable_repository(id, row.version, meant, caller.principal)\n                .await",
                "            tx.enable_repository(\n                id,\n                row.version,\n                row.value.project_map.clone().expect(\"a map\").commit,\n                caller.principal,\n            )\n            .await",
            ),
        ],
    ),
    (
        "REG-1: the switch-off of an enabled repository leaves no audit record",
        [("    let switched_off = if row.value.enabled && !current.value.enabled {", "    let switched_off = if false {")],
    ),
    (
        "REG-1: the typed answer for a moved map is the answer for no map",
        [("        StoreError::Constraint(ConstraintRule::ProjectMapChanged) => ApiError::ProjectMapChanged,\n", ""),
         ("            Some(_) => return Err(ApiError::ProjectMapChanged),", "            Some(_) => return Err(ApiError::ProjectMapNotAttested),")],
    ),
]


def run():
    command = ["cargo", "test", "-p", "factory-api", "--offline", "--test", "repositories"]
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def main():
    original = FILE.read_text()
    outcomes = []
    try:
        for name, edits in BREAKS:
            text = original
            for old, new in edits:
                if text.count(old) != 1:
                    raise SystemExit(f"{name}: the text to change occurs {text.count(old)} times")
                text = text.replace(old, new)
            FILE.write_text(text)
            code, output = run()
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
        FILE.write_text(original)
    bad = [o for o in outcomes if not o[1].startswith("CAUGHT")]
    print(f"{len(outcomes) - len(bad)} of {len(outcomes)} breaks caught")
    sys.exit(1 if bad else 0)


main()
