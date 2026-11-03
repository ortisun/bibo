"""Deliberate breaks of the repository routes (REG-1, REG-4, REG-5, REG-6), each of which a test must catch.

    FACTORY_DB_PROVISION=local python3 -I apps/api/tests/mutations/repository_breaks.py

For each break the script changes one or more places in the files it names (each old text must
occur exactly once in its file), runs `cargo test -p factory-api --test repositories`, and puts every
file back. A break of REG-6 may change `apps/api/src/jobs.rs`, `apps/api/src/webhook.rs`, the
composition crate or the storage crate, because the rule has consumers in all of them.
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
REPOSITORIES = "apps/api/src/repositories.rs"
JOBS = "apps/api/src/jobs.rs"
WEBHOOK = "apps/api/src/webhook.rs"
AUTHORITY = "crates/composition/src/authority.rs"
STORAGE = "crates/storage/src/pg/jobs.rs"
ERROR = "crates/storage/src/pg/error.rs"

# (name, [(old, new)]) for REPOSITORIES, or (name, [(old, new, file)]) for another file
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
    (
        "REG-6: the registration forgets the single-maintainer flag the operator sent",
        [("            single_maintainer: parsed.single_maintainer,\n        })", "            single_maintainer: false,\n        })")],
    ),
    (
        "REG-6: every registration is a single-maintainer one (the strict rule is never applied)",
        [("            single_maintainer: parsed.single_maintainer,\n        })", "            single_maintainer: true,\n        })")],
    ),
    (
        "REG-6: the strict rule has no typed answer at any layer (API check, store statement and the mapping of the table's error)",
        [
            ("            Some(map)\n                if map.commit == *meant\n                    && !row.value.single_maintainer\n                    && map.attested_by == caller.principal =>\n            {\n                return Err(ApiError::EnablerIsAttestor);\n            }\n", ""),
            ("            AND (single_maintainer OR project_map_attested_by_principal_id IS DISTINCT FROM $5) \\\n", "", STORAGE),
            ("        \"repositories_enabler_differs_from_attestor\" => rule(ConstraintRule::EnablerIsAttestor),\n", "", ERROR),
        ],
    ),
    (
        "REG-6: show hides that the people behind a repository are gone (standing reported as good)",
        [("            \"open_for_new_jobs\": repository.open_for_new_jobs(),", "            \"open_for_new_jobs\": repository.enabled,")],
    ),
    (
        "REG-6: the job route opens a repository whose attestor or enabler is gone",
        [("    if !registered.value.open_for_new_jobs() {", "    if !registered.value.enabled {", JOBS)],
    ),
    (
        "REG-6: the webhook binds a repository whose attestor or enabler is gone",
        [("        let open = registered.value.open_for_new_jobs();", "        let open = registered.value.enabled;", WEBHOOK)],
    ),
    (
        "REG-6: the standing of the enabler is never judged (computed as always active)",
        [("(enabled_by_principal_id IS NULL OR EXISTS (SELECT 1 FROM principals p \\\n        WHERE p.tenant_id = repositories.tenant_id AND p.id = enabled_by_principal_id \\\n          AND p.kind = 'human' AND p.disabled_at IS NULL)) AS enabler_is_active", "true AS enabler_is_active", STORAGE)],
    ),
]


def run():
    command = ["cargo", "test", "-p", "factory-api", "--offline", "--test", "repositories"]
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def main():
    originals = {}
    outcomes = []
    try:
        for name, edits in BREAKS:
            # `repository_breaks.py WORDS...` runs only the breaks whose name holds one of the words.
            if sys.argv[1:] and not any(word in name for word in sys.argv[1:]):
                continue
            changed = {}
            for edit in edits:
                old, new = edit[0], edit[1]
                relative = edit[2] if len(edit) > 2 else REPOSITORIES
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
                code, output = run()
            finally:
                for path in changed:
                    path.write_text(originals[path])
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
        for path, text in originals.items():
            path.write_text(text)
    bad = [o for o in outcomes if not o[1].startswith("CAUGHT")]
    print(f"{len(outcomes) - len(bad)} of {len(outcomes)} breaks caught")
    sys.exit(1 if bad else 0)


main()
