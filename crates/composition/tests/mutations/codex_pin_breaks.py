"""Deliberate breaks of the pin of the Codex skills of Spec Kit, each of which a test must catch.

    python3 -I crates/composition/tests/mutations/codex_pin_breaks.py [WORD ...]

For each break the script changes one or two places in the sources (the old text must occur exactly
once in its file), runs the tests named for the break, and puts every file back. A break is CAUGHT
when a test fails, MISSED when they all pass, and INVALID when the changed source does not compile.
The script exits with 1 if any break is MISSED or INVALID. It leaves the working tree as it found
it, also when it is interrupted, but run it on a clean tree.

The tests that catch a break are in `crates/spec_adapter/tests/codex_pin.rs` and the unit tests of
`crates/spec_adapter/src/integrity.rs` (the pin and the comparison), in
`crates/composition/tests/spec_pins.rs` (the tables against the manifests and the files) and
`crates/composition/tests/spec_skills.rs` (what the worker builds its bundle from), and in
`apps/worker/tests/composed_start.rs` (the worker itself). Each of them has a sibling that passes on
the unbroken code, so a break that is CAUGHT is caught for the reason in its name.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
PINNED = "crates/spec_adapter/src/pinned.rs"
INTEGRITY = "crates/spec_adapter/src/integrity.rs"
INVOCATION = "crates/spec_adapter/src/invocation.rs"
SKILLS = "crates/composition/src/spec_skills.rs"
PIPELINE = "apps/worker/src/pipeline.rs"

ADAPTER = ["cargo", "test", "-p", "factory-spec_adapter", "--offline", "--lib", "--test", "codex_pin"]
COMPOSITION = ["cargo", "test", "-p", "factory-composition", "--offline", "--test", "spec_skills", "--test", "spec_pins"]
WORKER = ["cargo", "test", "-p", "factory-worker", "--offline", "--test", "composed_start", "codex"]

# (name, [(file, old, new)], [commands, tried in order until one fails])
BREAKS = [
    (
        "the pin is compared by its first characters again, as the 16-character table was",
        [(INTEGRITY, "Sha256Digest::of(bytes).hex() == pin.sha256", "Sha256Digest::of(bytes).hex().starts_with(pin.sha256)")],
        [ADAPTER],
    ),
    (
        "the Codex skills are checked against the table of the Claude Code skills",
        [(INTEGRITY, "        Host::Codex => &CODEX_SKILLS,", "        Host::Codex => &CLAUDE_SKILLS,")],
        [ADAPTER],
    ),
    (
        "one hash of the Codex table is changed in its last character",
        [(PINNED, "sha256: \"a505028de7f6489878696d6656c7d057f3a66119ebb8c0cc82d69fabb7b344ff\",", "sha256: \"a505028de7f6489878696d6656c7d057f3a66119ebb8c0cc82d69fabb7b344fe\",")],
        [ADAPTER],
    ),
    (
        "an installed integration outside the host table is skipped instead of refused",
        [(INVOCATION, "                let config = Self::for_key(&value, key)?;\n                if found.iter().all", "                let Ok(config) = Self::for_key(&value, key) else {\n                    continue;\n                };\n                if found.iter().all")],
        [ADAPTER, COMPOSITION],
    ),
    (
        "the bundle never looks at the skills of the other host",
        [(SKILLS, "        verify_other_hosts(protected_checkout, &installed, operation, id)?;\n", "")],
        [COMPOSITION, WORKER],
    ),
    (
        "a Codex skill that does not hash to the pin is accepted",
        [(SKILLS, "        if !matches_pin(pinned, &bytes) {", "        if false && !matches_pin(pinned, &bytes) {")],
        [COMPOSITION, WORKER],
    ),
    (
        "a Codex skill that is listed and cannot be read is skipped",
        [(SKILLS, "            Err(_) => return Err(SpecSkillsError::Unreadable(relative)),", "            Err(_) => continue,")],
        [COMPOSITION],
    ),
    (
        "a Codex directory that the installation file does not list is not looked at",
        [(SKILLS, "        let listed = installed.iter().find(|config| config.host == host);\n", "        let listed = installed.iter().find(|config| config.host == host);\n        if listed.is_none() {\n            continue;\n        }\n")],
        [COMPOSITION],
    ),
    (
        "a missing Codex skill that is listed is taken for one that is not installed",
        [(SKILLS, "            Err(error) if listed.is_none() && error.kind() == std::io::ErrorKind::NotFound => {", "            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {")],
        [COMPOSITION],
    ),
    (
        "the worker builds no bundle from the protected checkout, so nothing is pinned",
        [(PIPELINE, "        Err(error) => (\n            None,\n            Some(format!(\"agent runtime: protected_checkout: {error}\")),\n        ),", "        Err(_) => (None, None),")],
        [WORKER],
    ),
]


def run(commands):
    """Runs the commands in order and stops at the first that fails."""
    output = ""
    for command in commands:
        done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        output = done.stdout + done.stderr
        if done.returncode != 0:
            return done.returncode, output
    return 0, output


def main():
    originals = {}
    outcomes = []
    # Words after the script name select the breaks whose name contains one of them.
    only = sys.argv[1:]
    try:
        for name, edits, commands in BREAKS:
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
            code, output = run(commands)
            for file in texts:
                (ROOT / file).write_text(originals[file])
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
        for file, text in originals.items():
            (ROOT / file).write_text(text)
    bad = [o for o in outcomes if not o[1].startswith("CAUGHT")]
    print(f"{len(outcomes) - len(bad)} of {len(outcomes)} breaks caught")
    sys.exit(1 if bad else 0)


main()
