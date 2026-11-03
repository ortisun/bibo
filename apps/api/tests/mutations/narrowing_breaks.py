"""Deliberate breaks of the narrowing by GitHub's repository id (RR-28), each of which a test must catch.

    FACTORY_DB_PROVISION=local python3 -I apps/api/tests/mutations/narrowing_breaks.py [WORDS...]

For each break the script changes one or more places (each old text must occur exactly once in its
file), runs the three test targets that cover the narrowing, and puts every file back. A break is
CAUGHT when at least one target fails, MISSED when all pass, and INVALID when the changed source does
not compile. The script exits with 1 if any break is MISSED or INVALID. It leaves the working tree as
it found it, also when it is interrupted, but run it on a clean tree. With words after the script name
it runs only the breaks whose name holds one of them.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]

DOMAIN = "crates/domain/src/policy/authority.rs"
SEAMS = "crates/composition/src/seams.rs"
AUTH = "apps/api/src/auth.rs"
WEBHOOK = "apps/api/src/webhook.rs"
ADMISSION = "crates/composition/src/authority.rs"
HOOK = "crates/composition/src/decisions.rs"
PORTS = "crates/ports/src/store.rs"

COMMANDS = [
    ["cargo", "test", "-p", "factory-domain", "--offline", "--test", "policy", "rr_28"],
    ["cargo", "test", "-p", "factory-composition", "--offline", "--test", "security_rereview", "rr_28"],
    ["cargo", "test", "-p", "factory-composition", "--offline", "--test", "repository_identity"],
    ["cargo", "test", "-p", "factory-composition", "--offline", "--test", "claim_work", "rr_28"],
    ["cargo", "test", "-p", "factory-api", "--offline", "--test", "repositories", "github_id"],
]

# (name, [(file, old, new)])
BREAKS = [
    (
        "RR-28: the narrowing compares names even when the repository has an id",
        [(DOMAIN, "            (Some(listed), Some(known)) => listed == known,\n", "            (Some(_), Some(_)) => self.name.eq_ignore_ascii_case(asked.name),\n")],
    ),
    (
        "RR-28: an id that differs is taken for a match when the names are the same (the name decides first)",
        [(DOMAIN, "            (Some(listed), Some(known)) => listed == known,\n", "            (Some(listed), Some(known)) => listed == known || self.name.eq_ignore_ascii_case(asked.name),\n")],
    ),
    (
        "RR-28: the loader drops the id of a listing",
        [(SEAMS, "                .then(|| ListedRepository::with_id(&item.name, item.github_repository_id)),", "                .then(|| ListedRepository::named(&item.name)),")],
    ),
    (
        "RR-28: the loader accepts an id of zero",
        [(SEAMS, "            Self::WithId(item) => (item.github_repository_id > 0)\n", "            Self::WithId(item) => (item.github_repository_id < u64::MAX)\n")],
    ),
    (
        "RR-28: the API asks with the name alone",
        [(PORTS, "        factory_domain::policy::authority::RepositoryIdentity::registered(\n            &self.full_name,\n            self.github_repository_id.0,\n        )", "        factory_domain::policy::authority::RepositoryIdentity::by_name_only(&self.full_name)")],
    ),
    (
        "RR-28: the webhook asks with the name alone",
        [(WEBHOOK, ".covers(bound.tenant, sender, &registered.value.identity())", ".covers(bound.tenant, sender, &factory_domain::policy::authority::RepositoryIdentity::by_name_only(&registered.value.full_name))")],
    ),
    (
        "RR-28: the admission of a job asks with the name alone",
        [(ADMISSION, "                    .map(|(name, id)| RepositoryIdentity::registered(name, *id));", "                    .map(|(name, _)| RepositoryIdentity::by_name_only(name));")],
    ),
    (
        "RR-28: the claim hook asks with the name alone",
        [(HOOK, "                &RepositoryIdentity::registered(&repository, github_repository),\n", "                &RepositoryIdentity::by_name_only(&repository),\n")],
    ),
    (
        "RR-28: the weaker form is not reported",
        [(DOMAIN, "            .filter(|listed| listed.github_repository_id.is_none())\n", "            .filter(|listed| listed.github_repository_id.is_some())\n")],
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
