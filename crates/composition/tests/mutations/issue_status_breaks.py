"""Deliberate breaks of the issue status step (ADR 0017), each of which a test must catch.

    python3 -I crates/composition/tests/mutations/issue_status_breaks.py

For each break the script changes one place in `crates/composition/src/issue_status.rs` (the old
text must occur exactly once), runs `cargo test -p factory-composition --test issue_status`, and
puts the file back. A break is CAUGHT when the tests fail, MISSED when they pass, and INVALID when
the changed source does not compile. The script exits with 1 if any break is MISSED or INVALID. It
leaves the working tree as it found it, also when it is interrupted, but run it on a clean tree.

The repository is checked twice (when the job is read and again before the write), so a break that
removes one of the two shows nothing by design. The break below removes both.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
FILE = ROOT / "crates" / "composition" / "src" / "issue_status.rs"

# (name, [(old, new)])
BREAKS = [
    (
        "ignore a superseded comment and write the label anyway",
        [("            if matches!(written, CommentWrite::Superseded(_)) {", "            if false && matches!(written, CommentWrite::Superseded(_)) {")],
    ),
    (
        "write for a repository that is switched off (both checks removed)",
        [
            ("        if !self.still_allowed(item).await? {", "        if false {"),
            ("        if !repository.enabled\n            || !issue", "        if false\n            || !issue"),
        ],
    ),
    (
        "write on an issue of another repository than the job's",
        [("            || !issue\n                .repo\n                .to_string()\n                .eq_ignore_ascii_case(&repo.to_string())", "            || false")],
    ),
    (
        "rewrite the history of jobs that ended long ago",
        [("            if !recent {", "            if false {")],
    ),
    (
        "queue a version again while it is being written, skipping its back-off",
        [("            || state\n                .in_flight\n                .get(&job.value.id)\n                .is_some_and(|v| *v >= version)\n", "")],
    ),
    (
        "no bound on the updates of a minute",
        [("        if state.recent_updates.len() >= MAX_UPDATES_PER_MINUTE {", "        if false {")],
    ),
    (
        "never give up on a version",
        [("        let give_up = !code.can_be_retried() || item.failures >= MAX_TRIES;", "        let give_up = false;")],
    ),
    (
        "do not shield the session of a round from the sweep of ended jobs",
        [("        self.deps.jobs.enter(session, item.tenant);", "")],
    ),
    (
        "do not end the credential of a round",
        [("        let _ = self.deps.host.revoke_job_tokens(session).await;", "")],
    ),
    (
        "do not record a success in the audit log",
        [("                self.record(&item, WRITTEN, AuditDecision::Record, 0, None)", "                std::future::ready(())")],
    ),
]


def run():
    command = ["cargo", "test", "-p", "factory-composition", "--offline", "--test", "issue_status"]
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
