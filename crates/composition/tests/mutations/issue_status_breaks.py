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
            ("        if !repository.enabled || !named.repo.same_repository(&repo) {", "        if !named.repo.same_repository(&repo) {"),
        ],
    ),
    (
        "write on an issue of another repository than the job's",
        [("        if !repository.enabled || !named.repo.same_repository(&repo) {", "        if !repository.enabled {")],
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
        [("        if in_the_last_minute >= MAX_UPDATES_PER_MINUTE\n", "        if false && in_the_last_minute >= MAX_UPDATES_PER_MINUTE\n")],
    ),
    (
        "never give up on a version",
        [("        let give_up = !code.can_be_retried() || item.failures >= MAX_TRIES;", "        let give_up = false;")],
    ),
    (
        "do not shield the session of a round from the sweep of ended jobs",
        [("        jobs.enter(session, tenant);", "")],
    ),
    (
        "do not end the credential of a round",
        [("        let _ = self.host.revoke_job_tokens(self.session).await;\n        self.jobs.leave(self.session);\n    }\n}\n\nimpl Drop", "        self.jobs.leave(self.session);\n    }\n}\n\nimpl Drop")],
    ),
    (
        "do not record a success in the audit log",
        [("                self.record(&item, WRITTEN, AuditDecision::Record, 0, None)", "                std::future::ready(())")],
    ),
    # The review fixes (docs/reviews/engine-registration-and-status-security-review.md).
    (
        "STS-1: write for a job whose intake stage has not passed",
        [("        if !intake_accepted(runs.iter().map(|r| (r.value.kind, r.value.status))) {", "        if false {")],
    ),
    (
        "STS-2: ignore the wait that GitHub asked for",
        [("                let wait = next_wait(item.failures, failure.retry_after);", "                let wait = next_wait(item.failures, None);")],
    ),
    (
        "STS-2: no bound on the updates of an hour",
        [("            || state.recent_updates.len() >= MAX_UPDATES_PER_HOUR", "            || false")],
    ),
    (
        "STS-3: do not write the end state a second time",
        [("                    if item.status.is_terminal() {\n                        // The end state stays for good", "                    if false {\n                        // The end state stays for good")],
    ),
    (
        "STS-4: a round that panics or is dropped keeps its session in the shield and its credential",
        [("        if self.finished {\n            return;\n        }\n        let (jobs, host, session)", "        if true {\n            return;\n        }\n        let (jobs, host, session)")],
    ),
    (
        "STS-6: write without asking the row write_status_label of the approval policy",
        [("        if !self.deps.permission.allows(job.value.autonomy_level) {", "        if false {")],
    ),
    (
        "STS-7: the off step does not record that it is off",
        [("                self.record_for(tenant).await;", "                ();")],
    ),
    (
        "STS-8: address the issue with the case of the request, not the registered name",
        [("        let issue = IssueRef {\n            repo: repo.clone(),\n            number: named.number,\n        };", "        let issue = named.clone();")],
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
