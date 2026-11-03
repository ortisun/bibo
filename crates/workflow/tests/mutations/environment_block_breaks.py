"""Deliberate breaks of the comment for a job that is blocked by the environment after the gate
(LB-02), each of which a test must catch.

    python3 -I crates/workflow/tests/mutations/environment_block_breaks.py [WORD]

With a word, only the breaks whose name contains it are run.

For each break the script changes one place in the source (the old text must occur exactly once),
runs the tests named for it with `cargo nextest`, and puts the file back. A break is CAUGHT when the
tests fail, MISSED when they pass, and INVALID when the changed source does not compile. The script
exits with 1 if any break is MISSED or INVALID. It leaves the working tree as it found it, also when
it is interrupted, but run it on a clean tree.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]

HANDLER = "crates/workflow/src/stages/intake/handler.rs"
DESIGN = "crates/workflow/src/stages/intake/design.rs"
STATUS = "crates/composition/src/issue_status.rs"

NEXTEST = ["cargo", "nextest", "run", "--offline", "--no-fail-fast"]
WORKFLOW_TESTS = NEXTEST + ["-p", "factory-workflow", "--test", "intake_repo", "-E", "test(design::)"]
STATUS_TESTS = NEXTEST + ["-p", "factory-composition", "--test", "issue_status"]

# (name, command, [(file, old, new)])
BREAKS = [
    (
        "LB-02: a missing sandbox is not told to the person who asked",
        WORKFLOW_TESTS,
        [(HANDLER, "        if matches!(error, StageError::Environment(_) | StageError::Blocked(_)) {\n            let cap = rule.reply_cap();", "        if false && matches!(error, StageError::Environment(_) | StageError::Blocked(_)) {\n            let cap = rule.reply_cap();")],
    ),
    (
        "LB-02: the environment is told before the design gate has passed (the unreadable rule gets the environment text)",
        WORKFLOW_TESTS,
        [(HANDLER, "                    .reply(&identity, &snapshot.issue, Reply::CannotCheck, \"\", &cap)", "                    .reply(&identity, &snapshot.issue, Reply::EnvironmentBlocked, \"\", &cap)")],
    ),
    (
        "LB-02: a comment that cannot be posted fails the attempt and turns the block into a retry",
        WORKFLOW_TESTS,
        [(HANDLER, "                design::reply_reason(design::ENVIRONMENT_REPLY_LEAD, issue_text, status, &cap),\n            );\n        }\n        error", "                design::reply_reason(design::ENVIRONMENT_REPLY_LEAD, issue_text, status, &cap),\n            );\n            if status == ReplyStatus::Later {\n                return StageError::Tool;\n            }\n        }\n        error")],
    ),
    (
        "LB-02: the comment is asked for with a cap of its own and not the policy's",
        WORKFLOW_TESTS,
        [(HANDLER, "        if matches!(error, StageError::Environment(_) | StageError::Blocked(_)) {\n            let cap = rule.reply_cap();", "        if matches!(error, StageError::Environment(_) | StageError::Blocked(_)) {\n            let cap = factory_domain::policy::issue_workflow::ReplyCap::WHEN_THE_POLICY_CANNOT_BE_READ;")],
    ),
    (
        "LB-02: the comment has the key of the design replies, so one stage run may leave two",
        WORKFLOW_TESTS,
        [(HANDLER, "            Reply::EnvironmentBlocked => format!(\"environment-{}\", identity.stage_run),", "            Reply::EnvironmentBlocked => format!(\"design-gate-{}\", identity.stage_run),")],
    ),
    (
        "LB-02: the record of the comment is not written",
        WORKFLOW_TESTS,
        [(HANDLER, "            ctx.note_audit_because(\n                AuditAction::new(\n                    AuditKind::SandboxCreatedPostureResultDestroyed,\n                    AuditDecision::Denied,\n                ),\n                design::reply_reason(design::ENVIRONMENT_REPLY_LEAD, issue_text, status, &cap),\n            );", "            let _ = status;")],
    ),
    (
        "STS-1 stays: the status step writes for a job whose intake is only blocked",
        STATUS_TESTS,
        [(STATUS, "            && matches!(status, StageRunStatus::Passed | StageRunStatus::Superseded)", "            && matches!(\n                status,\n                StageRunStatus::Passed | StageRunStatus::Superseded | StageRunStatus::Blocked\n            )")],
    ),
]


def failed_tests(output):
    found = set()
    for line in output.splitlines():
        words = line.split()
        if len(words) >= 4 and words[0] == "FAIL":
            found.add(words[-1])
    return sorted(found)


def main():
    originals = {}
    outcomes = []
    only = sys.argv[1:]
    try:
        for name, command, edits in BREAKS:
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
            done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            output = done.stdout + done.stderr
            for file in texts:
                (ROOT / file).write_text(originals[file])
            if "could not compile" in output or "error[E" in output:
                verdict = "INVALID (does not compile)"
            elif done.returncode == 0:
                verdict = "MISSED"
            else:
                failed = failed_tests(output)
                shown = "; ".join(failed[:3]) + (f"; and {len(failed) - 3} more" if len(failed) > 3 else "")
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
