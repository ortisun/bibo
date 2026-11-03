"""Deliberate breaks of the two decisions of the product owner of 2026-11-02 (ADR 0016), each of
which a test must catch.

    python3 -I crates/workflow/tests/mutations/design_text_and_recheck_breaks.py [--check] [WORD ...]

* DG-3: the text a job carries must be the text of the live issue (`design.rs`, `judge.rs`).
* DG-8: the design is checked again right before the pull request is opened
  (`delivery/design_recheck.rs`, `delivery/handler.rs`).

For each break the script changes one or two places in the sources (the old text must occur exactly
once in its file), runs the tests that must notice (`cargo test -p factory-workflow --offline
--no-fail-fast` with the targets named for the break), and puts every file back. A break is CAUGHT
when the tests fail, MISSED when they pass, and INVALID when the changed source does not compile.
The script exits with 1 if any break is MISSED or INVALID. It leaves the working tree as it found
it, also when it is interrupted, but run it on a clean tree.

`--check` runs nothing and changes nothing: it reports every break whose old text does not occur
exactly once in its file, which is a break that proves nothing, and exits with 1 if there is one.
Run it after any change to the sources named here.

Words after the script name select the breaks whose name contains one of them. The breaks of the
older fixes of the design gate (DG-1 to DG-7) are in `design_gate_breaks.py`.
"""

import os
import pathlib
import signal
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[4]
DESIGN = "crates/workflow/src/stages/intake/design.rs"
JUDGE = "crates/workflow/src/stages/intake/judge.rs"
HANDLER = "crates/workflow/src/stages/intake/handler.rs"
RECHECK = "crates/workflow/src/stages/delivery/design_recheck.rs"
DELIVERY = "crates/workflow/src/stages/delivery/handler.rs"

# The test targets that must notice a break of each decision.
TEXT = ["--lib", "--test", "intake_repo"]
RECHECKING = ["--test", "delivery"]

# (name, targets, [(file, old, new)])
BREAKS = [
    # ---- DG-3: the text of the job is the text of the live issue ----
    (
        "DG-3: the texts are never compared, every job counts as the issue's text",
        TEXT,
        [(JUDGE, "                design::compare_text(&live, stored)", "                { let _ = (&live, stored); TextCheck::Same }")],
    ),
    (
        "DG-3: the live text is not passed to the gate for a job that has text (the webhook path is not the only one)",
        TEXT,
        [(HANDLER, "                stored_text: Some(&snapshot.text),", "                stored_text: None,")],
    ),
    (
        "DG-3: a different text refuses only an issue that is on the design track",
        TEXT,
        [(DESIGN, "        (DesignDecision::NotOnTrack | DesignDecision::Approved { .. }, TextCheck::Different) => {", "        (DesignDecision::Approved { .. }, TextCheck::Different) => {")],
    ),
    (
        "DG-3: a different text does not refuse an issue whose design is approved",
        TEXT,
        [(DESIGN, "        (DesignDecision::NotOnTrack | DesignDecision::Approved { .. }, TextCheck::Different) => {", "        (DesignDecision::NotOnTrack, TextCheck::Different) => {")],
    ),
    (
        "DG-3: the comparison is byte for byte, line ends and outer white space count",
        TEXT,
        [(DESIGN, "    text.replace(\"\\r\\n\", \"\\n\")\n        .replace('\\r', \"\\n\")\n        .trim()\n        .to_owned()", "    text.to_owned()")],
    ),
    (
        "DG-3: the comparison ignores the letter case",
        TEXT,
        [(DESIGN, "        .trim()\n        .to_owned()", "        .trim()\n        .to_lowercase()")],
    ),
    (
        "DG-3: the comparison ignores everything after the first line",
        TEXT,
        [(DESIGN, "    if canonical_text(live) == canonical_text(stored) {", "    if canonical_text(live).lines().next() == canonical_text(stored).lines().next() {")],
    ),
    (
        "DG-3: the live text is compared before the secrets in it are replaced",
        TEXT,
        [(JUDGE, "                let (live, _) =\n                    redact_request(&self.redactor, &request_text(&fetched.title, &fetched.body))\n                        .map_err(DesignStop::Stage)?;", "                let live = request_text(&fetched.title, &fetched.body);")],
    ),
    (
        "DG-3: the audit line does not say what the comparison found",
        TEXT,
        [(DESIGN, "    let compared = format!(\n        \"text of the job compared with the live issue: {}\",\n        text.word()\n    );", "    let compared = \"text of the job compared with the live issue: same\".to_owned();")],
    ),
    (
        "DG-3: a refusal for the text is reported as the design not approved, with no reason of its own",
        TEXT,
        [(DESIGN, "            Self::TextNotTheIssue => \"text_not_the_issue\",", "            Self::TextNotTheIssue => \"not_approved\",")],
    ),
    # ---- DG-8: the design is checked again before the pull request is opened ----
    (
        "DG-8: the design is not checked again before the pull request",
        RECHECKING,
        [(DELIVERY, "        self.deps.recheck.check(ctx, &git, &target.issue).await?;", "        let _ = (&git, &target.issue);")],
    ),
    (
        "DG-8: a design that is not approved now does not stop the stage",
        RECHECKING,
        [(RECHECK, "                    return Err(StageError::Blocked(BlockedCode::DesignNotApproved));", "                    return Ok(());")],
    ),
    (
        "DG-8: a refusal of the re-check fails the attempt as a tool error instead of blocking the run",
        RECHECKING,
        [(RECHECK, "                    return Err(StageError::Blocked(BlockedCode::DesignNotApproved));", "                    return Err(StageError::Tool);")],
    ),
    (
        "DG-8: a code host that cannot be read is taken for a pass",
        RECHECKING,
        [(RECHECK, "                Err(error)\n            }\n        }\n    }", "                let _ = error;\n                Ok(())\n            }\n        }\n    }")],
    ),
    (
        "DG-8: a rule that cannot be read is taken for a pass",
        RECHECKING,
        [(RECHECK, "        Err(StageError::Environment(EnvironmentCause::PolicyUnloadable))\n    }", "        let _ = (ctx, scope, issue, issue_text);\n        Ok(())\n    }")],
    ),
    (
        "DG-8: an allowlist that cannot be read is taken for a pass",
        RECHECKING,
        [(RECHECK, "        let Ok(allowlist) = self.allowlists.current(scope.tenant).await else {\n            return self.cannot_judge(ctx, scope, issue, &issue_text).await;\n        };", "        let Ok(allowlist) = self.allowlists.current(scope.tenant).await else {\n            return Ok(());\n        };")],
    ),
    (
        "DG-8: nothing is written on the record when the design is refused (neither the decision nor the reply)",
        RECHECKING,
        [
            (RECHECK, "                    ctx.record_now(\n                        AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),\n                        self.judge.redacted_reason(design::recheck_audit_reason(\n                            &decision,\n                            &issue_text,\n                            Some(ReplyStatus::ToFollow),\n                        )),\n                    )\n                    .await?;", "                    let _ = &decision;"),
            (RECHECK, "                    ctx.note_audit_because(\n                        AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),\n                        design::reply_reason(design::RECHECK_REPLY_LEAD, &issue_text, status, &cap),\n                    );", "                    let _ = status;"),
        ],
    ),
    (
        "DG-8: the audit line of the re-check is stored without the secret redactor",
        RECHECKING,
        [(RECHECK, "                        self.judge.redacted_reason(design::recheck_audit_reason(\n                            &decision,\n                            &issue_text,\n                            Some(ReplyStatus::ToFollow),\n                        )),", "                        design::recheck_audit_reason(&decision, &issue_text, Some(ReplyStatus::ToFollow)),")],
    ),
    (
        "DG-8: the person is not told that no pull request was opened",
        RECHECKING,
        [(RECHECK, "        ReplyStatus::of(\n            self.replies\n                .post(scope.tenant, issue, &key, &text, cap)\n                .await,\n        )", "        let _ = (&key, &text, cap);\n        ReplyStatus::of(Ok(()))")],
    ),
    (
        "DG-8: a code host that is down is reported as a pass by the judge (the shared reader forgets the failed fetch)",
        RECHECKING,
        [(JUDGE, "            .fetch_issue(scope, issue)\n            .await\n            .map_err(|_| DesignStop::Stage(StageError::Tool))?;", "            .fetch_issue(scope, issue)\n            .await\n            .map_err(|_| DesignStop::Unjudgeable)?;")],
    ),
]


def run_cargo(command):
    """Runs the tests and returns (exit code, output).

    A break can leave a test waiting for something that never happens (a reply that is never
    posted, so the test that waits for it never starts). libtest says so after 60 seconds with
    "has been running for over 60 seconds". The run is then given 20 seconds to finish the other
    tests and is ended with SIGTERM, never SIGKILL, and the tests that finished and failed are the
    catch. The hung tests are named in the verdict.
    """
    process = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
    lines = []
    reader = threading.Thread(target=lambda: lines.extend(process.stdout), daemon=True)
    reader.start()
    seen_hung = None
    while process.poll() is None:
        time.sleep(2)
        if seen_hung is None and any("has been running for over" in line for line in lines):
            seen_hung = time.monotonic()
        if seen_hung is not None and time.monotonic() - seen_hung > 20:
            os.killpg(process.pid, signal.SIGTERM)
            break
    process.wait()
    reader.join(timeout=10)
    return process.returncode, "".join(lines)


def hung_tests(output):
    """The names of the tests that libtest reported as running for over 60 seconds."""
    return sorted({line.split()[1] for line in output.splitlines() if line.startswith("test ") and "has been running for over" in line})


def run(targets):
    return run_cargo(["cargo", "test", "-p", "factory-workflow", "--offline", "--no-fail-fast", *targets])


def check():
    """Reports every break whose old text does not occur exactly once in its file. Runs nothing."""
    bad = 0
    for name, targets, edits in BREAKS:
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


def main():
    if "--check" in sys.argv[1:]:
        check()
    originals = {}
    outcomes = []
    only = sys.argv[1:]
    try:
        for name, targets, edits in BREAKS:
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
            code, output = run(targets)
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
                if hung_tests(output):
                    verdict += " (the run also hung on " + "; ".join(hung_tests(output)) + " and was ended with SIGTERM)"
            outcomes.append((name, verdict))
            print(f"{name}: {verdict}", flush=True)
    finally:
        for file, text in originals.items():
            (ROOT / file).write_text(text)
    bad = [o for o in outcomes if not o[1].startswith("CAUGHT")]
    print(f"{len(outcomes) - len(bad)} of {len(outcomes)} breaks caught")
    sys.exit(1 if bad else 0)


main()
