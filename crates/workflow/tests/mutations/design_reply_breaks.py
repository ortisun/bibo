"""Deliberate breaks of the reply to a refused design (DG-9), each of which a test must catch.

    python3 -I crates/workflow/tests/mutations/design_reply_breaks.py [WORD]

With a word, only the breaks whose name contains it are run.

The four parts of DG-9: (a) a cap on the replies for one issue, (b) a bounded look for the reply
that was already posted, (c) the token of the reply ended on every outcome, and (d) the record of the
refusal written before the reply, and a reply that cannot be posted never turning a block into a
failure. For each break the script changes one place in the source (the old text must occur exactly
once), runs the tests named for it, and puts the file back. A break is CAUGHT when the tests fail,
MISSED when they pass, and INVALID when the changed source does not compile. The script exits with 1
if any break is MISSED or INVALID. It leaves the working tree as it found it, also when it is
interrupted, but run it on a clean tree.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]

CHANGES = "crates/github/src/changes.rs"
HANDLER = "crates/workflow/src/stages/intake/handler.rs"
DESIGN = "crates/workflow/src/stages/intake/design.rs"
RECHECK = "crates/workflow/src/stages/delivery/design_recheck.rs"
COMPOSITION = "crates/composition/src/design_gate.rs"
DOMAIN = "crates/domain/src/policy/issue_workflow.rs"
PORTS = "crates/ports/src/githost.rs"
PYTHON_LIB = "scripts/lib/issue_workflow.py"

NEXTEST = ["cargo", "nextest", "run", "--offline", "--no-fail-fast"]
ADAPTER_TESTS = NEXTEST + ["-p", "factory-github", "--test", "comment_cap"]
COMPOSITION_TESTS = NEXTEST + ["-p", "factory-composition", "--test", "design_gate"]
WORKFLOW_TESTS = NEXTEST + ["-p", "factory-workflow", "--test", "intake_repo", "--test", "delivery", "-E", "test(design)"]
POLICY_TESTS = NEXTEST + ["-p", "factory-contracts", "--test", "issue_workflow"]
PORTS_TESTS = NEXTEST + ["-p", "factory-ports", "--lib"]
PYTHON_TESTS = ["uv", "run", "--no-project", "--with", "pyyaml==6.0.3", "python", "-I", "scripts/tests/test_issue_workflow.py"]

# (name, command, [(file, old, new)])
BREAKS = [
    # ---- (a) the cap ------------------------------------------------------------------------
    (
        "DG-9a: the adapter ignores the cap and posts a sixth reply",
        ADAPTER_TESTS,
        [(CHANGES, "        if u32::try_from(held).map_or(true, |held| held >= cap.max()) {\n            return Ok(CappedPost::CapReached);", "        if false && u32::try_from(held).map_or(true, |held| held >= cap.max()) {\n            return Ok(CappedPost::CapReached);")],
    ),
    (
        "DG-9a: the adapter counts every comment of the App and not only the replies of the family",
        ADAPTER_TESTS,
        [(CHANGES, "            .filter(|comment| carries(comment, &family))\n            .count();", "            .count();")],
    ),
    (
        "DG-9a: the adapter counts the comments of anybody, so a pasted copy uses up the cap",
        ADAPTER_TESTS,
        [(CHANGES, "        let own: Vec<&Value> = page\n            .items\n            .iter()\n            .filter(|comment| comment[\"user\"][\"login\"].as_str() == Some(bot.as_str()))\n            .collect();", "        let own: Vec<&Value> = page.items.iter().collect();\n        let _ = &bot;")],
    ),
    (
        "DG-9a: the window is dropped, so a reply of last year counts",
        ADAPTER_TESTS,
        [(CHANGES, "        let path = format!(\n            \"{}/issues/{number}/comments?since={since}\",\n            repo_path(&scope.repo)\n        );", "        let _ = &since;\n        let path = format!(\"{}/issues/{number}/comments\", repo_path(&scope.repo));")],
    ),
    (
        "DG-9a: the stage asks with a number of its own and not the cap of the policy",
        WORKFLOW_TESTS,
        [(HANDLER, "            let cap = design_rule.reply_cap();", "            let cap = ReplyCap::WHEN_THE_POLICY_CANNOT_BE_READ;")],
    ),
    (
        "DG-9a: the re-check asks with a number of its own and not the cap of the policy",
        WORKFLOW_TESTS,
        [(RECHECK, "                    let cap = rule.reply_cap();", "                    let cap = ReplyCap::WHEN_THE_POLICY_CANNOT_BE_READ;")],
    ),
    (
        "DG-9a: a reply held back by the cap is recorded as posted",
        WORKFLOW_TESTS,
        [(DESIGN, "            Err(ReplyError::CapReached) => Self::CapReached,", "            Err(ReplyError::CapReached) => Self::Posted,")],
    ),
    (
        "DG-9a: a cap of zero is accepted by the policy type",
        POLICY_TESTS,
        [(DOMAIN, "        if !(1..=REPLY_CAP_MOST).contains(&max)\n", "        if max > REPLY_CAP_MOST\n")],
    ),
    (
        "DG-9a: a cap of zero is accepted by the port type",
        PORTS_TESTS,
        [(PORTS, "        if max == 0 || max > Self::MOST || window.is_zero() {", "        if max > Self::MOST || window.is_zero() {")],
    ),
    (
        "DG-9a: the Python tool accepts a cap of zero",
        PYTHON_TESTS,
        [(PYTHON_LIB, "_REPLY_CAP_RANGE = (1, 100)", "_REPLY_CAP_RANGE = (0, 100)")],
    ),
    # ---- (b) the bounded look ---------------------------------------------------------------
    (
        "DG-9b: a cut listing is not noticed, so the adapter posts without knowing",
        ADAPTER_TESTS,
        [(CHANGES, "        if page.truncated {\n            return Ok(CappedPost::NotChecked);\n        }\n", "")],
    ),
    (
        "DG-9b: the adapter reads ten pages, as the old look for a marker did",
        ADAPTER_TESTS,
        [(CHANGES, "            .get_pages_up_to(scope, TokenClass::Comment, &path, 1)", "            .get_pages_up_to(scope, TokenClass::Comment, &path, 10)")],
    ),
    (
        "DG-9b: a thread too long to check is taken for a reply that went through",
        COMPOSITION_TESTS,
        [(COMPOSITION, "        Ok(CappedPost::NotChecked) => Err(ReplyError::NotChecked),", "        Ok(CappedPost::NotChecked) => Ok(()),")],
    ),
    (
        "DG-9b: any reply of the family is taken for the answer to this key",
        ADAPTER_TESTS,
        [(CHANGES, "            .filter(|comment| carries(comment, &marker))", "            .filter(|comment| carries(comment, \"factory-family:\"))")],
    ),
    # ---- (c) the token ----------------------------------------------------------------------
    (
        "DG-9c: the token of a reply that is for later is kept (the old condition)",
        COMPOSITION_TESTS,
        [(COMPOSITION, "        let _ = self.host.revoke_job_tokens(scope.job).await;\n        result", "        if result != Err(ReplyError::Later) {\n            let _ = self.host.revoke_job_tokens(scope.job).await;\n        }\n        result")],
    ),
    (
        "DG-9c: the token of a reply that was held back by the cap is kept",
        COMPOSITION_TESTS,
        [(COMPOSITION, "        let _ = self.host.revoke_job_tokens(scope.job).await;\n        result", "        if !matches!(result, Err(ReplyError::CapReached | ReplyError::NotChecked)) {\n            let _ = self.host.revoke_job_tokens(scope.job).await;\n        }\n        result")],
    ),
    # ---- (d) the record, and a block that stays a block ---------------------------------------
    (
        "DG-9d: the last attempt also fails for a comment that cannot be posted, so the block ends as a failed job",
        WORKFLOW_TESTS,
        [(HANDLER, "            if status == ReplyStatus::Later && i64::from(ctx.attempt_number) < attempts {", "            let _ = attempts;\n            if status == ReplyStatus::Later {")],
    ),
    (
        "DG-9d: a comment that cannot be posted is never tried again, so a blip loses the answer",
        WORKFLOW_TESTS,
        [(HANDLER, "            if status == ReplyStatus::Later && i64::from(ctx.attempt_number) < attempts {", "            if false && status == ReplyStatus::Later && i64::from(ctx.attempt_number) < attempts {")],
    ),
    (
        "DG-9d: the record of the refusal is not written before the reply",
        WORKFLOW_TESTS,
        [(HANDLER, "                refused.then_some(ReplyStatus::ToFollow),", "                None,")],
    ),
    (
        "DG-9d: the reply has no record of its own, so a held-back reply leaves no trace",
        WORKFLOW_TESTS,
        [(HANDLER, "            ctx.note_audit_because(\n                AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),\n                design::reply_reason(design::INTAKE_REPLY_LEAD, &issue_text, status, &cap),\n            );\n            // A comment that cannot be posted now", "            let _ = (&cap, &issue_text);\n            // A comment that cannot be posted now")],
    ),
    (
        "DG-9d: the re-check writes no record of its reply",
        WORKFLOW_TESTS,
        [(RECHECK, "                    ctx.note_audit_because(\n                        AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),\n                        design::reply_reason(design::RECHECK_REPLY_LEAD, &issue_text, status, &cap),\n                    );\n", "                    let _ = status;\n")],
    ),
]


def failed_tests(output):
    found = set()
    for line in output.splitlines():
        words = line.split()
        if len(words) >= 4 and words[0] == "FAIL":
            found.add(words[-1])
        elif words and words[0] in ("FAIL:", "ERROR:") and len(words) > 1:
            found.add(words[1])
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
