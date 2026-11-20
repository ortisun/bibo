"""Deliberate breaks of the fixes of the review of the design gate round two and the runtime
configuration (`docs/reviews/design-gate-round-two-and-runtime-security-review.md`), each of which a
test must catch.

    python3 -I crates/workflow/tests/mutations/review_round_two_breaks.py [WORD ...]

* DR-1: the approval covers the words as they were when it was applied (`design.rs`, `judge.rs`, and
  the reading of the edit time in `crates/github/src/edits.rs` and `issues.rs`).
* DR-3: the record of a refusal is written to the store before the reply is tried (`handler.rs`,
  `delivery/design_recheck.rs`, `engine/durable.rs`).
* DR-4: a cap for each kind of reply, and a bounded look at the thread (`domain`, `github`,
  `composition`).
* DR-10: the re-check before the pull request reads the issue with the narrow scope of the intake
  stage and not with the token of the delivery stage (`delivery/design_recheck.rs`).

For each break the script changes one or two places in the sources (the old text must occur exactly
once in its file), runs the tests that must notice with `cargo nextest`, and puts every file back. A
break is CAUGHT when the tests fail, MISSED when they pass, and INVALID when the changed source does
not compile. The script exits with 1 if any break is MISSED or INVALID. It leaves the working tree as
it found it, also when it is interrupted, but run it on a clean tree. Words after the script name
select the breaks whose name contains one of them.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
DESIGN = "crates/workflow/src/stages/intake/design.rs"
JUDGE = "crates/workflow/src/stages/intake/judge.rs"
HANDLER = "crates/workflow/src/stages/intake/handler.rs"
RECHECK = "crates/workflow/src/stages/delivery/design_recheck.rs"
DURABLE = "crates/workflow/src/engine/durable.rs"
CONTEXT = "crates/workflow/src/handlers/context.rs"
EDITS = "crates/github/src/edits.rs"
ISSUES = "crates/github/src/issues.rs"
CHANGES = "crates/github/src/changes.rs"
DOMAIN = "crates/domain/src/policy/issue_workflow.rs"
GATE = "crates/composition/src/design_gate.rs"

# What each group of breaks is tested with: (package arguments, nextest filter).
INTAKE = (["-p", "factory-workflow", "--test", "intake_repo"], "test(approval_words) or test(durable_record)")
RECHECKING = (["-p", "factory-workflow", "--test", "delivery"], "test(design_recheck_words) or test(design_recheck_durable)")
UNITS = (["-p", "factory-workflow", "--lib"], "test(stages::intake::design)")
ENGINE = (["-p", "factory-workflow", "--test", "intake_repo"], "test(durable_record)")
ADAPTER = (["-p", "factory-github"], "binary(issue_text_edit) or test(edits::tests)")
CAP_ADAPTER = (["-p", "factory-github", "--test", "comment_cap"], "all()")
KINDS_DOMAIN = (["-p", "factory-contracts", "--test", "issue_workflow"], "all()")
KINDS_COMPOSED = (["-p", "factory-composition", "--test", "design_gate"], "all()")

# (name, tests, [(file, old, new)])
BREAKS = [
    # ---- DR-1: the approval covers the words as they were ----
    (
        "DR-1: an edit in the same second as the approval counts as before it",
        UNITS,
        [(DESIGN, "(Some(applied), TextEdit::At(edited)) if edited < applied => Self::Covers,", "(Some(applied), TextEdit::At(edited)) if edited <= applied => Self::Covers,")],
    ),
    (
        "DR-1: an edit after the approval is not refused",
        INTAKE,
        [(DESIGN, "(Some(_), TextEdit::At(_)) => Self::EditedAfter,", "(Some(_), TextEdit::At(_)) => Self::Covers,")],
    ),
    (
        "DR-1: an edit time the source cannot say covers the words",
        INTAKE,
        [(DESIGN, "(_, TextEdit::Unknown) | (None, _) => Self::Unreadable,", "(_, TextEdit::Unknown) => Self::Covers,\n            (None, _) => Self::Unreadable,")],
    ),
    (
        "DR-1: an approval with no time of application covers the words",
        INTAKE,
        [(DESIGN, "(_, TextEdit::Unknown) | (None, _) => Self::Unreadable,", "(_, TextEdit::Unknown) => Self::Unreadable,\n            (None, _) => Self::Covers,")],
    ),
    (
        "DR-1: the judgement does not ask whether the approval covers the words",
        INTAKE,
        [(JUDGE, "            ApprovalCoverage::of(applied.as_ref().and_then(|found| found.applied_at), edit)", "            { let _ = edit; ApprovalCoverage::Covers }")],
    ),
    (
        "DR-1: a host that cannot answer the edit time is taken for a pass",
        INTAKE,
        [(JUDGE, "                .text_edit(scope, issue)\n                .await\n                .map_err(|_| DesignStop::Stage(StageError::Tool))?;", "                .text_edit(scope, issue)\n                .await\n                .unwrap_or(factory_ports::githost::TextEdit::Never);")],
    ),
    (
        "DR-1: the gate lets an issue through that is covered only when the person is wrong too (the unreadable case approves)",
        INTAKE,
        [(DESIGN, "                    ApprovalCoverage::Unreadable | ApprovalCoverage::NotAsked => {\n                        refused(RefusalReason::EditTimeUnreadable, seen, Some(actor))\n                    }", "                    ApprovalCoverage::Unreadable | ApprovalCoverage::NotAsked => {\n                        DesignDecision::Approved { approver: actor, allowlist_version }\n                    }")],
    ),
    (
        "DR-1: the re-check before the pull request does not look at the edit (only intake does)",
        RECHECKING,
        [(JUDGE, "        let coverage = if labels == DesignLabels::ApprovalLabelOnly {", "        let coverage = if labels == DesignLabels::ApprovalLabelOnly && stored_text.is_some() {"),
         (JUDGE, "        } else {\n            ApprovalCoverage::NotAsked\n        };", "        } else if labels == DesignLabels::ApprovalLabelOnly {\n            ApprovalCoverage::Covers\n        } else {\n            ApprovalCoverage::NotAsked\n        };")],
    ),
    (
        "DR-1: an edit of the words that is not after the approval refuses it (the comparison is the wrong way round)",
        INTAKE,
        [(DESIGN, "(Some(applied), TextEdit::At(edited)) if edited < applied => Self::Covers,", "(Some(applied), TextEdit::At(edited)) if edited > applied => Self::Covers,")],
    ),
    (
        "DR-1: the reason for the person comes after the edit (an edit hides the wrong approver)",
        INTAKE,
        [(DESIGN, "    let by_the_labels = match labels {", "    let by_the_labels = match labels {\n        DesignLabels::ApprovalLabelOnly if coverage == ApprovalCoverage::EditedAfter => {\n            refused(RefusalReason::ApprovalOlderThanText, vec![], None)\n        }")],
    ),
    (
        "DR-1: the adapter reads only the body edit and not the title",
        ADAPTER,
        [(EDITS, "        (Some(a), Some(b)) => TextEdit::At(a.max(b)),", "        (Some(a), Some(_)) => TextEdit::At(a),")],
    ),
    (
        "DR-1: the adapter ignores the renamed events (a title edit does not count)",
        ADAPTER,
        [(EDITS, "        if kind != \"renamed\" {\n            continue;\n        }", "        if kind != \"renamed\" || true {\n            continue;\n        }")],
    ),
    (
        "DR-1: a missing lastEditedAt reads as never edited",
        ADAPTER,
        [(EDITS, "    match issue.get(\"lastEditedAt\").ok_or(())? {", "    match issue.get(\"lastEditedAt\").unwrap_or(&Value::Null) {")],
    ),
    (
        "DR-1: an errors member of the answer is ignored",
        ADAPTER,
        [(EDITS, "    if answer.get(\"errors\").is_some_and(|errors| !errors.is_null()) {\n        return Err(());\n    }", "")],
    ),
    (
        "DR-1: a list of events that is cut is taken for the whole",
        ADAPTER,
        [(ISSUES, "        if events.truncated {\n            return Ok(TextEdit::Unknown);\n        }", "")],
    ),
    # ---- DR-3: the record is in the store before the reply ----
    (
        "DR-3: the decision of a refusal is only noted for the end of the attempt",
        ENGINE,
        [(HANDLER, "            ctx.record_now(decision_action, decision_reason).await?;", "            ctx.note_audit_because(decision_action, decision_reason);")],
    ),
    (
        "DR-3: the decision of a design that cannot be judged is only noted",
        ENGINE,
        [(HANDLER, "                ctx.record_now(\n                    AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),\n                    design::unjudgeable_reason(&issue_text, Some(ReplyStatus::ToFollow)),\n                )\n                .await?;", "                ctx.note_audit_because(\n                    AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),\n                    design::unjudgeable_reason(&issue_text, Some(ReplyStatus::ToFollow)),\n                );")],
    ),
    (
        "DR-3: the record that the notice about the environment is to follow is not written first",
        ENGINE,
        [(HANDLER, "            if ctx\n                .record_now(", "            if false\n                && ctx\n                .record_now(")],
    ),
    (
        "DR-3: the re-check writes its decision only as a note",
        RECHECKING,
        [(RECHECK, "                    ctx.record_now(\n                        AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),\n                        self.judge.redacted_reason(design::recheck_audit_reason(\n                            &decision,\n                            &issue_text,\n                            Some(ReplyStatus::ToFollow),\n                        )),\n                    )\n                    .await?;", "                    ctx.note_audit_because(\n                        AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),\n                        self.judge.redacted_reason(design::recheck_audit_reason(\n                            &decision,\n                            &issue_text,\n                            Some(ReplyStatus::ToFollow),\n                        )),\n                    );")],
    ),
    (
        "DR-3: the re-check that cannot judge writes its decision only as a note",
        RECHECKING,
        [(RECHECK, "        ctx.record_now(\n            AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),\n            design::recheck_unjudgeable_reason(issue_text, Some(ReplyStatus::ToFollow)),\n        )\n        .await?;", "        ctx.note_audit_because(\n            AuditAction::new(AuditKind::AuthorizationDecision, AuditDecision::Denied),\n            design::recheck_unjudgeable_reason(issue_text, Some(ReplyStatus::ToFollow)),\n        );")],
    ),
    (
        "DR-3: the writer of the engine never commits",
        ENGINE,
        [(DURABLE, "        tx.commit().await.map_err(|_| StageError::Tool)", "        tx.rollback().await.map_err(|_| StageError::Tool)")],
    ),
    (
        "DR-3: a record that cannot be written does not stop the reply",
        RECHECKING,
        [(CONTEXT, "            Some(records) => records.record(action, reason).await,", "            Some(records) => {\n                let _ = records.record(action, reason).await;\n                Ok(())\n            }")],
    ),
    # ---- DR-10: the re-check reads with the narrow scope ----
    (
        "DR-10: the re-check reads the issue with the token of the delivery stage, which can write",
        RECHECKING,
        [(RECHECK, "                scope: &reading,", "                scope,")],
    ),
    # ---- DR-4: a cap for each kind, and a bounded look ----
    (
        "DR-4: the stop before the pull request is counted with the refusals",
        UNITS,
        [(DESIGN, "            Self::DesignWithdrawn | Self::CannotCheckAgain => ReplyKind::Withdrawal,", "            Self::DesignWithdrawn | Self::CannotCheckAgain => ReplyKind::Refusal,")],
    ),
    (
        "DR-4: the notice about the environment is counted with the refusals",
        UNITS,
        [(DESIGN, "            Self::EnvironmentBlocked => ReplyKind::Environment,", "            Self::EnvironmentBlocked => ReplyKind::Refusal,")],
    ),
    (
        "DR-4: every kind has the family of the refusals",
        KINDS_DOMAIN,
        [(DOMAIN, "            Self::Withdrawal => \"design-withdrawal\",", "            Self::Withdrawal => \"design-refusal\","),
         (DOMAIN, "            Self::Environment => \"design-environment\",", "            Self::Environment => \"design-refusal\",")],
    ),
    (
        "DR-4: every kind has the cap of the refusals",
        KINDS_DOMAIN,
        [(DOMAIN, "            ReplyKind::Withdrawal => self.reply_caps[1],", "            ReplyKind::Withdrawal => self.reply_caps[0],")],
    ),
    (
        "DR-4: the poster marks every reply with one family whatever its kind",
        KINDS_COMPOSED,
        [(GATE, "CommentCap::new(cap.kind().family(), cap.max(), cap.window())", "CommentCap::new(\"intake-design\", cap.max(), cap.window())")],
    ),
    (
        "DR-4: the look at the thread is one page again",
        CAP_ADAPTER,
        [(CHANGES, "const CAPPED_LOOK_PAGES: u32 = 3;", "const CAPPED_LOOK_PAGES: u32 = 1;")],
    ),
    (
        "DR-4: the look at the thread is not bounded",
        CAP_ADAPTER,
        [(CHANGES, "const CAPPED_LOOK_PAGES: u32 = 3;", "const CAPPED_LOOK_PAGES: u32 = 30;")],
    ),
    (
        "DR-4: a look that is cut is taken for the whole thread",
        CAP_ADAPTER,
        [(CHANGES, "        if page.truncated {\n            return Ok(CappedPost::NotChecked);\n        }", "")],
    ),
]


def command(tests):
    packages, expression = tests
    return ["cargo", "nextest", "run", "--offline", "--no-fail-fast", *packages, "-E", expression]


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
        for name, tests, edits in BREAKS:
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
            done = subprocess.run(command(tests), cwd=ROOT, capture_output=True, text=True)
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
