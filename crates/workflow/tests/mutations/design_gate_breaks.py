"""Deliberate breaks of the design gate at intake (ADR 0016), each of which a test must catch.

    python3 -I crates/workflow/tests/mutations/design_gate_breaks.py [WORD ...]

For each break the script changes one or two places in the sources of the gate (the old text must
occur exactly once in its file), runs `cargo test -p factory-workflow --offline --test intake_repo`,
and puts every file back. A break is CAUGHT when the tests fail, MISSED when they pass, and INVALID
when the changed source does not compile. The script exits with 1 if any break is MISSED or
INVALID. It leaves the working tree as it found it, also when it is interrupted, but run it on a
clean tree.

The tests that catch a break are in `crates/workflow/tests/intake_repo/design.rs`. Each of them has
a sibling that passes on the unbroken code, so a break that is CAUGHT is caught for the reason in
its name and not because the setup is wrong.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[4]
HANDLER = "crates/workflow/src/stages/intake/handler.rs"
DESIGN = "crates/workflow/src/stages/intake/design.rs"
DOMAIN = "crates/domain/src/policy/issue_workflow.rs"

# (name, [(file, old, new)])
BREAKS = [
    (
        "skip the refusal: an issue whose design is not approved goes on to the classifier",
        [(HANDLER, "        if !design_decision.allows_work() {\n            // No sandbox was made", "        if false && !design_decision.allows_work() {\n            // No sandbox was made")],
    ),
    (
        "read no design labels at all, as if the issue were a small change",
        [(HANDLER, "        let labels = rule.classify(&fetched.labels);", "        let labels = rule.classify(&[]);")],
    ),
    (
        "take the person who applied the approval from the factory label instead of from the approved label",
        [(HANDLER, "                .label_application(&scope, issue, rule.approved_label())", "                .label_application(&scope, issue, &self.config.label)")],
    ),
    (
        "hold the person who applied the approval to the requester designation",
        [(DESIGN, "                judging.gate.approved_by(),\n", "                factory_domain::policy::decision::Designation::Requester,\n")],
    ),
    (
        "approve a label whose applier cannot be found",
        [(DESIGN, "                } => refused(RefusalReason::ApprovalLabelGone, seen, None),", "                } => DesignDecision::Approved {\n                    approver: 0,\n                    allowlist_version: String::new(),\n                },")],
    ),
    (
        "do not post the comment",
        [(HANDLER, "        match self.replies.post(identity.tenant, issue, &key, &text).await {", "        let _ = (&key, &text);\n        match Ok::<(), ReplyError>(()) {")],
    ),
    (
        "a comment that cannot be posted now is forgotten instead of tried again",
        [(HANDLER, "            Err(ReplyError::Later) => Err(StageError::Tool),", "            Err(ReplyError::Later) => Ok(ReplyStatus::NotSent),")],
    ),
    (
        "a rule that cannot be read fails the attempt as a tool error instead of blocking the run",
        [(HANDLER, "                return Err(StageError::Environment(\n                    factory_domain::machines::guards::EnvironmentCause::PolicyUnloadable,\n                ));\n            }\n            Err(DesignStop::Stage(error))", "                return Err(StageError::Tool);\n            }\n            Err(DesignStop::Stage(error))")],
    ),
    (
        "the gate reports PASSED when the design is not approved",
        [(DESIGN, "                \"BLOCKED\",\n                \"The design is not approved\",", "                \"PASSED\",\n                \"The design is not approved\",")],
    ),
    (
        "match the design prefix with the case of the letters",
        [(DOMAIN, "head.eq_ignore_ascii_case(&self.track_key)", "head == self.track_key")],
    ),
    (
        "the approved label beside another design label counts as approved",
        [(DOMAIN, "            (true, true) => DesignLabels::Ambiguous { seen },", "            (true, true) => DesignLabels::ApprovalLabelOnly,")],
    ),
    (
        "compare the approved label after trimming and without the case of the letters",
        [
            (DOMAIN, "            .any(|name| name.as_str() == self.approved_label);\n        let others", "            .any(|name| name.trim().eq_ignore_ascii_case(&self.approved_label));\n        let others"),
            (DOMAIN, "            .any(|name| name.as_str() != self.approved_label);", "            .any(|name| !name.trim().eq_ignore_ascii_case(&self.approved_label));"),
        ],
    ),
]


def run():
    command = ["cargo", "test", "-p", "factory-workflow", "--offline", "--test", "intake_repo"]
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def main():
    originals = {}
    outcomes = []
    # Words after the script name select the breaks whose name contains one of them.
    only = sys.argv[1:]
    try:
        for name, edits in BREAKS:
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
            code, output = run()
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
