#!/usr/bin/env python3
"""Control-off variants for the P0 tests: remove one control from the sources, and the tests that
depend on it must fail.

Run from the repository root:

    python3 -I tests/security/mutations.py [--record] [name ...]
    python3 -I tests/security/mutations.py [--record] --script crates/sandbox/tests/mutations.py [name ...]

The first form runs the breaks of this file. The second form runs the breaks of another mutation
script of the repository that has a MUTATIONS table and a run_tests function (the sandbox, the
egress and the runtime packages have them), so that what each break made fail is written down in
the same way. The script github/tests/mutations/run_mutations.py runs its breaks when it is
loaded, so it is run on its own and its output is copied by hand.

For each break the script changes the sources (it refuses an edit that does not match exactly once),
runs the tests that are named for it with cargo nextest, prints the tests that failed, and puts the
sources back, also when it is interrupted. A break that no test catches is MISSED and the script
exits with 1. It stops when the tree has uncommitted changes in a file it is about to change, so a
restore can never lose work.

With --record the result of each break is written to `mutation_runs` of docs/security/p0-coverage.json,
which is how the coverage page knows that a break was run, when, and which tests it made fail.
Nothing here is part of the product, and none of it runs in CI: each break rebuilds a crate.
"""

import datetime
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
DATA = ROOT / "docs/security/p0-coverage.json"
SELF = "tests/security/mutations.py"

WORKSPACE = "crates/testkit/src/workspace.rs"
COMMANDS = "crates/domain/src/policy/commands.rs"
EGRESS = "crates/domain/src/policy/egress.rs"
TOOLS = "crates/domain/src/policy/tools.rs"
ATTEMPT = "crates/workflow/src/engine/attempt.rs"
BLOCK = "crates/workflow/src/prompts/block.rs"
PATHS = "crates/domain/src/policy/paths.rs"
JUDGE = "crates/workflow/src/stages/approval/judge.rs"
AUTHORITY = "crates/domain/src/policy/authority.rs"
ATTEMPTS = "crates/storage/src/pg/attempts.rs"
SANDBOX_AUDIT = "crates/workflow/src/engine/sandbox_audit.rs"
WEBHOOK = "apps/api/src/webhook.rs"
IMPLEMENTATION = "crates/workflow/src/stages/implementation/run.rs"
GITHUB_TEXT = "crates/github/src/text.rs"
GITHUB_WEBHOOK = "crates/github/src/webhook.rs"
CONFIG = "crates/composition/src/config.rs"
SIGNING = "crates/composition/src/decision_signing.rs"
TIGHTEN = "crates/domain/src/policy/tighten.rs"
PORTS_SANDBOX = "crates/ports/src/sandbox.rs"
GITHUB_PERMISSIONS = "crates/github/src/permissions.rs"

# name -> (what is broken, [(file, old, new), ...])
MUTATIONS = {
    "the-workspace-lets-any-edit-in": (
        "the audited ingestion of a change no longer checks the protected paths of the rules, so a change to a workflow, a CI script, a test or a fixture is taken in",
        [(WORKSPACE, "                _ if self.has(WorkspaceDefect::AllowsAnyEdit) => false,", "                _ if true => false,")],
    ),
    "the-workspace-skips-the-secret-scan": (
        "the audited ingestion of a change no longer looks for a secret in the files that changed",
        [(WORKSPACE, "        if !self.has(WorkspaceDefect::SkipsSecretScan) {", "        if false {")],
    ),
    "a-forbidden-command-class-denies-nothing": (
        "a command that matches a forbidden class is no longer denied; it falls through to the human gate or the command set",
        [(COMMANDS, "        if let Some(hard) = matched.iter().find(|c| c.action == CommandAction::Deny) {", "        if let Some(hard) = matched.iter().find(|c| c.action == CommandAction::Deny).filter(|_| false) {")],
    ),
    "the-egress-allowlist-matches-any-host": (
        "the egress check lets a host that ends in .test through, so a host that is not on the list is allowed",
        [(EGRESS, "        if self.never_allowed.contains(&host) {", "        if host.ends_with(\".test\") {\n            return EgressVerdict::Allowed {\n                rule: RuleRef::new(area, \"mutation\"),\n            };\n        }\n        if self.never_allowed.contains(&host) {")],
    ),
    "an-agent-may-grant-itself-a-tool": (
        "a request for a grant from the agent is answered like a request from the policy engine",
        [(TOOLS, "            Requester::Agent => ToolVerdict::Denied {\n                reason: ToolDenial::SelfGrant,\n                rule: RuleRef::new(\"tools\", \"agents_may_self_grant\"),\n            },", "            Requester::Agent => ToolVerdict::Allowed { human_gate: HumanGate::None },")],
    ),
    "the-budget-threshold-is-never-recorded": (
        "crossing the budget warning writes no audit record",
        [(ATTEMPT, "        if crossed || job_crossed {", "        if false && (crossed || job_crossed) {")],
    ),
    "a-deny-write-path-may-be-written": (
        "the path policy lets every operation through on a path of a deny_write group",
        [(PATHS, "        ProtectionMode::DenyWrite => matches!(op, Operation::Read),", "        ProtectionMode::DenyWrite => true,")],
    ),
    "a-moved-head-is-not-noticed": (
        "the approval judge no longer compares the head that the person saw with the head of the pull request now",
        [(JUDGE, "    if live.pr_head != &seen.pr_head {", "    if false && live.pr_head != &seen.pr_head {")],
    ),
    "an-expired-allowlist-entry-still-grants": (
        "an entry of the allowlist that has expired is still read as a designation",
        [(AUTHORITY, "        if entry.expires_at.as_ref().is_some_and(|end| end <= now) {", "        if false && entry.expires_at.as_ref().is_some_and(|end| end <= now) {")],
    ),
    "a-bot-may-hold-a-designation": (
        "an actor that is not a person is looked up on the allowlist like a person",
        [(AUTHORITY, "        if actor.kind != ActorKind::User {", "        if false && actor.kind != ActorKind::User {")],
    ),
    "data-lines-are-not-quoted": (
        "a line of data in the prompt is written without the quote prefix, so a line of data can pass for a delimiter",
        [(BLOCK, 'pub(super) const QUOTE: &str = "> ";', 'pub(super) const QUOTE: &str = "";')],
    ),
    "a-renewal-ignores-the-lapse": (
        "a lease that has lapsed can still be renewed by the worker that held it, so the sweeper and the worker can both act on one attempt (the lease-expiry fence is gone)",
        [(ATTEMPTS, "AND status IN ('STARTING', 'RUNNING', 'CANCELLING') AND lease_expires_at > now() \\\n          RETURNING status, lease_expires_at, deadline_at", "AND status IN ('STARTING', 'RUNNING', 'CANCELLING') \\\n          RETURNING status, lease_expires_at, deadline_at")],
    ),
    "a-renewal-ignores-the-owner": (
        "a renewal in the name of another worker renews the lease",
        [(ATTEMPTS, "AND id = $2 AND lease_owner = $3 AND lease_epoch = $4 \\\n            AND status IN", "AND id = $2 AND $3 <> '' AND lease_epoch = $4 \\\n            AND status IN")],
    ),
    "a-renewal-ignores-the-epoch": (
        "a renewal at an epoch the lease does not hold renews the lease",
        [(ATTEMPTS, "AND lease_owner = $3 AND lease_epoch = $4 \\\n            AND status IN", "AND lease_owner = $3 AND $4 >= 0 \\\n            AND status IN")],
    ),
    "a-second-claimant-is-not-told-it-lost": (
        "the check that a claim was read at the version the run still has is gone, so the second worker is refused by a later rule with another answer",
        [(ATTEMPTS, 'if run.version != start.expected.get() || run.status != "READY" {', "if false {")],
    ),
    "the-engine-does-not-write-command-executed": (
        "the engine writes no audit record for a command the sandbox ran",
        [(SANDBOX_AUDIT, "if seen < MAX_COMMAND_RECORDS {", "if false && seen < MAX_COMMAND_RECORDS {")],
    ),
    "the-api-writes-the-old-webhook-name": (
        "the API audits an accepted delivery as webhook.accepted again, a name a reader that filters by the type of the policy does not know",
        [(WEBHOOK, '            "webhook_accepted_or_rejected.granted",\n            "The delivery was verified and recorded.",', '            "webhook.accepted",\n            "The delivery was verified and recorded.",')],
    ),
    "the-job-token-is-accepted-by-the-webhook-endpoint": (
        "the webhook endpoint takes a job token in the Authorization header in place of the signature, so one operation of the API trusts the credential of a job",
        [(WEBHOOK, "    let verifier = state.ports.webhooks.as_ref().ok_or(ApiError::NotFound)?;\n", "    let verifier = state.ports.webhooks.as_ref().ok_or(ApiError::NotFound)?;\n    if headers\n        .get(\"authorization\")\n        .is_some_and(|value| value.as_bytes().windows(5).any(|window| window == b\"sfjt_\"))\n    {\n        return accepted();\n    }\n")],
    ),
    "the-builder-report-is-stored-as-written": (
        "the text the builder reports about its own work is stored without the redactor having looked at it",
        [(IMPLEMENTATION, "    match handler.redactor.redact_str(text) {\n        Ok(redacted) => {\n            if redacted.report.replacements() > 0 {", "    match handler.redactor.redact_str(text).map(|mut redacted| {\n        redacted.output = std::borrow::Cow::Owned(text.to_owned());\n        redacted\n    }) {\n        Ok(redacted) => {\n            if redacted.report.replacements() > 0 {")],
    ),
    "a-failing-gate-does-not-stop-an-approval": (
        "the approval judge no longer refuses an approval when the gates of the pull request are not clear",
        [(JUDGE, "    if !request.gates_clear {\n        return Err(Refusal::GatesNotClear);", "    if false && !request.gates_clear {\n        return Err(Refusal::GatesNotClear);")],
    ),
    "stale-evidence-does-not-stop-an-approval": (
        "the approval judge no longer compares the evidence the person saw with the evidence now",
        [(JUDGE, "    if let Some((part, _)) = stale {\n        return Err(Refusal::StaleBinding(part));", "    if false && let Some((part, _)) = stale {\n        return Err(Refusal::StaleBinding(part));")],
    ),
    "a-forbidden-argument-is-allowed": (
        "an argument that the policy forbids for a program no longer denies the command",
        [(COMMANDS, "            .find(|f| matches_forbidden_arg(f, tail))", "            .find(|f| false && matches_forbidden_arg(f, tail))")],
    ),
    "a-parent-component-is-not-refused": (
        "a path that is `..` is no longer refused on sight",
        [(PATHS, "        if squashed == \"..\" {\n            return Err(PathRefusal::ParentComponent);", "        if false && squashed == \"..\" {\n            return Err(PathRefusal::ParentComponent);")],
    ),
    "a-widening-of-a-switch-counts-as-a-tightening": (
        "a project override that turns on a setting that widens the central policy is read as a tightening",
        [(TIGHTEN, "const fn off() -> Rule {\n    Rule::Switch {\n        tight: false,", "const fn off() -> Rule {\n    Rule::Switch {\n        tight: true,")],
    ),
    "the-text-bound-for-github-is-not-checked-for-a-secret": (
        "text that holds a secret is sent to the code host",
        [(GITHUB_TEXT, "            Ok(true) | Err(_) => Err(GitHostError::UnsafeText),", "            Ok(true) | Err(_) => Ok(()),")],
    ),
    "markdown-bound-for-github-is-sent-as-written": (
        "links and images in the markdown sent to the code host are not neutralized",
        [(GITHUB_TEXT, "            TextKind::Markdown => clean_markdown(text, &self.policy.link_domains),", "            TextKind::Markdown => text.to_owned(),")],
    ),
    "a-bot-is-not-a-bot": (
        "a delivery sent by a bot, which includes the factory's own App, is read as the hint of a person",
        [(GITHUB_WEBHOOK, "fn sent_by_a_bot(object: &Map<String, Value>) -> bool {\n    object.get(\"sender\")", "fn sent_by_a_bot(object: &Map<String, Value>) -> bool {\n    if true {\n        return false;\n    }\n    object.get(\"sender\")")],
    ),
    "a-delivery-that-fails-verification-is-acknowledged": (
        "the API answers a delivery whose signature does not verify with the acknowledgement of an accepted one",
        [(WEBHOOK, "                reason: \"The delivery did not pass its checks.\",\n            });\n            return Err(ApiError::Unauthorized);", "                reason: \"The delivery did not pass its checks.\",\n            });\n            return accepted();")],
    ),
    "a-secret-file-may-be-read-by-group-and-others": (
        "the mode of a secret file is not checked, so a key that group or others can read is loaded",
        [(CONFIG, "        if meta.permissions().mode() & 0o077 != 0 {", "        if false && meta.permissions().mode() & 0o077 != 0 {")],
    ),
    "a-rotation-to-the-same-key-is-accepted": (
        "a previous decision signing key equal to the current one is accepted",
        [(SIGNING, "        let previous = previous.map(Key::from_bytes).transpose()?;\n        if previous.as_ref().is_some_and(|old| old.0 == current.0) {", "        let previous = previous.map(Key::from_bytes).transpose()?;\n        if false && previous.as_ref().is_some_and(|old| old.0 == current.0) {")],
    ),
    "a-privileged-container-is-not-refused": (
        "the check of a sandbox spec no longer refuses privileged mode",
        [(PORTS_SANDBOX, "        if h.privileged {\n            rules.push(SandboxRule::Privileged);", "        if false && h.privileged {\n            rules.push(SandboxRule::Privileged);")],
    ),
    "an-app-with-a-forbidden-permission-gets-a-token": (
        "the audit of the App no longer refuses an App that holds a permission the policy forbids",
        [(GITHUB_PERMISSIONS, "    if !forbidden_held.is_empty() {\n        return AppAudit::Refuse { forbidden_held };", "    if false && !forbidden_held.is_empty() {\n        return AppAudit::Refuse { forbidden_held };")],
    ),
}

# name -> the arguments of cargo nextest for the tests that must fail. The tests that are named
# are the negative tests of the packages the break touches; whatever fails is written down.
BROAD = ["-p", "factory-workflow", "-p", "factory-domain", "negative_nt_"]
TESTS = {
    "the-workspace-lets-any-edit-in": BROAD,
    "the-workspace-skips-the-secret-scan": BROAD,
    "a-forbidden-command-class-denies-nothing": BROAD,
    "the-egress-allowlist-matches-any-host": BROAD,
    "an-agent-may-grant-itself-a-tool": BROAD,
    "the-budget-threshold-is-never-recorded": ["-p", "factory-workflow", "negative_nt_aud_03", "every_required_event_type"],
    "a-deny-write-path-may-be-written": BROAD,
    "a-moved-head-is-not-noticed": BROAD,
    "an-expired-allowlist-entry-still-grants": BROAD,
    "a-bot-may-hold-a-designation": BROAD,
    "data-lines-are-not-quoted": BROAD,
    "a-renewal-ignores-the-lapse": ["-p", "factory-storage", "negative_nt_lse_02"],
    "a-renewal-ignores-the-owner": ["-p", "factory-storage", "negative_nt_lse_02"],
    "a-renewal-ignores-the-epoch": ["-p", "factory-storage", "negative_nt_lse_02"],
    "a-second-claimant-is-not-told-it-lost": ["-p", "factory-storage", "negative_nt_lse_02"],
    "the-engine-does-not-write-command-executed": ["-p", "factory-workflow", "negative_nt_aud_03"],
    "the-api-writes-the-old-webhook-name": ["-p", "factory-api", "--test", "negative_composed", "negative_nt_aud_03"],
    "the-job-token-is-accepted-by-the-webhook-endpoint": ["-p", "factory-api", "--test", "negative_composed", "negative_nt_inj_04"],
    "the-builder-report-is-stored-as-written": ["-p", "factory-workflow", "-p", "factory-api", "negative_nt_sec_01"],
    "a-failing-gate-does-not-stop-an-approval": ["-p", "factory-workflow", "negative_nt_mrg_01"],
    "stale-evidence-does-not-stop-an-approval": ["-p", "factory-workflow", "negative_nt_mrg_02"],
    "a-forbidden-argument-is-allowed": ["-p", "factory-domain", "negative_nt_tool_05"],
    "a-parent-component-is-not-refused": ["-p", "factory-domain", "negative_nt_tool_04"],
    "a-widening-of-a-switch-counts-as-a-tightening": ["-p", "factory-domain", "negative_nt_pol_02"],
    "the-text-bound-for-github-is-not-checked-for-a-secret": ["-p", "factory-github", "negative_nt_sec_03", "negative_nt_sec_04"],
    "markdown-bound-for-github-is-sent-as-written": ["-p", "factory-github", "negative_nt_sec_04"],
    "a-bot-is-not-a-bot": ["-p", "factory-github", "negative_nt_wh_09"],
    "a-delivery-that-fails-verification-is-acknowledged": ["-p", "factory-api", "--test", "webhook", "negative_nt_wh_01"],
    "a-secret-file-may-be-read-by-group-and-others": ["-p", "factory-composition", "--test", "security_rereview", "--test", "external_world", "held_the_key_file", "a_secret_key_file_that"],
    "a-rotation-to-the-same-key-is-accepted": ["-p", "factory-composition", "--test", "security_rereview", "held_a_rotation_to_the_same_key"],
    "a-privileged-container-is-not-refused": ["-p", "factory-sandbox", "negative_nt_sbx_01"],
    "an-app-with-a-forbidden-permission-gets-a-token": ["-p", "factory-github", "negative_nt_authz_09"],
}

# Tests that are red with every control on. They fail in every run, so a failure of theirs says
# nothing about the control that was removed. Findings F-1 and F-3 of the first review are fixed in
# the base branch (their tests pass); the composed run reports F-6 and F-7 (docs/security/p0-coverage.md).
BASELINE_RED = {
    "negative_nt_sec_01_composed_a_full_job_with_a_canary_of_every_class_leaves_none_in_any_sink",
}

FAILED = re.compile(r"^\s+FAIL \[[^\]]*\] \(\s*\d+/\d+\) (.+)$", re.M)


def names_of(failed_lines):
    """The function name of each failed test: the last word of a line, after the last `::`."""
    return sorted({line.split()[-1].split("::")[-1] for line in failed_lines})


def run_tests(name):
    """Returns (compiled, failed test function names)."""
    command = ["cargo", "nextest", "run", "--locked", "--no-fail-fast", *TESTS[name]]
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=1800)
    text = done.stdout + done.stderr
    if "could not compile" in text or re.search(r"^error\[E\d+\]", text, re.M):
        return False, []
    return True, [n for n in names_of(FAILED.findall(text)) if n not in BASELINE_RED]


def load(script):
    spec = importlib.util.spec_from_file_location("mutation_script", ROOT / script)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load the mutation script {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(script, name, result, failed):
    document = json.loads(DATA.read_text(encoding="utf-8"))
    runs = [r for r in document["mutation_runs"] if (r["script"], r["name"]) != (script, name)]
    runs.append({"script": script, "name": name, "date": datetime.date.today().isoformat(), "result": result, "failed": failed})
    document["mutation_runs"] = sorted(runs, key=lambda r: (r["script"], r["name"]))
    DATA.write_text(json.dumps(document, indent=1) + "\n", encoding="utf-8")


def tracked_changes(paths):
    out = subprocess.run(["git", "status", "--porcelain", "--", *sorted(paths)], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    return out


def main():
    args = sys.argv[1:]
    do_record = "--record" in args
    args = [a for a in args if a != "--record"]
    script = SELF
    runner = sys.modules[__name__]
    if args[:1] == ["--script"]:
        script = args[1]
        runner = load(script)
        args = args[2:]
    table = runner.MUTATIONS
    wanted = args or list(table)
    unknown = [n for n in wanted if n not in table]
    if unknown:
        print(f"unknown break: {unknown}")
        return 2
    files = {edit[0] for n in wanted for edit in table[n][1]}
    dirty = tracked_changes(files)
    if dirty:
        print("refusing to run: there are uncommitted changes in a file a break changes:\n" + dirty)
        return 2
    missed = []
    for name in wanted:
        what, edits = table[name]
        originals = {}
        try:
            for path, old, new in edits:
                file = ROOT / path
                current = file.read_text(encoding="utf-8")
                originals.setdefault(path, current)
                if current.count(old) != 1:
                    print(f"{name}: the text to replace occurs {current.count(old)} times in {path}")
                    return 2
                file.write_text(current.replace(old, new), encoding="utf-8")
            if runner is sys.modules[__name__]:
                compiled, failed = run_tests(name)
            else:
                compiled, failed = runner.run_tests()
                failed = names_of(failed)
        finally:
            for path, text in originals.items():
                (ROOT / path).write_text(text, encoding="utf-8")
        if not compiled:
            print(f"INVALID  {name}: does not compile")
            result = "INVALID"
            missed.append(name)
        elif failed:
            print(f"CAUGHT   {name}: {what}")
            for test in failed[:8]:
                print(f"           {test}")
            if len(failed) > 8:
                print(f"           and {len(failed) - 8} more")
            result = "CAUGHT"
        else:
            print(f"MISSED   {name}: {what}")
            result = "MISSED"
            missed.append(name)
        if do_record:
            record(script, name, result, failed)
    print(f"{len(wanted) - len(missed)} of {len(wanted)} breaks caught")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
