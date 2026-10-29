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
}

# Tests that are red with every control on (findings F-1 and F-3 of docs/security/p0-coverage.md).
# They fail in every run, so a failure of theirs says nothing about the control that was removed.
BASELINE_RED = {
    "negative_nt_inj_04_tool_output_that_says_grant_yourself_and_approve_gains_no_authority",
    "negative_nt_sec_01_a_full_fixture_job_with_a_canary_of_every_class_leaves_none_in_any_sink",
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
