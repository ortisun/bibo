"""Deliberate breaks of the installer's own safeguards, each of which a test must catch.

    python3 -I scripts/tests/mutations/installer_breaks.py [WORD ...]

For each break the script changes one or two places in the sources of the installer (the old text must occur
exactly once in its file), runs the test class that is named for the break, and puts every file back. A break is
CAUGHT when the tests fail, MISSED when they pass, and INVALID when the changed source does not run at all (a
syntax error). The script exits with 1 if any break is MISSED or INVALID. It leaves the working tree as it found it,
also when it is interrupted, but run it on a clean tree.

The tests that catch a break are in `scripts/tests/test_install.py`: `SpecKit` (the Spec Kit step), `BotLogin`,
`ReviewRule` and `BranchReviewsTool` (FACTORY_BOT_LOGIN and the reviewed-merge check), and in
`scripts/tests/test_issue_workflow.py`: `WithoutTheBotLogin`, `Apply` and `ShippedFiles` (the Action). Each of them has a sibling that passes on the unbroken code, so a
break that is CAUGHT is caught for the reason in its name.
"""

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
INSTALL = "scripts/install.sh"
SPECKIT = "scripts/lib/speckit_integration.py"
ACTION = "scripts/lib/issue_workflow.py"
REVIEWS = "scripts/lib/branch_reviews.py"
WORKFLOW = "onboarding/github/workflows/issue-workflow.yml"

TESTS = ["python3", "-I", "scripts/tests/test_install.py"]
WORKFLOW_TESTS = ["uv", "run", "--no-project", "--with", "pyyaml==6.0.3", "python", "-I", "scripts/tests/test_issue_workflow.py"]

# (name, [(file, old, new)], test command and the classes or tests to run)
BREAKS = [
    # ---- the Spec Kit step ----
    (
        "the install command gets --force, which lets Spec Kit overwrite what it does not know to be safe",
        [(INSTALL, "specify integration install \"$key\")", "specify integration install --force \"$key\")")],
        TESTS + ["SpecKit"],
    ),
    (
        "the files that specify wrote are not compared with the pinned hashes after the install",
        [(INSTALL, "    if [ \"$wrong\" -eq 1 ]; then\n      report BLOCKED speckit \"$key: the files that specify wrote", "    if false; then\n      report BLOCKED speckit \"$key: the files that specify wrote")],
        TESTS + ["SpecKit"],
    ),
    (
        "a skill whose hash is not the pinned one is taken for the pinned one",
        [(SPECKIT, "                elif got != manifests[key][path]:", "                elif False:")],
        TESTS + ["SpecKit"],
    ),
    (
        "a .gitignore that hides the new files does not stop the step",
        [(INSTALL, "      if path_is_ignored \"$path\"; then", "      if false && path_is_ignored \"$path\"; then")],
        TESTS + ["SpecKit"],
    ),
    (
        "--check runs the install anyway",
        [(INSTALL, "  if [ \"$check_only\" -eq 1 ]; then\n    for key in $missing_keys; do", "  if [ \"$check_only\" -eq 99 ]; then\n    for key in $missing_keys; do")],
        TESTS + ["SpecKit"],
    ),
    (
        "specify keeps the GitHub tokens of the person's shell",
        [(INSTALL, "run_specify() { env -u GH_TOKEN -u GITHUB_TOKEN NO_COLOR=1 specify \"$@\"; }", "run_specify() { env NO_COLOR=1 specify \"$@\"; }")],
        TESTS + ["SpecKit"],
    ),
    (
        "a symbolic link in the way is followed",
        [(SPECKIT, "        if os.path.islink(current):\n            return True\n", "        if False:\n            return True\n")],
        TESTS + ["SpecKit"],
    ),
    (
        "another release of specify is accepted",
        [(INSTALL, "  if [ \"$have\" != \"$pinned\" ]; then", "  if false; then")],
        TESTS + ["SpecKit"],
    ),
    (
        "files of an integration that is not listed are taken for an integration to add, and overwritten",
        [(SPECKIT, "            if present:\n                out.append(\"unlisted-files", "            if False:\n                out.append(\"unlisted-files")],
        TESTS + ["SpecKit"],
    ),
    (
        "a project that records another Spec Kit version is treated like one that records the pinned version",
        [(SPECKIT, "    if version != version_pinned:\n", "    if False:\n")],
        TESTS + ["SpecKit"],
    ),
    (
        "an installed integration the factory has no pin for is not reported",
        [(SPECKIT, "    out.extend(\"unknown\\t\" + key for key in keys if key not in manifests)\n", "")],
        TESTS + ["SpecKit"],
    ),
    # ---- PL-21: the Action and the installer when FACTORY_BOT_LOGIN is not set ----
    (
        "PL-21 Action: it judges the labels although the variable is not set",
        [(ACTION, "    if not bot_login:\n", "    if False:\n")],
        WORKFLOW_TESTS + ["WithoutTheBotLogin"],
    ),
    (
        "PL-21 Action: a variable that holds only spaces counts as set",
        [(ACTION, "os.environ.get(\"FACTORY_BOT_LOGIN\", \"\").strip()\n    if not bot_login", "os.environ.get(\"FACTORY_BOT_LOGIN\", \"\")\n    if not bot_login")],
        WORKFLOW_TESTS + ["WithoutTheBotLogin"],
    ),
    (
        "PL-21 workflow: the board move runs although the variable is not set",
        [(WORKFLOW, "      - name: Move the issue on the board\n        if: ${{ vars.FACTORY_BOT_LOGIN != '' }}\n", "      - name: Move the issue on the board\n")],
        WORKFLOW_TESTS + ["WithoutTheBotLogin"],
    ),
    (
        "PL-21 installer: a run that is not --check goes on although the variable is missing",
        [(INSTALL, "    HALT=1\n    needs_you \"Nothing was installed or changed. Set the repository variable",
          "    HALT=0\n    needs_you \"Nothing was installed or changed. Set the repository variable")],
        TESTS + ["BotLogin"],
    ),
    # ---- the git policy: settings, hooks, gitflow ----
    (
        "git policy: a flag that disagrees with .factory/repository.json does not stop the run",
        [(INSTALL, "    SETTINGS_STATE=conflict\n    HALT=1\n", "    SETTINGS_STATE=conflict\n    HALT=0\n")],
        TESTS + ["GitPolicy"],
    ),
    (
        "git policy: a core.hooksPath of another tool is replaced",
        [(INSTALL, "      report NEEDS git-hooks \"core.hooksPath is already '$current'; it was left alone\"",
          "      checkout_git config core.hooksPath \"$HOOKS_REL\"; report NEEDS git-hooks \"core.hooksPath is already '$current'; it was left alone\"")],
        TESTS + ["GitPolicy"],
    ),
    (
        "git policy: --check writes the settings file",
        [(INSTALL, "  if [ \"$check_only\" -eq 1 ]; then args+=(--check); fi\n  local out rc=0 state detail",
          "  local out rc=0 state detail")],
        TESTS + ["GitPolicy"],
    ),
    (
        "git policy: hooks already active in .git/hooks are turned off",
        [(INSTALL, "      if [ -n \"$active\" ]; then\n        report NEEDS git-hooks", "      if false; then\n        report NEEDS git-hooks")],
        TESTS + ["GitPolicy"],
    ),
    (
        "PL-21 installer: --allow-missing-bot-login is ignored",
        [(INSTALL, "  if [ \"$allow_missing_bot\" -eq 1 ]; then\n    report NOTE", "  if [ \"$allow_missing_bot\" -eq 99 ]; then\n    report NOTE")],
        TESTS + ["BotLogin"],
    ),
    (
        "PL-21 installer: a variable list that cannot be read counts as set",
        [(INSTALL, "  if ! listing=$(gh variable list --repo \"$repo\" --json name 2>/dev/null); then\n    state=2", "  if ! listing=$(gh variable list --repo \"$repo\" --json name 2>/dev/null); then\n    state=0")],
        TESTS + ["BotLogin"],
    ),
    (
        "PL-21 installer: a variable that is not in the list counts as set",
        [(INSTALL, "sys.exit(0 if \"FACTORY_BOT_LOGIN\" in names else 1)", "sys.exit(0)")],
        TESTS + ["BotLogin"],
    ),
    (
        "PL-21 installer: the steps that change things run after the stop",
        [(INSTALL, "if [ \"$HALT\" -eq 0 ]; then\n  step_host_tools", "if true; then\n  step_host_tools")],
        TESTS + ["BotLogin"],
    ),
    # ---- PL-12: the gate comment and the review rule ----
    (
        "PL-12 Action: the marker anywhere in a comment of the Actions bot silences the gate comment",
        [(ACTION, "and str(comment.get(\"body\", \"\")).startswith(GATE_MARKER))", "and GATE_MARKER in str(comment.get(\"body\", \"\")))")],
        WORKFLOW_TESTS + ["Apply"],
    ),
    (
        "PL-12 Action: a person named like the bot silences the gate comment",
        [(ACTION, "user.get(\"login\") == \"github-actions[bot]\" and user.get(\"type\") == \"Bot\"", "user.get(\"login\") == \"github-actions[bot]\"")],
        WORKFLOW_TESTS + ["Apply"],
    ),
    (
        "PL-12 installer: a branch whose rules could not be read is reported as fine",
        [(REVIEWS, "    if not rules_ok and not protection_ok:\n        return \"unreadable", "    if not rules_ok and not protection_ok:\n        return \"required\\t1\\tnothing\"\n        return \"unreadable")],
        TESTS + ["BranchReviewsTool", "ReviewRule"],
    ),
    (
        "PL-12 installer: a true taken for a review count of one",
        [(REVIEWS, "    if isinstance(value, bool) or not isinstance(value, int)", "    if not isinstance(value, int)")],
        TESTS + ["BranchReviewsTool"],
    ),
    (
        "PL-12 installer: pull requests with no approving review count as a review",
        [(REVIEWS, "        if count >= 1:\n            return \"required", "        if count >= 0:\n            return \"required")],
        TESTS + ["BranchReviewsTool", "ReviewRule"],
    ),
    (
        "PL-12 installer: a failed read of the protection is believed when its body says a review is required",
        [(REVIEWS, "    if exit_code == 0 and isinstance(body, dict):\n        reviews", "    if isinstance(body, dict):\n        reviews")],
        TESTS + ["BranchReviewsTool"],
    ),
    (
        "PL-12 installer: the check asks the host to change something",
        [(INSTALL, "  gh api \"repos/$repo/rules/branches/$branch\" >", "  gh api -X POST \"repos/$repo/rules/branches/$branch\" >")],
        TESTS + ["ReviewRule"],
    ),
]


def run(command):
    done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def main():
    originals = {}
    outcomes = []
    # Words after the script name select the breaks whose name contains one of them.
    only = sys.argv[1:]
    try:
        for name, edits, command in BREAKS:
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
            code, output = run(command)
            for file in texts:
                (ROOT / file).write_text(originals[file])
            if "SyntaxError" in output:
                verdict = "INVALID (does not run)"
            elif code == 0:
                verdict = "MISSED"
            else:
                failed = sorted({line.split("(")[0].replace("FAIL: ", "").replace("ERROR: ", "").strip()
                                 for line in output.splitlines() if line.startswith(("FAIL: ", "ERROR: "))})
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
