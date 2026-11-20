#!/usr/bin/env python3
"""Say whether a repository's default branch requires an approving review before a merge (process layer review, PL-12).

The design gate treats "a merged pull request that holds the design document" as the approval of the design (ADR 0016).
That holds only if the default branch cannot be changed without a reviewed pull request. This script reads what GitHub
said about that, as files written by the installer, and prints one line. It reads no network and writes nothing.

The installer asks GitHub two read-only questions with `gh api` and passes the answers here:
  * the rules that apply to the branch (`repos/OWNER/NAME/rules/branches/BRANCH`): a list, readable by anyone who can
    read the repository; a rule of type `pull_request` carries `required_approving_review_count`;
  * the classic branch protection (`repos/OWNER/NAME/branches/BRANCH/protection`): an object with
    `required_pull_request_reviews.required_approving_review_count`. GitHub answers 404 "Branch not protected" when there
    is none. Any other failure (no admin right, a plan without the feature, no network) means it could not be read.
    On 2026-11-03 a read-only GET on a public repository that the account does not administer answered
    404 "Not Found", which is "could not be read" here and never "not protected".

Usage:
  branch_reviews.py judge RULES_FILE RULES_EXIT PROTECTION_FILE PROTECTION_EXIT

Prints one line, fields separated by a tab:
  required  N  SOURCE     a review is required: N approving reviews, from "a ruleset" or "branch protection"
  weak                    pull requests are required but with no approving review, so a merge needs no approval
  none                    both sources were read and neither requires a pull request with an approving review
  unreadable  REASON      it could not be told; nothing is claimed either way

Exit codes: 0 a line was printed, 2 wrong arguments.
"""
from __future__ import annotations

import json
import sys

MAX_BYTES = 1024 * 1024
NOT_PROTECTED = "Branch not protected"


def _load(path):
    """The JSON in a file of reasonable size, or None. The file is written by the installer from a `gh api` answer."""
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read(MAX_BYTES + 1)
    except OSError:
        return None
    if len(text) > MAX_BYTES:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def _count(value):
    """A review count that is a whole number from 0 to 100, or None. A bool is not a number here."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        return None
    return value


def from_rules(rules, exit_code):
    """(readable, count): count is None when no pull request rule applies."""
    if exit_code != 0 or not isinstance(rules, list):
        return False, None
    counts = []
    for rule in rules:
        if isinstance(rule, dict) and rule.get("type") == "pull_request":
            parameters = rule.get("parameters")
            counts.append(_count(parameters.get("required_approving_review_count")) if isinstance(parameters, dict) else 0)
    counts = [0 if count is None else count for count in counts]
    return True, (max(counts) if counts else None)


def from_protection(body, exit_code):
    """(readable, count)."""
    if exit_code == 0 and isinstance(body, dict):
        reviews = body.get("required_pull_request_reviews")
        if isinstance(reviews, dict):
            count = _count(reviews.get("required_approving_review_count"))
            return True, 0 if count is None else count
        return True, None
    if isinstance(body, dict) and body.get("message") == NOT_PROTECTED:
        return True, None
    return False, None


def judge(rules, rules_exit, protection, protection_exit):
    rules_ok, rules_count = from_rules(rules, rules_exit)
    protection_ok, protection_count = from_protection(protection, protection_exit)
    found = [(count, source) for count, source in ((rules_count, "a ruleset"), (protection_count, "branch protection"))
             if count is not None]
    if found:
        count, source = max(found)
        if count >= 1:
            return "required\t%d\t%s" % (count, source)
    if rules_ok and protection_ok:
        return "weak" if found else "none"
    if not rules_ok and not protection_ok:
        return "unreadable\tneither the rules of the branch nor its protection could be read"
    if not rules_ok:
        return "unreadable\tthe rules of the branch could not be read"
    return "unreadable\tthe protection of the branch could not be read (it needs the right to administer the repository)"


def main(argv):
    if len(argv) != 5 or argv[0] != "judge":
        sys.stderr.write("usage: branch_reviews.py judge RULES_FILE RULES_EXIT PROTECTION_FILE PROTECTION_EXIT\n")
        return 2
    try:
        rules_exit, protection_exit = int(argv[2]), int(argv[4])
    except ValueError:
        sys.stderr.write("the exit codes must be numbers\n")
        return 2
    print(judge(_load(argv[1]), rules_exit, _load(argv[3]), protection_exit))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
