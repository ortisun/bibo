# Fixtures of the GitHub adapter

None of these files was recorded from the real GitHub. No GitHub App is registered yet, so there
is nothing to record from. Each one is written by hand, on 2026-10-28, from the shape of the
response that the GitHub documentation and ADR 0014 describe. They are **UNVERIFIED** against the
real service, and a test that passes on them proves that the adapter reads this shape, not that
GitHub sends it.

| File | What it stands for | What is unverified |
|---|---|---|
| `rules_branches_strong.json` | `GET /repos/{owner}/{repo}/rules/branches/{branch}` for a repository that meets the policy: pull request required, code owner review, stale approvals dismissed, force push and deletion blocked, the factory's checks pinned to the App (id 424242, the id of the fake App in the test kit). | The exact `type` names (`pull_request`, `required_status_checks`, `non_fast_forward`, `deletion`) and the parameter names. |
| `rules_branches_unpinned.json` | The same, from an organization ruleset, with one factory check that any App may satisfy and one pinned to another App. | The same, and the `ruleset_source_type` values. |
| `rules_branches_empty.json` | A repository that has only classic branch protection, or none. The rules route lists active rules of rulesets only, so it answers an empty list. | That GitHub answers `[]` and not an error. |
| `branch_protection_classic_strong.json` | `GET /repos/{owner}/{repo}/branches/{branch}/protection` (classic branch protection, read with `administration: read` since the owner's decision of 2026-11-12) for a branch that meets the policy. Written on 2026-11-12. | Every member name, the `checks` list next to the older `contexts`, and that a branch without classic protection answers 404 "Branch not protected" and a token without the permission 403. |
| `issue_comment_on_pull_request.json`, `issue_comment_on_issue.json` | An `issue_comment` delivery on a pull request and on an issue. | That `issue.pull_request` is present for a pull request and absent for an issue. The page the architect read does not say so (ports-v1.1, section 13). |

## What a person must do

With a registered App and the protected fixture repository:

1. Fetch the real rules answer for the default branch of the fixture repository, once for each of
   the three situations above, and replace these files with the answers, adding the date they were
   taken to this table. Do the same for the classic protection answer, and record the 404 of a
   branch without classic protection and the 403 of a token without `administration: read`.
2. Capture one real `issue_comment` delivery on a pull request and one on an issue, and replace the
   two delivery files. Remove the value of every secret and token from them first.
3. Run `FACTORY_LIVE=1 cargo nextest run -p factory-github --test live_smoke --test live_pinning`
   with the credentials listed in the messages those tests print.
