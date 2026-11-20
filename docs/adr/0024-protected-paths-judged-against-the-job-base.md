# 0024: Protected paths are judged against the commit the job started from

- Status: **Proposed, pending the owner**. Built on the branch `fix/agent-report-channel` from real run 33 of scenario E1. No independent review has covered it.
- Date: 2026-11-20
- Deciders: the engineer, for the owner to confirm.
- Amends: the `WorkspaceRequest` of ports v1.1 ([ADR 0014](0014-ports-v1-1-claim-protocol-and-port-revision.md), "Protected paths from the policy (F-10)") by one field, `protected_base`. Related: `docs/security/sandbox-policy.md` sections 6.3 and 6.5, `policies/security.yaml` `protected_paths`.

## Context and problem statement

In run 33, round 1 of `IMPLEMENTATION` added `tests/json_output.rs` and committed it. `VALIDATION` sent the work back. Round 2's builder edited that same file, and the ingestion audit refused the change under `additions_only` (gate `protected-paths-unchanged`). The job ended BLOCKED.

The rule `additions_only` (group `test_code`) exists so that an agent cannot weaken tests that were in the repository before the job. The audit judged each path by its difference from the workspace's base commit. A rework round's workspace starts from the previous round's head, so the audit saw the job's own test as an existing file that was "modified". The same happens between two tasks of one round, because each task starts from the commit of the task before it.

`append_only` (group `test_fixtures_and_goldens`) had the same flaw, worse: any change to a file that existed at the round's base was refused, and the file was also mounted read-only in the sandbox, so a round could not even rewrite a fixture the job had added. `deny_write` does not have the flaw: it refuses any change, including an addition, so no job-added file can be under it.

## What the rules must say

- A path absent at the job's base is an addition of this job, whatever earlier rounds or tasks did to it. The job may change it or delete it.
- A path present at the job's base keeps its rule, compared with its content at the job's base. A later round cannot remove a line that existed before the job, even if an earlier round left the file alone.
- `deny_write` stays absolute: any change since the round's own base is refused.
- If the job's base cannot be read, nothing is judged: the workspace is refused.

## Considered options

1. **A field `protected_base: Option<CommitSha>` on `WorkspaceRequest`, set by each stage that builds on earlier commits of the job** (chosen). The workspace computes a second difference, from the protected base to the same head tree, and `append_only` and `additions_only` judge each path this attempt changed by that difference. The change set the workspace reports, and the commit it makes, stay relative to the round's own base, so nothing downstream (the commits gate, the patch, the evidence) changes. The rule lives in one place per adapter (`rules::evaluate` in `sandbox`, `FakeWorkspace::audit` in `testkit`), and the contract suite checks both the same way. `None` keeps today's behaviour, so every stage that does not ingest work (review, validation, verify workspaces) is unchanged.
2. **Judge each path against both commits and combine the answers.** Rejected. Refusing when either answer breaks the rule is today's bug: the round's own base still calls the job's test "modified". Refusing only when both break gives the same answers as option 1, but only because every earlier round was audited, so the second check adds work and no protection, and the rule becomes harder to state and to test ("what existed before the job" is one comparison, not two).
3. **Start every round from the job's base and replay the earlier rounds' content into the checkout.** Rejected: the round's commit would no longer have the previous round's head as its parent, so the commits gate, the patch export and the rework accounting (`started_from`) would all change, and a replay is a second way to write the checkout that the audit would have to trust.
4. **Exempt the paths an earlier round of the job added, by listing them in the request.** Rejected: the list is a second record of what the job changed, which the stage would have to keep in step with the object store; the store already knows it from the job's base. It also says nothing about a pre-existing file that an earlier round grew.
5. **Have the workspace find the job's base by itself**, for example from the fetched ref in the store. Rejected: the store holds every branch tip fetched for the job, and only the stage knows which commit the job's work started from (the repository map's commit). A guess in the adapter is a hidden input to a security rule.

## Decision outcome

Option 1.

- `WorkspaceRequest` gains `protected_base: Option<CommitSha>`. `create` refuses with `UnknownCommit` when the commit is not in the job's object store or is not an ancestor of `base` (or `base` itself). Naming `base` itself is the same as `None`.
- At ingestion, for each path in the difference from the round's base: `deny_write` refuses; `append_only` and `additions_only` look the path up in the difference from the protected base. A path not there is back to its content before the job and passes. A path added there is the job's own and passes. A path modified or deleted there meets the mode as before (`append_only` refuses; `additions_only` allows a modification that only gained lines and kept the mode and type). If the second difference cannot be computed, ingestion fails.
- The compiled policy layer (`PathPolicyLayer`), when the provider has it, gets the same view: the protected-base facts of the changed paths.
- `append_only` overlays: a file under `append_only` is mounted read-only only if it existed at the protected base. A fixture the job added stays writable in a later round. `deny_write` overlays are unchanged.
- The `IMPLEMENTATION` stage names the repository map's commit (the job's base) on every workspace, so later tasks and rework rounds are judged against it. The `DOCUMENTING` stage names the implementation result's `base_commit`, which is the same commit. The `SPECIFICATION` stage keeps `None`: its writer changes only its own feature directory, which no `append_only` or `additions_only` rule covers, and a revision may start from a frozen specification's commit whose ancestry to the map's commit is not established. Stages that only read or verify keep `None`.

### Deleting a file the job added

Allowed. Before the job the path did not exist, and after the deletion it does not exist either, so the difference from the job's base has nothing to judge. The rule protects what existed before the job; a test the job wrote and then took out was never part of what the rule protects. Whether the job's remaining tests are enough is for `VALIDATION` and the acceptance evidence to judge, not for the path rules.

### Costs

- One more `git diff-tree` pair (raw and numstat) per ingestion, and one more `ls-tree` and one `merge-base --is-ancestor` per workspace creation, when a protected base is named.
- A stage that gives a wrong protected base weakens the rule for the files between that commit and the true base. The ancestry check rules out an unrelated commit, not an older ancestor; the stage reads the base from the artifact the contract pinned.
- A rework that changes the job's base (a new fetch with a moved tip) while `previous_head` still sits on the old one would now be refused with `UnknownCommit`. No such flow exists today.

## What was checked and what was not

- Checked: the unit tests of `crates/sandbox/src/workspace/rules.rs`, and three new checks of the workspace contract suite that the fake and the git adapter both run: `a_file_the_job_added_may_be_changed_in_a_later_round`, `what_existed_before_the_job_stays_protected_in_a_later_round`, `a_protected_base_that_cannot_be_read_is_refused`. Two new fake defects (`JudgesAgainstTheRoundBase`, `IgnoresUnreadableProtectedBase`) are caught by them.
- Not checked here: a rerun of scenario E1.
