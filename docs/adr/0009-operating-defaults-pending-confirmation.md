# 0009: Adopt nineteen operating defaults, each pending human confirmation

- Status: **Decided by default, pending human confirmation.** Each default lets work proceed. None is settled. A human can reverse any of them, and the cost of doing so is stated.
- Date: 2026-10-27. Items 7 to 19 were added the same day, after the engineers of the Slice 0 packages reported gaps. Items 1 to 6 are unchanged except for the notes on policy conflicts, which the policy owners have since resolved.
- Deciders: software_architect, following the security specialist's recommended defaults (`docs/security/threat-model.md` section 9) and the coordinator's instruction. Items 15 to 19 are the documenter's open questions, decided by default.
- Related: [ADR 0003](0003-sandbox-strategy.md), [ADR 0005](0005-agent-runtime-adapter-boundary.md), [ADR 0010](0010-failure-escalation-routing-and-invalidation.md), [ADR 0011](0011-canonical-time-and-numbers.md), [ADR 0012](0012-row-level-security-in-slice-1.md), [ADR 0013](0013-telemetry-wiring.md), [state machines](../architecture/state-machine.md)

## Context and problem statement

Several choices need a person's decision: legal, commercial or risk acceptance that an architect cannot make. Work cannot wait for them. Each default below is the safer option, and items 1 to 6 are the security specialist's recommendation. This record keeps them in one place and says what each costs. Where an existing file disagreed, it says so and whether that is resolved.

## The defaults

### 1. The agent command line tool runs inside the sandbox in Slice 1

- Alternative: run it on the host with built-in tools disabled and a tool bridge.
- Why: command allowlists do not contain an agent (verified independently by the security review and the Spec Kit specialist), and the container is then the boundary.
- Cost: needs the broker and the sidecar, which do not exist yet.
- Reverse by: choosing `host_tool_bridge`, which the schemas already allow. Needs the spike to show the tools can be limited that way.
- Detail: [ADR 0005](0005-agent-runtime-adapter-boundary.md).

### 2. Model credentials are API keys with hard spend limits, behind a broker

- Alternative: subscription (OAuth) logins.
- Why: the factory cannot broker or meter a subscription login, and it may conflict with provider terms. `--bare` in Claude Code ignores OAuth by design.
- Cost: **a real-provider adapter test, and any live end-to-end run with real agents, is BLOCKED until a human supplies API keys with a provider-side spend limit.** Both tools on this machine are logged in by subscription only. Fake-runtime results in test mode do not substitute for it and must be labelled as such.
- Reverse by: a human accepting subscription logins on the host for a named demo profile, and the legal question being settled.

### 3. Repositories without branch-protection rulesets run at autonomy level L0 only

- Alternative: allow draft pull requests anyway (level L1, the policy default).
- Why: the required checks, the App's absence from any bypass list and the protected default branch are what keep the factory's checks authoritative. L0 reads and comments only: no branches, no pull requests.
- Cost: the fixture repository on GitHub needs a ruleset before the end-to-end run can open a draft pull request (negative test NT-MRG-07). That is a person's action on GitHub.
- Reverse by: an org admin lowering the requirement for a named repository.

### 4. New direct dependencies always need a human

- Alternative: auto-approve names already in the lockfile or on an organization allowlist.
- Why: slopsquatting and typosquatting. A name already in the lockfile is not new, so it does not trigger the rule.
- Cost: slower dependency changes.
- Resolved: `policies/security.yaml` no longer has an `auto_approve_when` key for a new dependency, and `policies/approval.yaml` says no allowlist or heuristic approves a package name absent from the base lockfile (read 2026-10-27).

### 5. Requester authorization comes from a named allowlist in protected configuration, not from GitHub roles

- Alternative: resolve the requester's GitHub repository permission live.
- Why: a named list is explicit, reviewable, and independent of repository settings that a repository admin can change. It is read only from the protected configuration source, never from the target repository.
- Cost: someone maintains the list, and removing a person from it is the revocation. A GitHub permission lookup is not used to authorize.
- Resolved: `policies/approval.yaml` now has `authority.source: named_allowlist`, and the catalog setups of NT-AUTHZ-01 and NT-AUTHZ-02 use allowlist membership (read 2026-10-27). The engine requires allowlist membership for requester, operator, approver and security approver, and treats a GitHub permission as an additional condition at most.

### 6. Rework is capped at two rounds, then a human decides, for code and for documentation

- Alternative: three rounds.
- Why: bounded loops with measurable progress; a third round rarely fixes what two did not, and costs real money.
- Cost: more escalations to a human.
- Resolved: `policies/security.yaml` `budgets.per_job.max_rework_iterations` is 2 (read 2026-10-27). The engine still takes the lower of the policy value and 2, and a test in `s1-policy-evaluation` fails if the policy file exceeds 2.
- Encoded in: [state-machine.md](../architecture/state-machine.md) bounds table, guards `G_REWORK_ALLOWED` and `G_HUMAN_REWORK_ALLOWED`, invariant INV-10.

### 7. A limit asks a person, and a budget limit neither fails nor blocks a stage

- Alternative: fail the stage when `max_attempts` is reached (the old guard), or block it when the budget is gone (`policies/security.yaml` `budgets.on_exhaustion`).
- Why: failing is hard to undo, and `BLOCKED` has no exit that adds budget. `WAITING_FOR_HUMAN` has one (`S13`). Detail and the full rule: [ADR 0010](0010-failure-escalation-routing-and-invalidation.md) decision 1.
- Cost: more questions to a person. `policies/security.yaml` `budgets.on_exhaustion` must change from `stop_job_revoke_job_token_mark_BLOCKED` to `stop_job_revoke_job_token_wait_for_human`.
- Reverse by: a superseding record that sends exhaustion to `BLOCKED` and adds a budget exit to that state.

### 8. Attempts are counted from the last human answer, and a repair is a retry capped at two

- Alternative: count attempts over the whole life of the stage run, and keep repairs in a separate count inside an attempt.
- Why: a count over the whole life makes the first failure after an answer escalate again at once. A repair that is a retry needs no second counter. The cap is `bounded_repair_attempts` in the policy, lower only.
- Cost: the total number of attempts is bounded by the number of human answers, not by a fixed number.
- Reverse by: changing `G_RETRY_ALLOWED` and the retry function. The cost is one domain change.

### 9. A skipped stage satisfies the stages that require it and the completion check

- Alternative: never skip a stage that another stage requires, or run it and pass it with a not-applicable report.
- Why: [ADR 0010](0010-failure-escalation-routing-and-invalidation.md) decision 2. A skipped run is never evidence and can be superseded.
- Cost: one database migration for the edge `SKIPPED` to `SUPERSEDED`.
- Reverse by: removing `S02` for required stages.

### 10. Specification and policy defects ask a person, and a person may send rework to the listed earlier stages

- Alternative: route a specification defect back to `SPECIFICATION`, or fail the stage.
- Why: [ADR 0010](0010-failure-escalation-routing-and-invalidation.md) decision 3. The factory does not reopen an approved specification by itself, and the revision method is unproven (ADR 0006).
- Cost: a person who finds the specification wrong at review can answer, approve with a reason, or reject the job. They cannot send it back to `SPECIFICATION` in Slice 1.
- Reverse by: adding `SPECIFICATION` to the human routes after the Spec Kit spike proves revision.

### 11. A change to the source request supersedes the whole job, and values bound to gate evidence are checked at two points

- Alternative: continue on the old snapshot after an edit, and watch the base branch, the policy and the image continuously.
- Why: [ADR 0010](0010-failure-escalation-routing-and-invalidation.md) decision 4. Watching would restart the jobs of busy repositories again and again.
- Cost: an edit by a person who is not on the allowlist discards a job's progress, though not its audit trail. A change between the two checks is noticed late.
- Reverse by: removing a row from the invalidation table, or adding a check.

### 12. Timestamps compare by instant and are written in the shortest form, and ledger integers stay within 2^53 - 1

- Alternative: normalize timestamps on read, or forbid the long form in the schema.
- Why: [ADR 0011](0011-canonical-time-and-numbers.md).
- Cost: `Eq` ignores the spelling while the serialized text does not.
- Reverse by: a new schema version with a stricter pattern.

### 13. Row-level security is on in Slice 1

- Alternative: keep the deferral to Slice 4 that ADR 0007 states.
- Why: [ADR 0012](0012-row-level-security-in-slice-1.md). The policy file requires it, the test NT-TEN-01 cannot pass without it, and the storage crate is not written yet.
- Cost: two roles, two pools in the worker, one more statement per tenant transaction, and the DBA package `s1-database-tenancy-and-state-sync` before `s1-storage-postgres`. **This default reverses a statement of the accepted ADR 0007**, which carries a revision note.
- Reverse by: removing the dependency and the policies. Cheap before the storage crate exists, expensive after.

### 14. Telemetry names are literals checked by a repository scan, one redactor is injected, and a job is traced by an id derived from it

- Alternative: shared constants (they cannot name a `tracing` field), a stopgap scrubber kept as the default, a span held open for the whole job.
- Why: [ADR 0013](0013-telemetry-wiring.md).
- Cost: a text scan with the limits of one, and the package `s1-telemetry-wiring`.
- Reverse by: a superseding record.

### 15. Warnings have a place in gate reports

- Alternative: leave warnings out of the report, or put them in `failures`.
- Why: the readability gate must report warnings apart from blocking findings, and a PASSED report must keep `failures` empty. `gate-report.schema.json` gains an optional `warnings` list with no severity field. A warning never changes the outcome.
- Cost: the Rust report type and its tests follow (work package `s1-domain-revision`).
- Reverse by: removing the optional field, which no existing document uses.

### 16. A page header stays the repository's bullet header, not front matter

- Alternative: front matter with owner, status, review date and validated commit on every page, as the documenter's page standard asks.
- Why: every document in this repository already uses the bullet header, and the schemas define no front matter. Changing both is a large edit for no gain in checks.
- Cost: the documenter's standard and the repository differ, so the documentation gate checks the bullet header.
- Reverse by: a superseding record and a mechanical rewrite of the headers.

### 17. An unfaithful translation is a reviewer warning, and approval needs a recorded human decision on it

- Alternative: block on it (a reviewer can be wrong), or leave it as a warning nobody reads.
- Why: `translation-unfaithful` is a reviewer rule and a reviewer can only warn (documentation policy 9.3). The guard `G_APPROVER_AUTHORIZED` now requires a recorded human decision for every open warning of that rule in the evidence the approver saw.
- Cost: one more fact in the approval guard, and the approval screen lists those warnings.
- Reverse by: removing that condition from the guard.

### 18. External links are not checked by default

- Alternative: fetch external URLs in the gate.
- Why: the sandbox may have no network, and a fetched page is untrusted content. The gate checks internal links and anchors. It never reports an external link as valid, and it says in the report's reason how many external links it did not check.
- Cost: a dead external link reaches review.
- Reverse by: a project manifest option with an allowlist of hosts, after a security review.

### 19. Conventional-commit tags in titles stay a warning that a repository may switch off

- Alternative: block them, or never allow switching them off.
- Why: many teams write `feat(auth):` by habit, and the tag does not make the title unclear. `schemas/project-manifest.schema.json` gains `documentation.disabled_readability_rules`, which can name `title-type-tag` and no blocking rule.
- Cost: one optional manifest field, read by the readability gate.
- Reverse by: removing the field.

## Consequences

- Good: work is not blocked on nineteen open decisions, and each default is the more conservative choice.
- Bad: defaults 2 and 3 each need a person before the end-to-end proof can use real agents or open a pull request. The plan marks the affected steps BLOCKED and does not fake them.
- Bad: default 7 asks for a change in `policies/security.yaml`, which the security specialist owns, so there are two sources of truth until it changes.
- Bad: default 13 changes an accepted record. It is the only one in this list that does.
- Neutral: each default can be reversed later. The cost of reversal is stated above.

## Confirmation

A human confirms or reverses each default and the status of this record changes to Accepted or is superseded by a new record. Until then the slice plan, the state machine and the schemas follow the defaults, and the open questions in the slice plan ask for each decision.
