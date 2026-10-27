# 0009: Adopt six operating defaults, each pending human confirmation

- Status: **Decided by default, pending human confirmation.** Each default lets work proceed. None is settled. A human can reverse any of them, and the cost of doing so is stated.
- Date: 2026-10-27
- Deciders: software_architect, following the security specialist's recommended defaults (`docs/security/threat-model.md` section 9) and the coordinator's instruction
- Related: [ADR 0003](0003-sandbox-strategy.md), [ADR 0005](0005-agent-runtime-adapter-boundary.md), [state machines](../architecture/state-machine.md)

## Context and problem statement

Several choices need a person's decision: legal, commercial or risk acceptance that an architect cannot make. Work cannot wait for them. Each default below is the safer option and is already the security specialist's recommendation. This record keeps the six in one place, says what each costs, and lists the places where an existing file disagrees.

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
- **Conflict:** `policies/security.yaml` `supply_chain.new_direct_dependency.auto_approve_when` lists `name_on_org_allowlist`, which is an automatic approval of a new name. Its owner decides whether to remove it.

### 5. Requester authorization comes from a named allowlist in protected configuration, not from GitHub roles

- Alternative: resolve the requester's GitHub repository permission live.
- Why: a named list is explicit, reviewable, and independent of repository settings that a repository admin can change. It is read only from the protected configuration source, never from the target repository.
- Cost: someone maintains the list, and removing a person from it is the revocation. A GitHub permission lookup is not used to authorize.
- **Conflict:** `policies/approval.yaml` `roles` define each role by `github_permission_at_least` and state that "GitHub repository permission is the source of truth". `docs/security/secrets-and-credentials.md` section 3.6 says the label actor is authorized by a live permission lookup. Their owner has to reconcile. Until then the engine requires allowlist membership for requester, operator, approver and security approver, and treats a GitHub permission as an additional condition at most. Several catalog tests (NT-AUTHZ-01, -02) assume the lookup. Their expected results hold under the allowlist, because a reader is not on the list, but the setup text needs adjusting.

### 6. Rework is capped at two rounds, then a human decides, for code and for documentation

- Alternative: three rounds.
- Why: bounded loops with measurable progress; a third round rarely fixes what two did not, and costs real money.
- Cost: more escalations to a human.
- **Conflict:** `policies/security.yaml` `budgets.per_job.max_rework_iterations` is 3. Its owner lowers it to 2, or this default changes. The engine takes the lower of the two values, and a test in `s1-policy-evaluation` fails if the policy file exceeds 2.
- Encoded in: [state-machine.md](../architecture/state-machine.md) bounds table, guards `G_REWORK_ALLOWED` and `G_HUMAN_REWORK_ALLOWED`, invariant INV-10.

## Consequences

- Good: work is not blocked on six open decisions, and each default is the more conservative choice.
- Bad: defaults 2 and 3 each need a person before the end-to-end proof can use real agents or open a pull request. The plan marks the affected steps BLOCKED and does not fake them.
- Bad: three defaults (4, 5, 6) disagree with files the security specialist owns, so there are two sources of truth until those files change. The conflicts are listed here and in the Slice 0 report.
- Neutral: each default can be reversed later. The cost of reversal is stated above.

## Confirmation

A human confirms or reverses each default and the status of this record changes to Accepted or is superseded by a new record. Until then the slice plan and the schemas follow the defaults, and the open questions in the Slice 0 report ask for each decision.
