# 0010: Limits ask a person, a skipped stage satisfies its dependants, unfixable findings go to a person, and every outside change has a row in the invalidation table

- Status: Accepted by the architect. The defaults below are **pending human confirmation** and are listed in [ADR 0009](0009-operating-defaults-pending-confirmation.md), items 7 to 11. Revised again on 2026-10-27 by ADR 0014 (see "Revision note (ADR 0014)").
- Date: 2026-10-27
- Deciders: software_architect, after the engineers who wrote the state machines in `domain` found the gaps
- Related: [state machines](../architecture/state-machine.md), [`state-machine.json`](../architecture/state-machine.json), [ADR 0001](0001-orchestration-engine.md), [ADR 0009](0009-operating-defaults-pending-confirmation.md), [ADR 0011](0011-canonical-time-and-numbers.md)

## Revision note (ADR 0014)

Revised on 2026-10-27 by [ADR 0014](0014-ports-v1-1-claim-protocol-and-port-revision.md): two transitions are added. `S21` blocks a stage run whose attempt ended because the environment is missing or unsafe, and takes row 0 of the order of moves after a failed attempt. `S22` sends a new `INTAKE` run to a person before any agent reads a request that changed after it was authorized. `G_UNRECOVERABLE` is restated so it is built from the listing of stage runs.

## Context and problem statement

The implementers of the Slice 0 domain code read `state-machine.json` as written and found places where it contradicts itself, contradicts a policy file, or says nothing. Each one is a place where two engineers would build two different behaviors. This record decides four groups of them and changes the JSON file. The Rust code follows in the work package `s1-domain-revision`, and until it lands the conformance tests of the `domain` crate fail. That is deliberate: the tests are the proof that the code follows the file.

1. **Retry exhaustion.** Transition `S06` fails a stage run when `max_attempts` is reached (guard `G_RETRY_EXHAUSTED_OR_NONRETRYABLE`). Invariant INV-10 and the ground rule "reaching a limit sends the stage to a human" say a person decides. `policies/security.yaml` `budgets.on_exhaustion` says `stop_job_revoke_job_token_mark_BLOCKED`. Three documents, three outcomes. The domain code chose the person.
2. **Skipped stages.** `G_UPSTREAM_PASSED` accepts only a `PASSED` upstream run. A stage that a rule marks `SKIPPED` would leave every stage that requires it in `PENDING` forever. `G_PIPELINE_SCOPE_COMPLETE` has the same flaw: a skipped stage in scope would stop the job from ever completing.
3. **Rework routing.** The review verdict schema has four defect classes. The machine routes two of them, and only at `DOCUMENTATION_REVIEW`. A `specification` or `policy` defect there ends in `S12`, which fails the stage and then the job, when it needs a decision. The `REVIEW` row ignores the class. A human can request rework (`S15`) from any waiting or blocked stage run, but only `APPROVAL` has a route.
4. **Invalidation.** Five rules exist, all for artifacts the pipeline produces. Nothing covers the source request changing, a new repository map, a person's answer, or the five values that `gate_integrity.invalidated_by` lists.

## What was checked

On 2026-10-27, in this repository.

- Each claim above was verified against the files: `state-machine.md` (guards `G_RETRY_EXHAUSTED_OR_NONRETRYABLE`, `G_UPSTREAM_PASSED`, INV-10), `policies/security.yaml` line 1057 (`on_exhaustion`) and line 1077 (`invalidated_by`), `crates/domain/src/machines/retry.rs` (the module comment says the file "disagrees with itself" and picks the person), `guards/stage_run.rs` (`upstream_passed` tests `run.status == StageRunStatus::Passed`), `guards/job.rs` (`pipeline_scope_complete` does the same) and `rework.rs` (`route()` finds a human route only from `APPROVAL`; a `specification` or `policy` class at `DOCUMENTATION_REVIEW` gives `NoReworkRoute::Defect` and so `S12`).
- The skip flaw is wider than it was first reported. `G_PIPELINE_SCOPE_COMPLETE` has it as well as `G_UPSTREAM_PASSED`.
- After the JSON change, `cargo test -p factory-domain --test state_machine_conformance` ran: 13 passed and 7 failed, each failure naming the changed guard, the changed edge or the new invalidation rows. This shows the tests read the file and are not vacuous.
- `docs/database/tools/state_machine_sql.py` and the migrations also read the JSON. The edge `SKIPPED` to `SUPERSEDED` needs a migration (see the work package `s1-database-tenancy-and-state-sync`).

Not verified: any behavior of the engine, because it does not exist yet.

## Decision 1: a limit asks a person, and only a failure that retrying cannot fix fails the stage

### Considered options

1. **Fail the stage when `max_attempts` is reached** (the guard as written). A provider outage that outlasts three attempts ends the stage, and with `G_UNRECOVERABLE` the job. Failing is hard to undo, and a person could have waited an hour.
2. **Block the stage** (the policy as written). `BLOCKED` has the wrong exits. Its ways out are a capability re-probe (`S17`), an override that turns the run into `PASSED` (`S18`), or rework (`S15`). None of them is "add budget and try again", and an override of a budget stop into a pass is meaningless.
3. **Ask a person.** `WAITING_FOR_HUMAN` has the exit that is needed: `S13`, an answer such as a budget extension, which re-opens the run. It also has approve, rework and reject.

### Outcome

Chosen: **option 3**, for retries, for the budget and for `BUDGET_EXHAUSTED`. The engine takes the first row that applies when an attempt has failed:

| Order | The attempt failed with | Move |
|---|---|---|
| 1 | `BUDGET_EXHAUSTED` | `S07`, and the job's broker token is revoked |
| 2 | A class the contract lists in `retry_on`, with attempts, repairs and budget left | `S05` |
| 3 | `POLICY_DENIED`, `INTERNAL`, or a class not in `retry_on` | `S06` |
| 4 | A class in `retry_on`, with no attempt or repair left, or with no budget | `S07` |

Consequences for the file and the code:

- The guard of `S06` is renamed `G_FAILURE_NONRETRYABLE`. Its old name said "exhausted", which is the opposite of the new rule. A guard keeps its name when the name is still true (see decision 2), and changes it when the name states the opposite.
- `G_ESCALATION_REQUIRED` includes the attempt limit and the repair cap, as its own condition. The domain code currently disguises the attempt limit as `policy_requires_human_decision`, which hides the cause.
- An **attempt window** starts at each human answer (`S13`). Attempts and repairs are counted from the last answer. A person who answers a stage run that stopped at its limit gets a new window, and the total stays bounded because a person is in the loop each time. Without this, the first failure after an answer would escalate again at once.
- `S13` gains the actor `org_admin`. A budget extension that raises a ceiling is an `org_admin` decision (`raise_budget_ceiling` in `policies/approval.yaml`), and no transition let that role act.
- `S07` has the effect "when a budget limit was hit, revoke the job's broker token". The policy already lists `budget_exhausted` among the reasons a token is revoked (`policies/security.yaml` line 931).
- The **repair cap** is two. A repair is a retry that follows an `INVALID_OUTPUT` failure, so it also counts as an attempt, which is how the old bounds table read "counted inside the attempt limit". Its value is `untrusted_content.structured_output.bounded_repair_attempts` in `policies/security.yaml`, and a policy may lower it and never raise it, the same rule as for the rework cap. In code it lives next to `DEFAULT_REWORK_CAP` in `machines/limits.rs`, and `G_RETRY_ALLOWED` reads it from `RetryFacts`.
- Invariant INV-10 now says that exhaustion, including a budget limit, escalates and does not fail the stage run.

### What the policy file must say

`budgets.on_exhaustion` becomes `stop_job_revoke_job_token_wait_for_human`: the running stage run goes to `WAITING_FOR_HUMAN`, the job follows (`J03`), no new attempt is leased while the job is not `ACTIVE`, and the broker revokes the job token. Raising the ceiling is `raise_budget_ceiling`. The word BLOCKED in the old value stays reserved for gates that cannot run and for policy violations that a deterministic check detects. The negative test NT-TOOL-09 expects the stage state `FAILED` after two repairs. Under this decision it is `WAITING_FOR_HUMAN`, or `FAILED` when the contract does not list `INVALID_OUTPUT` in `retry_on`. The test's real claim, that the output does not advance and no unknown field is honored, holds either way, and its wording should say "does not advance".

## Decision 2: a skipped stage satisfies its dependants and the completion check

### Considered options

1. **Leave the guards as they are, and never use `S02` for a stage that another stage requires.** Every stage except `MERGE` is required by another, so `S02` would be dead.
2. **Run the stage and pass it with a `NOT_APPLICABLE` gate report.** The status says `PASSED` for work that was not done, and an assurance level could be derived from it by mistake.
3. **`SKIPPED` satisfies the dependency and the completion check, and can be superseded.**

### Outcome

Chosen: **option 3**.

- `G_UPSTREAM_PASSED` and `G_PIPELINE_SCOPE_COMPLETE` accept a run that is `PASSED` or `SKIPPED`, and not superseded. The guard keeps its name, because "passed or skipped by rule" is still the upstream condition in plain terms, and a rename would touch every file for no change in behavior.
- A skipped run is never evidence. It creates no assurance level (rule 1 of the assurance section is unchanged), and the stage contract of the next stage records the skip rule where it would record an artifact hash.
- `SKIPPED` becomes supersedable, and `S20` lists it as a source state. This is not optional. The skip decision was made on recorded inputs. When an upstream artifact changes, the decision must be made again, and the engine creates a new run. If the old `SKIPPED` run stayed in place, `upstream_passed` (which asks whether any run of the stage qualifies) would still be satisfied by the stale run while the new one is `PENDING`.
- This changes an edge, so the database needs a migration: the edge `SKIPPED` to `SUPERSEDED` in `state_machine_edges`, and the terminal-row trigger.

## Decision 3: findings that the builder cannot fix go to a person, and a person can send rework further back

### Considered options

1. **Keep two routes and fail the rest** (the file as written). A reviewer who finds that the specification is wrong ends the job in `FAILED`, with nobody asked.
2. **Route `specification` back to `SPECIFICATION`.** Re-running the specification supersedes every later run, and it needs the revision method that ADR 0006 has not proven. It also lets a reviewer agent reopen an approved specification.
3. **Ask a person for `specification` and `policy` defects, rework the rest.**

### Outcome

Chosen: **option 3**. The defect class comes from the findings that justify the verdict (severity blocker, high or medium). When they differ, the first in this order wins: `specification`, `policy`, `code_behavior`, `documentation`, so a decision that needs a person is not hidden behind an easy fix.

- The matrix `pipeline.defect_routing` in the JSON gives the outcome for each of the four stages that have an independent reviewer. A `policy` finding gives `gate_needs_human` (`S10`) at every stage. A `specification` finding does too, except at the stage that produces the specification, which reworks its own artifact.
- A reviewer's `policy` finding asks a person and does not block. `G_BLOCKING_CONDITION` is for violations that a deterministic check detected. A reviewer's opinion can be wrong, and a block with nobody asked is a worse outcome than a question.
- `G_NEEDS_HUMAN_VERDICT` gains the condition for these classes.
- A deterministic failure at `DOCUMENTATION_REVIEW` has no reviewer class and counts as `documentation`. Today it would hit `DefectNeeded` and fail the job over a broken link.
- The table `pipeline.human_rework_routes` lists, for each waiting or blocked stage, the stages a person may send rework to: the agent-produced stages `ARCHITECTURE`, `TASK_PLANNING`, `IMPLEMENTATION` and `DOCUMENTING` that are at or before it. `SPECIFICATION` is a target only from `SPECIFICATION`, because revising a frozen specification needs the unproven method of ADR 0006. A person who finds the specification wrong at `REVIEW` answers, approves with a recorded reason, or rejects the job. The cap of two rounds and the code and documentation counts are unchanged.

## Decision 4: every change that makes a result stale has a row

### Outcome

The invalidation table grows from five to eight rows. The new ones are external changes or changes the pipeline does not produce, so they have no producing stage and every listed run is superseded, including the first.

| New row | Supersedes | Why |
|---|---|---|
| The source request is edited after the intake snapshot | `INTAKE` and every stage after it | The text every later stage read is no longer the text a person authorized. The new intake run asks for re-authorization before any agent reads the new text (NT-AUTHZ-05). The catalog's state name `awaiting_reauthorization` is this condition: the new intake run and the job are `WAITING_FOR_HUMAN`. |
| `REPOSITORY_INTELLIGENCE` produces a new repository map | `SPECIFICATION` and every stage after it | The specification consumed the map and the baseline. Reachable in Slice 1 only through the row above. |
| A value bound to gate evidence changes | `VALIDATION`, `REVIEW`, `DOCUMENTATION_REVIEW`, `DELIVERY`, `APPROVAL` | The base commit, the gate definition hash, the policy hash and the image digest (`gate_integrity.evidence_binding`). `DOCUMENTING` stays, because the text did not change. |

The items of `gate_integrity.invalidated_by` map like this: `new_commit` and `rebase` to the commit rows (a rebase writes new commits), `spec_revision` to the specification row, and `base_moved`, `policy_change` and `image_change` to the last new row. The table is in `state-machine.md`.

Two decisions keep this affordable.

- **Evidence values are checked at two points, not watched.** The engine compares the bound values with the ones in the evidence manifest before `DELIVERY` pushes and when an approval is recorded. A base branch moves on busy repositories many times an hour, and restarting a job on each move would never finish. A merge, in Slice 4, adds a check right before it.
- **A human answer (`S13`) supersedes nothing.** A stage run that waits for a person has produced nothing yet, so no later run exists to become stale. The answer is a new input of the stage run, and the stage contract is resolved again with the new input hash.

## Consequences

- Good: three documents now agree. Nothing fails a stage because a provider was slow or a budget was small, and a person can always continue.
- Good: a skipped stage no longer stalls the pipeline, and the old run cannot satisfy a new run's condition.
- Good: the routing table is a matrix that a test can compare cell by cell.
- Bad: more escalations to a person, which is the cost ADR 0009 already accepts for rework.
- Bad: the edge `SKIPPED` to `SUPERSEDED` and the new guard names reach into three places: the JSON, the Rust code, and the database migrations. The work packages `s1-domain-revision` and `s1-database-tenancy-and-state-sync` carry them, and the first lists every test that must change in `domain-revision-checklist.md` (deleted when the work landed).
- Bad: the rule that the engine "takes the first row that applies" is a priority order that the guards do not express by themselves. It lives in the retry function of `domain` and in the stage run machine's description, and a property test covers it.
- Neutral: the catalog's NT-TOOL-09 and NT-AUTHZ-05 need small wording changes from the security specialist.

## Confirmation

- The conformance test of `domain` reads the file again: guards, edges, actors, the matrix, the human routes and the eight invalidation rows.
- A domain test shows that `BUDGET_EXHAUSTED` and an exhausted attempt limit choose `S07`, never `S06`, whatever the other facts are.
- A domain test shows that a skipped run satisfies `upstream_passed` and `pipeline_scope_complete`, is superseded by an upstream change, and creates no assurance level.
- The engine test with an always-failing fake runtime (INV-10) reaches `WAITING_FOR_HUMAN` in a bounded number of steps, and a human answer starts a new window.
