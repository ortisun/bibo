# 0022: A rework count for each phase: specification, design, code and documentation

- Status: **Proposed, pending the owner**. Built on the branch `fix/agent-report-channel` from real run 29 of scenario E1. No independent review has covered it.
- Date: 2026-11-20
- Deciders: the engineer, for the owner to confirm.
- Amends: [ADR 0009](0009-operating-defaults-pending-confirmation.md) item 6 (how the two rounds are counted, not how many there are), invariant INV-10, guards `G_REWORK_ALLOWED` and `G_HUMAN_REWORK_ALLOWED`, and the bounds table of [state-machine.md](../architecture/state-machine.md).
- Related: [ADR 0010](0010-failure-escalation-routing-and-invalidation.md) (rework routes and human rework targets), NT-BUD-04.

## Context and problem statement

ADR 0009 item 6 caps rework at two rounds, then a person decides, "for code and for documentation". The engine had two counts. `ReworkTrack::for_target` charged a round that targets `DOCUMENTING` to the documentation count and every other round to the code count, so re-runs of `SPECIFICATION`, `ARCHITECTURE` and `TASK_PLANNING` shared the two rounds that `state-machine.md` names for `IMPLEMENTATION` re-runs. The engine chose that so the design rounds had some bound.

In run 29 of scenario E1 the specification needed its two rounds to converge, and the owner approved it. The first architecture gate failure then stopped with `rework-limit`: the job had no round left for the architecture, and the implementation and review loop would have had none either. A person could not send the work back for the same reason. Two rounds spent on one artifact took the rounds of two later artifacts, which a cap per artifact loop was never meant to do.

## Which stages are the design phase

`state-machine.json` has these rework targets: `SPECIFICATION` (its own gate, and a person from `SPECIFICATION`), `ARCHITECTURE` and `TASK_PLANNING` (their own gates, and a person from any later stage), `IMPLEMENTATION` (the scope check, validation, review, the documentation review on a code defect, and a person) and `DOCUMENTING`. `DOMAIN_DISCOVERY` is deterministic and is no target at all.

The specification is not in the design count. It ends when it is frozen, with a person's approval by risk, and every later stage is judged against the frozen text; the architecture's failures say nothing about the specification and the other way round. Putting both in one count reproduces run 29 one phase earlier: two specification rounds, and the first architecture failure asks a person. So the specification has a count of its own.

`ARCHITECTURE` and `TASK_PLANNING` share the design count. The task plan is cut from the architecture, a round on the architecture replaces the task plan, and a person who sends work back from the task plan usually names the architecture. Two rounds for both together bound the design loop as one loop.

`DOMAIN_DISCOVERY` goes with the design it feeds, and `INTAKE` and `REPOSITORY_INTELLIGENCE` with the specification, so that a route added to them later is bounded from its first round. Every stage from `IMPLEMENTATION` on that is not `DOCUMENTING` stays on the code count, as before.

## Considered options

1. **A count per phase: specification, design, code, documentation** (chosen). Each count has its own policy key and the cap of two. A round on one never uses a round of another.
2. **One design count for `SPECIFICATION`, `ARCHITECTURE` and `TASK_PLANNING`.** It keeps the code rounds for the implementation, which fixes half of run 29, but the first architecture failure after two specification rounds still asks a person. Rejected: it does not fix the run that motivated it.
3. **A count per target stage.** Specification, architecture, task plan, implementation and documentation each with two rounds. It fixes run 29 too. Rejected: a task plan round and an architecture round rework the same design, so the design loop could take four rounds before a person sees it, and the count no longer matches a loop a person can name. It also needs a key per stage or one key for several counts.
4. **Raise the code cap.** Three or four rounds on the one code count. Rejected: ADR 0009 item 6 sets two and says raising it is a widening that needs a recorded human decision (`raise_budget_ceiling`); it also still lets the specification spend the implementation's rounds, only later.
5. **Exclude the design phase from the caps.** Rejected: INV-10 requires every loop to be bounded, and an unbounded specification or architecture loop spends the job's budget before a person sees it.

## Decision outcome

Option 1. `ReworkTrack` has four values, `specification`, `design`, `code` and `documentation`, and `ReworkTrack::for_target` maps every stage kind to one of them. `ReworkLimits` and `ReworkLedger` hold one cap and one count for each track; `ReworkLimits::with_policy` takes the lower of the policy value and `DEFAULT_REWORK_CAP`, so no cap is above two.

The policy has two new required keys, `budgets.hard_ceilings.per_job.max_specification_rework_iterations` and `max_design_rework_iterations`, both 2. The loader refuses a value above 2, like the other two keys, and refuses a file that lacks either (a missing bound is not read as a default). A repository policy may only lower them: `budgets.hard_ceilings.*.*` is a ceiling in `tighten.rs`, and a repository file that omits one does not load.

The composition root now hands the policy's caps to the engine (`apply_budget_policy`): before this change the engine ran on its default caps, so a repository policy that lowered a rework or repair cap was not applied. The policy values are all 2 today, so nothing changes for a job under the central policy.

The job view reports `specification_rework_rounds` and `design_rework_rounds` beside the code and documentation counts, and the `rework_track` field of the rework event can now say `specification` or `design`.

## Consequences

- Good: a specification that needs its two rounds leaves the architecture two and the implementation two; run 29 would have reworked the architecture.
- Good: each count names a loop a person can recognise, and the escalation message names it ("the design rework cap of 2 rounds is reached").
- Cost: a job can now go through up to eight automatic rework rounds before a person decides, where it went through four. The per-job budget (`max_usd`) still stops all of them, and each count is still two.
- Cost: two more keys in every policy file. A repository policy written before this change fails to load until it states them.
- Jobs already in the database: the engine stores no count. It reads the rounds of a job from its stage runs each time (`timeline::rework_ledger`), charging each round to the count of its target. A job in flight is therefore counted under the new rule at once: its specification and design rounds move off the code count, and none is lost or invented. A job that waits for a person because the shared count was full may now be sent back by that person to the architecture or the implementation. The `rework_track` written into an earlier rework event still says `code` for a design round; it is a record of what was decided then and nothing reads it back.

## Verification

Domain tests: each target's count, counts kept apart, caps of 0, 1 and 2 on each count, a policy value above 2 clamped, the run 29 sequence through `decide_gate_rework`, a person's round charged to the design count while the code count is full, the loader refusing 3 and a missing key, and `tighten` refusing a raised design or specification cap and accepting a lowered one. Engine tests (in-memory, and on PostgreSQL through `apps/worker/tests/engine_scenarios_all_on_postgres.rs`, which includes the same scenarios): two specification rounds then three architecture failures (two reworks, then a person); two specification rounds and one design round, then the implementation still gets its two rounds; a person sends the design back when the code count is full. Not verified: a real end-to-end run.
