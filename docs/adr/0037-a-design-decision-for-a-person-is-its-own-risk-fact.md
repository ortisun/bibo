# 0037: A design decision that needs a person is its own risk fact, at the medium tier, and still calls the critic

- Status: **Decided by the owner on 2026-11-24**; the engineer wrote the options and the shape. No independent review has covered it.
- Date: 2026-11-24
- Deciders: the owner chose among four options for the risk of such a decision, and between two for the critic.
- Related: [policies](../reference/policies.md) (`risk_tiers`), the [state machine](../architecture/state-machine.md) (stage 5, `ARCHITECTURE`), [ADR 0022](0022-solo-approval-mode.md) (the solo waits that the high tier sets), the real E1 runs of 2026-11-22 (follow-up of PR #18).

## Context and problem statement

The architect marks a decision of its design `needs_person` when a person must approve it. The prompt names a new dependency as the usual case, but it can be any choice. The policy had no criterion for such a decision, so the architecture stage counted each one as `new_dependency` (`crates/workflow/src/stages/architecture/risk.rs`). `new_dependency` is a criterion of the **high** tier in `policies/approval.yaml`. So one decision for a person:

1. made the design high, which calls the independent critic (`critic_from: high`) and a person (`human_from: high`);
2. made the pull request high too, because the delivery stage measures the design again and joins it with the diff (`crates/composition/src/delivery.rs`). The high tier adds the `security_reviewer` and the `adversarial_reviewer`, and in the solo mode a 10 minute wait and the confirmation phrase;
3. was recorded under a name that says a dependency was added when none was.

In the real E1 run of 2026-11-22 a one-flag change (`--json` for a word counter) became high this way. A person was already asked: the design gate stops for a person whenever any decision has `needs_person` (`gates.rs`).

A real new dependency does not need this lift. It stays high by two other facts. At design time the dependency manifest is a sensitive path, so a design that touches it has `sensitive_file_change`. At pull request time the diff check sets `new_dependency` when a manifest adds a direct dependency (`crates/workflow/src/stages/delivery/risk.rs`).

## Considered options

1. **A fact of its own, at the medium tier** (chosen). A new fact `design_decision_needs_person` in `RiskFacts`, named as a criterion of the medium tier. The name says what happened, and the policy file, not the code, says what it costs.
2. **A fact of its own, at the high tier.** The name is honest, and the cost is the same as before.
3. **No risk effect.** The decision only stops the design gate for a person. Later stages lose the fact that a person decided something in the design.
4. **No change.** Keep the follow-up open.

For the critic, two options:

- **Call the critic for every design with such a decision** (chosen). The person gets a decision that a second agent has already reviewed. It costs one more model call, only in this case.
- **Follow the tier.** At medium the critic does not run, and the person is the only reviewer of the decision.

## Decision

- `RiskFacts` gains `design_decision_needs_person`: "a decision of the design needs a person to approve it". The architecture stage sets it when any decision of the design has `needs_person`. It no longer sets `new_dependency`.
- `policies/approval.yaml` names `design_decision_needs_person` in `criteria_any` of the **medium** tier.
- `single_module_change_without_sensitive_or_protected_paths` still does not hold when such a decision exists, as before. That changes no tier, since medium is above low, and it keeps the fact from reading as a plain change.
- The architecture stage calls the independent critic when the tier is at or above `critic_from`, **or** when any decision has `needs_person`. The record keeps the tier, `critic_from` and `decisions_for_a_person`, which together show why the critic ran, and the critic gate's reason names both rules when no critic was required or none could be used.
- The design gate still stops for a person when any decision has `needs_person`, as before.
- `decisions_for_a_person` in the architecture record still lists the decisions; it is now explained by the new criterion, not by `new_dependency`.

## Consequences

- Good: a design and a pull request whose only fact is a decision for a person are medium. They get the `code_reviewer` and `qa` reviews, and no solo wait.
- Good: the record names what happened. No audit reads "a new dependency" for a change that added none.
- Good: a real new dependency is still high, by `sensitive_file_change` at design time and `new_dependency` at pull request time.
- Good: the critic still reviews every decision a person is asked to approve.
- Bad: one more criterion to keep in step between the code and the policy file. The engine refuses a criterion that has no fact, but a fact that no tier names would just never match, so a test checks that the policy names this one at the medium tier.
- Neutral: the separation of duties conditions do not name the new fact. In the solo mode the requester approves a medium pull request with no wait and no phrase, like any medium change.

## What was checked

- Unit tests of the architecture stage: a design with a decision for a person is medium, matches `design_decision_needs_person` and not `new_dependency`, and calls the critic. A design that also touches the manifest is still high.
- A domain test: the real policy names `design_decision_needs_person` at the medium tier.
- The domain tests that build `RiskFacts` and the policy fixture, regenerated from `policies/approval.yaml`.
- Not run: a real E1 run with this change.
