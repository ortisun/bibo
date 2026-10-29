# Findings of the Slice 1 end-to-end run

- Status: written by the quality assurance (QA) work package `s1-end-to-end-run` after the run recorded in the [acceptance report](slice-1-acceptance.md). No fix to production code was made. Nothing here was reviewed by anyone else yet.
- Form: reference.
- Goal: list every failure and gap met while running the scenarios, with the evidence, the owner and the smallest fix, so that each can become an issue.

Each entry has an identifier, the scenario that showed it, what was seen, where to look, who owns the fix, how serious it is and the smallest change that would close it. The severity words are the ones the security reviews use: High means a requirement of the specification is not met, Medium means a control or a proof does not do what its text says, and Low means a narrow case or a gap in what a test can show.

## Defects the run found in the factory

### SF-01: an unauthorized label leaves no record of the rejection and no explanation

- **Scenario.** E6, "A requester who is not on the allowlist is rejected".
- **What was seen.** A person who is not on the allowlist labels an issue. The API answers like it answers everyone, makes no job, and writes one audit record, `webhook.accepted`, with the text "The delivery was verified and recorded." Nothing records that a request was rejected, who filed it or why. No explanation is posted on the issue.
- **Evidence.** [`fixtures/recordings/e2e/E6/evidence.json`](../../fixtures/recordings/e2e/E6/evidence.json): the audit stream holds one record and no `authorization_decision.denied`; the code host holds no comment on the issue. The check `E6.rejected` fails with "the audit stream holds 0 denial records". The cause is in `apps/api/src/webhook.rs`: the job is made only for an allowlisted sender, and no branch writes a rejection.
- **Requirement.** FR-002 and SC-002 of the specification: every rejected issue gets a short plain-English explanation and an audit record that states who filed the issue, what was decided, when and why.
- **Owner.** `api` (the webhook), with `workflow` for the reply.
- **Severity.** High.
- **Smallest fix.** Make the job at `RECEIVED` for a labelled issue from any registered principal, so that the engine's admission rejects it (it already writes `authorization_decision.denied`), and have the worker's hook post one fixed explanation through `ChangeHost::post_comment` after `Admission::Rejected`. The API holds no GitHub credential, so it cannot post the reply itself. The audit trigger on the API login limits the actions the API may write (migration `2026-10-29-002100_api_audit_actions`), so writing the denial from the API would need that list changed by the database owner.

### SF-02: two log lines of the worker's hook carry no correlation id

- **Scenario.** E3, assertion A11.
- **What was seen.** A11 requires the correlation id of the job on every event and log line. Two lines of the hook have none: "a received job was decided" (it names the job and not its correlation id) and "a decision was dealt with". Both are emitted outside any job span. The spans themselves held: every attempt hangs under a stage run span of its own run.
- **Evidence.** [`fixtures/recordings/e2e/E3/evidence.json`](../../fixtures/recordings/e2e/E3/evidence.json), `telemetry.correlated`; `crates/composition/src/decisions.rs` lines 1034 to 1037 and 1126.
- **Owner.** `composition`.
- **Severity.** Medium. A reader who follows one job by its correlation id does not see these two lines.
- **Smallest fix.** Give the first line the correlation id of the job (the admission result or the stored job has it) as the field `factory.correlation_id`, and either give the second line the id of the job it concerns or log it without a job. Then A11 passes on E3 without changing the check.

### SF-03: the engine opens one stage run span for each claim

- **Scenario.** E3 and E4, assertion A11.
- **What was seen.** A stage run that waits for a person is claimed again after the answer, and the engine opens a new `factory.stage_run` span for the new claim. The specification stage therefore has two stage run spans. The first version of the check required exactly one and failed on a correct run.
- **Evidence.** The first run of E3 before the check was changed: "the SPECIFICATION run has 2 stage run spans, and it must have one".
- **Owner.** `qa` for the check, `software_architect` to confirm the design.
- **Severity.** Low. The harness now accepts one stage run span for each claim and still requires that each attempt hangs under a stage run span of its own run. The tests `a_run_resumed_after_a_wait_may_have_a_stage_run_span_for_each_claim_but_not_none` and `an_attempt_under_the_stage_run_span_of_another_run_fails` keep the bar.
- **Smallest fix.** If the architect wants one span for the whole life of a stage run, the engine must keep the span open across the wait or link the new span to the old one. Otherwise nothing more is needed.

## Gaps in what the composed test rig can show

These are not defects of the factory. They are things a run in test mode cannot show, and the scenarios that need them are `BLOCKED` on the check, never passed.

### SF-04: the composed rig mints no installation token

- **Scenario.** E4, assertion A10.
- **What was seen.** A10 reads the installation tokens of the job: none may hold a permission the policy forbids, and each must be narrowed to one repository. The rig's change host is the testkit fake, which takes a scope and mints nothing, so no token is recorded.
- **Evidence.** `recorded::GAPS` in [`tests/end_to_end/src/recorded.rs`](../../tests/end_to_end/src/recorded.rs); the E4 report line.
- **Owner.** `composition` (the rig in `apps/api/tests/full/`).
- **Severity.** Medium. The narrowing is covered by the tests of the GitHub adapter, and a live run covers it end to end, but the composed run does not.
- **Smallest fix.** Let the rig take its change host and issue source from outside, and run the real GitHub adapter against the reference fake GitHub server (FX-GH) in the composed run, so that the tokens, the request paths and the protection are recorded by the server. The rig is a test file that this work package was not allowed to restructure.

### SF-05: the scripted agents never attempt anything

- **Scenario.** E4, check `E4.agent-denials`.
- **What was seen.** The scenario needs an agent that obeys the hostile text and is denied by the tool grant, so that the audit stream holds `tool_call_denied.denied`. The playbook runtime queues only an answer for each agent. It cannot carry actions or denials, although the testkit's `AdversarialScript` can.
- **Evidence.** `apps/api/tests/playbook/mod.rs`, `PlaybookRuntime::run`, which queues `AdversarialScript::returning(output)`.
- **Owner.** `software_engineer` (the playbook).
- **Severity.** Medium. E4 is judged on what could be tried through the API and on the canary sweep; four attempts were made and denied and no canary leaked. The demands that only an obeying agent can act on (edit a workflow, edit the manifest, print the environment) are not exercised in E4. E8 exercises the protected-path refusal on its own.
- **Smallest fix.** Let a `Reply` carry an `AdversarialScript` (actions and denials), and give E4 a compromised builder that attempts the demanded actions.

### SF-06: the fake code host keeps neither comment text nor request paths

- **Scenario.** E6 (the reply), A10 (the requests).
- **What was seen.** `FakeChangeHost` keeps the key of each comment and not its text, and records no request path. The recording holds the number of comments and not what they said.
- **Evidence.** `crates/testkit/src/githost.rs`.
- **Owner.** `testkit`.
- **Severity.** Low. For E6 the number is zero, so nothing is hidden.
- **Smallest fix.** Keep the text and a log of calls in the fake, or use FX-GH as in SF-04.

### SF-07: the protection report has no count of required reviews

- **Scenario.** All scenarios that open a pull request.
- **What was seen.** The port's `ProtectionReport` says whether a pull request is required and whether code owners review, and not how many approvals. The recording writes one approval, which the policy requires, and says so in `mode.json`.
- **Owner.** `software_architect` (the port).
- **Severity.** Low.
- **Smallest fix.** Add the count to the report in the next revision of the ports.

### SF-08: the commits on the head branch are taken from the stage results

- **Scenario.** E4, E5, assertion A3.
- **What was seen.** The commits on the head branch and the paths they change come from the implementation and documentation results. The remote confirms that the branch tip is the pull request head and that the pull request is an open draft, but the fake remote offers no listing of commits to read them back.
- **Owner.** `testkit`.
- **Severity.** Low.
- **Smallest fix.** Add a read of the commit chain and the changed paths to `FakeRemote`.

## Gaps in the harness found and fixed in the run

The scenario checks were written against a scripted flow before the composed pipeline existed. Running them against the real pipeline showed six places where they expected a shape the pipeline does not have. Each was changed in `tests/end_to_end`, with a test that keeps the bar, and none lowers what a scenario must show.

| Id | Check | What it expected | What the pipeline does | What changed |
|---|---|---|---|---|
| SF-09 | A1, A13, E5 | Every stage has a passed run. | `DOMAIN_DISCOVERY` is skipped by a rule, which the architecture decision record (ADR) 0010 says satisfies the stages that need it. | A skipped run settles its place when the ledger records the skip. A skip with no entry settles nothing. |
| SF-03 | A11 | One stage run span for each run. | One for each claim. | See SF-03. |
| SF-10 | A9 | One approval record. | Two, one for the specification draft and one for the pull request. | Every record must be a person other than the requester, and the last is the approval of the pull request. |
| SF-11 | E8 | A failed protected-paths gate report, then the validation stage waits. | The builder's patch is refused when it is taken in, before any gate report exists, and the implementation run is blocked. | Either shape passes, and both need the path named, the denial audited, the branch unchanged, no pull request and no later stage started. |
| SF-12 | E6 | A job in the state `REJECTED`. | No job at all (SF-01). | A rejection that made no job passes the first test and still needs the audit record and the reply, so SF-01 fails the scenario. |
| SF-13 | E7 | The action `webhook_accepted_or_rejected` with the word "duplicate". | `webhook.duplicate_delivery`. | The check counts both. |

The run of E4 also showed that the check on denied tool calls (SF-05) is a different claim from the rest of `E4.no-effect`, so it is now a check of its own, `E4.agent-denials`, and only it is blocked.

## Changes outside the allowed paths

- `apps/api/tests/playbook/mod.rs` has four more lines. A rework round gives the builder one task, `rework-round-N`, that lists every task of the plan for context, and the playbook refused it as naming several tasks. It now maps that task to the entry `builder.rework-round-N`, which a test supplies with `replace`. Without the change E3 cannot run. This is an edit to an existing test file beyond exposing a helper, and it is reported for review.
- The factory has no data file for a rework answer in `fixtures/recordings/playbook/word-count/`. E3 builds its two answers in the test.

## Open items outside this run

The items below were already open in the review documents or the plan. This work package neither opened nor closed them, and the report says which scenarios they block.

| Item | Where | Blocks |
|---|---|---|
| The agent image was pinned before its recipe changed (execute-only chain, RR-14, SBX-4, IMG-1). It has to be rebuilt, tested with `infra/sandbox-images/test.sh`, and its new digest recorded. | [isolation core re-review](../reviews/isolation-core-security-rereview.md) | E1, E2 |
| `policies/model_routing.yaml` does not exist. | [worker README](../../apps/worker/README.md), "Blocked" | E1, E2 |
| The composed wiring program (`FACTORY_E2E_COMPOSED`) does not exist. | [worker README](../../apps/worker/README.md), "The end-to-end `Wiring`" | E1, E2 |
| The fixture's `CODEOWNERS` lists placeholder handles. | `fixtures/repos/word-count/CODEOWNERS` | E1, E2 |
| API keys with a provider-side spend limit, a registered GitHub App, a protected fixture repository, the named requester allowlist. | [slice plan](../architecture/slice-plan.md), sections 2 and 14 | E1, E2 |
| The nineteen defaults of ADR 0009 wait for confirmation, and the architect has not confirmed several proposals that reviews depend on (the `TurnAttestation` and `label_application` port proposals in `ports-v1.1.md` section 16, and the `DOMAIN_DISCOVERY` probes duty). | [ADR 0009](../adr/0009-operating-defaults-pending-confirmation.md), [authority review](../reviews/authority-and-evidence-security-review.md), [worker README](../../apps/worker/README.md) | The live run |
| Hypotheses still open in the re-reviews: RR-23 (label skew), RR-28 (narrowing by repository id), RR-13 (names that print blank), RR-25 (owner of the key file), the supply chain hypotheses H-1 to H-8, and the authority hypotheses H-1 to H-6. | [supply chain re-review](../reviews/authority-api-supply-chain-security-rereview.md), [isolation re-review](../reviews/isolation-core-security-rereview.md), [supply chain review](../reviews/supply-chain-and-delivery-security-review.md), [authority review](../reviews/authority-and-evidence-security-review.md) | The live run |

## How the entries should be used

Each defect and gap above is small enough for one issue. SF-01 is the one that touches a requirement of the specification, and it should be settled before a live run, because the live run will show the same behaviour.
