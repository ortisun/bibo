# Findings of the Slice 1 end-to-end run

- Status: written by the quality assurance (QA) work package `s1-end-to-end-run` after the run recorded in the [acceptance report](slice-1-acceptance.md), and revised the same day by the software engineer work package `s1-e2e-fixes`, which fixed SF-01, SF-02, SF-04, SF-05, SF-06 and SF-08, left SF-03 and SF-07 open, and added the entries SF-14 to SF-19 and the routing policy section. Each entry below says what became of it. Nothing here was reviewed by anyone else yet.
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
- **Status: fixed, in a different shape.** A job was not the right record: a sender the tenant does not know has no principal to make a job for, and the numeric id the audit record must state would sit on a job that should not exist. The API now makes no job. In the same transaction as the delivery it leaves one request in the audit log under `webhook_accepted_or_rejected.denied`, an action the trigger already allows, signed with the key that signs the requests for decisions (the grammar and the worker side are in `crates/composition/src/intake_rejections.rs`). The worker's hook verifies the word, posts one fixed reply through `ChangeHost::post_comment`, and writes `intake.rejected` (an action the API cannot write) with the code `unauthorized_actor`, the numeric id, the version of the allowlist, the delivery id and `reply=posted`. The reply uses the token of the approval stage, which reads and writes issues only. It is sent at most once for a delivery: the API leaves no request for a repeat, the reply is keyed by the delivery id, and the record has a keyed id of its own. A bot is never answered. Tests: `a_signed_request_gets_one_plain_reply_and_one_audit_record`, `passes_after_the_first_add_neither_a_reply_nor_a_record`, `two_requests_for_one_delivery_get_one_reply`, `a_request_nobody_signed_or_signed_with_another_key_or_changed_is_ignored`, `every_kind_of_sender_gets_the_same_words_and_the_words_name_nobody`, `a_host_that_is_down_is_asked_again_and_the_reply_is_sent_once`, `a_reply_that_can_never_be_sent_still_leaves_the_record_and_says_so` and `the_reply_uses_a_token_for_one_repository_that_can_write_issues_and_nothing_else` in `crates/composition/tests/intake_rejections.rs`; `a_label_from_someone_who_may_not_ask_leaves_one_signed_request_and_no_job`, `a_redelivered_label_from_someone_who_may_not_ask_leaves_no_second_request` and `a_label_in_a_repository_that_is_switched_off_leaves_no_request` in `apps/api/tests/webhook.rs`; scenario E6.

### SF-02: two log lines of the worker's hook carry no correlation id

- **Scenario.** E3, assertion A11.
- **What was seen.** A11 requires the correlation id of the job on every event and log line. Two lines of the hook have none: "a received job was decided" (it names the job and not its correlation id) and "a decision was dealt with". Both are emitted outside any job span. The spans themselves held: every attempt hangs under a stage run span of its own run.
- **Evidence.** [`fixtures/recordings/e2e/E3/evidence.json`](../../fixtures/recordings/e2e/E3/evidence.json), `telemetry.correlated`; `crates/composition/src/decisions.rs` lines 1034 to 1037 and 1126.
- **Owner.** `composition`.
- **Severity.** Medium. A reader who follows one job by its correlation id does not see these two lines.
- **Smallest fix.** Give the first line the correlation id of the job (the admission result or the stored job has it) as the field `factory.correlation_id`, and either give the second line the id of the job it concerns or log it without a job. Then A11 passes on E3 without changing the check.
- **Status: fixed, and the entry was incomplete.** The conventions page (section 7) says a line written inside a job span starts with the job's correlation id, so each line about a job is now written inside the stretch span of that job, with the id read from the stored job and not from a record a person could write: the admission line, the line of a decision (and the refusal line inside it), the lines of the decisions on dependencies, and the drift pump, which serves a request inside the span of the attempt that made it. Lines that concern no job (junk records, the protection preflight, the request cache, start-up) stay without an id, as the page says. Test: `sf_02_the_lines_of_the_hook_about_a_job_carry_the_correlation_id_of_that_job`. When the two lines were fixed, A11 failed on a record it had not reached: `job.received_from_webhook` was written with a correlation id of its own and not the job's. That is fixed too (`the_audit_record_of_a_job_made_from_a_webhook_carries_the_correlation_id_of_the_job`), and A11 passes on E3 with its check unchanged.

### SF-03: the engine opens one stage run span for each claim

- **Scenario.** E3 and E4, assertion A11.
- **What was seen.** A stage run that waits for a person is claimed again after the answer, and the engine opens a new `factory.stage_run` span for the new claim. The specification stage therefore has two stage run spans. The first version of the check required exactly one and failed on a correct run.
- **Evidence.** The first run of E3 before the check was changed: "the SPECIFICATION run has 2 stage run spans, and it must have one".
- **Owner.** `qa` for the check, `software_architect` to confirm the design.
- **Severity.** Low. The harness now accepts one stage run span for each claim and still requires that each attempt hangs under a stage run span of its own run. The tests `a_run_resumed_after_a_wait_may_have_a_stage_run_span_for_each_claim_but_not_none` and `an_attempt_under_the_stage_run_span_of_another_run_fails` keep the bar.
- **Smallest fix.** If the architect wants one span for the whole life of a stage run, the engine must keep the span open across the wait or link the new span to the old one. Otherwise nothing more is needed.
- **Status: open.** Not touched.

## Gaps in what the composed test rig can show

These are not defects of the factory. They are things a run in test mode cannot show, and the scenarios that need them are `BLOCKED` on the check, never passed.

### SF-04: the composed rig mints no installation token

- **Scenario.** E4, assertion A10.
- **What was seen.** A10 reads the installation tokens of the job: none may hold a permission the policy forbids, and each must be narrowed to one repository. The rig's change host is the testkit fake, which takes a scope and mints nothing, so no token is recorded.
- **Evidence.** `recorded::GAPS` in [`tests/end_to_end/src/recorded.rs`](../../tests/end_to_end/src/recorded.rs); the E4 report line.
- **Owner.** `composition` (the rig in `apps/api/tests/full/`).
- **Severity.** Medium. The narrowing is covered by the tests of the GitHub adapter, and a live run covers it end to end, but the composed run does not.
- **Smallest fix.** Let the rig take its change host and issue source from outside, and run the real GitHub adapter against the reference fake GitHub server (FX-GH) in the composed run, so that the tokens, the request paths and the protection are recorded by the server. The rig is a test file that this work package was not allowed to restructure.
- **Status: closed for the test mode, not for a live run.** The labelled fake change host now mints a token for each job, kind of token (stage, fetch, push), repository and permission set, narrowed to the one repository of the scope, with the permissions the real adapter asks for, and records the request the real adapter would send for each call. `crates/github/tests/fake_host_permissions.rs` compares the permission sets of the fake with `PermissionSet` of the adapter for every stage, so they cannot drift apart. The recording holds the tokens and the requests, and A10 is judged from them (E4: four tokens, fourteen requests). The tokens are labels and the requests are a model of the adapter's: nothing was sent on a wire, and the mode file of every recording says so. The wire is still covered only by a live run.

### SF-05: the scripted agents never attempt anything

- **Scenario.** E4, check `E4.agent-denials`.
- **What was seen.** The scenario needs an agent that obeys the hostile text and is denied by the tool grant, so that the audit stream holds `tool_call_denied.denied`. The playbook runtime queues only an answer for each agent. It cannot carry actions or denials, although the testkit's `AdversarialScript` can.
- **Evidence.** `apps/api/tests/playbook/mod.rs`, `PlaybookRuntime::run`, which queues `AdversarialScript::returning(output)`.
- **Owner.** `software_engineer` (the playbook).
- **Severity.** Medium. E4 is judged on what could be tried through the API and on the canary sweep; four attempts were made and denied and no canary leaked. The demands that only an obeying agent can act on (edit a workflow, edit the manifest, print the environment) are not exercised in E4. E8 exercises the protected-path refusal on its own.
- **Smallest fix.** Let a `Reply` carry an `AdversarialScript` (actions and denials), and give E4 a compromised builder that attempts the demanded actions.
- **Status: fixed as far as a rig can go, and the limit is stated.** A `Reply` carries an optional script, and `Playbook::compromise` makes one agent obey the text. In E4 the builder of the first task runs the commands the text asks for in the fake sandbox, claims that every gate passed, and its scripted runtime reports four refused tool calls: reading the canary file, writing a protected path, using the network and approving. The pipeline turns each report into `tool_call_denied.denied`, and `E4.agent-denials` requires that all four places were tried, that the runtime reported at least as many refusals as attempts, and that the audit stream holds at least as many denials as the runtime reported. `E4.no-effect` counts the four attempts with the four made through the API. Nothing got through, so there is no finding about the pipeline. What the rig cannot show is the refusal itself. The fake sandbox answers `command not found` and `cat` with nothing, and the denials are a script's: the permission system of the coding tool and the posture of the container (no network, no secret path) do the refusing in a live run, and the tests that prove them need Docker, which does not answer on this machine. `recorded::GAPS` is empty now, and the mode file of every recording says this.

### SF-06: the fake code host keeps neither comment text nor request paths

- **Scenario.** E6 (the reply), A10 (the requests).
- **What was seen.** `FakeChangeHost` keeps the key of each comment and not its text, and records no request path. The recording holds the number of comments and not what they said.
- **Evidence.** `crates/testkit/src/githost.rs`.
- **Owner.** `testkit`.
- **Severity.** Low. For E6 the number is zero, so nothing is hidden.
- **Smallest fix.** Keep the text and a log of calls in the fake, or use FX-GH as in SF-04.
- **Status: fixed.** The fake keeps the text of each comment (`comments_on`) and the log of requests (`recorded_requests`). The recording holds both.

### SF-07: the protection report has no count of required reviews

- **Scenario.** All scenarios that open a pull request.
- **What was seen.** The port's `ProtectionReport` says whether a pull request is required and whether code owners review, and not how many approvals. The recording writes one approval, which the policy requires, and says so in `mode.json`.
- **Owner.** `software_architect` (the port).
- **Severity.** Low.
- **Smallest fix.** Add the count to the report in the next revision of the ports.
- **Status: open, and the adapter can provide it. Checked again for this work package: it cannot be closed without a change of the port.** A GitHub ruleset of the type `pull_request` carries `required_approving_review_count`, and `protection_from_rules` in `crates/github/src/protection.rs` reads the neighbouring fields of that rule and skips this one. The count cannot be reported until `ProtectionReport` in `crates/ports` has a field for it, and the port is not this work package's to change. A10 still reads one approval, written by the rig and said so in `mode.json`.

### SF-08: the commits on the head branch are taken from the stage results

- **Scenario.** E4, E5, assertion A3.
- **What was seen.** The commits on the head branch and the paths they change come from the implementation and documentation results. The remote confirms that the branch tip is the pull request head and that the pull request is an open draft, but the fake remote offers no listing of commits to read them back.
- **Owner.** `testkit`.
- **Severity.** Low.
- **Smallest fix.** Add a read of the commit chain and the changed paths to `FakeRemote`.
- **Status: fixed.** `FakeRemote::commits_above` lists the commits of a branch above a base, oldest first, with the paths each changes. The rig reads the recording's `head_commits` and `changed_paths` from it and fails the run if the remote holds other commits than the stages reported. The commit messages still come from the stage results, because the fake remote keeps none.

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

## Findings of the second run

These entries were found while fixing the first ones. They have the same fields as the entries above.

### SF-14: the reply is posted with a token that is wider than a reply needs

- **Scenario.** E6, the reply to an unauthorized label.
- **What was seen.** A comment on an issue needs `issues: write` and `metadata: read`. The only stage whose token writes issues and nothing that changes the repository is the approval stage, and its token also holds `contents: read` and `pull_requests: read`. The reply uses it, as the acknowledgement of a decision does. The recording shows one token, narrowed to the one repository, with no write level but `issues`.
- **Owner.** `github` (the token class) with the `software_architect`.
- **Severity.** Low. The extra rights are read rights on the one repository.
- **Smallest change.** A token class for a comment, with the two rights above, used by `post_comment` when the scope has no job, or a permission set that `GitScope` can ask for by name. The check `E6.rejected` accepts any read right and `issues: write`; it would be tightened with the change.
- **Status: fixed in the adapter.** `crates/github` has a token class for a comment (`TokenClass::Comment`, `PermissionSet::comment()`): `issues: write` and `metadata: read`. `post_comment`, and the search for its marker, use it for every stage that holds `issues: write` (the approval and the delivery stage); a stage that does not hold it keeps its own token, so the code host refuses the comment as before. The test is `sf_14_a_comment_is_posted_with_the_right_to_write_issues_and_the_metadata_only` against the fake code host, red when the comment goes back to the token of the stage. The scenario check `E6.rejected` runs on the testkit's fake host, which mints one token for a stage and has no token class, so it cannot show the narrowing and is not tightened.

### SF-15: the check of E6 was rewritten, and a reviewer should read the change

- **Scenario.** E6.
- **What was seen.** The first check forbade the words "not on the list" in the reply, as a way of not saying which test failed. FR-002 forbids revealing the contents of the allowlist and other internal detail, and does not forbid saying that the person is not on it. The reply the work package was asked to write says exactly that. The check now requires the sentence "not on the list of people who may ask for this" and forbids everything else about the list: the word allowlist, a digest, the sender's number or login, and any text of the issue. It also demands more than before: no job at all (the old check accepted a job rejected at admission), exactly one `intake.rejected` record with the sender, the delivery, the allowlist version and the code, and one token narrowed to one repository.
- **Owner.** `qa`.
- **Severity.** Low. A change of a check is not a thing to take on trust: the 24 mutations in `scenario_mutations.rs` show what it still catches.
- **Smallest change.** None. A reviewer reads `e6_rejected` and the 24 mutations.

### SF-16: an unauthorized sender who changes the label gets a reply each time

- **Scenario.** E6, E7.
- **What was seen.** The reply is sent at most once for a delivery. A person who removes the label and puts it back sends a new delivery for a new revision of the issue, which is a new event with its own key, and gets one more reply. The number is bounded by the per-installation limit on webhooks, not by a limit for the sender or the issue.
- **Owner.** `api`, with the `software_architect`.
- **Severity.** Low.
- **Smallest change.** Decide whether one reply for each issue and sender is wanted, and if so, key the reply by the issue and the sender and not by the delivery.
- **Status: fixed in the worker's step.** A sender is answered at most once in ten minutes (`REPLY_WINDOW`), for the sender in the tenant and not for an issue, counted from the time the database wrote the request that was answered. The other toggles are recorded with `reply=suppressed` and post no comment. The bound is rebuilt from the rejection records that say `reply=posted`, so a restart or a second worker keeps the window. The test is `an_unauthorized_sender_who_toggles_the_label_gets_one_reply_in_the_window`, red with four replies before.

### SF-17: two parts of the routing policy have nothing to bind them to yet

- **Scenario.** The routing policy (section "The routing policy").
- **What was seen.** The broker applies one set of per-request caps to every token, so `broker_caps` takes the largest cap of any role, and the smaller cap of a role is not enforced. The router receives a stage, a tier and the runtimes already excluded, and no model of the author of the work, so it cannot choose a reviewer of another family by itself: the reviewing stages list the model of the other family first, and `ModelRoutingPolicy::independent` answers the question for a caller that knows the author.
- **Owner.** `software_architect` (both are port changes: a field on `JobTokenRequest`, a field on `RoutingNeed`).
- **Severity.** Medium for the second, Low for the first. Without the second, a builder that fell back to the model of the first family can be reviewed by a model of the same family when the first candidate of the review is excluded.
- **Smallest change.** Add `author: Option<ModelSelection>` to `RoutingNeed` and make `PolicyModelRouter` drop the candidates the rule of independence refuses. Add the per-request caps to `JobTokenRequest`.

### SF-18: text about the missing routing policy is stale in one place outside the paths of this work package

- **Where.** The module comment of `crates/contracts/src/lib.rs` ("What is not here: `ModelRouter`") says the file does not exist and no schema describes it. Two other texts were updated: the reason for `PortName::Router` in `crates/composition/src/assemble.rs` and the worker README.
- **Owner.** `contracts`.
- **Severity.** Low.
- **Smallest change.** Rewrite that paragraph to point at `policy::routing` and `factory_composition::routing`.

### SF-19: a label in a repository the factory is switched off for leaves only `webhook.accepted`

- **Scenario.** E6, the cases around it.
- **What was seen.** When the repository is registered and not enabled, the API makes no job and leaves no request for a reply, whoever the sender is. The delivery is recorded and audited as `webhook.accepted`. FR-002 speaks of every issue the factory rejects; a repository that is switched off is a different state, and the work package chose to say nothing there. The test `a_label_in_a_repository_that_is_switched_off_leaves_no_request` pins this.
- **Owner.** `product_owner`.
- **Severity.** Low.
- **Smallest change.** Decide whether a switched-off repository should answer. If it should, the same request applies, with another reason code.

## The routing policy

`policies/model_routing.yaml` was added with its loader (`crates/contracts/src/policy/routing.rs`), its typed view and tighten check (`crates/domain/src/policy/routing.rs`), a JSON Schema with twelve examples (`schemas/policy-model-routing.schema.json`), and the pieces the running system uses (`crates/composition/src/routing.rs`: `PolicyModelRouter`, `price_table`, `broker_caps`, `token_request`). Every number in the file is marked as waiting for the project owner. The file holds no key, no token and no address, and a test reads the document with its comments taken off to check it.

**What it says.**

- Three models, taken from the agent manifests and no others: `claude-sonnet-5-5` and `claude-opus-5-5` (provider `anthropic`, runtime `claude-code-cli`, family `claude`, tiers `standard` and `large`) and `gpt-6.1-sol` (provider `openai`, runtime `codex-cli`, family `gpt`, tier `standard`). The loader checks each name and runtime against the manifests.
- Nine roles, one for each agent manifest. Each role lists the models it may use (all three), the model it starts with, the larger model it escalates to after two failed repairs, a ceiling for a run of its stage (dollars and tokens) and a cap for one request (input and output tokens). The dollar ceilings are about half of the limits in the manifests (the token ceiling of the intake role is the manifest's own), and the caps are under the caps of `policies/security.yaml`. The three reviewing roles start with `gpt-6.1-sol`.
- Routes: for each stage that runs an agent, the standard tier lists the models to try in order and the large tier lists `claude-opus-5-5`. The reviewing stages list the model of the other family first. There is no small tier, because the manifests name no small model.
- Three rules of independence: the code reviewer, the documentation reviewer and the specification reviewer must differ in family from the builder, the technical writer and the specification writer. The loader refuses a rule that some author model could never satisfy. When no allowed model is independent, the reviewing stage waits for a person.
- A ceiling for a job: 10 dollars and 1.5 million tokens, under the hard ceiling of 25 dollars in the security policy.
- Prices for the three models in millionths of a dollar for a million tokens, with `price_checked_on: unchecked` and a source note. They are placeholders chosen to be high, so that the broker counts more than a real bill would.
- Tighten only: `check_tighten` lists every place a project policy is looser (a model added, a price lowered, a ceiling or a cap raised, a rule of independence removed or weakened, an earlier escalation).

**How the broker and the router use it.** `price_table` is what `BrokerConfig.prices` should be, so the broker refuses a model without a price. `token_request` gives a job token the models of the stage's routes and the stage's ceiling. Tests drive the real broker core with them: a model that no route lists is refused, the cost ceiling of the policy revokes the token with the reason `CostCeiling` (answer 402), and a dearer model reaches the ceiling sooner because the price is the policy's. `PolicyModelRouter` reads the routes, skips a runtime that was excluded or lacks a capability, and never returns a model outside a route. Nothing in the worker's start-up loads the policy yet.

**What the owner must decide.** Each of these is a number or a choice in the file, and none was confirmed.

1. The prices of each model, read from the providers' price pages, with the date (`price_checked_on`). Until then the placeholders are high and the broker over-counts. The price of `gpt-6.1-sol` has no separate cache write price, and the manifests say its price tier is not confirmed.
2. The ceiling of a run of each stage, in dollars and tokens (section 2 of the file), and the ceiling of a job (section 5). They were chosen low. A real change may need more, and a ceiling that is too low stops a job in the middle and asks a person.
3. The per-request caps of each role. The broker applies the largest one to every token (SF-17).
4. Which model each role starts with, and which it escalates to. The reviewing roles start with `gpt-6.1-sol` so that the first choice is independent of a builder that starts with `claude-sonnet-5-5`. If the provider of one family is not available to the project, the rule of independence cannot be met and the reviews wait for a person.
5. Whether independence by family is the right strength. `provider` is stronger and `model` is weaker; `must_differ_by` says which.
6. Whether the file stays `designed` until a live run passes, and who flips it to `enforced`. The typed view's `unconfirmed()` lists what still waits (the status and each unchecked price), so a production start can refuse a file that is not confirmed. No start-up does that yet.
7. Whether the tier names (`standard`, `large`) map to the models as written. The manifests also call `gpt-6.1-sol` standard on the word of its notes.

## Changes outside the allowed paths

- `apps/api/tests/playbook/mod.rs` has four more lines. A rework round gives the builder one task, `rework-round-N`, that lists every task of the plan for context, and the playbook refused it as naming several tasks. It now maps that task to the entry `builder.rework-round-N`, which a test supplies with `replace`. Without the change E3 cannot run. This is an edit to an existing test file beyond exposing a helper, and it is reported for review.
- The factory has no data file for a rework answer in `fixtures/recordings/playbook/word-count/`. E3 builds its two answers in the test.

Edits of the second run that are not in the paths the work package listed, each small and kept for review:

- `crates/contracts/tests/schema_examples.rs`: the test `schemas_match_the_files_in_the_schemas_directory` compared every `*.schema.json` in `schemas/` with the eleven embedded contract schemas, so a schema for a policy file made it fail. It now leaves out files named `policy-*`, which govern a policy file and not a document that passes between stages. `crates/contracts/tests/model_routing.rs` checks the policy schema against the policy and its examples with the Rust engine.
- `crates/composition/tests/telemetry_allowlist.rs`: three reviewed log fields of the new module (`code`, `error`, `replied`), each with its reason, as the test asks.
- `apps/api/tests/playbook/mod.rs` and `apps/api/tests/e2e/mod.rs`: the script on a reply, `Playbook::compromise` and `HOSTILE_ATTEMPTS`; the recording of subjects, comments, tokens and requests; the read of the commits from the remote.
- `crates/testkit/tests/change_host_records.rs`, `crates/testkit/tests/remote_commit_chain.rs` and `crates/github/tests/fake_host_permissions.rs`: new tests of the fake host and the remote.
- No migration, no `infra/**` file, no other policy and no agent file was touched. The API's database trigger already allowed the action the request uses.

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

Each defect and gap above is small enough for one issue. SF-01 touched a requirement of the specification and is fixed: a live run now shows the behaviour that FR-002 and SC-002 ask for, as far as test mode can show it. The open entries are SF-03, SF-07 and SF-14 to SF-19; SF-17 (two port changes the routing policy needs) is the one to settle before a live run, and the decisions for the owner are listed at the end of the section "The routing policy".
