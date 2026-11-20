# Architecture review of the Slice 0 foundation

- Reviewer: software_architect, acting as an independent reviewer. I wrote none of the code under review and changed none of it.
- Date: 2026-10-27
- Commit reviewed: `c4d7df19a04484926263dee57dd4be74fb9a2313` (`feat/slice-0-foundation`; the worktree was fast-forwarded from `119607d`)
- Authority: `universal_agentic_software_factory_master_prompt.md` (the V6 chapter supersedes), `specs/001-end-to-end-mvp/spec.md`, the ADRs, `docs/architecture/`, `schemas/`.
- Code reviewed: `crates/ports`, `crates/testkit` (without `src/fx/`), `crates/domain`, `crates/contracts`, `xtask`.

## Verdict

**CHANGES_REQUIRED.** Tagging `ports-v1`: **NO-GO**.

The domain model, the schema engine, the YAML reader and the dependency-edge rules do what their documents say, and I could not break them. The port surface is the problem. The Store cannot write what the migrations require (F-01) and has no operation for several tables the specification needs (F-02). Nothing can read back what the sandbox produced or export a diff, so the specification, review and documentation stages cannot be built (F-03). The workspace cannot obtain a repository and cannot be reattached after a restart (F-04). Behind those four blockers are thirteen major findings: a validator that cannot see duplicate keys on the path the engine uses, an ambiguous commit outcome, a router that cannot fall back, a sandbox guard that is a deny list, protected-path rules the policy cannot express, a transition that is not bound to its guard, architecture checks that I bypassed in a scratch copy, and fakes that are easier than PostgreSQL. Every adapter package would be built against these ports, so the changes belong before the tag, not after it.

| Severity | Count |
|---|---|
| blocker | 4 |
| major | 13 |
| minor | 9 |
| note | 5 |
| total | 31 |

In the verdict block at the end, the schema's severity words are used: blocker stays blocker, major becomes high, minor becomes low and note becomes info.

### Index

| Id | Severity | Finding |
|---|---|---|
| F-01 | blocker | The Store write model cannot persist what the migrations require |
| F-02 | blocker | The Store has no operations for requests, deliveries, approvals, lookups, listings and timers |
| F-03 | blocker | Nothing can read back what the sandbox wrote, and no port exports a diff |
| F-04 | blocker | The workspace cannot obtain a repository and cannot survive a worker restart |
| F-05 | major | The output validator port receives an already parsed value, so the strict parser is skipped |
| F-06 | major | Tx::commit cannot report an unknown outcome, and a failed commit may not leave nothing behind |
| F-07 | major | ModelRouter cannot express fallback or probed capabilities |
| F-08 | major | AgentRunError discards usage, transcript and denials of a failed run |
| F-09 | major | The sandbox guard is a deny list, accepts zero limits, and the posture report checks only Hardening |
| F-10 | major | Protected paths: the port cannot express the policy that guards builder changes |
| F-11 | major | A state transition is not bound to the guard that must hold for it |
| F-12 | major | The architecture checks can be bypassed in ways the tests do not cover |
| F-13 | major | The GitHub ports cannot read comments, cannot pin checks to the App, and give webhooks no home |
| F-14 | major | No port writes the job token file, and the engine is not allowed to |
| F-15 | major | Artifact reads are not tenant-scoped by type |
| F-16 | major | Fakes are easier than the systems they stand for, and many contract checks were never shown to fail |
| F-17 | major | FR-023 and SC-008 cannot be met: a non-PASS finding may omit its file and line |
| F-18 | minor | The specification counts eleven stages; the state machine has thirteen, plus MERGE |
| F-19 | minor | Several documents contradict each other or the code |
| F-20 | minor | A stage contract may leave out the retry classes that make crash recovery work |
| F-21 | minor | Hardening cannot say AppArmor is unavailable or IPC is none |
| F-22 | minor | The schema engine ignores `format`, and regex classes follow Unicode rules |
| F-23 | minor | Two xtask tests fail when CARGO_TARGET_DIR is set |
| F-24 | minor | Several invariants have no test that names them |
| F-25 | minor | Several rules are kept by convention, not by type |
| F-26 | minor | Agent output contracts mix fields the engine owns with fields the agent writes |
| F-27 | note | The YAML reader matches the parser contract in the header of security.yaml |
| F-28 | note | The schema engine refuses unknown keywords and its work is bounded |
| F-29 | note | The domain state machines equal state-machine.json and the crate does no I/O |
| F-30 | note | LeaseEpoch::next saturates instead of failing |
| F-31 | note | The edge rules DEP-01, DEP-02, DEP-03 and DEP-08 held against my mutations |

## Findings, ranked

Each finding says how I know. "Verified" means I read the code or ran something, and says which. "Judgment" means I reasoned from the text and could not test it.

## Blocker findings

### F-01 (blocker): The Store write model cannot persist what the migrations require

**Affected:**

- crates/ports/src/store.rs:226-237 (NewJob), 256-267 (NewStageRun), 303-323 (ClaimedWork, NewAttempt), 598-604, 638-652, 691-697
- migrations/2026-10-27-000400_jobs_and_requests/up.sql:10-18
- migrations/2026-10-27-000500_stage_runs_attempts_tasks/up.sql:19, 69, 148, 182-183 and function stage_runs_guard
- docs/database/for-the-storage-crate.md, recipe 'Claim a stage run'

**Evidence status:** Verified by reading both sides. No PostgreSQL adapter exists, so the failure itself was not run.

**What is wrong.**

The port types and the tables disagree in five places.

- `jobs` has NOT NULL columns `repository_id`, `execution_mode`, `autonomy_level` and `pipeline_scope`. `NewJob` holds an id, a correlation id, a requester and a creation time. `Job` cannot return the four columns either, so after a restart the engine cannot learn which repository a job belongs to or whether it runs in production mode (INV-08).
- `stage_runs.run_number` is NOT NULL. `NewStageRun` has no such field.
- A PASSED stage run must carry `gate_outcome` (CHECK `stage_runs_passed_has_outcome`), and a SKIPPED one must carry NOT_APPLICABLE. `transition_stage_run` takes only an `AppliedTransition`, which holds from, event, to, transition id and time. The gate outcome and the gate report hash have no way in.
- `attempts.deadline_at` is NOT NULL, a FAILED attempt needs `failure_class`, and a SUCCEEDED one needs `output_sha256`. `NewAttempt` and `transition_attempt` carry none of these. The domain's retry decision (`decide_after_failure`) is driven by the failure class, and the port drops it.
- The claim protocol differs. The port says `claim_ready` runs in one system transaction, raises the stage run's epoch, leaves the status READY (store.rs:307) and returns a stage-run `Lease`. The migration has no lease columns on `stage_runs`. Its trigger lets `lease_epoch` change only together with READY to RUNNING, and the lease lives on `attempts`. The DBA's tested recipe is two transactions: a system transaction picks a candidate, then a tenant transaction does READY to RUNNING, the epoch increment and the attempt insert.

**Why it matters.** `s1-storage-postgres` has to pass the same contract suite as the in-memory store (slice plan, done check 1). With these types it cannot, because the rows cannot be written. If `ports-v1` is tagged and `s1-engine-core` is built against it, every call site changes later.

**Reproduction or counter-example.** From the types alone: `insert_job(NewJob { .. })` has no value for `repository_id`, so the first insert fails with SQLSTATE 23502. `transition_stage_run(id, v, AppliedTransition::plan(Gating, GatePassed, t)?)` has no way to set `gate_outcome` and fails with 23514 on `stage_runs_passed_has_outcome`.

**Proposed fix.** Add to the port: `NewJob { repository, execution_mode, autonomy_level, pipeline_scope, idempotency_key, webhook_delivery }`; `NewStageRun { run_number, max_attempts, not_before, rework_of }`; a `GateRecord { outcome, report_sha256, contract_sha256 }` argument on the PASSED, SKIPPED and REWORK transitions; an `AttemptEnd { failure_class, output_sha256, sandbox_id, sandbox_leaked }` argument on attempt transitions; and `NewAttempt { deadline, lease_owner, lease_expires_in }`. Move the lease from `StageRun` to `Attempt`. Replace `claim_ready` by the two-step protocol the DBA tested (`find_claim_candidates` in a system transaction, `start_attempt` in a tenant transaction), or change the migration, and record which in an ADR. Change the in-memory store and the contract suite in the same pull request.

**Confidence:** 0.90

### F-02 (blocker): The Store has no operations for requests, deliveries, approvals, lookups, listings and timers

**Affected:**

- crates/ports/src/store.rs:591-883 (every *Ops trait)
- migrations: 000200 (repositories, api_tokens), 000300 (artifacts, webhook_deliveries), 000400:78 (original_requests), 000500:120 and 321 (stage_run_artifacts, task_node_dependencies), 000700:46 (audit_events), 000800 (inbox, approvals)
- docs/architecture/slice-plan.md:696-697 (Store sketch with resolve_token and resolve_installation) and :1427 (done check 14)
- crates/domain/src/machines/guards/stage_run.rs:19-27 (UpstreamFacts.stage_runs: 'every stage run of the job')

**Evidence status:** Verified by reading and by searching the ports crate (no match for original_request, approval, webhook, resolve_token, resolve_installation, list_).

**What is wrong.**

The tables exist and the specification needs them, but no port method touches them.

- Original issue text, kept apart from the normalized request (FR-003): table `original_requests`, no method.
- Webhook delivery record and duplicate suppression (FR-040): table `webhook_deliveries`, no method.
- Operator and approver decisions (FR-029, FR-031): table `approvals`, no method.
- `resolve_token` and `resolve_installation`, which the slice plan sketches on `Store` and the DBA's webhook recipe needs before any tenant is known. The final trait dropped them, yet done check 14 of `s1-storage-postgres` still tests them.
- Listing: nothing lists the stage runs of a job, the attempts of a stage run or the nodes of a plan. The guards `G_UPSTREAM_PASSED`, `G_ANY_STAGE_WAITING`, `G_PIPELINE_SCOPE_COMPLETE` and the attempt window all take "every stage run of the job" as input. `TaskNodeOps` also cannot record dependency edges, so `G_TASK_DEPS_SUCCEEDED` cannot be evaluated.
- Timers: `not_before` (retry back-off), attempt deadlines and the teardown deadline are columns, but the port has no way to set them or to ask for the stage runs and attempts that are due. `expired_leases` covers lease expiry only.
- Consumed and produced artifact hashes per stage run (`stage_run_artifacts`), which ADR 0010 invalidation relies on.
- `AuditEvent` (store.rs:447-460) requires a `job_id`, has no subject, decision or reason, and carries a caller-chosen time. The table requires subject, decision and reason, allows a null job, and says the time is the database's. An issue rejected at intake (FR-002, SC-002) has no job, so its audit record cannot be written through the port.

**Why it matters.** Intake, admission, scheduling, approval and recovery cannot be built on the port as it stands. The engine package would have to invent side doors to the database or reopen the port after the tag.

**Reproduction or counter-example.** `grep -rn "original_request\|approval\|webhook\|resolve_token\|fn list_" crates/ports` returns nothing. The only mention of `resolve_token` is in the slice plan sketch.

**Proposed fix.** Add `RequestOps` (store and read original text with its hash), `DeliveryOps` (record a delivery, report whether it is new), `ApprovalOps`, `LookupOps` (`resolve_token`, `resolve_installation`, outside a transaction, `None` for every miss), listing methods (`stage_runs_of_job`, `attempts_of_stage_run`, `task_nodes_of_job`, `task_dependencies`), timer methods (`schedule_retry(not_before)`, `due_work`), `StageRunArtifactOps`, and a corrected `AuditEvent { job: Option<JobId>, actor, action, subject, decision, reason, policy_hash, correlation_id }` whose time the store assigns. Extend the fake and the contract suite for each.

**Confidence:** 0.90

### F-03 (blocker): Nothing can read back what the sandbox wrote, and no port exports a diff

**Affected:**

- crates/ports/src/workspace.rs:72-110 (IngestedChange holds paths and kinds only), 257-295 (read_base_file and list_base read the base commit only)
- crates/ports/src/spec.rs:132-145 (SpecContext has no WorkspaceProvider and no ArtifactStore)
- crates/testkit/src/spec.rs:49-73 (the fake ignores its context)
- schemas/review-verdict.schema.json (inputs_reviewed.diff_sha256); specs/001-end-to-end-mvp/spec.md FR-010, FR-022, FR-025

**Evidence status:** Verified by reading the ports and the fakes. The workaround described below is my reading of the fake, not something I ran against a real adapter.

**What is wrong.**

A stage that needs the content of what an agent produced has no sanctioned way to get it.

- `Workspace::read_base_file` and `list_base` read the trusted base commit, "never the sandbox-writable tree". `IngestedChange` lists changed paths and kinds, not content.
- The Spec Kit adapter must read `spec.md`, the checklist and the constitution to build a `SpecificationContract` with "the exact artifact hashes" (master prompt section 4, FR-010). Its `SpecContext` carries a `Workspace`, a sandbox session and a runtime. Reading through `exec` and `cat` would store a redacted copy, so the hashes would be wrong, and `SpecContext` carries no `ArtifactStore` to read it back anyway. The `spec_adapter` crate may not read files itself (its clippy.toml bans `std::fs`, and static check ST-09 forbids file reads outside the sandbox crate's ingestion module).
- The reviewer's input includes `diff_sha256` (review-verdict schema) and FR-022 says the reviewer receives "the diff". No port method produces a diff or a patch artifact.
- The only route I can see is: ingest, commit, create a second workspace whose base is the new commit, and call `read_base_file` on it. No document or contract check says a workspace may be created at a commit that another workspace made, and `SpecificationProvider::run` has no `WorkspaceProvider` to do it with.

**Why it matters.** Stage 3 (specification), stage 9 (independent review) and stage 11 (documentation gate) cannot be implemented without it. Three work packages (`s1-spec-adapter-and-stage`, `s1-stage-implementation-and-review`, `s1-stage-documentation`) depend on this surface.

**Reproduction or counter-example.** Search `crates/ports/src/workspace.rs` for a method that returns bytes of a path other than at the base commit: there is none. `FakeSpecificationProvider::run` never touches `ctx.workspace`, so no test exercises the gap.

**Proposed fix.** Add `Workspace::read_changed_file(&IngestedChange, &RepoPath, max_bytes)`, `Workspace::export_patch(&IngestedChange) -> ArtifactRef` (the diff as a stored artifact, with its hash), and `Workspace::read_file_at(&CommitSha, &RepoPath, max_bytes)` for committed content. Put an `&dyn ArtifactStore` in `SpecContext`, or have `SpecificationProvider::run` return the raw files and let the engine store them. Document, and add a contract check for, a second workspace created at a commit made by the first.

**Confidence:** 0.85

### F-04 (blocker): The workspace cannot obtain a repository and cannot survive a worker restart

**Affected:**

- crates/ports/src/workspace.rs:19-30 (WorkspaceRequest), 233-255 (create preconditions), 282-295 (commit, push)
- crates/testkit/src/workspace.rs:523-590 (commit and push; `made` is per instance)
- crates/testkit/src/contracts/workspace.rs (check a_commit_the_workspace_did_not_make_is_not_pushed)
- crates/ports/src/githost.rs:120-130 (DraftPrRequest.base is a branch name)
- docs/adr/0001-orchestration-engine.md, Confirmation for Slice 1; docs/architecture/overview.md QA-8

**Evidence status:** Part 2 verified by running a test against the fake (below). Part 1 is a gap in the ports found by reading; an adapter might hide it with ambient credentials.

**What is wrong.**

Two gaps in the same lifecycle.

1. Acquisition. `create` requires that "the request's repository and base commit exist in the trusted object store". No port fetches the repository. There is a `PushTarget` with a narrowed credential for writing, but no read counterpart, and the adapters may not depend on each other, so the sandbox crate cannot ask the GitHub crate for a token. No port resolves a branch to a commit either: `WorkspaceRequest.base` is a `CommitSha`, while `IssueSource` and `ChangeHost` return only branch protection booleans. Stage 2 (repository intelligence) cannot start.
2. Durability. A `Workspace` is an in-memory `Box<dyn Workspace>` with no identifier and no way to reattach. `push` refuses any commit "this workspace" did not make, and the contract suite checks that refusal. The implementation commit, the documentation commit and the push happen in different stages, with reviews and possible human waits between them. After a worker restart the delivery stage cannot push.

**Why it matters.** ADR 0001's Slice 1 confirmation is "an end-to-end run that restarts the worker between stages and finishes". With this port the run cannot finish after a restart between DOCUMENTING and DELIVERY.

**Reproduction or counter-example.** Scratch test `scratchpad/exp/tests/workspace.rs`: create a workspace, write a file, `ingest`, `commit`, drop the workspace, create a second workspace whose base is that commit (accepted), then `push` the commit from the second workspace. Result: `Err(Git("the commit was not made by this workspace"))`. In the fake, `made` is a per-instance set.

**Proposed fix.** Give `WorkspaceProvider` a `WorkspaceId`, `open(job) -> Box<dyn Workspace>` to reattach, and a `fetch(repo, FetchTarget)` operation where `FetchTarget` is a narrowed read credential issued by `ChangeHost` (mirror of `push_target`). Add `ChangeHost::resolve_branch(scope, branch) -> CommitSha`. Define `push` as "pushes a commit that exists in this job's object store", and add contract checks for push after reattach and for a commit made by an earlier workspace.

**Confidence:** 0.80

## Major findings

### F-05 (major): The output validator port receives an already parsed value, so the strict parser is skipped

**Affected:**

- crates/ports/src/registry.rs:182-200 (OutputValidator::validate takes &serde_json::Value)
- crates/ports/src/agent.rs:326-339 (AgentRunOutcome.output is a serde_json::Value)
- crates/contracts/src/validator.rs:235-262 (parse_and_validate, the strict path, is not on the port)

**Evidence status:** Verified by running an experiment (below).

**What is wrong.**

The trait documentation promises "Size and depth limits apply before any parse that could exhaust memory". The signature cannot keep that promise, because the argument is a `Value` that somebody has already parsed. `AgentRunOutcome.output` is also a `Value`, so the runtime adapter parses the tool's output with `serde_json` before any limit applies. The strict path (size, UTF-8, depth scan, duplicate-key refusal, node budget) exists in `SchemaOutputValidator::parse_and_validate`, but the engine reaches the validator only through the port.

**Why it matters.** Agent output is untrusted. A duplicate key is the standard way to make two parsers disagree: serde_json keeps the last value, while other parsers keep the first or refuse. The stored artifact bytes and the validated `Value` can then mean different things.

**Reproduction or counter-example.** With the real validator: `parse_and_validate(ReviewVerdict, 1, br#"{"schema_version":1,"verdict":"BLOCK","verdict":"PASS"}"#)` is refused ("the object repeats the key `verdict`"). The same bytes parsed into a `serde_json::Value` first give `verdict = "PASS"`, and that is the value the port would then validate. Scratch test: `scratchpad/exp/tests/validator.rs`.

**Proposed fix.** Change `AgentRunOutcome` to return the raw output as bytes (or an `ArtifactRef` plus size), and add `OutputValidator::validate_bytes(kind, version, &[u8]) -> Result<Value, Vec<Violation>>`. Keep `validate(&Value)` only for values the factory built itself. Add a contract check with a duplicate key and an oversize body.

**Confidence:** 0.90

### F-06 (major): Tx::commit cannot report an unknown outcome, and a failed commit may not leave nothing behind

**Affected:**

- crates/ports/src/store.rs:540-543 (Tx errors and postconditions), 464-493 (StoreError), 590-605 (insert_job is not idempotent)

**Evidence status:** Judgment from the port text and from how PostgreSQL clients behave. No adapter exists to test.

**What is wrong.**

`Tx` documents: "`commit` returns Conflict when another transaction committed a change... and Unavailable when the database is gone. A failed commit leaves nothing behind." If the connection drops after the server applied COMMIT and before the client saw the reply, the call fails with `Unavailable` and the transaction is committed. The port has no variant for "outcome unknown". The insert methods are not idempotent (a second insert with the same id is `Constraint`), so the engine cannot tell its own earlier insert from a duplicate.

**Why it matters.** This is the crash-recovery case the project cares about (QA-2, QA-8). The engine will either repeat a decision that was already recorded or give up on one that was not.

**Reproduction or counter-example.** Reasoning only. The contract check `a_failed_commit_leaves_nothing_behind` exercises `Conflict`, which cannot show the other case.

**Proposed fix.** Add `StoreError::CommitOutcomeUnknown`. State that after it the caller reads the aggregate versions again before acting. Make the `insert_*` methods return the existing row when the id and the content match (idempotent by id), or add `get_or_insert`. Add a fake lever that applies the commit and then fails, and a contract check for the reconcile path.

**Confidence:** 0.80

### F-07 (major): ModelRouter cannot express fallback or probed capabilities

**Affected:**

- crates/ports/src/agent.rs:440-491 (RoutingNeed, ModelRouter::route)
- crates/testkit/src/contracts/router.rs (check the_same_need_always_gets_the_same_decision)
- docs/adr/0005-agent-runtime-adapter-boundary.md, 'Prompts, output and budgets'; master prompt section 2, principle 10

**Evidence status:** Verified by reading the trait, its postcondition and the contract check.

**What is wrong.**

The trait requires "the same need always gets the same decision", and `RoutingNeed` has no field for runtimes that already failed or for an attempt number. ADR 0005 says "the engine may retry on another runtime"; the master prompt asks for fallback across providers. With this signature the second call returns the first runtime again. `RoutingNeed.required` lists capabilities, but the router is "a pure function of the routing policy", so it has no probe result to compare them with. `RoutingError::CapabilityUnavailable` can only mean "the policy file says so", not "the probe found it missing".

**Why it matters.** Provider outage handling is a stated requirement and an acceptance test in section 16 of the master prompt.

**Reproduction or counter-example.** Reading. The contract check asserts ten identical answers for one need.

**Proposed fix.** Add `exclude: Vec<RuntimeId>` and the probed `RuntimeCapabilities` (or a map of them) to the input of `route`, and keep determinism as "same need and same exclusions give the same decision". Add a check that excluding the first answer yields a different runtime, or `NoRoute`.

**Confidence:** 0.85

### F-08 (major): AgentRunError discards usage, transcript and denials of a failed run

**Affected:**

- crates/ports/src/agent.rs:326-362 (AgentRunOutcome carries usage and transcript; AgentRunError carries neither)

**Evidence status:** Verified by reading.

**What is wrong.**

Only a successful run returns `usage`, `transcript` and `permission_denials`. Timeout, ProcessFailed, OutputMissing, Cancelled and BudgetRefused return none of them. The failed attempt is exactly the one that needs evidence (V6: each stage keeps evidence for its claims, and failures never silently convert to success) and the one that may have cost money.

**Why it matters.** Budget accounting and the audit trail have a hole where the expensive failures are. `ModelBroker::usage` can recover the spend, but not the transcript or the denials.

**Reproduction or counter-example.** Reading.

**Proposed fix.** Make the error `AgentRunFailure { error: AgentRunError, partial: PartialRun { usage, transcript: Option<ArtifactRef>, denials } }`, or return `Result<AgentRunReport, ...>` where the report always has these fields and an `outcome`. Extend the agent contract suite to check them.

**Confidence:** 0.85

### F-09 (major): The sandbox guard is a deny list, accepts zero limits, and the posture report checks only Hardening

**Affected:**

- crates/ports/src/sandbox.rs:491-506 (check_mounts), 536-557 (check_limits), 593-602 (PostureReport), 312-337 (SandboxSpec)
- policies/security.yaml:694-707 (forbidden_mount_sources), 733-751 (profiles; verify mounts the source tree read-only and holdouts read-only)

**Evidence status:** Verified by running an experiment against the real `SandboxSpec::validate`. Docker's treatment of zero is from my knowledge of the Docker Engine, which I did not run.

**What is wrong.**

`validate` refuses a list of known-bad sources and accepts everything else. A test in the same file is named `a_mount_next_to_a_forbidden_source_is_not_refused`. The limit check is "not above the maximum" only. The posture check compares `Hardening` and nothing else, so the engine cannot see whether the created container has the memory, pids, network, mounts, environment and image the spec asked for, which is what ADR 0003 promises ("verify posture by `docker inspect` against policy").

The specification cannot express the `verify` profile in `policies/security.yaml`: source tree read-only, holdout tests mounted read-only (`holdouts_mounted: true`).

**Why it matters.** The policy file is the security baseline and `validate` is the port-level guard that every adapter and the fake share. A guard that accepts arbitrary mounts and zero limits is not the "nothing weaker than the policy" the ADR describes.

**Reproduction or counter-example.** With the forbidden list copied from `policies/security.yaml` (lines 694-704), these all returned `Ok(())` from `SandboxSpec::validate`: an extra mount whose source is `/run`, `/run/containerd/containerd.sock`, `/srv/../run/docker.sock`, `//var/run/docker.sock` or `/Users/me`; limits with `cpu_millis`, `memory_mb`, `memory_swap_mb`, `pids` and `wall_clock` all zero; `memory_swap_mb` of 100 with `memory_mb` of 512. `/var/run/docker.sock/` was refused only because of the trailing slash. As far as I know Docker treats 0 as "no limit" for memory, cpus and pids. Scratch test: `scratchpad/exp/tests/ports.rs`.

**Proposed fix.** Make mounts an allowlist: the only legal extras are the supervisor's own named mounts, as typed variants (`ProtectedOverlay`, `HoldoutReadOnly`, `GitMask`) rather than free strings. Reject zero and `memory_swap_mb < memory_mb`. Normalize any remaining path (no `..`, no double slash, no trailing slash) before comparing. Add `limits`, `network`, `mounts`, `env` and `image` to `PostureReport` and compare them. Add a read-only workspace flag and a holdout mount to `WorkspaceMounts` for the verify profile.

**Confidence:** 0.90

### F-10 (major): Protected paths: the port cannot express the policy that guards builder changes

**Affected:**

- crates/ports/src/workspace.rs:19-30 (WorkspaceRequest.hidden and .protected are plain glob lists)
- crates/ports/src/paths.rs:120-175 (RepoGlob is case sensitive, no negation, no NFC), 78-101 (RepoPath checks `.git` as an ASCII case-insensitive component only)
- policies/security.yaml:44-60 (matching), 90-110 (modes), 212-264 (append_only, additions_only, hidden, a `!` re-inclusion)

**Evidence status:** Verified by running an experiment for case and `.git` variants. The mode gap is verified by reading.

**What is wrong.**

The policy defines five modes (`hidden`, `deny_write`, `append_only`, `additions_only`, `sensitive`), NFC normalization, case-insensitive matching ("so that `.GitHub/Workflows` cannot dodge `.github/**`") and a `!` re-inclusion. The port has two lists. Any change to a path in `protected` is refused. Consequences:

- `tests/**` is `additions_only` in the policy: builders must be able to add tests (master prompt section 7, FR-018). With one protected mode the choice is to protect tests, which blocks every added test, or not to protect them.
- `RepoGlob::new(".github/**").matches(".GITHUB/workflows/ci.yml")` is false. On a case-insensitive host filesystem both names are the same directory.
- `RepoGlob` treats `!` literally, so `!.env.example` matches nothing.
- `RepoPath::new` accepts `.g\u{200c}it/config`, `.git./config`, `GIT~1/config` and `.git /config`. Git has dedicated checks for the Unicode-ignorable and 8.3 forms (`core.protectHFS`, `core.protectNTFS`), which shows they are real attack forms.

**Why it matters.** Protected-path enforcement is the main control behind SC-006. It runs on a diff that the port cannot describe in the policy's terms.

**Reproduction or counter-example.** Scratch test `scratchpad/exp/tests/ports.rs`, test `glob_is_case_sensitive`: output `.github/workflows/ci.yml: true`, `.GITHUB/workflows/ci.yml: false`, and `Ok(RepoPath(...))` for the four `.git` variants.

**Proposed fix.** Replace `protected: Vec<RepoGlob>` by `Vec<ProtectedPath { glob, mode }>` using the policy's mode names, and add `RepoGlob::matches_folded` (NFC plus case folding) used by every adapter. Support re-inclusion explicitly (`include` and `exclude` lists). Reject the Unicode-ignorable and 8.3 forms of `.git` in `RepoPath::new`. Add contract checks for a case variant, an added test file under an `additions_only` glob, and an edited test file.

**Confidence:** 0.85

### F-11 (major): A state transition is not bound to the guard that must hold for it

**Affected:**

- crates/ports/src/store.rs:165-224 (AppliedTransition::plan)
- crates/domain/src/machines/guards.rs:420-480 (evaluate returns Result<(), GuardError>)
- crates/domain/src/state/mod.rs:93-105 (Status::transition)

**Evidence status:** Verified by reading. The consequence is a design judgment.

**What is wrong.**

`AppliedTransition::plan(from, event, at)` consults the transition table and drops the row's guard. `guards::evaluate` returns `Ok(())`, with no value that proves which guard held on which facts. Facts are booleans supplied by the caller (`decision_is_pass_and_persisted`, `lease_compare_and_swap_succeeded`). So `GATING -> PASSED` can be planned and stored without any guard having run, and the store cannot tell. INV-03 ("PASSED only when the gate decision and its evidence are persisted") and FR-032 ("only a verified gate decision advances a stage") depend on the engine author's discipline. The contract suite itself moves a stage run to READY with no guard.

**Why it matters.** The principle "deterministic shell" is only as strong as the type that stops a caller from skipping it. This is cheap to fix before adapters exist and expensive after.

**Reproduction or counter-example.** `AppliedTransition::plan(StageRunStatus::Gating, StageRunEvent::GatePassed, now)` compiles and succeeds with no guard in sight.

**Proposed fix.** Make `evaluate` return a `GuardCleared<G>` token (private constructor, carries the guard name and a digest of the facts) and make `AppliedTransition::plan` take it, checking that the token's guard equals the table row's guard. Put the token's digest in the ledger entry for the transition. Keep the booleans, but make the engine build them in one place that tests can attack.

**Confidence:** 0.70

### F-12 (major): The architecture checks can be bypassed in ways the tests do not cover

**Affected:**

- crates/domain/clippy.toml, crates/ports/clippy.toml, crates/workflow/clippy.toml, crates/spec_adapter/clippy.toml (identical ban lists)
- xtask/src/static_checks.rs:200-290 (process_spawning, spawn_calls), xtask/src/scan.rs:299-360 (production_sources, collect_rust_files, is_test_file_name)
- xtask/src/topology.rs:307 (external_crates_and_features returns early for adapters)
- crates/domain/Cargo.toml comments on `time` and `uuid`; docs/adr/0011-canonical-time-and-numbers.md (table row on the clippy ban on now_utc); docs/adr/0002 (uuid generators 'not yet tried')

**Evidence status:** Verified by running mutations in a scratch copy (`scratchpad/copy`). Controls: a direct `Command::new("sh")` and a peer-adapter dependency were caught.

**What is wrong.**

DEP-01, DEP-02, DEP-03 and DEP-08 (the edge rules) held against my attempts. The rules built on lists and text scans did not.

1. **DEP-05 ban list.** The four inner crates ban `std::fs::*` functions, the `File`, `OpenOptions`, `TcpStream`, `TcpListener`, `UdpSocket` and `process::Command` types, and three clock calls. They do not ban the `Path` and `PathBuf` methods (`exists`, `is_file`, `read_dir`, `metadata`, `canonicalize`), `std::env`, Unix sockets, `tokio::time`, `time::OffsetDateTime::now_utc`, `uuid::Uuid::now_v7` or `new_v4`. ADR 0011 says a clippy ban on `now_utc` exists. It does not. In my copy, `factory-domain` called `Path::exists()`, `Path::read_dir()`, `std::env::var()` and `UnixStream::connect()`, and both `cargo xtask check-architecture` and `cargo clippy --workspace --all-targets -- -D warnings` (the CI command) passed.
2. **Feature unification.** The `domain` manifest says it "has no way to call `now_utc`" because `time/std` is off. That holds only while no other workspace member enables it. When I enabled `time/std` in the (empty) `storage` crate, `OffsetDateTime::now_utc()` compiled inside `factory-domain` and both checks passed. The planned `s1-xtask-extensions` item 4 checks the features `domain` itself declares, which would not see this.
3. **Allow attributes.** `#[allow(clippy::disallowed_methods)]` over `std::fs::read` in `factory-domain` passed clippy. Nothing in xtask looks for `allow` or `expect` on the DEP-05 lints.
4. **Spawn scan.** `use std::process::Command as Cmd; Cmd::new("sh")` in the `runtime` crate passed ST-03. A module file named `webhook_tests.rs` in the `github` crate, declared with a plain `mod` (no `cfg(test)`), containing `Command::new("sh")`, passed too, because `production_sources` skips any file named `*_tests.rs` or `tests.rs` and any directory named `tests`, `benches` or `examples` under `src`.
5. **Adapters.** DEP-04 does not apply to adapter crates, so an adapter may add any process-spawning or HTTP crate. The rules file lists `external_allow` for them, which reads as if it were enforced. This one is planned (`s1-xtask-extensions`) and the check itself says so.

**Why it matters.** ADR 0002 says the dependency rule must "fail the build when broken". The boundary that matters most for this project is the one that keeps untrusted code and host effects out of inner rings.

**Reproduction or counter-example.** Mutations are in `scratchpad/copy` (not in the repository). Commands: `cargo run --manifest-path scratchpad/copy/xtask/Cargo.toml -- check-architecture` and `cargo clippy --workspace --all-targets -- -D warnings` in that copy. Control: adding a direct `std::process::Command::new("sh")` to `runtime` gives `error[ST-03]` at that line only.

**Proposed fix.** Extend the generated ban list with the `Path` methods, `std::env::{var, vars, set_var}`, `std::os::unix::net::*`, `tokio::time::{sleep, Instant::now, timeout}`, `time::OffsetDateTime::{now_utc, now_local}`, `uuid::Uuid::{now_v7, new_v4}`. Read the resolved feature set from `cargo metadata --format-version 1` (`resolve.nodes[].features`) for `time`, `uuid` and `tokio` and compare with the allow list. Fail the check on `allow`/`expect` of the DEP-05 lints in inner crates. In the spawn scan, resolve `use ... as` aliases, and scan every file that the crate's module tree includes, deciding "test" only from `#[cfg(test)]`. Add a failing fixture for each of these.

**Confidence:** 0.90

### F-13 (major): The GitHub ports cannot read comments, cannot pin checks to the App, and give webhooks no home

**Affected:**

- crates/ports/src/githost.rs:264-311 (IssueSource), 312-370 (ChangeHost), 197-210 (StatusRequest)
- specs/001-end-to-end-mvp/spec.md FR-029, FR-040; docs/architecture/slice-plan.md, packages s1-github-adapter and s1-stage-delivery-and-approval

**Evidence status:** The comment and webhook gaps are verified by reading. The check-run point is my understanding of GitHub and I did not check it against current GitHub documentation.

**What is wrong.**

- Operator decisions arrive as pull request comments (FR-029). `IssueSource` says a webhook payload is "only a hint" and everything is fetched live. There is no method that fetches a comment and its author, so a comment command cannot be authorized under the port's own rule.
- `ProtectionReport.required_checks_pinned_to_app` requires checks pinned to the App. As far as I know GitHub can pin a required check to an App for check runs, and commit statuses carry no App identity. `ChangeHost::set_status` is the commit status API (`Pending/Success/Failure/Error`). If that is right, the port cannot satisfy the condition it demands.
- Webhook signature verification and delivery de-duplication are listed in the `github` crate responsibilities, but no port gives the `api` binary a typed way to call them, and the de-duplication needs `webhook_deliveries` (F-02).
- No method can mark a pull request ready for review, although the plan has negative test NT-MRG-08 ("marking ready is refused before gates finish"). That test has nothing to refuse.

**Why it matters.** FR-029 is a requirement of the first slice, and user story 9, scenario 3 tests it.

**Reproduction or counter-example.** Search `crates/ports/src/githost.rs` for a method that returns a comment: only `post_comment` exists.

**Proposed fix.** Add `IssueSource::fetch_comment(scope, CommentRef) -> Comment { author, body, created_at }`. Decide check runs versus statuses and change `ChangeHost` and `ProtectionReport` to match (an ADR). Add a `WebhookVerifier` port (`verify(raw_body, headers) -> VerifiedDelivery`) implemented in the `github` crate, so the API depends on a port. Either add `mark_ready_for_review` with the refusal rule or drop NT-MRG-08.

**Confidence:** 0.70

### F-14 (major): No port writes the job token file, and the engine is not allowed to

**Affected:**

- crates/ports/src/sandbox.rs:119-125 (JobTokenFile holds only a host path), 329-330
- crates/ports/src/agent.rs:222-245 (JobTokenSecret), 513-522 (IssuedJobToken)
- crates/workflow/clippy.toml (bans std::fs writes); docs/adr/0005 ('a read-only file on a worker-side tmpfs')

**Evidence status:** Verified by reading.

**What is wrong.**

`ModelBroker::issue` returns the secret in memory. `SandboxSpec.job_token` must name a file that already exists on the host. The engine (`workflow`) cannot create it: its clippy configuration bans `std::fs` writes and file creation. The sandbox adapter receives only a path. No port moves the secret from the broker to the file.

**Why it matters.** This is the credential path of every agent run. Left open, the first implementer will put a file write into the engine and remove the ban, or write the secret from the composition root.

**Reproduction or counter-example.** Reading. No code outside tests calls `JobTokenSecret::expose` yet, so the gap has not been hit.

**Proposed fix.** Let `JobTokenFile` carry the `JobTokenSecret` instead of a path, and have `SandboxProvider::create_verified` materialize it on a tmpfs it controls and remove it at teardown. Add a contract check that the file is absent after `stop_and_remove` and never appears in `Debug` output.

**Confidence:** 0.80

### F-15 (major): Artifact reads are not tenant-scoped by type

**Affected:**

- crates/ports/src/artifact.rs:94-129 (ArtifactStore::get and exists take only an ArtifactRef)
- docs/adr/0008-artifact-store-and-evidence-ledger.md ('access always goes through the tenant's metadata row')
- docs/adr/0007-persistence-access-and-tenancy.md (rule 4: 'a query that forgets the tenant does not compile')

**Evidence status:** Verified by reading. The exposure is design-level; no adapter exists.

**What is wrong.**

ADR 0007 makes tenancy a type error for the `Store`. ADR 0008 lets blobs be shared by hash across tenants and relies on the caller to check the tenant's index row first ("Callers check the tenant's index row first"). `get` and `exists` accept any `ArtifactRef`. Anyone holding a hash can read the blob, and `exists` is an oracle for "does anyone hold this exact content", which is what the ADR says must not leak.

**Why it matters.** The master prompt requires a tenant-aware data model and authorization. A convention that every one of eleven or more call sites must remember is the pattern the Store design was built to avoid.

**Reproduction or counter-example.** Reading.

**Proposed fix.** Make reads take a proof of the index check, for example `ArtifactStore::get(&self, scope: &TenantScope, r: &ArtifactRef)` implemented as a join with the index, or move reads into `ArtifactIndexOps::read_artifact(sha) -> bytes`. Add a contract check in which tenant B cannot read tenant A's blob and `exists` returns false.

**Confidence:** 0.75

### F-16 (major): Fakes are easier than the systems they stand for, and many contract checks were never shown to fail

**Affected:**

- crates/testkit/src/store.rs:672-731 (claim_ready), 775-820 (insert_attempt), 896-926 (insert_task_node), 1108-1120 (read_audit)
- crates/testkit/src/githost.rs:202-239 (open_draft_pull_request)
- crates/testkit/src/spec.rs (whole file); crates/testkit/src/sandbox.rs:178-228 (create_verified)
- crates/testkit/src/contracts/mod.rs; crates/testkit/tests/*.rs (defect tables)
- crates/ports/tests/trait_docs.rs

**Evidence status:** The store counter-examples and the two surviving mutants were run. The rest is verified by reading.

**What is wrong.**

**Behavior the fakes get wrong (the real systems would not):**

- `InMemoryStore::claim_ready` hands out stage runs of a job that is `RECEIVED`, not `ACTIVE` (it never reads the job). The migration's claim joins `jobs.status = 'ACTIVE'`, and state-machine.md says a pause "stops new leases". The contract world never activates its jobs, so the suite encodes the weaker rule.
- `insert_attempt` accepts a second live attempt for one stage run. The migration has a unique index `attempts_one_active_per_stage_run`. The port does not mention the rule.
- `claim_ready` orders by `created_at`; the table orders by `not_before`, which the port cannot set.
- `FakeChangeHost::open_draft_pull_request` succeeds for a head branch that was never pushed, ignores `base`, and returns the first pull request for the same head even if it was closed. GitHub rejects an unpushed head.
- `FakeSandbox` can drift only the `privileged` field in a posture check. It cannot drift limits, network or mounts, because the port does not report them (F-09).
- `FakeSpecificationProvider` plays back a queue and ignores its context. There is no contract suite for `SpecificationProvider`, so the most complex adapter in the plan has no shared test, contrary to the `ports` crate documentation ("every adapter must pass the same shared contract suite as its in-memory fake"). The same is true of `Clock`, `IdGenerator`, `CancelSignal` and `OutputValidator`.

**Checks that cannot fail, or were never shown to:**

- I mutated the fake store in a scratch copy. Removing the documented rule "a key already used in the job is a Constraint error" (store.rs:709-710) left the whole store suite green. Making `read_audit` ignore its `limit` also left it green.
- The defect tables in `crates/testkit/tests` name the checks that must fail for each seeded defect. By string search, 65 of 132 contract checks (store 34 of 45, workspace 9 of 19, sandbox 4 of 15, registry 4 of 8, artifact 4 of 9, broker 4 of 10, agent 3 of 10, change host 3 of 12, router 0 of 4) are never named. A check that no seeded defect fails may still be useful, but nobody has shown that it can fail.
- `trait_docs_state_the_contract` checks that four headings exist and are not empty. It does not check that the claims are true (see F-05 and F-06).

**Why it matters.** The fakes are what the engine will be tested against for the next two slices. A fake that is easier than PostgreSQL moves the failure to the end-to-end run.

**Reproduction or counter-example.** `scratchpad/exp/tests/store.rs` prints `claim_ready handed out 1 stage run(s)` for a job in `Received`, then `ok = true` twice for two live attempts. Mutations: `scratchpad/copy/crates/testkit/src/store.rs`; `cargo test -p factory-testkit --test store_contract` in the copy still reports `4 passed`.

**Proposed fix.** Add the job-ACTIVE and one-live-attempt rules to the port documentation, the fake and the suite. Add checks for the duplicate task key and the audit limit. Add a `SpecificationProvider` suite and make the fake run a minimal scripted tool inside the fake sandbox. Make the fake change host track pushes. Add a `cargo xtask` or test step that mutates each fake rule in turn (or lists the checks missing from the defect tables) and fails on survivors.

**Confidence:** 0.90

### F-17 (major): FR-023 and SC-008 cannot be met: a non-PASS finding may omit its file and line

**Affected:**

- schemas/review-verdict.schema.json:81-88 (`location` is optional; `line_start` is optional inside it)
- crates/domain/src/contracts/review_verdict.rs:193, 225
- specs/001-end-to-end-mvp/spec.md FR-023 and SC-008; schemas/examples/review-verdict/invalid (no example for this rule)

**Evidence status:** Verified by running (`scratchpad/exp/tests/claims.rs`) and by reading the schema, the domain type and the invalid examples.

**What is wrong.**

FR-023: "each finding MUST cite a file and line". SC-008: "every non-pass finding cites a file and line that exists in the diff". The schema allows a CHANGES_REQUIRED, BLOCK or NEEDS_HUMAN verdict whose findings have no `location`. The domain type mirrors the schema. There is no invalid example. "Exists in the diff" also needs the diff (F-03).

**Why it matters.** An acceptance criterion with no enforcing check will be reported as met by the end-to-end test that only checks the schema.

**Reproduction or counter-example.** Take `schemas/examples/review-verdict/valid/changes-required-missing-test.json` (verdict CHANGES_REQUIRED), delete the `location` object, and pass it to `SchemaOutputValidator::check`: it validates.

**Proposed fix.** Add an `if verdict != PASS then every finding requires location with path and line_start` rule to the schema, an invalid example, and a domain rule. Add a gate step that checks `location` against the exported patch once F-03 is fixed.

**Confidence:** 0.90

## Minor findings

### F-18 (minor): The specification counts eleven stages; the state machine has thirteen, plus MERGE

**Affected:**

- specs/001-end-to-end-mvp/spec.md:38 and :312 ('all eleven stages')
- docs/architecture/state-machine.md (pipeline table, 14 stage kinds)
- migrations/2026-10-27-000400_jobs_and_requests/up.sql:18 (pipeline_scope up to 14)

**Evidence status:** Verified by reading.

**What is wrong.**

US1 acceptance scenario 1 and SC-001 require "all eleven stages in order". The machine has `INTAKE` to `APPROVAL`, which is thirteen kinds (domain discovery and the separate architecture and planning stages are the extras), and a fourteenth, `MERGE`, outside Slice 1. ADR 0001 says "about a dozen". The end-to-end test needs one number.

**Why it matters.** SC-001 is the headline acceptance test.

**Reproduction or counter-example.** Count the rows of the pipeline table in state-machine.md.

**Proposed fix.** Edit the specification (or its clarifications) to name the thirteen stages, or record which two the eleven merge. Make the end-to-end assertion read the stage list from `state-machine.json`.

**Confidence:** 0.95

### F-19 (minor): Several documents contradict each other or the code

**Affected:**

- crates/ports/src/store.rs:645-646 and migrations/2026-10-27-000500_stage_runs_attempts_tasks/up.sql:6 ('FOR UPDATE SKIP LOCKED')
- docs/architecture/state-machine.md:3 ('conformance tests fail until it lands')
- docs/adr/0011-canonical-time-and-numbers.md (clippy ban on now_utc); docs/adr/0002 (uuid generators 'not yet tried')
- docs/architecture/crate-dependency-rules.json (ports.responsibility lists 12 of the 18 ports)
- crates/ports/src/githost.rs:296-297 ('posted at most once per idempotency key') versus docs/adr/0004-event-model.md
- crates/contracts/src/yaml/mod.rs and policies/security.yaml:15 ('block style')

**Evidence status:** Verified by reading. The conformance tests pass today.

**What is wrong.**

- ADR 0001, 0007 and 0012 chose `FOR NO KEY UPDATE SKIP LOCKED`; the port documentation and the migration header still say `FOR UPDATE`.
- state-machine.md says the domain implements the version before the ADR 0010 revision and the conformance tests fail; they pass (22 of 22).
- ADR 0011 lists a clippy ban on `now_utc`; the files have none (F-12). ADR 0002 says the uuid generators belong on the list; they are not there.
- The rules file describes the `ports` crate as holding twelve traits; there are eighteen.
- `post_comment` is documented as "at most once per key". ADR 0004 says external effects are at least once and "no document may claim otherwise". GitHub has no idempotency key, so the adapter can only reduce duplicates.
- The policy header says "block style"; the policy files use flow style. The reader accepts both and says so in its own documentation.

**Why it matters.** Implementers read these documents literally.

**Reproduction or counter-example.** Reading.

**Proposed fix.** Correct each statement or the code it describes.

**Confidence:** 0.95

### F-20 (minor): A stage contract may leave out the retry classes that make crash recovery work

**Affected:**

- schemas/stage-contract.schema.json:772-786 (`retry_on` has no minItems and no required members)
- crates/domain/src/machines/retry.rs (decide_after_failure: a class not in retry_on fails the stage run)

**Evidence status:** Verified by running (`scratchpad/exp/tests/claims.rs`) and by reading.

**What is wrong.**

`retry_on` may be empty or omit `LEASE_LOST` and `TIMED_OUT`. If it omits `LEASE_LOST`, a worker crash ends in `S06` (FAILED), then `G_UNRECOVERABLE`, then a failed job. The master prompt requires recovery after a process crash.

**Why it matters.** Recovery should not depend on every stage contract author remembering two values.

**Reproduction or counter-example.** Take `schemas/examples/stage-contract/valid/specification-stage.json`, set `retry_on` to `[]`, and pass it to `SchemaOutputValidator::check`: it validates.

**Proposed fix.** Require `LEASE_LOST` and `TIMED_OUT` in `retry_on` (schema `contains`), or treat them as always retryable in `decide_after_failure`.

**Confidence:** 0.85

### F-21 (minor): Hardening cannot say AppArmor is unavailable or IPC is none

**Affected:**

- crates/ports/src/sandbox.rs:168-183 (Confinement, Namespace)
- policies/security.yaml:667-680 (apparmor 'inactive on Docker Desktop', ipc_mode none or private)

**Evidence status:** Judgment. I did not run Docker.

**What is wrong.**

The policy accepts AppArmor as "runtime default or stricter where available" and notes it is inactive on Docker Desktop, the development target. `Hardening.apparmor` is `RuntimeDefault` or `Unconfined`, and `differences` compares the requested and observed values exactly. On a daemon without AppArmor the adapter must either report `RuntimeDefault` falsely or fail every posture check. IPC `none` has no value in `Namespace`.

**Why it matters.** The first real adapter will hit this on the developer machine.

**Reproduction or counter-example.** Reading.

**Proposed fix.** Add `Confinement::NotAvailable` (allowed only where the policy says so, with the reason recorded), and `Namespace::None` for IPC.

**Confidence:** 0.60

### F-22 (minor): The schema engine ignores `format`, and regex classes follow Unicode rules

**Affected:**

- crates/contracts/src/schema_engine.rs:1-60 (documented behavior)
- schemas/evidence-ledger-entry.schema.json:559 (`format: uri` on `source.url`)

**Evidence status:** Verified by running (`scratchpad/exp/tests/claims.rs`) and by reading. The engine documents the `format` choice.

**What is wrong.**

Everything else the schemas use is applied: the engine refuses an unknown keyword when it compiles a schema, and I found no keyword in use that it ignores. `format` is an annotation, so `source.url` accepts any string. Patterns run on the Rust `regex` crate where `\d`, `\s` and `\S` are Unicode-aware (ECMA-262 `\d` is ASCII). The schemas use `\S` and `\s` for trimmed text and the title-prefix rule.

**Why it matters.** A `source.url` such as `javascript:...` lands in the ledger and later in a pull request body.

**Reproduction or counter-example.** Compile `{"type":"string","format":"uri"}` with `Schema::compile_text` and validate the string `not a uri at all`: zero violations.

**Proposed fix.** Add a `pattern` for `url` (scheme `https`), or implement `format: uri` in the engine. Write `[0-9]` where the intent is ASCII digits (already the case for timestamps).

**Confidence:** 0.90

### F-23 (minor): Two xtask tests fail when CARGO_TARGET_DIR is set

**Affected:**

- xtask/tests/clippy_bans.rs:64-75 (the scratch crates inherit the caller's environment)

**Evidence status:** Verified by running.

**What is wrong.**

`every_ban_fires_under_the_clippy_toml_each_inner_crate_actually_has` and `every_ban_in_the_rendered_file_fires_in_a_scratch_crate` fail with "these bans did not fire" when `CARGO_TARGET_DIR` points at a shared directory, because clippy reuses a cached result for the scratch crates. With the variable unset, all 15 tests of that binary pass.

**Why it matters.** A developer or CI with a shared target directory sees a confusing failure, or, worse, learns to ignore this test.

**Reproduction or counter-example.** Run `CARGO_TARGET_DIR=/some/dir cargo test --offline -p xtask`. My first baseline run failed this way (`scratchpad/baseline-test.log`); the rerun without the variable passed (`scratchpad/xtask-test.log`).

**Proposed fix.** Set `.env_remove("CARGO_TARGET_DIR")` and a per-scratch `CARGO_TARGET_DIR` in `Scratch::clippy`.

**Confidence:** 0.95

### F-24 (minor): Several invariants have no test that names them

**Affected:**

- docs/architecture/state-machine.md (invariant table INV-01 to INV-11)
- search result: no Rust file mentions INV-01, INV-09 or INV-11; INV-03 and INV-05 appear only in port documentation

**Evidence status:** Verified by searching the Rust sources.

**What is wrong.**

Rust tests reference INV-02, INV-04, INV-06, INV-07, INV-08 and INV-10. The others are covered, if at all, by tests named after behavior (for example the store check on zombie workers for INV-05) that nobody can map back. INV-01 and INV-09 are planned for the engine and the database; INV-11 has invalidation tests in the domain crate without the label.

**Why it matters.** The slice plan's done check 2 for the engine is "each invariant INV-01 to INV-11 has a named test". A name that does not exist yet cannot be checked.

**Reproduction or counter-example.** `grep -rln "INV-11" crates xtask` returns nothing.

**Proposed fix.** Add an `invariant_register` test that reads the table from state-machine.json and fails when an id has no test attribute or doc comment naming it.

**Confidence:** 0.80

### F-25 (minor): Several rules are kept by convention, not by type

**Affected:**

- crates/domain/src/scope.rs:30 (TenantScope::new is public)
- crates/ports/src/store.rs:151 (SystemScope::engine is public)
- crates/ports/src/workspace.rs:82 (IngestedChange::new is public; its documentation says only ingest makes one)
- crates/ports/src/agent.rs:183 (GrantedTools is a public Vec)
- crates/ports/src/store.rs:492, workspace.rs:196-199, sandbox.rs:732 (String payloads in 'closed' error enums)

**Evidence status:** Verified by reading.

**What is wrong.**

Any crate can build a `TenantScope` for any tenant, a `SystemScope`, an `IngestedChange`, or a list of granted tools. The architecture check guards `begin_system` by text. The workspace fake refuses a forged `IngestedChange` by tree digest and the contract suite checks that, which is the right backstop. Error enums such as `StoreError::Constraint(String)` and `WorkspaceError::Git(String)` carry free text. The documentation says the text never includes a value from a row or a secret, which no type enforces.

**Why it matters.** Each is a small gap on its own. Together they are the places where the next adapter author can make a mistake the compiler would have caught.

**Reproduction or counter-example.** `IngestedChange::new(base, changes, digest)` compiles in any crate (scratch test `forged_ingested_change_is_constructible`).

**Proposed fix.** Construct `TenantScope` only from a `ResolvedPrincipal` returned by the lookup (F-02); make `IngestedChange::new` `pub(crate)` with a `testkit` feature; replace the `String` payloads by an enum of rule names plus an opaque code.

**Confidence:** 0.70

### F-26 (minor): Agent output contracts mix fields the engine owns with fields the agent writes

**Affected:**

- schemas/review-verdict.schema.json (metadata ids, reviewer.runtime.fidelity, inputs_reviewed, saw_builder_self_assessment)
- schemas/gate-report.schema.json, schemas/evidence-ledger-entry.schema.json (same pattern)
- crates/ports/src/registry.rs:44-70 (ContractKind includes ReviewVerdict as agent output)

**Evidence status:** Judgment.

**What is wrong.**

The review verdict is validated as agent output, yet the schema says the engine builds `inputs_reviewed` and asserts `saw_builder_self_assessment: false`. If the agent emits the whole document, the agent reports its own provenance and fidelity. If the engine overwrites them, the validated document and the stored one differ.

**Why it matters.** Principle 15: no self-assessed grading monopoly. The reviewer should not be able to claim what it saw.

**Reproduction or counter-example.** Reading.

**Proposed fix.** Define a smaller agent-output schema (verdict, summary, findings, confidence) and have the engine wrap it into the stored verdict with the engine-owned fields.

**Confidence:** 0.55

## Note findings

### F-27 (note): The YAML reader matches the parser contract in the header of security.yaml

**Affected:**

- crates/contracts/src/yaml/mod.rs
- policies/security.yaml:14-37

**Evidence status:** Verified by running 37 hostile inputs (`scratchpad/exp/tests/yaml.rs`).

**What is wrong.**

Refused with a located message: anchors, aliases, the merge key `<<` (with and without an anchor), tags, custom tags, a second document, directives, duplicate keys (block and flow), `yes/no/y/n/on/off`, `0777`, `0o7`, `0x1F`, `1e3`, `1_000`, `+1`, `.inf`, sexagesimal values, dates, `null`, `~`, an empty value, a non-string key, numeric and boolean keys, tab indentation, 300-deep flow nesting, an alias bomb. Accepted as the contract allows: quoted strings, block and folded scalars, a leading byte order mark. The one difference from the contract is known: the header says block style and the files use flow style.

**Why it matters.** Recorded so the next reviewer does not repeat it.

**Reproduction or counter-example.** `cargo test --manifest-path scratchpad/exp/Cargo.toml --test yaml -- --nocapture`.

**Proposed fix.** None needed.

**Confidence:** 0.90

### F-28 (note): The schema engine refuses unknown keywords and its work is bounded

**Affected:**

- crates/contracts/src/schema_engine.rs
- crates/contracts/src/validator.rs

**Evidence status:** Verified by running (`scratchpad/exp/tests/validator.rs`, release build).

**What is wrong.**

Compile-time refusal of unsupported keywords means no schema keyword is silently ignored; the only annotations it ignores are listed in its documentation, and the schemas use `format` once (F-22). `uniqueItems` is linear (hash of a canonical text). Timings on 120 KB and 270 KB documents with 40,000 and 90,000 empty objects (each failing a `required` rule inside an `anyOf`): 63 ms and 134 ms, with 100 violations listed. A 500 KB title is refused in under 1 ms, and 20,000 nested arrays stop at the 100,000-value limit in 4 ms.

**Why it matters.** Recorded as evidence for question 5.

**Reproduction or counter-example.** As above.

**Proposed fix.** None needed. The bypass is the port signature (F-05), not the engine.

**Confidence:** 0.85

### F-29 (note): The domain state machines equal state-machine.json and the crate does no I/O

**Affected:**

- crates/domain/tests/state_machine_conformance.rs
- crates/domain/tests/state_machine_properties.rs
- crates/domain/src/state/*.rs

**Evidence status:** Verified by running the tests and by searching the sources.

**What is wrong.**

The conformance test compares states, events, transitions, guards, actors, the defect matrix, the human rework routes and the invalidation rows with the JSON in both directions; 22 of 22 pass, and 19 property tests pass. The domain sources contain no `std::env`, `std::fs`, `std::io`, clock, randomness or `HashMap` iteration (one `HashSet` used for a uniqueness test). `Timestamp` equality, hash and order use the instant, as ADR 0011 says, and the ledger hash is checked against an independent Python oracle fixture. The ADR 0010 priority order (budget, retry, nonretryable, escalate) is implemented in `decide_after_failure` as the table says. The weaknesses are F-11, F-12 and F-24.

**Why it matters.** Recorded so the verdict is not read as a complaint about the domain.

**Reproduction or counter-example.** `cargo test --offline -p factory-domain`.

**Proposed fix.** None needed.

**Confidence:** 0.85

### F-30 (note): LeaseEpoch::next saturates instead of failing

**Affected:**

- crates/ports/src/store.rs:116-119

**Evidence status:** Verified by reading.

**What is wrong.**

At `u64::MAX`, `next()` returns the same value, so the fencing counter would stop being monotonic. The value is not reachable in practice.

**Why it matters.** Noted for completeness.

**Reproduction or counter-example.** The unit test `a_lease_epoch_only_goes_up` asserts the saturating behavior.

**Proposed fix.** Return an error from the claim at the maximum.

**Confidence:** 0.90

### F-31 (note): The edge rules DEP-01, DEP-02, DEP-03 and DEP-08 held against my mutations

**Affected:**

- xtask/src/topology.rs
- xtask/tests/dependency_rules.rs
- docs/architecture/crate-dependency-rules.json

**Evidence status:** Verified by running one mutation (a peer adapter dependency) and by running the 41 fixture tests of the dependency-rules binary.

**What is wrong.**

Adding `factory-sandbox` to the `runtime` crate gave `error[DEP-01]` and `error[DEP-02]`. The 41 dependency-rule fixture tests pass. I did not try a path or git dependency under an allowed crate name; `deny.toml` is the control for sources and I did not run `cargo deny`.

**Why it matters.** Recorded to bound what F-12 covers.

**Reproduction or counter-example.** See F-12.

**Proposed fix.** None needed.

**Confidence:** 0.80

## Decision on tagging `ports-v1`

**NO-GO.** Changes required before the tag. Each item names the type or method to add or change, and every change goes with the in-memory fake and the shared contract suite in the same pull request.

**Store (F-01, F-02, F-06, F-15)**

- Add `repository`, `execution_mode`, `autonomy_level`, `pipeline_scope`, `idempotency_key` and `webhook_delivery` to `NewJob`, and return them in `Job`.
- Add `run_number`, `max_attempts`, `not_before` and `rework_of` to `NewStageRun`. Add a `GateRecord { outcome, report_sha256, contract_sha256 }` argument to the PASSED, SKIPPED and REWORK transitions.
- Add `deadline`, `lease_owner` and `lease_expires_in` to `NewAttempt`, and an `AttemptEnd { failure_class, output_sha256, sandbox_id, sandbox_leaked }` argument to attempt transitions. Move the lease from `StageRun` to `Attempt`.
- Replace `claim_ready` by the two-step claim the DBA tested, or change the migration. Record the choice in an ADR. Correct the lock mode in the documentation to `FOR NO KEY UPDATE`.
- Add `RequestOps`, `DeliveryOps`, `ApprovalOps`, `LookupOps` (`resolve_token`, `resolve_installation`), listing methods (stage runs of a job, attempts of a stage run, task nodes and their edges), timer methods (`schedule_retry`, `due_work`) and `StageRunArtifactOps`.
- Correct `AuditEvent`: optional job, plus subject, decision and reason; the store assigns the time.
- Add `StoreError::CommitOutcomeUnknown`; make `insert_*` idempotent by id and content.
- Make artifact reads take a tenant scope or move them behind the tenant's index row.

**Workspace, sandbox and git host (F-03, F-04, F-09, F-10, F-13, F-14)**

- Add `Workspace::read_changed_file`, `Workspace::export_patch` (a stored artifact with a hash) and `Workspace::read_file_at(commit, path)`. Put an `ArtifactStore` in `SpecContext`.
- Add `WorkspaceId`, `WorkspaceProvider::open(job)` and `fetch(repo, FetchTarget)`; add `ChangeHost::resolve_branch` and a `FetchTarget` credential. Define and test a second workspace created at a commit made by the first, and push after reattach.
- Replace `protected: Vec<RepoGlob>` by `Vec<ProtectedPath { glob, mode }>` with the policy's modes. Add folded (NFC, case-insensitive) matching and re-inclusion. Reject the Unicode and 8.3 forms of `.git`.
- Make extra mounts typed variants, reject zero limits and `memory_swap_mb < memory_mb`, normalize paths, and add `limits`, `network`, `mounts`, `env` and `image` to `PostureReport`. Add a read-only workspace flag and a holdout mount for the verify profile.
- Let `JobTokenFile` carry the secret and have the sandbox adapter materialize and remove it.
- Add `IssueSource::fetch_comment`; decide check runs versus statuses; add a `WebhookVerifier` port.

**Agent, registry and transitions (F-05, F-07, F-08, F-11)**

- Return the agent's raw output as bytes or an artifact reference, and add `OutputValidator::validate_bytes`.
- Add `exclude` and the probed capabilities to `RoutingNeed` and `route`.
- Return usage, transcript and denials with an `AgentRunError`.
- Return a `GuardCleared` token from `guards::evaluate` and require it in `AppliedTransition::plan`.

**Tests (F-16)**

- Add a `SpecificationProvider` contract suite and make its fake run a scripted tool inside the fake sandbox.
- Add the missing store checks (job must be `ACTIVE` to claim, one live attempt, duplicate task key, audit limit) and make the fake change host track pushes.
- Add a step that fails when a check is missing from the defect tables or a seeded rule survives.

**Can follow the tag:** F-12 (it is tooling, and the DEP-05 bans do not change the ports), F-17, F-18, F-19 except the port documentation lines, F-20 to F-26.

**Decisions that need the architect or a human:** whether the claim is changed in the port or in the migration (F-01); check runs or commit statuses for the App's required checks (F-13); whether to tag a release candidate (`ports-v1-rc1`) after the Store, workspace and agent changes so the first adapter packages can start while the rest is finished. I recommend the release candidate only if it carries the same contract suites as the final tag.

## Answers to the seven questions

### 1. Are the eighteen ports sufficient and minimal?

**Sufficient: no.** **Minimal: nearly.** I found no method that nobody can use. One error variant, `SpecError::ForbiddenOperation`, can never be produced, because `SpecOperation` is a closed enum, and `ExtraMount` exists only so that it can be refused. The eighteen are `Clock`, `IdGenerator`, `CancelSignal`, `Store`, `Tx`, `ArtifactStore`, `SandboxProvider`, `SandboxSession`, `WorkspaceProvider`, `Workspace`, `AgentRuntime`, `ModelRouter`, `ModelBroker`, `AgentRegistry`, `OutputValidator`, `SpecificationProvider`, `IssueSource` and `ChangeHost` (the slice plan's registry).

Stage by stage, what a stage needs that no port gives:

| Stage | Missing capability | Finding |
|---|---|---|
| Intake | Store the original issue text apart from the normalized one; record the webhook delivery and refuse a repeat; resolve token and installation to a tenant; audit a rejection that has no job; read a comment and its author | F-02, F-13 |
| Repository intelligence | Fetch the repository with a narrowed read credential; resolve a branch to a commit | F-04 |
| Spec Kit specification | Read the files the skills wrote, with their exact hashes; store them | F-03 |
| Spec gate | Same read-back (checklist and `spec.md`) | F-03 |
| Architecture and planning | Model fallback when a runtime fails; persist task dependency edges; list the stage runs of a job | F-07, F-02 |
| Scheduling | Claim as the migration defines it; set retry back-off; ask for due work; list attempts | F-01, F-02 |
| Isolated implementation | Write the job token file; protected-path modes; failed-run usage and transcript | F-14, F-10, F-08 |
| Deterministic validation | Verify profile with a read-only source tree and read-only holdouts; run at a commit made by an earlier workspace | F-09, F-03 |
| Reviews, adversarial and security | A diff or patch artifact; location of findings checked against it | F-03, F-17 |
| Rework | Count attempts and rework rounds across stage runs (listing) | F-02 |
| Documentation and its review | Read documentation files at a commit; reattach the workspace | F-03, F-04 |
| Approval | Record an approval; read an operator comment | F-02, F-13 |
| Pull request | Push after a restart; mark ready; checks pinned to the App | F-04, F-13 |

Cross-cutting properties:

- **Idempotency.** Every method documents it. Two documented claims are stronger than can be delivered: `Tx::commit` leaves nothing behind on failure (F-06) and `post_comment` posts at most once per key (F-19).
- **Cancellation.** Only `SandboxSession::exec`, `AgentRuntime::run` and `SpecificationProvider::run` take a `CancelSignal`. `Workspace::{ingest, commit, push}`, `ChangeHost::*`, `SandboxProvider::create_verified` and `AgentRuntime::probe` do not, and none says whether dropping the future is safe.
- **Timeout.** `ExecRequest.timeout`, `AgentLimits` and `SandboxLimits.wall_clock` exist. `StoreError`, `ArtifactError`, `WorkspaceError` and `GitHostError` have no timeout or outcome-unknown variant, so a timeout becomes `Unavailable`, which reads as safe to retry (F-06).
- **Closed error sets.** All ports have one. Several variants carry free text (F-25).
- **Adapter types.** None leak: no Diesel, HTTP or Docker types. `serde_json::Value`, `uuid::Uuid` and `std::path::PathBuf` appear; `PathBuf` puts host paths into `WorkspaceMounts` and `JobTokenFile`.
- **Async object safety.** `Box<dyn Tx>`, `Box<dyn SandboxSession>`, `&mut dyn SandboxSession` and `&dyn CancelSignal` compile and the fakes use them (`#[async_trait]`, one boxed future per call).
- **Fidelity.** Every port with a stand-in has `fidelity()`, and `require_permitted` refuses a fake in production. The value is self-reported, so it protects against mistakes and not against a lie, and nothing forces the composition root to call it for every adapter (an engine test is planned). `OutputValidator` has no fake and no label.
- **Agents cannot change state or merge.** No port hands an agent a `Store`, `ChangeHost` or `Workspace::push`; `AgentRuntime::run` returns data. The no-merge rule on `ChangeHost` is a method-name rule checked by text scan (F-12), and `set_status(Success)` can be called by any holder of a `ChangeHost` without proof of a gate decision (F-11).

### 2. Are the fakes faithful?

No, in the ways listed in F-16: the fake store claims work for a job that is not active and allows two live attempts on one stage run, the fake change host opens a pull request for a branch that was never pushed, the fake spec provider ignores its context and has no shared suite, and the fake sandbox can drift only one posture field. The defect-injection design (a fake built with a deliberate fault, and tests that require the named check to fail) is sound, but it covers 67 of 132 checks. Two documented rules of the store survived deletion from the fake (duplicate task key, audit limit). Some of the unfaithfulness is not the fakes' fault: the ports omit what the database enforces (F-01, F-02).

### 3. Do the domain machines match the specification?

Yes for the machines, guards and routing tables: the conformance test compares the code with `state-machine.json` in both directions and passes, ADR 0010's order of failure handling is what `decide_after_failure` does, ADR 0011's equality by instant is implemented and tested, and the domain does no I/O and reads no clock (F-29). The gaps are about how the engine will use them. A transition is not bound to the guard that must hold (F-11), the guard facts are booleans the caller supplies, three invariants have no test that names them (F-24), a stage contract can omit the retry classes that make crash recovery work (F-20), and the review verdict schema lets findings omit file and line (F-17).

### 4. Do the dependency rules enforce the hexagon?

The edge rules do (DEP-01, DEP-02, DEP-03, DEP-08, with 41 fixture tests and my control mutation, F-31). The rules built on lists and text scans do not, and I found four bypasses in a scratch copy and one gap that the plan already lists (F-12): the DEP-05 ban list misses `Path` methods, the environment, sockets, `tokio::time`, `now_utc` and the uuid generators; an adapter crate can enable `time/std` so the domain crate can read the clock; an `allow` attribute silences a ban; a spawn through an import alias and through a file named `*_tests.rs` is not seen. The gap the plan lists is that adapters are exempt from the external crate check. The planned package `s1-xtask-extensions` covers that and part of the feature check.

### 5. Contracts and validator

The schema engine refuses a keyword it does not implement when a schema is compiled, so nothing is silently ignored; the one annotation the schemas rely on that it does not assert is `format` (F-22). Untrusted output cannot cause unbounded work through `SchemaOutputValidator` (F-28), and the YAML reader matches the parser contract at the top of `policies/security.yaml` for all 37 hostile inputs I tried, except the known block-versus-flow style difference (F-27). The weak point is the port: `OutputValidator::validate` and `AgentRunOutcome.output` carry an already parsed `Value`, so the strict parser, which refuses duplicate keys and checks size and depth before parsing, is not on the path the engine uses (F-05).

### 6. Consistency

The most important contradictions are the port and the migrations (F-01, F-02), the policy and the protected-path model (F-10), the spec and the schema (F-17), and the specification's "eleven stages" against a thirteen-stage machine (F-18). Smaller ones are in F-19 and F-20. What the master prompt requires of these layers and is missing: held-out tests mounted for verification (F-09), the diff for independent review (F-03), fallback across providers (F-07), and a way to resume after a crash (F-04, F-06).

### 7. Readiness of the next packages

| Package | Can it be built on the ports as they are? | Blocking findings |
|---|---|---|
| `s1-engine-core` | No. It cannot persist, list, time or resume | F-01, F-02, F-04, F-06, F-07, F-11 |
| `s1-storage-postgres` | No. The suite would pass on the fake and fail on the schema | F-01, F-02, F-06, F-15 |
| `s1-sandbox-adapter` | Partly. The container side yes; verify profile, token file and posture no | F-09, F-14 |
| `s1-workspace-ingestion` | No | F-03, F-04, F-10 |
| `s1-agent-runtime-adapters` | Mostly. Output and failure shapes would change | F-05, F-08, F-14 |
| `s1-github-adapter` | Partly. Comment read, check runs and webhook boundary are open | F-13, F-04 |
| `s1-spec-adapter-and-stage` | No | F-03 |
| Intake, architecture, implementation and review, validation, documentation, delivery stages | No | F-02, F-03, F-04, F-13, F-17 |

## What I ran (verified facts)

All commands ran in the worktree at the commit above, offline. Scratch work is outside the repository, in `/private/tmp/claude-501/-Users-marcelo-Documents-Projects-ortisun-software-factory-ai/7efc9dcd-1125-4dcc-9aa3-dcbbe25183eb/scratchpad/` (shortened to `scratchpad/` below). It is not part of this commit and may be deleted, so each finding lists the inputs needed to repeat the experiment.

- `cargo test --offline` for `factory-domain`, `factory-ports`, `factory-testkit` and `factory-contracts`: no failures. Counts by binary include domain 206 unit tests, 22 conformance tests, 19 property tests; ports 62 unit tests and 5 trait-documentation tests; testkit 208 unit tests and every contract suite.
- `cargo test --offline -p xtask`: all pass (61 unit, 15 clippy-ban, 41 dependency-rule, 91 static-check tests). My first run failed two clippy-ban tests because I had set `CARGO_TARGET_DIR`; see F-23.
- `cargo xtask check-architecture`: passes on the real workspace (17 packages).
- `cargo clippy --offline --workspace --all-targets -- -D warnings`: clean.
- The three documentation checkers (`render_state_machine.py --check`, `check_crate_rules.py --check`, `check_work_packages.py --check`): pass.
- Experiments in `scratchpad/exp` (a scratch crate depending on the repository crates by path): `ports.rs` (sandbox guard, glob and path cases, forged ingested change), `validator.rs` (hostile documents, duplicate key), `yaml.rs` (37 hostile YAML inputs), `store.rs` (fake store versus the migrations), `workspace.rs` (push after reattach), `claims.rs` (three schema claims), `verdict.rs` (this report's verdict block).
- Mutations in `scratchpad/copy` (a copy of the repository): clock, filesystem, environment and socket calls in the domain crate; a feature enabled in an empty adapter crate; a shell spawn through an alias and through a `_tests.rs` module; an `allow` attribute over a banned call; a peer-adapter dependency (control); two rules removed from the fake store.
- Everything that depends on PostgreSQL, Docker or GitHub is judged from code, schemas, migrations and documents. No such adapter exists yet.

## What I did not review

- `crates/testkit/src/fx/` (security tooling, out of scope as instructed), `crates/observability`, `apps/*`, `crates/{workflow,storage,runtime,sandbox,github,egress,spec_adapter}` (empty stubs).
- The migrations beyond the tables and constraints I cite; I did not run them or the SQL tests in `docs/database/tests`.
- `docs/security/*`, `docs/spec-kit/*`, `policies/approval.yaml` and most of `policies/security.yaml`; I read the parser contract, the matching rules, the protected-path groups and the sandbox section. In `crates/contracts` I read the validator, the schema engine and the YAML reader closely, and only skimmed the policy loaders, the registry and the loader.
- `crates/domain/src/contracts/*` field by field against the schemas (I relied on the example and rule tests, which pass); the guard predicates for the attempt, job and task node machines, `invalidation.rs` and most of the rework ledger.
- `slice-plan.md` except the ports section and the packages I cite; `work-packages.json` except through its checker.
- The Python ledger oracle was not rerun; the Rust tests that compare with its fixture pass.

## What I could not verify

- Anything that needs PostgreSQL, Docker, GitHub or a real agent tool: the failures predicted in F-01, F-06 and F-09, Docker's treatment of zero limits, AppArmor on Docker Desktop (F-21), and GitHub's pinning of required checks (F-13).
- `cargo deny`, `cargo audit` and `schemas/validate.sh` as a whole: I did not run them (the first two need an advisory database). I did run the pinned `check-jsonschema` 0.39.0 on the verdict block below, from its offline cache.
- Whether a real git adapter would allow a second workspace to be created at a commit made by another (F-03, F-04). The fake allows it, the port does not say.
- I read the ADRs' own statements of what was checked and treated them as claims. I did not receive the builders' hand-off report.

## Verdict block

The block follows `schemas/review-verdict.schema.json`. The job and stage run ids are all zeros because this review was not run by the factory. The two `gate_reports` entries are my own recorded command logs (`scratchpad/baseline-test.log`, `scratchpad/xtask-test.log`), listed only because the schema requires at least one; they are not factory gate reports. `execution_mode` is `test` for the same reason.

**Validation:** The block passes two independent checks. `check-jsonschema` 0.39.0 (the validator pinned by `schemas/validate.sh`) reported "ok -- validation done" against `schemas/review-verdict.schema.json`. The repository's own `SchemaOutputValidator::parse_and_validate` and `ReviewVerdict::validate` in the domain crate both accepted it. Severity words follow the schema: blocker, high (a major finding), low (a minor finding) and info (a note).

```json
{
  "schema_version": 1,
  "metadata": {
    "review_id": "3869ace3-ed40-5886-9f50-d903ae98b91b",
    "job_id": "00000000-0000-0000-0000-000000000000",
    "stage_run_id": "00000000-0000-0000-0000-000000000000",
    "execution_mode": "test",
    "created_at": "2026-10-27T12:48:36Z",
    "reviewer": {
      "agent_id": "software-architect",
      "agent_version": "1.0.0",
      "role": "architecture_critic",
      "runtime": {
        "adapter": "claude-agent-sdk",
        "adapter_version": "unknown",
        "model": "claude-sonnet-5-5",
        "fidelity": "real"
      }
    }
  },
  "title": "The foundation needs port changes before ports-v1 can be tagged",
  "verdict": "CHANGES_REQUIRED",
  "summary": "The domain crate, the schema engine, the YAML reader and the edge rules of the architecture check do what their documents say. The port surface does not yet support the pipeline: the Store cannot persist what the migrations require, nothing can read back what the sandbox produced, the workspace cannot be reattached after a restart, and several guards and fakes are weaker than the policy and the database they stand for. Tagging ports-v1 now would force rework in every package that builds on it.",
  "inputs_reviewed": {
    "frozen_spec_sha256": "sha256:6e76c2c6b79f3d91706e2fac559ad09db1f8f64fff0a70c815fd2698594f0927",
    "diff_sha256": "sha256:1e2a51d81746bc05297f54b56466f86f2494b541a9f2070a6e000a5d84d452f7",
    "gate_reports": [
      {
        "gate_report_id": "d7dcf3bb-1646-57fe-a26c-6a13a7dc6fc0",
        "sha256": "sha256:73167f87ff485d20d4ed3c109dfd9f94405455640dda7d0f9bbe97423ed6cea4"
      },
      {
        "gate_report_id": "42b56733-f516-5f85-bb9a-15364a1bb1c0",
        "sha256": "sha256:0272bf59adc2327b9d9f06bb85ed6bfc58ab9a343732b5c568f6980459eee400"
      }
    ],
    "context_artifacts": [
      {
        "sha256": "sha256:ed55fa1a28a79ea10617edb1657e2d661ae2a16083ba0a59ad17d7309938dddd",
        "media_type": "text/markdown",
        "size_bytes": 79900
      }
    ],
    "saw_builder_self_assessment": false
  },
  "findings": [
    {
      "finding_id": "f-01",
      "severity": "blocker",
      "category": "compatibility",
      "title": "The Store write model cannot persist what the migrations require",
      "description": "The port types and the tables disagree in five places. - `jobs` has NOT NULL columns `repository_id`, `execution_mode`, `autonomy_level` and `pipeline_scope`. `NewJob` holds an id, a correlation id, a requester and a creation time. `Job` cannot return the four columns either, so after a restart the engine cannot learn which repository a job belongs to or whether it runs in...",
      "confidence": 0.9,
      "proposed_next_action": "fix",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/ports/src/store.rs",
        "line_start": 226,
        "line_end": 237
      }
    },
    {
      "finding_id": "f-02",
      "severity": "blocker",
      "category": "compatibility",
      "title": "The Store has no operations for requests, deliveries, approvals, lookups, listings and timers",
      "description": "The tables exist and the specification needs them, but no port method touches them. - Original issue text, kept apart from the normalized request (FR-003): table `original_requests`, no method. - Webhook delivery record and duplicate suppression (FR-040): table `webhook_deliveries`, no method. - Operator and approver decisions (FR-029, FR-031): table `approvals`, no method....",
      "confidence": 0.9,
      "proposed_next_action": "fix",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/ports/src/store.rs",
        "line_start": 591,
        "line_end": 883
      },
      "reproduction": {
        "kind": "steps",
        "detail": "`grep -rn \"original_request\\|approval\\|webhook\\|resolve_token\\|fn list_\" crates/ports` returns nothing. The only mention of `resolve_token` is in the slice plan sketch."
      }
    },
    {
      "finding_id": "f-03",
      "severity": "blocker",
      "category": "correctness",
      "title": "Nothing can read back what the sandbox wrote, and no port exports a diff",
      "description": "A stage that needs the content of what an agent produced has no sanctioned way to get it. - `Workspace::read_base_file` and `list_base` read the trusted base commit, \"never the sandbox-writable tree\". `IngestedChange` lists changed paths and kinds, not content. - The Spec Kit adapter must read `spec.md`, the checklist and the constitution to build a `SpecificationContract`...",
      "confidence": 0.85,
      "proposed_next_action": "fix",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/ports/src/workspace.rs",
        "line_start": 72,
        "line_end": 110
      }
    },
    {
      "finding_id": "f-04",
      "severity": "blocker",
      "category": "correctness",
      "title": "The workspace cannot obtain a repository and cannot survive a worker restart",
      "description": "Two gaps in the same lifecycle. 1. Acquisition. `create` requires that \"the request's repository and base commit exist in the trusted object store\". No port fetches the repository. There is a `PushTarget` with a narrowed credential for writing, but no read counterpart, and the adapters may not depend on each other, so the sandbox crate cannot ask the GitHub crate for a...",
      "confidence": 0.8,
      "proposed_next_action": "fix",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/ports/src/workspace.rs",
        "line_start": 19,
        "line_end": 30
      },
      "reproduction": {
        "kind": "test",
        "detail": "Scratch test `scratchpad/exp/tests/workspace.rs`: create a workspace, write a file, `ingest`, `commit`, drop the workspace, create a second workspace whose base is that commit (accepted), then `push` the commit from the second workspace. Result: `Err(Git(\"the commit was not made by this..."
      }
    },
    {
      "finding_id": "f-05",
      "severity": "high",
      "category": "security",
      "title": "The output validator port receives an already parsed value, so the strict parser is skipped",
      "description": "The trait documentation promises \"Size and depth limits apply before any parse that could exhaust memory\". The signature cannot keep that promise, because the argument is a `Value` that somebody has already parsed. `AgentRunOutcome.output` is also a `Value`, so the runtime adapter parses the tool's output with `serde_json` before any limit applies. The strict path (size,...",
      "confidence": 0.9,
      "proposed_next_action": "fix",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/ports/src/registry.rs",
        "line_start": 182,
        "line_end": 200
      },
      "reproduction": {
        "kind": "test",
        "detail": "With the real validator: `parse_and_validate(ReviewVerdict, 1, br#\"{\"schema_version\":1,\"verdict\":\"BLOCK\",\"verdict\":\"PASS\"}\"#)` is refused (\"the object repeats the key `verdict`\"). The same bytes parsed into a `serde_json::Value` first give `verdict = \"PASS\"`, and that is the value the port would..."
      }
    },
    {
      "finding_id": "f-06",
      "severity": "high",
      "category": "correctness",
      "title": "Tx::commit cannot report an unknown outcome, and a failed commit may not leave nothing behind",
      "description": "`Tx` documents: \"`commit` returns Conflict when another transaction committed a change... and Unavailable when the database is gone. A failed commit leaves nothing behind.\" If the connection drops after the server applied COMMIT and before the client saw the reply, the call fails with `Unavailable` and the transaction is committed. The port has no variant for \"outcome...",
      "confidence": 0.8,
      "proposed_next_action": "fix",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/ports/src/store.rs",
        "line_start": 540,
        "line_end": 543
      }
    },
    {
      "finding_id": "f-07",
      "severity": "high",
      "category": "correctness",
      "title": "ModelRouter cannot express fallback or probed capabilities",
      "description": "The trait requires \"the same need always gets the same decision\", and `RoutingNeed` has no field for runtimes that already failed or for an attempt number. ADR 0005 says \"the engine may retry on another runtime\"; the master prompt asks for fallback across providers. With this signature the second call returns the first runtime again. `RoutingNeed.required` lists...",
      "confidence": 0.85,
      "proposed_next_action": "fix",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/ports/src/agent.rs",
        "line_start": 440,
        "line_end": 491
      }
    },
    {
      "finding_id": "f-08",
      "severity": "high",
      "category": "correctness",
      "title": "AgentRunError discards usage, transcript and denials of a failed run",
      "description": "Only a successful run returns `usage`, `transcript` and `permission_denials`. Timeout, ProcessFailed, OutputMissing, Cancelled and BudgetRefused return none of them. The failed attempt is exactly the one that needs evidence (V6: each stage keeps evidence for its claims, and failures never silently convert to success) and the one that may have cost money.",
      "confidence": 0.85,
      "proposed_next_action": "fix",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/ports/src/agent.rs",
        "line_start": 326,
        "line_end": 362
      }
    },
    {
      "finding_id": "f-09",
      "severity": "high",
      "category": "security",
      "title": "The sandbox guard is a deny list, accepts zero limits, and the posture report checks only Hardening",
      "description": "`validate` refuses a list of known-bad sources and accepts everything else. A test in the same file is named `a_mount_next_to_a_forbidden_source_is_not_refused`. The limit check is \"not above the maximum\" only. The posture check compares `Hardening` and nothing else, so the engine cannot see whether the created container has the memory, pids, network, mounts, environment...",
      "confidence": 0.9,
      "proposed_next_action": "fix",
      "defect_class": "policy",
      "location": {
        "path": "crates/ports/src/sandbox.rs",
        "line_start": 491,
        "line_end": 506
      },
      "reproduction": {
        "kind": "test",
        "detail": "With the forbidden list copied from `policies/security.yaml` (lines 694-704), these all returned `Ok(())` from `SandboxSpec::validate`: an extra mount whose source is `/run`, `/run/containerd/containerd.sock`, `/srv/../run/docker.sock`, `//var/run/docker.sock` or `/Users/me`; limits with..."
      }
    },
    {
      "finding_id": "f-10",
      "severity": "high",
      "category": "security",
      "title": "Protected paths: the port cannot express the policy that guards builder changes",
      "description": "The policy defines five modes (`hidden`, `deny_write`, `append_only`, `additions_only`, `sensitive`), NFC normalization, case-insensitive matching (\"so that `.GitHub/Workflows` cannot dodge `.github/**`\") and a `!` re-inclusion. The port has two lists. Any change to a path in `protected` is refused. Consequences: - `tests/**` is `additions_only` in the policy: builders must...",
      "confidence": 0.85,
      "proposed_next_action": "fix",
      "defect_class": "policy",
      "location": {
        "path": "crates/ports/src/workspace.rs",
        "line_start": 19,
        "line_end": 30
      },
      "reproduction": {
        "kind": "test",
        "detail": "Scratch test `scratchpad/exp/tests/ports.rs`, test `glob_is_case_sensitive`: output `.github/workflows/ci.yml: true`, `.GITHUB/workflows/ci.yml: false`, and `Ok(RepoPath(...))` for the four `.git` variants."
      }
    },
    {
      "finding_id": "f-11",
      "severity": "high",
      "category": "correctness",
      "title": "A state transition is not bound to the guard that must hold for it",
      "description": "`AppliedTransition::plan(from, event, at)` consults the transition table and drops the row's guard. `guards::evaluate` returns `Ok(())`, with no value that proves which guard held on which facts. Facts are booleans supplied by the caller (`decision_is_pass_and_persisted`, `lease_compare_and_swap_succeeded`). So `GATING -> PASSED` can be planned and stored without any guard...",
      "confidence": 0.7,
      "proposed_next_action": "fix",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/ports/src/store.rs",
        "line_start": 165,
        "line_end": 224
      }
    },
    {
      "finding_id": "f-12",
      "severity": "high",
      "category": "maintainability",
      "title": "The architecture checks can be bypassed in ways the tests do not cover",
      "description": "DEP-01, DEP-02, DEP-03 and DEP-08 (the edge rules) held against my attempts. The rules built on lists and text scans did not. 1. **DEP-05 ban list.** The four inner crates ban `std::fs::*` functions, the `File`, `OpenOptions`, `TcpStream`, `TcpListener`, `UdpSocket` and `process::Command` types, and three clock calls. They do not ban the `Path` and `PathBuf` methods...",
      "confidence": 0.9,
      "proposed_next_action": "fix",
      "defect_class": "policy",
      "location": {
        "path": "xtask/src/static_checks.rs",
        "line_start": 200,
        "line_end": 290
      },
      "reproduction": {
        "kind": "test",
        "detail": "Mutations are in `scratchpad/copy` (not in the repository). Commands: `cargo run --manifest-path scratchpad/copy/xtask/Cargo.toml -- check-architecture` and `cargo clippy --workspace --all-targets -- -D warnings` in that copy. Control: adding a direct `std::process::Command::new(\"sh\")` to..."
      }
    },
    {
      "finding_id": "f-13",
      "severity": "high",
      "category": "correctness",
      "title": "The GitHub ports cannot read comments, cannot pin checks to the App, and give webhooks no home",
      "description": "- Operator decisions arrive as pull request comments (FR-029). `IssueSource` says a webhook payload is \"only a hint\" and everything is fetched live. There is no method that fetches a comment and its author, so a comment command cannot be authorized under the port's own rule. - `ProtectionReport.required_checks_pinned_to_app` requires checks pinned to the App. As far as I...",
      "confidence": 0.7,
      "proposed_next_action": "fix",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/ports/src/githost.rs",
        "line_start": 264,
        "line_end": 311
      }
    },
    {
      "finding_id": "f-14",
      "severity": "high",
      "category": "security",
      "title": "No port writes the job token file, and the engine is not allowed to",
      "description": "`ModelBroker::issue` returns the secret in memory. `SandboxSpec.job_token` must name a file that already exists on the host. The engine (`workflow`) cannot create it: its clippy configuration bans `std::fs` writes and file creation. The sandbox adapter receives only a path. No port moves the secret from the broker to the file.",
      "confidence": 0.8,
      "proposed_next_action": "fix",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/ports/src/sandbox.rs",
        "line_start": 119,
        "line_end": 125
      }
    },
    {
      "finding_id": "f-15",
      "severity": "high",
      "category": "security",
      "title": "Artifact reads are not tenant-scoped by type",
      "description": "ADR 0007 makes tenancy a type error for the `Store`. ADR 0008 lets blobs be shared by hash across tenants and relies on the caller to check the tenant's index row first (\"Callers check the tenant's index row first\"). `get` and `exists` accept any `ArtifactRef`. Anyone holding a hash can read the blob, and `exists` is an oracle for \"does anyone hold this exact content\",...",
      "confidence": 0.75,
      "proposed_next_action": "fix",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/ports/src/artifact.rs",
        "line_start": 94,
        "line_end": 129
      }
    },
    {
      "finding_id": "f-16",
      "severity": "high",
      "category": "tests",
      "title": "Fakes are easier than the systems they stand for, and many contract checks were never shown to fail",
      "description": "**Behavior the fakes get wrong (the real systems would not):** - `InMemoryStore::claim_ready` hands out stage runs of a job that is `RECEIVED`, not `ACTIVE` (it never reads the job). The migration's claim joins `jobs.status = 'ACTIVE'`, and state-machine.md says a pause \"stops new leases\". The contract world never activates its jobs, so the suite encodes the weaker rule. -...",
      "confidence": 0.9,
      "proposed_next_action": "add_test",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/testkit/src/store.rs",
        "line_start": 672,
        "line_end": 731
      },
      "reproduction": {
        "kind": "test",
        "detail": "`scratchpad/exp/tests/store.rs` prints `claim_ready handed out 1 stage run(s)` for a job in `Received`, then `ok = true` twice for two live attempts. Mutations: `scratchpad/copy/crates/testkit/src/store.rs`; `cargo test -p factory-testkit --test store_contract` in the copy still reports `4 passed`."
      }
    },
    {
      "finding_id": "f-17",
      "severity": "high",
      "category": "intent_alignment",
      "title": "FR-023 and SC-008 cannot be met: a non-PASS finding may omit its file and line",
      "description": "FR-023: \"each finding MUST cite a file and line\". SC-008: \"every non-pass finding cites a file and line that exists in the diff\". The schema allows a CHANGES_REQUIRED, BLOCK or NEEDS_HUMAN verdict whose findings have no `location`. The domain type mirrors the schema. There is no invalid example. \"Exists in the diff\" also needs the diff (F-03).",
      "confidence": 0.9,
      "proposed_next_action": "fix",
      "defect_class": "specification",
      "location": {
        "path": "schemas/review-verdict.schema.json",
        "line_start": 81,
        "line_end": 88
      }
    },
    {
      "finding_id": "f-18",
      "severity": "low",
      "category": "intent_alignment",
      "title": "The specification counts eleven stages; the state machine has thirteen, plus MERGE",
      "description": "US1 acceptance scenario 1 and SC-001 require \"all eleven stages in order\". The machine has `INTAKE` to `APPROVAL`, which is thirteen kinds (domain discovery and the separate architecture and planning stages are the extras), and a fourteenth, `MERGE`, outside Slice 1. ADR 0001 says \"about a dozen\". The end-to-end test needs one number.",
      "confidence": 0.95,
      "proposed_next_action": "clarify_specification",
      "defect_class": "specification",
      "location": {
        "path": "specs/001-end-to-end-mvp/spec.md",
        "line_start": 38
      }
    },
    {
      "finding_id": "f-19",
      "severity": "low",
      "category": "documentation",
      "title": "Several documents contradict each other or the code",
      "description": "- ADR 0001, 0007 and 0012 chose `FOR NO KEY UPDATE SKIP LOCKED`; the port documentation and the migration header still say `FOR UPDATE`. - state-machine.md says the domain implements the version before the ADR 0010 revision and the conformance tests fail; they pass (22 of 22). - ADR 0011 lists a clippy ban on `now_utc`; the files have none (F-12). ADR 0002 says the uuid...",
      "confidence": 0.95,
      "proposed_next_action": "fix",
      "defect_class": "documentation",
      "location": {
        "path": "crates/ports/src/store.rs",
        "line_start": 645,
        "line_end": 646
      }
    },
    {
      "finding_id": "f-20",
      "severity": "low",
      "category": "correctness",
      "title": "A stage contract may leave out the retry classes that make crash recovery work",
      "description": "`retry_on` may be empty or omit `LEASE_LOST` and `TIMED_OUT`. If it omits `LEASE_LOST`, a worker crash ends in `S06` (FAILED), then `G_UNRECOVERABLE`, then a failed job. The master prompt requires recovery after a process crash.",
      "confidence": 0.85,
      "proposed_next_action": "fix",
      "defect_class": "specification",
      "location": {
        "path": "schemas/stage-contract.schema.json",
        "line_start": 772,
        "line_end": 786
      }
    },
    {
      "finding_id": "f-21",
      "severity": "low",
      "category": "compatibility",
      "title": "Hardening cannot say AppArmor is unavailable or IPC is none",
      "description": "The policy accepts AppArmor as \"runtime default or stricter where available\" and notes it is inactive on Docker Desktop, the development target. `Hardening.apparmor` is `RuntimeDefault` or `Unconfined`, and `differences` compares the requested and observed values exactly. On a daemon without AppArmor the adapter must either report `RuntimeDefault` falsely or fail every...",
      "confidence": 0.6,
      "proposed_next_action": "fix",
      "defect_class": "policy",
      "location": {
        "path": "crates/ports/src/sandbox.rs",
        "line_start": 168,
        "line_end": 183
      }
    },
    {
      "finding_id": "f-22",
      "severity": "low",
      "category": "correctness",
      "title": "The schema engine ignores `format`, and regex classes follow Unicode rules",
      "description": "Everything else the schemas use is applied: the engine refuses an unknown keyword when it compiles a schema, and I found no keyword in use that it ignores. `format` is an annotation, so `source.url` accepts any string. Patterns run on the Rust `regex` crate where `\\d`, `\\s` and `\\S` are Unicode-aware (ECMA-262 `\\d` is ASCII). The schemas use `\\S` and `\\s` for trimmed text...",
      "confidence": 0.9,
      "proposed_next_action": "fix",
      "defect_class": "specification",
      "location": {
        "path": "crates/contracts/src/schema_engine.rs",
        "line_start": 1,
        "line_end": 60
      }
    },
    {
      "finding_id": "f-23",
      "severity": "low",
      "category": "tests",
      "title": "Two xtask tests fail when CARGO_TARGET_DIR is set",
      "description": "`every_ban_fires_under_the_clippy_toml_each_inner_crate_actually_has` and `every_ban_in_the_rendered_file_fires_in_a_scratch_crate` fail with \"these bans did not fire\" when `CARGO_TARGET_DIR` points at a shared directory, because clippy reuses a cached result for the scratch crates. With the variable unset, all 15 tests of that binary pass.",
      "confidence": 0.95,
      "proposed_next_action": "fix",
      "defect_class": "code_behavior",
      "location": {
        "path": "xtask/tests/clippy_bans.rs",
        "line_start": 64,
        "line_end": 75
      },
      "reproduction": {
        "kind": "test",
        "detail": "Run `CARGO_TARGET_DIR=/some/dir cargo test --offline -p xtask`. My first baseline run failed this way (`scratchpad/baseline-test.log`); the rerun without the variable passed (`scratchpad/xtask-test.log`)."
      }
    },
    {
      "finding_id": "f-24",
      "severity": "low",
      "category": "tests",
      "title": "Several invariants have no test that names them",
      "description": "Rust tests reference INV-02, INV-04, INV-06, INV-07, INV-08 and INV-10. The others are covered, if at all, by tests named after behavior (for example the store check on zombie workers for INV-05) that nobody can map back. INV-01 and INV-09 are planned for the engine and the database; INV-11 has invalidation tests in the domain crate without the label.",
      "confidence": 0.8,
      "proposed_next_action": "add_test",
      "defect_class": "code_behavior",
      "location": {
        "path": "docs/architecture/state-machine.md"
      },
      "reproduction": {
        "kind": "steps",
        "detail": "`grep -rln \"INV-11\" crates xtask` returns nothing."
      }
    },
    {
      "finding_id": "f-25",
      "severity": "low",
      "category": "security",
      "title": "Several rules are kept by convention, not by type",
      "description": "Any crate can build a `TenantScope` for any tenant, a `SystemScope`, an `IngestedChange`, or a list of granted tools. The architecture check guards `begin_system` by text. The workspace fake refuses a forged `IngestedChange` by tree digest and the contract suite checks that, which is the right backstop. Error enums such as `StoreError::Constraint(String)` and...",
      "confidence": 0.7,
      "proposed_next_action": "fix",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/domain/src/scope.rs",
        "line_start": 30
      },
      "reproduction": {
        "kind": "test",
        "detail": "`IngestedChange::new(base, changes, digest)` compiles in any crate (scratch test `forged_ingested_change_is_constructible`)."
      }
    },
    {
      "finding_id": "f-26",
      "severity": "low",
      "category": "maintainability",
      "title": "Agent output contracts mix fields the engine owns with fields the agent writes",
      "description": "The review verdict is validated as agent output, yet the schema says the engine builds `inputs_reviewed` and asserts `saw_builder_self_assessment: false`. If the agent emits the whole document, the agent reports its own provenance and fidelity. If the engine overwrites them, the validated document and the stored one differ.",
      "confidence": 0.55,
      "proposed_next_action": "clarify_specification",
      "defect_class": "specification",
      "location": {
        "path": "crates/ports/src/registry.rs",
        "line_start": 44,
        "line_end": 70
      }
    },
    {
      "finding_id": "f-27",
      "severity": "info",
      "category": "other",
      "title": "The YAML reader matches the parser contract in the header of security.yaml",
      "description": "Refused with a located message: anchors, aliases, the merge key `<<` (with and without an anchor), tags, custom tags, a second document, directives, duplicate keys (block and flow), `yes/no/y/n/on/off`, `0777`, `0o7`, `0x1F`, `1e3`, `1_000`, `+1`, `.inf`, sexagesimal values, dates, `null`, `~`, an empty value, a non-string key, numeric and boolean keys, tab indentation,...",
      "confidence": 0.9,
      "proposed_next_action": "accept_risk",
      "defect_class": "code_behavior",
      "location": {
        "path": "policies/security.yaml",
        "line_start": 14,
        "line_end": 37
      },
      "reproduction": {
        "kind": "test",
        "detail": "`cargo test --manifest-path scratchpad/exp/Cargo.toml --test yaml -- --nocapture`."
      }
    },
    {
      "finding_id": "f-28",
      "severity": "info",
      "category": "performance",
      "title": "The schema engine refuses unknown keywords and its work is bounded",
      "description": "Compile-time refusal of unsupported keywords means no schema keyword is silently ignored; the only annotations it ignores are listed in its documentation, and the schemas use `format` once (F-22). `uniqueItems` is linear (hash of a canonical text). Timings on 120 KB and 270 KB documents with 40,000 and 90,000 empty objects (each failing a `required` rule inside an `anyOf`):...",
      "confidence": 0.85,
      "proposed_next_action": "accept_risk",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/contracts/src/schema_engine.rs"
      }
    },
    {
      "finding_id": "f-29",
      "severity": "info",
      "category": "correctness",
      "title": "The domain state machines equal state-machine.json and the crate does no I/O",
      "description": "The conformance test compares states, events, transitions, guards, actors, the defect matrix, the human rework routes and the invalidation rows with the JSON in both directions; 22 of 22 pass, and 19 property tests pass. The domain sources contain no `std::env`, `std::fs`, `std::io`, clock, randomness or `HashMap` iteration (one `HashSet` used for a uniqueness test)....",
      "confidence": 0.85,
      "proposed_next_action": "accept_risk",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/domain/tests/state_machine_conformance.rs"
      },
      "reproduction": {
        "kind": "test",
        "detail": "`cargo test --offline -p factory-domain`."
      }
    },
    {
      "finding_id": "f-30",
      "severity": "info",
      "category": "correctness",
      "title": "LeaseEpoch::next saturates instead of failing",
      "description": "At `u64::MAX`, `next()` returns the same value, so the fencing counter would stop being monotonic. The value is not reachable in practice.",
      "confidence": 0.9,
      "proposed_next_action": "accept_risk",
      "defect_class": "code_behavior",
      "location": {
        "path": "crates/ports/src/store.rs",
        "line_start": 116,
        "line_end": 119
      }
    },
    {
      "finding_id": "f-31",
      "severity": "info",
      "category": "correctness",
      "title": "The edge rules DEP-01, DEP-02, DEP-03 and DEP-08 held against my mutations",
      "description": "Adding `factory-sandbox` to the `runtime` crate gave `error[DEP-01]` and `error[DEP-02]`. The 41 dependency-rule fixture tests pass. I did not try a path or git dependency under an allowed crate name; `deny.toml` is the control for sources and I did not run `cargo deny`.",
      "confidence": 0.8,
      "proposed_next_action": "accept_risk",
      "defect_class": "code_behavior",
      "location": {
        "path": "xtask/src/topology.rs"
      }
    }
  ],
  "confidence_overall": 0.8,
  "residual_risks": [
    "No PostgreSQL, Docker or GitHub adapter exists, so every finding about them rests on reading code, schemas and documents, not on a failing run.",
    "I did not run cargo deny, cargo audit or the schema validation script, and I did not review the security documents, the observability crate or the applications."
  ]
}
```
