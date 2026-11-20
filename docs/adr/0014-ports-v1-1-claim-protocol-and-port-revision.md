# 0014: Revise the ports to v1.1: one claim protocol, a complete store, guard-bound transitions, a job-scoped repository, a typed sandbox and check runs

- Status: Accepted by the architect. The defaults marked **pending human confirmation** in "Decisions that need a person" are decided so that work can start. None of them is settled.
- Date: 2026-10-27
- Deciders: software_architect. Schema and migrations belong to the DBA, the Rust belongs to the software engineer, the policy text belongs to the security specialist. This record says what each of them changes and why.
- Related: [architecture review of the foundation](../reviews/architecture-foundation-review.md), [ports-v1.1](../architecture/ports-v1.1.md) (the exact signatures, the finding table and the change tables), [ADR 0001](0001-orchestration-engine.md), [ADR 0003](0003-sandbox-strategy.md), [ADR 0004](0004-event-model.md), [ADR 0005](0005-agent-runtime-adapter-boundary.md), [ADR 0007](0007-persistence-access-and-tenancy.md), [ADR 0008](0008-artifact-store-and-evidence-ledger.md), [ADR 0010](0010-failure-escalation-routing-and-invalidation.md), [ADR 0012](0012-row-level-security-in-slice-1.md), [state machines](../architecture/state-machine.md)

## Context and problem statement

An independent review of commit `c4d7df1` returned CHANGES_REQUIRED and declined to tag `ports-v1`: 31 findings, four blockers, thirteen majors. The workflow engine (`crates/workflow`) was merged afterwards and met the same defects from the other side. Its author kept job bookkeeping in outbox event payloads because the store has no listing, no `not_before`, no way to release a lease and no query for attempts past a deadline. The engine's retry waits for a lease to lapse, because the port's `claim_ready` leaves a lease on the stage run, while the database notes show SQL that never reads a lease. The database author needed the repository id for the installation lookup and a platform scope for rejected webhooks. The ports author defined about forty types the sketches left open. The harness author found no seam for starting git and Docker, and found that the policy forbids the one GitHub permission that branch protection detail seems to need.

All of this lands in one revision, `ports-v1.1`, before any adapter is built on the ports. The cost of changing a port is a trait, a fake and a contract suite today. After the first adapter it is every call site.

I checked each finding against the code before acting. All 31 hold, with three corrections that appear in the finding table of [ports-v1.1](../architecture/ports-v1.1.md): F-01 is right and also understated (the claim cannot work as the port describes it even in principle, see decision 1); two of the engine author's and ports author's observations are already fixed in the code (`SandboxError::Cancelled` exists at `sandbox.rs:739` and `AgentRuntime::run` takes the session at `agent.rs:430`); and the slice plan's sketches are stale on both, which this record also corrects.

## What was checked

On 2026-10-27, from the repository at `4e5a5b6`.

**In the code and the documents (verified by reading, and where stated by running):**

- Every port module, the testkit store fake and change-host fake, the workflow claim, sweeper, admission and payload modules, the migrations 000400, 000500, 000700 and 000800, `docs/database/for-the-storage-crate.md`, `tenancy.md`, `policies/security.yaml` sections 1, 2, 7, 10 and 11, and the specification's requirements.
- The new signatures in [ports-v1.1](../architecture/ports-v1.1.md) were compiled in a scratch crate against `factory-domain` and `factory-ports` at this commit (`cargo check --offline`, Rust 1.98). They compile, including `dyn` use of `Tx`, `SystemTx`, `Workspace`, `JobRepo`, `SandboxSession` and `ProcessRunner`. Nothing was run: the pure functions are `todo!()` in the scratch crate, and the behaviour belongs to the TDD work of the implementing package.
- `schemas/validate.sh` passed 123 of 123 checks after the schema edits (118 before; 5 new examples).
- `render_state_machine.py --check`, `check_crate_rules.py --check` and `check_work_packages.py --check` pass at the end of this change (output in the final report).

**In GitHub's documentation (read on 2026-10-27 at docs.github.com; pages named in decision 7).** Each statement is marked VERIFIED where a page says it and UNVERIFIED where it does not.

| Statement | Status |
|---|---|
| A required status check in branch protection takes a `checks` array of `{context, app_id}`. `app_id` is "The ID of the GitHub App that must provide this check". Omitted, GitHub picks the app that recently provided the check. `-1` allows any app. | VERIFIED (REST branch protection page) |
| "Required status checks can be checks or commit statuses." In the interface you can select an app that recently set a check "as the expected source of status updates", and "If the status is set by any other person or integration, merging won't be allowed." | VERIFIED (About protected branches) |
| Only GitHub Apps can create check runs. Each check run carries an `app` object. | VERIFIED (REST check runs page) |
| A commit status response has `creator`, "any of: null, Simple User". The page names no app or integration identity. There is a limit of 1000 statuses per SHA and context. | VERIFIED as a statement about the page. |
| Whether a status created with an installation token satisfies a requirement pinned to that App's id. | UNVERIFIED. No page read says so. |
| Reading branch protection (`GET .../branches/{branch}/protection`) needs the **Administration** repository permission, read. `GET .../rules/branches/{branch}` and `GET .../rulesets` need **Metadata**, read. `POST .../check-runs` needs **Checks**, write. `POST .../statuses/{sha}` needs **Commit statuses**, write. `GET .../branches/{branch}` needs **Contents**, read. | VERIFIED (permissions-required-for-GitHub-Apps page; 100,000 of its 102,085 characters read) |
| `GET .../rules/branches/{branch}` returns "all active rules that apply", at any level, omits rulesets whose enforcement is `evaluate` or `disabled`, and its `required_status_checks` rule has `integration_id` ("The optional integration ID that this status check must originate from"). The response has no bypass actors. | VERIFIED (REST rules page) |
| `bypass_actors` appears in "Get a repository ruleset" "only if the user has write access to the ruleset". Which App permission that means. | UNVERIFIED |
| The REST "update a pull request" endpoint has no `draft` parameter; "create a pull request" has one. | VERIFIED |
| Marking a draft ready through the API is the GraphQL mutation `markPullRequestReadyForReview`. | UNVERIFIED (the pages read do not name it; the web interface and `gh pr ready` are documented) |
| A webhook signature is `X-Hub-Signature-256`, `sha256=` plus an HMAC hex digest, compared in constant time. `X-GitHub-Delivery` is "a globally unique identifier (GUID) to identify the event". Payloads are capped at 25 MB. | VERIFIED |
| `issue_comment` covers comments on issues and on pull requests. How the payload tells them apart. | The first VERIFIED, the second UNVERIFIED (the page read does not describe `issue.pull_request`) |
| The exact parameter names of the `pull_request` and `required_status_checks` ruleset rules (`dismiss_stale_reviews_on_push`, `require_code_owner_review`, `non_fast_forward`, `deletion`) | UNVERIFIED. The GitHub adapter records one real response as a fixture before it relies on them. |

Not checked: any behaviour of a real GitHub App, Docker daemon or PostgreSQL server. The claim protocol is the DBA's tested recipe (`tests/lease.sql`, 12 rounds of four workers, one winner each) and is not re-run here.

## Decisions

Each decision names the options, the default taken, the reason, and what it costs. The exact Rust is in [ports-v1.1](../architecture/ports-v1.1.md).

### 1. One claim protocol: find in the system scope, start in the tenant scope, the lease lives on the attempt

**The problem.** The port's `claim_ready` runs in a system transaction, raises the stage run's epoch, leaves the status `READY` and returns a stage-run lease. The database cannot do that: the system role may lock and read but not write (ADR 0012, `tenancy.md`), the stage run has no lease columns, and a trigger lets `lease_epoch` change only together with `READY` to `RUNNING`. The tested recipe is two transactions: find a candidate, then in a tenant transaction move `READY` to `RUNNING` with epoch plus one and insert the attempt that carries the lease. A retry then waits for nothing, because the previous attempt is terminal.

**Options.**

1. **Change the migration** to give the stage run lease columns and let the system role write them. Keeps the port, adds a write grant to a cross-tenant role, and contradicts the decision of ADR 0012 section 3 that the system scope only finds work.
2. **Change the port to the tested recipe.** Two methods, one in each scope. The lease belongs to the attempt. The DBA's SQL, the fake and the engine then agree.
3. **One port method that hides both steps** (`claim_ready` as before, the adapter does find plus start internally). The adapter would need a system pool and a tenant pool and the fake would hide the race the real system has.

**Default: option 2.** Three rules, stated once and used by the port, the fake, the SQL and the engine:

- **R1. Where the lease lives.** An attempt holds a lease: `worker`, `epoch`, `lease_expires_at`. A stage run holds only `lease_epoch`, a fencing counter. There is no `StageRun::lease`.
- **R2. How the epoch moves.** `AttemptOps::start_attempt` is the only operation that creates an attempt and the only one that raises the epoch. In one atomic step it checks that the stage run is `READY` at the version the candidate carried, that its job is `ACTIVE` and that `not_before` has passed by the database clock; raises the epoch by one; moves the run `READY` to `RUNNING` (`S03`); and inserts the attempt as number `previous + 1` in `STARTING`, with the lease and the deadline both computed from the database clock. If the epoch is at its maximum the step fails. `LeaseEpoch::next` no longer saturates (F-30).
- **R3. What a fence proves.** A write that carries a `Fence { attempt, epoch, worker }` is rejected with `LeaseFenced` unless the attempt is live (`STARTING`, `RUNNING`, `CANCELLING`) and its epoch is the stage run's current epoch. A heartbeat renews the lease from the database clock and only while the lease has not lapsed. A lapsed lease belongs to the sweeper.

`SystemTx::find_claim_candidates` returns `READY` runs of `ACTIVE` jobs whose `not_before` has passed, with `FOR NO KEY UPDATE SKIP LOCKED`, and reads no lease because a stage run has none. A candidate is a hint. Two workers may find the same one, and `start_attempt` decides: the loser gets `Conflict`.

**Retry and back-off.** The failed attempt is terminal in the same transaction that takes `S05`, so nothing holds a lease while the run waits. `S05`, `S13` and `S17` set `not_before` to the database time plus a delay (`StageRunEffects::not_before_after`). Nothing waits for a lease to lapse.

**Releasing a lease.** There is nothing to release. A candidate that the engine finds and cannot start (quota, router, contract, budget) was never granted anything. To keep it from being found again at once, the engine calls `postpone_stage_run`, which moves `not_before` while the run stays `READY`. It is the only update of a stage run that is not a transition, and it is valid only in `READY`.

**Timers.** `SystemTx::find_due_attempts(reason, limit)` answers the three questions the sweeper has, by the database clock: lease expired (`A07`), deadline passed (`A06`), teardown deadline passed (`A10`). The engine no longer records a deadline in an event payload.

**Cost.** The engine's `claim_next` and `sweep` change, and its tests with them. Two round trips per claim, which the DBA already measured. The fake gains a real race: two fake transactions can find the same candidate.

### 2. A complete store: every table has operations, every insert is idempotent, a commit can be unknown

**Write and read model.** The port gains the operations its tables need and loses the places where the engine kept state in event payloads: `NewJob` and `Job` carry repository, execution mode, autonomy level, pipeline scope and origin; `RequestOps` stores the original request apart from the normalized one (FR-003); `DeliveryOps` records a webhook delivery and says which key found a repeat (FR-040); `RepositoryOps` reads a registered repository and records the preflight; `StageRunOps` lists the stage runs of a job and takes the gate record, the contract hash and the back-off on its transitions; `AttemptOps` lists attempts and takes the failure class, the output hash, the sandbox facts and the teardown grace on its transitions; `TaskNodeOps` creates a plan as one atomic graph with its edges and fences node moves by attempt; `StageArtifactOps` links the artifacts a run consumed and produced (a human answer is an input with the role `human-answer-<n>`, and the attempt window starts at the newest one); `ApprovalOps` records decisions and answers "which approvals still count for this head"; `PrincipalOps` and the two lookups on `Store` match the tables. A listing replaces every payload workaround: `stage_runs_of_job`, `list_attempts`, `list_task_nodes`, `task_dependencies`, `stage_runs_consuming`, `list_jobs`, `read_audit`.

**The outbox is not a read model.** The outbox key `(aggregate, transition, event_type)` leaves no "created" event, which is why admission listed the stage runs in the `job.admitted` payload. Options: add creation events (a migration, a state-machine change and a payload convention), or list rows. **Default: list rows.** Events announce transitions; the engine reads what exists from the tables. The payload keys `stage_runs`, `created_stage_runs`, `replaced_by`, `not_before`, `deadline_at`, `attempt_id`, `failure_class` and `outputs` of `crates/workflow/src/engine/payload.rs` are removed in the revision package. The payload still carries identifiers and the guard clearance (decision 3).

**Audit.** `NewAuditEvent` has the table's shape: actor (human, service, system or anonymous), a dotted action, a subject, a decision (`allow`, `deny`, `record`), a reason, the policy hash, an optional job and stage run, and a correlation id. The store assigns the time, the sequence and the hash chain. An event with no job (a rejected issue, FR-002) is a normal event. The webhook receiver's `webhook.rejected` event, which belongs to no tenant, goes through `Store::record_platform_audit(PlatformScope, event)`, one call that writes one record under the platform tenant. There is no transaction type for the platform tenant, so no job can be created under it through the port. `tenancy.md` asked a person to confirm the platform tenant: that stays open.

**Lookups.** `Store::resolve_token(hash, audience)` and `Store::resolve_installation(installation, repository)` come back to the trait, as the slice plan and the storage notes expect. The second takes the repository id, because one installation covers many repositories. Both return `None` for every miss, so the caller cannot tell why.

**Unknown commit outcome (F-06).** Options: a variant `CommitOutcomeUnknown` plus a way to find out; or document that `Unavailable` may mean either. **Default: the variant and the witness.** Every state-changing engine transaction writes at least one outbox event or audit record and keeps its id. After `CommitOutcomeUnknown` the caller asks `Store::committed(scope, Witness)` and acts on the answer. Inserts are idempotent by id and content (`Inserted { row, created }`), so replaying a decision is safe, and the same id with other content is `Constraint(IdReusedWithDifferentContent)`. A job is also identified by its origin (webhook delivery or caller key), so a second insert with another id returns the first job. A method future that is dropped poisons its transaction: the only safe step is to drop the transaction.

**Caller-chosen times.** `created_at` leaves every `New*` type. The database assigns it. This makes the idempotent comparison exact and ends the question of which clock a row's time came from.

**The system scope cannot write.** `begin_system` returns `Box<dyn SystemTx>`, a read-only type with three methods. `ScopeNotAllowed` disappears from `StoreError` because the wrong call no longer compiles.

**Cost.** The largest change in the revision. About half of `store.rs` and half of the store fake and suite are rewritten. One migration is needed (work package `s1-database-port-alignment`, owner `dba`): the new state machine rows, `stage_runs.failing_set_sha256`, and two nullable attestation columns on `repositories`.

### 3. A transition proves its guard

**The problem (F-11).** `AppliedTransition::plan(from, event, at)` ignores the guard of the table row. `guards::evaluate` returns `Ok(())`. A stage run can be moved to `PASSED` with no guard having run.

**Options.** (a) A `GuardCleared` token that `evaluate` returns and `plan` requires. (b) The store re-checks the guard. (c) Keep the discipline and add a test.

**Default: (a).** `evaluate` returns `GuardCleared { guard, facts_sha256 }`, whose only constructor is private to the guards module. `plan` takes it and fails with `PlanError::WrongGuard` when it is for another guard than the table row names. The engine puts `guard` and `facts_sha256` into the payload of the event that announces the move, so the clearance is part of the stored record. The store cannot check a guard that needs policy and the clock, so (b) is out. A test (c) cannot stop the next author from forgetting.

`G_LEASE_ACQUIRED` contained the fact "the compare and swap succeeded", which is only known after the write. It is restated: the stage run is `READY` at the version the claim read, and the store's single atomic step makes the check and the move one. The engine builds guard facts in one module (`engine/facts.rs`) that its tests attack, instead of in each call site.

**Cost.** Every call of `evaluate` in the engine and every call of `plan` changes. The facts digest needs a stable rendering of each facts struct: `name=value` lines in field order.

### 4. The repository belongs to the job; a workspace belongs to an attempt

**The problem (F-03, F-04).** Nothing can read back what the sandbox wrote, nothing exports a diff, nothing fetches a repository, and the workspace that made a commit is the only one that can push it. The review proposed `WorkspaceId`, `open`, `fetch`, `read_changed_file`, `export_patch` and `read_file_at`.

**Options.** (1) The review's list. (2) Split the object store from the worktree: the job owns a trusted object store; an attempt owns a worktree over it.

**Default: option 2.** Commits live in the job's object store, so they survive any workspace and any restart without a reattach. Concretely:

- `WorkspaceProvider::fetch(job, FetchTarget, branch, cancel)` puts the branch tip into the job's store and returns the commit it fetched. `FetchTarget` is a read credential narrowed to one repository, issued by `ChangeHost::fetch_target`, the mirror of `PushTarget`. `ChangeHost::resolve_branch` is a cheap API read, kept for the checks that ask whether the base moved (ADR 0010).
- `WorkspaceProvider::create(req, cancel)` makes a sparse detached worktree of a commit in that store, for one attempt. The base can be the fetched base or a commit an earlier stage made.
- `WorkspaceProvider::repo(job) -> JobRepo` gives `read_file_at`, `list_at`, `export_patch` and `push`, all against the store. `ReadView::Agent` hides what the rules call hidden; `ReadView::Trusted` does not.
- `Workspace` keeps `mounts`, `ingest`, `commit` and `dispose`. `ingest` loses its base argument: the workspace knows its own.
- `push` sends a commit the factory made in this job, recorded durably in the store (a ref under a reserved namespace), and refuses any other with `NotMadeHere`. It works after a restart and from a different workspace.

**Reading files the sandbox wrote.** `commit` first, then `read_file_at`. The review's `read_changed_file` reads uncommitted bytes through a second path that the committed-tree guarantee does not cover, so it is rejected. The Spec Kit port splits into `run` (skills in the sandbox) and a pure `assemble(files)`: the stage handler stops the sandbox, ingests, commits, reads the files and calls `assemble`. The `spec_adapter` crate reads no file and holds no workspace.

**A diff for the reviewer.** `JobRepo::export_patch(base, head)` returns the unified diff as a stored artifact and the changed paths. The review gate parses it to check that a finding's line is in the diff (SC-008).

**Reattaching (the review's second request).** Not needed. A worker that crashed mid-attempt has a `LEASE_LOST` attempt; the retry gets a fresh worktree of the same base; the orphan worktree is removed by `sweep_orphans`. The only thing that must survive is the commit, and the store keeps it.

**Protected paths from the policy (F-10).** `PathRules` replaces the two glob lists. It carries the policy's five modes (`hidden`, `deny_write`, `append_only`, `additions_only`, `sensitive`), the `!` re-inclusion scoped to its group, and one function `classify(path)` that folds Unicode NFC and case before matching. Every adapter and every fake calls it and none matches globs on its own. `RepoPath::new` also refuses the Unicode-ignorable and 8.3 forms of `.git` that git's own protections target. `additions_only` is checked on the tree diff by counting removed lines. `sensitive` paths are listed on the `IngestedChange` for the semantic checks. The `ports` crate gains one dependency for NFC, `unicode-normalization`, which has no I/O and goes on the `ports` allow list. UNVERIFIED: its current version, licence and `cargo deny` result. It is not in the offline cargo cache I worked from, so the implementer runs `cargo info` and `cargo deny check` before adding it, and if it fails the licence or advisory check the folding moves to a small table in `domain`.

**The verify profile.** `WorkspacePurpose::Verify { holdouts }` makes a read-only checkout of the candidate commit in which the held-out test paths are present and everything else the rules call hidden is not. Build output goes to `/out`.

**Cost.** `Workspace` and `WorkspaceProvider` are rewritten, and the two fakes with them. The engine uses neither yet, so no engine code changes. `s1-workspace-ingestion` is built on this shape.

### 5. The sandbox guard is an allow list, the posture report covers everything

**The problem (F-09, F-14, F-21).** `validate` refused known-bad mount sources and accepted the rest, accepted zero limits, and the posture report compared only `Hardening`. The job token file had to exist before the sandbox did, and no component was allowed to write it.

**Default.**

- **Typed mounts.** A spec holds `SandboxMounts { workspace, caches }` and nothing else. A cache is a name; the host directory behind it is the adapter's. A writable cache is legal only for `fetch_deps`. There is no free-form mount, so the Docker socket cannot be written. `forbidden_mount_sources` stays as a second layer for the two host paths a workspace brings, and those must be absolute and normalized.
- **Limits.** Eight limits are `NonZeroU32`. A zero wall clock and `memory_swap_mb < memory_mb` are rules. I did not run Docker, so the review's statement that Docker reads 0 as "no limit" for memory, CPUs and pids stays unverified here. The type makes the question moot.
- **Posture.** `PostureReport` holds `observed` hardening, `image`, `limits`, `network`, `mounts`, `env` and the self-check. `PostureReport::differences(spec, policy)` is pure and lives in `ports`, so the Docker adapter fills in what `docker inspect` says and the fake can drift any part. `SandboxSpec::expected_mounts()` is the other half.
- **The token file.** `JobTokenMount { secret }` carries the secret, whose `Debug` output is redacted. The sandbox adapter writes it to a tmpfs it controls, mode 0400, mounts it read-only at a fixed path and removes it at teardown on every path, including failure and cancel; `sweep_orphans` removes strays. The engine writes nothing. ADR 0005 said "a read-only file on a worker-side tmpfs"; this says who owns it.
- **Hardening.** `Confinement::NotAvailable` is accepted for AppArmor only when `SandboxPolicy::apparmor_may_be_unavailable` is set, which the development host sets and a production host does not. `Namespace::None` is `ipc: none`. This settles the Docker Desktop case with a recorded reason and no false report.
- **Errors.** `ProvisionFailed` names the stage that failed (`ProvisionStage`) instead of carrying text. `create_verified` takes a cancel signal.

**Cost.** `s1-sandbox-adapter` reads one more document. The posture compare gets its own test table. The fake sandbox can drift limits, network, mounts and environment.

### 6. Agent output is bytes, a failed run still reports, routing can fall back, spend has a seam, processes have one funnel

- **Output as bytes (F-05).** `AgentRunReport.outcome` carries `RawOutput(Vec<u8>)`, at most `max_output_bytes`. `OutputValidator::validate_bytes` is the only path for agent output and for anything read from a file or the network: it refuses a repeated key, an oversize body, deep nesting and a node count over the budget before a parser builds a value, and returns the parsed value with the hash of the exact bytes. `validate_value` stays for values the factory built. The strict parser already exists in `SchemaOutputValidator::parse_and_validate`.
- **A failed run reports (F-08).** `AgentRuntime::run` returns an `AgentRunReport` that always has the transcript, usage and denials the adapter could collect, with the outcome inside. Spend was already recoverable from the broker; the transcript and denials were not.
- **Routing (F-07).** `RoutingNeed` gains `exclude` and `probed`. The router is still a pure function of the policy and its input: the same need with the same exclusions and probe results gets the same decision, and excluding the answer yields another runtime or an error. The engine probes each runtime once per version and image digest and passes the results in.
- **Metering.** `MeteringOps::record_usage(token, delta)` is the seam through which spend reaches a broker. The real broker's relay calls it inside `egress`; the fake runtime calls it on the fake broker. The engine never holds one, and a static check (ST-14) fails a reference in `workflow`, so the engine cannot invent spend. `ModelBroker` gains `revoke_for_job`, which removes tokens whose attempt crashed.
- **A process funnel.** Options: a trait in `ports`, a trait inside `sandbox`, or none. **Default: `ports::process::ProcessRunner` with a closed `Program { Docker, Git }`.** Two packages in `sandbox` start processes (the Docker supervisor and the git workspace) and have disjoint directories, so a shared definition needs an owner, and a closed program list makes "the only crate that spawns" checkable as "the only file that contains `std::process`". The runner clears the environment of the child and takes secrets as `EnvValue::Secret`, which is redacted in `Debug`. The security harness's `FX-SPAWN` trap becomes a `ProcessRunner`.

### 7. GitHub: check runs, protection by rulesets, comments, webhooks, no ready-for-review

- **Check runs, not commit statuses.** The policy wants the required checks pinned to the App. Pinning is by `app_id` (branch protection) or `integration_id` (rulesets). A check run carries the identity of the App that made it, and only an App can create one (both VERIFIED). A commit status shows a user as its creator and no App identity in the documentation read, and I found no page saying a status satisfies a requirement pinned to an App (UNVERIFIED). So `ChangeHost::set_status` is replaced by `publish_check`, one check run per `(commit, name, external_id)`. The permission `statuses: write` is no longer needed. The GitHub adapter proves the pinning against a real repository in its contract test; until then the claim that a pinned required check cannot be satisfied by another actor is a design claim, not a result.
- **Protection preflight without `administration` (F-13).** The policy forbids `administration` and the preflight wants branch protection detail. Reading classic branch protection needs `administration: read` (VERIFIED), and the bypass list is visible only to someone with write access to the ruleset (what that means for an App is UNVERIFIED). **Options:** (A) read rulesets with the Metadata permission, require the factory's checks to be pinned by `integration_id`, and replace the bypass check by a recorded attestation from an organization admin; (B) grant `administration: read`. **Default: A.** B widens the App's reach on every repository, may not expose the bypass list anyway, and breaks the rule that the App never holds `administration`. A repository with only classic branch protection is capped at L0 with a named reason until it has a ruleset, which ADR 0009 item 3 already assumed. This is a risk call: **pending human confirmation**. `ProtectionReport::evaluate(app, factory_checks, attestation)` is a pure function that lists every failed item.
  - **Text that must change** (owners are outside my directories): `policies/security.yaml` `credentials.github_app.permissions_required` loses `statuses: write`, and `repository_requirements` states that the bypass check is attested; `docs/security/secrets-and-credentials.md` sections 3.1 and 3.5; `docs/security/negative-test-catalog.md` NT-MRG-07 gains the variants "classic protection only" and "bypass not attested", and NT-MRG-08 is reworded (below). The exact lines are in [ports-v1.1](../architecture/ports-v1.1.md).
- **Comments (FR-029).** `IssueSource::fetch_comment` returns the comment with its author's numeric id. `label_actor` and `Issue::author` return a `GithubActor { id, login }`: authority is matched on the numeric id (the policy says so), and the old port returned only a login, so nobody could be authorized. That is a defect the review did not list.
- **Webhooks (F-13).** `WebhookVerifier` is a pure port. It checks size, headers, content type and the HMAC against the secrets in the rotation window before anything is parsed or stored, and returns a `VerifiedDelivery`. The `api` binary depends on the port. The `github` crate implements it.
- **Ready for review.** The factory never marks a pull request ready in Slice 1: the autonomy ceiling is L1, and at L1 "a human acts" (NT-MRG-08). The REST update endpoint has no `draft` parameter (VERIFIED), and the GraphQL mutation is unverified here. So there is no method, and the scan that forbids `merge*` also forbids `ready*` and `undraft*`. NT-MRG-08 is reworded to assert that the pull request is still a draft at the end of the Slice 1 run and that the port has no such method. The `secrets-and-credentials.md` table that lists "ready-for-review" under Pull requests: write loses that phrase. **Pending human confirmation** with the test text.
- **`post_comment`** is at least once. The adapter embeds a marker derived from the key and searches for it before posting. The port documentation said "at most once"; ADR 0004 already said no document may claim that.

### 8. The state machine and the schemas

JSON changes, applied in this change, with the Rust that must follow in [ports-v1.1](../architecture/ports-v1.1.md):

- **`S21`, `RUNNING` to `BLOCKED` (`attempt_blocked`, `G_ENVIRONMENT_BLOCKED`).** NT-SBX-14 and NT-GATE-07 expect `BLOCKED` when the daemon is down, the image is missing, the posture differs, the spec is weaker than the policy, a tool is absent or the policy file is unreadable. The engine failed the attempt with `POLICY_DENIED` and escalated, which asks a person to decide something that is not a decision. The adapter's error type decides: `DaemonUnavailable`, `ImageUnavailable`, `PostureMismatch`, `PolicyViolation` and a missing tool are environment causes; `ProvisionFailed`, `Timeout` and `ResourceExceeded` stay retryable. The attempt ends `FAILED` in the same transaction. The order of ADR 0010 gains a row 0.
- **`S22`, `READY` to `WAITING_FOR_HUMAN` (`require_reauthorization`, `G_REAUTHORIZATION_REQUIRED`).** A new `INTAKE` run after an external change must reach a person before any agent reads the new text (NT-AUTHZ-05), and the only existing way to `WAITING_FOR_HUMAN` needed an attempt, a sandbox and a runtime. The alternative, running a throwaway attempt to escalate, spends a sandbox on a refusal.
- **Guard text restated:** `G_LEASE_ACQUIRED` (decision 3), `G_SANDBOX_PROVISIONED` (names facts the engine can know: the provider returned a session, which means the posture matched in every part, the grants are recorded, the probe satisfies the stage, the epoch is current) and `G_UNRECOVERABLE` (built from the stage run listing; after `S06`, `S12` and `S16` it holds by construction, and its value is that a rework which created a newer run first leaves it unmet).
- **Assurance on `GateDecision`.** The handler may propose `AssuranceClaim { level, evidence }`; the engine attaches a level to a ledger entry only from real, current evidence (INV-08, rule 1 of the assurance section). This is a Rust change in `workflow`. No JSON changes.
- **`retry_on` must list `LEASE_LOST` and `TIMED_OUT` (F-20)**, by `contains` in `stage-contract.schema.json`. Without them a worker crash ends in `S06`. The schemas README says tightening a rule needs a new schema version. Nothing has ever been stored under version 1, so I tighten in place and record it here. **Pending human confirmation.**
- **Non-`PASS` findings cite a file and a line (F-17, FR-023, SC-008)** by a rule in `review-verdict.schema.json`: for the verdicts `CHANGES_REQUIRED`, `BLOCK` and `NEEDS_HUMAN`, every finding has `location.path` and `location.line_start`. FR-023 says "each finding"; SC-008 says "every non-pass finding". I follow SC-008 and list the wording question for a human. The review gate adds the check that the line is in the exported patch.
- **`source.url` is an https URL (F-22)** by `pattern`, because the engine does not assert `format`.
- **Not applied, specified:** an agent-output schema for the review verdict (F-26): `verdict`, `summary`, `findings`, `confidence_overall`, `human_question`, `residual_risks`; the engine wraps it into the stored `ReviewVerdict` with `metadata`, `inputs_reviewed` and `saw_builder_self_assessment`. It needs a new `ContractKind`, a domain type and examples, and belongs in the revision package. The outline is in ports-v1.1.

**Migrations.** The state machine tables in the database are generated from this JSON. `S21`, `S22` and the new events need a migration (`docs/database/tools/state_machine_sql.py`). That belongs to the DBA and is in the work package `s1-database-port-alignment`.

### 9. Artifact reads are scoped to the tenant

**Options.** (a) `get(scope, ref)` where the adapter joins the tenant's index row. (b) A proof type that the index lookup returns. (c) Reads through `ArtifactIndexOps`. **Default: (a).** The artifact store implementation lives in the `storage` crate beside the database adapter, so it can read the index row through the same store; a proof type would need a public constructor that any crate could call, which is the weakness we are removing. `get` returns `NotFound` and `exists` returns `false` for a hash the tenant has not indexed. `put` stays tenant-agnostic and stores a blob once; the tenant indexes it in the transaction that uses it. Before indexing, a tenant cannot read what it just wrote, and that is the rule.

### 10. Fakes must be as hard as the thing they stand for, and every check must be shown to fail

The fakes get the rules the database enforces: a job must be `ACTIVE` to start work, one live attempt per stage run, `not_before` honoured, the attempt limit, unique task keys, audit limits honoured, `start_attempt` atomic, a change host that opens a pull request only for a pushed head and tracks pushes, a workspace that survives a restart, a sandbox that can drift every part of the posture, a scripted Spec Kit runner that really runs a tool in the fake sandbox. A `FakeRemote` shared by the fake workspace and the fake change host represents the code host's repository. The missing suites are written: `SpecificationProvider`, `Clock`, `IdGenerator`, `CancelSignal`, `OutputValidator`, `WebhookVerifier`, `ProcessRunner`, `MeteringOps`.

**The rule that makes the suites trustworthy.** Every check of every contract suite must be named in at least one defect table (a fake built with a seeded defect that must fail that check), or carry a waiver with a reason and a trigger. A test (`contract_register`) reads the suite's check list and each defect table and fails if a check is in neither. A second step mutates each rule of each fake in turn and fails on a survivor. The review found 65 of 132 checks never named; those become the first work of the package.

### 11. The architecture checks close the bypasses the review found

Listed exactly in [ports-v1.1](../architecture/ports-v1.1.md), section "Architecture checks". The decisions: a scan reads `cargo metadata` resolved features for `time`, `uuid` and `tokio` and compares them with the allow list, so an adapter cannot enable `time/std` for the domain; the ban list gains the `Path` methods, `std::env`, Unix sockets, `tokio::time`, `OffsetDateTime::now_utc`/`now_local` and the `uuid` generators; an `allow` or `expect` of a DEP-05 lint in an inner crate fails the check; the spawn scan resolves `use ... as` aliases and scans every file the crate's module tree includes, treating a file as test code only under `#[cfg(test)]`; adapters stop being exempt from the external-crate check; `ProcessRunner` makes ST-03 a one-file rule. `TenantScope::new`, `SystemScope::engine`, `PlatformScope::receiver`, `ResolvedPrincipal` construction and `IngestedChange::new` stay public and are guarded by scans that name the crates allowed to call them (ST-13), because Rust cannot restrict a constructor to a named crate. Error enums stop carrying free text: they carry closed rule codes.

### 12. Smaller findings and the documents

Each of F-18 to F-26 and F-27 to F-31 has a row in the finding table. The documents that contradicted the code are corrected in this change: the lock mode (`FOR NO KEY UPDATE`), the status line of `state-machine.md`, the claim in ADR 0011 that a clippy ban on `now_utc` exists, the claim in ADR 0002 that the `uuid` generators were tried, the `ports` crate description, and the stale sketches in the slice plan. The `eleven stages` wording in the specification is listed for a person, because the specification is not mine to edit.

## Considered options for the revision as a whole

1. **Tag `ports-v1` as it is and fix forward.** Every adapter package would be written against types that cannot hold the database's rows. The review's verdict was no-go for this reason.
2. **Revise now, tag `ports-v1.1`.** One package changes the ports, the fakes, the suites and the engine's use of them, and every adapter starts after it. The critical path gets longer by that package. **Chosen.**
3. **Revise in parts, tagging a release candidate.** The review recommends it "only if it carries the same contract suites as the final tag". I agree and record it as an option the lead may take: `ports-v1.1-rc1` after done criteria 1 to 6 of the package (Store, workspace, sandbox, agent), so that the storage and sandbox adapters can start while the GitHub and test-hardening parts finish. It adds a second round of adapter rebasing if the rest moves a type they use. I do not make the call.

## Consequences

- Good: the store can persist what the migrations require, the engine reads rows instead of payloads, and the same claim rule holds in the port, the fake, the SQL and the engine.
- Good: transitions carry their proof, the sandbox spec cannot name a mount of the host, agent output goes through the strict parser, and a failed run leaves its evidence.
- Good: the work packages that build adapters know what they build against.
- Bad: one large package (size XL) sits on the critical path before every adapter, and the workflow engine, already merged, changes again.
- Bad: three JSON changes (`state-machine.json`, two schemas) make the domain conformance and example tests fail until the Rust lands, and the database tests fail until the migration lands. The revision package carries the table of what changes where.
- Bad: the protection preflight now depends on an attestation by a person, which is weaker than an API check and cannot be re-verified by the factory.
- Neutral: the `ports` crate gets one pure dependency (`unicode-normalization`).

## Confirmation

- Every contract suite passes against its fake and against each seeded defect, and `contract_register` shows no check outside the defect tables. (F-16)
- The same store suite passes against the fake and against PostgreSQL in `s1-storage-postgres`, including: `start_attempt` races, a job that is not `ACTIVE` is not started, a second live attempt is refused, an unknown commit outcome is resolved through `committed`, and a tenant cannot read another tenant's artifact.
- The engine scenarios run on the revised store with no payload workaround, including a crash between `find_claim_candidates` and `start_attempt` and a crash after `start_attempt`.
- The conformance, property and example tests of the domain pass with `S21`, `S22`, the two schema rules and the guard clearance.
- A mutation of each architecture-check bypass in the review fails `cargo xtask check-architecture`.

## Decisions that need a person

Each is decided by default above so that work proceeds. None is settled. A number in brackets is the finding or decision.

1. **Protection preflight by rulesets and an admin attestation, no `administration` permission** (decision 7). Alternative: `administration: read`. Cost of reversing: the policy line, the App registration, and a preflight rewrite.
2. **Check runs instead of commit statuses, and `statuses: write` dropped from the App** (decision 7).
3. **The factory never marks a pull request ready; NT-MRG-08 is reworded** (decision 7).
4. **Tighten `stage-contract` and `review-verdict` in place, without a new schema version** (decision 8).
5. **FR-023 versus SC-008:** every finding of a non-pass verdict, or every finding at all (decision 8).
6. **The platform tenant** holds audit events that belong to no tenant (decision 2; `tenancy.md` asked the same).
7. **The specification says eleven stages; the machine has thirteen in Slice 1.** Exact edits are in ports-v1.1 (F-18).
8. **Whether to tag `ports-v1.1-rc1`** after the Store, workspace, sandbox and agent parts (option 3 above).

## Amendments

### Amendment 1 (2026-10-28): a gate decision always rests on a stored report

**What was found.** The worker composition ran the engine on `PgStore` for the first time. No job could reach `COMPLETED`, and an environment block could not be recorded. `Engine::decide` (the approval, `S14`) and the environment-blocked path (`S21`) wrote `GateRecord { report_sha256: None }`. `PgStore::transition_stage_run` refused both as `ConstraintRule::GateRecordRule`. The in-memory store accepted them, so the engine suite passed. A third site had the same flaw and had not been reported: `engine/gate.rs` built its record from the first gate report or the review verdict, and when the gate produced neither (a gate that could not run, evidence the engine refused) the record carried `None` for `PASSED`, `FAILED` and `BLOCKED` alike.

**Which side is wrong: the engine and the fake, not the store.** The evidence:

- `GateRecord::report_sha256` is documented as "the gate report, stored as an artifact. `None` only for `NOT_APPLICABLE`" (`crates/ports/src/store.rs`, ports-v1.1 section 5.2).
- The table of effects in ports-v1.1 section 5.2 says `S08` and `S14` record `PASSED` "with the report", `S09` and `S12` `FAILED` "with the report and `failing_set_sha256`", and `S11` and `S21` `BLOCKED` "with the report". Only `S02` is "no report".
- `docs/database/for-the-storage-crate.md` shows the `S21` statement as `gate_outcome = 'BLOCKED', gate_report_sha256 = $report`.
- The column has a composite foreign key `(tenant_id, gate_report_sha256)` to `artifacts`, so a report is an artifact the tenant holds. The database does not force the column to be non-null (`constraints-and-indexes.md`: "the port types it optional"); the adapter does (`check_effects`), and says so in its module notes.
- The Store contract suite tested "`PASSED` with no gate record at all" and "`PASSED` with a `FAILED` record", never "`PASSED` with a record and no report". The fake therefore drifted from the port without a check failing, and the engine drifted with it.

**Decision.** The store is right. A decision with no document behind it is exactly what the factory forbids: "approved" or "blocked" would be a bare claim, and for a block the cause would be lost with the failed attempt. Making the store accept `None` would legalise decisions made without evidence, against the port's own text. So:

1. The engine stores a small JSON document for every decision that no gate reported, indexes it for the tenant in the transaction that records the decision (as it does for the stage contract), writes the bytes after the commit, and passes the hash as the report. Three kinds exist: `human-approval` (who decided, in which role, which evidence they had seen), `environment-block` (the cause and the failed attempt) and `gate-decision` (the engine's own cause, when a gate gave it nothing to cite). The document holds identifiers, codes and times and no text a person wrote. It never repeats evidence the engine refused. The code is `crates/workflow/src/engine/decision.rs`.
2. The Store contract suite gains three checks, each with a seeded defect in the fake: a gate record names its report except for `NOT_APPLICABLE` (`S08`, `S09`, `S11`, `S14`); a gate report and a contract must be artifacts the tenant holds (the foreign key, which the fake also ignored); and a second stage run of one job, kind and run number is refused. Both stores pass them. The fake now refuses what `PgStore` refuses.

**Cost and what remains.** One small artifact per approval, block or report-less gate decision. The documents are not yet governed by a JSON Schema: a schema needs a Rust type in `factory-domain` and a registration in `factory-contracts`, which this change did not touch. Until then their shape is fixed by `decision.rs` and by the scenarios that read them back.

### Amendment 2 (2026-10-28): a second admission is `Illegal`, decided by the state machine

**What was found.** Admitting a job twice returned `EngineError::Illegal` on the in-memory store and `Store(Constraint(IdReusedWithDifferentContent))` on PostgreSQL. The job was safe either way, but a caller could not tell "already admitted" from a fault of the store.

**Root cause.** `admit_job` inserted the 13 stage runs first and moved the job second. The only thing that stopped a second admission on the in-memory store was the move, which the state machine refuses from any status but `RECEIVED`. PostgreSQL has a unique key on `(tenant, job, stage_kind, run_number)`, so it refused the insert before the move was reached. The in-memory store had no such key: another way the fake was more lenient than the port's tables (ports-v1.1 and migration 000500).

**Decision.** The engine answers `Illegal`, and a store constraint must not be what a caller sees for this case. The job moves first; the state machine is the authority on which statuses can be admitted, and it refuses before a single stage run is planned. The unique key is now part of the contract (`a_second_stage_run_of_the_same_kind_and_number_is_refused`) and of the fake, so the key can no longer be what hides an engine mistake on one store and not the other.
