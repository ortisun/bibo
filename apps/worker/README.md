# factory-worker

The worker is a binary in ring 3 ([ADR 0002](../../docs/adr/0002-workspace-layout-and-dependency-rule.md)).
It chooses the adapters, wires them to the engine and runs the engine loop: claim, run a stage
attempt, sweep leases and deadlines, wait. It also hosts the model broker listener.

The composition core that the API and the operator CLI share is **not in this package**. Since the
second part of work package `s1-apps-composition` it is the library crate
[`factory-composition`](../../crates/composition/README.md) ([ADR 0015](../../docs/adr/0015-composition-library.md)).
This package keeps what only a process that claims work needs.

The package is a library (`src/lib.rs`, crate `factory_worker`) and a thin binary (`src/main.rs`).

## Where things are

| Module | What it holds |
|---|---|
| `boot` | Start-up of the worker: the shared checks (`factory_composition::assemble::prepare`), then the broker listener, then the check that every kind of secret the policy lists has a value |
| `broker_host` | Hosts the model broker listener in the worker's process |
| `run` | The worker loop |

Everything else that this README used to list here (`config`, `profile`, `registry`, `startup`,
`redaction`, `database`, `health`, `telemetry`, `system`, `seams`, `authority`, `sandbox_specs`,
`indexing`, `assemble`) is in `crates/composition/src/` with the same module names. The tests moved
with them: `tests/database.rs` and `tests/profiles.rs` are in `crates/composition/tests/`, and the
database test support (`tests/support/`) is the one in that crate, included here by `#[path]` so
that there is one provisioning code.

### Reuse by the API and the CLI

`DEP-01` lets an app depend on library crates only, so the core could not stay in a library target
of this binary. [ADR 0015](../../docs/adr/0015-composition-library.md) adds the ring 3 library
`composition`; rule `DEP-11` lets binaries depend on it and nobody in rings 0 to 2, and says it has no
`main`. The API and the CLI depend on `factory-composition` and write their own shell.

## Running it

```text
FACTORY_CONFIG=/etc/factory/worker.yaml factory-worker
```

Exit codes: `0` a clean stop; `1` an engine error or a failed start-up check; `2` the configuration
was refused; `3` BLOCKED (one `BLOCKED: <port or seam>: <reason>` line on standard error for each adapter
or seam method this build cannot assemble); `4` an attempt was abandoned at the end of the drain budget.

Today the binary runs every start-up check (policy, image catalog, redactor, secrets, telemetry, both
database pools with their roles and the schema version, the artifact store, the broker listener, the
secret-kind check) and **assembles the real sandbox, workspace and specification providers**
(`factory_composition::providers`), and then exits with code 3, because four ports need a credential
or a file that does not exist (the agent runtime, the model router, the issue source and the change
host), and two delivery methods fail closed (see "Blocked"). It never starts the loop on a half-built
registry and never fills a hole with a fake: the fakes live in `factory-testkit`, which no binary may
link (`DEP-03`). The loop, the seams and the engine are exercised by the tests, over the real
PostgreSQL store.

### Configuration

The reference is in [`crates/composition/README.md`](../../crates/composition/README.md). Two settings
are new in this part, both under `sandbox`: `remote` (`https_host`, default `github.com`, or `directory`
for a local mirror, which the production profile refuses) and `sidecar_command` (the arguments of the
egress sidecar's program). `artifacts` takes an optional `max_bytes`.

## The worker loop

`run::WorkerLoop` runs on one thread (the engine's futures are not `Send`) and one attempt at a time.
It sweeps when due, claims one attempt (the engine is built with `claim_batch = 1`, so it never holds a
lease it is not running), runs it inside a `factory.job` span, and waits for the poll interval or the
stop request. A stop request (SIGTERM or SIGINT through `system::raise_on_termination`) is checked
before each claim and while waiting. It never interrupts an attempt at once: a running attempt gets
the drain budget to commit its result. If the budget ends first the loop stops waiting, logs an error,
returns the attempt in `LoopSummary::abandoned` and exits with code 4. It does not release the lease,
because the attempt is still in flight in the store: the lease expires and the sweeper of the next
worker moves the attempt to `LEASE_LOST`. So a lease is never abandoned silently.

While an attempt runs, the loop also serves the **evidence-drift** requests of the stage handlers
(`with_drift_pump`): a handler's future is `Send` and the engine's is not, so the delivery stage reports
a changed binding down a channel and the loop, which owns the engine, makes the `apply_change` call.
`tests/drift.rs` shows that, the runs it replaces, and the break where the seam ignores the report.

### Before each claim

The loop runs its hooks (`factory_composition::hooks::BeforeClaim`, in the order they were added) before
every claim. A worker adds two:

1. `seams::RefreshRequests` fills the request cache, because `RequestSource::recorded` must answer
   without waiting while the claim runs, and the contract of a stage is resolved when a job is admitted.
2. `decisions::ClaimWork` ([`crates/composition/src/decisions.rs`](../../crates/composition/src/decisions.rs))
   admits the `RECEIVED` jobs of the tenants the worker serves and applies the decisions that people asked
   for. The API records both and does neither.

For decisions: the API writes the audit record `decision.requested`; `ClaimWork` reads it, checks the
allowlist **again, now, by the numeric GitHub id** of the principal behind the record, and applies it once:
pause, resume and cancel through `Engine::control`; approve, reject and rework through
`ApprovalService::submit`. The record's id is the command id the engine uses, so a repeat is a no-op
(`Duplicate`). When the decision is dealt with, the worker writes a marker for the same job,
`decision.applied` or `decision.rejected`, which the timeline of the API shows. A worker that stops
between the engine's commit and the marker finds the request with no marker, asks the engine whether it
applied that command (`Engine::command_applied`) and writes the marker without touching the job. A refusal
says "the person may not take this decision now" and never which test failed. A decision that cannot be
decided for a reason that may pass (the allowlist file cannot be read, the store is busy) waits and is
rejected with a plain reason after 20 passes. A worker that starts reads the tenant's audit log from the
start, so nothing depends on its memory; for a long log that is one pass over it.

`tests/claim_work.rs` runs the real loop with the hook: a received job is admitted and runs to the
approval, and a loop without the hook never admits it.

`tests/kill_at_every_boundary.rs` kills the worker after and during each of the 13 stages of the Slice 1
scope, over the real store, and a new engine finishes the job: with the engine and store parity work
merged, all 26 cases reach `COMPLETED` after a person's approval.

## Tests and how to run them

```text
cargo nextest run -p factory-composition -p factory-worker          # everything below
cargo nextest run -p factory-worker --test kill_at_every_boundary
cargo nextest run -p factory-worker --test smoke --no-capture        # prints where the job stops
cargo nextest run -p factory-worker --test engine_scenarios_all_on_postgres   # 96 of 97, slow
```

The database tests start a private PostgreSQL cluster from the local binaries, through the same
provisioning code as the storage crate's tests (`#[path]` include of `crates/storage/tests/support`). A
test that cannot get a server panics with `BLOCKED:` and is never a pass. The support code is the one in
`crates/composition/tests/support`, included here by `#[path]`.

| File | What it proves |
|---|---|
| `tests/kill_at_every_boundary.rs` | kill after and during each stage; every case reaches `COMPLETED` |
| `tests/drift.rs` | a changed evidence binding replaces the dependent runs; the loop serves the report while an attempt runs; a seam that ignores it leaves stale evidence (the break) |
| `tests/breaks.rs` | the deliberate breaks of the loop and the sandbox (below) |
| `tests/telemetry.rs` | the real scrubber is in the pipeline; the loop's log line carries the job's correlation id |
| `tests/broker.rs` | the broker listener is hosted, refuses a request with no token, never shows the key |
| `tests/prepare.rs` | the binary's start-up path from files, exit codes 2 and 3 |
| `tests/smoke.rs` | the word-count job, stage by stage, and where it stops |
| `tests/domain_discovery.rs` | what the engine does for a stage with no handler, and the real skip handler over PostgreSQL |
| `tests/claim_work.rs` | the loop with the step before each claim: a received job is admitted and runs; without it, never (the break) |
| `tests/engine_scenarios_on_postgres.rs` | 13 of the engine scenarios, with the lease waits real |
| `tests/engine_scenarios_all_on_postgres.rs` | the engine suite on PostgreSQL: 96 of 97 (from the parity work) |
| `tests/known_defects.rs` | defects of the engine and the store, as tests that flip when fixed |

The tests of the composition core (`tests/database.rs`, `tests/profiles.rs`, the ledger, the seams over
the store, the providers, the example configurations) are in `crates/composition/tests/`.

## How far the job gets

### The complete run (`apps/api/tests/complete_run.rs`)

One `word-count` job, from a signed webhook to `COMPLETED`, in test mode. It lives in the API package
because the workspace rules refuse an edge from one application to another (`DEP-01`), so no test can
link the API server and `WorkerLoop` together; it runs the same steps in a few lines (refresh the
request cache, `ClaimWork`, sweep, claim, run the attempt) and the loop itself is tested here.

Real: PostgreSQL (the API login on the server, the worker and engine logins on the worker side), the
API server on loopback with a bearer token, the signed webhook, the allowlist and policy files, the
engine, `ClaimWork`, the approval service with its judge, the ledger, the composition seams, and the
handlers marked real below. Scripted and labelled: the agent runtime, the sandbox (`cargo` is a program of
the testkit's sandbox), workspaces, code host and issue source (the testkit's fakes), the model broker,
the engine suite's stand-in handlers, and two values that fail closed in the composition library
(`DeliverySources::tree_of`, `current_values`).

| State | Handler | Real or scripted | Result |
|---|---|---|---|
| webhook, `RECEIVED` | the API | real | `202`, a `RECEIVED` job with no text |
| admission | `ClaimWork` and the engine | real | `ACTIVE`, 13 stage runs |
| `INTAKE` | `IntakeHandler` | **real** (the classifier's answer is the recorded valid fixture) | `PASSED`; the stage fetched the issue and stored revision 1 |
| `REPOSITORY_INTELLIGENCE` | `RepoIntelHandler` | **real** over the fake workspace and sandbox | `PASSED` |
| `DOMAIN_DISCOVERY` | `DomainDiscoveryHandler` | **real** | `SKIPPED` by `static-general-software-profile` |
| `SPECIFICATION`, `ARCHITECTURE`, `TASK_PLANNING`, `IMPLEMENTATION`, `VALIDATION`, `REVIEW`, `DOCUMENTING`, `DOCUMENTATION_REVIEW`, `DELIVERY` | the engine suite's scripted handler | scripted | `PASSED` |
| `APPROVAL` | the scripted handler | scripted | `WAITING_FOR_HUMAN` |
| the decision | the API, `ClaimWork`, `ApprovalService`, `judge`, `Engine::decide` | **real** (over a pull request on the fake code host and an `approval-request` the test builds) | `APPROVAL` `PASSED`, job `COMPLETED`; the timeline shows `decision.requested`, `decision.applied` |

**Where it stops being real, and why.** The stages from `SPECIFICATION` to `DELIVERY` and `APPROVAL` are
stand-ins in this run. Each real handler needs the documents the stages before it store and agent output the
scripted runtime does not write; the workflow suite runs them as separate jobs
(`crates/workflow/tests/stage_contracts`), and chaining them in one job is the work that is left. The
specification stage stops at the first skill (see below).

### The smoke (`tests/smoke.rs`)

`tests/smoke.rs` submits a job for `fixtures/repos/word-count` through the store, as the API will, and
drives it with the worker loop and the scripted runtime. **Real**: PostgreSQL with both pools, the local
artifact store, `policies/*.yaml` loaded and hashed, `agents/` through `FileAgentRegistry`, the output
schema check, the allowlist file, `StoreAuthority`, `StoreRequests`, `StoreRepositories`, the sandbox spec
builder checked against a policy derived from the same document, the redactor, the real `IntakeHandler`,
`RepoIntelHandler` and **`SpecificationHandler`** over the real seams (`SpecApprovals`, `SpecDrafts`,
`SpecHistory`, `ReworkSource`) and the real `SpecKitProvider`. **Faked**: the agent runtime (scripted),
the sandbox (the testkit's, running `cargo` as a scripted program), the workspace provider and change host
(over the files of the fixture), the issue source and the broker. The real Docker sandbox and the real git
workspace were not used in the smoke; the reasons are below.

State by state, with the stages in scope:

| Scope | `INTAKE` | `REPOSITORY_INTELLIGENCE` | `SPECIFICATION` | Job |
|---|---|---|---|---|
| first two | `PASSED` (1 attempt) | `PASSED` (1 attempt) | not in scope | `COMPLETED` |
| first three, no constitution | `PASSED` | `PASSED` | `WAITING_FOR_HUMAN` after 1 attempt: `constitution-required` | `WAITING_FOR_HUMAN` |
| first three, constitution committed | `PASSED` | `PASSED` | `WAITING_FOR_HUMAN` after 2 `FAILED` attempts (`Sandbox`) | `WAITING_FOR_HUMAN` |
| first three, installation and constitution committed, file programs in the scripted sandbox | `PASSED` | `PASSED` | `WAITING_FOR_HUMAN` after 2 `FAILED` attempts (`Tool`) | `WAITING_FOR_HUMAN` |

**Where it stops and why.**

1. **No constitution.** The fixture has no `.specify/memory/constitution.md`. The stage asks a person
   (`constitution-required`). **For Slice 1 the constitution is a precondition of the repository that the
   factory only verifies.** No stage runs `SpecOperation::Constitution`, and the writer agent is granted
   `speckit.specify`, `speckit.clarify` and `speckit.checklist` only
   (`agents/specification-writer/manifest.json`). The master prompt says the specification stage should
   "establish or consult" a constitution (line 437) and that the constitution is established once and its
   changes tracked apart from feature requests (line 91); **if it means the factory authors it, a flow must
   run the skill and the manifest must grant it. That is for the lead and the architect to decide.** The
   smoke copies the fixture in memory and adds a constitution, as the stage expects; the fixture directory
   is never edited.
2. **The `Sandbox` error: found.** The stage runs `mkdir -p inputs`, `tee -- inputs/request.md` and, after
   the skill, `rm -f --` in its sandbox, and ends with `Sandbox` when one exits with a code other than 0
   (`run_command`, `stages/specification/run.rs`). The testkit's sandbox answers exit code 127 for any
   program it does not know. So the first command failed, **before** the provider looked at the
   installation: the missing Spec Kit installation was not the cause.
   `smoke_the_sandbox_error_came_from_the_sandbox_not_from_the_installation` shows it: with the
   installation and the constitution committed and no `mkdir`, `tee`, `rm` or `cp` the stage still ends in
   `Sandbox` twice; with those four programs (which succeed and change nothing, labelled a stand-in) it
   ends in `Tool` twice. The `Tool` is the next stop: the scripted runtime has no script queued for the
   first skill, answers `OutputMissing` (which the stage maps to `Tool`) and writes no file. **Not done:** a
   runtime that writes `spec.md`, the checklists and `.specify/feature.json` into the fake workspace
   (`FakeWorkspaceProvider::edit_tree`, which the testkit's runtime cannot call) for the three skills, and a
   scripted reviewer.
3. **A person cannot approve a specification through the API.** `ApprovalService::submit` reads the stored
   `approval-request` of the stage run, which only the `APPROVAL` stage writes, so the specification
   stage's human gate (`specification-approval-needed`, when `human_approval_required` is true;
   `state-machine.json` says `policy_by_risk`) has no path from the API. Smallest fix, owner `workflow`
   and `composition::decisions`: route an approve or reject of a run whose kind is not `APPROVAL` to
   `Engine::decide` after the same authority check, once the policy names the action and designation.
4. **Later stages** need their wiring: `ARCHITECTURE` and
   `TASK_PLANNING` need `RiskSource` and `RoundSource` (done) and agent output the scripted runtime does not
   write; `IMPLEMENTATION` needs `TaskLedger` (done); `VALIDATION` needs the sandbox to run the verify
   image; `DELIVERY` needs the change host and two methods of `DeliverySources` that fail closed;
   `APPROVAL` needs `ApprovalSources` (done). The engine suite runs all 13 stages with scripted handlers
   and reaches `COMPLETED`; what the real handlers add is the stage-to-stage content, and none of those
   stages was reached with a real handler in one job. (`DOMAIN_DISCOVERY` is now a real handler, below.)

**The real Docker sandbox.** (On 2026-10-28 the test passed seven runs out of seven in this worktree, the
retry of a failed creation was never taken and nothing with the test labels was left behind; the earlier
failures could not be reproduced and their cause is still not known. The test stays ignored, since it
needs the Docker daemon and the pinned images; moving it into the default suite for a machine that has
them is the lead's decision. The text below is the earlier finding.) The three pinned images (`factory-sandbox/agent`, `.../egress-sidecar`,
`.../verify`) are on this machine. `crates/composition/tests/docker_sandbox.rs` takes the sandbox that
`providers::assemble` builds, makes a `verify` sandbox from the real policy and the pinned image (no network,
so no address block and no lock on the shared pool), runs `cargo --version` in it, reads the output as the
owning tenant through the indexing wrapper over PostgreSQL, removes the container, and checks that nothing with
its labels (`factory.test=true`, `factory.test.run=<pid>`) is left. **It passed on one run and failed on the
next four**: `docker create` answered "bind source path does not exist" for a directory the test had just made,
for five seconds running (Docker Desktop for Mac, `/host_mnt`). A plain `docker run` over a directory of the
same tree worked. The cause is not found, so the test is `#[ignore]`d with that reason, not counted as a pass
and not deleted; the smoke does not use the real sandbox. **The real git workspace** cannot be mixed with the
fake change host: `REPOSITORY_INTELLIGENCE` takes the base commit from the change host and the workspace takes
it from git, and the two disagree about a commit id.

### `DOMAIN_DISCOVERY`

`state-machine.json` lists it in Slice 1 (`requires: [SPECIFICATION]`, deterministic, "profile resolution and
tool capability probes; BLOCKED when a mandatory profile gate cannot run", human gate never) and
`SLICE_ONE_SCOPE` contains it. The engine refuses to admit a job whose scope names a stage with no handler
(`EngineError::NoHandler`), and supports a stage that does not apply: `applicability` returns
`NotApplicable(SkipRule)`, the run becomes `SKIPPED` with the rule in the ledger, and ADR 0010 lets a skipped
run satisfy the stages that need it and the completion of the job.

**Done for Slice 1 (the lead accepted it).** `factory_workflow::stages::domain_discovery::DomainDiscoveryHandler`
records the skip with the basis `DomainProfile`, the rule `static-general-software-profile` and the reason
"Slice 1 does not profile the domain. It resolves one static profile, general-software, so there is no domain
to discover." It reports fidelity `real` (no collaborator), and `execute` and `evaluate` fail closed.
`tests/domain_discovery.rs` runs it over PostgreSQL and reads the ledger back (no assurance level). No function
of the worker builds the registry of handlers yet: the binary stops at BLOCKED before it would, because the
agent runtime, the router, the issue source and the change host need credentials. When it does, it registers
`DomainDiscoveryHandler::new()` with the others; the complete run (`apps/api/tests/complete_run.rs`) registers
it today.

**Pending the architect.** The stage's second duty, the tool capability probes with a `BLOCKED` outcome when a
mandatory profile gate cannot run, is **not** taken by this handler. It stays with the start-up probes
(`seams::CachedProbes`) and with the router, which refuses a stage whose runtime lacks a capability it needs.
Whether that is enough needs the architect's confirmation, which has not been given. The handler lives in the
workflow stage package, in a file that was a placeholder, which is outside the paths this change was meant to
own; it is reported for that reason.

### The end-to-end `Wiring`

`tests/end_to_end/README.md` offers two ways in; the linked library is the one to take, because the harness
reads the store, the ledger and the audit stream, which a program that prints JSON would have to rebuild.
**Not implemented, and why it is not small.** (1) It cannot be a path dependency of a workspace member: the
harness is a standalone cargo project (`[workspace]` in its manifest), it is not in the rules file, and
`xtask check-architecture` would report an unlisted package and an unlisted edge; a ring 3 library linking
a test harness also points the wrong way. It belongs in a standalone project beside the harness that
depends on both `factory-e2e` and `factory-composition`, which is a second dependency tree to build. (2) Its
body would be two methods, and both end in `Blocked` today: `protection()` reads the protection of the
fixture remote through the GitHub App, and `run()` needs the runtime, the router, the issue source and the
change host. So the first useful step is the project and the two `Blocked` returns that name each missing
item, which `blocked_adapters` and `blocked_seams` already list. `FACTORY_E2E_COMPOSED` is not provided.

## Seams

Every injection trait the stages and the engine declare, with what the composition crate does about it.
All are in `crates/composition/src/`.

| Seam | Status | Type | Reads |
|---|---|---|---|
| `Ticker` | implemented | `system::TokioTicker` | the tokio timer |
| `AgentOutputCheck` | implemented | `seams::SchemaChecker` | the agent's own schema file |
| `ProjectManifestParser` | implemented | `seams::YamlManifests` | the contracts loader |
| `AllowlistSource` | implemented | `seams::FileAllowlist` | the allowlist file, on every call |
| `RequestSource` | implemented | `seams::StoreRequests` | `RequestOps`, with a cache for the synchronous `recorded` |
| `JobRepository` | implemented | `seams::StoreRepositories` | `JobOps`, `RepositoryOps` |
| `CapabilityProbes` | implemented | `seams::CachedProbes` | the probes taken at start-up; the live probe is BLOCKED |
| `AgentSandboxSpecs`, `VerifySandboxSpecs`, `WorkspaceAgentSpecs` | implemented | `sandbox_specs::PolicySpecs` | the policy |
| `Authority` | implemented | `authority::StoreAuthority` | the allowlist and `PrincipalOps` |
| `TaskLedger` | implemented | `ledger::StoreTaskLedger` | `TaskNodeOps`, fenced by attempt and epoch |
| `ReworkSource`, `RoundSource` | implemented | `feedback::StoreFeedback` | stage runs, the ledger, stored gate reports and verdicts |
| `RiskSource` | implemented | `risk::StoreRisk` | the stored intake |
| `EvidenceDrift` | implemented | `drift::ChannelDrift` and `DriftPump` | a channel to the loop that owns the engine |
| `SpecApprovals`, `SpecDrafts`, `SpecHistory` | implemented | `specs::StoreSpecApprovals`, `StoreSpecDrafts`, `StoreSpecHistory` | stage run links, the artifact store, the ledger |
| `ApprovalSources` | implemented | `delivery::StoreApprovalSources` | the principal row, the allowlist, the stored `approval-request` |
| `DeliverySources` | **partly BLOCKED** | `delivery::StoreDeliverySources` | `target` and `ledger` answered; `current_values` and `tree_of` fail closed |
| Workspace patch indexing | implemented | `indexing::IndexingWorkspaces` | wraps the workspace provider |
| `GateContext` reading engine-stored documents | fixed in the engine | `Engine::produce` | see "Cross-stage mismatches", 14 |
| Constitution skill grant | **not in this crate** | | `agents/**` and a flow; see "How far the job gets" |

The approval command parsers (a GitHub comment, command line arguments, a dashboard form) are pure
functions in `commands`; the HTTP and the process arguments stay with the API and the CLI.

## Deliberate breaks

| Break | Caught by |
|---|---|
| The production profile built with a fake adapter, for each of the 25 ports | `crates/composition/tests/profiles.rs`: a registry of fakes is refused for all 25; one fake among real ports is named; the eight seams that report a fidelity are each refused in production and in `local` |
| A seam forgotten at wiring | `profiles.rs::a_seam_forgotten_at_wiring_stops_start_up_and_is_named`: the seam set cannot be built and names the missing seam, so there is no registry and no engine |
| An unfenced `TaskLedger` write | `crates/composition/tests/ledger.rs`: a stale epoch is `Fenced` and writes nothing; the store itself refuses a start with no fence and one with a wrong epoch |
| Stale evidence drift ignored | `tests/drift.rs`: with the real seam the dependent runs are replaced; with a seam that says "done" and tells nobody they stay `PASSED` |
| A patch not indexed for the tenant | `crates/composition/tests/patch_index.rs`: unreadable without the wrapper, readable by its tenant and no other with it, and the wrapper fails closed for an unknown job |
| A config example the parser refuses | `crates/composition/tests/examples.rs`: the API example of the local stack is refused (it names `database.api` and `listen` and lacks the protected checkout); the worker example parses |
| A decision applied twice after a stop | `crates/composition/tests/claim_work.rs` (a stop before the marker, for a pause and for a cancel that ends the job) and `apps/api/tests/complete_run.rs` (the same through the real approval service). Shown by editing the source for the run: with a fresh command id on every attempt four tests fail, and with the already-applied check removed the cancel test fails |
| A decision applied without re-checking authority | `claim_work.rs::break_applying_a_decision_without_rechecking_authority_is_caught`: the same check passes on the real wiring and fails when the hook says yes to everyone and the engine grants every role |
| A received job never admitted | `tests/claim_work.rs::break_a_loop_without_the_step_never_admits_a_received_job` |
| A gate that cannot read the engine's documents | `crates/composition/tests/gate_reads_outputs.rs` (was the known defect; the assertion is flipped) |
| A webhook job with no issue text proceeding | `crates/workflow/tests/intake_repo/webhook.rs`: an issue the host does not return, and an empty one, end the attempt with no prompt; `break_an_issue_source_that_invents_an_issue_lets_the_job_proceed` shows what the defective host does |
| The smoke fixture without the constitution proceeding | `tests/smoke.rs::smoke_stops_at_the_specification_for_a_constitution` |
| Skip the role readiness check, run a tenant transaction on the system pool, forget to index a sandbox output, drop the redactor, ignore SIGTERM | as before: `crates/composition/tests/database.rs`, `tests/breaks.rs`, `tests/telemetry.rs` |

## Cross-stage mismatches

Each was found by running the real pieces together. "Fixed" means fixed inside `crates/composition` or this
package. Statuses were checked on 2026-10-28 against the merged foundation.

1. **Fixed by the parity work.** The engine recorded a gate with no report and the PostgreSQL store refused
   it; the engine now stores a decision report for every gate decision, jobs complete on PostgreSQL, and
   the 26 kill cases reach `COMPLETED`. `tests/known_defects.rs` was flipped by that work.
2. **A sandbox spec under the system temporary directory is refused on macOS.** The policy forbids `/var`
   as a mount source and `std::env::temp_dir()` is below it. Deployment note: workspace and token roots must
   not be under a forbidden source. The smoke keeps its scratch under `target/`.
3. **`WorkspaceAccess::Inspect` cannot be a read-only mount. Open.** `SandboxSpec::validate` refuses a
   read-only workspace under the `agent` profile (`WorkspaceAccessMismatch`, `crates/ports/src/sandbox.rs`),
   checked again on 2026-10-28. Reviewers get the worktree read-write; the tool grants and the workspace
   purpose keep them from changing it. *Smallest change, owner `ports` and `sandbox`:* a workspace purpose
   for inspection whose mounts have `workspace_read_only = true`, and a rule that accepts that in the `agent`
   profile (the reviewer uses `agent` because only that profile reaches the broker).
4. **`RequestSource::recorded` is synchronous. Worked around.** `StageHandler::contract` is, and the engine
   calls it while it claims, for candidates of every tenant. `StoreRequests` answers from a cache filled by
   `refresh(tenants)` and `remember`; the loop refreshes before each claim for `worker.tenants`. A job whose
   request is not cached waits one poll. *Smallest change, owner `workflow`:* put the recorded request hash
   in `ContractContext`, read by the engine while it holds the tenant transaction.
5. **`Authority::admission` carried no repository. Fixed.** It takes the `RepositoryId` now; `StoreAuthority`
   reads the repository's row for `enabled` and `protection_preflight_passed` and counts the repository's own
   jobs against the policy's per-repository caps (`crates/composition/tests/authority_admission.rs`).
6. **`AgentSandboxSpecs::agent_spec` receives only a `JobTokenRef`. Fixed:** `RegisteringBroker` keeps each
   token's secret from `issue` to `revoke`, and the spec builder asks it.
7. **The agent runtimes bind one tenant at construction. Fixed:** `runtimes::TenantRuntimes` stands in front
   of them, makes the runtime of a tenant on first use and finds the tenant of each call in `ActiveJobs`
   (`run` by attempt, `probe` by the one attempt that runs; with none or several it refuses to guess).
   `tests/runtimes.rs` shows the dispatch and the refusal. The assembly of the real adapter itself stays
   BLOCKED on a credential and the tool in the image.
8. **`OutputValidator` reports no fidelity. Open**, checked on 2026-10-28 (`crates/ports/src/registry.rs`), so
   a fake validator cannot be refused by `require_permitted`. *Smallest change, owner `ports`:* add
   `fn fidelity(&self) -> Fidelity` to the trait; the registry then reports it under a new port name.
9. **`s1-telemetry-wiring` has not landed. Open.** `TelemetryConfig::new` still installs the stopgap scrubber
   by default and there is no helper that sets the derived trace context. `telemetry::config_for` passes
   the real scrubber, so a binary of this repository cannot forget it; `job_stretch` opens `factory.job` with
   no remote parent. *Owner `observability`:* the required scrubber argument and a `set_job_parent` helper.
10. **`SandboxError` and `WorkspaceError` have no variant for "the output could not be stored".** The indexing
    wrappers report `Resource::Disk` (sandbox) and `Io(CreateDirectory)` (workspace). *Owner `ports`:* a
    variant for each.
11. **The engine suite on PostgreSQL.** Now run in full from `tests/engine_scenarios_all_on_postgres.rs`
    (96 of 97); `engine_scenarios_on_postgres.rs` keeps the 13 with real lease waits.
12. **`DOMAIN_DISCOVERY` had no handler. Fixed for Slice 1**, with the second duty pending the architect.
    See "`DOMAIN_DISCOVERY`".
13. **Decisions made here that need review:** the allowlist file format; the three lists in `sandbox_specs`
    (lowest user id 10000, forbidden and allowed environment names); the sidecar alias `egress`; the job
    tokens are registered with the redactor under the kind `job_tokens`; the default per-task retry limit
    of the ledger (two; no policy file names one); the meaning of "approved" in the ledger sentence the
    specification approval seam reads; the revision reason sentence; `local` and `test` profiles accept
    `AppArmor` being unavailable on the host.
14. **A stage's gate could not read the documents the engine stored from its output. Fixed in the engine.**
    `Engine::produce` indexes every output and the attempt manifest for the tenant before it builds the
    `GateContext`; a different tenant still gets `NotFound` for the same hash. The engine suite passes in memory
    and on PostgreSQL.
15. **Specification approvals are not bound to the draft by the engine.** `Decision::Approve` records who and
    when, not which draft. `StoreSpecApprovals` binds by time window (an approval counts for the draft that
    was current when it was recorded) using the engine clock and the database clock of one machine.
    *Smallest change, owner `workflow`:* carry the draft hash on the decision.
16. **The delivery stage needs two things that do not exist.** `DeliverySources::tree_of`: no port exposes a
    tree id and only `sandbox` may start `git` (needs `JobRepo::tree_of`, owner `ports` and `sandbox`).
    `DeliverySources::current_values`: the gate definition hash is computed by private code of the validation
    stage (needs a public function there, owner `workflow`). Both fail closed and are listed by `blocked_seams`.
17. **The API example of the local stack is refused by the parser.** It names `database.api` and `listen` and
    lacks `protected_checkout` and `definitions_root`; the API has no configuration type yet (`infra/**` is
    not edited here). The worker example parses. See "What the deployment must do" in the composition README.

18. **Nothing records the protection preflight. Open.** A repository with no passed preflight runs at level L0
    (the store reports L0, ADR 0009), and at L0 `approve_pr` is refused as below its minimum level, so no job of
    such a repository can ever be approved. No process calls `record_protection_preflight`. The complete run
    records it in the database as an administrator would. *Smallest change, owner `workflow` or the worker
    assembly:* read `IssueSource::repository_protection` for each repository, judge it against
    `policies/security.yaml` and record the result before the first job and on a schedule.
19. **The hook set `warnings_decided` to false for every approval. Fixed**, found by the complete run: the
    engine's guard `G_APPROVER_AUTHORIZED` wants it true, so no approval could pass. It is now true when the
    stored request has no open translation warning, and false otherwise. No path of the API records a
    decision about a warning, so an approval with one open is refused. *Open, owner `api`:* an endpoint for it.
20. **A person cannot answer the specification stage's human gate through the API.** See "Where it stops and
    why", item 3.
21. **A job from the API with no `source_ref` cannot pass `INTAKE`.** Intake authorizes the person who applied the
    factory label on an issue, and reads the issue pointer from `source_ref`. A job submitted without one has
    no issue. *Decision for the owner:* require a `source_ref` that names an issue at submission, or give
    intake a way to authorize a request that has none.
22. **The issue of a webhook job lives in an audit subject.** The delivery row holds no issue number, so the
    only record of the issue is the subject `issue <owner>/<name>#<number>` of the audit record
    `job.received_from_webhook`. `StoreRequests` reads it from there (`WEBHOOK_JOB_ACTION`). *Smallest change,
    owner `storage` and `api`:* a column on the job or the delivery.
23. **No test can link the API and the worker loop.** `DEP-01` refuses an edge from one application to another in
    any kind of dependency. *Decision for the architect:* move `WorkerLoop` into `factory-composition`
    (ADR 0015 says the library holds no loop), or add a library crate for tests that wire both.
24. **The intake contract names a webhook job's input by the issue reference.** A job with no text has no hash
    to put in the contract, so the input `original-request` is named by the SHA-256 of
    `github-issue:<owner>/<name>#<number>` until the stage stores revision 1. The contract is stored when the
    run becomes ready; it is not the contract the next attempt resolves after the text exists.

## Blocked

| Port or seam | Reason |
|---|---|
| Agent runtime | a live run needs a model credential and the tool in the agent image |
| Model router | `policies/model_routing.yaml` does not exist |
| Issue source, change host | need a registered GitHub App and its key |
| `DeliverySources::tree_of`, `current_values` | see mismatch 16 |
| The real Docker sandbox, run in a test | the pinned images are present; the one test of it is ignored because the daemon did not see its bind sources on four runs of five (see "How far the job gets") |

Everything about a live provider or live GitHub is BLOCKED and was not attempted.

## Entries for the rules file

Made in this part, with the architect's decision pending ([ADR 0015](../../docs/adr/0015-composition-library.md)):
the `composition` entry, `DEP-11`, the `DEP-08` wording and `composition` in `st_13`. The earlier request for
`signal` in the `tokio` features is applied. The direct dependencies of `factory-composition` are the ones
the worker had (`async-trait`, `serde`, `serde_json`, `thiserror`, `tracing`, `tokio`, `time`, `uuid`) and
the workspace crates; there is no new external crate, and `cargo deny --locked check` passes.
