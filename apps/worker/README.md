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
| `tests/domain_discovery.rs` | what the engine does for a stage with no handler, and the skip option |
| `tests/engine_scenarios_on_postgres.rs` | 13 of the engine scenarios, with the lease waits real |
| `tests/engine_scenarios_all_on_postgres.rs` | the engine suite on PostgreSQL: 96 of 97 (from the parity work) |
| `tests/known_defects.rs` | defects of the engine and the store, as tests that flip when fixed |

The tests of the composition core (`tests/database.rs`, `tests/profiles.rs`, the ledger, the seams over
the store, the providers, the example configurations) are in `crates/composition/tests/`.

## How far the job gets

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
| first three, constitution committed | `PASSED` | `PASSED` | `WAITING_FOR_HUMAN` after 2 `FAILED` attempts | `WAITING_FOR_HUMAN` |

**Where it stops and why.**

1. **No constitution.** The fixture has no `.specify/memory/constitution.md`. The stage asks a person.
   Nothing in the pipeline writes a constitution: the writer agent is granted `speckit.specify`,
   `speckit.clarify` and `speckit.checklist` (`agents/specification-writer/manifest.json`), the fourth
   operation, `SpecOperation::Constitution`, is run by no stage, so the grant the README once listed is
   not missing from a manifest, it is missing from a flow. Owner of the fix: the architect (who writes
   the constitution and when) and `agents/**` if a stage is to run the skill.
2. **A constitution, and the skills write nothing.** The scripted runtime writes no Spec Kit files. The
   stage fails with the closed error `Sandbox` twice, and the engine asks a person (the attempt limit,
   ADR 0010). The stage maps several causes to that one value, so the smoke cannot see which; the likely
   one is that the fixture repository has no Spec Kit installation (`.specify/` with the pinned files), which
   the provider checks before it trusts a skill's output, and which no stage installs. Not verified. To
   pass the stage the runtime must be scripted to write a feature directory; the engine suite does that
   over a scripted provider (`crates/workflow/tests/specification/rig.rs`), which cannot be reused here.
3. **Later stages** need their wiring: `DOMAIN_DISCOVERY` has no handler; `ARCHITECTURE` and
   `TASK_PLANNING` need `RiskSource` and `RoundSource` (done) and agent output the scripted runtime does not
   write; `IMPLEMENTATION` needs `TaskLedger` (done); `VALIDATION` needs the sandbox to run the verify
   image; `DELIVERY` needs the change host and two methods of `DeliverySources` that fail closed;
   `APPROVAL` needs `ApprovalSources` (done). The engine suite runs all 13 stages with scripted handlers
   and reaches `COMPLETED`; what the real handlers add is the stage-to-stage content, and none of those
   stages was reached with a real handler.

**The real Docker sandbox.** The three pinned images (`factory-sandbox/agent`, `.../egress-sidecar`,
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
`SLICE_ONE_SCOPE` contains it, but `crates/workflow/src/stages/domain_discovery/mod.rs` is a placeholder.
**The engine refuses to admit a job whose scope names a stage with no handler** (`admit_job` answers
`EngineError::NoHandler(DomainDiscovery)` and the job stays `RECEIVED`), so a full-scope job cannot run
until the stage has a handler. **The engine does support a stage that does not apply**: a handler's
`applicability` returns `NotApplicable(SkipRule)`; the run becomes `SKIPPED` with the rule in the ledger, and
ADR 0010 lets a skipped run satisfy the stages that need it and the completion of the job.
`tests/domain_discovery.rs` shows both. **The smallest correct option** is a handler of about thirty lines
whose `applicability` returns `NotApplicable` with the basis `DomainProfile`, the rule
`static-general-software-profile` and the input "Slice 1 resolves one static profile, general-software". It
drops the stage's second duty (the tool capability probes with a BLOCKED outcome), so the owner and the
architect must accept that or write the real stage. This crate writes neither.

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
| `GateContext` reading engine-stored documents | **not fixable here** | | see "Cross-stage mismatches", 14 |
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
5. **`Authority::admission(tenant, requester)` carries no repository. Open.** `repository_registered_and_enabled`
   and `protection_preflight_passed` cannot be read and the per-repository caps cannot be applied;
   `StoreAuthority` answers `true` and `false` (the safe side, L0 only) and uses the tenant-wide sum.
   *Smallest change, owner `workflow` (`commands::Authority`):* add the `RepositoryId` to `admission`.
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
12. **`DOMAIN_DISCOVERY` has no handler** and is in `SLICE_ONE_SCOPE`. See "How far the job gets".
13. **Decisions made here that need review:** the allowlist file format; the three lists in `sandbox_specs`
    (lowest user id 10000, forbidden and allowed environment names); the sidecar alias `egress`; the job
    tokens are registered with the redactor under the kind `job_tokens`; the default per-task retry limit
    of the ledger (two; no policy file names one); the meaning of "approved" in the ledger sentence the
    specification approval seam reads; the revision reason sentence; `local` and `test` profiles accept
    `AppArmor` being unavailable on the host.
14. **A stage's gate cannot read the documents the engine stored from its output. Open, confirmed on
    PostgreSQL** by `crates/composition/tests/gate_reads_outputs.rs` (a known-defect test that flips when
    fixed). The engine `put`s the outputs and indexes them for the tenant only in the transaction that
    follows the gate, so `ArtifactStore::get` answers `NotFound` inside `evaluate`. A wrapper in this crate
    would have to serve a blob the tenant has not indexed, which turns the cross-tenant rule off.
    *Smallest change, owner `workflow` (`engine/attempt.rs`, `Engine::produce`):* call `index_declared` for
    every stored output and for the attempt manifest before the `GateContext` is built.
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
