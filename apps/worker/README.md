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

The binary runs every start-up check (policies, the routing policy, image catalog, redactor, secrets, telemetry, both
database pools with their roles and the schema version, the artifact store, the broker listener, the secret-kind check),
**assembles the real sandbox, workspace and specification providers** (`factory_composition::providers`), and then builds
the adapters for the outside world from the configuration (`factory_composition::external`): the GitHub issue source and
change host, the agent runtimes (Claude Code and Codex, one dispatcher), the router over the routing policy, the capability
probes, the crates.io registry client and the advisory database date. It never fills a hole with a fake: the fakes live in
`factory-testkit`, which no binary may link (`DEP-03`).

* **With a complete configuration** the worker serves the broker, runs the loop and exits with code 0 when it gets SIGTERM
  (`tests/composed_start.rs`, over a loopback GitHub and registry).
* **With something missing** it prints one line for each item, `BLOCKED: <port>: <configuration key>: <reason>`, and exits
  with code 3. The ports a line can be about are listed in `factory_composition::assemble::blocked_adapters` and
  `blocked_pipeline_inputs`, and the documentation check compares them with `docs/reference/commands.md`.

The engine's job tokens go through `PolicyBroker`, which cuts each request to the stage's models, the stage's ceiling and
what is left of the job's ceiling. A step before each claim (`RevokeEndedJobs`) revokes the GitHub installation tokens of jobs
that are over.

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

For decisions: the API writes the audit record `decision.requested`, ending with a keyed word
(`mac=`) that only the API can make; `ClaimWork` recomputes the word with each key it holds
(`decisions.key_file` and, in a rotation, `decisions.previous_key_file`) and compares in constant time before
it reads anything else in the record, and rejects a record with no word or the wrong one with the fixed
code `not_signed`. The worker's own marker (`decision.applied`, `decision.rejected`) carries a word of its
own, made with the same key over another first line, and the worker counts a request as dealt with only when
the marker that names it has a good word (RR-8); a row that only has the action of a marker is ignored and
recorded once as `decision.marker_ignored`. Records that are not requests it trusts have a budget of their
own, apart from the signed ones (RR-21). It then reads the record, checks the
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
| `tests/prepare.rs` | the binary's start-up path from files, exit codes 2 and 3, and that each BLOCKED line starts with the key to write |
| `tests/composed_start.rs` | the binary with a complete loopback configuration serves the broker, runs the loop and exits 0 on SIGTERM; one key removed gives exit 3 naming it; no routing policy gives exit 1 |
| `tests/composed_broker.rs` | the broker the worker hosts, the routing policy in front of it and the real Claude Code adapter, against a fake provider: attested run, allow-schema refusals, model outside the route, stage and job ceilings |
| `tests/smoke.rs` | the word-count job, stage by stage, and where it stops |
| `tests/domain_discovery.rs` | what the engine does for a stage with no handler, and the real skip handler over PostgreSQL |
| `tests/claim_work.rs` | the loop with the step before each claim: a received job is admitted and runs; without it, never (the break) |
| `tests/engine_scenarios_on_postgres.rs` | 13 of the engine scenarios, with the lease waits real |
| `tests/engine_scenarios_all_on_postgres.rs` | the engine suite on PostgreSQL: 96 of 97 (from the parity work) |
| `tests/known_defects.rs` | defects of the engine and the store, as tests that flip when fixed |

The tests of the composition core (`tests/database.rs`, `tests/profiles.rs`, the ledger, the seams over
the store, the providers, the example configurations) are in `crates/composition/tests/`.

## How far the job gets

### The full run (`apps/api/tests/full_run.rs`)

One `word-count` job from a signed webhook to `COMPLETED` in test mode, with the **real handler of
every stage** of Slice 1: `IntakeHandler`, `RepoIntelHandler`, `SpecificationHandler`,
`DomainDiscoveryHandler`, `ArchitectureHandler`, `PlanningHandler`, `ImplementationHandler`,
`ValidationHandler`, `ReviewHandler`, `DocumentingHandler`, `DocumentationReviewHandler`,
`DeliveryHandler` and `ApprovalHandler`. It does not use the engine suite's scripted handlers for
any stage. It lives in the API package for the reason `complete_run.rs` does (`DEP-01`), runs on a
real PostgreSQL behind the real API server on loopback (the two people's tokens are written to
files and read back, as a command line client reads them), and the person's two decisions go
through `POST /v1/jobs/{id}/decisions`: first the specification draft, then the pull request. The
loop is the same few lines as in `complete_run.rs`, with the evidence-drift pump served next to the
attempt.

**Real:** PostgreSQL, the API, the signed webhook, the allowlist and policy files, the engine,
`ClaimWork`, `ProtectionPreflight`, the approval service and its judge, the ledger, the schema check
of every agent's output, the Spec Kit provider (`SpecKitProvider`) and the installation of this
repository's Spec Kit, the composition seams, and the 13 handlers.

**Scripted and labelled** (each reports itself as a fake, and the run prints which stages used it):

| What | Stand-in | Used by |
|---|---|---|
| The nine agents | the playbook (`apps/api/tests/playbook/`, data in `fixtures/recordings/playbook/word-count/`), played by a runtime that reports fidelity `fake` and writes the files an agent would write into the workspace of its sandbox | every agent stage |
| The sandbox | the testkit's fake, with `cargo` and the tool answering with output **recorded from a real run** of the patched fixture, and `mkdir`, `tee`, `rm` and `cp` that succeed and change nothing | `REPOSITORY_INTELLIGENCE`, `SPECIFICATION`, `VALIDATION`, `DOCUMENTATION_REVIEW` run commands in it; the agent stages run the playbook in it |
| Workspaces and the code host | the testkit's fakes over the files of the fixture, with the patch exported in the shape of `git diff` (`apps/api/tests/full/gitshape.rs`) | all |
| The supply chain's registry and advisory database | `SupplyChainSources::stand_in` (`StandInRegistry` knows no package, `StandInAdvisoryDatabase` says the database is a day old); the ordinary patch adds no dependency, so the gate does not apply. The decisions people record are **not** a stand-in: the pipeline reads them from the ledger, and `apps/api/tests/dependency_run.rs` runs a job whose change adds a dependency through them | `VALIDATION` |
| The administrator's statement that the App is on no bypass list | the tenant's operator, in the rig | `ProtectionPreflight` |

**Real Docker.** The commands that the fake sandbox answers were also run in the real pinned `verify`
image, offline, on the fixture with the playbook's patch: `crates/composition/tests/real_verify_of_the_patch.rs`
(ignored by default like `docker_sandbox.rs`, `BLOCKED` and never a pass without Docker). It passed
three runs of three and left nothing with the test labels. The full run itself does not use Docker:
the real git workspace cannot be mixed with the fake code host (see the paragraph on the real Docker
sandbox below), and a whole-job run on the real sandbox needs the agent stages to run an agent in a
container, which a scripted agent cannot.

State by state, from the run (durations are the sum of the attempts of the stage on one machine):

| Stage | Handler | Real or scripted | Sandbox | Result | Duration |
|---|---|---|---|---|---|
| `INTAKE` | `IntakeHandler` | real handler, scripted agent | fake | `PASSED`, 1 attempt | 0.11 s |
| `REPOSITORY_INTELLIGENCE` | `RepoIntelHandler` | real | fake | `PASSED`, 1 attempt | 0.11 s |
| `SPECIFICATION` | `SpecificationHandler` | real handler, real Spec Kit provider, scripted skills and reviewer | fake | `NEEDS_HUMAN` (draft approval) then `PASSED`, 2 attempts | 1.2 s |
| `DOMAIN_DISCOVERY` | `DomainDiscoveryHandler` | real | none | `SKIPPED` by `static-general-software-profile` | 0 |
| `ARCHITECTURE` | `ArchitectureHandler` | real handler, scripted architect | fake | `PASSED`, 1 attempt | 0.24 s |
| `TASK_PLANNING` | `PlanningHandler` | real handler, scripted planner | fake | `PASSED`, 1 attempt | 0.24 s |
| `IMPLEMENTATION` | `ImplementationHandler` | real handler, scripted builder, two tasks | fake | `PASSED`, 1 attempt | 0.47 s |
| `VALIDATION` | `ValidationHandler` | real, recorded `cargo` output | fake | `PASSED`, 1 attempt | 0.42 s |
| `REVIEW` | `ReviewHandler` | real handler, scripted reviewer | fake | `PASSED`, 1 attempt | 0.25 s |
| `DOCUMENTING` | `DocumentingHandler` | real handler, scripted writer | fake | `PASSED`, 1 attempt | 0.22 s |
| `DOCUMENTATION_REVIEW` | `DocumentationReviewHandler` | real handler, scripted reviewer, recorded tool output | fake | `PASSED`, 1 attempt | 0.33 s |
| `DELIVERY` | `DeliveryHandler` | real, fake code host | none | `PASSED`, 1 attempt | 0.14 s |
| `APPROVAL` | `ApprovalHandler` | real, fake code host | none | `WAITING_FOR_HUMAN`, then `PASSED` by the person's decision | 0.09 s |

The job ends `COMPLETED`, the evidence manifest, the documentation gate report and the pull request
description are stored and readable, and the run asserts, besides completion: the ledger chain
verifies for the job; every gate decision has a stored report the tenant can read; the validation
binding, the implementation result and the approval request agree about the code head, and the pull
request head is the documentation commit above it; the reviewer is another agent than the builder;
the documentation gate ran and passed; the specification came from the Spec Kit writer and only that
agent wrote under `.specify` or `specs`; a set of canary secrets planted in hidden paths of the
fixture reached no stored blob, prompt, log line or audit record; the pull request text passes the
readability gate; and the timeline shows both decisions requested and applied once each.

**Two runs of the same job agree.** The run is repeated and 27 deliverables are compared. The bytes
of 17 differ; with the identifiers (job, stage run, attempt, report), the times and the hashes and
commit ids that follow from them taken out, all 27 agree. What differs is only: UUIDs, timestamps,
the last eight characters of the job id in the feature directory name, every hash of a document
that embeds one of those (the commits, trees, contracts, reports, the manifest), and the sizes and
token estimates of documents that embed a time (a time with microseconds drops its trailing zeros, so
the same time is a character shorter one time in ten, which showed as a one-byte difference in the
record of the review on three runs of five before the comparison took sizes out). Nothing else
differs: the playbook, the policy and the fixture are the same, and the clock of the sandbox is fake.

**Deliberate breaks, shown caught** (all in `full_run.rs`; an eighth refuses an approval of a specification
draft that names another commit than the draft the stage kept, with the code `draft_moved`, and shows the
honest approval working afterwards): a stage that stores a deliverable under
another name (the engine refuses the undeclared name and nothing is stored); a builder patch that
touches `.github/workflows/ci.yml` (the ingestion refuses it, the audit records the denial, the
evidence names the path); a reviewer of the same type as the builder (the review stage refuses an
agent that can write); a documentation README that names an option the program does not have (the
documentation gate fails, the stored report names the option, delivery never starts); a canary secret
in the builder's output (the ingestion refuses it, and the sweep finds it nowhere); a missing evidence
artifact before delivery (the job stops before delivery); an approval given for a stale head (refused,
in the timeline, nothing moves).

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
`tests/domain_discovery.rs` runs it over PostgreSQL and reads the ledger back (no assurance level). The registry
of handlers is built by `assemble_loop` in `apps/worker/src/pipeline.rs`, through
`composition::pipeline::assemble_pipeline`, which registers `DomainDiscoveryHandler::new()` with the others; the
binary calls it as soon as `external_ports` returns the four ports. Until then the binary stops at BLOCKED before it gets there, because the agent runtime,
the router, the issue source and the change host need credentials. The complete run
(`apps/api/tests/complete_run.rs`) registers it today.

**Pending the architect.** The stage's second duty, the tool capability probes with a `BLOCKED` outcome when a
mandatory profile gate cannot run, is **not** taken by this handler. It stays with the start-up probes
(`seams::CachedProbes`) and with the router, which refuses a stage whose runtime lacks a capability it needs.
Whether that is enough needs the architect's confirmation, which has not been given. The handler lives in the
workflow stage package, in a file that was a placeholder, which is outside the paths this change was meant to
own; it is reported for that reason.

### The end-to-end `Wiring` (`FACTORY_E2E_COMPOSED`)

`tests/end_to_end/README.md` offers two ways in: a linked library, or a program that `FACTORY_E2E_COMPOSED` names and that
answers `PROGRAM protection` and `PROGRAM run SCENARIO_ID`. **Neither is provided.** What exists now: the worker can be
assembled from a configuration (`external_ports`), so the program has something to stand on. What is missing, exactly:

1. **A second program.** `factory-worker` takes no arguments, and adding `protection` and `run` to it would change its
   command line (and `docs/reference/commands.md`). A `factory-worker-e2e` binary beside it is the shape that meets the
   contract, and it is small.
2. **`protection`.** It would build the GitHub adapter from the same configuration and print the fields of
   `evidence::ProtectionFacts`. `ports::ProtectionReport` carries the rules of the default branch and the check pins but
   not the number of required approvals or whether the rules bind administrators, and the App's bypass status comes from the
   administrator's statement (`github.bypass_attestations`), not from GitHub. The mapping needs the architect to say which
   `ProtectionFacts` fields are read from GitHub and which are the statement.
3. **`run`.** It has to put an issue on the fixture repository and label it **as the requester**, which is a person and not the
   App (the App holds no permission to create issues or labels). That needs a credential of the requester, which no
   configuration key names yet. It then has to feed the signed webhook to the API, run the loop to a pull request, record the
   approver's decision through the API, and collect `evidence::RunEvidence` (stage runs, ledger, audit stream, timeline,
   texts, contract documents, GitHub's holdings, spans, spend). That collector exists only as test code in
   `apps/api/tests/e2e/`, which no library may link, so it has to move into a library that depends on the harness types. The
   harness is a standalone cargo project outside the workspace, so the dependency has to be declared in the rules file.
4. **The live prerequisites** the harness already checks and names: a model key with a provider-side spend limit, a registered
   GitHub App and its installations, a protected fixture repository with real code owners, the rebuilt agent image, and a
   routing policy the owner has confirmed (production refuses it until then).

Until then `scripts/e2e.sh --scenario E1 --scenario E2` is `BLOCKED` on its own prerequisites, as it was.

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
| `CapabilityProbes` | implemented | `seams::CachedProbes` | the probes taken at start-up (`external::probe_at_startup`), or a declared list in the local and test profiles |
| `AgentSandboxSpecs`, `VerifySandboxSpecs`, `WorkspaceAgentSpecs` | implemented | `sandbox_specs::PolicySpecs` | the policy |
| `Authority` | implemented | `authority::StoreAuthority` | the allowlist and `PrincipalOps` |
| `TaskLedger` | implemented | `ledger::StoreTaskLedger` | `TaskNodeOps`, fenced by attempt and epoch |
| `ReworkSource`, `RoundSource` | implemented | `feedback::StoreFeedback` | stage runs, the ledger, stored gate reports and verdicts |
| `RiskSource` | implemented | `risk::StoreRisk` | the stored intake |
| `EvidenceDrift` | implemented | `drift::ChannelDrift` and `DriftPump` | a channel to the loop that owns the engine |
| `SpecApprovals`, `SpecDrafts`, `SpecHistory` | implemented | `specs::StoreSpecApprovals`, `StoreSpecDrafts`, `StoreSpecHistory` | stage run links, the artifact store, the ledger; a person's approval reaches them through `ClaimWork::with_specification` and the engine (mismatch 26) |
| Protection preflight | implemented | `preflight::ProtectionPreflight` | the code host's protection of the default branch and the administrator's statement (`BypassAttestations`, no production source: mismatch 36) |
| `ApprovalSources` | implemented | `delivery::StoreApprovalSources` | the principal row, the allowlist, the stored `approval-request` |
| `DeliverySources` | implemented, **wired only where the handlers are registered** | `delivery::StoreDeliverySources` | `target` and `ledger` from the store; `tree_of` and `current_values` once `with_repository` gave it the job's object store and the validation configuration (mismatch 35); without it they fail closed |
| Workspace patch indexing | implemented | `indexing::IndexingWorkspaces` | wraps the workspace provider |
| `GateContext` reading engine-stored documents | fixed in the engine | `Engine::produce` | see "Cross-stage mismatches", 14 |
| Constitution skill grant | **not in this crate** | | `agents/**` and a flow; see "How far the job gets" |

The approval command parsers (a GitHub comment, command line arguments, a dashboard form) are pure
functions in `commands`; the HTTP and the process arguments stay with the API and the CLI.

## Deliberate breaks

| Break | Caught by |
|---|---|
| The production profile built with a fake adapter, for each of the 37 ports | `crates/composition/tests/profiles.rs`: a registry of fakes is refused for all 37; one fake among real ports is named; the twenty seams (the sixteen of the stages and the four inputs of the security decisions) are each refused in production, and in `local` unless they stand for an outside service |
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
| Production pointed at an http address; a secret key file readable by group; a missing routing policy; a model outside the route; a configuration with one key missing; the installation tokens of an ended job left live | `crates/composition/src/config.rs` tests (`production_refuses_plain_http_for_every_outside_service`), `crates/composition/tests/external_world.rs` (`a_secret_key_file_that_group_can_read_blocks_the_github_ports_and_says_why`, `each_missing_key_is_named_by_the_blocked_line_it_causes`), `crates/composition/tests/policy_wiring.rs` and `apps/worker/tests/composed_start.rs` (the missing policy), `apps/worker/tests/composed_broker.rs` (the model outside the route), `crates/composition/tests/token_sweep.rs` (tokens revoked once the job is over, and left live without the step) |
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
16. **Fixed by the full run (see 25 to 36).** *Original text:* **The delivery stage needs two things that do not exist.** `DeliverySources::tree_of`: no port exposes a
    tree id and only `sandbox` may start `git` (needs `JobRepo::tree_of`, owner `ports` and `sandbox`).
    `DeliverySources::current_values`: the gate definition hash is computed by private code of the validation
    stage (needs a public function there, owner `workflow`). Both fail closed and are listed by `blocked_seams`.
17. **The API example of the local stack is refused by the parser.** It names `database.api` and `listen` and
    lacks `protected_checkout` and `definitions_root`; the API has no configuration type yet (`infra/**` is
    not edited here). The worker example parses. See "What the deployment must do" in the composition README.

18. **Fixed by the full run: `factory_composition::preflight::ProtectionPreflight`** is a step before each claim, with the production source of the administrator's statement still undecided (36). *Original text:* **Nothing records the protection preflight.** A repository with no passed preflight runs at level L0
    (the store reports L0, ADR 0009), and at L0 `approve_pr` is refused as below its minimum level, so no job of
    such a repository can ever be approved. No process calls `record_protection_preflight`. The complete run
    records it in the database as an administrator would. *Smallest change, owner `workflow` or the worker
    assembly:* read `IssueSource::repository_protection` for each repository, judge it against
    `policies/security.yaml` and record the result before the first job and on a schedule.
19. **The hook set `warnings_decided` to false for every approval. Fixed**, found by the complete run: the
    engine's guard `G_APPROVER_AUTHORIZED` wants it true, so no approval could pass. It is now true when the
    stored request has no open translation warning, and false otherwise. No path of the API records a
    decision about a warning, so an approval with one open is refused. *Open, owner `api`:* an endpoint for it.
20. **Fixed by the full run: `ClaimWork::with_specification` and an engine change** (26). *Original text:* **A person cannot answer the specification stage's human gate through the API.** See "Where it stops and
    why", item 3.
21. **Fixed by the full run: the API refuses it with a 400** (decision below). *Original text:* **A job from the API with no `source_ref` cannot pass `INTAKE`.** Intake authorizes the person who applied the
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

### Found by the full run (25 to 39)

Each was found by running the real handlers together. "Fixed" says where; "Open" says the owner and the
smallest change.

25. **The policy protects `.specify/**` and lists `.specify/feature.json` among the writes of the specify skill. Fixed** in
    `composition::providers::specification_path_rules`: the host refused the pointer, and the specification stage was
    blocked on its first run. The writes the policy lists for that stage, except the one that needs a person's
    exception (the constitution), are lifted for that stage only. *Owner `security`:* confirm that reading the lifted
    writes from `agent_stage_profiles` is the intended way, or add the re-inclusion to the policy file.
26. **An approval of a specification went nowhere. Fixed** in `Engine::decide`: a specification run waits with its draft
    kept aside, and its next attempt reads the approval from the ledger. S14 would have passed a run that had stored
    nothing, so an approval of a specification records the judgment and returns the run to `READY` as S13 does.
    `ClaimWork::with_specification` applies it, bound to the commit of the draft the person names (the hook's answer
    for any other commit is the new reason `draft_moved`). *Owner `architect`:* the state machine document says S14
    for every stage; it needs a sentence for this one. No endpoint lets a person read the draft or the ledger head
    they must name (`head`, `evidence`): *Owner `api`.*
27. **The specification stage handed the engine no transcript to index. Fixed:** the gate could not read the transcripts
    of the skills back, and blocked every run, while the first read of the same transcripts in `execute` quietly found
    nothing (so the check for a skill outside the profile was blind there). `StageContext::note_transcript` lets a
    handler ask the engine to keep any number of transcripts. *Owner `workflow`:* `execute` still ignores a transcript
    it cannot read; it should refuse.
28. **The architecture gate demands a design element for each success criterion (`SC-001`), and the task graph accepts
    only `FR-` ids in `requirement_ids`. Open.** The plan passes without citing them, so the two stages disagree about
    what a requirement is. *Owner `contracts` and `workflow`:* decide whether success criteria are requirements.
29. **The validation stage read the project manifest as JSON only, and every manifest is YAML. Fixed:** `YamlManifests`
    implements `ManifestReader`. Without it the stage reported "the gate definitions could not be read from the
    protected base commit" for a good manifest.
30. **A job's autonomy level was read from the job row, fixed when the job is received, before the first preflight. Fixed**
    for the approval (`StoreApprovalSources::level` reads the repository's effective ceiling now, and so also lowers a
    job whose repository lost its protection). The row itself still holds L0 for such a job. *Owner `architect`,
    `storage`:* decide whether the level of a job should be set at admission.
31. **The documenting stage read back the plan it had just stored, before the engine had indexed it for the tenant,
    and ended with a tool error on every run. Fixed.**
32. **The testkit's `FakeJobRepo::export_patch` is not git-shaped, and the documenting stage treats a patch it cannot
    read as "nothing to document" and passes without calling the writer.** The run proved nothing until the rig wrapped
    the fake (`full/gitshape.rs`). *Owner `testkit`:* give the fake the shape. *Owner `workflow`:* a plan that reads no
    changed file from a patch that lists changes should be refused, not passed as not applicable.
33. **The `verify` sandbox spec set only `HOME`; the first `cargo build` in the real image ended with "Read-only file
    system". Fixed** in `composition::sandbox_specs` (the image README lists what to set).
34. **The README's title of the fixture, `word-count`, fails the readability gate's title rule ("no ordinary word").**
    Any change that touches it must retitle it. The playbook retitles it "Word count". *Owner `readability` rules:*
    treat a compound of ordinary words as words, or the fixture's README should change.
35. **Fixed (AUT-13): `DeliverySources::tree_of` and `current_values` are answered** (`JobRepo::tree_of`, pending
    architect confirmation; `validation::current_values`) where the handlers are registered with
    `StoreDeliverySources::with_repository`, and `composition::pipeline::assemble_pipeline` does that. A binary that
    does not assemble the pipeline, such as the operator CLI, still gets a closed answer, and `blocked_seams` says so.
36. **The production source of the administrator's statement that the App is on no bypass list does not exist.**
    `NoAttestations` fails closed, so a deployment that passes nothing caps every repository at L0. *Owner `architect`
    and `security`.*
37. **Fixed (AUT-13): the registry of handlers is built by `composition::pipeline::assemble_pipeline`.** It builds all
    thirteen handlers, the engine, the approval service, the hook, the protection preflight and the drift channel from
    the configuration (`stages:`, `StageSettings`, with the numbers the stage tests use as defaults and the commit of
    the gate definitions required in production), checks every port against the profile (production refuses every
    stand-in; local lets the model and GitHub side stand in) and names any stage of the engine's scope that has no
    handler. The rig of the full run calls it, so all ten journeys of `apps/api/tests/full_run.rs` run through the
    function the worker calls (`factory_worker::pipeline::assemble_loop`). *What is still not given:* the four BLOCKED
    ports (runtime, router, issue source, change host), the two sources of the dependency gates that no adapter
    implements (`RegistryMetadata`, `AdvisoryDatabase`; `RecordedApprovals` is read from the ledger since the final wiring),
    and the capability probes, which `main` lists with `BLOCKED:` lines and exit code 3 until
    `factory_worker::pipeline::external_ports` returns them.
38. **The reviewer of the code is checked for independence only by what it may do** (`verify_read_only_tools`), not by
    its agent id or role. Configuring the builder as reviewer is caught; configuring a second agent of the same role is
    not. *Owner `workflow`.*
39. **Decision: a job needs an issue.** The API refuses a submission whose `source_ref` is missing, is not
    `owner/name#number`, or names another repository than the job's. The spec says a job is for one accepted issue
    (FR-001, FR-027), and a job with no issue could not pass intake or be delivered.

## Blocked

| Port or seam | Reason |
|---|---|
| Agent runtime | built from `broker.upstreams` and `runtimes`; the live run needs a provider key and the tool in the agent image, which no test here ran (the sandbox in the loopback tests is a labelled stand-in) |
| Model router | built from `policies/model_routing.yaml` and the models `broker.upstreams` enables. Every number in the file still waits for the project owner, so the production profile refuses it |
| Issue source, change host | built from `github`; a live run needs a registered GitHub App, its key and its installations. Never run against the real GitHub |
| `RegistryMetadata`, `AdvisoryDatabase` | built from `registry` and `advisory_database.date_file`. The registry client has never run against the real crates.io, and the stock policy does not list `crates.io` as a host, so production refuses it until a person adds it. An unreadable answer is unknown, and the gate fails closed on unknown |
| `CapabilityProbes` | each runtime is probed in an `agent` sandbox at start-up, and is BLOCKED with the reason when the sandbox cannot be made. The success path ran only against a labelled stand-in session (`runtimes.declare_capabilities` in the local and test profiles takes a declared list) |
| The skills of the specification stage | `external_ports` gives the Claude Code adapter no skill bundle (`spec_skills: None`), which makes the `SPECIFICATION` stage unavailable with the real tool. Building one needs a decision on which of the installed `speckit-*` skills the stage may see (the policy's allowed list) and on how their directory names map to the policy's names |
| The 13-stage `word-count` job over real GitHub, real runtime and real broker, to a draft pull request and a person's approval | not run. The model path (`tests/composed_broker.rs`) and the GitHub path (`crates/composition/tests/external_world.rs`) are each proven over loopback; the stages in between still run only with the scripted runtime in `apps/api/tests/full_run.rs` |
| `DeliverySources::tree_of`, `current_values` | implemented and wired by `assemble_pipeline` (mismatches 35 and 37), so the worker answers them. A binary that does not assemble the pipeline, such as the operator CLI, still gets the closed answer, and `factory-cli probe` lists the two as `BLOCKED:` |
| The real Docker sandbox, run in a test | the pinned images are present; the one test of it is ignored because the daemon did not see its bind sources on four runs of five (see "How far the job gets") |

Everything about a live provider or live GitHub is BLOCKED and was not attempted.

## Entries for the rules file

Made in this part, with the architect's decision pending ([ADR 0015](../../docs/adr/0015-composition-library.md)):
the `composition` entry, `DEP-11`, the `DEP-08` wording and `composition` in `st_13`. The earlier request for
`signal` in the `tokio` features is applied. The direct dependencies of `factory-composition` are the ones
the worker had (`async-trait`, `serde`, `serde_json`, `thiserror`, `tracing`, `tokio`, `time`, `uuid`) and
the workspace crates; there is no new external crate, and `cargo deny --locked check` passes.

Added by `s1-composition-external-world`: `ureq` (features `rustls` only) is a direct dependency of `factory-composition`, for the
crates.io client, declared in the rules file with the same reason as the GitHub adapter. It is already in the resolved tree
through `factory-github` and `factory-egress`, so `Cargo.lock` gains one dependency edge and no package, and
`cargo deny --locked check` passes.
