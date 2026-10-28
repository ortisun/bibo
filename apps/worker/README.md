# factory-worker

The worker is a composition root (ring 3, [ADR 0002](../../docs/adr/0002-workspace-layout-and-dependency-rule.md)).
It chooses the adapters, wires them to the engine and runs the engine loop: claim, run a stage
attempt, sweep leases and deadlines, wait. It also hosts the model broker listener.

This package is the **first part** of work package `s1-apps-composition`. It holds the shared
composition core that the API and the operator CLI will reuse, and the worker. The API
(`apps/api`) and the CLI (`apps/cli`) are later parts and still print "not implemented".

The package is a library (`src/lib.rs`, crate `factory_worker`) and a thin binary (`src/main.rs`).

## Where things are

| Module | What it holds | Reused by the API and the CLI |
|---|---|---|
| `config` | The typed configuration: one YAML file read with the restricted reader of `factory-contracts`, the environment, secrets by file reference | yes |
| `profile` | `production`, `local`, `test`, and the ports each may stand in for | yes |
| `registry` | `PortRegistry`: every adapter in one value, and the check that runs `require_permitted` for every port | yes |
| `startup` | The policy from the protected checkout (hashed), the sandbox image catalog | yes |
| `redaction` | The redactor built from the policy, the registry of the factory's secret values, the telemetry scrubber, the broker wrapper that registers job tokens | yes |
| `database` | The two pools and the two logins (ADR 0012) | yes |
| `health` | Health and readiness as plain data | yes |
| `telemetry` | The telemetry configuration with the real scrubber, and the `factory.job` stretch span | yes |
| `system` | The real clock, identifier source, `Ticker` and shutdown signal | yes |
| `seams`, `authority`, `sandbox_specs` | The seams the stages declare (table below) | yes |
| `indexing` | Indexes sandbox outputs for the tenant when they are written | worker |
| `broker_host` | Hosts the model broker listener | worker |
| `run` | The worker loop | worker |
| `assemble` | Start-up in order, and the list of adapters that are not assembled | yes |

### Reuse by the API and the CLI

The dependency rules do not let an app depend on another app (`DEP-01`: an app may depend on library
crates only), and the rules file lists no composition crate. So the core lives in this package, and
`apps/api` cannot link it yet. Two ways out, both a change to
`docs/architecture/crate-dependency-rules.json` that needs the architect: allow a binary to depend on
a library target of another binary, or add a ring 3 library entry for composition. Until then the
API part would have to copy the modules, which is the wrong answer. The core has no dependency on
anything that is specific to the worker except `run`, `indexing` and `broker_host`.

## Running it

```text
FACTORY_CONFIG=/etc/factory/worker.yaml factory-worker
```

Exit codes: `0` a clean stop; `1` an engine error or a failed start-up check; `2` the configuration
was refused; `3` BLOCKED (one `BLOCKED: <port>: <reason>` line on standard error for each adapter this
build cannot assemble); `4` an attempt was abandoned at the end of the drain budget.

Today the binary runs every start-up check (policy, image catalog, redactor, secrets, telemetry, both
database pools with their roles and the schema version, the broker listener) and then exits with code
3, because the adapters listed under "Blocked" below are not assembled. It never starts the loop on a
half-built registry and never fills a hole with a fake: the fakes live in `factory-testkit`, which no
binary may link (`DEP-03`). The loop, the seams and the engine are exercised by the tests, over the
real PostgreSQL store.

### Configuration

One YAML file. `deny_unknown_fields` is on, so a misspelled setting is an error and not a weaker run.
There is no default for the profile, the two database logins, the protected checkout or the artifact
root. A secret is always a path to a file (`url_file`, `key_file`) that is a regular file, not a
symbolic link, and not readable by group or others; a value in the file that looks like a URL with a
password is refused before decoding. The environment names the file (`FACTORY_CONFIG`), may repeat the
profile (`FACTORY_PROFILE`, refused if it differs) and may replace the log filter (`FACTORY_LOG`).

```yaml
profile: production            # production | local | test
protected_checkout: /srv/factory/protected    # holds policies/, allowlist/allowlist.yaml
definitions_root: /srv/factory/protected      # holds agents/, profiles/, schemas
database:
  tenant: { url_file: /run/secrets/db_worker, login: factory_worker, max_connections: 8 }
  system: { url_file: /run/secrets/db_engine, login: factory_engine, max_connections: 4 }
artifacts: { root: /var/lib/factory/artifacts }
sandbox:
  images_catalog: /srv/factory/protected/infra/sandbox-images/images.json
  token_root: /var/lib/factory/tokens
  workspace_root: /var/lib/factory/workspaces
broker:
  listen: 127.0.0.1:8731
  upstreams:
    - { provider: anthropic, base_url: 'https://api.anthropic.com', key_file: /run/secrets/anthropic }
  prices:
    - { provider: anthropic, model: claude-sonnet-5-5, input: 3000000, cache_write: 3750000, cache_read: 300000, output: 15000000 }
github: { app_id: 1, key_file: /run/secrets/github_app_key }
worker: { name_prefix: worker, poll_interval_ms: 1000, sweep_interval_s: 10, drain_s: 120 }
```

The allowlist is a second file in the protected checkout, `allowlist/allowlist.yaml`, read on every
decision. **The format is decided here** because no document defines one; it needs architect review:

```yaml
version: 1
entries:
  - tenant: 2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60
    github_user_id: 1001
    login: requester-one
    designations: [requester, approver]   # requester operator approver security_approver repo_admin org_admin
    repositories: [org/repo]              # optional
    expires_at: 2027-01-01T00:00:00Z      # optional
```

## Profiles

| Profile | Mode the engine records | A fake is accepted for |
|---|---|---|
| `production` | `production` | nothing |
| `local` | `test` | the agent runtime, router, broker and the GitHub ports |
| `test` | `test` | every port |

The check is `PortRegistry::check(profile)`, which runs `require_permitted` for each of the 17 ports
and lists every refusal. `tests/profiles.rs` builds a registry of the testkit's fakes and shows that
production refuses every one.

## The two pools

`database::connect` reads the two URL files, checks that the login each URL names is the login the
configuration names, registers the URLs and their passwords with the redactor and hands both pools to
`PgStore::connect`, which runs the role query on each and refuses a superuser, a role that bypasses
row-level security, an owner of tables, or a role in the wrong groups, and refuses a database that is
behind the code. A configuration that names one login for both pools is refused
(`two_pools_two_roles`). `tests/database.rs` shows swapped logins and a superuser on either pool being
refused, and that readiness fails when the schema is behind (`health::check_schema`, which compares the
applied migrations with the count `build.rs` took from `migrations/`).

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

`tests/kill_at_every_boundary.rs` kills the worker after and during each of the 13 stages of the Slice 1
scope, over the real store, and a new engine finishes the job. See "Cross-stage mismatches", 1, for why
the end state is the approval and not `COMPLETED`.

## Tests and how to run them

```text
cargo nextest run -p factory-worker                       # everything below
cargo nextest run -p factory-worker production_profile_refuses_fakes
cargo nextest run -p factory-worker two_pools_two_roles
cargo nextest run -p factory-worker telemetry_gets_the_real_redactor job_work_runs_in_a_job_span
cargo nextest run -p factory-worker --test kill_at_every_boundary
cargo nextest run -p factory-worker --test smoke --no-capture
```

The database tests start a private PostgreSQL cluster from the local binaries, through the same
provisioning code as the storage crate's tests (`#[path]` include of `crates/storage/tests/support`). A
test that cannot get a server panics with `BLOCKED:` and is never a pass.

| File | What it proves |
|---|---|
| `src/*` unit tests | configuration rules, profile matrix, registry check, redactor, policy and catalog loading, sandbox specs against the policy |
| `tests/database.rs` | two pools, role refusal, readiness against the schema version |
| `tests/profiles.rs` | production refuses every fake |
| `tests/telemetry.rs` | the real scrubber is in the pipeline; the loop's log line carries the job's correlation id |
| `tests/kill_at_every_boundary.rs` | kill after and during each stage |
| `tests/breaks.rs` | the deliberate breaks (below) |
| `tests/broker.rs` | the broker listener is hosted, refuses a request with no token, never shows the key |
| `tests/prepare.rs` | the binary's start-up path from files, exit codes 2 and 3 |
| `tests/smoke.rs` | the first end-to-end smoke, below |
| `tests/known_defects.rs` | defects of the first meeting of the engine and the store, as tests that flip when fixed |

### The first smoke

`tests/smoke.rs` submits a job for `fixtures/repos/word-count` through the store, as the API will, and
drives it with the worker loop and the scripted runtime. **What is real**: PostgreSQL with both pools,
the local artifact store, `policies/*.yaml` loaded and hashed, `agents/` through `FileAgentRegistry`, the
output schema check, the allowlist file, `StoreAuthority`, `StoreRequests`, `StoreRepositories`, the
sandbox spec builder checked against a policy derived from the same document, the redactor, and the
**real `IntakeHandler` and `RepoIntelHandler`**. **What is faked**: the agent runtime (scripted, with the
valid fixture of the classifier), the sandbox (the testkit's, running `cargo` as a scripted program), the
workspace provider and change host (over the files of the fixture), the issue source, the broker.

**How far it gets**: the pipeline scope of the smoke is `INTAKE`, `REPOSITORY_INTELLIGENCE`. Both stages
pass at the first attempt and the job completes. **Where it stops**: the next stage, `SPECIFICATION`, is
not wired, because its seams (`SpecApprovals`, `SpecDrafts`, `SpecHistory`, `ReworkSource`) are not
implemented in this part, and then `ARCHITECTURE`, `TASK_PLANNING`, `IMPLEMENTATION` and the rest need
`RiskSource`, `RoundSource`, `TaskLedger`, `DeliverySources`, `ApprovalSources` and `EvidenceDrift`.
`DOMAIN_DISCOVERY` has no handler at all (a placeholder file in the workflow crate) and is in
`SLICE_ONE_SCOPE`, so a full-scope job cannot be admitted with real handlers until that is settled.

How the composed wiring is exposed to the end-to-end harness (`tests/end_to_end/README.md`): **not
implemented in this part.** The choice is the linked library: the harness would implement
`runner::Wiring` over `factory_worker::assemble` and the engine, with `default-features = false`,
because the harness reads the store, the ledger and the audit stream, which a program that prints JSON
would have to rebuild. The `FACTORY_E2E_COMPOSED` program contract is not provided. The test-profile
wiring that exists today is `tests/support/engine.rs` and the smoke.

## Seams

Every injection trait the stages and the engine declare, with what this package does about it.

| Seam | Status | Type | Note |
|---|---|---|---|
| `Ticker` | implemented | `system::TokioTicker` | |
| `AgentOutputCheck` | implemented | `seams::SchemaChecker` | over `AgentSchemaLoader` and `AgentSchema::validate_bytes` |
| `ProjectManifestParser` | implemented | `seams::YamlManifests` | YAML or JSON through the contracts loader |
| `ManifestReader` | implemented by the workflow crate | `JsonManifestReader` | the default is JSON only; the validation stage is not wired here |
| `AllowlistSource` | implemented | `seams::FileAllowlist` | file format decided here |
| `RequestSource` | implemented | `seams::StoreRequests` | `recorded` is synchronous: see mismatch 4 |
| `JobRepository` | implemented | `seams::StoreRepositories` | |
| `CapabilityProbes` | implemented | `seams::CachedProbes` | the live probe that fills it is BLOCKED (needs the tool in the image) |
| `AgentSandboxSpecs`, `VerifySandboxSpecs`, `WorkspaceAgentSpecs` | implemented | `sandbox_specs::PolicySpecs` | limits and mounts from the policy; see mismatch 6 |
| `Authority` | implemented | `authority::StoreAuthority` | see mismatch 5 |
| `TaskLedger` | NOT STARTED | | over `TaskNodeOps` with a fence of attempt and epoch; out of budget in this run |
| `ReworkSource` | NOT STARTED | | the engine hands a rework run no feedback; the implementation returns `None` until it does |
| `DeliverySources`, `ApprovalSources`, `EvidenceDrift` | NOT STARTED | | `EvidenceDrift` needs a channel because the engine's futures are not `Send` |
| `SpecApprovals`, `SpecDrafts`, `SpecHistory` | NOT STARTED | | no table holds a spec draft: the store port has no operation for it |
| `RiskSource`, `RoundSource` | NOT STARTED | | |
| Documentation seams | none exist as traits | | the documenting stages take only `ReworkSource` and the shared ones |

### The cross-stage gaps stage authors reported

* **Sandbox output artifacts must be indexed for the tenant at write time**: done for the sandbox
  (`indexing::IndexingSandbox`, with `ActiveJobs` filled by the loop). `tests/breaks.rs` shows the
  output unreadable without it and readable with it, not readable by another tenant, and the wrapper
  failing closed for a job it does not know. **Not done**: the workspace patch
  (`Workspace::ingest`, `JobRepo::export_patch`) has the same gap and no wrapper yet.
* **`GateContext` cannot read documents the engine stored itself before the gate**: not worked on in this
  run.
* **The job branch lineage** (the specification commit is not on the implementation lineage): not
  worked on in this run; it needs the specification stage wired first.
* **The constitution skill is granted to no agent manifest**: not worked on in this run.

## Deliberate breaks

| Break | Caught by |
|---|---|
| The production profile built with a fake adapter | `profiles.rs`: a registry of every testkit fake is refused for all 17 ports; one fake among real ports is named |
| Skip the role readiness check | `database.rs`: a superuser on the tenant pool and on the system pool is refused; swapped logins are refused. The store offers no way to connect without the check |
| Run a tenant transaction on the system pool | `breaks.rs::the_system_pool_cannot_write_a_row`: the engine login gets `permission denied`; and `SystemTx` has no write method |
| Forget to index an output | `breaks.rs::a_sandbox_output_that_is_not_indexed...`: `NotFound` without the wrapper |
| Drop the redactor | `telemetry.rs::telemetry_gets_the_real_redactor`: a configuration built with the stopgap scrubber leaks a registered value; the one `config_for` builds does not |
| Ignore SIGTERM | `breaks.rs`: SIGTERM raises the shutdown signal; a stop request ends an idle loop, lets a running attempt finish inside the drain budget, and reports an attempt that outlasts it (exit code 4) |

## Cross-stage mismatches found at the first meeting

Each was found by running the real pieces together. "Fixed" means fixed inside this package.

1. **The engine records a gate with no report; the PostgreSQL store refuses it.** `Engine::decide`
   (approval, `engine/decide.rs`) and the environment-blocked path (`engine/failure.rs`) write
   `GateRecord { report_sha256: None }` for `PASSED` and `BLOCKED`. The port says a report hash is `None`
   only for `NOT_APPLICABLE`, and `PgStore::transition_stage_run` refuses the move as
   `ConstraintRule::GateRecordRule`. The in-memory store does not check, so the engine suite passes.
   Effects on PostgreSQL: **no job can complete** (completion needs a recorded approval), and **an
   environment block cannot be recorded**, which also hides its cause (the smoke first failed this way).
   Not fixable here; the fix is in the workflow crate: store the approval record or a block report as an
   artifact, index it for the tenant and pass its hash. `tests/known_defects.rs` asserts the refusal.
2. **A sandbox spec under the system temporary directory is refused on macOS.** The policy forbids
   `/var` as a mount source and `std::env::temp_dir()` is below it. The smoke keeps its scratch under
   `target/`. Deployment note: workspace and token roots must not be under a forbidden source.
3. **`WorkspaceAccess::Inspect` cannot be a read-only mount.** `SandboxSpec::validate` refuses a read-only
   workspace under the `agent` profile (`WorkspaceAccessMismatch`). Reviewer and critic agents therefore
   get the worktree read-write; keeping them from changing it is left to the workspace purpose and the
   tool grants. Not fixable here; needs a decision in the ports (a profile or a flag for an inspecting
   agent).
4. **`RequestSource::recorded` is synchronous** because `StageHandler::contract` is, and the engine calls
   `contract` while it claims, for candidates of every tenant. The composition root cannot read the
   database there. `StoreRequests` answers from a cache filled by `refresh(tenants)` and `remember`. A job
   whose request is not cached has no contract and is deferred as `NoContract` until the next refresh.
   The worker loop does not call `refresh` yet, and the worker is not told which tenants it serves.
5. **`Authority::admission(tenant, requester)` carries no repository**, so `repository_registered_and_enabled`
   and `protection_preflight_passed` cannot be read and the per-repository caps of the policy cannot be
   applied. `StoreAuthority` answers `true` and `false` (the safe side, L0 only) and uses the tenant-wide
   sum of the two caps.
6. **`AgentSandboxSpecs::agent_spec` receives only a `JobTokenRef`**, and the spec needs the secret. Fixed:
   `RegisteringBroker` keeps each token's secret from `issue` to `revoke`, and the spec builder asks it.
7. **The agent runtimes bind one tenant at construction** (`RunIo` takes a `TenantScope`; `AgentRunRequest`
   has no tenant), and the worker serves many. A runtime per tenant, or a tenant on the request, is
   needed before the real runtime can be assembled.
8. **`OutputValidator` reports no fidelity**, so a fake validator cannot be refused by `require_permitted`.
9. **`s1-telemetry-wiring` has not landed**: `TelemetryConfig::new` still installs the stopgap scrubber, and
   the trace context for a stretch of work cannot be set (no helper in the observability crate, and the
   OpenTelemetry crates are not a dependency of this package). `telemetry::config_for` passes the real
   scrubber; `job_stretch` opens `factory.job` with no remote parent.
10. **`SandboxError` has no variant for "the output could not be stored"**; the adapter reports the disk
    resource and `IndexingSandbox` does the same.
11. **The engine suite cannot run on PostgreSQL as it stands.** `crates/workflow/tests/engine_scenarios.rs`
    has 94 tests on a `World` built over `InMemoryStore` and a `FakeClock` that also stands for the
    database clock; 48 places move that clock. A real database has its own clock. Running the same suite
    needs `World` to be generic over the store and the lease and back-off tests to wait or to set short
    times. **`engine_scenarios_on_postgres` is not done**; `tests/kill_at_every_boundary.rs` and
    `tests/breaks.rs` cover the claim, lease loss, sweep and retry on PostgreSQL.
12. **`DOMAIN_DISCOVERY` has no handler** and is in `SLICE_ONE_SCOPE` (see the smoke).
13. **Decisions made here that need review**: the allowlist file format; the three lists in
    `sandbox_specs` (lowest user id 10000, forbidden and allowed environment names), which the policy does
    not state; the sidecar alias `egress`; the job tokens are registered with the redactor under the kind
    `job_tokens`.

## Blocked

| Port | Reason |
|---|---|
| Agent runtime | binds one tenant (mismatch 7); a live run needs a model credential and the tool in the agent image |
| Model router | `policies/model_routing.yaml` does not exist |
| Issue source, change host, workspace provider | need a registered GitHub App and its key |
| Sandbox provider | real Docker is available; not assembled in this part |
| Specification provider | not assembled in this part |

Everything about a live provider or live GitHub is BLOCKED and was not attempted.

## Entries the lead must add to the rules file

`docs/architecture/crate-dependency-rules.json` is not owned by this package.

1. `source_scans.dep_05.resolved_features`, package `tokio`: add `signal` to `allowed`. The worker needs
   it for SIGTERM and SIGINT (`tokio::signal::unix`). With that one change `cargo xtask check-architecture`
   passes (checked on a copy). It adds no crate to `Cargo.lock`: `signal-hook-registry` is already there
   as a dependency of tokio.
2. Nothing for `DEP-04`: it applies to library crates, not to apps. The new direct dependencies of
   `factory-worker` are `async-trait`, `serde`, `serde_json`, `thiserror`, `tracing`, `tokio`, `time` and
   `uuid` (all already in the lock at the same versions and features, `uuid` without a generator
   feature) and the workspace crates. `cargo deny --locked check` passes.
3. A decision on reuse (see above) before `apps/api` can link the core.
