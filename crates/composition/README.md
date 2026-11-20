# factory-composition

The shared composition core of the factory: what the worker, and later the API and the operator
CLI, are made of before each adds its own shell. A ring 3 **library**
([ADR 0015](../../docs/adr/0015-composition-library.md)). Only binaries in `apps/` may depend on it
(rule `DEP-11`), and it has no `main`, no HTTP route, no handling of process arguments and no loop (the grammar of an approval decision is pure text and lives here).

## Modules

| Module | What it holds |
|---|---|
| `config` | The typed configuration: one YAML file read with the restricted reader of `factory-contracts`, the environment, secrets by file reference |
| `profile` | `production`, `local`, `test`, and the ports each may stand in for |
| `registry` | `PortRegistry`: every adapter in one value, and the check that runs `require_permitted` for every port |
| `startup` | The policy from the protected checkout (hashed), the sandbox image catalog |
| `redaction` | The redactor built from the policy, the registry of the factory's secret values, the telemetry scrubber, the broker wrapper that registers job tokens |
| `database` | The two pools and the two logins (ADR 0012) |
| `health` | Health and readiness as plain data |
| `telemetry` | The telemetry configuration with the real scrubber, and the `factory.job` stretch span |
| `system` | The real clock, identifier source, `Ticker` and shutdown signal |
| `seams`, `authority`, `sandbox_specs` | The seams the stages declare that need no store state: schema check, manifests, allowlist, requests, repositories, probes, spec builders. `sandbox_specs` also holds the address an agent reaches the broker at (`broker_endpoint`: the sidecar by its alias, over http), the directories of a scratch workspace (made when the spec is accepted) and the path of a program the build made (`built_program`) |
| `ledger` | `TaskLedger` over `TaskNodeOps`, fenced by attempt and epoch |
| `feedback`, `risk` | `ReworkSource`, `RoundSource` and `RiskSource`, read from the evidence the engine stored |
| `drift` | `EvidenceDrift` as a channel to the loop that owns the engine |
| `specs` | `SpecDrafts`, `SpecApprovals`, `SpecHistory` |
| `delivery` | `ApprovalSources` and `DeliverySources` (two methods fail closed) |
| `commands` | The pure parsers from a comment, `argv` or a form to an approval command |
| `reading` | Shared reads of stage run outputs, the ledger and the artifact store |
| `providers` | The real Docker sandbox, host-side workspace and Spec Kit provider from the configuration; `specification_path_rules` (the stage's rules with the writes of its skills lifted) and `layer_policy` (the compiled policy the real workspace takes its second look with, with the same writes re-included); `spec_kit_provider` and `spec_kit_installation` from a checkout |
| `runtimes` | One agent runtime that serves every tenant |
| `indexing` | Indexes what a sandbox writes and what a workspace exports, for the tenant, when it is written |
| `hooks` | The work a loop does before it claims (`BeforeClaim`) |
| `preflight` | `ProtectionPreflight`, a step before each claim: for the repository of each waiting job it reads the protection of the default branch from the code host, judges it against the policy and records the result, so that a repository does not run at L0 for ever. The administrator's statement about the bypass list comes from `BypassAttestations`, which has no production source yet (`NoAttestations` fails closed) |
| `decisions` | `ClaimWork`, the step that admits received jobs and applies the decisions people asked for, once, with the allowlist read again by numeric id; the grammar of a decision record shared with the API |
| `decision_signing` | `DecisionKeys`: the keys, read from files, that sign a `decision.requested` record (`at=` and `mac=`, HMAC-SHA256 over the tenant, the person, the event id, the time and the other words) and verify it in constant time, with the previous key accepted during a rotation. The hook applies a request only if its word is right (AUT-12) |
| `pipeline` | `assemble_pipeline`: the thirteen handlers, the engine, the approval service, the hook and the preflight from the configuration (`stages:`), with `PortRegistry::check` for the profile over every port and a refusal of a registry that lacks a handler. The caller gives `ExternalPorts` (runtime, router, issue source, change host, probes, `SupplyChainSources`, the bypass attestations) and the `Providers`; production refuses a stand-in for any of them (AUT-13). The settings of the dependency gates come from the policy (`SupplyChainSettings::from_policy`: the policy is the ceiling, configuration may only lower it), the recorded decisions are read from the ledger (`LedgerApprovals` inside `CurrentApprovals`, never handed in), and the engine is given the blocks the policy says no override may pass |
| `supply_chain` | `SupplyChainSources`: the registry source and the advisory-database date, for which no adapter exists. Production takes `BlockedRegistry` and `BlockedAdvisoryDatabase`, which answer "unknown" so that the gates fail closed; the `local` and `test` profiles take labelled stand-ins, which production refuses (`PipelineError::StandIn`). `CurrentApprovals` keeps a recorded decision only while its person still holds the designation on the allowlist, read at every call |
| `stage_decisions` | A person's decision about a stage run that is not an approval: `unblock` (the operator lets a blocked run go again) and `approve-project-build-code` (a security approver accepts one file of the project's own build code, bound to its path and the hash of its content). The API records `decision.stage_requested`, signed with its own context line; the step reads the stored evidence, asks the policy engine for the proof and calls the engine. The capability re-probe is `NoReprobe` until a probe adapter exists |
| `dependency_decisions` | A person's decision on a new dependency or on its build code (`approve-dependency`, `approve-build-code`): the request the API records (`decision.dependency_requested`, signed with its own context line) and the step of `ClaimWork` that applies it: it reads the evidence the blocked validation run stored, finds the awaited package the words select, asks the policy engine for the proof, redacts the reason (the engine has no redactor) and calls `Engine::record_dependency_decision` |
| `assemble` | Start-up in order (`prepare`: policies, hosts, the routing policy), the ports a missing configuration key can block (`blocked_adapters`, `blocked_pipeline_inputs`) and the seam methods that fail closed (`blocked_seams`) |
| `external` | `assemble_external`: the issue source and change host (`factory-github` over `ureq`), the runtime set (Claude Code and Codex adapters, a tenant at a time), the router, the registry and advisory sources and the capability probes, from the configuration; every item it cannot build comes back as a `BlockedItem` that starts with the configuration key. `probe_at_startup` runs each runtime's probe in an `agent` sandbox. `ConfigAttestations` reads the administrators' statements |
| `policy_broker` | `PolicyBroker`: stands in front of the broker and cuts every token request to the stage's models, the stage's ceiling and what is left of the job's ceiling (all from `policies/model_routing.yaml`) |
| `token_sweep` | `RevokeEndedJobs`: a step before each claim that revokes the GitHub installation tokens of every job that is over |
| `spec_skills` | `bundle_for_writer`: the pinned skills the specification writer may see, built from the Spec Kit installed in the **protected checkout** (never the repository under change): the skills the writer's manifest names, each refused unless the policy allows it and does not deny it, under the directory name the installation's separator gives, and only if the file hashes to the value of the pinned manifest. The same skill of the other host (Codex, under `.agents/skills`) must be the pinned file too: a listed Codex integration with a missing file, a Codex skill that differs, and an installed integration outside the host table are each refused (`SpecSkillsError::HostModified` and `Installation`). The worker passes the bundle to the Claude Code adapter; a checkout that cannot supply it is a `BLOCKED: agent runtime: protected_checkout:` line |
| `crates_io` | The package registry source: a small client for the crates.io API with a timeout, a response cap and a `User-Agent`; anything it cannot read is unknown |
| `advisory` | The advisory database date, read from `advisory_database.date_file` |
| `webhook` | The webhook verifier of the API, built from secret files (one per secret in the rotation window) |

## What the full run needed of it

The full run (`apps/api/tests/full_run.rs`) is the first thing that built all thirteen handlers and ran them in one job. What it
needed from this crate, and what it added:

* `ProtectionPreflight` before `ClaimWork`, in that order, so a job is admitted against a protection judged now.
* `ClaimWork::with_specification(drafts)`, so that a person's approval of a specification draft is applied.
* `StoreDeliverySources::with_repository(workspaces, validation_config)`, so that `tree_of` and `current_values` answer.
* `PolicySpecs::verify_sandbox` and `fetch_sandbox`, the fixed part of the sandboxes the validation and documentation review
  stages carry in their own configuration, with the environment the pinned image needs (`CARGO_TARGET_DIR`, `CARGO_HOME`,
  `CARGO_NET_OFFLINE`, `TMPDIR`).
* `sandbox_specs::agent_build_env`, the build variables of the Claude Code and Codex runs (ADR 0024): the same target and
  temporary directories as the `verify` sandbox, offline, with the cargo home in each run's own home.
* `YamlManifests` as the `ManifestReader` of the validation stage.
* The indexing wrappers (`IndexingSandbox`, `IndexingWorkspaces`) around the sandbox and the workspaces, and the loop noting the
  tenant of each attempt in `ActiveJobs` before it runs it.

The function that builds the registry of handlers is `pipeline::assemble_pipeline` (worker README, mismatch 37). The worker binary
builds the ports that reach the outside world with `external::assemble_external` and passes them in. What the configuration
does not supply it lists as `BLOCKED:` lines that start with the key to write, and stops.

## The outside world, from the configuration

The configuration keys that point at the outside world are in [the reference](../../docs/reference/configuration.md): `github`
(App id, key file, installations, API address, administrators' statements), `broker.upstreams[].models`, `registry`,
`advisory_database` and `runtimes`. Rules the code keeps:

* A secret is a file reference, mode-checked like the others. The App key is read when the adapter is built; an unsafe file
  blocks the issue source and the change host and says which key.
* The production profile reaches the outside world over `https` only, and only hosts the policy lists: the model providers
  against `egress.broker_upstreams`, GitHub against `api.github.com`, the registry against the cargo hosts of the `fetch_deps`
  profile. The stock policy lists `crates.io` (the entry `crates_api`), `index.crates.io` and `static.crates.io`, so the
  registry client can run in production against `https://crates.io`. The local and test profiles also accept plain `http` on the loopback
  interface, and only there.
* The routing policy is loaded with the other policies. A missing file stops the start. The production profile also stops while
  `ModelRoutingPolicy::unconfirmed()` is not empty (every price and ceiling of the file waits for the project owner today).
* Prices come from the policy. `broker.prices` may only raise one.
* `RevokeEndedJobs` revokes the installation tokens of jobs that are over. It lists the open jobs of the tenants the worker
  serves, and revokes nothing in a pass where it cannot list them. Given a bound (`revoking_blocked_after`, from
  `credentials.github_app.installation_token.revoke_when_blocked_after_s`) it also revokes, without ending the job, the
  tokens of a job that has been `BLOCKED` for that long; a job that waits for a person keeps its token (LB-04).

## What a binary does with it

1. Read the configuration: `FactoryConfig::from_environment` or `from_file`.
2. `assemble::prepare(&config, Identity { service, version })` runs the start-up checks and returns
   the policy, the redactor, the registry of secret values, the connected store and the telemetry
   guard.
3. Add what the binary alone needs (the worker starts the broker listener), then
   `Prepared::check_secret_kinds(profile, not_held)`. `not_held` lists the kinds of secret the policy names for
   the factory as a whole that this binary never holds (the worker passes `WORKER_DOES_NOT_HOLD`, the webhook
   secret, which only the API holds): they are skipped, with no warning. A kind the binary holds and lacks is
   still refused in the production profile and logged in the others.
4. Build a `PortRegistry`, call `check(profile)`, and only then build the engine.

## Tests

```text
cargo nextest run -p factory-composition
```

The database tests start a private PostgreSQL cluster from the local binaries through the storage
crate's provisioning code (`#[path]` include of `crates/storage/tests/support`). A test that cannot
get a server panics with `BLOCKED:` and is never a pass.

## Configuration

One YAML file, read with the restricted reader of `factory-contracts`. `deny_unknown_fields` is on, so a
misspelled setting is an error and not a weaker run. There is no default for the profile, the two
database logins, the protected checkout or the artifact root. A secret is always a path to a file
(`url_file`, `key_file`) that is a regular file, not a symbolic link, and not readable by group or others;
a value in the file that looks like a URL with a password is refused before decoding. The environment
names the file (`FACTORY_CONFIG`), may repeat the profile (`FACTORY_PROFILE`, refused if it differs) and
may replace the log filter (`FACTORY_LOG`).

```yaml
profile: production            # production | local | test
protected_checkout: /srv/factory/protected    # holds policies/, allowlist/allowlist.yaml, .specify/
definitions_root: /srv/factory/protected      # holds agents/, profiles/, schemas
database:
  tenant: { url_file: /run/secrets/db_worker, login: factory_worker, max_connections: 8 }
  system: { url_file: /run/secrets/db_engine, login: factory_engine, max_connections: 4 }
artifacts: { root: /var/lib/factory/artifacts, max_bytes: 67108864 }   # max_bytes is optional
sandbox:
  images_catalog: /srv/factory/protected/infra/sandbox-images/images.json
  token_root: /var/lib/factory/tokens
  workspace_root: /var/lib/factory/workspaces
  labels: {}                                # more Docker labels; a test run adds its own
  remote: { https_host: github.com }        # or { directory: /abs/path } outside production
  sidecar_command: []                       # the egress sidecar's arguments
  gateway_upstream: null                    # troubleshooter only: the MCP gateway as the sidecar sees it
  # docker_host: unix:///var/run/docker.sock   # where the Docker daemon is (the client runs with an empty environment)
  # docker_config: /home/factory/.docker       # the client's configuration directory; absolute, must exist
  # allow_remote_docker: false                 # true allows a tcp:// host off the loopback interface; production refuses it
broker:
  listen: 127.0.0.1:8731
  upstreams:
    - { provider: anthropic, base_url: 'https://api.anthropic.com', key_file: /run/secrets/anthropic }
  prices: []                                # the policy is the price list; an entry here may only raise a price
github:
  app_id: 1
  key_file: /run/secrets/github_app_key
  installations: [{ tenant: 2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60, repository: org/repo, installation_id: 1 }]
registry: { base_url: 'https://crates.io', user_agent: 'software-factory (ops@example.org)' }
advisory_database: { date_file: /srv/factory/protected/advisory-database.date }
stages:                                     # optional; the defaults are the numbers the stage tests use
  definition_commit: 1405df66cbe219b0bf6355bc3d60361a8376b6b4   # required in production
  # label: factory
  # budget: { wall_time_seconds: 3600, max_tokens: 2000000, max_cost_usd: 10.0, attempt_timeout_seconds: 3600, max_attempts: 2 }
  # agents: { reviewer: code-reviewer }       # an agent id of agents/ for each stage
  # documentation: { build: [cargo, build, --locked], binary: word-count }
decisions:                                  # the key that signs decision requests; required in production
  key_file: /run/secrets/decision_signing_key
  # previous_key_file: /run/secrets/decision_signing_key_previous   # during a rotation
  # previous_key_valid_until: 2026-11-02T12:00:00Z                  # 72 hours after the rotation; production ignores the previous key without it
worker: { name_prefix: worker, poll_interval_ms: 1000, sweep_interval_s: 10, drain_s: 120, tenants: [2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60] }
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
    repositories: [org/repo]              # optional; the weaker form (see below)
    expires_at: 2027-01-01T00:00:00Z      # optional
  - tenant: 2f0c7f64-0d1c-4c5e-9f0a-1b2c3d4e5f60
    github_user_id: 1002
    login: approver-one
    designations: [approver]
    repositories:                         # optional; the form to prefer
      - name: org/repo                    # for people to read; it can be stale after a rename
        github_repository_id: 7890123     # GitHub's numeric id of the repository; this decides
```

**Narrowing to repositories (API-1, RR-28).** An entry with no `repositories` list covers every
repository of the tenant. An entry with a list covers the repositories on it and no others, and an empty
list covers none. Each item is written one of two ways. A bare `owner/name` is compared by name, without
regard to case. That is the weaker form: a repository that is renamed or transferred leaves the grant
behind, and a new repository created under the old name inherits it (RR-28). A mapping with `name` and
`github_repository_id` is compared by the id when the repository that is asked about has one (every
registered repository has), so the grant follows the repository through a rename and a transfer and does
not pass to a new repository under the old name. `gh api repos/OWNER/NAME --jq .id` prints the id. An id
of zero, a missing name or a key that nobody knows makes the whole file unreadable, and every reader fails
closed. Reading a file with a list of bare names logs one warning for each version of the file, naming the
person and the repositories (`FileAllowlist::name_only_narrowing` returns the same list). The API (job
submission, decisions, reads, the webhook), the claim hook (`AllowlistAuthority`), the admission of a job
(`StoreAuthority`) and the approvals of a dependency (`CurrentApprovals`) ask with the id. The stages of the
workflow crate know a repository by its name (their inputs carry no id) and compare the name recorded next to
the id; a job or a decision reaches them only through the gates that ask with the id.

## Profiles

| Profile | Mode the engine records | A fake is accepted for |
|---|---|---|
| `production` | `production` | nothing |
| `local` | `test` | the agent runtime, router, broker and the GitHub ports |
| `test` | `test` | every port |

`PortRegistry::check(profile)` runs `require_permitted` for each of the **37** ports of `PortName::ALL` (the 17 of
the engine and the 20 seams of the stages that report a fidelity; a test in `profile.rs` pins the total) and lists
every refusal. The registry holds a `Seams` value that exists only when all 20 seams were supplied (`SeamsBuilder::build` names each one that is
missing), so a seam forgotten at wiring stops the process at start-up. A fake never comes from
`providers::assemble`; a test wiring that wants a stand-in builds its own registry from the testkit.

## The two pools

`database::connect` reads the two URL files, checks that the login each URL names is the login the
configuration names, registers the URLs and their passwords with the redactor and hands both pools to
`PgStore::connect`, which runs the role query on each and refuses a superuser, a role that bypasses
row-level security, an owner of tables, or a role in the wrong groups, and refuses a database that is
behind the code. A configuration that names one login for both pools is refused. `tests/database.rs`
shows swapped logins and a superuser on either pool being refused, and that readiness fails when the
schema is behind (`health::check_schema`, which compares the applied migrations with the count `build.rs`
took from `migrations/`).

## What the deployment must do

Checked by `tests/examples.rs`, which reads `infra/compose/config/*.example.yaml` itself (not a copy of their text),
so an example the parser refuses fails the test. This crate does not edit `infra/**`; its owner made the changes
below, and the test keeps them true.

1. **The worker example parses.** It is a valid configuration of the `local` profile with no credential, so the
   worker is BLOCKED until the deployment adds `broker.upstreams`, `broker.prices`, `github` and
   `worker.tenants`. It may add `sandbox.remote`, `sandbox.sidecar_command`, `sandbox.docker_host` and
   `sandbox.docker_config` (the two Docker keys are the only way to reach a daemon that is not on the default
   socket: the `docker` client of the worker runs with an empty environment).
2. **The API example is refused by the worker's parser, and is the API's own.** It names `database.api` and
   `listen`, which `FactoryConfig` does not have, and lacks `definitions_root`; the test
   `the_api_example_is_refused_by_the_worker_parser` shows the refusal. The API has its own type
   (`apps/api/src/config.rs`, `ApiConfig`), and `apps/api/tests/profile.rs` parses the file, which names the
   protected checkout, the decision key and the webhook secret. Do not point a worker at that file. The worker
   example names the same `decisions.key_file` as the API example, and `profile.rs` compares the two.
3. **Secret files.** The worker refuses a secret file that is a symbolic link, is not a regular file, or is readable
   by group or others (mode bits `0o077`); `tests/examples.rs` shows `0600` and `0400` accepted and `0640`,
   `0644` and `0604` refused. Compose mounts a secret with the mode and owner of the host file, so
   `scripts/local-up.sh` (which creates them `0600`) satisfies the mode rule, and the file must also be
   *readable by the user the container runs as* (`10010:10010` in `local.yml`). On a Linux host that means
   the stack runs as the user who owns the files: `local.yml` takes the user from `FACTORY_UID` and
   `FACTORY_GID` (default 10010), and `scripts/local-up.sh --factory` stops on Linux when the files belong to
   someone else. A file owned by another uid with mode `0600` passes the worker's check and then fails to open.
   Not run: no container of the factory profile has started. On Docker Desktop for Mac the ownership the
   container sees was not verified here. A value that must not be loosened: do not
   `chmod 0644` to make a mount readable; the worker will refuse it, correctly.
4. **Paths the daemon mounts.** `sandbox.token_root` and `sandbox.workspace_root` are mounted into sandbox
   containers by the Docker daemon, so they must be paths on the machine where the daemon runs, and must not
   be under a forbidden mount source of the policy (`/var`, `/etc`, `/home`, `/usr`, `/root`, `/`). On macOS
   that rules out the system temporary directory.
5. **The sidecar.** A deployment that runs agents sets `sandbox.sidecar_command` (`--mode`, `--listen`,
   `--upstream` pointing at the broker as the sidecar sees it, `--max-bytes`, `--allow` hosts). With none the
   real sidecar refuses to start.
