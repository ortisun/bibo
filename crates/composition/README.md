# factory-composition

The shared composition core of the factory: what the worker, and later the API and the operator
CLI, are made of before each adds its own shell. A ring 3 **library**
([ADR 0015](../../docs/adr/0015-composition-library.md)). Only binaries in `apps/` may depend on it
(rule `DEP-11`), and it has no `main`, no HTTP route, no command parser and no loop.

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
| `seams`, `authority`, `sandbox_specs` | The seams the stages declare that need no store state: schema check, manifests, allowlist, requests, repositories, probes, spec builders |
| `ledger` | `TaskLedger` over `TaskNodeOps`, fenced by attempt and epoch |
| `feedback`, `risk` | `ReworkSource`, `RoundSource` and `RiskSource`, read from the evidence the engine stored |
| `drift` | `EvidenceDrift` as a channel to the loop that owns the engine |
| `specs` | `SpecDrafts`, `SpecApprovals`, `SpecHistory` |
| `delivery` | `ApprovalSources` and `DeliverySources` (two methods fail closed) |
| `commands` | The pure parsers from a comment, `argv` or a form to an approval command |
| `reading` | Shared reads of stage run outputs, the ledger and the artifact store |
| `providers` | The real Docker sandbox, host-side workspace and Spec Kit provider from the configuration |
| `runtimes` | One agent runtime that serves every tenant |
| `indexing` | Indexes what a sandbox writes and what a workspace exports, for the tenant, when it is written |
| `hooks` | The work a loop does before it claims (`BeforeClaim`) |
| `assemble` | Start-up in order (`prepare`), the list of adapters not assembled (`blocked_adapters`) and of seam methods that fail closed (`blocked_seams`) |

## What a binary does with it

1. Read the configuration: `FactoryConfig::from_environment` or `from_file`.
2. `assemble::prepare(&config, Identity { service, version })` runs the start-up checks and returns
   the policy, the redactor, the registry of secret values, the connected store and the telemetry
   guard.
3. Add what the binary alone needs (the worker starts the broker listener), then
   `Prepared::check_secret_kinds(profile)`.
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
  remote: { https_host: github.com }        # or { directory: /abs/path } outside production
  sidecar_command: []                       # the egress sidecar's arguments
broker:
  listen: 127.0.0.1:8731
  upstreams:
    - { provider: anthropic, base_url: 'https://api.anthropic.com', key_file: /run/secrets/anthropic }
  prices:
    - { provider: anthropic, model: claude-sonnet-5-5, input: 3000000, cache_write: 3750000, cache_read: 300000, output: 15000000 }
github: { app_id: 1, key_file: /run/secrets/github_app_key }
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
    repositories: [org/repo]              # optional
    expires_at: 2027-01-01T00:00:00Z      # optional
```

## Profiles

| Profile | Mode the engine records | A fake is accepted for |
|---|---|---|
| `production` | `production` | nothing |
| `local` | `test` | the agent runtime, router, broker and the GitHub ports |
| `test` | `test` | every port |

`PortRegistry::check(profile)` runs `require_permitted` for each of the **25** ports (the 17 of the engine and
the 8 seams of the stages that report a fidelity) and lists every refusal. The registry holds a `Seams`
value that exists only when all 16 seams were supplied (`SeamsBuilder::build` names each one that is
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

Checked by `tests/examples.rs` against `infra/compose/config/*.example.yaml`. This crate does not edit
`infra/**`; these are the changes its owner makes.

1. **The worker example parses.** It is a valid configuration of the `local` profile with no credential, so the
   worker is BLOCKED until the deployment adds `broker.upstreams`, `broker.prices`, `github` and
   `worker.tenants`. It may add `sandbox.remote` and `sandbox.sidecar_command`.
2. **The API example is refused.** It names `database.api` and `listen`, which the configuration does not have
   (the API has no configuration type yet; the placeholder says so), and it lacks `protected_checkout` and
   `definitions_root`, which are required. Until the API part defines its own type, do not point a worker
   at that file. When it does, it will need the protected checkout for the policy and the allowlist.
3. **Secret files.** The worker refuses a secret file that is a symbolic link, is not a regular file, or is readable
   by group or others (mode bits `0o077`); `tests/examples.rs` shows `0600` and `0400` accepted and `0640`,
   `0644` and `0604` refused. Compose mounts a secret with the mode and owner of the host file, so
   `scripts/local-up.sh` (which creates them `0600`) satisfies the mode rule, and the file must also be
   *readable by the user the container runs as* (`10010:10010` in `local.yml`). On a Linux host that means
   the secret files are owned by uid 10010 (`chown`) or the stack runs as the host user; a file owned by
   another uid with mode `0600` passes the worker's check and then fails to open. On Docker Desktop for Mac
   the ownership the container sees was not verified here. A value that must not be loosened: do not
   `chmod 0644` to make a mount readable; the worker will refuse it, correctly.
4. **Paths the daemon mounts.** `sandbox.token_root` and `sandbox.workspace_root` are mounted into sandbox
   containers by the Docker daemon, so they must be paths on the machine where the daemon runs, and must not
   be under a forbidden mount source of the policy (`/var`, `/etc`, `/home`, `/usr`, `/root`, `/`). On macOS
   that rules out the system temporary directory.
5. **The sidecar.** A deployment that runs agents sets `sandbox.sidecar_command` (`--mode`, `--listen`,
   `--upstream` pointing at the broker as the sidecar sees it, `--max-bytes`, `--allow` hosts). With none the
   real sidecar refuses to start.
